/*
 *  Copyright (C) 2017, Nayuta, Inc. All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
/** @file   ln_routing.cpp
 *  @brief  routing計算
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>

#include "ln_local.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"
#include "ln_segwit_addr.h"

#include <iostream>
#include <fstream>
#include <deque>
#include <vector>

#include <boost/config.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/property_map/property_map.hpp>


using namespace boost;

/**************************************************************************
 * macros
 **************************************************************************/

#define M_CLTV_INIT                         ((uint16_t)0xffff)

#if 1
#define M_DBGLOG(...)
#define M_DBGDUMPG(...)
#else
#define M_DBGLOG                            LOGD
#define M_DBGDUMPG                          DUMPD
#endif


/**************************************************************************
 * typedefs
 **************************************************************************/

extern "C" {
    bool ln_getids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len);
    bool ln_channel_update_get_params(ln_cnl_update_t *pUpd, const uint8_t *pData, uint16_t Len);
}

struct Node {
    //std::string name;
    const uint8_t*  p_node;
};

struct Fee {
    //std::string name;
    uint64_t    short_channel_id;
    uint32_t    fee_base_msat;
    uint32_t    fee_prop_millionths;
    uint16_t    cltv_expiry_delta;
    const uint8_t   *node_id;
};

typedef adjacency_list <
                listS,
                vecS,
                bidirectionalS,
                Node,
                Fee
        > graph_t;
typedef graph_traits < graph_t >::vertex_descriptor vertex_descriptor;
typedef graph_traits < graph_t >::vertex_iterator vertex_iterator;

struct nodes_t {
    uint64_t    short_channel_id;
    struct {
        uint8_t     node_id[BTC_SZ_PUBKEY];
        uint16_t    cltv_expiry_delta;
        uint64_t    htlc_minimum_msat;
        uint32_t    fee_base_msat;
        uint32_t    fee_prop_millionths;
    } ninfo[2];         //[0]channel_updateのdir0, [1]channel_updateのdir1
};

struct nodes_result_t {
    uint32_t    node_num;
    nodes_t     *p_nodes;
};

struct param_self_t {
    nodes_result_t  *p_result;
    const uint8_t   *p_payer;
};


/********************************************************************
 * functions
 ********************************************************************/

static int direction(const uint8_t **ppNode1, const uint8_t **ppNode2, const uint8_t *pNode1, const uint8_t *pNode2)
{
    int lp2;
    for (lp2 = 0; lp2 < BTC_SZ_PUBKEY; lp2++) {
        if (pNode1[lp2] != pNode2[lp2]) {
            break;
        }
    }
    int dir = (pNode1[lp2] < pNode2[lp2]) ? 0 : 1;
    if (dir == 0) {
        *ppNode1 = pNode1;
        *ppNode2 = pNode2;
    } else {
        *ppNode2 = pNode1;
        *ppNode1 = pNode2;
    }
    return dir;
}


static uint64_t edgefee(uint64_t amtmsat, uint32_t fee_base_msat, uint32_t fee_prop_millionths)
{
    return (uint64_t)fee_base_msat + (uint64_t)((amtmsat * fee_prop_millionths) / 1000000);
}


static void dumpit_chan(nodes_result_t *p_result, char type, const utl_buf_t *p_buf)
{
    nodes_t *p_nodes;

    /*
     * channel_announcementとchannel_updateの存在パターンとして、以下がある。
     *      a) channel_announcementのみ
     *      b) channel_updateのみ
     *      c) 両方
     *
     * 通常、channel_announcementとchannel_updateは両方存在するが、announcement前は相手からchannel_updateだけ送信することがある。
     *      https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001220.html
     * ただし、channelのnodeidはchannel_announcementが保持しているため、自分が持つshort_chennl_idと一致する場合のみroutingに加える。
     */

    switch (type) {
    case LN_DB_CNLANNO_ANNO:
        p_result->node_num++;
        p_result->p_nodes = (nodes_t *)realloc(p_result->p_nodes, sizeof(nodes_t) * p_result->node_num);
        p_nodes = &p_result->p_nodes[p_result->node_num - 1];

        ln_getids_cnl_anno(
                            &p_nodes->short_channel_id,
                            p_nodes->ninfo[0].node_id,
                            p_nodes->ninfo[1].node_id,
                            p_buf->buf, p_buf->len);
        p_nodes->ninfo[0].cltv_expiry_delta = M_CLTV_INIT;     //未設定判定用
        p_nodes->ninfo[1].cltv_expiry_delta = M_CLTV_INIT;     //未設定判定用

        M_DBGLOG("[cnl]nodenum=%d\n", p_result->node_num);
        M_DBGLOG("[cnl]short_channel_id: %016" PRIx64 "\n", p_nodes->short_channel_id);
        M_DBGLOG("[cnl]node1= ");
        M_DBGDUMPG(p_nodes->ninfo[0].node_id, BTC_SZ_PUBKEY);
        M_DBGLOG("[cnl]node2= ");
        M_DBGDUMPG(p_nodes->ninfo[1].node_id, BTC_SZ_PUBKEY);
        break;
    case LN_DB_CNLANNO_UPD1:
    case LN_DB_CNLANNO_UPD2:
        if (p_result->node_num > 0) {
            p_nodes = &p_result->p_nodes[p_result->node_num - 1];

            ln_cnl_update_t upd;
            int idx = type - LN_DB_CNLANNO_UPD1;
            bool bret = ln_channel_update_get_params(&upd, p_buf->buf, p_buf->len);
            if (bret && ((upd.flags & LN_CNLUPD_FLAGS_DISABLE) == 0)) {
                if (p_nodes->short_channel_id == upd.short_channel_id) {
                    //disable状態ではない && channel_announcement.short_channel_idと一致
                    p_nodes->ninfo[idx].cltv_expiry_delta = upd.cltv_expiry_delta;
                    p_nodes->ninfo[idx].htlc_minimum_msat = upd.htlc_minimum_msat;
                    p_nodes->ninfo[idx].fee_base_msat = upd.fee_base_msat;
                    p_nodes->ninfo[idx].fee_prop_millionths = upd.fee_prop_millionths;

                    M_DBGLOG("[upd]nodenum=%d\n", p_result->node_num);
                    M_DBGLOG("[upd]short_channel_id: %016" PRIx64 "\n", p_nodes->short_channel_id);
                    M_DBGLOG("[upd]node1= ");
                    M_DBGDUMPG(p_nodes->ninfo[0].node_id, BTC_SZ_PUBKEY);
                    M_DBGLOG("[upd]node2= ");
                    M_DBGDUMPG(p_nodes->ninfo[1].node_id, BTC_SZ_PUBKEY);
                }
            } else {
                //disableの場合は、対象外にされるよう初期値にしておく
                M_DBGLOG("[upd]short_channel_id: %016" PRIx64 "\n", p_nodes->short_channel_id);
                M_DBGLOG("[upd]skip[%c]\n", type);
                p_nodes->ninfo[idx].cltv_expiry_delta = M_CLTV_INIT;
            }

        }
        break;
    default:
        break;
    }
}


//開設済みで生きている送金元channelは、announcementの有無にかかわらず検索候補に追加する
static bool comp_func_self(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_db_param;

    bool bret;
    param_self_t *p_prm_self = (param_self_t *)p_param;

    if ((self->short_channel_id != 0) && (ln_close_type(self) == LN_CLOSETYPE_NONE)) {
        //チャネルは開設している && close処理をしていない
        bret = ln_db_routeskip_search(self->short_channel_id);
        if (bret) {
            //skip DBに載っているchannelは使用しない
            M_DBGLOG("skip : %" PRIx64 "\n", self->short_channel_id);
            return false;
        }

        if (memcmp(self->peer_node_id, p_prm_self->p_payer, BTC_SZ_PUBKEY) == 0) {
            return false;
        }

        p_prm_self->p_result->node_num++;
        p_prm_self->p_result->p_nodes = (nodes_t *)realloc(p_prm_self->p_result->p_nodes, sizeof(nodes_t) * p_prm_self->p_result->node_num);
        p_prm_self->p_result->p_nodes[p_prm_self->p_result->node_num - 1].short_channel_id = self->short_channel_id;

        nodes_t *p_nodes_result = &p_prm_self->p_result->p_nodes[p_prm_self->p_result->node_num - 1];
        const uint8_t *p1, *p2;
        direction(&p1, &p2, p_prm_self->p_payer, self->peer_node_id);
        memcpy(p_nodes_result->ninfo[0].node_id, p1, BTC_SZ_PUBKEY);
        memcpy(p_nodes_result->ninfo[1].node_id, p2, BTC_SZ_PUBKEY);
        for (int lp = 0; lp < 2; lp++) {
            p_nodes_result->ninfo[lp].cltv_expiry_delta = 0;
            p_nodes_result->ninfo[lp].htlc_minimum_msat = 0;
            p_nodes_result->ninfo[lp].fee_base_msat = 0;
            p_nodes_result->ninfo[lp].fee_prop_millionths = 0;
        }

        M_DBGLOG("[self]nodenum=%d\n",  p_prm_self->p_result->node_num);
        M_DBGLOG("[self]short_channel_id: %016" PRIx64 "\n", self->short_channel_id);
        M_DBGLOG("[self]p_payer= ");
        M_DBGDUMPG(p_prm_self->p_payer, BTC_SZ_PUBKEY);
        M_DBGLOG("[self]self->peer_node_id= ");
        M_DBGDUMPG(self->peer_node_id, BTC_SZ_PUBKEY);
    }

    return false;   //false=検索継続
}


/**
 * @param[in]       pPayerId            送金元node_id
 */
static bool loaddb(nodes_result_t *p_result, const uint8_t *pPayerId)
{
    int ret;
    bool bret;

    //self
    param_self_t prm_self;

    prm_self.p_result = p_result;
    prm_self.p_payer = pPayerId;
    ln_db_self_search(comp_func_self, &prm_self);

    //channel_anno
    void *p_cur;

    ret = ln_db_anno_transaction();
    if (!ret) {
        //channel_announcementを1回も受信せずにDBが存在しない場合もあるため、trueで返す
        return true;
    }

    ret = ln_db_anno_cur_open(&p_cur, LN_DB_CUR_CNL);
    if (ret) {
        uint64_t short_channel_id;
        char type;
        utl_buf_t buf_cnl = UTL_BUF_INIT;

        while ((ret = ln_db_annocnl_cur_get(p_cur, &short_channel_id, &type, NULL, &buf_cnl))) {
            bret = ln_db_routeskip_search(short_channel_id);
            if (bret) {
                utl_buf_free(&buf_cnl);
                continue;
            }

            dumpit_chan(p_result, type, &buf_cnl);
            utl_buf_free(&buf_cnl);
        }
    }

    ln_db_anno_commit(true);

    return true;
}


static graph_t::vertex_descriptor ver_add(graph_t& g, const uint8_t *pNodeId)
{
    graph_t::vertex_descriptor v = static_cast<graph_t::vertex_descriptor>(-1);
    bool ret = false;

    std::pair<graph_t::vertex_iterator, graph_t::vertex_iterator> ver_its = vertices(g);
    for (graph_t::vertex_iterator st = ver_its.first, et = ver_its.second; st != et; st++) {
        if (memcmp(g[*st].p_node, pNodeId, BTC_SZ_PUBKEY) == 0) {
            ret = true;
            v = *st;
            break;
        }
    }
    if (!ret) {
        v = add_vertex(g);
        g[v].p_node = pNodeId;
    }

    return v;
}


lnerr_route_t ln_routing_calculate(
        ln_routing_result_t *pResult,
        const uint8_t *pPayerId,
        const uint8_t *pPayeeId,
        uint32_t CltvExpiry,
        uint64_t AmountMsat,
        uint8_t AddNum,
        const ln_fieldr_t *pAddRoute)
{
    pResult->hop_num = 0;

    nodes_result_t rt_res;
    rt_res.node_num = 0;
    rt_res.p_nodes = NULL;

    if ((pPayerId == NULL) || (pPayeeId == NULL)) {
        LOGD("fail: null input\n");
        return LNROUTE_PARAM;
    }

    bool ret = loaddb(&rt_res, pPayerId);
    if (!ret) {
        LOGD("fail: loaddb\n");
        return LNROUTE_LOADDB;
    }

    if (AddNum > 0) {
        //r-filedの追加
        int node_num = rt_res.node_num;
        rt_res.node_num += AddNum;
        rt_res.p_nodes = (nodes_t *)realloc(rt_res.p_nodes, sizeof(nodes_t) * rt_res.node_num);

        for (uint8_t lp = 0; lp < AddNum; lp++) {
            nodes_t *p_nodes = &rt_res.p_nodes[node_num];

            bool bret = ln_db_routeskip_search(pAddRoute[lp].short_channel_id);
            if (bret) {
                continue;
            }

            // add_node(0) --> payee(1)
            p_nodes->short_channel_id = pAddRoute[lp].short_channel_id;
            const uint8_t *p1, *p2;
            int dir = direction(&p1, &p2, pAddRoute[lp].node_id, pPayeeId);
            memcpy(p_nodes->ninfo[0].node_id, p1, BTC_SZ_PUBKEY);
            memcpy(p_nodes->ninfo[1].node_id, p2, BTC_SZ_PUBKEY);
            p_nodes->ninfo[0].cltv_expiry_delta = M_CLTV_INIT;     //未設定
            p_nodes->ninfo[1].cltv_expiry_delta = M_CLTV_INIT;     //未設定
            p_nodes->ninfo[dir].fee_base_msat = pAddRoute[lp].fee_base_msat;
            p_nodes->ninfo[dir].fee_prop_millionths = pAddRoute[lp].fee_prop_millionths;
            p_nodes->ninfo[dir].cltv_expiry_delta = pAddRoute[lp].cltv_expiry_delta;
            p_nodes->ninfo[dir].htlc_minimum_msat = 0;
            node_num++;

            M_DBGLOG("  [add]short_channel_id=%016" PRIx64 "\n", pAddRoute[lp].short_channel_id);
            M_DBGLOG("  [add]  [1]");
            M_DBGDUMPG(p1, BTC_SZ_PUBKEY);
            M_DBGLOG("  [add]  [2]");
            M_DBGDUMPG(p2, BTC_SZ_PUBKEY);
        }
    }
    LOGD("node_num: %d\n", rt_res.node_num);

    LOGD("start nodeid : ");
    DUMPD(pPayerId, BTC_SZ_PUBKEY);
    LOGD("end nodeid   : ");
    DUMPD(pPayeeId, BTC_SZ_PUBKEY);

    graph_t g;

    bool set_start = false;
    bool set_goal = false;
    graph_t::vertex_descriptor pnt_start = static_cast<graph_t::vertex_descriptor>(-1);
    graph_t::vertex_descriptor pnt_goal = static_cast<graph_t::vertex_descriptor>(-1);

    //Edge追加
    for (uint32_t lp = 0; lp < rt_res.node_num; lp++) {
        M_DBGLOG("  short_channel_id=%016" PRIx64 "\n", rt_res.p_nodes[lp].short_channel_id);
        M_DBGLOG("    [1]");
        M_DBGDUMPG(rt_res.p_nodes[lp].ninfo[0].node_id, BTC_SZ_PUBKEY);
        M_DBGLOG("    [2]");
        M_DBGDUMPG(rt_res.p_nodes[lp].ninfo[1].node_id, BTC_SZ_PUBKEY);

        graph_t::vertex_descriptor node1 = ver_add(g, rt_res.p_nodes[lp].ninfo[0].node_id);
        graph_t::vertex_descriptor node2 = ver_add(g, rt_res.p_nodes[lp].ninfo[1].node_id);

        if (!set_start) {
            if (memcmp(rt_res.p_nodes[lp].ninfo[0].node_id, pPayerId, BTC_SZ_PUBKEY) == 0) {
                pnt_start = node1;
                set_start = true;
            } else if (memcmp(rt_res.p_nodes[lp].ninfo[1].node_id, pPayerId, BTC_SZ_PUBKEY) == 0) {
                pnt_start = node2;
                set_start = true;
            }
        }
        if (!set_goal) {
            if (memcmp(rt_res.p_nodes[lp].ninfo[0].node_id, pPayeeId, BTC_SZ_PUBKEY) == 0) {
                pnt_goal = node1;
                set_goal = true;
            } else if (memcmp(rt_res.p_nodes[lp].ninfo[1].node_id, pPayeeId, BTC_SZ_PUBKEY) == 0) {
                pnt_goal = node2;
                set_goal = true;
            }
        }

        if (node1 != node2) {
            if (rt_res.p_nodes[lp].ninfo[0].cltv_expiry_delta != M_CLTV_INIT) {
                //channel_update1
                bool inserted = false;
                graph_t::edge_descriptor e1;

                boost::tie(e1, inserted) = add_edge(node1, node2, g);
                g[e1].short_channel_id = rt_res.p_nodes[lp].short_channel_id;
                g[e1].fee_base_msat = rt_res.p_nodes[lp].ninfo[0].fee_base_msat;
                g[e1].fee_prop_millionths = rt_res.p_nodes[lp].ninfo[0].fee_prop_millionths;
                g[e1].cltv_expiry_delta = rt_res.p_nodes[lp].ninfo[0].cltv_expiry_delta;
                g[e1].node_id = rt_res.p_nodes[lp].ninfo[0].node_id;
            }
            if (rt_res.p_nodes[lp].ninfo[1].cltv_expiry_delta != M_CLTV_INIT) {
                //channel_update2
                bool inserted = false;
                graph_t::edge_descriptor e2;

                boost::tie(e2, inserted) = add_edge(node2, node1, g);
                g[e2].short_channel_id = rt_res.p_nodes[lp].short_channel_id;
                g[e2].fee_base_msat = rt_res.p_nodes[lp].ninfo[1].fee_base_msat;
                g[e2].fee_prop_millionths = rt_res.p_nodes[lp].ninfo[1].fee_prop_millionths;
                g[e2].cltv_expiry_delta = rt_res.p_nodes[lp].ninfo[1].cltv_expiry_delta;
                g[e2].node_id = rt_res.p_nodes[lp].ninfo[1].node_id;
            }
        }
    }

    //LOGD("pnt_start=%d, pnt_goal=%d\n", (int)pnt_start, (int)pnt_goal);
    if (!set_start) {
        LOGD("fail: no start node\n");
        return LNROUTE_NOSTART;
    }
    if (!set_goal) {
        LOGD("fail: no goal node\n");
        return LNROUTE_NOGOAL;
    }

    std::vector<vertex_descriptor> p(num_vertices(g));      //parent
    std::vector<int> d(num_vertices(g));
    dijkstra_shortest_paths(g, pnt_start,
                        weight_map(boost::get(&Fee::fee_base_msat, g)).
                        predecessor_map(&p[0]).
                        distance_map(&d[0]));

    if (p[pnt_goal] == pnt_goal) {
        LOGD("fail: cannot find route\n");
        free(rt_res.p_nodes);
        return LNROUTE_NOTFOUND;
    }

    //逆順に入っているので、並べ直す
    //ついでに、min_final_cltv_expiryを足す
    std::deque<vertex_descriptor> route;        //std::vectorにはpush_front()がない
    std::deque<uint64_t> msat;
    std::deque<uint32_t> cltv;

    route.push_front(pnt_goal);
    msat.push_front(AmountMsat);
    cltv.push_front(CltvExpiry);

    for (vertex_descriptor v = pnt_goal; v != pnt_start; v = p[v]) {
        bool found;
        graph_t::edge_descriptor e;
        boost::tie(e, found) = edge(p[v], v, g);
        if (!found) {
            LOGD("not foooooooooound\n");
            abort();
        }

        route.push_front(p[v]);
        msat.push_front(AmountMsat);
        cltv.push_front(CltvExpiry);

        AmountMsat = AmountMsat + edgefee(AmountMsat, g[e].fee_base_msat, g[e].fee_prop_millionths);
        CltvExpiry += g[e].cltv_expiry_delta;
    }

    if (route.size() > LN_HOP_MAX + 1) {
        //先頭に自ノードが入るため+1
        LOGD("fail: too many hops\n");
        free(rt_res.p_nodes);
        return LNROUTE_TOOMANYHOP;
    }

    //戻り値の作成
    pResult->hop_num = (uint8_t)route.size();
    const uint8_t *p_next;

    for (int lp = 0; lp < pResult->hop_num - 1; lp++) {
        const uint8_t *p_now  = g[route[lp]].p_node;
        p_next = g[route[lp + 1]].p_node;

        const uint8_t *p_node_id1;
        const uint8_t *p_node_id2;
        direction(&p_node_id1, &p_node_id2, p_now, p_next);
        uint64_t sci = 0;
        for (uint32_t lp3 = 0; lp3 < rt_res.node_num; lp3++) {
            if ( (memcmp(p_node_id1, rt_res.p_nodes[lp3].ninfo[0].node_id, BTC_SZ_PUBKEY) == 0) &&
                 (memcmp(p_node_id2, rt_res.p_nodes[lp3].ninfo[1].node_id, BTC_SZ_PUBKEY) == 0) ) {
                sci = rt_res.p_nodes[lp3].short_channel_id;
                break;
            }
        }
        if (sci == 0) {
            LOGD("not match!\n");
            abort();
        }

        pResult->hop_datain[lp].short_channel_id = sci;
        pResult->hop_datain[lp].amt_to_forward = msat[lp];
        pResult->hop_datain[lp].outgoing_cltv_value = cltv[lp];
        memcpy(pResult->hop_datain[lp].pubkey, p_now, BTC_SZ_PUBKEY);
    }

    //最後
    pResult->hop_datain[pResult->hop_num - 1].short_channel_id = 0;
    pResult->hop_datain[pResult->hop_num - 1].amt_to_forward = msat[pResult->hop_num - 1];
    pResult->hop_datain[pResult->hop_num - 1].outgoing_cltv_value = cltv[pResult->hop_num - 1];
    memcpy(pResult->hop_datain[pResult->hop_num - 1].pubkey, p_next, BTC_SZ_PUBKEY);

    free(rt_res.p_nodes);

    return LNROUTE_NONE;
}


void ln_routing_clear_skipdb(void)
{
    bool bret;

    bret = ln_db_routeskip_drop(false);
    LOGD("%s: clear routing skip DB\n", (bret) ? "OK" : "fail");

    bret = ln_db_invoice_drop();
    LOGD("%s: clear invoice DB\n", (bret) ? "OK" : "fail");
}
