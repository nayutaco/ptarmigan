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
#include "ln_invoice.h"
#include "utl_dbg.h"

#include <iostream>
#include <fstream>
#include <deque>
#include <vector>

//#define M_GRAPHVIZ
#include <boost/config.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/dijkstra_shortest_paths.hpp>
#include <boost/graph/graph_traits.hpp>
#include <boost/property_map/property_map.hpp>
#ifdef M_GRAPHVIZ
#include <boost/graph/graphviz.hpp>
#endif  //M_GRAPHVIZ

#include "ln_routing.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_CLTV_INIT                         ((uint16_t)0xffff)

#define M_SHADOW_ROUTE                      (10)    // shadow route extension
                                                    //  攪乱するためにオフセットとして加算するCLTV
                                                    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#recommendations-for-routing

//
//#define USE_WEIGHT_MILLIONTHS

#if 0
#define M_DBGLOG(...)
#define M_DBGDUMP(...)
#else
#define M_DBGLOG                            LOGD
#define M_DBGDUMP                           DUMPD
#endif

#if 0
#define M_DBGLOGV(...)
#define M_DBGDUMPV(...)
#else
#define M_DBGLOGV                           LOGD
#define M_DBGDUMPV                          DUMPD
#endif


/**************************************************************************
 * typedefs
 **************************************************************************/

//
//boost graph
//

struct vertex_prop_t {
    uint8_t   node_id[BTC_SZ_PUBKEY];
};

struct edge_prop_t {
    uint64_t    short_channel_id;
    uint32_t    fee_base_msat;
    uint32_t    fee_prop_millionths;
    uint16_t    cltv_expiry_delta;
    uint64_t    weight;
};

typedef boost::adjacency_list<
    boost::listS, boost::vecS, boost::bidirectionalS,
    vertex_prop_t, edge_prop_t
> graph_t;
typedef boost::graph_traits<graph_t>::vertex_descriptor vertex_descriptor_t;


//
//DB load
//

struct nodeinfo_t {
    uint8_t     node_id[BTC_SZ_PUBKEY];
    uint16_t    cltv_expiry_delta;
    uint64_t    htlc_minimum_msat;
    uint32_t    fee_base_msat;
    uint32_t    fee_prop_millionths;
    ln_db_route_skip_t   route_skip;              //ln_db_route_skip_search()
};

struct nodes_t {
    uint64_t    short_channel_id;
    nodeinfo_t  ninfo[2];         //[0]channel_updateのdir0, [1]channel_updateのdir1
};

struct nodes_result_t {
    uint32_t    node_num;
    nodes_t     *p_nodes;
};

struct param_channel_t {
    nodes_result_t  *p_result;
    const uint8_t   *p_payer;
};


/********************************************************************
 * prototypes
 ********************************************************************/

extern "C" {
    bool ln_get_ids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len);
    bool ln_channel_update_get_params(ln_msg_channel_update_t *pUpd, const uint8_t *pData, uint16_t Len);
}

static int direction(const uint8_t **ppNode1, const uint8_t **ppNode2, const uint8_t *pNode1, const uint8_t *pNode2);
static uint64_t edgefee(uint64_t amtmsat, uint32_t fee_base_msat, uint32_t fee_prop_millionths);
static void dumpit_chan(nodes_result_t *p_result, char type, const utl_buf_t *p_buf, ln_db_route_skip_t rskip);
static bool comp_func_channel(ln_channel_t *pChannel, void *p_db_param, void *p_param);
static void add_r_field(graph_t& Graph,
        const uint8_t *pPayeeId,
        const ln_r_field_t *pAddRoute,
        int AddNum);
static bool load_db(nodes_result_t *p_result, const uint8_t *pPayerId);
static bool routing_add_channel(graph_t& Graph,
        uint64_t ShortChannelId,
        const nodeinfo_t *pNinfo,
        const uint8_t *pNode1, const uint8_t *pNode2);
static graph_t::vertex_descriptor routing_vertex_add(graph_t& Graph, const uint8_t *pNodeId);
static void routing_edge_add(graph_t& Graph,
        uint64_t ShortChannelId, const nodeinfo_t *pInfo,
        graph_t::vertex_descriptor Node1, graph_t::vertex_descriptor Node2
#ifdef USE_WEIGHT_MILLIONTHS
        ,uint64_t AmountMsat
#endif
        );


/********************************************************************
 * static variables
 ********************************************************************/

static graph_t mGraph;


/********************************************************************
 * public functions
 ********************************************************************/

bool ln_routing_init(const uint8_t *pPayerId)
{
    LOGD("initialize routing graph\n");

    nodes_result_t rt_res;
    rt_res.node_num = 0;
    rt_res.p_nodes = NULL;

    bool ret = load_db(&rt_res, pPayerId);
    if (!ret) {
        LOGE("fail: load_db\n");
        return false;
    }
    LOGD("node_num: %d\n", rt_res.node_num);

    //Edge追加
    for (uint32_t lp = 0; lp < rt_res.node_num; lp++) {
        //LOGD("  short_channel_id=%016" PRIx64 "\n", rt_res.p_nodes[lp].short_channel_id);
        M_DBGLOGV("    [1]");
        M_DBGDUMPV(rt_res.p_nodes[lp].ninfo[0].node_id, BTC_SZ_PUBKEY);
        M_DBGLOGV("    [2]");
        M_DBGDUMPV(rt_res.p_nodes[lp].ninfo[1].node_id, BTC_SZ_PUBKEY);

        graph_t::vertex_descriptor node1 = routing_vertex_add(mGraph, rt_res.p_nodes[lp].ninfo[0].node_id);
        graph_t::vertex_descriptor node2 = routing_vertex_add(mGraph, rt_res.p_nodes[lp].ninfo[1].node_id);

        if (node1 != node2) {
            if (rt_res.p_nodes[lp].ninfo[0].cltv_expiry_delta != M_CLTV_INIT) {
                //channel_update1
                routing_edge_add(mGraph,
                    rt_res.p_nodes[lp].short_channel_id,
                    &rt_res.p_nodes[lp].ninfo[0],
                    node1, node2
#ifdef USE_WEIGHT_MILLIONTHS
                    , AmountMsat
#endif
                );
            }
            if (rt_res.p_nodes[lp].ninfo[1].cltv_expiry_delta != M_CLTV_INIT) {
                //channel_update2
                routing_edge_add(mGraph,
                    rt_res.p_nodes[lp].short_channel_id,
                    &rt_res.p_nodes[lp].ninfo[1],
                    node2, node1
#ifdef USE_WEIGHT_MILLIONTHS
                    , AmountMsat
#endif
                );
            }
        }
    }

    UTL_DBG_FREE(rt_res.p_nodes);

    LOGD("initialize routing graph - exit\n");

    return true;
}


bool ln_routing_add_channel(
        const ln_msg_channel_update_t *pChannelUpdate,
        const uint8_t *pNode1, const uint8_t *pNode2)
{
    LOGD("add routing graph\n");

    nodeinfo_t ninfo;
    ninfo.cltv_expiry_delta = pChannelUpdate->cltv_expiry_delta;
    ninfo.htlc_minimum_msat = pChannelUpdate->htlc_minimum_msat;
    ninfo.fee_base_msat = pChannelUpdate->fee_base_msat;
    ninfo.fee_prop_millionths = pChannelUpdate->fee_proportional_millionths;
    if (pChannelUpdate->channel_flags & LN_CNLUPD_CHFLAGS_DISABLE) {
        ninfo.route_skip = LN_DB_ROUTE_SKIP_TEMP;
    } else {
        ninfo.route_skip = LN_DB_ROUTE_SKIP_NONE;
    }
    bool ret = routing_add_channel(mGraph,
        pChannelUpdate->short_channel_id,
        &ninfo,
        pNode1, pNode2);

    LOGD("add routing graph - exit %d\n", ret);

    return ret;
}


void ln_routing_add_rfield(uint8_t AddNum, const ln_r_field_t *pAddRoute, const uint8_t *pPayeeId)
{
    if (AddNum > 0) {
        LOGD("add routing r-field\n");
        add_r_field(mGraph, pPayeeId, pAddRoute, AddNum);
        LOGD("add routing r-field - exit\n");
    }
}


lnerr_route_t ln_routing_calculate(
    ln_routing_result_t *pResult, const uint8_t *pPayerId, const uint8_t *pPayeeId,
    uint32_t CltvExpiry, uint64_t AmountMsat)
{
    if ((pPayerId == NULL) || (pPayeeId == NULL)) {
        LOGE("fail: null input\n");
        return LNROUTE_PARAM;
    }

    pResult->num_hops = 0;

    LOGD("start node_id : ");
    DUMPD(pPayerId, BTC_SZ_PUBKEY);
    LOGD("end node_id   : ");
    DUMPD(pPayeeId, BTC_SZ_PUBKEY);

    graph_t::vertex_descriptor pnt_start = routing_vertex_add(mGraph, pPayerId);
    graph_t::vertex_descriptor pnt_goal = routing_vertex_add(mGraph, pPayeeId);

    LOGD("VERTEX: %d\n", num_vertices(mGraph));
    LOGD("EDGE: %d\n", num_edges(mGraph));

    std::vector<vertex_descriptor_t> pt(num_vertices(mGraph));     //parent
    std::vector<uint64_t> dist(num_vertices(mGraph));
    dijkstra_shortest_paths(mGraph, pnt_start,
                weight_map(boost::get(&edge_prop_t::weight, mGraph)).
                    predecessor_map(&pt[0]).
                        distance_map(&dist[0]));

    if (pt[pnt_goal] == pnt_goal) {
        LOGE("fail: cannot find route\n");
        return LNROUTE_NOTFOUND;
    }

    //逆順に入っているので、並べ直す
    //ついでに、min_final_cltv_expiryを足す
    std::deque<vertex_descriptor_t> route;        //std::vectorにはpush_front()がない
    std::deque<uint64_t> msat;
    std::deque<uint32_t> cltv;
    std::deque<uint64_t> scid;

    CltvExpiry += M_SHADOW_ROUTE;

    route.push_front(pnt_goal);
    msat.push_front(AmountMsat);
    cltv.push_front(CltvExpiry);
    scid.push_front(0);

    for (vertex_descriptor_t vtx = pnt_goal; vtx != pnt_start; vtx = pt[vtx]) {
        bool found;
        graph_t::edge_descriptor eg;
        boost::tie(eg, found) = edge(pt[vtx], vtx, mGraph);
        if (!found) {
            LOGE("fail: not foooooooooound\n");
            return LNROUTE_NOTFOUND;
        }

        route.push_front(pt[vtx]);
        msat.push_front(AmountMsat);
        cltv.push_front(CltvExpiry);
        scid.push_front(mGraph[eg].short_channel_id);

        AmountMsat = AmountMsat + edgefee(AmountMsat, mGraph[eg].fee_base_msat, mGraph[eg].fee_prop_millionths);
        CltvExpiry += mGraph[eg].cltv_expiry_delta;
    }

    if (route.size() > LN_HOP_MAX + 1) {
        //先頭に自ノードが入るため+1
        LOGE("fail: too many hops\n");
        return LNROUTE_TOOMANYHOP;
    }

    //戻り値の作成
    pResult->num_hops = (uint8_t)route.size();
    const uint8_t *p_next;

    for (int lp = 0; lp < pResult->num_hops - 1; lp++) {
        const uint8_t *p_now  = mGraph[route[lp]].node_id;
        p_next = mGraph[route[lp + 1]].node_id;

        pResult->hop_datain[lp].short_channel_id = scid[lp];
        pResult->hop_datain[lp].amt_to_forward = msat[lp];
        pResult->hop_datain[lp].outgoing_cltv_value = cltv[lp];
        memcpy(pResult->hop_datain[lp].pubkey, p_now, BTC_SZ_PUBKEY);
        LOGD("  route [%d]", lp);
        DUMPD(p_now, BTC_SZ_PUBKEY);
    }

    //最後
    pResult->hop_datain[pResult->num_hops - 1].short_channel_id = 0;
    pResult->hop_datain[pResult->num_hops - 1].amt_to_forward = msat[pResult->num_hops - 1];
    pResult->hop_datain[pResult->num_hops - 1].outgoing_cltv_value = cltv[pResult->num_hops - 1];
    memcpy(pResult->hop_datain[pResult->num_hops - 1].pubkey, p_next, BTC_SZ_PUBKEY);
    LOGD("  route [%d]", pResult->num_hops - 1);
    DUMPD(p_next, BTC_SZ_PUBKEY);

    return LNROUTE_OK;
}


void ln_routing_clear_skipdb(void)
{
    bool bret;

    bret = ln_db_route_skip_drop(false);
    LOGD("%s: clear routing skip DB\n", (bret) ? "OK" : "fail");
}


void ln_routing_create_dot(const char *pFilename)
{
#ifdef M_GRAPHVIZ
    // http://www.boost.org/doc/libs/1_55_0/libs/graph/example/dijkstra-example.cpp
    std::ofstream dot_file(pFilename);

    dot_file << "digraph D {\n"
             //<< "  rankdir=LR\n"
             //<< "  ratio=\"fill\"\n"
             << "  graph[layout=circo];\n"
             //<< "  edge[style=\"bold\"];\n"
             << "  node[style=\"solid,filled\", fillcolor=\"#8080ff\"];\n"
             ;

    boost::graph_traits<graph_t>::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = edges(mGraph); ei != ei_end; ++ei) {
        boost::graph_traits<graph_t>::edge_descriptor e = *ei;
        boost::graph_traits<graph_t>::vertex_descriptor u = source(e, mGraph);
        boost::graph_traits<graph_t>::vertex_descriptor v = target(e, mGraph);
        if (u != v) {
            char node1[128] = "\"";
            char node2[128] = "\"";
            const uint8_t *p_node1 = mGraph[u].node_id;
            const uint8_t *p_node2 = mGraph[v].node_id;
            for (int lp = 0; lp < 6; lp++) {
                char s[3];
                sprintf(s, "%02x", p_node1[lp]);
                strcat(node1, s);
                sprintf(s, "%02x", p_node2[lp]);
                strcat(node2, s);
            }
            strcat(node1, "\"");
            strcat(node2, "\"");
            int col = memcmp(p_node1, p_node2, BTC_SZ_PUBKEY);
            if (col > 0) {
                dot_file << node1 << " -> " << node2
                        << "["
                        << "label=\""
                        << std::hex << mGraph[e].short_channel_id << std::dec
                        //<< ","
                        //<< mGraph[e].fee_base_msat
                        //<< ","
                        //<< mGraph[e].fee_prop_millionths
                        //<< ","
                        //<< mGraph[e].cltv_expiry_delta
                        << "\""
                        << ", color=\"black\""
                        << ", fontcolor=\"#804040\""
                        << ", arrowhead=\"none\""
                        << "]" << std::endl;
            }
        }
    }
    dot_file << "}";
#else
    (void)pFilename;
#endif  //M_GRAPHVIZ
}


/********************************************************************
 * private functions
 ********************************************************************/

/**
 * @retval  0       *ppNode1 = pNode1, *ppNode2 = pNode2
 * @retval  1       *ppNode1 = pNode2, *ppNode2 = pNode1
 */
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


static void dumpit_chan(nodes_result_t *p_result, char type, const utl_buf_t *p_buf, ln_db_route_skip_t rskip)
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
     * ただし、channelのnode_idはchannel_announcementが保持しているため、自分が持つshort_chennl_idと一致する場合のみroutingに加える。
     */

    switch (type) {
    case LN_DB_CNLANNO_ANNO:
        p_result->node_num++;
        p_result->p_nodes = (nodes_t *)UTL_DBG_REALLOC(p_result->p_nodes, sizeof(nodes_t) * p_result->node_num);
        p_nodes = &p_result->p_nodes[p_result->node_num - 1];

        ln_get_ids_cnl_anno(
                            &p_nodes->short_channel_id,
                            p_nodes->ninfo[0].node_id,
                            p_nodes->ninfo[1].node_id,
                            p_buf->buf, p_buf->len);
        p_nodes->ninfo[0].route_skip = rskip;
        p_nodes->ninfo[1].route_skip = rskip;
        p_nodes->ninfo[0].cltv_expiry_delta = M_CLTV_INIT;     //未設定判定用
        p_nodes->ninfo[1].cltv_expiry_delta = M_CLTV_INIT;     //未設定判定用

        M_DBGLOGV("[cnl]nodenum=%d\n", p_result->node_num);
        M_DBGLOGV("[cnl]short_channel_id: %016" PRIx64 "\n", p_nodes->short_channel_id);
        M_DBGLOGV("[cnl]node1= ");
        M_DBGDUMPV(p_nodes->ninfo[0].node_id, BTC_SZ_PUBKEY);
        M_DBGLOGV("[cnl]node2= ");
        M_DBGDUMPV(p_nodes->ninfo[1].node_id, BTC_SZ_PUBKEY);
        break;
    case LN_DB_CNLANNO_UPD0:
    case LN_DB_CNLANNO_UPD1:
        if (p_result->node_num > 0) {
            p_nodes = &p_result->p_nodes[p_result->node_num - 1];

            ln_msg_channel_update_t upd;
            int idx = type - LN_DB_CNLANNO_UPD0;
            bool bret = ln_channel_update_get_params(&upd, p_buf->buf, p_buf->len);
            if (bret && ((upd.channel_flags & LN_CNLUPD_CHFLAGS_DISABLE) == 0)) {
                if (p_nodes->short_channel_id == upd.short_channel_id) {
                    //disable状態ではない && channel_announcement.short_channel_idと一致
                    p_nodes->ninfo[idx].cltv_expiry_delta = upd.cltv_expiry_delta;
                    p_nodes->ninfo[idx].htlc_minimum_msat = upd.htlc_minimum_msat;
                    p_nodes->ninfo[idx].fee_base_msat = upd.fee_base_msat;
                    p_nodes->ninfo[idx].fee_prop_millionths = upd.fee_proportional_millionths;

                    M_DBGLOGV("[upd]nodenum=%d\n", p_result->node_num);
                    M_DBGLOGV("[upd]short_channel_id: %016" PRIx64 "\n", p_nodes->short_channel_id);
                    M_DBGLOGV("[upd]node1= ");
                    M_DBGDUMPV(p_nodes->ninfo[0].node_id, BTC_SZ_PUBKEY);
                    M_DBGLOGV("[upd]node2= ");
                    M_DBGDUMPV(p_nodes->ninfo[1].node_id, BTC_SZ_PUBKEY);
                } else {
                    M_DBGLOG("short_channel_id not match(%016" PRIx64 " !=%016" PRIx64 ")\n", p_nodes->short_channel_id, upd.short_channel_id);
                }
            } else {
                //disableの場合は、対象外にされるよう初期値にしておく
                M_DBGLOGV("[upd]short_channel_id: %016" PRIx64 "\n", p_nodes->short_channel_id);
                M_DBGLOGV("[upd]skip[%c]\n", type);
                p_nodes->ninfo[idx].cltv_expiry_delta = M_CLTV_INIT;
            }
        }
        break;
    default:
        break;
    }
}


//開設済みで生きている送金元channelは、announcementの有無にかかわらず検索候補に追加する
static bool comp_func_channel(ln_channel_t *pChannel, void *p_db_param, void *p_param)
{
    (void)p_db_param;

    param_channel_t *p_param_channel = (param_channel_t *)p_param;

    M_DBGLOG("channel: short_channel_id=%016" PRIx64 "\n", pChannel->short_channel_id);
    M_DBGLOG("      status=%d\n", ln_status_get(pChannel));
    if ((pChannel->short_channel_id != 0) && (ln_status_get(pChannel) == LN_STATUS_NORMAL_OPE)) {
        //チャネルは開設している && normal operation
        if (memcmp(pChannel->peer_node_id, p_param_channel->p_payer, BTC_SZ_PUBKEY) == 0) {
            M_DBGLOG("skip\n");
            return false;
        }

        p_param_channel->p_result->node_num++;
        p_param_channel->p_result->p_nodes = (nodes_t *)UTL_DBG_REALLOC(p_param_channel->p_result->p_nodes, sizeof(nodes_t) * p_param_channel->p_result->node_num);
        p_param_channel->p_result->p_nodes[p_param_channel->p_result->node_num - 1].short_channel_id = pChannel->short_channel_id;

        nodes_t *p_nodes_result = &p_param_channel->p_result->p_nodes[p_param_channel->p_result->node_num - 1];
        const uint8_t *p1, *p2;
        direction(&p1, &p2, p_param_channel->p_payer, pChannel->peer_node_id);
        memcpy(p_nodes_result->ninfo[0].node_id, p1, BTC_SZ_PUBKEY);
        memcpy(p_nodes_result->ninfo[1].node_id, p2, BTC_SZ_PUBKEY);
        for (int lp = 0; lp < 2; lp++) {
            p_nodes_result->ninfo[lp].cltv_expiry_delta = 0;
            p_nodes_result->ninfo[lp].htlc_minimum_msat = 0;
            p_nodes_result->ninfo[lp].fee_base_msat = 0;
            p_nodes_result->ninfo[lp].fee_prop_millionths = 0;
            p_nodes_result->ninfo[lp].route_skip = LN_DB_ROUTE_SKIP_NONE;
        }

        M_DBGLOGV("[channel]nodenum=%d\n",  p_param_channel->p_result->node_num);
        LOGD("[channel]short_channel_id: %016" PRIx64 "\n", pChannel->short_channel_id);
        M_DBGLOGV("[channel]p_payer= ");
        M_DBGDUMPV(p_param_channel->p_payer, BTC_SZ_PUBKEY);
        LOGD("[channel]pChannel->peer_node_id= ");
        DUMPD(pChannel->peer_node_id, BTC_SZ_PUBKEY);
    } else {
        M_DBGLOG("skip\n");
    }

    return false;   //false=検索継続
}


//r-fieldの追加
//  r-fieldのnode_id ==> pPayeeId の方向になる
static void add_r_field(graph_t& Graph,
        const uint8_t *pPayeeId,
        const ln_r_field_t *pAddRoute,
        int AddNum)
{
    for (uint8_t lp = 0; lp < AddNum; lp++) {
        // add_node(0) --> payee(1)
        nodeinfo_t ninfo;

        ninfo.fee_base_msat = pAddRoute[lp].fee_base_msat;
        ninfo.fee_prop_millionths = pAddRoute[lp].fee_prop_millionths;
        ninfo.cltv_expiry_delta = pAddRoute[lp].cltv_expiry_delta;
        ninfo.htlc_minimum_msat = 0;
        ninfo.route_skip = LN_DB_ROUTE_SKIP_NONE; //skip DBをチェックしない
        routing_add_channel(Graph,
            pAddRoute[lp].short_channel_id,
            &ninfo,
            pAddRoute[lp].node_id, pPayeeId
        );

        M_DBGLOG("  [add]short_channel_id=%016" PRIx64 "\n", pAddRoute[lp].short_channel_id);
        M_DBGLOG("  [add]  [1]");
        M_DBGDUMP(pAddRoute[lp].node_id, BTC_SZ_PUBKEY);
        M_DBGLOG("  [add]  [2]");
        M_DBGDUMP(pPayeeId, BTC_SZ_PUBKEY);
    }
}


/**
 * @param[in]       pPayerId            送金元node_id
 */
static bool load_db(nodes_result_t *p_result, const uint8_t *pPayerId)
{
    int ret;

    //channel
    param_channel_t param_channel;

    param_channel.p_result = p_result;
    param_channel.p_payer = pPayerId;
    ln_db_channel_search_readonly_nokey(comp_func_channel, &param_channel);

    LOGD("added local route: %" PRIu32 "\n", p_result->node_num);
    uint32_t prev_node_num = p_result->node_num;

    //channel_anno
    void *p_cur;

    ret = ln_db_anno_transaction();
    if (!ret) {
        //channel_announcementを1回も受信せずにDBが存在しない場合もあるため、trueで返す
        LOGE("fail through: no announce DB\n");
        return true;
    }

    ret = ln_db_anno_cur_open(&p_cur, LN_DB_CUR_CNLANNO);
    if (ret) {
        uint64_t short_channel_id;
        char type;
        utl_buf_t buf_cnl = UTL_BUF_INIT;

        while ((ret = ln_db_cnlanno_cur_get(p_cur, &short_channel_id, &type, NULL, &buf_cnl))) {
            ln_db_route_skip_t rskip = ln_db_route_skip_search(short_channel_id);
            if ((rskip != LN_DB_ROUTE_SKIP_NONE) && (rskip != LN_DB_ROUTE_SKIP_WORK)) {
                LOGE("  skip DB: %016" PRIx64 "\n", short_channel_id);
                utl_buf_free(&buf_cnl);
                continue;
            }

            dumpit_chan(p_result, type, &buf_cnl, rskip);
            utl_buf_free(&buf_cnl);
        }
    } else {
        LOGE("fail: open\n");
    }

    ln_db_anno_commit(false);

    LOGD("added announce route: %" PRIu32 "\n", p_result->node_num - prev_node_num);

    return true;
}


//pNode1=>pNode2の情報として追加する
static bool routing_add_channel(graph_t& Graph,
        uint64_t ShortChannelId,
        const nodeinfo_t *pNinfo,
        const uint8_t *pNode1, const uint8_t *pNode2)
{
    graph_t::vertex_descriptor node1 = routing_vertex_add(Graph, pNode1);
    graph_t::vertex_descriptor node2 = routing_vertex_add(Graph, pNode2);

    if (node1 != node2) {
        routing_edge_add(Graph,
            ShortChannelId,
            pNinfo,
            node1, node2
#ifdef USE_WEIGHT_MILLIONTHS
            , AmountMsat
#endif
        );
    }

    return node1 != node2;
}


//Graphの中にpNodeIdがあればそのvertex_descriptorを、なければ追加して返す。
static graph_t::vertex_descriptor routing_vertex_add(graph_t& Graph, const uint8_t *pNodeId)
{
    graph_t::vertex_descriptor vtx = static_cast<graph_t::vertex_descriptor>(-1);
    bool ret = false;

    std::pair<graph_t::vertex_iterator, graph_t::vertex_iterator> ver_its = vertices(Graph);
    for (graph_t::vertex_iterator st = ver_its.first, et = ver_its.second; st != et; st++) {
        if (memcmp(Graph[*st].node_id, pNodeId, BTC_SZ_PUBKEY) == 0) {
            //find
            LOGD("find vertex\n");
            ret = true;
            vtx = *st;
            break;
        }
    }
    if (!ret) {
        //new vertex
        vtx = add_vertex(Graph);
        //property
        memcpy(Graph[vtx].node_id, pNodeId, BTC_SZ_PUBKEY);
        LOGD("add vertex\n");
    }

    return vtx;
}


static void routing_edge_add(graph_t& Graph,
        uint64_t ShortChannelId, const nodeinfo_t *pInfo,
        graph_t::vertex_descriptor Node1, graph_t::vertex_descriptor Node2
#ifdef USE_WEIGHT_MILLIONTHS
        ,uint64_t AmountMsat
#endif
        )
{
    bool inserted = false;
    graph_t::edge_descriptor desc;

    boost::graph_traits<graph_t>::edge_iterator ei, ei_end;
    for (boost::tie(ei, ei_end) = edges(mGraph); ei != ei_end; ++ei) {
        boost::graph_traits<graph_t>::edge_descriptor e = *ei;
        boost::graph_traits<graph_t>::vertex_descriptor u = source(e, mGraph);
        boost::graph_traits<graph_t>::vertex_descriptor v = target(e, mGraph);
        if ((u == Node1) && (v == Node2)) {
            //find
            LOGD("find edge\n");
            return;
        }
    }

    //edge
    boost::tie(desc, inserted) = add_edge(Node1, Node2, Graph);
    //property
    Graph[desc].short_channel_id = ShortChannelId;
    Graph[desc].fee_base_msat = pInfo->fee_base_msat;
    Graph[desc].fee_prop_millionths = pInfo->fee_prop_millionths;
    Graph[desc].cltv_expiry_delta = pInfo->cltv_expiry_delta;
#ifdef USE_WEIGHT_MILLIONTHS
    Graph[desc].weight = edgefee(
                            AmountMsat,
                            Graph[desc].fee_base_msat,
                            Graph[desc].fee_prop_millionths);
#else
    Graph[desc].weight = Graph[desc].fee_base_msat;
#endif
    if (pInfo->route_skip == LN_DB_ROUTE_SKIP_WORK) {
        M_DBGLOG("HEAVY: %016" PRIx64 "\n", Graph[desc].short_channel_id);
        Graph[desc].weight *= 100;
    }
    LOGD("add edge\n");
}
