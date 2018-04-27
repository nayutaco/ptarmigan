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
 *  @author ueno@nayuta.co
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


/**************************************************************************
 * typedefs
 **************************************************************************/

extern "C" {
    void ln_print_announce(const uint8_t *pData, uint16_t Len);
    bool ln_getids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len);
    bool ln_getparams_cnl_upd(ln_cnl_update_t *pUpd, const uint8_t *pData, uint16_t Len);
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
        uint8_t     node_id[UCOIN_SZ_PUBKEY];
        uint16_t    cltv_expiry_delta;
        uint64_t    htlc_minimum_msat;
        uint32_t    fee_base_msat;
        uint32_t    fee_prop_millionths;
    } ninfo[2];
};

struct nodes_result_t {
    uint32_t    node_num;
    nodes_t     *p_nodes;
};

struct param_self_t {
    nodes_result_t  result;
    const uint8_t   *p1;
    const uint8_t   *p2;
    void            *skip_db;
};


/********************************************************************
 * external prototypes
 ********************************************************************/

extern "C" {
void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_anno);
}


/********************************************************************
 * functions
 ********************************************************************/

static uint64_t edgefee(uint64_t amtmsat, uint32_t fee_base_msat, uint32_t fee_prop_millionths)
{
    return (uint64_t)fee_base_msat + (uint64_t)((amtmsat * fee_prop_millionths) / 1000000);
}


static void dumpit_chan(nodes_result_t *p_result, char type, ucoin_buf_t *p_buf)
{
    nodes_t *p_nodes;

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
        p_nodes->ninfo[1].cltv_expiry_delta = M_CLTV_INIT;     //未設定反映用
        break;
    case LN_DB_CNLANNO_UPD1:
    case LN_DB_CNLANNO_UPD2:
        if (p_result->node_num > 0) {
            p_nodes = &p_result->p_nodes[p_result->node_num - 1];

            ln_cnl_update_t upd;
            int idx = type - LN_DB_CNLANNO_UPD1;
            bool bret = ln_getparams_cnl_upd(&upd, p_buf->buf, p_buf->len);
            if ( bret && ((upd.flags & LN_CNLUPD_FLAGS_DISABLE) == 0) &&
                (p_nodes->short_channel_id == upd.short_channel_id) ) {
                //disable状態ではない && channel_announcement.short_channel_idと一致
                p_nodes->ninfo[idx].cltv_expiry_delta = upd.cltv_expiry_delta;
                p_nodes->ninfo[idx].htlc_minimum_msat = upd.htlc_minimum_msat;
                p_nodes->ninfo[idx].fee_base_msat = upd.fee_base_msat;
                p_nodes->ninfo[idx].fee_prop_millionths = upd.fee_prop_millionths;
            } else {
                //disableの場合は、対象外にされるよう初期値にしておく
                p_nodes->ninfo[idx].cltv_expiry_delta = M_CLTV_INIT;
            }
        }
        break;
    default:
        break;
    }
}

static bool comp_func_self(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_db_param;

    param_self_t *p_prm_self = (param_self_t *)p_param;

    //p1: my node_id(送金元とmy node_idが不一致の場合はNULL), p2: target node_id
    //
    // チャネル開設済みのノードに対しては、routing計算に含める。
    // fee計算にそのルートは関係がないため、パラメータは0にしておく。
    //

    //p1が非NULL == my node_id
    if ((self->short_channel_id != 0) && ((self->fund_flag & LN_FUNDFLAG_CLOSE) == 0)) {
        //チャネルは開設している && close処理をしていない

        if (p_prm_self->skip_db != NULL) {
            bool bret = ln_db_annoskip_search(p_prm_self->skip_db, self->short_channel_id);
            if (bret) {
                DBG_PRINTF("skip : %016" PRIx64 "\n", self->short_channel_id);
                goto LABEL_EXIT;
            }
        }

        p_prm_self->p2 = self->peer_node_id;

        // DBG_PRINTF("p_self->short_channel_id: %" PRIx64 "\n", self->short_channel_id);
        // DBG_PRINTF("p1= ");
        // DUMPBIN(p_prm_self->p1, UCOIN_SZ_PUBKEY);
        // DBG_PRINTF("p2= ");
        // DUMPBIN(p_prm_self->p2, UCOIN_SZ_PUBKEY);

        p_prm_self->result.node_num++;
        p_prm_self->result.p_nodes = (nodes_t *)realloc(p_prm_self->result.p_nodes, sizeof(nodes_t) * p_prm_self->result.node_num);
        p_prm_self->result.p_nodes[p_prm_self->result.node_num - 1].short_channel_id = self->short_channel_id;
        if (memcmp(p_prm_self->p1, p_prm_self->p2, UCOIN_SZ_PUBKEY) > 0) {
            const uint8_t *p = p_prm_self->p1;
            p_prm_self->p1 = p_prm_self->p2;
            p_prm_self->p2 = p;
        }
        nodes_t *p_nodes_result = &p_prm_self->result.p_nodes[p_prm_self->result.node_num - 1];
        memcpy(p_nodes_result->ninfo[0].node_id, p_prm_self->p1, UCOIN_SZ_PUBKEY);
        memcpy(p_nodes_result->ninfo[1].node_id, p_prm_self->p2, UCOIN_SZ_PUBKEY);
        for (int lp = 0; lp < 2; lp++) {
            p_nodes_result->ninfo[lp].cltv_expiry_delta = 0;
            p_nodes_result->ninfo[lp].htlc_minimum_msat = 0;
            p_nodes_result->ninfo[lp].fee_base_msat = 0;
            p_nodes_result->ninfo[lp].fee_prop_millionths = 0;
        }
    }

LABEL_EXIT:
    return false;
}


/**
 * @param[in]       p1      送金元node_id(NULLあり)
 * @param[in]       p2      送金先node_id(NULLあり)
 * @param[in]       clear_skip_db       true:routing skip DBクリア
 */
static bool loaddb(nodes_result_t *p_result, const char *pDbPath, const uint8_t *p1, const uint8_t *p2, bool clear_skip_db)
{
    int ret;
    bool bret;
    MDB_env     *pDbSelf = NULL;
    MDB_env     *pDbNode = NULL;
    char        selfpath[256];
    char        nodepath[256];

    if (pDbPath != NULL) {
        strcpy(selfpath, pDbPath);
        size_t len = strlen(selfpath);
        if (selfpath[len - 1] == '/') {
            selfpath[len - 1] = '\0';
        }
        strcpy(nodepath, selfpath);
        strcat(selfpath, LNDB_SELFENV_DIR);
        strcat(nodepath, LNDB_NODEENV_DIR);

        ret = mdb_env_create(&pDbSelf);
        assert(ret == 0);
        ret = mdb_env_set_maxdbs(pDbSelf, 10);
        assert(ret == 0);
        ret = mdb_env_open(pDbSelf, selfpath, MDB_RDONLY, 0664);
        if (ret) {
            DBG_PRINTF("fail: cannot open[%s]\n", selfpath);
            return false;
        }

        ret = mdb_env_create(&pDbNode);
        assert(ret == 0);
        ret = mdb_env_set_maxdbs(pDbNode, 10);
        assert(ret == 0);
        ret = mdb_env_open(pDbNode, nodepath, 0, 0664);
        if (ret) {
            DBG_PRINTF("fail: cannot open[%s]\n", nodepath);
            return false;
        }
        ln_lmdb_setenv(pDbSelf, pDbNode);
    }

    if (clear_skip_db) {
        bret = ln_db_annoskip_drop(false);
        DBG_PRINTF("%s: clear routing skip DB\n", (bret) ? "OK" : "fail");
        return true;
    }

    uint8_t my_nodeid[UCOIN_SZ_PUBKEY];
    if (pDbPath != NULL) {
        ucoin_genesis_t gtype;
        bret = ln_db_ver_check(my_nodeid, &gtype);
        if (!bret) {
            DBG_PRINTF("fail: DB version mismatch\n");
            return false;
        }

        ln_set_genesishash(ucoin_util_get_genesis_block(gtype));
        switch (gtype) {
        case UCOIN_GENESIS_BTCMAIN:
            ucoin_init(UCOIN_MAINNET, true);
            break;
        case UCOIN_GENESIS_BTCTEST:
        case UCOIN_GENESIS_BTCREGTEST:
            ucoin_init(UCOIN_TESTNET, true);
            break;
        default:
            DBG_PRINTF("fail: unknown chainhash in DB\n");
            return false;
        }
    } else {
        memcpy(my_nodeid, ln_node_getid(), UCOIN_SZ_PUBKEY);
    }

    // DBG_PRINTF("my node_id: ");
    // DUMPBIN(my_nodeid, sizeof(my_nodeid));

    if (p1 && (memcmp(my_nodeid, p1, UCOIN_SZ_PUBKEY) != 0)) {
        //p1がmy node_idと不一致なら、NULL扱い
        p1 = NULL;
    }

#if 1
    void *p_db_skip;
    bret = ln_db_node_cur_transaction(&p_db_skip, LN_DB_TXN_SKIP);
    if (!bret) {
        p_db_skip = NULL;
    }

    //self
    if (p1 && p2) {
        param_self_t prm_self;
        memset(&prm_self.result, 0, sizeof(nodes_result_t));
        prm_self.p1 = p1;
        prm_self.p2 = p2;
        prm_self.skip_db = p_db_skip;
        ln_db_self_search(comp_func_self, &prm_self);
    }

    //channel_anno
    void *p_db_anno;
    void *p_cur;

    ret = ln_db_node_cur_transaction(&p_db_anno, LN_DB_TXN_CNL);
    if (!ret) {
        DBG_PRINTF("fail\n");
        return false;
    }
    ret = ln_db_annocnl_cur_open(&p_cur, p_db_anno);
    if (ret) {
        uint64_t short_channel_id;
        char type;
        ucoin_buf_t buf_cnl = UCOIN_BUF_INIT;

        while ((ret = ln_db_annocnl_cur_get(p_cur, &short_channel_id, &type, NULL, &buf_cnl))) {
            if (p_db_skip != NULL) {
                bret = ln_db_annoskip_search(p_db_skip, short_channel_id);
                if (bret) {
                    ucoin_buf_free(&buf_cnl);
                    continue;
                }
            }
            dumpit_chan(p_result, type, &buf_cnl);
            ucoin_buf_free(&buf_cnl);
        }
    }

    ln_db_node_cur_commit(p_db_anno);
    if (p_db_skip != NULL) {
        ln_db_node_cur_commit(p_db_skip);
    }

#else
    //node
    ret = mdb_txn_begin(pDbNode, NULL, MDB_RDONLY, &txn_node);
    if (ret != 0) {
        DBG_PRINTF("fail: DB txn 2\n");
        return false;
    }
    MDB_dbi dbi_skip;
    ret = mdb_dbi_open(txn_node, LNDB_DBI_ANNO_SKIP, 0, &dbi_skip);
    if (ret != 0) {
        dbi_skip = (MDB_dbi)-1;
    }
    ln_lmdb_db_t db_skip;
    db_skip.txn = txn_node;
    db_skip.dbi = dbi_skip;

    //self
    ret = mdb_txn_begin(pDbSelf, NULL, MDB_RDONLY, &txn_self);
    if (ret != 0) {
        DBG_PRINTF("fail: DB txn 1\n");
        mdb_txn_abort(txn_node);
        return false;
    }
    ret = mdb_dbi_open(txn_self, NULL, 0, &dbi);
    assert(ret == 0);
    ret = mdb_cursor_open(txn_self, dbi, &cursor);
    assert(ret == 0);

    int list = 0;
    while ((ret = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi dbi2;
        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        char *name = (char *)malloc(key.mv_size + 1);
        memcpy(name, key.mv_data, key.mv_size);
        name[key.mv_size] = '\0';
        ret = mdb_dbi_open(txn_self, name, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else {
                ln_lmdb_dbtype_t dbtype = ln_lmdb_get_dbtype(name);
                if (dbtype == LN_LMDB_DBTYPE_SELF) {
                    dumpit_self(txn_self, dbi2, &db_skip, p_result, p1, p2);
                }
            }
            mdb_close(mdb_txn_env(txn_self), dbi2);
        } else {
            DBG_PRINTF("err1[%s]: %s\n",name, mdb_strerror(ret));
        }
        free(name);
    }
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn_self);

    //channel_anno
    ret = mdb_dbi_open(txn_node, NULL, 0, &dbi);
    assert(ret == 0);
    ret = mdb_cursor_open(txn_node, dbi, &cursor);
    assert(ret == 0);

    list = 0;
    while ((ret = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi dbi2;
        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        char *name = (char *)malloc(key.mv_size + 1);
        memcpy(name, key.mv_data, key.mv_size);
        name[key.mv_size] = '\0';
        ret = mdb_dbi_open(txn_node, name, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else {
                ln_lmdb_dbtype_t dbtype = ln_lmdb_get_dbtype(name);
                if (dbtype == LN_LMDB_DBTYPE_CHANNEL_ANNO) {
                    dumpit_chan(txn_node, dbi2, &db_skip, p_result);
                }
            }
            mdb_close(mdb_txn_env(txn_node), dbi2);
        } else {
            DBG_PRINTF("err2[%s]: %s\n", name, mdb_strerror(ret));
        }
        free(name);
    }
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn_node);

    mdb_env_close(pDbNode);
    mdb_env_close(pDbSelf);
#endif

    return true;
}


static int direction(const uint8_t *pNode1, const uint8_t *pNode2)
{
    int lp2;
    for (lp2 = 0; lp2 < UCOIN_SZ_PUBKEY; lp2++) {
        if (pNode1[lp2] != pNode2[lp2]) {
            break;
        }
    }
    return (pNode1[lp2] < pNode2[lp2]) ? 0 : 1;
}


static graph_t::vertex_descriptor ver_add(graph_t& g, const uint8_t *pNodeId)
{
    graph_t::vertex_descriptor v = static_cast<graph_t::vertex_descriptor>(-1);
    bool ret = false;

    std::pair<graph_t::vertex_iterator, graph_t::vertex_iterator> ver_its = vertices(g);
    for (graph_t::vertex_iterator st = ver_its.first, et = ver_its.second; st != et; st++) {
        if (memcmp(g[*st].p_node, pNodeId, UCOIN_SZ_PUBKEY) == 0) {
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


int ln_routing_calculate(
        ln_routing_result_t *p_result,
        const uint8_t *send_nodeid,
        const uint8_t *recv_nodeid,
        uint32_t cltv_expiry,
        uint64_t amtmsat,
        const char *dbdir,
        bool clear_skip_db)
{
    p_result->hop_num = 0;

    nodes_result_t rt_res;
    rt_res.node_num = 0;
    rt_res.p_nodes = NULL;

    bool ret = loaddb(&rt_res, dbdir, send_nodeid, recv_nodeid, clear_skip_db);
    if (!ret) {
        DBG_PRINTF("fail: loaddb\n");
        return -1;
    }
    if (ret && clear_skip_db) {
        DBG_PRINTF("clear skip db\n");
        return 0;
    }

    DBG_PRINTF("start nodeid : ");
    ucoin_util_dumpbin(stderr, send_nodeid, UCOIN_SZ_PUBKEY, true);
    DBG_PRINTF("end nodeid   : ");
    ucoin_util_dumpbin(stderr, recv_nodeid, UCOIN_SZ_PUBKEY, true);

    graph_t g;

    bool set_start = false;
    bool set_goal = false;
    graph_t::vertex_descriptor pnt_start = static_cast<graph_t::vertex_descriptor>(-1);
    graph_t::vertex_descriptor pnt_goal = static_cast<graph_t::vertex_descriptor>(-1);

    //Edge追加
    for (uint32_t lp = 0; lp < rt_res.node_num; lp++) {
        DBG_PRINTF("  short_channel_id=%016" PRIx64 "\n", rt_res.p_nodes[lp].short_channel_id);
        DBG_PRINTF("    [1]");
        ucoin_util_dumpbin(stderr, rt_res.p_nodes[lp].ninfo[0].node_id, UCOIN_SZ_PUBKEY, true);
        DBG_PRINTF("    [2]");
        ucoin_util_dumpbin(stderr, rt_res.p_nodes[lp].ninfo[1].node_id, UCOIN_SZ_PUBKEY, true);
        DBG_PRINTF("\n");

        graph_t::vertex_descriptor node1 = ver_add(g, rt_res.p_nodes[lp].ninfo[0].node_id);
        graph_t::vertex_descriptor node2 = ver_add(g, rt_res.p_nodes[lp].ninfo[1].node_id);

        if (!set_start) {
            if (memcmp(rt_res.p_nodes[lp].ninfo[0].node_id, send_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                pnt_start = node1;
                set_start = true;
            } else if (memcmp(rt_res.p_nodes[lp].ninfo[1].node_id, send_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                pnt_start = node2;
                set_start = true;
            }
        }
        if (!set_goal) {
            if (memcmp(rt_res.p_nodes[lp].ninfo[0].node_id, recv_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                pnt_goal = node1;
                set_goal = true;
            } else if (memcmp(rt_res.p_nodes[lp].ninfo[1].node_id, recv_nodeid, UCOIN_SZ_PUBKEY) == 0) {
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

    //DBG_PRINTF("pnt_start=%d, pnt_goal=%d\n", (int)pnt_start, (int)pnt_goal);
    if (!set_start) {
        DBG_PRINTF("fail: no start node\n");
        return -2;
    }
    if (!set_goal) {
        DBG_PRINTF("fail: no goal node\n");
        return -3;
    }

    std::vector<vertex_descriptor> p(num_vertices(g));      //parent
    std::vector<int> d(num_vertices(g));
    dijkstra_shortest_paths(g, pnt_start,
                        weight_map(boost::get(&Fee::fee_base_msat, g)).
                        predecessor_map(&p[0]).
                        distance_map(&d[0]));

    if (p[pnt_goal] == pnt_goal) {
        DBG_PRINTF("fail: cannot find route\n");
        free(rt_res.p_nodes);
        return -4;
    }

    //逆順に入っているので、並べ直す
    //ついでに、min_final_cltv_expiryを足す
    std::deque<vertex_descriptor> route;        //std::vectorにはpush_front()がない
    std::deque<uint64_t> msat;
    std::deque<uint32_t> cltv;

    route.push_front(pnt_goal);
    msat.push_front(amtmsat);
    cltv.push_front(cltv_expiry);

    for (vertex_descriptor v = pnt_goal; v != pnt_start; v = p[v]) {
        bool found;
        graph_t::edge_descriptor e;
        boost::tie(e, found) = edge(p[v], v, g);
        if (!found) {
            DBG_PRINTF("not foooooooooound\n");
            abort();
        }

        DBG_PRINTF("node_id: ");
        for (int llp = 0; llp < UCOIN_SZ_PUBKEY; llp++) {
            DBG_PRINTF("%02x", g[e].node_id[llp]);
        }
        DBG_PRINTF("\n");

        DBG_PRINTF("amount_msat: %" PRIu64 "\n", amtmsat);
        DBG_PRINTF("cltv_expiry: %" PRIu32 "\n\n", cltv_expiry);

        route.push_front(p[v]);
        msat.push_front(amtmsat);
        cltv.push_front(cltv_expiry);

        amtmsat = amtmsat + edgefee(amtmsat, g[e].fee_base_msat, g[e].fee_prop_millionths);
        cltv_expiry += g[e].cltv_expiry_delta;
    }
    //std::cout << "distance: " << d[pnt_goal] << std::endl;

    if (route.size() > LN_HOP_MAX + 1) {
        //先頭に自ノードが入るため+1
        DBG_PRINTF("fail: too many hops\n");
        free(rt_res.p_nodes);
        return -5;
    }

    //戻り値の作成
    p_result->hop_num = (uint8_t)route.size();
    const uint8_t *p_next;

    for (int lp = 0; lp < p_result->hop_num - 1; lp++) {
        const uint8_t *p_now  = g[route[lp]].p_node;
        p_next = g[route[lp + 1]].p_node;

        const uint8_t *p_node_id1;
        const uint8_t *p_node_id2;
        int dir = direction(p_now, p_next);
        if (dir == 0) {
            p_node_id1 = p_now;
            p_node_id2 = p_next;
            dir = 0;
        } else {
            p_node_id1 = p_next;
            p_node_id2 = p_now;
            dir = 1;
        }
        uint64_t sci = 0;
        for (uint32_t lp3 = 0; lp3 < rt_res.node_num; lp3++) {
            if ( (memcmp(p_node_id1, rt_res.p_nodes[lp3].ninfo[0].node_id, UCOIN_SZ_PUBKEY) == 0) &&
                (memcmp(p_node_id2, rt_res.p_nodes[lp3].ninfo[1].node_id, UCOIN_SZ_PUBKEY) == 0) ) {
                sci = rt_res.p_nodes[lp3].short_channel_id;
                break;
            }
        }
        if (sci == 0) {
            DBG_PRINTF("not match!\n");
            abort();
        }

        p_result->hop_datain[lp].short_channel_id = sci;
        p_result->hop_datain[lp].amt_to_forward = msat[lp];
        p_result->hop_datain[lp].outgoing_cltv_value = cltv[lp];
        memcpy(p_result->hop_datain[lp].pubkey, p_now, UCOIN_SZ_PUBKEY);
    }

    //最後
    p_result->hop_datain[p_result->hop_num - 1].short_channel_id = 0;
    p_result->hop_datain[p_result->hop_num - 1].amt_to_forward = msat[p_result->hop_num - 1];
    p_result->hop_datain[p_result->hop_num - 1].outgoing_cltv_value = cltv[p_result->hop_num - 1];
    memcpy(p_result->hop_datain[p_result->hop_num - 1].pubkey, p_next, UCOIN_SZ_PUBKEY);

    free(rt_res.p_nodes);

    return 0;
}
