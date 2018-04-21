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
/** @file   routing.cpp
 *  @brief  routing計算
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <assert.h>

#include "ucoind.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"
#include "conf.h"

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

//#define M_DEBUG
#define M_SPOIL_STDERR

#define ARGS_GRAPH                          (2)     ///< [引数の数]graphviz用ファイル出力のみ
#define ARGS_PAYMENT                        (5)     ///< [引数の数]routing(min_final_cltv_expiryはデフォルト)
#define ARGS_PAY_AND_EXPIRY                 (6)     ///< [引数の数]routing(min_final_cltv_expiryは指定)
#define ARGS_ALL                            (7)     ///< [引数の数]routing(min_final_cltv_expiry, payment_hash指定)

#define M_CLTV_INIT                         ((uint16_t)0xffff)
#define M_SHADOW_ROUTE                      (0)     // shadow route extension
                                                    //  攪乱するためにオフセットとして加算するCLTV
                                                    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#recommendations-for-routing

#define M_ROUTE_SKIP_DBNAME                 "route_skip"

/**************************************************************************
 * typedefs
 **************************************************************************/

extern "C" {
    void ln_print_announce(const uint8_t *pData, uint16_t Len);
    bool ln_getids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len);
    bool ln_getparams_cnl_upd(ln_cnl_update_t *pUpd, const uint8_t *pData, uint16_t Len);
}

typedef struct {
    uint8_t     node_id[UCOIN_SZ_PUBKEY];
    uint16_t    cltv_expiry_delta;
    uint64_t    htlc_minimum_msat;
    uint32_t    fee_base_msat;
    uint32_t    fee_prop_millionths;
} nodeinfo_t;


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


/********************************************************************
 * static variables
 ********************************************************************/

static struct nodes_t {
    uint64_t    short_channel_id;
    nodeinfo_t  ninfo[2];
} *mpNodes = NULL;
static int mNodeNum = 0;
static FILE *fp_err;


/********************************************************************
 * external prototypes
 ********************************************************************/

extern "C" {
void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_anno);
}


/********************************************************************
 * functions
 ********************************************************************/

#ifdef M_DEBUG
static void dumpbin(const uint8_t *pData, int Len)
{
    for (int lp = 0; lp < Len; lp++) {
        fprintf(fp_err, "%02x", pData[lp]);
    }
    fprintf(fp_err, "\n");
}
#endif


static uint64_t edgefee(uint64_t amtmsat, uint32_t fee_base_msat, uint32_t fee_prop_millionths)
{
    return (uint64_t)fee_base_msat + (uint64_t)((amtmsat * fee_prop_millionths) / 1000000);
}


static void dumpit_chan(MDB_txn *txn, MDB_dbi dbi, ln_lmdb_db_t *p_skip)
{
    int retval;
    MDB_cursor  *cursor;

    retval = mdb_cursor_open(txn, dbi, &cursor);
    assert(retval == 0);
    int ret;

    do {
        uint64_t short_channel_id;
        char type;
        uint32_t timestamp;
        ucoin_buf_t buf = UCOIN_BUF_INIT;

        ret = ln_lmdb_annocnl_cur_load(cursor, &short_channel_id, &type, &timestamp, &buf);
        if (ret == 0) {
            ln_cnl_update_t upd;
            bool bret;

            if (p_skip->dbi != (MDB_dbi)-1) {
                bret = ln_db_annoskip_search(p_skip, short_channel_id);
                if (bret) {
#ifdef M_DEBUG
                    fprintf(fp_err, "skip : %016" PRIx64 "\n", short_channel_id);
#endif
                    continue;
                }
            }
            switch (type) {
            case LN_DB_CNLANNO_ANNO:
                mNodeNum++;
                mpNodes = (struct nodes_t *)realloc(mpNodes, sizeof(struct nodes_t) * mNodeNum);

                ln_getids_cnl_anno(
                                    &mpNodes[mNodeNum - 1].short_channel_id,
                                    mpNodes[mNodeNum - 1].ninfo[0].node_id,
                                    mpNodes[mNodeNum - 1].ninfo[1].node_id,
                                    buf.buf, buf.len);
                mpNodes[mNodeNum - 1].ninfo[0].cltv_expiry_delta = M_CLTV_INIT;     //未設定判定用
                mpNodes[mNodeNum - 1].ninfo[1].cltv_expiry_delta = M_CLTV_INIT;     //未設定反映用
#ifdef M_DEBUG
                fprintf(fp_err, "channel_announce : %016" PRIx64 "\n", mpNodes[mNodeNum - 1].short_channel_id);
                ln_print_announce(buf.buf, buf.len);
#endif
                break;
            case LN_DB_CNLANNO_UPD1:
            case LN_DB_CNLANNO_UPD2:
                if (mNodeNum > 0) {
                    int idx = type - LN_DB_CNLANNO_UPD1;
                    bret = ln_getparams_cnl_upd(&upd, buf.buf, buf.len);
                    if ( bret && ((upd.flags & LN_CNLUPD_FLAGS_DISABLE) == 0) &&
                        (mpNodes[mNodeNum - 1].short_channel_id == upd.short_channel_id) ) {
                        //disable状態ではない && channel_announcement.short_channel_idと一致
                        mpNodes[mNodeNum - 1].ninfo[idx].cltv_expiry_delta = upd.cltv_expiry_delta;
                        mpNodes[mNodeNum - 1].ninfo[idx].htlc_minimum_msat = upd.htlc_minimum_msat;
                        mpNodes[mNodeNum - 1].ninfo[idx].fee_base_msat = upd.fee_base_msat;
                        mpNodes[mNodeNum - 1].ninfo[idx].fee_prop_millionths = upd.fee_prop_millionths;
                    } else {
                        //disableの場合は、対象外にされるよう初期値にしておく
                        mpNodes[mNodeNum - 1].ninfo[idx].cltv_expiry_delta = M_CLTV_INIT;
                    }
#ifdef M_DEBUG
                    fprintf(fp_err, "channel update : %c\n", type);
                    ln_print_announce(buf.buf, buf.len);
#endif
                }
                break;
            default:
                break;
            }
        }
        ucoin_buf_free(&buf);
    } while (ret == 0);
    mdb_cursor_close(cursor);
}

static void dumpit_self(MDB_txn *txn, MDB_dbi dbi, ln_lmdb_db_t *p_skip, const uint8_t *p1, const uint8_t *p2)
{
    int retval;
    MDB_cursor  *cursor;

    if (p1 && p2) {
        retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        ln_self_t *p_self = static_cast<ln_self_t *>(malloc(sizeof(ln_self_t)));
        memset(p_self, 0, sizeof(ln_self_t));
        ret = ln_lmdb_self_load(p_self, txn, dbi);
        if (ret == 0) {
            //p1: my node_id(送金元とmy node_idが不一致の場合はNULL), p2: target node_id
            //
            // チャネル開設済みのノードに対しては、routing計算に含める。
            // fee計算にそのルートは関係がないため、パラメータは0にしておく。
            //

            //p1が非NULL == my node_id
            if ((p_self->short_channel_id != 0) && ((p_self->fund_flag & LN_FUNDFLAG_CLOSE) == 0)) {
                //チャネルは開設している && close処理をしていない

                if (p_skip->dbi != (MDB_dbi)-1) {
                    bool bret = ln_db_annoskip_search(p_skip, p_self->short_channel_id);
                    if (bret) {
#ifdef M_DEBUG
                        fprintf(fp_err, "skip : %016" PRIx64 "\n", short_channel_id);
#endif
                        goto LABEL_EXIT;
                    }
                }

                p2 = p_self->peer_node_id;

#ifdef M_DEBUG
                fprintf(fp_err, "p_self->short_channel_id: %" PRIx64 "\n", p_self->short_channel_id);
                fprintf(fp_err, "p1= ");
                dumpbin(p1, 33);
                fprintf(fp_err, "p2= ");
                dumpbin(p2, 33);
#endif
                mNodeNum++;
                mpNodes = (struct nodes_t *)realloc(mpNodes, sizeof(struct nodes_t) * mNodeNum);
                mpNodes[mNodeNum - 1].short_channel_id = p_self->short_channel_id;
                if (memcmp(p1, p2, UCOIN_SZ_PUBKEY) > 0) {
                    const uint8_t *p = p1;
                    p1 = p2;
                    p2 = p;
                }
                memcpy(mpNodes[mNodeNum - 1].ninfo[0].node_id, p1, UCOIN_SZ_PUBKEY);
                memcpy(mpNodes[mNodeNum - 1].ninfo[1].node_id, p2, UCOIN_SZ_PUBKEY);
                for (int lp = 0; lp < 2; lp++) {
                    mpNodes[mNodeNum - 1].ninfo[lp].cltv_expiry_delta = 0;
                    mpNodes[mNodeNum - 1].ninfo[lp].htlc_minimum_msat = 0;
                    mpNodes[mNodeNum - 1].ninfo[lp].fee_base_msat = 0;
                    mpNodes[mNodeNum - 1].ninfo[lp].fee_prop_millionths = 0;
                }
            }

        }

LABEL_EXIT:
        ln_term(p_self);
        free(p_self);
        mdb_close(mdb_txn_env(txn), dbi);
    }
}


/**
 * @param[in]       p1      送金元node_id(NULLあり)
 * @param[in]       p2      送金先node_id(NULLあり)
 * @param[in]       clear_skip_db       true:routing skip DBクリア
 * @param[in]       stop_after_dbclear  true:routing skip DBクリア後、すぐにreturnする
 */
static bool loaddb(const char *pDbPath, const uint8_t *p1, const uint8_t *p2, bool clear_skip_db, bool stop_after_dbclear)
{
    int ret;
    bool bret;
    MDB_env     *pDbSelf = NULL;
    MDB_env     *pDbNode = NULL;
    MDB_txn     *txn_self;
    MDB_txn     *txn_node;
    MDB_dbi     dbi;
    MDB_val     key;
    MDB_cursor  *cursor;
    char        selfpath[256];
    char        nodepath[256];

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
        fprintf(fp_err, "fail: cannot open[%s]\n", selfpath);
        return false;
    }

    ret = mdb_env_create(&pDbNode);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(pDbNode, 10);
    assert(ret == 0);
    ret = mdb_env_open(pDbNode, nodepath, 0, 0664);
    if (ret) {
        fprintf(fp_err, "fail: cannot open[%s]\n", nodepath);
        return false;
    }
    ln_lmdb_setenv(pDbSelf, pDbNode);

    if (clear_skip_db) {
        bret = ln_db_annoskip_drop(false);
        fprintf(fp_err, "%s: clear routing skip DB\n", (bret) ? "OK" : "fail");
        if (stop_after_dbclear) {
            return false;
        }
    }

    uint8_t my_nodeid[UCOIN_SZ_PUBKEY];
    ucoin_genesis_t gtype;
    bret = ln_db_ver_check(my_nodeid, &gtype);
    if (!bret) {
        fprintf(fp_err, "fail: DB version mismatch\n");
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
        fprintf(fp_err, "fail: unknown chainhash in DB\n");
        return false;
    }

#ifdef M_DEBUG
    fprintf(fp_err, "my node_id: ");
    dumpbin(my_nodeid, sizeof(my_nodeid));
#endif
    if (p1 && (memcmp(my_nodeid, p1, UCOIN_SZ_PUBKEY) != 0)) {
        //p1がmy node_idと不一致なら、NULL扱い
        p1 = NULL;
    }

    //node
    ret = mdb_txn_begin(pDbNode, NULL, MDB_RDONLY, &txn_node);
    if (ret != 0) {
        fprintf(fp_err, "fail: DB txn 2\n");
        return false;
    }
    MDB_dbi dbi_skip;
    ret = mdb_dbi_open(txn_node, M_ROUTE_SKIP_DBNAME, 0, &dbi_skip);
    if (ret != 0) {
        dbi_skip = (MDB_dbi)-1;
    }
    ln_lmdb_db_t db_skip;
    db_skip.txn = txn_node;
    db_skip.dbi = dbi_skip;

    //self
    ret = mdb_txn_begin(pDbSelf, NULL, MDB_RDONLY, &txn_self);
    if (ret != 0) {
        fprintf(fp_err, "fail: DB txn 1\n");
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
                    dumpit_self(txn_self, dbi2, &db_skip, p1, p2);
                }
            }
            mdb_close(mdb_txn_env(txn_self), dbi2);
        } else {
            fprintf(fp_err, "err1[%s]: %s\n",name, mdb_strerror(ret));
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
                    dumpit_chan(txn_node, dbi2, &db_skip);
                }
            }
            mdb_close(mdb_txn_env(txn_node), dbi2);
        } else {
            fprintf(fp_err, "err2[%s]: %s\n", name, mdb_strerror(ret));
        }
        free(name);
    }
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn_node);

    mdb_env_close(pDbNode);
    mdb_env_close(pDbSelf);
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


/********************************************************************
 * main entry
 ********************************************************************/

int main(int argc, char* argv[])
{
    bool ret;
    fp_err = stderr;

    uint8_t send_nodeid[UCOIN_SZ_PUBKEY];
    uint8_t recv_nodeid[UCOIN_SZ_PUBKEY];
    uint32_t cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    uint64_t amtmsat = 0;
    bool only_graph = false;
    bool output_json = false;
    bool clear_skip_db = false;
    char *payment_hash = NULL;
    char *dbdir = strdup(LNDB_DBDIR);

    int opt;
    int options = 0;
    while ((opt = getopt(argc, argv, "hd:s:r:a:e:p:jc")) != -1) {
        switch (opt) {
        case 'd':
            //db directory
            free(dbdir);
            dbdir = strdup(optarg);
            break;
        case 's':
            //sender(payer)
            ret = misc_str2bin(send_nodeid, sizeof(send_nodeid), optarg);
            if (!ret) {
                fprintf(fp_err, "invalid arg: payer node id\n");
                return -1;
            }
            options |= 1;
            break;
        case 'r':
            //receiver(payee)
            ret = misc_str2bin(recv_nodeid, sizeof(recv_nodeid), optarg);
            if (!ret) {
                fprintf(fp_err, "invalid arg: payee node id\n");
                return -1;
            }
            options |= 2;
            break;
        case 'a':
            //amount
            errno = 0;
            amtmsat = (uint64_t)strtoull(optarg, NULL, 10);
            if (errno) {
                DBG_PRINTF("errno=%s\n", strerror(errno));
                return -1;
            }
            break;
        case 'e':
            //min_final_expiry_delta
            cltv_expiry = (uint32_t)atoi(optarg);
            break;
        case 'p':
            //payment_hash
            payment_hash = strdup(optarg);
            break;
        case 'j':
            //JSON
            output_json = true;
            break;
        case 'c':
            //clear skip DB before routing
            clear_skip_db = true;
            break;
        case 'h':
            //help
            fprintf(fp_err, "usage:");
            fprintf(fp_err, "\t%s -s PAYER_NODEID -r PAYEE_NODEID [-d DB_DIR] [-a AMOUNT_MSAT] [-e MIN_FINAL_CLTV_EXPIRY] [-p PAYMENT_HASH] [-j] [-c]\n", argv[0]);
            fprintf(fp_err, "\t\t-s : sender(payer) node_id\n");
            fprintf(fp_err, "\t\t-r : receiver(payee) node_id\n");
            fprintf(fp_err, "\t\t-d : db directory\n");
            fprintf(fp_err, "\t\t-a : amount_msat\n");
            fprintf(fp_err, "\t\t-e : min_final_cltv_expiry\n");
            fprintf(fp_err, "\t\t-p : payment_hash\n");
            fprintf(fp_err, "\t\t-j : output JSON format(default: CSV format)\n");
            fprintf(fp_err, "\t\t-c : clear routing skip channel list\n");
            return -1;
        default:
            break;
        }
    }

    bool stop_after_dbclear = false;
    if (options != 3) {
        if (clear_skip_db) {
            stop_after_dbclear = true;
        } else {
            fprintf(fp_err, "fail: need -s and -r\n");
            return -1;
        }
    }
    if (output_json && (payment_hash == NULL)) {
        if (clear_skip_db) {
            stop_after_dbclear = true;
        } else {
            fprintf(fp_err, "fail: need PAYMENT_HASH if JSON output\n");
            return -1;
        }
    }

    cltv_expiry += M_SHADOW_ROUTE;

#ifdef M_SPOIL_STDERR
    //stderrを捨てる
    int fd_err = dup(2);
    fp_err = fdopen(fd_err, "w");
    close(2);
#endif  //M_SPOIL_STDERR

    if (!only_graph) {
        ret = loaddb(dbdir, send_nodeid, recv_nodeid, clear_skip_db, stop_after_dbclear);
        if (!ret) {
            return -1;
        }

#ifdef M_DEBUG
        fprintf(fp_err, "start nodeid : ");
        ucoin_util_dumpbin(fp_err, send_nodeid, UCOIN_SZ_PUBKEY, true);
        fprintf(fp_err, "end nodeid   : ");
        ucoin_util_dumpbin(fp_err, recv_nodeid, UCOIN_SZ_PUBKEY, true);
#endif
    } else {
        ret = loaddb(dbdir, NULL, NULL, false, false);
        if (!ret) {
            return -1;
        }
    }
    if (stop_after_dbclear) {
        return -1;
    }

    graph_t g;

    bool set_start;
    bool set_goal;
    graph_t::vertex_descriptor pnt_start = static_cast<graph_t::vertex_descriptor>(-1);
    graph_t::vertex_descriptor pnt_goal = static_cast<graph_t::vertex_descriptor>(-1);

    if (only_graph) {
        set_start = true;
        set_goal = true;
    } else {
        set_start = false;
        set_goal = false;
    }

    //Edge追加
    for (int lp = 0; lp < mNodeNum; lp++) {
#ifdef M_DEBUG
        fprintf(fp_err, "  short_channel_id=%016" PRIx64 "\n", mpNodes[lp].short_channel_id);
        fprintf(fp_err, "    [1]");
        ucoin_util_dumpbin(fp_err, mpNodes[lp].ninfo[0].node_id, UCOIN_SZ_PUBKEY, true);
        fprintf(fp_err, "    [2]");
        ucoin_util_dumpbin(fp_err, mpNodes[lp].ninfo[1].node_id, UCOIN_SZ_PUBKEY, true);
        fprintf(fp_err, "\n");
#endif

        graph_t::vertex_descriptor node1 = ver_add(g, mpNodes[lp].ninfo[0].node_id);
        graph_t::vertex_descriptor node2 = ver_add(g, mpNodes[lp].ninfo[1].node_id);

        if (!set_start) {
            if (memcmp(mpNodes[lp].ninfo[0].node_id, send_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                pnt_start = node1;
                set_start = true;
            } else if (memcmp(mpNodes[lp].ninfo[1].node_id, send_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                pnt_start = node2;
                set_start = true;
            }
        }
        if (!set_goal) {
            if (memcmp(mpNodes[lp].ninfo[0].node_id, recv_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                pnt_goal = node1;
                set_goal = true;
            } else if (memcmp(mpNodes[lp].ninfo[1].node_id, recv_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                pnt_goal = node2;
                set_goal = true;
            }
        }

        if (node1 != node2) {
            if (mpNodes[lp].ninfo[0].cltv_expiry_delta != M_CLTV_INIT) {
                //channel_update1
                bool inserted = false;
                graph_t::edge_descriptor e1;

                boost::tie(e1, inserted) = add_edge(node1, node2, g);
                g[e1].short_channel_id = mpNodes[lp].short_channel_id;
                g[e1].fee_base_msat = mpNodes[lp].ninfo[0].fee_base_msat;
                g[e1].fee_prop_millionths = mpNodes[lp].ninfo[0].fee_prop_millionths;
                g[e1].cltv_expiry_delta = mpNodes[lp].ninfo[0].cltv_expiry_delta;
                g[e1].node_id = mpNodes[lp].ninfo[0].node_id;
            }
            if (mpNodes[lp].ninfo[1].cltv_expiry_delta != M_CLTV_INIT) {
                //channel_update2
                bool inserted = false;
                graph_t::edge_descriptor e2;

                boost::tie(e2, inserted) = add_edge(node2, node1, g);
                g[e2].short_channel_id = mpNodes[lp].short_channel_id;
                g[e2].fee_base_msat = mpNodes[lp].ninfo[1].fee_base_msat;
                g[e2].fee_prop_millionths = mpNodes[lp].ninfo[1].fee_prop_millionths;
                g[e2].cltv_expiry_delta = mpNodes[lp].ninfo[1].cltv_expiry_delta;
                g[e2].node_id = mpNodes[lp].ninfo[1].node_id;
            }
        }
    }

    if (!only_graph) {
#ifdef M_DEBUG
        fprintf(fp_err, "pnt_start=%d, pnt_goal=%d\n", (int)pnt_start, (int)pnt_goal);
#endif
        if (!set_start) {
            fprintf(fp_err, "fail: no start node\n");
            return -1;
        }
        if (!set_goal) {
            fprintf(fp_err, "fail: no goal node\n");
            return -1;
        }

        std::vector<vertex_descriptor> p(num_vertices(g));      //parent
        std::vector<int> d(num_vertices(g));
        dijkstra_shortest_paths(g, pnt_start,
                            weight_map(boost::get(&Fee::fee_base_msat, g)).
                            predecessor_map(&p[0]).
                            distance_map(&d[0]));

        if (p[pnt_goal] == pnt_goal) {
            fprintf(fp_err, "fail: cannot find route\n");
            return -1;
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
                fprintf(fp_err, "not foooooooooound\n");
                abort();
            }

#ifdef M_DEBUG
            fprintf(fp_err, "node_id: ");
            for (int llp = 0; llp < UCOIN_SZ_PUBKEY; llp++) {
                fprintf(fp_err, "%02x", g[e].node_id[llp]);
            }
            fprintf(fp_err, "\n");

            fprintf(fp_err, "amount_msat: %" PRIu64 "\n", amtmsat);
            fprintf(fp_err, "cltv_expiry: %" PRIu32 "\n\n", cltv_expiry);
#endif

            route.push_front(p[v]);
            msat.push_front(amtmsat);
            cltv.push_front(cltv_expiry);

            amtmsat = amtmsat + edgefee(amtmsat, g[e].fee_base_msat, g[e].fee_prop_millionths);
            cltv_expiry += g[e].cltv_expiry_delta;
        }
        //std::cout << "distance: " << d[pnt_goal] << std::endl;

        //pay.conf形式の出力
        int hop = (int)route.size();
        const uint8_t *p_next;
        //nodeinfo_t ninfo;

        //memset(&ninfo, 0, sizeof(ninfo));

        if (!output_json) {
            //CSV形式
            printf("hop_num=%d\n", hop);
            for (int lp = 0; lp < hop - 1; lp++) {
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
                for (int lp3 = 0; lp3 < mNodeNum; lp3++) {
                    if ( (memcmp(p_node_id1, mpNodes[lp3].ninfo[0].node_id, UCOIN_SZ_PUBKEY) == 0) &&
                        (memcmp(p_node_id2, mpNodes[lp3].ninfo[1].node_id, UCOIN_SZ_PUBKEY) == 0) ) {
                        sci = mpNodes[lp3].short_channel_id;
                        //ninfo = mpNodes[lp3].ninfo[dir];
                        break;
                    }
                }
                if (sci == 0) {
                    fprintf(fp_err, "not match!\n");
                    abort();
                }

                printf("route%d=", lp);
                ucoin_util_dumpbin(stdout, p_now, UCOIN_SZ_PUBKEY, false);
                printf(",%016" PRIx64 ",%" PRIu64 ",%" PRIu32 "\n", sci, msat[lp], cltv[lp]);
            }

            //最後
            printf("route%d=", hop - 1);
            ucoin_util_dumpbin(stdout, p_next, UCOIN_SZ_PUBKEY, false);
            printf(",0,%" PRIu64 ",%" PRIu32 "\n", msat[hop - 1], cltv[hop - 1]);
        } else {
            //JSON形式
            printf("{\"method\":\"pay\",\"params\":[\"%s\",%d, [", payment_hash, hop);
            for (int lp = 0; lp < hop - 1; lp++) {
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
                for (int lp3 = 0; lp3 < mNodeNum; lp3++) {
                    if ( (memcmp(p_node_id1, mpNodes[lp3].ninfo[0].node_id, UCOIN_SZ_PUBKEY) == 0) &&
                        (memcmp(p_node_id2, mpNodes[lp3].ninfo[1].node_id, UCOIN_SZ_PUBKEY) == 0) ) {
                        sci = mpNodes[lp3].short_channel_id;
                        //ninfo = mpNodes[lp3].ninfo[dir];
                        break;
                    }
                }
                if (sci == 0) {
                    fprintf(fp_err, "not match!\n");
                    abort();
                }

                printf("[\"");
                ucoin_util_dumpbin(stdout, p_now, UCOIN_SZ_PUBKEY, false);
                printf("\",\"%016" PRIx64 "\",%" PRIu64 ",%" PRIu32 "],", sci, msat[lp], cltv[lp]);
            }

            //最後
            printf("[\"");
            ucoin_util_dumpbin(stdout, p_next, UCOIN_SZ_PUBKEY, false);
            printf("\",\"0\",%" PRIu64 ",%" PRIu32 "]]]}\n", msat[hop - 1], cltv[hop - 1]);
        }
    } else {
        // http://www.boost.org/doc/libs/1_55_0/libs/graph/example/dijkstra-example.cpp
        std::ofstream dot_file("routing.dot");

        dot_file << "digraph D {\n"
                //<< "  rankdir=LR\n"
                //<< "  ratio=\"fill\"\n"
                << "  graph[layout=circo];\n"
                //<< "  edge[style=\"bold\"];\n"
                << "  node[style=\"solid,filled\", fillcolor=\"#8080ff\"];\n"
                ;

        graph_traits < graph_t >::edge_iterator ei, ei_end;
        for (boost::tie(ei, ei_end) = edges(g); ei != ei_end; ++ei) {
            graph_traits < graph_t >::edge_descriptor e = *ei;
            graph_traits < graph_t >::vertex_descriptor u = source(e, g);
            graph_traits < graph_t >::vertex_descriptor v = target(e, g);
            if (u != v) {
                char node1[68];
                char node2[68];
                node1[0] = '\"';
                node1[1] = '\0';
                node2[0] = '\"';
                node2[1] = '\0';
                const uint8_t *p_node1 = g[u].p_node;
                const uint8_t *p_node2 = g[v].p_node;
                //node_id先頭の数桁だけ使う
                for (int lp = 0; lp < 3; lp++) {
                    char s[3];
                    sprintf(s, "%02x", p_node1[lp]);
                    strcat(node1, s);
                    sprintf(s, "%02x", p_node2[lp]);
                    strcat(node2, s);
                }
                strcat(node1, "\"");
                strcat(node2, "\"");
                int col = memcmp(p_node1, p_node2, UCOIN_SZ_PUBKEY);
                if (col > 0) {
                    dot_file << node1 << " -> " << node2
                            << "["
                            << "label=\""
                            << std::hex << g[e].short_channel_id << std::dec
                            //<< ","
                            //<< g[e].fee_base_msat
                            //<< ","
                            //<< g[e].fee_prop_millionths
                            //<< ","
                            //<< g[e].cltv_expiry_delta
                            << "\""
                            << ", color=\"black\""
                            << ", fontcolor=\"#804040\""
                            << ", arrowhead=\"none\""
                            << "]" << std::endl;
                }
            }
        }
        dot_file << "}";
    }

    free(dbdir);
    free(payment_hash);
    free(mpNodes);

    return 0;
}
