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
#include <assert.h>

//#define M_DEBUG
#define M_SPOIL_STDERR

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

#define ARGS_GRAPH                          (3)     ///< [引数の数]graphviz用ファイル出力のみ
#define ARGS_PAYMENT                        (6)     ///< [引数の数]routing(min_final_cltv_expiryはデフォルト)
#define ARGS_PAY_AND_EXPIRY                 (7)     ///< [引数の数]routing(min_final_cltv_expiryは指定)
#define ARGS_ALL                            (8)     ///< [引数の数]routing(min_final_cltv_expiry, payment_hash指定)

#define MSGTYPE_CHANNEL_ANNOUNCEMENT        ((uint16_t)0x0100)
#define MSGTYPE_NODE_ANNOUNCEMENT           ((uint16_t)0x0101)
#define MSGTYPE_CHANNEL_UPDATE              ((uint16_t)0x0102)
#define MSGTYPE_ANNOUNCEMENT_SIGNATURES     ((uint16_t)0x0103)

#define M_CLTV_INIT                         ((uint16_t)0xffff)


/**************************************************************************
 * prototypes
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

static MDB_env      *mpDbEnv = NULL;
static struct nodes_t {
    uint64_t    short_channel_id;
    nodeinfo_t  ninfo[2];
} *mpNodes = NULL;
static int mNodeNum = 0;
static uint8_t mMyNodeId[UCOIN_SZ_PUBKEY];
static uint8_t mTgtNodeId[UCOIN_SZ_PUBKEY];
static uint16_t mMinFinalCltvExpiry = 0;
static FILE *fp_err;

// https://github.com/lightningnetwork/lightning-rfc/issues/237
// https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
static const uint8_t M_BTC_GENESIS_MAIN[] = {
    // bitcoin mainnet
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_TEST[] = {
    // bitcoin testnet
    0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
    0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
    0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
    0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_REGTEST[] = {
    // bitcoin regtest
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
    0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
    0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
};


/********************************************************************
 * misc
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


/* Dump in BDB-compatible format */
static int dumpit(MDB_txn *txn, const MDB_val *p_key, const uint8_t *p1, const uint8_t *p2)
{
    MDB_dbi     dbi;
    MDB_cursor  *cursor;
    const char *name = (const char *)p_key->mv_data;

    ln_lmdb_dbtype_t dbtype = ln_lmdb_get_dbtype(name);

    if (dbtype == LN_LMDB_DBTYPE_CHANNEL_ANNO) {
        int retval = mdb_dbi_open(txn, name, 0, &dbi);
        assert(retval == 0);
        retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        do {
            uint64_t short_channel_id;
            char type;
            int idx;
            ucoin_buf_t buf;

            ucoin_buf_init(&buf);
            ret = ln_lmdb_load_anno_channel_cursor(cursor, &short_channel_id, &type, &buf);
            if (ret == 0) {
                ln_cnl_update_t upd;
                bool bret;

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
                    idx = type - LN_DB_CNLANNO_UPD1;
                    bret = ln_getparams_cnl_upd(&upd, buf.buf, buf.len);
                    if (bret && ((upd.flags & LN_CNLUPD_FLAGS_DISABLE) == 0)) {
                        //disable状態ではない
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
                    break;
                default:
                    break;
                }
            }
            ucoin_buf_free(&buf);
        } while (ret == 0);
        mdb_cursor_close(cursor);
        mdb_close(mpDbEnv, dbi);
    } else if ((dbtype == LN_LMDB_DBTYPE_SELF) && p1 && p2) {
        int retval = mdb_dbi_open(txn, name, 0, &dbi);
        assert(retval == 0);
        retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        ln_self_t   self;
        memset(&self, 0, sizeof(self));
        ret = ln_lmdb_load_channel(&self, txn, &dbi);
        if (ret == 0) {
            //p1: my node_id(送金元とmy node_idが不一致の場合はNULL), p2: target node_id
#if 0
            //
            // まだannounceする前でも、送金元が自分でチャネル開設が完了しているのならルートに含めるべき
            // しかし、相手のchannel情報を持たないため、反対側のchannel_updateデータを使用する(c-lightningの動作)
            //

            //p1が非NULL == my node_id
            if (self.short_channel_id != 0) {
                //チャネルは開設している
                p2 = self.peer_node.node_id;

#ifdef M_DEBUG
                fprintf(fp_err, "self.short_channel_id: %" PRIx64 "\n", self.short_channel_id);
                fprintf(fp_err, "p1= ");
                dumpbin(p1, 33);
                fprintf(fp_err, "p2= ");
                dumpbin(p2, 33);
#endif
                mNodeNum++;
                mpNodes = (struct nodes_t *)realloc(mpNodes, sizeof(struct nodes_t) * mNodeNum);
                mpNodes[mNodeNum - 1].short_channel_id = self.short_channel_id;
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
#else
            //
            // まだannounceする前で、送金元が自分、送金先がpeer相手でチャネル開設が完了している場合のみルートを許可
            //

            if ((self.short_channel_id != 0) && (memcmp(self.peer_node.node_id, p2, UCOIN_SZ_PUBKEY) == 0)) {
                //チャネル接続しているが、announcement_signaturesはしていない相手
#ifdef M_DEBUG
                fprintf(fp_err, "self.short_channel_id: %" PRIx64 "\n", self.short_channel_id);
                fprintf(fp_err, "p1= ");
                dumpbin(p1, 33);
                fprintf(fp_err, "p2= ");
                dumpbin(p2, 33);
#endif
                mNodeNum++;
                mpNodes = (struct nodes_t *)realloc(mpNodes, sizeof(struct nodes_t) * mNodeNum);
                mpNodes[mNodeNum - 1].short_channel_id = self.short_channel_id;
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
#endif
        }
        ln_term(&self);
        mdb_close(mpDbEnv, dbi);
    } else {
        //none
    }

    return 0;
}


/**
 * @param[in]       p1      送金元node_id(NULLあり)
 * @param[in]       p2      送金先node_id(NULLあり)
 *
 */
static void loaddb(const char *pDbPath, const uint8_t *p1, const uint8_t *p2)
{
    int ret;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key;
    MDB_cursor  *cursor;

    ret = mdb_env_create(&mpDbEnv);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbEnv, 2);
    assert(ret == 0);
    ret = mdb_env_open(mpDbEnv, pDbPath, MDB_RDONLY, 0664);
    if (ret) {
        fprintf(fp_err, "fail: cannot open[%s]\n", pDbPath);
        assert(ret == 0);
    }

    ret = mdb_txn_begin(mpDbEnv, NULL, MDB_RDONLY, &txn);
    assert(ret == 0);
    uint8_t my_nodeid[UCOIN_SZ_PUBKEY];
    ret = ln_lmdb_check_version(txn, my_nodeid);
    assert(ret == 0);
#ifdef M_DEBUG
    fprintf(fp_err, "my node_id: ");
    dumpbin(my_nodeid, sizeof(my_nodeid));
#endif
    if (p1 && (memcmp(my_nodeid, p1, UCOIN_SZ_PUBKEY) != 0)) {
        //p1がmy node_idと不一致なら、NULL扱い
        p1 = NULL;
    }
    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    assert(ret == 0);

    ret = mdb_cursor_open(txn, dbi, &cursor);
    assert(ret == 0);

    int list = 0;
    while ((ret = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi dbi2;
        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        ret = mdb_dbi_open(txn, (const char *)key.mv_data, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else {
                ret = dumpit(txn, &key, p1, p2);
                if (ret) {
                    break;
                }
            }
            mdb_close(mpDbEnv, dbi2);
        } else {
            fprintf(fp_err, "???\n");
        }
    }
    mdb_cursor_close(cursor);
    mdb_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);
    mdb_env_close(mpDbEnv);
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


//true:含む
static graph_t::vertex_descriptor ver_add(graph_t& g, const uint8_t *pNodeId)
{
    graph_t::vertex_descriptor v;
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
 *
 ********************************************************************/

int main(int argc, char* argv[])
{
    fp_err = stderr;
    uint64_t amtmsat;

    const char *nettype;
    const char *dbdir;
    const char *my_node;
    const char *tgt_node;
    const char *amount;
    const char *payment_hash = NULL;

    if (argc == ARGS_GRAPH) {
        nettype = argv[1];
        dbdir = argv[2];
        my_node = NULL;
        tgt_node = NULL;
        amount = NULL;
    } else if (argc >= ARGS_PAYMENT) {
        nettype = argv[1];
        dbdir = argv[2];
        my_node = argv[3];
        tgt_node = argv[4];
        amount = argv[5];
        if (argc >= ARGS_PAY_AND_EXPIRY) {
            mMinFinalCltvExpiry = (uint16_t)atoi(argv[6]);
        } else {
            mMinFinalCltvExpiry = LN_MIN_FINAL_CLTV_EXPIRY;
        }
        //fprintf(fp_err, "min_final_cltv_expiry = %" PRIu16 "\n", mMinFinalCltvExpiry);
        if (argc == ARGS_ALL) {
            payment_hash = argv[7];
        }
    } else {
        fprintf(fp_err, "usage:");
        //                    1                 2
        fprintf(fp_err, "\t%s [mainnet/testnet] [db dir]\n", argv[0]);
        //                    1                 2        3               4               5             6
        fprintf(fp_err, "\t%s [mainnet/testnet] [db dir] [payer node_id] [payee node_id] [amount_msat] <[min_final_cltv_expiry]>\n", argv[0]);
        return -1;
    }


    if (strcmp(nettype, "mainnet") == 0) {
        ln_set_genesishash(M_BTC_GENESIS_MAIN);
    } else if (strcmp(nettype, "testnet") == 0) {
        ln_set_genesishash(M_BTC_GENESIS_TEST);
    } else if (strcmp(nettype, "regtest") == 0) {
        ln_set_genesishash(M_BTC_GENESIS_REGTEST);
    } else {
        fprintf(fp_err, "mainnet or testnet only[%s]\n", nettype);
        return -1;
    }

    if (argc >= ARGS_PAYMENT) {
        bool ret;

        ret = misc_str2bin(mMyNodeId, sizeof(mMyNodeId), my_node);
        if (!ret) {
            fprintf(fp_err, "invalid arg: payer node id\n");
            return -1;
        }

        ret = misc_str2bin(mTgtNodeId, sizeof(mTgtNodeId), tgt_node);
        if (!ret) {
            fprintf(fp_err, "invalid arg: payee node id\n");
            return -1;
        }
    }

#ifdef M_SPOIL_STDERR
    //stderrを捨てる
    int fd_err = dup(2);
    fp_err = fdopen(fd_err, "w");
    close(2);
#endif  //M_SPOIL_STDERR

    if (argc >= ARGS_PAYMENT) {
        loaddb(dbdir, mMyNodeId, mTgtNodeId);

        errno = 0;
        amtmsat = (uint64_t)strtoull(amount, NULL, 10);
        if (errno) {
            DBG_PRINTF("errno=%s\n", strerror(errno));
            return -1;
        }

#ifdef M_DEBUG
        fprintf(fp_err, "start nodeid : ");
        ucoin_util_dumpbin(fp_err, mMyNodeId, UCOIN_SZ_PUBKEY, true);
        fprintf(fp_err, "end nodeid   : ");
        ucoin_util_dumpbin(fp_err, mTgtNodeId, UCOIN_SZ_PUBKEY, true);
#endif
    } else {
        loaddb(dbdir, NULL, NULL);
    }

    graph_t g;

    bool set_start;
    bool set_goal;
    graph_t::vertex_descriptor pnt_start = static_cast<graph_t::vertex_descriptor>(-1);
    graph_t::vertex_descriptor pnt_goal = static_cast<graph_t::vertex_descriptor>(-1);

    if (argc == ARGS_GRAPH) {
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
            if (memcmp(mpNodes[lp].ninfo[0].node_id, mMyNodeId, UCOIN_SZ_PUBKEY) == 0) {
                pnt_start = node1;
                set_start = true;
            } else if (memcmp(mpNodes[lp].ninfo[1].node_id, mMyNodeId, UCOIN_SZ_PUBKEY) == 0) {
                pnt_start = node2;
                set_start = true;
            }
        }
        if (!set_goal) {
            if (memcmp(mpNodes[lp].ninfo[0].node_id, mTgtNodeId, UCOIN_SZ_PUBKEY) == 0) {
                pnt_goal = node1;
                set_goal = true;
            } else if (memcmp(mpNodes[lp].ninfo[1].node_id, mTgtNodeId, UCOIN_SZ_PUBKEY) == 0) {
                pnt_goal = node2;
                set_goal = true;
            }
        }

        if ( (node1 != node2) &&
             (mpNodes[lp].ninfo[0].cltv_expiry_delta != M_CLTV_INIT) &&
             (mpNodes[lp].ninfo[1].cltv_expiry_delta != M_CLTV_INIT) ) {
            //channel_updateが両方必要
            bool inserted = false;
            graph_t::edge_descriptor e1, e2;

            boost::tie(e1, inserted) = add_edge(node1, node2, g);
            g[e1].short_channel_id = mpNodes[lp].short_channel_id;
            g[e1].fee_base_msat = mpNodes[lp].ninfo[1].fee_base_msat;
            g[e1].fee_prop_millionths = mpNodes[lp].ninfo[1].fee_prop_millionths;
            g[e1].cltv_expiry_delta = mpNodes[lp].ninfo[1].cltv_expiry_delta;
            boost::tie(e2, inserted) = add_edge(node2, node1, g);
            g[e2].short_channel_id = mpNodes[lp].short_channel_id;
            g[e2].fee_base_msat = mpNodes[lp].ninfo[0].fee_base_msat;
            g[e2].fee_prop_millionths = mpNodes[lp].ninfo[0].fee_prop_millionths;
            g[e2].cltv_expiry_delta = mpNodes[lp].ninfo[0].cltv_expiry_delta;
        }
    }

    if (argc >= ARGS_PAYMENT) {
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
        uint32_t cltv_expiry = mMinFinalCltvExpiry;
        for (vertex_descriptor v = pnt_goal; v != pnt_start; v = p[v]) {
            route.push_front(v);

            bool found;
            graph_t::edge_descriptor e;
            boost::tie(e, found) = edge(p[v], v, g);
            if (!found) {
                fprintf(fp_err, "not foooooooooound\n");
                abort();
            }

            msat.push_front(amtmsat);
            if (v != pnt_goal) {
                //BOLT#4
                //  Where fee is calculated according to
                //      the receiving node's advertised fee schema as described in BOLT 7,
                //      or 0 if this node is the final hop.
                amtmsat = amtmsat + edgefee(amtmsat, g[e].fee_base_msat, g[e].fee_prop_millionths);
            }

            if (cltv_expiry == mMinFinalCltvExpiry) {
                //初回
                cltv.push_front(g[e].cltv_expiry_delta + mMinFinalCltvExpiry);
            }
            cltv_expiry += g[e].cltv_expiry_delta;
            cltv.push_front(cltv_expiry);
        }
        route.push_front(pnt_start);
        msat.push_front(amtmsat);

        //std::cout << "distance: " << d[pnt_goal] << std::endl;

        //pay.conf形式の出力
        int hop = (int)route.size();
        const uint8_t *p_next;
        nodeinfo_t ninfo;

        memset(&ninfo, 0, sizeof(ninfo));

        if (argc <= ARGS_PAY_AND_EXPIRY) {
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
                        ninfo = mpNodes[lp3].ninfo[dir];
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
                        ninfo = mpNodes[lp3].ninfo[dir];
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

    return 0;
}
