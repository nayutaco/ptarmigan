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
/** @file   ln_db_lmdb.c
 *  @brief  Lightning DB保存/復元
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "ln/ln_local.h"

#include "ln_db_lmdb.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

// ln_node_tのバックアップ
//      gapを減らそうと思って位置を移動させたが、ln_node_tと同じにしてmemcpyさせた方がよかったかも
typedef struct {
    uint8_t                     features;                       ///< localfeatures
    uint8_t                     node_num;                       ///< 保持しているnodes数
    uint8_t                     channel_num;
    uint32_t                    timestamp[LN_NODE_MAX];

    ucoin_util_keys_t           keys;                           ///< node鍵
    char                        alias[LN_SZ_ALIAS];             ///< ノード名(\0 terminate)
    uint8_t                     node_id[LN_NODE_MAX][UCOIN_SZ_PUBKEY];
    char                        node_alias[LN_NODE_MAX][LN_SZ_ALIAS];
    ucoin_keys_sort_t           sort[LN_NODE_MAX];
    ln_node_info_t              node_info[LN_NODE_MAX];
    ln_channel_info_t           channel_info[LN_CHANNEL_MAX];
} backup_node_t;


// ln_self_tのバックアップ
typedef struct {
    int8_t                      node_idx;                       ///<  1:接続先ノード(p_node->nodes[node_idx])
    //uint8_t                     init_sent;                      ///<  2:true:initメッセージ送信済み
    uint8_t                     lfeature_remote;                ///<  3:initで取得したlocalfeature
    //ln_derkey_storage           storage;                        ///<  4:key storage
    uint64_t                    storage_index;                  ///<  5:現在のindex
    uint8_t                     storage_seed[UCOIN_SZ_PRIVKEY]; ///<  6:ユーザから指定されたseed
    ln_funding_local_data_t     funding_local;                  ///<  7:funding情報:local
    ln_funding_remote_data_t    funding_remote;                 ///<  8:funding情報:remote
    uint64_t                    obscured;                       ///<  9:commitment numberをXORするとobscured commitment numberになる値。
    ucoin_keys_sort_t           key_fund_sort;                  ///< 10:2-of-2のソート順(local, remoteを正順とした場合)
    uint16_t                    htlc_num;                       ///< 11:HTLC数
    uint64_t                    commit_num;                     ///< 12:commitment txを作るたびにインクリメントする48bitカウンタ(0～)
    uint64_t                    htlc_id_num;                    ///< 13:update_add_htlcで使うidの管理
    uint64_t                    our_msat;                       ///< 14:自分の持ち分
    uint64_t                    their_msat;                     ///< 15:相手の持ち分
    ln_update_add_htlc_t        cnl_add_htlc[LN_HTLC_MAX];      ///< 16:追加したHTLC
    uint8_t                     channel_id[LN_SZ_CHANNEL_ID];   ///< 17:channel_id
    uint64_t                    short_channel_id;               ///< 18:short_channel_id
    ln_commit_data_t            commit_local;                   ///< 19:local commit_tx用
    ln_commit_data_t            commit_remote;                  ///< 20:remote commit_tx用
    uint64_t                    funding_sat;                    ///< 21:funding_msat
    uint32_t                    feerate_per_kw;                 ///< 22:feerate_per_kw
    ln_derkey_storage           peer_storage;                   ///< 23:key storage(peer)
    uint64_t                    peer_storage_index;             ///< 24:現在のindex(peer)
} backup_self_t;


/**************************************************************************
 * public functions
 **************************************************************************/

/*
 * ノード
 */

bool ln_db_load_node(ln_node_t *node, MDB_txn *txn, MDB_dbi *pdbi)
{
    MDB_val     key, data;

    key.mv_size = 5;
    key.mv_data = "node";
    int retval = mdb_get(txn, *pdbi, &key, &data);
    if (retval == 0) {
        const backup_node_t *p_bk = (const backup_node_t *)data.mv_data;

        node->features = p_bk->features;
        node->node_num = p_bk->node_num;
        node->channel_num = p_bk->channel_num;
        node->keys = p_bk->keys;
        strcpy(node->alias, p_bk->alias);
        memcpy(node->node_info, p_bk->node_info, sizeof(ln_node_info_t) * LN_NODE_MAX);
        memcpy(node->channel_info, p_bk->channel_info, sizeof(ln_channel_info_t) * LN_CHANNEL_MAX);
    }

    return retval == 0;
}


bool ln_db_save_node(const ln_node_t *node, MDB_txn *txn, MDB_dbi *pdbi)
{
    MDB_val     key, data;
    backup_node_t bk;

    memset(&bk, 0, sizeof(bk));
    bk.features = node->features;
    bk.node_num = node->node_num;
    bk.channel_num = node->channel_num;
    bk.keys = node->keys;
    strcpy(bk.alias, node->alias);
    memcpy(bk.node_info, node->node_info, sizeof(ln_node_info_t) * LN_NODE_MAX);
    memcpy(bk.channel_info, node->channel_info, sizeof(ln_channel_info_t) * LN_CHANNEL_MAX);

    key.mv_size = 5;
    key.mv_data = "node";
    data.mv_size = sizeof(bk);
    data.mv_data = &bk;
    int retval = mdb_put(txn, *pdbi, &key, &data, 0);

    return retval == 0;
}


/*
 * チャネル
 */

bool ln_db_load_channel(ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi)
{
    MDB_val     key, data;

    key.mv_size = 6;
    key.mv_data = "self1";
    int retval = mdb_get(txn, *pdbi, &key, &data);

    //構造体部分
    if ((retval == 0) && (data.mv_size == sizeof(backup_self_t))) {
        //リストア
        const backup_self_t *p_bk = (const backup_self_t *)data.mv_data;

        self->node_idx = p_bk->node_idx;       //1
        //self->init_sent = (bool)p_bk->init_sent;      //2
        self->lfeature_remote = p_bk->lfeature_remote;     //3
        //self->storage = p_bk->storage;     //4
        self->storage_index = p_bk->storage_index;     //5
        memcpy(self->storage_seed, p_bk->storage_seed, UCOIN_SZ_PRIVKEY);      //6
        self->funding_local = p_bk->funding_local;     //7
        self->funding_remote = p_bk->funding_remote;       //8
        self->obscured = p_bk->obscured;       //9
        self->key_fund_sort = p_bk->key_fund_sort;     //10
        self->htlc_num = p_bk->htlc_num;       //11
        self->commit_num = p_bk->commit_num;       //12
        self->htlc_id_num = p_bk->htlc_id_num;     //13
        self->our_msat = p_bk->our_msat;       //14
        self->their_msat = p_bk->their_msat;       //15
        for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
            self->cnl_add_htlc[idx] = p_bk->cnl_add_htlc[idx];       //16
            self->cnl_add_htlc[idx].p_channel_id = NULL;     //送受信前に決定する
            self->cnl_add_htlc[idx].p_onion_route = NULL;
        }
        memcpy(self->channel_id, p_bk->channel_id, LN_SZ_CHANNEL_ID);      //17
        self->short_channel_id = p_bk->short_channel_id;       //18
        self->commit_local = p_bk->commit_local;       //19
        self->commit_remote = p_bk->commit_remote;     //20
        self->funding_sat = p_bk->funding_sat;     //21
        self->feerate_per_kw = p_bk->feerate_per_kw;       //22
        self->peer_storage = p_bk->peer_storage;     //23
        self->peer_storage_index = p_bk->peer_storage_index;     //24

        //次読込み
        key.mv_size = 6;
        key.mv_data = "self2";
        retval = mdb_get(txn, *pdbi, &key, &data);
    }

    //スクリプト部分
    if (retval == 0) {
        uint16_t len;
        int pos = 0;

        //cnl_anno
        len = *(const uint16_t *)(data.mv_data + pos);
        pos += sizeof(uint16_t);
        ucoin_buf_free(&self->cnl_anno);
        ucoin_buf_alloccopy(&self->cnl_anno, data.mv_data + pos, len);
        pos += len;
        //redeem_fund

        len = *(const uint16_t *)(data.mv_data + pos);
        pos += sizeof(uint16_t);
        ucoin_buf_free(&self->redeem_fund);
        ucoin_buf_alloccopy(&self->redeem_fund, data.mv_data + pos, len);
        pos += len;

        //tx_funding
        len = *(const uint16_t *)(data.mv_data + pos);
        pos += sizeof(uint16_t);
        ucoin_tx_free(&self->tx_funding);
        ucoin_tx_read(&self->tx_funding, data.mv_data + pos, len);
    }

    return retval == 0;
}


bool ln_db_save_channel(const ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi)
{
    MDB_val key, data;

    //構造体部分
    backup_self_t bk;

    memset(&bk, 0, sizeof(bk));
    bk.node_idx = self->node_idx;       //1
    //bk.init_sent = (uint8_t)self->init_sent;      //2
    bk.lfeature_remote = self->lfeature_remote;     //3
    //bk.storage = self->storage;     //4
    bk.storage_index = self->storage_index;     //5
    memcpy(bk.storage_seed, self->storage_seed, UCOIN_SZ_PRIVKEY);      //6
    bk.funding_local = self->funding_local;     //7
    bk.funding_remote = self->funding_remote;       //8
    bk.obscured = self->obscured;       //9
    bk.key_fund_sort = self->key_fund_sort;     //10
    bk.htlc_num = self->htlc_num;       //11
    bk.commit_num = self->commit_num;       //12
    bk.htlc_id_num = self->htlc_id_num;     //13
    bk.our_msat = self->our_msat;       //14
    bk.their_msat = self->their_msat;       //15
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        bk.cnl_add_htlc[idx] = self->cnl_add_htlc[idx];       //16
    }
    memcpy(bk.channel_id, self->channel_id, LN_SZ_CHANNEL_ID);      //17
    bk.short_channel_id = self->short_channel_id;       //18
    bk.commit_local = self->commit_local;       //19
    bk.commit_remote = self->commit_remote;     //20
    bk.funding_sat = self->funding_sat;     //21
    bk.feerate_per_kw = self->feerate_per_kw;       //22
    bk.peer_storage = self->peer_storage;     //23
    bk.peer_storage_index = self->peer_storage_index;     //24

    key.mv_size = 6;
    key.mv_data = "self1";
    data.mv_size = sizeof(bk);
    data.mv_data = &bk;
    int retval = mdb_put(txn, *pdbi, &key, &data, 0);

    //スクリプト部分
    if (retval == 0) {
        ucoin_buf_t buf_bk;
        ucoin_buf_t buf_funding;

        ucoin_buf_init(&buf_bk);
        ucoin_buf_init(&buf_funding);
        ucoin_tx_create(&buf_funding, &self->tx_funding);

        size_t sz = sizeof(uint16_t) + self->cnl_anno.len +
                        sizeof(uint16_t) + self->redeem_fund.len +
                        sizeof(uint16_t) + buf_funding.len;
        uint16_t len;
        ucoin_push_t ps;
        ucoin_push_init(&ps, &buf_bk, sz);

        //cnl_anno
        len = self->cnl_anno.len;
        ucoin_push_data(&ps, &len, sizeof(len));
        ucoin_push_data(&ps, self->cnl_anno.buf, len);
        //redeem_fund
        len = self->redeem_fund.len;
        ucoin_push_data(&ps, &len, sizeof(len));
        ucoin_push_data(&ps, self->redeem_fund.buf, len);
        //buf_funding
        len = buf_funding.len;
        ucoin_push_data(&ps, &len, sizeof(len));
        ucoin_push_data(&ps, buf_funding.buf, len);

        ucoin_buf_free(&buf_funding);

        key.mv_size = 6;
        key.mv_data = "self2";
        data.mv_size = buf_bk.len;
        data.mv_data = buf_bk.buf;
        retval = mdb_put(txn, *pdbi, &key, &data, 0);

        ucoin_buf_free(&buf_bk);
    }

    return retval == 0;
}

