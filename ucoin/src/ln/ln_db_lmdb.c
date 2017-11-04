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
#include <inttypes.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "ln/ln_local.h"
#include "ln/ln_msg_anno.h"

#include "ln_db.h"
#include "ln_db_lmdb.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_LMDB_MAXDBS           (2 * 10)        ///< 同時オープンできるDB数
                                                //  channel
                                                //  channel_anno

#define M_LMDB_ENV              "./dbucoin"     ///< LMDB名
#define M_PREFIX_LEN            (2)
#define M_CHANNEL_NAME          "CN"            ///< channel
#define M_SHAREDSECRET_NAME     "SS"            ///< shared secret
#define M_DB_ANNO_CNL           "channel_anno"
#define M_DB_ANNO_NODE          "node_anno"
#define M_DB_VERSION            "version"
#define M_DB_VERSION_VAL        (-7)            ///< DBバージョン
/*
    -1 : first
    -2 : ln_update_add_htlc_t変更
    -3 : ln_funding_remote_data_t変更
    -4 : ln_funding_local_data_t, ln_funding_remote_data_t変更
    -5 : backup_self_tにln_node_info_t追加
    -6 : self.min_depth追加
    -7 : ln_commit_data_tにtxid追加
 */


/**************************************************************************
 * typedefs
 **************************************************************************/

// ln_self_tのバックアップ
typedef struct {
                                                                ///<  1
                                                                ///<  2
    uint8_t                     lfeature_remote;                ///<  3:initで取得したlocalfeature
                                                                ///<  4
    uint64_t                    storage_index;                  ///<  5:現在のindex
    uint8_t                     storage_seed[UCOIN_SZ_PRIVKEY]; ///<  6:ユーザから指定されたseed
    ln_funding_local_data_t     funding_local;                  ///<  7:funding情報:local
    ln_funding_remote_data_t    funding_remote;                 ///<  8:funding情報:remote
    uint64_t                    obscured;                       ///<  9:commitment numberをXORするとobscured commitment numberになる値。
    ucoin_keys_sort_t           key_fund_sort;                  ///< 10:2-of-2のソート順(local, remoteを正順とした場合)
    uint16_t                    htlc_num;                       ///< 11:HTLC数
    uint64_t                    commit_num;                     ///< 12:commitment_signed送信後にインクリメントする48bitカウンタ(0～)
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
    uint64_t                    remote_commit_num;              ///< 25:commitment_signed受信時にインクリメントする
    uint64_t                    revoke_num;                     ///< 26:revoke_and_ack送信後にインクリメントする
    uint64_t                    remote_revoke_num;              ///< 27:revoke_and_ack受信時にインクリメントする
    uint8_t                     fund_flag;                      ///< 28:none/funder/fundee
    ln_node_info_t              peer_node;                      ///< 29:peer_node情報
    uint32_t                    min_depth;                      ///< 30:minimum_depth
} backup_self_t;


typedef struct {
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_cursor  *cursor;
} lmdb_cursor_t;


/********************************************************************
 * static variables
 ********************************************************************/

//LMDB
static MDB_env      *mpDbEnv = NULL;


/********************************************************************
 * prototypes
 ********************************************************************/

static int load_shared_secret(ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi);
static int save_shared_secret(const ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi);

static int save_channel(const ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi);

static int load_anno_channel(MDB_txn *txn, MDB_dbi *pdbi, ucoin_buf_t *pCnlAnno, uint64_t short_channel_id);
static int save_anno_channel(MDB_txn *txn, MDB_dbi *pdbi, const ucoin_buf_t *pCnlAnno, uint64_t CnlSci);
static bool open_anno_channel_cursor(lmdb_cursor_t *pCur, unsigned int DbFlags);
static void close_anno_channel_cursor(lmdb_cursor_t *pCur);
//static bool search_anno_channel(lmdb_cursor_t *pCur, uint64_t short_channel_id, ucoin_buf_t *pBuf, char Type);

static int load_anno_channel_upd(MDB_txn *txn, MDB_dbi *pdbi, ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir);
static int save_anno_channel_upd(MDB_txn *txn, MDB_dbi *pdbi, const ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir);

static int load_anno_channel_sinfo(MDB_txn *txn, MDB_dbi *pdbi, uint64_t short_channel_id, ln_db_channel_sinfo *p_sinfo);
static int save_anno_channel_sinfo(MDB_txn *txn, MDB_dbi *pdbi, uint64_t short_channel_id, ln_db_channel_sinfo *p_sinfo);

static int load_anno_node(MDB_txn *txn, MDB_dbi *pdbi, ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, uint8_t *pSendId, const uint8_t *pNodeId);
static int save_anno_node(MDB_txn *txn, MDB_dbi *pdbi, const ucoin_buf_t *pNodeAnno, uint32_t TimeStamp, const uint8_t *pSendId, const uint8_t *pNodeId);
static bool open_anno_node_cursor(lmdb_cursor_t *pCur, unsigned int DbFlags);

static int write_version(MDB_txn *txn, const uint8_t *pMyNodeId);
static int check_version(MDB_txn *txn, MDB_dbi *pdbi, uint8_t *pMyNodeId);

static void misc_bin2str(char *pStr, const uint8_t *pBin, uint16_t BinLen);


/**************************************************************************
 * public functions
 **************************************************************************/

void HIDDEN ln_db_init(const uint8_t *pMyNodeId)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    //lmdbのopenは複数呼ばないでenvを共有する
    if (mpDbEnv == NULL) {
        retval = mdb_env_create(&mpDbEnv);
        assert(retval == 0);

        retval = mdb_env_set_maxdbs(mpDbEnv, M_LMDB_MAXDBS);
        assert(retval == 0);

        mkdir(M_LMDB_ENV, 0755);
        retval = mdb_env_open(mpDbEnv, M_LMDB_ENV, 0, 0644);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            abort();
        }
    }

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        abort();
    }
    retval = mdb_dbi_open(txn, M_DB_VERSION, 0, &dbi);
    if (retval != 0) {
        retval = write_version(txn, pMyNodeId);
        if (retval == 0) {
            mdb_txn_commit(txn);
        } else {
            DBG_PRINTF("FAIL: create version db\n");
            mdb_txn_abort(txn);
            abort();
        }
    } else {
        uint8_t my_nodeid[UCOIN_SZ_PUBKEY];
        retval = check_version(txn, &dbi, my_nodeid);
        mdb_txn_abort(txn);
        if (retval == 0) {
            if (memcmp(pMyNodeId, my_nodeid, UCOIN_SZ_PUBKEY) == 0) {
                DBG_PRINTF("ok\n");
            } else {
                DBG_PRINTF("FAIL: node_id mismatch\n");
                abort();
            }
        } else {
            DBG_PRINTF("FAIL: check version db\n");
            abort();
        }
    }
}


void ln_db_term(void)
{
    mdb_env_close(mpDbEnv);
    mpDbEnv = NULL;
}


/********************************************************************
 * self
 ********************************************************************/

bool ln_db_load_channel(ln_self_t *self, const uint8_t *pChannelId)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi;
    char        dbname[M_PREFIX_LEN + LN_SZ_CHANNEL_ID * 2 + 1];

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT2;
    }

    strcpy(dbname, M_CHANNEL_NAME);
    misc_bin2str(dbname + M_PREFIX_LEN, pChannelId, LN_SZ_CHANNEL_ID);
    retval = mdb_dbi_open(txn, dbname, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = ln_lmdb_load_channel(self, txn, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    memcpy(dbname, M_SHAREDSECRET_NAME, M_PREFIX_LEN);
    retval = mdb_dbi_open(txn, dbname, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = load_shared_secret(self, txn, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    if (txn) {
        mdb_txn_abort(txn);
    }

LABEL_EXIT2:
    DBG_PRINTF("retval=%d\n", retval);
    return retval == 0;
}


int ln_lmdb_load_channel(ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi)
{
    MDB_val     key, data;

    key.mv_size = 6;
    key.mv_data = "self1";
    int retval = mdb_get(txn, *pdbi, &key, &data);

    //構造体部分
    if ((retval == 0) && (data.mv_size == sizeof(backup_self_t))) {
        //リストア
        const backup_self_t *p_bk = (const backup_self_t *)data.mv_data;

        self->lfeature_remote = p_bk->lfeature_remote;     //3
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
            //shared secretは別DB
            ucoin_buf_init(&self->cnl_add_htlc[idx].shared_secret);
        }
        memcpy(self->channel_id, p_bk->channel_id, LN_SZ_CHANNEL_ID);      //17
        self->short_channel_id = p_bk->short_channel_id;       //18
        self->commit_local = p_bk->commit_local;       //19
        self->commit_remote = p_bk->commit_remote;     //20
        self->funding_sat = p_bk->funding_sat;     //21
        self->feerate_per_kw = p_bk->feerate_per_kw;       //22
        self->peer_storage = p_bk->peer_storage;     //23
        self->peer_storage_index = p_bk->peer_storage_index;     //24
        self->remote_commit_num = p_bk->remote_commit_num;  //25
        self->revoke_num = p_bk->revoke_num;  //26
        self->remote_revoke_num = p_bk->remote_revoke_num;  //27
        self->fund_flag = p_bk->fund_flag;  //28
        memcpy(&self->peer_node, &p_bk->peer_node, sizeof(ln_node_info_t));   //29
        self->min_depth = p_bk->min_depth;  //30

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

    return retval;
}


bool ln_db_save_channel(const ln_self_t *self)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi;
    char        dbname[M_PREFIX_LEN + LN_SZ_CHANNEL_ID * 2 + 1];

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    strcpy(dbname, M_CHANNEL_NAME);
    misc_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    retval = mdb_dbi_open(txn, dbname, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = save_channel(self, txn, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    memcpy(dbname, M_SHAREDSECRET_NAME, M_PREFIX_LEN);
    retval = mdb_dbi_open(txn, dbname, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = save_shared_secret(self, txn, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    //mdb_dbi_close(mpDbEnv, dbi);
    mdb_txn_commit(txn);
    txn = NULL;

LABEL_EXIT:
    if (txn) {
        mdb_txn_abort(txn);
    }
    DBG_PRINTF("retval=%d\n", retval);
    return retval == 0;
}


bool ln_db_del_channel(const ln_self_t *self)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi_anno;
    MDB_dbi     dbi_cnl;
    MDB_cursor  *cursor;
    MDB_val     key, data;
    char        dbname[M_PREFIX_LEN + LN_SZ_CHANNEL_ID * 2 + 1];

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    //channel_announcementから自分のshort_channel_idを含むデータを削除
    retval = mdb_dbi_open(txn, M_DB_ANNO_CNL, MDB_CREATE, &dbi_anno);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(txn, dbi_anno, &cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    while ((retval = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            uint64_t load_sci;
            memcpy(&load_sci, key.mv_data, LN_SZ_SHORT_CHANNEL_ID);
            if (load_sci == ln_short_channel_id(self)) {
                DBG_PRINTF("delete short_channel_id=%016" PRIx64 "[%c]\n", load_sci, ((const char *)key.mv_data)[LN_SZ_SHORT_CHANNEL_ID]);
                retval = mdb_cursor_del(cursor, 0);
                if (retval != 0) {
                    DBG_PRINTF("err: %s\n", mdb_strerror(retval));
                }
            }
        }
    }
    mdb_cursor_close(cursor);


    //channel削除
    strcpy(dbname, M_CHANNEL_NAME);
    misc_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    retval = mdb_dbi_open(txn, dbname, MDB_CREATE, &dbi_cnl);
    if (retval == 0) {
        retval = mdb_drop(txn, dbi_cnl, 1);
    }
    DBG_PRINTF("err: %s\n", mdb_strerror(retval));

    memcpy(dbname, M_SHAREDSECRET_NAME, M_PREFIX_LEN);
    retval = mdb_dbi_open(txn, dbname, 0, &dbi_cnl);
    if (retval == 0) {
        retval = mdb_drop(txn, dbi_cnl, 1);
    }
    DBG_PRINTF("err: %s\n", mdb_strerror(retval));

    mdb_txn_commit(txn);
    txn = NULL;

LABEL_EXIT:
    if (txn) {
        mdb_txn_abort(txn);
    }
    return retval == 0;
}


bool ln_db_search_channel(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
    bool result = false;
    int retval;
    lmdb_cursor_t cur;

    retval = mdb_txn_begin(mpDbEnv, NULL, MDB_RDONLY, &cur.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_dbi_open(cur.txn, NULL, 0, &cur.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(cur.txn);
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(cur.txn, cur.dbi, &cur.cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(cur.txn);
        goto LABEL_EXIT;
    }

    bool ret;
    int list = 0;
    MDB_val     key;
    while ((ret = mdb_cursor_get(cur.cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi dbi2;

        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        ret = mdb_open(cur.txn, key.mv_data, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else if ((key.mv_size > M_PREFIX_LEN) && (memcmp(key.mv_data, M_CHANNEL_NAME, M_PREFIX_LEN) == 0)) {
                ln_self_t self;

                memset(&self, 0, sizeof(self));
                retval = ln_lmdb_load_channel(&self, cur.txn, &dbi2);
                if (retval == 0) {
                    result = (*pFunc)(&self, pFuncParam);
                    if (result) {
                        DBG_PRINTF("match !\n");
                        break;
                    }
                    ln_term(&self);     //falseのみ解放
                } else {
                    DBG_PRINTF("err: %s\n", mdb_strerror(retval));
                }
            }
            mdb_close(mpDbEnv, dbi2);
        }
    }
    mdb_cursor_close(cur.cursor);
    mdb_close(mpDbEnv, cur.dbi);
    mdb_txn_abort(cur.txn);

LABEL_EXIT:
    return result;
}


void HIDDEN ln_db_copy_channel(ln_self_t *pOutSelf, const ln_self_t *pInSelf)
{
    pOutSelf->lfeature_remote = pInSelf->lfeature_remote;     //3
    pOutSelf->storage_index = pInSelf->storage_index;     //5
    memcpy(pOutSelf->storage_seed, pInSelf->storage_seed, UCOIN_SZ_PRIVKEY);      //6
    pOutSelf->funding_local = pInSelf->funding_local;     //7
    pOutSelf->funding_remote = pInSelf->funding_remote;       //8
    pOutSelf->obscured = pInSelf->obscured;       //9
    pOutSelf->key_fund_sort = pInSelf->key_fund_sort;     //10
    pOutSelf->htlc_num = pInSelf->htlc_num;       //11
    pOutSelf->commit_num = pInSelf->commit_num;       //12
    pOutSelf->htlc_id_num = pInSelf->htlc_id_num;     //13
    pOutSelf->our_msat = pInSelf->our_msat;       //14
    pOutSelf->their_msat = pInSelf->their_msat;       //15
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        pOutSelf->cnl_add_htlc[idx] = pInSelf->cnl_add_htlc[idx];       //16
        pOutSelf->cnl_add_htlc[idx].p_channel_id = NULL;     //送受信前に決定する
        pOutSelf->cnl_add_htlc[idx].p_onion_route = NULL;
        //shared secretは別DB
        ucoin_buf_init(&pOutSelf->cnl_add_htlc[idx].shared_secret);
    }
    memcpy(pOutSelf->channel_id, pInSelf->channel_id, LN_SZ_CHANNEL_ID);      //17
    pOutSelf->short_channel_id = pInSelf->short_channel_id;       //18
    pOutSelf->commit_local = pInSelf->commit_local;       //19
    pOutSelf->commit_remote = pInSelf->commit_remote;     //20
    pOutSelf->funding_sat = pInSelf->funding_sat;     //21
    pOutSelf->feerate_per_kw = pInSelf->feerate_per_kw;       //22
    pOutSelf->peer_storage = pInSelf->peer_storage;     //23
    pOutSelf->peer_storage_index = pInSelf->peer_storage_index;     //24
    pOutSelf->remote_commit_num = pInSelf->remote_commit_num;  //25
    pOutSelf->revoke_num = pInSelf->revoke_num;  //26
    pOutSelf->remote_revoke_num = pInSelf->remote_revoke_num;  //27
    pOutSelf->fund_flag = pInSelf->fund_flag;  //28
    memcpy(&pOutSelf->peer_node, &pInSelf->peer_node, sizeof(ln_node_info_t));   //29
    pOutSelf->min_depth = pInSelf->min_depth;  //30

    //スクリプト部分(shallow copy)

    //cnl_anno
    ucoin_buf_free(&pOutSelf->cnl_anno);
    memcpy(&pOutSelf->cnl_anno, &pInSelf->cnl_anno, sizeof(ucoin_buf_t));

    ucoin_buf_free(&pOutSelf->redeem_fund);
    memcpy(&pOutSelf->redeem_fund, &pInSelf->redeem_fund, sizeof(ucoin_buf_t));

    //tx_funding
    ucoin_tx_free(&pOutSelf->tx_funding);
    memcpy(&pOutSelf->tx_funding, &pInSelf->tx_funding, sizeof(ucoin_tx_t));
}


/********************************************************************
 * channel_announcement / channel_update
 ********************************************************************/

bool ln_db_load_anno_channel(ucoin_buf_t *pCnlAnno, uint64_t short_channel_id)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DB_ANNO_CNL, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(txn);
        goto LABEL_EXIT;
    }

    retval = load_anno_channel(txn, &dbi, pCnlAnno, short_channel_id);

    //mdb_dbi_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_save_anno_channel(const ucoin_buf_t *pCnlAnno, uint64_t CnlSci, const uint8_t *pNodeId)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DB_ANNO_CNL, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(txn);
        goto LABEL_EXIT;
    }

    ln_db_channel_sinfo sinfo;
    retval = load_anno_channel_sinfo(txn, &dbi, CnlSci, &sinfo);
    if (retval == 0) {
        //既存あり
        ucoin_buf_t buf_ann;

        ucoin_buf_init(&buf_ann);
        retval = load_anno_channel(txn, &dbi, &buf_ann, CnlSci);
        if (retval == 0) {
            if (ucoin_buf_cmp(&buf_ann, pCnlAnno)) {
                DBG_PRINTF("same channel_announcement\n");
            } else {
                DBG_PRINTF("err: channel_announcement mismatch !\n");
                retval = -1;
            }
        }
    } else {
        //新規
        retval = save_anno_channel(txn, &dbi, pCnlAnno, CnlSci);
        if (retval == 0) {
            sinfo.channel_anno = (uint32_t)time(NULL);
            sinfo.channel_upd[0] = 0;
            sinfo.channel_upd[1] = 0;
            memcpy(sinfo.send_nodeid, pNodeId, UCOIN_SZ_PUBKEY);
            retval = save_anno_channel_sinfo(txn, &dbi, CnlSci, &sinfo);
        }
    }

    //mdb_dbi_close(mpDbEnv, dbi);
    mdb_txn_commit(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_load_anno_channel_upd(ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DB_ANNO_CNL, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(txn);
        goto LABEL_EXIT;
    }

    retval = load_anno_channel_upd(txn, &dbi, pCnlUpd, short_channel_id, Dir);

    //mdb_dbi_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_save_anno_channel_upd(const ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    bool        upddb = false;
    ucoin_buf_t buf_upd;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    ucoin_buf_init(&buf_upd);
    retval = mdb_dbi_open(txn, M_DB_ANNO_CNL, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_ABORT;
    }

    ln_db_channel_sinfo sinfo;
    retval = load_anno_channel_sinfo(txn, &dbi, short_channel_id, &sinfo);
    if (retval != 0) {
        DBG_PRINTF("err: no channel_announcement\n");
        goto LABEL_ABORT;
    }

    if (sinfo.channel_upd[Dir] != 0) {
        //既存
        retval = load_anno_channel_upd(txn, &dbi, &buf_upd, short_channel_id, Dir);
        if (retval == 0) {
            if (ucoin_buf_cmp(&buf_upd, pCnlUpd)) {
                DBG_PRINTF("same channel_update: %d\n", Dir);
            } else {
                //不一致
                ln_cnl_update_t upd_db;
                ln_cnl_update_t upd_get;

                bool ret1 = ln_msg_cnl_update_read(&upd_db, buf_upd.buf, buf_upd.len);
                bool ret2 = ln_msg_cnl_update_read(&upd_get, pCnlUpd->buf, pCnlUpd->len);
                if (ret1 && ret2) {
                    if (upd_db.timestamp > upd_get.timestamp) {
                        //自分の方が新しければ、スルー
                        DBG_PRINTF("my channel_update is newer\n");
                        retval = 0;
                    } else if (upd_db.timestamp < upd_get.timestamp) {
                        //自分の方が古いので、更新
                        DBG_PRINTF("gotten channel_update is newer\n");
                        upddb = true;
                    } else {
                        DBG_PRINTF("err: channel_update %d mismatch !\n", Dir);
                        retval = -1;
                        goto LABEL_ABORT;
                    }
                } else {
                    DBG_PRINTF("err: channel_update %d cannot read\n", Dir);
                    retval = -1;
                    goto LABEL_ABORT;
                }
            }
        } else {
            //既存なのにDB読み出し失敗
            DBG_PRINTF("err: load_anno_channel_upd()\n");
            retval = -1;
            goto LABEL_ABORT;
        }
    } else {
        //新規
        upddb = true;
    }
    ucoin_buf_free(&buf_upd);

    if (upddb) {
        retval = save_anno_channel_upd(txn, &dbi, pCnlUpd, short_channel_id, Dir);
        if (retval == 0) {
            //受信した時刻と最後にannouncementを送信した時刻を比較する
            sinfo.channel_upd[Dir] = (uint32_t)time(NULL);
            retval = save_anno_channel_sinfo(txn, &dbi, short_channel_id, &sinfo);
        }
    }

    //mdb_dbi_close(mpDbEnv, dbi);
    mdb_txn_commit(txn);

LABEL_EXIT:
    return retval == 0;

LABEL_ABORT:
    mdb_txn_abort(txn);
    ucoin_buf_free(&buf_upd);
    return false;
}


uint64_t ln_db_search_channel_short_channel_id(const uint8_t *pNodeId1, const uint8_t *pNodeId2)
{
    bool ret;
    int retval;
    lmdb_cursor_t cur;
    MDB_val key, data;
    uint64_t short_channel_id = 0;

    ret = open_anno_channel_cursor(&cur, MDB_RDONLY);
    if (!ret) {
        DBG_PRINTF("err: cursor open\n");
        goto LABEL_EXIT;
    }

    while ((retval = mdb_cursor_get(cur.cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            if (*(char *)(key.mv_data + LN_SZ_SHORT_CHANNEL_ID) == LN_DB_CNLANNO_ANNO) {
                ln_cnl_announce_read_t ann;

                ret = ln_msg_cnl_announce_read(&ann, data.mv_data, data.mv_size);
                if (ret && (
                            (memcmp(ann.node_id1, pNodeId1, UCOIN_SZ_PUBKEY) == 0) &&
                            (memcmp(ann.node_id2, pNodeId2, UCOIN_SZ_PUBKEY) == 0)
                           ) ) {
                    memcpy(&short_channel_id, key.mv_data, LN_SZ_SHORT_CHANNEL_ID);
                    break;
                }
            }
        }
    }

    close_anno_channel_cursor(&cur);

LABEL_EXIT:
    return short_channel_id;
}


bool ln_db_cursor_anno_channel_open(void **ppCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)malloc(sizeof(lmdb_cursor_t));

    bool ret = open_anno_channel_cursor(p_cur, 0);
    if (ret) {
        *ppCur = p_cur;
    } else {
        DBG_PRINTF("err: cursor open\n");
        free(p_cur);
        *ppCur = NULL;
    }

    return ret;
}


void ln_db_cursor_anno_channel_close(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    mdb_cursor_close(p_cur->cursor);
    mdb_txn_commit(p_cur->txn);
    free(p_cur);
}


bool ln_db_cursor_anno_channel_get(void *pCur, uint64_t *p_short_channel_id, char *p_type, ucoin_buf_t *pBuf)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    int retval = ln_lmdb_load_anno_channel_cursor(p_cur->cursor, p_short_channel_id, p_type, pBuf);

    return retval == 0;
}


int ln_lmdb_load_anno_channel_cursor(MDB_cursor *cur, uint64_t *p_short_channel_id, char *p_type, ucoin_buf_t *pBuf)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(cur, &key, &data, MDB_NEXT_NODUP);
    if (retval == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            memcpy(p_short_channel_id, key.mv_data, LN_SZ_SHORT_CHANNEL_ID);
            *p_type = *(char *)(key.mv_data + LN_SZ_SHORT_CHANNEL_ID);
            switch (*p_type) {
            case LN_DB_CNLANNO_SINFO:   //sendinfo
            case LN_DB_CNLANNO_ANNO:    //channel_announcement
            case LN_DB_CNLANNO_UPD1:    //channel_update(node_1)
            case LN_DB_CNLANNO_UPD2:    //channel_update(node_2)
                ucoin_buf_alloccopy(pBuf, data.mv_data, data.mv_size);
                break;
            default:
                DBG_PRINTF("fail: unknown name: %c\n", *p_type);
                retval = -1;
            }
        } else {
            DBG_PRINTF("fail: invalid key length: %d\n", (int)key.mv_size);
            DUMPBIN(key.mv_data, key.mv_size);
            retval = -1;
        }
    } else {
        if (retval != MDB_NOTFOUND) {
            DBG_PRINTF("fail: mdb_cursor_get(): %s\n", mdb_strerror(retval));
        }
    }

    return retval;
}


/********************************************************************
 * node_announcement
 ********************************************************************/

bool ln_db_load_anno_node(ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, uint8_t *pSendId, const uint8_t *pNodeId)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DB_ANNO_NODE, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(txn);
        goto LABEL_EXIT;
    }

    retval = load_anno_node(txn, &dbi, pNodeAnno, pTimeStamp, pSendId, pNodeId);

    //mdb_dbi_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_save_anno_node(const ucoin_buf_t *pNodeAnno, const uint8_t *pSendId, const uint8_t *pNodeId)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DB_ANNO_NODE, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(txn);
        goto LABEL_EXIT;
    }

    uint32_t now = (uint32_t)time(NULL);
    retval = save_anno_node(txn, &dbi, pNodeAnno, now, pSendId, pNodeId);

    //mdb_dbi_close(mpDbEnv, dbi);
    mdb_txn_commit(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_cursor_anno_node_open(void **ppCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)malloc(sizeof(lmdb_cursor_t));

    bool ret = open_anno_node_cursor(p_cur, 0);
    if (ret) {
        *ppCur = p_cur;
    } else {
        DBG_PRINTF("err: cursor open\n");
        free(p_cur);
        *ppCur = NULL;
    }

    return ret;
}


void ln_db_cursor_anno_node_close(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    mdb_cursor_close(p_cur->cursor);
    mdb_txn_commit(p_cur->txn);
    free(p_cur);
}


bool ln_db_cursor_anno_node_get(void *pCur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pSendId, uint8_t *pNodeId)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    int retval = ln_lmdb_load_anno_node_cursor(p_cur->cursor, pBuf, pTimeStamp, pSendId, pNodeId);

    return retval == 0;
}


int ln_lmdb_load_anno_node_cursor(MDB_cursor *cur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pSendId, uint8_t *pNodeId)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(cur, &key, &data, MDB_NEXT_NODUP);
    if (retval == 0) {
        if (pNodeId) {
            memcpy(pNodeId, key.mv_data, key.mv_size);
        }
        memcpy(pTimeStamp, data.mv_data, sizeof(uint32_t));
        memcpy(pSendId, (uint8_t *)data.mv_data + sizeof(uint32_t), UCOIN_SZ_PUBKEY);
        ucoin_buf_alloccopy(pBuf, data.mv_data + sizeof(uint32_t) + UCOIN_SZ_PUBKEY,
                                data.mv_size - sizeof(uint32_t) - UCOIN_SZ_PUBKEY);
    } else {
        if (retval != MDB_NOTFOUND) {
            DBG_PRINTF("fail: mdb_cursor_get(): %d\n", retval);
        }
    }

    return retval;
}


int ln_lmdb_check_version(MDB_txn *txn, uint8_t *pMyNodeId)
{
    int         retval;
    MDB_dbi     dbi;

    retval = mdb_dbi_open(txn, M_DB_VERSION, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = check_version(txn, &dbi, pMyNodeId);

LABEL_EXIT:
    return retval;
}


ln_lmdb_dbtype_t ln_lmdb_get_dbtype(const char *pDbName)
{
    ln_lmdb_dbtype_t dbtype;

    if (strncmp(pDbName, M_CHANNEL_NAME, M_PREFIX_LEN) == 0) {
        //self
        dbtype = LN_LMDB_DBTYPE_SELF;
    } else if (strncmp(pDbName, M_SHAREDSECRET_NAME, M_PREFIX_LEN) == 0) {
        //shared secret
        dbtype = LN_LMDB_DBTYPE_SHARED_SECRET;
    } else if (strcmp(pDbName, M_DB_ANNO_CNL) == 0) {
        //channel_announcement
        dbtype = LN_LMDB_DBTYPE_CHANNEL_ANNO;
    } else if (strcmp(pDbName, M_DB_ANNO_NODE) == 0) {
        //node_announcement
        dbtype = LN_LMDB_DBTYPE_NODE_ANNO;
    } else if (strcmp(pDbName, M_DB_VERSION) == 0) {
        //version
        dbtype = LN_LMDB_DBTYPE_VERSION;
    } else {
        dbtype = LN_LMDB_DBTYPE_UNKNOWN;
    }

    return dbtype;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** channel_announcement読込み
 *
 * @param[out]      self
 * @param[in]       txn
 * @param[in]       pdbi
 * @retval      true    成功
 */
static int load_shared_secret(ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi)
{
    int retval = 0;
    MDB_val key, data;

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        key.mv_size = sizeof(int);
        key.mv_data = &lp;
        retval = mdb_get(txn, *pdbi, &key, &data);
        if (retval != 0) {
            break;
        }
        ucoin_buf_alloccopy(&self->cnl_add_htlc[lp].shared_secret, data.mv_data, data.mv_size);
    }

    return retval;
}


/** channel: HTLC shared secret書込み
 *
 * @param[in]       self
 * @param[in]       txn
 * @param[in]       pdbi
 * @retval      true    成功
 */
static int save_shared_secret(const ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi)
{
    int retval = 0;
    MDB_val key, data;

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        key.mv_size = sizeof(int);
        key.mv_data = &lp;
        data.mv_size = self->cnl_add_htlc[lp].shared_secret.len;
        data.mv_data = self->cnl_add_htlc[lp].shared_secret.buf;
        retval = mdb_put(txn, *pdbi, &key, &data, 0);
        if (retval != 0) {
            break;
        }
    }

    return retval;
}


/** channel情報書き込み
 *
 * @param[in]       self
 * @param[in,out]   txn
 * @param[in,out]   pdbi
 * @retval      true    成功
 */
static int save_channel(const ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi)
{
    MDB_val key, data;

    //構造体部分
    backup_self_t *bk = (backup_self_t *)malloc(sizeof(backup_self_t));

    memset(bk, 0, sizeof(backup_self_t));
    bk->lfeature_remote = self->lfeature_remote;     //3
    bk->storage_index = self->storage_index;     //5
    memcpy(bk->storage_seed, self->storage_seed, UCOIN_SZ_PRIVKEY);      //6
    bk->funding_local = self->funding_local;     //7
    bk->funding_remote = self->funding_remote;       //8
    bk->obscured = self->obscured;       //9
    bk->key_fund_sort = self->key_fund_sort;     //10
    bk->htlc_num = self->htlc_num;       //11
    bk->commit_num = self->commit_num;       //12
    bk->htlc_id_num = self->htlc_id_num;     //13
    bk->our_msat = self->our_msat;       //14
    bk->their_msat = self->their_msat;       //15
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        bk->cnl_add_htlc[idx] = self->cnl_add_htlc[idx];       //16
    }
    memcpy(bk->channel_id, self->channel_id, LN_SZ_CHANNEL_ID);      //17
    bk->short_channel_id = self->short_channel_id;       //18
    bk->commit_local = self->commit_local;       //19
    bk->commit_remote = self->commit_remote;     //20
    bk->funding_sat = self->funding_sat;     //21
    bk->feerate_per_kw = self->feerate_per_kw;       //22
    bk->peer_storage = self->peer_storage;     //23
    bk->peer_storage_index = self->peer_storage_index;     //24
    bk->remote_commit_num = self->remote_commit_num;       //25
    bk->revoke_num = self->revoke_num;       //26
    bk->remote_revoke_num = self->remote_revoke_num;       //27
    bk->fund_flag = self->fund_flag;       //28
    memcpy(&bk->peer_node, &self->peer_node, sizeof(ln_node_info_t));    //29
    bk->min_depth = self->min_depth; //30

    key.mv_size = 6;
    key.mv_data = "self1";
    data.mv_size = sizeof(backup_self_t);
    data.mv_data = bk;
    int retval = mdb_put(txn, *pdbi, &key, &data, 0);
    free(bk);

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
    if (retval != 0) {
        DBG_PRINTF("retval=%d\n", retval);
    }

    return retval;
}


/** channel_announcement読込み
 *
 * @param[in]       txn
 * @param[in]       pdbi
 * @param[out]      pCnlAnno
 * @param[in]       short_channel_id
 * @retval      true    成功
 */
static int load_anno_channel(MDB_txn *txn, MDB_dbi *pdbi, ucoin_buf_t *pCnlAnno, uint64_t short_channel_id)
{
    DBG_PRINTF("short_channel_id=%016" PRIx64 "\n", short_channel_id);

    MDB_val key, data;
    uint8_t keydata[sizeof(short_channel_id) + 1];

    memcpy(keydata, &short_channel_id, sizeof(short_channel_id));
    keydata[sizeof(short_channel_id)] = LN_DB_CNLANNO_ANNO;
    key.mv_size = sizeof(keydata);
    key.mv_data = keydata;
    int retval = mdb_get(txn, *pdbi, &key, &data);
    if (retval == 0) {
        ucoin_buf_alloccopy(pCnlAnno, data.mv_data, data.mv_size);
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return retval;
}


/** channel_announcement書込み
 *
 * @param[in]       txn
 * @param[in]       pdbi
 * @param[in]       pCnlAnno
 * @param[in]       short_channel_id
 * @retval      true    成功
 */
static int save_anno_channel(MDB_txn *txn, MDB_dbi *pdbi, const ucoin_buf_t *pCnlAnno, uint64_t short_channel_id)
{
    DBG_PRINTF("short_channel_id=%016" PRIx64 "\n", short_channel_id);

    MDB_val key, data;
    uint8_t keydata[sizeof(short_channel_id) + 1];

    memcpy(keydata, &short_channel_id, sizeof(short_channel_id));
    keydata[sizeof(short_channel_id)] =LN_DB_CNLANNO_ANNO;
    key.mv_size = sizeof(keydata);
    key.mv_data = keydata;
    data.mv_size = pCnlAnno->len;
    data.mv_data = pCnlAnno->buf;
    int retval = mdb_put(txn, *pdbi, &key, &data, 0);

    return retval;
}


/** lmdb cursorオープン(channel_announcement系)
 *
 */
static bool open_anno_channel_cursor(lmdb_cursor_t *pCur, unsigned int DbFlags)
{
    int retval;

    retval = mdb_txn_begin(mpDbEnv, NULL, DbFlags, &pCur->txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_dbi_open(pCur->txn, M_DB_ANNO_CNL, 0, &pCur->dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(pCur->txn);
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(pCur->txn, pCur->dbi, &pCur->cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(pCur->txn);
    }

LABEL_EXIT:
    return retval == 0;
}


/** lmdb cursorクローズ(channel_announcement系)
 *
 */
static void close_anno_channel_cursor(lmdb_cursor_t *pCur)
{
    mdb_cursor_close(pCur->cursor);
    mdb_close(mpDbEnv, pCur->dbi);
    mdb_txn_abort(pCur->txn);
}


#if 0
/** lmdb channel_announcement系検索
 *
 */
static bool search_anno_channel(lmdb_cursor_t *pCur, uint64_t short_channel_id, ucoin_buf_t *pBuf, char Type)
{
    int retval;
    MDB_val key, data;

    ucoin_buf_init(pBuf);
    while ((retval = mdb_cursor_get(pCur->cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            uint64_t load_sci;
            memcpy(&load_sci, key.mv_data, LN_SZ_SHORT_CHANNEL_ID);
            if ((load_sci == short_channel_id) && (*(char *)(key.mv_data + LN_SZ_SHORT_CHANNEL_ID) == Type)) {
                ucoin_buf_alloccopy(pBuf, data.mv_data, data.mv_size);
                break;
            }
        }
    }

    return pBuf->len != 0;
}
#endif


/** channel_update読込み
 *
 * @param[in]       txn
 * @param[in]       pdbi
 * @param[out]      pCnlAnno
 * @param[in]       short_channel_id
 * @param[in]       Dir                 0:node_1, 1:node_2
 * @retval      true    成功
 */
static int load_anno_channel_upd(MDB_txn *txn, MDB_dbi *pdbi, ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir)
{
    DBG_PRINTF("short_channel_id=%016" PRIx64 ", dir=%d\n", short_channel_id, Dir);

    MDB_val key, data;
    uint8_t keydata[sizeof(short_channel_id) + 1];

    memcpy(keydata, &short_channel_id, sizeof(short_channel_id));
    keydata[sizeof(short_channel_id)] = (Dir) ?  LN_DB_CNLANNO_UPD2 : LN_DB_CNLANNO_UPD1;
    key.mv_size = sizeof(keydata);
    key.mv_data = keydata;
    int retval = mdb_get(txn, *pdbi, &key, &data);
    if (retval == 0) {
        ucoin_buf_alloccopy(pCnlUpd, data.mv_data, data.mv_size);
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return retval;
}


/** channel_update書込み
 *
 * @param[in]       txn
 * @param[in]       pdbi
 * @param[in]       pCnlAnno
 * @param[in]       short_channel_id
 * @param[in]       Dir                 0:node_1, 1:node_2
 * @retval      true    成功
 */
static int save_anno_channel_upd(MDB_txn *txn, MDB_dbi *pdbi, const ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir)
{
    DBG_PRINTF("short_channel_id=%016" PRIx64 ", dir=%d\n", short_channel_id, Dir);

    MDB_val key, data;
    uint8_t keydata[sizeof(short_channel_id) + 1];

    memcpy(keydata, &short_channel_id, sizeof(short_channel_id));
    keydata[sizeof(short_channel_id)] = (Dir) ?  LN_DB_CNLANNO_UPD2 : LN_DB_CNLANNO_UPD1;
    key.mv_size = sizeof(keydata);
    key.mv_data = keydata;
    data.mv_size = pCnlUpd->len;
    data.mv_data = pCnlUpd->buf;
    int retval = mdb_put(txn, *pdbi, &key, &data, 0);

    return retval;
}


static int load_anno_channel_sinfo(MDB_txn *txn, MDB_dbi *pdbi, uint64_t short_channel_id, ln_db_channel_sinfo *p_sinfo)
{
    MDB_val key, data;
    uint8_t keydata[sizeof(short_channel_id) + 1];

    memcpy(keydata, &short_channel_id, sizeof(short_channel_id));
    keydata[sizeof(short_channel_id)] =LN_DB_CNLANNO_SINFO;
    key.mv_size = sizeof(keydata);
    key.mv_data = keydata;
    int retval = mdb_get(txn, *pdbi, &key, &data);
    if (retval == 0) {
        memcpy(p_sinfo, data.mv_data, data.mv_size);
        DBG_PRINTF("sinfo: channel_announcement : %" PRIu32 "\n", p_sinfo->channel_anno);
        DBG_PRINTF("sinfo: channel_update(1)    : %" PRIu32 "\n", p_sinfo->channel_upd[0]);
        DBG_PRINTF("sinfo: channel_update(2)    : %" PRIu32 "\n", p_sinfo->channel_upd[1]);
        DBG_PRINTF("sinfo: send_nodeid : ");
        DUMPBIN(p_sinfo->send_nodeid, UCOIN_SZ_PUBKEY);
    }

    return retval;
}


static int save_anno_channel_sinfo(MDB_txn *txn, MDB_dbi *pdbi, uint64_t short_channel_id, ln_db_channel_sinfo *p_sinfo)
{
    MDB_val key, data;
    uint8_t keydata[sizeof(short_channel_id) + 1];

    memcpy(keydata, &short_channel_id, sizeof(short_channel_id));
    keydata[sizeof(short_channel_id)] =LN_DB_CNLANNO_SINFO;
    key.mv_size = sizeof(keydata);
    key.mv_data = keydata;
    data.mv_size = sizeof(ln_db_channel_sinfo);
    data.mv_data = p_sinfo;
    int retval = mdb_put(txn, *pdbi, &key, &data, 0);

    return retval;
}


static int load_anno_node(MDB_txn *txn, MDB_dbi *pdbi, ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, uint8_t *pSendId, const uint8_t *pNodeId)
{
    MDB_val key, data;

    key.mv_size = UCOIN_SZ_PUBKEY;
    key.mv_data = (CONST_CAST uint8_t *)pNodeId;
    int retval = mdb_get(txn, *pdbi, &key, &data);
    if (retval == 0) {
        if (pNodeAnno != NULL) {
            if (pTimeStamp != NULL) {
                *pTimeStamp = *(uint32_t *)data.mv_data;
            }
            if (pSendId != NULL) {
                memcpy(pSendId, (uint8_t *)data.mv_data + sizeof(uint32_t), UCOIN_SZ_PUBKEY);
            }
            ucoin_buf_alloccopy(pNodeAnno, (uint8_t *)data.mv_data + sizeof(uint32_t) + UCOIN_SZ_PUBKEY, data.mv_size - sizeof(uint32_t) - UCOIN_SZ_PUBKEY);
        }
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return retval;
}


static int save_anno_node(MDB_txn *txn, MDB_dbi *pdbi, const ucoin_buf_t *pNodeAnno, uint32_t TimeStamp, const uint8_t *pSendId, const uint8_t *pNodeId)
{
    MDB_val key, data;
    ucoin_buf_t buf;

    ucoin_buf_alloc(&buf, sizeof(uint32_t) + UCOIN_SZ_PUBKEY + pNodeAnno->len);
    memcpy(buf.buf, &TimeStamp, sizeof(uint32_t));
    memcpy(buf.buf + sizeof(uint32_t), pSendId, UCOIN_SZ_PUBKEY);
    memcpy(buf.buf + sizeof(uint32_t) + UCOIN_SZ_PUBKEY, pNodeAnno->buf, pNodeAnno->len);

    key.mv_size = UCOIN_SZ_PUBKEY;
    key.mv_data = (CONST_CAST uint8_t *)pNodeId;
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    int retval = mdb_put(txn, *pdbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }
    ucoin_buf_free(&buf);

    return retval;
}




/** lmdb cursorオープン(node_announcement系)
 *
 */
static bool open_anno_node_cursor(lmdb_cursor_t *pCur, unsigned int DbFlags)
{
    int retval;

    retval = mdb_txn_begin(mpDbEnv, NULL, DbFlags, &pCur->txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_dbi_open(pCur->txn, M_DB_ANNO_NODE, 0, &pCur->dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(pCur->txn);
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(pCur->txn, pCur->dbi, &pCur->cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        mdb_txn_abort(pCur->txn);
    }

LABEL_EXIT:
    return retval == 0;
}


static int write_version(MDB_txn *txn, const uint8_t *pMyNodeId)
{
    int         retval;
    MDB_dbi     dbi;
    MDB_val     key, data;
    int         version = M_DB_VERSION_VAL;

    retval = mdb_dbi_open(txn, M_DB_VERSION, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    //version
    key.mv_size = 3;
    key.mv_data = "ver";
    data.mv_size = sizeof(int);
    data.mv_data = &version;
    retval = mdb_put(txn, dbi, &key, &data, 0);

    //my node_id
    if ((retval == 0) && pMyNodeId) {
        key.mv_size = 8;
        key.mv_data = "mynodeid";
        data.mv_size = UCOIN_SZ_PUBKEY;
        data.mv_data = (void *)pMyNodeId;
        retval = mdb_put(txn, dbi, &key, &data, 0);
    }

LABEL_EXIT:
    return retval;
}


/** DBバージョンチェック
 *
 * @param[in]   txn
 * @param[in]   pdbi
 * @param[out]  pMyNodeId   [NULL]無視 / [非NULL]自nodeid
 * @retval  0   DBバージョン一致
 */
static int check_version(MDB_txn *txn, MDB_dbi *pdbi, uint8_t *pMyNodeId)
{
    int         retval;
    MDB_val key, data;

    //version
    key.mv_size = 3;
    key.mv_data = "ver";
    retval = mdb_get(txn, *pdbi, &key, &data);
    if (retval == 0) {
        int version = *(int *)data.mv_data;
        if (version != M_DB_VERSION_VAL) {
            DBG_PRINTF("FAIL: version mismatch : %d\n", version);
            retval = -1;
        }
    }
    if (retval == 0) {
        if (pMyNodeId) {
            key.mv_size = 8;
            key.mv_data = "mynodeid";
            retval = mdb_get(txn, *pdbi, &key, &data);
            if ((retval == 0) && (data.mv_size == UCOIN_SZ_PUBKEY)) {
                memcpy(pMyNodeId, data.mv_data, UCOIN_SZ_PUBKEY);
            } else {
                memset(pMyNodeId, 0, UCOIN_SZ_PUBKEY);
            }
        }
    } else {
        DBG_PRINTF("*** version check: %d ***\n", retval);
    }

    return retval;
}


static void misc_bin2str(char *pStr, const uint8_t *pBin, uint16_t BinLen)
{
    *pStr = '\0';
    for (int lp = 0; lp < BinLen; lp++) {
        char str[3];
        sprintf(str, "%02x", pBin[lp]);
        strcat(pStr, str);
    }
}
