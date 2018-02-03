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


#define M_DB_DEBUG

/********************************************************************
 * macros
 ********************************************************************/

#define M_LMDB_MAXDBS           (2 * 10)        ///< 同時オープンできるDB数
                                                //  channel
                                                //  channel_anno
#define M_LMDB_MAPSIZE          ((uint64_t)4294967296)      //DB最大長[byte]
                                                // mdb_txn_commit()でMDB_MAP_FULLになったため拡張

#define M_LMDB_DIR              "./dbucoin"
#define M_LMDB_ENV              M_LMDB_DIR "/dbucoin"       ///< LMDB名(announce以外)
#define M_LMDB_ANNO             M_LMDB_DIR "/dbucoin_anno"  ///< LMDB名(announce)
#define M_PREFIX_LEN            (2)
#define M_CHANNEL_NAME          "CN"            ///< channel
#define M_SHAREDSECRET_NAME     "SS"            ///< shared secret
#define M_REVOKED_NAME          "RV"            ///< revoked transaction用

#define M_DB_ANNO_CNL           "channel_anno"
#define M_DB_ANNOINFO_CNL       "channel_annoinfo"
#define M_DB_ANNO_NODE          "node_anno"
#define M_DB_ANNOINFO_NODE      "node_annoinfo"
#define M_DB_PREIMAGE           "preimage"
#define M_DB_PAYHASH            "payhash"
#define M_DB_VERSION            "version"

#define M_SZ_DBNAME_LEN         (M_PREFIX_LEN + LN_SZ_CHANNEL_ID * 2 + 1)
#define M_SZ_ANNOINFO_CNL       (sizeof(uint64_t) + 1)
#define M_SZ_ANNOINFO_NODE      (UCOIN_SZ_PUBKEY)

#define M_DB_VERSION_VAL        (-14)           ///< DBバージョン
/*
    -1 : first
    -2 : ln_update_add_htlc_t変更
    -3 : ln_funding_remote_data_t変更
    -4 : ln_funding_local_data_t, ln_funding_remote_data_t変更
    -5 : backup_self_tにln_node_info_t追加
    -6 : self.min_depth追加
    -7 : ln_commit_data_tにtxid追加
    -8 : ln_commit_data_tにhtlc_num追加
    -9 : self.shutdown_scriptpk_localを対象に追加
    -10: htlckey対応
    -11: self.shutdown_scriptpk_remoteを対象に追加, LOCALKEY削除, funding_local/remote整理
    -12: revoked transaction用データ追加
    -13: self.anno_flag追加
    -14: announcementの送信管理追加
 */


/********************************************************************
 * macro functions
 ********************************************************************/

#define M_ANNOINFO_CNL_SET(keydata, key, short_channel_id, type) {\
    key.mv_size = sizeof(keydata);\
    key.mv_data = keydata;\
    memcpy(keydata, &short_channel_id, LN_SZ_SHORT_CHANNEL_ID);\
    keydata[LN_SZ_SHORT_CHANNEL_ID] = type;\
}

#define M_ANNOINFO_NODE_SET(keydata, key, node_id) {\
    key.mv_size = sizeof(keydata);\
    key.mv_data = keydata;\
    memcpy(keydata, node_id, UCOIN_SZ_PUBKEY);\
}

#ifndef M_DB_DEBUG
#define MDB_TXN_BEGIN(a,b,c,d)      mdb_txn_begin(a, b, c, d)
#define MDB_TXN_ABORT(a)            mdb_txn_abort(a)
#define MDB_TXN_COMMIT(a)           int txn_retval = mdb_txn_commit(a); if (txn_retval) DBG_PRINTF("err: %s\n", mdb_strerror(txn_retval))
#else
static int g_cnt[2];
#define MDB_TXN_BEGIN(a,b,c,d)      my_mdb_txn_begin(a,b,c,d, __LINE__);
#define MDB_TXN_ABORT(a)            my_mdb_txn_abort(a, __LINE__)
#define MDB_TXN_COMMIT(a)           my_mdb_txn_commit(a, __LINE__)
#endif


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

    //ln_funding_local_data_t     funding_local;                  ///<  7:funding情報:local
    uint8_t                     funding_local_txid[UCOIN_SZ_TXID];  ///< 7.1:funding情報:local:funding_tx txid
    uint16_t                    funding_local_txindex;          ///<  7.2:funding情報:local:txindex
    uint8_t                     funding_local_privkey[LN_FUNDIDX_MAX][UCOIN_SZ_PRIVKEY];    ///< 7.3:funding情報:local:privkey

    //ln_funding_remote_data_t    funding_remote;                 ///<  8:funding情報:remote
    uint8_t                     funding_remote_pubkey[LN_FUNDIDX_MAX][UCOIN_SZ_PUBKEY];     ///< 8.1:funding情報:remote:pubkey
    uint8_t                     funding_remote_prev_percommit[UCOIN_SZ_PUBKEY];     ///< 8.2:funding情報:remote:1つ前のper_commit_point

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
    uint8_t                     anno_flag;                      ///< 31:anno_flag
} backup_self_t;


typedef struct {
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_cursor  *cursor;
} lmdb_cursor_t;


typedef struct {
    uint64_t amount;
    time_t creation;
} preimage_info_t;


/********************************************************************
 * static variables
 ********************************************************************/

//LMDB
static MDB_env      *mpDbEnv = NULL;
static MDB_env      *mpDbAnno = NULL;


/********************************************************************
 * prototypes
 ********************************************************************/

//static int load_shared_secret(ln_self_t *self, ln_lmdb_db_t *pDb);
static int self_ss_save(const ln_self_t *self, ln_lmdb_db_t *pDb);

static int self_save(const ln_self_t *self, ln_lmdb_db_t *pDb);

static int annocnl_load(ln_lmdb_db_t *pDb, ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId);
static int annocnl_save(ln_lmdb_db_t *pDb, const ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId);
static bool annocnl_cur_open(lmdb_cursor_t *pCur);
//static bool annocnl_search(lmdb_cursor_t *pCur, uint64_t ShortChannelId, ucoin_buf_t *pBuf, char Type);

static int annocnlupd_load(ln_lmdb_db_t *pDb, ucoin_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir);
static int annocnlupd_save(ln_lmdb_db_t *pDb, const ucoin_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd);

static int annonod_load(ln_lmdb_db_t *pDb, ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);
static int annonod_save(ln_lmdb_db_t *pDb, const ucoin_buf_t *pNodeAnno, const ln_node_announce_t *pAnno);
static bool annonod_cur_open(lmdb_cursor_t *pCur);

static bool annoinfo_add(ln_lmdb_db_t *pDb, MDB_val *pMdbKey, MDB_val *pMdbData, const uint8_t *pNodeId);
static bool annoinfo_search(MDB_val *pMdbData, const uint8_t *pNodeId);
//static void annoinfo_clear(ln_lmdb_db_t *pDb);

static bool preimg_open(ln_lmdb_db_t *p_db, MDB_txn *txn);
static void preimg_close(ln_lmdb_db_t *p_db, MDB_txn *txn);

static int ver_write(MDB_txn *txn, const uint8_t *pMyNodeId);
static int ver_check(ln_lmdb_db_t *pDb, uint8_t *pMyNodeId);

static void misc_bin2str(char *pStr, const uint8_t *pBin, uint16_t BinLen);


#ifdef M_DB_DEBUG
static inline int my_mdb_txn_begin(MDB_env *env, MDB_txn *parent, unsigned int flags, MDB_txn **txn, int line) {
    int ggg = (env == mpDbEnv) ? 0 : 1;
    g_cnt[ggg]++;
    DBG_PRINTF("mdb_txn_begin:%d:[%d]%d(%d)\n", line, ggg, g_cnt[ggg], (int)flags);
    if ((ggg == 1) && (g_cnt[ggg] > 1)) {
        DBG_PRINTF("multi txs\n");
    }
    return mdb_txn_begin(env, parent, flags, txn);
}

static inline int my_mdb_txn_commit(MDB_txn *txn, int line) {
    int ggg = (mdb_txn_env(txn) == mpDbEnv) ? 0 : 1;
    g_cnt[ggg]--;
    DBG_PRINTF("mdb_txn_commit:%d:[%d]%d\n", line, ggg, g_cnt[ggg]);
    int txn_retval = mdb_txn_commit(txn);
    if (txn_retval) {
        DBG_PRINTF("err: %s\n", mdb_strerror(txn_retval));
    }
    return txn_retval;
}

static inline void my_mdb_txn_abort(MDB_txn *txn, int line) {
    int ggg = (mdb_txn_env(txn) == mpDbEnv) ? 0 : 1;
    g_cnt[ggg]--;
    DBG_PRINTF("mdb_txn_abort:%d:[%d]%d\n", line, ggg, g_cnt[ggg]);
    mdb_txn_abort(txn);
}

#endif  //M_DB_DEBUG


/**************************************************************************
 * public functions
 **************************************************************************/

void HIDDEN ln_db_init(const uint8_t *pMyNodeId)
{
    int         retval;
    ln_lmdb_db_t   db;

    //lmdbのopenは複数呼ばないでenvを共有する
    if (mpDbEnv == NULL) {
        retval = mdb_env_create(&mpDbEnv);
        assert(retval == 0);

        retval = mdb_env_set_maxdbs(mpDbEnv, M_LMDB_MAXDBS);
        assert(retval == 0);

        retval = mdb_env_set_mapsize(mpDbEnv, M_LMDB_MAPSIZE);
        assert(retval == 0);

        mkdir(M_LMDB_DIR, 0755);
        mkdir(M_LMDB_ENV, 0755);
        mkdir(M_LMDB_ANNO, 0755);

        retval = mdb_env_open(mpDbEnv, M_LMDB_ENV, 0, 0644);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            abort();
        }

        retval = mdb_env_create(&mpDbAnno);
        assert(retval == 0);

        retval = mdb_env_set_maxdbs(mpDbAnno, M_LMDB_MAXDBS);
        assert(retval == 0);

        retval = mdb_env_set_mapsize(mpDbAnno, M_LMDB_MAPSIZE);
        assert(retval == 0);

        retval = mdb_env_open(mpDbAnno, M_LMDB_ANNO, 0, 0644);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            abort();
        }

    }

    retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        abort();
    }
    retval = mdb_dbi_open(db.txn, M_DB_VERSION, 0, &db.dbi);
    if (retval != 0) {
        retval = ver_write(db.txn, pMyNodeId);
        if (retval == 0) {
            MDB_TXN_COMMIT(db.txn);
        } else {
            DBG_PRINTF("FAIL: create version db\n");
            MDB_TXN_ABORT(db.txn);
            abort();
        }
    } else {
        uint8_t my_nodeid[UCOIN_SZ_PUBKEY];
        retval = ver_check(&db, my_nodeid);
        MDB_TXN_ABORT(db.txn);
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
    mdb_env_close(mpDbAnno);
    mpDbAnno = NULL;
    mdb_env_close(mpDbEnv);
    mpDbEnv = NULL;
}


/********************************************************************
 * self
 ********************************************************************/
#if 0
bool ln_db_load_channel(ln_self_t *self, const uint8_t *pChannelId)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi;
    char        dbname[M_SZ_DBNAME_LEN];

    retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &txn);
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
    retval = ln_lmdb_self_load(self, txn, dbi);
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

    memcpy(dbname, M_REVOKED_NAME, M_PREFIX_LEN);
    retval = mdb_dbi_open(txn, dbname, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    if (txn) {
        MDB_TXN_ABORT(txn);
    }

LABEL_EXIT2:
    DBG_PRINTF("retval=%d\n", retval);
    return retval == 0;
}
#endif

int ln_lmdb_self_load(ln_self_t *self, MDB_txn *txn, MDB_dbi dbi)
{
    MDB_val     key, data;

    key.mv_size = 6;
    key.mv_data = "self1";
    int retval = mdb_get(txn, dbi, &key, &data);

    //構造体部分
    if ((retval == 0) && (data.mv_size == sizeof(backup_self_t))) {
        //リストア
        const backup_self_t *p_bk = (const backup_self_t *)data.mv_data;

        self->lfeature_remote = p_bk->lfeature_remote;     //3
        self->storage_index = p_bk->storage_index;     //5
        memcpy(self->storage_seed, p_bk->storage_seed, UCOIN_SZ_PRIVKEY);      //6

        //self->funding_local = p_bk->funding_local;     //7
        memcpy(self->funding_local.txid, p_bk->funding_local_txid, UCOIN_SZ_TXID);      //7.1
        self->funding_local.txindex = p_bk->funding_local_txindex;      //7.2
        for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
            memcpy(self->funding_local.keys[lp].priv, p_bk->funding_local_privkey[lp], UCOIN_SZ_PRIVKEY);   //7.3
            ucoin_keys_priv2pub(self->funding_local.keys[lp].pub, self->funding_local.keys[lp].priv);
        }

        //self->funding_remote = p_bk->funding_remote;       //8
        for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
            memcpy(self->funding_remote.pubkeys[lp], p_bk->funding_remote_pubkey[lp], UCOIN_SZ_PUBKEY);     //8.1
        }
        memcpy(self->funding_remote.prev_percommit, p_bk->funding_remote_prev_percommit, UCOIN_SZ_PUBKEY);  //8.2

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
        self->anno_flag = p_bk->anno_flag;  //31

        //次読込み
        key.mv_size = 6;
        key.mv_data = "self2";
        retval = mdb_get(txn, dbi, &key, &data);
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

        //shutdown_scriptpk_local
        len = *(const uint16_t *)(data.mv_data + pos);
        pos += sizeof(uint16_t);
        ucoin_buf_free(&self->shutdown_scriptpk_local);
        ucoin_buf_alloccopy(&self->shutdown_scriptpk_local, data.mv_data + pos, len);
        pos += len;

        //shutdown_scriptpk_remote
        len = *(const uint16_t *)(data.mv_data + pos);
        pos += sizeof(uint16_t);
        ucoin_buf_free(&self->shutdown_scriptpk_remote);
        ucoin_buf_alloccopy(&self->shutdown_scriptpk_remote, data.mv_data + pos, len);
        pos += len;

        //tx_funding
        len = *(const uint16_t *)(data.mv_data + pos);
        pos += sizeof(uint16_t);
        ucoin_tx_free(&self->tx_funding);
        ucoin_tx_read(&self->tx_funding, data.mv_data + pos, len);
    }

    return retval;
}


bool ln_db_self_save(const ln_self_t *self)
{
    int         retval;
    ln_lmdb_db_t   db;
    char        dbname[M_SZ_DBNAME_LEN];

    retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    strcpy(dbname, M_CHANNEL_NAME);
    misc_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    retval = mdb_dbi_open(db.txn, dbname, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = self_save(self, &db);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    memcpy(dbname, M_SHAREDSECRET_NAME, M_PREFIX_LEN);
    retval = mdb_dbi_open(db.txn, dbname, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = self_ss_save(self, &db);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    MDB_TXN_COMMIT(db.txn);
    db.txn = NULL;

LABEL_EXIT:
    if (db.txn) {
        DBG_PRINTF("abort\n");
        MDB_TXN_ABORT(db.txn);
    }
    DBG_PRINTF("retval=%d\n", retval);
    return retval == 0;
}


bool ln_db_self_del(const ln_self_t *self, void *p_db_param)
{
    int         retval;
    MDB_dbi     dbi_anno;
    MDB_dbi     dbi_cnl;
    MDB_cursor  *cursor;
    MDB_val     key, data;
    char        dbname[M_SZ_DBNAME_LEN];
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)p_db_param;

    //channel_announcementから自分のshort_channel_idを含むデータを削除
    retval = mdb_dbi_open(p_cur->txn, M_DB_ANNO_CNL, 0, &dbi_anno);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        if (retval == MDB_NOTFOUND) {
            DBG_PRINTF("fall through\n");
            goto LABEL_DEL_SS;
        } else {
            goto LABEL_EXIT;
        }
    }
    retval = mdb_cursor_open(p_cur->txn, dbi_anno, &cursor);
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

    //shared secret
LABEL_DEL_SS:
    memcpy(dbname, M_SHAREDSECRET_NAME, M_PREFIX_LEN);
    misc_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    retval = mdb_dbi_open(p_cur->txn, dbname, 0, &dbi_cnl);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        if (retval == MDB_NOTFOUND) {
            DBG_PRINTF("fall through: %s\n", dbname);
            goto LABEL_DEL_RV;
        } else {
            goto LABEL_EXIT;
        }
    }
    retval = mdb_drop(p_cur->txn, dbi_cnl, 1);
    DBG_PRINTF("drop: %s(%d)\n", dbname, retval);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    //revoked transaction用データ
LABEL_DEL_RV:
    memcpy(dbname, M_REVOKED_NAME, M_PREFIX_LEN);
    misc_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    retval = mdb_dbi_open(p_cur->txn, dbname, 0, &dbi_cnl);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        if (retval == MDB_NOTFOUND) {
            DBG_PRINTF("fall through: %s\n", dbname);
            goto LABEL_DEL_CNL;
        } else {
            goto LABEL_EXIT;
        }
    }
    retval = mdb_drop(p_cur->txn, dbi_cnl, 1);
    DBG_PRINTF("drop: %s(%d)\n", dbname, retval);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    //channel削除
LABEL_DEL_CNL:
    memcpy(dbname, M_CHANNEL_NAME, M_PREFIX_LEN);
    retval = mdb_dbi_open(p_cur->txn, dbname, 0, &dbi_cnl);
    if (retval == 0) {
        retval = mdb_drop(p_cur->txn, dbi_cnl, 1);
        DBG_PRINTF("drop: %s(%d)\n", dbname, retval);
    }

LABEL_EXIT:
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }
    return retval == 0;
}


bool ln_db_self_search(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
    bool result = false;
    int retval;
    lmdb_cursor_t cur;

    retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &cur.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_dbi_open(cur.txn, NULL, 0, &cur.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(cur.txn);
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(cur.txn, cur.dbi, &cur.cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(cur.txn);
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
            } else if ((key.mv_size == (M_SZ_DBNAME_LEN - 1)) && (memcmp(key.mv_data, M_CHANNEL_NAME, M_PREFIX_LEN) == 0)) {
                ln_self_t self;

                memset(&self, 0, sizeof(self));
                retval = ln_lmdb_self_load(&self, cur.txn, dbi2);
                if (retval == 0) {
                    result = (*pFunc)(&self, (void *)&cur, pFuncParam);
                    if (result) {
                        DBG_PRINTF("match !\n");
                        break;
                    }
                    ln_term(&self);     //falseのみ解放
                } else {
                    //DBG_PRINTF("err: %s\n", mdb_strerror(retval));
                }
            }
        }
    }
    mdb_cursor_close(cur.cursor);
    MDB_TXN_COMMIT(cur.txn);

LABEL_EXIT:
    return result;
}


/********************************************************************
 * announcement用DB
 ********************************************************************/

bool ln_db_anno_cur_transaction(void **ppDb, ln_db_txn_t Type)
{
    MDB_txn *txn = NULL;

    int retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &txn);
    if (retval == 0) {
        ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)M_MALLOC(sizeof(ln_lmdb_db_t));
        p_db->txn = txn;
        *ppDb = p_db;

        const char *p_name;
        switch (Type) {
        case LN_DB_TXN_CNL:
            p_name = M_DB_ANNOINFO_CNL;
            break;
        case LN_DB_TXN_NODE:
            p_name = M_DB_ANNOINFO_NODE;
            break;
        default:
            assert(0);
            return false;
        }
        retval = mdb_dbi_open(txn, p_name, MDB_CREATE, &p_db->dbi);
    }
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        *ppDb = NULL;
    }
    return retval == 0;
}


void ln_db_anno_cur_commit(void *pDb)
{
    if (pDb != NULL) {
        ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;
        MDB_TXN_COMMIT(p_db->txn);
        M_FREE(pDb);
    }
}


/********************************************************************
 * channel_announcement / channel_update
 *
 * +-----------------------------------------+
 * |"channel_anno"                           |
 * |   +-------------------------------------+
 * |   |channel_announcement                 |
 * |   | key : short_channel_id + 'A'        |
 * |   | data: channel_announcement packet   |
 * |   +-------------------------------------+
 * |   |channel_update                       |
 * |   | key : short_channel_id + 'B' or 'C' |
 * |   | data: timestamp[4]                  |
 * |   |       channel_update packet         |
 * +---+-------------------------------------+
 *
 * +-----------------------------------------+
 * |"channel_annoinfo"                       |
 * |   +-------------------------------------+
 * |   |channel_announcement                 |
 * |   | key : short_channel_id + 'A'        |
 * |   | data: node_ids[33*n]                |
 * |   +-------------------------------------+
 * |   |channel_update                       |
 * |   | key : short_channel_id + 'B' or 'C' |
 * |   | data: node_ids[33*n]                |
 * +---+-------------------------------------+
 *
 ********************************************************************/

bool ln_db_annocnl_load(ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    int         retval;
    ln_lmdb_db_t   db;

    retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DB_ANNO_CNL, 0, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    retval = annocnl_load(&db, pCnlAnno, ShortChannelId);

    MDB_TXN_ABORT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnl_save(const ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId, const uint8_t *pSendId)
{
    int         retval;
    ln_lmdb_db_t   db, db_info;

    retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    db_info.txn = db.txn;
    retval = mdb_dbi_open(db.txn, M_DB_ANNO_CNL, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DB_ANNOINFO_CNL, MDB_CREATE, &db_info.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    //channel_announcement
    ucoin_buf_t buf_ann;
    ucoin_buf_init(&buf_ann);
    retval = annocnl_load(&db, &buf_ann, ShortChannelId);
    if (retval != 0) {
        retval = annocnl_save(&db, pCnlAnno, ShortChannelId);
        if ((retval == 0) && (pSendId != NULL)) {
            bool ret = ln_db_annocnls_add_nodeid(&db_info, ShortChannelId, LN_DB_CNLANNO_ANNO, false, pSendId);
            if (!ret) {
                retval = -1;
            }
        }
    } else {
        if (!ucoin_buf_cmp(&buf_ann, pCnlAnno)) {
            DBG_PRINTF("fail: different channel_announcement\n");
            retval = -1;
        }
    }

    MDB_TXN_COMMIT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnlupd_load(ucoin_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir)
{
    int         retval;
    ln_lmdb_db_t   db;

    retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DB_ANNO_CNL, 0, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    retval = annocnlupd_load(&db, pCnlUpd, pTimeStamp, ShortChannelId, Dir);

    MDB_TXN_ABORT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnlupd_save(const ucoin_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd, const uint8_t *pSendId)
{
    int             retval;
    ln_lmdb_db_t    db, db_info;

    retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    db_info.txn = db.txn;
    retval = mdb_dbi_open(db.txn, M_DB_ANNO_CNL, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DB_ANNOINFO_CNL, MDB_CREATE, &db_info.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    ucoin_buf_t     buf_upd;
    uint32_t        timestamp;
    bool            upddb = false;
    bool            clr = false;

    ucoin_buf_init(&buf_upd);
    retval = annocnlupd_load(&db, &buf_upd, &timestamp, pUpd->short_channel_id, ln_cnlupd_direction(pUpd));
    if (retval == 0) {
        if (timestamp > pUpd->timestamp) {
            //自分の方が新しければ、スルー
            //DBG_PRINTF("my channel_update is newer\n");
        } else if (timestamp < pUpd->timestamp) {
            //自分の方が古いので、更新
            //DBG_PRINTF("gotten channel_update is newer\n");
            upddb = true;

            //announceし直す必要があるため、クリアする
            clr = true;
        } else {
            if (ucoin_buf_cmp(&buf_upd, pCnlUpd)) {
                //DBG_PRINTF("same channel_update: %d\n", ln_cnlupd_direction(pUpd));
            } else {
                //日時が同じなのにデータが異なる
                DBG_PRINTF("err: channel_update %d mismatch !\n", ln_cnlupd_direction(pUpd));
                DBG_PRINTF("  db: ");
                DUMPBIN(buf_upd.buf, buf_upd.len);
                DBG_PRINTF("  rv: ");
                DUMPBIN(pCnlUpd->buf, pCnlUpd->len);
                retval = -1;
                ucoin_buf_free(&buf_upd);
                MDB_TXN_ABORT(db.txn);
                goto LABEL_EXIT;
            }
        }
    } else {
        //新規
        upddb = true;
    }
    ucoin_buf_free(&buf_upd);

    if (upddb) {
        retval = annocnlupd_save(&db, pCnlUpd, pUpd);
    }
    if ((retval == 0) && (pSendId != NULL)) {
        char type = ln_cnlupd_direction(pUpd) ?  LN_DB_CNLANNO_UPD2 : LN_DB_CNLANNO_UPD1;
        bool ret = ln_db_annocnls_add_nodeid(&db_info, pUpd->short_channel_id, type, clr, pSendId);
        if (!ret) {
            retval = -1;
        }
    }

    MDB_TXN_COMMIT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnlall_del(uint64_t ShortChannelId)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi, dbi_info;
    MDB_val     key;
    uint8_t     keydata[M_SZ_ANNOINFO_CNL];

    retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_dbi_open(txn, M_DB_ANNO_CNL, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_ABORT;
    }
    retval = mdb_dbi_open(txn, M_DB_ANNOINFO_CNL, MDB_CREATE, &dbi_info);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_ABORT;
    }

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, 0);

    char POSTFIX[] = { LN_DB_CNLANNO_ANNO, LN_DB_CNLANNO_UPD1, LN_DB_CNLANNO_UPD2 };
    for (size_t lp = 0; lp < ARRAY_SIZE(POSTFIX); lp++) {
        keydata[LN_SZ_SHORT_CHANNEL_ID] = POSTFIX[lp];
        retval = mdb_del(txn, dbi, &key, NULL);
        if (retval != 0) {
            DBG_PRINTF("err[%c]: %s\n", POSTFIX[lp], mdb_strerror(retval));
        }
        retval = mdb_del(txn, dbi_info, &key, NULL);
        if (retval != 0) {
            DBG_PRINTF("err[%c]: %s\n", POSTFIX[lp], mdb_strerror(retval));
        }
    }

    MDB_TXN_COMMIT(txn);

    return true;

LABEL_ABORT:
    MDB_TXN_ABORT(txn);
LABEL_EXIT:
    return false;
}


bool ln_db_annocnls_search_nodeid(void *pDb, uint64_t ShortChannelId, char Type, const uint8_t *pSendId)
{
    bool ret = false;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL];

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, Type);
    int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
    if (retval == 0) {
        //DBG_PRINTF("short_channel_id[%c]= %" PRIx64 "\n", Type, ShortChannelId);
        //DBG_PRINTF("send_id= ");
        //DUMPBIN(pSendId, UCOIN_SZ_PUBKEY);
        ret = annoinfo_search(&data, pSendId);
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return ret;
}


bool ln_db_annocnls_add_nodeid(void *pDb, uint64_t ShortChannelId, char Type, bool bClr, const uint8_t *pSendId)
{
    bool ret = true;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL];
    bool detect = false;

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, Type);
    if (!bClr) {
        int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
        if (retval == 0) {
            detect = annoinfo_search(&data, pSendId);
        } else {
            DBG_PRINTF("new[%c] ", Type);
            DUMPBIN(pSendId, UCOIN_SZ_PUBKEY);
            data.mv_size = 0;
        }
    } else {
        data.mv_size = 0;
    }
    if (!detect) {
        ret = annoinfo_add(p_db, &key, &data, pSendId);
    }

    return ret;
}


#if 0
uint64_t ln_db_annocnlall_search_channel_short_channel_id(const uint8_t *pNodeId1, const uint8_t *pNodeId2)
{
    bool ret;
    int retval;
    lmdb_cursor_t cur = {0};
    MDB_val key, data;
    uint64_t short_channel_id = 0;

    ret = annocnl_cur_open(&cur);
    if (!ret) {
        DBG_PRINTF("err: cursor open\n");
        goto LABEL_EXIT;
    }

    while ((retval = mdb_cursor_get(cur.cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            if (*(char *)((uint8_t *)key.mv_data + LN_SZ_SHORT_CHANNEL_ID) == LN_DB_CNLANNO_ANNO) {
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

    mdb_cursor_close(cur.cursor);
    MDB_TXN_ABORT(cur.txn);

LABEL_EXIT:
    return short_channel_id;
}
#endif


bool ln_db_annocnl_cur_open(void **ppCur, void *pDb)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)M_MALLOC(sizeof(lmdb_cursor_t));
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    p_cur->txn = p_db->txn;
    bool ret = annocnl_cur_open(p_cur);
    if (ret) {
        *ppCur = p_cur;
    } else {
        DBG_PRINTF("err: cursor open\n");
        M_FREE(p_cur);
        *ppCur = NULL;
    }

    return ret;
}


void ln_db_annocnl_cur_close(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    mdb_cursor_close(p_cur->cursor);
    M_FREE(p_cur);
}


bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, ucoin_buf_t *pBuf)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    int retval = ln_lmdb_annocnl_cur_load(p_cur->cursor, pShortChannelId, pType, pTimeStamp, pBuf);

    return retval == 0;
}


int ln_lmdb_annocnl_cur_load(MDB_cursor *cur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, ucoin_buf_t *pBuf)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(cur, &key, &data, MDB_NEXT_NODUP);
    if (retval == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            //key = short_channel_id + type
            memcpy(pShortChannelId, key.mv_data, LN_SZ_SHORT_CHANNEL_ID);
            *pType = *(char *)((uint8_t *)key.mv_data + LN_SZ_SHORT_CHANNEL_ID);
            //data
            uint8_t *pData = (uint8_t *)data.mv_data;
            if ((*pType == LN_DB_CNLANNO_UPD1) || (*pType == LN_DB_CNLANNO_UPD2)) {
                if (pTimeStamp != NULL) {
                    *pTimeStamp = *(uint32_t *)pData;
                }
                pData += sizeof(uint32_t);
                data.mv_size -= sizeof(uint32_t);
            } else {
                //channel_announcementにtimestampは無い
            }
            ucoin_buf_alloccopy(pBuf, pData, data.mv_size);
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

bool ln_db_annonod_load(ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId)
{
    int         retval;
    ln_lmdb_db_t   db;

    retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DB_ANNO_NODE, 0, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = annonod_load(&db, pNodeAnno, pTimeStamp, pNodeId);

    MDB_TXN_ABORT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annonod_save(const ucoin_buf_t *pNodeAnno, const ln_node_announce_t *pAnno, const uint8_t *pSendId)
{
    int             retval;
    ln_lmdb_db_t    db, db_info;

    retval = MDB_TXN_BEGIN(mpDbAnno, NULL, 0, &db.txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    db_info.txn = db.txn;
    retval = mdb_dbi_open(db.txn, M_DB_ANNO_NODE, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DB_ANNOINFO_NODE, MDB_CREATE, &db_info.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    ucoin_buf_t buf_node;
    uint32_t    timestamp;
    uint8_t     nodeid[UCOIN_SZ_PUBKEY];
    bool        upddb = false;
    bool        clr = false;

    ucoin_buf_init(&buf_node);
    retval = annonod_load(&db, &buf_node, &timestamp, nodeid);
    if (retval == 0) {
        if (timestamp > pAnno->timestamp) {
            //自分の方が新しければ、スルー
            //DBG_PRINTF("my node_announcement is newer\n");
            retval = 0;
        } else if (timestamp < pAnno->timestamp) {
            //自分の方が古いので、更新
            //DBG_PRINTF("gotten node_announcement is newer\n");
            upddb = true;

            //announceし直す必要があるため、クリアする
            clr = true;
        } else {
            if (ucoin_buf_cmp(&buf_node, pNodeAnno)) {
                //DBG_PRINTF("same node_announcement\n");
            } else {
                //日時が同じなのにデータが異なる
                DBG_PRINTF("err: node_announcement mismatch !\n");
                retval = -1;
                ucoin_buf_free(&buf_node);
                MDB_TXN_ABORT(db.txn);
                goto LABEL_EXIT;
            }
        }
    } else {
        //新規
        upddb = true;
    }
    ucoin_buf_free(&buf_node);

    if (upddb) {
        retval = annonod_save(&db, pNodeAnno, pAnno);
        if ((retval == 0) && (pSendId != NULL)) {
            bool ret = ln_db_annonod_add_nodeid(&db_info, pAnno->p_node_id, clr, pSendId);
            if (!ret) {
                retval = -1;
            }
        }
    }

    MDB_TXN_COMMIT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annonod_search_nodeid(void *pDb, const uint8_t *pNodeId, const uint8_t *pSendId)
{
    DBG_PRINTF("node_id= ");
    DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);
    DBG_PRINTF("send_id= ");
    DUMPBIN(pSendId, UCOIN_SZ_PUBKEY);

    bool ret = false;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_NODE];

    M_ANNOINFO_NODE_SET(keydata, key, pNodeId);
    int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
    if (retval == 0) {
        DBG_PRINTF("search...\n");
        ret = annoinfo_search(&data, pSendId);
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return ret;
}


bool ln_db_annonod_add_nodeid(void *pDb, const uint8_t *pNodeId, bool bClr, const uint8_t *pSendId)
{
    bool ret = true;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_NODE];
    bool detect = false;

    M_ANNOINFO_NODE_SET(keydata, key, pNodeId);
    if (!bClr) {
        int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
        if (retval == 0) {
            detect = annoinfo_search(&data, pNodeId);
        } else {
            DBG_PRINTF("new ");
            DUMPBIN(pSendId, UCOIN_SZ_PUBKEY);
            data.mv_size = 0;
        }
    } else {
        data.mv_size = 0;
    }
    if (!detect) {
        ret = annoinfo_add(p_db, &key, &data, pSendId);
    }

    return ret;
}


bool ln_db_annonod_cur_open(void **ppCur, void *pDb)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)M_MALLOC(sizeof(lmdb_cursor_t));
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    p_cur->txn = p_db->txn;
    bool ret = annonod_cur_open(p_cur);
    if (ret) {
        *ppCur = p_cur;
    } else {
        DBG_PRINTF("err: cursor open\n");
        M_FREE(p_cur);
        *ppCur = NULL;
    }

    return ret;
}


void ln_db_annonod_cur_close(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    mdb_cursor_close(p_cur->cursor);
    M_FREE(p_cur);
}


bool ln_db_annonod_cur_get(void *pCur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    int retval = ln_lmdb_annonod_cur_load(p_cur->cursor, pBuf, pTimeStamp, pNodeId);

    return retval == 0;
}


int ln_lmdb_annonod_cur_load(MDB_cursor *cur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(cur, &key, &data, MDB_NEXT_NODUP);
    if (retval == 0) {
        // DBG_PRINTF("key:  ");
        // DUMPBIN(key.mv_data, key.mv_size);
        // DBG_PRINTF("data: ");
        // DUMPBIN(data.mv_data, data.mv_size);
        if (pNodeId) {
            memcpy(pNodeId, key.mv_data, key.mv_size);
        }
        memcpy(pTimeStamp, data.mv_data, sizeof(uint32_t));
        ucoin_buf_alloccopy(pBuf, (const uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t));
    } else {
        if (retval != MDB_NOTFOUND) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        } else {
            //end of cursor
        }
    }

    return retval;
}


/**************************************************************************
 * payment preimage
 **************************************************************************/

bool ln_db_preimg_save(const uint8_t *pPreImage, uint64_t Amount, void *pDbParam)
{
    bool ret;
    ln_lmdb_db_t db;
    MDB_val key, data;
    MDB_txn *txn = NULL;
    preimage_info_t info;

    if (pDbParam != NULL) {
        txn = ((ln_lmdb_db_t *)pDbParam)->txn;
    }
    ret = preimg_open(&db, txn);
    assert(ret);

    key.mv_size = LN_SZ_PREIMAGE;
    key.mv_data = (CONST_CAST uint8_t *)pPreImage;
    data.mv_size = sizeof(info);
    info.amount = Amount;
    info.creation = time(NULL);
    data.mv_data = &info;
    int retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval == 0) {
        DBG_PRINTF("\n");
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    preimg_close(&db, txn);

    return retval == 0;
}


bool ln_db_preimg_del(const uint8_t *pPreImage)
{
    bool ret;
    int retval = -1;
    ln_lmdb_db_t db;

    ret = preimg_open(&db, NULL);
    if (!ret) {
        DBG_PRINTF("fail: open\n");
        assert(ret);
        goto LABEL_EXIT;
    }

    if (pPreImage != NULL) {
        MDB_val key;

        DBG_PRINTF("remove: ");
        DUMPBIN(pPreImage, LN_SZ_PREIMAGE);
        key.mv_size = LN_SZ_PREIMAGE;
        key.mv_data = (CONST_CAST uint8_t *)pPreImage;
        retval = mdb_del(db.txn, db.dbi, &key, NULL);
        if (retval == 0) {
            DBG_PRINTF("\n");
        } else {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        }
    } else {
        DBG_PRINTF("remove all\n");
        retval = mdb_drop(db.txn, db.dbi, 1);
    }

    preimg_close(&db, NULL);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_preimg_del_hash(const uint8_t *pPreImageHash)
{
    int retval = -1;
    bool ret;
    lmdb_cursor_t *p_cur;
    uint8_t preimage[LN_SZ_PREIMAGE];
    uint8_t preimage_hash[LN_SZ_HASH];
    uint64_t amount;

    ret = ln_db_preimg_cur_open((void **)&p_cur);
    while (ret) {
        ret = ln_db_preimg_cur_get(p_cur, preimage, &amount);
        if (ret) {
            ln_calc_preimage_hash(preimage_hash, preimage);
            if (memcmp(preimage_hash, pPreImageHash, LN_SZ_HASH) == 0) {
                retval = mdb_cursor_del(p_cur->cursor, 0);
                break;
            }
        }
    }
    ln_db_preimg_cur_close(p_cur);

    return retval == 0;
}


bool ln_db_preimg_cur_open(void **ppCur)
{
    int         retval;
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)M_MALLOC(sizeof(lmdb_cursor_t));

    p_cur->txn = NULL;
    retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &p_cur->txn);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(p_cur->txn, M_DB_PREIMAGE, 0, &p_cur->dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(p_cur->txn, p_cur->dbi, &p_cur->cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    if (retval == 0) {
        *ppCur = p_cur;
    } else {
        if (p_cur->txn != NULL) {
            MDB_TXN_ABORT(p_cur->txn);
        }
        M_FREE(p_cur);
        *ppCur = NULL;
    }
    return retval == 0;
}


void ln_db_preimg_cur_close(void *pCur)
{
    if (pCur != NULL) {
        lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
        mdb_cursor_close(p_cur->cursor);
        if (p_cur->txn != NULL) {
            MDB_TXN_COMMIT(p_cur->txn);
        }
    }
}


bool ln_db_preimg_cur_get(void *pCur, uint8_t *pPreImage, uint64_t *pAmount)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval;
    MDB_val key, data;
    time_t now = time(NULL);

    if ((retval = mdb_cursor_get(p_cur->cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        preimage_info_t *p_info = (preimage_info_t *)data.mv_data;
        DBG_PRINTF("amount: %" PRIu64"\n", p_info->amount);
        DBG_PRINTF("time: %lu\n", p_info->creation);
        if (now <= p_info->creation + LN_INVOICE_EXPIRY) {
            memcpy(pPreImage, key.mv_data, key.mv_size);
            *pAmount = p_info->amount;

            uint8_t hash[LN_SZ_HASH];
            ln_calc_preimage_hash(hash, pPreImage);
            DBG_PRINTF2("    ");
            DUMPBIN(hash, LN_SZ_HASH);
        } else {
            //期限切れ
            DBG_PRINTF("invoice timeout del: ");
            DUMPBIN(key.mv_data, key.mv_size);
            mdb_cursor_del(p_cur->cursor, 0);
            retval = MDB_NOTFOUND;  //見つからなかったことにする
        }
    }

    return retval == 0;
}


#ifdef LN_UGLY_NORMAL
/********************************************************************
 * payment_hash
 ********************************************************************/

bool ln_db_phash_save(const uint8_t *pPayHash, const uint8_t *pVout, ln_htlctype_t Type, uint32_t Expiry, void *pDbParam)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi;
    MDB_val     key, data;

    if (pDbParam != NULL) {
        txn = ((ln_lmdb_db_t *)pDbParam)->txn;
    } else {
        retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &txn);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    }
    retval = mdb_dbi_open(txn, M_DB_PAYHASH, MDB_CREATE, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_size = M_SZ_WITPROG_WSH;
    key.mv_data = (CONST_CAST uint8_t *)pVout;
    uint8_t hash[1 + sizeof(uint32_t) + LN_SZ_HASH];
    hash[0] = (uint8_t)Type;
    memcpy(hash + 1, &Expiry, sizeof(uint32_t));
    memcpy(hash + 1 + sizeof(uint32_t), pPayHash, LN_SZ_HASH);
    data.mv_size = sizeof(hash);
    data.mv_data = hash;
    retval = mdb_put(txn, dbi, &key, &data, 0);
    if (retval == 0) {
        DBG_PRINTF("\n");
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    if ((pDbParam == NULL) && (txn != NULL)) {
        if (retval == 0) {
            MDB_TXN_COMMIT(txn);
        } else {
            MDB_TXN_ABORT(txn);
        }
    }

    return retval == 0;
}


bool ln_db_phash_search(uint8_t *pPayHash, ln_htlctype_t *pType, uint32_t *pExpiry, const uint8_t *pVout, void *pDbParam)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi;
    MDB_cursor  *cursor;
    MDB_val     key, data;
    bool found = false;

    if (pDbParam != NULL) {
        txn = ((ln_lmdb_db_t *)pDbParam)->txn;
    } else {
        retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &txn);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    }
    retval = mdb_dbi_open(txn, M_DB_PAYHASH, 0, &dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(txn, dbi, &cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    while ((retval = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        if ( (key.mv_size == M_SZ_WITPROG_WSH) &&
             (memcmp(key.mv_data, pVout, M_SZ_WITPROG_WSH) == 0) ) {
            uint8_t *p = (uint8_t *)data.mv_data;
            *pType = (ln_htlctype_t)*p;
            *pExpiry = *(uint32_t *)(p + 1);
            memcpy(pPayHash, p + 1 + sizeof(uint32_t), LN_SZ_HASH);
            found = true;
            break;
        }
    }
    mdb_cursor_close(cursor);

LABEL_EXIT:
    if ((pDbParam == NULL) && (txn != NULL)) {
        MDB_TXN_ABORT(txn);
    }

    return found;
}

#endif  //LN_UGLY_NORMAL


/**************************************************************************
 * revoked transaction用データ
 **************************************************************************/

bool ln_db_revtx_load(ln_self_t *self, void *pDbParam)
{
    MDB_val key, data;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    char        dbname[M_SZ_DBNAME_LEN];

    txn = ((ln_lmdb_db_t *)pDbParam)->txn;

    strcpy(dbname, M_REVOKED_NAME);
    misc_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    int retval = mdb_dbi_open(txn, dbname, 0, &dbi);
    if (retval != 0) {
        //DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    ln_free_revoked_buf(self);

    key.mv_size = 3;
    key.mv_data = "rvn";
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    uint16_t *p = (uint16_t *)data.mv_data;
    self->revoked_cnt = p[0];
    self->revoked_num = p[1];
    ln_alloc_revoked_buf(self);
    key.mv_data = "rvv";
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    uint8_t *p_scr = (uint8_t *)data.mv_data;
    for (int lp = 0; lp < self->revoked_num; lp++) {
        uint16_t len = *(uint16_t *)p_scr;
        p_scr += sizeof(uint16_t);
        ucoin_buf_alloccopy(&self->p_revoked_vout[lp], p_scr, len);
        p_scr += len;
    }

    key.mv_data = "rvw";
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    p_scr = (uint8_t *)data.mv_data;
    for (int lp = 0; lp < self->revoked_num; lp++) {
        uint16_t len = *(uint16_t *)p_scr;
        p_scr += sizeof(uint16_t);
        ucoin_buf_alloccopy(&self->p_revoked_wit[lp], p_scr, len);
        p_scr += len;
    }

    key.mv_data = "rvs";
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    ucoin_buf_free(&self->revoked_sec);
    ucoin_buf_alloccopy(&self->revoked_sec, data.mv_data, data.mv_size);

    key.mv_data = "rvc";
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    self->revoked_chk = *(uint32_t *)data.mv_data;

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_revtx_save(const ln_self_t *self, bool bUpdate, void *pDbParam)
{
    MDB_val key, data;
    ln_lmdb_db_t   db;
    char        dbname[M_SZ_DBNAME_LEN];
    ucoin_buf_t buf;
    ucoin_push_t push;

    ucoin_buf_init(&buf);
    db.txn = ((ln_lmdb_db_t *)pDbParam)->txn;

    strcpy(dbname, M_REVOKED_NAME);
    misc_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    int retval = mdb_dbi_open(db.txn, dbname, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_size = 3;

    key.mv_data = "rvv";
    ucoin_push_init(&push, &buf, 0);
    for (int lp = 0; lp < self->revoked_num; lp++) {
        ucoin_push_data(&push, &self->p_revoked_vout[lp].len, sizeof(uint16_t));
        ucoin_push_data(&push, self->p_revoked_vout[lp].buf, self->p_revoked_vout[lp].len);
    }
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    ucoin_buf_free(&buf);

    key.mv_data = "rvw";
    ucoin_push_init(&push, &buf, 0);
    for (int lp = 0; lp < self->revoked_num; lp++) {
        ucoin_push_data(&push, &self->p_revoked_wit[lp].len, sizeof(uint16_t));
        ucoin_push_data(&push, self->p_revoked_wit[lp].buf, self->p_revoked_wit[lp].len);
    }
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    ucoin_buf_free(&buf);

    key.mv_data = "rvs";
    data.mv_size = self->revoked_sec.len;
    data.mv_data = self->revoked_sec.buf;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_data = "rvn";
    data.mv_size = sizeof(uint16_t) * 2;
    uint16_t p[2];
    p[0] = self->revoked_cnt;
    p[1] = self->revoked_num;
    data.mv_data = p;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_data = "rvc";
    data.mv_size = sizeof(self->revoked_chk);
    data.mv_data = (CONST_CAST uint32_t *)&self->revoked_chk;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    if (bUpdate) {
        memcpy(dbname, M_CHANNEL_NAME, M_PREFIX_LEN);
        retval = mdb_dbi_open(db.txn, dbname, 0, &db.dbi);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
        retval = self_save(self, &db);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }

    }
LABEL_EXIT:
    DBG_PRINTF("retval=%d\n", retval);
    return retval == 0;
}


/**************************************************************************
 * version
 **************************************************************************/

int ln_lmdb_ver_check(ln_lmdb_db_t *pDb, uint8_t *pMyNodeId)
{
    int         retval;

    retval = mdb_dbi_open(pDb->txn, M_DB_VERSION, 0, &pDb->dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = ver_check(pDb, pMyNodeId);

LABEL_EXIT:
    return retval;
}


/********************************************************************
 * others
 ********************************************************************/

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
    } else if (strcmp(pDbName, M_DB_ANNOINFO_CNL) == 0) {
        //channel_announcement/channel_update information
        dbtype = LN_LMDB_DBTYPE_NODE_ANNOINFO;
    } else if (strcmp(pDbName, M_DB_ANNOINFO_NODE) == 0) {
        //node_announcement information
        dbtype = LN_LMDB_DBTYPE_NODE_ANNOINFO;
    } else if (strcmp(pDbName, M_DB_PREIMAGE) == 0) {
        //preimage
        dbtype = LN_LMDB_DBTYPE_PREIMAGE;
#ifdef LN_UGLY_NORMAL
    } else if (strcmp(pDbName, M_DB_PAYHASH) == 0) {
        //preimage
        dbtype = LN_LMDB_DBTYPE_PAYHASH;
#endif //LN_UGLY_NORMAL
    } else if (strcmp(pDbName, M_DB_VERSION) == 0) {
        //version
        dbtype = LN_LMDB_DBTYPE_VERSION;
    } else {
        dbtype = LN_LMDB_DBTYPE_UNKNOWN;
    }

    return dbtype;
}


/* ucoinのDB動作を借りたいために、showdbから使用される。
 *
 */
void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_anno)
{
    mpDbEnv = p_env;
    mpDbAnno = p_anno;
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
    pOutSelf->anno_flag = pInSelf->anno_flag;  //31

    //スクリプト部分(shallow copy)

    //cnl_anno
    ucoin_buf_free(&pOutSelf->cnl_anno);
    memcpy(&pOutSelf->cnl_anno, &pInSelf->cnl_anno, sizeof(ucoin_buf_t));

    //redeem_fund
    ucoin_buf_free(&pOutSelf->redeem_fund);
    memcpy(&pOutSelf->redeem_fund, &pInSelf->redeem_fund, sizeof(ucoin_buf_t));

    //shutdown_scriptpk_local
    ucoin_buf_free(&pOutSelf->shutdown_scriptpk_local);
    memcpy(&pOutSelf->shutdown_scriptpk_local, &pInSelf->shutdown_scriptpk_local, sizeof(ucoin_buf_t));

    //shutdown_scriptpk_remote
    ucoin_buf_free(&pOutSelf->shutdown_scriptpk_remote);
    memcpy(&pOutSelf->shutdown_scriptpk_remote, &pInSelf->shutdown_scriptpk_remote, sizeof(ucoin_buf_t));

    //tx_funding
    ucoin_tx_free(&pOutSelf->tx_funding);
    memcpy(&pOutSelf->tx_funding, &pInSelf->tx_funding, sizeof(ucoin_tx_t));
}


/********************************************************************
 * private functions
 ********************************************************************/

#if 0
/** channel_announcement読込み
 *
 * @param[out]      self
 * @param[in]       pDb
 * @retval      true    成功
 */
static int load_shared_secret(ln_self_t *self, ln_lmdb_db_t *pDb)
{
    int retval = 0;
    MDB_val key, data;

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        key.mv_size = sizeof(int);
        key.mv_data = &lp;
        retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
        if (retval != 0) {
            break;
        }
        ucoin_buf_alloccopy(&self->cnl_add_htlc[lp].shared_secret, data.mv_data, data.mv_size);
    }

    return retval;
}
#endif

/** channel: HTLC shared secret書込み
 *
 * @param[in]       self
 * @param[in]       pDb
 * @retval      true    成功
 */
static int self_ss_save(const ln_self_t *self, ln_lmdb_db_t *pDb)
{
    int retval = 0;
    MDB_val key, data;

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        key.mv_size = sizeof(int);
        key.mv_data = &lp;
        data.mv_size = self->cnl_add_htlc[lp].shared_secret.len;
        data.mv_data = self->cnl_add_htlc[lp].shared_secret.buf;
        retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
        if (retval != 0) {
            break;
        }
    }

    return retval;
}


/** channel情報書き込み
 *
 * @param[in]       self
 * @param[in,out]   pDb
 * @retval      true    成功
 */
static int self_save(const ln_self_t *self, ln_lmdb_db_t *pDb)
{
    MDB_val key, data;

    //構造体部分
    backup_self_t *bk = (backup_self_t *)M_MALLOC(sizeof(backup_self_t));

    memset(bk, 0, sizeof(backup_self_t));
    bk->lfeature_remote = self->lfeature_remote;     //3
    bk->storage_index = self->storage_index;     //5
    memcpy(bk->storage_seed, self->storage_seed, UCOIN_SZ_PRIVKEY);      //6

    //bk->funding_local = self->funding_local;     //7
    memcpy(bk->funding_local_txid, self->funding_local.txid, UCOIN_SZ_TXID);    //7.1
    bk->funding_local_txindex = self->funding_local.txindex;        //7.2
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        memcpy(bk->funding_local_privkey[lp], self->funding_local.keys[lp].priv, UCOIN_SZ_PRIVKEY);     //7.3
    }

    //bk->funding_remote = self->funding_remote;       //8
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        memcpy(bk->funding_remote_pubkey[lp], self->funding_remote.pubkeys[lp], UCOIN_SZ_PUBKEY);       //8.1
    }
    memcpy(bk->funding_remote_prev_percommit, self->funding_remote.prev_percommit, UCOIN_SZ_PUBKEY);    //8.2

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
    bk->anno_flag = self->anno_flag;    //31

    key.mv_size = 6;
    key.mv_data = "self1";
    data.mv_size = sizeof(backup_self_t);
    data.mv_data = bk;
    int retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    M_FREE(bk);

    //スクリプト部分
    if (retval == 0) {
        ucoin_buf_t buf_bk;
        ucoin_buf_t buf_funding;

        ucoin_buf_init(&buf_bk);
        ucoin_buf_init(&buf_funding);
        ucoin_tx_create(&buf_funding, &self->tx_funding);

        size_t sz = sizeof(uint16_t) + self->cnl_anno.len +
                        sizeof(uint16_t) + self->redeem_fund.len +
                        sizeof(uint16_t) + self->shutdown_scriptpk_local.len +
                        sizeof(uint16_t) + self->shutdown_scriptpk_remote.len +
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
        //shutdown_scriptpk_local
        len = self->shutdown_scriptpk_local.len;
        ucoin_push_data(&ps, &len, sizeof(len));
        ucoin_push_data(&ps, self->shutdown_scriptpk_local.buf, len);
        //shutdown_scriptpk_remote
        len = self->shutdown_scriptpk_remote.len;
        ucoin_push_data(&ps, &len, sizeof(len));
        ucoin_push_data(&ps, self->shutdown_scriptpk_remote.buf, len);

        //buf_funding
        len = buf_funding.len;
        ucoin_push_data(&ps, &len, sizeof(len));
        ucoin_push_data(&ps, buf_funding.buf, len);
        ucoin_buf_free(&buf_funding);

        key.mv_size = 6;
        key.mv_data = "self2";
        data.mv_size = buf_bk.len;
        data.mv_data = buf_bk.buf;
        retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);

        ucoin_buf_free(&buf_bk);
    }
    if (retval != 0) {
        DBG_PRINTF("retval=%d\n", retval);
    }

    return retval;
}


/** channel_announcement読込み
 *
 * @param[in]       pDb
 * @param[out]      pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
static int annocnl_load(ln_lmdb_db_t *pDb, ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    DBG_PRINTF("short_channel_id=%016" PRIx64 "\n", ShortChannelId);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL];

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, LN_DB_CNLANNO_ANNO);
    int retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
    if (retval == 0) {
        ucoin_buf_alloccopy(pCnlAnno, data.mv_data, data.mv_size);
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return retval;
}


/** channel_announcement書込み
 *
 * @param[in,out]   pDb
 * @param[in]       pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
static int annocnl_save(ln_lmdb_db_t *pDb, const ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    //DBG_PRINTF("short_channel_id=%016" PRIx64 "\n", ShortChannelId);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL];

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, LN_DB_CNLANNO_ANNO);
    data.mv_size = pCnlAnno->len;
    data.mv_data = pCnlAnno->buf;
    int retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return retval;
}


/** lmdb cursorオープン(channel_announcement系)
 *
 * @note
 *      - pCur->txnは設定済みであること
 */
static bool annocnl_cur_open(lmdb_cursor_t *pCur)
{
    int retval;

    retval = mdb_dbi_open(pCur->txn, M_DB_ANNO_CNL, 0, &pCur->dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(pCur->txn, pCur->dbi, &pCur->cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    return retval == 0;
}


#if 0
/** lmdb channel_announcement系検索
 *
 */
static bool annocnl_search(lmdb_cursor_t *pCur, uint64_t ShortChannelId, ucoin_buf_t *pBuf, char Type)
{
    int retval;
    MDB_val key, data;

    ucoin_buf_init(pBuf);
    while ((retval = mdb_cursor_get(pCur->cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            uint64_t load_sci;
            memcpy(&load_sci, key.mv_data, LN_SZ_SHORT_CHANNEL_ID);
            if ((load_sci == ShortChannelId) && (*(char *)((uint8_t *)key.mv_data + LN_SZ_SHORT_CHANNEL_ID) == Type)) {
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
 * @param[in]       pDb
 * @param[out]      pCnlAnno
 * @param[out]      pTimeStamp          保存しているchannel_updateのTimeStamp
 * @param[in]       ShortChannelId
 * @param[in]       Dir                 0:node_1, 1:node_2
 * @retval      true    成功
 */
static int annocnlupd_load(ln_lmdb_db_t *pDb, ucoin_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir)
{
    DBG_PRINTF("short_channel_id=%016" PRIx64 ", dir=%d\n", ShortChannelId, Dir);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL];

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, ((Dir) ?  LN_DB_CNLANNO_UPD2 : LN_DB_CNLANNO_UPD1));
    int retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
    if (retval == 0) {
        *pTimeStamp = *(uint32_t *)data.mv_data;
        ucoin_buf_alloccopy(pCnlUpd, (uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t));
    } else {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return retval;
}


/** channel_update書込み
 *
 * @param[in,out]   pDb
 * @param[in]       pCnlAnno
 * @param[in]       pUpd
 * @retval      true    成功
 */
static int annocnlupd_save(ln_lmdb_db_t *pDb, const ucoin_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd)
{
    DBG_PRINTF("short_channel_id=%016" PRIx64 ", dir=%d\n", pUpd->short_channel_id, ln_cnlupd_direction(pUpd));

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL];

    M_ANNOINFO_CNL_SET(keydata, key, pUpd->short_channel_id, (ln_cnlupd_direction(pUpd) ?  LN_DB_CNLANNO_UPD2 : LN_DB_CNLANNO_UPD1));
    ucoin_buf_t buf;
    ucoin_buf_alloc(&buf, sizeof(uint32_t) + pCnlUpd->len);

    //timestamp + channel_update
    memcpy(buf.buf, &pUpd->timestamp, sizeof(uint32_t));
    memcpy(buf.buf + sizeof(uint32_t), pCnlUpd->buf, pCnlUpd->len);
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    int retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }
    ucoin_buf_free(&buf);

    return retval;
}


/* node_announcement取得
 *
 * @param[in,out]   pDb
 * @param[out]      pNodeAnno       (非NULL時)取得したnode_announcement
 * @param[out]      pTimeStamp      (非NULL時)タイムスタンプ
 * @paramin]        pNodeId         検索するnode_id
 * @retval      true
 */
static int annonod_load(ln_lmdb_db_t *pDb, ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId)
{
    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_NODE];

    M_ANNOINFO_NODE_SET(keydata, key, pNodeId);
    int retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
    if (retval == 0) {
        if (pTimeStamp != NULL) {
            *pTimeStamp = *(uint32_t *)data.mv_data;
        }
        if (pNodeAnno != NULL) {
            ucoin_buf_alloccopy(pNodeAnno, (uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t));
        }
    } else {
        //DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

    return retval;
}


/* node_announcement書込み
 *
 * @param[in,out]   pDb
 * @param[in]       pNodeAnno       node_announcementパケット
 * @param[in]       pAnno           node_announcement構造体
 * @retval      true
 */
static int annonod_save(ln_lmdb_db_t *pDb, const ucoin_buf_t *pNodeAnno, const ln_node_announce_t *pAnno)
{
    DBG_PRINTF("node_id=");
    DUMPBIN(pAnno->p_node_id, UCOIN_SZ_PUBKEY);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_NODE];

    M_ANNOINFO_NODE_SET(keydata, key, pAnno->p_node_id);
    ucoin_buf_t buf;
    ucoin_buf_alloc(&buf, sizeof(uint32_t) + pNodeAnno->len);

    //timestamp + node_announcement
    memcpy(buf.buf, &pAnno->timestamp, sizeof(uint32_t));
    memcpy(buf.buf + sizeof(uint32_t), pNodeAnno->buf, pNodeAnno->len);
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    int retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }
    ucoin_buf_free(&buf);

    return retval;
}


/** annoinfoにnode_idを追加(channel, node共通)
 *
 * @param[in,out]   pDb         annoinfo
 * @param[in]       pMdbKey     loadしたchannel_announcement infoのkey
 * @param[in]       pMdbData    loadしたchannel_announcement infoのdata
 * @param[in]       pNodeId     追加するnode_id
 */
static bool annoinfo_add(ln_lmdb_db_t *pDb, MDB_val *pMdbKey, MDB_val *pMdbData, const uint8_t *pNodeId)
{
    int nums = pMdbData->mv_size / UCOIN_SZ_PUBKEY;
for (int lp = 0; lp < nums; lp++) {
    DBG_PRINTF("[%d]", lp);
    DUMPBIN(pMdbData->mv_data + lp * UCOIN_SZ_PUBKEY, UCOIN_SZ_PUBKEY);
}

    uint8_t *p_ids = (uint8_t *)M_MALLOC((nums + 1) * UCOIN_SZ_PUBKEY);
    memcpy(p_ids, pMdbData->mv_data, pMdbData->mv_size);
    memcpy(p_ids + pMdbData->mv_size, pNodeId, UCOIN_SZ_PUBKEY);

    pMdbData->mv_data = p_ids;
    pMdbData->mv_size += UCOIN_SZ_PUBKEY;
    int retval = mdb_put(pDb->txn, pDb->dbi, pMdbKey, pMdbData, 0);
    if (retval == 0) {
        DBG_PRINTF("add node: ");
        DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);
    } else {
        DBG_PRINTF("fail\n");
    }
    M_FREE(p_ids);

    return retval == 0;
}


/** annoinfoからnode_idの有無を検索(channel, node共通)
 *
 * @param[in]   pMdbData
 * @param[in]   pNodeId
 * @retval  true    検出
 */
static bool annoinfo_search(MDB_val *pMdbData, const uint8_t *pNodeId)
{
    int nums = pMdbData->mv_size / UCOIN_SZ_PUBKEY;
    DBG_PRINTF("nums=%d\n", nums);
    DBG_PRINTF("search id: ");
    DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);
    int lp;
    for (lp = 0; lp < nums; lp++) {
        DBG_PRINTF("  node_id[%d]= ", lp);
        DUMPBIN(pMdbData->mv_data + UCOIN_SZ_PUBKEY * lp, UCOIN_SZ_PUBKEY);
        if (memcmp((uint8_t *)pMdbData->mv_data + UCOIN_SZ_PUBKEY * lp, pNodeId, UCOIN_SZ_PUBKEY) == 0) {
            break;
        }
    }

    return lp < nums;
}


#if 0
/** annoinfoをクリア(channel, node共通)
 *
 * @param[in,out]   pDb         annoinfo
 */
static void annoinfo_clear(ln_lmdb_db_t *pDb)
{
    int retval = mdb_drop(pDb->txn, pDb->dbi, 0);
    if (retval == 0) {
        DBG_PRINTF("clear\n");
    } else {
        DBG_PRINTF("fail\n");
    }
}
#endif


/** lmdb cursorオープン(node_announcement)
 *
 */
static bool annonod_cur_open(lmdb_cursor_t *pCur)
{
    int retval;

    retval = mdb_dbi_open(pCur->txn, M_DB_ANNO_NODE, 0, &pCur->dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(pCur->txn, pCur->dbi, &pCur->cursor);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    return retval == 0;
}


static bool preimg_open(ln_lmdb_db_t *p_db, MDB_txn *txn)
{
    int retval;

    if (txn == NULL) {
        retval = MDB_TXN_BEGIN(mpDbEnv, NULL, 0, &p_db->txn);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    } else {
        p_db->txn = txn;
    }
    retval = mdb_dbi_open(p_db->txn, M_DB_PREIMAGE, MDB_CREATE, &p_db->dbi);
    if (retval != 0) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(p_db->txn);
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    return retval == 0;
}


static void preimg_close(ln_lmdb_db_t *p_db, MDB_txn *txn)
{
    if (txn == NULL) {
        MDB_TXN_COMMIT(p_db->txn);
    }
}


static int ver_write(MDB_txn *txn, const uint8_t *pMyNodeId)
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
    } else if (retval) {
        DBG_PRINTF("err: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    return retval;
}


/** DBバージョンチェック
 *
 * @param[in,out]   pDb
 * @param[out]      pMyNodeId   [NULL]無視 / [非NULL]自nodeid
 * @retval  0   DBバージョン一致
 */
static int ver_check(ln_lmdb_db_t *pDb, uint8_t *pMyNodeId)
{
    int         retval;
    MDB_val key, data;

    //version
    key.mv_size = 3;
    key.mv_data = "ver";
    retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
    if (retval == 0) {
        int version = *(int *)data.mv_data;
        if (version != M_DB_VERSION_VAL) {
            DBG_PRINTF("FAIL: version mismatch : %d(require %d)\n", version, M_DB_VERSION_VAL);
            retval = -1;
        }
    }
    if (retval == 0) {
        if (pMyNodeId) {
            key.mv_size = 8;
            key.mv_data = "mynodeid";
            retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
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
