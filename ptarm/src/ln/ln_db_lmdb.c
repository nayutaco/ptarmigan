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
#include <sys/stat.h>
#include <sys/types.h>

#include "ln_local.h"
#include "ln_msg_anno.h"
#include "ln_misc.h"
#include "ln_node.h"
#include "ln_signer.h"

#include "ln_db.h"
#include "ln_db_lmdb.h"


//#define M_DB_DEBUG

/********************************************************************
 * macros
 ********************************************************************/

#define M_LMDB_MAXDBS           (2 * 10)        ///< 同時オープンできるDB数
#define M_LMDB_MAPSIZE          ((size_t)10485760)          // DB最大長[byte](LMDBのデフォルト値)

#define M_LMDB_NODE_MAXDBS      (2 * 10)        ///< 同時オープンできるDB数
#define M_LMDB_NODE_MAPSIZE     ((size_t)134217728)         // DB最大長[byte](mdb_txn_commit()でMDB_MAP_FULLになったため拡張)
                                                            // 32bit環境ではsize_tが4byteになるため、4294967295が最大になる
#define M_DBPATH_MAX            (256)
#define M_DBDIR                 "dbptarm"
#define M_SELFENV_DIR           "dbptarm_self"
#define M_NODEENV_DIR           "dbptarm_node"


#define M_SELF_BUFS             (3)             ///< DB保存する可変長データ数

#define M_PREFIX_LEN            (2)
#define M_PREF_CHANNEL          "CN"            ///< channel
#define M_PREF_SECRET           "SE"            ///< secret
#define M_PREF_ADDHTLC          "HT"            ///< update_add_htlc関連
#define M_PREF_REVOKED          "RV"            ///< revoked transaction用
#define M_PREF_BAKCHANNEL       "cn"            ///< closed channel

#define M_DBI_ANNO_CNL          "channel_anno"
#define M_DBI_ANNOINFO_CNL      "channel_annoinfo"
#define M_DBI_ANNO_NODE         "node_anno"
#define M_DBI_ANNOINFO_NODE     "node_annoinfo"
#define M_DBI_ANNOINFO_CHAN     "chan_annoinfo"
#define M_DBI_ANNO_SKIP         LNDB_DBI_ANNO_SKIP
#define M_DBI_ANNO_INVOICE      "route_invoice"
#define M_DBI_PREIMAGE          "preimage"
#define M_DBI_PAYHASH           "payhash"
#define M_DBI_VERSION           "version"

#define M_SZ_DBNAME_LEN         (M_PREFIX_LEN + LN_SZ_CHANNEL_ID * 2)
#define M_SZ_HTLC_STR           (3)
#define M_SZ_ANNOINFO_CNL       (sizeof(uint64_t))
#define M_SZ_ANNOINFO_NODE      (PTARM_SZ_PUBKEY)

#define M_KEY_SHAREDSECRET      "shared_secret"
#define M_SZ_SHAREDSECRET       (sizeof(M_KEY_SHAREDSECRET) - 1)

#define M_SKIP_TEMP             ((uint8_t)1)

#define M_DB_VERSION_VAL        ((int32_t)-20)      ///< DBバージョン
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
    -15: node.conf情報をversionに追加
    -16: selfはmpDbEnv、それ以外はmpDbNodeEnvにする
    -17: selfの構造体を個別に保存する
         selfのsecret情報をself.priv_dataに集約
    -18: node_announcement除外用DB追加(annoinfo_chan)
    -18: [SPVのみ]funding_txのblock hash追加
    -19: revocation_number追加
    -20: current_commit_num追加、scriptpubkeys削除
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
    memcpy(keydata, node_id, PTARM_SZ_PUBKEY);\
}

#define M_SIZE(type, mem)       (sizeof(((type *)0)->mem))
#define M_ITEM(type, mem)       { #mem, M_SIZE(type, mem), offsetof(type, mem) }
#define MM_ITEM(type1, mem1, type2, mem2) \
                                { #mem1 "." #mem2, M_SIZE(type2, mem2), offsetof(type1, mem1) + offsetof(type2, mem2) }
#define MMN_ITEM(type1, mem1, n, type2, mem2) \
                                { #mem1 "." #mem2 ":" #n, M_SIZE(type2, mem2), offsetof(type1, mem1) + sizeof(type2) * n + offsetof(type2, mem2) }
#define M_BUF_ITEM(idx, mem)    { p_dbscript_keys[idx].name = #mem; p_dbscript_keys[idx].p_buf = (CONST_CAST ptarm_buf_t*)&self->mem; }

#ifndef M_DB_DEBUG
#define MDB_TXN_BEGIN(a,b,c,d)      mdb_txn_begin(a, b, c, d)
#define MDB_TXN_ABORT(a)            mdb_txn_abort(a)
#define MDB_TXN_COMMIT(a)           int txn_retval = mdb_txn_commit(a); if (txn_retval) {LOGD("ERR: %s\n", mdb_strerror(txn_retval));}
#else
static volatile int g_cnt[2];
#define MDB_TXN_BEGIN(a,b,c,d)      my_mdb_txn_begin(a,b,c,d, __LINE__);
#define MDB_TXN_ABORT(a)            my_mdb_txn_abort(a, __LINE__)
#define MDB_TXN_COMMIT(a)           my_mdb_txn_commit(a, __LINE__)
#endif

#define M_DEBUG_KEYS
#define M_SIZE(type, mem)       (sizeof(((type *)0)->mem))


/********************************************************************
 * typedefs
 ********************************************************************/

// ln_self_tのバックアップ
typedef struct backup_param_t {
    const char  *name;
    size_t      datalen;
    size_t      offset;
} backup_param_t;


typedef struct backup_buf_t {
    const char  *name;
    ptarm_buf_t *p_buf;
} backup_buf_t;


/** @typedef    nodeinfo_t
 *  @brief      [version]に保存するnode情報
 */
typedef struct {
    uint8_t     genesis[LN_SZ_HASH];
    char        wif[PTARM_SZ_WIF_MAX];
    char        name[LN_SZ_ALIAS];
    uint16_t    port;
} nodeinfo_t;


/** @typedef    preimg_info_t
 *  @brief      [preimage]に保存するpreimage情報
 */
typedef struct {
    uint64_t amount;            ///< amount[satoshi]
    uint64_t creation;          ///< invoice creation epoch
    uint32_t expiry;            ///< expiry[sec]
                                //      0: 3600s=1h(BOLT#11のデフォルト値)
                                //      UINT32_MAX: expiryによる自動削除禁止
} preimg_info_t;


/** #ln_db_self_del_prm()用(ln_db_preimg_search)
 *
 */
typedef struct {
    const ln_update_add_htlc_t  *add_htlc;
} preimg_close_t;


/********************************************************************
 * static variables
 ********************************************************************/

//LMDB
static MDB_env      *mpDbSelf = NULL;           // channel
static MDB_env      *mpDbNode = NULL;           // node
static char         mPath[M_DBPATH_MAX];
static char         mPathSelf[M_DBPATH_MAX];
static char         mPathNode[M_DBPATH_MAX];


static const backup_param_t DBSELF_SECRET[] = {
    M_ITEM(ln_self_priv_t, storage_index),
    M_ITEM(ln_self_priv_t, storage_seed),
    M_ITEM(ln_self_priv_t, priv),
};


static const backup_param_t DBSELF_KEYS[] = {
    M_ITEM(ln_self_t, peer_node_id),
    M_ITEM(ln_self_t, status),
    M_ITEM(ln_self_t, peer_storage),            //ln_derkey_storage
                                                //      {
                                                //          uint8[]
                                                //          uint64
                                                //      }[]
    M_ITEM(ln_self_t, peer_storage_index),
    M_ITEM(ln_self_t, fund_flag),

    //M_ITEM(ln_self_t, funding_local),           //ln_funding_local_data_t(outpoint, privkey)
    MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, txid),
    MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, txindex),
    MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, pubkeys),
    //MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, scriptpubkeys),
    MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, current_commit_num),

    //M_ITEM(ln_self_t, funding_remote),          //ln_funding_remote_data_t(pubkey, percommit)
    MM_ITEM(ln_self_t, funding_remote, ln_funding_remote_data_t, pubkeys),
    MM_ITEM(ln_self_t, funding_remote, ln_funding_remote_data_t, prev_percommit),
    //MM_ITEM(ln_self_t, funding_remote, ln_funding_remote_data_t, scriptpubkeys),
    MM_ITEM(ln_self_t, funding_remote, ln_funding_remote_data_t, current_commit_num),

    M_ITEM(ln_self_t, obscured),
    //redeem_fund --> none
    //key_fund_sort --> none
    //tx_funding --> script
#ifndef USE_SPV
#else
    M_ITEM(ln_self_t, funding_bhash),
#endif
    //flck_flag: none
    //p_establish: none
    M_ITEM(ln_self_t, min_depth),
    M_ITEM(ln_self_t, anno_flag),
    //anno_prm: none
    //cnl_anno --> none
    //init_flag: none
    M_ITEM(ln_self_t, lfeature_remote),
    //tx_closing: none
    //shutdown_flag: none
    //close_fee_sat: none
    //close_last_fee_sat: none
    //shutdown_scriptpk_local --> script
    //shutdown_scriptpk_remote --> script
    //cnl_closing_singed: none

    //p_revoked_vout --> revoked db
    //p_revoked_wit  --> revoked db
    //p_revoked_type: --> revoked db
    //revoked_sec: --> revoked db
    //revoked_num: --> revoked db
    //revoked_cnt: --> revoked db
    //revoked_chk --> revoked db

    M_ITEM(ln_self_t, htlc_num),
    M_ITEM(ln_self_t, htlc_id_num),
    M_ITEM(ln_self_t, our_msat),
    M_ITEM(ln_self_t, their_msat),
    M_ITEM(ln_self_t, channel_id),
    M_ITEM(ln_self_t, short_channel_id),
    //M_ITEM(ln_self_t, cnl_add_htlc),            //ln_update_add_htlc_t
    //missing_pong_cnt: none
    //last_num_pong_bytes: none

    //M_ITEM(ln_self_t, commit_local),            //ln_commit_data_t
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, dust_limit_sat),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, max_htlc_value_in_flight_msat),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, channel_reserve_sat),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, htlc_minimum_msat),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, to_self_delay),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, max_accepted_htlcs),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, signature),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, txid),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, htlc_num),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, commit_num),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, revoke_num),
    //M_ITEM(ln_self_t, commit_remote),           //ln_commit_data_t
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, dust_limit_sat),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, max_htlc_value_in_flight_msat),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, channel_reserve_sat),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, htlc_minimum_msat),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, to_self_delay),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, max_accepted_htlcs),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, signature),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, txid),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, htlc_num),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, commit_num),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, revoke_num),

    M_ITEM(ln_self_t, funding_sat),
    M_ITEM(ln_self_t, feerate_per_kw),
};


// DBCOPY_KEYS[]とDBCOPY_IDX[]を同時に更新すること
static const backup_param_t DBCOPY_KEYS[] = {
    M_ITEM(ln_self_t, peer_node_id),
    M_ITEM(ln_self_t, channel_id),
    M_ITEM(ln_self_t, short_channel_id),
    M_ITEM(ln_self_t, our_msat),
    M_ITEM(ln_self_t, their_msat),
    MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, txid),
    MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, txindex),
    MM_ITEM(ln_self_t, funding_local, ln_funding_local_data_t, pubkeys),
    MM_ITEM(ln_self_t, funding_remote, ln_funding_remote_data_t, pubkeys),
    MM_ITEM(ln_self_t, funding_remote, ln_funding_remote_data_t, prev_percommit),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, commit_num),
    MM_ITEM(ln_self_t, commit_local, ln_commit_data_t, revoke_num),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, commit_num),
    MM_ITEM(ln_self_t, commit_remote, ln_commit_data_t, revoke_num),
};
static const struct {
    enum {
        ETYPE_BYTEPTR,      //const uint8_t*
        ETYPE_UINT64U,      //uint64_t(unsigned decimal)
        ETYPE_UINT64X,      //uint64_t(unsigned hex)
        ETYPE_UINT16,       //uint16_t
        ETYPE_TXID,         //txid
        ETYPE_FUNDTXID,     //funding_local.txid
        ETYPE_FUNDTXIDX,    //funding_local.txindex
        ETYPE_LOCALKEYS,    //funding_local.keys
        ETYPE_REMOTEKEYS,   //funding_remote.publickeys
        ETYPE_REMOTECOMM,   //funding_remote.prev_percommit
    } type;
    int length;
    bool disp;
} DBCOPY_IDX[] = {
    { ETYPE_BYTEPTR,    PTARM_SZ_PUBKEY, true },    // peer_node_id
    { ETYPE_BYTEPTR,    LN_SZ_CHANNEL_ID, true },   // channel_id
    { ETYPE_UINT64X,    1, true },                  // short_channel_id
    { ETYPE_UINT64U,    1, true },                  // our_msat
    { ETYPE_UINT64U,    1, true },                  // their_msat
    { ETYPE_FUNDTXID,   PTARM_SZ_TXID, true },      // funding_local.txid
    { ETYPE_FUNDTXIDX,  1, true },                  // funding_local.txindex
    { ETYPE_LOCALKEYS,  1, false },                 // funding_local.pubkeys
    { ETYPE_REMOTEKEYS, 1, false },                 // funding_remote.pubkeys
    { ETYPE_REMOTECOMM, 1, false },                 // funding_remote.prev_percommit
    { ETYPE_UINT64U,    1, true },                  // commit_local.commit_num
    { ETYPE_UINT64U,    1, true },                  // commit_local.revoke_num
    { ETYPE_UINT64U,    1, true },                  // commit_remote.commit_num
    { ETYPE_UINT64U,    1, true },                  // commit_remote.revoke_num
};


static const backup_param_t DBHTLC_KEYS[] = {
    M_ITEM(ln_update_add_htlc_t, id),
    M_ITEM(ln_update_add_htlc_t, amount_msat),
    M_ITEM(ln_update_add_htlc_t, cltv_expiry),
    M_ITEM(ln_update_add_htlc_t, payment_sha256),
    M_ITEM(ln_update_add_htlc_t, flag),
    M_ITEM(ln_update_add_htlc_t, signature),
    M_ITEM(ln_update_add_htlc_t, prev_short_channel_id),
    M_ITEM(ln_update_add_htlc_t, prev_id),
};


//tx_funding
//shutdown_scriptpk_local
//shutdown_scriptpk_remote


/********************************************************************
 * prototypes
 ********************************************************************/

static int self_addhtlc_load(ln_self_t *self, ln_lmdb_db_t *pDb);
static int self_addhtlc_save(const ln_self_t *self, ln_lmdb_db_t *pDb);

static int self_save(const ln_self_t *self, ln_lmdb_db_t *pDb);

static int secret_load(ln_self_t *self, ln_lmdb_db_t *pDb);

static int annocnl_load(ln_lmdb_db_t *pDb, ptarm_buf_t *pCnlAnno, uint64_t ShortChannelId);
static int annocnl_save(ln_lmdb_db_t *pDb, const ptarm_buf_t *pCnlAnno, uint64_t ShortChannelId);
static bool annocnl_cur_open(lmdb_cursor_t *pCur);
//static bool annocnl_search(lmdb_cursor_t *pCur, uint64_t ShortChannelId, ptarm_buf_t *pBuf, char Type);

static int annocnlupd_load(ln_lmdb_db_t *pDb, ptarm_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir);
static int annocnlupd_save(ln_lmdb_db_t *pDb, const ptarm_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd);

static int annonod_load(ln_lmdb_db_t *pDb, ptarm_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);
static int annonod_save(ln_lmdb_db_t *pDb, const ptarm_buf_t *pNodeAnno, const uint8_t *pNodeId, uint32_t Timestamp);
static bool annonod_cur_open(lmdb_cursor_t *pCur);

static bool annoinfo_add(ln_lmdb_db_t *pDb, MDB_val *pMdbKey, MDB_val *pMdbData, const uint8_t *pNodeId);
static bool annoinfo_search(MDB_val *pMdbData, const uint8_t *pNodeId);
static void annoinfo_trim(MDB_cursor *pCursor, const uint8_t *pNodeId);

static bool preimg_open(ln_lmdb_db_t *p_db, MDB_txn *txn);
static void preimg_close(ln_lmdb_db_t *p_db, MDB_txn *txn);
static bool preimg_del_func(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);
static bool preimg_close_func(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);

static int ver_write(ln_lmdb_db_t *pDb, const char *pWif, const char *pNodeName, uint16_t Port);
static int ver_check(ln_lmdb_db_t *pDb, char *pWif, char *pNodeName, uint16_t *pPort, uint8_t *pGenesis);

static void addhtlc_dbname(char *pDbName, int num);
static bool comp_func_cnldel(ln_self_t *self, void *p_db_param, void *p_param);

static int self_cursor_open(lmdb_cursor_t *pCur);
static void self_cursor_close(lmdb_cursor_t *pCur);

static int backup_param_load(void *pData, ln_lmdb_db_t *pDb, const backup_param_t *pParam, size_t Num);
static int backup_param_save(const void *pData, ln_lmdb_db_t *pDb, const backup_param_t *pParam, size_t Num);

static int initialize_dbself(void);
static int initialize_dbnode(void);

#ifdef M_DB_DEBUG
static inline int my_mdb_txn_begin(MDB_env *env, MDB_txn *parent, unsigned int flags, MDB_txn **txn, int line) {
    int ggg = (env == mpDbSelf) ? 0 : 1;
    g_cnt[ggg]++;
    LOGD("mdb_txn_begin:%d:[%d]%d(%d)\n", line, ggg, g_cnt[ggg], (int)flags);
    if ((ggg == 1) && (g_cnt[ggg] > 1)) {
        LOGD("multi txs\n");
    }
    return mdb_txn_begin(env, parent, flags, txn);
}

static inline int my_mdb_txn_commit(MDB_txn *txn, int line) {
    int ggg = (mdb_txn_env(txn) == mpDbSelf) ? 0 : 1;
    g_cnt[ggg]--;
    LOGD("mdb_txn_commit:%d:[%d]%d\n", line, ggg, g_cnt[ggg]);
    int txn_retval = mdb_txn_commit(txn);
    if (txn_retval) {
        LOGD("ERR: %s\n", mdb_strerror(txn_retval));
    }
    return txn_retval;
}

static inline void my_mdb_txn_abort(MDB_txn *txn, int line) {
    int ggg = (mdb_txn_env(txn) == mpDbSelf) ? 0 : 1;
    g_cnt[ggg]--;
    LOGD("mdb_txn_abort:%d:[%d]%d\n", line, ggg, g_cnt[ggg]);
    mdb_txn_abort(txn);
}

#endif  //M_DB_DEBUG


/********************************************************************
 * public functions
 ********************************************************************/

void ln_lmdb_set_path(const char *pPath)
{
    char path[M_DBPATH_MAX];

    strcpy(path, pPath);
    size_t len = strlen(path);
    if (path[len - 1] == '/') {
        path[len - 1] = '\0';
    }
    sprintf(mPath, "%s/%s", path, M_DBDIR);
    sprintf(mPathSelf, "%s/%s", mPath, M_SELFENV_DIR);
    sprintf(mPathNode, "%s/%s", mPath, M_NODEENV_DIR);

    LOGD("db dir: %s\n", mPath);
    LOGD("  self: %s\n", mPathSelf);
    LOGD("  node: %s\n", mPathNode);
}


const char *ln_lmdb_get_selfpath(void)
{
    return mPathSelf;
}


const char *ln_lmdb_get_nodepath(void)
{
    return mPathNode;
}


bool HIDDEN ln_db_init(char *pWif, char *pNodeName, uint16_t *pPort)
{
    int         retval;
    ln_lmdb_db_t   db;

    //lmdbのopenは複数呼ばないでenvを共有する
    if (mpDbSelf == NULL) {
        retval = initialize_dbself();
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }

        retval = initialize_dbnode();
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    } else {
        LOGD("FATAL: already initialized\n");
        abort();
    }

    retval = MDB_TXN_BEGIN(mpDbSelf, NULL, 0, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_VERSION, 0, &db.dbi);
    if (retval != 0) {
        //新規の場合は作成/保存する
        //      node_id : 生成
        //      aliase : 指定が無ければ生成
        //      port : 指定された値
        LOGD("create node DB\n");
        uint8_t pub[PTARM_SZ_PUBKEY];
        ln_node_create_key(pWif, pub);

        char nodename[LN_SZ_ALIAS + 1];
        if (pNodeName == NULL) {
            pNodeName = nodename;
            nodename[0] = '\0';
        }
        if (strlen(pNodeName) == 0) {
            sprintf(pNodeName, "node_%02x%02x%02x%02x%02x%02x",
                        pub[0], pub[1], pub[2], pub[3], pub[4], pub[5]);
        }
        //LOGD("wif=%s\n", pWif);
        LOGD("aliase=%s\n", pNodeName);
        LOGD("port=%d\n", *pPort);
        retval = ver_write(&db, pWif, pNodeName, *pPort);
        if (retval != 0) {
            LOGD("FAIL: create version db\n");
            MDB_TXN_ABORT(db.txn);
            goto LABEL_EXIT;
        }
    }

    uint8_t genesis[LN_SZ_HASH];
    retval = ver_check(&db, pWif, pNodeName, pPort, genesis);
    MDB_TXN_COMMIT(db.txn);
    if (retval == 0) {
        //LOGD("wif=%s\n", pWif);
        LOGD("aliase=%s\n", pNodeName);
        LOGD("port=%d\n", *pPort);

        retval = memcmp(gGenesisChainHash, genesis, LN_SZ_HASH);
    }
    if (retval == 0) {
        ptarm_genesis_t gtype = ptarm_util_get_genesis(genesis);
        switch (gtype) {
        case PTARM_GENESIS_BTCMAIN:
            LOGD("chainhash: bitcoin mainnet\n");
            break;
        case PTARM_GENESIS_BTCTEST:
            LOGD("chainhash: bitcoin testnet\n");
            break;
        case PTARM_GENESIS_BTCREGTEST:
            LOGD("chainhash: bitcoin regtest\n");
            break;
        default:
            LOGD("chainhash: unknown chainhash\n");
            break;
        }
    } else {
        LOGD("FAIL: check version db\n");
        goto LABEL_EXIT;
    }
    ln_db_invoice_drop();
    ln_db_annocnl_del_orphan();

LABEL_EXIT:
    if (retval != 0) {
        ln_db_term();
    }

    return retval == 0;
}


void ln_db_term(void)
{
    mdb_env_close(mpDbNode);
    mpDbNode = NULL;
    mdb_env_close(mpDbSelf);
    mpDbSelf = NULL;
}


/********************************************************************
 * self
 ********************************************************************/

int ln_lmdb_self_load(ln_self_t *self, MDB_txn *txn, MDB_dbi dbi)
{
    int         retval;
    MDB_val     key, data;
    ln_lmdb_db_t db;

    //固定サイズ
    db.txn = txn;
    db.dbi = dbi;
    retval = backup_param_load(self, &db, DBSELF_KEYS, ARRAY_SIZE(DBSELF_KEYS));
    if (retval != 0) {
        goto LABEL_EXIT;
    }

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        self->cnl_add_htlc[idx].p_channel_id = NULL;
        self->cnl_add_htlc[idx].p_onion_route = NULL;
        ptarm_buf_init(&self->cnl_add_htlc[idx].shared_secret);
    }

    //復元データからさらに復元
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ptarm_util_create2of2(&self->redeem_fund, &self->key_fund_sort,
            self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING],
            self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);

    //可変サイズ
    ptarm_buf_t buf_funding = PTARM_BUF_INIT;
    //
    backup_buf_t *p_dbscript_keys = (backup_buf_t *)M_MALLOC(sizeof(backup_buf_t) * M_SELF_BUFS);
    int index = 0;
    p_dbscript_keys[index].name = "buf_funding";
    p_dbscript_keys[index].p_buf = &buf_funding;
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_local);
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_remote);
    //index++;

    for (size_t lp = 0; lp < M_SELF_BUFS; lp++) {
        key.mv_size = strlen(p_dbscript_keys[lp].name);
        key.mv_data = (CONST_CAST char*)p_dbscript_keys[lp].name;
        retval = mdb_get(txn, dbi, &key, &data);
        if (retval == 0) {
            ptarm_buf_alloccopy(p_dbscript_keys[lp].p_buf, data.mv_data, data.mv_size);
        } else {
            LOGD("fail: %s\n", p_dbscript_keys[lp].name);
        }
    }

    ptarm_tx_read(&self->tx_funding, buf_funding.buf, buf_funding.len);
    ptarm_buf_free(&buf_funding);
    M_FREE(p_dbscript_keys);

    //add_htlc
    retval = self_addhtlc_load(self, &db);
    if (retval != 0) {
        LOGD("ERR\n");
        goto LABEL_EXIT;
    }

    //secret
    retval = secret_load(self, &db);
    if (retval != 0) {
        LOGD("ERR\n");
    }

LABEL_EXIT:
    return retval;
}


bool ln_db_self_save(const ln_self_t *self)
{
    int             retval = -1;
    ln_lmdb_db_t    db;
    char            dbname[M_SZ_DBNAME_LEN + 1];

    for (int lp = 0; lp < LN_SZ_CHANNEL_ID; lp++) {
        if (self->channel_id[lp] != 0) {
            retval = 0;
            break;
        }
    }
    if (retval != 0) {
        LOGD("fail: channel_id is 0\n");
        return false;
    }

    retval = MDB_TXN_BEGIN(mpDbSelf, NULL, 0, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_CHANNEL, M_PREFIX_LEN);

    retval = mdb_dbi_open(db.txn, dbname, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = self_save(self, &db);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = self_addhtlc_save(self, &db);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    MDB_TXN_COMMIT(db.txn);
    db.txn = NULL;

LABEL_EXIT:
    if (db.txn) {
        LOGD("abort\n");
        MDB_TXN_ABORT(db.txn);
    }
    return retval == 0;
}


bool ln_db_self_del(const uint8_t *pChannelId)
{
    return ln_db_self_search(comp_func_cnldel, (CONST_CAST void *)pChannelId);
}


bool ln_db_self_del_prm(const ln_self_t *self, void *p_db_param)
{
    int         retval;
    MDB_dbi     dbi;
    char        dbname[M_SZ_DBNAME_LEN + M_SZ_HTLC_STR + 1];
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)p_db_param;

    //add_htlcと関連するpreimage削除
    preimg_close_t prm;
    prm.add_htlc = self->cnl_add_htlc;
    ln_db_preimg_search(preimg_close_func, &prm);

    //add_htlc
    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_ADDHTLC, M_PREFIX_LEN);

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        addhtlc_dbname(dbname, lp);
        //LOGD("[%d]dbname: %s\n", lp, dbname);
        retval = mdb_dbi_open(p_cur->txn, dbname, 0, &dbi);
        if (retval == 0) {
            retval = mdb_drop(p_cur->txn, dbi, 1);
        } else {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
        if (retval == 0) {
            LOGD("drop: %s\n", dbname);
        } else {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
    }

    //revoked transaction用データ
    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_REVOKED, M_PREFIX_LEN);

    retval = mdb_dbi_open(p_cur->txn, dbname, 0, &dbi);
    if (retval == 0) {
        retval = mdb_drop(p_cur->txn, dbi, 1);
    }
    if (retval == 0) {
        LOGD("drop: %s\n", dbname);
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    //channel削除
    memcpy(dbname, M_PREF_CHANNEL, M_PREFIX_LEN);
    retval = mdb_dbi_open(p_cur->txn, dbname, 0, &dbi);
    if (retval == 0) {
        retval = mdb_drop(p_cur->txn, dbi, 1);
    }
    if (retval == 0) {
        LOGD("drop: %s\n", dbname);
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    //記録として残す
    memcpy(dbname, M_PREF_BAKCHANNEL, M_PREFIX_LEN);
    retval = mdb_dbi_open(p_cur->txn, dbname, MDB_CREATE, &dbi);
    if (retval == 0) {
        ln_lmdb_db_t db;

        db.txn = p_cur->txn;
        db.dbi = dbi;
        retval = backup_param_save(self, &db, DBCOPY_KEYS, ARRAY_SIZE(DBCOPY_KEYS));
        if (retval != 0) {
            LOGD("fail\n");
        }
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
    }

    return true;
}


bool ln_db_self_search(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
    bool            result = false;
    int             retval;
    lmdb_cursor_t   cur;

    retval = self_cursor_open(&cur);
    if (retval != 0) {
        LOGD("fail: open\n");
        goto LABEL_EXIT;
    }

    ln_self_t *p_self = (ln_self_t *)M_MALLOC(sizeof(ln_self_t));
    bool ret;
    MDB_val     key;
    char name[M_SZ_DBNAME_LEN + 1];
    name[sizeof(name) - 1] = '\0';
    while ((ret = mdb_cursor_get(cur.cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        if ((key.mv_size == M_SZ_DBNAME_LEN) && (memcmp(key.mv_data, M_PREF_CHANNEL, M_PREFIX_LEN) == 0)) {
            memcpy(name, key.mv_data, M_SZ_DBNAME_LEN);
            ret = mdb_dbi_open(cur.txn, name, 0, &cur.dbi);
            if (ret == 0) {
                memset(p_self, 0, sizeof(ln_self_t));
                retval = ln_lmdb_self_load(p_self, cur.txn, cur.dbi);
                if (retval == 0) {
                    result = (*pFunc)(p_self, (void *)&cur, pFuncParam);
                    if (result) {
                        LOGD("match !\n");
                        break;
                    }
                    ln_term(p_self);     //falseのみ解放
                } else {
                    LOGD("ERR: %s\n", mdb_strerror(retval));
                }
            } else {
                LOGD("ERR: %s\n", mdb_strerror(retval));
            }
        }
    }
    self_cursor_close(&cur);
    M_FREE(p_self);

LABEL_EXIT:
    return result;
}


bool ln_db_self_save_closeflg(const ln_self_t *self, void *pDbParam)
{
    int             retval;
    MDB_val         key, data;
    lmdb_cursor_t   *p_cur;

    //self->fund_flagのみ
    const backup_param_t DBSELF_KEY = M_ITEM(ln_self_t, fund_flag);

    p_cur = (lmdb_cursor_t *)pDbParam;
    key.mv_size = strlen(DBSELF_KEY.name);
    key.mv_data = (CONST_CAST char*)DBSELF_KEY.name;
    data.mv_size = DBSELF_KEY.datalen;
    data.mv_data = (uint8_t *)self + DBSELF_KEY.offset;
    retval = mdb_put(p_cur->txn, p_cur->dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("fail: %s(%s)\n", mdb_strerror(retval), DBSELF_KEY.name);
    }

    return retval == 0;
}


void ln_lmdb_bkself_show(MDB_txn *txn, MDB_dbi dbi)
{
    MDB_val         key, data;
#ifdef M_DEBUG_KEYS
    ln_funding_local_data_t     local;
    ln_funding_remote_data_t    remote;
    memset(&local, 0, sizeof(local));
    memset(&remote, 0, sizeof(remote));
#endif  //M_DEBUG_KEYS

    for (size_t lp = 0; lp < ARRAY_SIZE(DBCOPY_KEYS); lp++) {
        key.mv_size = strlen(DBCOPY_KEYS[lp].name);
        key.mv_data = (CONST_CAST char*)DBCOPY_KEYS[lp].name;
        int retval = mdb_get(txn, dbi, &key, &data);
        if (retval == 0) {
            const uint8_t *p = (const uint8_t *)data.mv_data;
            if ((lp != 0) && (DBCOPY_IDX[lp].disp)) {
                printf(",\n");
            }
            if (DBCOPY_IDX[lp].disp) {
                printf("      \"%s\": ", DBCOPY_KEYS[lp].name);
            }
            switch (DBCOPY_IDX[lp].type) {
            case ETYPE_BYTEPTR: //const uint8_t*
            case ETYPE_REMOTECOMM:
                if (DBCOPY_IDX[lp].disp) {
                    printf("\"");
                    ptarm_util_dumpbin(stdout, p, DBCOPY_IDX[lp].length, false);
                    printf("\"");
                }
#ifdef M_DEBUG_KEYS
                if (DBCOPY_IDX[lp].type == ETYPE_REMOTECOMM) {
                    memcpy(remote.prev_percommit, p, DBCOPY_IDX[lp].length);
                }
#endif  //M_DEBUG_KEYS
                break;
            case ETYPE_UINT64U:
                if (DBCOPY_IDX[lp].disp) {
                    printf("%" PRIu64 "", *(const uint64_t *)p);
                }
                break;
            case ETYPE_UINT64X:
                if (DBCOPY_IDX[lp].disp) {
                    printf("\"%" PRIx64 "\"", *(const uint64_t *)p);
                }
                break;
            case ETYPE_UINT16:
            case ETYPE_FUNDTXIDX:
                if (DBCOPY_IDX[lp].disp) {
                    printf("%" PRIu16, *(const uint16_t *)p);
                }
#ifdef M_DEBUG_KEYS
                if (DBCOPY_IDX[lp].type == ETYPE_FUNDTXIDX) {
                    local.txindex = *(const uint16_t *)p;
                }
#endif  //M_DEBUG_KEYS
                break;
            case ETYPE_TXID: //txid
            case ETYPE_FUNDTXID:
                if (DBCOPY_IDX[lp].disp) {
                    printf("\"");
                    ptarm_util_dumptxid(stdout, p);
                    printf("\"");
                }
#ifdef M_DEBUG_KEYS
                if (DBCOPY_IDX[lp].type == ETYPE_FUNDTXID) {
                    memcpy(local.txid, p, DBCOPY_IDX[lp].length);
                }
#endif  //M_DEBUG_KEYS
                break;
            case ETYPE_LOCALKEYS: //funding_local.keys
#ifdef M_DEBUG_KEYS
                {
                    const ptarm_util_keys_t *p_keys = (const ptarm_util_keys_t *)p;
                    memcpy(local.pubkeys, p_keys, M_SIZE(ln_funding_local_data_t, pubkeys));
                }
#endif  //M_DEBUG_KEYS
                break;
            case ETYPE_REMOTEKEYS: //funding_remote.keys
#ifdef M_DEBUG_KEYS
                {
                    memcpy(remote.pubkeys, p, M_SIZE(ln_funding_remote_data_t, pubkeys));
                }
#endif  //M_DEBUG_KEYS
                break;
            default:
                break;
            }
        } else {
            LOGD("fail: %s\n", DBCOPY_KEYS[lp].name);
        }
    }
#ifdef M_DEBUG_KEYS
    if ( ((local.pubkeys[0][0] == 0x02) || (local.pubkeys[0][0] == 0x03)) &&
         ((remote.pubkeys[0][0] == 0x02) || (remote.pubkeys[0][0] == 0x03))) {
        printf("\n");
        ln_misc_update_scriptkeys(&local, &remote);
        //ln_print_keys(&local, &remote);
    }
#endif  //M_DEBUG_KEYS
}


bool ln_db_secret_save(ln_self_t *self)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            dbname[M_SZ_DBNAME_LEN + 1];

    retval = MDB_TXN_BEGIN(mpDbSelf, NULL, 0, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_SECRET, M_PREFIX_LEN);
    retval = mdb_dbi_open(db.txn, dbname, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    retval = backup_param_save(&self->priv_data, &db, DBSELF_SECRET, ARRAY_SIZE(DBSELF_SECRET));
    if (retval == 0) {
        MDB_TXN_COMMIT(db.txn);
    } else {
        MDB_TXN_ABORT(db.txn);
    }

LABEL_EXIT:
    return retval == 0;
}


/********************************************************************
 * node用DB
 ********************************************************************/

bool ln_db_node_cur_transaction(void **ppDb, ln_db_txn_t Type, void *pLockedDb)
{
    int retval;
    MDB_txn *txn = NULL;
    int opt = MDB_CREATE;
    ln_lmdb_db_t *p_locked_db = NULL;

    *ppDb = NULL;
    if (pLockedDb != NULL) {
        p_locked_db = (ln_lmdb_db_t *)pLockedDb;
        retval = !(p_locked_db->txn != NULL);
        txn = p_locked_db->txn;
    } else {
        retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    }
    if (retval == 0) {
        ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)M_MALLOC(sizeof(ln_lmdb_db_t));
        p_db->txn = txn;
        *ppDb = p_db;

        const char *p_name;
        switch (Type) {
        case LN_DB_TXN_CNL:
            p_name = M_DBI_ANNOINFO_CNL;
            break;
        case LN_DB_TXN_NODE:
            p_name = M_DBI_ANNOINFO_NODE;
            break;
        case LN_DB_TXN_SKIP:
            p_name = M_DBI_ANNO_SKIP;
            opt = 0;        //検索のみのため、DBが無くてもよい
            break;
        default:
            LOGD("fail: unknown TXN: %02x\n", Type);
            return false;
        }
        retval = mdb_dbi_open(txn, p_name, opt, &p_db->dbi);
    }
    if ((retval != 0) && (p_locked_db == NULL)) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        M_FREE(*ppDb);
        *ppDb = NULL;
    }
    return retval == 0;
}


void ln_db_node_cur_commit(void *pDb)
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

bool ln_db_annocnl_load(ptarm_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    int         retval;
    ln_lmdb_db_t   db;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, MDB_RDONLY, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_CNL, 0, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    retval = annocnl_load(&db, pCnlAnno, ShortChannelId);

    MDB_TXN_ABORT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnl_save(const ptarm_buf_t *pCnlAnno, uint64_t ShortChannelId, const uint8_t *pSendId,
                        const uint8_t *pChan1, const uint8_t *pChan2)
{
    int         retval;
    ln_lmdb_db_t   db, db_info, db_aichan;
    MDB_val     key, data;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    db_info.txn = db.txn;
    db_aichan.txn = db.txn;
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_CNL, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNOINFO_CNL, MDB_CREATE, &db_info.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    //BOLT#07
    //  * if node_id is NOT previously known from a channel_announcement message, OR if timestamp is NOT greater than the last-received node_announcement from this node_id:
    //    * SHOULD ignore the message.
    //  channel_announcementで受信していないnode_idは無視する
    retval = mdb_dbi_open(db.txn, M_DBI_ANNOINFO_CHAN, MDB_CREATE, &db_aichan.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    data.mv_size = 0;
    data.mv_data = NULL;
    key.mv_size = PTARM_SZ_PUBKEY;
    key.mv_data = (CONST_CAST uint8_t *)pChan1;
    retval = mdb_put(db_aichan.txn, db_aichan.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: channel_announcement node_id 1\n");
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    key.mv_data = (CONST_CAST uint8_t *)pChan2;
    retval = mdb_put(db_aichan.txn, db_aichan.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: channel_announcement node_id 2\n");
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    //channel_announcement
    ptarm_buf_t buf_ann = PTARM_BUF_INIT;
    retval = annocnl_load(&db, &buf_ann, ShortChannelId);
    if (retval != 0) {
        //DB保存されていない＝新規channel
        retval = annocnl_save(&db, pCnlAnno, ShortChannelId);
    } else {
        LOGV("exist channel_announcement: %016" PRIx64 "\n", ShortChannelId);
        if (!ptarm_buf_cmp(&buf_ann, pCnlAnno)) {
            LOGD("fail: different channel_announcement\n");
            retval = -1;
        }
    }
    ptarm_buf_free(&buf_ann);
    //annoinfo channel
    if ((retval == 0) && (pSendId != NULL)) {
        bool ret = ln_db_annocnls_add_nodeid(&db_info, ShortChannelId, LN_DB_CNLANNO_ANNO, false, pSendId);
        if (!ret) {
            retval = -1;
        }
    }

    MDB_TXN_COMMIT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnlupd_load(ptarm_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir)
{
    int         retval;
    ln_lmdb_db_t   db;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, MDB_RDONLY, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_CNL, 0, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    retval = annocnlupd_load(&db, pCnlUpd, pTimeStamp, ShortChannelId, Dir);

    MDB_TXN_ABORT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnlupd_save(const ptarm_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd, const uint8_t *pSendId)
{
    int             retval;
    ln_lmdb_db_t    db, db_info;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    db_info.txn = db.txn;
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_CNL, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNOINFO_CNL, MDB_CREATE, &db_info.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    ptarm_buf_t     buf_upd = PTARM_BUF_INIT;
    uint32_t        timestamp;
    bool            upddb = false;
    bool            clr = false;

    retval = annocnlupd_load(&db, &buf_upd, &timestamp, pUpd->short_channel_id, ln_cnlupd_direction(pUpd));
    if (retval == 0) {
        if (timestamp > pUpd->timestamp) {
            //自分の方が新しければ、スルー
            //LOGD("my channel_update is newer\n");
        } else if (timestamp < pUpd->timestamp) {
            //自分の方が古いので、更新
            //LOGD("gotten channel_update is newer\n");
            upddb = true;

            //announceし直す必要があるため、クリアする
            clr = true;
        } else {
            if (ptarm_buf_cmp(&buf_upd, pCnlUpd)) {
                //LOGD("same channel_update: %d\n", ln_cnlupd_direction(pUpd));
            } else {
                //日時が同じなのにデータが異なる
                LOGD("ERR: channel_update %d mismatch !\n", ln_cnlupd_direction(pUpd));
                LOGD("  db: ");
                DUMPD(buf_upd.buf, buf_upd.len);
                LOGD("  rv: ");
                DUMPD(pCnlUpd->buf, pCnlUpd->len);
                retval = -1;
                ptarm_buf_free(&buf_upd);
                MDB_TXN_ABORT(db.txn);
                goto LABEL_EXIT;
            }
        }
    } else {
        //新規
        upddb = true;
    }
    ptarm_buf_free(&buf_upd);

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
    uint8_t     keydata[M_SZ_ANNOINFO_CNL + 1];

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_dbi_open(txn, M_DBI_ANNO_CNL, MDB_CREATE, &dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNOINFO_CNL, MDB_CREATE, &dbi_info);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        goto LABEL_EXIT;
    }

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, 0);

    char POSTFIX[] = { LN_DB_CNLANNO_ANNO, LN_DB_CNLANNO_UPD1, LN_DB_CNLANNO_UPD2 };
    for (size_t lp = 0; lp < ARRAY_SIZE(POSTFIX); lp++) {
        keydata[LN_SZ_SHORT_CHANNEL_ID] = POSTFIX[lp];
        retval = mdb_del(txn, dbi, &key, NULL);
        if ((retval != 0) && (retval != MDB_NOTFOUND)) {
            LOGD("err[%c]: %s\n", POSTFIX[lp], mdb_strerror(retval));
        }
        retval = mdb_del(txn, dbi_info, &key, NULL);
        if ((retval != 0) && (retval != MDB_NOTFOUND)) {
            LOGD("err[%c]: %s\n", POSTFIX[lp], mdb_strerror(retval));
        }
    }

    MDB_TXN_COMMIT(txn);
    retval = 0;

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annocnls_search_nodeid(void *pDb, uint64_t ShortChannelId, char Type, const uint8_t *pSendId)
{
    bool ret = false;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL + 1];

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, Type);
    int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
    if (retval == 0) {
        //LOGD("short_channel_id[%c]= %" PRIx64 "\n", Type, ShortChannelId);
        //LOGD("send_id= ");
        //DUMPD(pSendId, PTARM_SZ_PUBKEY);
        ret = annoinfo_search(&data, pSendId);
    } else {
        //LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    return ret;
}


/* channel_announcement/channel_updateの送信元/送信先登録
 *
 * 既にchannel_announcement/channel_updateを送信したノードや、
 * その情報をもらったノードへはannoundementを送信したくないため、登録しておく。
 *
 * #ln_db_annocnls_search_nodeid()で、送信不要かどうかをチェックする。
 */
bool ln_db_annocnls_add_nodeid(void *pDb, uint64_t ShortChannelId, char Type, bool bClr, const uint8_t *pSendId)
{
    bool ret = true;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL + 1];
    bool detect = false;

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, Type);
    if (!bClr) {
        int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
        if (retval == 0) {
            detect = annoinfo_search(&data, pSendId);
        } else {
            LOGV("new reg[%016" PRIx64 ":%c] ", ShortChannelId, Type);
            DUMPV(pSendId, PTARM_SZ_PUBKEY);
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
        LOGD("ERR: cursor open\n");
        goto LABEL_EXIT;
    }

    while ((retval = mdb_cursor_get(cur.cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            if (*(char *)((uint8_t *)key.mv_data + LN_SZ_SHORT_CHANNEL_ID) == LN_DB_CNLANNO_ANNO) {
                ln_cnl_announce_read_t ann;

                ret = ln_msg_cnl_announce_read(&ann, data.mv_data, data.mv_size);
                if (ret && (
                            (memcmp(ann.node_id1, pNodeId1, PTARM_SZ_PUBKEY) == 0) &&
                            (memcmp(ann.node_id2, pNodeId2, PTARM_SZ_PUBKEY) == 0)
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
        //LOGD("ERR: cursor open\n");
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


bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, ptarm_buf_t *pBuf)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    int retval = ln_lmdb_annocnl_cur_load(p_cur->cursor, pShortChannelId, pType, pTimeStamp, pBuf);

    return retval == 0;
}


int ln_lmdb_annocnl_cur_load(MDB_cursor *cur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, ptarm_buf_t *pBuf)
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
            ptarm_buf_alloccopy(pBuf, pData, data.mv_size);
        } else {
            LOGD("fail: invalid key length: %d\n", (int)key.mv_size);
            DUMPD(key.mv_data, key.mv_size);
            retval = -1;
        }
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGD("fail: mdb_cursor_get(): %s\n", mdb_strerror(retval));
        }
    }

    return retval;
}


void ln_db_annocnl_del_orphan(void)
{
    bool ret;

    void *p_db = NULL;
    ret = ln_db_node_cur_transaction(&p_db, LN_DB_TXN_CNL, NULL);
    if (!ret) {
        LOGD("fail\n");
        return;
    }

    uint64_t now = (uint64_t)time(NULL);
    void *p_cur;
    ret = ln_db_annocnl_cur_open(&p_cur, p_db);
    if (ret) {
        uint64_t short_channel_id;
        uint64_t last_short_chennel_id = 0;
        char type;
        ptarm_buf_t buf_cnl = PTARM_BUF_INIT;
        uint32_t timestamp;
        while ((ret = ln_db_annocnl_cur_get(p_cur, &short_channel_id, &type, &timestamp, &buf_cnl))) {
            ptarm_buf_free(&buf_cnl);
            if (type == LN_DB_CNLANNO_ANNO) {
                last_short_chennel_id = short_channel_id;
            }
            if ( (type != LN_DB_CNLANNO_ANNO) &&
                 ( (last_short_chennel_id != short_channel_id) || (ln_db_annocnlupd_is_prune(now, timestamp))) ) {
                //
                MDB_cursor *cursor = ((lmdb_cursor_t *)p_cur)->cursor;
                int retval = mdb_cursor_del(cursor, 0);
                if (retval == 0) {
                    LOGD("remove orphan: %0" PRIx64 "\n", short_channel_id);
                } else {
                    LOGD("err: %s\n", mdb_strerror(retval));
                }
            }
        }
        ln_db_annocnl_cur_close(p_cur);
    }

    ln_db_node_cur_commit(p_db);
}


/********************************************************************
 * skip routing list
 ********************************************************************/

bool ln_db_annoskip_save(uint64_t ShortChannelId, bool bTemp)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val key, data;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNO_SKIP, MDB_CREATE, &dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        goto LABEL_EXIT;
    }

    //keyだけを使う
    key.mv_size = sizeof(ShortChannelId);
    key.mv_data = &ShortChannelId;
    uint8_t data_temp = M_SKIP_TEMP;
    if (bTemp) {
        data.mv_size = sizeof(data_temp);
        data.mv_data = &data_temp;
    } else {
        data.mv_size = 0;
    }
    retval = mdb_put(txn, dbi, &key, &data, 0);
    if (retval == 0) {
        LOGD("add skip[%d]: %016" PRIx64 "\n", bTemp, ShortChannelId);
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    MDB_TXN_COMMIT(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annoskip_search(void *pDb, uint64_t ShortChannelId)
{
    int         retval;
    MDB_val key, data;

    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    //keyだけを使う
    key.mv_size = sizeof(ShortChannelId);
    key.mv_data = &ShortChannelId;
    retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);

    return retval == 0;

}


bool ln_db_annoskip_drop(bool bTemp)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNO_SKIP, 0, &dbi);
    if (retval != 0) {
        //存在しないなら削除しなくてよい
        MDB_TXN_ABORT(txn);
        retval = 0;
        goto LABEL_EXIT;
    }

    if (bTemp) {
        MDB_cursor  *cursor;
        MDB_val     key, data;

        retval = mdb_cursor_open(txn, dbi, &cursor);
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
        while ((retval = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
            if ( (data.mv_size == sizeof(uint8_t)) &&
                 (*(uint8_t *)data.mv_data == M_SKIP_TEMP) ) {
                    int ret = mdb_cursor_del(cursor, 0);
                    if (ret == 0) {
                        LOGD("del skip: %016" PRIx64 "\n", *(uint64_t *)key.mv_data);
                    } else {
                        LOGD("ERR: %s\n", mdb_strerror(ret));
                    }
            }
        }
        retval = 0;
    } else {
        retval = mdb_drop(txn, dbi, 1);
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
    }

    MDB_TXN_COMMIT(txn);

LABEL_EXIT:
    LOGD("skip drop=%d\n", retval);
    return retval == 0;
}


/********************************************************************
 * invoice
 ********************************************************************/

bool ln_db_invoice_save(const char *pInvoice, uint64_t AddAmountMsat, const uint8_t *pPayHash)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key, data;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNO_INVOICE, MDB_CREATE, &dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        goto LABEL_EXIT;
    }

    key.mv_size = LN_SZ_HASH;
    key.mv_data = (CONST_CAST uint8_t *)pPayHash;
    size_t len = strlen(pInvoice);
    data.mv_size = len + 1 + sizeof(AddAmountMsat);    //invoice(\0含む) + uint64_t
    uint8_t *p_data = (uint8_t *)M_MALLOC(data.mv_size);
    data.mv_data = p_data;
    memcpy(p_data, pInvoice, len + 1);  //\0までコピー
    p_data += len + 1;
    memcpy(p_data, &AddAmountMsat, sizeof(AddAmountMsat));
    retval = mdb_put(txn, dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }
    M_FREE(data.mv_data);

    MDB_TXN_COMMIT(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_invoice_load(char **ppInvoice, uint64_t *pAddAmountMsat, const uint8_t *pPayHash)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key, data;

    *ppInvoice = NULL;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, MDB_RDONLY, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNO_INVOICE, 0, &dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        goto LABEL_EXIT;
    }

    key.mv_size = LN_SZ_HASH;
    key.mv_data = (CONST_CAST uint8_t *)pPayHash;
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval == 0) {
        *ppInvoice = strdup(data.mv_data);
        size_t len = strlen(*ppInvoice);
        data.mv_size -= len;
        if (data.mv_size > sizeof(uint64_t)) {
            memcpy(pAddAmountMsat, data.mv_data + len + 1, sizeof(uint64_t));
        } else {
            *pAddAmountMsat = 0;
        }
    }
    MDB_TXN_ABORT(txn);

LABEL_EXIT:
    return retval == 0;
}


int ln_db_invoice_get(uint8_t **ppPayHash)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi;
    MDB_val     key, data;
    MDB_cursor  *cursor;

    *ppPayHash = NULL;
    int cnt = 0;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, MDB_RDONLY, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNO_INVOICE, 0, &dbi);
    if (retval != 0) {
        if (retval != MDB_NOTFOUND) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
        MDB_TXN_ABORT(txn);
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(txn, dbi, &cursor);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    while ((retval = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        if (key.mv_size == LN_SZ_HASH) {
            cnt++;
            *ppPayHash = (uint8_t *)realloc(*ppPayHash, cnt * LN_SZ_HASH);
            memcpy(*ppPayHash + (cnt - 1) * LN_SZ_HASH, key.mv_data, LN_SZ_HASH);
        }
    }
    MDB_TXN_ABORT(txn);

LABEL_EXIT:
    return cnt;
}


bool ln_db_invoice_del(const uint8_t *pPayHash)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key;

    LOGD("payment_hash=");
    DUMPD(pPayHash, LN_SZ_HASH);

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNO_INVOICE, MDB_CREATE, &dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(txn);
        goto LABEL_EXIT;
    }

    //再送があるため、同じkeyで上書きして良い
    key.mv_size = LN_SZ_HASH;
    key.mv_data = (CONST_CAST uint8_t*)pPayHash;
    retval = mdb_del(txn, dbi, &key, NULL);
    if ((retval != 0) && (retval != MDB_NOTFOUND)) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    MDB_TXN_COMMIT(txn);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_invoice_drop(void)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNO_INVOICE, 0, &dbi);
    if (retval != 0) {
        //存在しないなら削除もしなくて良い
        MDB_TXN_ABORT(txn);
        retval = 0;
        goto LABEL_EXIT;
    }

    retval = mdb_drop(txn, dbi, 1);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    MDB_TXN_COMMIT(txn);

LABEL_EXIT:
    return retval == 0;
}


/********************************************************************
 * node_announcement
 ********************************************************************/

bool ln_db_annonod_load(ptarm_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId, void *pDb)
{
    int         retval;
    ln_lmdb_db_t   db;

    if (pDb == NULL) {
        retval = MDB_TXN_BEGIN(mpDbNode, NULL, MDB_RDONLY, &db.txn);
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    } else {
        ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;
        db.txn = p_db->txn;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_NODE, 0, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = annonod_load(&db, pNodeAnno, pTimeStamp, pNodeId);

    if (pDb == NULL) {
        MDB_TXN_ABORT(db.txn);
    }

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_annonod_save(const ptarm_buf_t *pNodeAnno, const ln_node_announce_t *pAnno, const uint8_t *pSendId)
{
    int             retval;
    ln_lmdb_db_t    db, db_info, db_aichan;
    ptarm_buf_t buf_node = PTARM_BUF_INIT;
    uint32_t    timestamp;
    bool        upddb = false;
    bool        clr = false;
    MDB_val     key, data;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    db_info.txn = db.txn;
    db_aichan.txn = db.txn;
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_NODE, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNOINFO_NODE, MDB_CREATE, &db_info.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    if (memcmp(pAnno->p_node_id, ln_node_getid(), PTARM_SZ_PUBKEY) != 0) {
        //BOLT#07
        //  * if node_id is NOT previously known from a channel_announcement message, OR if timestamp is NOT greater than the last-received node_announcement from this node_id:
        //    * SHOULD ignore the message.
        //  channel_announcementで受信していないnode_idは無視する
        retval = mdb_dbi_open(db.txn, M_DBI_ANNOINFO_CHAN, 0, &db_aichan.dbi);
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
            MDB_TXN_ABORT(db.txn);
            goto LABEL_EXIT;
        }
        if (retval == 0) {
            key.mv_size = PTARM_SZ_PUBKEY;
            key.mv_data = pAnno->p_node_id;
            retval = mdb_get(db_aichan.txn, db_aichan.dbi, &key, &data);
            if (retval != 0) {
                LOGD("skip: not have channel_announcement node_id\n");
                MDB_TXN_ABORT(db.txn);
                goto LABEL_EXIT;
            }
        }
    }

    retval = annonod_load(&db, &buf_node, &timestamp, pAnno->p_node_id);
    if (retval == 0) {
        if (timestamp > pAnno->timestamp) {
            //自分の方が新しければ、スルー
            LOGV("my node_announcement is newer\n");
            retval = 0;
        } else if (timestamp < pAnno->timestamp) {
            //自分の方が古いので、更新
            LOGV("gotten node_announcement is newer\n");
            upddb = true;

            //announceし直す必要があるため、クリアする
            clr = true;
        } else {
            if (ptarm_buf_cmp(&buf_node, pNodeAnno)) {
                LOGV("same node_announcement\n");
            } else {
                //日時が同じなのにデータが異なる
                LOGD("ERR: node_announcement mismatch !\n");
                retval = -1;
                ptarm_buf_free(&buf_node);
                MDB_TXN_ABORT(db.txn);
                goto LABEL_EXIT;
            }
        }
    } else {
        //新規
        LOGV("new node_announcement\n");
        upddb = true;
    }
    ptarm_buf_free(&buf_node);

    if (upddb) {
        retval = annonod_save(&db, pNodeAnno, pAnno->p_node_id, pAnno->timestamp);
        if ((retval == 0) && ((pSendId != NULL) || (clr && (pSendId == NULL)))) {
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


bool ln_db_annonod_drop(void)
{
    int             retval;
    ln_lmdb_db_t    db, db_self;

    db.txn = NULL;
    db_self.txn = NULL;

    if (mpDbSelf != NULL) {
        LOGD("fail: already started\n");
        return false;
    }

    retval = initialize_dbnode();
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = initialize_dbself();
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_NODE, 0, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = MDB_TXN_BEGIN(mpDbSelf, NULL, 0, &db_self.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db_self.txn, M_DBI_VERSION, 0, &db_self.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    char wif[PTARM_SZ_WIF_MAX];
    char nodename[LN_SZ_ALIAS + 1];
    uint8_t genesis[LN_SZ_HASH];
    uint16_t port;
    retval = ver_check(&db_self, wif, nodename, &port, genesis);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    ptarm_buf_t bufnod = PTARM_BUF_INIT;
    uint32_t timestamp;
    ptarm_util_keys_t keys;
    ptarm_chain_t chain;
    ptarm_util_wif2keys(&keys, &chain, wif);
    retval = annonod_load(&db, &bufnod, &timestamp, keys.pub);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_drop(db.txn, db.dbi, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_ANNO_NODE, 0, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    if (retval == 0) {
        //自ノード再登録
        annonod_save(&db, &bufnod, keys.pub, timestamp);
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    ptarm_buf_free(&bufnod);

    MDB_TXN_COMMIT(db.txn);
    db.txn = NULL;

LABEL_EXIT:
    if (db_self.txn != NULL) {
        MDB_TXN_ABORT(db_self.txn);
    }
    if (db.txn != NULL) {
        MDB_TXN_ABORT(db.txn);
    }

    return retval == 0;
}


bool ln_db_annonod_search_nodeid(void *pDb, const uint8_t *pNodeId, const uint8_t *pSendId)
{
    //LOGD("node_id= ");
    //DUMPD(pNodeId, PTARM_SZ_PUBKEY);
    //LOGD("send_id= ");
    //DUMPD(pSendId, PTARM_SZ_PUBKEY);

    bool ret = false;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_NODE];

    M_ANNOINFO_NODE_SET(keydata, key, pNodeId);
    int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
    if (retval == 0) {
        //LOGD("search...\n");
        ret = annoinfo_search(&data, pSendId);
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
    }

    return ret;
}


bool ln_db_annonod_add_nodeid(void *pDb, const uint8_t *pNodeId, bool bClr, const uint8_t *pSendId)
{
    if ((pSendId == NULL) && !bClr) {
        //更新する必要がないため、何もしない
        LOGD("do nothing\n");
        return true;
    }

    bool ret = true;
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDb;

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_NODE];
    bool detect = false;

    M_ANNOINFO_NODE_SET(keydata, key, pNodeId);
    if (!bClr) {
        int retval = mdb_get(p_db->txn, p_db->dbi, &key, &data);
        if (retval == 0) {
            detect = annoinfo_search(&data, pSendId);
        } else {
            LOGV("new from ");
            if (pSendId != NULL) {
                DUMPV(pSendId, PTARM_SZ_PUBKEY);
            } else {
                LOGV(": only clear\n");
            }
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
        LOGD("ERR: cursor open\n");
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


bool ln_db_annonod_cur_get(void *pCur, ptarm_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    int retval = ln_lmdb_annonod_cur_load(p_cur->cursor, pBuf, pTimeStamp, pNodeId);

    return retval == 0;
}


int ln_lmdb_annonod_cur_load(MDB_cursor *cur, ptarm_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(cur, &key, &data, MDB_NEXT_NODUP);
    if (retval == 0) {
        // LOGD("key:  ");
        // DUMPD(key.mv_data, key.mv_size);
        // LOGD("data: ");
        // DUMPD(data.mv_data, data.mv_size);
        if (pNodeId) {
            memcpy(pNodeId, key.mv_data, key.mv_size);
        }
        memcpy(pTimeStamp, data.mv_data, sizeof(uint32_t));
        ptarm_buf_alloccopy(pBuf, (const uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t));
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        } else {
            //end of cursor
        }
    }

    return retval;
}


/********************************************************************
 * annocnl, annonod共通
 ********************************************************************/

bool ln_db_annoinfo_del(const uint8_t *pNodeId)
{
    int         retval;
    MDB_txn     *txn;
    MDB_dbi     dbi_cnl;
    MDB_dbi     dbi_nod;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        txn = NULL;
        goto LABEL_EXIT;
    }

    retval = mdb_dbi_open(txn, M_DBI_ANNOINFO_CNL, 0, &dbi_cnl);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_ANNOINFO_NODE, 0, &dbi_nod);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    if (pNodeId != NULL) {
        MDB_cursor  *cursor;

        //annocnl info
        retval = mdb_cursor_open(txn, dbi_cnl, &cursor);
        if (retval == 0) {
            annoinfo_trim(cursor, pNodeId);
            mdb_cursor_close(cursor);
        } else {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }

        //annonode info
        retval = mdb_cursor_open(txn, dbi_nod, &cursor);
        if (retval == 0) {
            annoinfo_trim(cursor, pNodeId);
            mdb_cursor_close(cursor);
        } else {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
    } else {
        //annocnl info
        int retval_cnl = mdb_drop(txn, dbi_cnl, 1);
        if (retval_cnl != 0) {
            LOGD("err: %s\n", mdb_strerror(retval_cnl));
            retval = retval_cnl;
            //エラーでも継続
        }

        //annonod info
        int retval_nod = mdb_drop(txn, dbi_nod, 1);
        if (retval_nod != 0) {
            LOGD("err: %s\n", mdb_strerror(retval_nod));
            retval = retval_nod;
        }
    }

    MDB_TXN_COMMIT(txn);
    txn = NULL;

    if (pNodeId != NULL) {
        LOGD("remove annoinfo: ");
        DUMPD(pNodeId, PTARM_SZ_PUBKEY);
    } else {
        LOGD("remove annoinfo: ALL\n");
    }

LABEL_EXIT:
    if (txn != NULL) {
        MDB_TXN_ABORT(txn);
    }

    return retval == 0;
}


/********************************************************************
 * payment preimage
 ********************************************************************/

bool ln_db_preimg_save(ln_db_preimg_t *pPreImg, void *pDb)
{
    bool ret;
    ln_lmdb_db_t db;
    MDB_val key, data;
    MDB_txn *txn = NULL;
    preimg_info_t info;

    if (pDb != NULL) {
        txn = ((ln_lmdb_db_t *)pDb)->txn;
    }
    ret = preimg_open(&db, txn);
    if (!ret) {
        LOGD("fail\n");
        return false;
    }

    key.mv_size = LN_SZ_PREIMAGE;
    key.mv_data = pPreImg->preimage;
    data.mv_size = sizeof(info);
    info.amount = pPreImg->amount_msat;
    info.creation = (uint64_t)time(NULL);
    info.expiry = pPreImg->expiry;
    data.mv_data = &info;
    int retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval == 0) {
        pPreImg->creation_time = info.creation;
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
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
        LOGD("fail: open\n");
        goto LABEL_EXIT;
    }

    if (pPreImage != NULL) {
        MDB_val key;

        LOGD("remove: ");
        DUMPD(pPreImage, LN_SZ_PREIMAGE);
        key.mv_size = LN_SZ_PREIMAGE;
        key.mv_data = (CONST_CAST uint8_t *)pPreImage;
        retval = mdb_del(db.txn, db.dbi, &key, NULL);
    } else {
        LOGD("remove all\n");
        retval = mdb_drop(db.txn, db.dbi, 1);
    }
    if (retval == 0) {
        LOGD("success\n");
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    preimg_close(&db, NULL);

LABEL_EXIT:
    return retval == 0;
}


bool ln_db_preimg_search(ln_db_func_preimg_t pFunc, void *p_param)
{
    void *p_cur;
    bool ret = ln_db_preimg_cur_open(&p_cur);
    while (ret) {
        ln_db_preimg_t preimg;
        bool detect;
        ret = ln_db_preimg_cur_get(p_cur, &detect, &preimg);
        if (detect) {
            ret = (*pFunc)(preimg.preimage, preimg.amount_msat, preimg.expiry, p_cur, p_param);
            if (ret) {
                break;
            }
            ret = true;
        }
    }
    ln_db_preimg_cur_close(p_cur);

    return ret;
}


bool ln_db_preimg_del_hash(const uint8_t *pPreImageHash)
{
    bool ret = ln_db_preimg_search(preimg_del_func, (CONST_CAST uint8_t *)pPreImageHash);
    return ret;
}


bool ln_db_preimg_cur_open(void **ppCur)
{
    int         retval;
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)M_MALLOC(sizeof(lmdb_cursor_t));

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &p_cur->txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(p_cur->txn, M_DBI_PREIMAGE, 0, &p_cur->dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(p_cur->txn);
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(p_cur->txn, p_cur->dbi, &p_cur->cursor);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    if (retval == 0) {
        *ppCur = p_cur;
    } else {
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


bool ln_db_preimg_cur_get(void *pCur, bool *pDetect, ln_db_preimg_t *pPreImg)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval;
    MDB_val key, data;
    uint64_t now = (uint64_t)time(NULL);

    *pDetect = false;

    if ((retval = mdb_cursor_get(p_cur->cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        preimg_info_t *p_info = (preimg_info_t *)data.mv_data;
        LOGD("amount: %" PRIu64"\n", p_info->amount);
        LOGD("time: %lu\n", p_info->creation);
        pPreImg->expiry = p_info->expiry;
        pPreImg->creation_time = p_info->creation;
        if ((p_info->expiry == UINT32_MAX) || (now <= p_info->creation + p_info->expiry)) {
            memcpy(pPreImg->preimage, key.mv_data, key.mv_size);
            pPreImg->amount_msat = p_info->amount;
            *pDetect = true;

            uint8_t hash[LN_SZ_HASH];
            ln_calc_preimage_hash(hash, pPreImg->preimage);
            LOGD("invoice hash: ");
            DUMPD(hash, LN_SZ_HASH);
        } else {
            //期限切れ
            LOGD("invoice timeout del: ");
            DUMPD(key.mv_data, key.mv_size);
            mdb_cursor_del(p_cur->cursor, 0);
        }
    }

    return retval == 0;
}


bool ln_db_preimg_set_expiry(void *pCur, uint32_t Expiry)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval;
    MDB_val key, data;

    retval = mdb_cursor_get(p_cur->cursor, &key, &data, MDB_GET_CURRENT);
    if (retval == 0) {
        preimg_info_t *p_info = (preimg_info_t *)data.mv_data;
        LOGD("amount: %" PRIu64"\n", p_info->amount);
        LOGD("time: %lu\n", p_info->creation);

        preimg_info_t info;
        memcpy(&info, p_info, data.mv_size);
        info.expiry = Expiry;
        data.mv_data = &info;
        data.mv_size = sizeof(preimg_info_t);
        retval = mdb_cursor_put(p_cur->cursor, &key, &data, MDB_CURRENT);
    }
    if (retval == 0) {
        LOGD("  change expiry: %" PRIu32 "\n", Expiry);
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

    return retval == 0;
}


#ifdef LN_UGLY_NORMAL
/********************************************************************
 * payment_hash
 ********************************************************************/

bool ln_db_phash_save(const uint8_t *pPayHash, const uint8_t *pVout, ln_htlctype_t Type, uint32_t Expiry)
{
    int         retval;
    MDB_txn     *txn = NULL;
    MDB_dbi     dbi;
    MDB_val     key, data;

    retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(txn, M_DBI_PAYHASH, MDB_CREATE, &dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_size = LNL_SZ_WITPROG_WSH;
    key.mv_data = (CONST_CAST uint8_t *)pVout;
    uint8_t hash[1 + sizeof(uint32_t) + LN_SZ_HASH];
    hash[0] = (uint8_t)Type;
    memcpy(hash + 1, &Expiry, sizeof(uint32_t));
    memcpy(hash + 1 + sizeof(uint32_t), pPayHash, LN_SZ_HASH);
    data.mv_size = sizeof(hash);
    data.mv_data = hash;
    retval = mdb_put(txn, dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    if (txn != NULL) {
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
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_cursor  *cursor;
    MDB_val     key, data;
    bool found = false;

    MDB_txn *txn_tmp = ((ln_lmdb_db_t *)pDbParam)->txn;
    if (mdb_txn_env(txn_tmp) == mpDbNode) {
        txn = txn_tmp;
    } else {
        MDB_TXN_BEGIN(mpDbNode, NULL, 0, &txn);
    }

    retval = mdb_dbi_open(txn, M_DBI_PAYHASH, 0, &dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(txn, dbi, &cursor);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    while ((retval = mdb_cursor_get(cursor, &key, &data, MDB_NEXT)) == 0) {
        if ( (key.mv_size == LNL_SZ_WITPROG_WSH) &&
             (memcmp(key.mv_data, pVout, LNL_SZ_WITPROG_WSH) == 0) ) {
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
    if (txn != txn_tmp) {
        MDB_TXN_ABORT(txn);
    }
    return found;
}

#endif  //LN_UGLY_NORMAL


/********************************************************************
 * revoked transaction用データ
 ********************************************************************/

bool ln_db_revtx_load(ln_self_t *self, void *pDbParam)
{
    MDB_val key, data;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    char        dbname[M_SZ_DBNAME_LEN + 1];

    txn = ((ln_lmdb_db_t *)pDbParam)->txn;

    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_REVOKED, M_PREFIX_LEN);

    int retval = mdb_dbi_open(txn, dbname, 0, &dbi);
    if (retval != 0) {
        //LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    ln_free_revoked_buf(self);
    key.mv_size = LNDBK_RLEN;

    //number of vout scripts
    key.mv_data = LNDBK_RVN;
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    uint16_t *p = (uint16_t *)data.mv_data;
    self->revoked_cnt = p[0];
    self->revoked_num = p[1];
    ln_alloc_revoked_buf(self);

    //vout scripts
    key.mv_data = LNDBK_RVV;
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    uint8_t *p_scr = (uint8_t *)data.mv_data;
    for (int lp = 0; lp < self->revoked_num; lp++) {
        uint16_t len = *(uint16_t *)p_scr;
        p_scr += sizeof(uint16_t);
        ptarm_buf_alloccopy(&self->p_revoked_vout[lp], p_scr, len);
        p_scr += len;
    }

    //witness script
    key.mv_data = LNDBK_RVW;
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    p_scr = (uint8_t *)data.mv_data;
    for (int lp = 0; lp < self->revoked_num; lp++) {
        uint16_t len = *(uint16_t *)p_scr;
        p_scr += sizeof(uint16_t);
        ptarm_buf_alloccopy(&self->p_revoked_wit[lp], p_scr, len);
        p_scr += len;
    }

    //HTLC type
    key.mv_data = LNDBK_RVT;
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    memcpy(self->p_revoked_type, data.mv_data, data.mv_size);

    //remote per_commit_secret
    key.mv_data = LNDBK_RVS;
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    ptarm_buf_free(&self->revoked_sec);
    ptarm_buf_alloccopy(&self->revoked_sec, data.mv_data, data.mv_size);

    //confirmation数
    key.mv_data = LNDBK_RVC;
    retval = mdb_get(txn, dbi, &key, &data);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
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
    char        dbname[M_SZ_DBNAME_LEN + 1];
    ptarm_buf_t buf = PTARM_BUF_INIT;
    ptarm_push_t push;

    db.txn = ((ln_lmdb_db_t *)pDbParam)->txn;

    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_REVOKED, M_PREFIX_LEN);

    int retval = mdb_dbi_open(db.txn, dbname, MDB_CREATE, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_size = LNDBK_RLEN;

    key.mv_data = LNDBK_RVV;
    ptarm_push_init(&push, &buf, 0);
    for (int lp = 0; lp < self->revoked_num; lp++) {
        ptarm_push_data(&push, &self->p_revoked_vout[lp].len, sizeof(uint16_t));
        ptarm_push_data(&push, self->p_revoked_vout[lp].buf, self->p_revoked_vout[lp].len);
    }
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    ptarm_buf_free(&buf);

    key.mv_data = LNDBK_RVW;
    ptarm_push_init(&push, &buf, 0);
    for (int lp = 0; lp < self->revoked_num; lp++) {
        ptarm_push_data(&push, &self->p_revoked_wit[lp].len, sizeof(uint16_t));
        ptarm_push_data(&push, self->p_revoked_wit[lp].buf, self->p_revoked_wit[lp].len);
    }
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    ptarm_buf_free(&buf);

    key.mv_data = LNDBK_RVT;
    data.mv_size = sizeof(ln_htlctype_t) * self->revoked_num;
    data.mv_data = self->p_revoked_type;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_data = LNDBK_RVS;
    data.mv_size = self->revoked_sec.len;
    data.mv_data = self->revoked_sec.buf;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_data = LNDBK_RVN;
    data.mv_size = sizeof(uint16_t) * 2;
    uint16_t p[2];
    p[0] = self->revoked_cnt;
    p[1] = self->revoked_num;
    data.mv_data = p;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    key.mv_data = LNDBK_RVC;
    data.mv_size = sizeof(self->revoked_chk);
    data.mv_data = (CONST_CAST uint32_t *)&self->revoked_chk;
    retval = mdb_put(db.txn, db.dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    if (bUpdate) {
        memcpy(dbname, M_PREF_CHANNEL, M_PREFIX_LEN);
        retval = mdb_dbi_open(db.txn, dbname, 0, &db.dbi);
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
        retval = self_save(self, &db);
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }

    }
LABEL_EXIT:
    LOGD("retval=%d\n", retval);
    return retval == 0;
}


/********************************************************************
 * version
 ********************************************************************/

bool ln_db_ver_check(uint8_t *pMyNodeId, ptarm_genesis_t *pGType)
{
    int             retval;
    ln_lmdb_db_t    db;

    retval = MDB_TXN_BEGIN(mpDbSelf, NULL, MDB_RDONLY, &db.txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(db.txn, M_DBI_VERSION, 0, &db.dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.txn);
        goto LABEL_EXIT;
    }

    char wif[PTARM_SZ_WIF_MAX];
    char alias[LN_SZ_ALIAS + 1];
    uint16_t port;
    uint8_t genesis[LN_SZ_HASH];
    retval = ver_check(&db, wif, alias, &port, genesis);
    if (retval == 0) {
        ptarm_util_keys_t key;
        ptarm_chain_t chain;

        ptarm_genesis_t gtype = ptarm_util_get_genesis(genesis);
        bool ret = ptarm_util_wif2keys(&key, &chain, wif);
        if (
          ((chain == PTARM_MAINNET) && (gtype == PTARM_GENESIS_BTCMAIN)) ||
          ((chain == PTARM_TESTNET) && (
                (gtype == PTARM_GENESIS_BTCTEST) || (gtype == PTARM_GENESIS_BTCREGTEST)) ) ) {
            //ok
        } else {
            ret = false;
        }
        if (ret) {
            if (pMyNodeId != NULL) {
                memcpy(pMyNodeId, key.pub, PTARM_SZ_PUBKEY);
            }
            if (pGType != NULL) {
                *pGType = gtype;
            }
        } else {
            retval = -1;
        }
    }
    MDB_TXN_COMMIT(db.txn);

LABEL_EXIT:
    return retval == 0;
}


int ln_db_lmdb_get_mynodeid(MDB_txn *txn, MDB_dbi dbi, char *wif, char *alias, uint16_t *p_port, uint8_t *genesis)
{
    int             retval;
    ln_lmdb_db_t    db;

    db.txn = txn;
    db.dbi = dbi;
    retval = ver_check(&db, wif, alias, p_port, genesis);
    return retval;
}


/********************************************************************
 * others
 ********************************************************************/

ln_lmdb_dbtype_t ln_lmdb_get_dbtype(const char *pDbName)
{
    ln_lmdb_dbtype_t dbtype;

    if (strncmp(pDbName, M_PREF_CHANNEL, M_PREFIX_LEN) == 0) {
        //self
        dbtype = LN_LMDB_DBTYPE_SELF;
    } else if (strncmp(pDbName, M_PREF_ADDHTLC, M_PREFIX_LEN) == 0) {
        //add_htlc
        dbtype = LN_LMDB_DBTYPE_ADD_HTLC;
    } else if (strncmp(pDbName, M_PREF_REVOKED, M_PREFIX_LEN) == 0) {
        //revoked transaction
        dbtype = LN_LMDB_DBTYPE_REVOKED;
    } else if (strncmp(pDbName, M_PREF_BAKCHANNEL, M_PREFIX_LEN) == 0) {
        //removed self
        dbtype = LN_LMDB_DBTYPE_BKSELF;
    } else if (strcmp(pDbName, M_DBI_ANNO_CNL) == 0) {
        //channel_announcement
        dbtype = LN_LMDB_DBTYPE_CHANNEL_ANNO;
    } else if (strcmp(pDbName, M_DBI_ANNO_NODE) == 0) {
        //node_announcement
        dbtype = LN_LMDB_DBTYPE_NODE_ANNO;
    } else if (strcmp(pDbName, M_DBI_ANNOINFO_CNL) == 0) {
        //channel_announcement/channel_update information
        dbtype = LN_LMDB_DBTYPE_CHANNEL_ANNOINFO;
    } else if (strcmp(pDbName, M_DBI_ANNOINFO_NODE) == 0) {
        //node_announcement information
        dbtype = LN_LMDB_DBTYPE_NODE_ANNOINFO;
    } else if (strcmp(pDbName, M_DBI_ANNO_SKIP) == 0) {
        //route skip
        dbtype = LN_LMDB_DBTYPE_ANNO_SKIP;
    } else if (strcmp(pDbName, M_DBI_ANNO_INVOICE) == 0) {
        //payment invoice
        dbtype = LN_LMDB_DBTYPE_ANNO_INVOICE;
    } else if (strcmp(pDbName, M_DBI_PREIMAGE) == 0) {
        //preimage
        dbtype = LN_LMDB_DBTYPE_PREIMAGE;
#ifdef LN_UGLY_NORMAL
    } else if (strcmp(pDbName, M_DBI_PAYHASH) == 0) {
        //preimage
        dbtype = LN_LMDB_DBTYPE_PAYHASH;
#endif //LN_UGLY_NORMAL
    } else if (strcmp(pDbName, M_DBI_VERSION) == 0) {
        //version
        dbtype = LN_LMDB_DBTYPE_VERSION;
    } else {
        dbtype = LN_LMDB_DBTYPE_UNKNOWN;
    }

    return dbtype;
}


/* ptarmのDB動作を借りたいために、showdb/routingから使用される。
 *
 */
void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_anno)
{
    mpDbSelf = p_env;
    mpDbNode = p_anno;
}


bool ln_db_reset(void)
{
    int retval;

    if (mpDbSelf != NULL) {
        LOGD("fail: already started\n");
        return false;
    }

    retval = initialize_dbself();
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    bool ret = false;
    lmdb_cursor_t cur;
    retval = self_cursor_open(&cur);
    if (retval != 0) {
        LOGD("fail: open\n");
        goto LABEL_EXIT;
    }
    ret = true;     //ここまで来たら成功と見なしてよい

    MDB_val     key;
    while ((ret = mdb_cursor_get(cur.cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        if (memcmp(key.mv_data, M_DBI_VERSION, sizeof(M_DBI_VERSION) - 1) != 0) {
            //"version"以外は削除
            MDB_dbi dbi2;
            char *name = (char *)malloc(key.mv_size + 1);
            memcpy(name, key.mv_data, key.mv_size);
            name[key.mv_size] = '\0';
            LOGD("dbname: %s\n", name);

            retval = mdb_dbi_open(cur.txn, name, 0, &dbi2);
            free(name);
            if (retval == 0) {
                retval = mdb_drop(cur.txn, dbi2, 1);
                if (retval != 0) {
                    LOGD("ERR: %s\n", mdb_strerror(retval));
                }
            }
        }
    }
    self_cursor_close(&cur);

    //node側はディレクトリごと削除
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", ln_lmdb_get_nodepath());
    system(cmd);

LABEL_EXIT:
    return ret;
}


void HIDDEN ln_db_copy_channel(ln_self_t *pOutSelf, const ln_self_t *pInSelf)
{
    LOGD("recover\n");
    //固定サイズ

    for (size_t lp = 0; lp < ARRAY_SIZE(DBSELF_KEYS); lp++) {
        memcpy((uint8_t *)pOutSelf + DBSELF_KEYS[lp].offset, (uint8_t *)pInSelf + DBSELF_KEYS[lp].offset,  DBSELF_KEYS[lp].datalen);
    }

    // add_htlc
    memcpy(pOutSelf->cnl_add_htlc,  pInSelf->cnl_add_htlc, M_SIZE(ln_self_t, cnl_add_htlc));
    // scriptpubkeys
    memcpy(pOutSelf->funding_local.scriptpubkeys, pInSelf->funding_local.scriptpubkeys,
                                            M_SIZE(ln_funding_local_data_t, scriptpubkeys));
    memcpy(pOutSelf->funding_remote.scriptpubkeys, pInSelf->funding_remote.scriptpubkeys,
                                            M_SIZE(ln_funding_remote_data_t, scriptpubkeys));

    //復元データ
    ptarm_buf_alloccopy(&pOutSelf->redeem_fund, pInSelf->redeem_fund.buf, pInSelf->redeem_fund.len);
    pOutSelf->key_fund_sort = pInSelf->key_fund_sort;


    //可変サイズ(shallow copy)

    //tx_funding
    ptarm_tx_free(&pOutSelf->tx_funding);
    memcpy(&pOutSelf->tx_funding, &pInSelf->tx_funding, sizeof(ptarm_tx_t));

    //shutdown_scriptpk_local
    ptarm_buf_free(&pOutSelf->shutdown_scriptpk_local);
    memcpy(&pOutSelf->shutdown_scriptpk_local, &pInSelf->shutdown_scriptpk_local, sizeof(ptarm_buf_t));

    //shutdown_scriptpk_remote
    ptarm_buf_free(&pOutSelf->shutdown_scriptpk_remote);
    memcpy(&pOutSelf->shutdown_scriptpk_remote, &pInSelf->shutdown_scriptpk_remote, sizeof(ptarm_buf_t));

    //secret
    for (size_t lp = 0; lp < ARRAY_SIZE(DBSELF_SECRET); lp++) {
        memcpy((uint8_t *)&pOutSelf->priv_data + DBSELF_SECRET[lp].offset,
                    (uint8_t *)&pInSelf->priv_data + DBSELF_SECRET[lp].offset,
                    DBSELF_SECRET[lp].datalen);
    }
}


/********************************************************************
 * private functions
 ********************************************************************/

/** channel: add_htlc読み込み
 *
 * @param[out]      self
 * @param[in]       pDb
 * @retval      true    成功
 */
static int self_addhtlc_load(ln_self_t *self, ln_lmdb_db_t *pDb)
{
    int         retval;
    MDB_dbi     dbi;
    MDB_val     key, data;
    char        dbname[M_SZ_DBNAME_LEN + M_SZ_HTLC_STR + 1];

    uint8_t *OFFSET = ((uint8_t *)self) + offsetof(ln_self_t, cnl_add_htlc);

    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_ADDHTLC, M_PREFIX_LEN);

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        addhtlc_dbname(dbname, lp);
        //LOGD("[%d]dbname: %s\n", lp, dbname);
        retval = mdb_dbi_open(pDb->txn, dbname, 0, &dbi);
        if (retval != 0) {
            LOGD("ERR: %s(%s)\n", mdb_strerror(retval), dbname);
            continue;
        }
        for (size_t lp2 = 0; lp2 < ARRAY_SIZE(DBHTLC_KEYS); lp2++) {
            key.mv_size = strlen(DBHTLC_KEYS[lp2].name);
            key.mv_data = (CONST_CAST char*)DBHTLC_KEYS[lp2].name;
            retval = mdb_get(pDb->txn, dbi, &key, &data);
            if (retval == 0) {
                //LOGD("[%d]%s: ", lp, DBHTLC_KEYS[lp2].name);
                //DUMPD(data.mv_data, data.mv_size);
                memcpy(OFFSET + sizeof(ln_update_add_htlc_t) * lp + DBHTLC_KEYS[lp2].offset, data.mv_data, DBHTLC_KEYS[lp2].datalen);
            } else {
                LOGD("ERR: %s(%s)\n", mdb_strerror(retval), DBHTLC_KEYS[lp2].name);
            }
        }
        key.mv_size = M_SZ_SHAREDSECRET;
        key.mv_data = M_KEY_SHAREDSECRET;
        retval = mdb_get(pDb->txn, dbi, &key, &data);
        if (retval == 0) {
            ptarm_buf_alloccopy(&self->cnl_add_htlc[lp].shared_secret, data.mv_data, data.mv_size);
        } else {
            LOGD("ERR: %s(shared_secret)\n", mdb_strerror(retval));
        }
        mdb_dbi_close(mpDbSelf, dbi);
    }

    return retval;
}


/** channel: add_htlc書込み
 *
 * @param[in]       self
 * @param[in]       pDb
 * @retval      true    成功
 */
static int self_addhtlc_save(const ln_self_t *self, ln_lmdb_db_t *pDb)
{
    int         retval;
    MDB_dbi     dbi;
    MDB_val     key, data;
    char        dbname[M_SZ_DBNAME_LEN + M_SZ_HTLC_STR + 1];

    uint8_t *OFFSET = ((uint8_t *)self) + offsetof(ln_self_t, cnl_add_htlc);

    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_ADDHTLC, M_PREFIX_LEN);

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        addhtlc_dbname(dbname, lp);
        //LOGD("[%d]dbname: %s\n", lp, dbname);
        retval = mdb_dbi_open(pDb->txn, dbname, MDB_CREATE, &dbi);
        if (retval != 0) {
            LOGD("ERR: %s(%s)\n", mdb_strerror(retval), dbname);
            continue;
        }

        ln_lmdb_db_t db;
        db.txn = pDb->txn;
        db.dbi = dbi;
        retval = backup_param_save(OFFSET + sizeof(ln_update_add_htlc_t) * lp,
                        &db, DBHTLC_KEYS, ARRAY_SIZE(DBHTLC_KEYS));
        if (retval != 0) {
            LOGD("ERR\n");
        }

        key.mv_size = M_SZ_SHAREDSECRET;
        key.mv_data = M_KEY_SHAREDSECRET;
        data.mv_size = self->cnl_add_htlc[lp].shared_secret.len;
        data.mv_data = self->cnl_add_htlc[lp].shared_secret.buf;
        retval = mdb_put(pDb->txn, dbi, &key, &data, 0);
        if (retval != 0) {
            LOGD("ERR: %s(shared_secret)\n", mdb_strerror(retval));
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
    int retval;

    //固定サイズ
    retval = backup_param_save(self, pDb, DBSELF_KEYS, ARRAY_SIZE(DBSELF_KEYS));
    if (retval != 0) {
        goto LABEL_EXIT;
    }

    //可変サイズ
    ptarm_buf_t buf_funding = PTARM_BUF_INIT;
    ptarm_tx_create(&buf_funding, &self->tx_funding);
    //
    backup_buf_t *p_dbscript_keys = (backup_buf_t *)M_MALLOC(sizeof(backup_buf_t) * M_SELF_BUFS);
    int index = 0;
    p_dbscript_keys[index].name = "buf_funding";
    p_dbscript_keys[index].p_buf = &buf_funding;
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_local);
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_remote);
    //index++;

    for (size_t lp = 0; lp < M_SELF_BUFS; lp++) {
        key.mv_size = strlen(p_dbscript_keys[lp].name);
        key.mv_data = (CONST_CAST char*)p_dbscript_keys[lp].name;
        data.mv_size = p_dbscript_keys[lp].p_buf->len;
        data.mv_data = p_dbscript_keys[lp].p_buf->buf;
        retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
        if (retval != 0) {
            LOGD("fail: %s\n", p_dbscript_keys[lp].name);
            break;
        }
    }

    ptarm_buf_free(&buf_funding);
    M_FREE(p_dbscript_keys);

LABEL_EXIT:
    return retval;
}


static int secret_load(ln_self_t *self, ln_lmdb_db_t *pDb)
{
    int retval;
    char        dbname[M_SZ_DBNAME_LEN + M_SZ_HTLC_STR + 1];

    ptarm_util_bin2str(dbname + M_PREFIX_LEN, self->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(dbname, M_PREF_SECRET, M_PREFIX_LEN);
    retval = mdb_dbi_open(pDb->txn, dbname, 0, &pDb->dbi);
    if (retval == 0) {
        retval = backup_param_load(&self->priv_data, pDb, DBSELF_SECRET, ARRAY_SIZE(DBSELF_SECRET));
    }
    if (retval != 0) {
        LOGD("ERR: %s(backup_param_load)\n", mdb_strerror(retval));
    }
    // LOGD("[priv]storage_index: %" PRIx64 "\n", self->priv_data.storage_index);
    // LOGD("[priv]storage_seed: ");
    // DUMPD(self->priv_data.storage_seed, PTARM_SZ_PRIVKEY);
    // for (size_t lp = 0; lp < MSG_FUNDIDX_MAX; lp++) {
    //     LOGD("[priv][%lu] ", lp);
    //     DUMPD(self->priv_data.priv[lp], PTARM_SZ_PRIVKEY);
    // }

    return retval;
}


/** channel_announcement読込み
 *
 * @param[in]       pDb
 * @param[out]      pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
static int annocnl_load(ln_lmdb_db_t *pDb, ptarm_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    LOGV("short_channel_id=%016" PRIx64 "\n", ShortChannelId);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL + 1];

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, LN_DB_CNLANNO_ANNO);
    int retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
    if (retval == 0) {
        ptarm_buf_alloccopy(pCnlAnno, data.mv_data, data.mv_size);
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
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
static int annocnl_save(ln_lmdb_db_t *pDb, const ptarm_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    LOGV("short_channel_id=%016" PRIx64 "\n", ShortChannelId);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL + 1];

#ifdef DEVELOPER_MODE
    ln_msg_cnl_announce_print(pCnlAnno->buf, pCnlAnno->len);    
#endif

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, LN_DB_CNLANNO_ANNO);
    data.mv_size = pCnlAnno->len;
    data.mv_data = pCnlAnno->buf;
    int retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
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

    retval = mdb_dbi_open(pCur->txn, M_DBI_ANNO_CNL, 0, &pCur->dbi);
    if (retval != 0) {
        //LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(pCur->txn, pCur->dbi, &pCur->cursor);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    return retval == 0;
}


#if 0
/** lmdb channel_announcement系検索
 *
 */
static bool annocnl_search(lmdb_cursor_t *pCur, uint64_t ShortChannelId, ptarm_buf_t *pBuf, char Type)
{
    int retval;
    MDB_val key, data;

    ptarm_buf_init(pBuf);
    while ((retval = mdb_cursor_get(pCur->cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size == LN_SZ_SHORT_CHANNEL_ID + 1) {
            uint64_t load_sci;
            memcpy(&load_sci, key.mv_data, LN_SZ_SHORT_CHANNEL_ID);
            if ((load_sci == ShortChannelId) && (*(char *)((uint8_t *)key.mv_data + LN_SZ_SHORT_CHANNEL_ID) == Type)) {
                ptarm_buf_alloccopy(pBuf, data.mv_data, data.mv_size);
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
 * @param[out]      pTimeStamp          (非NULL)保存しているchannel_updateのTimeStamp
 * @param[in]       ShortChannelId
 * @param[in]       Dir                 0:node_1, 1:node_2
 * @retval      true    成功
 */
static int annocnlupd_load(ln_lmdb_db_t *pDb, ptarm_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir)
{
    LOGV("short_channel_id=%016" PRIx64 ", dir=%d\n", ShortChannelId, Dir);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL + 1];

    M_ANNOINFO_CNL_SET(keydata, key, ShortChannelId, ((Dir) ?  LN_DB_CNLANNO_UPD2 : LN_DB_CNLANNO_UPD1));
    int retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
    if (retval == 0) {
        if (pTimeStamp != NULL) {
            *pTimeStamp = *(uint32_t *)data.mv_data;
        }
        ptarm_buf_alloccopy(pCnlUpd, (uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t));
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
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
static int annocnlupd_save(ln_lmdb_db_t *pDb, const ptarm_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd)
{
    LOGV("short_channel_id=%016" PRIx64 ", dir=%d\n", pUpd->short_channel_id, ln_cnlupd_direction(pUpd));

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_CNL + 1];

    M_ANNOINFO_CNL_SET(keydata, key, pUpd->short_channel_id, (ln_cnlupd_direction(pUpd) ?  LN_DB_CNLANNO_UPD2 : LN_DB_CNLANNO_UPD1));
    ptarm_buf_t buf;
    ptarm_buf_alloc(&buf, sizeof(uint32_t) + pCnlUpd->len);

    //timestamp + channel_update
    memcpy(buf.buf, &pUpd->timestamp, sizeof(uint32_t));
    memcpy(buf.buf + sizeof(uint32_t), pCnlUpd->buf, pCnlUpd->len);
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    int retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }
    ptarm_buf_free(&buf);

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
static int annonod_load(ln_lmdb_db_t *pDb, ptarm_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId)
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
            ptarm_buf_alloccopy(pNodeAnno, (uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t));
        }
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
    }

    return retval;
}


/* node_announcement書込み
 *
 * @param[in,out]   pDb
 * @param[in]       pNodeAnno       node_announcementパケット
 * @param[in]       pNodeId         node_announcementのnode_id
 * @param[in]       Timestamp       保存時間
 * @retval      true
 */
static int annonod_save(ln_lmdb_db_t *pDb, const ptarm_buf_t *pNodeAnno, const uint8_t *pNodeId, uint32_t Timestamp)
{
    LOGV("node_id=");
    DUMPV(pNodeId, PTARM_SZ_PUBKEY);

    MDB_val key, data;
    uint8_t keydata[M_SZ_ANNOINFO_NODE];

    M_ANNOINFO_NODE_SET(keydata, key, pNodeId);
    ptarm_buf_t buf;
    ptarm_buf_alloc(&buf, sizeof(uint32_t) + pNodeAnno->len);

    //timestamp + node_announcement
    memcpy(buf.buf, &Timestamp, sizeof(uint32_t));
    memcpy(buf.buf + sizeof(uint32_t), pNodeAnno->buf, pNodeAnno->len);
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    int retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }
    ptarm_buf_free(&buf);

    return retval;
}


/** annoinfoにnode_idを追加(channel, node共通)
 *
 * @param[in,out]   pDb         annoinfo
 * @param[in]       pMdbKey     loadしたchannel_announcement infoのkey
 * @param[in]       pMdbData    loadしたchannel_announcement infoのdata
 * @param[in]       pNodeId     追加するnode_id(NULL時はクリア)
 */
static bool annoinfo_add(ln_lmdb_db_t *pDb, MDB_val *pMdbKey, MDB_val *pMdbData, const uint8_t *pNodeId)
{
    uint8_t *p_ids;

    if (pNodeId != NULL) {
        int nums = pMdbData->mv_size / PTARM_SZ_PUBKEY;
        p_ids = (uint8_t *)M_MALLOC((nums + 1) * PTARM_SZ_PUBKEY);
        memcpy(p_ids, pMdbData->mv_data, pMdbData->mv_size);
        memcpy(p_ids + pMdbData->mv_size, pNodeId, PTARM_SZ_PUBKEY);
        pMdbData->mv_size += PTARM_SZ_PUBKEY;
    } else {
        pMdbData->mv_size = 0;
        p_ids = NULL;
    }

    pMdbData->mv_data = p_ids;
    int retval = mdb_put(pDb->txn, pDb->dbi, pMdbKey, pMdbData, 0);
    if (retval == 0) {
        LOGV("add annoinfo: ");
        DUMPV(pNodeId, PTARM_SZ_PUBKEY);
    } else {
        LOGD("fail\n");
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
    int nums = pMdbData->mv_size / PTARM_SZ_PUBKEY;
    //LOGD("nums=%d\n", nums);
    //LOGD("search id: ");
    //DUMPD(pNodeId, PTARM_SZ_PUBKEY);
    int lp;
    for (lp = 0; lp < nums; lp++) {
        //LOGD("  node_id[%d]= ", lp);
        //DUMPD(pMdbData->mv_data + PTARM_SZ_PUBKEY * lp, PTARM_SZ_PUBKEY);
        if (memcmp((uint8_t *)pMdbData->mv_data + PTARM_SZ_PUBKEY * lp, pNodeId, PTARM_SZ_PUBKEY) == 0) {
            break;
        }
    }

    return lp < nums;
}


static void annoinfo_trim(MDB_cursor *pCursor, const uint8_t *pNodeId)
{
    MDB_val     key, data;

    while (mdb_cursor_get(pCursor, &key, &data, MDB_NEXT) == 0) {
        int nums = data.mv_size / PTARM_SZ_PUBKEY;
        for (int lp = 0; lp < nums; lp++) {
            if (memcmp((uint8_t *)data.mv_data + PTARM_SZ_PUBKEY * lp, pNodeId, PTARM_SZ_PUBKEY) == 0) {
                nums--;
                if (nums > 0) {
                    uint8_t *p_data = (uint8_t *)M_MALLOC(PTARM_SZ_PUBKEY * nums);
                    data.mv_size = PTARM_SZ_PUBKEY * nums;
                    data.mv_data = p_data;
                    memcpy(p_data,
                                (uint8_t *)data.mv_data,
                                PTARM_SZ_PUBKEY * lp);
                    memcpy(p_data + PTARM_SZ_PUBKEY * lp,
                                (uint8_t *)data.mv_data + PTARM_SZ_PUBKEY * (lp + 1),
                                PTARM_SZ_PUBKEY * (nums - lp));
                    mdb_cursor_put(pCursor, &key, &data, MDB_CURRENT);
                    M_FREE(data.mv_data);
                } else {
                    mdb_cursor_del(pCursor, 0);
                }
                break;
            }
        }
    }
}


/** lmdb cursorオープン(node_announcement)
 *
 */
static bool annonod_cur_open(lmdb_cursor_t *pCur)
{
    int retval;

    retval = mdb_dbi_open(pCur->txn, M_DBI_ANNO_NODE, 0, &pCur->dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = mdb_cursor_open(pCur->txn, pCur->dbi, &pCur->cursor);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    return retval == 0;
}


static bool preimg_open(ln_lmdb_db_t *p_db, MDB_txn *txn)
{
    int retval;

    if (txn == NULL) {
        retval = MDB_TXN_BEGIN(mpDbNode, NULL, 0, &p_db->txn);
        if (retval != 0) {
            LOGD("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    } else {
        p_db->txn = txn;
    }
    retval = mdb_dbi_open(p_db->txn, M_DBI_PREIMAGE, MDB_CREATE, &p_db->dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
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


/** #ln_db_preimg_del_hash()用処理関数
 *
 * SHA256(preimage)がpayment_hashと一致した場合にDBから削除する。
 */
static bool preimg_del_func(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param)
{
    (void)Amount; (void)Expiry;

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)p_db_param;
    const uint8_t *hash = (const uint8_t *)p_param;
    uint8_t preimage_hash[LN_SZ_HASH];
    int retval = MDB_NOTFOUND;

    LOGD("compare preimage : ");
    DUMPD(pPreImage, LN_SZ_PREIMAGE);
    ln_calc_preimage_hash(preimage_hash, pPreImage);
    if (memcmp(preimage_hash, hash, LN_SZ_HASH) == 0) {
        retval = mdb_cursor_del(p_cur->cursor, 0);
        LOGD("  remove from DB: %s\n", mdb_strerror(retval));
    }

    return retval == 0;
}


/** ln_db_self_del_prm用処理関数
 *
 * SHA256(preimage)がpayment_hashと一致した場合、DBから削除する。
 */
static bool preimg_close_func(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param)
{
    (void)Amount; (void)Expiry;

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)p_db_param;
    preimg_close_t *prm = (preimg_close_t *)p_param;
    uint8_t preimage_hash[LN_SZ_HASH];

    LOGD("compare preimage : ");
    DUMPD(pPreImage, LN_SZ_PREIMAGE);
    ln_calc_preimage_hash(preimage_hash, pPreImage);

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        if (memcmp(preimage_hash, prm->add_htlc[lp].payment_sha256, LN_SZ_HASH) == 0) {
            //一致
            int retval = mdb_cursor_del(p_cur->cursor, 0);
            LOGD("  remove from DB: %s\n", mdb_strerror(retval));
        }
    }

    return false;
}


static int ver_write(ln_lmdb_db_t *pDb, const char *pWif, const char *pNodeName, uint16_t Port)
{
    int         retval;
    MDB_val     key, data;
    int32_t     version = M_DB_VERSION_VAL;

    retval = mdb_dbi_open(pDb->txn, M_DBI_VERSION, MDB_CREATE, &pDb->dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    //version
    key.mv_size = LNDBK_LEN(LNDBK_VER);
    key.mv_data = LNDBK_VER;
    data.mv_size = sizeof(version);
    data.mv_data = &version;
    retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);

    //my node info
    if ((retval == 0) && (pWif != NULL)) {
        key.mv_size = LNDBK_LEN(LNDBK_NODEID);
        key.mv_data = LNDBK_NODEID;

        // LOGD("wif=%s\n", pWif);
        // LOGD("name=%s\n", pNodeName);
        // LOGD("port=%" PRIu16 "\n", Port);
        nodeinfo_t nodeinfo;
        memcpy(nodeinfo.genesis, gGenesisChainHash, LN_SZ_HASH);
        strcpy(nodeinfo.wif, pWif);
        strcpy(nodeinfo.name, pNodeName);
        nodeinfo.port = Port;
        data.mv_size = sizeof(nodeinfo);
        data.mv_data = (void *)&nodeinfo;
        retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
    } else if (retval) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }

LABEL_EXIT:
    return retval;
}


/** DBバージョンチェック
 *
 * @param[in,out]   pDb
 * @param[out]      pWif
 * @param[out]      pNodeName
 * @param[out]      pPort
 * @retval  0   DBバージョン一致
 */
static int ver_check(ln_lmdb_db_t *pDb, char *pWif, char *pNodeName, uint16_t *pPort, uint8_t *pGenesis)
{
    int         retval;
    MDB_val key, data;

    //version
    key.mv_size = LNDBK_LEN(LNDBK_VER);
    key.mv_data = LNDBK_VER;
    retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
    if (retval == 0) {
        int32_t version = *(int32_t *)data.mv_data;
        if (version != M_DB_VERSION_VAL) {
            LOGD("FAIL: version mismatch : %d(require %d)\n", version, M_DB_VERSION_VAL);
            retval = -1;
        }
    } else {
        LOGD("ERR: %s\n", mdb_strerror(retval));
    }
    if ((retval == 0) && (pWif != NULL)) {
        key.mv_size = LNDBK_LEN(LNDBK_NODEID);
        key.mv_data = LNDBK_NODEID;
        retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
        if (retval == 0) {
            const nodeinfo_t *p_nodeinfo = (const nodeinfo_t*)data.mv_data;

            strcpy(pWif, p_nodeinfo->wif);
            strcpy(pNodeName, p_nodeinfo->name);
            *pPort = p_nodeinfo->port;
            if (pGenesis != NULL) {
                memcpy(pGenesis, p_nodeinfo->genesis, LN_SZ_HASH);
            }
            // LOGD("wif=%s\n", pWif);
            // LOGD("name=%s\n", pNodeName);
            // LOGD("port=%" PRIu16 "\n", *pPort);
            // LOGD("genesis=");
            // DUMPD(p_nodeinfo->genesis, LN_SZ_HASH);
        } else {
            LOGD("ERR: %s\n", mdb_strerror(retval));
        }
    }

    return retval;
}


/** addhtlc用db名の作成
 *
 * @note
 *      - "HT" + xxxxxxxx...xx[32*2] + "ddd"
 *        |<-- M_SZ_DBNAME_LEN  -->|
 *
 * @attention
 *      - 予め pDbName に M_PREF_ADDHTLC と channel_idはコピーしておくこと
 */
static void addhtlc_dbname(char *pDbName, int num)
{
    char htlc_str[M_SZ_HTLC_STR + 1];

    snprintf(htlc_str, sizeof(htlc_str), "%03d", num);
    memcpy(pDbName + M_SZ_DBNAME_LEN, htlc_str, M_SZ_HTLC_STR);
    pDbName[M_SZ_DBNAME_LEN + M_SZ_HTLC_STR] = '\0';

}


/** #ln_node_search_channel()処理関数
 *
 * @param[in,out]   self            DBから取得したself
 * @param[in,out]   p_db_param      DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         comp_param_cnl_t構造体
 */
static bool comp_func_cnldel(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_db_param;
    const uint8_t *p_channel_id = (const uint8_t *)p_param;

    bool ret = (memcmp(self->channel_id, p_channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (ret) {
        ln_db_self_del_prm(self, p_db_param);

        //true時は呼び元では解放しないので、ここで解放する
        ln_term(self);
    }
    return ret;
}


/**
 *
 * @param[out]      pCur
 * @retval      0   成功
 */
static int self_cursor_open(lmdb_cursor_t *pCur)
{
    int             retval;

    retval = MDB_TXN_BEGIN(mpDbSelf, NULL, 0, &pCur->txn);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_dbi_open(pCur->txn, NULL, 0, &pCur->dbi);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(pCur->txn);
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(pCur->txn, pCur->dbi, &pCur->cursor);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(pCur->txn);
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    return retval;
}


/**
 *
 * @param[out]      pCur
 */
static void self_cursor_close(lmdb_cursor_t *pCur)
{
    mdb_cursor_close(pCur->cursor);
    MDB_TXN_COMMIT(pCur->txn);
}


/** backup_param_tデータ読込み
 *
 * @param[out]      pData
 * @param[in]       pDb
 * @param[in]       pParam
 * @param[in]       Num             pParam数
 */
static int backup_param_load(void *pData, ln_lmdb_db_t *pDb, const backup_param_t *pParam, size_t Num)
{
    int         retval;
    MDB_val     key, data;

    for (size_t lp = 0; lp < Num; lp++) {
        key.mv_size = strlen(pParam[lp].name);
        key.mv_data = (CONST_CAST char *)pParam[lp].name;
        retval = mdb_get(pDb->txn, pDb->dbi, &key, &data);
        if (retval == 0) {
            //LOGD("%s: %lu\n", pParam[lp].name, pParam[lp].offset);
            memcpy((uint8_t *)pData + pParam[lp].offset, data.mv_data,  pParam[lp].datalen);
        } else {
            LOGD("fail: %s\n", pParam[lp].name);
            if (retval != MDB_NOTFOUND) {
                break;
            } else {
                retval = 0;
            }
        }
    }

    return retval;
}


/** backup_param_tデータ保存
 *
 * @param[in]       pData
 * @param[in]       pDb
 * @param[in]       pParam
 * @param[in]       Num             pParam数
 */
static int backup_param_save(const void *pData, ln_lmdb_db_t *pDb, const backup_param_t *pParam, size_t Num)
{
    int             retval;
    MDB_val         key, data;

    for (size_t lp = 0; lp < Num; lp++) {
        key.mv_size = strlen(pParam[lp].name);
        key.mv_data = (CONST_CAST char *)pParam[lp].name;
        data.mv_size = pParam[lp].datalen;
        data.mv_data = (CONST_CAST uint8_t *)pData + pParam[lp].offset;
        retval = mdb_put(pDb->txn, pDb->dbi, &key, &data, 0);
        if (retval != 0) {
            LOGD("fail: %s\n", pParam[lp].name);
            break;
        }
    }

    return retval;
}


static int initialize_dbself(void)
{
    int retval;

    if (mPath[0] == '\0') {
        ln_lmdb_set_path(".");
    }
    mkdir(mPath, 0755);
    mkdir(ln_lmdb_get_selfpath(), 0755);

    retval = mdb_env_create(&mpDbSelf);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }
    retval = mdb_env_set_maxdbs(mpDbSelf, M_LMDB_MAXDBS);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }
    retval = mdb_env_set_mapsize(mpDbSelf, M_LMDB_MAPSIZE);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }
    retval = mdb_env_open(mpDbSelf, ln_lmdb_get_selfpath(), 0, 0644);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }

    return 0;
}


static int initialize_dbnode(void)
{
    int retval;

    if (mPath[0] == '\0') {
        ln_lmdb_set_path(".");
    }
    mkdir(mPath, 0755);
    mkdir(ln_lmdb_get_nodepath(), 0755);

    retval = mdb_env_create(&mpDbNode);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }

    retval = mdb_env_set_maxdbs(mpDbNode, M_LMDB_NODE_MAXDBS);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }

    retval = mdb_env_set_mapsize(mpDbNode, M_LMDB_NODE_MAPSIZE);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }

    retval = mdb_env_open(mpDbNode, ln_lmdb_get_nodepath(), 0, 0644);
    if (retval != 0) {
        LOGD("ERR: %s\n", mdb_strerror(retval));
        return -1;
    }

    return 0;
}
