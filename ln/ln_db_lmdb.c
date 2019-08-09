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
 *  @brief  DB access(LMDB)
 */
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <ftw.h>
#include <stddef.h>
#include <limits.h>

#include "utl_str.h"
#include "utl_dbg.h"
#include "utl_time.h"
#include "utl_int.h"
#include "utl_mem.h"

#include "btc_crypto.h"
#include "btc_sw.h"
#include "btc_script.h"
#include "btc_dbg.h"

#include "ln_local.h"
#include "ln_msg_anno.h"
#include "ln_node.h"
#include "ln_signer.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"
#include "ln_version.h"


//#define M_DB_DEBUG

/********************************************************************
 * macros
 ********************************************************************/

//INIT_PARAM[]の添字
#define M_INIT_PARAM_CHANNEL    (0)

#define M_MAPSIZE_REMAIN_LIMIT  (2)                         ///< DB compactionを実施する残りpage

#define M_DEFAULT_MAPSIZE       ((size_t)10485760)          // DB最大長[byte](LMDBのデフォルト値)
#define M_CHANNEL_MAXDBS        (12 * 2 * MAX_CHANNELS)     ///< 同時オープンできるDB数
#define M_CHANNEL_MAPSIZE       M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_NODE_MAXDBS           (50)                        ///< 同時オープンできるDB数
#define M_NODE_MAPSIZE          M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_ANNO_MAXDBS           (50)                        ///< 同時オープンできるDB数
//#define M_ANNO_MAPSIZE        ((size_t)4294963200)        // DB最大長[byte] Ubuntu 18.04(64bit)で使用できたサイズ
#define M_ANNO_MAPSIZE          ((size_t)2147483648)        // DB最大長[byte] Raspberry Piで使用できたサイズ
                                                            // 32bit環境ではsize_tが4byteになるため、32bitの範囲内にすること

#define M_WALLET_MAXDBS         (MAX_CHANNELS)              ///< 同時オープンできるDB数
#define M_WALLET_MAPSIZE        M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_FORWARD_MAXDBS        (MAX_CHANNELS * 3)          ///< 同時オープンできるDB数
#define M_FORWARD_MAPSIZE       M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_PAYMENT_MAXDBS        (10)                        ///< 同時オープンできるDB数
#define M_PAYMENT_MAPSIZE       M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_CLOSED_MAXDBS         (10)                        ///< 同時オープンできるDB数
#define M_CLOSED_MAPSIZE        M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_DB_PATH_STR_MAX       (PATH_MAX - 1)              //path max but exclude null char
#define M_DB_DIR                "db"
#define M_CHANNEL_ENV_DIR       "channel"                   ///< channel
#define M_NODE_ENV_DIR          "node"                      ///< node
#define M_ANNO_ENV_DIR          "anno"                      ///< announcement
#define M_WALLET_ENV_DIR        "wallet"                    ///< 1st layer wallet
#define M_FORWARD_ENV_DIR       "forward"                   ///< forward
#define M_PAYMENT_ENV_DIR       "payment"                   ///< payment
#define M_CLOSED_ENV_DIR        "closed"                    ///< closed


#define M_NUM_CHANNEL_BUFS      (3)                         ///< DB保存するvariable長データ数
                                                            //      funding
                                                            //      local shutdown scriptPubKeyHash
                                                            //      remote shutdown scriptPubKeyHash

#define M_SZ_PREF_STR           (2)
#define M_PREF_CHANNEL          "CN"                        ///< channel
#define M_PREF_SECRET           "SE"                        ///< secret
#define M_PREF_HTLC             "HT"                        ///< htlc
#define M_PREF_REVOKED_TX       "RV"                        ///< revoked transaction
#define M_PREF_FORWARD_ADD_HTLC "AD"                        ///< forward add htlc msg
#define M_PREF_FORWARD_DEL_HTLC "DL"                        ///< forward del htlc msg

#define M_DBI_CNLANNO           "channel_anno"              ///< 受信したchannel_announcement/channel_update
#define M_DBI_CNLANNO_INFO      "channel_anno_info"         ///< channel_announcement/channel_updateの受信元・送信先
#define M_DBI_NODEANNO          "node_anno"                 ///< 受信したnode_announcement
#define M_DBI_NODEANNO_INFO     "node_anno_info"            ///< node_announcementの受信元・送信先
#define M_DBI_CNLANNO_RECV      "channel_anno_recv"         ///< channel_announcementのnode_id
#define M_DBI_CNL_OWNED         "channel_owned"             ///< 自分の持つchannel
#define M_DBI_ROUTE_SKIP        LN_DB_DBI_ROUTE_SKIP        ///< 送金失敗short_channel_id
#define M_DBI_PREIMAGE          "preimage"                  ///< preimage
#define M_DBI_PAYMENT_HASH      "payment_hash"              ///< revoked transaction close用
#define M_DBI_WALLET            "wallet"                    ///< wallet
#define M_DBI_VERSION           "version"                   ///< verion
#define M_DBI_PAYMENT           "payment"                   ///< payment
#define M_DBI_SHARED_SECRETS    "shared_secrets"            ///< shared secrets
#define M_DBI_ROUTE             "route"                     ///< route
#define M_DBI_PAYMENT_INVOICE   "invoice"                   ///< payment invoice
#define M_DBI_PAYMENT_INFO      "payment_info"              ///< payment info

#define M_SZ_CHANNEL_DB_NAME_STR    (M_SZ_PREF_STR + LN_SZ_CHANNEL_ID * 2)
#define M_SZ_FORWARD_DB_NAME_STR    (M_SZ_PREF_STR + LN_SZ_SHORT_CHANNEL_ID * 2)
#define M_SZ_HTLC_IDX_STR           (3)     // "%03d" 0-482
#define M_SZ_CNLANNO_INFO_KEY       (LN_SZ_SHORT_CHANNEL_ID + sizeof(char))
#define M_SZ_NODEANNO_INFO_KEY      (BTC_SZ_PUBKEY)
#define M_SZ_FORWARD_KEY            (LN_SZ_SHORT_CHANNEL_ID + sizeof(uint64_t))
#define M_SZ_PAYMENT_ID_KEY         (sizeof(uint64_t))

#define M_KEY_PREIMAGE          "preimage"
#define M_SZ_PREIMAGE           (sizeof(M_KEY_PREIMAGE) - 1)
#define M_KEY_ONION_ROUTE       "onion_route"
#define M_SZ_ONION_ROUTE        (sizeof(M_KEY_ONION_ROUTE) - 1)
#define M_KEY_SHARED_SECRET     "shared_secret"
#define M_SZ_SHARED_SECRET      (sizeof(M_KEY_SHARED_SECRET) - 1)
#define M_KEY_PAYMENT_ID        "payment_id"
#define M_SZ_PAYMENT_ID         (sizeof(M_KEY_PAYMENT_ID) - 1)


/********************************************************************
 * macro functions
 ********************************************************************/

#define M_SIZE(type, member)        (sizeof(((type *)0)->member))
#define M_ITEM(type, member)        { #member, M_SIZE(type, member), offsetof(type, member) }
#define MM_ITEM(type1, member1, type2, member2) \
                                    { #member1 "." #member2, M_SIZE(type2, member2), \
                                        offsetof(type1, member1) + offsetof(type2, member2) }
#define MMN_ITEM(type1, member1, n, type2, member2) \
                                    { #member1 "." #member2 ":" #n, M_SIZE(type2, member2), \
                                        offsetof(type1, member1) + sizeof(type2) * n + offsetof(type2, member2) }
#define M_BUF_ITEM(idx, member)     { p_variable_items[idx].p_name = #member; p_variable_items[idx].p_buf = \
                                        (CONST_CAST utl_buf_t*)&pChannel->member; }

#ifndef M_DB_DEBUG
#define MDB_TXN_BEGIN(a, b, c, d)   my_mdb_txn_begin(a, b, c, d, __LINE__)
#define MDB_TXN_ABORT(a)            { mdb_txn_abort(a); (a) = NULL; }
#define MDB_TXN_COMMIT(a)           { my_mdb_txn_commit(a, __LINE__); (a) = NULL; }
#define MDB_DBI_OPEN(a, b, c, d)    my_mdb_dbi_open(a, b, c, d, __LINE__)
#define MDB_DBI_CLOSE(a, b)         mdb_dbi_close(a, b)
#define MDB_CURSOR_CLOSE(a)         { mdb_cursor_close(a); (a) = NULL; }

#define MDB_TXN_CHECK_CHANNEL(a)    //none
#define MDB_TXN_CHECK_NODE(a)       //none
#define MDB_TXN_CHECK_ANNO(a)       //none
#define MDB_TXN_CHECK_WALLET(a)     //none
#define MDB_TXN_CHECK_FORWARD(a)    //none
#define MDB_TXN_CHECK_PAYMENT(a)    //none
#else
static volatile int g_cnt[6];
static pthread_mutex_t  g_cnt_mux;
#define MDB_TXN_BEGIN(a, b, c, d)   my_mdb_txn_begin(a, b, c, d, __LINE__);
#define MDB_TXN_ABORT(a)            { my_mdb_txn_abort(a, __LINE__); (a) = NULL; }
#define MDB_TXN_COMMIT(a)           { my_mdb_txn_commit(a, __LINE__); (a) = NULL; }
#define MDB_DBI_OPEN(a, b, c, d)    my_mdb_dbi_open(a, b, c, d, __LINE__)
#define MDB_DBI_CLOSE(a, b)         my_mdb_dbi_close(a, b, __LINE__)
#define MDB_CURSOR_CLOSE(a)         { mdb_cursor_close(a); (a) = NULL; }

#define MDB_TXN_CHECK_CHANNEL(a)    if (mdb_txn_env(a) != mpEnvChannel) { LOGE("ERR: txn not CHANNEL\n"); abort(); }
#define MDB_TXN_CHECK_NODE(a)       if (mdb_txn_env(a) != mpEnvNode) { LOGE("ERR: txn not NODE\n"); abort(); }
#define MDB_TXN_CHECK_ANNO(a)       if (mdb_txn_env(a) != mpEnvAnno) { LOGE("ERR: txn not ANNO\n"); abort(); }
#define MDB_TXN_CHECK_WALLET(a)     if (mdb_txn_env(a) != mpEnvWallet) { LOGE("ERR: txn not WALLET\n"); abort(); }
#define MDB_TXN_CHECK_FORWARD(a)    if (mdb_txn_env(a) != mpEnvForward) { LOGE("ERR: txn not FORWARD\n"); abort(); }
#define MDB_TXN_CHECK_PAYMENT(a)    if (mdb_txn_env(a) != mpEnvPayment) { LOGE("ERR: txn not PAYMENT\n"); abort(); }
#endif


/********************************************************************
 * typedefs
 ********************************************************************/

/**
 * @typedef fixed_item_t
 * @brief   fixed item
 */
typedef struct fixed_item_t {
    const char  *p_name;
    size_t      data_len;
    size_t      offset;
} fixed_item_t;


/**
 * @typedef variable_item_t
 * @brief   variable item
 */
typedef struct variable_item_t {
    const char  *p_name;
    utl_buf_t   *p_buf;
} variable_item_t;


/**
 * @typedef init_param_t
 * @brief   DB初期化パラメータ
 */
typedef struct {
    MDB_env         **pp_env;
    const char      *p_path;
    MDB_dbi         maxdbs;         //mdb_env_set_maxdbs()
    size_t          mapsize;        //mdb_env_set_mapsize()
    unsigned int    open_flag;      //mdb_env_open()
} init_param_t;


/** @typedef    node_info_t
 *  @brief      [version]に保存するnode情報
 */
typedef struct {
    uint8_t     genesis[BTC_SZ_HASH256];
    char        wif[BTC_SZ_WIF_STR_MAX + 1];
    char        name[LN_SZ_ALIAS_STR + 1];
    uint16_t    port;
    uint8_t     create_bhash[BTC_SZ_HASH256];
} node_info_t;


/** @typedef    preimage_info_ver68_t
 *  @brief      [preimage]に保存するpreimage情報(DB ver.-68)
 */
typedef struct {
    uint64_t amount;            ///< amount[satoshi]
    uint64_t creation;          ///< invoice creation epoch
    uint32_t expiry;            ///< expiry[sec]
} preimage_info_ver68_t;


/** @typedef    preimage_info_t
 *  @brief      [preimage]に保存するpreimage情報(DB ver.-69)
 */
typedef struct {
    uint64_t amount;            ///< amount[satoshi]
    uint64_t creation;          ///< invoice creation epoch
    uint32_t expiry;            ///< expiry[sec]
    uint8_t state;              ///< ln_lmdb_preimage_state_t
    char bolt11[1];             ///< BOLT11 invoice string
} preimage_info_t;


/** #ln_db_channel_del_param()用(ln_db_preimage_search)
 *
 */
typedef struct {
    const ln_htlc_t  *p_htlcs;
} preimage_close_t;


/********************************************************************
 * static variables
 ********************************************************************/

//LMDB
static MDB_env      *mpEnvChannel = NULL;       //channel
static MDB_env      *mpEnvNode = NULL;          //node
static MDB_env      *mpEnvAnno = NULL;          //announcement
static MDB_env      *mpEnvWallet = NULL;        //wallet
static MDB_env      *mpEnvForward = NULL;       //forward
static MDB_env      *mpEnvPayment = NULL;       //payment

static char         mPath[M_DB_PATH_STR_MAX + 1];

static char         mPathChannel[M_DB_PATH_STR_MAX + 1];
static char         mPathNode[M_DB_PATH_STR_MAX + 1];
static char         mPathAnno[M_DB_PATH_STR_MAX + 1];
static char         mPathWallet[M_DB_PATH_STR_MAX + 1];
static char         mPathForward[M_DB_PATH_STR_MAX + 1];
static char         mPathPayment[M_DB_PATH_STR_MAX + 1];

static pthread_mutex_t  mMuxAnno;
static MDB_txn          *mpTxnAnno;


/**
 *  @var    DBCHANNEL_SECRET
 *  @brief  ln_channel_tのsecret
 */
static const fixed_item_t DBCHANNEL_SECRET[] = {
    MM_ITEM(ln_channel_t, keys_local, ln_derkey_local_keys_t, secrets),             //[KEYS_01]
    MM_ITEM(ln_channel_t, keys_local, ln_derkey_local_keys_t, storage_seed),        //[KEYS_01]
    MM_ITEM(ln_channel_t, keys_local, ln_derkey_local_keys_t, next_storage_index),  //[KEYS_01]
};


/**
 *  @var    DBCHANNEL_VALUES
 *  @brief  ln_channel_tのほぼすべて
 */
static const fixed_item_t DBCHANNEL_VALUES[] = {
    //
    //conn
    //
    M_ITEM(ln_channel_t, peer_node_id),             //[CONN_01]
    M_ITEM(ln_channel_t, last_connected_addr),      //[CONN_02]
    M_ITEM(ln_channel_t, status),                   //[CONN_03]

    //
    //keys
    //
    //[KEYS_01]keys_local --> secret
    MM_ITEM(ln_channel_t, keys_remote, ln_derkey_remote_keys_t, basepoints),                //[KEYS_02]
    MM_ITEM(ln_channel_t, keys_remote, ln_derkey_remote_keys_t, next_storage_index),        //[KEYS_02]
    MM_ITEM(ln_channel_t, keys_remote, ln_derkey_remote_keys_t, storage),                   //[KEYS_02]
    MM_ITEM(ln_channel_t, keys_remote, ln_derkey_remote_keys_t, per_commitment_point),      //[KEYS_02]
    MM_ITEM(ln_channel_t, keys_remote, ln_derkey_remote_keys_t, prev_per_commitment_point), //[KEYS_02]

    //
    //fund
    //
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, role),                             //[FUND_01]
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, state),                            //[FUND_01]
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, txid),                             //[FUND_01]
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, txindex),                          //[FUND_01]
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, funding_satoshis),                 //[FUND_01]
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, minimum_depth),                    //[FUND_01]
    M_ITEM(ln_channel_t, funding_blockhash),    //[FUNDSPV_01]
    M_ITEM(ln_channel_t, funding_last_confirm), //[FUNDSPV_02]

    //
    //anno
    //
    M_ITEM(ln_channel_t, anno_flag),       //[ANNO_01]
    //[ANNO_02]anno_param
    //[ANNO_03]cnl_anno

    //
    //init
    //
    //[INIT_01]init_flag
    //[INIT_02]lfeature_local
    //[INIT_03]lfeature_remote
    //[INIT_04]reest_next_local_commit_num
    //[INIT_05]reest_next_remote_revoke_num

    //
    //clse
    //
    //[CLSE_01]---
    //[CLSE_02]tx_closing
    M_ITEM(ln_channel_t, shutdown_flag),   //[CLSE_03]shutdown_flag
    //[CLSE_04]close_fee_sat
    //[CLSE_05]close_last_fee_sat
    //[CLSE_06]shutdown_scriptpk_local --> script
    //[CLSE_07]shutdown_scriptpk_remote --> script

    //
    //revk
    //
    //[REVK_01]p_revoked_vout --> revoked db
    //[REVK_02]p_revoked_wit  --> revoked db
    //[REVK_03]p_revoked_type --> revoked db
    //[REVK_04]revoked_sec --> revoked db
    //[REVK_05]revoked_num --> revoked db
    //[REVK_06]revoked_cnt --> revoked db
    //[REVK_07]revoked_chk --> revoked db

    //
    //norm
    //
    M_ITEM(ln_channel_t, channel_id),           //[NORM_01]
    M_ITEM(ln_channel_t, short_channel_id),     //[NORM_02]
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, updates),                              //[NORM_03]
    //[NORM_03]htlcs --> HTLC
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, next_htlc_id),                         //[NORM_03]
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, fee_updates),                          //[NORM_03]
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, feerate_per_kw_irrevocably_committed), //[NORM_03]
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, next_fee_update_id),                   //[NORM_03]

    //
    //comm
    //
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, dust_limit_sat),                   //[COMM_01]commit_info_local
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, max_htlc_value_in_flight_msat),    //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, channel_reserve_sat),              //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, htlc_minimum_msat),                //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, to_self_delay),                    //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, max_accepted_htlcs),               //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, remote_sig),                       //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, txid),                             //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, num_htlc_outputs),                 //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, commit_num),                       //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, revoke_num),                       //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, local_msat),                       //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, remote_msat),                      //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, obscured_commit_num_mask),         //[COMM_01]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, dust_limit_sat),                  //[COMM_02]commit_info_remote
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, max_htlc_value_in_flight_msat),   //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, channel_reserve_sat),             //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, htlc_minimum_msat),               //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, to_self_delay),                   //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, max_accepted_htlcs),              //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, remote_sig),                      //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, txid),                            //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, num_htlc_outputs),                //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, commit_num),                      //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, revoke_num),                      //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, local_msat),                      //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, remote_msat),                     //[COMM_02]
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, obscured_commit_num_mask),        //[COMM_02]
    M_ITEM(ln_channel_t, prev_remote_commit_txid),                                                //[COMM_03]and more
    //
    //erro
    //
    //[ERRO_01]err
    //[ERRO_02]err_msg

    //
    //apps
    //
    //[APPS_01]p_callback
    //[APPS_02]p_param
};


/**
 *  @var    DBHTLC_VALUES
 *  @brief  HTLC
 */
static const fixed_item_t DBHTLC_VALUES[] = {
    M_ITEM(ln_htlc_t, enabled),
    M_ITEM(ln_htlc_t, id),
    M_ITEM(ln_htlc_t, amount_msat),
    M_ITEM(ln_htlc_t, cltv_expiry),
    M_ITEM(ln_htlc_t, payment_hash),
    //buf_preimage --> HTLC buf
    //buf_onion_reason --> HTLC buf
    M_ITEM(ln_htlc_t, remote_sig),
    //buf_shared_secret --> HTLC buf
    //buf_forward_msg --> HTLC buf
};


// LMDB initialize parameter
static const init_param_t INIT_PARAM[] = {
    { &mpEnvChannel, mPathChannel, M_CHANNEL_MAXDBS, M_CHANNEL_MAPSIZE, 0 },
    { &mpEnvNode, mPathNode, M_NODE_MAXDBS, M_NODE_MAPSIZE, 0 },
    { &mpEnvAnno, mPathAnno, M_ANNO_MAXDBS, M_ANNO_MAPSIZE, MDB_NOSYNC },
    { &mpEnvWallet, mPathWallet, M_WALLET_MAXDBS, M_WALLET_MAPSIZE, 0 },
    { &mpEnvForward, mPathForward, M_FORWARD_MAXDBS, M_FORWARD_MAPSIZE, 0 },
    { &mpEnvPayment, mPathPayment, M_PAYMENT_MAXDBS, M_PAYMENT_MAPSIZE, 0 },
};


/********************************************************************
 * prototypes
 ********************************************************************/

static bool set_path(char *pPath, size_t Size, const char *pDir, const char *pName);

static int db_open(ln_lmdb_db_t *pDb, MDB_env *env, const char *pDbName, int OptTxn, int OptDb);
static int db_open_2(ln_lmdb_db_t *pDb, MDB_txn *pTxn, const char *pDbName, int OptDb);

static int channel_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);
static int channel_htlc_load(ln_channel_t *pChannel, ln_lmdb_db_t *pDb);
static int channel_htlc_save(const ln_channel_t *pChannel, ln_lmdb_db_t *pDb);
static int channel_save(const ln_channel_t *pChannel, ln_lmdb_db_t *pDb);
static int channel_item_load(ln_channel_t *pChannel, const fixed_item_t *pItems, ln_lmdb_db_t *pDb);
static int channel_item_save(const ln_channel_t *pChannel, const fixed_item_t *pItems, ln_lmdb_db_t *pDb);
static int channel_secret_load(ln_channel_t *pChannel, ln_lmdb_db_t *pDb);
static int channel_secret_restore(ln_channel_t *pChannel);
static int channel_cursor_open(lmdb_cursor_t *pCur, bool bWritable);
static void channel_cursor_close(lmdb_cursor_t *pCur, bool bWritable);
static void channel_htlc_db_name(char *pDbName, int num);
static bool channel_cmp_func_channel_del(ln_channel_t *pChannel, void *pDbParam, void *pParam);
static bool channel_search(ln_db_func_cmp_t pFunc, void *pFuncParam, bool bWritable, bool bRestore, bool bCont);
static void channel_copy_closed(MDB_txn *pTxn, const char *pChannelStr);

static int node_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);

static int cnlanno_load(ln_lmdb_db_t *pDb, utl_buf_t *pCnlAnno, uint64_t ShortChannelId);
static int cnlanno_save(ln_lmdb_db_t *pDb, const utl_buf_t *pCnlAnno, uint64_t ShortChannelId);
static int cnlupd_load(ln_lmdb_db_t *pDb, utl_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir);
static int cnlupd_save(ln_lmdb_db_t *pDb, const utl_buf_t *pCnlUpd, const ln_msg_channel_update_t *pUpd);
static int cnlanno_cur_load(MDB_cursor *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf, MDB_cursor_op Op);
static int nodeanno_load(ln_lmdb_db_t *pDb, utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);
static int nodeanno_save(ln_lmdb_db_t *pDb, const utl_buf_t *pNodeAnno, const uint8_t *pNodeId, uint32_t Timestamp);

static bool annoinfos_trim_node_id(
    const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo);
static bool annoinfos_trim_node_id_selected(
    const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo,
    const uint64_t *pShortChannelIds, size_t Num);
static bool annoinfos_trim_node_id_timestamp(
    const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo,
    uint32_t TimeFirst, uint32_t TimeRange);
static bool annoinfos_trim_node_id_nodeanno(
    const uint8_t *pNodeId, uint64_t ShortChannelId, MDB_dbi DbiNodeannoInfo,
    ln_lmdb_db_t *pDb);
static bool annoinfos_del_all(MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo);

static void cnlanno_info_set_key(uint8_t *pKeyData, MDB_val *pKey, uint64_t ShortChannelId, char Type);
static bool cnlanno_info_parse_key(MDB_val *pKey, uint64_t *pShortChannelId, char *pType);
static void nodeanno_info_set_key(uint8_t *pKeyData, MDB_val *pKey, const uint8_t *pNodeId);
//static bool nodeanno_info_parse_key(MDB_val *pKey, uint8_t *pNodeId);

static bool annoinfo_add_node_id(MDB_val *pData, const uint8_t *pNodeId);
static bool annoinfo_add(ln_lmdb_db_t *pDb, MDB_val *pMdbKey, MDB_val *pMdbData, const uint8_t *pNodeId);
static bool annoinfo_search_node_id(MDB_val *pMdbData, const uint8_t *pNodeId);
static bool annoinfo_cur_trim_node_id(MDB_cursor *pCursor, const uint8_t *pNodeId);
static bool annoinfo_trim_node_id(MDB_val *pData, const uint8_t *pNodeId);
static void annoinfo_cur_add(MDB_cursor *pCursor, const uint8_t *pNodeId);
static void anno_del_prune(void);

static bool preimage_open(ln_lmdb_db_t *pDb, MDB_txn *pTxn);
static void preimage_close(ln_lmdb_db_t *pDb, bool bCommit);
static bool preimage_cmp_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *pDbParam, void *pParam);
static bool preimage_cmp_all_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *pDbParam, void *pParam);
static bool preimage_search(ln_db_func_preimage_t pFunc, bool bCommit, void *pFuncParam);

static int wallet_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);

static int version_write(ln_lmdb_db_t *pDb, const char *pWif, const char *pNodeName, uint16_t Port);
static int version_check(ln_lmdb_db_t *pDb, int32_t *pVer, char *pWif, char *pNodeName, uint16_t *pPort, uint8_t *pGenesis, bool bAutoUpdate);

static bool forward_create(uint64_t NextShortChannelId, const char *pDbNamePrefix);
static int forward_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);
static int forward_db_open_2(ln_lmdb_db_t *pDb, MDB_txn *pTxn, const char *pDbName, int OptDb);
static int forward_save(ln_lmdb_db_t *pDb, const ln_db_forward_t *pForward);
static bool forward_save_2(const ln_db_forward_t *pForward, const char *pDbNamePrefix);
static bool forward_save_3(const ln_db_forward_t *pForward, const char *pDbNamePrefix, MDB_txn *pTxn);
static int forward_del(ln_lmdb_db_t *pDb, uint64_t PrevShortChannelId, uint64_t PrevHtlcId);
static bool forward_del_2(uint64_t NextShortChannelId, uint64_t PrevShortChannelId, uint64_t PrevHtlcId, const char *pDbNamePrefix);
static bool forward_drop(uint64_t NextShortChannelId, const char *pDbNamePrefix);
static bool forward_cur_open(void **ppCur, uint64_t NextShortChannelId, const char *pDbNamePrefix);
static void forward_cur_close(void *pCur, bool bCommit);
static int forward_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);
static bool forward_cur_get(void *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg);
static int forward_cur_load(
    MDB_cursor *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg, MDB_cursor_op Op);
static bool forward_cur_del(void *pCur);
static void forward_set_db_name(char *pDbName, uint64_t NextShortChannelId, const char *pDbNamePrefix);
static void forward_set_key(uint8_t *pKeyData, MDB_val *pKey, uint64_t PrevShortChannelId, uint64_t PrevHtlcId);
static bool forward_parse_key(MDB_val *pKey, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId);

static int payment_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);
static int payment_db_open_2(ln_lmdb_db_t *pDb, MDB_txn *pTxn, const char *pDbName, int OptDb);
static void payment_id_set_key(uint8_t *pKeyData, MDB_val *pKey, uint64_t PaymentId);
static bool payment_id_parse_key(MDB_val *pKey, uint64_t *pPaymentId);
static bool payment_save(const char *pDbName, uint64_t PaymentId, const uint8_t *pData, uint32_t Len);
static int payment_load(ln_lmdb_db_t *pDb, utl_buf_t *pBuf, uint64_t PaymentId);
static bool payment_load_2(const char *pDbName, utl_buf_t *pBuf, uint64_t PaymentId);
static bool payment_load_3(const char *pDbName, utl_buf_t *pBuf, uint64_t PaymentId, MDB_txn *pTxn);
static bool payment_del(const char *pDbName, uint64_t PaymentId);

static bool payment_cur_open(void **ppCur, const char *pDbName);
static void payment_cur_close(void *pCur, bool bCommit);
static bool payment_cur_get(void *pCur, uint64_t *pPaymentId, utl_buf_t *pBuf);
static int payment_cur_load(
    MDB_cursor *pCur, uint64_t *pPaymentId, utl_buf_t *pBuf, MDB_cursor_op Op);
static bool payment_cur_del(void *pCur);

static int fixed_items_load(void *pData, ln_lmdb_db_t *pDb, const fixed_item_t *pItems, size_t Num);
static int fixed_items_save(const void *pData, ln_lmdb_db_t *pDb, const fixed_item_t *pItems, size_t Num);

static int init_db_env(const init_param_t  *p_param);
static int rm_files(const char *pPath, const struct stat *pStat, int Type, struct FTW *pFtwb);
static bool rmdir_recursively(const char *pPath);
static int lmdb_init(const init_param_t  *p_param);
static int lmdb_compaction(const init_param_t  *p_param);

static bool auto_update_68_to_69(void);
static bool auto_update_69_to_70(void);

#ifndef M_DB_DEBUG
static inline int my_mdb_txn_begin(MDB_env *pEnv, MDB_txn *pParent, unsigned int Flags, MDB_txn **ppTxn, int Line) {
    int retval = mdb_txn_begin(pEnv, pParent, Flags, ppTxn);
    if ((retval != 0) && (retval != MDB_NOTFOUND)) {
        LOGE("ERR(%d): %s\n", Line, mdb_strerror(retval));
    }
    return retval;
}

static inline int my_mdb_txn_commit(MDB_txn *pTxn, int Line) {
    int txn_retval = mdb_txn_commit(pTxn);
    if (txn_retval) {
        LOGE("ERR(%d): %s\n", Line, mdb_strerror(txn_retval));
        if (txn_retval == MDB_BAD_TXN) {
            mdb_txn_abort(pTxn);
            LOGE("FATAL: FATAL DB ERROR!\n");
            fprintf(stderr, "FATAL DB ERROR!\n");
            exit(EXIT_FAILURE);
        }
    }
    return txn_retval;
}

static inline int my_mdb_dbi_open(MDB_txn *pTxn, const char *pName, unsigned int Flags, MDB_dbi *pDbi, int Line) {
    int retval = mdb_dbi_open(pTxn, pName, Flags, pDbi);
    if (retval && (retval != MDB_NOTFOUND)) {
        LOGE("ERR(%d): %s\n", Line, mdb_strerror(retval));
    }
    return retval;
}
#else
static inline int env_number(const MDB_env *env) {
    int env_num = -1;
    for (size_t lp = 0; lp < ARRAY_SIZE(INIT_PARAM); lp++) {
        if (env == *(INIT_PARAM[lp].pp_env)) {
            env_num = lp;
            break;
        }
    }
    return env_num;
}
static inline int env_inc(const MDB_env *env, int *pCnt) {
    pthread_mutex_lock(&g_cnt_mux);
    int idx = env_number(env);
    g_cnt[idx]++;
    *pCnt = g_cnt[idx];
    pthread_mutex_unlock(&g_cnt_mux);
    return idx;
}
static inline int env_dec(const MDB_env *env, int *pCnt) {
    pthread_mutex_lock(&g_cnt_mux);
    int idx = env_number(env);
    g_cnt[idx]--;
    *pCnt = g_cnt[idx];
    pthread_mutex_unlock(&g_cnt_mux);
    return idx;
}
static inline int my_mdb_txn_begin(MDB_env *env, MDB_txn *pParent, unsigned int Flags, MDB_txn **ppTxn, int Line) {
    assert(sizeof(g_cnt) <= sizeof(INIT_PARAM));
    int cnt;
    int idx = env_inc(env, &cnt);
    LOGD("mdb_txn_begin:%d:[%d]open=%d(%d)\n", Line, idx, cnt, (int)Flags);
    MDB_envinfo stat;
    if (mdb_env_info(env, &stat) == 0) {
        LOGD("  last txnid=%lu\n", stat.me_last_txnid);
    }
    int retval = mdb_txn_begin(env, pParent, Flags, ppTxn);
    if (retval == 0) {
        LOGD("  txnid=%lu\n", (unsigned long)mdb_txn_id(*ppTxn));
    } else {
        LOGE("ERR(%d): %s\n", Line, mdb_strerror(retval));
        if (retval != MDB_NOTFOUND) abort();
        idx = env_dec(env, &cnt);
        LOGD("  fail :%d:[%d]open=%d\n", Line, idx, cnt);
    }
    return retval;
}

static inline int my_mdb_txn_commit(MDB_txn *pTxn, int Line) {
    int cnt;
    int idx = env_dec(mdb_txn_env(pTxn), &cnt);
    LOGD("mdb_txn_commit:%d:[%d]open=%d\n", Line, idx, cnt);
    if (cnt < 0) {
        LOGE("too many txn_commit[%d]\n", idx);
        abort();
    }
    int retval = mdb_txn_commit(pTxn);
    if (retval) {
        LOGE("ERR(%d): %s\n", Line, mdb_strerror(retval));
        if (retval != MDB_NOTFOUND) abort();
    }
    return retval;
}

static inline void my_mdb_txn_abort(MDB_txn *pTxn, int Line) {
    int cnt;
    int idx = env_dec(mdb_txn_env(pTxn), &cnt);
    LOGD("mdb_txn_abort:%d:[%d]open=%d\n", Line, idx, cnt);
    if (cnt < 0) {
        LOGE("too many txn_abort[%d]\n", idx);
        abort();
    }
    mdb_txn_abort(pTxn);
}


static inline int my_mdb_dbi_open(MDB_txn *pTxn, const char *pName, unsigned int Flags, MDB_dbi *pDbi, int Line) {
    int retval = mdb_dbi_open(pTxn, pName, Flags, pDbi);
    LOGD("mdb_dbi_open(%d): retval=%d\n", Line, retval);
    if (retval == 0) {
        LOGD("   DBI=%d\n", (int)*pDbi);
    } else {
        LOGE("ERR(%d): %s\n", Line, mdb_strerror(retval));
        if (retval != MDB_NOTFOUND) abort();
    }
    return retval;
}

static inline void my_mdb_dbi_close(MDB_env *env, MDB_dbi Dbi, int Line) {
    mdb_dbi_close(env, Dbi);
    LOGD("mdb_dbi_close(%d) DBI=%d\n", Line, (int)Dbi);
}
#endif  //M_DB_DEBUG


/** copy MDB_val
 *
 * @param[out]      pDst        destination data
 * @param[in]       pSrc        source data
 * @retval  (uint8_t *)pDst->mv_data
 * @note
 *      - mdb_cursor_put() sometime change `key`/`data` from mdb_cursor_get().
 *          For safety use, mdb_cursor_put() use copied `key`.
 */
static inline uint8_t *my_mdb_val_alloccopy(MDB_val *pDst, const MDB_val *pSrc) {
    void *p = UTL_DBG_MALLOC(pSrc->mv_size);
    if (!p) return NULL;
    memcpy(p, pSrc->mv_data, pSrc->mv_size);
    pDst->mv_size = pSrc->mv_size;
    pDst->mv_data = p;
    return (uint8_t *)p;
}


/********************************************************************
 * public functions
 ********************************************************************/

bool ln_lmdb_set_home_dir(const char *pPath)
{
    char path[M_DB_PATH_STR_MAX + 1];

    if (!utl_str_copy_and_fill_zeros(path, pPath, sizeof(path))) return false;

    int len = (int)strlen(path);
    while (--len >= 0 && path[len] == '/') {
        ;
    }
    path[len + 1] = '\0';

    if (!set_path(mPath, sizeof(mPath), path, M_DB_DIR)) return false;
    if (!set_path(mPathChannel, sizeof(mPathChannel), mPath, M_CHANNEL_ENV_DIR)) return false;
    if (!set_path(mPathNode, sizeof(mPathNode), mPath, M_NODE_ENV_DIR)) return false;
    if (!set_path(mPathAnno, sizeof(mPathAnno), mPath, M_ANNO_ENV_DIR)) return false;
    if (!set_path(mPathWallet, sizeof(mPathWallet), mPath, M_WALLET_ENV_DIR)) return false;
    if (!set_path(mPathForward, sizeof(mPathForward), mPath, M_FORWARD_ENV_DIR)) return false;
    if (!set_path(mPathPayment, sizeof(mPathPayment), mPath, M_PAYMENT_ENV_DIR)) return false;

    LOGD("db dir: %s\n", mPath);
    LOGD("  channel: %s\n", mPathChannel);
    LOGD("  node: %s\n", mPathNode);
    LOGD("  anno: %s\n", mPathAnno);
    LOGD("  wallet: %s\n", mPathWallet);
    LOGD("  forward: %s\n", mPathForward);
    return true;
}


bool ln_db_have_db_dir(void)
{
    struct stat buf;
    int retval = stat(M_DB_DIR, &buf);
    return (retval == 0) && S_ISDIR(buf.st_mode);
}


const char *ln_lmdb_get_channel_db_path(void)
{
    return mPathChannel;
}


const char *ln_lmdb_get_node_db_path(void)
{
    return mPathNode;
}


const char *ln_lmdb_get_anno_db_path(void)
{
    return mPathAnno;
}


const char *ln_lmdb_get_wallet_db_path(void)
{
    return mPathWallet;
}


const char *ln_lmdb_get_forward_db_path(void)
{
    return mPathForward;
}


const char *ln_lmdb_get_payment_db_path(void)
{
    return mPathPayment;
}


void ln_lmdb_get_closed_db_path(char *pPath, const char *pChannelStr)
{
    if (pChannelStr == NULL) {
        snprintf(pPath, PATH_MAX, "%.1024s/" M_CLOSED_ENV_DIR, mPath);
    } else {
        snprintf(pPath, PATH_MAX, "%.1024s/" M_CLOSED_ENV_DIR "/%.1024s", mPath, pChannelStr);
    }
}


bool ln_db_init(char *pWif, char *pNodeName, uint16_t *pPort, bool bAutoUpdate, bool bStdErr)
{
    int             retval;
    ln_lmdb_db_t    db;

    LOGD("node: %s\n", pNodeName);

    if (mPath[0] == '\0') {
        ln_lmdb_set_home_dir(".");
    }

    if (mkdir(mPath, 0755) && errno != EEXIST) {
        LOGE("fail: mkdir, errno=%d\n", errno);
        return false;
    }

    if (mpEnvChannel) {
        LOGE("fail: already initialized\n");
        abort();
    }

#ifdef M_DB_DEBUG
    pthread_mutex_init(&g_cnt_mux, NULL);
#endif

    for (size_t lp = 0; lp < ARRAY_SIZE(INIT_PARAM); lp++) {
        retval = init_db_env(&INIT_PARAM[lp]);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    }

    if (bStdErr) fprintf(stderr, "DB checking: open...");

    retval = MDB_TXN_BEGIN(mpEnvChannel, NULL, 0, &db.p_txn);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = MDB_DBI_OPEN(db.p_txn, M_DBI_VERSION, 0, &db.dbi);
    if (retval) {
        //新規の場合は作成/保存する
        //      node_id : 生成
        //      alias : 指定が無ければ生成
        //      port : 指定された値
        LOGD("create node DB\n");
        uint8_t pub[BTC_SZ_PUBKEY];
        ln_node_create_key(pWif, pub);

        if (strlen(pNodeName) == 0) {
            sprintf(pNodeName, "node_%02x%02x%02x%02x%02x%02x",
                pub[0], pub[1], pub[2], pub[3], pub[4], pub[5]);
        }
        if (*pPort == 0) {
            *pPort = LN_PORT_DEFAULT;
        }
        //LOGD("wif=%s\n", pWif);
        LOGD("alias=%s\n", pNodeName);
        LOGD("port=%d\n", *pPort);
        retval = version_write(&db, pWif, pNodeName, *pPort);
        if (retval) {
            if (bStdErr) fprintf(stderr, "create version db\n");
            MDB_TXN_ABORT(db.p_txn);
            goto LABEL_EXIT;
        }
    }

    if (bStdErr) fprintf(stderr, "done!\nDB checking: version...");

    int32_t ver;
    uint8_t genesis[BTC_SZ_HASH256];
    retval = version_check(&db, &ver, pWif, pNodeName, pPort, genesis, bAutoUpdate);
    MDB_TXN_COMMIT(db.p_txn);
    MDB_DBI_CLOSE(mpEnvChannel, db.dbi);
    if (retval) {
        if (bStdErr) fprintf(stderr, "invalid version\n");
        goto LABEL_EXIT;
    }
    //LOGD("wif=%s\n", pWif);
    LOGD("alias=%s\n", pNodeName);
    LOGD("port=%d\n", *pPort);
    if (memcmp(genesis, ln_genesishash_get(), BTC_SZ_HASH256) != 0) {
        LOGE("fail: genesis hash not match\n");
        if (bStdErr) fprintf(stderr, "genesis hash not match\n");
        retval = -1;
        goto LABEL_EXIT;
    }
    fprintf(stderr, "done!\n");

    anno_del_prune();           //channel_updateだけの場合でも保持しておく

LABEL_EXIT:
    if (retval == 0) {
        pthread_mutex_init(&mMuxAnno, NULL);
    } else {
        //failed
        ln_db_term();
    }
    return retval == 0;
}


void ln_db_term(void)
{
    if (!mpEnvChannel) return;

    pthread_mutex_destroy(&mMuxAnno);

    mdb_env_close(mpEnvPayment);
    mpEnvPayment = NULL;
    mdb_env_close(mpEnvForward);
    mpEnvForward = NULL;
    mdb_env_close(mpEnvWallet);
    mpEnvWallet = NULL;
    mdb_env_close(mpEnvAnno);
    mpEnvAnno = NULL;
    mdb_env_close(mpEnvNode);
    mpEnvNode = NULL;
    mdb_env_close(mpEnvChannel);
    mpEnvChannel = NULL;
}


/********************************************************************
 * channel
 ********************************************************************/

int ln_lmdb_channel_load(ln_channel_t *pChannel, MDB_txn *pTxn, MDB_dbi Dbi, bool bRestore)
{
    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;

    //fixed size data
    db.p_txn = pTxn;
    db.dbi = Dbi;
    retval = fixed_items_load(pChannel, &db, DBCHANNEL_VALUES, ARRAY_SIZE(DBCHANNEL_VALUES));
    if (retval) {
        goto LABEL_EXIT;
    }

    for (uint16_t idx = 0; idx < LN_HTLC_MAX; idx++) {
        utl_buf_init(&pChannel->update_info.htlcs[idx].buf_preimage);
        utl_buf_init(&pChannel->update_info.htlcs[idx].buf_onion_reason);
        utl_buf_init(&pChannel->update_info.htlcs[idx].buf_shared_secret);
    }

    //variable size data
    utl_buf_t buf_fund_tx = UTL_BUF_INIT;
    variable_item_t *p_variable_items = (variable_item_t *)UTL_DBG_MALLOC(sizeof(variable_item_t) * M_NUM_CHANNEL_BUFS);
    if (!p_variable_items) goto LABEL_EXIT;
    int index = 0;
    p_variable_items[index].p_name = "buf_fund_tx";
    p_variable_items[index].p_buf = &buf_fund_tx;
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_local);
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_remote);
    //index++;

    for (size_t lp = 0; lp < M_NUM_CHANNEL_BUFS; lp++) {
        key.mv_size = strlen(p_variable_items[lp].p_name);
        key.mv_data = (CONST_CAST char*)p_variable_items[lp].p_name;
        retval = mdb_get(pTxn, Dbi, &key, &data);
        if (retval == 0) {
            utl_buf_alloccopy(p_variable_items[lp].p_buf, data.mv_data, data.mv_size);
        } else {
            LOGE("fail: %s\n", p_variable_items[lp].p_name);
        }
    }

    btc_tx_read(&pChannel->funding_info.tx_data, buf_fund_tx.buf, buf_fund_tx.len);
    utl_buf_free(&buf_fund_tx);
    UTL_DBG_FREE(p_variable_items);

    //htlc
    retval = channel_htlc_load(pChannel, &db);
    if (retval) {
        LOGE("ERR\n");
        goto LABEL_EXIT;
    }

    //secret
    retval = channel_secret_load(pChannel, &db);
    if (retval) {
        LOGE("ERR\n");
        goto LABEL_EXIT;
    }

    if (bRestore) {
        //復元データからさらに復元
        retval = channel_secret_restore(pChannel);
        if (retval) {
            LOGE("ERR\n");
            goto LABEL_EXIT;
        }
    }

LABEL_EXIT:
    if (retval == 0) {
        LOGD("loaded: short_channel_id=0x%016" PRIx64 "\n", pChannel->short_channel_id);
    }
    return retval;
}


bool ln_db_channel_save(const ln_channel_t *pChannel)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_CHANNEL_DB_NAME_STR + 1];

    db.p_txn = NULL;

    if (utl_mem_is_all_zero(pChannel->channel_id, LN_SZ_CHANNEL_ID)) {
        LOGD("through: channel_id is 0\n");
        return true;
    }

    memcpy(db_name, M_PREF_CHANNEL, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
    retval = channel_db_open(&db, db_name, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = channel_save(pChannel, &db);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = channel_htlc_save(pChannel, &db);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    MDB_TXN_COMMIT(db.p_txn);
    db.p_txn = NULL;

LABEL_EXIT:
    if (retval) {
        LOGE("fail: save\n");
    }
    if (db.p_txn) {
        MDB_TXN_ABORT(db.p_txn);
    }
    return retval == 0;
}


bool ln_db_channel_del(const uint8_t *pChannelId)
{
    bool ret = ln_db_channel_search(channel_cmp_func_channel_del, (CONST_CAST void *)pChannelId);
    ln_db_channel_close(pChannelId);
    return ret;
}


bool ln_db_channel_del_param(const ln_channel_t *pChannel, void *pDbParam)
{
    int             retval;
    MDB_dbi         dbi;
    char            db_name[M_SZ_CHANNEL_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];
    lmdb_cursor_t   *p_cur = (lmdb_cursor_t *)pDbParam;
    char            chanid_str[LN_SZ_CHANNEL_ID * 2 + 1];

    utl_str_bin2str(chanid_str, pChannel->channel_id, LN_SZ_CHANNEL_ID);

    LOGD("del channel_id=%s\n", chanid_str);

    MDB_TXN_CHECK_CHANNEL(p_cur->p_txn);

    //copy to closed env
    channel_copy_closed(p_cur->p_txn, chanid_str);

    //remove preimages
    preimage_close_t param;
    param.p_htlcs = pChannel->update_info.htlcs;
    ln_db_preimage_search(preimage_cmp_all_func, &param);

    //db_name base
    memcpy(db_name + M_SZ_PREF_STR, chanid_str, LN_SZ_CHANNEL_ID * 2);

   //htlcs
    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        memcpy(db_name, M_PREF_HTLC, M_SZ_PREF_STR);
        channel_htlc_db_name(db_name, lp);
        //LOGD("[%d]db_name: %s\n", lp, db_name);

        retval = MDB_DBI_OPEN(p_cur->p_txn, db_name, 0, &dbi);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            continue;
        }

        retval = mdb_drop(p_cur->p_txn, dbi, 1);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            continue;
        }
        LOGD("drop: %s\n", db_name);
    }

    //shorten
    db_name[M_SZ_CHANNEL_DB_NAME_STR] = '\0';

    //revoked transaction
    memcpy(db_name, M_PREF_REVOKED_TX, M_SZ_PREF_STR);
    retval = MDB_DBI_OPEN(p_cur->p_txn, db_name, 0, &dbi);
    if (retval == 0) {
        retval = mdb_drop(p_cur->p_txn, dbi, 1);
        if (retval == 0) {
            LOGD("drop: %s\n", db_name);
        } else {
            LOGE("ERR: %s(db_name=%s)\n", mdb_strerror(retval), db_name);
        }
    }

    //channel
    memcpy(db_name, M_PREF_CHANNEL, M_SZ_PREF_STR);
    retval = MDB_DBI_OPEN(p_cur->p_txn, db_name, 0, &dbi);
    if (retval == 0) {
        retval = mdb_drop(p_cur->p_txn, dbi, 1);
        if (retval == 0) {
            LOGD("drop: %s\n", db_name);
        } else {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval));
    }

    //secret
    memcpy(db_name, M_PREF_SECRET, M_SZ_PREF_STR);
    retval = MDB_DBI_OPEN(p_cur->p_txn, db_name, 0, &dbi);
    if (retval == 0) {
        retval = mdb_drop(p_cur->p_txn, dbi, 1);
        if (retval == 0) {
            LOGD("drop: %s\n", db_name);
        } else {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval));
    }
    return true;
}


bool ln_db_channel_search(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
    return channel_search(pFunc, pFuncParam, true, true, false);
}


bool ln_db_channel_search_cont(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
    return channel_search(pFunc, pFuncParam, true, true, true);
}


bool ln_db_channel_search_readonly(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
//ToDo: NOT READONLY
    return channel_search(pFunc, pFuncParam, true, true, false);
}


bool ln_db_channel_search_readonly_nokey(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
//ToDo: NOT READONLY
    return channel_search(pFunc, pFuncParam, true, false, false);
}


bool ln_db_channel_load_status(ln_channel_t *pChannel)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_CHANNEL_DB_NAME_STR + 1];
    const fixed_item_t DBCHANNEL_KEY = M_ITEM(ln_channel_t, status);

    db.p_txn = NULL;

    if (utl_mem_is_all_zero(pChannel->channel_id, LN_SZ_CHANNEL_ID)) {
        LOGE("fail: channel_id is 0\n");
        return false;
    }

    memcpy(db_name, M_PREF_CHANNEL, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
    retval = channel_db_open(&db, db_name, MDB_RDONLY, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = channel_item_load(pChannel, &DBCHANNEL_KEY, &db);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    if (db.p_txn) {
        MDB_TXN_ABORT(db.p_txn);
    }
    return retval == 0;
}


bool ln_db_channel_save_status(const ln_channel_t *pChannel, void *pDbParam)
{
    const fixed_item_t DBCHANNEL_KEY = M_ITEM(ln_channel_t, status);
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDbParam;
    int retval = channel_item_save(pChannel, &DBCHANNEL_KEY, p_db);
    LOGD("status=%02x, retval=%d\n", pChannel->status, retval);
    return retval == 0;
}


bool ln_db_channel_save_last_confirm(const ln_channel_t *pChannel, void *pDbParam)
{
    const fixed_item_t DBCHANNEL_KEY = M_ITEM(ln_channel_t, funding_last_confirm);
    ln_lmdb_db_t *p_db = (ln_lmdb_db_t *)pDbParam;
    int retval = channel_item_save(pChannel, &DBCHANNEL_KEY, p_db);
    LOGD("last_confirm=%" PRIu32 ", retval=%d\n", pChannel->funding_last_confirm, retval);
    return retval == 0;
}


void ln_db_channel_close(const uint8_t *pChannelId)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_CHANNEL_DB_NAME_STR + 1];

    LOGD("close start\n");

    if (utl_mem_is_all_zero(pChannelId, LN_SZ_CHANNEL_ID)) {
        LOGD("no channel opened\n");
        return;
    }

    db.p_txn = NULL;

    memcpy(db_name, M_PREF_CHANNEL, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannelId, LN_SZ_CHANNEL_ID);
    retval = channel_db_open(&db, db_name, 0, 0);
    if (retval == 0) {
        LOGD("close: channel(%s)\n", db_name);
        MDB_DBI_CLOSE(mpEnvChannel, db.dbi);
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return;
    }

    memcpy(db_name, M_PREF_SECRET, M_SZ_PREF_STR);
    retval = MDB_DBI_OPEN(db.p_txn, db_name, 0, &db.dbi);
    if (retval == 0) {
        LOGD("close: secret(%s)\n", db_name);
        MDB_DBI_CLOSE(mpEnvChannel, db.dbi);
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval));
    }

    char htlc_name[M_SZ_CHANNEL_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];
    MDB_dbi dbi;
    memcpy(htlc_name, M_PREF_HTLC, M_SZ_PREF_STR);
    utl_str_bin2str(htlc_name + M_SZ_PREF_STR, pChannelId, LN_SZ_CHANNEL_ID);
    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        channel_htlc_db_name(htlc_name, lp);
        retval = MDB_DBI_OPEN(db.p_txn, htlc_name, 0, &dbi);
        if (retval == 0) {
            LOGD("close: htlc(%s)\n", htlc_name);
            MDB_DBI_CLOSE(mpEnvChannel, dbi);
        } else {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
    }

    LOGD("close: end\n");
    MDB_TXN_ABORT(db.p_txn);
}


bool ln_db_secret_save(ln_channel_t *pChannel)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_CHANNEL_DB_NAME_STR + 1];

    memcpy(db_name, M_PREF_SECRET, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
    retval = channel_db_open(&db, db_name, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = fixed_items_save(pChannel, &db, DBCHANNEL_SECRET, ARRAY_SIZE(DBCHANNEL_SECRET));
    if (retval == 0) {
        MDB_TXN_COMMIT(db.p_txn);
    } else {
        MDB_TXN_ABORT(db.p_txn);
    }

LABEL_EXIT:
    return retval == 0;
}


/********************************************************************
 * anno用DB
 ********************************************************************/

bool ln_db_anno_transaction(void)
{
    int retval;

    //LOGD("anno_transaction\n");
    pthread_mutex_lock(&mMuxAnno);
    //LOGD("anno_transaction -- in\n");
    retval = MDB_TXN_BEGIN(mpEnvAnno, NULL, 0, &mpTxnAnno);
    if (retval) {
        pthread_mutex_unlock(&mMuxAnno);
    }
    return retval == 0;
}


void ln_db_anno_commit(bool bCommit)
{
    if (mpTxnAnno) {
        if (bCommit) {
            MDB_TXN_COMMIT(mpTxnAnno);
        } else {
            MDB_TXN_ABORT(mpTxnAnno);
        }
        mpTxnAnno = NULL;
    }
    pthread_mutex_unlock(&mMuxAnno);
    //LOGD("anno_transaction -- out\n");
}


/********************************************************************
 * [anno]channel_announcement / channel_update
 ********************************************************************/

/*-------------------------------------------------------------------
 *  dbi: "channel_anno" (M_DBI_CNLANNO)
 *      key:  [channel_announcement]short_channel_id + 'A'
 *            [channel_update dir0]short_channel_id + 'B'
 *            [channel_update dir1]short_channel_id + 'C'
 *      data:
 *          - [channel_announcement]
 *              - `channel_announcement` packet
 *          - [channel_update dir0/1]
 *              - timestamp: uint32_t
 *              - `channel_update` packet
 *      note:
 *          - `key` is structed like below:
 *              ``` uint8_t key[9];
 *                  key[0..7] = (BigEndian)short_channel_id;
 *                  key[8] = 'A' or 'B' or 'C';   ```
 *-------------------------------------------------------------------
 *  dbi: "channel_anno_info" (M_DBI_CNLANNO_INFO, LN_DB_CUR_CNLANNO_INFO)
 *      key:  [channel_announcement]short_channel_id + 'A'
 *            [channel_update dir0]short_channel_id + 'B'
 *            [channel_update dir1]short_channel_id + 'C'
 *      data:
 *          - node_ids sending to or receiving from(uint8_t[33] * n)
 *      note:
 *          - `key` same as "channel_anno"
 *-------------------------------------------------------------------
 *  dbi: "channal_anno_recv" (M_DBI_CNLANNO_RECV)
 *      key:  node_id(uint8_t[33])
 *      data: -
 *      note:
 *          - `key` `channel_announcement` both side node_id
 *-------------------------------------------------------------------
 *-------------------------------------------------------------------
 *  dbi: "node_anno" (M_DBI_NODEANNO)
 *      key:  node_id(uint8_t[33])
 *      data:
 *          - timestamp: uint32_t
 *          - `node_announcement` packet
 *-------------------------------------------------------------------
 *  dbi: "node_anno_info" (M_DBI_NODEANNO_INFO, LN_DB_CUR_NODEANNO_INFO)
 *      key:  node_id(uint8_t[33])
 *      data:
 *          - node_ids sending to or receiving from(uint8_t[33] * n)
 *-------------------------------------------------------------------
 */

/* [channel_announcement]load
 *  dbi: "channel_anno"
 */
bool ln_db_cnlanno_load(utl_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    int         retval;
    ln_lmdb_db_t   db;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO, 0, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = cnlanno_load(&db, pCnlAnno, ShortChannelId);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    ln_db_anno_commit(false);
    return retval == 0;
}


/* [channel_announcement]save
 *  パケット保存と、その送信元node_idの保存を行う。
 *  また、channel_announcementの両端node_idを保存する(node_announcement送信判定用)。
 *
 *  dbi: "channel_anno"
 *  dbi: "channel_anno_info"
 *  dbi: "channal_anno_recv"
 */
bool ln_db_cnlanno_save(const utl_buf_t *pCnlAnno, uint64_t ShortChannelId, const uint8_t *pSendId,
                        const uint8_t *pNodeId1, const uint8_t *pNodeId2)
{
    int             retval;
    ln_lmdb_db_t    db, db_info, db_recv;
    MDB_val         key, data;
    utl_buf_t       buf_anno = UTL_BUF_INIT;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO, MDB_CREATE, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        goto LABEL_EXIT;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_INFO, MDB_CREATE, &db_info.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        goto LABEL_EXIT;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_RECV, MDB_CREATE, &db_recv.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    //BOLT#07
    //  * if node_id is NOT previously known from a channel_announcement message, OR if timestamp is NOT greater than the last-received node_announcement from this node_id:
    //    * SHOULD ignore the message.
    //  channel_announcementで受信していないnode_idは無視する

    //recv node 1
    key.mv_size = BTC_SZ_PUBKEY;
    key.mv_data = (CONST_CAST uint8_t *)pNodeId1;
    data.mv_size = 0;
    data.mv_data = NULL;
    retval = mdb_put(mpTxnAnno, db_recv.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: channel_announcement node_id 1\n");
        goto LABEL_EXIT;
    }

    //recv node 2
    key.mv_data = (CONST_CAST uint8_t *)pNodeId2;
    retval = mdb_put(mpTxnAnno, db_recv.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: channel_announcement node_id 2\n");
        goto LABEL_EXIT;
    }

    //channel_announcement
    retval = cnlanno_load(&db, &buf_anno, ShortChannelId);
    if (retval) { //XXX: check error
        //DB保存されていない＝新規channel
        retval = cnlanno_save(&db, pCnlAnno, ShortChannelId);
        if (retval) {
            LOGE("ERR: save\n");
            goto LABEL_EXIT;
        }
    } else if (utl_buf_equal(&buf_anno, pCnlAnno)) {
        LOGV("same channel_announcement: %016" PRIx64 "\n", ShortChannelId);
    } else {
        LOGE("exist channel_announcement: %016" PRIx64 "\n", ShortChannelId);
        LOGE("fail: different channel_announcement\n");
        retval = -1;
        goto LABEL_EXIT;
    }

    //info
    if (pSendId) {
        if (!ln_db_cnlanno_info_add_node_id(
            &db_info, ShortChannelId, LN_DB_CNLANNO_ANNO, false, pSendId)) {
            retval = -1;
            goto LABEL_EXIT;
        }
    }

LABEL_EXIT:
    if (retval == 0) {
        ln_db_anno_commit(true);
    } else {
        //failed
        ln_db_anno_commit(false);
    }
    utl_buf_free(&buf_anno);
    return retval == 0;
}


/* [channel_update]load
 *
 *  dbi: "channel_anno"
 */
bool ln_db_cnlupd_load(utl_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir, void *pDbParam)
{
    int             retval;
    ln_lmdb_db_t    db;
    ln_lmdb_db_t    *p_db;

    if (pDbParam) {
        p_db = (ln_lmdb_db_t *)pDbParam;
    } else {
        if (!ln_db_anno_transaction()) {
            LOGE("ERR: anno transaction\n");
            return false;
        }
        retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO, 0, &db.dbi);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            ln_db_anno_commit(false);
            return false;
        }
        p_db = &db;
    }

    retval = cnlupd_load(p_db, pCnlUpd, pTimeStamp, ShortChannelId, Dir);
    if (retval) {
        if (!pDbParam) {
            ln_db_anno_commit(false);
        }
        return false;
    }

    if (!pDbParam) {
        ln_db_anno_commit(false);
    }
    return true;
}


/* [channel_update]save
 *  パケット保存と、その送信元node_idの保存を行う。
 *
 *  dbi: "channel_anno"
 *  dbi: "channel_anno_info"
 */
bool ln_db_cnlupd_save(const utl_buf_t *pCnlUpd, const ln_msg_channel_update_t *pUpd, const uint8_t *pSendId)
{
    int             retval;
    ln_lmdb_db_t    db, db_info;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO, MDB_CREATE, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_INFO, MDB_CREATE, &db_info.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    utl_buf_t   buf_upd = UTL_BUF_INIT;
    uint32_t    timestamp;
    bool        update = false;
    bool        clear_node_ids = false;

    retval = cnlupd_load(&db, &buf_upd, &timestamp, pUpd->short_channel_id, ln_cnlupd_direction(pUpd));
    if (retval) {
        //新規
        //LOGD("new: short_channel_id=%016" PRIx64 "(dir=%d)\n", pUpd->short_channel_id, ln_cnlupd_direction(pUpd));
        update = true;
    } else {
        if (timestamp > pUpd->timestamp) {
            //BOLT07
            //  if timestamp is NOT greater than that of the last-received channel_update for this short_channel_id AND for node_id:
            //      SHOULD ignore the message.
            //自分の方が新しければ、スルー
            //LOGD("my channel_update is newer\n");
        } else if (timestamp < pUpd->timestamp) {
            //自分の方が古いので、更新
            LOGD("update: short_channel_id=%016" PRIx64 "(dir=%d)\n", pUpd->short_channel_id, ln_cnlupd_direction(pUpd));
            update = true;
            //announceし直す必要があるため、クリアする
            clear_node_ids = true;
        } else if (utl_buf_equal(&buf_upd, pCnlUpd)) {
            //LOGV("same channel_update\n");
        } else {
            //日時が同じなのにデータが異なる
            LOGE("ERR: channel_update %d mismatch !\n", ln_cnlupd_direction(pUpd));
            LOGE("  db: ");
            DUMPE(buf_upd.buf, buf_upd.len);
            LOGE("  rv: ");
            DUMPE(pCnlUpd->buf, pCnlUpd->len);
            utl_buf_free(&buf_upd);
            ln_db_anno_commit(false);
            return false;
        }
    }
    utl_buf_free(&buf_upd);

    if (update) {
        retval = cnlupd_save(&db, pCnlUpd, pUpd);
        if (retval) {
            LOGE("fail: save\n");
            ln_db_anno_commit(false);
            return false;
        }
    }
    if (pSendId) {
        char type = ln_cnlupd_direction(pUpd) ?  LN_DB_CNLANNO_UPD1 : LN_DB_CNLANNO_UPD0;
        if (!ln_db_cnlanno_info_add_node_id(
            &db_info, pUpd->short_channel_id, type, clear_node_ids, pSendId)) {
            LOGE("fail: ???\n");
            ln_db_anno_commit(false);
            return false;
        }
    }

    ln_db_anno_commit(true);
    return true;
}


bool ln_db_cnlupd_need_to_prune(uint64_t Now, uint32_t TimesStamp)
{
    //BOLT#7: Pruning the Network View
    //  if a channel's latest channel_updates timestamp is older than two weeks (1209600 seconds):
    //      MAY prune the channel.
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#recommendation-on-pruning-stale-entries
    return (uint64_t)TimesStamp + (uint64_t)1209600 < Now;
}


/* [channel_announcement]delete
 *
 *
 *  dbi: "channel_anno"
 *  dbi: "channel_anno_info"
 */
bool ln_db_cnlanno_del(uint64_t ShortChannelId)
{
    int         retval;
    MDB_dbi     dbi, dbi_info;
    MDB_val     key;
    uint8_t     key_data[M_SZ_CNLANNO_INFO_KEY];

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO, MDB_CREATE, &dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_INFO, MDB_CREATE, &dbi_info);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    char SUFFIX[] = { LN_DB_CNLANNO_ANNO, LN_DB_CNLANNO_UPD0, LN_DB_CNLANNO_UPD1 };
    for (size_t lp = 0; lp < ARRAY_SIZE(SUFFIX); lp++) {
        cnlanno_info_set_key(key_data, &key, ShortChannelId, SUFFIX[lp]);
        retval = mdb_del(mpTxnAnno, dbi, &key, NULL);
        if (retval && (retval != MDB_NOTFOUND)) {
            LOGE("ERR[%c]: %s\n", SUFFIX[lp], mdb_strerror(retval));
        }
        retval = mdb_del(mpTxnAnno, dbi_info, &key, NULL);
        if (retval && (retval != MDB_NOTFOUND)) {
            LOGE("ERR[%c]: %s\n", SUFFIX[lp], mdb_strerror(retval));
        }
    }
    ln_db_anno_commit(true);
    LOGD("remove channel_announcement: %016" PRIx64 "\n", ShortChannelId);
    return true;
}


/********************************************************************
 * node_announcement
 ********************************************************************/

// dbi: "node_anno"
bool ln_db_nodeanno_load(utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId)
{
    int             retval;
    ln_lmdb_db_t    db;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_NODEANNO, 0, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    retval = nodeanno_load(&db, pNodeAnno, pTimeStamp, pNodeId);
    if (retval) {
        ln_db_anno_commit(false);
        return false;
    }

    ln_db_anno_commit(false);
    return true;
}


// dbi: "node_anno"
// dbi: "node_anno_info"
bool ln_db_nodeanno_save(const utl_buf_t *pNodeAnno, const ln_msg_node_announcement_t *pAnno, const uint8_t *pSendId)
{
    int             retval;
    ln_lmdb_db_t    db, db_info, db_recv;
    utl_buf_t       buf_node = UTL_BUF_INIT;
    uint32_t        timestamp;
    bool            update = false;
    bool            clear_node_ids = false;
    MDB_val         key, data;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_NODEANNO, MDB_CREATE, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_NODEANNO_INFO, MDB_CREATE, &db_info.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    if (memcmp(pAnno->p_node_id, ln_node_get_id(), BTC_SZ_PUBKEY)) {
        //BOLT#07
        //  * if node_id is NOT previously known from a channel_announcement message, OR if timestamp is NOT greater than the last-received node_announcement from this node_id:
        //    * SHOULD ignore the message.
        //  channel_announcementで受信していないnode_idは無視する
        retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_RECV, 0, &db_recv.dbi);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            ln_db_anno_commit(false);
            return false;
        }

        key.mv_size = BTC_SZ_PUBKEY;
        key.mv_data = (CONST_CAST uint8_t *)pAnno->p_node_id;
        retval = mdb_get(mpTxnAnno, db_recv.dbi, &key, &data);
        if (retval) {
            LOGD("skip: not have channel_announcement node_id\n");
            ln_db_anno_commit(false);
            return false;
        }
    }

    retval = nodeanno_load(&db, &buf_node, &timestamp, pAnno->p_node_id);
    if (retval) { //XXX: check error code
        //新規
        //LOGV("new node_announcement\n");
        update = true;
    } else {
        if (timestamp > pAnno->timestamp) {
            //自分の方が新しければ、スルー
            LOGV("my node_announcement is newer\n");
        } else if (timestamp < pAnno->timestamp) {
            //自分の方が古いので、更新
            LOGV("gotten node_announcement is newer\n");
            update = true;

            //announceし直す必要があるため、クリアする
            clear_node_ids = true;
        } else if (utl_buf_equal(&buf_node, pNodeAnno)) {
            LOGV("same node_announcement\n");
        } else {
            //日時が同じなのにデータが異なる
            LOGE("ERR: node_announcement mismatch !\n");
            utl_buf_free(&buf_node);
            ln_db_anno_commit(false);
            return false;
        }
    }
    utl_buf_free(&buf_node);

    if (update) {
        retval = nodeanno_save(&db, pNodeAnno, pAnno->p_node_id, pAnno->timestamp);
        if (retval) {
            ln_db_anno_commit(false);
            return false;
        }
        if (pSendId || clear_node_ids) {
            // if (pSendId != NULL) {
            //     LOGD("  node_info: ");
            //     DUMPD(pAnno->p_node_id, BTC_SZ_PUBKEY);
            //     LOGD("  sender: ");
            //     DUMPD(pSendId, BTC_SZ_PUBKEY);
            // }
            if (!ln_db_nodeanno_info_add_node_id(&db_info, pAnno->p_node_id, clear_node_ids, pSendId)) {
                ln_db_anno_commit(false);
                return false;
            }
        }
        ln_db_anno_commit(true);
    } else {
        ln_db_anno_commit(false);
    }
    return true;
}


/********************************************************************
 * [anno]cursor
 ********************************************************************/

bool ln_db_anno_cur_open(void **ppCur, ln_db_cur_t Type)
{
    int retval;
    MDB_dbi dbi;
    MDB_cursor *p_cursor;

    const char *p_name;
    switch (Type) {
    case LN_DB_CUR_CNLANNO:
        p_name = M_DBI_CNLANNO;
        break;
    case LN_DB_CUR_NODEANNO:
        p_name = M_DBI_NODEANNO;
        break;
    case LN_DB_CUR_CNLANNO_INFO:
        p_name = M_DBI_CNLANNO_INFO;
        break;
    case LN_DB_CUR_NODEANNO_INFO:
        p_name = M_DBI_NODEANNO_INFO;
        break;
    default:
        LOGE("fail: unknown CUR: %02x\n", Type);
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, p_name, MDB_CREATE, &dbi);
    if (retval) {
        LOGE("fail: ???\n");
        *ppCur = NULL;
        return false;
    }

    retval = mdb_cursor_open(mpTxnAnno, dbi, &p_cursor);
    if (retval) {
        LOGE("ERR(%s): %s\n", p_name, mdb_strerror(retval));
        *ppCur = NULL;
        return false;
    }

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)UTL_DBG_MALLOC(sizeof(lmdb_cursor_t));
    if (!p_cur) {
        LOGE("fail: ???\n");
        MDB_CURSOR_CLOSE(p_cursor);
        *ppCur = NULL;
        return false;
    }

    p_cur->p_txn = (MDB_txn *)p_name;
    p_cur->dbi = dbi;
    p_cur->p_cursor = p_cursor;
    *ppCur = p_cur;
    return true;
}


void ln_db_anno_cur_close(void *pCur)
{
    if (pCur) {
        MDB_CURSOR_CLOSE(((lmdb_cursor_t *)pCur)->p_cursor);
        UTL_DBG_FREE(pCur);
    }
}


/* channel_announcement/channel_updateの送信元/送信先登録
 *
 * 既にchannel_announcement/channel_updateを送信したノードや、
 * その情報をもらったノードへはannoundementを送信したくないため、登録しておく。
 *
 * #ln_db_cnlanno_info_search_node_id()で、送信不要かどうかをチェックする。

 *  dbi: "channel_anno_info"
 */
bool ln_db_cnlanno_info_add_node_id(void *pCur, uint64_t ShortChannelId, char Type, bool bClear, const uint8_t *pNodeId)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    MDB_val key, data;
    uint8_t key_data[M_SZ_CNLANNO_INFO_KEY];
    bool detect = false;

    cnlanno_info_set_key(key_data, &key, ShortChannelId, Type);
    if (bClear) {
        data.mv_size = 0;
    } else {
        int retval = mdb_get(mpTxnAnno, p_cur->dbi, &key, &data);
        if (retval == 0) {
            detect = annoinfo_search_node_id(&data, pNodeId);
        } else {
            LOGV("new reg[%016" PRIx64 ":%c] ", ShortChannelId, Type);
            DUMPV(pNodeId, BTC_SZ_PUBKEY);
            data.mv_size = 0;
        }
    }
    if (!detect) {
        if (!annoinfo_add((ln_lmdb_db_t *)p_cur, &key, &data, pNodeId)) {
            return false;
        }
    }
    return true;
}


/* [channel_announcement / channel_update]search received/sent DB
 *
 *  dbi: "channel_anno_info"
 */
bool ln_db_cnlanno_info_search_node_id(void *pCur, uint64_t ShortChannelId, char Type, const uint8_t *pNodeId)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    MDB_val key, data;
    uint8_t key_data[M_SZ_CNLANNO_INFO_KEY];

    cnlanno_info_set_key(key_data, &key, ShortChannelId, Type);
    int retval = mdb_get(mpTxnAnno, p_cur->dbi, &key, &data);
    if (retval) {
        //LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    // LOGD("short_channel_id[%c]= %016" PRIx64 "\n", Type, ShortChannelId);
    // LOGD("send_id= ");
    // DUMPD(pSendId, BTC_SZ_PUBKEY);
    return annoinfo_search_node_id(&data, pNodeId);
}


/* [channel_announcement / channel_update]cursor
 *
 *  dbi: "channel_anno"
 */
bool ln_db_cnlanno_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval = cnlanno_cur_load(p_cur->p_cursor, pShortChannelId, pType, pTimeStamp, pBuf, MDB_NEXT_NODUP);
    if (retval) {
        return false;
    }
    return true;
}


bool ln_db_cnlanno_cur_back(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    uint64_t short_channel_id;
    char type;
    uint32_t timestamp;
    utl_buf_t buf = UTL_BUF_INIT;
    int retval = cnlanno_cur_load(p_cur->p_cursor, &short_channel_id, &type, &timestamp, &buf, MDB_PREV_NODUP);
    utl_buf_free(&buf);
    return retval == 0;
}


/* [channel_announcement / channel_update]
 *
 *  dbi: "channel_anno"
 */
bool ln_db_cnlanno_cur_del(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval = mdb_cursor_del(p_cur->p_cursor, 0);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: mdb_cursor_del(): %s\n", mdb_strerror(retval));
        }
        return false;
    }
    return true;
}


/* [channel_announcement / channel_update]
 *
 *  dbi: "channel_anno"
 */
int ln_lmdb_cnlanno_cur_load(MDB_cursor *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf)
{
    return cnlanno_cur_load(pCur, pShortChannelId, pType, pTimeStamp, pBuf, MDB_NEXT_NODUP);
}


/* [node_announcement]
 *
 *  dbi: "node_anno"
 */
bool ln_db_nodeanno_cur_load(void *pCur, utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId)
{
    int             retval;
    lmdb_cursor_t   *p_cur = (lmdb_cursor_t *)pCur;
    retval = nodeanno_load((ln_lmdb_db_t *)p_cur, pNodeAnno, pTimeStamp, pNodeId);
    return retval == 0;
}


/* [node_announcement]
 *
 *  dbi: "node_anno_info"
 */
bool ln_db_nodeanno_info_search_node_id(void *pCur, const uint8_t *pNodeId, const uint8_t *pSendId)
{
    //LOGD("node_id= ");
    //DUMPD(pNodeId, BTC_SZ_PUBKEY);
    //LOGD("send_id= ");
    //DUMPD(pSendId, BTC_SZ_PUBKEY);

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;

    MDB_val key, data;
    uint8_t key_data[M_SZ_NODEANNO_INFO_KEY];

    nodeanno_info_set_key(key_data, &key, pNodeId);
    int retval = mdb_get(mpTxnAnno, p_cur->dbi, &key, &data);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        return false;
    }

    //LOGD("search...\n");
    return annoinfo_search_node_id(&data, pSendId);
}


/* [node_announcement]
 *
 *  dbi: "node_anno_info"
 */
bool ln_db_nodeanno_info_add_node_id(void *pCur, const uint8_t *pNodeId, bool bClear, const uint8_t *pSendId)
{
    if (!pSendId && !bClear) {
        LOGD("do nothing\n");
        return true;
    }

    lmdb_cursor_t   *p_cur = (lmdb_cursor_t *)pCur;
    MDB_val         key, data;
    uint8_t         key_data[M_SZ_NODEANNO_INFO_KEY];
    bool            detect = false;

    nodeanno_info_set_key(key_data, &key, pNodeId);
    if (bClear) {
        data.mv_size = 0;
    } else {
        int retval = mdb_get(mpTxnAnno, p_cur->dbi, &key, &data);
        if (retval == 0) {
            detect = annoinfo_search_node_id(&data, pSendId);
        } else {
            data.mv_size = 0;
        }
    }

    if (!detect) {
        LOGV("new from ");
        if (pSendId) {
            DUMPV(pSendId, BTC_SZ_PUBKEY);
        } else {
            LOGV(": only clear\n");
        }
        if (!annoinfo_add((ln_lmdb_db_t *)p_cur, &key, &data, pSendId)) {
            LOGE("fail: ???\n");
            return false;
        }
    }
    return true;
}


/* [node_announcement]
 *
 *  dbi: "node_anno"
 */
bool ln_db_nodeanno_cur_get(void *pCur, utl_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval = ln_lmdb_nodeanno_cur_load(p_cur->p_cursor, pBuf, pTimeStamp, pNodeId);
    return retval == 0;
}


/* [node_announcement]
 *
 *  dbi: "node_anno"
 */
int ln_lmdb_nodeanno_cur_load(MDB_cursor *pCur, utl_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(pCur, &key, &data, MDB_NEXT_NODUP);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        } else {
            //end of cursor
        }
        return retval;
    }

    // LOGD("key:  ");
    // DUMPD(key.mv_data, key.mv_size);
    // LOGD("data: ");
    // DUMPD(data.mv_data, data.mv_size);
    if (pNodeId) {
        memcpy(pNodeId, key.mv_data, key.mv_size);
    }
    memcpy(pTimeStamp, data.mv_data, sizeof(uint32_t)); //XXX: should not use sizeof(uint32_t) but sizeof timestamp
    if (!utl_buf_alloccopy(
        pBuf, (const uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t))) {
        LOGE("fail: ???\n");
        return -1;
    }
    return 0;
}


/********************************************************************
 * [anno]own channel
 ********************************************************************/

/*
 * dbi: "channel_owned"
 */
bool ln_db_channel_owned_save(uint64_t ShortChannelId)
{
    int             retval;
    ln_lmdb_db_t    db;
    MDB_val         key, data;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNL_OWNED, MDB_CREATE, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    key.mv_size = sizeof(uint64_t);
    key.mv_data = (uint8_t *)&ShortChannelId;
    data.mv_size = 0;
    data.mv_data = NULL;
    retval = mdb_put(mpTxnAnno, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    ln_db_anno_commit(true);
    return true;
}


/*
 * dbi: "channel_owned"
 */
bool ln_db_channel_owned_check(uint64_t ShortChannelId)
{
    int             retval;
    ln_lmdb_db_t    db;
    MDB_val         key, data;

    if (mpTxnAnno == NULL) {
        LOGE("fail: no txn\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNL_OWNED, 0, &db.dbi);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        return false;
    }

    key.mv_size = sizeof(uint64_t);
    key.mv_data = (uint8_t *)&ShortChannelId;
    retval = mdb_get(mpTxnAnno, db.dbi, &key, &data);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        return false;
    }

    return true;
}


/*
 * dbi: "channel_owned"
 */
bool ln_db_channel_owned_del(uint64_t ShortChannelId)
{
    int             retval;
    ln_lmdb_db_t    db;
    MDB_val         key;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNL_OWNED, 0, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    key.mv_size = sizeof(uint64_t);
    key.mv_data = (uint8_t *)&ShortChannelId;
    retval = mdb_del(mpTxnAnno, db.dbi, &key, NULL);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    ln_db_anno_commit(true);
    return true;
}


/********************************************************************
 * [anno]cnlanno, nodeanno共通
 ********************************************************************/

bool ln_db_annoinfos_del_node_id(const uint8_t *pNodeId, const uint64_t *pShortChannelIds, size_t Num)
{
    int         retval;
    MDB_dbi     dbi_cnlanno_info;
    MDB_dbi     dbi_nodeanno_info;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_INFO, 0, &dbi_cnlanno_info);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        ln_db_anno_commit(false);
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_NODEANNO_INFO, 0, &dbi_nodeanno_info);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        ln_db_anno_commit(false);
        return false;
    }

    if (pNodeId) {
        if ((pShortChannelIds == NULL) && (Num == 0)) {
            //all trim
            (void)annoinfos_trim_node_id(pNodeId, dbi_cnlanno_info, dbi_nodeanno_info);
        } else {
            //selected trim
            (void)annoinfos_trim_node_id_selected(pNodeId, dbi_cnlanno_info, dbi_nodeanno_info, pShortChannelIds, Num);
        }
    } else {
        //drop
        (void)annoinfos_del_all(dbi_cnlanno_info, dbi_nodeanno_info);
    }

    if (pNodeId) {
        LOGD("remove annoinfo: ");
        DUMPD(pNodeId, BTC_SZ_PUBKEY);
    } else {
        LOGD("remove annoinfo: ALL\n");
    }
    ln_db_anno_commit(true);
    return true;
}


bool ln_db_annoinfos_add_node_id(const uint8_t *pNodeId)
{
    int         retval;
    MDB_dbi     dbi_cnl;
    MDB_dbi     dbi_node;
    MDB_cursor  *p_cursor;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_INFO, 0, &dbi_cnl);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_NODEANNO_INFO, 0, &dbi_node);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }

    LOGD("add annoinfo: ");
    DUMPD(pNodeId, BTC_SZ_PUBKEY);

    //cnlanno_info
    retval = mdb_cursor_open(mpTxnAnno, dbi_cnl, &p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }
    annoinfo_cur_add(p_cursor, pNodeId);
    MDB_CURSOR_CLOSE(p_cursor);

    //nodeanno_info
    retval = mdb_cursor_open(mpTxnAnno, dbi_node, &p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ln_db_anno_commit(false);
        return false;
    }
    annoinfo_cur_add(p_cursor, pNodeId);
    MDB_CURSOR_CLOSE(p_cursor);

    ln_db_anno_commit(true);
    return true;
}


bool ln_db_annoinfos_del_timestamp(const uint8_t *pNodeId, uint32_t TimeFirst, uint32_t TimeRange)
{
    int         retval;
    MDB_dbi     dbi_cnlanno_info;
    MDB_dbi     dbi_nodeanno_info;

    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO_INFO, 0, &dbi_cnlanno_info);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        ln_db_anno_commit(false);
        return false;
    }

    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_NODEANNO_INFO, 0, &dbi_nodeanno_info);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        ln_db_anno_commit(false);
        return false;
    }

    (void)annoinfos_trim_node_id_timestamp(
        pNodeId, dbi_cnlanno_info, dbi_nodeanno_info,
        TimeFirst, TimeRange);

    ln_db_anno_commit(true);

    LOGD("remove annoinfo: ");
    DUMPD(pNodeId, BTC_SZ_PUBKEY);

    return true;
}



/********************************************************************
 * [node]skip routing list
 ********************************************************************/

bool ln_db_route_skip_save(uint64_t ShortChannelId, bool bTemp)
{
    LOGD("short_channel_id=%016" PRIx64 ", bTemp=%d\n", ShortChannelId, bTemp);

    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;

    retval = node_db_open(&db, M_DBI_ROUTE_SKIP, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = sizeof(ShortChannelId);
    key.mv_data = &ShortChannelId;
    uint8_t tmp_data;
    if (bTemp) {
        tmp_data = LN_DB_ROUTE_SKIP_TEMP;
        data.mv_size = sizeof(tmp_data);
        data.mv_data = &tmp_data;
    } else {
        tmp_data = LN_DB_ROUTE_SKIP_PERM;
        data.mv_size = sizeof(tmp_data);
        data.mv_data = &tmp_data;
    }
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }
    LOGD("add skip[%d]: %016" PRIx64 "\n", bTemp, ShortChannelId);

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


bool ln_db_route_skip_work(bool bWork)
{
    LOGD("bWork=%d\n", bWork);

    int             retval;
    MDB_val         key, data;
    MDB_cursor      *p_cursor = NULL;
    ln_lmdb_db_t    db;

    db.p_txn = NULL;

    retval = node_db_open(&db, M_DBI_ROUTE_SKIP, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_ERROR;
    }

    retval = mdb_cursor_open(db.p_txn, db.dbi, &p_cursor);
    if (retval) {
        p_cursor = NULL;
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_ERROR;
    }

    while (mdb_cursor_get(p_cursor, &key, &data, MDB_NEXT) == 0) {
        const uint8_t *p_data = (const uint8_t *)data.mv_data;
        if (data.mv_size != sizeof(uint8_t)) continue;

        if (!my_mdb_val_alloccopy(&key, &key)) {
            LOGE("fail: ???\n");
            goto LABEL_ERROR;
        }

        uint64_t short_channel_id = *(uint64_t *)key.mv_data;
        uint8_t wk = LN_DB_ROUTE_SKIP_NONE;
        if (bWork && (p_data[0] == LN_DB_ROUTE_SKIP_TEMP)) {
            LOGD("TEMP-->WORK: %016" PRIx64 "\n", short_channel_id);
            wk = LN_DB_ROUTE_SKIP_WORK;
        } else if (!bWork && (p_data[0] == LN_DB_ROUTE_SKIP_WORK)) {
            LOGD("WORK-->TEMP: %016" PRIx64 "\n", short_channel_id);
            wk = LN_DB_ROUTE_SKIP_TEMP;
        }
        if (wk != LN_DB_ROUTE_SKIP_NONE) {
            data.mv_data = &wk;
            int retval = mdb_cursor_put(p_cursor, &key, &data, MDB_CURRENT);
            UTL_DBG_FREE(key.mv_data);
            if (retval) {
                LOGD("through: put(%s)\n", mdb_strerror(retval));
                //XXX: ignore error
            }
        }
    }

    MDB_CURSOR_CLOSE(p_cursor);
    MDB_TXN_COMMIT(db.p_txn);
    return true;

LABEL_ERROR:
    if (p_cursor) {
        MDB_CURSOR_CLOSE(p_cursor);
    }
    if (db.p_txn) {
        MDB_TXN_ABORT(db.p_txn);
    }
    return true;

}


/* open DB cursor(M_DBI_ROUTE_SKIP)
 *
 *  dbi: "route_skip"
 */
ln_db_route_skip_t ln_db_route_skip_search(uint64_t ShortChannelId)
{
    ln_db_route_skip_t  result = LN_DB_ROUTE_SKIP_NONE;
    int                 retval;
    MDB_val             key, data;
    ln_lmdb_db_t        db;

    db.p_txn = NULL;

    retval = node_db_open(&db, M_DBI_ROUTE_SKIP, 0, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return LN_DB_ROUTE_SKIP_NONE;
    }

    key.mv_size = sizeof(ShortChannelId);
    key.mv_data = &ShortChannelId;
    retval = mdb_get(db.p_txn, db.dbi, &key, &data);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: %s\n", mdb_strerror(retval));
        }
        MDB_TXN_ABORT(db.p_txn);
        return LN_DB_ROUTE_SKIP_NONE;
    }

    const uint8_t *p_data = (const uint8_t *)data.mv_data;
    if (data.mv_size != sizeof(uint8_t)) {
        LOGE("fail\n");
        MDB_TXN_ABORT(db.p_txn);
        return LN_DB_ROUTE_SKIP_NONE;
    }
    result = p_data[0];

    MDB_TXN_ABORT(db.p_txn);
    return result;
}


bool ln_db_route_skip_drop(bool bTemp)
{
    int             retval;
    ln_lmdb_db_t    db;
    MDB_cursor      *p_cursor = NULL;
    MDB_val         key, data;

    db.p_txn = NULL;

    retval = node_db_open(&db, M_DBI_ROUTE_SKIP, 0, 0);
    if (retval) {
        if (retval == MDB_NOTFOUND) {
            LOGD("no db\n");
            return true;
        }
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    if (bTemp) {
        LOGD("remove temporary only\n");
        retval = mdb_cursor_open(db.p_txn, db.dbi, &p_cursor);
        if (retval) {
            p_cursor = NULL;
            LOGE("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_ERROR;
        }

        while (mdb_cursor_get(p_cursor, &key, &data, MDB_NEXT) == 0) {
            const uint8_t *p_data = (const uint8_t *)data.mv_data;
            if (data.mv_size != sizeof(uint8_t)) continue;
            if (p_data[0] != LN_DB_ROUTE_SKIP_TEMP) continue;

            retval = mdb_cursor_del(p_cursor, 0);
            if (retval) {
                LOGE("ERR: %s\n", mdb_strerror(retval));
                goto LABEL_ERROR;
            }

            uint64_t val;
            memcpy(&val, key.mv_data, sizeof(uint64_t));
            LOGD("del skip: %016" PRIx64 "\n", val);
        }

        MDB_CURSOR_CLOSE(p_cursor);
    } else {
        LOGD("remove all\n");
        retval = mdb_drop(db.p_txn, db.dbi, 1);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_ERROR;
        }
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;

LABEL_ERROR:
    if (p_cursor) {
        MDB_CURSOR_CLOSE(p_cursor);
    }
    if (db.p_txn) {
        MDB_TXN_ABORT(db.p_txn);
    }
    return false;
}


/********************************************************************
 * [node]payment preimage
 ********************************************************************/

bool ln_db_preimage_save(const ln_db_preimage_t *pPreimage, const char *pBolt11, void *pDb)
{
    ln_lmdb_db_t    db;
    MDB_val         key, data;
    MDB_txn         *p_txn = NULL;
    preimage_info_t *p_info;
    size_t          invoice_len = 0;

    if (pDb) {
        p_txn = ((ln_lmdb_db_t *)pDb)->p_txn;
        MDB_TXN_CHECK_NODE(p_txn);
    }
    if (!preimage_open(&db, p_txn)) {
        LOGE("fail\n");
        return false;
    }
    if (pBolt11 != NULL) {
        invoice_len = strlen(pBolt11);
    }

    key.mv_size = LN_SZ_PREIMAGE;
    key.mv_data = (CONST_CAST uint8_t *)pPreimage->preimage;
    data.mv_size = sizeof(preimage_info_t) + invoice_len;
    p_info = (preimage_info_t *)UTL_DBG_MALLOC(data.mv_size);
    p_info->amount = pPreimage->amount_msat;
    p_info->creation = pPreimage->creation_time;
    p_info->expiry = pPreimage->expiry;
    p_info->state = LN_DB_PREIMAGE_STATE_UNUSED;
    p_info->bolt11[0] = '\0';
    memcpy(p_info->bolt11, pBolt11, invoice_len + 1);   //copy include '\0'
    data.mv_data = p_info;
    int retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    UTL_DBG_FREE(p_info);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        preimage_close(&db, false);
        return false;
    }

    preimage_close(&db, true);
    return true;
}


bool ln_db_preimage_del(const uint8_t *pPreimage)
{
    int             retval;
    ln_lmdb_db_t    db;

    if (!preimage_open(&db, NULL)) {
        LOGE("fail: open\n");
        return false;
    }

    if (pPreimage) {
        MDB_val key;

        //LOGD("remove: ");
        //DUMPD(pPreimage, LN_SZ_PREIMAGE);
        LOGD("remove\n");
        key.mv_size = LN_SZ_PREIMAGE;
        key.mv_data = (CONST_CAST uint8_t *)pPreimage;
        retval = mdb_del(db.p_txn, db.dbi, &key, NULL);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            preimage_close(&db, false);
            return false;
        }
    } else {
        LOGD("remove all\n");
        retval = mdb_drop(db.p_txn, db.dbi, 1);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            preimage_close(&db, false);
            return false;
        }
    }

    LOGD("success\n");
    preimage_close(&db, true);
    return true;
}


bool ln_db_preimage_search(ln_db_func_preimage_t pFunc, void *pFuncParam)
{
    return preimage_search(pFunc, false, pFuncParam);
}


bool ln_db_preimage_del_hash(const uint8_t *pPaymentHash)
{
    return preimage_search(preimage_cmp_func, true, (CONST_CAST uint8_t *)pPaymentHash);
}


bool ln_db_preimage_cur_open(void **ppCur)
{
    int             retval;
    lmdb_cursor_t   *p_cur;

    *ppCur = NULL;

    p_cur  = (lmdb_cursor_t *)UTL_DBG_MALLOC(sizeof(lmdb_cursor_t));
    if (!p_cur) {
        LOGE("fail: ???\n");
        return false;
    }

    retval = node_db_open((ln_lmdb_db_t *)p_cur, M_DBI_PREIMAGE, 0, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        UTL_DBG_FREE(p_cur);
        return false;
    }

    retval = mdb_cursor_open(p_cur->p_txn, p_cur->dbi, &p_cur->p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        UTL_DBG_FREE(p_cur);
        return false;
    }

    *ppCur = p_cur;
    return true;
}


void ln_db_preimage_cur_close(void *pCur, bool bCommit)
{
    if (!pCur) return;

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    MDB_CURSOR_CLOSE(p_cur->p_cursor);

    if (!p_cur->p_txn) return;
    MDB_TXN_CHECK_NODE(p_cur->p_txn);
    if (bCommit) {
        MDB_TXN_COMMIT(p_cur->p_txn);
    } else {
        MDB_TXN_ABORT(p_cur->p_txn);
    }
    UTL_DBG_FREE(pCur);
}


bool ln_db_preimage_cur_get(void *pCur, bool *pDetect, ln_db_preimage_t *pPreimage, const char **ppBolt11)
{
    lmdb_cursor_t   *p_cur = (lmdb_cursor_t *)pCur;
    int             retval;
    MDB_val         key, data;
    uint64_t        now = (uint64_t)utl_time_time();

    *pDetect = false;

    retval = mdb_cursor_get(p_cur->p_cursor, &key, &data, MDB_NEXT_NODUP);
    if (retval) {
        return false;
    }
    *pDetect = true;

    preimage_info_t *p_info = (preimage_info_t *)data.mv_data;
    LOGD("amount: %" PRIu64"\n", p_info->amount);
    LOGD("time: %lu\n", p_info->creation);

    memcpy(pPreimage->preimage, key.mv_data, key.mv_size);
    pPreimage->expiry = p_info->expiry;
    pPreimage->creation_time = p_info->creation;
    pPreimage->amount_msat = p_info->amount;
    if (ppBolt11 != NULL) {
        *ppBolt11 = p_info->bolt11;
    }
    pPreimage->state = (ln_db_preimage_state_t)p_info->state;
    if (now > p_info->creation + p_info->expiry) {
        //expired
        if (pPreimage->state == LN_DB_PREIMAGE_STATE_UNUSED) {
            pPreimage->state = LN_DB_PREIMAGE_STATE_EXPIRE;
        }
    }
    return true;
}


bool ln_db_preimage_used(const uint8_t *pPreimage)
{
    ln_lmdb_db_t    db;
    int             retval;
    MDB_val         key, data;

    LOGD("preimage: ");
    DUMPD(pPreimage, LN_SZ_PREIMAGE);

    if (!preimage_open(&db, NULL)) {
        LOGE("fail\n");
        return false;
    }
    key.mv_data = (CONST_CAST uint8_t *)pPreimage;
    key.mv_size = LN_SZ_PREIMAGE;
    retval = mdb_get(db.p_txn, db.dbi, &key, &data);
    if (retval != 0) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: %s\n", mdb_strerror(retval));
        }
        preimage_close(&db, false);
        return false;
    }

    if (!my_mdb_val_alloccopy(&key, &key)) {
        LOGE("fail: ???\n");
        preimage_close(&db, false);
        return false;
    }

    preimage_info_t *p_infonew = (preimage_info_t *)UTL_DBG_MALLOC(data.mv_size);
    memcpy(p_infonew, data.mv_data, data.mv_size);
    p_infonew->state = LN_DB_PREIMAGE_STATE_USED;
    data.mv_data = p_infonew;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    UTL_DBG_FREE(p_infonew);
    UTL_DBG_FREE(key.mv_data);

    preimage_close(&db, true);
    return true;
}


/********************************************************************
 * [node]payment_hash
 ********************************************************************/

bool ln_db_payment_hash_save(const uint8_t *pPaymentHash, const uint8_t *pVout, ln_commit_tx_output_type_t Type, uint32_t Expiry)
{
    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;

    assert(Type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED || Type == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED);

    retval = node_db_open(&db, M_DBI_PAYMENT_HASH, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = BTC_SZ_WITPROG_P2WSH;
    key.mv_data = (CONST_CAST uint8_t *)pVout;
    uint8_t hash[1 + sizeof(uint32_t) + BTC_SZ_HASH256];
    hash[0] = (uint8_t)Type;
    memcpy(hash + 1, &Expiry, sizeof(uint32_t));
    memcpy(hash + 1 + sizeof(uint32_t), pPaymentHash, BTC_SZ_HASH256);
    data.mv_size = sizeof(hash);
    data.mv_data = hash;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


bool ln_db_payment_hash_search(
    uint8_t *pPaymentHash, ln_commit_tx_output_type_t *pType, uint32_t *pExpiry, const uint8_t *pVout, void *pDbParam)
{
    int         retval;
    MDB_txn     *p_txn;
    MDB_dbi     dbi;
    MDB_cursor  *p_cursor;
    MDB_val     key, data;
    bool        found = false;

    if (pDbParam && (mdb_txn_env(((ln_lmdb_db_t *)pDbParam)->p_txn) == mpEnvNode)) {
        p_txn = ((ln_lmdb_db_t *)pDbParam)->p_txn;
    } else {
        pDbParam = NULL;
        retval = MDB_TXN_BEGIN(mpEnvNode, NULL, 0, &p_txn);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return false;
        }
    }

    retval = MDB_DBI_OPEN(p_txn, M_DBI_PAYMENT_HASH, 0, &dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        if (!pDbParam) MDB_TXN_ABORT(p_txn);
        return false;
    }

    retval = mdb_cursor_open(p_txn, dbi, &p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        if (!pDbParam) MDB_TXN_ABORT(p_txn);
        return false;
    }

    while (mdb_cursor_get(p_cursor, &key, &data, MDB_NEXT) == 0) {
        if (key.mv_size != BTC_SZ_WITPROG_P2WSH) continue;
        if (memcmp(key.mv_data, pVout, BTC_SZ_WITPROG_P2WSH)) continue;

        uint8_t *p = (uint8_t *)data.mv_data;
        *pType = (ln_commit_tx_output_type_t)*p;
        memcpy(pExpiry, p + 1, sizeof(uint32_t));
        memcpy(pPaymentHash, p + 1 + sizeof(uint32_t), BTC_SZ_HASH256);
        found = true;
        break;
    }

    MDB_CURSOR_CLOSE(p_cursor);
    if (!pDbParam) MDB_TXN_ABORT(p_txn);
    return found;
}


/********************************************************************
 * [channel]revoked transaction close
 ********************************************************************/

bool ln_db_revoked_tx_load(ln_channel_t *pChannel, void *pDbParam)
{
    MDB_val     key, data;
    MDB_txn     *p_txn;
    MDB_dbi     dbi;
    char        db_name[M_SZ_CHANNEL_DB_NAME_STR + 1];

    p_txn = ((ln_lmdb_db_t *)pDbParam)->p_txn;
    assert(p_txn);

    memcpy(db_name, M_PREF_REVOKED_TX, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);

    int retval = MDB_DBI_OPEN(p_txn, db_name, 0, &dbi);
    if (retval) {
        //LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    ln_revoked_buf_free(pChannel);
    key.mv_size = LN_DB_KEY_RLEN;

    //number of vout scripts
    key.mv_data = LN_DB_KEY_RVN;
    retval = mdb_get(p_txn, dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    uint16_t *p = (uint16_t *)data.mv_data;
    pChannel->revoked_cnt = p[0];
    pChannel->revoked_num = p[1];
    ln_revoked_buf_alloc(pChannel); //XXX: check error code

    //vout scripts
    key.mv_data = LN_DB_KEY_RVV;
    retval = mdb_get(p_txn, dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    uint8_t *p_script = (uint8_t *)data.mv_data;
    for (int lp = 0; lp < pChannel->revoked_num; lp++) {
        uint16_t len;
        memcpy(&len, p_script, sizeof(len));
        p_script += sizeof(len);
        if (!utl_buf_alloccopy(&pChannel->p_revoked_vout[lp], p_script, len)) {
            LOGE("fail: ???\n");
            return false;
        }
        p_script += len;
    }

    //witness script
    key.mv_data = LN_DB_KEY_RVW;
    retval = mdb_get(p_txn, dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    p_script = (uint8_t *)data.mv_data;
    for (int lp = 0; lp < pChannel->revoked_num; lp++) {
        uint16_t len;
        memcpy(&len, p_script, sizeof(len));
        p_script += sizeof(len);
        if (!utl_buf_alloccopy(&pChannel->p_revoked_wit[lp], p_script, len)) {
            LOGE("fail: ???\n");
            return false;
        }
        p_script += len;
    }

    //HTLC type
    key.mv_data = LN_DB_KEY_RVT;
    retval = mdb_get(p_txn, dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    memcpy(pChannel->p_revoked_type, data.mv_data, data.mv_size);

    //remote per_commit_secret
    key.mv_data = LN_DB_KEY_RVS;
    retval = mdb_get(p_txn, dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    utl_buf_free(&pChannel->revoked_sec);
    if (!utl_buf_alloccopy(&pChannel->revoked_sec, data.mv_data, data.mv_size)) {
        LOGE("fail: ???\n");
        return false;
    }

    //confirmation数
    key.mv_data = LN_DB_KEY_RVC;
    retval = mdb_get(p_txn, dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    memcpy(&pChannel->revoked_chk, data.mv_data, sizeof(uint32_t));
    return true;
}


bool ln_db_revoked_tx_save(const ln_channel_t *pChannel, bool bUpdate, void *pDbParam)
{
    bool ret = true;
    int retval;
    MDB_val key, data;
    ln_lmdb_db_t   db;
    ln_lmdb_db_t   *p_db_param = (ln_lmdb_db_t *)pDbParam;
    char        db_name[M_SZ_CHANNEL_DB_NAME_STR + 1];
    utl_buf_t buf = UTL_BUF_INIT;
    utl_push_t push;

    if (pDbParam != NULL) {
        db.p_txn = p_db_param->p_txn;
    } else {
        retval = MDB_TXN_BEGIN(mpEnvChannel, NULL, 0, &db.p_txn);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return false;
        }
    }

    memcpy(db_name, M_PREF_REVOKED_TX, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);

    retval = MDB_DBI_OPEN(db.p_txn, db_name, MDB_CREATE, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ret = false;
        goto LABEL_EXIT;
    }

    key.mv_size = LN_DB_KEY_RLEN;
    key.mv_data = LN_DB_KEY_RVV;
    utl_push_init(&push, &buf, 0);
    for (int lp = 0; lp < pChannel->revoked_num; lp++) { //XXX: check return value
        utl_push_data(&push, &pChannel->p_revoked_vout[lp].len, sizeof(uint16_t));
        utl_push_data(&push, pChannel->p_revoked_vout[lp].buf, pChannel->p_revoked_vout[lp].len);
    }
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ret = false;
        goto LABEL_EXIT;
    }
    utl_buf_free(&buf);

    key.mv_data = LN_DB_KEY_RVW;
    utl_push_init(&push, &buf, 0);
    for (int lp = 0; lp < pChannel->revoked_num; lp++) { //XXX: check return value
        utl_push_data(&push, &pChannel->p_revoked_wit[lp].len, sizeof(uint16_t));
        utl_push_data(&push, pChannel->p_revoked_wit[lp].buf, pChannel->p_revoked_wit[lp].len);
    }
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ret = false;
        goto LABEL_EXIT;
    }
    utl_buf_free(&buf);

    key.mv_data = LN_DB_KEY_RVT;
    data.mv_size = sizeof(ln_commit_tx_output_type_t) * pChannel->revoked_num;
    data.mv_data = pChannel->p_revoked_type;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ret = false;
        goto LABEL_EXIT;
    }

    key.mv_data = LN_DB_KEY_RVS;
    data.mv_size = pChannel->revoked_sec.len;
    data.mv_data = pChannel->revoked_sec.buf;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ret = false;
        goto LABEL_EXIT;
    }

    key.mv_data = LN_DB_KEY_RVN;
    data.mv_size = sizeof(uint16_t) * 2;
    uint16_t p[2];
    p[0] = pChannel->revoked_cnt;
    p[1] = pChannel->revoked_num;
    data.mv_data = p;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ret = false;
        goto LABEL_EXIT;
    }

    key.mv_data = LN_DB_KEY_RVC;
    data.mv_size = sizeof(pChannel->revoked_chk);
    data.mv_data = (CONST_CAST uint32_t *)&pChannel->revoked_chk;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        ret = false;
        goto LABEL_EXIT;
    }

    if (bUpdate) {
        //save part of channel
        memcpy(db_name, M_PREF_CHANNEL, M_SZ_PREF_STR);
        retval = MDB_DBI_OPEN(db.p_txn, db_name, 0, &db.dbi);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            ret = false;
            goto LABEL_EXIT;
        }
        retval = channel_save(pChannel, &db);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            ret = false;
            goto LABEL_EXIT;
        }
    }

LABEL_EXIT:
    if (pDbParam == NULL) {
        MDB_TXN_COMMIT(db.p_txn);
    }
    return ret;
}


/********************************************************************
 * [wallet]wallet
 ********************************************************************/

#if 0
bool ln_db_wallet_load(utl_buf_t *pBuf, const uint8_t *pTxid, uint32_t Index)
{
    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;

    uint8_t outpoint[BTC_SZ_TXID + sizeof(uint32_t)];
    memcpy(outpoint, pTxid, BTC_SZ_TXID);
    memcpy(outpoint + BTC_SZ_TXID, &Index, sizeof(uint32_t));

    retval = wallet_db_open(&db, M_DBI_WALLET, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = sizeof(outpoint);
    key.mv_data = outpoint;
    retval = mdb_get(db.p_txn, db.dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    if (pBuf) {
        if (!utl_buf_alloccopy(pBuf, data.mv_data, data.mv_size)) {
            LOGE("fail: ???");
            MDB_TXN_ABORT(db.p_txn);
            return false;
        }
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}
#endif


/**
 * key: outpoint
 *      [32: txid] little endian
 *      [4: index]
 * data:
 *      [1: type]
 *      [8: amount] little endian
 *      [4: sequence]
 *      [4: locktime]
 *      [1: datanum] {
 *          1: len
 *          len: data
 *      }
 */
bool ln_db_wallet_save(const ln_db_wallet_t *pWallet)
{
    // LOGD("txid=");
    // TXIDD(pWallet->p_txid);
    // LOGD("index=%d\n", pWallet->index);
    // LOGD("amount=%" PRIu64 "\n", pWallet->amount);
    // LOGD("sequence=%" PRIx32 "\n", pWallet->sequence);
    // LOGD("locktime=%" PRIx32 "\n", pWallet->locktime);
    // LOGD("cnt=%d\n", pWallet->wit_item_cnt);
    // for (uint8_t lp = 0; lp < pWallet->wit_item_cnt; lp++) {
    //     LOGD("[%d]", lp);
    //     DUMPD(pWallet->p_wit_items[lp].buf, pWallet->p_wit_items[lp].len);
    // }
    // LOGD("mined_height=%d\n", pWallet->mined_height);

    if (pWallet->wit_item_cnt < 2) {
        LOGE("fail: wit_item_cnt < 2\n");
        return false;
    }
    if (pWallet->p_wit_items[0].len != BTC_SZ_PRIVKEY) {
        LOGE("fail: wit0 must be privkey\n");
        return false;
    }

    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;
    uint8_t outpoint[BTC_SZ_TXID + sizeof(uint32_t)];

    memcpy(outpoint, pWallet->p_txid, BTC_SZ_TXID);
    memcpy(outpoint + BTC_SZ_TXID, &pWallet->index, sizeof(uint32_t));
    LOGD(" txid: ");
    TXIDD(pWallet->p_txid);
    LOGD(" idx : %d\n", (int)pWallet->index);

    retval = wallet_db_open(&db, M_DBI_WALLET, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = sizeof(outpoint);
    key.mv_data = outpoint;
    data.mv_size =
        sizeof(uint8_t) +   //type
        sizeof(uint64_t) +  //amount
        sizeof(uint32_t) +  //sequence
        sizeof(uint32_t) +  //locktime
        sizeof(uint8_t) +   //datanum
        sizeof(uint32_t);   //mined_height
    for (uint32_t lp = 0; lp < pWallet->wit_item_cnt; lp++) {
        //len + data
        LOGD("[%d]len=%d, ", lp, pWallet->p_wit_items[lp].len);
        DUMPD(pWallet->p_wit_items[lp].buf, pWallet->p_wit_items[lp].len);
        data.mv_size += sizeof(uint8_t) + (uint8_t)pWallet->p_wit_items[lp].len;
    }
    uint8_t *p_wit_items = (uint8_t *)UTL_DBG_MALLOC(data.mv_size);
    if (!p_wit_items) {
        LOGE("fail: ???");
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }
    uint8_t *p_pos = p_wit_items;
    *p_pos = pWallet->type;
    p_pos++;
    memcpy(p_pos, &pWallet->amount, sizeof(uint64_t));
    p_pos += sizeof(uint64_t);
    memcpy(p_pos, &pWallet->sequence, sizeof(uint32_t));
    p_pos += sizeof(uint32_t);
    memcpy(p_pos, &pWallet->locktime, sizeof(uint32_t));
    p_pos += sizeof(uint32_t);
    *p_pos = (uint8_t)(pWallet->wit_item_cnt);
    p_pos++;
    for (uint32_t lp = 0; lp < pWallet->wit_item_cnt; lp++) {
        *p_pos = (uint8_t)pWallet->p_wit_items[lp].len;
        p_pos++;
        memcpy(p_pos, pWallet->p_wit_items[lp].buf, pWallet->p_wit_items[lp].len);
        p_pos += pWallet->p_wit_items[lp].len;
    }
    memcpy(p_pos, &pWallet->mined_height, sizeof(uint32_t));
    p_pos += sizeof(uint32_t);

    data.mv_data = p_wit_items;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        UTL_DBG_FREE(p_wit_items);
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    UTL_DBG_FREE(p_wit_items);
    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


bool ln_db_wallet_search(ln_db_func_wallet_t pWalletFunc, void *pFuncParam)
{
    int             retval;
    lmdb_cursor_t   cur;

    cur.p_cursor = NULL;
    retval = wallet_db_open((ln_lmdb_db_t *)&cur, M_DBI_WALLET, 0, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    if (!ln_lmdb_wallet_search(&cur, pWalletFunc, pFuncParam)) {
        if (cur.p_cursor) {
            MDB_CURSOR_CLOSE(cur.p_cursor);
        }
        MDB_TXN_ABORT(cur.p_txn);
        return false;
    }

    if (cur.p_cursor) {
        MDB_CURSOR_CLOSE(cur.p_cursor);
    }
    MDB_TXN_ABORT(cur.p_txn);
    return true;
}


bool ln_lmdb_wallet_search(lmdb_cursor_t *pCur, ln_db_func_wallet_t pWalletFunc, void *pFuncParam)
{
    int         retval;
    MDB_val     key;
    MDB_val     data;

    retval = mdb_cursor_open(pCur->p_txn, pCur->dbi, &pCur->p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    while ((retval = mdb_cursor_get(pCur->p_cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        ln_db_wallet_t wallet = LN_DB_WALLET_INIT(0);

        uint8_t *p_key = (uint8_t *)key.mv_data;
        uint8_t *p_data = (uint8_t *)data.mv_data;

        wallet.p_txid = p_key;
        memcpy(&wallet.index, p_key + BTC_SZ_TXID, sizeof(uint32_t));

        wallet.type = *p_data;
        p_data++;
        memcpy(&wallet.amount, p_data, sizeof(uint64_t));
        p_data += sizeof(uint64_t);
        memcpy(&wallet.sequence, p_data, sizeof(uint32_t));
        p_data += sizeof(uint32_t);
        memcpy(&wallet.locktime, p_data, sizeof(uint32_t));
        p_data += sizeof(uint32_t);
        wallet.wit_item_cnt = *p_data;
        p_data++;
        if (wallet.wit_item_cnt) {
            wallet.p_wit_items = UTL_DBG_MALLOC(sizeof(utl_buf_t) * wallet.wit_item_cnt);
            if (!wallet.p_wit_items) {
                LOGE("fail: ???");
                retval = -1;
                break;
            }
            for (uint8_t lp = 0; lp < wallet.wit_item_cnt; lp++) {
                wallet.p_wit_items[lp].len = *p_data;
                p_data++;
                if (wallet.p_wit_items[lp].len) {
                    wallet.p_wit_items[lp].buf = p_data;
                    p_data += wallet.p_wit_items[lp].len;
                } else {
                    wallet.p_wit_items[lp].buf = NULL;
                }
            }
        }
        if (data.mv_size >= (size_t)((void *)p_data - data.mv_data + sizeof(uint32_t))) {
            memcpy(&wallet.mined_height, p_data, sizeof(uint32_t));
        } else {
            wallet.mined_height = 0;
        }
        bool stop = (*pWalletFunc)(&wallet, pFuncParam);
        UTL_DBG_FREE(wallet.p_wit_items);
        if (stop) {
            break;
        }
    }

    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return false;
        }
    }
    return true;
}


bool ln_db_wallet_del(const uint8_t *pTxid, uint32_t Index)
{
    int             retval;
    MDB_val         key;
    ln_lmdb_db_t    db;
    uint8_t         outpoint[BTC_SZ_TXID + sizeof(uint32_t)];

    memcpy(outpoint, pTxid, BTC_SZ_TXID);
    memcpy(outpoint + BTC_SZ_TXID, &Index, sizeof(uint32_t));
    LOGD(" txid: ");
    TXIDD(pTxid);
    LOGD(" idx : %d\n", (int)Index);

    retval = wallet_db_open(&db, M_DBI_WALLET, 0, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = sizeof(outpoint);
    key.mv_data = outpoint;
    retval = mdb_del(db.p_txn, db.dbi, &key, NULL);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


/********************************************************************
 * [channel]version
 ********************************************************************/

bool ln_db_version_check(uint8_t *pMyNodeId, btc_block_chain_t *pBlockChain)
{
    int             retval;
    ln_lmdb_db_t    db;

    retval = channel_db_open(&db, M_DBI_VERSION, MDB_RDONLY, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    bool        ret = false;
    int32_t     ver;
    char        wif[BTC_SZ_WIF_STR_MAX + 1] = "";
    char        alias[LN_SZ_ALIAS_STR + 1] = "";
    uint16_t    port = 0;
    uint8_t     genesis[BTC_SZ_HASH256];
    retval = version_check(&db, &ver, wif, alias, &port, genesis, false);
    if (retval) {
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    btc_keys_t key;
    btc_chain_t chain;
    if (!btc_keys_wif2keys(&key, &chain, wif)) {
        goto LABEL_EXIT;
    }

    btc_block_chain_t type = btc_block_get_chain(genesis);
    if (((chain == BTC_MAINNET) && (type == BTC_BLOCK_CHAIN_BTCMAIN)) ||
        ((chain == BTC_TESTNET) && (type == BTC_BLOCK_CHAIN_BTCTEST)) ||
        ((chain == BTC_TESTNET) && (type == BTC_BLOCK_CHAIN_BTCREGTEST))) {
        //ok
    } else {
        goto LABEL_EXIT;
    }

    if (pMyNodeId) {
        memcpy(pMyNodeId, key.pub, BTC_SZ_PUBKEY);
    }
    if (pBlockChain) {
        *pBlockChain = type;
    }
    ret = true;

LABEL_EXIT:
    MDB_TXN_ABORT(db.p_txn);
    return ret;
}


int ln_db_lmdb_get_my_node_id(
    MDB_txn *pTxn, MDB_dbi Dbi, int32_t *pVersion, char *pWif, char *pAlias, uint16_t *pPort, uint8_t *pGenesis)
{
    ln_lmdb_db_t    db;

    db.p_txn = pTxn;
    db.dbi = Dbi;
    return version_check(&db, pVersion, pWif, pAlias, pPort, pGenesis, false);
}


/********************************************************************
 * others
 ********************************************************************/

ln_lmdb_db_type_t ln_lmdb_get_db_type(const MDB_env *pEnv, const char *pDbName)
{
    if (pEnv == mpEnvChannel) {
        if (strncmp(pDbName, M_PREF_CHANNEL, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_CHANNEL;
        if (strncmp(pDbName, M_PREF_SECRET, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_SECRET;
        if (strncmp(pDbName, M_PREF_HTLC, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_HTLC;
        if (strncmp(pDbName, M_PREF_REVOKED_TX, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_REVOKED_TX;
    } else {
        if (strncmp(pDbName, M_PREF_CHANNEL, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_CLOSED_CHANNEL;
        if (strncmp(pDbName, M_PREF_SECRET, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_CLOSED_SECRET;
        if (strncmp(pDbName, M_PREF_HTLC, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_CLOSED_HTLC;
        if (strncmp(pDbName, M_PREF_REVOKED_TX, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_CLOSED_REVOKED_TX;
    }

    if (strcmp(pDbName, M_DBI_WALLET) == 0) return LN_LMDB_DB_TYPE_WALLET;
    if (strcmp(pDbName, M_DBI_CNLANNO) == 0) return LN_LMDB_DB_TYPE_CNLANNO;
    if (strcmp(pDbName, M_DBI_NODEANNO) == 0) return LN_LMDB_DB_TYPE_NODEANNO;
    if (strcmp(pDbName, M_DBI_CNLANNO_INFO) == 0) return LN_LMDB_DB_TYPE_CNLANNO_INFO;
    if (strcmp(pDbName, M_DBI_NODEANNO_INFO) == 0) return LN_LMDB_DB_TYPE_NODEANNO_INFO;

    if (pEnv == mpEnvNode) {
        if (strcmp(pDbName, M_DBI_ROUTE_SKIP) == 0) return LN_LMDB_DB_TYPE_ROUTE_SKIP;
        if (strcmp(pDbName, M_DBI_PREIMAGE) == 0) return LN_LMDB_DB_TYPE_PREIMAGE;
        if (strcmp(pDbName, M_DBI_PAYMENT_HASH) == 0) return LN_LMDB_DB_TYPE_PAYMENT_HASH;
    }

    if (strcmp(pDbName, M_DBI_VERSION) == 0) return LN_LMDB_DB_TYPE_VERSION;

    if (strncmp(pDbName, M_PREF_FORWARD_ADD_HTLC, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_FORWARD_ADD;
    if (strncmp(pDbName, M_PREF_FORWARD_DEL_HTLC, M_SZ_PREF_STR) == 0) return LN_LMDB_DB_TYPE_FORWARD_DEL;

    if (pEnv == mpEnvPayment) {
        if (strcmp(pDbName, M_DBI_PAYMENT) == 0) return LN_LMDB_DB_TYPE_PAYMENT;
        if (strcmp(pDbName, M_DBI_SHARED_SECRETS) == 0) return LN_LMDB_DB_TYPE_SHARED_SECRETS;
        if (strcmp(pDbName, M_DBI_ROUTE) == 0) return LN_LMDB_DB_TYPE_ROUTE;
        if (strcmp(pDbName, M_DBI_PAYMENT_INVOICE) == 0) return LN_LMDB_DB_TYPE_PAYMENT_INVOICE;
        if (strcmp(pDbName, M_DBI_PAYMENT_INFO) == 0) return LN_LMDB_DB_TYPE_PAYMENT_INFO;
    }

    return LN_LMDB_DB_TYPE_UNKNOWN;
}


/* showdb/routingから使用される。
 *
 */
void ln_lmdb_set_env(MDB_env *pEnv, MDB_env *pNode, MDB_env *pAnno, MDB_env *pWallet)
{
    mpEnvChannel = pEnv;
    mpEnvNode = pNode;
    mpEnvAnno = pAnno;
    mpEnvWallet = pWallet;
}


bool ln_db_reset(void)
{
    int retval;

    if (mpEnvChannel) {
        fprintf(stderr, "fail: already started\n");
        return false;
    }

    if (mPath[0] == '\0') {
        ln_lmdb_set_home_dir(".");
    }
    retval = init_db_env(&INIT_PARAM[M_INIT_PARAM_CHANNEL]);
    if (retval) {
        fprintf(stderr, "ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    lmdb_cursor_t cur;
    LOGD("channel cursor open\n");
    retval = channel_cursor_open(&cur, true);
    if (retval) {
        fprintf(stderr, "fail: open\n");
        return false;
    }

    //ここまで来たら成功と見なしてよい //XXX: ???

    //tar db directory
    char bak_tgz[PATH_MAX];
    char cmdline[512];
    snprintf(bak_tgz, sizeof(bak_tgz), "bak_db_%" PRIu64 ".tgz", (uint64_t)utl_time_time());
    snprintf(cmdline, sizeof(cmdline), "tar zcf %.500s db", bak_tgz);
    retval = system(cmdline);
    LOGD(" system=%d\n", retval);

    //remove other directories
    const char *DELPATH[] = {
        ln_lmdb_get_node_db_path(),
        ln_lmdb_get_anno_db_path(),
        ln_lmdb_get_wallet_db_path(),
        ln_lmdb_get_forward_db_path(),
        ln_lmdb_get_payment_db_path(),
    };
    for (size_t lp = 0; lp < ARRAY_SIZE(DELPATH); lp++) {
        snprintf(cmdline, sizeof(cmdline), "rm -rf %s", DELPATH[lp]);
        fprintf(stderr, "  remove %s\n", DELPATH[lp]);
        retval = system(cmdline);
        LOGD(" system=%d\n", retval);
    }

    MDB_val key;
    while (mdb_cursor_get(cur.p_cursor, &key, NULL, MDB_NEXT_NODUP) == 0) {
        //"version"以外は削除
        if (memcmp(key.mv_data, M_DBI_VERSION, sizeof(M_DBI_VERSION) - 1) == 0) continue;

        char *p_name = (char *)UTL_DBG_MALLOC(key.mv_size + 1);
        if (!p_name) {
            LOGE("fail: ???");
            break;
        }

        memcpy(p_name, key.mv_data, key.mv_size);
        p_name[key.mv_size] = '\0';
        LOGD("db_name: %s\n", p_name);

        MDB_dbi dbi;
        retval = MDB_DBI_OPEN(cur.p_txn, p_name, 0, &dbi);
        if (retval == 0) {
            retval = mdb_drop(cur.p_txn, dbi, 1);
            if (retval) {
                LOGE("ERR: %s\n", mdb_strerror(retval));
            }
        }

        UTL_DBG_FREE(p_name);
    }

    channel_cursor_close(&cur, true);

    fprintf(stderr, "removed.\n");
    return true;
}


void ln_db_copy_channel(ln_channel_t *pOutChannel, const ln_channel_t *pInChannel)
{
    //XXX: check return code

    LOGD("recover\n");
    //fixed size data

    for (size_t lp = 0; lp < ARRAY_SIZE(DBCHANNEL_VALUES); lp++) {
        memcpy((uint8_t *)pOutChannel + DBCHANNEL_VALUES[lp].offset, (uint8_t *)pInChannel + DBCHANNEL_VALUES[lp].offset,  DBCHANNEL_VALUES[lp].data_len);
    }

    memcpy(
        pOutChannel->update_info.htlcs,  pInChannel->update_info.htlcs,
        M_SIZE(ln_update_info_t, htlcs));

    //復元データ
    utl_buf_alloccopy(&pOutChannel->funding_info.wit_script, pInChannel->funding_info.wit_script.buf, pInChannel->funding_info.wit_script.len);
    pOutChannel->funding_info.key_order = pInChannel->funding_info.key_order;


    //fixed size data(shallow copy)

    //funding_info.tx_data
    btc_tx_free(&pOutChannel->funding_info.tx_data);
    memcpy(&pOutChannel->funding_info.tx_data, &pInChannel->funding_info.tx_data, sizeof(btc_tx_t));

    //shutdown_scriptpk_local
    utl_buf_free(&pOutChannel->shutdown_scriptpk_local);
    memcpy(&pOutChannel->shutdown_scriptpk_local, &pInChannel->shutdown_scriptpk_local, sizeof(utl_buf_t));

    //shutdown_scriptpk_remote
    utl_buf_free(&pOutChannel->shutdown_scriptpk_remote);
    memcpy(&pOutChannel->shutdown_scriptpk_remote, &pInChannel->shutdown_scriptpk_remote, sizeof(utl_buf_t));

    //keys
    memcpy(&pOutChannel->keys_local, &pInChannel->keys_local, sizeof(ln_derkey_local_keys_t));
    memcpy(&pOutChannel->keys_remote, &pInChannel->keys_remote, sizeof(ln_derkey_remote_keys_t));
}


/********************************************************************
 * forward
 ********************************************************************/

bool ln_db_forward_add_htlc_create(uint64_t NextShortChannelId)
{
    LOGD("NextShortChannelId: %016" PRIx64 "\n", NextShortChannelId);
    return forward_create(NextShortChannelId, M_PREF_FORWARD_ADD_HTLC);
}


bool ln_db_forward_add_htlc_save(const ln_db_forward_t *pForward)
{
    //LOGD("NextShortChannelId: %016" PRIx64 "\n", pForward->next_short_channel_id);
    //LOGD("PrevShortChannelId: %016" PRIx64 "\n", pForward->prev_short_channel_id);
    //LOGD("PrevHtlcId: %016" PRIx64 "\n", pForward->prev_htlc_id);
    return forward_save_2(pForward, M_PREF_FORWARD_ADD_HTLC);
}


bool ln_db_forward_add_htlc_del(uint64_t NextShortChannelId, uint64_t PrevShortChannelId, uint64_t PrevHtlcId)
{
    //LOGD("NextShortChannelId: %016" PRIx64 "\n", NextShortChannelId);
    //LOGD("PrevShortChannelId: %016" PRIx64 "\n", PrevShortChannelId);
    //LOGD("PrevHtlcId: %016" PRIx64 "\n", PrevHtlcId);
    return forward_del_2(NextShortChannelId, PrevShortChannelId, PrevHtlcId, M_PREF_FORWARD_ADD_HTLC);
}


bool ln_db_forward_add_htlc_drop(uint64_t NextShortChannelId)
{
    LOGD("NextShortChannelId: %016" PRIx64 "\n", NextShortChannelId);
    return forward_drop(NextShortChannelId, M_PREF_FORWARD_ADD_HTLC);
}


bool ln_db_forward_del_htlc_create(uint64_t NextShortChannelId)
{
    LOGD("NextShortChannelId: %016" PRIx64 "\n", NextShortChannelId);
    return forward_create(NextShortChannelId, M_PREF_FORWARD_DEL_HTLC);
}


bool ln_db_forward_del_htlc_save(const ln_db_forward_t* pForward)
{
    //LOGD("NextShortChannelId: %016" PRIx64 "\n", pForward->next_short_channel_id);
    //LOGD("PrevShortChannelId: %016" PRIx64 "\n", pForward->prev_short_channel_id);
    //LOGD("PrevHtlcId: %016" PRIx64 "\n", pForward->prev_htlc_id);
    return forward_save_2(pForward, M_PREF_FORWARD_DEL_HTLC);
}


bool ln_db_forward_del_htlc_save_2(const ln_db_forward_t* pForward, void *pDbParam)
{
    //LOGD("NextShortChannelId: %016" PRIx64 "\n", pForward->next_short_channel_id);
    //LOGD("PrevShortChannelId: %016" PRIx64 "\n", pForward->prev_short_channel_id);
    //LOGD("PrevHtlcId: %016" PRIx64 "\n", pForward->prev_htlc_id);

    ln_lmdb_db_t    *p_db = (ln_lmdb_db_t *)pDbParam;
    assert(p_db);
    MDB_txn         *p_txn = p_db->p_txn;
    assert(p_txn);
    return forward_save_3(pForward, M_PREF_FORWARD_DEL_HTLC, p_txn);
}


bool ln_db_forward_del_htlc_del(uint64_t NextShortChannelId, uint64_t PrevShortChannelId, uint64_t PrevHtlcId)
{
    //LOGD("NextShortChannelId: %016" PRIx64 "\n", NextShortChannelId);
    //LOGD("PrevShortChannelId: %016" PRIx64 "\n", PrevShortChannelId);
    //LOGD("PrevHtlcId: %016" PRIx64 "\n", PrevHtlcId);
    return forward_del_2(NextShortChannelId, PrevShortChannelId, PrevHtlcId, M_PREF_FORWARD_DEL_HTLC);
}


bool ln_db_forward_del_htlc_drop(uint64_t NextShortChannelId)
{
    LOGD("NextShortChannelId: %016" PRIx64 "\n", NextShortChannelId);
    return forward_drop(NextShortChannelId, M_PREF_FORWARD_DEL_HTLC);
}


/********************************************************************
 * forward cursor
 ********************************************************************/

bool ln_db_forward_add_htlc_cur_open(void **ppCur, uint64_t NextShortChannelId)
{
    return forward_cur_open(ppCur, NextShortChannelId, M_PREF_FORWARD_ADD_HTLC);
}


void ln_db_forward_add_htlc_cur_close(void *pCur, bool bCommit)
{
    forward_cur_close(pCur, bCommit);
}


bool ln_db_forward_add_htlc_cur_get(void *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg)
{
    return forward_cur_get(pCur, pPrevShortChannelId, pPrevHtlcId, pMsg);
}


bool ln_db_forward_add_htlc_cur_del(void *pCur)
{
    //LOGD("\n");
    return forward_cur_del(pCur);
}


bool ln_db_forward_del_htlc_cur_open(void **ppCur, uint64_t NextShortChannelId)
{
    return forward_cur_open(ppCur, NextShortChannelId, M_PREF_FORWARD_DEL_HTLC);
}


void ln_db_forward_del_htlc_cur_close(void *pCur, bool bCommit)
{
    forward_cur_close(pCur, bCommit);
}


bool ln_db_forward_del_htlc_cur_get(void *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg)
{
    return forward_cur_get(pCur, pPrevShortChannelId, pPrevHtlcId, pMsg);
}


bool ln_db_forward_del_htlc_cur_del(void *pCur)
{
    //LOGD("\n");
    return forward_cur_del(pCur);
}


/********************************************************************
 * payment
 ********************************************************************/

bool ln_db_payment_get_new_payment_id(uint64_t *pPaymentId)
{
    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;

    retval = payment_db_open(&db, M_DBI_PAYMENT, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = M_SZ_PAYMENT_ID;
    key.mv_data = M_KEY_PAYMENT_ID;
    retval = mdb_get(db.p_txn, db.dbi, &key, &data);
    if (retval == 0) {
        if (data.mv_size != sizeof(uint64_t)) {
            LOGE("fail: ???\n");
            MDB_TXN_ABORT(db.p_txn);
            return false;
        }
        *pPaymentId = *((uint64_t *)data.mv_data);
    } else {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            MDB_TXN_ABORT(db.p_txn);
            return false;
        }
        *pPaymentId = 0;
    }

    uint64_t next_payment_id = *pPaymentId;
    next_payment_id++;

    key.mv_size = M_SZ_PAYMENT_ID;
    key.mv_data = M_KEY_PAYMENT_ID;
    data.mv_size = sizeof(uint64_t);
    data.mv_data = &next_payment_id;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


bool ln_db_payment_shared_secrets_save(uint64_t PaymentId, const uint8_t *pData, uint32_t Len)
{
    return payment_save(M_DBI_SHARED_SECRETS, PaymentId, pData, Len);
}


bool ln_db_payment_shared_secrets_load(utl_buf_t *pBuf, uint64_t PaymentId)
{
    return payment_load_2(M_DBI_SHARED_SECRETS, pBuf, PaymentId);
}


bool ln_db_payment_shared_secrets_del(uint64_t PaymentId)
{
    return payment_del(M_DBI_SHARED_SECRETS, PaymentId);
}


bool ln_db_payment_route_save(uint64_t PaymentId, const uint8_t *pData, uint32_t Len)
{
    return payment_save(M_DBI_ROUTE, PaymentId, pData, Len);
}


bool ln_db_payment_route_load(utl_buf_t *pBuf, uint64_t PaymentId)
{
    return payment_load_2(M_DBI_ROUTE, pBuf, PaymentId);
}


bool ln_db_payment_route_del(uint64_t PaymentId)
{
    return payment_del(M_DBI_ROUTE, PaymentId);
}


bool ln_db_payment_invoice_save(uint64_t PaymentId, const uint8_t *pData, uint32_t Len)
{
    return payment_save(M_DBI_PAYMENT_INVOICE, PaymentId, pData, Len);
}


bool ln_db_payment_invoice_load(utl_buf_t *pBuf, uint64_t PaymentId)
{
    return payment_load_2(M_DBI_PAYMENT_INVOICE, pBuf, PaymentId);
}


bool ln_db_payment_invoice_load_2(utl_buf_t *pBuf, uint64_t PaymentId, void *pDbParam)
{
    ln_lmdb_db_t    *p_db = (ln_lmdb_db_t *)pDbParam;
    assert(p_db);
    MDB_txn         *p_txn = p_db->p_txn;
    assert(p_txn);
    return payment_load_3(M_DBI_PAYMENT_INVOICE, pBuf, PaymentId, p_txn);
}


bool ln_db_payment_invoice_del(uint64_t PaymentId)
{
    return payment_del(M_DBI_PAYMENT_INVOICE, PaymentId);
}


bool ln_db_payment_info_save(uint64_t PaymentId, const ln_payment_info_t *pInfo)
{
    return payment_save(
        M_DBI_PAYMENT_INFO, PaymentId, (const uint8_t *)pInfo, sizeof(ln_payment_info_t));
}


bool ln_db_payment_info_load(ln_payment_info_t *pInfo, uint64_t PaymentId)
{
    utl_buf_t buf = UTL_BUF_INIT;
    if (!payment_load_2(M_DBI_PAYMENT_INFO, &buf, PaymentId)) {
        LOGE("fail: ???\n");
        return false;
    }
    if (buf.len != sizeof(ln_payment_info_t)) {
        LOGE("fail: ???\n");
        return false;
    }
    memcpy(pInfo, buf.buf, buf.len);
    utl_buf_free(&buf);
    return true;
}


bool ln_db_payment_info_del(uint64_t PaymentId)
{
    return payment_del(M_DBI_PAYMENT_INFO, PaymentId);
}


bool ln_db_payment_del_all(uint64_t PaymentId)
{
    /*ignore*/ln_db_payment_shared_secrets_del(PaymentId);
    /*ignore*/ln_db_payment_route_del(PaymentId);
    /*ignore*/ln_db_payment_invoice_del(PaymentId);
    return ln_db_payment_info_del(PaymentId);
}


/********************************************************************
 * forward cursor
 ********************************************************************/

bool ln_db_payment_info_cur_open(void **ppCur)
{
    return payment_cur_open(ppCur, M_DBI_PAYMENT_INFO);
}


void ln_db_payment_info_cur_close(void *pCur, bool bCommit)
{
    payment_cur_close(pCur, bCommit);
}


bool ln_db_payment_info_cur_get(void *pCur, uint64_t *pPaymentId, ln_payment_info_t *pInfo)
{
    utl_buf_t buf = UTL_BUF_INIT;
    if (!payment_cur_get(pCur, pPaymentId, &buf)) {
        utl_buf_free(&buf);
        return false;
    }
    if (buf.len != sizeof(ln_payment_info_t)) {
        LOGE("fail: ???\n");
        utl_buf_free(&buf);
        return false;
    }
    memcpy(pInfo, buf.buf, buf.len);
    return true;
}


bool ln_db_payment_info_cur_del(void *pCur)
{
    return payment_cur_del(pCur);
}


/********************************************************************
 * private functions
 ********************************************************************/

static int db_open(ln_lmdb_db_t *pDb, MDB_env *env, const char *pDbName, int OptTxn, int OptDb)
{
    int retval;

    retval = MDB_TXN_BEGIN(env, NULL, OptTxn, &pDb->p_txn);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        pDb->p_txn = NULL;
        goto LABEL_EXIT;
    }
    retval = MDB_DBI_OPEN(pDb->p_txn, pDbName, OptDb, &pDb->dbi);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        MDB_TXN_ABORT(pDb->p_txn);
        pDb->p_txn = NULL;
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    return retval;
}


static int db_open_2(ln_lmdb_db_t *pDb, MDB_txn *pTxn, const char *pDbName, int OptDb)
{
    int retval;

    retval = MDB_DBI_OPEN(pTxn, pDbName, OptDb, &pDb->dbi);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        pDb->p_txn = NULL;
        goto LABEL_EXIT;
    }
    pDb->p_txn = pTxn;

LABEL_EXIT:
    return retval;
}


/********************************************************************
 * private functions: channel
 ********************************************************************/

static bool set_path(char *pPath, size_t Size, const char *pDir, const char *pName)
{
    if (strlen(pDir) + 1 + strlen(pName) > M_DB_PATH_STR_MAX) return false;
    snprintf(pPath, Size, "%s/%s", pDir, pName);
    return true;
}


static int channel_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb)
{
    return db_open(pDb, mpEnvChannel, pDbName , OptTxn, OptDb);
}


/** channel: htlc読み込み
 *
 * @param[out]      pChannel
 * @param[in]       pDb
 * @retval      true    成功
 */
static int channel_htlc_load(ln_channel_t *pChannel, ln_lmdb_db_t *pDb)
{
    //XXX: Error is not checked

    int         retval = -1;
    MDB_dbi     dbi;
    MDB_val     key, data;
    char        db_name[M_SZ_CHANNEL_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];

    uint8_t *OFFSET =
        ((uint8_t *)pChannel) + offsetof(ln_channel_t, update_info) + offsetof(ln_update_info_t, htlcs);

    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(db_name, M_PREF_HTLC, M_SZ_PREF_STR);

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        channel_htlc_db_name(db_name, lp);
        //LOGD("[%d]db_name: %s\n", lp, db_name);
        retval = MDB_DBI_OPEN(pDb->p_txn, db_name, 0, &dbi);
        if (retval) {
            LOGE("ERR: %s(%s)\n", mdb_strerror(retval), db_name);
            continue; //XXX: ???
        }

        //fixed
        for (size_t lp2 = 0; lp2 < ARRAY_SIZE(DBHTLC_VALUES); lp2++) {
            key.mv_size = strlen(DBHTLC_VALUES[lp2].p_name);
            key.mv_data = (CONST_CAST char*)DBHTLC_VALUES[lp2].p_name;
            retval = mdb_get(pDb->p_txn, dbi, &key, &data);
            if (retval == 0) {
                //LOGD("[%d]%s: ", lp, DBHTLC_VALUES[lp2].p_name);
                //DUMPD(data.mv_data, data.mv_size);
                memcpy(OFFSET + sizeof(ln_htlc_t) * lp + DBHTLC_VALUES[lp2].offset, data.mv_data, DBHTLC_VALUES[lp2].data_len);
            } else {
                LOGE("ERR: %s(%s)\n", mdb_strerror(retval), DBHTLC_VALUES[lp2].p_name);
            }
        }

        //variable
        key.mv_size = M_SZ_PREIMAGE;
        key.mv_data = M_KEY_PREIMAGE;
        retval = mdb_get(pDb->p_txn, dbi, &key, &data);
        if (retval == 0) {
            if (!utl_buf_alloccopy(
                &pChannel->update_info.htlcs[lp].buf_preimage, data.mv_data, data.mv_size)) {
                LOGE("fail: ???\n");
                retval = -1;
                MDB_DBI_CLOSE(mpEnvChannel, dbi);
                break;
            }
        } else {
            //LOGE("ERR: %s(preimage)\n", mdb_strerror(retval));
            retval = 0;     //FALLTHROUGH
        }

        key.mv_size = M_SZ_ONION_ROUTE;
        key.mv_data = M_KEY_ONION_ROUTE;
        retval = mdb_get(pDb->p_txn, dbi, &key, &data);
        if (retval == 0) {
            if (!utl_buf_alloccopy(
                &pChannel->update_info.htlcs[lp].buf_onion_reason, data.mv_data, data.mv_size)) {
                LOGE("fail: ???\n");
                retval = -1;
                MDB_DBI_CLOSE(mpEnvChannel, dbi);
                break;
            }
        } else {
            //LOGE("ERR: %s(onion_route)\n", mdb_strerror(retval));
            retval = 0;     //FALLTHROUGH
        }

        key.mv_size = M_SZ_SHARED_SECRET;
        key.mv_data = M_KEY_SHARED_SECRET;
        retval = mdb_get(pDb->p_txn, dbi, &key, &data);
        if (retval == 0) {
            if (!utl_buf_alloccopy(
                &pChannel->update_info.htlcs[lp].buf_shared_secret, data.mv_data, data.mv_size)) {
                LOGE("fail: ???\n");
                retval = -1;
                MDB_DBI_CLOSE(mpEnvChannel, dbi);
                break;
            }
        } else {
            //LOGE("ERR: %s(shared_secret)\n", mdb_strerror(retval));
            retval = 0;     //FALLTHROUGH
        }

        MDB_DBI_CLOSE(mpEnvChannel, dbi);
    }

    return retval;
}


/** channel: htlc書込み
 *
 * @param[in]       pChannel
 * @param[in]       pDb
 * @retval      true    成功
 */
static int channel_htlc_save(const ln_channel_t *pChannel, ln_lmdb_db_t *pDb)
{
    int         retval;
    MDB_dbi     dbi;
    MDB_val     key, data;
    char        db_name[M_SZ_CHANNEL_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];

    uint8_t *OFFSET =
        ((uint8_t *)pChannel) + offsetof(ln_channel_t, update_info) + offsetof(ln_update_info_t, htlcs);

    memcpy(db_name, M_PREF_HTLC, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        channel_htlc_db_name(db_name, lp);
        //LOGD("[%d]db_name: %s\n", lp, db_name);
        retval = MDB_DBI_OPEN(pDb->p_txn, db_name, MDB_CREATE, &dbi);
        if (retval) {
            LOGE("ERR: %s(%s)\n", mdb_strerror(retval), db_name);
            goto LABEL_EXIT;
        }

        //fixed
        ln_lmdb_db_t db;
        db.p_txn = pDb->p_txn;
        db.dbi = dbi;
        retval = fixed_items_save(OFFSET + sizeof(ln_htlc_t) * lp,
                        &db, DBHTLC_VALUES, ARRAY_SIZE(DBHTLC_VALUES));
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }

        //variable
        if (pChannel->update_info.htlcs[lp].buf_preimage.len) {
            key.mv_size = M_SZ_PREIMAGE;
            key.mv_data = M_KEY_PREIMAGE;
            data.mv_size = pChannel->update_info.htlcs[lp].buf_preimage.len;
            data.mv_data = pChannel->update_info.htlcs[lp].buf_preimage.buf;
            retval = mdb_put(pDb->p_txn, dbi, &key, &data, 0);
            if (retval) {
                LOGE("ERR: %s(preimage)\n", mdb_strerror(retval));
                goto LABEL_EXIT;
            }
        }

        key.mv_size = M_SZ_ONION_ROUTE;
        key.mv_data = M_KEY_ONION_ROUTE;
        data.mv_size = pChannel->update_info.htlcs[lp].buf_onion_reason.len;
        data.mv_data = pChannel->update_info.htlcs[lp].buf_onion_reason.buf;
        retval = mdb_put(pDb->p_txn, dbi, &key, &data, 0);
        if (retval) {
            LOGE("ERR: %s(onion_route)\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }

        key.mv_size = M_SZ_SHARED_SECRET;
        key.mv_data = M_KEY_SHARED_SECRET;
        data.mv_size = pChannel->update_info.htlcs[lp].buf_shared_secret.len;
        data.mv_data = pChannel->update_info.htlcs[lp].buf_shared_secret.buf;
        retval = mdb_put(pDb->p_txn, dbi, &key, &data, 0);
        if (retval) {
            LOGE("ERR: %s(shared_secret)\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
    }

LABEL_EXIT:
    return retval;
}


/** channel情報書き込み
 *
 * @param[in]       pChannel
 * @param[in,out]   pDb
 * @retval      true    成功
 */
static int channel_save(const ln_channel_t *pChannel, ln_lmdb_db_t *pDb)
{
    MDB_val key, data;
    int     retval;

    //fixed size data
    retval = fixed_items_save(pChannel, pDb, DBCHANNEL_VALUES, ARRAY_SIZE(DBCHANNEL_VALUES));
    if (retval) {
        return retval;
    }

    //variable size data
    utl_buf_t buf_fund_tx = UTL_BUF_INIT;
    btc_tx_write(&pChannel->funding_info.tx_data, &buf_fund_tx);
    variable_item_t *p_variable_items = (variable_item_t *)UTL_DBG_MALLOC(sizeof(variable_item_t) * M_NUM_CHANNEL_BUFS);
    if (!p_variable_items) {
        LOGE("fail: ???");
        goto LABEL_EXIT;
    }
    int index = 0;
    p_variable_items[index].p_name = "buf_fund_tx";
    p_variable_items[index].p_buf = &buf_fund_tx;
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_local);
    index++;
    M_BUF_ITEM(index, shutdown_scriptpk_remote);
    //index++;

    for (size_t lp = 0; lp < M_NUM_CHANNEL_BUFS; lp++) {
        key.mv_size = strlen(p_variable_items[lp].p_name);
        key.mv_data = (CONST_CAST char*)p_variable_items[lp].p_name;
        data.mv_size = p_variable_items[lp].p_buf->len;
        data.mv_data = p_variable_items[lp].p_buf->buf;
        retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
        if (retval) {
            LOGE("fail: %s\n", p_variable_items[lp].p_name);
            goto LABEL_EXIT;
        }
    }

LABEL_EXIT:
    utl_buf_free(&buf_fund_tx);
    UTL_DBG_FREE(p_variable_items);
    return retval;
}


static int channel_item_load(ln_channel_t *pChannel, const fixed_item_t *pItems, ln_lmdb_db_t *pDb)
{
    int     retval;
    MDB_val key, data;

    key.mv_size = strlen(pItems->p_name);
    key.mv_data = (CONST_CAST char*)pItems->p_name;
    retval = mdb_get(pDb->p_txn, pDb->dbi, &key, &data);
    if (retval) {
        LOGE("fail: %s(%s)\n", mdb_strerror(retval), pItems->p_name);
        return retval;
    }

    if (data.mv_size != pItems->data_len) {
        retval = -1;
        LOGE("fail: %s(%s)\n", mdb_strerror(retval), pItems->p_name);
        return retval;
    }

    memcpy((uint8_t *)pChannel + pItems->offset, data.mv_data, data.mv_size);
    return 0;
}


static int channel_item_save(const ln_channel_t *pChannel, const fixed_item_t *pItems, ln_lmdb_db_t *pDb)
{
    int     retval;
    MDB_val key, data;

    ln_lmdb_db_t *p_bak_db_param = pDb;
    ln_lmdb_db_t db;
    db.p_txn = NULL;

    if (p_bak_db_param == NULL) {
        char    db_name[M_SZ_CHANNEL_DB_NAME_STR + 1];
        memcpy(db_name, M_PREF_CHANNEL, M_SZ_PREF_STR);
        utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
        retval = channel_db_open(&db, db_name, 0, 0);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            goto LABEL_EXIT;
        }
        pDb = &db;
    }

    key.mv_size = strlen(pItems->p_name);
    key.mv_data = (CONST_CAST char*)pItems->p_name;
    data.mv_size = pItems->data_len;
    data.mv_data = (uint8_t *)pChannel + pItems->offset;
    retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
    if (retval) {
        LOGE("fail: %s(%s)\n", mdb_strerror(retval), pItems->p_name);
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    if (p_bak_db_param == NULL) {
        if (retval == 0) {
            MDB_TXN_COMMIT(db.p_txn);
        } else {
            MDB_TXN_ABORT(db.p_txn);
        }
    }
    return retval;
}


static int channel_secret_load(ln_channel_t *pChannel, ln_lmdb_db_t *pDb)
{
    int     retval;
    char    db_name[M_SZ_CHANNEL_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];

    memcpy(db_name, M_PREF_SECRET, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
    retval = MDB_DBI_OPEN(pDb->p_txn, db_name, 0, &pDb->dbi);
    if (retval) {
        LOGE("ERR: %s(secret db open)\n", mdb_strerror(retval));
        return retval;
    }
    retval = fixed_items_load(pChannel, pDb, DBCHANNEL_SECRET, ARRAY_SIZE(DBCHANNEL_SECRET));
    if (retval) {
        LOGE("ERR: %s(fixed_items_load)\n", mdb_strerror(retval));
        return retval;
    }
    // LOGD("[priv]storage_index: %016" PRIx64 "\n", ln_derkey_local_privkeys_get_current_storage_index(&pChannel->privkeys);
    // LOGD("[priv]storage_seed: ");
    // DUMPD(pChannel->privkeys.storage_seed, BTC_SZ_PRIVKEY);
    // size_t lp;
    // for (lp = 0; lp < LN_BASEPOINT_IDX_NUM; lp++) {
    //     LOGD("[priv][%lu] ", lp);
    //     DUMPD(pChannel->privkeys.key[lp], BTC_SZ_PRIVKEY);
    // }
    // LOGD("[priv][%lu] ", lp);
    // DUMPD(pChannel->privkeys.per_commitment_secret, BTC_SZ_PRIVKEY);

    return 0;
}


static int channel_secret_restore(ln_channel_t *pChannel)
{
    if (!ln_derkey_restore(&pChannel->keys_local, &pChannel->keys_remote)) {
        LOGE("ERR\n");
        return -1;
    }
    if (!btc_script_2of2_create_redeem_sorted(
        &pChannel->funding_info.wit_script,
        &pChannel->funding_info.key_order,
        pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING],
        pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING])) {
        LOGE("ERR\n");
        return -1;
    }
    LOGD("key restored.\n");
    return 0;
}


/**
 *
 * @param[out]      pCur
 * @retval      0   成功
 */
static int channel_cursor_open(lmdb_cursor_t *pCur, bool bWritable)
{
    int retval;
    int opt;

    opt = (bWritable) ? 0 : MDB_RDONLY;
    retval = channel_db_open((ln_lmdb_db_t *)pCur, NULL, opt, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }
    retval = mdb_cursor_open(pCur->p_txn, pCur->dbi, &pCur->p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(pCur->p_txn);
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    return retval;
}


/**
 *
 * @param[out]      pCur
 */
static void channel_cursor_close(lmdb_cursor_t *pCur, bool bWritable)
{
    //XXX: check return value
    MDB_CURSOR_CLOSE(pCur->p_cursor);
    if (bWritable) {
        MDB_TXN_COMMIT(pCur->p_txn);
    } else {
        MDB_TXN_ABORT(pCur->p_txn);
    }
}


/** htlc用db名の作成
 *
 * @note
 *      - "HT" + xxxxxxxx...xx[32*2] + "ddd"
 *        |<-- M_SZ_CHANNEL_DB_NAME_STR  -->|
 *
 * @attention
 *      - 予め pDbName に M_PREF_HTLC と channel_idはコピーしておくこと
 */
static void channel_htlc_db_name(char *pDbName, int num)
{
    assert(num <= 999);
    snprintf(pDbName + M_SZ_CHANNEL_DB_NAME_STR, M_SZ_HTLC_IDX_STR + 1, "%03d", num);
}


/** #ln_node_search_channel()処理関数
 *
 * @param[in,out]   pChannel        channel from DB
 * @param[in,out]   pDbParam        DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         cmp_param_channel_t構造体
 */
static bool channel_cmp_func_channel_del(ln_channel_t *pChannel, void *pDbParam, void *pParam)
{
    (void)pDbParam;
    const uint8_t *p_channel_id = (const uint8_t *)pParam;
    if (memcmp(pChannel->channel_id, p_channel_id, LN_SZ_CHANNEL_ID)) return false;
    ln_db_channel_del_param(pChannel, pDbParam);
    //true時は呼び元では解放しないので、ここで解放する //XXX: ???
    ln_term(pChannel);
    return true;
}


/** #ln_node_search_channel()処理関数
 *
 * @param[in]   pFunc           search function
 * @param[in]   pFuncParam      pFunc parameter
 * @param[in]   bWritable       true: write and txn_commit, false: readonly and txn_abort
 * @param[in]   bRestore        true: restore secrets
 * @param[in]   bCont           true: continue if (*pFunc)() return true, false: stop if (*pFunc)() return true
 * @retval  true    (*pFunc)() return true at least once
 */
static bool channel_search(ln_db_func_cmp_t pFunc, void *pFuncParam, bool bWritable, bool bRestore, bool bCont)
{
    bool            found = false;
    int             retval;
    lmdb_cursor_t   cur;

    LOGD("channl cursor open(writable=%d)\n", bWritable);
    retval = channel_cursor_open(&cur, bWritable);
    if (retval) {
        LOGE("fail: open\n");
        goto LABEL_EXIT;
    }

    ln_channel_t *p_channel = (ln_channel_t *)UTL_DBG_MALLOC(sizeof(ln_channel_t));
    if (!p_channel) {
        channel_cursor_close(&cur, bWritable);
        LOGE("fail: ???\n");
        goto LABEL_EXIT;
    }

    MDB_val key;
    char    name[M_SZ_CHANNEL_DB_NAME_STR + 1];
    name[sizeof(name) - 1] = '\0';
    while ((retval = mdb_cursor_get(cur.p_cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size != M_SZ_CHANNEL_DB_NAME_STR) continue;
        if (memcmp(key.mv_data, M_PREF_CHANNEL, M_SZ_PREF_STR)) continue;

        memcpy(name, key.mv_data, M_SZ_CHANNEL_DB_NAME_STR);
        retval = MDB_DBI_OPEN(cur.p_txn, name, 0, &cur.dbi);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            continue;
        }

        ln_init(p_channel, NULL, NULL, NULL, NULL);
        retval = ln_lmdb_channel_load(p_channel, cur.p_txn, cur.dbi, bRestore);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            MDB_DBI_CLOSE(mpEnvChannel, cur.dbi);
            continue;
        }

        if (!(*pFunc)(p_channel, (void *)&cur, pFuncParam)) {
            ln_term(p_channel);     //falseのみ解放
            continue;
        }

        found = true;
        LOGD("match !\n");
        if (!bCont) {
            break;
        }
    }
    channel_cursor_close(&cur, bWritable);
    UTL_DBG_FREE(p_channel);

LABEL_EXIT:
    LOGD("found=%d(writable=%d)\n", found, bWritable);
    return found;
}


//copy channel DBs to closed env
static void channel_copy_closed(MDB_txn *pTxn, const char *pChannelStr)
{
    int             retval;
    MDB_dbi         dbi;
    MDB_txn         *txn_closed = NULL;
    MDB_cursor      *p_cursor = NULL;
    MDB_dbi         dbi_closed;
    MDB_val         key, data;
    MDB_env         *p_env_closed = NULL;
    ln_lmdb_db_t    db_ver;
    char            path_env[M_DB_PATH_STR_MAX + 1];

    snprintf(path_env, sizeof(path_env), "%.500s/" M_CLOSED_ENV_DIR, mPath);
    mkdir(path_env, 0755);
    snprintf(path_env, sizeof(path_env), "%.500s/" M_CLOSED_ENV_DIR "/%.500s", mPath, pChannelStr);

    init_param_t init_param;
    init_param.pp_env = &p_env_closed;
    init_param.p_path = path_env;
    init_param.maxdbs = M_CLOSED_MAXDBS;
    init_param.mapsize = M_CLOSED_MAPSIZE;
    init_param.open_flag = 0;
    retval = init_db_env(&init_param);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    retval = MDB_DBI_OPEN(pTxn, NULL, 0, &dbi);
    if (retval == 0) {
        retval = mdb_cursor_open(pTxn, dbi, &p_cursor);
    }
    if (retval == 0) {
        while (mdb_cursor_get(p_cursor, &key, NULL, MDB_NEXT_NODUP) == 0) {
            MDB_dbi dbi2;
            MDB_cursor *p_cursor2 = NULL;
            if (memchr(key.mv_data, '\0', key.mv_size)) {
                continue;
            }
            if ( (key.mv_size >= M_SZ_CHANNEL_DB_NAME_STR) &&
                 (memcmp(key.mv_data + M_SZ_PREF_STR, pChannelStr, LN_SZ_CHANNEL_ID * 2) == 0) ) {

                //closed env
                txn_closed = NULL;
                char *name = (char *)UTL_DBG_MALLOC(key.mv_size + 1);
                memcpy(name, key.mv_data, key.mv_size);
                name[key.mv_size] = '\0';
                LOGD("copy[%s]\n", name);
                retval = MDB_TXN_BEGIN(p_env_closed, NULL, 0, &txn_closed);
                if (retval == 0) {
                    retval = MDB_DBI_OPEN(txn_closed, name, MDB_CREATE, &dbi_closed);
                }
                if (retval == 0) {
                    retval = MDB_DBI_OPEN(pTxn, name, 0, &dbi2);
                }
                UTL_DBG_FREE(name);
                if (retval == 0) {
                    retval = mdb_cursor_open(pTxn, dbi2, &p_cursor2);
                }
                if (retval == 0) {
                    while (mdb_cursor_get(p_cursor2, &key, &data, MDB_NEXT_NODUP) == 0) {
                        int retval2 = mdb_put(txn_closed, dbi_closed, &key, &data, 0);
                        if (retval2 != 0) {
                            LOGE("ERR: %s\n", mdb_strerror(retval2));
                        }
                    }
                }
                if (p_cursor2 != NULL) {
                    MDB_CURSOR_CLOSE(p_cursor2);
                }
                {
                    //save DB version()
                    db_ver.p_txn = txn_closed;
                    retval = MDB_DBI_OPEN(db_ver.p_txn, M_DBI_VERSION, 0, &db_ver.dbi);
                    if (retval) {
                        //dummy
                        retval = version_write(&db_ver, "", "", 0);
                        if (retval) {
                            LOGE("create version db\n");
                        }
                    }
                }
                if (retval == 0) {
                    MDB_TXN_COMMIT(txn_closed);
                    MDB_DBI_CLOSE(p_env_closed, dbi_closed);
                    MDB_DBI_CLOSE(p_env_closed, db_ver.dbi);
                } else {
                    MDB_TXN_ABORT(txn_closed);
                }
                if (retval != 0) {
                    LOGE("ERR: %s\n", mdb_strerror(retval));
                }
            }
        }
    }
    if (p_cursor != NULL) {
        MDB_CURSOR_CLOSE(p_cursor);
    }
    if (retval == 0) {
        LOGD("copy OK\n");
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        if (txn_closed != NULL) {
            MDB_TXN_ABORT(txn_closed);
        }
    }
    mdb_env_close(p_env_closed);

LABEL_EXIT:
    ;
}



/********************************************************************
 * private functions: node
 ********************************************************************/

static int node_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb)
{
    return db_open(pDb, mpEnvNode, pDbName, OptTxn, OptDb);
}


/********************************************************************
 * private functions: announce
 ********************************************************************/

/** channel_announcement読込み
 *
 * @param[in]       pDb
 * @param[out]      pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
static int cnlanno_load(ln_lmdb_db_t *pDb, utl_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    LOGV("short_channel_id=%016" PRIx64 "\n", ShortChannelId);

    MDB_val key, data;
    uint8_t key_data[M_SZ_CNLANNO_INFO_KEY];

    cnlanno_info_set_key(key_data, &key, ShortChannelId, LN_DB_CNLANNO_ANNO);
    int retval = mdb_get(mpTxnAnno, pDb->dbi, &key, &data);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        return retval;
    }

    if (!utl_buf_alloccopy(pCnlAnno, data.mv_data, data.mv_size)) {
        return -1;
    }
    return 0;
}


/** channel_announcement書込み
 *
 * @param[in,out]   pDb
 * @param[in]       pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
static int cnlanno_save(ln_lmdb_db_t *pDb, const utl_buf_t *pCnlAnno, uint64_t ShortChannelId)
{
    //LOGV("short_channel_id=%016" PRIx64 "\n", ShortChannelId);

    MDB_val key, data;
    uint8_t key_data[M_SZ_CNLANNO_INFO_KEY];

    cnlanno_info_set_key(key_data, &key, ShortChannelId, LN_DB_CNLANNO_ANNO);
    data.mv_size = pCnlAnno->len;
    data.mv_data = pCnlAnno->buf;
    int retval = mdb_put(mpTxnAnno, pDb->dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    return 0;
}


/** channel_update読込み
 *
 * @param[in]       pDb
 * @param[out]      pCnlAnno
 * @param[out]      pTimeStamp          (非NULL)保存しているchannel_updateのTimeStamp
 * @param[in]       ShortChannelId
 * @param[in]       Dir                 0:node_1, 1:node_2
 * @retval      true    成功
 */
static int cnlupd_load(ln_lmdb_db_t *pDb, utl_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir)
{
    LOGV("short_channel_id=%016" PRIx64 ", dir=%d\n", ShortChannelId, Dir);

    MDB_val key, data;
    uint8_t key_data[M_SZ_CNLANNO_INFO_KEY];

    cnlanno_info_set_key(
        key_data, &key, ShortChannelId,
        Dir ?  LN_DB_CNLANNO_UPD1 : LN_DB_CNLANNO_UPD0);
    int retval = mdb_get(mpTxnAnno, pDb->dbi, &key, &data);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        return retval;
    }

    if (pTimeStamp) {
        memcpy(pTimeStamp, data.mv_data, sizeof(uint32_t));
    }
    if (!utl_buf_alloccopy(pCnlUpd, (uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t))) {
        return -1;
    }
    return 0;
}


/** channel_update書込み
 *
 * @param[in,out]   pDb
 * @param[in]       pCnlAnno
 * @param[in]       pUpd
 * @retval      true    成功
 */
static int cnlupd_save(ln_lmdb_db_t *pDb, const utl_buf_t *pCnlUpd, const ln_msg_channel_update_t *pUpd)
{
    LOGV("short_channel_id=%016" PRIx64 ", dir=%d\n", pUpd->short_channel_id, ln_cnlupd_direction(pUpd));

    MDB_val key, data;
    uint8_t key_data[M_SZ_CNLANNO_INFO_KEY];

    cnlanno_info_set_key(
        key_data, &key, pUpd->short_channel_id,
        ln_cnlupd_direction(pUpd) ?  LN_DB_CNLANNO_UPD1 : LN_DB_CNLANNO_UPD0);
    utl_buf_t buf = UTL_BUF_INIT;
    if (!utl_buf_alloc(&buf, sizeof(uint32_t) + pCnlUpd->len)) {
        LOGE("fail: ???\n");
        return -1;
    }

    //timestamp + channel_update
    memcpy(buf.buf, &pUpd->timestamp, sizeof(uint32_t));
    memcpy(buf.buf + sizeof(uint32_t), pCnlUpd->buf, pCnlUpd->len);
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    int retval = mdb_put(mpTxnAnno, pDb->dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        utl_buf_free(&buf);
        return retval;
    }

    utl_buf_free(&buf);
    return 0;
}


/* [channel_announcement / channel_update]
 *
 *  dbi: "channel_anno"
 */
static int cnlanno_cur_load(MDB_cursor *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf, MDB_cursor_op Op)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(pCur, &key, &data, Op);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: mdb_cursor_get(): %s\n", mdb_strerror(retval));
        }
        return retval;
    }

    char type;
    if (!cnlanno_info_parse_key(&key, pShortChannelId, &type)) {
        LOGE("fail: invalid key length: %d\n", (int)key.mv_size);
        DUMPD(key.mv_data, key.mv_size);
        return -1;
    }

    if (pType) {
        *pType = type;
    }

    //data
    uint8_t *p_data = (uint8_t *)data.mv_data;
    if ((type == LN_DB_CNLANNO_UPD0) || (type == LN_DB_CNLANNO_UPD1)) {
        if (pTimeStamp) {
            memcpy(pTimeStamp, p_data, sizeof(uint32_t));
        }
        p_data += sizeof(uint32_t);
        data.mv_size -= sizeof(uint32_t);
    } else {
        //channel_announcementにtimestampは無い
        if (pTimeStamp) {
            *pTimeStamp = 0;
        }
    }

    if (pBuf) {
        if (!utl_buf_alloccopy(pBuf, p_data, data.mv_size)) {
            LOGE("fail: ???\n");
            return -1;
        }
    }
    return 0;
}


/* node_announcement取得
 *
 * @param[in,out]   pDb
 * @param[out]      pNodeAnno       (非NULL時)取得したnode_announcement
 * @param[out]      pTimeStamp      (非NULL時)タイムスタンプ
 * @paramin]        pNodeId         検索するnode_id
 * @retval      true
 */
static int nodeanno_load(ln_lmdb_db_t *pDb, utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId)
{
    MDB_val key, data;
    uint8_t key_data[M_SZ_NODEANNO_INFO_KEY];

    nodeanno_info_set_key(key_data, &key, pNodeId);
    int retval = mdb_get(mpTxnAnno, pDb->dbi, &key, &data);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        return retval;
    }

    if (pTimeStamp) {
        memcpy(pTimeStamp, data.mv_data, sizeof(uint32_t));
    }
    if (pNodeAnno) {
        if (!utl_buf_alloccopy(
            pNodeAnno, (uint8_t *)data.mv_data + sizeof(uint32_t), data.mv_size - sizeof(uint32_t))) {
            LOGE("fail: ???\n");
            return -1;
        }
    }
    return 0;
}


/* node_announcement書込み
 *
 * @param[in,out]   pDb
 * @param[in]       pNodeAnno       node_announcementパケット
 * @param[in]       pNodeId         node_announcementのnode_id
 * @param[in]       Timestamp       保存時間
 * @retval      true
 */
static int nodeanno_save(ln_lmdb_db_t *pDb, const utl_buf_t *pNodeAnno, const uint8_t *pNodeId, uint32_t Timestamp)
{
    LOGV("node_id=");
    DUMPV(pNodeId, BTC_SZ_PUBKEY);

    MDB_val key, data;
    uint8_t key_data[M_SZ_NODEANNO_INFO_KEY];

    nodeanno_info_set_key(key_data, &key, pNodeId);
    utl_buf_t buf = UTL_BUF_INIT;
    if (!utl_buf_alloc(&buf, sizeof(uint32_t) + pNodeAnno->len)) {
        LOGE("fail: ???\n");
        return -1;
    }
    //timestamp + node_announcement
    memcpy(buf.buf, &Timestamp, sizeof(uint32_t));
    memcpy(buf.buf + sizeof(uint32_t), pNodeAnno->buf, pNodeAnno->len);
    data.mv_size = buf.len;
    data.mv_data = buf.buf;
    int retval = mdb_put(mpTxnAnno, pDb->dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
    }
    utl_buf_free(&buf);
    return retval;
}


static bool annoinfos_trim_node_id(const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo)
{
    LOGD("del annoinfo: ");
    DUMPD(pNodeId, BTC_SZ_PUBKEY);
    MDB_cursor  *p_cursor;

    //cnlanno_info
    int retval1 = mdb_cursor_open(mpTxnAnno, DbiCnlannoInfo, &p_cursor);
    if (retval1 == 0) {
        if (!annoinfo_cur_trim_node_id(p_cursor, pNodeId)) {
            retval1 = -1;
        }
        MDB_CURSOR_CLOSE(p_cursor);
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval1));
    }

    //nodeanno_info
    int retval2 = mdb_cursor_open(mpTxnAnno, DbiNodeannoInfo, &p_cursor);
    if (retval2 == 0) {
        if (!annoinfo_cur_trim_node_id(p_cursor, pNodeId)) {
            retval2 = -1;
        }
        MDB_CURSOR_CLOSE(p_cursor);
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval2));
    }

    return (retval1 == 0) && (retval2 == 0);
}


/** annoinfo(送信済み情報)のchannelとnodeから、指定されたshort_channel_id[]についてだけ未送信状態にする。
 *  (未送信状態＝node_idを mv_dataから削除する)
 *
 * 未送信のannouncementは、自動的に送信が行われる。
 * channel_announcementから両端のnode_idもわかるため、それを未送信にする。
 */
static bool annoinfos_trim_node_id_selected(
    const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo,
    const uint64_t *pShortChannelIds, size_t Num)
{
    int retval;
    LOGD("del selected annoinfo: ");
    DUMPD(pNodeId, BTC_SZ_PUBKEY);

    //channel_announcement取得用
    ln_lmdb_db_t db;
    retval = MDB_DBI_OPEN(mpTxnAnno, M_DBI_CNLANNO, 0, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    db.p_txn = mpTxnAnno;

    for(size_t lp = 0; lp < Num; lp++) {
        LOGD(" %d: %016" PRIx64 "\n", lp, pShortChannelIds[lp]);

        MDB_val key, data;
        uint8_t key_data[M_SZ_CNLANNO_INFO_KEY];

        const char TYPES[] = { LN_DB_CNLANNO_ANNO, LN_DB_CNLANNO_UPD0, LN_DB_CNLANNO_UPD1 };
        for (size_t type = 0; type < ARRAY_SIZE(TYPES); type++) {
            cnlanno_info_set_key(key_data, &key, pShortChannelIds[lp], TYPES[type]);
            int retval = mdb_get(mpTxnAnno, DbiCnlannoInfo, &key, &data);
            if (retval) {
                LOGD("nof found: %016" PRIx64 " %c\n", pShortChannelIds[lp], TYPES[type]);
                continue;
            }

            LOGD("found: %016" PRIx64 " %c\n", pShortChannelIds[lp], TYPES[type]);

            if (TYPES[type] == LN_DB_CNLANNO_ANNO) {
                //trim node_id in  node_announcement
                annoinfos_trim_node_id_nodeanno(pNodeId, pShortChannelIds[lp], DbiNodeannoInfo, &db);
            }

            if (!annoinfo_trim_node_id(&data, pNodeId)) {
                continue;
            }
            if (!my_mdb_val_alloccopy(&key, &key)) {
                LOGE("fail: ???\n");
                UTL_DBG_FREE(data.mv_data);
                return false;
            }
            retval = mdb_put(mpTxnAnno, DbiCnlannoInfo, &key, &data, 0);
            if (retval) {
                LOGE("ERR: %s\n", mdb_strerror(retval));
                //XXX: ???
            }
            UTL_DBG_FREE(data.mv_data);
            UTL_DBG_FREE(key.mv_data);
        }
    }
    //XXX: return true;
    //  not tested, always return false
    return false;
}


/** annoinfo(送信済み情報)のchannelとnodeから、指定されたshort_channel_id[]についてだけ未送信状態にする。
 *  (未送信状態＝node_idを mv_dataから削除する)
 *
 * 未送信のannouncementは、自動的に送信が行われる。
 * channel_announcementから両端のnode_idもわかるため、それを未送信にする。
 */
static bool annoinfos_trim_node_id_timestamp(
    const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo,
    uint32_t TimeFirst, uint32_t TimeRange)
{
    int retval;
    void *p_cur;
    LOGD("del selected annoinfo: ");
    DUMPD(pNodeId, BTC_SZ_PUBKEY);

    //channel_announcement, channel_update
    if (!ln_db_anno_cur_open(&p_cur, LN_DB_CUR_CNLANNO)) {
        LOGE("fail: cursor open\n");
        ln_db_anno_commit(false);
        return false;
    }

    uint64_t    short_channel_id;
    char        type;
    utl_buf_t   buf_cnlanno = UTL_BUF_INIT;
    uint32_t    timestamp;
    while (ln_db_cnlanno_cur_get(p_cur, &short_channel_id, &type, &timestamp, &buf_cnlanno)) {
        utl_buf_free(&buf_cnlanno);
        if ((type != LN_DB_CNLANNO_UPD0) && (type != LN_DB_CNLANNO_UPD1)) continue;
        //LOGD("  short_channel_id=%016" PRIx64 ",  timestamp=%" PRIu32 "\n", short_channel_id, timestamp);
        bool resend;
        if ((timestamp < TimeFirst) || (TimeFirst + TimeRange < timestamp)) {
            resend = false;
        } else {
            resend = true;
        }

        //remove node_id from sent list
        char SUFFIX[2] = { LN_DB_CNLANNO_ANNO, 0 };
        SUFFIX[1] = type;
        for (size_t lp = 0; lp < ARRAY_SIZE(SUFFIX); lp++) {
            MDB_val     key;
            MDB_val     data;
            uint8_t     key_data[M_SZ_CNLANNO_INFO_KEY];

            cnlanno_info_set_key(key_data, &key, short_channel_id, SUFFIX[lp]);
            retval = mdb_get(mpTxnAnno, DbiCnlannoInfo, &key, &data);
            if (retval == 0) {
                // LOGD("  before=");
                // DUMPD(data.mv_data, data.mv_size);
                if (resend) {
                    if (!annoinfo_trim_node_id(&data, pNodeId)) {
                        continue;
                    }
                } else {
                    if (!annoinfo_add_node_id(&data, pNodeId)) {
                        continue;
                    }
                }
                if (!my_mdb_val_alloccopy(&key, &key)) {
                    LOGE("fail: ???\n");
                    UTL_DBG_FREE(data.mv_data);
                    return false;
                }
                // LOGD("  after=");
                // DUMPD(data.mv_data, data.mv_size);

                retval = mdb_put(mpTxnAnno, DbiCnlannoInfo, &key, &data, 0);
                if (retval) {
                    LOGE("ERR: %s\n", mdb_strerror(retval));
                    //XXX: ???
                }
                UTL_DBG_FREE(data.mv_data);
                UTL_DBG_FREE(key.mv_data);
            } else {
                if (retval && (retval != MDB_NOTFOUND)) {
                    LOGE("ERR[%c]: %s\n", SUFFIX[lp], mdb_strerror(retval));
                }
            }
        }
    }
    utl_buf_free(&buf_cnlanno);
    ln_db_anno_cur_close(p_cur);


    //node_announcement
    if (!ln_db_anno_cur_open(&p_cur, LN_DB_CUR_NODEANNO)) {
        LOGE("fail: cursor open\n");
        ln_db_anno_commit(false);
        return false;
    }

    utl_buf_t   buf_nodeanno = UTL_BUF_INIT;
    uint8_t     node_id[BTC_SZ_PUBKEY];
    while (ln_db_nodeanno_cur_get(p_cur, &buf_nodeanno, &timestamp, node_id)) {
        utl_buf_free(&buf_nodeanno);
        // LOGD("  node_id=");
        // DUMPD(node_id, BTC_SZ_PUBKEY);
        bool resend;
        if ((timestamp < TimeFirst) || (TimeFirst + TimeRange < timestamp)) {
            resend = false;
        } else {
            resend = true;
        }

        //remove node_id from sent list
        MDB_val     key;
        MDB_val     data;
        uint8_t     key_data[M_SZ_NODEANNO_INFO_KEY];

        nodeanno_info_set_key(key_data, &key, node_id);
        retval = mdb_get(mpTxnAnno, DbiNodeannoInfo, &key, &data);
        if (retval == 0) {
            // LOGD("  before=");
            // DUMPD(data.mv_data, data.mv_size);
            if (resend) {
                if (!annoinfo_trim_node_id(&data, pNodeId)) {
                    continue;
                }
            } else {
                if (!annoinfo_add_node_id(&data, pNodeId)) {
                    continue;
                }
            }
            if (!my_mdb_val_alloccopy(&key, &key)) {
                LOGE("fail: ???\n");
                UTL_DBG_FREE(data.mv_data);
                return false;
            }
            // LOGD("  after=");
            // DUMPD(data.mv_data, data.mv_size);

            retval = mdb_put(mpTxnAnno, DbiNodeannoInfo, &key, &data, 0);
            if (retval) {
                LOGE("ERR: %s\n", mdb_strerror(retval));
                //XXX: ???
            }
            UTL_DBG_FREE(data.mv_data);
            UTL_DBG_FREE(key.mv_data);
        } else {
            if (retval && (retval != MDB_NOTFOUND)) {
                LOGE("ERR: %s\n", mdb_strerror(retval));
            }
        }
    }
    utl_buf_free(&buf_nodeanno);
    ln_db_anno_cur_close(p_cur);


    ln_db_anno_commit(true);

    //XXX: return true;
    //  not tested, always return false
    return false;
}


static bool annoinfos_trim_node_id_nodeanno(
    const uint8_t *pNodeId, uint64_t ShortChannelId, MDB_dbi DbiNodeannoInfo,
    ln_lmdb_db_t *pDb)
{
    ln_msg_channel_announcement_t msg;
    utl_buf_t buf_cnlanno = UTL_BUF_INIT;
    int retval = cnlanno_load(pDb, &buf_cnlanno, ShortChannelId);
    if (retval) {
        //XXX: ???
        return true;
    }
    if (!ln_msg_channel_announcement_read(&msg, buf_cnlanno.buf, buf_cnlanno.len)) {
        //XXX: ???
        utl_buf_free(&buf_cnlanno);
        return true;
    }
    MDB_val key, data;
    uint8_t key_data[M_SZ_NODEANNO_INFO_KEY];

    const uint8_t *p_node_id[2];
    p_node_id[0] = msg.p_node_id_1;
    p_node_id[1] = msg.p_node_id_2;
    for (int lp = 0; lp < 2; lp++) {
        nodeanno_info_set_key(key_data, &key, p_node_id[lp]);
        int retval = mdb_get(mpTxnAnno, DbiNodeannoInfo, &key, &data);
        if (retval) {
            //XXX: ???
            continue;
        }
        LOGD("found: ");
        DUMPD(p_node_id[lp], BTC_SZ_PUBKEY);

        if (!annoinfo_trim_node_id(&data, pNodeId)) {
            //XXX: ???
            continue;
        }
        if (!my_mdb_val_alloccopy(&key, &key)) {
            //XXX: ???
            UTL_DBG_FREE(data.mv_data);
            continue;
        }
        retval = mdb_put(mpTxnAnno, DbiNodeannoInfo, &key, &data, 0);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        UTL_DBG_FREE(data.mv_data);
        UTL_DBG_FREE(key.mv_data);
    }
    utl_buf_free(&buf_cnlanno);
    return true;
}


static bool annoinfos_del_all(MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo)
{
    LOGD("del annoinfo: ALL\n");
    //cnlanno_info
    int retval1 = mdb_drop(mpTxnAnno, DbiCnlannoInfo, 1);
    if (retval1) {
        LOGE("ERR: %s\n", mdb_strerror(retval1));
        //エラーでも継続
    }

    //nodeanno_info
    int retval2 = mdb_drop(mpTxnAnno, DbiNodeannoInfo, 1);
    if (retval2) {
        LOGE("ERR: %s\n", mdb_strerror(retval2));
        //エラーでも継続
    }

    return (retval1 == 0) && (retval2 == 0);
}


static void cnlanno_info_set_key(uint8_t *pKeyData, MDB_val *pKey, uint64_t ShortChannelId, char Type)
{
    pKey->mv_size = M_SZ_CNLANNO_INFO_KEY;
    pKey->mv_data = pKeyData;
    utl_int_unpack_u64be(pKeyData, ShortChannelId);
    pKeyData[LN_SZ_SHORT_CHANNEL_ID] = Type;
}


static bool cnlanno_info_parse_key(MDB_val *pKey, uint64_t *pShortChannelId, char *pType)
{
    if (pKey->mv_size != M_SZ_CNLANNO_INFO_KEY) {
        return false;
    }
    *pShortChannelId = utl_int_pack_u64be(pKey->mv_data);
    *pType = *(char *)((uint8_t *)pKey->mv_data + LN_SZ_SHORT_CHANNEL_ID);
    return true;
}


static void nodeanno_info_set_key(uint8_t *pKeyData, MDB_val *pKey, const uint8_t *pNodeId)
{
    pKey->mv_size = M_SZ_NODEANNO_INFO_KEY;
    pKey->mv_data = pKeyData;
    memcpy(pKeyData, pNodeId, BTC_SZ_PUBKEY);
}


//ToDo: 最終的にいらないなら削除
// static bool nodeanno_info_parse_key(MDB_val *pKey, uint8_t *pNodeId)
// {
//     if (pKey->mv_size != M_SZ_NODEANNO_INFO_KEY) {
//         return false;
//     }
//     memcpy(pNodeId, pKey->mv_data, BTC_SZ_PUBKEY);
//     return true;
// }


//need free() pData->mv_data
static bool annoinfo_add_node_id(MDB_val *pData, const uint8_t *pNodeId)
{
    bool detect = annoinfo_search_node_id(pData, pNodeId);
    int nums = pData->mv_size / BTC_SZ_PUBKEY;
    if (!detect) {
        nums++;
    }
    uint8_t *p_ids = (uint8_t *)UTL_DBG_MALLOC(nums * BTC_SZ_PUBKEY);
    if (!p_ids) {
        LOGE("fail: ???");
        return false;
    }
    //append
    memcpy(p_ids, pData->mv_data, pData->mv_size);
    //search & hit
    if (!detect) {
        memcpy(p_ids + pData->mv_size, pNodeId, BTC_SZ_PUBKEY);
        pData->mv_size += BTC_SZ_PUBKEY;
    }
    pData->mv_data = p_ids;

    return true;
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
    if (pNodeId) {
        if (!annoinfo_add_node_id(pMdbData, pNodeId)) {
            return false;
        }
    } else {
        pMdbData->mv_size = 0;
        pMdbData->mv_data = NULL;
    }

    int retval = mdb_put(mpTxnAnno, pDb->dbi, pMdbKey, pMdbData, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
    }
    UTL_DBG_FREE(pMdbData->mv_data);
    return retval == 0;
}


/** annoinfoからnode_idの有無を検索(channel, node共通)
 *
 * @param[in]   pMdbData
 * @param[in]   pNodeId
 * @retval  true    検出
 */
static bool annoinfo_search_node_id(MDB_val *pMdbData, const uint8_t *pNodeId)
{
    int nums = pMdbData->mv_size / BTC_SZ_PUBKEY;
    //LOGD("nums=%d\n", nums);
    //LOGD("search id: ");
    //DUMPD(pNodeId, BTC_SZ_PUBKEY);
    for (int lp = 0; lp < nums; lp++) {
        //LOGD("  node_id[%d]= ", lp);
        //DUMPD(pMdbData->mv_data + BTC_SZ_PUBKEY * lp, BTC_SZ_PUBKEY);
        if (memcmp((uint8_t *)pMdbData->mv_data + BTC_SZ_PUBKEY * lp, pNodeId, BTC_SZ_PUBKEY)) continue;
        return true;
    }
    return false;
}


/** annoinfoからnode_idを削除(channel, node共通)
 *
 * @param[in]   pCursor
 * @param[in]   pNodeId
 */
static bool annoinfo_cur_trim_node_id(MDB_cursor *pCursor, const uint8_t *pNodeId)
{
    //XXX: check error code
    MDB_val key, data;

    while (mdb_cursor_get(pCursor, &key, &data, MDB_NEXT) == 0) {
        if (!annoinfo_trim_node_id(&data, pNodeId)) continue;
        if (!my_mdb_val_alloccopy(&key, &key)) {
            UTL_DBG_FREE(data.mv_data);
            LOGE("fail: ???\n");
            return false;
        }
        int retval = mdb_cursor_put(pCursor, &key, &data, MDB_CURRENT);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        UTL_DBG_FREE(data.mv_data);
        UTL_DBG_FREE(key.mv_data);
    }
    return true; //XXX: ???
}


//need free() pData->mv_data
static bool annoinfo_trim_node_id(MDB_val *pData, const uint8_t *pNodeId)
{
    int nums = pData->mv_size / BTC_SZ_PUBKEY;

    if (!nums) {
        return false;
    }

    int lp;
    for (lp = 0; lp < nums; lp++) {
        if (memcmp((uint8_t *)pData->mv_data + BTC_SZ_PUBKEY * lp, pNodeId, BTC_SZ_PUBKEY)) continue;
        break;
    }

    if (lp == nums) {
        return false;
    }

    nums--;
    if (nums) {
        uint8_t *p_data = (uint8_t *)UTL_DBG_MALLOC(BTC_SZ_PUBKEY * nums);
        if (!p_data) {
            LOGE("fail: ???\n");
            return false;
        }
        memcpy(p_data, (uint8_t *)pData->mv_data, BTC_SZ_PUBKEY * lp);
        memcpy(p_data + BTC_SZ_PUBKEY * lp,
            (uint8_t *)pData->mv_data + BTC_SZ_PUBKEY * (lp + 1), BTC_SZ_PUBKEY * (nums - lp));

        pData->mv_size = BTC_SZ_PUBKEY * nums;
        pData->mv_data = p_data;
    } else {
        pData->mv_size = 0;
        pData->mv_data = NULL;
    }
    return true;
}


/** annoinfoにnode_idを追加(channel, node共通)
 *
 * @param[in]   pCursor
 * @param[in]   pNodeId
 */
static void annoinfo_cur_add(MDB_cursor *pCursor, const uint8_t *pNodeId)
{
    //XXX: check error code
    MDB_val     key, data;

    while (mdb_cursor_get(pCursor, &key, &data, MDB_NEXT) == 0) {
        int nums = data.mv_size / BTC_SZ_PUBKEY;
        int lp;
        for (lp = 0; lp < nums; lp++) {
            if (memcmp((uint8_t *)data.mv_data + BTC_SZ_PUBKEY * lp, pNodeId, BTC_SZ_PUBKEY)) continue;
            break;
        }
        if (lp < nums) continue;

        if (!my_mdb_val_alloccopy(&key, &key)) {
            LOGE("fail: ???");
            break;
        }
        nums++;
        uint8_t *p_data = (uint8_t *)UTL_DBG_MALLOC(BTC_SZ_PUBKEY * nums);
        if (!p_data) {
            UTL_DBG_FREE(key.mv_data);
            LOGE("fail: ???");
            break;
        }
        memcpy(p_data, data.mv_data, data.mv_size);
        memcpy(p_data + data.mv_size, pNodeId, BTC_SZ_PUBKEY);
        data.mv_size = BTC_SZ_PUBKEY * nums;
        data.mv_data = p_data;
        int retval = mdb_cursor_put(pCursor, &key, &data, MDB_CURRENT);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        UTL_DBG_FREE(data.mv_data);
        UTL_DBG_FREE(key.mv_data);
    }
}


/** channel_updateの枝刈り
 *      - channel_announcementがない(自channel以外)
 *      - 期限切れ
 */
static void anno_del_prune(void)
{
    if (!ln_db_anno_transaction()) {
        LOGE("ERR: anno transaction\n");
        return;
    }

    //時間がかかる場合があるため、状況を出力する
    fprintf(stderr, "DB checking: announcement...");

    uint64_t now = (uint64_t)utl_time_time();

    void *p_cur;
    if (!ln_db_anno_cur_open(&p_cur, LN_DB_CUR_CNLANNO)) {
        ln_db_anno_commit(false);
        return;
    }

    uint64_t    short_channel_id;
    char        type;
    utl_buf_t   buf_cnlanno = UTL_BUF_INIT;
    uint32_t    timestamp;
    while (ln_db_cnlanno_cur_get(p_cur, &short_channel_id, &type, &timestamp, &buf_cnlanno)) {
        fprintf(stderr, ".");
        utl_buf_free(&buf_cnlanno);
        if ((type != LN_DB_CNLANNO_UPD0) && (type != LN_DB_CNLANNO_UPD1)) continue;
        if (!ln_db_cnlupd_need_to_prune(now, timestamp)) continue;

        MDB_cursor *p_cursor = ((lmdb_cursor_t *)p_cur)->p_cursor;
        int retval = mdb_cursor_del(p_cursor, 0);
        if (retval == 0) {
            LOGD("prune channel_update(%c): %016" PRIx64 "\n", type, short_channel_id);
        } else {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
    }

    ln_db_anno_cur_close(p_cur);
    ln_db_anno_commit(true);
    fprintf(stderr, "done!\n");
}


/********************************************************************
 * private functions: preimage
 ********************************************************************/

static bool preimage_open(ln_lmdb_db_t *pDb, MDB_txn *pTxn)
{
    int retval;

    if (pTxn) {
        pDb->p_txn = pTxn;
    } else {
        retval = MDB_TXN_BEGIN(mpEnvNode, NULL, 0, &pDb->p_txn);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return false;
        }
    }
    retval = MDB_DBI_OPEN(pDb->p_txn, M_DBI_PREIMAGE, MDB_CREATE, &pDb->dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        if (!pTxn) {
            MDB_TXN_ABORT(pDb->p_txn);
        }
        return false;
    }
    return true;
}


static void preimage_close(ln_lmdb_db_t *pDb, bool bCommit)
{
    if (bCommit) {
        MDB_TXN_COMMIT(pDb->p_txn);
    } else {
        MDB_TXN_ABORT(pDb->p_txn);
    }
}


/** #ln_db_preimage_del_hash()用処理関数
 *
 * SHA256(preimage)がpayment_hashと一致した場合にDBから削除する。
 */
static bool preimage_cmp_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *pDbParam, void *pParam)
{
    (void)Amount; (void)Expiry;

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pDbParam;
    const uint8_t *hash = (const uint8_t *)pParam;
    uint8_t preimage_hash[BTC_SZ_HASH256];

    //LOGD("compare preimage : ");
    //DUMPD(pPreimage, LN_SZ_PREIMAGE);
    LOGD("compare preimage\n");
    ln_payment_hash_calc(preimage_hash, pPreimage);

    if (memcmp(preimage_hash, hash, BTC_SZ_HASH256)) {
        LOGD("  not found");
        return false;
    }

    int retval = mdb_cursor_del(p_cur->p_cursor, 0);
    LOGD("  remove from DB: %s\n", mdb_strerror(retval));
    return retval == 0;
}


/** ln_db_channel_del_param用処理関数
 *
 * SHA256(preimage)がpayment_hashと一致した場合、DBから削除する。
 */
static bool preimage_cmp_all_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *pDbParam, void *pParam)
{
    (void)Amount; (void)Expiry;

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pDbParam;
    preimage_close_t *param = (preimage_close_t *)pParam;
    uint8_t preimage_hash[BTC_SZ_HASH256];

    //LOGD("compare preimage : ");
    //DUMPD(pPreimage, LN_SZ_PREIMAGE);
    LOGD("compare preimage\n");
    ln_payment_hash_calc(preimage_hash, pPreimage);

    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        if (memcmp(preimage_hash, param->p_htlcs[lp].payment_hash, BTC_SZ_HASH256)) continue;
        //match
        int retval = mdb_cursor_del(p_cur->p_cursor, 0);
        LOGD("  remove from DB: %s\n", mdb_strerror(retval));
    }
    return false; //continue
}


/** preimage検索(自分で作成)
 *  @param[in]bCommit       true    cursor close時にcommitを行う
 */
static bool preimage_search(ln_db_func_preimage_t pFunc, bool bCommit, void *pFuncParam)
{
    bool found = false;
    void *p_cur;
    ln_db_preimage_t preimage;
    bool detect;

    if (!ln_db_preimage_cur_open(&p_cur)) return false;
    while (ln_db_preimage_cur_get(p_cur, &detect, &preimage, NULL)) {
        if (!detect) continue;
        if (!(*pFunc)(preimage.preimage, preimage.amount_msat, preimage.expiry, p_cur, pFuncParam)) continue;
        found = true;
        break;
    }
    ln_db_preimage_cur_close(p_cur, bCommit);
    return found;
}


/********************************************************************
 * private functions: wallet
 ********************************************************************/

static int wallet_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb)
{
    return db_open(pDb, mpEnvWallet, pDbName , OptTxn, OptDb);
}


/********************************************************************
 * private functions: version
 ********************************************************************/

static int version_write(ln_lmdb_db_t *pDb, const char *pWif, const char *pNodeName, uint16_t Port)
{
    int         retval;
    MDB_val     key, data;
    int32_t     version = LN_DB_VERSION;

    retval = MDB_DBI_OPEN(pDb->p_txn, M_DBI_VERSION, MDB_CREATE, &pDb->dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }

    //version
    key.mv_size = LN_DB_KEY_LEN(LN_DB_KEY_VERSION);
    key.mv_data = LN_DB_KEY_VERSION;
    data.mv_size = sizeof(version);
    data.mv_data = &version;
    retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }

    //my node info
    if (pWif) {
        // LOGD("wif=%s\n", pWif);
        // LOGD("name=%s\n", pNodeName);
        // LOGD("port=%" PRIu16 "\n", Port);
        node_info_t node_info;
        memcpy(node_info.genesis, ln_genesishash_get(), BTC_SZ_HASH256);
        if (!utl_str_copy_and_fill_zeros(node_info.wif, pWif, sizeof(node_info.wif))) {
            LOGE("fail\n");
            return -1;
        }
        if (!utl_str_copy_and_fill_zeros(node_info.name, pNodeName, sizeof(node_info.name))) {
            LOGE("fail\n");
            return -1;
        }
        node_info.port = Port;
        memcpy(node_info.create_bhash, ln_creationhash_get(), BTC_SZ_HASH256);

        key.mv_size = LN_DB_KEY_LEN(LN_DB_KEY_NODEID);
        key.mv_data = LN_DB_KEY_NODEID;
        data.mv_size = sizeof(node_info);
        data.mv_data = (void *)&node_info;
        retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return retval;
        }
    }
    return 0;
}


/** DBバージョンチェック
 *
 * @param[in,out]   pDb
 * @param[out]      pVer
 * @param[out]      pWif
 * @param[in,out]   pNodeName       [in]setting name(default:"") [out]set name
 * @param[in,out]   pPort           [in]setting value [out]set value
 * @param[out]      pGenesis
 * @param[in]       bAutoUpdate     true: auto version update(if it can)
 * @retval  0   DBバージョン一致
 */
static int version_check(ln_lmdb_db_t *pDb, int32_t *pVer, char *pWif, char *pNodeName, uint16_t *pPort, uint8_t *pGenesis, bool bAutoUpdate)
{
    int         retval;
    MDB_val key, data;
    node_info_t node_info;

    //version
    key.mv_size = LN_DB_KEY_LEN(LN_DB_KEY_VERSION);
    key.mv_data = LN_DB_KEY_VERSION;
    retval = mdb_get(pDb->p_txn, pDb->dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    memcpy(pVer, data.mv_data, sizeof(int32_t));
    if (*pVer != LN_DB_VERSION) {
        fprintf(stderr, "version mismatch : %d(require %d)\n", *pVer, LN_DB_VERSION);
        bool auto_update = bAutoUpdate;
        if (auto_update) {
            fprintf(stderr, "  auto update...");

            if ((*pVer == -68) && (LN_DB_VERSION <= -69)) {
                auto_update &= auto_update_68_to_69();
                if (auto_update) {
                    *pVer = -69;
                }
            }
            if ((*pVer == -69) && (LN_DB_VERSION <= -70)) {
                auto_update &= auto_update_69_to_70();
                if (auto_update) {
                    *pVer = -70;
                }
            }
        }
        if (!auto_update) {
            fprintf(stderr, "FAIL\n\n");
            if (bAutoUpdate) {
                fprintf(stderr, "==========================================\n");
                fprintf(stderr, "Please use old ptarmd, and close all channels.\n");
                fprintf(stderr, "After all channel closed, update ptarmd\n");
                fprintf(stderr, "  and type below command to remove channel DB.\n");
                fprintf(stderr, "\n\tptarmd --clear_channel_db\n\n");
                fprintf(stderr, "==========================================\n");
            }
            LOGE("fail: version mismatch\n");
            return -1;
        }

        if (my_mdb_val_alloccopy(&data, &data)) {
            memcpy(data.mv_data, pVer, sizeof(int32_t));
            retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
            UTL_DBG_FREE(data.mv_data);
            if (retval) {
                LOGE("ERR: %s\n", mdb_strerror(retval));
                return retval;
            }

            fprintf(stderr, "Success!\n");
            LOGD("auto update: version %d\n", *pVer);
        } else {
            fprintf(stderr, "FAIL\n");
            LOGE("fail: ???\n");
        }
    } else {
        LOGD("OK: version %d\n", *pVer);
    }

    key.mv_size = LN_DB_KEY_LEN(LN_DB_KEY_NODEID);
    key.mv_data = LN_DB_KEY_NODEID;
    retval = mdb_get(pDb->p_txn, pDb->dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    if (data.mv_size != sizeof(node_info_t)) {
        return MDB_BAD_VALSIZE;
    }

    bool update = false;
    memcpy(&node_info, (const node_info_t*)data.mv_data, data.mv_size);
    strcpy(pWif, node_info.wif);
    if ((pNodeName[0] != '\0') && strcmp(node_info.name, pNodeName)) {
        //update
        strncpy(node_info.name, pNodeName, sizeof(node_info.name));
        update = true;
    } else {
        strcpy(pNodeName, node_info.name);
    }
    if ((*pPort != 0) && (node_info.port != *pPort)) {
        //update
        node_info.port = *pPort;
        update = true;
    } else {
        *pPort = node_info.port;
    }
    memcpy(pGenesis, node_info.genesis, BTC_SZ_HASH256); //XXX: compare genesis?
    ln_creationhash_set(node_info.create_bhash);
    // LOGD("wif=%s\n", pWif);
    // LOGD("name=%s\n", pNodeName);
    // LOGD("port=%" PRIu16 "\n", *pPort);
    // LOGD("genesis=");
    // DUMPD(p_node_info->genesis, BTC_SZ_HASH256);

    if (update) {
        data.mv_data = &node_info;
        data.mv_size = sizeof(node_info);
        retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
        if (retval) {
            LOGE("fail: %s\n", mdb_strerror(retval));
            return retval;
        }
    }
    return 0;
}


/********************************************************************
 * private functions: forward
 ********************************************************************/

static bool forward_create(uint64_t NextShortChannelId, const char *pDbNamePrefix)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_FORWARD_DB_NAME_STR + 1];

    db.p_txn = NULL;

    forward_set_db_name(db_name, NextShortChannelId, pDbNamePrefix);
    retval = forward_db_open(&db, db_name, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }
    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


static int forward_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb)
{
    return db_open(pDb, mpEnvForward, pDbName, OptTxn, OptDb);
}


static int forward_db_open_2(ln_lmdb_db_t *pDb, MDB_txn *pTxn, const char *pDbName, int OptDb)
{
    return db_open_2(pDb, pTxn, pDbName, OptDb);
}


static int forward_save(ln_lmdb_db_t *pDb, const ln_db_forward_t *pForward)
{
    MDB_val key, data;
    uint8_t key_data[M_SZ_FORWARD_KEY];

    forward_set_key(key_data, &key, pForward->prev_short_channel_id, pForward->prev_htlc_id);
    data.mv_size = pForward->p_msg->len;
    data.mv_data = pForward->p_msg->buf;
    int retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    return 0;
}


static bool forward_save_2(const ln_db_forward_t* pForward, const char *pDbNamePrefix)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_FORWARD_DB_NAME_STR + 1];

    db.p_txn = NULL;

    forward_set_db_name(db_name, pForward->next_short_channel_id, pDbNamePrefix);
    //forward dbs is created explicitly for each channel and removed when closed.
    //When DB does not exist, writing from other channels must fail. Do not specify MDB_CREATE.
    retval = forward_db_open(&db, db_name, 0, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    retval = forward_save(&db, pForward);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

    MDB_TXN_COMMIT(db.p_txn);
    db.p_txn = NULL;

LABEL_EXIT:
    if (retval) {
        LOGE("fail: save\n");
    }
    if (db.p_txn) {
        MDB_TXN_ABORT(db.p_txn);
    }
    return retval == 0;
}


static bool forward_save_3(const ln_db_forward_t* pForward, const char *pDbNamePrefix, MDB_txn *pTxn)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_FORWARD_DB_NAME_STR + 1];

    db.p_txn = NULL;

    forward_set_db_name(db_name, pForward->next_short_channel_id, pDbNamePrefix);
    //forward dbs is created explicitly for each channel and removed when closed.
    //When DB does not exist, writing from other channels must fail. Do not specify MDB_CREATE.
    retval = forward_db_open_2(&db, pTxn, db_name, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    retval = forward_save(&db, pForward);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    if (retval) {
        LOGE("fail: save\n");
    }
    return retval == 0;
}


static int forward_del(ln_lmdb_db_t *pDb, uint64_t PrevShortChannelId, uint64_t PrevHtlcId)
{
    MDB_val key;
    uint8_t key_data[M_SZ_FORWARD_KEY];

    forward_set_key(key_data, &key, PrevShortChannelId, PrevHtlcId);
    int retval = mdb_del(pDb->p_txn, pDb->dbi, &key, NULL);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    return 0;
}


static bool forward_del_2(uint64_t NextShortChannelId, uint64_t PrevShortChannelId, uint64_t PrevHtlcId, const char *pDbNamePrefix)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_FORWARD_DB_NAME_STR + 1];

    forward_set_db_name(db_name, NextShortChannelId, pDbNamePrefix);
    retval = forward_db_open(&db, db_name, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    retval = forward_del(&db, PrevShortChannelId, PrevHtlcId);
    if (retval && (retval != MDB_NOTFOUND)) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


static bool forward_drop(uint64_t NextShortChannelId, const char *pDbNamePrefix)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_FORWARD_DB_NAME_STR + 1];

    forward_set_db_name(db_name, NextShortChannelId, pDbNamePrefix);
    retval = forward_db_open(&db, db_name, 0, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    retval = mdb_drop(db.p_txn, db.dbi, 1);
    if (retval && (retval != MDB_NOTFOUND)) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


static bool forward_cur_open(void **ppCur, uint64_t NextShortChannelId, const char *pDbNamePrefix)
{
    int             retval;
    lmdb_cursor_t   *p_cur;
    char            db_name[M_SZ_FORWARD_DB_NAME_STR + 1];

    *ppCur = NULL;

    p_cur  = (lmdb_cursor_t *)UTL_DBG_MALLOC(sizeof(lmdb_cursor_t));
    if (!p_cur) {
        LOGE("fail: ???\n");
        return false;
    }

    forward_set_db_name(db_name, NextShortChannelId, pDbNamePrefix);
    retval = forward_db_open((ln_lmdb_db_t *)p_cur, db_name, 0, 0);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        UTL_DBG_FREE(p_cur);
        return false;
    }

    retval = mdb_cursor_open(p_cur->p_txn, p_cur->dbi, &p_cur->p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        UTL_DBG_FREE(p_cur);
        return false;
    }

    *ppCur = p_cur;
    return true;
}


static void forward_cur_close(void *pCur, bool bCommit)
{
    if (!pCur) return;

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    MDB_CURSOR_CLOSE(p_cur->p_cursor);

    if (!p_cur->p_txn) return;
    MDB_TXN_CHECK_FORWARD(p_cur->p_txn);
    if (bCommit) {
        MDB_TXN_COMMIT(p_cur->p_txn);
    } else {
        MDB_TXN_ABORT(p_cur->p_txn);
    }
    UTL_DBG_FREE(pCur);
}


static bool forward_cur_get(void *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval = forward_cur_load(p_cur->p_cursor, pPrevShortChannelId, pPrevHtlcId, pMsg, MDB_NEXT_NODUP);
    if (retval) {
        return false;
    }
    return true;
}


static int forward_cur_load(
    MDB_cursor *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg, MDB_cursor_op Op)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(pCur, &key, &data, Op);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: mdb_cursor_get(): %s\n", mdb_strerror(retval));
        }
        return retval;
    }

    //key
    if (!forward_parse_key(&key, pPrevShortChannelId, pPrevHtlcId)) {
        LOGE("fail: invalid key length: %d\n", (int)key.mv_size);
        DUMPD(key.mv_data, key.mv_size);
        return -1;
    }

    //data
    if (!utl_buf_alloccopy(pMsg, (uint8_t *)data.mv_data, data.mv_size)) {
        LOGE("fail: ???\n");
        return -1;
    }
    return 0;
}


static bool forward_cur_del(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval = mdb_cursor_del(p_cur->p_cursor, 0);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: mdb_cursor_del(): %s\n", mdb_strerror(retval));
        }
        return false;
    }
    return true;
}


static void forward_set_db_name(char *pDbName, uint64_t NextShortChannelId, const char *pDbNamePrefix)
{
    uint8_t next_short_channel_id[LN_SZ_SHORT_CHANNEL_ID];
    memcpy(pDbName, pDbNamePrefix, M_SZ_PREF_STR);
    utl_int_unpack_u64be(next_short_channel_id, NextShortChannelId);
    utl_str_bin2str(pDbName + M_SZ_PREF_STR, next_short_channel_id, LN_SZ_SHORT_CHANNEL_ID);
}


static void forward_set_key(uint8_t *pKeyData, MDB_val *pKey, uint64_t PrevShortChannelId, uint64_t PrevHtlcId)
{
    pKey->mv_size = M_SZ_FORWARD_KEY;
    pKey->mv_data = pKeyData;
    utl_int_unpack_u64be(pKeyData, PrevShortChannelId);
    utl_int_unpack_u64be(pKeyData + sizeof(uint64_t), PrevHtlcId);
}


static bool forward_parse_key(MDB_val *pKey, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId)
{
    if (pKey->mv_size != M_SZ_FORWARD_KEY) {
        return false;
    }
    *pPrevShortChannelId = utl_int_pack_u64be(pKey->mv_data);
    *pPrevHtlcId = utl_int_pack_u64be(pKey->mv_data + sizeof(uint64_t));
    return true;
}


/********************************************************************
 * private functions: payment
 ********************************************************************/

static int payment_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb)
{
    return db_open(pDb, mpEnvPayment, pDbName, OptTxn, OptDb);
}


static int payment_db_open_2(ln_lmdb_db_t *pDb, MDB_txn *pTxn, const char *pDbName, int OptDb)
{
    return db_open_2(pDb, pTxn, pDbName, OptDb);
}


static void payment_id_set_key(uint8_t *pKeyData, MDB_val *pKey, uint64_t PaymentId)
{
    pKey->mv_size = M_SZ_PAYMENT_ID_KEY;
    pKey->mv_data = pKeyData;
    utl_int_unpack_u64be(pKeyData, PaymentId);
}


static bool payment_id_parse_key(MDB_val *pKey, uint64_t *pPaymentId)
{
    if (pKey->mv_size != M_SZ_PAYMENT_ID_KEY) {
        return false;
    }
    *pPaymentId = utl_int_pack_u64be(pKey->mv_data);
    return true;
}


static bool payment_save(const char *pDbName, uint64_t PaymentId, const uint8_t *pData, uint32_t Len)
{
    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;
    uint8_t         key_data[M_SZ_PAYMENT_ID_KEY];

    retval = payment_db_open(&db, pDbName, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    payment_id_set_key(key_data, &key, PaymentId);
    data.mv_size = Len;
    data.mv_data = (CONST_CAST char*)pData;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


static int payment_load(ln_lmdb_db_t *pDb, utl_buf_t *pBuf, uint64_t PaymentId)
{
    MDB_val key, data;
    uint8_t key_data[M_SZ_PAYMENT_ID_KEY];

    payment_id_set_key(key_data, &key, PaymentId);
    int retval = mdb_get(pDb->p_txn, pDb->dbi, &key, &data);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }

    if (!utl_buf_alloccopy(pBuf, data.mv_data, data.mv_size)) {
        LOGE("fail: ???\n");
        return -1;
    }
    return 0;
}


static bool payment_load_2(const char *pDbName, utl_buf_t *pBuf, uint64_t PaymentId)
{
    int             retval;
    ln_lmdb_db_t    db;

    retval = payment_db_open(&db, pDbName, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    retval = payment_load(&db, pBuf, PaymentId);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_ABORT(db.p_txn);
    return true;
}


static bool payment_load_3(
    const char *pDbName, utl_buf_t *pBuf, uint64_t PaymentId, MDB_txn *pTxn)
{
    int             retval;
    ln_lmdb_db_t    db;

    retval = payment_db_open_2(&db, pTxn, pDbName, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    retval = payment_load(&db, pBuf, PaymentId);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    return true;
}


static bool payment_del(const char *pDbName, uint64_t PaymentId)
{
    int             retval;
    MDB_val         key;
    ln_lmdb_db_t    db;
    uint8_t         key_data[M_SZ_PAYMENT_ID_KEY];

    retval = payment_db_open(&db, pDbName, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    payment_id_set_key(key_data, &key, PaymentId);
    retval = mdb_del(db.p_txn, db.dbi, &key, NULL);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


static bool payment_cur_open(void **ppCur, const char *pDbName)
{
    int             retval;
    lmdb_cursor_t   *p_cur;

    *ppCur = NULL;

    p_cur  = (lmdb_cursor_t *)UTL_DBG_MALLOC(sizeof(lmdb_cursor_t));
    if (!p_cur) {
        LOGE("fail: ???\n");
        return false;
    }

    retval = payment_db_open((ln_lmdb_db_t *)p_cur, pDbName, 0, 0);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        UTL_DBG_FREE(p_cur);
        return false;
    }

    retval = mdb_cursor_open(p_cur->p_txn, p_cur->dbi, &p_cur->p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        UTL_DBG_FREE(p_cur);
        return false;
    }

    *ppCur = p_cur;
    return true;
}


static void payment_cur_close(void *pCur, bool bCommit)
{
    if (!pCur) return;

    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    MDB_CURSOR_CLOSE(p_cur->p_cursor);

    if (!p_cur->p_txn) return;
    MDB_TXN_CHECK_PAYMENT(p_cur->p_txn);
    if (bCommit) {
        MDB_TXN_COMMIT(p_cur->p_txn);
    } else {
        MDB_TXN_ABORT(p_cur->p_txn);
    }
}


static bool payment_cur_get(void *pCur, uint64_t *pPaymentId, utl_buf_t *pBuf)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval = payment_cur_load(p_cur->p_cursor, pPaymentId, pBuf, MDB_NEXT_NODUP);
    if (retval) {
        return false;
    }
    return true;
}


static int payment_cur_load(
    MDB_cursor *pCur, uint64_t *pPaymentId, utl_buf_t *pBuf, MDB_cursor_op Op)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(pCur, &key, &data, Op);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: mdb_cursor_get(): %s\n", mdb_strerror(retval));
        }
        return retval;
    }

    //key
    if (!payment_id_parse_key(&key, pPaymentId)) {
        LOGE("fail: invalid key length: %d\n", (int)key.mv_size);
        DUMPD(key.mv_data, key.mv_size);
        return -1;
    }

    //data
    if (!utl_buf_alloccopy(pBuf, (uint8_t *)data.mv_data, data.mv_size)) {
        LOGE("fail: ???\n");
        return -1;
    }
    return 0;
}


static bool payment_cur_del(void *pCur)
{
    lmdb_cursor_t *p_cur = (lmdb_cursor_t *)pCur;
    int retval = mdb_cursor_del(p_cur->p_cursor, 0);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: mdb_cursor_del(): %s\n", mdb_strerror(retval));
        }
        return false;
    }
    return true;
}


/********************************************************************
 * private functions: item
 ********************************************************************/

/** fixed_item_tデータ読込み
 *
 * @param[out]      pData
 * @param[in]       pDb
 * @param[in]       pItems
 * @param[in]       Num             pItems数
 */
static int fixed_items_load(void *pData, ln_lmdb_db_t *pDb, const fixed_item_t *pItems, size_t Num)
{
    int     retval;
    MDB_val key, data;

    for (size_t lp = 0; lp < Num; lp++) {
        key.mv_size = strlen(pItems[lp].p_name);
        key.mv_data = (CONST_CAST char *)pItems[lp].p_name;
        retval = mdb_get(pDb->p_txn, pDb->dbi, &key, &data);
        if (retval == 0) {
            //LOGD("%s: %lu\n", pItems[lp].p_name, pItems[lp].offset);
            memcpy((uint8_t *)pData + pItems[lp].offset, data.mv_data,  pItems[lp].data_len);
        } else {
            if (retval != MDB_NOTFOUND) {
            LOGE("fail: %s\n", mdb_strerror(retval));
            LOGE("fail: %s\n", pItems[lp].p_name);
                return retval;
            } else {
                LOGE("item \"%s\" not found.\n", pItems[lp].p_name);
            }
        }
    }

    return 0;
}


/** fixed_item_tデータ保存
 *
 * @param[in]       pData
 * @param[in]       pDb
 * @param[in]       pItems
 * @param[in]       Num             pItems数
 */
static int fixed_items_save(const void *pData, ln_lmdb_db_t *pDb, const fixed_item_t *pItems, size_t Num)
{
    int     retval;
    MDB_val key, data;

    for (size_t lp = 0; lp < Num; lp++) {
        key.mv_size = strlen(pItems[lp].p_name);
        key.mv_data = (CONST_CAST char *)pItems[lp].p_name;
        data.mv_size = pItems[lp].data_len;
        data.mv_data = (CONST_CAST uint8_t *)pData + pItems[lp].offset;
        retval = mdb_put(pDb->p_txn, pDb->dbi, &key, &data, 0);
        if (retval) {
            LOGE("fail: %s\n", mdb_strerror(retval));
            LOGE("fail: %s\n", pItems[lp].p_name);
            return retval;
        }
    }

    return 0;
}


/********************************************************************
 * private functions: initialize
 ********************************************************************/

static int init_db_env(const init_param_t  *p_param)
{
    int retval;

    retval = lmdb_init(p_param);
    if (retval) {
        LOGE("ERR: (%s)\n", p_param->p_path);
        return retval;
    }

    retval = lmdb_compaction(p_param);
    if (retval) {
        LOGE("ERR: (%s)\n", p_param->p_path);
        return retval;
    }
    LOGD("DB: OK(%s)\n", p_param->p_path);

    return 0;
}


static int lmdb_init(const init_param_t  *p_param)
{
    int retval;

    LOGD("BEGIN(%s)\n", p_param->p_path);

    mkdir(p_param->p_path, 0755);

    retval = mdb_env_create(p_param->pp_env);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    retval = mdb_env_set_maxdbs(*p_param->pp_env, p_param->maxdbs);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    retval = mdb_env_set_mapsize(*p_param->pp_env, p_param->mapsize);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }
    retval = mdb_env_open(*p_param->pp_env, p_param->p_path, p_param->open_flag, 0644);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }

    LOGD("DB: OK(%s)\n", p_param->p_path);
    return 0;
}


static int lmdb_compaction(const init_param_t  *p_param)
{
    int                 retval;
    MDB_envinfo         info;
    long                pagesize = sysconf(_SC_PAGESIZE);

    retval = mdb_env_info(*p_param->pp_env, &info);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }

    LOGD("-------------------------------------------\n");
    LOGD("pagesize=%d\n", pagesize);
    LOGD("env_info.mapsize=%lu\n", info.me_mapsize);
    LOGD("env_info.last_pgno=%lu\n", info.me_last_pgno);
    // LOGD("env_info.last_txnid=%lu\n", info.me_last_txnid);
    // LOGD("env_info.maxreaders=%lu\n", info.me_maxreaders);
    // LOGD("env_info.numreaders=%lu\n", info.me_numreaders);
    LOGD("-------------------------------------------\n");

    if (info.me_mapsize > (info.me_last_pgno + M_MAPSIZE_REMAIN_LIMIT) * pagesize) {
        LOGD("DB: OK(%s)\n", p_param->p_path);
        return 0;
    }

    LOGE("ERR: page not remain\n");
    size_t prev_me_last_pgno = info.me_last_pgno;

    char tmppath[M_DB_PATH_STR_MAX + 16 + 1];
    snprintf(tmppath, M_DB_PATH_STR_MAX, "%.1024s/tmpdir", mPath);
    mkdir(tmppath, 0755);
    retval = mdb_env_copy2(*p_param->pp_env, tmppath, MDB_CP_COMPACT);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }

    retval = mdb_env_info(*p_param->pp_env, &info); //XXX: old env's info?
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return retval;
    }

    if (prev_me_last_pgno > info.me_last_pgno) {
        if (rmdir_recursively(p_param->p_path)) {
            if (rename(tmppath, p_param->p_path)) {
                retval = -1;
                LOGE("errno: %d\n", errno);
                LOGE("ERR: %s\n", mdb_strerror(retval));
                return retval;
            }
        } else {
            LOGE("fail\n");
        }

        //開き直す //XXX: why? --> そのまま継続したかった or チェック
        mdb_env_close(*p_param->pp_env);
        retval = lmdb_init(p_param);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return retval;
        }

        fprintf(stderr, "DB optimized. Please rerun !\n");
    } else {
        if (!rmdir_recursively(tmppath)) {
            LOGE("fail\n");
        }

        fprintf(stderr, "DB mapsize is flood...\n");
    }

    LOGD("prev pgno=%lu, now pgno=%lu\n", prev_me_last_pgno, info.me_last_pgno);
    retval = ENOMEM;
    LOGE("ERR: %s\n", mdb_strerror(retval));
    return retval;
}


//https://stackoverflow.com/a/42978529
static int rm_files(const char *pPath, const struct stat *pStat, int Type, struct FTW *pFtwb)
{
    (void)pStat; (void)Type; (void)pFtwb;

    if (remove(pPath) < 0) {
        LOGE("errno: %d\n", errno);
        LOGE("ERR: remove\n");
        return -1;
    }
    return 0;
}


static bool rmdir_recursively(const char *pPath)
{
    int ret = nftw(pPath, rm_files, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
    return ret == 0;
}


/********************************************************************
 * private functions: auto update
 ********************************************************************/

/** auto update: -68 ==> -69
 *
 * node/preimage: preimage_info_t::status
 */
static bool auto_update_68_to_69(void)
{
    LOGD("\n");

    bool ret;
    lmdb_cursor_t *p_cur;

    ret = ln_db_preimage_cur_open((void **)&p_cur);
    if (!ret) {
        LOGD("OK: no convert DB\n");
        ret = true;
        goto LABEL_EXIT;
    }

    while (true) {
        MDB_val         key, data;
        int retval = mdb_cursor_get(p_cur->p_cursor, &key, &data, MDB_NEXT_NODUP);
        if (retval != 0) {
            if (retval == MDB_NOTFOUND) {
                ret = true;
            } else {
                LOGE("fail: %s\n", mdb_strerror(retval));
            }
            break;
        }

        preimage_info_ver68_t *p_info68 = (preimage_info_ver68_t *)data.mv_data;

        if (!my_mdb_val_alloccopy(&key, &key)) {
            LOGE("fail: ???\n");
            break;
        }
        preimage_info_t info;
        info.amount = p_info68->amount;
        info.creation = p_info68->creation;
        info.expiry = p_info68->expiry;
        info.state = LN_DB_PREIMAGE_STATE_UNUSED;
        info.bolt11[0] = '\0';

        data.mv_data = &info;
        data.mv_size = sizeof(info);
        retval = mdb_cursor_put(p_cur->p_cursor, &key, &data, MDB_CURRENT);
        UTL_DBG_FREE(key.mv_data);
        if (retval != 0) {
            LOGE("fail: %s\n", mdb_strerror(retval));
            ret = false;
            break;
        }
    }

    ln_db_preimage_cur_close(p_cur, true);

LABEL_EXIT:
    return ret;
}


#if defined(USE_BITCOIND)
static bool auto_update_69_to_70(void)
{
    LOGE("bitcoind auto update.\n");
    return true;
}

#elif defined(USE_BITCOINJ)
/** auto update: -69 ==> -70
 *
    -70: add `ln_db_wallet_t::mined_height` (bitcoind auto update: -69 ==> -70)
 */
static bool auto_update_69_to_70_func(const ln_db_wallet_t *pWallet, void *p_param)
{
    bool *p_ret = (bool *)p_param;

    bool ret = false;

    if ((pWallet->sequence != 0) && (pWallet->sequence < BTC_TX_SEQUENCE)) {
        LOGD("have sequence\n");
        *p_ret = true;
        ret = true;
    } else if (pWallet->locktime != 0) {
        LOGD("have locktime\n");
        *p_ret = true;
        ret = true;
    }
    return ret;
}


static bool auto_update_69_to_70(void)
{
    bool have_wallet = false;
    (void)ln_db_wallet_search(auto_update_69_to_70_func, &have_wallet);
    if (have_wallet) {
        LOGE("bitcoinj need mined_height.\n");
    }
    return !have_wallet;
}
#endif
