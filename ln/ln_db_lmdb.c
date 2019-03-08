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


//#define M_DB_DEBUG

/********************************************************************
 * macros
 ********************************************************************/

//INIT_PARAM[]の添字
#define M_INIT_PARAM_CHANNEL    (0)
#define M_INIT_PARAM_NODE       (1)
#define M_INIT_PARAM_ANNO       (2)
#define M_INIT_PARAM_WALLET     (3)

#define M_MAPSIZE_REMAIN_LIMIT  (2)                         ///< DB compactionを実施する残りpage

#define M_DEFAULT_MAPSIZE       ((size_t)10485760)          // DB最大長[byte](LMDBのデフォルト値)
#define M_CHANNEL_MAXDBS        (12 * 2 * MAX_CHANNELS)     ///< 同時オープンできるDB数
#define M_CHANNEL_MAPSIZE       M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_NODE_MAXDBS           (50)                        ///< 同時オープンできるDB数
#define M_NODE_MAPSIZE          M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_ANNO_MAXDBS           (50)                        ///< 同時オープンできるDB数
//#define M_ANNO_MAPSIZE        ((size_t)4294963200)        // DB最大長[byte] Ubuntu 18.04(64bit)で使用できたサイズ
#define M_ANNO_MAPSIZE          ((size_t)1073741824)        // DB最大長[byte] Raspberry Piで使用できたサイズ
                                                            // 32bit環境ではsize_tが4byteになるため、32bitの範囲内にすること

#define M_WALLET_MAXDBS         (MAX_CHANNELS)              ///< 同時オープンできるDB数
#define M_WALLET_MAPSIZE        M_DEFAULT_MAPSIZE           // DB最大長[byte]

#define M_DB_PATH_STR_MAX       (PATH_MAX - 1)              //path max but exclude null char
#define M_DB_DIR                "db"
#define M_CHANNEL_ENV_DIR       "channel"                   ///< channel
#define M_NODE_ENV_DIR          "node"                      ///< node
#define M_ANNO_ENV_DIR          "anno"                      ///< announcement
#define M_WALLET_ENV_DIR        "wallet"                    ///< 1st layer wallet


#define M_NUM_CHANNEL_BUFS      (3)                         ///< DB保存するvariable長データ数
                                                            //      funding
                                                            //      local shutdown scriptPubKeyHash
                                                            //      remote shutdown scriptPubKeyHash

#define M_SZ_PREF_STR           (2)
#define M_PREF_CHANNEL          "CN"                        ///< channel
#define M_PREF_SECRET           "SE"                        ///< secret
#define M_PREF_HTLC             "HT"                        ///< htlc
#define M_PREF_REVOKED_TX       "RV"                        ///< revoked transaction
#define M_PREF_CHANNEL_BACKUP   "cn"                        ///< closed channel backup

#define M_DBI_CNLANNO           "channel_anno"              ///< 受信したchannel_announcement/channel_update
#define M_DBI_CNLANNO_INFO      "channel_anno_info"         ///< channel_announcement/channel_updateの受信元・送信先
#define M_DBI_NODEANNO          "node_anno"                 ///< 受信したnode_announcement
#define M_DBI_NODEANNO_INFO     "node_anno_info"            ///< node_announcementの受信元・送信先
#define M_DBI_CNLANNO_RECV      "channel_anno_recv"         ///< channel_announcementのnode_id
#define M_DBI_CNL_OWNED         "channel_owned"             ///< 自分の持つchannel
#define M_DBI_ROUTE_SKIP        LN_DB_DBI_ROUTE_SKIP        ///< 送金失敗short_channel_id
#define M_DBI_INVOICE           "invoice"                   ///< 送金中invoice一時保存
#define M_DBI_PREIMAGE          "preimage"                  ///< preimage
#define M_DBI_PAYMENT_HASH      "payment_hash"              ///< revoked transaction close用
#define M_DBI_WALLET            "wallet"                    ///< wallet
#define M_DBI_VERSION           "version"                   ///< verion

#define M_SZ_DB_NAME_STR        (M_SZ_PREF_STR + LN_SZ_CHANNEL_ID * 2)
#define M_SZ_HTLC_IDX_STR       (3)     // "%03d" 0-482
#define M_SZ_CNLANNO_INFO       (LN_SZ_SHORT_CHANNEL_ID + sizeof(char))
#define M_SZ_NODEANNO_INFO      (BTC_SZ_PUBKEY)

#define M_KEY_PREIMAGE          "preimage"
#define M_SZ_PREIMAGE           (sizeof(M_KEY_PREIMAGE) - 1)
#define M_KEY_ONION_ROUTE       "onion_route"
#define M_SZ_ONION_ROUTE        (sizeof(M_KEY_ONION_ROUTE) - 1)
#define M_KEY_SHARED_SECRET     "shared_secret"
#define M_SZ_SHARED_SECRET      (sizeof(M_KEY_SHARED_SECRET) - 1)

#define M_DB_VERSION_VAL        ((int32_t)(-59))            ///< DB version
/*
    -1 : first
    -2 : ln_update_add_htlc_t変更
    -3 : ln_funding_remote_data_t変更
    -4 : ln_funding_local_data_t, ln_funding_remote_data_t変更
    -5 : backup_self_tにln_node_info_t追加
    -6 : self.min_depth追加
    -7 : ln_commit_tx_tにtxid追加
    -8 : ln_commit_tx_tにhtlc_num追加
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
    -21: fix: alias length
    -22: onion route
    -23: announcement dbを分離
    -24: self.cnl_add_htlc[].flag変更
    -25: self.close_type追加
    -26: DB_COPYにhtlc_num, htld_id_num追加
    -27: self.close_type変更
    -28: self.htlc_num削除
    -29: self.statusとself.close_typeのマージ
    -30: bitcoindとSPVを同じにする
    -31: include peer_storage_index in ln_derkey_storage_t
    -32: exchange the values of commit_tx_local.to_self_delay and commit_tx_remote.to_self_delay
    -33: change the format of pub/priv keys
    -34: change the size of ln_derkey_local_privkeys_t::per_commitment_secret
         BTC_SZ_PUBKEY -> BTC_SZ_PRIVKEY
    -35: change the order of internal members in ln_derkey_local_privkeys_t
    -36: change self->peer_storage -> self->privkeys_remote
    -37: funding_local -> pubkeys_local, funding_remote -> pubkeys_remote
    -38: rename db name, dbparam_self -> dbptarm_chnl
         rename self -> channel
    -39: DBCHANNEL_SECRET:
             ln_channel_t::privkeys_local ->
                 ln_channel_t::keys_local.ln_derkey_local_keys_t::secrets
                 ln_channel_t::keys_local.ln_derkey_local_keys_t::storage_seed
                 ln_channel_t::keys_local.ln_derkey_local_keys_t::next_storage_index
         DBCHANNEL_VALUES:
             ln_channel_t::privkeys_remote
             ln_channel_t::pubkeys_remote ->
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::basepoints
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::next_storage_index
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::storage
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::per_commitment_point
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::prev_per_commitment_point
             ln_channel_t::pubkeys_local -> removed
         and the local public keys and the script pubkeys are restored after loading
    -40: save only txid and txindex in ln_funding_tx_t
    -41: add `funding_tx_t::funding_satoshis`
         rm `ln_channel_t::funding_sat`
    -42: rename `our_msat` -> `local_msat` and `their_msat` -> `remote_msat`
    -43: rename `ln_update_add_htlc_t::stat` -> `ln_update_add_htlc_t::flags`
    -44: rm `ln_channel_t::local_msat`
         rm `ln_channel_t::remote_msat`
         add `ln_commit_tx_t::local_msat`
         add `ln_commit_tx_t::remote_msat`
    -45: rename `htlc_id_num` -> `num_htlc_ids`
         rename `htlc_output_num` -> `num_htlc_outputs`
    -46: separate `ln_update_add_htlc_t` into `ln_update_t` and `ln_htlc_t`
         rename `num_htlc_ids` -> `next_htlc_id`
    -47: the size of `ln_update_t` gets smaller
         rm `ln_update_t::prev_short_channel_id`
         rm `ln_update_t::prev_idx`
         rm `ln_update_t::next_short_channel_id`
         rm `ln_update_t::next_idx`
         add `ln_update_t::neighbor_short_channel_id`
         add `ln_update_t::neighbor_idx`
    -48: fix ln_update_t::enabled
    -49: update `ln_update_t` and `ln_htlc_t`
    -50: rename `ln_funding_tx_t` -> `ln_funding_info_t`
         rename `ln_commit_t` -> `ln_commit_info_t`
    -51: `ln_channel_t::updates` -> `ln_channel_t::update_info.updates`
         `ln_channel_t::htlcs` -> `ln_channel_t::update_info.htlcs`
         `ln_channel_t::next_htlc_id` -> `ln_channel_t::update_info.next_htlc_id`
    -52: rm `ln_channel_t::feerate_per_kw`
         add `ln_commit_info_t::feerate_per_kw`
    -53: add `ln_update_info_t::fee_updates`
    -54: update `ln_update_info_t::updates`
    -55: update `ln_update_info_t::fee_updates`
    -56: add `ln_update_info_t::next_fee_update_id`
         add `ln_fee_update_t::id`
         rename `ln_update_t::htlc_idx` -> `ln_update_t::type_specific_idx`
    -57: channel_announcement/channel_update key: little endian -> big endian(for auto sort)
    -58: update the size of `ln_update_info_t::updates` and `ln_update_info_t::fee_updates`
         rm `ln_commit_info_t::feerate_per_kw`
    -59: updated a lot!
         change db paths and db names and so on
 */


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
#define MDB_CURSOR_CLOSE(a)         { mdb_cursor_close(a); (a) = NULL; }

#define MDB_TXN_CHECK_CHANNEL(a)    //none
#define MDB_TXN_CHECK_NODE(a)       //none
#define MDB_TXN_CHECK_ANNO(a)       //none
#define MDB_TXN_CHECK_WALLET(a)     //none
#else
static volatile int g_cnt[2];
#define MDB_TXN_BEGIN(a, b, c, d)   my_mdb_txn_begin(a, b, c, d, __LINE__);
#define MDB_TXN_ABORT(a)            { my_mdb_txn_abort(a, __LINE__); (a) = NULL; }
#define MDB_TXN_COMMIT(a)           { my_mdb_txn_commit(a, __LINE__); (a) = NULL; }
#define MDB_DBI_OPEN(a, b, c, d)    my_mdb_dbi_open(a, b, c, d, __LINE__)
#define MDB_CURSOR_CLOSE(a)         { mdb_cursor_close(a); (a) = NULL; }

#define MDB_TXN_CHECK_CHANNEL(a)    if (mdb_txn_env(a) != mpEnvChannel) { LOGE("ERR: txn not CHANNEL\n"); abort(); }
#define MDB_TXN_CHECK_NODE(a)       if (mdb_txn_env(a) != mpEnvNode) { LOGE("ERR: txn not NODE\n"); abort(); }
#define MDB_TXN_CHECK_ANNO(a)       if (mdb_txn_env(a) != mpEnvAnno) { LOGE("ERR: txn not ANNO\n"); abort(); }
#define MDB_TXN_CHECK_WALLET(a)     if (mdb_txn_env(a) != mpEnvWallet) { LOGE("ERR: txn not WALLET\n"); abort(); }
#endif

#define M_DEBUG_KEYS


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


/** @typedef    preimage_info_t
 *  @brief      [preimage]に保存するpreimage情報
 */
typedef struct {
    uint64_t amount;            ///< amount[satoshi]
    uint64_t creation;          ///< invoice creation epoch
    uint32_t expiry;            ///< expiry[sec]
                                //      0: 3600s=1h(BOLT#11のデフォルト値)
                                //      UINT32_MAX: expiryによる自動削除禁止
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
static MDB_env      *mpEnvChannel = NULL;        //channel
static MDB_env      *mpEnvNode = NULL;           //node
static MDB_env      *mpEnvAnno = NULL;           //announcement
static MDB_env      *mpEnvWallet = NULL;         //wallet
static char         mPath[M_DB_PATH_STR_MAX + 1];
static char         mPathChannel[M_DB_PATH_STR_MAX + 1];
static char         mPathNode[M_DB_PATH_STR_MAX + 1];
static char         mPathAnno[M_DB_PATH_STR_MAX + 1];
static char         mPathWallet[M_DB_PATH_STR_MAX + 1];

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
    //[INIT_04]reest_commit_num
    //[INIT_05]reest_revoke_num

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
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, updates),              //[NORM_03]
    //[NORM_03]htlcs --> HTLC
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, next_htlc_id),         //[NORM_03]
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, fee_updates),          //[NORM_03]
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, next_fee_update_id),   //[NORM_03]

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

    //
    //nois
    //
    //[NOIS_01]noise

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
 *  @var    DBCHANNEL_COPY
 *  @brief  値コピー用
 *  @note
 *      - DBCHANNEL_COPY[]とDBCHANNEL_COPYIDX[]を同時に更新すること
 */
static const fixed_item_t DBCHANNEL_COPY[] = {
    M_ITEM(ln_channel_t, peer_node_id),
    M_ITEM(ln_channel_t, channel_id),
    M_ITEM(ln_channel_t, short_channel_id),
    MM_ITEM(ln_channel_t, update_info, ln_update_info_t, next_htlc_id),
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, txid),
    MM_ITEM(ln_channel_t, funding_info, ln_funding_info_t, txindex),
    M_ITEM(ln_channel_t, keys_local),
    M_ITEM(ln_channel_t, keys_remote),
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, commit_num),
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, revoke_num),
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, local_msat),
    MM_ITEM(ln_channel_t, commit_info_local, ln_commit_info_t, remote_msat),
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, commit_num),
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, revoke_num),
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, local_msat),
    MM_ITEM(ln_channel_t, commit_info_remote, ln_commit_info_t, remote_msat),
};


/**
 *  @var    DBCHANNEL_COPYIDX
 *  @brief  値コピー用(index)
 *  @note
 *      - DBCHANNEL_COPY[]とDBCHANNEL_COPYIDX[]を同時に更新すること
 */
static const struct {
    enum {
        ETYPE_BYTEPTR,      //const uint8_t*
        ETYPE_UINT64U,      //uint64_t(unsigned decimal)
        ETYPE_UINT64X,      //uint64_t(unsigned hex)
        ETYPE_UINT16,       //uint16_t
        ETYPE_TXID,         //txid
        ETYPE_FUNDTXID,     //funding_local.txid
        ETYPE_FUNDTXIDX,    //funding_local.txindex
        ETYPE_LOCALKEYS,    //keys_local
        ETYPE_REMOTEKEYS,   //keys_remote
        //ETYPE_REMOTECOMM,   //funding_remote.prev_percommit
    } type;
    int length;
    bool disp;      //true: showdbで表示する
} DBCHANNEL_COPYIDX[] = {
    { ETYPE_BYTEPTR,    BTC_SZ_PUBKEY, true },      // peer_node_id
    { ETYPE_BYTEPTR,    LN_SZ_CHANNEL_ID, true },   // channel_id
    { ETYPE_UINT64X,    1, true },                  // short_channel_id
    { ETYPE_UINT64U,    1, true },                  // num_htlc_ids
    { ETYPE_FUNDTXID,   BTC_SZ_TXID, true },        // funding_txid
    { ETYPE_FUNDTXIDX,  1, true },                  // funding_txindex
    { ETYPE_LOCALKEYS,  1, false },                 // keys_local
    { ETYPE_REMOTEKEYS, 1, false },                 // keys_remote
    { ETYPE_UINT64U,    1, true },                  // commit_info_local.commit_num
    { ETYPE_UINT64U,    1, true },                  // commit_info_local.revoke_num
    { ETYPE_UINT64U,    1, true },                  // commit_info_local.local_msat
    { ETYPE_UINT64U,    1, true },                  // commit_info_local.remote_msat
    { ETYPE_UINT64U,    1, true },                  // commit_info_remote.commit_num
    { ETYPE_UINT64U,    1, true },                  // commit_info_remote.revoke_num
    { ETYPE_UINT64U,    1, true },                  // commit_info_remote.local_msat
    { ETYPE_UINT64U,    1, true },                  // commit_info_remote.remote_msat
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
};


// LMDB initialize parameter
static const init_param_t INIT_PARAM[] = {
    //M_INIT_PARAM_CHANNEL
    { &mpEnvChannel, mPathChannel, M_CHANNEL_MAXDBS, M_CHANNEL_MAPSIZE, 0 },
    //M_INIT_PARAM_NODE
    { &mpEnvNode, mPathNode, M_NODE_MAXDBS, M_NODE_MAPSIZE, 0 },
    //M_INIT_PARAM_ANNO
    { &mpEnvAnno, mPathAnno, M_ANNO_MAXDBS, M_ANNO_MAPSIZE, MDB_NOSYNC },
    //M_INIT_PARAM_WALLET
    { &mpEnvWallet, mPathWallet, M_WALLET_MAXDBS, M_WALLET_MAPSIZE, 0 },
};


/********************************************************************
 * prototypes
 ********************************************************************/

static bool set_path(char *pPath, size_t Size, const char *pDir, const char *pName);

static int db_open(ln_lmdb_db_t *pDb, MDB_env *env, const char *pDbName, int OptTxn, int OptDb);

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
static bool channel_search(ln_db_func_cmp_t pFunc, void *pFuncParam, bool bWritable, bool bRestore);

static int node_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);

static int cnlanno_load(ln_lmdb_db_t *pDb, utl_buf_t *pCnlAnno, uint64_t ShortChannelId);
static int cnlanno_save(ln_lmdb_db_t *pDb, const utl_buf_t *pCnlAnno, uint64_t ShortChannelId);
static int cnlupd_load(ln_lmdb_db_t *pDb, utl_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir);
static int cnlupd_save(ln_lmdb_db_t *pDb, const utl_buf_t *pCnlUpd, const ln_msg_channel_update_t *pUpd);
static int cnlanno_cur_load(MDB_cursor *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf, MDB_cursor_op op);
static int nodeanno_load(ln_lmdb_db_t *pDb, utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);
static int nodeanno_save(ln_lmdb_db_t *pDb, const utl_buf_t *pNodeAnno, const uint8_t *pNodeId, uint32_t Timestamp);

static bool annoinfos_trim_node_id(
    const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo);
static bool annoinfos_trim_node_id_selected(
    const uint8_t *pNodeId, MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo, const uint64_t *pShortChannelIds, size_t Num);
static bool annoinfos_trim_node_id_nodeanno(
    const uint8_t *pNodeId, uint64_t ShortChannelId, MDB_dbi DbiNodeannoInfo, ln_lmdb_db_t *pDb);
static bool annoinfos_del_all(MDB_dbi DbiCnlannoInfo, MDB_dbi DbiNodeannoInfo);

static void cnlanno_info_set(uint8_t *pKeyData, MDB_val *pKey, uint64_t ShortChannelId, char Type);
static bool cnlanno_info_get(MDB_val *pKey, uint64_t *pShortChannelId, char *pType);
static void nodeanno_info_set(uint8_t *pKeyData, MDB_val *pKey, const uint8_t *pNodeId);
//static bool nodeanno_info_get(MDB_val *pKey, uint8_t *pNodeId);

static bool annoinfo_add(ln_lmdb_db_t *pDb, MDB_val *pMdbKey, MDB_val *pMdbData, const uint8_t *pNodeId);
static bool annoinfo_search_node_id(MDB_val *pMdbData, const uint8_t *pNodeId);
static bool annoinfo_cur_trim_node_id(MDB_cursor *pCursor, const uint8_t *pNodeId);
static bool annoinfo_trim_node_id(MDB_val *pData, const uint8_t *pNodeId);
static void annoinfo_cur_add(MDB_cursor *pCursor, const uint8_t *pNodeId);
static void anno_del_prune(void);

static bool preimage_open(ln_lmdb_db_t *pDb, MDB_txn *pTxn);
static void preimage_close(ln_lmdb_db_t *pDb, MDB_txn *pTxn, bool bCommit);
static bool preimage_cmp_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *pDbParam, void *pParam);
static bool preimage_cmp_all_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *pDbParam, void *pParam);

static int wallet_db_open(ln_lmdb_db_t *pDb, const char *pDbName, int OptTxn, int OptDb);

static int version_write(ln_lmdb_db_t *pDb, const char *pWif, const char *pNodeName, uint16_t Port);
static int version_check(ln_lmdb_db_t *pDb, int32_t *pVer, char *pWif, char *pNodeName, uint16_t *pPort, uint8_t *pGenesis);

static int fixed_items_load(void *pData, ln_lmdb_db_t *pDb, const fixed_item_t *pItems, size_t Num);
static int fixed_items_save(const void *pData, ln_lmdb_db_t *pDb, const fixed_item_t *pItems, size_t Num);

static int init_db_env(int InitParamIdx);
static int rm_files(const char *pPath, const struct stat *pStat, int Type, struct FTW *pFtwb);
static bool rmdir_recursively(const char *pPath);
static int lmdb_init(int InitParamIdx);
static int lmdb_compaction(int InitParamIdx);


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
static inline int my_mdb_txn_begin(MDB_env *env, MDB_txn *pParent, unsigned int Flags, MDB_txn **ppTxn, int Line) {
    int ggg = (env == mpEnvChannel) ? 0 : 1;
    g_cnt[ggg]++;
    LOGD("mdb_txn_begin:%d:[%d]opens=%d(%d)\n", Line, ggg, g_cnt[ggg], (int)Flags);
    MDB_envinfo stat;
    if (mdb_env_info(env, &stat) == 0) {
        LOGD("  last txnid=%lu\n", stat.me_last_txnid);
    }
    int retval = mdb_txn_begin(env, pParent, Flags, ppTxn);
    if (retval == 0) {
        LOGD("  txnid=%lu\n", (unsigned long)mdb_txn_id(*ppTxn));
    }
    return retval;
}

static inline int my_mdb_txn_commit(MDB_txn *pTxn, int Line) {
    int ggg = (mdb_txn_env(txn) == mpEnvChannel) ? 0 : 1;
    g_cnt[ggg]--;
    LOGD("mdb_txn_commit:%d:[%d]opend=%d\n", Line, ggg, g_cnt[ggg]);
    int txn_retval = mdb_txn_commit(txn);
    if (txn_retval) {
        LOGE("ERR: %s\n", mdb_strerror(txn_retval));
    }
    return txn_retval;
}

static inline void my_mdb_txn_abort(MDB_txn *pTxn, int Line) {
    int ggg = (mdb_txn_env(txn) == mpEnvChannel) ? 0 : 1;
    g_cnt[ggg]--;
    LOGD("mdb_txn_abort:%d:[%d]opend=%d\n", Line, ggg, g_cnt[ggg]);
    mdb_txn_abort(txn);
}


static inline int my_mdb_dbi_open(MDB_txn *pTxn, const char *pName, unsigned int Flags, MDB_dbi *pDbi, int Line) {
    int retval = mdb_dbi_open(txn, pName, Flags, pDbi);
    LOGD("mdb_dbi_open(%d): retval=%d\n", Line, retval);
    if (retval && (retval != MDB_NOTFOUND)) {
        LOGE("ERR(%d): %s\n", Line, mdb_strerror(retval));
    }
    return retval;
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

    LOGD("db dir: %s\n", mPath);
    LOGD("  channel: %s\n", mPathChannel);
    LOGD("  node: %s\n", mPathNode);
    LOGD("  anno: %s\n", mPathAnno);
    LOGD("  wallet: %s\n", mPathWallet);
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


bool ln_db_init(char *pWif, char *pNodeName, uint16_t *pPort, bool bStdErr)
{
    int             retval;
    ln_lmdb_db_t    db;

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

    for (size_t lp = 0; lp < ARRAY_SIZE(INIT_PARAM); lp++) {
        retval = init_db_env(lp);
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
    retval = version_check(&db, &ver, pWif, pNodeName, pPort, genesis);
    MDB_TXN_COMMIT(db.p_txn);
    if (retval) {
        if (bStdErr) fprintf(stderr, "invalid version\n");
        goto LABEL_EXIT;
    }
    //LOGD("wif=%s\n", pWif);
    LOGD("alias=%s\n", pNodeName);
    LOGD("port=%d\n", *pPort);
    LOGD("genesis hash (db, node):\n");
    if (btc_block_get_chain(genesis) != btc_block_get_chain(ln_genesishash_get())) {
        LOGE("fail: genesis hash not match\n");
        if (bStdErr) fprintf(stderr, "genesis hash not match\n");
        retval = -1;
        goto LABEL_EXIT;
    }
    fprintf(stderr, "done!\n");

    //ln_db_invoice_drop();     //送金を再開する場合があるが、その場合は再入力させるか？
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

    for (uint16_t idx = 0; idx < LN_HTLC_RECEIVED_MAX; idx++) {
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
    char            db_name[M_SZ_DB_NAME_STR + 1];

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
    return ln_db_channel_search(channel_cmp_func_channel_del, (CONST_CAST void *)pChannelId);
}


bool ln_db_channel_del_param(const ln_channel_t *pChannel, void *pDbParam)
{
    int             retval;
    MDB_dbi         dbi;
    char            db_name[M_SZ_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];
    lmdb_cursor_t   *p_cur = (lmdb_cursor_t *)pDbParam;

    MDB_TXN_CHECK_CHANNEL(p_cur->p_txn);

    //remove preimages
    preimage_close_t param;
    param.p_htlcs = pChannel->update_info.htlcs;
    ln_db_preimage_search(preimage_cmp_all_func, &param);

    //htlcs
    memcpy(db_name, M_PREF_HTLC, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
    for (int lp = 0; lp < LN_HTLC_RECEIVED_MAX; lp++) {
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

    //revoked transaction
    memcpy(db_name, M_PREF_REVOKED_TX, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
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

    //backup
    memcpy(db_name, M_PREF_CHANNEL_BACKUP, M_SZ_PREF_STR);
    retval = MDB_DBI_OPEN(p_cur->p_txn, db_name, MDB_CREATE, &dbi);
    if (retval == 0) {
        ln_lmdb_db_t db;

        db.p_txn = p_cur->p_txn;
        db.dbi = dbi;
        retval = fixed_items_save(pChannel, &db, DBCHANNEL_COPY, ARRAY_SIZE(DBCHANNEL_COPY));
        if (retval) {
            LOGE("fail\n");
        }
    } else {
        LOGE("ERR: %s\n", mdb_strerror(retval));
    }
    return true;
}


bool ln_db_channel_search(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
    return channel_search(pFunc, pFuncParam, true, true);
}


bool ln_db_channel_search_readonly(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
//ToDo: NOT READONLY
    return channel_search(pFunc, pFuncParam, true, true);
}


bool ln_db_channel_search_readonly_nokey(ln_db_func_cmp_t pFunc, void *pFuncParam)
{
//ToDo: NOT READONLY
    return channel_search(pFunc, pFuncParam, true, false);
}


bool ln_db_channel_load_status(ln_channel_t *pChannel)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_DB_NAME_STR + 1];
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


void ln_lmdb_channel_backup_show(MDB_txn *pTxn, MDB_dbi Dbi)
{
    MDB_val         key, data;
#ifdef M_DEBUG_KEYS
    ln_funding_info_t funding_info;
    ln_derkey_local_keys_t keys_local;
    ln_derkey_remote_keys_t keys_remote;
    memset(&funding_info, 0x00, sizeof(funding_info));
    memset(&keys_local, 0x00, sizeof(keys_local));
    memset(&keys_remote, 0x00, sizeof(keys_remote));
#endif  //M_DEBUG_KEYS

    for (size_t lp = 0; lp < ARRAY_SIZE(DBCHANNEL_COPY); lp++) {
        key.mv_size = strlen(DBCHANNEL_COPY[lp].p_name);
        key.mv_data = (CONST_CAST char*)DBCHANNEL_COPY[lp].p_name;
        int retval = mdb_get(pTxn, Dbi, &key, &data);
        if (retval) {
            LOGE("fail: %s\n", DBCHANNEL_COPY[lp].p_name);
            continue;
        }

        const uint8_t *p = (const uint8_t *)data.mv_data;
        if ((lp != 0) && (DBCHANNEL_COPYIDX[lp].disp)) {
            printf(",\n");
        }
        if (DBCHANNEL_COPYIDX[lp].disp) {
            printf("      \"%s\": ", DBCHANNEL_COPY[lp].p_name);
        }
        switch (DBCHANNEL_COPYIDX[lp].type) {
        case ETYPE_BYTEPTR: //const uint8_t*
        //case ETYPE_REMOTECOMM:
            if (DBCHANNEL_COPYIDX[lp].disp) {
                printf("\"");
                utl_dbg_dump(stdout, p, DBCHANNEL_COPYIDX[lp].length, false);
                printf("\"");
            }
            break;
        case ETYPE_UINT64U:
            if (DBCHANNEL_COPYIDX[lp].disp) {
                printf("%" PRIu64 "", *(const uint64_t *)p);
            }
            break;
        case ETYPE_UINT64X:
            if (DBCHANNEL_COPYIDX[lp].disp) {
                printf("\"%016" PRIx64 "\"", *(const uint64_t *)p);
            }
            break;
        case ETYPE_UINT16:
        case ETYPE_FUNDTXIDX:
            if (DBCHANNEL_COPYIDX[lp].disp) {
                printf("%" PRIu16, *(const uint16_t *)p);
            }
#ifdef M_DEBUG_KEYS
            if (DBCHANNEL_COPYIDX[lp].type == ETYPE_FUNDTXIDX) {
                funding_info.txindex = *(const uint16_t *)p;
            }
#endif  //M_DEBUG_KEYS
            break;
        case ETYPE_TXID: //txid
        case ETYPE_FUNDTXID:
            if (DBCHANNEL_COPYIDX[lp].disp) {
                printf("\"");
                btc_dbg_dump_txid(stdout, p);
                printf("\"");
            }
#ifdef M_DEBUG_KEYS
            if (DBCHANNEL_COPYIDX[lp].type == ETYPE_FUNDTXID) {
                memcpy(funding_info.txid, p, DBCHANNEL_COPYIDX[lp].length);
            }
#endif  //M_DEBUG_KEYS
            break;
        case ETYPE_LOCALKEYS: //keys_local
#ifdef M_DEBUG_KEYS
            {
                memcpy(&keys_local, p, sizeof(ln_derkey_local_keys_t));
            }
#endif  //M_DEBUG_KEYS
            break;
        case ETYPE_REMOTEKEYS: //keys_remote
#ifdef M_DEBUG_KEYS
            {
                memcpy(&keys_remote, p, sizeof(ln_derkey_remote_keys_t));
            }
#endif  //M_DEBUG_KEYS
            break;
        default:
            ;
        }
    }
#ifdef M_DEBUG_KEYS
    if ( ((keys_local.basepoints[0][0] == 0x02) || (keys_local.basepoints[0][0] == 0x03)) &&
         ((keys_remote.basepoints[0][0] == 0x02) || (keys_remote.basepoints[0][0] == 0x03))) {
        printf("\n");
        //ln_update_script_pubkeys(&local, &remote);
        //ln_print_keys(&local, &remote);
    }
#endif  //M_DEBUG_KEYS
}


bool ln_db_secret_save(ln_channel_t *pChannel)
{
    int             retval;
    ln_lmdb_db_t    db;
    char            db_name[M_SZ_DB_NAME_STR + 1];

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
        LOGE("ERR: %s\n", mdb_strerror(retval));
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
        LOGD("new: short_channel_id=%016" PRIx64 "(dir=%d)\n", pUpd->short_channel_id, ln_cnlupd_direction(pUpd));
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
    uint8_t     key_data[M_SZ_CNLANNO_INFO];

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
        cnlanno_info_set(key_data, &key, ShortChannelId, SUFFIX[lp]);
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
        LOGV("new node_announcement\n");
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
    uint8_t key_data[M_SZ_CNLANNO_INFO];
    bool detect = false;

    cnlanno_info_set(key_data, &key, ShortChannelId, Type);
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
    uint8_t key_data[M_SZ_CNLANNO_INFO];

    cnlanno_info_set(key_data, &key, ShortChannelId, Type);
    int retval = mdb_get(mpTxnAnno, p_cur->dbi, &key, &data);
    if (retval == 0) {
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
    uint8_t key_data[M_SZ_NODEANNO_INFO];

    nodeanno_info_set(key_data, &key, pNodeId);
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
    uint8_t         key_data[M_SZ_NODEANNO_INFO];
    bool            detect = false;

    nodeanno_info_set(key_data, &key, pNodeId);
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

bool ln_db_annoinfos_del(const uint8_t *pNodeId, const uint64_t *pShortChannelIds, size_t Num)
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


bool ln_db_annoinfos_add(const uint8_t *pNodeId)
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
 * [node]invoice
 ********************************************************************/

bool ln_db_invoice_save(const char *pInvoice, uint64_t AddAmountMsat, const uint8_t *pPaymentHash)
{
    LOGD("\n");

    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;

    retval = node_db_open(&db, M_DBI_INVOICE, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = BTC_SZ_HASH256;
    key.mv_data = (CONST_CAST uint8_t *)pPaymentHash;
    size_t len = strlen(pInvoice);
    data.mv_size = len + 1 + sizeof(AddAmountMsat);    //invoice(\0含む) + uint64_t
    uint8_t *p_data = (uint8_t *)UTL_DBG_MALLOC(data.mv_size);
    if (!p_data) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }
    data.mv_data = p_data;

    memcpy(p_data, pInvoice, len + 1);  //\0までコピー
    p_data += len + 1;
    memcpy(p_data, &AddAmountMsat, sizeof(AddAmountMsat));
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        UTL_DBG_FREE(data.mv_data);
        return false;
    }

    UTL_DBG_FREE(data.mv_data);
    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


bool ln_db_invoice_load(char **ppInvoice, uint64_t *pAddAmountMsat, const uint8_t *pPaymentHash)
{
    int             retval;
    MDB_val         key, data;
    ln_lmdb_db_t    db;

    *ppInvoice = NULL;

    retval = node_db_open(&db, M_DBI_INVOICE, MDB_RDONLY, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = BTC_SZ_HASH256;
    key.mv_data = (CONST_CAST uint8_t *)pPaymentHash;
    retval = mdb_get(db.p_txn, db.dbi, &key, &data);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
        }
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    *ppInvoice = UTL_DBG_STRDUP(data.mv_data);
    if (!*ppInvoice) {
        LOGE("???\n");
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }
    size_t len = strlen(*ppInvoice);
    data.mv_size -= len;
    if (data.mv_size > sizeof(uint64_t)) {
        memcpy(pAddAmountMsat, data.mv_data + len + 1, sizeof(uint64_t));
    } else {
        *pAddAmountMsat = 0;
    }

    MDB_TXN_ABORT(db.p_txn);
    return true;
}


int ln_db_invoice_get(uint8_t **ppPaymentHash) //XXX: return error code
{
    int             retval;
    MDB_val         key, data;
    MDB_cursor      *p_cursor = NULL;
    ln_lmdb_db_t    db;

    *ppPaymentHash = NULL;
    int count = 0;

    retval = node_db_open(&db, M_DBI_INVOICE, MDB_RDONLY, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return 0;
    }

    retval = mdb_cursor_open(db.p_txn, db.dbi, &p_cursor);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return 0;
    }

    while (mdb_cursor_get(p_cursor, &key, &data, MDB_NEXT) == 0) {
        if (key.mv_size != BTC_SZ_HASH256) continue;
        count++;
        *ppPaymentHash = (uint8_t *)UTL_DBG_REALLOC(*ppPaymentHash, count * BTC_SZ_HASH256);
        memcpy(*ppPaymentHash + (count - 1) * BTC_SZ_HASH256, key.mv_data, BTC_SZ_HASH256);
    }

    MDB_TXN_ABORT(db.p_txn);
    return count;
}


bool ln_db_invoice_del(const uint8_t *pPaymentHash)
{
    int             retval;
    MDB_val         key;
    ln_lmdb_db_t    db;

    LOGD("payment_hash=");
    DUMPD(pPaymentHash, BTC_SZ_HASH256);

    retval = node_db_open(&db, M_DBI_INVOICE, 0, MDB_CREATE);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_size = BTC_SZ_HASH256;
    key.mv_data = (CONST_CAST uint8_t*)pPaymentHash;
    retval = mdb_del(db.p_txn, db.dbi, &key, NULL);
    if (retval && (retval != MDB_NOTFOUND)) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


bool ln_db_invoice_drop(void)
{
    LOGD("\n");

    int             retval;
    ln_lmdb_db_t    db;

    retval = node_db_open(&db, M_DBI_INVOICE, 0, 0);
    if (retval) {
        if (retval == MDB_NOTFOUND) {
            return true;
        }
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    retval = mdb_drop(db.p_txn, db.dbi, 1);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    MDB_TXN_COMMIT(db.p_txn);
    return true;
}


/********************************************************************
 * [node]payment preimage
 ********************************************************************/

bool ln_db_preimage_save(ln_db_preimage_t *pPreimage, void *pDb)
{
    ln_lmdb_db_t    db;
    MDB_val         key, data;
    MDB_txn         *p_txn = NULL;
    preimage_info_t info;

    if (pDb) {
        p_txn = ((ln_lmdb_db_t *)pDb)->p_txn;
        MDB_TXN_CHECK_NODE(p_txn);
    }
    if (!preimage_open(&db, p_txn)) {
        LOGE("fail\n");
        return false;
    }

    key.mv_size = LN_SZ_PREIMAGE;
    key.mv_data = pPreimage->preimage;
    data.mv_size = sizeof(info);
    info.amount = pPreimage->amount_msat;
    info.creation = (uint64_t)utl_time_time();
    info.expiry = pPreimage->expiry;
    data.mv_data = &info;
    int retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        preimage_close(&db, p_txn, false);
        return false;
    }

    pPreimage->creation_time = info.creation;
    preimage_close(&db, p_txn, true);
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

        LOGD("remove: ");
        DUMPD(pPreimage, LN_SZ_PREIMAGE);
        key.mv_size = LN_SZ_PREIMAGE;
        key.mv_data = (CONST_CAST uint8_t *)pPreimage;
        retval = mdb_del(db.p_txn, db.dbi, &key, NULL);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            preimage_close(&db, NULL, false);
            return false;
        }
    } else {
        LOGD("remove all\n");
        retval = mdb_drop(db.p_txn, db.dbi, 1);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            preimage_close(&db, NULL, false);
            return false;
        }
    }

    LOGD("success\n");
    preimage_close(&db, NULL, true);
    return true;
}


bool ln_db_preimage_search(ln_db_func_preimage_t pFunc, void *pFuncParam)
{
    bool found = false;
    void *p_cur;
    ln_db_preimage_t preimage;
    bool detect;

    if (!ln_db_preimage_cur_open(&p_cur)) return false;
    while (ln_db_preimage_cur_get(p_cur, &detect, &preimage)) {
        if (!detect) continue;
        if (!(*pFunc)(preimage.preimage, preimage.amount_msat, preimage.expiry, p_cur, pFuncParam)) continue;
        found = true;
        break;
    }
    ln_db_preimage_cur_close(p_cur, false);
    return found;
}


bool ln_db_preimage_del_hash(const uint8_t *pPaymentHash)
{
    return ln_db_preimage_search(preimage_cmp_func, (CONST_CAST uint8_t *)pPaymentHash);
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
}


bool ln_db_preimage_cur_get(void *pCur, bool *pDetect, ln_db_preimage_t *pPreimage)
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

    preimage_info_t *p_info = (preimage_info_t *)data.mv_data;
    LOGD("amount: %" PRIu64"\n", p_info->amount);
    LOGD("time: %lu\n", p_info->creation);
    pPreimage->expiry = p_info->expiry;
    pPreimage->creation_time = p_info->creation;

    if ((p_info->expiry == UINT32_MAX) || (now <= p_info->creation + p_info->expiry)) {
        memcpy(pPreimage->preimage, key.mv_data, key.mv_size);
        pPreimage->amount_msat = p_info->amount;
        *pDetect = true;

        uint8_t hash[BTC_SZ_HASH256];
        ln_payment_hash_calc(hash, pPreimage->preimage);
        LOGD("invoice hash: ");
        DUMPD(hash, BTC_SZ_HASH256);
    } else {
        LOGD("invoice expired del: ");
        DUMPD(key.mv_data, key.mv_size);
        mdb_cursor_del(p_cur->p_cursor, 0);
    }
    return true;
}


bool ln_db_preimage_set_expiry(void *pCur, uint32_t Expiry)
{
    lmdb_cursor_t   *p_cur = (lmdb_cursor_t *)pCur;
    int             retval;
    MDB_val         key, data;

    retval = mdb_cursor_get(p_cur->p_cursor, &key, &data, MDB_GET_CURRENT);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    preimage_info_t *p_info = (preimage_info_t *)data.mv_data;
    LOGD("amount: %" PRIu64"\n", p_info->amount);
    LOGD("time: %lu\n", p_info->creation);

    if (!my_mdb_val_alloccopy(&key, &key)) {
        LOGE("???\n");
        return false;
    }

    preimage_info_t info;
    memcpy(&info, p_info, data.mv_size);
    info.expiry = Expiry;
    data.mv_data = &info;
    data.mv_size = sizeof(preimage_info_t);
    retval = mdb_cursor_put(p_cur->p_cursor, &key, &data, MDB_CURRENT);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        UTL_DBG_FREE(key.mv_data);
        return false;
    }

    LOGD("  change expiry: %" PRIu32 "\n", Expiry);
    UTL_DBG_FREE(key.mv_data);
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

    if (mdb_txn_env(((ln_lmdb_db_t *)pDbParam)->p_txn) == mpEnvNode) {
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
    char        db_name[M_SZ_DB_NAME_STR + 1];

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
    MDB_val key, data;
    ln_lmdb_db_t   db;
    char        db_name[M_SZ_DB_NAME_STR + 1];
    utl_buf_t buf = UTL_BUF_INIT;
    utl_push_t push;

    db.p_txn = ((ln_lmdb_db_t *)pDbParam)->p_txn;
    assert(db.p_txn);

    memcpy(db_name, M_PREF_REVOKED_TX, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);

    int retval = MDB_DBI_OPEN(db.p_txn, db_name, MDB_CREATE, &db.dbi);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
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
        return false;
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
        return false;
    }
    utl_buf_free(&buf);

    key.mv_data = LN_DB_KEY_RVT;
    data.mv_size = sizeof(ln_commit_tx_output_type_t) * pChannel->revoked_num;
    data.mv_data = pChannel->p_revoked_type;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    key.mv_data = LN_DB_KEY_RVS;
    data.mv_size = pChannel->revoked_sec.len;
    data.mv_data = pChannel->revoked_sec.buf;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
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
        return false;
    }

    key.mv_data = LN_DB_KEY_RVC;
    data.mv_size = sizeof(pChannel->revoked_chk);
    data.mv_data = (CONST_CAST uint32_t *)&pChannel->revoked_chk;
    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    if (bUpdate) {
        //save part of channel
        memcpy(db_name, M_PREF_CHANNEL, M_SZ_PREF_STR);
        retval = MDB_DBI_OPEN(db.p_txn, db_name, 0, &db.dbi);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return false;
        }
        retval = channel_save(pChannel, &db);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            return false;
        }
    }
    return true;
}


/********************************************************************
 * [wallet]wallet
 ********************************************************************/

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
bool ln_db_wallet_add(const ln_db_wallet_t *pWallet)
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

    if (pWallet->wit_item_cnt < 2) {
        LOGE("fail: wit_item_cnt < 2\n");
        return false;
    }
    if (pWallet->p_wit_items[0].len != BTC_SZ_PRIVKEY) {
        LOGE("fail: wit0 must be privkey\n");
        return false;
    }

    int         retval;
    MDB_val     key, data;
    ln_lmdb_db_t db;
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
        sizeof(uint8_t);    //datanum
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
    data.mv_data = p_wit_items;
    *p_wit_items = pWallet->type;
    p_wit_items++;
    memcpy(p_wit_items, &pWallet->amount, sizeof(uint64_t));
    p_wit_items += sizeof(uint64_t);
    memcpy(p_wit_items, &pWallet->sequence, sizeof(uint32_t));
    p_wit_items += sizeof(uint32_t);
    memcpy(p_wit_items, &pWallet->locktime, sizeof(uint32_t));
    p_wit_items += sizeof(uint32_t);
    *p_wit_items = (uint8_t)(pWallet->wit_item_cnt);
    p_wit_items++;
    for (uint32_t lp = 0; lp < pWallet->wit_item_cnt; lp++) {
        *p_wit_items = (uint8_t)pWallet->p_wit_items[lp].len;
        p_wit_items++;
        memcpy(p_wit_items, pWallet->p_wit_items[lp].buf, pWallet->p_wit_items[lp].len);
        p_wit_items += pWallet->p_wit_items[lp].len;
    }

    retval = mdb_put(db.p_txn, db.dbi, &key, &data, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(db.p_txn);
        UTL_DBG_FREE(p_wit_items);
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

    int32_t     ver;
    char        wif[BTC_SZ_WIF_STR_MAX + 1] = "";
    char        alias[LN_SZ_ALIAS_STR + 1] = "";
    uint16_t    port = 0;
    uint8_t     genesis[BTC_SZ_HASH256];
    retval = version_check(&db, &ver, wif, alias, &port, genesis);
    if (retval) {
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    btc_keys_t key;
    btc_chain_t chain;
    if (!btc_keys_wif2keys(&key, &chain, wif)) {
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    btc_block_chain_t type = btc_block_get_chain(genesis);
    if (((chain == BTC_MAINNET) && (type == BTC_BLOCK_CHAIN_BTCMAIN)) ||
        ((chain == BTC_TESTNET) && (type == BTC_BLOCK_CHAIN_BTCTEST)) ||
        ((chain == BTC_TESTNET) && (type == BTC_BLOCK_CHAIN_BTCREGTEST))) {
        //ok
    } else {
        MDB_TXN_ABORT(db.p_txn);
        return false;
    }

    if (pMyNodeId) {
        memcpy(pMyNodeId, key.pub, BTC_SZ_PUBKEY);
    }
    if (pBlockChain) {
        *pBlockChain = type;
    }
    MDB_TXN_ABORT(db.p_txn);
    return true;
}


int ln_db_lmdb_get_my_node_id(
    MDB_txn *pTxn, MDB_dbi Dbi, int32_t *pVersion, char *pWif, char *pAlias, uint16_t *pPort, uint8_t *pGenesis)
{
    ln_lmdb_db_t    db;

    db.p_txn = pTxn;
    db.dbi = Dbi;
    return version_check(&db, pVersion, pWif, pAlias, pPort, pGenesis);
}


/********************************************************************
 * others
 ********************************************************************/

ln_lmdb_dbtype_t ln_lmdb_get_dbtype(const char *pDbName)
{
    if (strncmp(pDbName, M_PREF_CHANNEL, M_SZ_PREF_STR) == 0) return LN_LMDB_DBTYPE_CHANNEL;
    if (strncmp(pDbName, M_PREF_SECRET, M_SZ_PREF_STR) == 0) return LN_LMDB_DBTYPE_SECRET;
    if (strncmp(pDbName, M_PREF_HTLC, M_SZ_PREF_STR) == 0) return LN_LMDB_DBTYPE_HTLC;
    if (strncmp(pDbName, M_PREF_REVOKED_TX, M_SZ_PREF_STR) == 0) return LN_LMDB_DBTYPE_REVOKED_TX;
    if (strncmp(pDbName, M_PREF_CHANNEL_BACKUP, M_SZ_PREF_STR) == 0) return LN_LMDB_DBTYPE_CHANNEL_BACKUP;
    if (strcmp(pDbName, M_DBI_WALLET) == 0) return LN_LMDB_DBTYPE_WALLET;
    if (strcmp(pDbName, M_DBI_CNLANNO) == 0) return LN_LMDB_DBTYPE_CNLANNO;
    if (strcmp(pDbName, M_DBI_NODEANNO) == 0) return LN_LMDB_DBTYPE_NODEANNO;
    if (strcmp(pDbName, M_DBI_CNLANNO_INFO) == 0) return LN_LMDB_DBTYPE_CNLANNO_INFO;
    if (strcmp(pDbName, M_DBI_NODEANNO_INFO) == 0) return LN_LMDB_DBTYPE_NODEANNO_INFO;
    if (strcmp(pDbName, M_DBI_ROUTE_SKIP) == 0) return LN_LMDB_DBTYPE_ROUTE_SKIP;
    if (strcmp(pDbName, M_DBI_INVOICE) == 0) return LN_LMDB_DBTYPE_INVOICE;
    if (strcmp(pDbName, M_DBI_PREIMAGE) == 0) return LN_LMDB_DBTYPE_PREIMAGE;
    if (strcmp(pDbName, M_DBI_PAYMENT_HASH) == 0) return LN_LMDB_DBTYPE_PAYMENT_HASH;
    if (strcmp(pDbName, M_DBI_VERSION) == 0) return LN_LMDB_DBTYPE_VERSION;
    return LN_LMDB_DBTYPE_UNKNOWN;
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
        LOGE("fail: already started\n");
        return false;
    }

    if (mPath[0] == '\0') {
        ln_lmdb_set_home_dir(".");
    }
    retval = init_db_env(M_INIT_PARAM_CHANNEL);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
        return false;
    }

    lmdb_cursor_t cur;
    LOGD("channel cursor open\n");
    retval = channel_cursor_open(&cur, true);
    if (retval) {
        LOGE("fail: open\n");
        return false;
    }

    //ここまで来たら成功と見なしてよい //XXX: ???

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

    //rm node and anno directories
    const char *p_cmd = "rm -rf ";
    char cmdline[strlen(p_cmd) + M_DB_PATH_STR_MAX + 1];
    snprintf(cmdline, sizeof(cmdline), "%s%s", p_cmd, ln_lmdb_get_node_db_path());
    system(cmdline);
    snprintf(cmdline, sizeof(cmdline), "%s%s", p_cmd, ln_lmdb_get_anno_db_path());
    system(cmdline);
    return true;
}


void HIDDEN ln_db_copy_channel(ln_channel_t *pOutChannel, const ln_channel_t *pInChannel)
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
        LOGE("ERR: %s\n", mdb_strerror(retval));
        MDB_TXN_ABORT(pDb->p_txn);
        pDb->p_txn = NULL;
        goto LABEL_EXIT;
    }

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
    char        db_name[M_SZ_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];

    uint8_t *OFFSET =
        ((uint8_t *)pChannel) + offsetof(ln_channel_t, update_info) + offsetof(ln_update_info_t, htlcs);

    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);
    memcpy(db_name, M_PREF_HTLC, M_SZ_PREF_STR);

    for (int lp = 0; lp < LN_HTLC_RECEIVED_MAX; lp++) {
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
                mdb_dbi_close(mpEnvChannel, dbi);
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
                mdb_dbi_close(mpEnvChannel, dbi);
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
                mdb_dbi_close(mpEnvChannel, dbi);
                break;
            }
        } else {
            //LOGE("ERR: %s(shared_secret)\n", mdb_strerror(retval));
            retval = 0;     //FALLTHROUGH
        }
        mdb_dbi_close(mpEnvChannel, dbi);
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
    char        db_name[M_SZ_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];

    uint8_t *OFFSET =
        ((uint8_t *)pChannel) + offsetof(ln_channel_t, update_info) + offsetof(ln_update_info_t, htlcs);

    memcpy(db_name, M_PREF_HTLC, M_SZ_PREF_STR);
    utl_str_bin2str(db_name + M_SZ_PREF_STR, pChannel->channel_id, LN_SZ_CHANNEL_ID);

    for (int lp = 0; lp < LN_HTLC_RECEIVED_MAX; lp++) {
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
        char    db_name[M_SZ_DB_NAME_STR + 1];
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
    char    db_name[M_SZ_DB_NAME_STR + M_SZ_HTLC_IDX_STR + 1];

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
 *        |<-- M_SZ_DB_NAME_STR  -->|
 *
 * @attention
 *      - 予め pDbName に M_PREF_HTLC と channel_idはコピーしておくこと
 */
static void channel_htlc_db_name(char *pDbName, int num)
{
    assert(num <= 999);
    snprintf(pDbName + M_SZ_DB_NAME_STR, M_SZ_HTLC_IDX_STR + 1, "%03d", num);
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


static bool channel_search(ln_db_func_cmp_t pFunc, void *pFuncParam, bool bWritable, bool bRestore)
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
    char    name[M_SZ_DB_NAME_STR + 1];
    name[sizeof(name) - 1] = '\0';
    while ((retval = mdb_cursor_get(cur.p_cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        if (key.mv_size != M_SZ_DB_NAME_STR) continue;
        if (memcmp(key.mv_data, M_PREF_CHANNEL, M_SZ_PREF_STR)) continue;

        memcpy(name, key.mv_data, M_SZ_DB_NAME_STR);
        retval = MDB_DBI_OPEN(cur.p_txn, name, 0, &cur.dbi);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            continue;
        }

        memset(p_channel, 0, sizeof(ln_channel_t));
        retval = ln_lmdb_channel_load(p_channel, cur.p_txn, cur.dbi, bRestore);
        if (retval) {
            LOGE("ERR: %s\n", mdb_strerror(retval));
            continue;
        }

        if (!(*pFunc)(p_channel, (void *)&cur, pFuncParam)) {
            ln_term(p_channel);     //falseのみ解放
            continue;
        }

        found = true;
        LOGD("match !\n");
        break;
    }
    channel_cursor_close(&cur, bWritable);
    UTL_DBG_FREE(p_channel);

LABEL_EXIT:
    LOGD("found=%d(writable=%d)\n", found, bWritable);
    return found;
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
    uint8_t key_data[M_SZ_CNLANNO_INFO];

    cnlanno_info_set(key_data, &key, ShortChannelId, LN_DB_CNLANNO_ANNO);
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
    LOGV("short_channel_id=%016" PRIx64 "\n", ShortChannelId);

    MDB_val key, data;
    uint8_t key_data[M_SZ_CNLANNO_INFO];

    cnlanno_info_set(key_data, &key, ShortChannelId, LN_DB_CNLANNO_ANNO);
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
    uint8_t key_data[M_SZ_CNLANNO_INFO];

    cnlanno_info_set(
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
    uint8_t key_data[M_SZ_CNLANNO_INFO];

    cnlanno_info_set(
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
static int cnlanno_cur_load(MDB_cursor *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf, MDB_cursor_op op)
{
    MDB_val key, data;

    int retval = mdb_cursor_get(pCur, &key, &data, op);
    if (retval) {
        if (retval != MDB_NOTFOUND) {
            LOGE("fail: mdb_cursor_get(): %s\n", mdb_strerror(retval));
        }
        return retval;
    }

    char type;
    if (!cnlanno_info_get(&key, pShortChannelId, &type)) {
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
    uint8_t key_data[M_SZ_NODEANNO_INFO];

    nodeanno_info_set(key_data, &key, pNodeId);
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
    uint8_t key_data[M_SZ_NODEANNO_INFO];

    nodeanno_info_set(key_data, &key, pNodeId);
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
        uint8_t key_data[M_SZ_CNLANNO_INFO];

        const char TYPES[] = { LN_DB_CNLANNO_ANNO, LN_DB_CNLANNO_UPD0, LN_DB_CNLANNO_UPD1 };
        for (size_t type = 0; type < ARRAY_SIZE(TYPES); type++) {
            cnlanno_info_set(key_data, &key, pShortChannelIds[lp], TYPES[type]);
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
    uint8_t key_data[M_SZ_NODEANNO_INFO];

    const uint8_t *p_node_id[2];
    p_node_id[0] = msg.p_node_id_1;
    p_node_id[1] = msg.p_node_id_2;
    for (int lp = 0; lp < 2; lp++) {
        nodeanno_info_set(key_data, &key, p_node_id[lp]);
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


static void cnlanno_info_set(uint8_t *pKeyData, MDB_val *pKey, uint64_t ShortChannelId, char Type)
{
    pKey->mv_size = M_SZ_CNLANNO_INFO;
    pKey->mv_data = pKeyData;
    utl_int_unpack_u64be(pKeyData, ShortChannelId);
    pKeyData[LN_SZ_SHORT_CHANNEL_ID] = Type;
}


static bool cnlanno_info_get(MDB_val *pKey, uint64_t *pShortChannelId, char *pType)
{
    if (pKey->mv_size != M_SZ_CNLANNO_INFO) {
        return false;
    }
    *pShortChannelId = utl_int_pack_u64be(pKey->mv_data);
    *pType = *(char *)((uint8_t *)pKey->mv_data + LN_SZ_SHORT_CHANNEL_ID);
    return true;
}


static void nodeanno_info_set(uint8_t *pKeyData, MDB_val *pKey, const uint8_t *pNodeId)
{
    pKey->mv_size = M_SZ_NODEANNO_INFO;
    pKey->mv_data = pKeyData;
    memcpy(pKeyData, pNodeId, BTC_SZ_PUBKEY);
}


//ToDo: 最終的にいらないなら削除
// static bool nodeanno_info_get(MDB_val *pKey, uint8_t *pNodeId)
// {
//     if (pKey->mv_size != M_SZ_NODEANNO_INFO) {
//         return false;
//     }
//     memcpy(pNodeId, pKey->mv_data, BTC_SZ_PUBKEY);
//     return true;
// }


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

    if (pNodeId) {
        int nums = pMdbData->mv_size / BTC_SZ_PUBKEY;
        p_ids = (uint8_t *)UTL_DBG_MALLOC((nums + 1) * BTC_SZ_PUBKEY);
        if (!p_ids) {
            LOGE("fail: ???");
            return false;
        }
        //append
        memcpy(p_ids, pMdbData->mv_data, pMdbData->mv_size);
        memcpy(p_ids + pMdbData->mv_size, pNodeId, BTC_SZ_PUBKEY);
        pMdbData->mv_size += BTC_SZ_PUBKEY;
    } else {
        pMdbData->mv_size = 0;
        p_ids = NULL;
    }

    pMdbData->mv_data = p_ids;
    int retval = mdb_put(mpTxnAnno, pDb->dbi, pMdbKey, pMdbData, 0);
    if (retval) {
        LOGE("ERR: %s\n", mdb_strerror(retval));
    }
    UTL_DBG_FREE(p_ids);
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
        if (lp == nums) continue;

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
        if (type != LN_DB_CNLANNO_UPD0 || type != LN_DB_CNLANNO_UPD1) continue;
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


static void preimage_close(ln_lmdb_db_t *pDb, MDB_txn *pTxn, bool bCommit)
{
    if (pTxn) return;

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

    LOGD("compare preimage : ");
    DUMPD(pPreimage, LN_SZ_PREIMAGE);
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

    LOGD("compare preimage : ");
    DUMPD(pPreimage, LN_SZ_PREIMAGE);
    ln_payment_hash_calc(preimage_hash, pPreimage);

    for (int lp = 0; lp < LN_HTLC_RECEIVED_MAX; lp++) {
        if (memcmp(preimage_hash, param->p_htlcs[lp].payment_hash, BTC_SZ_HASH256)) continue;
        //match
        int retval = mdb_cursor_del(p_cur->p_cursor, 0);
        LOGD("  remove from DB: %s\n", mdb_strerror(retval));
    }
    return false; //continue
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
    int32_t     version = M_DB_VERSION_VAL;

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
 * @retval  0   DBバージョン一致
 */
static int version_check(ln_lmdb_db_t *pDb, int32_t *pVer, char *pWif, char *pNodeName, uint16_t *pPort, uint8_t *pGenesis)
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
    if (*pVer != M_DB_VERSION_VAL) {
        fprintf(stderr, "fail: version mismatch : %d(require %d)\n", *pVer, M_DB_VERSION_VAL);
        LOGE("fail: version mismatch\n");
        return -1;
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
        if (retval) {
            LOGE("fail: %s\n", mdb_strerror(retval));
            LOGE("fail: %s\n", pItems[lp].p_name);
            if (retval != MDB_NOTFOUND) {
                return retval;
            }
        }
        //LOGD("%s: %lu\n", pItems[lp].p_name, pItems[lp].offset);
        memcpy((uint8_t *)pData + pItems[lp].offset, data.mv_data,  pItems[lp].data_len);
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

static int init_db_env(int InitParamIdx)
{
    int retval;

    retval = lmdb_init(InitParamIdx);
    if (retval) {
        LOGE("ERR: (%d)\n", InitParamIdx);
        return retval;
    }

    retval = lmdb_compaction(InitParamIdx);
    if (retval) {
        LOGE("ERR: (%d)\n", InitParamIdx);
        return retval;
    }
    LOGD("DB: OK(%d)\n", InitParamIdx);

    return 0;
}


static int lmdb_init(int InitParamIdx)
{
    int retval;
    const init_param_t *p_param = &INIT_PARAM[InitParamIdx];

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


static int lmdb_compaction(int InitParamIdx)
{
    int                 retval;
    MDB_envinfo         info;
    const init_param_t  *p_param = &INIT_PARAM[InitParamIdx];
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
    snprintf(tmppath, M_DB_PATH_STR_MAX, "%s/tmpdir", mPath);
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

        //開き直す //XXX: why?
        mdb_env_close(*p_param->pp_env);
        retval = lmdb_init(InitParamIdx);
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
