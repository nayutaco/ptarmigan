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
/** @file   ln_db_lmdb.h
 *  @brief  for LMDB implementation
 *  @note
 *      - environment/dbi
 *          -# channel
 *              -# "CN" + channel_id
 *              -# "SE" + channel_id
 *              -# "HT" + channel_id + "ddd"(0 - LN_HTLC_MAX-1)
 *              -# "RV" + channel_id
 *              -# "cn" + channel_id
 *              -# "version"
 *          -# anno
 *              -# "channel_anno"
 *                  - key: short_channel_id + SUFFIX
 *                  - data: timestamp + announcement packet
 *                      - SUFFIX='A': channel_announcement
 *                      - SUFFIX='B': channel_update(lower node_id)
 *                      - SUFFIX='C': channel_update(upper node_id)
 *                  - usage: save announcement packet.
 *              -# "channel_anno_info"
 *                  - key: short_channel_id + SUFFIX("A" or "B" or "C")
 *                  - data: receiving/sending node_ids
 *                  - usage: check already sent.
 *              -# "node_anno"
 *                  - key: node_id
 *                  - data: timestamp + node_announcement packet
 *                  - usage: save node_announcement packet(including own node)
 *                  - memo: skip if "channal_anno_recv" not registered.
 *              -# "node_anno_info"
 *                  - key: node_id
 *                  - data: receiving/sending node_ids
 *                  - usage: check already sent.
 *              -# "channal_anno_recv"
 *                  - key: node_id(channel_announcement's node_id_1 and node_id_2)
 *                  - data: (none)
 *                  - usage: save node_announcement packet if exist node_id.
 *                          this db save on receiving channel_announcement.
 *              -# "channel_owned"
 *                  - key: channel_id(own node)
 *                  - data: (none)
 *                  - usage: for check local channel or not.
 *          -# node
 *              -# "route_skip"
 *                  - key: short_channel_id
 *                  - data: (none)=permanently skip, 0x01=temporary skip, 0x02=routing low priority
 *                  - usage: ignore route if exists and data == skip.
 *              -# "invoice"
 *                  - key: payment_hash
 *                  - data: BOLT11 string + additional amount_msat
 *                  - usage: save at start payment. drop at fail all retry.
 *              -# "preimage"
 *                  - key: preimage
 *                  - data: amount_msat + creation timestamp + expiry block
 *                  - usage: save created invoice
 *              -# "payment_hash"
 *                  - key: vout script
 *                  - data: HTLC type + expiry + payment_hash
 *                  - usage: for revoked transaction close. is this need yet?
 *          -# wallet
 *              -# "wallet"
 *                  - key: outpoint(txid + index)
 *                  - data:
 *                      - [0]: type
 *                      - [1-8]: amount
 *                      - [9-12]: sequence
 *                      - [13-16]: locktime
 *                      - [17]: data num
 *                      - [18-]: len + data
 *                  - usage: closed output for `emptywallet`.
 *          -# forward
 *              -# "AD" + next_short_channel_id
 *                  - key: prev_short_channel_id[8] + prev_htlc_id[8]
 *                  - data: msg of update_add_htlc
 *              -# "DL" + next_short_channel_id
 *                  - key: prev_short_channel_id[8] + prev_htlc_id[8]
 *                  - data: msg of update_fulfill_htlc/update_fail_htlc
 *          -# payment
 *              -# "payment"
 *                  - key: "payment_id"
 *                  - data: next_payment_id
 *              -# "shared_secrets"
 *                  - key: payment_id
 *                  - data: shared_secrets
 *              -# "route"
 *                  - key: payment_id
 *                  - data: route
 */
#ifndef LN_DB_LMDB_H__
#define LN_DB_LMDB_H__

#include "lmdb.h"

#include "ln.h"
#include "ln_db.h"


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/********************************************************************
 * LMDB
 ********************************************************************/

//key名
#define LN_DB_KEY_RVV               "rvv"           ///< [revoked]vout
#define LN_DB_KEY_RVW               "rvw"           ///< [revoked]witness
#define LN_DB_KEY_RVT               "rvt"           ///< [revoked]HTLC type
#define LN_DB_KEY_RVS               "rvs"           ///< [revoked]script
#define LN_DB_KEY_RVN               "rvn"           ///< [revoked]num
#define LN_DB_KEY_RVC               "rvc"           ///< [revoked]count

#define LN_DB_KEY_VERSION           "version"       ///< [version]version
#define LN_DB_KEY_NODEID            "node_id"        ///< [version]自node_id

#define LN_DB_KEY_LEN(key)          (sizeof(key) - 1)   ///< key長
#define LN_DB_KEY_RLEN              (3)                 ///< [revoked]key長

#define LN_DB_DBI_ROUTE_SKIP        "route_skip"
#define LN_DB_ROUTE_SKIP_TEMP       ((uint8_t)1)    // 一時的にskip
#define LN_DB_ROUTE_SKIP_WORK       ((uint8_t)2)    // 一時的にrouteに含める


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef enum {
    LN_LMDB_DB_TYPE_UNKNOWN,
    LN_LMDB_DB_TYPE_CHANNEL,
    LN_LMDB_DB_TYPE_SECRET,
    LN_LMDB_DB_TYPE_HTLC,
    LN_LMDB_DB_TYPE_REVOKED_TX,
    LN_LMDB_DB_TYPE_WALLET,
    LN_LMDB_DB_TYPE_CNLANNO,
    LN_LMDB_DB_TYPE_NODEANNO,
    LN_LMDB_DB_TYPE_CNLANNO_INFO,
    LN_LMDB_DB_TYPE_NODEANNO_INFO,
    LN_LMDB_DB_TYPE_ROUTE_SKIP,
    LN_LMDB_DB_TYPE_INVOICE,
    LN_LMDB_DB_TYPE_PREIMAGE,
    LN_LMDB_DB_TYPE_PAYMENT_HASH,
    LN_LMDB_DB_TYPE_VERSION,
    LN_LMDB_DB_TYPE_FORWARD_ADD,
    LN_LMDB_DB_TYPE_FORWARD_DEL,
    LN_LMDB_DB_TYPE_CLOSED_CHANNEL,
    LN_LMDB_DB_TYPE_CLOSED_SECRET,
    LN_LMDB_DB_TYPE_CLOSED_HTLC,
    LN_LMDB_DB_TYPE_CLOSED_REVOKED_TX,
    LN_LMDB_DB_TYPE_PAYMENT,
    LN_LMDB_DB_TYPE_SHARED_SECRETS,
    LN_LMDB_DB_TYPE_ROUTE,
    LN_LMDB_DB_TYPE_PAYMENT_INVOICE,
} ln_lmdb_db_type_t;


typedef struct {
    MDB_txn     *p_txn;
    MDB_dbi     dbi;
} ln_lmdb_db_t;


/** @typedef    lmdb_cursor_t
 *  @brief      lmdbのcursor情報。外部へはvoid*でキャストして渡す。
 *  @attention
 *      - キャストしてln_lmdb_db_tと同等に使用できる(逆はできない)
 */
typedef struct {
    //ln_lmdb_db_t
    MDB_txn     *p_txn;
    MDB_dbi     dbi;

    //cursor
    MDB_cursor  *p_cursor;
} lmdb_cursor_t;


/**************************************************************************
 * public functions
 **************************************************************************/

/** LMDBパス設定
 *
 * LMDBのenvironmentを格納するパスを指定する。
 * 指定したパスの中に、dbchannel/ と dbnode/ を作成する。
 *
 * @param[in]   pPath       DBを作成するディレクトリ
 */
bool ln_lmdb_set_home_dir(const char *pPath);


/** LMDB channelパス取得
 *
 * @return  channelパス
 */
const char *ln_lmdb_get_channel_db_path(void);


/** LMDB nodeパス取得
 *
 * @return  nodeパス
 */
const char *ln_lmdb_get_node_db_path(void);


/** LMDB annoパス取得
 *
 * @return  annoパス
 */
const char *ln_lmdb_get_anno_db_path(void);


/** LMDB walletパス取得
 *
 * @return  walletパス
 */
const char *ln_lmdb_get_wallet_db_path(void);


/** LMDB forwardパス取得
 *
 * @return  forwardパス
 */
const char *ln_lmdb_get_forward_db_path(void);


/** LMDB paymentパス取得
 *
 * @return  paymentパス
 */
const char *ln_lmdb_get_payment_db_path(void);


/** LMDB closedパス取得
 *
 * @return  closedパス
 * @note
 *  - closed envをchannelごとにするため、一時的に使用停止する。
 *  - これにともない、showdbでもclosed channel情報を見えないようにしている。
 */
//const char *ln_lmdb_get_closed_db_path(void);


/** channel情報読込み
 *
 * @param[out]      pChannel
 * @param[in]       txn
 * @param[in]       pdbi
 * @param[in]       bRestore        true:restore keys from basepoint
 * @retval      0       成功
 * @attention
 *      -
 *      - 新規 pChannel に読込を行う場合は、事前に #ln_init()を行っておくこと(seedはNULLでよい)
 */
int ln_lmdb_channel_load(ln_channel_t *pChannel, MDB_txn *pTxn, MDB_dbi Dbi, bool bRestore);


/**
 *
 */
int ln_lmdb_cnlanno_cur_load(MDB_cursor *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf);


/**
 *
 *
 */
int ln_lmdb_nodeanno_cur_load(MDB_cursor *pCur, utl_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId);


ln_lmdb_db_type_t ln_lmdb_get_db_type(const MDB_env *pEnv, const char *pDbName);


int ln_db_lmdb_get_my_node_id(MDB_txn *pTxn, MDB_dbi Dbi, int32_t *pVersion, char *pWif, char *pAlias, uint16_t *pPort, uint8_t *pGenesis);


bool ln_lmdb_wallet_search(lmdb_cursor_t *pCur, ln_db_func_wallet_t pWalletFunc, void *pFuncParam);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_DB_LMDB_H__ */
