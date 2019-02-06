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
 *          -# dbptarm_chnl
 *              -# "CN" + channel_id
 *              -# "SE" + channel_id
 *              -# "HT" + channel_id + "ddd"(0〜LN_HTLC_MAX-1)
 *              -# "RV" + channel_id
 *              -# "cn" + channel_id
 *              -# "version"
 *          -# dbptarm_anno
 *              -# "channel_anno"
 *                  - key: short_channel_id + SUFFIX
 *                  - data: timestamp + announcement packet
 *                      - SUFFIX='A': channel_announcement
 *                      - SUFFIX='B': channel_update(lower node_id)
 *                      - SUFFIX='C': channel_update(upper node_id)
 *                  - usage: save announcement packet.
 *              -# "channel_annoinfo"
 *                  - key: short_channel_id + SUFFIX("A" or "B" or "C")
 *                  - data: receiving/sending node_ids
 *                  - usage: check already sent.
 *              -# "node_anno"
 *                  - key: node_id
 *                  - data: timestamp + node_announcement packet
 *                  - usage: save node_announcement packet(including own node)
 *                  - memo: skip if "chananno_recv" not registered.
 *              -# "node_annoinfo"
 *                  - key: node_id
 *                  - data: receiving/sending node_ids
 *                  - usage: check already sent.
 *              -# "chananno_recv"
 *                  - key: node_id(channel_announcement's node_id_1 and node_id_2)
 *                  - data: (none)
 *                  - usage: save node_announcement packet if exist node_id.
 *                          this db save on receiving channel_announcement.
 *              -# "annoown"
 *                  - key: channel_id(own node)
 *                  - data: (none)
 *                  - usage: for check our channel or not.
 *          -# dbptarm_node
 *              -# "route_skip"
 *                  - key: short_channel_id
 *                  - data: (none)=permanently skip, 0x01=temporary skip, 0x02=routing low priority
 *                  - usage: ignore route if exists and data == skip.
 *              -# "route_invoice"
 *                  - key: payment_hash
 *                  - data: BOLT11 string + additional amount_msat
 *                  - usage: save at start payment. drop at fail all retry.
 *              -# "preimage"
 *                  - key: preimage
 *                  - data: amount_msat + creation timestamp + expiry block
 *                  - usage: save created invoice
 *              -# "payhash"
 *                  - key: vout script
 *                  - data: HTLC type + expiry + payment_hash
 *                  - usage: for revoked transaction close. is this need yet?
 *          -# dbptarm_walt
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
#define LNDBK_RVV               "rvv"           ///< [revoked]vout
#define LNDBK_RVW               "rvw"           ///< [revoked]witness
#define LNDBK_RVT               "rvt"           ///< [revoked]HTLC type
#define LNDBK_RVS               "rvs"           ///< [revoked]script
#define LNDBK_RVN               "rvn"           ///< [revoked]num
#define LNDBK_RVC               "rvc"           ///< [revoked]count
#define LNDBK_VER               "ver"           ///< [version]version
#define LNDBK_NODEID            "mynodeid"      ///< [version]自node_id

#define LNDBK_LEN(key)          (sizeof(key) - 1)       ///< key長
#define LNDBK_RLEN              (3)                     ///< [revoked]key長

#define LNDB_DBI_ROUTE_SKIP     "route_skip"
#define LNDB_ROUTE_SKIP_TEMP    ((uint8_t)1)    // 一時的にskip
#define LNDB_ROUTE_SKIP_WORK    ((uint8_t)2)    // 一時的にrouteに含める


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef enum {
    LN_LMDB_DBTYPE_UNKNOWN,
    LN_LMDB_DBTYPE_CHANNEL,
    LN_LMDB_DBTYPE_SECRET,
    LN_LMDB_DBTYPE_ADD_HTLC,
    LN_LMDB_DBTYPE_REVOKED,
    LN_LMDB_DBTYPE_BKCHANNEL,
    LN_LMDB_DBTYPE_WALLET,
    LN_LMDB_DBTYPE_ANNO_CNL,
    LN_LMDB_DBTYPE_ANNO_NODE,
    LN_LMDB_DBTYPE_ANNOINFO_CNL,
    LN_LMDB_DBTYPE_ANNOINFO_NODE,
    LN_LMDB_DBTYPE_ROUTE_SKIP,
    LN_LMDB_DBTYPE_INVOICE,
    LN_LMDB_DBTYPE_PREIMAGE,
    LN_LMDB_DBTYPE_PAYHASH,
    LN_LMDB_DBTYPE_VERSION,
} ln_lmdb_dbtype_t;


typedef struct {
    MDB_txn     *txn;
    MDB_dbi     dbi;
} ln_lmdb_db_t;


/** @typedef    lmdb_cursor_t
 *  @brief      lmdbのcursor情報。外部へはvoid*でキャストして渡す。
 *  @attention
 *      - キャストしてln_lmdb_db_tと同等に使用できる(逆はできない)
 */
typedef struct {
    //ln_lmdb_db_t
    MDB_txn     *txn;
    MDB_dbi     dbi;

    //cursor
    MDB_cursor  *cursor;
} lmdb_cursor_t;


/**************************************************************************
 * public functions
 **************************************************************************/

/** LMDBパス設定
 *
 * LMDBのenvironmentを格納するパスを指定する。
 * 指定したパスの中に、dbchnl/ と dbnode/ を作成する。
 *
 * @param[in]   pPath       DBを作成するディレクトリ
 */
void ln_lmdb_set_path(const char *pPath);


/** LMDB channelパス取得
 *
 * @return  dbptarm_chnlパス
 */
const char *ln_lmdb_get_chnlpath(void);


/** LMDB nodeパス取得
 *
 * @return  dbptarm_nodeパス
 */
const char *ln_lmdb_get_nodepath(void);


/** LMDB annoパス取得
 *
 * @return  dbptarm_annoパス
 */
const char *ln_lmdb_get_annopath(void);


/** LMDB waltパス取得
 *
 * @return  dbptarm_waltパス
 */
const char *ln_lmdb_get_waltpath(void);


/** channel情報読込み
 *
 * @param[out]      pChannel
 * @param[in]       txn
 * @param[in]       pdbi
 * @retval      0       成功
 * @attention
 *      -
 *      - 新規 pChannel に読込を行う場合は、事前に #ln_init()を行っておくこと(seedはNULLでよい)
 */
int ln_lmdb_channel_load(ln_channel_t *pChannel, MDB_txn *txn, MDB_dbi dbi);


/** closeしたDB("cn")を出力
 *
 */
void ln_lmdb_bkchannel_show(MDB_txn *txn, MDB_dbi dbi);


/**
 *
 */
int ln_lmdb_annocnl_cur_load(MDB_cursor *cur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf);


/**
 *
 *
 */
int ln_lmdb_annonod_cur_load(MDB_cursor *cur, utl_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId);


ln_lmdb_dbtype_t ln_lmdb_get_dbtype(const char *pDbName);


int ln_db_lmdb_get_mynodeid(MDB_txn *txn, MDB_dbi dbi, int32_t *ver, char *wif, char *alias, uint16_t *p_port, uint8_t *genesis);


bool ln_lmdb_wallet_search(lmdb_cursor_t *pCur, ln_db_func_wallet_t pWalletFunc, void *pFuncParam);


/** DBで保存している対象のデータだけコピーする
 *
 * @param[out]  pOutChannel
 * @param[in]   pInChannel
 */
void HIDDEN ln_db_copy_channel(ln_channel_t *pOutChannel, const ln_channel_t *pInChannel);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_DB_LMDB_H__ */
