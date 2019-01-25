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
 *  @brief  showdb用
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
    LN_LMDB_DBTYPE_SELF,
    LN_LMDB_DBTYPE_SECRET,
    LN_LMDB_DBTYPE_ADD_HTLC,
    LN_LMDB_DBTYPE_REVOKED,
    LN_LMDB_DBTYPE_BKSELF,
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
 * 指定したパスの中に、dbself/ と dbnode/ を作成する。
 *
 * @param[in]   pPath       DBを作成するディレクトリ
 */
void ln_lmdb_set_path(const char *pPath);


/** LMDB selfパス取得
 *
 * @return  dbptarm_selfパス
 */
const char *ln_lmdb_get_selfpath(void);


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
 * @param[out]      self
 * @param[in]       txn
 * @param[in]       pdbi
 * @retval      0       成功
 * @attention
 *      -
 *      - 新規 self に読込を行う場合は、事前に #ln_self_init()を行っておくこと(seedはNULLでよい)
 */
int ln_lmdb_self_load(ln_self_t *self, MDB_txn *txn, MDB_dbi dbi);


/** closeしたDB("cn")を出力
 *
 */
void ln_lmdb_bkself_show(MDB_txn *txn, MDB_dbi dbi);


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
 * @param[out]  pOutSelf    コピー先
 * @param[in]   pInSelf     コピー元
 */
void HIDDEN ln_db_copy_channel(ln_self_t *pOutSelf, const ln_self_t *pInSelf);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_DB_LMDB_H__ */
