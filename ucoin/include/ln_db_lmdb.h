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
 *  @author ueno@nayuta.co
 */
#ifndef LN_DB_LMDB_H__
#define LN_DB_LMDB_H__

#include "lmdb.h"

#include "ln.h"


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

#define LNDB_DBDIR              "./dbucoin"
#define LNDB_SELFENV_DIR        "/dbucoin_self"
#define LNDB_NODEENV_DIR        "/dbucoin_node"
#define LNDB_SELFENV            LNDB_DBDIR LNDB_SELFENV_DIR     ///< LMDB名(self)
#define LNDB_NODEENV            LNDB_DBDIR LNDB_NODEENV_DIR     ///< LMDB名(self以外)


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef enum {
    LN_LMDB_DBTYPE_UNKNOWN,
    LN_LMDB_DBTYPE_SELF,
    LN_LMDB_DBTYPE_ADD_HTLC,
    LN_LMDB_DBTYPE_REVOKED,
    LN_LMDB_DBTYPE_BKSELF,
    LN_LMDB_DBTYPE_CHANNEL_ANNO,
    LN_LMDB_DBTYPE_NODE_ANNO,
    LN_LMDB_DBTYPE_CHANNEL_ANNOINFO,
    LN_LMDB_DBTYPE_NODE_ANNOINFO,
    LN_LMDB_DBTYPE_ANNO_SKIP,
    LN_LMDB_DBTYPE_ANNO_INVOICE,
    LN_LMDB_DBTYPE_PREIMAGE,
    LN_LMDB_DBTYPE_PAYHASH,
    LN_LMDB_DBTYPE_VERSION,
} ln_lmdb_dbtype_t;


typedef struct {
    MDB_txn     *txn;
    MDB_dbi     dbi;
} ln_lmdb_db_t;


/**************************************************************************
 * public functions
 **************************************************************************/

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
int ln_lmdb_annocnl_cur_load(MDB_cursor *cur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, ucoin_buf_t *pBuf);


/**
 *
 *
 */
int ln_lmdb_annonod_cur_load(MDB_cursor *cur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId);


ln_lmdb_dbtype_t ln_lmdb_get_dbtype(const char *pDbName);


int ln_db_lmdb_get_mynodeid(MDB_txn *txn, MDB_dbi dbi, char *wif, char *alias, uint16_t *p_port, uint8_t *genesis);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_DB_LMDB_H__ */
