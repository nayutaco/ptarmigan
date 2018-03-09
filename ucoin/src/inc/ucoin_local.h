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
/** @file   ucoin_local.h
 *  @brief  libucoin内インターフェース
 *  @author ueno@nayuta.co
 */
#ifndef UCOIN_LOCAL_H__
#define UCOIN_LOCAL_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

static inline int tid() {
    return (int)syscall(SYS_gettid);
}

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "mbedtls/sha256.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/ecp.h"
#ifdef UCOIN_USE_RNG
#include "mbedtls/ctr_drbg.h"
#endif  //UCOIN_USE_RNG

#include "ucoin.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define HIDDEN __attribute__((visibility("hidden")))
#define CONST_CAST      /* const外しキャストを検索しやすくするため */

#define LNL_SZ_2OF2             (1 + 34 + 34 + 2)           ///< OP_m 21 [pub1] 21 [pub2] OP_n OP_CHKMULTISIG
#define LNL_SZ_WITPROG_WPKH     (2 + UCOIN_SZ_HASH160)      ///< P2WPKHのwitnessProgramサイズ
#define LNL_SZ_WITPROG_WSH      (2 + UCOIN_SZ_HASH256)      ///< P2WSHのwitnessProgramサイズ

#define OP_0                    (0x00)
#define OP_HASH160              (0xa9)
#define OP_EQUAL                (0x87)
#define OP_EQUALVERIFY          (0x88)
#define OP_PUSHDATA1            (0x4c)
#define OP_PUSHDATA2            (0x4d)
#define OP_CHECKSIG             (0xac)
#define OP_CHECKMULTISIG        (0xae)
#define OP_CHECKLOCKTIMEVERIFY  (0xb1)
#define OP_CHECKSEQUENCEVERIFY  (0xb2)
#define OP_DROP                 (0x75)
#define OP_2DROP                (0x6d)
#define OP_DUP                  (0x76)
#define OP_IF                   (0x63)
#define OP_NOTIF                (0x64)
#define OP_ELSE                 (0x67)
#define OP_ENDIF                (0x68)
#define OP_SWAP                 (0x7c)
#define OP_ADD                  (0x93)
#define OP_SIZE                 (0x82)
#define OP_x                    (0x50)  //0x50はOP_RESERVEDだが、ここでは足し算して使う用途
#define OP_1                    (0x51)
#define OP_2                    (0x52)
#define OP_16                   (0x60)

#define SIGHASH_ALL             (0x01)

#define VARINT_1BYTE_MAX        (0xfc)
#define VARINT_3BYTE_MIN        (0xfd)


/**************************************************************************
 * macro functions
 **************************************************************************/

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))  ///< 配列要素数

#define PRINTOUT        stdout

#ifdef UCOIN_DEBUG
#define DEBUGOUT        stderr

/// @def    DBG_PRINTF(format, ...)
/// @brief  デバッグ出力(UCOIN_DEBUG定義時のみ有効)
#define DBG_PRINTF(format, ...) {fprintf(DEBUGOUT, "%lu (%d)[%s:%d]", (unsigned long)time(NULL), (int)tid(), __func__, (int)__LINE__); fprintf(DEBUGOUT, format, ##__VA_ARGS__);}
#define DBG_PRINTF2(format, ...) {fprintf(DEBUGOUT, format, ##__VA_ARGS__);}
/// @def    DUMPBIN(dt,ln)
/// @brief  ダンプ出力(UCOIN_DEBUG定義時のみ有効)
#define DUMPBIN(dt,ln)      ucoin_util_dumpbin(DEBUGOUT, dt, ln, true)
#define DUMPTXID(dt)        {ucoin_util_dumptxid(DEBUGOUT, dt); fprintf(DEBUGOUT, "\n");}
#else //UCOIN_DEBUG
#define DBG_PRINTF(...)     //none
#define DBG_PRINTF2(...)     //none
#define DUMPBIN(...)
#endif //UCOIN_DEBUG


#ifdef UCOIN_DEBUG_MEM
#define M_MALLOC(a)         ucoin_dbg_malloc(a); DBG_PRINTF("M_MALLOC:%d\n", ucoin_dbg_malloc_cnt());       ///< malloc(カウント付き)(UCOIN_DEBUG_MEM定義時のみ有効)
#define M_REALLOC(a,b)      ucoin_dbg_realloc(a,b); DBG_PRINTF("M_REALLOC:%d\n", ucoin_dbg_malloc_cnt());   ///< realloc(カウント付き)(UCOIN_DEBUG_MEM定義時のみ有効)
#define M_CALLOC(a,b)       ucoin_dbg_calloc(a,b); DBG_PRINTF("M_CALLOC:%d\n", ucoin_dbg_malloc_cnt());       ///< realloc(カウント付き)(UCOIN_DEBUG_MEM定義時のみ有効)
#define M_FREE(ptr)         { ucoin_dbg_free(ptr); ptr = NULL; DBG_PRINTF("M_FREE:%d\n", ucoin_dbg_malloc_cnt()); }     ///< free(カウント付き)(UCOIN_DEBUG_MEM定義時のみ有効)
#else   //UCOIN_DEBUG_MEM
#define M_MALLOC            malloc
#define M_REALLOC           realloc
#define M_CALLOC            calloc
#define M_FREE(ptr)         { free(ptr); ptr = NULL; }
#endif  //UCOIN_DEBUG_MEM


/**************************************************************************
 * package variables
 **************************************************************************/

extern uint8_t  mPref[UCOIN_PREF_MAX];
extern bool     mNativeSegwit;
#ifdef UCOIN_USE_RNG
extern mbedtls_ctr_drbg_context mRng;
#endif  //UCOIN_USE_RNG


/**************************************************************************
 * prototypes
 **************************************************************************/

/** RIPMED160計算
 *
 * @param[out]      pRipemd160      演算結果(UCOIN_SZ_RIPEMD160以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
static inline void ucoin_util_ripemd160(uint8_t *pRipemd160, const uint8_t *pData, uint16_t Len) {
    mbedtls_ripemd160(pData, Len, pRipemd160);
}


/** SHA256計算
 *
 * @param[out]      pSha256         演算結果(UCOIN_SZ_SHA256以上のサイズが必要)
 * @param[in]       pData           元データ
 * @param[in]       Len             pData長
 */
static inline void ucoin_util_sha256(uint8_t *pSha256, const uint8_t *pData, uint16_t Len) {
    mbedtls_sha256(pData, Len, pSha256, 0);
}


/** HASH160計算
 *
 * @param[out]      pHash160        演算結果(UCOIN_SZ_HASH160以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void ucoin_util_hash160(uint8_t *pHash160, const uint8_t *pData, uint16_t Len);


/** HASH256計算
 *
 * @param[out]      pHash256        演算結果(UCOIN_SZ_HASH256以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void ucoin_util_hash256(uint8_t *pHash256, const uint8_t *pData, uint16_t Len);


/** HASH256計算(連結)
 *
 * @param[out]      pHash256        演算結果(UCOIN_SZ_HASH256以上のサイズが必要)
 * @param[in]       pData1          対象データ1
 * @param[in]       Len1            pData1長
 * @param[in]       pData2          対象データ2
 * @param[in]       Len2            pData2長
 */
void ucoin_util_sha256cat(uint8_t *pSha256, const uint8_t *pData1, uint16_t Len1, const uint8_t *pData2, uint16_t Len2);

int ucoin_util_set_keypair(mbedtls_ecp_keypair *pKeyPair, const uint8_t *pPubKey);
int ucoin_util_ecp_point_read_binary2(mbedtls_ecp_point *point, const uint8_t *pPubKey);
void ucoin_util_create_pkh2wpkh(uint8_t *pWPubKeyHash, const uint8_t *pPubKeyHash);
void ucoin_util_create_scriptpk(ucoin_buf_t *pBuf, const uint8_t *pPubKeyHash, int Prefix);
bool ucoin_util_keys_pkh2addr(char *pAddr, const uint8_t *pPubKeyHash, uint8_t Prefix);
int ucoin_util_ecp_muladd(uint8_t *pResult, const uint8_t *pPubKeyIn, const mbedtls_mpi *pA);
bool ucoin_util_mul_pubkey(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pMul, int MulLen);
void ucoin_util_generate_shared_secret(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pPrivKey);
bool ucoin_util_calc_mac(uint8_t *pMac, const uint8_t *pKeyStr, int StrLen,  const uint8_t *pMsg, int MsgLen);
bool ucoin_util_create_tx(ucoin_buf_t *pBuf, const ucoin_tx_t *pTx, bool enableSegWit);
void ucoin_util_add_vout_pub(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey, uint8_t Pref);
void ucoin_util_add_vout_pkh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash, uint8_t Pref);
int ucoin_util_get_varint_len(int Len);
int ucoin_util_set_varint_len(uint8_t *pData, const uint8_t *pOrg, uint16_t Len, bool isScript);

#ifdef UCOIN_DEBUG_MEM
void* ucoin_dbg_malloc(size_t);
void* ucoin_dbg_realloc(void*, size_t);
void* ucoin_dbg_calloc(size_t, size_t);
void  ucoin_dbg_free(void*);
#endif  //UCOIN_DEBUG_MEM


#endif /* UCOIN_LOCAL_H__ */
