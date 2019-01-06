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
/** @file   btc_crypto.h
 *  @brief  btc_crypto
 */
#ifndef BTC_CRYPTO_H__
#define BTC_CRYPTO_H__

#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>


/**************************************************************************
 * typedefs
 **************************************************************************/

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_HASH160          (20)                ///< サイズ:HASH160
#define BTC_SZ_HASH256          (32)                ///< サイズ:HASH256
#define BTC_SZ_HASH_MAX         (BTC_SZ_HASH256)    ///< サイズ:Hashの最大値


/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * package variables
 **************************************************************************/

/**************************************************************************
 * prototypes (btc_hash)
 **************************************************************************/

/** RIPMED-160計算
 *
 * @param[out]      pRipemd160      演算結果(BTC_SZ_RIPEMD160以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void btc_md_ripemd160(uint8_t *pRipemd160, const uint8_t *pData, uint16_t Len);


/** SHA256計算
 *
 * @param[out]      pSha256         演算結果(BTC_SZ_SHA256以上のサイズが必要)
 * @param[in]       pData           元データ
 * @param[in]       Len             pData長
 */
void btc_md_sha256(uint8_t *pSha256, const uint8_t *pData, uint16_t Len);


/** HASH160計算
 *
 * @param[out]      pHash160        演算結果(BTC_SZ_HASH160以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void btc_md_hash160(uint8_t *pHash160, const uint8_t *pData, uint16_t Len);


/** HASH256計算
 *
 * @param[out]      pHash256        演算結果(BTC_SZ_HASH256以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void btc_md_hash256(uint8_t *pHash256, const uint8_t *pData, uint16_t Len);


/** HASH256計算(連結)
 *
 * @param[out]      pHash256        演算結果(BTC_SZ_HASH256以上のサイズが必要)
 * @param[in]       pData1          対象データ1
 * @param[in]       Len1            pData1長
 * @param[in]       pData2          対象データ2
 * @param[in]       Len2            pData2長
 */
void btc_md_sha256cat(uint8_t *pSha256, const uint8_t *pData1, uint16_t Len1, const uint8_t *pData2, uint16_t Len2);


/**************************************************************************
 * prototypes (???)
 **************************************************************************/

/** 圧縮公開鍵を非圧縮公開鍵展開
 *
 * @param[out]  point       非圧縮公開鍵座標
 * @param[in]   pPubKey     圧縮公開鍵
 * @return      0...正常
 *
 * @note
 *      - https://gist.github.com/flying-fury/6bc42c8bb60e5ea26631
 */
int btc_util_ecp_point_read_binary2(void *pPoint, const uint8_t *pPubKey);


/**
 * pPubKeyOut = pPubKeyIn + pA * G
 *
 */
int btc_util_ecp_muladd(uint8_t *pResult, const uint8_t *pPubKeyIn, const void *pA);


/**
 * pResult = pPubKey * pMul
 *
 */
bool btc_util_mul_pubkey(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pMul, int MulLen);


/** 圧縮された公開鍵をkeypairに展開する
 *
 * @param[in]       pPubKey     圧縮された公開鍵
 * @return      0   成功
 * @note
 *      - https://bitcointalk.org/index.php?topic=644919.0
 *      - https://gist.github.com/flying-fury/6bc42c8bb60e5ea26631
 */
int btcl_util_set_keypair(void *pKeyPair, const uint8_t *pPubKey);


/**************************************************************************
 * prototypes (btc_rng)
 **************************************************************************/

/** init random generator
 *
 * @return          true        success
 */
bool btc_rng_init(void);


/** generate random data
 *
 * @param[out]      pData       random data
 * @param[in]       Len         data length
 * @return          true        success
 */
bool btc_rng_rand(uint8_t *pData, uint16_t Len);


/** free random generator
 *
 */
void btc_rng_free(void);


#endif /* BTC_CRYPTO_H__ */
