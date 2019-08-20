/*
 *  Copyright (C) 2017 Ptarmigan Project
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
/** @file   ln_derkey.c
 *  @brief  Key Derivation
 *  @note
 *      - https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation
 */
#ifndef LN_DERKEY_H__
#define LN_DERKEY_H__

#include "btc_keys.h"


/********************************************************************
 * macros
 ********************************************************************/

#define PER_COMMIT_SECRET_PAIR_NUM  (49)

// https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#per-commitment-secret-requirements
#define LN_SECRET_INDEX_INIT            (UINT64_C(0xffffffffffff))      ///< per-commitment secret生成用indexの初期値


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct ln_derkey_storage_t
 *  @brief  per-commitment secret storage
 *      https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#efficient-per-commitment-secret-storage
 */
typedef struct {
    struct {
        uint8_t     secret[BTC_SZ_PRIVKEY];     ///< secret
        uint64_t    index;                      ///< index
    } storage[PER_COMMIT_SECRET_PAIR_NUM];
    //uint64_t    next_index;
} ln_derkey_storage_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** key導出
 *
 * @param[out]      pPubKey         pubkey
 * @param[in]       pBasePoint      BasePoint
 * @param[in]       pPerCommitPoint per Commitment Point
 */
bool HIDDEN ln_derkey_pubkey(uint8_t *pPubKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint);


/** private key導出
 *
 * @param[out]      pPrivKey        privatekey
 * @param[in]       pBasePoint      BasePoint
 * @param[in]       pPerCommitPoint per Commitment Point
 * @param[in]       pBaseSecret     Base Secret Point
 */
bool HIDDEN ln_derkey_privkey(uint8_t *pPrivKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint,
            const uint8_t *pBaseSecret);


/** revocation key導出
 *
 * @param[out]      pPubKey         Revocation key
 * @param[in]       pBasePoint      BasePoint
 * @param[in]       pPerCommitPoint per Commitment Point
 */
bool HIDDEN ln_derkey_revocation_pubkey(uint8_t *pPubKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint);


/** revocation private key導出
 *
 * @param[out]      pPrivKey            Revocation privatekey
 * @param[in]       pBasePoint          BasePoint
 * @param[in]       pPerCommitPoint     per Commitment Point
 * @param[in]       pBaseSecret         Base Secret Point
 * @param[in]       pPerCommitSecret    per Commitment Secret Point
 */
bool HIDDEN ln_derkey_revocation_privkey(uint8_t *pPrivKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint,
            const uint8_t *pBaseSecret, const uint8_t *pPerCommitSecret);


/** per-commitment secret生成
 *
 * @param[out]      pSecret
 * @param[in]       pSeed(32byte)
 * @param[in]       Index(下位6byte使用)
 */
void HIDDEN ln_derkey_storage_create_secret(uint8_t *pSecret, const uint8_t *pSeed, uint64_t Index);


/** per-commitment secret storage初期化
 *
 * @param[out]      pStorage
 */
void HIDDEN ln_derkey_storage_init(ln_derkey_storage_t *pStorage);


/** per-commitment secret storage追加
 *
 * @param[in,out]   pStorage
 * @param[in]       pSecret
 * @param[in]       Index
 * @return      true    成功
 */
bool HIDDEN ln_derkey_storage_insert_secret(ln_derkey_storage_t *pStorage, const uint8_t *pSecret, uint64_t Index);


/** per-commitment secret取得
 *
 * @param[out]      pSecret
 * @param[in]       pStorage
 * @param[in]       Index
 * @return      true    成功
 */
bool HIDDEN ln_derkey_storage_get_secret(uint8_t *pSecret, const ln_derkey_storage_t *pStorage, uint64_t Index);


#endif /* LN_DERKEY_H__ */
