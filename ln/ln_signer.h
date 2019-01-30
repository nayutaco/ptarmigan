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
/** @file   ln_signer.h
 *  @brief  ln_signer
 */
#ifndef LN_SIGNER_H__
#define LN_SIGNER_H__

#include "btc_tx.h"

#include "ln_derkey_ex.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

/** sign
 *
 * @param[out]      pSig
 * @param[in]       pSigHash
 * @param[in]       pLocalKeys
 * @param[in]       Index
 * @return      true:成功
 * @note
 *      - 中身は #btc_sig_sign()
 */
bool HIDDEN ln_signer_sign(utl_buf_t *pSig, const uint8_t *pSigHash, const ln_derkey_local_keys_t *pLocalKeys, int Index);


/** sign
 *
 * @param[out]      pSig
 * @param[in]       pSigHash
 * @param[in]       pKey
 * @return      true:成功
 * @note
 *      - 中身は #btc_sig_sign()
 */
bool HIDDEN ln_signer_sign_2(utl_buf_t *pSig, const uint8_t *pSigHash, const btc_keys_t *pKey);


/** P2WPKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pKey
 * @return      true:成功
 * @note
 *      - #btc_init()の設定で署名する
 */
bool HIDDEN ln_signer_p2wpkh(btc_tx_t *pTx, int Index, uint64_t Value, const btc_keys_t *pKey);


/** 署名(R/S)
 *
 * @param[out]      pRS         署名結果
 * @param[in]       pSigHash     ハッシュ値
 * @param[in]       pLocalKeys
 * @param[in]       Index
 * @return      true:成功
 * @note
 *      - #btc_init()の設定で署名する
 */
bool HIDDEN ln_signer_sign_rs(uint8_t *pRS, const uint8_t *pSigHash, const ln_derkey_local_keys_t *pLocalKeys, int Index);


/** to_local script署名用鍵取得
 *
 */
bool HIDDEN ln_signer_to_local_key(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys,
    const uint8_t *pRevokedPerCommitSecOrNull);


bool HIDDEN ln_signer_to_remote_key(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys);
bool HIDDEN ln_signer_htlc_localkey(btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys);
bool HIDDEN ln_signer_htlc_remotekey(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys);


/**
 *
 */
bool HIDDEN ln_signer_revocation_privkey(btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const uint8_t *pPerCommitPt, const uint8_t *pPerCommitSec);


/**
 *
 */
#if 0
bool HIDDEN ln_signer_to_local_tx(
    btc_tx_t *pTx, utl_buf_t *pSig,
    const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys,
    uint64_t Value, const utl_buf_t *pWitScript, bool bRevoked);
#endif


#endif /* LN_SIGNER_H__ */
