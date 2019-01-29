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
 *  @brief  [LN]秘密鍵管理
 */
#ifndef LN_SIGNER_H__
#define LN_SIGNER_H__

#include "ln.h"


/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

/**
 *
 */
bool HIDDEN ln_signer_init(ln_channel_t *pChannel);


/**
 *
 */
void HIDDEN ln_signer_term(ln_channel_t *pChannel);


/** チャネル用鍵生成
 *
 * @param[in,out]   pChannel    チャネル情報
 * @note
 *      - open_channel/accept_channelの送信前に使用する想定
 */
bool HIDDEN ln_signer_create_channel_keys(ln_channel_t *pChannel);


/** local per_commitment_secret更新およびstorage_next_index更新
 *
 * @param[in,out]   pChannel    チャネル情報
 * @note
 *      - indexを進める
 */
bool HIDDEN ln_signer_keys_update_per_commitment_secret(ln_channel_t *pChannel);


/** local per_commitment_secret更新(storage_next_index指定)
 *
 */
bool HIDDEN ln_signer_keys_update_force(ln_channel_t *pChannel, uint64_t Index);


/** 1つ前のper_commit_secret取得
 *
 * @param[in,out]   pChannel    チャネル情報
 * @param[out]      pSecret         1つ前のper_commit_secret
 */
bool HIDDEN ln_signer_create_prev_per_commit_secret(const ln_channel_t *pChannel, uint8_t *pSecret, uint8_t *pPerCommitPt);


/**
 *
 */
bool HIDDEN ln_signer_get_revoke_secret(const ln_channel_t *pChannel, btc_keys_t *pKeys, const uint8_t *pPerCommit, const uint8_t *pRevokedSec);


/** P2WSH署名 - Phase2: 署名作成
 *
 * @param[out]      pSig
 * @param[in]       pTxHash
 * @param[in]       pPrivKeys
 * @param[in]       Index
 * @return      true:成功
 * @note
 *      - 中身は #btc_sig_sign()
 */
bool HIDDEN ln_signer_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const ln_derkey_local_keys_t *pKeys, int Index);


/** P2WSH署名 - Phase2: 署名作成(key指定)
 *
 * @param[out]      pSig
 * @param[in]       pTxHash
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - 中身は #btc_sig_sign()
 */
bool HIDDEN ln_signer_p2wsh_force(utl_buf_t *pSig, const uint8_t *pTxHash, const btc_keys_t *pKeys);


/** P2WPKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - #btc_init()の設定で署名する
 */
bool HIDDEN ln_signer_p2wpkh(btc_tx_t *pTx, int Index, uint64_t Value, const btc_keys_t *pKeys);


/** 署名(R/S)
 *
 * @param[out]      pRS         署名結果
 * @param[in]       pTxHash     ハッシュ値
 * @param[in]       pKeys
 * @param[in]       Index
 * @return      true:成功
 * @note
 *      - #btc_init()の設定で署名する
 */
bool HIDDEN ln_signer_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const ln_derkey_local_keys_t *pKeys, int Index);


/** to_local script署名用鍵取得
 *
 */
bool HIDDEN ln_signer_tolocal_key(const ln_channel_t *pChannel, btc_keys_t *pKey, bool bRevoked);


bool HIDDEN ln_signer_toremote_key(const ln_channel_t *pChannel, btc_keys_t *pKey);
bool HIDDEN ln_signer_htlc_localkey(const ln_channel_t *pChannel, btc_keys_t *pKey);
bool HIDDEN ln_signer_htlc_remotekey(const ln_channel_t *pChannel, btc_keys_t *pKey);


/**
 *
 */
bool HIDDEN ln_signer_tolocal_tx(const ln_channel_t *pChannel, btc_tx_t *pTx,
                    utl_buf_t *pSig,
                    uint64_t Value,
                    const utl_buf_t *pWitScript, bool bRevoked);

#endif /* LN_SIGNER_H__ */
