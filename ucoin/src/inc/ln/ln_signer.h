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
 *  @author ueno@nayuta.co
 */
#ifndef LN_SIGNER_H__
#define LN_SIGNER_H__

#include "ln_local.h"

/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

/**
 *
 */
void HIDDEN ln_signer_init(ln_self_t *self, const uint8_t *pSeed);


/**
 *
 */
void HIDDEN ln_signer_term(ln_self_t *self);


/** チャネル用鍵生成
 *
 * @param[in,out]   self        チャネル情報
 * @retval  true    成功
 * @note
 *      - open_channel/accept_channelの送信前に使用する想定
 */
bool HIDDEN ln_signer_create_channelkeys(ln_self_t *self);


/** per_commitment_secret更新
 *
 * @param[in,out]   self        チャネル情報
 * @note
 *      - indexを進める
 */
void HIDDEN ln_signer_update_percommit_secret(ln_self_t *self);


/**
 *
 */
void HIDDEN ln_signer_keys_update(ln_self_t *self, int64_t Offset);


/**
 *
 */
void HIDDEN ln_signer_keys_update_force(ln_self_t *self, uint64_t Index);


/** 1つ前のper_commit_secret取得
 *
 * @param[in,out]   self            チャネル情報
 * @param[out]      pSecret         1つ前のper_commit_secret
 */
void HIDDEN ln_signer_get_prevkey(const ln_self_t *self, uint8_t *pSecret);


/**
 *
 */
void HIDDEN ln_signer_get_secret(const ln_self_t *self, ucoin_util_keys_t *pKeys, int MsgFundIdx, const uint8_t *pPerCommit);


/**
 *
 */
void HIDDEN ln_signer_get_revokesec(const ln_self_t *self, ucoin_util_keys_t *pKeys, const uint8_t *pPerCommit, const uint8_t *pRevokedSec);


/** P2WSH署名 - Phase2: 署名作成
 *
 * @param[out]      pSig
 * @param[in]       pTxHash
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - #ucoin_util_sign_p2wsh()
 *      - 中身は #ucoin_tx_sign()
 */
bool HIDDEN ln_signer_p2wsh(ucoin_buf_t *pSig, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys);


/** P2WPKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - #ucoin_init()の設定で署名する
 */
bool HIDDEN ln_signer_p2wpkh(ucoin_tx_t *pTx, int Index, uint64_t Value, const ucoin_util_keys_t *pKeys);


/** 署名(R/S)
 *
 * @param[out]      pRS         署名結果
 * @param[in]       pTxHash     ハッシュ値
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - #ucoin_init()の設定で署名する
 */
bool HIDDEN ln_signer_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys);


/**
 *
 */
bool HIDDEN ln_signer_tolocal_tx(const ln_self_t *self, ucoin_tx_t *pTx,
                    uint64_t Value,
                    const ucoin_buf_t *pWitScript, bool bRevoked);

#endif /* LN_SIGNER_H__ */
