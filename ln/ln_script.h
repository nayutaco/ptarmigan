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
/** @file   ln_script.h
 *  @brief  ln_script
 */
#ifndef LN_SCRIPT_H__
#define LN_SCRIPT_H__

#include "ln_derkey_ex.h"
#include "ln_commit_tx_util.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

/** To-Localスクリプト作成
 *
 * @param[out]      pWitScript                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocaledKey         Local Delayed Key[33]
 * @param[in]       LocalToSelfDelay    Local ToSelfDelay(OP_CSV)
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
bool HIDDEN ln_script_create_to_local(
    utl_buf_t *pWitScript,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pLocaledKey,
    uint32_t LocalToSelfDelay);


/** 公開鍵からscriptPubKeyを生成
 *
 * @param[out]      pScriptPk
 * @param[in]       pPub        公開鍵 or witnessScript
 * @param[in]       Pref        BTC_PREF_xxx
 * @retval      true    成功
 * @retval      false   Prefix範囲外
 * @note
 *      - shutdownメッセージ用
 */
bool HIDDEN ln_script_scriptpk_create(utl_buf_t *pScriptPk, const utl_buf_t *pPub, int Pref);


/** scriptPubKeyのチェック(P2PKH/P2SH/P2WPKH/P2WSH)
 *
 * @param[in]       pScriptPk
 * @retval      true    チェックOK
 * @note
 *      - shutdownメッセージ受信用
 */
bool HIDDEN ln_script_scriptpk_check(const utl_buf_t *pScriptPk);


/** HTLC Txスクリプト生成
 *
 * @param[out]      pScript             生成したスクリプト
 * @param[in]       Type                HTLC種別
 * @param[in]       pLocalHtlcKey       Local htlckey[33]
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pRemoteHtlcKey      Remote htlckey[33]
 * @param[in]       pPaymentHash        payment_hash[32]
 * @param[in]       CltvExpiry          cltv_expiry(HTLC-Success用)
 */
bool HIDDEN ln_script_create_htlc(
    utl_buf_t *pScript,
    ln_commit_tx_output_type_t Type,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pRemoteHtlcKey,
    const uint8_t *pPaymentHash,
    uint32_t CLtvExpiry);


#endif /* LN_SCRIPT_H__ */
