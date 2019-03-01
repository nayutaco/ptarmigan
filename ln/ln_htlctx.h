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
/** @file   ln_htlctx.h
 *  @brief  ln_htlctx
 */
#ifndef LN_HTLCTX_H__
#define LN_HTLCTX_H__

#include <stdint.h>
#include <stdbool.h>

#include "utl_common.h"

#include "btc_tx.h"

#include "ln_commit_tx_util.h"

//XXX: unit test


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct ln_htlctx_sig_type_t
 *  @brief  ln_htlctx_sig_type_t
 */
typedef enum {
    LN_HTLCTX_SIG_NONE,              ///< 未設定
    LN_HTLCTX_SIG_TIMEOUT_SUCCESS,   ///< HTLC Timeout/Success
    LN_HTLCTX_SIG_REMOTE_OFFER,      ///< 相手が送信したcommit_txのOffered HTLC
    LN_HTLCTX_SIG_REMOTE_RECV,       ///< 相手が送信したcommit_txのReceived HTLC
    LN_HTLCTX_SIG_REVOKE_RECV,       ///< revoked transactionのreceived HTLC output
    LN_HTLCTX_SIG_REVOKE_OFFER,      ///< revoked transactionのoffered HTLC output
} ln_htlctx_sig_type_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** Offered/Receveid HTLC Transaction作成
 *
 * @param[out]      pTx         TX情報
 * @param[in]       Value       vout amount
 * @param[in]       pWitScript  vout P2WSHスクリプト
 * @param[in]       Type        pScriptタイプ(LN_COMMIT_TX_OUTPUT_TYPE_xxx)
 * @param[in]       CltvExpiry  locktime(TypeがOffered HTLCの場合のみ)
 * @param[in]       pTxid       vin TXID
 * @param[in]       Index       vin index
 */
bool HIDDEN ln_htlctx_create(
    btc_tx_t *pTx,
    uint64_t Value,
    const utl_buf_t *pWitScript,
    ln_commit_tx_output_type_t Type,
    uint32_t CltvExpiry,
    const uint8_t *pTxid,
    int Index);


/** Offered/Receveid HTLC Transaction署名
 *
 * @param[in,out]   pTx
 * @param[out]      pSig            signature
 * @param[in]       Value           INPUTのamount
 * @param[in]       pKeys           CommitTxのlocal署名用
 * @param[in]       pRemoteSig      commit_tx相手からの署名
 * @param[in]       pPreimage       非NULL:payment_preimageでHTLC-Successとして署名, NULL:HTLC-Timeoutとして署名
 * @param[in]       pWitScript      voutとなるスクリプト
 * @param[in]       HtlcSigType     #ln_htlctx_sig_type_t
 * @return      true:成功
 */
bool HIDDEN ln_htlctx_sign(
    btc_tx_t *pTx,
    utl_buf_t *pSig,
    uint64_t Value,
    const btc_keys_t *pKeys,
    const utl_buf_t *pWitScript);


bool HIDDEN ln_htlctx_sign_rs(
    btc_tx_t *pTx,
    uint8_t *pSig,
    uint64_t Value,
    const btc_keys_t *pKeys,
    const utl_buf_t *pWitScript);


bool HIDDEN ln_htlctx_set_vin0(
    btc_tx_t *pTx,
    const utl_buf_t *pLocalSig,
    const utl_buf_t *pRemoteSig,
    const uint8_t *pPreimage,
    const btc_keys_t *pRevoKeys,
    const utl_buf_t *pWitScript,
    ln_htlctx_sig_type_t HtlcSigType);


bool HIDDEN ln_htlctx_set_vin0_rs(
    btc_tx_t *pTx,
    const uint8_t *pLocalSig,
    const uint8_t *pRemoteSig,
    const uint8_t *pPreimage,
    const btc_keys_t *pRevoKeys,
    const utl_buf_t *pWitScript,
    ln_htlctx_sig_type_t HtlcSigType);


/** Offered/Receveid HTLC Transaction署名verify
 *
 * @param[in]       pTx
 * @param[in]       Value           INPUTのamount
 * @param[in]       pLocalPubKey
 * @param[in]       pLocalSig
 * @param[in]       pRemotePubKey
 * @param[in]       pRemoteSig      commit_tx相手からの署名
 * @param[in]       pWitScript      voutとなるスクリプト
 * @return      true:成功
 */
bool HIDDEN ln_htlctx_verify(const btc_tx_t *pTx,
    uint64_t Value,
    const uint8_t *pLocalPubKey,
    const utl_buf_t *pLocalSig,
    const uint8_t *pRemotePubKey,
    const utl_buf_t *pRemoteSig,
    const utl_buf_t *pWitScript);


#endif /* LN_HTLCTX_H__ */
