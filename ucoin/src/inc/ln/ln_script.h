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
 *  @brief  [LN]スクリプト
 *  @author ueno@nayuta.co
 */
#ifndef LN_SCRIPT_H__
#define LN_SCRIPT_H__


#include "ln_local.h"


/** Obscured Commitment Number計算
 *
 * @param[in]       pLocalBasePt
 * @param[in]       pRemoteBasePt
 * @return      Obscured Commitment Number
 */
uint64_t HIDDEN ln_calc_obscured_txnum(const uint8_t *pLocalBasePt, const uint8_t *pRemoteBasePt);


/** To-Localスクリプト作成
 *
 * @param[out]      pBuf                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocalDelayedKey    Local Delayed Key[33]
 * @param[in]       LocalDelay          Local Delay(OP_CSV)
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
void HIDDEN ln_create_script_local(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay);


/**
 *
 */
bool HIDDEN ln_create_tolocal_tx(ucoin_tx_t *pTx,
                uint64_t Value, const ucoin_buf_t *pScriptPk, uint32_t LockTime,
                const uint8_t *pTxid, int Index, bool bRevoked);


/**
 *
 */
bool HIDDEN ln_sign_tolocal_tx(ucoin_tx_t *pTx, ucoin_buf_t *pSig,
                    uint64_t Value,
                    const ucoin_util_keys_t *pKeys,
                    const ucoin_buf_t *pWitScript, bool bRevoked);


/** HTLC-Timeout Txの出力先スクリプト作成
 *
 * @param[out]      pBuf                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocalDelayedKey    Local Delayed Key[33]
 * @param[in]       LocalDelay          Local Delay(OP_CSV)
 * @note
 *      - ln_create_script_local()と同じ
 */
static inline void ln_create_script_success(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay) {
    ln_create_script_local(pBuf, pLocalRevoKey, pLocalDelayedKey, LocalDelay);
}


/** HTLC-Success Txの出力先スクリプト作成
 *
 * @param[out]      pBuf                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocalDelayedKey    Local Delayed Key[33]
 * @param[in]       LocalDelay          Local Delay(OP_CSV)
 * @note
 *      - ln_create_script_local()と同じ
 */
static inline void ln_create_script_timeout(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay) {
    ln_create_script_local(pBuf, pLocalRevoKey, pLocalDelayedKey, LocalDelay);
}


/** 公開鍵からscriptPubKeyを生成
 *
 * @param[out]      pBuf
 * @param[in]       pPub        公開鍵 or witnessScript
 * @param[in]       Prefix      UCOIN_PREF_xxx
 * @retval      true    成功
 * @retval      false   Prefix範囲外
 * @note
 *      - shutdownメッセージ用
 */
bool HIDDEN ln_create_scriptpkh(ucoin_buf_t *pBuf, const ucoin_buf_t *pPub, int Prefix);


/** scriptPubKeyのチェック(P2PKH/P2SH/P2WPKH/P2WSH)
 *
 * @param[in]       pBuf
 * @retval      true    チェックOK
 * @note
 *      - shutdownメッセージ受信用
 */
bool HIDDEN ln_check_scriptpkh(const ucoin_buf_t *pBuf);


/** HTLC情報初期化
 *
 *
 */
void HIDDEN ln_htlcinfo_init(ln_htlcinfo_t *pHtlcInfo);


/** HTLC情報初期化
 *
 *
 */
void HIDDEN ln_htlcinfo_free(ln_htlcinfo_t *pHtlcInfo);


/** HTLC Txスクリプト生成
 *
 * @param[out]      pScript             生成したスクリプト
 * @param[in]       Type                HTLC種別
 * @param[in]       pLocalHtlcKey       Local htlckey[33]
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pRemoteHtlcKey      Remote htlckey[33]
 * @param[in]       pPaymentHash        payment_hash[32]
 * @param[in]       Expiry              expiry(HTLC-Success用)
 */
void HIDDEN ln_create_htlcinfo(ucoin_buf_t *pScript, ln_htlctype_t Type,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteHtlcKey,
                    const uint8_t *pPaymentHash,
                    uint32_t Expiry);


/** FEE計算
 *
 * feerate_per_kw, dust_limit_satoshiおよびHTLC情報から、HTLCおよびcommit txのFEEを算出する。
 *
 * @param[in,out]   pFeeInfo    FEE情報
 * @param[in]       ppHtlcInfo  HTLC情報ポインタ配列
 * @param[in]       Num         HTLC数
 * @return      actual FEE
 *
 * @note
 *      - pFeeInfoにfeerate_per_kwとdust_limit_satoshiを代入しておくこと
 */
uint64_t HIDDEN ln_fee_calc(ln_feeinfo_t *pFeeInfo, const ln_htlcinfo_t **ppHtlcInfo, int Num);


/** Commitment Transaction作成
 *
 * @param[out]      pTx         TX情報
 * @param[out]      pSig        local署名
 * @param[in]       pCmt        Commitment Transaction情報
 * @param[in]       Local       true:LocalがFEEを払う
 * @return      true:成功
 */
bool HIDDEN ln_create_commit_tx(ucoin_tx_t *pTx, ucoin_buf_t *pSig, const ln_tx_cmt_t *pCmt, bool Local);


/** Offered/Receveid HTLC Transaction作成
 *
 * @param[out]      pTx         TX情報
 * @param[in]       Value       vout amount
 * @param[in]       pScript     vout P2WSHスクリプト
 * @param[in]       Type        pScriptタイプ(LN_HTLCTYPE_xxx)
 * @param[in]       CltvExpiry  locktime(TypeがOffered HTLCの場合のみ)
 * @param[in]       pTxid       vin TXID
 * @param[in]       Index       vin index
 */
void HIDDEN ln_create_htlc_tx(ucoin_tx_t *pTx, uint64_t Value, const ucoin_buf_t *pScript,
                ln_htlctype_t Type, uint32_t CltvExpiry, const uint8_t *pTxid, int Index);


/** Offered/Receveid HTLC Transaction署名
 *
 * @param[in,out]   pTx
 * @param[out]      pLocalSig       署名
 * @param[in]       Value           INPUTのamount
 * @param[in]       pKeys           CommitTxのlocal署名用
 * @param[in]       pRemoteSig      commit_tx相手からの署名
 * @param[in]       pPreImage       非NULL:payment_preimageでHTLC-Successとして署名, NULL:HTLC-Timeoutとして署名
 * @param[in]       pWitScript      voutとなるスクリプト
 * @param[in]       HtlcSign        HTLCSIGN_xxx
 * @return      true:成功
 */
bool HIDDEN ln_sign_htlc_tx(ucoin_tx_t *pTx, ucoin_buf_t *pLocalSig,
                    uint64_t Value,
                    const ucoin_util_keys_t *pKeys,
                    const ucoin_buf_t *pRemoteSig,
                    const uint8_t *pPreImage,
                    const ucoin_buf_t *pWitScript,
                    ln_htlcsign_t HtlcSign);


/** Offered/Receveid HTLC Transaction署名verify
 *
 * @param[in]       pTx
 * @param[in]       Value           INPUTのamount
 * @param[in]       pLocalPubKey
 * @param[in]       pRemotePubKey
 * @param[in]       pLocalSig
 * @param[in]       pRemoteSig      commit_tx相手からの署名
 * @param[in]       pWitScript      voutとなるスクリプト
 * @return      true:成功
 */
bool HIDDEN ln_verify_htlc_tx(const ucoin_tx_t *pTx,
                    uint64_t Value,
                    const uint8_t *pLocalPubKey,
                    const uint8_t *pRemotePubKey,
                    const ucoin_buf_t *pLocalSig,
                    const ucoin_buf_t *pRemoteSig,
                    const ucoin_buf_t *pWitScript);

#endif /* LN_SCRIPT_H__ */
