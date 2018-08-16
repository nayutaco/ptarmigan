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


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct ln_feeinfo_t
 *  @brief  FEE情報
 */
typedef struct {
    uint32_t        feerate_per_kw;                 ///< [IN]1000byte辺りのsatoshi
    uint64_t        dust_limit_satoshi;             ///< [IN]dust_limit_satoshi

    uint64_t        htlc_success;                   ///< [CALC]HTLC success Transaction FEE
    uint64_t        htlc_timeout;                   ///< [CALC]HTLC timeout Transaction FEE
    uint64_t        commit;                         ///< [CALC]Commitment Transaction FEE
} ln_feeinfo_t;


/** @struct ln_htlcinfo_t
 *  @brief  HTLC情報
 */
typedef struct {
    ln_htlctype_t           type;                   ///< HTLC種別
    uint32_t                expiry;                 ///< Expiry
    uint64_t                amount_msat;            ///< amount_msat
    const uint8_t           *preimage_hash;         ///< preimageをHASH160したデータ
    ptarm_buf_t             script;                 ///< スクリプト
} ln_htlcinfo_t;


/** @struct ln_tx_cmt_t
 *  @brief  Commitment Transaction生成用情報
 */
typedef struct {
    struct {
        const uint8_t       *txid;              ///< funding txid
        uint32_t            txid_index;         ///< funding txid index
        uint64_t            satoshi;            ///< funding satoshi
        const ptarm_buf_t   *p_script;          ///< funding script
    } fund;

    struct {
        uint64_t            satoshi;            ///< local satoshi
        const ptarm_buf_t   *p_script;          ///< to-local script
    } local;
    struct {
        uint64_t            satoshi;            ///< remote satoshi
        const uint8_t       *pubkey;            ///< remote pubkey(to-remote用)
    } remote;

    uint64_t                obscured;           ///< Obscured Commitment Number(ln_calc_obscured_txnum())
    ln_feeinfo_t            *p_feeinfo;         ///< FEE情報
    ln_htlcinfo_t           **pp_htlcinfo;      ///< HTLC情報ポインタ配列(htlcinfo_num個分)
    uint8_t                 htlcinfo_num;       ///< HTLC数
} ln_tx_cmt_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** Obscured Commitment Number計算
 *
 * @param[in]       pOpenBasePt     payment_basepoint from open_channel
 * @param[in]       pAcceptBasePt   payment_basepoint from accept_channel
 * @return      Obscured Commitment Number
 */
uint64_t HIDDEN ln_calc_obscured_txnum(const uint8_t *pOpenBasePt, const uint8_t *pAcceptBasePt);


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
void HIDDEN ln_create_script_local(ptarm_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay);


/**
 *
 */
bool HIDDEN ln_create_tolocal_tx(ptarm_tx_t *pTx,
                uint64_t Value, const ptarm_buf_t *pScriptPk, uint32_t LockTime,
                const uint8_t *pTxid, int Index, bool bRevoked);


/** HTLC-Timeout Txの出力先スクリプト作成
 *
 * @param[out]      pBuf                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocalDelayedKey    Local Delayed Key[33]
 * @param[in]       LocalDelay          Local Delay(OP_CSV)
 * @note
 *      - ln_create_script_local()と同じ
 */
static inline void ln_create_script_success(ptarm_buf_t *pBuf,
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
static inline void ln_create_script_timeout(ptarm_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay) {
    ln_create_script_local(pBuf, pLocalRevoKey, pLocalDelayedKey, LocalDelay);
}


/** 公開鍵からscriptPubKeyを生成
 *
 * @param[out]      pBuf
 * @param[in]       pPub        公開鍵 or witnessScript
 * @param[in]       Prefix      PTARM_PREF_xxx
 * @retval      true    成功
 * @retval      false   Prefix範囲外
 * @note
 *      - shutdownメッセージ用
 */
bool HIDDEN ln_create_scriptpkh(ptarm_buf_t *pBuf, const ptarm_buf_t *pPub, int Prefix);


/** scriptPubKeyのチェック(P2PKH/P2SH/P2WPKH/P2WSH)
 *
 * @param[in]       pBuf
 * @retval      true    チェックOK
 * @note
 *      - shutdownメッセージ受信用
 */
bool HIDDEN ln_check_scriptpkh(const ptarm_buf_t *pBuf);


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
void HIDDEN ln_create_htlcinfo(ptarm_buf_t *pScript, ln_htlctype_t Type,
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
 * @param[in]       pPrivData
 * @return      true:成功
 */
bool HIDDEN ln_create_commit_tx(ptarm_tx_t *pTx, ptarm_buf_t *pSig, const ln_tx_cmt_t *pCmt, bool Local, const ln_self_priv_t *pPrivData);


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
void HIDDEN ln_create_htlc_tx(ptarm_tx_t *pTx, uint64_t Value, const ptarm_buf_t *pScript,
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
bool HIDDEN ln_sign_htlc_tx(ptarm_tx_t *pTx, ptarm_buf_t *pLocalSig,
                    uint64_t Value,
                    const ptarm_util_keys_t *pKeys,
                    const ptarm_buf_t *pRemoteSig,
                    const uint8_t *pPreImage,
                    const ptarm_buf_t *pWitScript,
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
bool HIDDEN ln_verify_htlc_tx(const ptarm_tx_t *pTx,
                    uint64_t Value,
                    const uint8_t *pLocalPubKey,
                    const uint8_t *pRemotePubKey,
                    const ptarm_buf_t *pLocalSig,
                    const ptarm_buf_t *pRemoteSig,
                    const ptarm_buf_t *pWitScript);

#endif /* LN_SCRIPT_H__ */
