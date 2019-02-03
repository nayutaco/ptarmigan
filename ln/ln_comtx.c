/*
 *  Copyright (C) 2019, Nayuta, Inc. All Rights Reserved
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
/** @file   ln_comtx.c
 *  @brief  commitment transaction
 */

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utl_str.h"
#include "utl_buf.h"
#include "utl_dbg.h"

#include "btc_crypto.h"
#include "btc_script.h"
#include "btc_sw.h"

#include "ln_db.h"
#include "ln_script.h"
#include "ln_signer.h"
#include "ln_normalope.h"
#include "ln_local.h"
#include "ln_wallet.h"
#include "ln_comtx.h"
#include "ln_comtx_util.h"
#include "ln_htlctx.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/** #search_preimage()用
 *
 */
typedef struct {
    uint8_t         *image;             ///< [out]preimage
    const uint8_t   *hash;              ///< [in]payment_hash
    bool            b_closing;          ///< true:一致したexpiryをUINT32_MAXに変更する
} preimage_t;


/********************************************************************
 * prototypes
 ********************************************************************/

//common
static bool create_htlc_info_and_amount(
    const ln_update_add_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pOurMsat,
    uint64_t *pTheirMsat,
    bool bLocal);


//local
static bool create_local_htlc_info_and_amount(
    const ln_update_add_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pOurMsat,
    uint64_t *pTheirMsat);
static bool create_local_set_vin0_and_verify(
    btc_tx_t *pTxCommit,
    const ln_funding_tx_t *pFundTx,
    const uint8_t *pSigLocal,
    const uint8_t *pSigRemote);
static bool create_local_spent(
    ln_channel_t *pChannel,
    ln_close_force_t *pClose,
    const uint8_t *pHtlcSigs,
    uint8_t HtlcSigsNum,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pFeeInfo,
    uint32_t ToSelfDelay);
static bool create_local_spent_to_local(
    const ln_channel_t *pChannel,
    btc_tx_t *pTxToLocal,
    const utl_buf_t *pBufWs,
    uint64_t Amount,
    uint32_t VoutIdx,
    uint32_t ToSelfDelay);
static bool create_local_verify_htlc(
    const ln_channel_t *pChannel,
    btc_tx_t *pTx,
    const uint8_t *pHtlcSig,
    const utl_buf_t *pScript,
    uint64_t Amount);
static bool create_local_spent_htlc(
    const ln_channel_t *pChannel,
    btc_tx_t *pCloseTxHtlc,
    btc_tx_t *pTxHtlc,
    utl_push_t *pPush,
    uint64_t Amount,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint32_t ToSelfDelay);


//remote
static bool create_remote_htlc_info_and_amount(
    const ln_update_add_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pOurMsat,
    uint64_t *pTheirMsat);
static bool create_remote_spent(
    const ln_channel_t *pChannel,
    ln_commit_tx_t *pCommit,
    ln_close_force_t *pClose,
    uint8_t *pHtlcSigs,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pFeeInfo);
static bool create_remote_spent_htlc(
    ln_commit_tx_t *pCommit,
    btc_tx_t *pTxHtlcs,
    uint8_t *pHtlcSigs,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    const uint8_t *pRemoteSig,
    uint64_t Fee,
    uint8_t HtlcNum,
    uint32_t VoutIdx,
    const uint8_t *pPayHash,
    bool bClosing);

static bool search_preimage(uint8_t *pPreimage, const uint8_t *pPayHash, bool bClosing);
static bool search_preimage_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);


/********************************************************************
 * public functions
 ********************************************************************/

bool HIDDEN ln_comtx_create_local(
    ln_channel_t *pChannel,
    ln_close_force_t *pClose,
    const uint8_t *pHtlcSigs,
    uint8_t HtlcSigsNum,
    uint64_t CommitNum,
    uint32_t ToSelfDelay,
    uint64_t DustLimitSat)
{
    LOGD("BEGIN\n");

    bool ret = false;

    ln_comtx_htlc_info_t **pp_htlc_info = 0;
    utl_buf_t buf_ws = UTL_BUF_INIT;
    uint8_t local_sig[LN_SZ_SIGNATURE];
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint16_t cnt = 0;

    ln_comtx_base_fee_info_t fee_info;
    ln_comtx_t comtx;
    uint64_t our_msat = pChannel->our_msat;
    uint64_t their_msat = pChannel->their_msat;

    //to_local
    if (!ln_script_create_to_local(
        &buf_ws,
        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        ToSelfDelay)) return false;

    //HTLC info(amount)
    pp_htlc_info = (ln_comtx_htlc_info_t **)UTL_DBG_MALLOC(sizeof(ln_comtx_htlc_info_t*) * LN_HTLC_MAX);
    if (!pp_htlc_info) return false;
    if (!create_local_htlc_info_and_amount(pChannel->cnl_add_htlc, pp_htlc_info, &cnt, &our_msat, &their_msat)) goto LABEL_EXIT;

    //HTLC info(script)
    for (int lp = 0; lp < cnt; lp++) {
        if (!ln_script_create_htlc(
            &pp_htlc_info[lp]->wit_script,
            pp_htlc_info[lp]->type,
            pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
            pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
            pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
            pp_htlc_info[lp]->payment_hash,
            pp_htlc_info[lp]->cltv_expiry)) goto LABEL_EXIT;
    }

    //print amount
    LOGD("-------\n");
    LOGD("our_msat   %" PRIu64 " --> %" PRIu64 "\n", pChannel->our_msat, our_msat);
    LOGD("their_msat %" PRIu64 " --> %" PRIu64 "\n", pChannel->their_msat, their_msat);
    for (int lp = 0; lp < cnt; lp++) {
        LOGD("  [%d] %" PRIu64 " (%s)\n", lp, pp_htlc_info[lp]->amount_msat, (pp_htlc_info[lp]->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //fee
    fee_info.feerate_per_kw = pChannel->feerate_per_kw;
    fee_info.dust_limit_satoshi = DustLimitSat;
    ln_comtx_base_fee_calc(&fee_info, (const ln_comtx_htlc_info_t **)pp_htlc_info, cnt);

    //commitment transaction
    LOGD("local commitment_number=%" PRIu64 "\n", CommitNum);
    comtx.fund.txid = ln_funding_txid(pChannel);
    comtx.fund.txid_index = ln_funding_txindex(pChannel);
    comtx.fund.satoshi = pChannel->funding_tx.funding_satoshis;
    comtx.fund.p_wit_script = &pChannel->funding_tx.wit_script;
    comtx.to_local.satoshi = LN_MSAT2SATOSHI(our_msat);
    comtx.to_local.p_wit_script = &buf_ws;
    comtx.to_remote.satoshi = LN_MSAT2SATOSHI(their_msat);
    comtx.to_remote.pubkey = pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_PUBKEY];
    comtx.obscured_commit_num = ln_comtx_calc_obscured_commit_num(pChannel->obscured_commit_num_mask, CommitNum);
    comtx.p_base_fee_info = &fee_info;
    comtx.pp_htlc_info = pp_htlc_info;
    comtx.htlc_info_num = cnt;
    if (!ln_comtx_create_rs(&tx_commit, local_sig, &comtx, ln_is_funder(pChannel), &pChannel->keys_local)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //2-of-2 verify
    if (!create_local_set_vin0_and_verify(&tx_commit, &pChannel->funding_tx, local_sig, pChannel->commit_tx_local.remote_sig)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    if (!btc_tx_txid(&tx_commit, pChannel->commit_tx_local.txid)) goto LABEL_EXIT;
    LOGD("local commit_txid: ");
    TXIDD(pChannel->commit_tx_local.txid);
    if (!create_local_spent(
        pChannel,
        pClose,
        pHtlcSigs,
        HtlcSigsNum,
        &tx_commit,
        &buf_ws,
        (const ln_comtx_htlc_info_t **)pp_htlc_info,
        &fee_info,
        ToSelfDelay)) goto LABEL_EXIT;

    if (pClose) {
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
    } else {
        btc_tx_free(&tx_commit);
    }

    ret = true;

LABEL_EXIT:
    utl_buf_free(&buf_ws);
    if (pp_htlc_info) {
        for (int lp = 0; lp < cnt; lp++) {
            ln_comtx_htlc_info_free(pp_htlc_info[lp]);
            UTL_DBG_FREE(pp_htlc_info[lp]);
        }
        UTL_DBG_FREE(pp_htlc_info);
    }
    return ret;
}


bool ln_comtx_create_remote(
    const ln_channel_t *pChannel,
    ln_commit_tx_t *pCommitRemote,
    ln_close_force_t *pClose,
    uint8_t **ppHtlcSigs,
    uint64_t CommitNum)
{
    LOGD("BEGIN\n");

    bool ret;
    utl_buf_t buf_ws = UTL_BUF_INIT;
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint16_t cnt = 0;

    ln_comtx_base_fee_info_t fee_info;
    ln_comtx_t comtx;
    uint64_t our_msat = pChannel->their_msat;
    uint64_t their_msat = pChannel->our_msat;

    //To-Local
    ln_script_create_to_local(
        &buf_ws,
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pChannel->commit_tx_remote.to_self_delay);

    //HTLC info(amount)
    ln_comtx_htlc_info_t **pp_htlc_info = (ln_comtx_htlc_info_t **)UTL_DBG_MALLOC(sizeof(ln_comtx_htlc_info_t*) * LN_HTLC_MAX);
    create_remote_htlc_info_and_amount(pChannel->cnl_add_htlc, pp_htlc_info, &cnt, &our_msat, &their_msat);

    //HTLC info(script)
    for (int lp = 0; lp < cnt; lp++) {
        ln_script_create_htlc(&pp_htlc_info[lp]->wit_script,
        pp_htlc_info[lp]->type,
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
        pp_htlc_info[lp]->payment_hash,
        pp_htlc_info[lp]->cltv_expiry);
#ifdef LN_UGLY_NORMAL //XXX:
        //payment_hash, type, expiry保存
        utl_buf_t vout = UTL_BUF_INIT;
        btc_script_p2wsh_create_scriptpk(&vout, &pp_htlc_info[lp]->wit_script);
        ln_db_phash_save(
            pp_htlc_info[lp]->payment_hash,
            vout.buf,
            pp_htlc_info[lp]->type,
            pp_htlc_info[lp]->cltv_expiry);
        utl_buf_free(&vout);
#endif  //LN_UGLY_NORMAL
    }

    LOGD("-------\n");
    LOGD("(remote)our_msat   %" PRIu64 " --> %" PRIu64 "\n", pChannel->their_msat, our_msat);
    LOGD("(remote)their_msat %" PRIu64 " --> %" PRIu64 "\n", pChannel->our_msat, their_msat);
    for (int lp = 0; lp < cnt; lp++) {
        LOGD("  have HTLC[%d] %" PRIu64 " (%s)\n", lp, pp_htlc_info[lp]->amount_msat, (pp_htlc_info[lp]->type != LN_COMTX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //FEE
    fee_info.feerate_per_kw = pChannel->feerate_per_kw;
    fee_info.dust_limit_satoshi = pCommitRemote->dust_limit_sat;
    ln_comtx_base_fee_calc(&fee_info, (const ln_comtx_htlc_info_t **)pp_htlc_info, cnt);

    //commitment transaction
    LOGD("remote commitment_number=%" PRIu64 "\n", CommitNum);
    comtx.fund.txid = ln_funding_txid(pChannel);
    comtx.fund.txid_index = ln_funding_txindex(pChannel);
    comtx.fund.satoshi = pChannel->funding_tx.funding_satoshis;
    comtx.fund.p_wit_script = &pChannel->funding_tx.wit_script;
    comtx.to_local.satoshi = LN_MSAT2SATOSHI(our_msat);
    comtx.to_local.p_wit_script = &buf_ws;
    comtx.to_remote.satoshi = LN_MSAT2SATOSHI(their_msat);
    comtx.to_remote.pubkey = pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_PUBKEY];
    comtx.obscured_commit_num = ln_comtx_calc_obscured_commit_num(pChannel->obscured_commit_num_mask, CommitNum);
    comtx.p_base_fee_info = &fee_info;
    comtx.pp_htlc_info = pp_htlc_info;
    comtx.htlc_info_num = cnt;
    ret = ln_comtx_create_rs(&tx_commit, pCommitRemote->remote_sig, &comtx, !ln_is_funder(pChannel), &pChannel->keys_local); //XXX:
    if (ret) {
        LOGD("++++++++++++++ remote commit tx: tx_commit[%016" PRIx64 "]\n", pChannel->short_channel_id);
        M_DBG_PRINT_TX(&tx_commit);

        ret = btc_tx_txid(&tx_commit, pCommitRemote->txid);
        LOGD("remote commit_txid: ");
        TXIDD(pCommitRemote->txid);
    }

    if (ret) {
        uint8_t *p_htlc_sigs = NULL;
        if (cnt > 0) {
            if (ppHtlcSigs != NULL) {
                //送信用 commitment_signed.htlc_signature
                *ppHtlcSigs = (uint8_t *)UTL_DBG_MALLOC(LN_SZ_SIGNATURE * cnt);
                p_htlc_sigs = *ppHtlcSigs;
            }
        }
        ret = create_remote_spent(
            pChannel,
            pCommitRemote,
            pClose,
            p_htlc_sigs,
            &tx_commit, &buf_ws,
            (const ln_comtx_htlc_info_t **)pp_htlc_info,
            &fee_info);
    }

    LOGD("free: ret=%d\n", ret);
    utl_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_comtx_htlc_info_free(pp_htlc_info[lp]);
        UTL_DBG_FREE(pp_htlc_info[lp]);
    }
    UTL_DBG_FREE(pp_htlc_info);

    if (pClose != NULL) { //XXX:
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
    } else {
        btc_tx_free(&tx_commit);
    }

    return ret;
}


bool ln_comtx_set_vin_p2wsh_2of2(
    btc_tx_t *pTx,
    int Index,
    btc_script_pubkey_order_t KeyOrder,
    const utl_buf_t *pSig1,
    const utl_buf_t *pSig2,
    const utl_buf_t *pWitScript)
{
    // 0
    // <sig1>
    // <sig2>
    // <script>

    const utl_buf_t zero = UTL_BUF_INIT;
    const utl_buf_t *wit_items[] = { &zero, NULL, NULL, pWitScript };
    if (KeyOrder == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
        wit_items[1] = pSig1;
        wit_items[2] = pSig2;
    } else {
        wit_items[1] = pSig2;
        wit_items[2] = pSig1;
    }
    if (!btc_sw_set_vin_p2wsh(pTx, Index, (const utl_buf_t **)wit_items, ARRAY_SIZE(wit_items))) return false;
    return true;
}


bool ln_comtx_set_vin_p2wsh_2of2_rs(
    btc_tx_t *pTx,
    int Index,
    btc_script_pubkey_order_t KeyOrder,
    const uint8_t *pSig1,
    const uint8_t *pSig2,
    const utl_buf_t *pWitScript)
{
    bool ret = false;
    utl_buf_t sig_der_1 = UTL_BUF_INIT;
    utl_buf_t sig_der_2 = UTL_BUF_INIT;
    if (!btc_sig_rs2der(&sig_der_1, pSig1)) goto LABEL_EXIT;
    if (!btc_sig_rs2der(&sig_der_2, pSig2)) goto LABEL_EXIT;
    if (!ln_comtx_set_vin_p2wsh_2of2(pTx, Index, KeyOrder, &sig_der_1, &sig_der_2, pWitScript)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&sig_der_1);
    utl_buf_free(&sig_der_2);
    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

static bool create_local_htlc_info_and_amount(
    const ln_update_add_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pOurMsat,
    uint64_t *pTheirMsat)
{
    return create_htlc_info_and_amount(pHtlcs, ppHtlcInfo, pHtlcInfoCnt, pOurMsat, pTheirMsat, true);
}


/** set vin[0] and verify sigs
 *
 * @param[in,out]   pTxCommit   [in]commit_tx(署名無し) / [out]commit_tx(署名あり)
 * @param[in]       pFundTx
 * @param[in]       pSigLocal
 * @param[in]       pSigRemote
 * @retval  true    成功
 */
static bool create_local_set_vin0_and_verify(
    btc_tx_t *pTxCommit,
    const ln_funding_tx_t *pFundTx,
    const uint8_t *pSigLocal,
    const uint8_t *pSigRemote)
{
    LOGD("local verify\n");

    bool ret = false;

    utl_buf_t script_code = UTL_BUF_INIT;
    uint8_t sighash[BTC_SZ_HASH256];

    //set vin[0]
    if (!ln_comtx_set_vin_p2wsh_2of2_rs(
        pTxCommit, 0, pFundTx->key_order, pSigLocal, pSigRemote, &pFundTx->wit_script)) goto LABEL_EXIT;
    //  LOGD("++++++++++++++ local commit tx: [%016" PRIx64 "]\n", pChannel->short_channel_id);
    M_DBG_PRINT_TX(pTxCommit);

    //verify
    if (!btc_script_p2wsh_create_scriptcode(&script_code, &pFundTx->wit_script)) goto LABEL_EXIT;
    if (!btc_sw_sighash(pTxCommit, sighash, 0, pFundTx->funding_satoshis, &script_code)) goto LABEL_EXIT;
    if (!btc_sw_verify_p2wsh_2of2(pTxCommit, 0, sighash, &pFundTx->tx_data.vout[pFundTx->txindex].script)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&script_code);
    return ret;
}


/** local commit_txの送金先処理
 *
 * commitment_signedとclose処理で共用している。
 * commitment_signedの場合は、HTLC Success/Timeout Tx署名のみ必要。
 *
 *  1. [close]HTLC署名用local_htlcsecret取得
 *  2. voutごとの処理
 *      2.1. vout indexから対応するpp_htlc_info[]を得る --> htlc_idx
 *      2.2. htlc_idxで分岐
 *          2.2.1. [to_local]
 *              -# [close]to_local tx作成 + 署名 --> 戻り値
 *          2.2.2. [to_remote]
 *              -# 処理なし
 *          2.2.3. [各HTLC]
 *              -# fee計算
 *              -# commit_txのvout amountが、dust + fee以上
 *                  -# HTLC tx作成
 *                  -# [署名inputあり]
 *                      - commitment_signedで受信したhtlc_signatureのverify
 *                      - HTLC txのverify
 *                      - verify失敗なら、3へ飛ぶ
 *                      - signatureの保存
 *                  -# [close]
 *                      - commit_txの送金先 tx作成 + 署名 --> 戻り値
 *  3. [署名inputあり]input署名数と処理したHTLC数が不一致なら、エラー
 *
 * @param[in,out]   pChannel
 * @param[out]      pClose
 * @param[in]       pHtlcSigs
 * @param[in]       HtlcSigsNum
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       ppHtlcInfo
 * @param[in]       pFeeInfo
 * @param[in]       ToSelfDelay
 * @retval  true    成功
 */
static bool create_local_spent(
    ln_channel_t *pChannel,
    ln_close_force_t *pClose,
    const uint8_t *pHtlcSigs,
    uint8_t HtlcSigsNum,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pFeeInfo,
    uint32_t ToSelfDelay)
{
    bool ret = true;
    uint16_t htlc_num = 0;
    btc_tx_t *pCloseTxToLocal = NULL;
    btc_tx_t *pCloseTxHtlcs = NULL;
    utl_push_t push;
    btc_keys_t htlckey;

    if (pClose != NULL) {
        pCloseTxToLocal = &pClose->p_tx[LN_CLOSE_IDX_TO_LOCAL];
        pCloseTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];

        utl_push_init(&push, &pClose->tx_buf, 0);

        //HTLC署名用鍵
        ln_signer_htlc_localkey(&htlckey, &pChannel->keys_local);
    } else {
        push.data = NULL;
    }

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("+++[%d]to_local\n", vout_idx);
            ret = create_local_spent_to_local(
                pChannel,
                pCloseTxToLocal,
                pBufWs,
                pTxCommit->vout[vout_idx].value,
                vout_idx,
                ToSelfDelay);
        } else if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("+++[%d]to_remote\n", vout_idx);
        } else {
            const ln_comtx_htlc_info_t *p_htlc_info = ppHtlcInfo[htlc_idx];
            uint64_t fee_sat = (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? pFeeInfo->htlc_timeout_fee : pFeeInfo->htlc_success_fee;
            LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? "offered" : "received");
            assert(pTxCommit->vout[vout_idx].value >= pFeeInfo->dust_limit_satoshi + fee_sat);

            btc_tx_t tx = BTC_TX_INIT;
            ln_htlctx_create(
                &tx,
                pTxCommit->vout[vout_idx].value - fee_sat,
                pBufWs,
                p_htlc_info->type,
                p_htlc_info->cltv_expiry,
                pChannel->commit_tx_local.txid, vout_idx);

            if ((pHtlcSigs != NULL) && (HtlcSigsNum != 0)) {
                //HTLC署名があるなら、verify
                //  - commitment_signed受信
                ret = create_local_verify_htlc(
                    pChannel,
                    &tx,
                    pHtlcSigs + htlc_num * LN_SZ_SIGNATURE,
                    &p_htlc_info->wit_script,
                    pTxCommit->vout[vout_idx].value);
                if (ret) {
                    //OKなら各HTLCに保持
                    //  相手がunilateral closeした後に送信しなかったら、この署名を使う
                    memcpy(pChannel->cnl_add_htlc[p_htlc_info->add_htlc_idx].remote_sig, pHtlcSigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
                } else {
                    break;
                }
            } else if (pClose != NULL) {
                //unilateral closeデータを作成
                //  - unilateral close要求
                ret = create_local_spent_htlc(
                    pChannel,
                    &pCloseTxHtlcs[htlc_num],
                    &tx,
                    &push,
                    pTxCommit->vout[vout_idx].value,
                    pBufWs,
                    p_htlc_info,
                    &htlckey,
                    ToSelfDelay);
                if (ret) {
                    pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                } else {
                    LOGE("fail: sign vout[%d]\n", vout_idx);
                    break;
                }
            } else {
                //HTLC署名なし、close要求なし
                //  - funding_created受信
                //  - funding_signed受信
            }
            btc_tx_free(&tx);

            htlc_num++;
        }
    }

    if ((pHtlcSigs != NULL) && (htlc_num != HtlcSigsNum)) {
        LOGE("署名数不一致: %d, %d\n", htlc_num, HtlcSigsNum);
        ret = false;
    }

    pChannel->commit_tx_local.htlc_num = htlc_num;

    return ret;
}


/** to_localをwalletに保存する情報作成
 *
 * @param[out]      pTxToLocal
 *
 * @note
 *  - pTxToLocalはbtc_tx_tフォーマットだが、blockchainに展開できるデータではない
 */
static bool create_local_spent_to_local(
    const ln_channel_t *pChannel,
    btc_tx_t *pTxToLocal,
    const utl_buf_t *pBufWs,
    uint64_t Amount,
    uint32_t VoutIdx,
    uint32_t ToSelfDelay)
{
    bool ret;
    if (pTxToLocal != NULL) {
        btc_tx_t tx = BTC_TX_INIT;
        ret = ln_wallet_create_to_local(
            pChannel,
            &tx,
            Amount,
            ToSelfDelay,
            pBufWs, pChannel->commit_tx_local.txid, VoutIdx, false);
        if (ret) {
            memcpy(pTxToLocal, &tx, sizeof(tx));
            btc_tx_init(&tx);     //txはfreeさせない
        } else {
            btc_tx_free(&tx);
        }
    } else {
        ret = true;
    }
    return ret;
}


static bool create_local_verify_htlc(
    const ln_channel_t *pChannel,
    btc_tx_t *pTx,
    const uint8_t *pHtlcSig,
    const utl_buf_t *pScript,
    uint64_t Amount)
{
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, pHtlcSig);

    bool ret = ln_htlctx_verify(
        pTx,
        Amount,
        NULL,
        NULL,
        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
        &buf_sig,
        pScript);
    utl_buf_free(&buf_sig);
    if (ret) {
        M_DBG_PRINT_TX2(pTx);
    } else {
        LOGE("fail: verify vout\n");
        btc_tx_free(pTx);
    }
    return ret;
}


/** local close後のHTLC_txからの送金情報作成
 *
 *  1. input署名をASN.1形式に展開
 *  2. [received HTLC]DBからpreimage検索
 *  3. HTLC Success/Timeout tx署名(呼び元でtx作成済み)
 *      - エラー時はここで終了
 *  4. [(received HTLC && preimageあり) || offered HTLC]
 *      -# 署名したHTLC txを処理結果にコピー
 *      -# HTLC txの送金を取り戻すtxを作成 + 署名(形はto_localと同じ) --> キューに積む
 *
 * @param[in,out]   pChannel
 * @param[out]      pCloseTxHtlcs   処理結果のHTLC tx配列(末尾に追加)
 * @param[in,out]   pTxHtlc         [in]処理中のHTLC tx(署名無し) / [out]HTLC tx(署名あり)
 * @param[out]      pPush           HTLC txから取り戻すtxのwallet情報
 * @param[in]       Amount
 * @param[in]       pBufWs
 * @param[in]       pHtlcInfo
 * @param[in]       pHtlcKey
 * @param[in]       ToSelfDelay
 * @retval  true    成功
 */
static bool create_local_spent_htlc(
    const ln_channel_t *pChannel,
    btc_tx_t *pCloseTxHtlc,
    btc_tx_t *pTxHtlc,
    utl_push_t *pPush,
    uint64_t Amount,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint32_t ToSelfDelay)
{
    bool ret;
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    uint8_t txid[BTC_SZ_TXID];
    uint8_t local_sig[LN_SZ_SIGNATURE];

    if (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) {
        //Receivedであればpreimageを所持している可能性がある
        ret_img = search_preimage(
            preimage,
            pChannel->cnl_add_htlc[pHtlcInfo->add_htlc_idx].payment_hash,
            true);
        LOGD("[received]have preimage=%s\n", (ret_img) ? "yes" : "NO");
    } else {
        ret_img = false;
        LOGD("[offered]\n");
    }
    if ( ((pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) && ret_img) ||
        (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ) {
        //継続
    } else {
        LOGD("skip create HTLC tx\n");
        btc_tx_init(pCloseTxHtlc);
        ret = true;
        goto LABEL_EXIT;
    }

    //署名:HTLC Success/Timeout Transaction
    ret = ln_htlctx_sign_rs(
        pTxHtlc,
        local_sig,
        Amount,
        pHtlcKey,
        &pHtlcInfo->wit_script);
    if (ret) {
        ret = ln_htlctx_set_vin_rs(
            pTxHtlc,
            local_sig,
            pChannel->cnl_add_htlc[pHtlcInfo->add_htlc_idx].remote_sig,
            (ret_img) ? preimage : NULL,
            NULL,
            &pHtlcInfo->wit_script,
            LN_HTLCTX_SIG_TIMEOUT_SUCCESS);
    }
    if (!ret) {
        LOGE("fail: sign_htlc_tx: vout\n");
        goto LABEL_EXIT;
    }
    M_DBG_PRINT_TX2(pTxHtlc);

    //署名したHTLC_txを上位に返して展開してもらう(sequence/locktimeのため展開されないかもしれない)
    memcpy(pCloseTxHtlc, pTxHtlc, sizeof(btc_tx_t));

    // HTLC Timeout/Success Txを作った場合はそれを取り戻す準備をする
    btc_tx_txid(pTxHtlc, txid);
    ret = ln_wallet_create_to_local(
        pChannel,
        &tx,
        pTxHtlc->vout[0].value,
        ToSelfDelay,
        pBufWs, txid, 0, false);
    if (ret) {
        LOGD("*** HTLC out Tx ***\n");
        M_DBG_PRINT_TX2(&tx);

        //HTLC txから取り戻すtxをキューに積む
        utl_push_data(pPush, &tx, sizeof(btc_tx_t));
    } else {
        btc_tx_free(&tx);
        ret = true;     //no to_local
    }
    btc_tx_init(pTxHtlc);     //txはfreeさせない(pTxHtlcsに任せる)

LABEL_EXIT:
    return ret;
}


static bool create_remote_htlc_info_and_amount(
    const ln_update_add_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pOurMsat,
    uint64_t *pTheirMsat)
{
    return create_htlc_info_and_amount(pHtlcs, ppHtlcInfo, pHtlcInfoCnt, pOurMsat, pTheirMsat, false);
}


static bool create_htlc_info_and_amount(
    const ln_update_add_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pOurMsat,
    uint64_t *pTheirMsat,
    bool bLocal)
{
    *pHtlcInfoCnt = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        const ln_update_add_htlc_t *p_htlc = &pHtlcs[idx];
        if (!LN_HTLC_ENABLE(p_htlc)) continue;

        bool htlcadd = false;
        if (LN_HTLC_ENABLE_ADDHTLC_OFFER(p_htlc, bLocal)) {
            LOGD("addhtlc_offer\n");
            htlcadd = true;
            *pOurMsat -= p_htlc->amount_msat;
        } else if (LN_HTLC_ENABLE_FULFILL_OFFER(p_htlc, bLocal)) {
            LOGD("delhtlc_offer\n");
            *pOurMsat -= p_htlc->amount_msat;
            *pTheirMsat += p_htlc->amount_msat;
        } else if (LN_HTLC_ENABLE_ADDHTLC_RECV(p_htlc, bLocal)) {
            LOGD("addhtlc_recv\n");
            htlcadd = true;
            *pTheirMsat -= p_htlc->amount_msat;
        } else if (LN_HTLC_ENABLE_FULFILL_RECV(p_htlc, bLocal)) {
            LOGD("delhtlc_recv\n");
            *pOurMsat += p_htlc->amount_msat;
            *pTheirMsat -= p_htlc->amount_msat;
        }

        if (!htlcadd) {
            LOGD(" DEL[%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, p_htlc->id, p_htlc->amount_msat);
            continue;
        }

        ln_comtx_htlc_info_t *p_info = (ln_comtx_htlc_info_t *)UTL_DBG_MALLOC(sizeof(ln_comtx_htlc_info_t));
        ln_comtx_htlc_info_init(p_info);
        switch (p_htlc->stat.flag.addhtlc) {
        case LN_ADDHTLC_RECV:
            p_info->type = bLocal ? LN_COMTX_OUTPUT_TYPE_RECEIVED : LN_COMTX_OUTPUT_TYPE_OFFERED;
            break;
        case LN_ADDHTLC_OFFER:
            p_info->type = bLocal ? LN_COMTX_OUTPUT_TYPE_OFFERED : LN_COMTX_OUTPUT_TYPE_RECEIVED;
            break;
        default:
            LOGE("unknown flag: %04x\n", p_htlc->stat.bits);
            assert(0);
            UTL_DBG_FREE(p_info);
            goto LABEL_ERROR;
        }
        p_info->add_htlc_idx = idx;
        p_info->cltv_expiry = p_htlc->cltv_expiry;
        p_info->amount_msat = p_htlc->amount_msat;
        p_info->payment_hash = p_htlc->payment_hash;
        ppHtlcInfo[*pHtlcInfoCnt] = p_info;
        (*pHtlcInfoCnt)++;
        LOGD(" ADD[%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, p_htlc->id, p_htlc->amount_msat);
    }
    return true;

LABEL_ERROR:
    while (*pHtlcInfoCnt--) {
        UTL_DBG_FREE(ppHtlcInfo[*pHtlcInfoCnt]);
    }
    return false;
}


/** remote commit_txの送金先処理
 *
 *  1. [close]HTLC署名用local_htlcsecret取得
 *  2. voutごとの処理
 *      2.1. vout indexから対応するppHtlcInfo[]を得る --> htlc_idx
 *      2.2. htlc_idxで分岐
 *          2.2.1. [to_local]
 *              -# 処理なし
 *          2.2.2. [to_remote]
 *              -# [close]to_remote tx作成 + 署名 --> 戻り値
 *          2.2.3. [各HTLC]
 *              -# fee計算
 *              -# commit_txのvout amountが、dust + fee以上
 *                  -# HTLC tx作成 + 署名 --> 戻り値
 *
 * @param[in,out]   pChannel
 * @param[out]      pClose
 * @param[out]      pHtlcSigs
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       ppHtlcInfo
 * @param[in]       pFeeInfo
 * @retval  true    成功
 */
static bool create_remote_spent(
    const ln_channel_t *pChannel,
    ln_commit_tx_t *pCommit,
    ln_close_force_t *pClose,
    uint8_t *pHtlcSigs,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pFeeInfo)
{
    bool ret = true;
    uint16_t htlc_num = 0;

    btc_tx_t *pTxHtlcs = NULL;
    if (pClose != NULL) {
        pTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];
    }

    //HTLC署名用鍵
    btc_keys_t htlckey;
    ln_signer_htlc_remotekey(&htlckey, &pChannel->keys_local, &pChannel->keys_remote);

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        //各HTLCのHTLC Timeout/Success Transactionを作って署名するために、
        //BIP69ソート後のtx_commit.voutからppHtlcInfo[]のindexを取得する
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("---[%d]to_local\n", vout_idx);
        } else if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("---[%d]to_remote\n", vout_idx);
            if (pClose != NULL) {
                btc_tx_t tx = BTC_TX_INIT;

                //wallet保存用のデータ作成
                ret = ln_wallet_create_to_remote(
                    pChannel, &tx, pTxCommit->vout[vout_idx].value, pCommit->txid, vout_idx);
                if (ret) {
                    memcpy(&pClose->p_tx[LN_CLOSE_IDX_TO_REMOTE], &tx, sizeof(tx));
                    btc_tx_init(&tx);     //txはfreeさせない
                } else {
                    LOGD("no to_remote output\n");
                    btc_tx_free(&tx);
                    ret = true;     //継続する
                }
            }
        } else {
            const ln_comtx_htlc_info_t *p_htlc_info = ppHtlcInfo[htlc_idx];
            const uint8_t *p_payhash = pChannel->cnl_add_htlc[p_htlc_info->add_htlc_idx].payment_hash;
            uint64_t fee_sat = (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? pFeeInfo->htlc_timeout_fee : pFeeInfo->htlc_success_fee;
            if (pTxCommit->vout[vout_idx].value >= pFeeInfo->dust_limit_satoshi + fee_sat) {
                ret = create_remote_spent_htlc(
                    pCommit,
                    pTxHtlcs,
                    pHtlcSigs,
                    pTxCommit,
                    pBufWs,
                    p_htlc_info,
                    &htlckey,
                    pChannel->commit_tx_local.remote_sig,
                    fee_sat,
                    htlc_num,
                    vout_idx,
                    p_payhash,
                    (pClose != NULL));
                if (ret) {
                    if (pClose != NULL) {
                        pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                    }
                } else {
                    LOGE("fail: sign vout[%d]\n", vout_idx);
                    break;
                }

                htlc_num++;
            } else {
                LOGD("cut HTLC[%d] %" PRIu64 " > %" PRIu64 "\n",
                    vout_idx, pTxCommit->vout[vout_idx].value, pFeeInfo->dust_limit_satoshi + fee_sat);
            }
        }
    }
    pCommit->htlc_num = htlc_num;

    return ret;
}


/** remote HTLCからの送金先情報作成
 *
 *  1. HTLC tx作成
 *  2. HTLC Success txを作成する予定にする
 *  3. HTLC種別での分岐
 *      3.1 [offered HTLC]preimage検索
 *          - [close && 検索成功]
 *              - preimageがあるofferedなので、即時broadcast可能tx作成にする
 *      3.2 [else]
 *          - [close]
 *              - HTLC Timeout tx作成にする
 *  4. HTLC tx署名
 *  5. [close]
 *      5.1. [(offered HTLC && preimageあり) || received HTLC]
 *          -# 署名したHTLC txを処理結果にコピー
 *
 * @param[in,out]   pChannel
 * @param[out]      pTxHtlcs        Close処理結果のHTLC tx配列(末尾に追加)
 * @param[out]      pHtlcSigs     HTLC署名
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       pHtlcInfo
 * @param[in]       pHtlcKey
 * @param[in]       pRemoteSig
 * @param[in]       Fee
 * @param[in]       HtlcNum
 * @param[in]       VoutIdx
 * @param[in]       pPayHash
 * @param[in]       bClosing        true:close処理
 * @retval  true    成功
 */
static bool create_remote_spent_htlc(
    ln_commit_tx_t *pCommit,
    btc_tx_t *pTxHtlcs,
    uint8_t *pHtlcSigs,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pBufWs,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    const uint8_t *pRemoteSig,
    uint64_t Fee,
    uint8_t HtlcNum,
    uint32_t VoutIdx,
    const uint8_t *pPayHash,
    bool bClosing)
{
    bool ret = false;
    btc_tx_t tx = BTC_TX_INIT;

    LOGD("---HTLC[%d]\n", VoutIdx);
    ln_htlctx_create(&tx, pTxCommit->vout[VoutIdx].value - Fee, pBufWs,
                pHtlcInfo->type, pHtlcInfo->cltv_expiry,
                pCommit->txid, VoutIdx);

    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    bool b_save = false;        //true: pTxHtlcs[HtlcNum]に残したい
    ln_htlctx_sig_type_t htlcsign = LN_HTLCTX_SIG_TIMEOUT_SUCCESS;
    if (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_OFFERED) {
        //remoteのoffered=自分のreceivedなのでpreimageを所持している可能性がある
        ret_img = search_preimage(preimage, pPayHash, bClosing);
        if (ret_img && (pTxHtlcs != NULL)) {
            LOGD("[offered]have preimage\n");
            //offeredかつpreimageがあるので、即時使用可能

            utl_buf_free(&tx.vout[0].script);
            tx.locktime = 0;
            //wit[0]に署名用秘密鍵を設定しておく(wallet用)
            ret = ln_wallet_htlctx_set_vin(&tx,
                pHtlcKey->priv,
                (ret_img) ? preimage : NULL,
                &pHtlcInfo->wit_script,
                LN_HTLCTX_SIG_REMOTE_OFFER);
            htlcsign = LN_HTLCTX_SIG_NONE;
        } else if (!ret_img) {
            //preimageがないためHTLCを解くことができない
            //  --> 署名はしてpTxHtlcs[HtlcNum]に残す
            LOGD("[offered]no preimage\n");
            //htlcsign = LN_HTLCTX_SIG_NONE;
            b_save = true;
            ret = true;
        } else {
            //署名のみ作成(commitment_signed用)
            LOGD("[offered]only sign\n");
            ret = true;
        }
    } else {
        //remoteのreceived=自分がofferedしているでtimeoutしたら取り戻す
        LOGD("[received]\n");

        ret_img = false;
        if (pTxHtlcs != NULL) {
            //タイムアウト待ち
            //  -->署名はしないがpTxHtlcs[HtlcNum]に残したい

            utl_buf_free(&tx.vout[0].script);
            tx.locktime = pHtlcInfo->cltv_expiry;
            //wit[0]に署名用秘密鍵を設定しておく(wallet用)
            ret = ln_wallet_htlctx_set_vin(&tx,
                pHtlcKey->priv,
                NULL,
                &pHtlcInfo->wit_script,
                LN_HTLCTX_SIG_REMOTE_RECV);
            htlcsign = LN_HTLCTX_SIG_NONE;
        }
    }

    //署名
    if (htlcsign != LN_HTLCTX_SIG_NONE) {
        uint8_t local_sig[LN_SZ_SIGNATURE];
        ret = ln_htlctx_sign_rs(&tx,
                    local_sig,
                    pTxCommit->vout[VoutIdx].value,
                    pHtlcKey,
                    &pHtlcInfo->wit_script);
        if (ret && (pHtlcSigs != NULL)) {
            memcpy(pHtlcSigs + LN_SZ_SIGNATURE * HtlcNum, local_sig, LN_SZ_SIGNATURE);
        }
        if (ret) {
            ret = ln_htlctx_set_vin_rs(&tx,
                    local_sig,
                    pRemoteSig,
                    (ret_img) ? preimage : NULL,
                    NULL,
                    &pHtlcInfo->wit_script,
                    htlcsign);
        }
        if (!ret) {
            LOGE("fail: sign_htlc_tx: vout[%d]\n", VoutIdx);
            goto LABEL_EXIT;
        }
    }

    if (pTxHtlcs != NULL) {
        if ( ((pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_OFFERED) && ret_img) ||
                (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) ||
                b_save ) {
            LOGD("create HTLC tx[%d]\n", HtlcNum);
            memcpy(&pTxHtlcs[HtlcNum], &tx, sizeof(tx));
            btc_tx_init(&tx);     //txはfreeさせない(pTxHtlcsに任せる)
        } else {
            LOGD("skip create HTLC tx[%d]\n", HtlcNum);
            btc_tx_init(&pTxHtlcs[HtlcNum]);
        }
    }

LABEL_EXIT:
    btc_tx_free(&tx);

    return ret;
}




/** payment_hashと一致するpreimage検索
 *
 * @param[out]      pPreimage
 * @param[in]       pPayHash        payment_hash
 * @param[in]       bClosing        true:一致したexpiryをUINT32_MAXに変更する
 * @retval  true    検索成功
 */
static bool search_preimage(uint8_t *pPreimage, const uint8_t *pPayHash, bool bClosing)
{
    if (!LN_DBG_MATCH_PREIMAGE()) {
        LOGE("DBG: HTLC preimage mismatch\n");
        return false;
    }
    // LOGD("pPayHash(%d)=", bClosing);
    // DUMPD(pPayHash, BTC_SZ_HASH256);

    preimage_t prm;
    prm.image = pPreimage;
    prm.hash = pPayHash;
    prm.b_closing = bClosing;
    if (!ln_db_preimage_search(search_preimage_func, &prm)) return false;
    return true;
}


/** search_preimage用処理関数
 *
 * SHA256(preimage)がpayment_hashと一致した場合にtrueを返す。
 * bClosingがtrueの場合、該当するpreimageのexpiryをUINT32_MAXにする(自動削除させないため)。
 */
static bool search_preimage_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param)
{
    (void)Amount; (void)Expiry;

    preimage_t *prm = (preimage_t *)p_param;
    uint8_t payment_hash[BTC_SZ_HASH256];
    bool ret = false;

    //LOGD("compare preimage : ");
    //DUMPD(pPreimage, LN_SZ_PREIMAGE);
    ln_payment_hash_calc(payment_hash, pPreimage);
    if (memcmp(payment_hash, prm->hash, BTC_SZ_HASH256) == 0) {
        //一致
        //LOGD("preimage match!: ");
        //DUMPD(pPreimage, LN_SZ_PREIMAGE);
        memcpy(prm->image, pPreimage, LN_SZ_PREIMAGE);
        if ((prm->b_closing) && (Expiry != UINT32_MAX)) {
            //期限切れによる自動削除をしない
            ln_db_preimage_set_expiry(p_db_param, UINT32_MAX);
        }
        ret = true;
    }

    return ret;
}
