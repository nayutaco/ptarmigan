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
static bool create_local_spent__verify(
    ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    uint16_t HtlcSigsNum,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo);
static bool create_local_spent__close(
    ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo,
    uint32_t ToSelfDelay);
static bool create_local_spent_to_local(
    const ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    btc_tx_t *pTxToLocal,
    const utl_buf_t *pWitScriptToLocal,
    uint64_t Amount,
    uint32_t VoutIdx,
    uint32_t ToSelfDelay);
static bool create_local_verify_htlc(
    const ln_channel_t *pChannel,
    btc_tx_t *pTx,
    const uint8_t *pHtlcSig,
    const utl_buf_t *pScript,
    uint64_t Amount);
static bool create_local_spent_htlc__htlc_tx(
    const ln_channel_t *pChannel,
    btc_tx_t *pTxHtlc,
    uint64_t Amount,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey);
static bool create_local_spent_htlc__spend_tx_for_htlc_tx(
    const ln_channel_t *pChannel,
    const btc_tx_t *pTxHtlc,
    btc_tx_t *pTxSpend,
    const utl_buf_t *pWitScriptToLocal,
    uint32_t ToSelfDelay);


//remote
static bool create_remote_htlc_info_and_amount(
    const ln_update_add_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pOurMsat,
    uint64_t *pTheirMsat);
static bool create_remote_spent__with_close(
    const ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo);
static bool create_remote_spent__with_htlc_sigs(
    const ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo);
static bool create_remote_spent_htlc__with_htlc_sig(
    const ln_commit_tx_t *pCommitTxInfo,
    uint8_t *pHtlcSig,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx);
static bool create_remote_spent_htlc__with_close(
    const ln_commit_tx_t *pCommitTxInfo,
    btc_tx_t *pCloseTxHtlc,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx,
    const uint8_t *pPayHash);

static bool search_preimage(uint8_t *pPreimage, const uint8_t *pPayHash, bool bClosing);
static bool search_preimage_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);


/********************************************************************
 * public functions
 ********************************************************************/

bool HIDDEN ln_comtx_create_local(
    ln_channel_t *pChannel,
    ln_commit_tx_t *pCommitTxInfo,
    ln_close_force_t *pClose,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    uint16_t HtlcSigsNum)
{
    LOGD("BEGIN\n");

    bool ret = false;

    ln_comtx_htlc_info_t **pp_htlc_info = 0;
    utl_buf_t wit_script_to_local = UTL_BUF_INIT;
    uint8_t local_sig[LN_SZ_SIGNATURE];
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint16_t htlc_info_num = 0;
    uint16_t htlc_output_num = 0;

    ln_comtx_base_fee_info_t base_fee_info;
    ln_comtx_t comtx = LN_COMTX_INIT;
    uint64_t our_msat = pChannel->our_msat;
    uint64_t their_msat = pChannel->their_msat;

    //to_local
    if (!ln_script_create_to_local(
        &wit_script_to_local,
        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pCommitTxInfo->to_self_delay)) return false;

    //HTLC info (amount)
    pp_htlc_info = (ln_comtx_htlc_info_t **)UTL_DBG_MALLOC(sizeof(ln_comtx_htlc_info_t*) * LN_HTLC_MAX);
    if (!pp_htlc_info) return false;
    if (!create_local_htlc_info_and_amount(pChannel->cnl_add_htlc, pp_htlc_info, &htlc_info_num, &our_msat, &their_msat)) goto LABEL_EXIT;

    //HTLC info (script)
    for (int lp = 0; lp < htlc_info_num; lp++) {
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
    for (int lp = 0; lp < htlc_info_num; lp++) {
        LOGD("  [%d] %" PRIu64 " (%s)\n", lp, pp_htlc_info[lp]->amount_msat, (pp_htlc_info[lp]->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //fee
    base_fee_info.feerate_per_kw = pChannel->feerate_per_kw;
    base_fee_info.dust_limit_satoshi = pCommitTxInfo->dust_limit_sat;
    /*void*/ ln_comtx_base_fee_calc(&base_fee_info, (const ln_comtx_htlc_info_t **)pp_htlc_info, htlc_info_num);

    //commitment transaction
    LOGD("local commitment_number=%" PRIu64 "\n", pCommitTxInfo->commit_num);
    comtx.fund.txid = ln_funding_txid(pChannel);
    comtx.fund.txid_index = ln_funding_txindex(pChannel);
    comtx.fund.satoshi = pChannel->funding_tx.funding_satoshis;
    comtx.fund.p_wit_script = &pChannel->funding_tx.wit_script;
    comtx.to_local.satoshi = LN_MSAT2SATOSHI(our_msat);
    comtx.to_local.p_wit_script = &wit_script_to_local;
    comtx.to_remote.satoshi = LN_MSAT2SATOSHI(their_msat);
    comtx.to_remote.pubkey = pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_PUBKEY];
    comtx.obscured_commit_num =
        ln_comtx_calc_obscured_commit_num(pChannel->obscured_commit_num_mask, pCommitTxInfo->commit_num);
    comtx.pp_htlc_info = pp_htlc_info;
    comtx.htlc_info_num = htlc_info_num;
    comtx.b_trimmed = false;
    ln_comtx_sub_fee_and_trim_outputs(&comtx, &base_fee_info, ln_is_funder(pChannel));

    //check htlc_output_num
    htlc_output_num = ln_comtx_get_htlc_output_num(&comtx);
    if (pClose) {
        if (htlc_output_num != pClose->num - LN_CLOSE_IDX_HTLC) { //XXX: ???
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
    }
    if (pHtlcSigs) {
        if (htlc_output_num != HtlcSigsNum) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
    }
    pCommitTxInfo->htlc_output_num = htlc_output_num;

    if (!ln_comtx_create_rs(&tx_commit, local_sig, &comtx, &pChannel->keys_local)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    if (!create_local_set_vin0_and_verify(&tx_commit, &pChannel->funding_tx, local_sig, pCommitTxInfo->remote_sig)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //txid
    if (!btc_tx_txid(&tx_commit, pCommitTxInfo->txid)) goto LABEL_EXIT;
    LOGD("local commit_txid: ");
    TXIDD(pCommitTxInfo->txid);

    if (pClose) {
        if (!create_local_spent__close(
            pChannel, pCommitTxInfo, pClose, &tx_commit, &wit_script_to_local, (const ln_comtx_htlc_info_t **)pp_htlc_info,
            &base_fee_info, pCommitTxInfo->to_self_delay)) goto LABEL_EXIT;
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
        btc_tx_init(&tx_commit); //force clear
    }
    if (pHtlcSigs) {
        if (!create_local_spent__verify(
            pChannel, pCommitTxInfo, pHtlcSigs, HtlcSigsNum, &tx_commit, &wit_script_to_local,
            (const ln_comtx_htlc_info_t **)pp_htlc_info, &base_fee_info)) goto LABEL_EXIT;
    }
    btc_tx_free(&tx_commit);

    ret = true;

LABEL_EXIT:
    utl_buf_free(&wit_script_to_local);
    if (pp_htlc_info) {
        for (int lp = 0; lp < htlc_info_num; lp++) {
            ln_comtx_htlc_info_free(pp_htlc_info[lp]);
            UTL_DBG_FREE(pp_htlc_info[lp]);
        }
        UTL_DBG_FREE(pp_htlc_info);
    }
    return ret;
}


bool ln_comtx_create_remote(
    const ln_channel_t *pChannel,
    ln_commit_tx_t *pCommitTxInfo,
    ln_close_force_t *pClose,
    uint8_t (**ppHtlcSigs)[LN_SZ_SIGNATURE])
{
    LOGD("BEGIN\n");

    bool ret = false;

    uint8_t (*p_htlc_sigs)[LN_SZ_SIGNATURE] = 0;
    ln_comtx_htlc_info_t **pp_htlc_info = 0;
    utl_buf_t wit_script_to_local = UTL_BUF_INIT;
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint16_t htlc_info_num = 0;

    ln_comtx_base_fee_info_t base_fee_info;
    ln_comtx_t comtx = LN_COMTX_INIT;
    uint64_t our_msat = pChannel->their_msat;
    uint64_t their_msat = pChannel->our_msat;
    uint16_t htlc_output_num = 0;

    //to_local
    if (!ln_script_create_to_local(
        &wit_script_to_local,
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pCommitTxInfo->to_self_delay)) return false;

    //HTLC info (amount)
    pp_htlc_info = (ln_comtx_htlc_info_t **)UTL_DBG_MALLOC(sizeof(ln_comtx_htlc_info_t*) * LN_HTLC_MAX);
    if (!pp_htlc_info) goto LABEL_EXIT;
    if (!create_remote_htlc_info_and_amount(pChannel->cnl_add_htlc, pp_htlc_info, &htlc_info_num, &our_msat, &their_msat)) goto LABEL_EXIT;

    //HTLC info (script)
    for (int lp = 0; lp < htlc_info_num; lp++) {
        if (!ln_script_create_htlc(
            &pp_htlc_info[lp]->wit_script,
            pp_htlc_info[lp]->type,
            pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
            pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
            pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
            pp_htlc_info[lp]->payment_hash,
            pp_htlc_info[lp]->cltv_expiry)) goto LABEL_EXIT;
    }

#ifdef LN_UGLY_NORMAL //XXX:
    for (int lp = 0; lp < htlc_info_num; lp++) {
        //payment_hash, type, expiry保存
        utl_buf_t vout = UTL_BUF_INIT;
        if (!btc_script_p2wsh_create_scriptpk(&vout, &pp_htlc_info[lp]->wit_script)) goto LABEL_EXIT;
        if (!ln_db_phash_save(
            pp_htlc_info[lp]->payment_hash,
            vout.buf,
            pp_htlc_info[lp]->type,
            pp_htlc_info[lp]->cltv_expiry)) {
            utl_buf_free(&vout);
            goto LABEL_EXIT;
        }
        utl_buf_free(&vout);
    }
#endif  //LN_UGLY_NORMAL

    LOGD("-------\n");
    LOGD("(remote)our_msat   %" PRIu64 " --> %" PRIu64 "\n", pChannel->their_msat, our_msat);
    LOGD("(remote)their_msat %" PRIu64 " --> %" PRIu64 "\n", pChannel->our_msat, their_msat);
    for (int lp = 0; lp < htlc_info_num; lp++) {
        LOGD("  have HTLC[%d] %" PRIu64 " (%s)\n", lp, pp_htlc_info[lp]->amount_msat, (pp_htlc_info[lp]->type != LN_COMTX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //fee
    base_fee_info.feerate_per_kw = pChannel->feerate_per_kw;
    base_fee_info.dust_limit_satoshi = pCommitTxInfo->dust_limit_sat;
    /*void*/ ln_comtx_base_fee_calc(&base_fee_info, (const ln_comtx_htlc_info_t **)pp_htlc_info, htlc_info_num);

    //commitment transaction
    LOGD("remote commitment_number=%" PRIu64 "\n", pCommitTxInfo->commit_num);
    comtx.fund.txid = ln_funding_txid(pChannel);
    comtx.fund.txid_index = ln_funding_txindex(pChannel);
    comtx.fund.satoshi = pChannel->funding_tx.funding_satoshis;
    comtx.fund.p_wit_script = &pChannel->funding_tx.wit_script;
    comtx.to_local.satoshi = LN_MSAT2SATOSHI(our_msat);
    comtx.to_local.p_wit_script = &wit_script_to_local;
    comtx.to_remote.satoshi = LN_MSAT2SATOSHI(their_msat);
    comtx.to_remote.pubkey = pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_PUBKEY];
    comtx.obscured_commit_num =
        ln_comtx_calc_obscured_commit_num(pChannel->obscured_commit_num_mask, pCommitTxInfo->commit_num);
    comtx.pp_htlc_info = pp_htlc_info;
    comtx.htlc_info_num = htlc_info_num;
    comtx.b_trimmed = false;
    ln_comtx_sub_fee_and_trim_outputs(&comtx, &base_fee_info, !ln_is_funder(pChannel));

    //check htlc_output_num
    htlc_output_num = ln_comtx_get_htlc_output_num(&comtx);
    if (pClose) {
        if (htlc_output_num != pClose->num - LN_CLOSE_IDX_HTLC) { //XXX: ???
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
    }
    pCommitTxInfo->htlc_output_num = htlc_output_num;

    if (!ln_comtx_create_rs(&tx_commit, pCommitTxInfo->remote_sig, &comtx, &pChannel->keys_local)) goto LABEL_EXIT;
    LOGD("++++++++++++++ remote commit tx: tx_commit[%016" PRIx64 "]\n", pChannel->short_channel_id);
    M_DBG_PRINT_TX(&tx_commit);
    if (!btc_tx_txid(&tx_commit, pCommitTxInfo->txid)) goto LABEL_EXIT;
    LOGD("remote commit_txid: ");
    TXIDD(pCommitTxInfo->txid);

    if (pClose) {
        if (!create_remote_spent__with_close(
            pChannel, pCommitTxInfo, pClose, &tx_commit, &wit_script_to_local,
            (const ln_comtx_htlc_info_t **)pp_htlc_info, &base_fee_info)) goto LABEL_EXIT;
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
        btc_tx_free(&tx_commit); //force clear
    }
    if (ppHtlcSigs) {
        if (htlc_output_num) {
            *ppHtlcSigs = (uint8_t (*)[LN_SZ_SIGNATURE])UTL_DBG_MALLOC(LN_SZ_SIGNATURE * htlc_output_num);
            if (!*ppHtlcSigs) goto LABEL_EXIT;
            p_htlc_sigs = *ppHtlcSigs;
        }
        if (!create_remote_spent__with_htlc_sigs(
            pChannel, pCommitTxInfo, p_htlc_sigs, &tx_commit, &wit_script_to_local,
            (const ln_comtx_htlc_info_t **)pp_htlc_info, &base_fee_info)) goto LABEL_EXIT;
    }

    ret = true;

LABEL_EXIT:
    if (!ret) {
        UTL_DBG_FREE(p_htlc_sigs);
    }
    btc_tx_free(&tx_commit);
    utl_buf_free(&wit_script_to_local);
    if (pp_htlc_info) {
        for (int lp = 0; lp < htlc_info_num; lp++) {
            ln_comtx_htlc_info_free(pp_htlc_info[lp]);
            UTL_DBG_FREE(pp_htlc_info[lp]);
        }
        UTL_DBG_FREE(pp_htlc_info);
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


/** local commit_txの送金先処理 (close)
 *
 *  1. create local htlc secret
 *  2. vout
 *      [to_local]
 *          to_local tx作成 + 署名 --> 戻り値 ???
 *      [to_remote]
 *          nothing
 *      [HTLCs]
 *          calc fee
 *          amount >= dust + fee
 *              create HTLC tx
 *              commit_txの送金先 tx作成 + 署名 --> 戻り値 ???
 *
 * @param[in,out]   pChannel
 * @param[in]       pCommitTxInfo
 * @param[out]      pClose
 * @param[in]       pTxCommit
 * @param[in]       pWitScriptToLocal
 * @param[in]       ppHtlcInfo
 * @param[in]       pBaseFeeInfo
 * @param[in]       ToSelfDelay
 * @retval  true    成功
 */
static bool create_local_spent__close(
    ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo,
    uint32_t ToSelfDelay)
{
    uint16_t htlc_num = 0;
    btc_tx_t *pCloseTxToLocal = &pClose->p_tx[LN_CLOSE_IDX_TO_LOCAL];
    btc_tx_t *pCloseTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];
    utl_push_t wallet_infos;
    btc_keys_t htlckey;

    utl_push_init(&wallet_infos, &pClose->tx_buf, 0);
    if (!ln_signer_htlc_localkey(&htlckey, &pChannel->keys_local)) return false;

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("+++[%d]to_local\n", vout_idx);
            if (!create_local_spent_to_local(
                pChannel, pCommitTxInfo, pCloseTxToLocal, pWitScriptToLocal, pTxCommit->vout[vout_idx].value, vout_idx, ToSelfDelay)) return false;
        } else if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("+++[%d]to_remote\n", vout_idx);
        } else {
            const ln_comtx_htlc_info_t *p_htlc_info = ppHtlcInfo[htlc_idx];
            uint64_t fee_sat = (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? pBaseFeeInfo->htlc_timeout_fee : pBaseFeeInfo->htlc_success_fee;

            LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? "offered" : "received");
            assert(pTxCommit->vout[vout_idx].value >= pBaseFeeInfo->dust_limit_satoshi + fee_sat);

            //htlc tx
            btc_tx_t htlc_tx = BTC_TX_INIT;
            if (!ln_htlctx_create(
                &htlc_tx, (pTxCommit->vout[vout_idx].value - fee_sat), pWitScriptToLocal,
                p_htlc_info->type, p_htlc_info->cltv_expiry, pCommitTxInfo->txid, vout_idx)) {
                btc_tx_free(&htlc_tx);
                return false;
            }
            if (!create_local_spent_htlc__htlc_tx(
                pChannel, &htlc_tx, pTxCommit->vout[vout_idx].value, p_htlc_info, &htlckey)) {
                LOGE("fail: sign vout[%d]\n", vout_idx);
                btc_tx_free(&htlc_tx);
                return false;
            }
            //return `htlc_tx` to the caller
            memcpy(&pCloseTxHtlcs[htlc_num], &htlc_tx, sizeof(btc_tx_t));

            //spending tx for the htlc tx
            btc_tx_t spend_tx = BTC_TX_INIT;
            if (!create_local_spent_htlc__spend_tx_for_htlc_tx(
                pChannel, &htlc_tx, &spend_tx, pWitScriptToLocal, ToSelfDelay)) {
                btc_tx_free(&spend_tx);
                return false;
            }

            //return `spend_tx` to the caller
            if (!utl_push_data(&wallet_infos, &spend_tx, sizeof(btc_tx_t))) {
                btc_tx_free(&spend_tx);
                return false;
            }
            pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
            htlc_num++;
        }
    }
    return true;
}


/** local commit_txの送金先処理 (commitment_signed, HTLC sigs only)
 *
 *  vout
 *      [to_local]
 *          nothing
 *      [to_remote]
 *          nothing
 *      [HTLCs]
 *          calc fee
 *          amount >= dust + fee
 *              create HTLC tx
 *              commitment_signedで受信したhtlc_signatureのverify
 *              HTLC txのverify
 *              verify失敗ならbreak
 *              signatureの保存
 *
 * @param[in,out]   pChannel
 * @param[in]       pCommitTxInfo
 * @param[in]       pHtlcSigs
 * @param[in]       HtlcSigsNum
 * @param[in]       pTxCommit
 * @param[in]       pWitScriptToLocal
 * @param[in]       ppHtlcInfo
 * @param[in]       pBaseFeeInfo
 * @param[in]       ToSelfDelay
 * @retval  true    成功
 */
static bool create_local_spent__verify(
    ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    uint16_t HtlcSigsNum,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo)
{
    uint16_t htlc_num = 0;
    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("+++[%d]to_local\n", vout_idx);
            continue;
        }
        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("+++[%d]to_remote\n", vout_idx);
            continue;
        }

        //HTLCs
        if (htlc_num >= HtlcSigsNum) {
            LOGE("fail: both the numbers of htlcs do not match vout_cnt=%u, sigs=%u\n", pTxCommit->vout_cnt, HtlcSigsNum);
            return false;
        }

        const ln_comtx_htlc_info_t *p_htlc_info = ppHtlcInfo[htlc_idx];
        uint64_t fee_sat = (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? pBaseFeeInfo->htlc_timeout_fee : pBaseFeeInfo->htlc_success_fee;

        LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? "offered" : "received");
        assert(pTxCommit->vout[vout_idx].value >= pBaseFeeInfo->dust_limit_satoshi + fee_sat);

        btc_tx_t tx = BTC_TX_INIT;
        if (!ln_htlctx_create(
            &tx, (pTxCommit->vout[vout_idx].value - fee_sat), pWitScriptToLocal,
            p_htlc_info->type, p_htlc_info->cltv_expiry, pCommitTxInfo->txid, vout_idx)) {
            btc_tx_free(&tx);
            return false;
        }
        if (!create_local_verify_htlc(
            pChannel, &tx, pHtlcSigs[htlc_num], &p_htlc_info->wit_script, pTxCommit->vout[vout_idx].value)) {
            btc_tx_free(&tx);
            return false;
        }
        //XXX: save the commitment_signed message?
        //OKなら各HTLCに保持
        //  相手がunilateral closeした後に送信しなかったら、この署名を使う
        memcpy(pChannel->cnl_add_htlc[p_htlc_info->add_htlc_idx].remote_sig, pHtlcSigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
        btc_tx_free(&tx);
        htlc_num++;
    }
    return true;
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
    const ln_commit_tx_t *pCommitTxInfo,
    btc_tx_t *pTxToLocal,
    const utl_buf_t *pWitScriptToLocal,
    uint64_t Amount,
    uint32_t VoutIdx,
    uint32_t ToSelfDelay)
{
    btc_tx_t tx = BTC_TX_INIT;
    if (!ln_wallet_create_to_local(
        pChannel, &tx, Amount, ToSelfDelay, pWitScriptToLocal, pCommitTxInfo->txid, VoutIdx, false)) {
        btc_tx_free(&tx);
        return false;
    }
    memcpy(pTxToLocal, &tx, sizeof(tx));
    return true;
}


static bool create_local_verify_htlc(
    const ln_channel_t *pChannel,
    btc_tx_t *pTx,
    const uint8_t *pHtlcSig,
    const utl_buf_t *pScript,
    uint64_t Amount)
{
    utl_buf_t buf_sig = UTL_BUF_INIT;
    if (!btc_sig_rs2der(&buf_sig, pHtlcSig)) return false;
    if (!ln_htlctx_verify(
        pTx, Amount, NULL, NULL, pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
        &buf_sig, pScript)) {
        utl_buf_free(&buf_sig);
        LOGE("fail: verify vout\n");
        btc_tx_free(pTx);
        return false;
    }
    utl_buf_free(&buf_sig);
    M_DBG_PRINT_TX2(pTx);
    return true;
}


static bool create_local_spent_htlc__htlc_tx(
    const ln_channel_t *pChannel,
    btc_tx_t *pTxHtlc,
    uint64_t Amount,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey)
{
    bool ret_img = false;
    uint8_t preimage[LN_SZ_PREIMAGE];

    if (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) {
        ret_img = search_preimage(
            preimage,
            pChannel->cnl_add_htlc[pHtlcInfo->add_htlc_idx].payment_hash,
            true);
        LOGD("[received]have preimage=%s\n", (ret_img) ? "yes" : "NO");
        if (!ret_img) {
            LOGD("skip create HTLC tx\n");
            return true;
        }
    } else if (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_OFFERED) {
        LOGD("[offered]\n");
    } else {
        assert(0);
        return false;
    }

    uint8_t local_sig[LN_SZ_SIGNATURE];
    if (!ln_htlctx_sign_rs(
        pTxHtlc, local_sig, Amount, pHtlcKey, &pHtlcInfo->wit_script)) {
        LOGE("fail: sign htlc_tx\n");
        return false;
    }
    if (!ln_htlctx_set_vin0_rs(
        pTxHtlc, local_sig, pChannel->cnl_add_htlc[pHtlcInfo->add_htlc_idx].remote_sig,
        (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) ? preimage : NULL,
        NULL, &pHtlcInfo->wit_script, LN_HTLCTX_SIG_TIMEOUT_SUCCESS)) {
        LOGE("fail: set htlc_tx vout\n");
        return false;
    }
    M_DBG_PRINT_TX2(pTxHtlc);
    return true;
}


//create spending tx for the htlc tx (same as one for `to_tocal` output)
static bool create_local_spent_htlc__spend_tx_for_htlc_tx(
    const ln_channel_t *pChannel,
    const btc_tx_t *pTxHtlc,
    btc_tx_t *pTxSpend,
    const utl_buf_t *pWitScriptToLocal,
    uint32_t ToSelfDelay)
{
    uint8_t txid[BTC_SZ_TXID];
    if (!btc_tx_txid(pTxHtlc, txid)) return false;

    if (!ln_wallet_create_to_local(
        pChannel, pTxSpend, pTxHtlc->vout[0].value, ToSelfDelay, pWitScriptToLocal, txid, 0, false)) {
        //XXX: return true;
        return false;
    }
    LOGD("*** HTLC out Tx ***\n");
    M_DBG_PRINT_TX2(pTxSpend);
    return true;
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
        } else {
            assert(0);
            goto LABEL_ERROR;
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


static bool create_remote_spent__with_close(
    const ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo)
{
    uint16_t htlc_num = 0;

    btc_tx_t *pCloseTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];

    btc_keys_t htlckey;
    if (!ln_signer_htlc_remotekey(&htlckey, &pChannel->keys_local, &pChannel->keys_remote)) return false;

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("---[%d]to_local\n", vout_idx);
            continue;
        }
        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("---[%d]to_remote\n", vout_idx);
            btc_tx_t tx = BTC_TX_INIT;
            if (!ln_wallet_create_to_remote(
                pChannel, &tx, pTxCommit->vout[vout_idx].value, pCommitTxInfo->txid, vout_idx)) {
                //LOGD("no to_remote output\n");
                LOGE("fail: ???\n");
                btc_tx_free(&tx);
                //continue;
                return true;
            }
            memcpy(&pClose->p_tx[LN_CLOSE_IDX_TO_REMOTE], &tx, sizeof(tx));
            btc_tx_init(&tx); //force clear
        }
        const ln_comtx_htlc_info_t *p_htlc_info = ppHtlcInfo[htlc_idx];
        const uint8_t *p_payhash = pChannel->cnl_add_htlc[p_htlc_info->add_htlc_idx].payment_hash;
        uint64_t fee_sat =
            (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ?
            pBaseFeeInfo->htlc_timeout_fee : pBaseFeeInfo->htlc_success_fee;

        if (!create_remote_spent_htlc__with_close(
            pCommitTxInfo, &pCloseTxHtlcs[htlc_num], pTxCommit, pWitScriptToLocal, p_htlc_info,
            &htlckey, fee_sat, vout_idx, p_payhash)) return false;
        pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
        htlc_num++;
    }
    return true;
}


static bool create_remote_spent__with_htlc_sigs(
    const ln_channel_t *pChannel,
    const ln_commit_tx_t *pCommitTxInfo,
    uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo)
{
    uint16_t htlc_num = 0;

    btc_keys_t htlckey;
    if (!ln_signer_htlc_remotekey(&htlckey, &pChannel->keys_local, &pChannel->keys_remote)) return false;

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("---[%d]to_local\n", vout_idx);
            continue;
        }
        if (htlc_idx == LN_COMTX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("---[%d]to_remote\n", vout_idx);
            continue;
        }
        const ln_comtx_htlc_info_t *p_htlc_info = ppHtlcInfo[htlc_idx];
        uint64_t fee_sat =
            (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ?
            pBaseFeeInfo->htlc_timeout_fee : pBaseFeeInfo->htlc_success_fee;

        if (!create_remote_spent_htlc__with_htlc_sig(
            pCommitTxInfo, pHtlcSigs[htlc_num], pTxCommit, pWitScriptToLocal, p_htlc_info,
            &htlckey, fee_sat, vout_idx)) {
            LOGE("fail: sign vout[%d]\n", vout_idx);
            return false;
        }
        htlc_num++;
    }
    return true;
}


/** create HTLC sigs in remote comitment transaction
 *
 * @param[in]       pCommitTxInfo
 * @param[out]      pHtlcSig        HTLC署名
 * @param[in]       pTxCommit
 * @param[in]       pWitScriptToLocal
 * @param[in]       pHtlcInfo
 * @param[in]       pHtlcKey
 * @param[in]       Fee
 * @param[in]       VoutIdx
 * @retval  true    成功
 */
static bool create_remote_spent_htlc__with_htlc_sig(
    const ln_commit_tx_t *pCommitTxInfo,
    uint8_t *pHtlcSig,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx)
{
    bool ret = false;

    LOGD("---HTLC[%d]\n", VoutIdx);
    btc_tx_t tx = BTC_TX_INIT;
    if (!ln_htlctx_create(
        &tx, pTxCommit->vout[VoutIdx].value - Fee, pWitScriptToLocal, pHtlcInfo->type,
        pHtlcInfo->cltv_expiry, pCommitTxInfo->txid, VoutIdx)) goto LABEL_EXIT;

    if (!ln_htlctx_sign_rs(
        &tx, pHtlcSig, pTxCommit->vout[VoutIdx].value, pHtlcKey, &pHtlcInfo->wit_script)) {
        LOGE("fail: sign_htlc_tx: vout[%d]\n", VoutIdx);
        goto LABEL_EXIT;
    }

    ret = true;

LABEL_EXIT:
    btc_tx_free(&tx);
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
 * @param[in]       pCommitTxInfo
 * @param[out]      pCloseTxHtlc        Close処理結果のHTLC tx
 * @param[in]       pTxCommit
 * @param[in]       pWitScriptToLocal
 * @param[in]       pHtlcInfo
 * @param[in]       pHtlcKey
 * @param[in]       Fee
 * @param[in]       VoutIdx
 * @param[in]       pPayHash
 * @retval  true    成功
 */
static bool create_remote_spent_htlc__with_close(
    const ln_commit_tx_t *pCommitTxInfo,
    btc_tx_t *pCloseTxHtlc,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx,
    const uint8_t *pPayHash)
{
    LOGD("---HTLC[%d]\n", VoutIdx);
    btc_tx_t tx = BTC_TX_INIT;
    if (!ln_htlctx_create(
        &tx, pTxCommit->vout[VoutIdx].value - Fee, pWitScriptToLocal,
        pHtlcInfo->type, pHtlcInfo->cltv_expiry, pCommitTxInfo->txid, VoutIdx)) return false;

    if (pHtlcInfo->type == LN_COMTX_OUTPUT_TYPE_OFFERED) {
        uint8_t preimage[LN_SZ_PREIMAGE];
        if (search_preimage(preimage, pPayHash, true)) {
            LOGD("[offered]have preimage\n");
            utl_buf_free(&tx.vout[0].script);
            tx.locktime = 0;
            if (!ln_wallet_htlctx_set_vin0( //wit[0]に署名用秘密鍵を設定しておく(wallet用)
                &tx, pHtlcKey->priv, preimage, &pHtlcInfo->wit_script, LN_HTLCTX_SIG_REMOTE_OFFER)) goto LABEL_ERROR;
        } else {
            LOGD("[offered]no preimage\n");
        }
    } else {
        LOGD("[received]\n");
        utl_buf_free(&tx.vout[0].script);
        tx.locktime = pHtlcInfo->cltv_expiry;
        if (!ln_wallet_htlctx_set_vin0( //wit[0]に署名用秘密鍵を設定しておく(wallet用)
            &tx, pHtlcKey->priv, NULL, &pHtlcInfo->wit_script, LN_HTLCTX_SIG_REMOTE_RECV)) goto LABEL_ERROR;
    }

    memcpy(pCloseTxHtlc, &tx, sizeof(tx));
    return true;

LABEL_ERROR:
    btc_tx_free(&tx);
    return false;
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

    //LOGD("compare preimage : ");
    //DUMPD(pPreimage, LN_SZ_PREIMAGE);
    uint8_t payment_hash[BTC_SZ_HASH256];
    ln_payment_hash_calc(payment_hash, pPreimage);
    if (memcmp(payment_hash, prm->hash, BTC_SZ_HASH256)) return false;
    //LOGD("preimage match!: ");
    //DUMPD(pPreimage, LN_SZ_PREIMAGE);
    memcpy(prm->image, pPreimage, LN_SZ_PREIMAGE);
    if (prm->b_closing && Expiry != UINT32_MAX) {
        //期限切れによる自動削除をしない
        ln_db_preimage_set_expiry(p_db_param, UINT32_MAX); //XXX:
    }
    return true;
}
