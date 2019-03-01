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
    const ln_update_t *pUpdates,
    const ln_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat,
    bool bLocal);


//local
static bool create_local_htlc_info_and_amount(
    const ln_update_t *pUpdates,
    const ln_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat);
static bool create_local_set_vin0_and_verify(
    btc_tx_t *pTxCommit,
    const ln_funding_info_t *pFundingInfo,
    const uint8_t *pSigLocal,
    const uint8_t *pSigRemote);
static bool create_local_spent__verify(
    ln_channel_t *pChannel,
    const ln_commit_info_t *pCommitInfo,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo);
static bool create_local_spent__close(
    ln_channel_t *pChannel,
    const ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo,
    uint32_t ToSelfDelay);
static bool create_local_spent_to_local(
    const ln_channel_t *pChannel,
    const ln_commit_info_t *pCommitInfo,
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
    const ln_update_t *pUpdates,
    const ln_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat);
static bool create_remote_spent__with_close(
    const ln_channel_t *pChannel,
    const ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo);
static bool create_remote_spent__with_htlc_sigs(
    const ln_channel_t *pChannel,
    const ln_commit_info_t *pCommitInfo,
    uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    const ln_comtx_base_fee_info_t *pBaseFeeInfo);
static bool create_remote_spent_htlc__with_htlc_sig(
    const ln_commit_info_t *pCommitInfo,
    uint8_t *pHtlcSig,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_comtx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx);
static bool create_remote_spent_htlc__with_close(
    const ln_commit_info_t *pCommitInfo,
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
    ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    uint16_t NumHtlcSigs)
{
    LOGD("BEGIN\n");

    bool ret = false;

    ln_comtx_info_t comtx_info;
    if (!ln_comtx_info_create_local(&comtx_info, pCommitInfo, pChannel)) return false;

    uint8_t local_sig[LN_SZ_SIGNATURE];
    btc_tx_t tx_commit = BTC_TX_INIT;

    //check num_htlc_outputs
    if (pClose) {
        if (comtx_info.num_htlc_outputs != pClose->num - LN_CLOSE_IDX_HTLC) { //XXX: ???
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
    }
    if (pHtlcSigs) {
        if (comtx_info.num_htlc_outputs != NumHtlcSigs) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
    }

    //set pCommitInfo
    pCommitInfo->local_msat = comtx_info.local_msat;
    pCommitInfo->remote_msat = comtx_info.remote_msat;
    pCommitInfo->num_htlc_outputs = comtx_info.num_htlc_outputs;
    if (!ln_comtx_create_rs(&tx_commit, local_sig, &comtx_info, &pChannel->keys_local)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //XXX: separate
    if (!create_local_set_vin0_and_verify(&tx_commit, &pChannel->funding_info, local_sig, pCommitInfo->remote_sig)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //txid
    if (!btc_tx_txid(&tx_commit, pCommitInfo->txid)) goto LABEL_EXIT;
    LOGD("local commit_txid: ");
    TXIDD(pCommitInfo->txid);

    //XXX:
    if (pClose) {
        if (!create_local_spent__close(
            pChannel, pCommitInfo, pClose, &tx_commit, &comtx_info.to_local.wit_script,
            (const ln_comtx_htlc_info_t **)comtx_info.pp_htlc_info,
            &comtx_info.base_fee_info, pCommitInfo->to_self_delay)) goto LABEL_EXIT;
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
        btc_tx_init(&tx_commit); //force clear
    }
    if (pHtlcSigs) {
        if (!create_local_spent__verify(
            pChannel, pCommitInfo, pHtlcSigs, &tx_commit, &comtx_info.to_local.wit_script,
            (const ln_comtx_htlc_info_t **)comtx_info.pp_htlc_info, &comtx_info.base_fee_info)) goto LABEL_EXIT;
    }
    btc_tx_free(&tx_commit);

    ret = true;

LABEL_EXIT:
    ln_comtx_info_free(&comtx_info);
    return ret;
}


bool HIDDEN ln_comtx_info_create_local(ln_comtx_info_t *pComTxInfo, const ln_commit_info_t *pCommitInfo, const ln_channel_t *pChannel)
{
    bool bLocal = true;    

    bool ret = false;

    memset(pComTxInfo, 0x00, sizeof(ln_comtx_info_t));

    pComTxInfo->local_msat = pCommitInfo->local_msat;
    pComTxInfo->remote_msat = pCommitInfo->remote_msat;

    LOGD("local commitment_number=%" PRIu64 "\n", pCommitInfo->commit_num);
    //
    pComTxInfo->obscured_commit_num =
        ln_comtx_calc_obscured_commit_num(pCommitInfo->obscured_commit_num_mask, pCommitInfo->commit_num);

    //HTLCs (amount)
    pComTxInfo->pp_htlc_info = (ln_comtx_htlc_info_t **)UTL_DBG_MALLOC(
        sizeof(ln_comtx_htlc_info_t *) * (LN_HTLC_MAX_XXX));
    if (!pComTxInfo->pp_htlc_info) goto LABEL_EXIT;
    if (!create_local_htlc_info_and_amount(
        pChannel->update_info.updates, pChannel->update_info.htlcs, pComTxInfo->pp_htlc_info, &pComTxInfo->num_htlc_infos,
        &pComTxInfo->local_msat, &pComTxInfo->remote_msat)) goto LABEL_EXIT;

    //HTLCs (script)
    for (int lp = 0; lp < pComTxInfo->num_htlc_infos; lp++) {
        if (!ln_script_create_htlc(
            &pComTxInfo->pp_htlc_info[lp]->wit_script,
            pComTxInfo->pp_htlc_info[lp]->type,
            pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
            pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
            pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
            pComTxInfo->pp_htlc_info[lp]->payment_hash,
            pComTxInfo->pp_htlc_info[lp]->cltv_expiry)) goto LABEL_EXIT;
    }

    //print amount of HTLCs
    LOGD("-------\n");
    LOGD("local_msat  %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->local_msat, pComTxInfo->local_msat);
    LOGD("remote_msat %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->remote_msat, pComTxInfo->remote_msat);
    for (int lp = 0; lp < pComTxInfo->num_htlc_infos; lp++) {
        LOGD("  [%d] %" PRIu64 " (%s)\n",
            lp, pComTxInfo->pp_htlc_info[lp]->amount_msat,
            (pComTxInfo->pp_htlc_info[lp]->type == LN_COMTX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //fund (vin)
    pComTxInfo->fund.txid = ln_funding_info_txid(pCommitInfo->p_funding_info);
    pComTxInfo->fund.txid_index = ln_funding_info_txindex(pCommitInfo->p_funding_info);
    pComTxInfo->fund.satoshi = pCommitInfo->p_funding_info->funding_satoshis;
    pComTxInfo->fund.p_wit_script = &pCommitInfo->p_funding_info->wit_script;

    //to_local
    pComTxInfo->to_local.satoshi = LN_MSAT2SATOSHI(pComTxInfo->local_msat);
    if (!ln_script_create_to_local(
        &pComTxInfo->to_local.wit_script,
        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pCommitInfo->to_self_delay)) return false;

    //to_remote
    pComTxInfo->to_remote.satoshi = LN_MSAT2SATOSHI(pComTxInfo->remote_msat);
    pComTxInfo->to_remote.pubkey = pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_PUBKEY];

    //fee
    pComTxInfo->base_fee_info.feerate_per_kw = pChannel->feerate_per_kw;
    pComTxInfo->base_fee_info.dust_limit_satoshi = pCommitInfo->dust_limit_sat;
    /*void*/ ln_comtx_base_fee_calc(
        &pComTxInfo->base_fee_info, (const ln_comtx_htlc_info_t **)pComTxInfo->pp_htlc_info, pComTxInfo->num_htlc_infos);

    pComTxInfo->b_trimmed = false;
    ln_comtx_info_sub_fee_and_trim_outputs(pComTxInfo, ln_funding_info_is_funder(pCommitInfo->p_funding_info, bLocal));
    pComTxInfo->num_htlc_outputs = ln_comtx_info_get_num_htlc_outputs(pComTxInfo);

    ret = true;

LABEL_EXIT:
    if (!ret) {
        ln_comtx_info_free(pComTxInfo);
    }
    return ret;
}


void HIDDEN ln_comtx_info_free(ln_comtx_info_t *pComTxInfo)
{
    utl_buf_free(&pComTxInfo->to_local.wit_script);
    if (pComTxInfo->pp_htlc_info) {
        for (int lp = 0; lp < pComTxInfo->num_htlc_infos; lp++) {
            ln_comtx_htlc_info_free(pComTxInfo->pp_htlc_info[lp]);
            UTL_DBG_FREE(pComTxInfo->pp_htlc_info[lp]);
        }
        UTL_DBG_FREE(pComTxInfo->pp_htlc_info);
    }
}


bool ln_comtx_create_remote(
    const ln_channel_t *pChannel,
    ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    uint8_t (**ppHtlcSigs)[LN_SZ_SIGNATURE])
{
    LOGD("BEGIN\n");

    bool bLocal = false;

    bool ret = false;

    uint8_t (*p_htlc_sigs)[LN_SZ_SIGNATURE] = 0;
    ln_comtx_htlc_info_t **pp_htlc_info = 0;
    utl_buf_t wit_script_to_local = UTL_BUF_INIT;
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint16_t num_htlc_infos = 0;

    ln_comtx_info_t comtx_info;
    memset(&comtx_info, 0x00, sizeof(ln_comtx_info_t));

    comtx_info.local_msat = pCommitInfo->local_msat;
    comtx_info.remote_msat = pCommitInfo->remote_msat;

    //to_local
    if (!ln_script_create_to_local(
        &wit_script_to_local,
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pCommitInfo->to_self_delay)) return false;

    //HTLC info (amount)
    pp_htlc_info = (ln_comtx_htlc_info_t **)UTL_DBG_MALLOC(sizeof(ln_comtx_htlc_info_t *) * LN_HTLC_MAX_XXX);
    if (!pp_htlc_info) goto LABEL_EXIT;
    if (!create_remote_htlc_info_and_amount(
        pChannel->update_info.updates, pChannel->update_info.htlcs, pp_htlc_info, &num_htlc_infos,
        &comtx_info.local_msat, &comtx_info.remote_msat)) goto LABEL_EXIT;

    //HTLC info (script)
    for (int lp = 0; lp < num_htlc_infos; lp++) {
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
    for (int lp = 0; lp < num_htlc_infos; lp++) {
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
    LOGD("(remote)local_msat  %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->local_msat, comtx_info.local_msat);
    LOGD("(remote)remote_msat %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->remote_msat, comtx_info.remote_msat);
    for (int lp = 0; lp < num_htlc_infos; lp++) {
        LOGD("  have HTLC[%d] %" PRIu64 " (%s)\n", lp, pp_htlc_info[lp]->amount_msat, (pp_htlc_info[lp]->type != LN_COMTX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");


    //commitment transaction
    LOGD("remote commitment_number=%" PRIu64 "\n", pCommitInfo->commit_num);
    //  fee
    comtx_info.base_fee_info.feerate_per_kw = pChannel->feerate_per_kw;
    comtx_info.base_fee_info.dust_limit_satoshi = pCommitInfo->dust_limit_sat;
    /*void*/ ln_comtx_base_fee_calc(&comtx_info.base_fee_info, (const ln_comtx_htlc_info_t **)pp_htlc_info, num_htlc_infos);
    //
    comtx_info.fund.txid = ln_funding_info_txid(pCommitInfo->p_funding_info);
    comtx_info.fund.txid_index = ln_funding_info_txindex(pCommitInfo->p_funding_info);
    comtx_info.fund.satoshi = pCommitInfo->p_funding_info->funding_satoshis;
    comtx_info.fund.p_wit_script = &pCommitInfo->p_funding_info->wit_script;
    comtx_info.to_local.satoshi = LN_MSAT2SATOSHI(comtx_info.local_msat);
    comtx_info.to_local.wit_script = wit_script_to_local;
    comtx_info.to_remote.satoshi = LN_MSAT2SATOSHI(comtx_info.remote_msat);
    comtx_info.to_remote.pubkey = pCommitInfo->p_script_pubkeys[LN_SCRIPT_IDX_PUBKEY];
    comtx_info.obscured_commit_num =
        ln_comtx_calc_obscured_commit_num(pCommitInfo->obscured_commit_num_mask, pCommitInfo->commit_num);
    comtx_info.pp_htlc_info = pp_htlc_info;
    comtx_info.num_htlc_infos = num_htlc_infos;
    comtx_info.b_trimmed = false;
    //
    ln_comtx_info_sub_fee_and_trim_outputs(&comtx_info, ln_funding_info_is_funder(pCommitInfo->p_funding_info, bLocal));
    comtx_info.num_htlc_outputs = ln_comtx_info_get_num_htlc_outputs(&comtx_info);

    //check num_htlc_outputs
    if (pClose) {
        if (comtx_info.num_htlc_outputs != pClose->num - LN_CLOSE_IDX_HTLC) { //XXX: ???
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
    }
    pCommitInfo->num_htlc_outputs = comtx_info.num_htlc_outputs;

    if (!ln_comtx_create_rs(&tx_commit, pCommitInfo->remote_sig, &comtx_info, &pChannel->keys_local)) goto LABEL_EXIT;
    LOGD("++++++++++++++ remote commit tx: tx_commit[%016" PRIx64 "]\n", pChannel->short_channel_id);
    M_DBG_PRINT_TX(&tx_commit);


    pCommitInfo->local_msat = comtx_info.local_msat;
    pCommitInfo->remote_msat = comtx_info.remote_msat;

    if (!btc_tx_txid(&tx_commit, pCommitInfo->txid)) goto LABEL_EXIT;
    LOGD("remote commit_txid: ");
    TXIDD(pCommitInfo->txid);

    if (pClose) {
        if (!create_remote_spent__with_close(
            pChannel, pCommitInfo, pClose, &tx_commit, &wit_script_to_local,
            (const ln_comtx_htlc_info_t **)pp_htlc_info, &comtx_info.base_fee_info)) goto LABEL_EXIT;
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
        btc_tx_free(&tx_commit); //force clear
    }
    if (ppHtlcSigs) {
        if (comtx_info.num_htlc_outputs) {
            *ppHtlcSigs = (uint8_t (*)[LN_SZ_SIGNATURE])UTL_DBG_MALLOC(LN_SZ_SIGNATURE * comtx_info.num_htlc_outputs);
            if (!*ppHtlcSigs) goto LABEL_EXIT;
            p_htlc_sigs = *ppHtlcSigs;
        }
        if (!create_remote_spent__with_htlc_sigs(
            pChannel, pCommitInfo, p_htlc_sigs, &tx_commit, &wit_script_to_local,
            (const ln_comtx_htlc_info_t **)pp_htlc_info, &comtx_info.base_fee_info)) goto LABEL_EXIT;
    }

    ret = true;

LABEL_EXIT:
    if (!ret) {
        UTL_DBG_FREE(p_htlc_sigs);
    }
    btc_tx_free(&tx_commit);
    utl_buf_free(&wit_script_to_local);
    if (pp_htlc_info) {
        for (int lp = 0; lp < num_htlc_infos; lp++) {
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
    const ln_update_t *pUpdates,
    const ln_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat)
{
    return create_htlc_info_and_amount(pUpdates, pHtlcs, ppHtlcInfo, pHtlcInfoCnt, pLocalMsat, pRemoteMsat, true);
}


/** set vin[0] and verify sigs
 *
 * @param[in,out]   pTxCommit   [in]commit_tx(署名無し) / [out]commit_tx(署名あり)
 * @param[in]       pFundingInfo
 * @param[in]       pSigLocal
 * @param[in]       pSigRemote
 * @retval  true    成功
 */
static bool create_local_set_vin0_and_verify(
    btc_tx_t *pTxCommit,
    const ln_funding_info_t *pFundingInfo,
    const uint8_t *pSigLocal,
    const uint8_t *pSigRemote)
{
    LOGD("local verify\n");

    bool ret = false;

    utl_buf_t script_code = UTL_BUF_INIT;
    uint8_t sighash[BTC_SZ_HASH256];

    //set vin[0]
    if (!ln_comtx_set_vin_p2wsh_2of2_rs(
        pTxCommit, 0, pFundingInfo->key_order, pSigLocal, pSigRemote, &pFundingInfo->wit_script)) goto LABEL_EXIT;
    //  LOGD("++++++++++++++ local commit tx: [%016" PRIx64 "]\n", pChannel->short_channel_id);
    M_DBG_PRINT_TX(pTxCommit);

    //verify
    if (!btc_script_p2wsh_create_scriptcode(&script_code, &pFundingInfo->wit_script)) goto LABEL_EXIT;
    if (!btc_sw_sighash(pTxCommit, sighash, 0, pFundingInfo->funding_satoshis, &script_code)) goto LABEL_EXIT;
    if (!btc_sw_verify_p2wsh_2of2(pTxCommit, 0, sighash, &pFundingInfo->tx_data.vout[pFundingInfo->txindex].script)) goto LABEL_EXIT;

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
 * @param[in]       pCommitInfo
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
    const ln_commit_info_t *pCommitInfo,
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
                pChannel, pCommitInfo, pCloseTxToLocal, pWitScriptToLocal, pTxCommit->vout[vout_idx].value, vout_idx, ToSelfDelay)) return false;
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
                p_htlc_info->type, p_htlc_info->cltv_expiry, pCommitInfo->txid, vout_idx)) {
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
            pClose->p_htlc_idxs[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
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
 * @param[in]       pCommitInfo
 * @param[in]       pHtlcSigs
 * @param[in]       NumHtlcSigs
 * @param[in]       pTxCommit
 * @param[in]       pWitScriptToLocal
 * @param[in]       ppHtlcInfo
 * @param[in]       pBaseFeeInfo
 * @param[in]       ToSelfDelay
 * @retval  true    成功
 */
static bool create_local_spent__verify(
    ln_channel_t *pChannel,
    const ln_commit_info_t *pCommitInfo,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
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

        const ln_comtx_htlc_info_t *p_htlc_info = ppHtlcInfo[htlc_idx];
        uint64_t fee_sat = (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? pBaseFeeInfo->htlc_timeout_fee : pBaseFeeInfo->htlc_success_fee;

        LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ? "offered" : "received");
        assert(pTxCommit->vout[vout_idx].value >= pBaseFeeInfo->dust_limit_satoshi + fee_sat);

        btc_tx_t tx = BTC_TX_INIT;
        if (!ln_htlctx_create(
            &tx, (pTxCommit->vout[vout_idx].value - fee_sat), pWitScriptToLocal,
            p_htlc_info->type, p_htlc_info->cltv_expiry, pCommitInfo->txid, vout_idx)) {
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
        memcpy(pChannel->update_info.htlcs[p_htlc_info->htlc_idx].remote_sig, pHtlcSigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
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
    const ln_commit_info_t *pCommitInfo,
    btc_tx_t *pTxToLocal,
    const utl_buf_t *pWitScriptToLocal,
    uint64_t Amount,
    uint32_t VoutIdx,
    uint32_t ToSelfDelay)
{
    btc_tx_t tx = BTC_TX_INIT;
    if (!ln_wallet_create_to_local(
        pChannel, &tx, Amount, ToSelfDelay, pWitScriptToLocal, pCommitInfo->txid, VoutIdx, false)) {
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
            pChannel->update_info.htlcs[pHtlcInfo->htlc_idx].payment_hash,
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
        pTxHtlc, local_sig, pChannel->update_info.htlcs[pHtlcInfo->htlc_idx].remote_sig,
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
    const ln_update_t *pUpdates,
    const ln_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat)
{
    return create_htlc_info_and_amount(pUpdates, pHtlcs, ppHtlcInfo, pHtlcInfoCnt, pLocalMsat, pRemoteMsat, false);
}


static bool create_htlc_info_and_amount(
    const ln_update_t *pUpdates,
    const ln_htlc_t *pHtlcs,
    ln_comtx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat,
    bool bLocal)
{
    *pHtlcInfoCnt = 0;
    for (uint16_t update_idx = 0; update_idx < LN_UPDATE_MAX; update_idx++) {
        const ln_update_t *p_update = &pUpdates[update_idx];
        LOGD("flags = 0x%04x\n", p_update->flags);
        if (!LN_UPDATE_ENABLED(p_update)) continue;

        if (LN_UPDATE_UNCOMMITTED(p_update, bLocal)) {
            if (LN_UPDATE_ADD_HTLC_SEND_ENABLED(p_update, bLocal)) {
                LOGD("add htlc send\n");
                *pLocalMsat -= pHtlcs[p_update->htlc_idx].amount_msat;
            } else if (LN_UPDATE_DEL_HTLC_RECV_ENABLED(p_update, bLocal)) {
                if (LN_UPDATE_FULFILL_HTLC_RECV_ENABLED(p_update, bLocal)) {
                    LOGD("fulfill htlc recv\n");
                    *pRemoteMsat += pHtlcs[p_update->htlc_idx].amount_msat;
                } else {
                    LOGD("fail htlc recv\n");
                    *pLocalMsat += pHtlcs[p_update->htlc_idx].amount_msat;
                }
                continue;
            } else if (LN_UPDATE_ADD_HTLC_RECV_ENABLED(p_update, bLocal)) {
                LOGD("add htlc recv\n");
                *pRemoteMsat -= pHtlcs[p_update->htlc_idx].amount_msat;
            } else if (LN_UPDATE_DEL_HTLC_SEND_ENABLED(p_update, bLocal)) {
                if (LN_UPDATE_FULFILL_HTLC_SEND_ENABLED(p_update, bLocal)) {
                    LOGD("fulfill htlc send\n");
                    *pLocalMsat += pHtlcs[p_update->htlc_idx].amount_msat;
                } else {
                    LOGD("fail htlc send\n");
                    *pRemoteMsat += pHtlcs[p_update->htlc_idx].amount_msat;
                }
                continue;
            } else {
                continue;
            }
        }

        const ln_htlc_t *p_htlc = &pHtlcs[p_update->htlc_idx];
        const ln_update_t *p_update_del_htlc = ln_update_get_update_del_htlc_const(pUpdates, p_update->htlc_idx);
        if (p_update_del_htlc && LN_UPDATE_SOME_UPDATE_ENABLED(p_update_del_htlc, bLocal)) {
            LOGD(" DEL UPDATE[%u] HTLC[%u] [id=%" PRIu64 "](%" PRIu64 ")\n",
                update_idx, p_update->htlc_idx, p_htlc->id, p_htlc->amount_msat);
            continue;
        }

        ln_comtx_htlc_info_t *p_info = (ln_comtx_htlc_info_t *)UTL_DBG_MALLOC(sizeof(ln_comtx_htlc_info_t));
        ln_comtx_htlc_info_init(p_info);
        if (LN_UPDATE_ADD_HTLC_SEND_ENABLED(p_update, bLocal)) {
            p_info->type = LN_COMTX_OUTPUT_TYPE_OFFERED;
        } else if (LN_UPDATE_ADD_HTLC_RECV_ENABLED(p_update, bLocal)) {
            p_info->type = LN_COMTX_OUTPUT_TYPE_RECEIVED;
        } else {
            LOGE("unknown flags: %04x\n", p_update->flags);
            assert(0);
            UTL_DBG_FREE(p_info);
            goto LABEL_ERROR;
        }
        p_info->htlc_idx = p_update->htlc_idx;
        p_info->cltv_expiry = p_htlc->cltv_expiry;
        p_info->amount_msat = p_htlc->amount_msat;
        p_info->payment_hash = p_htlc->payment_hash;
        ppHtlcInfo[*pHtlcInfoCnt] = p_info;
        (*pHtlcInfoCnt)++;
        LOGD(" ADD UPDATE[%u] HTLC[%u] [id=%" PRIu64 "](%" PRIu64 ")\n",
            update_idx, p_update->htlc_idx, p_htlc->id, p_htlc->amount_msat);
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
    const ln_commit_info_t *pCommitInfo,
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
                pChannel, &tx, pTxCommit->vout[vout_idx].value, pCommitInfo->txid, vout_idx)) {
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
        const uint8_t *p_payhash = pChannel->update_info.htlcs[p_htlc_info->htlc_idx].payment_hash;
        uint64_t fee_sat =
            (p_htlc_info->type == LN_COMTX_OUTPUT_TYPE_OFFERED) ?
            pBaseFeeInfo->htlc_timeout_fee : pBaseFeeInfo->htlc_success_fee;

        if (!create_remote_spent_htlc__with_close(
            pCommitInfo, &pCloseTxHtlcs[htlc_num], pTxCommit, pWitScriptToLocal, p_htlc_info,
            &htlckey, fee_sat, vout_idx, p_payhash)) return false;
        pClose->p_htlc_idxs[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
        htlc_num++;
    }
    return true;
}


static bool create_remote_spent__with_htlc_sigs(
    const ln_channel_t *pChannel,
    const ln_commit_info_t *pCommitInfo,
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
            pCommitInfo, pHtlcSigs[htlc_num], pTxCommit, pWitScriptToLocal, p_htlc_info,
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
 * @param[in]       pCommitInfo
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
    const ln_commit_info_t *pCommitInfo,
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
        pHtlcInfo->cltv_expiry, pCommitInfo->txid, VoutIdx)) goto LABEL_EXIT;

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
 * @param[in]       pCommitInfo
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
    const ln_commit_info_t *pCommitInfo,
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
        pHtlcInfo->type, pHtlcInfo->cltv_expiry, pCommitInfo->txid, VoutIdx)) return false;

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

    preimage_t param;
    param.image = pPreimage;
    param.hash = pPayHash;
    param.b_closing = bClosing;
    if (!ln_db_preimage_search(search_preimage_func, &param)) return false;
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

    preimage_t *param = (preimage_t *)p_param;

    //LOGD("compare preimage : ");
    //DUMPD(pPreimage, LN_SZ_PREIMAGE);
    uint8_t payment_hash[BTC_SZ_HASH256];
    ln_payment_hash_calc(payment_hash, pPreimage);
    if (memcmp(payment_hash, param->hash, BTC_SZ_HASH256)) return false;
    //LOGD("preimage match!: ");
    //DUMPD(pPreimage, LN_SZ_PREIMAGE);
    memcpy(param->image, pPreimage, LN_SZ_PREIMAGE);
    if (param->b_closing && Expiry != UINT32_MAX) {
        //期限切れによる自動削除をしない
        ln_db_preimage_set_expiry(p_db_param, UINT32_MAX); //XXX:
    }
    return true;
}
