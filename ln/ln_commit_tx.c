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
/** @file   ln_commit_tx.c
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
#include "ln_commit_tx.h"
#include "ln_commit_tx_util.h"
#include "ln_htlc_tx.h"


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
static bool create_htlc_info_and_amount_pre_committed(
    const ln_update_info_t *pUpdateInfo,
    ln_commit_tx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat,
    bool bLocal);

static bool create_htlc_info_and_amount_committed(
    const ln_update_info_t *pUpdateInfo,
    ln_commit_tx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    bool bLocal);

//local
static bool create_local_set_vin0_and_verify(
    btc_tx_t *pTxCommit,
    const ln_funding_info_t *pFundingInfo,
    const uint8_t *pSigLocal,
    const uint8_t *pSigRemote);

//local vefiry
static bool create_local_verify_htlcs(
    const ln_commit_info_t *pCommitInfo,
    ln_update_info_t *pUpdateInfo,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_derkey_local_keys_t *pKeysLocal);

static bool create_local_verify_htlc(
    btc_tx_t *pTx,
    const uint8_t *pHtlcSig,
    const utl_buf_t *pScript,
    uint64_t Amount,
    const ln_derkey_local_keys_t *pKeysLocal);

//local close
static bool create_local_spend_tx(
    const ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote);

static bool create_local_spend_to_local_tx(
    const ln_commit_info_t *pCommitInfo,
    btc_tx_t *pTxToLocal,
    const utl_buf_t *pWitScriptToLocal,
    uint64_t Amount,
    uint32_t VoutIdx,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote);

static bool create_local_htlc_tx(
    btc_tx_t *pTxHtlc,
    uint64_t Amount,
    const ln_commit_tx_htlc_info_t *pHtlcInfo,
    const ln_update_info_t *pUpdateInfo,
    const btc_keys_t *pHtlcKey);

static bool create_local_spend_htlc_tx(
    const btc_tx_t *pTxHtlc,
    btc_tx_t *pTxSpend,
    const utl_buf_t *pWitScriptToLocal,
    uint32_t ToSelfDelay,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote);


//remote

//remote sign
static bool create_remote_sign_htlcs(
    const ln_commit_info_t *pCommitInfo,
    uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote);

static bool create_remote_sign_htlc(
    const ln_commit_info_t *pCommitInfo,
    uint8_t *pHtlcSig,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_commit_tx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx);

//remote close
static bool create_remote_spend_tx(
    const ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote);

static bool create_remote_spend_htlc_output_tx(
    const ln_commit_info_t *pCommitInfo,
    btc_tx_t *pCloseTxHtlc,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_commit_tx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx,
    const uint8_t *pPaymentHash);

static bool search_preimage(uint8_t *pPreimage, const uint8_t *pPaymentHash, bool bClosing);
static bool search_preimage_func(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);
static bool save_vouts_remote(const ln_commit_tx_info_t *pCommitTxInfo);


/********************************************************************
 * public functions
 ********************************************************************/

bool HIDDEN ln_commit_tx_create_local(
    ln_commit_info_t *pCommitInfo,
    ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    uint16_t NumHtlcSigs)
{
    LOGD("BEGIN\n");

    bool ret = false;

    ln_commit_tx_info_t commit_tx_info;
    if (!ln_commit_tx_info_create_pre_committed(
        &commit_tx_info, pCommitInfo, pUpdateInfo, pKeysLocal->script_pubkeys, true)) return false;

    uint8_t local_sig[LN_SZ_SIGNATURE];
    btc_tx_t tx_commit = BTC_TX_INIT;

    //check num_htlc_outputs
    if (commit_tx_info.num_htlc_outputs != NumHtlcSigs) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //set pCommitInfo
    pCommitInfo->local_msat = commit_tx_info.local_msat;
    pCommitInfo->remote_msat = commit_tx_info.remote_msat;
    pCommitInfo->num_htlc_outputs = commit_tx_info.num_htlc_outputs;
    if (!ln_commit_tx_create_rs(&tx_commit, local_sig, &commit_tx_info, pKeysLocal)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //XXX: separate
    if (!create_local_set_vin0_and_verify(&tx_commit, pCommitInfo->p_funding_info, local_sig, pCommitInfo->remote_sig)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //txid
    if (!btc_tx_txid(&tx_commit, pCommitInfo->txid)) goto LABEL_EXIT;
    LOGD("local commit_txid: ");
    TXIDD(pCommitInfo->txid);

    if (NumHtlcSigs) {
        if (!create_local_verify_htlcs(
            pCommitInfo, pUpdateInfo, pHtlcSigs,
            &tx_commit, &commit_tx_info,
            pKeysLocal)) goto LABEL_EXIT;
    }
    btc_tx_free(&tx_commit);

    ret = true;

LABEL_EXIT:
    ln_commit_tx_info_free(&commit_tx_info);
    return ret;
}


bool HIDDEN ln_commit_tx_create_local_close(
    const ln_commit_info_t *pCommitInfo,
    const ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote,
    ln_close_force_t *pClose)
{
    LOGD("BEGIN\n");

    bool ret = false;

    ln_commit_tx_info_t commit_tx_info;
    if (!ln_commit_tx_info_create_committed(
        &commit_tx_info, pCommitInfo, pUpdateInfo, pKeysLocal->script_pubkeys, true)) return false;

    uint8_t local_sig[LN_SZ_SIGNATURE];
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];

    //check num_htlc_outputs
    if (commit_tx_info.num_htlc_outputs != pClose->num - LN_CLOSE_IDX_HTLC) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //check pCommitInfo
    if (pCommitInfo->local_msat != commit_tx_info.local_msat ||
        pCommitInfo->remote_msat != commit_tx_info.remote_msat ||
        pCommitInfo->num_htlc_outputs != commit_tx_info.num_htlc_outputs) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    if (!ln_commit_tx_create_rs(&tx_commit, local_sig, &commit_tx_info, pKeysLocal)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //XXX: separate
    if (!create_local_set_vin0_and_verify(&tx_commit, pCommitInfo->p_funding_info, local_sig, pCommitInfo->remote_sig)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    //check txid
    if (!btc_tx_txid(&tx_commit, txid)) goto LABEL_EXIT;
    LOGD("local commit_txid: ");
    TXIDD(pCommitInfo->txid);
    if (memcmp(txid, pCommitInfo->txid, BTC_SZ_TXID)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //XXX:
    if (!create_local_spend_tx(
        pCommitInfo, pClose, &tx_commit, &commit_tx_info,
        pUpdateInfo, pKeysLocal, pKeysRemote)) goto LABEL_EXIT;
    memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
    btc_tx_init(&tx_commit); //force clear

    ret = true;

LABEL_EXIT:
    ln_commit_tx_info_free(&commit_tx_info);
    return ret;
}


bool HIDDEN ln_commit_tx_info_create_pre_committed(
    ln_commit_tx_info_t *pCommitTxInfo,
    const ln_commit_info_t *pCommitInfo,
    const ln_update_info_t *pUpdateInfo,
    const uint8_t (*pScriptPubkeys)[BTC_SZ_PUBKEY],
    bool bLocal)
{

    bool ret = false;

    memset(pCommitTxInfo, 0x00, sizeof(ln_commit_tx_info_t));

    pCommitTxInfo->local_msat = pCommitInfo->local_msat;
    pCommitTxInfo->remote_msat = pCommitInfo->remote_msat;

    LOGD("commitment_number=%" PRIu64 "\n", pCommitInfo->commit_num);
    //
    pCommitTxInfo->obscured_commit_num =
        ln_commit_tx_calc_obscured_commit_num(pCommitInfo->obscured_commit_num_mask, pCommitInfo->commit_num);

    //HTLCs (amount)
    pCommitTxInfo->pp_htlc_info = (ln_commit_tx_htlc_info_t **)UTL_DBG_MALLOC(
        sizeof(ln_commit_tx_htlc_info_t *) * (LN_HTLC_MAX));
    if (!pCommitTxInfo->pp_htlc_info) goto LABEL_EXIT;
    if (!create_htlc_info_and_amount_pre_committed(
        pUpdateInfo, pCommitTxInfo->pp_htlc_info, &pCommitTxInfo->num_htlc_infos,
        &pCommitTxInfo->local_msat, &pCommitTxInfo->remote_msat, bLocal)) goto LABEL_EXIT;

    //HTLCs (script)
    for (int lp = 0; lp < pCommitTxInfo->num_htlc_infos; lp++) {
        if (!ln_script_create_htlc(
            &pCommitTxInfo->pp_htlc_info[lp]->wit_script,
            pCommitTxInfo->pp_htlc_info[lp]->type,
            pScriptPubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
            pScriptPubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
            pScriptPubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
            pCommitTxInfo->pp_htlc_info[lp]->payment_hash,
            pCommitTxInfo->pp_htlc_info[lp]->cltv_expiry)) goto LABEL_EXIT;
    }

    //print amount of HTLCs
    LOGD("-------\n");
    LOGD("local_msat  %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->local_msat, pCommitTxInfo->local_msat);
    LOGD("remote_msat %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->remote_msat, pCommitTxInfo->remote_msat);
    for (int lp = 0; lp < pCommitTxInfo->num_htlc_infos; lp++) {
        LOGD("  [%d] %" PRIu64 " (%s)\n",
            lp, pCommitTxInfo->pp_htlc_info[lp]->amount_msat,
            (pCommitTxInfo->pp_htlc_info[lp]->type == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //fund (vin)
    pCommitTxInfo->fund.txid = ln_funding_info_txid(pCommitInfo->p_funding_info);
    pCommitTxInfo->fund.txid_index = ln_funding_info_txindex(pCommitInfo->p_funding_info);
    pCommitTxInfo->fund.satoshi = pCommitInfo->p_funding_info->funding_satoshis;
    pCommitTxInfo->fund.p_wit_script = &pCommitInfo->p_funding_info->wit_script;

    //to_local
    pCommitTxInfo->to_local.satoshi = LN_MSAT2SATOSHI(pCommitTxInfo->local_msat);
    if (!ln_script_create_to_local(
        &pCommitTxInfo->to_local.wit_script,
        pScriptPubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pScriptPubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pCommitInfo->to_self_delay)) return false;

    //to_remote
    pCommitTxInfo->to_remote.satoshi = LN_MSAT2SATOSHI(pCommitTxInfo->remote_msat);
    pCommitTxInfo->to_remote.pubkey = pScriptPubkeys[LN_SCRIPT_IDX_PUBKEY];

    //fee
    pCommitTxInfo->base_fee_info.feerate_per_kw =
        ln_update_info_get_feerate_per_kw_pre_committed(pUpdateInfo, bLocal);
    pCommitTxInfo->base_fee_info.dust_limit_satoshi = pCommitInfo->dust_limit_sat;
    /*void*/ ln_commit_tx_base_fee_calc(
        &pCommitTxInfo->base_fee_info, (const ln_commit_tx_htlc_info_t **)pCommitTxInfo->pp_htlc_info,
        pCommitTxInfo->num_htlc_infos);

    pCommitTxInfo->b_trimmed = false;
    ln_commit_tx_info_sub_fee_and_trim_outputs(pCommitTxInfo,
        ln_funding_info_is_funder(pCommitInfo->p_funding_info, bLocal));
    pCommitTxInfo->num_htlc_outputs = ln_commit_tx_info_get_num_htlc_outputs(pCommitTxInfo);

    ret = true;

LABEL_EXIT:
    if (!ret) {
        ln_commit_tx_info_free(pCommitTxInfo);
    }
    return ret;
}


bool HIDDEN ln_commit_tx_info_create_committed(
    ln_commit_tx_info_t *pCommitTxInfo,
    const ln_commit_info_t *pCommitInfo,
    const ln_update_info_t *pUpdateInfo,
    const uint8_t (*pScriptPubkeys)[BTC_SZ_PUBKEY],
    bool bLocal)
{

    bool ret = false;

    memset(pCommitTxInfo, 0x00, sizeof(ln_commit_tx_info_t));

    pCommitTxInfo->local_msat = pCommitInfo->local_msat;
    pCommitTxInfo->remote_msat = pCommitInfo->remote_msat;

    LOGD("commitment_number=%" PRIu64 "\n", pCommitInfo->commit_num);
    //
    pCommitTxInfo->obscured_commit_num =
        ln_commit_tx_calc_obscured_commit_num(pCommitInfo->obscured_commit_num_mask, pCommitInfo->commit_num);

    //HTLCs (amount)
    pCommitTxInfo->pp_htlc_info = (ln_commit_tx_htlc_info_t **)UTL_DBG_MALLOC(
        sizeof(ln_commit_tx_htlc_info_t *) * (LN_HTLC_MAX));
    if (!pCommitTxInfo->pp_htlc_info) goto LABEL_EXIT;
    if (!create_htlc_info_and_amount_committed(
        pUpdateInfo, pCommitTxInfo->pp_htlc_info, &pCommitTxInfo->num_htlc_infos, bLocal)) goto LABEL_EXIT;

    //HTLCs (script)
    for (int lp = 0; lp < pCommitTxInfo->num_htlc_infos; lp++) {
        if (!ln_script_create_htlc(
            &pCommitTxInfo->pp_htlc_info[lp]->wit_script,
            pCommitTxInfo->pp_htlc_info[lp]->type,
            pScriptPubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
            pScriptPubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
            pScriptPubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
            pCommitTxInfo->pp_htlc_info[lp]->payment_hash,
            pCommitTxInfo->pp_htlc_info[lp]->cltv_expiry)) goto LABEL_EXIT;
    }

    //print amount of HTLCs
    LOGD("-------\n");
    LOGD("local_msat  %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->local_msat, pCommitTxInfo->local_msat);
    LOGD("remote_msat %" PRIu64 " --> %" PRIu64 "\n", pCommitInfo->remote_msat, pCommitTxInfo->remote_msat);
    for (int lp = 0; lp < pCommitTxInfo->num_htlc_infos; lp++) {
        LOGD("  [%d] %" PRIu64 " (%s)\n",
            lp, pCommitTxInfo->pp_htlc_info[lp]->amount_msat,
            (pCommitTxInfo->pp_htlc_info[lp]->type == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //fund (vin)
    pCommitTxInfo->fund.txid = ln_funding_info_txid(pCommitInfo->p_funding_info);
    pCommitTxInfo->fund.txid_index = ln_funding_info_txindex(pCommitInfo->p_funding_info);
    pCommitTxInfo->fund.satoshi = pCommitInfo->p_funding_info->funding_satoshis;
    pCommitTxInfo->fund.p_wit_script = &pCommitInfo->p_funding_info->wit_script;

    //to_local
    pCommitTxInfo->to_local.satoshi = LN_MSAT2SATOSHI(pCommitTxInfo->local_msat);
    if (!ln_script_create_to_local(
        &pCommitTxInfo->to_local.wit_script,
        pScriptPubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pScriptPubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pCommitInfo->to_self_delay)) return false;

    //to_remote
    pCommitTxInfo->to_remote.satoshi = LN_MSAT2SATOSHI(pCommitTxInfo->remote_msat);
    pCommitTxInfo->to_remote.pubkey = pScriptPubkeys[LN_SCRIPT_IDX_PUBKEY];

    //fee
    pCommitTxInfo->base_fee_info.feerate_per_kw =
        ln_update_info_get_feerate_per_kw_committed(pUpdateInfo, bLocal);
    pCommitTxInfo->base_fee_info.dust_limit_satoshi = pCommitInfo->dust_limit_sat;
    /*void*/ ln_commit_tx_base_fee_calc(
        &pCommitTxInfo->base_fee_info, (const ln_commit_tx_htlc_info_t **)pCommitTxInfo->pp_htlc_info,
        pCommitTxInfo->num_htlc_infos);

    pCommitTxInfo->b_trimmed = false;
    ln_commit_tx_info_sub_fee_and_trim_outputs(pCommitTxInfo,
        ln_funding_info_is_funder(pCommitInfo->p_funding_info, bLocal));
    pCommitTxInfo->num_htlc_outputs = ln_commit_tx_info_get_num_htlc_outputs(pCommitTxInfo);

    ret = true;

LABEL_EXIT:
    if (!ret) {
        ln_commit_tx_info_free(pCommitTxInfo);
    }
    return ret;
}


void HIDDEN ln_commit_tx_info_free(ln_commit_tx_info_t *pCommitTxInfo)
{
    utl_buf_free(&pCommitTxInfo->to_local.wit_script);
    if (pCommitTxInfo->pp_htlc_info) {
        for (int lp = 0; lp < pCommitTxInfo->num_htlc_infos; lp++) {
            ln_commit_tx_htlc_info_free(pCommitTxInfo->pp_htlc_info[lp]);
            UTL_DBG_FREE(pCommitTxInfo->pp_htlc_info[lp]);
        }
        UTL_DBG_FREE(pCommitTxInfo->pp_htlc_info);
    }
}


bool ln_commit_tx_create_remote(
    ln_commit_info_t *pCommitInfo,
    const ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote,
    uint8_t (**ppHtlcSigs)[LN_SZ_SIGNATURE])
{
    LOGD("BEGIN\n");

    bool ret = false;

    uint8_t (*p_htlc_sigs)[LN_SZ_SIGNATURE] = 0;
    btc_tx_t tx_commit = BTC_TX_INIT;

    ln_commit_tx_info_t commit_tx_info;
    if (!ln_commit_tx_info_create_pre_committed(
        &commit_tx_info, pCommitInfo, pUpdateInfo, pKeysRemote->script_pubkeys, false)) return false;

    if (!save_vouts_remote(&commit_tx_info)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //check num_htlc_outputs
    pCommitInfo->num_htlc_outputs = commit_tx_info.num_htlc_outputs;

    if (!ln_commit_tx_create_rs(&tx_commit, pCommitInfo->remote_sig, &commit_tx_info, pKeysLocal)) goto LABEL_EXIT;
    LOGD("++++++++++++++ remote commit tx: tx_commit\n");
    M_DBG_PRINT_TX(&tx_commit);

    pCommitInfo->local_msat = commit_tx_info.local_msat;
    pCommitInfo->remote_msat = commit_tx_info.remote_msat;

    if (!btc_tx_txid(&tx_commit, pCommitInfo->txid)) goto LABEL_EXIT;
    LOGD("remote commit_txid: ");
    TXIDD(pCommitInfo->txid);

    if (ppHtlcSigs) {
        if (commit_tx_info.num_htlc_outputs) {
            *ppHtlcSigs = (uint8_t (*)[LN_SZ_SIGNATURE])UTL_DBG_MALLOC(LN_SZ_SIGNATURE * commit_tx_info.num_htlc_outputs);
            if (!*ppHtlcSigs) goto LABEL_EXIT;
            p_htlc_sigs = *ppHtlcSigs;
        }
        if (!create_remote_sign_htlcs(
            pCommitInfo, p_htlc_sigs, &tx_commit, &commit_tx_info,
            pKeysLocal, pKeysRemote)) goto LABEL_EXIT;
    }

    ret = true;

LABEL_EXIT:
    if (!ret) {
        UTL_DBG_FREE(p_htlc_sigs);
    }
    btc_tx_free(&tx_commit);
    ln_commit_tx_info_free(&commit_tx_info);
    return ret;
}


bool ln_commit_tx_create_remote_close(
    const ln_commit_info_t *pCommitInfo,
    const ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote,
    ln_close_force_t *pClose)
{
    LOGD("BEGIN\n");

    bool ret = false;

    uint8_t (*p_htlc_sigs)[LN_SZ_SIGNATURE] = 0;
    btc_tx_t tx_commit = BTC_TX_INIT;

    ln_commit_tx_info_t commit_tx_info;
    if (!ln_commit_tx_info_create_committed(
        &commit_tx_info, pCommitInfo, pUpdateInfo, pKeysRemote->script_pubkeys, false)) return false;

    if (!save_vouts_remote(&commit_tx_info)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //check num_htlc_outputs
    if (commit_tx_info.num_htlc_outputs != pClose->num - LN_CLOSE_IDX_HTLC) { //XXX: ???
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //check pCommitInfo
    if (pCommitInfo->local_msat != commit_tx_info.local_msat ||
        pCommitInfo->remote_msat != commit_tx_info.remote_msat ||
        pCommitInfo->num_htlc_outputs != commit_tx_info.num_htlc_outputs) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    uint8_t remote_sig[LN_SZ_SIGNATURE];    //local (remote's remote) signature
    if (!ln_commit_tx_create_rs(&tx_commit, remote_sig, &commit_tx_info, pKeysLocal)) goto LABEL_EXIT;
    if (memcmp(remote_sig, pCommitInfo->remote_sig, LN_SZ_SIGNATURE)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    LOGD("++++++++++++++ remote commit tx: tx_commit\n");
    M_DBG_PRINT_TX(&tx_commit);

    uint8_t txid[BTC_SZ_TXID];
    if (!btc_tx_txid(&tx_commit, txid)) goto LABEL_EXIT;
    if (memcmp(txid, pCommitInfo->txid, BTC_SZ_TXID)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    LOGD("remote commit_txid: ");
    TXIDD(pCommitInfo->txid);

    if (!create_remote_spend_tx(
        pCommitInfo, pClose, &tx_commit, &commit_tx_info, pUpdateInfo, pKeysLocal, pKeysRemote)) goto LABEL_EXIT;
    memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
    btc_tx_init(&tx_commit); //force clear

    ret = true;

LABEL_EXIT:
    if (!ret) {
        UTL_DBG_FREE(p_htlc_sigs);
    }
    btc_tx_free(&tx_commit);
    ln_commit_tx_info_free(&commit_tx_info);
    return ret;
}


bool ln_commit_tx_set_vin_p2wsh_2of2(
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


bool ln_commit_tx_set_vin_p2wsh_2of2_rs(
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
    if (!ln_commit_tx_set_vin_p2wsh_2of2(pTx, Index, KeyOrder, &sig_der_1, &sig_der_2, pWitScript)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&sig_der_1);
    utl_buf_free(&sig_der_2);
    return ret;
}


void HIDDEN ln_commit_tx_rewind_one_commit_remote(
    ln_commit_info_t *pCommitInfo, ln_update_info_t *pUpdateInfo)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pUpdateInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (p_update->state == LN_UPDATE_STATE_OFFERED_CS_SEND) {
            p_update->state = LN_UPDATE_STATE_OFFERED_WAIT_SEND;
            uint64_t amount_msat = 0;
            if (p_update->type & LN_UPDATE_TYPE_MASK_HTLC) {
                amount_msat = pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
            }
            switch (p_update->type) {
            case LN_UPDATE_TYPE_ADD_HTLC:
                LOGD("CANCEL ADD HTLC OFFERED UPDATE[%u] HTLC[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                pCommitInfo->remote_msat += amount_msat;
                break;
            case LN_UPDATE_TYPE_FULFILL_HTLC:
                LOGD("CANCEL FULFILL HTLC OFFERED UPDATE[%u] HTLC[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                pCommitInfo->remote_msat -= amount_msat;
                break;
            case LN_UPDATE_TYPE_FAIL_HTLC:
            case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
                LOGD("CANCEL FAIL HTLC OFFERED UPDATE[%u] HTLC[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                pCommitInfo->local_msat -= amount_msat;
                break;
            case LN_UPDATE_TYPE_FEE:
                LOGD("CANCEL FEE OFFERED UPDATE[%u] FEE_UPDATE[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                break;
            default:
                LOGE("fail: ???\n");
            }
            //The update message will be sent in the idle proc.
        } else if (p_update->state == LN_UPDATE_STATE_RECEIVED_CS_SEND) {
            p_update->state = LN_UPDATE_STATE_RECEIVED_RA_SEND;
            uint64_t amount_msat = 0;
            if (p_update->type & LN_UPDATE_TYPE_MASK_HTLC) {
                amount_msat = pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
            }
            switch (p_update->type) {
            case LN_UPDATE_TYPE_ADD_HTLC:
                LOGD("CANCEL ADD HTLC RECEIVED UPDATE[%u] HTLC[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                pCommitInfo->local_msat += amount_msat;
                break;
            case LN_UPDATE_TYPE_FULFILL_HTLC:
                LOGD("CANCEL FULFILL HTLC RECEIVED UPDATE[%u] HTLC[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                pCommitInfo->local_msat -= amount_msat;
                break;
            case LN_UPDATE_TYPE_FAIL_HTLC:
            case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
                LOGD("CANCEL FAIL HTLC RECEIVED UPDATE[%u] HTLC[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                pCommitInfo->remote_msat -= amount_msat;
                break;
            case LN_UPDATE_TYPE_FEE:
                LOGD("CANCEL FEE RECEIVED UPDATE[%u] FEE_UPDATE[%u](%" PRIu64 ")\n",
                    idx, p_update->type_specific_idx, amount_msat);
                break;
            default:
                LOGE("fail: ???\n");
            }
        }
    }
    pCommitInfo->commit_num--;

    //we can clear `LN_UPDATE_STATE_OFFERED_WAIT_SEND` updates
    //  and reload and check them from forward db once again
    bool updated = false;
    ln_update_info_clear_pending_updates(pUpdateInfo, &updated);

    return;
}


/********************************************************************
 * private functions
 ********************************************************************/

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
    if (!ln_commit_tx_set_vin_p2wsh_2of2_rs(
        pTxCommit, 0, pFundingInfo->key_order, pSigLocal, pSigRemote, &pFundingInfo->wit_script)) goto LABEL_EXIT;
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
 * @param[in]       pCommitInfo
 * @param[out]      pClose
 * @param[in]       pTxCommit
 * @param[in]       pCommitTxInfo
 * @retval  true    成功
 */
static bool create_local_spend_tx(
    const ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote)
{
    uint16_t htlc_num = 0;
    btc_tx_t *p_close_tx_to_local = &pClose->p_tx[LN_CLOSE_IDX_TO_LOCAL];
    btc_tx_t *p_close_tx_htlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];
    utl_push_t wallet_infos;
    btc_keys_t htlckey;

    utl_push_init(&wallet_infos, &pClose->tx_buf, 0);
    if (!ln_signer_htlc_localkey(&htlckey, pKeysLocal)) return false;

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("+++[%d]to_local\n", vout_idx);
            if (!create_local_spend_to_local_tx(
                pCommitInfo, p_close_tx_to_local, &pCommitTxInfo->to_local.wit_script,
                pTxCommit->vout[vout_idx].value, vout_idx,
                pKeysLocal, pKeysRemote)) return false;
        } else if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("+++[%d]to_remote\n", vout_idx);
        } else {
            const ln_commit_tx_htlc_info_t *p_htlc_info = pCommitTxInfo->pp_htlc_info[htlc_idx];
            uint64_t fee_sat = (p_htlc_info->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ?
                pCommitTxInfo->base_fee_info.htlc_timeout_fee :
                pCommitTxInfo->base_fee_info.htlc_success_fee;

            LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlc_info->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ? "offered" : "received");
            assert(pTxCommit->vout[vout_idx].value >= pCommitTxInfo->base_fee_info.dust_limit_satoshi + fee_sat);

            //htlc tx
            btc_tx_t htlc_tx = BTC_TX_INIT;
            if (!ln_htlc_tx_create(
                &htlc_tx, (pTxCommit->vout[vout_idx].value - fee_sat),
                &pCommitTxInfo->to_local.wit_script,
                p_htlc_info->type, p_htlc_info->cltv_expiry, pCommitInfo->txid, vout_idx)) {
                btc_tx_free(&htlc_tx);
                return false;
            }
            if (!create_local_htlc_tx(
                &htlc_tx, pTxCommit->vout[vout_idx].value, p_htlc_info,
                pUpdateInfo, &htlckey)) {
                LOGE("fail: sign vout[%d]\n", vout_idx);
                btc_tx_free(&htlc_tx);
                return false;
            }
            //return `htlc_tx` to the caller
            memcpy(&p_close_tx_htlcs[htlc_num], &htlc_tx, sizeof(btc_tx_t));

            //spending tx for the htlc tx
            btc_tx_t spend_tx = BTC_TX_INIT;
            if (!create_local_spend_htlc_tx(
                &htlc_tx, &spend_tx, &pCommitTxInfo->to_local.wit_script,
                pCommitInfo->to_self_delay,
                pKeysLocal, pKeysRemote)) {
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
 * @param[in]       pCommitInfo
 * @param[in]       pHtlcSigs
 * @param[in]       NumHtlcSigs
 * @param[in]       pTxCommit
 * @param[in]       pCommitTxInfo
 * @retval  true    成功
 */
static bool create_local_verify_htlcs(
    const ln_commit_info_t *pCommitInfo,
    ln_update_info_t *pUpdateInfo,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_derkey_local_keys_t *pKeysLocal)
{
    uint16_t htlc_num = 0;
    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("+++[%d]to_local\n", vout_idx);
            continue;
        }
        if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("+++[%d]to_remote\n", vout_idx);
            continue;
        }

        const ln_commit_tx_htlc_info_t *p_htlc_info = pCommitTxInfo->pp_htlc_info[htlc_idx];
        uint64_t fee_sat = (p_htlc_info->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ?
            pCommitTxInfo->base_fee_info.htlc_timeout_fee :
            pCommitTxInfo->base_fee_info.htlc_success_fee;

        LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlc_info->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ? "offered" : "received");
        assert(pTxCommit->vout[vout_idx].value >= pCommitTxInfo->base_fee_info.dust_limit_satoshi + fee_sat);

        btc_tx_t tx = BTC_TX_INIT;
        if (!ln_htlc_tx_create(
            &tx, (pTxCommit->vout[vout_idx].value - fee_sat), &pCommitTxInfo->to_local.wit_script,
            p_htlc_info->type, p_htlc_info->cltv_expiry, pCommitInfo->txid, vout_idx)) {
            btc_tx_free(&tx);
            return false;
        }
        if (!create_local_verify_htlc(
            &tx, pHtlcSigs[htlc_num], &p_htlc_info->wit_script, pTxCommit->vout[vout_idx].value,
            pKeysLocal)) {
            btc_tx_free(&tx);
            return false;
        }
        //XXX: save the commitment_signed message?
        //OKなら各HTLCに保持
        //  相手がunilateral closeした後に送信しなかったら、この署名を使う
        memcpy(pUpdateInfo->htlcs[p_htlc_info->htlc_idx].remote_sig, pHtlcSigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
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
static bool create_local_spend_to_local_tx(
    const ln_commit_info_t *pCommitInfo,
    btc_tx_t *pTxToLocal,
    const utl_buf_t *pWitScriptToLocal,
    uint64_t Amount,
    uint32_t VoutIdx,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote)
{
    btc_tx_t tx = BTC_TX_INIT;
    if (!ln_wallet_create_to_local(
        &tx, Amount, pCommitInfo->to_self_delay,
        pWitScriptToLocal, pCommitInfo->txid, VoutIdx,
        pKeysLocal, pKeysRemote, NULL)) {
        btc_tx_free(&tx);
        return false;
    }
    memcpy(pTxToLocal, &tx, sizeof(tx));
    return true;
}


static bool create_local_verify_htlc(
    btc_tx_t *pTx,
    const uint8_t *pHtlcSig,
    const utl_buf_t *pScript,
    uint64_t Amount,
    const ln_derkey_local_keys_t *pKeysLocal)
{
    utl_buf_t buf_sig = UTL_BUF_INIT;
    if (!btc_sig_rs2der(&buf_sig, pHtlcSig)) return false;
    if (!ln_htlc_tx_verify(
        pTx, Amount, NULL, NULL, pKeysLocal->script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
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


static bool create_local_htlc_tx(
    btc_tx_t *pTxHtlc,
    uint64_t Amount,
    const ln_commit_tx_htlc_info_t *pHtlcInfo,
    const ln_update_info_t *pUpdateInfo,
    const btc_keys_t *pHtlcKey)
{
    bool ret_img = false;
    uint8_t preimage[LN_SZ_PREIMAGE];

    if (pHtlcInfo->type == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED) {
        ret_img = search_preimage(
            preimage,
            pUpdateInfo->htlcs[pHtlcInfo->htlc_idx].payment_hash,
            true);
        LOGD("[received]have preimage=%s\n", (ret_img) ? "yes" : "NO");
        if (!ret_img) {
            LOGD("skip create HTLC tx\n");
            return true;
        }
    } else if (pHtlcInfo->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) {
        LOGD("[offered]\n");
    } else {
        assert(0);
        return false;
    }

    uint8_t local_sig[LN_SZ_SIGNATURE];
    if (!ln_htlc_tx_sign_rs(
        pTxHtlc, local_sig, Amount, pHtlcKey, &pHtlcInfo->wit_script)) {
        LOGE("fail: sign htlc_tx\n");
        return false;
    }
    if (!ln_htlc_tx_set_vin0_rs(
        pTxHtlc, local_sig, pUpdateInfo->htlcs[pHtlcInfo->htlc_idx].remote_sig,
        (pHtlcInfo->type == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED) ? preimage : NULL,
        NULL, &pHtlcInfo->wit_script, LN_HTLC_TX_SIG_TIMEOUT_SUCCESS)) {
        LOGE("fail: set htlc_tx vout\n");
        return false;
    }
    M_DBG_PRINT_TX2(pTxHtlc);
    return true;
}


//create spending tx for the htlc tx (same as one for `to_tocal` output)
static bool create_local_spend_htlc_tx(
    const btc_tx_t *pTxHtlc,
    btc_tx_t *pTxSpend,
    const utl_buf_t *pWitScriptToLocal,
    uint32_t ToSelfDelay,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote)
{
    uint8_t txid[BTC_SZ_TXID];
    if (!btc_tx_txid(pTxHtlc, txid)) return false;

    if (!ln_wallet_create_to_local(
        pTxSpend, pTxHtlc->vout[0].value, ToSelfDelay, pWitScriptToLocal, txid, 0,
        pKeysLocal, pKeysRemote, NULL)) {
        //XXX: return true;
        return false;
    }
    LOGD("*** HTLC out Tx ***\n");
    M_DBG_PRINT_TX2(pTxSpend);
    return true;
}


static bool create_htlc_info_and_amount_pre_committed(
    const ln_update_info_t *pUpdateInfo,
    ln_commit_tx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    uint64_t *pLocalMsat,
    uint64_t *pRemoteMsat,
    bool bLocal)
{
    *pHtlcInfoCnt = 0;
    for (uint16_t update_idx = 0; update_idx < LN_UPDATE_MAX; update_idx++) {
        const ln_update_t *p_update = &pUpdateInfo->updates[update_idx];
        LOGD("state = 0x%04x\n", p_update->state);
        if (!LN_UPDATE_USED(p_update)) continue;

        if (LN_UPDATE_UNCOMMITTED(p_update, bLocal)) {
            if (LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_ALL, bLocal)) {
                switch (p_update->type) {
                case LN_UPDATE_TYPE_ADD_HTLC:
                    LOGD("add htlc send\n");
                    *pLocalMsat -= pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
                    break;
                case LN_UPDATE_TYPE_FULFILL_HTLC:
                    LOGD("fulfill htlc send\n");
                    *pLocalMsat += pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
                    break;
                case LN_UPDATE_TYPE_FAIL_HTLC:
                case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
                    LOGD("fail htlc send\n");
                    *pRemoteMsat += pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
                    break;
                default:
                    ;
                }
            } else if (LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_ALL, bLocal)) {
                switch (p_update->type) {
                case LN_UPDATE_TYPE_ADD_HTLC:
                    LOGD("add htlc recv\n");
                    *pRemoteMsat -= pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
                    break;
                case LN_UPDATE_TYPE_FULFILL_HTLC:
                    LOGD("fulfill htlc recv\n");
                    *pRemoteMsat += pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
                    break;
                case LN_UPDATE_TYPE_FAIL_HTLC:
                case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
                    LOGD("fail htlc recv\n");
                    *pLocalMsat += pUpdateInfo->htlcs[p_update->type_specific_idx].amount_msat;
                    break;
                default:
                    ;
                }
            }
        }

        if (!LN_UPDATE_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) continue;

        const ln_htlc_t *p_htlc = &pUpdateInfo->htlcs[p_update->type_specific_idx];

        uint16_t update_idx_del_htlc;
        if (ln_update_info_get_update(
            pUpdateInfo, &update_idx_del_htlc, LN_UPDATE_TYPE_MASK_DEL_HTLC, p_update->type_specific_idx) &&
            LN_UPDATE_ENABLED(&pUpdateInfo->updates[update_idx_del_htlc], LN_UPDATE_TYPE_MASK_ALL, bLocal)) {
            LOGD(" DEL UPDATE[%u] HTLC[%u] [id=%" PRIu64 "](%" PRIu64 ")\n",
                update_idx, p_update->type_specific_idx, p_htlc->id, p_htlc->amount_msat);
            continue;
        }

        ln_commit_tx_htlc_info_t *p_info = (ln_commit_tx_htlc_info_t *)UTL_DBG_MALLOC(sizeof(ln_commit_tx_htlc_info_t));
        ln_commit_tx_htlc_info_init(p_info);
        if (LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) {
            p_info->type = LN_COMMIT_TX_OUTPUT_TYPE_OFFERED;
        } else if (LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) {
            p_info->type = LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED;
        } else {
            assert(0);
            UTL_DBG_FREE(p_info);
            goto LABEL_ERROR;
        }

        p_info->htlc_idx = p_update->type_specific_idx;
        p_info->cltv_expiry = p_htlc->cltv_expiry;
        p_info->amount_msat = p_htlc->amount_msat;
        p_info->payment_hash = p_htlc->payment_hash;
        ppHtlcInfo[*pHtlcInfoCnt] = p_info;
        (*pHtlcInfoCnt)++;
        LOGD(" ADD UPDATE[%u] HTLC[%u] [id=%" PRIu64 "](%" PRIu64 ")\n",
            update_idx, p_update->type_specific_idx, p_htlc->id, p_htlc->amount_msat);
    }
    return true;

LABEL_ERROR:
    while (*pHtlcInfoCnt--) {
        UTL_DBG_FREE(ppHtlcInfo[*pHtlcInfoCnt]);
    }
    return false;
}


static bool create_htlc_info_and_amount_committed(
    const ln_update_info_t *pUpdateInfo,
    ln_commit_tx_htlc_info_t **ppHtlcInfo,
    uint16_t *pHtlcInfoCnt,
    bool bLocal)
{
    *pHtlcInfoCnt = 0;
    for (uint16_t update_idx = 0; update_idx < LN_UPDATE_MAX; update_idx++) {
        const ln_update_t *p_update = &pUpdateInfo->updates[update_idx];
        LOGD("state = 0x%04x\n", p_update->state);
        if (!LN_UPDATE_USED(p_update)) continue;
        if (LN_UPDATE_UNCOMMITTED(p_update, bLocal)) continue;
        if (!LN_UPDATE_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) continue;

        const ln_htlc_t *p_htlc = &pUpdateInfo->htlcs[p_update->type_specific_idx];

        uint16_t update_idx_del_htlc;
        if (ln_update_info_get_update(
            pUpdateInfo, &update_idx_del_htlc, LN_UPDATE_TYPE_MASK_DEL_HTLC, p_update->type_specific_idx) &&
            LN_UPDATE_ENABLED(&pUpdateInfo->updates[update_idx_del_htlc], LN_UPDATE_TYPE_MASK_ALL, bLocal) &&
            !LN_UPDATE_UNCOMMITTED(&pUpdateInfo->updates[update_idx_del_htlc], bLocal)) {
            LOGD(" DEL UPDATE[%u] HTLC[%u] [id=%" PRIu64 "](%" PRIu64 ")\n",
                update_idx, p_update->type_specific_idx, p_htlc->id, p_htlc->amount_msat);
            continue;
        }

        ln_commit_tx_htlc_info_t *p_info = (ln_commit_tx_htlc_info_t *)UTL_DBG_MALLOC(sizeof(ln_commit_tx_htlc_info_t));
        ln_commit_tx_htlc_info_init(p_info);
        if (LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) {
            p_info->type = LN_COMMIT_TX_OUTPUT_TYPE_OFFERED;
        } else if (LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) {
            p_info->type = LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED;
        } else {
            assert(0);
            UTL_DBG_FREE(p_info);
            goto LABEL_ERROR;
        }

        p_info->htlc_idx = p_update->type_specific_idx;
        p_info->cltv_expiry = p_htlc->cltv_expiry;
        p_info->amount_msat = p_htlc->amount_msat;
        p_info->payment_hash = p_htlc->payment_hash;
        ppHtlcInfo[*pHtlcInfoCnt] = p_info;
        (*pHtlcInfoCnt)++;
        LOGD(" ADD UPDATE[%u] HTLC[%u] [id=%" PRIu64 "](%" PRIu64 ")\n",
            update_idx, p_update->type_specific_idx, p_htlc->id, p_htlc->amount_msat);
    }
    return true;

LABEL_ERROR:
    while (*pHtlcInfoCnt--) {
        UTL_DBG_FREE(ppHtlcInfo[*pHtlcInfoCnt]);
    }
    return false;
}


static bool create_remote_spend_tx(
    const ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_update_info_t *pUpdateInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote)
{
    uint16_t htlc_num = 0;

    btc_tx_t *p_close_tx_htlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];

    btc_keys_t htlckey;
    if (!ln_signer_htlc_remotekey(&htlckey, pKeysLocal, pKeysRemote)) return false;

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("---[%d]to_local\n", vout_idx);
            continue;
        }
        if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("---[%d]to_remote\n", vout_idx);
            btc_tx_t tx = BTC_TX_INIT;
            if (!ln_wallet_create_to_remote(
                &tx, pTxCommit->vout[vout_idx].value, pCommitInfo->txid, vout_idx,
                pKeysLocal, pKeysRemote)) {
                //LOGD("no to_remote output\n");
                LOGE("fail: ???\n");
                btc_tx_free(&tx);
                //continue;
                return true;
            }
            memcpy(&pClose->p_tx[LN_CLOSE_IDX_TO_REMOTE], &tx, sizeof(tx));
            btc_tx_init(&tx); //force clear
            continue;
        }
        const ln_commit_tx_htlc_info_t *p_htlc_info = pCommitTxInfo->pp_htlc_info[htlc_idx];
        const uint8_t *p_payment_hash = pUpdateInfo->htlcs[p_htlc_info->htlc_idx].payment_hash;
        uint64_t fee_sat =
            (p_htlc_info->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ?
            pCommitTxInfo->base_fee_info.htlc_timeout_fee :
            pCommitTxInfo->base_fee_info.htlc_success_fee;

        if (!create_remote_spend_htlc_output_tx(
            pCommitInfo, &p_close_tx_htlcs[htlc_num], pTxCommit,
            &pCommitTxInfo->to_local.wit_script, p_htlc_info,
            &htlckey, fee_sat, vout_idx, p_payment_hash)) return false;
        pClose->p_htlc_idxs[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
        htlc_num++;
    }
    return true;
}


static bool create_remote_sign_htlcs(
    const ln_commit_info_t *pCommitInfo,
    uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    const btc_tx_t *pTxCommit,
    const ln_commit_tx_info_t *pCommitTxInfo,
    const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote)
{
    uint16_t htlc_num = 0;

    btc_keys_t htlckey;
    if (!ln_signer_htlc_remotekey(&htlckey, pKeysLocal, pKeysRemote)) return false;

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint16_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_LOCAL) {
            LOGD("---[%d]to_local\n", vout_idx);
            continue;
        }
        if (htlc_idx == LN_COMMIT_TX_OUTPUT_TYPE_TO_REMOTE) {
            LOGD("---[%d]to_remote\n", vout_idx);
            continue;
        }
        const ln_commit_tx_htlc_info_t *p_htlc_info = pCommitTxInfo->pp_htlc_info[htlc_idx];
        uint64_t fee_sat =
            (p_htlc_info->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ?
            pCommitTxInfo->base_fee_info.htlc_timeout_fee :
            pCommitTxInfo->base_fee_info.htlc_success_fee;

        if (!create_remote_sign_htlc(
            pCommitInfo, pHtlcSigs[htlc_num], pTxCommit,
            &pCommitTxInfo->to_local.wit_script, p_htlc_info,
            &htlckey, fee_sat, vout_idx)) {
            LOGE("fail: sign vout[%d]\n", vout_idx);
            return false;
        }
        htlc_num++;
    }
    return true;
}


/** create an HTLC sig in remote comitment transaction
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
static bool create_remote_sign_htlc(
    const ln_commit_info_t *pCommitInfo,
    uint8_t *pHtlcSig,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_commit_tx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx)
{
    bool ret = false;

    LOGD("---HTLC[%d]\n", VoutIdx);
    btc_tx_t tx = BTC_TX_INIT;
    if (!ln_htlc_tx_create(
        &tx, pTxCommit->vout[VoutIdx].value - Fee, pWitScriptToLocal, pHtlcInfo->type,
        pHtlcInfo->cltv_expiry, pCommitInfo->txid, VoutIdx)) goto LABEL_EXIT;

    if (!ln_htlc_tx_sign_rs(
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
 * @param[in]       pPaymentHash
 * @retval  true    成功
 */
static bool create_remote_spend_htlc_output_tx(
    const ln_commit_info_t *pCommitInfo,
    btc_tx_t *pCloseTxHtlc,
    const btc_tx_t *pTxCommit,
    const utl_buf_t *pWitScriptToLocal,
    const ln_commit_tx_htlc_info_t *pHtlcInfo,
    const btc_keys_t *pHtlcKey,
    uint64_t Fee,
    uint32_t VoutIdx,
    const uint8_t *pPaymentHash)
{
    LOGD("---HTLC[%d]\n", VoutIdx);
    btc_tx_t tx = BTC_TX_INIT;
    if (!ln_htlc_tx_create(
        &tx, pTxCommit->vout[VoutIdx].value - Fee, pWitScriptToLocal,
        pHtlcInfo->type, pHtlcInfo->cltv_expiry, pCommitInfo->txid, VoutIdx)) return false;

    if (pHtlcInfo->type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) {
        uint8_t preimage[LN_SZ_PREIMAGE];
        if (search_preimage(preimage, pPaymentHash, true)) {
            LOGD("[offered]have preimage\n");
            utl_buf_free(&tx.vout[0].script);
            tx.locktime = 0;
            if (!ln_wallet_htlc_tx_set_vin0( //wit[0]に署名用秘密鍵を設定しておく(wallet用)
                &tx, pHtlcKey->priv, preimage, &pHtlcInfo->wit_script, LN_HTLC_TX_SIG_REMOTE_OFFER)) goto LABEL_ERROR;
        } else {
            LOGD("[offered]no preimage\n");
        }
    } else {
        LOGD("[received]\n");
        utl_buf_free(&tx.vout[0].script);
        tx.locktime = pHtlcInfo->cltv_expiry;
        if (!ln_wallet_htlc_tx_set_vin0( //wit[0]に署名用秘密鍵を設定しておく(wallet用)
            &tx, pHtlcKey->priv, NULL, &pHtlcInfo->wit_script, LN_HTLC_TX_SIG_REMOTE_RECV)) goto LABEL_ERROR;
    }

    memcpy(pCloseTxHtlc, &tx, sizeof(tx));
    return true;

LABEL_ERROR:
    btc_tx_free(&tx);
    return false;
}


static bool save_vouts_remote(const ln_commit_tx_info_t *pCommitTxInfo)
{
    //payment_hash, type, expiry保存
    for (int lp = 0; lp < pCommitTxInfo->num_htlc_infos; lp++) {
        utl_buf_t vout = UTL_BUF_INIT;
        if (!btc_script_p2wsh_create_scriptpk(
            &vout, &pCommitTxInfo->pp_htlc_info[lp]->wit_script)) {
            return false;
        }
        if (!ln_db_payment_hash_save(
            pCommitTxInfo->pp_htlc_info[lp]->payment_hash,
            vout.buf,
            pCommitTxInfo->pp_htlc_info[lp]->type,
            pCommitTxInfo->pp_htlc_info[lp]->cltv_expiry)) {
            utl_buf_free(&vout);
            return false;
        }
        utl_buf_free(&vout);
    }
    return true;
}


/** payment_hashと一致するpreimage検索
 *
 * @param[out]      pPreimage
 * @param[in]       pPaymentHash        payment_hash
 * @param[in]       bClosing        true:一致したexpiryをUINT32_MAXに変更する
 * @retval  true    検索成功
 */
static bool search_preimage(uint8_t *pPreimage, const uint8_t *pPaymentHash, bool bClosing)
{
    if (!LN_DBG_MATCH_PREIMAGE()) {
        LOGE("DBG: HTLC preimage mismatch\n");
        return false;
    }
    // LOGD("pPaymentHash(%d)=", bClosing);
    // DUMPD(pPaymentHash, BTC_SZ_HASH256);

    preimage_t param;
    param.image = pPreimage;
    param.hash = pPaymentHash;
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
