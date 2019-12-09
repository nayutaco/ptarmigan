/*
 *  Copyright (C) 2017 Ptarmigan Project
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
/** @file   ln_commit_tx_util.c
 *  @brief  ln_commit_tx_ex
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "mbedtls/sha256.h"
//#include "mbedtls/ripemd160.h"
//#include "mbedtls/ecp.h"

#include "btc_keys.h"

#include "ln_commit_tx_util.h"
#include "ln_local.h"
#include "ln_signer.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SZ_OBSCURED_COMMIT_NUM            (6)

#if defined(USE_BITCOIN)
// https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#fee-calculation
#define M_FEE_HTLC_TIMEOUT_WEIGHT           ((uint64_t)663)
#define M_FEE_HTLC_SUCCESS_WEIGHT           ((uint64_t)703)
#elif defined(USE_ELEMENTS)
// https://github.com/ElementsProject/lightning/blob/a30ee2b7cd08053a2269712150204e9007976b04/common/htlc_tx.h#L22
#define M_FEE_HTLC_TIMEOUT_WEIGHT           ((uint64_t)(663 + 330))
#define M_FEE_HTLC_SUCCESS_WEIGHT           ((uint64_t)(703 + 330))
#endif


/**************************************************************************
 * prototypes
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

uint64_t HIDDEN ln_commit_tx_calc_obscured_commit_num_mask(const uint8_t *pOpenPayBasePt, const uint8_t *pAcceptPayBasePt)
{
    uint64_t obs = 0;
    uint8_t base[32];

    btc_md_sha256cat(base, pOpenPayBasePt, BTC_SZ_PUBKEY, pAcceptPayBasePt, BTC_SZ_PUBKEY);

    for (int lp = 0; lp < M_SZ_OBSCURED_COMMIT_NUM; lp++) {
        obs <<= 8;
        obs |= base[sizeof(base) - M_SZ_OBSCURED_COMMIT_NUM + lp];
    }

    return obs;
}


uint64_t HIDDEN ln_commit_tx_calc_obscured_commit_num(uint64_t ObscuredCommitNumBase, uint64_t CommitNum)
{
    return ObscuredCommitNumBase ^ CommitNum;
}


uint64_t HIDDEN ln_commit_tx_calc_commit_num_from_tx(uint32_t Sequence, uint32_t Locktime, uint64_t ObscuredCommitNumBase)
{
    uint64_t commit_num = ((uint64_t)(Sequence & 0xffffff)) << 24;
    commit_num |= (uint64_t)(Locktime & 0xffffff);
    return commit_num ^ ObscuredCommitNumBase;
}


void HIDDEN ln_commit_tx_htlc_info_init(ln_commit_tx_htlc_info_t *pHtlcInfo)
{
    pHtlcInfo->type = LN_COMMIT_TX_OUTPUT_TYPE_NONE;
    pHtlcInfo->htlc_idx = (uint16_t)-1;
    pHtlcInfo->cltv_expiry = 0;
    pHtlcInfo->amount_msat = 0;
    pHtlcInfo->payment_hash = NULL;
    utl_buf_init(&pHtlcInfo->wit_script);
}


void HIDDEN ln_commit_tx_htlc_info_free(ln_commit_tx_htlc_info_t *pHtlcInfo)
{
    utl_buf_free(&pHtlcInfo->wit_script);
}


void HIDDEN ln_commit_tx_base_fee_calc(
    ln_commit_tx_base_fee_info_t *pBaseFeeInfo,
    const ln_commit_tx_htlc_info_t **ppHtlcInfo,
    int Num)
{
    pBaseFeeInfo->htlc_success_fee = M_FEE_HTLC_SUCCESS_WEIGHT * pBaseFeeInfo->feerate_per_kw / 1000;
    pBaseFeeInfo->htlc_timeout_fee = M_FEE_HTLC_TIMEOUT_WEIGHT * pBaseFeeInfo->feerate_per_kw / 1000;
    pBaseFeeInfo->commit_fee = 0;
    uint64_t commit_fee_weight = LN_FEE_COMMIT_BASE_WEIGHT;
    uint64_t dust_msat = 0;

    for (int lp = 0; lp < Num; lp++) {
        switch (ppHtlcInfo[lp]->type) {
        case LN_COMMIT_TX_OUTPUT_TYPE_OFFERED:
            if (LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat) >= pBaseFeeInfo->dust_limit_satoshi + pBaseFeeInfo->htlc_timeout_fee) {
                commit_fee_weight += LN_FEE_COMMIT_HTLC_WEIGHT;
            } else {
                dust_msat += ppHtlcInfo[lp]->amount_msat;
            }
            break;
        case LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED:
            if (LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat) >= pBaseFeeInfo->dust_limit_satoshi + pBaseFeeInfo->htlc_success_fee) {
                commit_fee_weight += LN_FEE_COMMIT_HTLC_WEIGHT;
            } else {
                dust_msat += ppHtlcInfo[lp]->amount_msat;
            }
            break;
        default:
            break;
        }
    }
    pBaseFeeInfo->commit_fee = commit_fee_weight * pBaseFeeInfo->feerate_per_kw / 1000;
    LOGD("pBaseFeeInfo->commit_fee= %" PRIu64 "(weight=%" PRIu64 ", feerate_per_kw=%" PRIu32 ")\n", pBaseFeeInfo->commit_fee, commit_fee_weight, pBaseFeeInfo->feerate_per_kw);


    //XXX: probably not correct
    //  the base fee should be added after it has been calculated (after being divided by 1000)
    //pBaseFeeInfo->_rough_actual_fee = (commit_fee_weight * pBaseFeeInfo->feerate_per_kw + dust_msat) / 1000;

    pBaseFeeInfo->_rough_actual_fee = pBaseFeeInfo->commit_fee + dust_msat / 1000;
}


bool HIDDEN ln_commit_tx_create(
    btc_tx_t *pTx,
    utl_buf_t *pSig,
    const ln_commit_tx_info_t *pCommitTxInfoTrimmed,
    const ln_derkey_local_keys_t *pLocalKeys,
    uint64_t AmountInputs)
{
    uint8_t sig[LN_SZ_SIGNATURE];
    if (!ln_commit_tx_create_rs(pTx, sig, pCommitTxInfoTrimmed, pLocalKeys, AmountInputs)) return false;
    if (!btc_sig_rs2der(pSig, sig)) return false;
    return true;
}


bool HIDDEN ln_commit_tx_create_rs(
    btc_tx_t *pTx,
    uint8_t *pSig,
    const ln_commit_tx_info_t *pCommitTxInfoTrimmed,
    const ln_derkey_local_keys_t *pLocalKeys,
    uint64_t AmountInputs)
{
    assert(pCommitTxInfoTrimmed->b_trimmed);

    //output

    //  to_local (P2WSH)
    if (pCommitTxInfoTrimmed->to_local.satoshi) {
        if (!btc_sw_add_vout_p2wsh_wit(
            pTx, pCommitTxInfoTrimmed->to_local.satoshi, &pCommitTxInfoTrimmed->to_local.wit_script)) return false;
        pTx->vout[pTx->vout_cnt - 1].opt = LN_COMMIT_TX_OUTPUT_TYPE_TO_LOCAL;
    }

    //  to_remote (P2WPKH)
    if (pCommitTxInfoTrimmed->to_remote.satoshi) {
        if (!btc_sw_add_vout_p2wpkh_pub(
            pTx, pCommitTxInfoTrimmed->to_remote.satoshi, pCommitTxInfoTrimmed->to_remote.pubkey)) return false;
        pTx->vout[pTx->vout_cnt - 1].opt = LN_COMMIT_TX_OUTPUT_TYPE_TO_REMOTE;
    }

    //  HTLCs
    for (uint16_t lp = 0; lp < pCommitTxInfoTrimmed->num_htlc_infos; lp++) {
        if (!pCommitTxInfoTrimmed->pp_htlc_info[lp]->amount_msat) continue; //trimmed
        if (!btc_sw_add_vout_p2wsh_wit(
            pTx, LN_MSAT2SATOSHI(pCommitTxInfoTrimmed->pp_htlc_info[lp]->amount_msat),
            &pCommitTxInfoTrimmed->pp_htlc_info[lp]->wit_script)) return false;
        pTx->vout[pTx->vout_cnt - 1].opt = lp;
    }

    //input
    btc_vin_t *vin = btc_tx_add_vin(pTx, pCommitTxInfoTrimmed->fund.txid, pCommitTxInfoTrimmed->fund.txid_index);
    vin->sequence = LN_SEQUENCE(pCommitTxInfoTrimmed->obscured_commit_num);

    //locktime
    pTx->locktime = LN_LOCKTIME(pCommitTxInfoTrimmed->obscured_commit_num);

    //sort vin/vout
    btc_tx_sort_bip69(pTx);

#ifdef USE_ELEMENTS
    if (pCommitTxInfoTrimmed->base_fee_info.commit_fee > 0) {
        for (uint16_t lp = 0; lp < pTx->vout_cnt; lp++) {
            AmountInputs -= pTx->vout[lp].value;
        }
        if (!btc_tx_add_vout_fee(pTx, AmountInputs)) return false;
        pTx->vout[pTx->vout_cnt - 1].opt = LN_COMMIT_TX_OUTPUT_TYPE_TO_REMOTE;
    } else {
        LOGE("THROUGH: no fee value(bug?)\n");
    }
#else
    (void)AmountInputs;
#endif

    //sign
    uint8_t sighash[BTC_SZ_HASH256];
    if (!btc_sw_sighash_p2wsh_wit(
        pTx, sighash, 0, pCommitTxInfoTrimmed->fund.satoshi, pCommitTxInfoTrimmed->fund.p_wit_script)) {
        LOGE("fail: calc sighash\n");
        return false;
    }
    if (!ln_signer_sign_rs(pSig, sighash, pLocalKeys, LN_BASEPOINT_IDX_FUNDING)) {
        LOGE("fail: sign\n");
        return false;
    }
    return true;
}


void HIDDEN ln_commit_tx_info_sub_fee_and_trim_outputs(ln_commit_tx_info_t *pCommitTxInfo, bool ToLocalIsFounder)
{
    assert(!pCommitTxInfo->b_trimmed);

    uint64_t fee_local = ToLocalIsFounder ? pCommitTxInfo->base_fee_info.commit_fee : 0;
    uint64_t fee_remote = ToLocalIsFounder ? 0 : pCommitTxInfo->base_fee_info.commit_fee;

    //to_local
    if (pCommitTxInfo->to_local.satoshi >= pCommitTxInfo->base_fee_info.dust_limit_satoshi + fee_local) {
        LOGD("  add local: %" PRIu64 " - %" PRIu64 " sat\n", pCommitTxInfo->to_local.satoshi, fee_local);
        pCommitTxInfo->to_local.satoshi -= fee_local; //sub fee
    } else {
        LOGD("  [local output]below dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n",
            pCommitTxInfo->to_local.satoshi, pCommitTxInfo->base_fee_info.dust_limit_satoshi, fee_local);
#ifdef USE_ELEMENTS
        pCommitTxInfo->base_fee_info.commit_fee += pCommitTxInfo->to_local.satoshi;
#endif
        pCommitTxInfo->to_local.satoshi = 0; //trimmed
    }

    //to_remote
    if (pCommitTxInfo->to_remote.satoshi >= pCommitTxInfo->base_fee_info.dust_limit_satoshi + fee_remote) {
        LOGD("  add P2WPKH remote: %" PRIu64 " sat - %" PRIu64 " sat\n", pCommitTxInfo->to_remote.satoshi, fee_remote);
        pCommitTxInfo->to_remote.satoshi -= fee_remote; //sub fee
    } else {
        LOGD("  [remote output]below dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n",
            pCommitTxInfo->to_remote.satoshi, pCommitTxInfo->base_fee_info.dust_limit_satoshi, fee_remote);
#ifdef USE_ELEMENTS
        pCommitTxInfo->base_fee_info.commit_fee += pCommitTxInfo->to_remote.satoshi;
#endif
        pCommitTxInfo->to_remote.satoshi = 0; //trimmed
    }

    //HTLCs
    for (uint16_t lp = 0; lp < pCommitTxInfo->num_htlc_infos; lp++) {
        uint64_t output_sat = LN_MSAT2SATOSHI(pCommitTxInfo->pp_htlc_info[lp]->amount_msat);
        uint64_t fee;
        LOGD("lp=%d\n", lp);
        switch (pCommitTxInfo->pp_htlc_info[lp]->type) {
        case LN_COMMIT_TX_OUTPUT_TYPE_OFFERED:
            fee = pCommitTxInfo->base_fee_info.htlc_timeout_fee;
            LOGD("  HTLC: offered=%" PRIu64 " sat, fee=%" PRIu64 "\n", output_sat, fee);
            break;
        case LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED:
            fee = pCommitTxInfo->base_fee_info.htlc_success_fee;
            LOGD("  HTLC: received=%" PRIu64 " sat, fee=%" PRIu64 "\n", output_sat, fee);
            break;
        default:
            LOGE("  HTLC: type=%d ???\n", pCommitTxInfo->pp_htlc_info[lp]->type);
            assert(0);
        }
        if (output_sat >=  pCommitTxInfo->base_fee_info.dust_limit_satoshi + fee) {
            LOGD("script.len=%d\n", pCommitTxInfo->pp_htlc_info[lp]->wit_script.len);
            //btc_script_print(pCommitTxInfo->pp_htlc_info[lp]->wit_script.buf, pCommitTxInfo->pp_htlc_info[lp]->wit_script.len);
        } else {
            LOGD("    [HTLC]below dust: %" PRIu64 " < %" PRIu64 "(dust_limit) + %" PRIu64 "(fee)\n",
                output_sat, pCommitTxInfo->base_fee_info.dust_limit_satoshi, fee);
#ifdef USE_ELEMENTS
            pCommitTxInfo->base_fee_info.commit_fee += output_sat;
#endif
            pCommitTxInfo->pp_htlc_info[lp]->amount_msat = 0; //trimmed
        }
    }
    pCommitTxInfo->b_trimmed = true;
}


uint16_t HIDDEN ln_commit_tx_info_get_num_htlc_outputs(ln_commit_tx_info_t *pCommitTxInfoTrimmed)
{
    uint16_t num_htlc_outputs = 0;
    for (uint16_t lp = 0; lp < pCommitTxInfoTrimmed->num_htlc_infos; lp++) {
        if (!pCommitTxInfoTrimmed->pp_htlc_info[lp]->amount_msat) continue; //trimmed
        num_htlc_outputs++;
    }
    return num_htlc_outputs;
}


/********************************************************************
 * private functions
 ********************************************************************/
