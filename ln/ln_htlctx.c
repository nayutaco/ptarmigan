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
/** @file   ln_htlctx.c
 *  @brief  ln_htlctx
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "ln_local.h"
#include "ln_signer.h"
#include "ln_htlctx.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool HIDDEN ln_htlctx_create(
    btc_tx_t *pTx,
    uint64_t Value,
    const utl_buf_t *pWitScript,
    ln_commit_tx_output_type_t Type,
    uint32_t CltvExpiry,
    const uint8_t *pTxid,
    int Index)
{
    //vout
    if (!btc_sw_add_vout_p2wsh_wit(pTx, Value, pWitScript)) return false;
    pTx->vout[0].opt = (uint16_t)Type;
    switch (Type) {
    case LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED:
        LOGD("HTLC Success\n");
        pTx->locktime = 0;
        break;
    case LN_COMMIT_TX_OUTPUT_TYPE_OFFERED:
        LOGD("HTLC Timeout\n");
        pTx->locktime = CltvExpiry;
        break;
    default:
        LOGE("fail: opt not set\n");
        assert(0);
        return false;
    }

    //vin
    if (!btc_tx_add_vin(pTx, pTxid, Index)) return false;
    pTx->vin[0].sequence = 0;
    return true;
}


bool HIDDEN ln_htlctx_sign(
    btc_tx_t *pTx,
    utl_buf_t *pSig,
    uint64_t Value,
    const btc_keys_t *pKeys,
    const utl_buf_t *pWitScript)
{
    uint8_t sig[LN_SZ_SIGNATURE];
    if (!ln_htlctx_sign_rs(pTx, sig, Value, pKeys, pWitScript)) return false;
    if (!btc_sig_rs2der(pSig, sig)) return false;
    return true;
}


bool HIDDEN ln_htlctx_sign_rs(
    btc_tx_t *pTx,
    uint8_t *pSig,
    uint64_t Value,
    const btc_keys_t *pKeys,
    const utl_buf_t *pWitScript)
{
    // https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#htlc-timeout-and-htlc-success-transactions
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGE("fail: invalid vin/vout\n");
        return false;
    }

    uint8_t sighash[BTC_SZ_HASH256];
    if (!btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, Value, pWitScript)) {
        LOGE("fail: calc sighash\n");
        return false;
    }
    if (!ln_signer_sign_rs_2(pSig, sighash, pKeys)) {
        LOGE("fail: sign\n");
        return false;
    }
    return true;
}


bool HIDDEN ln_htlctx_set_vin0(
    btc_tx_t *pTx,
    const utl_buf_t *pLocalSig,
    const utl_buf_t *pRemoteSig,
    const uint8_t *pPreimage,
    const btc_keys_t *pRevoKeys,
    const utl_buf_t *pWitScript,
    ln_htlctx_sig_type_t HtlcSigType)
{
    switch (HtlcSigType) {
    case LN_HTLCTX_SIG_TIMEOUT_SUCCESS:
        {
            assert(pLocalSig);
            assert(pRemoteSig);
            // 0
            // <remotehtlcsig>
            // <localhtlcsig>
            // <payment-preimage>(HTLC Success) or 0(HTLC Timeout)
            // <witness script>
            const utl_buf_t zero = UTL_BUF_INIT;
            utl_buf_t preimage = UTL_BUF_INIT;
            if (pPreimage) {
                preimage.buf = (CONST_CAST uint8_t *)pPreimage;
                preimage.len = LN_SZ_PREIMAGE;
            }
            const utl_buf_t *wit_items[] = { &zero, pRemoteSig, pLocalSig, &preimage, pWitScript };
            LOGD("HTLC Timeout/Success Tx sign: wit_item_num=%d\n", ARRAY_SIZE(wit_items));
            if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
        }
        break;
    case LN_HTLCTX_SIG_REMOTE_OFFER:
        {
            // <remotehtlcsig>              remote's remote -> local
            // <payment-preimage>
            // <witness script>
            assert(pLocalSig);
            assert(pPreimage);
            utl_buf_t preimage = UTL_BUF_INIT;
            preimage.buf = (CONST_CAST uint8_t *)pPreimage;
            preimage.len = LN_SZ_PREIMAGE;
            const utl_buf_t *wit_items[] = { pLocalSig, &preimage, pWitScript };
            LOGD("Offered HTLC + preimage sign: wit_item_num=%d\n", ARRAY_SIZE(wit_items));
            if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
        }
        break;
    case LN_HTLCTX_SIG_REMOTE_RECV:
        {
            // <remotehtlcsig>              remote's remote -> local
            // 0
            // <witness script>
            assert(pLocalSig);
            const utl_buf_t zero = UTL_BUF_INIT;
            const utl_buf_t *wit_items[] = { pLocalSig, &zero, pWitScript};
            LOGD("Received HTLC sign: wit_item_num=%d\n", ARRAY_SIZE(wit_items));
            if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
        }
        break;
    case LN_HTLCTX_SIG_REVOKE_RECV:
    case LN_HTLCTX_SIG_REVOKE_OFFER:
        {
            // <revocation_sig>
            // <revocationpubkey>
            // <witness script>
            assert(pLocalSig);
            assert(pRevoKeys);
            const utl_buf_t revokey = { (CONST_CAST uint8_t *)pRevoKeys->pub, BTC_SZ_PUBKEY };
            const utl_buf_t *wit_items[] = { pLocalSig, &revokey, pWitScript };
            LOGD("revoked HTLC sign: wit_item_num=%d\n", ARRAY_SIZE(wit_items));
            if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
        }
        break;
    default:
        LOGD("HtlcSigType=%d\n", (int)HtlcSigType);
        assert(0);
        return false;
    }
    return true;
}


bool HIDDEN ln_htlctx_set_vin0_rs(
    btc_tx_t *pTx,
    const uint8_t *pLocalSig,
    const uint8_t *pRemoteSig,
    const uint8_t *pPreimage,
    const btc_keys_t *pRevoKeys,
    const utl_buf_t *pWitScript,
    ln_htlctx_sig_type_t HtlcSigType)
{
    bool ret = false;
    utl_buf_t local_sig = UTL_BUF_INIT;
    utl_buf_t remote_sig = UTL_BUF_INIT;
    utl_buf_t *p_local_sig = NULL;
    utl_buf_t *p_remote_sig = NULL;
    if (pLocalSig) {
        if (!btc_sig_rs2der(&local_sig, pLocalSig)) goto LABEL_EXIT;
        p_local_sig = &local_sig;
    }
    if (pRemoteSig) {
        if (!btc_sig_rs2der(&remote_sig, pRemoteSig)) goto LABEL_EXIT;
        p_remote_sig = &remote_sig;
    }

    if (!ln_htlctx_set_vin0(
        pTx,
        p_local_sig,
        p_remote_sig,
        pPreimage,
        pRevoKeys,
        pWitScript,
        HtlcSigType)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&local_sig);
    utl_buf_free(&remote_sig);
    return ret;
}


bool HIDDEN ln_htlctx_verify(
    const btc_tx_t *pTx,
    uint64_t Value,
    const uint8_t *pLocalPubKey,
    const utl_buf_t *pLocalSig,
    const uint8_t *pRemotePubKey,
    const utl_buf_t *pRemoteSig,
    const utl_buf_t *pWitScript)
{
    if ((!pLocalPubKey || !pLocalSig) && (!pRemotePubKey || !pRemoteSig)) {
        LOGE("fail: invalid arguments\n");
        return false;
    }
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGE("fail: invalid vin/vout\n");
        return false;
    }

    uint8_t sighash[BTC_SZ_HASH256];
    if (!btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, Value, pWitScript)) return false;
    if (pLocalPubKey && pLocalSig) {
        if (!btc_sig_verify(pLocalSig, sighash, pLocalPubKey)) return false;
    }
    if (pRemotePubKey && pRemoteSig) {
        if (!btc_sig_verify(pRemoteSig, sighash, pRemotePubKey)) return false;
    }
    return true;;
}


/********************************************************************
 * private functions
 ********************************************************************/
