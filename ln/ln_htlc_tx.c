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
/** @file   ln_htlc_tx.c
 *  @brief  ln_htlc_tx
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
#include "ln_htlc_tx.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool HIDDEN ln_htlc_tx_create(
    btc_tx_t *pTx,
    uint64_t Value,
    const utl_buf_t *pWitScript,
    ln_commit_tx_output_type_t Type,
    uint32_t CltvExpiry,
    const uint8_t *pTxid,
    int Index)
{
    //vout
    if (pWitScript != NULL) {
        if (!btc_sw_add_vout_p2wsh_wit(pTx, Value, pWitScript)) return false;
        pTx->vout[0].opt = (uint16_t)Type;
    }
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


bool HIDDEN ln_htlc_tx_sign(
    btc_tx_t *pTx,
    utl_buf_t *pSig,
    uint64_t Value,
    const btc_keys_t *pKeys,
    const utl_buf_t *pWitScript)
{
    uint8_t sig[LN_SZ_SIGNATURE];
    if (!ln_htlc_tx_sign_rs(pTx, sig, Value, pKeys, pWitScript)) return false;
    if (!btc_sig_rs2der(pSig, sig)) return false;
    return true;
}


bool HIDDEN ln_htlc_tx_sign_rs(
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


bool HIDDEN ln_htlc_tx_set_vin0(
    btc_tx_t *pTx,
    const utl_buf_t *pLocalSig,
    const utl_buf_t *pRemoteSig,
    const uint8_t *pPreimage,
    const btc_keys_t *pRevoKeys,
    const utl_buf_t *pWitScript,
    ln_htlc_tx_sig_type_t HtlcSigType)
{
    switch (HtlcSigType) {
    case LN_HTLC_TX_SIG_TIMEOUT_SUCCESS:
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
    case LN_HTLC_TX_SIG_REMOTE_OFFER:
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
    case LN_HTLC_TX_SIG_REMOTE_RECV:
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
    case LN_HTLC_TX_SIG_REVOKE_RECV:
    case LN_HTLC_TX_SIG_REVOKE_OFFER:
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


bool HIDDEN ln_htlc_tx_set_vin0_rs(
    btc_tx_t *pTx,
    const uint8_t *pLocalSig,
    const uint8_t *pRemoteSig,
    const uint8_t *pPreimage,
    const btc_keys_t *pRevoKeys,
    const utl_buf_t *pWitScript,
    ln_htlc_tx_sig_type_t HtlcSigType)
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

    if (!ln_htlc_tx_set_vin0(
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


bool HIDDEN ln_htlc_tx_verify(
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


bool HIDDEN ln_spend_htlc_offered_output_tx_create(
    btc_tx_t *pTx,
    uint64_t Value, //dummy
    const utl_buf_t *pScriptPk,
    const uint8_t *pTxid,
    int Index)
{
    //vout
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    if (!vout) return false;
    if (!utl_buf_alloccopy(&vout->script, pScriptPk->buf, pScriptPk->len)) return false;

    pTx->vout[0].opt = (uint16_t)LN_COMMIT_TX_OUTPUT_TYPE_OFFERED;
    pTx->locktime = 0;

    //vin
    if (!btc_tx_add_vin(pTx, pTxid, Index)) return false;
    pTx->vin[0].sequence = 0;
    return true;
}


bool HIDDEN ln_spend_htlc_received_output_tx_create(
    btc_tx_t *pTx,
    uint64_t Value, //dummy
    const utl_buf_t *pScriptPk,
    const uint8_t *pTxid,
    int Index,
    uint32_t CltvExpiry)
{
    //vout
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    if (!vout) return false;
    if (!utl_buf_alloccopy(&vout->script, pScriptPk->buf, pScriptPk->len)) return false;

    pTx->vout[0].opt = (uint16_t)LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED;
    pTx->locktime = CltvExpiry;

    //vin
    if (!btc_tx_add_vin(pTx, pTxid, Index)) return false;
    pTx->vin[0].sequence = 0;
    return true;
}


bool HIDDEN ln_spend_htlc_offered_output_tx_set_vin0(
    btc_tx_t *pTx,
    const uint8_t *pPreimage,
    const utl_buf_t *pWitScript)
{
    // <remotehtlcsig> dummmy
    // <payment-preimage>
    // <witness script>

    uint8_t dummy_sig[BTC_SZ_SIGN_DER_MAX] = {0};
    const utl_buf_t remote_htlc_sig = { (CONST_CAST uint8_t *)dummy_sig, BTC_SZ_SIGN_DER_MAX };
    const utl_buf_t preimage = { (CONST_CAST uint8_t *)pPreimage, LN_SZ_PREIMAGE };
    const utl_buf_t *wit_items[] = { &remote_htlc_sig, &preimage, pWitScript };
    if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
    return true;
}


bool HIDDEN ln_spend_htlc_received_output_tx_set_vin0(
    btc_tx_t *pTx,
    const utl_buf_t *pWitScript)
{
    // <remotehtlcsig> dummmy
    // 0
    // <witness script>

    uint8_t dummy_sig[BTC_SZ_SIGN_DER_MAX] = {0};
    const utl_buf_t remote_htlc_sig = { (CONST_CAST uint8_t *)dummy_sig, BTC_SZ_SIGN_DER_MAX };
    const utl_buf_t zero = UTL_BUF_INIT;
    const utl_buf_t *wit_items[] = { &remote_htlc_sig, &zero, pWitScript };
    if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
    return true;
}


bool HIDDEN ln_spend_htlc_output_tx_adjust_fee(btc_tx_t *pTx, uint32_t FeeratePerKw)
{
    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(pTx, &txbuf);
    uint32_t weight = btc_tx_get_weight_raw(txbuf.buf, txbuf.len);
    if (!weight) return false;
    uint64_t fee = ((uint64_t)weight * (uint64_t)FeeratePerKw + 999) / 1000;
    if (fee + BTC_DUST_LIMIT > pTx->vout[0].value) return false;
    pTx->vout[0].value -= fee;
    utl_buf_free(&txbuf);
    return true;
}


bool HIDDEN ln_spend_htlc_output_tx_sign_vin0(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPrivKey)
{
    btc_vin_t *p_vin = &pTx->vin[0];
    uint8_t sighash[BTC_SZ_HASH256];

    if (!btc_sw_sighash_p2wsh_wit(
        pTx, sighash, 0, Value, &p_vin->witness[p_vin->wit_item_cnt - 1])) return false;
    utl_buf_t sig = UTL_BUF_INIT;
    if (!btc_sig_sign(&sig, sighash, pPrivKey)) return false;
    utl_buf_free(&p_vin->witness[0]);
    if (!utl_buf_alloccopy(&p_vin->witness[0], sig.buf, sig.len)) {
        utl_buf_free(&sig);
        return false;
    }
    utl_buf_free(&sig);

    //log
    btc_tx_print(pTx);
    utl_buf_t txbuf = UTL_BUF_INIT;
    if (!btc_tx_write(pTx, &txbuf)) return false;
    LOGD("raw=");
    DUMPD(txbuf.buf, txbuf.len);
    return true;
}


/********************************************************************
 * private functions
 ********************************************************************/
