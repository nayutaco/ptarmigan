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
/** @file   ln_script.c
 *  @brief  ln_script
 */
#include <inttypes.h>

#include "mbedtls/sha256.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/ecp.h"

#include "utl_push.h"
#include "utl_dbg.h"

#include "btc_crypto.h"
#include "btc_sig.h"
#include "btc_script.h"
#include "btc_sw.h"

#include "ln_script.h"
#include "ln_signer.h"
#include "ln_local.h"
#include "ln_comtx_util.h"

//#define M_DBG_VERBOSE

/**************************************************************************
 * macros
 **************************************************************************/

//https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#fee-calculation
#define M_FEE_HTLC_TIMEOUT          (663ULL)
#define M_FEE_HTLC_SUCCESS          (703ULL)
#define M_FEE_COMMIT_HTLC           (172ULL)


/********************************************************************
 * prototypes
 ********************************************************************/

static bool create_offered_htlc(
    utl_buf_t *pWitScript,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pPaymentHash,
    const uint8_t *pRemoteHtlcKey);


static bool create_received_htlc(
    utl_buf_t *pWitScript,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pRemoteHtlcKey,
    const uint8_t *pPaymentHash,
    uint32_t CltvExpiry);


/**************************************************************************
 * public functions
 **************************************************************************/

bool HIDDEN ln_script_create_to_local(
    utl_buf_t *pWitScript,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pLocalDelayedKey,
    uint32_t LocalToSelfDelay)
{
    //    OP_IF
    //        # Penalty transaction
    //        <revocationkey>
    //    OP_ELSE
    //        `to_self_delay`
    //        OP_CSV
    //        OP_DROP
    //        <local_delayedkey>
    //    OP_ENDIF
    //    OP_CHECKSIG

    utl_push_t push;
    if (!utl_push_init(&push, pWitScript, 77)) return false;    //to_self_delayが2byteの場合
    if (!utl_push_data(&push, BTC_OP_IF BTC_OP_SZ_PUBKEY, 2)) return false;
    if (!utl_push_data(&push, pLocalRevoKey, BTC_SZ_PUBKEY)) return false;
    if (!utl_push_data(&push, BTC_OP_ELSE, 1)) return false;
    if (!utl_push_value(&push, LocalToSelfDelay)) return false;
    if (!utl_push_data(&push, BTC_OP_CSV BTC_OP_DROP BTC_OP_SZ_PUBKEY, 3)) return false;
    if (!utl_push_data(&push, pLocalDelayedKey, BTC_SZ_PUBKEY)) return false;
    if (!utl_push_data(&push, BTC_OP_ENDIF BTC_OP_CHECKSIG, 2)) return false;
    if (!utl_push_trim(&push)) return false;

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    LOGD("script:\n");
    btc_script_print(pWitScript->buf, pWitScript->len);
    utl_buf_t buf = UTL_BUF_INIT;
    if (!btc_script_p2wsh_create_scriptpk(&buf, pWitScript)) return false;
    LOGD("vout: ");
    DUMPD(buf.buf, buf.len);
    utl_buf_free(&buf);
#endif  //M_DBG_VERBOSE
    return true;
}



bool HIDDEN ln_script_to_local_set_vin0(
    btc_tx_t *pTx,
    const btc_keys_t *pKey,
    const utl_buf_t *pWitScript,
    bool bRevoked)
{
    // <local_delayedsig>
    // 0
    // <witness script>

    // OR

    // <revocation_sig>
    // 1
    // <witness script>

    const utl_buf_t key = { (CONST_CAST uint8_t *)pKey->priv, BTC_SZ_PRIVKEY };
    const utl_buf_t zero = UTL_BUF_INIT;
    const utl_buf_t one = { (CONST_CAST uint8_t *)"\x01", 1 };
    const utl_buf_t *items[] = { &key, (bRevoked) ? &one : &zero, pWitScript };
    if (!btc_sw_set_vin_p2wsh(pTx, 0, (const utl_buf_t **)items, ARRAY_SIZE(items))) return false;
    return true;
}


bool HIDDEN ln_script_to_remote_set_vin0(btc_tx_t *pTx, const btc_keys_t *pKey)
{
    utl_buf_t *p_wit = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * 2);
    if (!utl_buf_alloccopy(&p_wit[0], pKey->priv, BTC_SZ_PRIVKEY)) return false;
    if (!utl_buf_alloccopy(&p_wit[1], pKey->pub, BTC_SZ_PUBKEY)) return false;
    pTx->vin[0].wit_item_cnt = 2;
    pTx->vin[0].witness = p_wit;
    return true;
}


bool HIDDEN ln_script_scriptpk_create(utl_buf_t *pScriptPk, const utl_buf_t *pPub, int Pref)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    switch (Pref) {
    case BTC_PREF_P2PKH:
    case BTC_PREF_P2WPKH:
    case BTC_PREF_P2SH:
        btc_md_hash160(hash, pPub->buf, pPub->len);
        if (!btc_script_scriptpk_create(pScriptPk, hash, Pref)) return false;
        break;
    case BTC_PREF_P2WSH:
        btc_md_sha256(hash, pPub->buf, pPub->len);
        if (!btc_script_scriptpk_create(pScriptPk, hash, Pref)) return false;
        break;
    default:
        return false;
    }
    return true;
}


bool HIDDEN ln_script_scriptpk_check(const utl_buf_t *pScriptPk)
{
    const uint8_t *p = pScriptPk->buf;
    switch (pScriptPk->len) {
    case 25:
        //P2PKH
        //  OP_DUP OP_HASH160 20 [20-bytes] OP_EQUALVERIFY OP_CHECKSIG
        return (p[0] == OP_DUP) && (p[1] == OP_HASH160) && (p[2] == BTC_SZ_HASH160) && (p[23] == OP_EQUALVERIFY) && (p[24] == OP_CHECKSIG);
    case 23:
        //P2SH
        //  OP_HASH160 20 20-bytes OP_EQUAL
        return (p[0] == OP_HASH160) && (p[1] == BTC_SZ_HASH160) && (p[22] == OP_EQUAL);
    case 22:
        //P2WPKH
        //  OP_0 20 20-bytes
        return (p[0] == OP_0) && (p[1] == BTC_SZ_HASH160);
    case 34:
        //P2WSH
        //  OP_0 32 32-bytes
        return (p[0] == OP_0) && (p[1] == BTC_SZ_HASH256);
        break;
    default:
        ;
    }
    return false;
}


void HIDDEN ln_script_htlc_info_init(ln_script_htlc_info_t *pHtlcInfo)
{
    pHtlcInfo->type = LN_HTLC_TYPE_NONE;
    pHtlcInfo->add_htlc_idx = (uint16_t)-1;
    pHtlcInfo->cltv_expiry = 0;
    pHtlcInfo->amount_msat = 0;
    pHtlcInfo->payment_hash = NULL;
    utl_buf_init(&pHtlcInfo->wit_script);
}


void HIDDEN ln_script_htlc_info_free(ln_script_htlc_info_t *pHtlcInfo)
{
    utl_buf_free(&pHtlcInfo->wit_script);
}


bool HIDDEN ln_script_create_htlc(
    utl_buf_t *pWitScript,
    ln_htlc_type_t Type,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pRemoteHtlcKey,
    const uint8_t *pPaymentHash,
    uint32_t CltvExpiry)
{
    switch (Type) {
    case LN_HTLC_TYPE_OFFERED:
        return create_offered_htlc(
            pWitScript, pLocalHtlcKey, pLocalRevoKey, pPaymentHash, pRemoteHtlcKey);
    case LN_HTLC_TYPE_RECEIVED:
        return create_received_htlc(
            pWitScript, pLocalHtlcKey, pLocalRevoKey, pRemoteHtlcKey, pPaymentHash, CltvExpiry);
    default:
        ;
    }
    return false;
}


uint64_t HIDDEN ln_script_fee_calc(
    ln_script_fee_info_t *pFeeInfo,
    const ln_script_htlc_info_t **ppHtlcInfo,
    int Num)
{
    pFeeInfo->htlc_success_fee = M_FEE_HTLC_SUCCESS * pFeeInfo->feerate_per_kw / 1000;
    pFeeInfo->htlc_timeout_fee = M_FEE_HTLC_TIMEOUT * pFeeInfo->feerate_per_kw / 1000;
    pFeeInfo->commit_fee = LN_FEE_COMMIT_BASE;
    uint64_t dusts = 0;

    for (int lp = 0; lp < Num; lp++) {
        switch (ppHtlcInfo[lp]->type) {
        case LN_HTLC_TYPE_OFFERED:
            if (LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat) >= pFeeInfo->dust_limit_satoshi + pFeeInfo->htlc_timeout_fee) {
                pFeeInfo->commit_fee += M_FEE_COMMIT_HTLC;
            } else {
                dusts += LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat);
            }
            break;
        case LN_HTLC_TYPE_RECEIVED:
            if (LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat) >= pFeeInfo->dust_limit_satoshi + pFeeInfo->htlc_success_fee) {
                pFeeInfo->commit_fee += M_FEE_COMMIT_HTLC;
            } else {
                dusts += LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat);
            }
            break;
        default:
            break;
        }
    }
    pFeeInfo->commit_fee = pFeeInfo->commit_fee * pFeeInfo->feerate_per_kw / 1000;
    LOGD("pFeeInfo->commit_fee= %" PRIu64 "(feerate_per_kw=%" PRIu32 ")\n", pFeeInfo->commit_fee, pFeeInfo->feerate_per_kw);

    return pFeeInfo->commit_fee + dusts;
}


bool HIDDEN ln_script_commit_tx_create(
    btc_tx_t *pTx,
    utl_buf_t *pSig,
    const ln_script_commit_tx_t *pCmt,
    bool Local,
    const ln_derkey_local_keys_t *pKeys)
{
    uint64_t fee_local;
    uint64_t fee_remote;
    //commitment txのFEEはfunderが払う
    //  Base commitment transaction fees are extracted from the funder's amount; if that amount is insufficient, the entire amount of the funder's output is used.
    if (Local) {
        fee_local = pCmt->p_fee_info->commit_fee;
        fee_remote = 0;
    } else {
        fee_local = 0;
        fee_remote = pCmt->p_fee_info->commit_fee;
    }

    //output
    //  P2WPKH - remote
    if (pCmt->to_remote.satoshi >= pCmt->p_fee_info->dust_limit_satoshi + fee_remote) {
        LOGD("  add P2WPKH remote: %" PRIu64 " sat - %" PRIu64 " sat\n", pCmt->to_remote.satoshi, fee_remote);
        LOGD("    remote.pubkey: ");
        DUMPD(pCmt->to_remote.pubkey, BTC_SZ_PUBKEY);
        btc_sw_add_vout_p2wpkh_pub(pTx, pCmt->to_remote.satoshi - fee_remote, pCmt->to_remote.pubkey);
        pTx->vout[pTx->vout_cnt - 1].opt = LN_HTLC_TYPE_TO_REMOTE;
    } else {
        LOGD("  [remote output]below dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", pCmt->to_remote.satoshi, pCmt->p_fee_info->dust_limit_satoshi, fee_remote);
    }
    //  P2WSH - local
    if (pCmt->to_local.satoshi >= pCmt->p_fee_info->dust_limit_satoshi + fee_local) {
        LOGD("  add local: %" PRIu64 " - %" PRIu64 " sat\n", pCmt->to_local.satoshi, fee_local);
        btc_sw_add_vout_p2wsh_wit(pTx, pCmt->to_local.satoshi - fee_local, pCmt->to_local.p_wit_script);
        pTx->vout[pTx->vout_cnt - 1].opt = LN_HTLC_TYPE_TO_LOCAL;
    } else {
        LOGD("  [local output]below dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", pCmt->to_local.satoshi, pCmt->p_fee_info->dust_limit_satoshi, fee_local);
    }
    //  HTLCs
    for (int lp = 0; lp < pCmt->htlc_info_num; lp++) {
        uint64_t fee;
        uint64_t output_sat = LN_MSAT2SATOSHI(pCmt->pp_htlc_info[lp]->amount_msat);
        LOGD("lp=%d\n", lp);
        switch (pCmt->pp_htlc_info[lp]->type) {
        case LN_HTLC_TYPE_OFFERED:
            fee = pCmt->p_fee_info->htlc_timeout_fee;
            LOGD("  HTLC: offered=%" PRIu64 " sat, fee=%" PRIu64 "\n", output_sat, fee);
            break;
        case LN_HTLC_TYPE_RECEIVED:
            fee = pCmt->p_fee_info->htlc_success_fee;
            LOGD("  HTLC: received=%" PRIu64 " sat, fee=%" PRIu64 "\n", output_sat, fee);
            break;
        default:
            LOGD("  HTLC: type=%d ???\n", pCmt->pp_htlc_info[lp]->type);
            fee = 0;
            break;
        }
        if (output_sat >= pCmt->p_fee_info->dust_limit_satoshi + fee) {
            btc_sw_add_vout_p2wsh_wit(pTx,
                    output_sat,
                    &pCmt->pp_htlc_info[lp]->wit_script);
            pTx->vout[pTx->vout_cnt - 1].opt = (uint8_t)lp;
            LOGD("scirpt.len=%d\n", pCmt->pp_htlc_info[lp]->wit_script.len);
            //btc_script_print(pCmt->pp_htlc_info[lp]->wit_script.buf, pCmt->pp_htlc_info[lp]->wit_script.len);
        } else {
            LOGD("    [HTLC]below dust: %" PRIu64 " < %" PRIu64 "(dust_limit) + %" PRIu64 "(fee)\n", output_sat, pCmt->p_fee_info->dust_limit_satoshi, fee);
        }
    }

    //LOGD("pCmt->obscured=%016" PRIx64 "\n", pCmt->obscured);

    //input
    btc_vin_t *vin = btc_tx_add_vin(pTx, pCmt->fund.txid, pCmt->fund.txid_index);
    vin->sequence = LN_SEQUENCE(pCmt->obscured_commit_num);

    //locktime
    pTx->locktime = LN_LOCKTIME(pCmt->obscured_commit_num);

    //BIP69
    btc_tx_sort_bip69(pTx);

    //署名
    bool ret;
    uint8_t sighash[BTC_SZ_HASH256];
    ret = btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, pCmt->fund.satoshi, pCmt->fund.p_wit_script);
    if (ret) {
        ret = ln_signer_sign(pSig, sighash, pKeys, LN_BASEPOINT_IDX_FUNDING);
    } else {
        LOGE("fail: calc sighash\n");
    }

    return ret;
}


void HIDDEN ln_script_htlc_tx_create(
    btc_tx_t *pTx,
    uint64_t Value,
    const utl_buf_t *pWitScript,
    ln_htlc_type_t Type,
    uint32_t CltvExpiry,
    const uint8_t *pTxid,
    int Index)
{
    //vout
    btc_sw_add_vout_p2wsh_wit(pTx, Value, pWitScript);
    pTx->vout[0].opt = (uint8_t)Type;
    switch (Type) {
    case LN_HTLC_TYPE_RECEIVED:
        //HTLC-success
        LOGD("HTLC Success\n");
        pTx->locktime = 0;
        break;
    case LN_HTLC_TYPE_OFFERED:
        //HTLC-timeout
        LOGD("HTLC Timeout\n");
        pTx->locktime = CltvExpiry;
        break;
    default:
        LOGE("fail: opt not set\n");
        assert(0);
        break;
    }

    //vin
    btc_tx_add_vin(pTx, pTxid, Index);
    pTx->vin[0].sequence = 0;
}


bool HIDDEN ln_script_htlc_tx_sign(
    btc_tx_t *pTx,
    utl_buf_t *pLocalSig,
    uint64_t Value,
    const btc_keys_t *pKeys,
    const utl_buf_t *pWitScript)
{
    // https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#htlc-timeout-and-htlc-success-transactions

    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGE("fail: invalid vin/vout\n");
        return false;
    }

    bool ret;
    uint8_t sighash[BTC_SZ_HASH256];
    ret = btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, Value, pWitScript);    //vinは1つしかないので、Indexは0固定
    if (ret) {
        ret = ln_signer_sign_2(pLocalSig, sighash, pKeys);
    } else {
        LOGE("fail: calc sighash\n");
    }
    return ret;
}


bool HIDDEN ln_script_htlc_tx_wit(
    btc_tx_t *pTx,
    const utl_buf_t *pLocalSig,
    const btc_keys_t *pKeys,
    const utl_buf_t *pRemoteSig,
    const uint8_t *pPreImage,
    const utl_buf_t *pWitScript,
    ln_script_htlc_sig_t HtlcSign)
{
    const utl_buf_t wit0 = UTL_BUF_INIT;
    const utl_buf_t **pp_wits = NULL;
    int wits_num = 0;
    switch (HtlcSign) {
    case LN_HTLC_SIG_TIMEOUT_SUCCESS:
        if (pRemoteSig != NULL) {
            // 0
            // <remotesig>
            // <localsig>
            // <payment-preimage>(HTLC Success) or 0(HTLC Timeout)
            // <script>
            utl_buf_t preimage = UTL_BUF_INIT;
            if (pPreImage != NULL) {
                preimage.buf = (CONST_CAST uint8_t *)pPreImage;
                preimage.len = LN_SZ_PREIMAGE;
            }
            const utl_buf_t *wits[] = {
                &wit0,
                pRemoteSig,
                pLocalSig,
                &preimage,
                pWitScript
            };
            pp_wits = (const utl_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        LOGD("HTLC Timeout/Success Tx sign: wits_num=%d\n", wits_num);
        break;

    case LN_HTLC_SIG_REMOTE_OFFER:
        {
            // <remotesig>
            // <payment-preimage>
            // <script>
            utl_buf_t preimage = UTL_BUF_INIT;
            if (pPreImage != NULL) {
                preimage.buf = (CONST_CAST uint8_t *)pPreImage;
                preimage.len = LN_SZ_PREIMAGE;
            } else {
                assert(0);
            }
            const utl_buf_t *wits[] = {
                pLocalSig,
                &preimage,
                pWitScript
            };
            pp_wits = (const utl_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        LOGD("Offered HTLC + preimage sign: wits_num=%d\n", wits_num);
        break;

    case LN_HTLC_SIG_REMOTE_RECV:
        {
            // <remotesig>
            // 0
            // <script>
            const utl_buf_t *wits[] = {
                pLocalSig,
                &wit0,
                pWitScript
            };
            pp_wits = (const utl_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        LOGD("Received HTLC sign: wits_num=%d\n", wits_num);
        break;

    case LN_HTLC_SIG_REVOKE_RECV:
    case LN_HTLC_SIG_REVOKE_OFFER:
        {
            // <revocation_sig>
            // <revocationkey>
            const utl_buf_t revokey = { (CONST_CAST uint8_t *)pKeys->pub, BTC_SZ_PUBKEY };
            const utl_buf_t *wits[] = {
                pLocalSig,
                &revokey,
                pWitScript
            };
            pp_wits = (const utl_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        LOGD("revoked HTLC sign: wits_num=%d\n", wits_num);
        break;

    default:
        LOGD("HtlcSign=%d\n", (int)HtlcSign);
        assert(0);
        break;
    }
    bool ret = btc_sw_set_vin_p2wsh(pTx, 0, pp_wits, wits_num);

    return ret;
}


//署名の検証だけであれば、hashを計算して、署名と公開鍵を与えればよい
bool HIDDEN ln_script_htlc_tx_verify(
    const btc_tx_t *pTx,
    uint64_t Value,
    const uint8_t *pLocalPubKey,
    const uint8_t *pRemotePubKey,
    const utl_buf_t *pLocalSig,
    const utl_buf_t *pRemoteSig,
    const utl_buf_t *pWitScript)
{
    if (!pLocalPubKey && !pLocalSig && !pRemotePubKey && !pRemoteSig) {
        LOGE("fail: invalid arguments\n");
        return false;
    }
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGE("fail: invalid vin/vout\n");
        return false;
    }

    bool ret;
    uint8_t sighash[BTC_SZ_HASH256];

    //vinは1つしかないので、Indexは0固定
    ret = btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, Value, pWitScript);
    //LOGD("sighash: ");
    //DUMPD(sighash, BTC_SZ_HASH256);
    if (ret && pLocalPubKey && pLocalSig) {
        ret = btc_sig_verify(pLocalSig, sighash, pLocalPubKey);
        //LOGD("btc_sig_verify(local)=%d\n", ret);
        //LOGD("localkey: ");
        //DUMPD(pLocalPubKey, BTC_SZ_PUBKEY);
    }
    if (ret) {
        ret = btc_sig_verify(pRemoteSig, sighash, pRemotePubKey);
        //LOGD("btc_sig_verify(remote)=%d\n", ret);
        //LOGD("remotekey: ");
        //DUMPD(pRemotePubKey, BTC_SZ_PUBKEY);
    }

    //LOGD("push: ");
    //DUMPD(pWitScript->buf, pWitScript->len);

    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** Offered HTLCスクリプト作成
 *
 * @param[out]      pWitScript              生成したスクリプト
 * @param[in]       pLocalHtlcKey           Local htlcey[33]
 * @param[in]       pLocalRevoKey           Local RevocationKey[33]
 * @param[in]       pPaymentHash            payment_hash[32]
 * @param[in]       pRemoteHtlcKey          Remote htlckey[33]
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
static bool create_offered_htlc(
    utl_buf_t *pWitScript,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pPaymentHash,
    const uint8_t *pRemoteHtlcKey)
{
    //offered HTLC script
    //    OP_DUP OP_HASH160 <HASH160(remote revocationkey)> OP_EQUAL
    //    OP_IF
    //        OP_CHECKSIG
    //    OP_ELSE
    //        <remotekey> OP_SWAP OP_SIZE 32 OP_EQUAL
    //        OP_NOTIF
    //            # To me via HTLC-timeout transaction (timelocked).
    //            OP_DROP 2 OP_SWAP <localkey> 2 OP_CHECKMULTISIG
    //        OP_ELSE
    //            # To you with preimage.
    //            OP_HASH160 <RIPEMD160(payment-hash)> OP_EQUALVERIFY
    //            OP_CHECKSIG
    //        OP_ENDIF
    //    OP_ENDIF

    utl_push_t push;
    uint8_t hash[BTC_SZ_HASH160];
    if (!utl_push_init(&push, pWitScript, 133)) return false;
    if (!utl_push_data(&push, BTC_OP_DUP BTC_OP_HASH160 BTC_OP_SZ20, 3)) return false;
    btc_md_hash160(hash, pLocalRevoKey, BTC_SZ_PUBKEY);
    if (!utl_push_data(&push, hash, BTC_SZ_HASH160)) return false;
    if (!utl_push_data(&push, BTC_OP_EQUAL BTC_OP_IF BTC_OP_CHECKSIG BTC_OP_ELSE BTC_OP_SZ_PUBKEY, 5)) return false;
    if (!utl_push_data(&push, pRemoteHtlcKey, BTC_SZ_PUBKEY)) return false;
    if (!utl_push_data(&push, BTC_OP_SWAP BTC_OP_SIZE BTC_OP_SZ1 BTC_OP_SZ32 BTC_OP_EQUAL BTC_OP_NOTIF BTC_OP_DROP BTC_OP_2 BTC_OP_SWAP BTC_OP_SZ_PUBKEY, 10)) return false;
    if (!utl_push_data(&push, pLocalHtlcKey, BTC_SZ_PUBKEY)) return false;
    if (!utl_push_data(&push, BTC_OP_2 BTC_OP_CHECKMULTISIG BTC_OP_ELSE BTC_OP_HASH160 BTC_OP_SZ20, 5)) return false;
    btc_md_ripemd160(hash, pPaymentHash, BTC_SZ_HASH256);
    if (!utl_push_data(&push, hash, BTC_SZ_HASH160)) return false;
    if (!utl_push_data(&push, BTC_OP_EQUALVERIFY BTC_OP_CHECKSIG BTC_OP_ENDIF BTC_OP_ENDIF, 4)) return false;
    if (!utl_push_trim(&push)) return false;

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    LOGD("script:\n");
    btc_script_print(pWitScript->buf, pWitScript->len);
#endif  //M_DBG_VERBOSE
    return true;
}


/** Received HTLCスクリプト作成
 *
 * @param[out]      pWitScript              生成したスクリプト
 * @param[in]       pLocalHtlcKey           Local htlckey[33]
 * @param[in]       pLocalRevoKey           Local RevocationKey[33]
 * @param[in]       pRemoteHtlcKey          Remote htlckey[33]
 * @param[in]       pPaymentHash            payment_hash[32]
 * @param[in]       CltvExpiry              cltv_expiry
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
static bool create_received_htlc(
    utl_buf_t *pWitScript,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pRemoteHtlcKey,
    const uint8_t *pPaymentHash,
    uint32_t CltvExpiry)
{
    //received HTLC script
    //    OP_DUP OP_HASH160 <HASH160(revocationkey)> OP_EQUAL
    //    OP_IF
    //        OP_CHECKSIG
    //    OP_ELSE
    //        <remotekey> OP_SWAP OP_SIZE 32 OP_EQUAL
    //        OP_IF
    //            # To me via HTLC-success transaction.
    //            OP_HASH160 <RIPEMD160(payment-hash)> OP_EQUALVERIFY
    //            2 OP_SWAP <localkey> 2 OP_CHECKMULTISIG
    //        OP_ELSE
    //            # To you after timeout.
    //            OP_DROP <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
    //            OP_CHECKSIG
    //        OP_ENDIF
    //    OP_ENDIF

    utl_push_t push;
    uint8_t hash[BTC_SZ_HASH160];
    if (!utl_push_init(&push, pWitScript, 138)) return false;
    if (!utl_push_data(&push, BTC_OP_DUP BTC_OP_HASH160 BTC_OP_SZ20, 3)) return false;
    btc_md_hash160(hash, pLocalRevoKey, BTC_SZ_PUBKEY);
    if (!utl_push_data(&push, hash, BTC_SZ_HASH160)) return false;
    if (!utl_push_data(&push, BTC_OP_EQUAL BTC_OP_IF BTC_OP_CHECKSIG BTC_OP_ELSE BTC_OP_SZ_PUBKEY, 5)) return false;
    if (!utl_push_data(&push, pRemoteHtlcKey, BTC_SZ_PUBKEY)) return false;
    if (!utl_push_data(&push, BTC_OP_SWAP BTC_OP_SIZE BTC_OP_SZ1 BTC_OP_SZ32 BTC_OP_EQUAL BTC_OP_IF BTC_OP_HASH160 BTC_OP_SZ20, 8)) return false;
    btc_md_ripemd160(hash, pPaymentHash, BTC_SZ_HASH256);
    if (!utl_push_data(&push, hash, BTC_SZ_HASH160)) return false;
    if (!utl_push_data(&push, BTC_OP_EQUALVERIFY BTC_OP_2 BTC_OP_SWAP BTC_OP_SZ_PUBKEY, 4)) return false;
    if (!utl_push_data(&push, pLocalHtlcKey, BTC_SZ_PUBKEY)) return false;
    if (!utl_push_data(&push, BTC_OP_2 BTC_OP_CHECKMULTISIG BTC_OP_ELSE BTC_OP_DROP, 4)) return false;
    if (!utl_push_value(&push, CltvExpiry)) return false;
    if (!utl_push_data(&push, BTC_OP_CLTV BTC_OP_DROP BTC_OP_CHECKSIG BTC_OP_ENDIF BTC_OP_ENDIF, 5)) return false;
    if (!utl_push_trim(&push)) return false;

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    LOGD("script:\n");
    btc_script_print(pWitScript->buf, pWitScript->len);
    //LOGD("revocation=");
    //DUMPD(pLocalRevoKey, BTC_SZ_PUBKEY);
#endif  //M_DBG_VERBOSE
    return true;
}
