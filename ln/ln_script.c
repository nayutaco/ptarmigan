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
 *  @brief  [LN]スクリプト
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

//#define M_DBG_VERBOSE

/**************************************************************************
 * macros
 **************************************************************************/

#define M_FEE_HTLCSUCCESS           (703ULL)
#define M_FEE_HTLCTIMEOUT           (663ULL)
#define M_FEE_COMMIT_HTLC           (172ULL)

#define M_OBSCURED_TX_LEN           (6)


/********************************************************************
 * prototypes
 ********************************************************************/

static void create_script_offered(utl_buf_t *pBuf,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pLocalPreImageHash160,
    const uint8_t *pRemoteHtlcKey);


static void create_script_received(utl_buf_t *pBuf,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pRemoteHtlcKey,
    const uint8_t *pRemotePreImageHash160,
    uint32_t RemoteExpiry);


/**************************************************************************
 * public functions
 **************************************************************************/

uint64_t HIDDEN ln_script_calc_obscured_commit_num_base(const uint8_t *pOpenPayBasePt, const uint8_t *pAcceptPayBasePt)
{
    uint64_t obs = 0;
    uint8_t base[32];
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pOpenPayBasePt, BTC_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pAcceptPayBasePt, BTC_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base);
    mbedtls_sha256_free(&ctx);

    for (int lp = 0; lp < M_OBSCURED_TX_LEN; lp++) {
        obs <<= 8;
        obs |= base[sizeof(base) - M_OBSCURED_TX_LEN + lp];
    }

    return obs;
}


void HIDDEN ln_script_create_to_local(utl_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay)
{
    utl_push_t wscript;

    //local script
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
    utl_push_init(&wscript, pBuf, 77);        //to_self_delayが2byteの場合
    utl_push_data(&wscript, BTC_OP_IF BTC_OP_SZ_PUBKEY, 2);
    utl_push_data(&wscript, pLocalRevoKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, BTC_OP_ELSE, 1);
    utl_push_value(&wscript, LocalDelay);
    utl_push_data(&wscript, BTC_OP_CSV BTC_OP_DROP BTC_OP_SZ_PUBKEY, 3);
    utl_push_data(&wscript, pLocalDelayedKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, BTC_OP_ENDIF BTC_OP_CHECKSIG, 2);
    utl_push_trim(&wscript);

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    LOGD("script:\n");
    btc_script_print(pBuf->buf, pBuf->len);
    utl_buf_t prog = UTL_BUF_INIT;
    btc_script_p2wsh_create_scriptsig(&prog, pBuf);
    LOGD("vout: ");
    DUMPD(prog.buf, prog.len);
    utl_buf_free(&prog);
#endif  //M_DBG_VERBOSE
}



bool HIDDEN ln_script_to_local_wit(btc_tx_t *pTx,
                    const btc_keys_t *pKey,
                    const utl_buf_t *pWitScript, bool bRevoked)
{
    // <delayedsig>
    // 0
    // <script>
    const uint8_t WIT1 = 0x01;
    const utl_buf_t key = { (CONST_CAST uint8_t *)pKey->priv, BTC_SZ_PRIVKEY };
    const utl_buf_t wit0 = UTL_BUF_INIT;
    const utl_buf_t wit1 = { (CONST_CAST uint8_t *)&WIT1, 1 };
    const utl_buf_t *wits[] = {
        &key,
        NULL,
        pWitScript
    };
    wits[1] = (bRevoked) ? &wit1 : &wit0;

    bool ret = btc_sw_set_vin_p2wsh(pTx, 0, (const utl_buf_t **)wits, ARRAY_SIZE(wits));

    return ret;
}


void HIDDEN ln_script_to_remote_wit(btc_tx_t *pTx, const btc_keys_t *pKey)
{
    utl_buf_t *p_wit = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * 2);
    utl_buf_alloccopy(&p_wit[0], pKey->priv, BTC_SZ_PRIVKEY);
    utl_buf_alloccopy(&p_wit[1], pKey->pub, BTC_SZ_PUBKEY);
    pTx->vin[0].wit_item_cnt = 2;
    pTx->vin[0].witness = p_wit;
}


bool HIDDEN ln_script_scriptpkh_create(utl_buf_t *pBuf, const utl_buf_t *pPub, int Prefix)
{
    bool ret = true;
    uint8_t pkh[BTC_SZ_HASH256];      //一番長いサイズにしておく

    switch (Prefix) {
    case BTC_PREF_P2PKH:
    case BTC_PREF_P2WPKH:
    case BTC_PREF_P2SH:
        btc_md_hash160(pkh, pPub->buf, pPub->len);
        btc_script_scriptpk_create(pBuf, pkh, Prefix);
        break;
    case BTC_PREF_P2WSH:
        btc_md_sha256(pkh, pPub->buf, pPub->len);
        btc_script_scriptpk_create(pBuf, pkh, Prefix);
        break;
    default:
        ret = false;
    }

    return ret;
}


bool HIDDEN ln_script_scriptpkh_check(const utl_buf_t *pBuf)
{
    bool ret;
    const uint8_t *p = pBuf->buf;

    switch (pBuf->len) {
    case 25:
        //P2PKH
        //  OP_DUP OP_HASH160 20 [20-bytes] OP_EQUALVERIFY OP_CHECKSIG
        ret = (p[0] == OP_DUP) && (p[1] == OP_HASH160) && (p[2] == BTC_SZ_HASH160) &&
                (p[23] == OP_EQUALVERIFY) && (p[24] == OP_CHECKSIG);
        break;
    case 23:
        //P2SH
        //  OP_HASH160 20 20-bytes OP_EQUAL
        ret = (p[0] == OP_HASH160) && (p[1] == BTC_SZ_HASH160) && (p[22] == OP_EQUAL);
        break;
    case 22:
        //P2WPKH
        //  OP_0 20 20-bytes
        ret = (p[0] == OP_0) && (p[1] == BTC_SZ_HASH160);
        break;
    case 34:
        //P2WSH
        //  OP_0 32 32-bytes
        ret = (p[0] == OP_0) && (p[1] == BTC_SZ_HASH256);
        break;
    default:
        ret = false;
    }

    return ret;
}


void HIDDEN ln_script_htlc_info_init(ln_script_htlc_info_t *pHtlcInfo)
{
    pHtlcInfo->type = LN_HTLC_TYPE_NONE;
    pHtlcInfo->add_htlc_idx = (uint16_t)-1;
    pHtlcInfo->expiry = 0;
    pHtlcInfo->amount_msat = 0;
    pHtlcInfo->preimage_hash = NULL;
    utl_buf_init(&pHtlcInfo->script);
}


void HIDDEN ln_script_htlc_info_free(ln_script_htlc_info_t *pHtlcInfo)
{
    utl_buf_free(&pHtlcInfo->script);
}


void HIDDEN ln_script_htlc_info_script(utl_buf_t *pScript, ln_htlc_type_t Type,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteHtlcKey,
                    const uint8_t *pPaymentHash,
                    uint32_t Expiry)
{
    uint8_t hash160[BTC_SZ_HASH160];
    btc_md_ripemd160(hash160, pPaymentHash, BTC_SZ_HASH256);

    switch (Type) {
    case LN_HTLC_TYPE_OFFERED:
        //offered
        create_script_offered(pScript,
                    pLocalHtlcKey,
                    pLocalRevoKey,
                    hash160,
                    pRemoteHtlcKey);
        break;
    case LN_HTLC_TYPE_RECEIVED:
        //received
        create_script_received(pScript,
                    pLocalHtlcKey,
                    pLocalRevoKey,
                    pRemoteHtlcKey,
                    hash160,
                    Expiry);
        break;
    default:
        break;
    }
}


uint64_t HIDDEN ln_script_fee_calc(
                    ln_script_fee_info_t *pFeeInfo,
                    const ln_script_htlc_info_t **ppHtlcInfo,
                    int Num)
{
    pFeeInfo->htlc_success = M_FEE_HTLCSUCCESS * pFeeInfo->feerate_per_kw / 1000;
    pFeeInfo->htlc_timeout = M_FEE_HTLCTIMEOUT * pFeeInfo->feerate_per_kw / 1000;
    pFeeInfo->commit = LN_FEE_COMMIT_BASE;
    uint64_t dusts = 0;

    for (int lp = 0; lp < Num; lp++) {
        switch (ppHtlcInfo[lp]->type) {
        case LN_HTLC_TYPE_OFFERED:
            if (LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat) >= pFeeInfo->dust_limit_satoshi + pFeeInfo->htlc_timeout) {
                pFeeInfo->commit += M_FEE_COMMIT_HTLC;
            } else {
                dusts += LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat);
            }
            break;
        case LN_HTLC_TYPE_RECEIVED:
            if (LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat) >= pFeeInfo->dust_limit_satoshi + pFeeInfo->htlc_success) {
                pFeeInfo->commit += M_FEE_COMMIT_HTLC;
            } else {
                dusts += LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat);
            }
            break;
        default:
            break;
        }
    }
    pFeeInfo->commit = pFeeInfo->commit * pFeeInfo->feerate_per_kw / 1000;
    LOGD("pFeeInfo->commit= %" PRIu64 "(feerate_per_kw=%" PRIu32 ")\n", pFeeInfo->commit, pFeeInfo->feerate_per_kw);

    return pFeeInfo->commit + dusts;
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
        fee_local = pCmt->p_fee_info->commit;
        fee_remote = 0;
    } else {
        fee_local = 0;
        fee_remote = pCmt->p_fee_info->commit;
    }

    //output
    //  P2WPKH - remote
    if (pCmt->remote.satoshi >= pCmt->p_fee_info->dust_limit_satoshi + fee_remote) {
        LOGD("  add P2WPKH remote: %" PRIu64 " sat - %" PRIu64 " sat\n", pCmt->remote.satoshi, fee_remote);
        LOGD("    remote.pubkey: ");
        DUMPD(pCmt->remote.pubkey, BTC_SZ_PUBKEY);
        btc_sw_add_vout_p2wpkh_pub(pTx, pCmt->remote.satoshi - fee_remote, pCmt->remote.pubkey);
        pTx->vout[pTx->vout_cnt - 1].opt = LN_HTLC_TYPE_TO_REMOTE;
    } else {
        LOGD("  [remote output]below dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", pCmt->remote.satoshi, pCmt->p_fee_info->dust_limit_satoshi, fee_remote);
    }
    //  P2WSH - local
    if (pCmt->local.satoshi >= pCmt->p_fee_info->dust_limit_satoshi + fee_local) {
        LOGD("  add local: %" PRIu64 " - %" PRIu64 " sat\n", pCmt->local.satoshi, fee_local);
        btc_sw_add_vout_p2wsh_wit(pTx, pCmt->local.satoshi - fee_local, pCmt->local.p_script);
        pTx->vout[pTx->vout_cnt - 1].opt = LN_HTLC_TYPE_TO_LOCAL;
    } else {
        LOGD("  [local output]below dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", pCmt->local.satoshi, pCmt->p_fee_info->dust_limit_satoshi, fee_local);
    }
    //  HTLCs
    for (int lp = 0; lp < pCmt->htlc_info_num; lp++) {
        uint64_t fee;
        uint64_t output_sat = LN_MSAT2SATOSHI(pCmt->pp_htlc_info[lp]->amount_msat);
        LOGD("lp=%d\n", lp);
        switch (pCmt->pp_htlc_info[lp]->type) {
        case LN_HTLC_TYPE_OFFERED:
            fee = pCmt->p_fee_info->htlc_timeout;
            LOGD("  HTLC: offered=%" PRIu64 " sat, fee=%" PRIu64 "\n", output_sat, fee);
            break;
        case LN_HTLC_TYPE_RECEIVED:
            fee = pCmt->p_fee_info->htlc_success;
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
                    &pCmt->pp_htlc_info[lp]->script);
            pTx->vout[pTx->vout_cnt - 1].opt = (uint8_t)lp;
            LOGD("scirpt.len=%d\n", pCmt->pp_htlc_info[lp]->script.len);
            //btc_script_print(pCmt->pp_htlc_info[lp]->script.buf, pCmt->pp_htlc_info[lp]->script.len);
        } else {
            LOGD("    [HTLC]below dust: %" PRIu64 " < %" PRIu64 "(dust_limit) + %" PRIu64 "(fee)\n", output_sat, pCmt->p_fee_info->dust_limit_satoshi, fee);
        }
    }

    //LOGD("pCmt->obscured=%016" PRIx64 "\n", pCmt->obscured);

    //input
    btc_vin_t *vin = btc_tx_add_vin(pTx, pCmt->fund.txid, pCmt->fund.txid_index);
    vin->sequence = LN_SEQUENCE(pCmt->obscured);

    //locktime
    pTx->locktime = LN_LOCKTIME(pCmt->obscured);

    //BIP69
    btc_tx_sort_bip69(pTx);

    //署名
    bool ret;
    uint8_t sighash[BTC_SZ_HASH256];
    ret = btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, pCmt->fund.satoshi, pCmt->fund.p_script);
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
                    const utl_buf_t *pScript,
                    ln_htlc_type_t Type,
                    uint32_t CltvExpiry,
                    const uint8_t *pTxid,
                    int Index)
{
    //vout
    btc_sw_add_vout_p2wsh_wit(pTx, Value, pScript);
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


bool HIDDEN ln_script_htlc_tx_sign(btc_tx_t *pTx,
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


bool HIDDEN ln_script_htlc_tx_wit(btc_tx_t *pTx,
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
bool HIDDEN ln_script_htlc_tx_verify(const btc_tx_t *pTx,
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

    //LOGD("wscript: ");
    //DUMPD(pWitScript->buf, pWitScript->len);

    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** Offered HTLCスクリプト作成
 *
 * @param[out]      pBuf                    生成したスクリプト
 * @param[in]       pLocalHtlcKey           Local htlcey[33]
 * @param[in]       pLocalRevoKey           Local RevocationKey[33]
 * @param[in]       pLocalPreImageHash160   Local payment-preimage-hash[20]
 * @param[in]       pRemoteHtlcKey          Remote htlckey[33]
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
static void create_script_offered(utl_buf_t *pBuf,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalPreImageHash160,
                    const uint8_t *pRemoteHtlcKey)
{
    utl_push_t wscript;
    uint8_t h160[BTC_SZ_HASH160];

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
    //
    // payment-hash: payment-preimageをSHA256
    utl_push_init(&wscript, pBuf, 133);
    utl_push_data(&wscript, BTC_OP_DUP BTC_OP_HASH160 BTC_OP_SZ20, 3);
    btc_md_hash160(h160, pLocalRevoKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, h160, BTC_SZ_HASH160);
    utl_push_data(&wscript, BTC_OP_EQUAL BTC_OP_IF BTC_OP_CHECKSIG BTC_OP_ELSE BTC_OP_SZ_PUBKEY, 5);
    utl_push_data(&wscript, pRemoteHtlcKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, BTC_OP_SWAP BTC_OP_SIZE BTC_OP_SZ1 BTC_OP_SZ32 BTC_OP_EQUAL BTC_OP_NOTIF BTC_OP_DROP BTC_OP_2 BTC_OP_SWAP BTC_OP_SZ_PUBKEY, 10);
    utl_push_data(&wscript, pLocalHtlcKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, BTC_OP_2 BTC_OP_CHECKMULTISIG BTC_OP_ELSE BTC_OP_HASH160 BTC_OP_SZ20, 5);
    utl_push_data(&wscript, pLocalPreImageHash160, BTC_SZ_HASH160);
    utl_push_data(&wscript, BTC_OP_EQUALVERIFY BTC_OP_CHECKSIG BTC_OP_ENDIF BTC_OP_ENDIF, 4);
    utl_push_trim(&wscript);

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    LOGD("script:\n");
    btc_script_print(pBuf->buf, pBuf->len);
#endif  //M_DBG_VERBOSE
}


/** Received HTLCスクリプト作成
 *
 * @param[out]      pBuf                    生成したスクリプト
 * @param[in]       pLocalHtlcKey           Local htlckey[33]
 * @param[in]       pLocalRevoKey           Local RevocationKey[33]
 * @param[in]       pRemoteHtlcKey          Remote htlckey[33]
 * @param[in]       pRemotePreImageHash160  Remote payment-preimage-hash[20]
 * @param[in]       RemoteExpiry            Expiry
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
static void create_script_received(utl_buf_t *pBuf,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteHtlcKey,
                    const uint8_t *pRemotePreImageHash160,
                    uint32_t RemoteExpiry)
{
    utl_push_t wscript;
    uint8_t h160[BTC_SZ_HASH160];

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
    //
    // payment-hash: payment-preimageをSHA256
    utl_push_init(&wscript, pBuf, 138);
    utl_push_data(&wscript, BTC_OP_DUP BTC_OP_HASH160 BTC_OP_SZ20, 3);
    btc_md_hash160(h160, pLocalRevoKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, h160, BTC_SZ_HASH160);
    utl_push_data(&wscript, BTC_OP_EQUAL BTC_OP_IF BTC_OP_CHECKSIG BTC_OP_ELSE BTC_OP_SZ_PUBKEY, 5);
    utl_push_data(&wscript, pRemoteHtlcKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, BTC_OP_SWAP BTC_OP_SIZE BTC_OP_SZ1 BTC_OP_SZ32 BTC_OP_EQUAL BTC_OP_IF BTC_OP_HASH160 BTC_OP_SZ20, 8);
    utl_push_data(&wscript, pRemotePreImageHash160, BTC_SZ_HASH160);
    utl_push_data(&wscript, BTC_OP_EQUALVERIFY BTC_OP_2 BTC_OP_SWAP BTC_OP_SZ_PUBKEY, 4);
    utl_push_data(&wscript, pLocalHtlcKey, BTC_SZ_PUBKEY);
    utl_push_data(&wscript, BTC_OP_2 BTC_OP_CHECKMULTISIG BTC_OP_ELSE BTC_OP_DROP, 4);
    utl_push_value(&wscript, RemoteExpiry);
    utl_push_data(&wscript, BTC_OP_CLTV BTC_OP_DROP BTC_OP_CHECKSIG BTC_OP_ENDIF BTC_OP_ENDIF, 5);
    utl_push_trim(&wscript);

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    LOGD("script:\n");
    btc_script_print(pBuf->buf, pBuf->len);
    //LOGD("revocation=");
    //DUMPD(pLocalRevoKey, BTC_SZ_PUBKEY);
#endif  //M_DBG_VERBOSE
}
