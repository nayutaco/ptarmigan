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
 *  @author ueno@nayuta.co
 */
#include <inttypes.h>

#include "ln_script.h"
#include "ln_signer.h"

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

static void create_script_offered(ucoin_buf_t *pBuf,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pLocalPreImageHash160,
    const uint8_t *pRemoteHtlcKey);


static void create_script_received(ucoin_buf_t *pBuf,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pRemoteHtlcKey,
    const uint8_t *pRemotePreImageHash160,
    uint32_t RemoteExpiry);


/**************************************************************************
 * public functions
 **************************************************************************/

uint64_t HIDDEN ln_calc_obscured_txnum(const uint8_t *pLocalBasePt, const uint8_t *pRemoteBasePt)
{
    uint64_t obs = 0;
    uint8_t base[32];
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pLocalBasePt, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pRemoteBasePt, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base);
    mbedtls_sha256_free(&ctx);

    for (int lp = 0; lp < M_OBSCURED_TX_LEN; lp++) {
        obs <<= 8;
        obs |= base[sizeof(base) - M_OBSCURED_TX_LEN + lp];
    }

    return obs;
}


void HIDDEN ln_create_script_local(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay)
{
    ucoin_push_t wscript;

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
    ucoin_push_init(&wscript, pBuf, 77);        //to_self_delayが2byteの場合
    ucoin_push_data(&wscript, UCOIN_OP_IF UCOIN_OP_SZ_PUBKEY, 2);
    ucoin_push_data(&wscript, pLocalRevoKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, UCOIN_OP_ELSE, 1);
    ucoin_push_value(&wscript, LocalDelay);
    ucoin_push_data(&wscript, UCOIN_OP_CSV UCOIN_OP_DROP UCOIN_OP_SZ_PUBKEY, 3);
    ucoin_push_data(&wscript, pLocalDelayedKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, UCOIN_OP_ENDIF UCOIN_OP_CHECKSIG, 2);
    ucoin_push_trim(&wscript);

#ifdef M_DBG_VERBOSE
    DBG_PRINTF("script:\n");
    ucoin_print_script(pBuf->buf, pBuf->len);
    uint8_t prog[LNL_SZ_WITPROG_WSH];
    ucoin_sw_wit2prog_p2wsh(prog, pBuf);
    DBG_PRINTF("vout: ");
    DUMPBIN(prog, LNL_SZ_WITPROG_WSH);
#endif  //M_DBG_VERBOSE
}


/*  to_self_delay後(sequence=to_self_delay)
 *      <local_delayedsig> 0
 *
 *  revoked transaction
 *      <revocation_sig> 1
 *
 */
bool HIDDEN ln_create_tolocal_tx(ucoin_tx_t *pTx,
                uint64_t Value, const ucoin_buf_t *pScriptPk, uint32_t LockTime,
                const uint8_t *pTxid, int Index, bool bRevoked)
{
    //vout
    ucoin_vout_t* vout = ucoin_tx_add_vout(pTx, Value);
    ucoin_buf_alloccopy(&vout->script, pScriptPk->buf, pScriptPk->len);

    //vin
    ucoin_tx_add_vin(pTx, pTxid, Index);
    if (!bRevoked) {
        pTx->vin[0].sequence = LockTime;
    }

    return true;
}


bool HIDDEN ln_sign_tolocal_tx(ucoin_tx_t *pTx, ucoin_buf_t *pSig,
                    uint64_t Value,
                    const ucoin_util_keys_t *pKeys,
                    const ucoin_buf_t *pWitScript, bool bRevoked)
{
    // https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#htlc-timeout-and-htlc-success-transactions

    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        DBG_PRINTF("fail: invalid vin/vout\n");
        return false;
    }

    bool ret = false;
    uint8_t sighash[UCOIN_SZ_SIGHASH];

    //vinは1つしかないので、Indexは0固定
    ucoin_util_sign_p2wsh_1(sighash, pTx, 0, Value, pWitScript);

    ret = ln_signer_p2wsh_2(pSig, sighash, pKeys);
    if (ret) {
        // <delayedsig>
        // 0
        // <script>
        const uint8_t WIT1 = 0x01;
        const ucoin_buf_t wit0 = { NULL, 0 };
        const ucoin_buf_t wit1 = { (CONST_CAST uint8_t *)&WIT1, 1 };
        const ucoin_buf_t *wits[] = {
            pSig,
            NULL,
            pWitScript
        };
        wits[1] = (bRevoked) ? &wit1 : &wit0;

        ret = ucoin_sw_set_vin_p2wsh(pTx, 0, (const ucoin_buf_t **)wits, ARRAY_SIZE(wits));
    }

    return ret;
}


bool HIDDEN ln_create_scriptpkh(ucoin_buf_t *pBuf, const ucoin_buf_t *pPub, int Prefix)
{
    bool ret = true;
    uint8_t pkh[UCOIN_SZ_HASH256];      //一番長いサイズにしておく

    switch (Prefix) {
    case UCOIN_PREF_P2PKH:
    case UCOIN_PREF_NATIVE:
    case UCOIN_PREF_P2SH:
        ucoin_util_hash160(pkh, pPub->buf, pPub->len);
        ucoin_util_create_scriptpk(pBuf, pkh, Prefix);
        break;
    case UCOIN_PREF_NATIVE_SH:
        ucoin_util_sha256(pkh, pPub->buf, pPub->len);
        ucoin_util_create_scriptpk(pBuf, pkh, Prefix);
        break;
    default:
        ret = false;
    }

    return ret;
}


bool HIDDEN ln_check_scriptpkh(const ucoin_buf_t *pBuf)
{
    bool ret;
    const uint8_t *p = pBuf->buf;

    switch (pBuf->len) {
    case 25:
        //P2PKH
        //  OP_DUP OP_HASH160 20 [20-bytes] OP_EQUALVERIFY OP_CHECKSIG
        ret = (p[0] == OP_DUP) && (p[1] == OP_HASH160) && (p[2] == UCOIN_SZ_HASH160) &&
                (p[23] == OP_EQUALVERIFY) && (p[24] == OP_CHECKSIG);
        break;
    case 23:
        //P2SH
        //  OP_HASH160 20 20-bytes OP_EQUAL
        ret = (p[0] == OP_HASH160) && (p[1] == UCOIN_SZ_HASH160) && (p[22] == OP_EQUAL);
        break;
    case 22:
        //P2WPKH
        //  OP_0 20 20-bytes
        ret = (p[0] == OP_0) && (p[1] == UCOIN_SZ_HASH160);
        break;
    case 34:
        //P2WSH
        //  OP_0 32 32-bytes
        ret = (p[0] == OP_0) && (p[1] == UCOIN_SZ_HASH256);
        break;
    default:
        ret = false;
    }

    return ret;
}


void HIDDEN ln_htlcinfo_init(ln_htlcinfo_t *pHtlcInfo)
{
    pHtlcInfo->type = LN_HTLCTYPE_NONE;
    pHtlcInfo->expiry = 0;
    pHtlcInfo->amount_msat = 0;
    pHtlcInfo->preimage_hash = NULL;
    ucoin_buf_init(&pHtlcInfo->script);
}


void HIDDEN ln_htlcinfo_free(ln_htlcinfo_t *pHtlcInfo)
{
    ucoin_buf_free(&pHtlcInfo->script);
}


void HIDDEN ln_create_htlcinfo(ucoin_buf_t *pScript, ln_htlctype_t Type,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteHtlcKey,
                    const uint8_t *pPaymentHash,
                    uint32_t Expiry)
{
    uint8_t hash160[UCOIN_SZ_HASH160];
    ucoin_util_ripemd160(hash160, pPaymentHash, UCOIN_SZ_SHA256);

    switch (Type) {
    case LN_HTLCTYPE_OFFERED:
        //offered
        create_script_offered(pScript,
                    pLocalHtlcKey,
                    pLocalRevoKey,
                    hash160,
                    pRemoteHtlcKey);
        break;
    case LN_HTLCTYPE_RECEIVED:
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


uint64_t HIDDEN ln_fee_calc(ln_feeinfo_t *pFeeInfo, const ln_htlcinfo_t **ppHtlcInfo, int Num)
{
    pFeeInfo->htlc_success = M_FEE_HTLCSUCCESS * pFeeInfo->feerate_per_kw / 1000;
    pFeeInfo->htlc_timeout = M_FEE_HTLCTIMEOUT * pFeeInfo->feerate_per_kw / 1000;
    pFeeInfo->commit = LN_FEE_COMMIT_BASE;
    uint64_t dusts = 0;

    for (int lp = 0; lp < Num; lp++) {
        switch (ppHtlcInfo[lp]->type) {
        case LN_HTLCTYPE_OFFERED:
            if (LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat) >= pFeeInfo->dust_limit_satoshi + pFeeInfo->htlc_timeout) {
                pFeeInfo->commit += M_FEE_COMMIT_HTLC;
            } else {
                dusts += LN_MSAT2SATOSHI(ppHtlcInfo[lp]->amount_msat);
            }
            break;
        case LN_HTLCTYPE_RECEIVED:
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
    DBG_PRINTF("pFeeInfo->commit= %" PRIu64 "(%" PRIu32 ")\n", pFeeInfo->commit, pFeeInfo->feerate_per_kw);

    return pFeeInfo->commit + dusts;
}


bool HIDDEN ln_create_commit_tx(ucoin_tx_t *pTx, ucoin_buf_t *pSig, const ln_tx_cmt_t *pCmt, bool Local)
{
    uint64_t fee_local;
    uint64_t fee_remote;
    if (Local) {
        fee_local = pCmt->p_feeinfo->commit;
        fee_remote = 0;
    } else {
        fee_local = 0;
        fee_remote = pCmt->p_feeinfo->commit;
    }

    //output
    //  P2WPKH - remote
    if (pCmt->remote.satoshi >= pCmt->p_feeinfo->dust_limit_satoshi + fee_remote) {
        DBG_PRINTF("  add P2WPKH remote: %" PRIu64 " sat - %" PRIu64 " sat\n", pCmt->remote.satoshi, fee_remote);
        DBG_PRINTF2("    remote.pubkey: ");
        DUMPBIN(pCmt->remote.pubkey, UCOIN_SZ_PUBKEY);
        ucoin_sw_add_vout_p2wpkh_pub(pTx, pCmt->remote.satoshi - fee_remote, pCmt->remote.pubkey);
        pTx->vout[pTx->vout_cnt - 1].opt = LN_HTLCTYPE_TOREMOTE;
    } else {
        DBG_PRINTF("  output P2WPKH dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", pCmt->remote.satoshi, pCmt->p_feeinfo->dust_limit_satoshi, fee_remote);
    }
    //  P2WSH - local(commitment txのFEEはlocalが払う)
    if (pCmt->local.satoshi >= pCmt->p_feeinfo->dust_limit_satoshi + fee_local) {
        DBG_PRINTF("  add local: %" PRIu64 " - %" PRIu64 " sat\n", pCmt->local.satoshi, fee_local);
        ucoin_sw_add_vout_p2wsh(pTx, pCmt->local.satoshi - fee_local, pCmt->local.p_script);
        pTx->vout[pTx->vout_cnt - 1].opt = LN_HTLCTYPE_TOLOCAL;
    } else {
        DBG_PRINTF("  output P2WSH dust: %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", pCmt->local.satoshi, pCmt->p_feeinfo->dust_limit_satoshi, fee_local);
    }
    //  HTLCs
    for (int lp = 0; lp < pCmt->htlcinfo_num; lp++) {
        uint64_t fee;
        DBG_PRINTF("lp=%d\n", lp);
        switch (pCmt->pp_htlcinfo[lp]->type) {
        case LN_HTLCTYPE_OFFERED:
            DBG_PRINTF("  HTLC: offered: %" PRIu64 " sat\n", LN_MSAT2SATOSHI(pCmt->pp_htlcinfo[lp]->amount_msat));
            fee = pCmt->p_feeinfo->htlc_timeout;
            break;
        case LN_HTLCTYPE_RECEIVED:
            DBG_PRINTF("  HTLC: received: %" PRIu64 " sat\n", LN_MSAT2SATOSHI(pCmt->pp_htlcinfo[lp]->amount_msat));
            fee = pCmt->p_feeinfo->htlc_success;
            break;
        default:
            DBG_PRINTF("  HTLC: type=%d ???\n", pCmt->pp_htlcinfo[lp]->type);
            fee = 0;
            break;
        }
        if (LN_MSAT2SATOSHI(pCmt->pp_htlcinfo[lp]->amount_msat) >= pCmt->p_feeinfo->dust_limit_satoshi + fee) {
            ucoin_sw_add_vout_p2wsh(pTx,
                    LN_MSAT2SATOSHI(pCmt->pp_htlcinfo[lp]->amount_msat),
                    &pCmt->pp_htlcinfo[lp]->script);
            pTx->vout[pTx->vout_cnt - 1].opt = (uint8_t)lp;
            DBG_PRINTF("scirpt.len=%d\n", pCmt->pp_htlcinfo[lp]->script.len);
            //ucoin_print_script(pCmt->pp_htlcinfo[lp]->script.buf, pCmt->pp_htlcinfo[lp]->script.len);
        } else {
            DBG_PRINTF("    --> not add: %" PRIu64 " < %" PRIu64 "\n", LN_MSAT2SATOSHI(pCmt->pp_htlcinfo[lp]->amount_msat), pCmt->p_feeinfo->dust_limit_satoshi + fee);
        }
    }

    //DBG_PRINTF("pCmt->obscured=%" PRIx64 "\n", pCmt->obscured);

    //input
    ucoin_vin_t *vin = ucoin_tx_add_vin(pTx, pCmt->fund.txid, pCmt->fund.txid_index);
    vin->sequence = LN_SEQUENCE(pCmt->obscured);

    //locktime
    pTx->locktime = LN_LOCKTIME(pCmt->obscured);

    //BIP69
    ucoin_util_sort_bip69(pTx);

    //署名
    uint8_t txhash[UCOIN_SZ_SIGHASH];
    ucoin_util_sign_p2wsh_1(txhash, pTx, 0, pCmt->fund.satoshi, pCmt->fund.p_script);

    bool ret = ln_signer_p2wsh_2(pSig, txhash, pCmt->fund.p_keys);

    return ret;
}


void HIDDEN ln_create_htlc_tx(ucoin_tx_t *pTx, uint64_t Value, const ucoin_buf_t *pScript,
                ln_htlctype_t Type, uint32_t CltvExpiry, const uint8_t *pTxid, int Index)
{
    //vout
    ucoin_sw_add_vout_p2wsh(pTx, Value, pScript);
    pTx->vout[0].opt = (uint8_t)Type;
    switch (Type) {
    case LN_HTLCTYPE_RECEIVED:
        //HTLC-success
        DBG_PRINTF("HTLC Success\n");
        pTx->locktime = 0;
        break;
    case LN_HTLCTYPE_OFFERED:
        //HTLC-timeout
        DBG_PRINTF("HTLC Timeout\n");
        pTx->locktime = CltvExpiry;
        break;
    default:
        DBG_PRINTF("fail: opt not set\n");
        assert(0);
        break;
    }

    //vin
    ucoin_tx_add_vin(pTx, pTxid, Index);
    pTx->vin[0].sequence = 0;
}


bool HIDDEN ln_sign_htlc_tx(ucoin_tx_t *pTx, ucoin_buf_t *pLocalSig,
                    uint64_t Value,
                    const ucoin_util_keys_t *pKeys,
                    const ucoin_buf_t *pRemoteSig,
                    const uint8_t *pPreImage,
                    const ucoin_buf_t *pWitScript,
                    ln_htlcsign_t HtlcSign)
{
    // https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#htlc-timeout-and-htlc-success-transactions

    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        DBG_PRINTF("fail: invalid vin/vout\n");
        return false;
    }

    bool ret = false;
    uint8_t sighash[UCOIN_SZ_SIGHASH];
    ucoin_util_sign_p2wsh_1(sighash, pTx, 0, Value, pWitScript);    //vinは1つしかないので、Indexは0固定
    ret = ucoin_util_sign_p2wsh_2(pLocalSig, sighash, pKeys);

    const ucoin_buf_t wit0 = { NULL, 0 };
    const ucoin_buf_t **pp_wits = NULL;
    int wits_num = 0;
    switch (HtlcSign) {
    case HTLCSIGN_TO_SUCCESS:
        if (pRemoteSig != NULL) {
            // 0
            // <remotesig>
            // <localsig>
            // <payment-preimage>(HTLC Success) or 0(HTLC Timeout)
            // <script>
            ucoin_buf_t preimage;
            if (pPreImage != NULL) {
                preimage.buf = (CONST_CAST uint8_t *)pPreImage;
                preimage.len = LN_SZ_PREIMAGE;
            } else {
                ucoin_buf_init(&preimage);
            }
            const ucoin_buf_t *wits[] = {
                &wit0,
                pRemoteSig,
                pLocalSig,
                &preimage,
                pWitScript
            };
            pp_wits = (const ucoin_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        DBG_PRINTF("HTLC Timeout/Success Tx sign: wits_num=%d\n", wits_num);
        break;

    case HTLCSIGN_OF_PREIMG:
        {
            // <remotesig>
            // <payment-preimage>
            // <script>
            ucoin_buf_t preimage;
            if (pPreImage != NULL) {
                preimage.buf = (CONST_CAST uint8_t *)pPreImage;
                preimage.len = LN_SZ_PREIMAGE;
            } else {
                assert(0);
            }
            const ucoin_buf_t *wits[] = {
                pLocalSig,
                &preimage,
                pWitScript
            };
            pp_wits = (const ucoin_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        DBG_PRINTF("Offered HTLC + preimage sign: wits_num=%d\n", wits_num);
        break;

    case HTLCSIGN_RV_TIMEOUT:
        {
            // <remotesig>
            // 0
            // <script>
            const ucoin_buf_t *wits[] = {
                pLocalSig,
                &wit0,
                pWitScript
            };
            pp_wits = (const ucoin_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        DBG_PRINTF("Received HTLC sign: wits_num=%d\n", wits_num);
        break;

    case HTLCSIGN_RV_RECEIVED:
    case HTLCSIGN_RV_OFFERED:
        {
            // <revocation_sig>
            // <revocationkey>
            const ucoin_buf_t revokey = { (CONST_CAST uint8_t *)pKeys->pub, UCOIN_SZ_PUBKEY };
            const ucoin_buf_t *wits[] = {
                pLocalSig,
                &revokey,
                pWitScript
            };
            pp_wits = (const ucoin_buf_t **)wits;
            wits_num = ARRAY_SIZE(wits);
        }
        DBG_PRINTF("revoked HTLC sign: wits_num=%d\n", wits_num);
        break;

    default:
        DBG_PRINTF("HtlcSign=%d\n", (int)HtlcSign);
        assert(0);
        break;
    }
    ret = ucoin_sw_set_vin_p2wsh(pTx, 0, pp_wits, wits_num);

    return ret;
}


//署名の検証だけであれば、hashを計算して、署名と公開鍵を与えればよい
bool HIDDEN ln_verify_htlc_tx(const ucoin_tx_t *pTx,
                    uint64_t Value,
                    const uint8_t *pLocalPubKey,
                    const uint8_t *pRemotePubKey,
                    const ucoin_buf_t *pLocalSig,
                    const ucoin_buf_t *pRemoteSig,
                    const ucoin_buf_t *pWitScript)
{
    if (!pLocalPubKey && !pLocalSig && !pRemotePubKey && !pRemoteSig) {
        DBG_PRINTF("fail: invalid arguments\n");
        return false;
    }
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        DBG_PRINTF("fail: invalid vin/vout\n");
        return false;
    }

    bool ret = true;
    uint8_t sighash[UCOIN_SZ_SIGHASH];

    //vinは1つしかないので、Indexは0固定
    ucoin_util_sign_p2wsh_1(sighash, pTx, 0, Value, pWitScript);
    //DBG_PRINTF("sighash: ");
    //DUMPBIN(sighash, UCOIN_SZ_SIGHASH);
    if (pLocalPubKey && pLocalSig) {
        ret = ucoin_tx_verify(pLocalSig, sighash, pLocalPubKey);
        //DBG_PRINTF("ucoin_tx_verify(local)=%d\n", ret);
        //DBG_PRINTF("localkey: ");
        //DUMPBIN(pLocalPubKey, UCOIN_SZ_PUBKEY);
    }
    if (ret) {
        ret = ucoin_tx_verify(pRemoteSig, sighash, pRemotePubKey);
        //DBG_PRINTF("ucoin_tx_verify(remote)=%d\n", ret);
        //DBG_PRINTF("remotekey: ");
        //DUMPBIN(pRemotePubKey, UCOIN_SZ_PUBKEY);
    }

    //DBG_PRINTF("wscript: ");
    //DUMPBIN(pWitScript->buf, pWitScript->len);

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
static void create_script_offered(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalPreImageHash160,
                    const uint8_t *pRemoteHtlcKey)
{
    ucoin_push_t wscript;
    uint8_t h160[UCOIN_SZ_HASH160];

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
    ucoin_push_init(&wscript, pBuf, 133);
    ucoin_push_data(&wscript, UCOIN_OP_DUP UCOIN_OP_HASH160 UCOIN_OP_SZ20, 3);
    ucoin_util_hash160(h160, pLocalRevoKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, h160, UCOIN_SZ_HASH160);
    ucoin_push_data(&wscript, UCOIN_OP_EQUAL UCOIN_OP_IF UCOIN_OP_CHECKSIG UCOIN_OP_ELSE UCOIN_OP_SZ_PUBKEY, 5);
    ucoin_push_data(&wscript, pRemoteHtlcKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, UCOIN_OP_SWAP UCOIN_OP_SIZE UCOIN_OP_SZ1 UCOIN_OP_SZ32 UCOIN_OP_EQUAL UCOIN_OP_NOTIF UCOIN_OP_DROP UCOIN_OP_2 UCOIN_OP_SWAP UCOIN_OP_SZ_PUBKEY, 10);
    ucoin_push_data(&wscript, pLocalHtlcKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, UCOIN_OP_2 UCOIN_OP_CHECKMULTISIG UCOIN_OP_ELSE UCOIN_OP_HASH160 UCOIN_OP_SZ20, 5);
    ucoin_push_data(&wscript, pLocalPreImageHash160, UCOIN_SZ_HASH160);
    ucoin_push_data(&wscript, UCOIN_OP_EQUALVERIFY UCOIN_OP_CHECKSIG UCOIN_OP_ENDIF UCOIN_OP_ENDIF, 4);
    ucoin_push_trim(&wscript);

#ifdef M_DBG_VERBOSE
    DBG_PRINTF("script:\n");
    ucoin_print_script(pBuf->buf, pBuf->len);
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
static void create_script_received(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteHtlcKey,
                    const uint8_t *pRemotePreImageHash160,
                    uint32_t RemoteExpiry)
{
    ucoin_push_t wscript;
    uint8_t h160[UCOIN_SZ_HASH160];

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
    ucoin_push_init(&wscript, pBuf, 138);
    ucoin_push_data(&wscript, UCOIN_OP_DUP UCOIN_OP_HASH160 UCOIN_OP_SZ20, 3);
    ucoin_util_hash160(h160, pLocalRevoKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, h160, UCOIN_SZ_HASH160);
    ucoin_push_data(&wscript, UCOIN_OP_EQUAL UCOIN_OP_IF UCOIN_OP_CHECKSIG UCOIN_OP_ELSE UCOIN_OP_SZ_PUBKEY, 5);
    ucoin_push_data(&wscript, pRemoteHtlcKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, UCOIN_OP_SWAP UCOIN_OP_SIZE UCOIN_OP_SZ1 UCOIN_OP_SZ32 UCOIN_OP_EQUAL UCOIN_OP_IF UCOIN_OP_HASH160 UCOIN_OP_SZ20, 8);
    ucoin_push_data(&wscript, pRemotePreImageHash160, UCOIN_SZ_HASH160);
    ucoin_push_data(&wscript, UCOIN_OP_EQUALVERIFY UCOIN_OP_2 UCOIN_OP_SWAP UCOIN_OP_SZ_PUBKEY, 4);
    ucoin_push_data(&wscript, pLocalHtlcKey, UCOIN_SZ_PUBKEY);
    ucoin_push_data(&wscript, UCOIN_OP_2 UCOIN_OP_CHECKMULTISIG UCOIN_OP_ELSE UCOIN_OP_DROP, 4);
    ucoin_push_value(&wscript, RemoteExpiry);
    ucoin_push_data(&wscript, UCOIN_OP_CLTV UCOIN_OP_DROP UCOIN_OP_CHECKSIG UCOIN_OP_ENDIF UCOIN_OP_ENDIF, 5);
    ucoin_push_trim(&wscript);

#ifdef M_DBG_VERBOSE
    DBG_PRINTF("script:\n");
    ucoin_print_script(pBuf->buf, pBuf->len);
    //DBG_PRINTF("revocation=");
    //DUMPBIN(pLocalRevoKey, UCOIN_SZ_PUBKEY);
#endif  //M_DBG_VERBOSE
}
