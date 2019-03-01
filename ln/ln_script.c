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

#include "ln_script.h"
#include "ln_signer.h"
#include "ln_local.h"

//#define M_DBG_VERBOSE

/**************************************************************************
 * macros
 **************************************************************************/

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
    if (!utl_push_init(&push, pWitScript, 77)) goto LABEL_ERROR;    //to_self_delayが2byteの場合
    if (!utl_push_data(&push, BTC_OP_IF BTC_OP_SZ_PUBKEY, 2)) goto LABEL_ERROR;
    if (!utl_push_data(&push, pLocalRevoKey, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_ELSE, 1)) goto LABEL_ERROR;
    if (!utl_push_value(&push, LocalToSelfDelay)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_CSV BTC_OP_DROP BTC_OP_SZ_PUBKEY, 3)) goto LABEL_ERROR;
    if (!utl_push_data(&push, pLocalDelayedKey, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_ENDIF BTC_OP_CHECKSIG, 2)) goto LABEL_ERROR;
    if (!utl_push_trim(&push)) goto LABEL_ERROR;

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    {
        LOGD("script:\n");
        btc_script_print(pWitScript->buf, pWitScript->len);
        utl_buf_t buf = UTL_BUF_INIT;
        if (!btc_script_p2wsh_create_scriptpk(&buf, pWitScript)) goto LABEL_ERROR;
        LOGD("vout: ");
        DUMPD(buf.buf, buf.len);
        utl_buf_free(&buf);
    }
#endif  //M_DBG_VERBOSE
    return true;

LABEL_ERROR:
    utl_buf_free(pWitScript);
    return false;
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


bool HIDDEN ln_script_create_htlc(
    utl_buf_t *pWitScript,
    ln_commit_tx_output_type_t Type,
    const uint8_t *pLocalHtlcKey,
    const uint8_t *pLocalRevoKey,
    const uint8_t *pRemoteHtlcKey,
    const uint8_t *pPaymentHash,
    uint32_t CltvExpiry)
{
    switch (Type) {
    case LN_COMMIT_TX_OUTPUT_TYPE_OFFERED:
        return create_offered_htlc(
            pWitScript, pLocalHtlcKey, pLocalRevoKey, pPaymentHash, pRemoteHtlcKey);
    case LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED:
        return create_received_htlc(
            pWitScript, pLocalHtlcKey, pLocalRevoKey, pRemoteHtlcKey, pPaymentHash, CltvExpiry);
    default:
        ;
    }
    return false;
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
    if (!utl_push_init(&push, pWitScript, 133)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_DUP BTC_OP_HASH160 BTC_OP_SZ20, 3)) goto LABEL_ERROR;
    btc_md_hash160(hash, pLocalRevoKey, BTC_SZ_PUBKEY);
    if (!utl_push_data(&push, hash, BTC_SZ_HASH160)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_EQUAL BTC_OP_IF BTC_OP_CHECKSIG BTC_OP_ELSE BTC_OP_SZ_PUBKEY, 5)) goto LABEL_ERROR;
    if (!utl_push_data(&push, pRemoteHtlcKey, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_SWAP BTC_OP_SIZE BTC_OP_SZ1 BTC_OP_SZ32 BTC_OP_EQUAL BTC_OP_NOTIF BTC_OP_DROP BTC_OP_2 BTC_OP_SWAP BTC_OP_SZ_PUBKEY, 10)) goto LABEL_ERROR;
    if (!utl_push_data(&push, pLocalHtlcKey, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_2 BTC_OP_CHECKMULTISIG BTC_OP_ELSE BTC_OP_HASH160 BTC_OP_SZ20, 5)) goto LABEL_ERROR;
    btc_md_ripemd160(hash, pPaymentHash, BTC_SZ_HASH256);
    if (!utl_push_data(&push, hash, BTC_SZ_HASH160)) goto LABEL_ERROR;
    if (!utl_push_data(&push, BTC_OP_EQUALVERIFY BTC_OP_CHECKSIG BTC_OP_ENDIF BTC_OP_ENDIF, 4)) goto LABEL_ERROR;
    if (!utl_push_trim(&push)) goto LABEL_ERROR;

#if defined(M_DBG_VERBOSE) && defined(PTARM_USE_PRINTFUNC)
    LOGD("script:\n");
    btc_script_print(pWitScript->buf, pWitScript->len);
#endif  //M_DBG_VERBOSE
    return true;

LABEL_ERROR:
    utl_buf_free(pWitScript);
    return false;
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
