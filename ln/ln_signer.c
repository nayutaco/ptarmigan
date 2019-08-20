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
/** @file   ln_signer.c
 *  @brief  ln_signer
 */

#include "btc_crypto.h"
#include "btc_segwit_addr.h"
#include "btc_sig.h"
#include "btc_script.h"
#include "btc_sw.h"

#include "ln_signer.h"
#include "ln_derkey.h"
#include "ln_node.h"
#include "ln_local.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool get_privkey(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, int Index, const uint8_t *pPerCommitPt);


/**************************************************************************
 * public functions
 **************************************************************************/

bool HIDDEN ln_signer_sign_rs(uint8_t *pSig, const uint8_t *pSigHash, const ln_derkey_local_keys_t *pKey, int Index)
{
    return btc_sig_sign_rs(pSig, pSigHash, pKey->secrets[Index]);
}


bool HIDDEN ln_signer_sign_rs_2(uint8_t *pSig, const uint8_t *pSigHash, const btc_keys_t *pKey)
{
    return btc_sig_sign_rs(pSig, pSigHash, pKey->priv);
}


bool HIDDEN ln_signer_p2wpkh(btc_tx_t *pTx, int Index, uint64_t Value, const btc_keys_t *pKey)
{
    bool ret = false;
    uint8_t sighash[BTC_SZ_HASH256];
    utl_buf_t sigbuf = UTL_BUF_INIT;
    utl_buf_t script_code = UTL_BUF_INIT;

    if (!btc_script_p2wpkh_create_scriptcode(&script_code, pKey->pub)) goto LABEL_EXIT;
    if (!btc_sw_sighash(pTx, sighash, Index, Value, &script_code)) goto LABEL_EXIT;;
    if (!btc_sig_sign(&sigbuf, sighash, pKey->priv)) goto LABEL_EXIT;;
    if (!btc_sw_set_vin_p2wpkh(pTx, Index, &sigbuf, pKey->pub)) goto LABEL_EXIT;;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&sigbuf);
    utl_buf_free(&script_code);
    return ret;
}


bool HIDDEN ln_signer_to_local_key(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys,
    const uint8_t *pRevokedPerCommitSecOrNull)
{
    if (pRevokedPerCommitSecOrNull) {
        return ln_signer_revocation_privkey(
            pKey, pLocalKeys, pRemoteKeys->per_commitment_point, pRevokedPerCommitSecOrNull);
    } else {
        return get_privkey(pKey, pLocalKeys, LN_BASEPOINT_IDX_DELAYED, pLocalKeys->per_commitment_point);
    }
}


bool HIDDEN ln_signer_to_remote_key(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys)
{
    return get_privkey(
        pKey, pLocalKeys, LN_BASEPOINT_IDX_PAYMENT, pRemoteKeys->per_commitment_point);
}


bool HIDDEN ln_signer_htlc_localkey(btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys)
{
    return get_privkey(
        pKey, pLocalKeys, LN_BASEPOINT_IDX_HTLC, pLocalKeys->per_commitment_point);
}


bool HIDDEN ln_signer_htlc_remotekey(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys)
{
    return get_privkey(
        pKey, pLocalKeys, LN_BASEPOINT_IDX_HTLC, pRemoteKeys->per_commitment_point);
}


bool HIDDEN ln_signer_revocation_privkey(btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, const uint8_t *pPerCommitPt, const uint8_t *pPerCommitSec)
{
    if (!ln_derkey_revocation_privkey(
        pKey->priv,
        pLocalKeys->basepoints[LN_BASEPOINT_IDX_REVOCATION], pPerCommitPt,
        pLocalKeys->secrets[LN_BASEPOINT_IDX_REVOCATION], pPerCommitSec)) return false;
    return btc_keys_priv2pub(pKey->pub, pKey->priv);
}


#if 0
bool HIDDEN ln_signer_to_local_tx(
    btc_tx_t *pTx, utl_buf_t *pSig,
    const ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_local_keys_t *pRemoteKeys,
    uint64_t Value, const utl_buf_t *pWitScript, bool bRevoked)
{
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGE("fail: invalid vin/vout\n");
        return false;
    }

    btc_keys_t key;
    if (!ln_signer_to_local_key(&key, pLocalKeys, pRemoteKeys, bRevoked)) return false;

    uint8_t hash[BTC_SZ_HASH256];
    if (!btc_sw_sighash_p2wsh_wit(pTx, hash,
        0, //only one vin
        Value, pWitScript)) return false;
    return btc_sig_sign(pSig, hash, key.priv);
}
#endif


/**************************************************************************
 * private functions
 **************************************************************************/

static bool get_privkey(
    btc_keys_t *pKey, const ln_derkey_local_keys_t *pLocalKeys, int Index, const uint8_t *pPerCommitPt)
{
    if (!ln_derkey_privkey(
        pKey->priv, pLocalKeys->basepoints[Index], pPerCommitPt, pLocalKeys->secrets[Index])) return false;
    return btc_keys_priv2pub(pKey->pub, pKey->priv);
}
