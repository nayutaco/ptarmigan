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

static bool get_secret(const ln_channel_t *pChannel, btc_keys_t *pKeys, int Index, const uint8_t *pPerCommit);


/**************************************************************************
 * library functions
 **************************************************************************/

bool HIDDEN ln_signer_init(ln_channel_t *pChannel, const uint8_t *pSeed)
{
    if (!pSeed) return true;

    if (!ln_derkey_local_privkeys_init(&pChannel->privkeys_local, pSeed)) return false;
    /*void*/ ln_derkey_remote_privkeys_init(&pChannel->privkeys_remote);
    /*void*/ ln_derkey_storage_create_secret(
        pChannel->privkeys_local.per_commitment_secret,
        pChannel->privkeys_local._storage_seed,
        pChannel->privkeys_local._next_storage_index);
    pChannel->privkeys_local._next_storage_index--;
    return true;
}


void HIDDEN ln_signer_term(ln_channel_t *pChannel)
{
    /*void*/ ln_derkey_local_privkeys_term(&pChannel->privkeys_local);
    /*void*/ ln_derkey_remote_privkeys_term(&pChannel->privkeys_remote);
}


bool HIDDEN ln_signer_create_channel_keys(ln_channel_t *pChannel)
{
    //create pubkeys
    for (int lp = LN_BASEPOINT_IDX_FUNDING; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        if (!btc_keys_priv2pub(pChannel->pubkeys_local.basepoints[lp], pChannel->privkeys_local.secrets[lp])) return false;
    }
    if (!btc_keys_priv2pub(
        pChannel->pubkeys_local.per_commitment_point,
        pChannel->privkeys_local.per_commitment_secret)) return false;
    return true;
}


bool HIDDEN ln_signer_keys_update_per_commitment_secret(ln_channel_t *pChannel)
{
    /*void*/ ln_derkey_storage_create_secret(
        pChannel->privkeys_local.per_commitment_secret,
        pChannel->privkeys_local._storage_seed,
        pChannel->privkeys_local._next_storage_index);
    pChannel->privkeys_local._next_storage_index--;
    if (!btc_keys_priv2pub(
        pChannel->pubkeys_local.per_commitment_point,
        pChannel->privkeys_local.per_commitment_secret)) return false;
    return true;
}


bool HIDDEN ln_signer_keys_update_force(ln_channel_t *pChannel, uint64_t Index)
{
    /*void*/ ln_derkey_storage_create_secret(
        pChannel->privkeys_local.per_commitment_secret, pChannel->privkeys_local._storage_seed, Index);
    return btc_keys_priv2pub(
        pChannel->pubkeys_local.per_commitment_point, pChannel->privkeys_local.per_commitment_secret);
}


bool HIDDEN ln_signer_create_prev_per_commit_secret(const ln_channel_t *pChannel, uint8_t *pSecret, uint8_t *pPerCommitPt)
{
    if (ln_derkey_local_privkeys_get_prev_storage_index(&pChannel->privkeys_local)) {
        /*void*/ ln_derkey_storage_create_secret(
            pSecret, pChannel->privkeys_local._storage_seed, ln_derkey_local_privkeys_get_prev_storage_index(&pChannel->privkeys_local));
        if (pPerCommitPt) {
            if (!btc_keys_priv2pub(pPerCommitPt, pSecret)) return false;
        }
    } else {
        memset(pSecret, 0x00, BTC_SZ_PRIVKEY);
        if (pPerCommitPt) {
            memcpy(pPerCommitPt, pChannel->pubkeys_local.per_commitment_point, BTC_SZ_PUBKEY);
        }
    }
    return true;
}


bool HIDDEN ln_signer_get_revoke_secret(const ln_channel_t *pChannel, btc_keys_t *pKeys, const uint8_t *pPerCommit, const uint8_t *pRevokedSec)
{
    if (!ln_derkey_revocation_privkey(pKeys->priv, pChannel->pubkeys_local.basepoints[LN_BASEPOINT_IDX_REVOCATION],
        pPerCommit, pChannel->privkeys_local.secrets[LN_BASEPOINT_IDX_REVOCATION], pRevokedSec)) return false;
    return btc_keys_priv2pub(pKeys->pub, pKeys->priv);
}


bool HIDDEN ln_signer_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const ln_derkey_local_privkeys_t *pPrivKey, int Index)
{
    return btc_sig_sign(pSig, pTxHash, pPrivKey->secrets[Index]);
}


bool HIDDEN ln_signer_p2wsh_force(utl_buf_t *pSig, const uint8_t *pTxHash, const btc_keys_t *pKeys)
{
    return btc_sig_sign(pSig, pTxHash, pKeys->priv);
}


bool HIDDEN ln_signer_p2wpkh(btc_tx_t *pTx, int Index, uint64_t Value, const btc_keys_t *pKeys)
{
    bool ret = false;
    uint8_t txhash[BTC_SZ_HASH256];
    utl_buf_t sigbuf = UTL_BUF_INIT;
    utl_buf_t script_code = UTL_BUF_INIT;

    if (!btc_script_p2wpkh_create_scriptcode(&script_code, pKeys->pub)) goto LABEL_EXIT;
    if (!btc_sw_sighash(pTx, txhash, Index, Value, &script_code)) goto LABEL_EXIT;;
    if (!btc_sig_sign(&sigbuf, txhash, pKeys->priv)) goto LABEL_EXIT;;
    if (!btc_sw_set_vin_p2wpkh(pTx, Index, &sigbuf, pKeys->pub)) goto LABEL_EXIT;;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&sigbuf);
    utl_buf_free(&script_code);
    return ret;
}


bool HIDDEN ln_signer_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const ln_derkey_local_privkeys_t *pPrivKey, int Index)
{
    return btc_sig_sign_rs(pRS, pTxHash, pPrivKey->secrets[Index]);
}


bool HIDDEN ln_signer_tolocal_key(const ln_channel_t *pChannel, btc_keys_t *pKey, bool bRevoked)
{
    if (bRevoked) {
        return ln_signer_get_revoke_secret(pChannel, pKey, 
            pChannel->pubkeys_remote.per_commitment_point, pChannel->revoked_sec.buf);
    } else {
        return get_secret(pChannel, pKey, LN_BASEPOINT_IDX_DELAYED,
            pChannel->pubkeys_local.per_commitment_point);
    }
}


bool HIDDEN ln_signer_toremote_key(const ln_channel_t *pChannel, btc_keys_t *pKey)
{
    return get_secret(pChannel, pKey, LN_BASEPOINT_IDX_PAYMENT,
        pChannel->pubkeys_remote.per_commitment_point);
}


bool HIDDEN ln_signer_htlc_localkey(const ln_channel_t *pChannel, btc_keys_t *pKey)
{
    return get_secret(pChannel, pKey, LN_BASEPOINT_IDX_HTLC,
        pChannel->pubkeys_local.per_commitment_point);
}


bool HIDDEN ln_signer_htlc_remotekey(const ln_channel_t *pChannel, btc_keys_t *pKey)
{
    return get_secret(pChannel, pKey, LN_BASEPOINT_IDX_HTLC,
        pChannel->pubkeys_remote.per_commitment_point);
}


bool HIDDEN ln_signer_tolocal_tx(
    const ln_channel_t *pChannel, btc_tx_t *pTx, utl_buf_t *pSig, uint64_t Value,
    const utl_buf_t *pWitScript, bool bRevoked)
{
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGE("fail: invalid vin/vout\n");
        return false;
    }

    btc_keys_t key;
    if (!ln_signer_tolocal_key(pChannel, &key, bRevoked)) return false;

    uint8_t hash[BTC_SZ_HASH256];
    if (!btc_sw_sighash_p2wsh_wit(pTx, hash,
        0, //only one vin
        Value, pWitScript)) return false;
    return btc_sig_sign(pSig, hash, key.priv);
}


/**************************************************************************
 * private functions
 **************************************************************************/

static bool get_secret(const ln_channel_t *pChannel, btc_keys_t *pKeys, int Index, const uint8_t *pPerCommit)
{
    if (!ln_derkey_privkey(
        pKeys->priv, pChannel->pubkeys_local.basepoints[Index],
        pPerCommit, pChannel->privkeys_local.secrets[Index])) return false;
    return btc_keys_priv2pub(pKeys->pub, pKeys->priv);
}
