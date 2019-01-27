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

static bool create_per_commit_secret(const ln_self_t *self, uint8_t *pSecret, uint8_t *pPerCommitPt, uint64_t Offset);
static bool get_secret(const ln_self_t *self, btc_keys_t *pKeys, int Index, const uint8_t *pPerCommit);


/**************************************************************************
 * library functions
 **************************************************************************/

bool HIDDEN ln_signer_init(ln_self_t *self, const uint8_t *pSeed)
{
    if (!pSeed) return true;

    if (!ln_derkey_privkeys_init(&self->privkeys, pSeed)) return false;
    ln_derkey_storage_init(&self->peer_storage);
    return true;
}


void HIDDEN ln_signer_term(ln_self_t *self)
{
    /*void*/ ln_derkey_privkeys_term(&self->privkeys);
}


bool HIDDEN ln_signer_create_channel_keys(ln_self_t *self)
{
    //create pubkeys
    for (int lp = LN_BASEPOINT_IDX_FUNDING; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        if (!btc_keys_priv2pub(self->funding_local.pubkeys.keys[lp], self->privkeys.keys[lp])) return false;
    }

    //for open_channel/accept_channel
    return ln_signer_keys_update_per_commitment_secret(self);
}


bool HIDDEN ln_signer_keys_update_per_commitment_secret(ln_self_t *self)
{
    if (!ln_signer_keys_update_force(self, self->privkeys._next_storage_index)) return false;
    self->privkeys._next_storage_index--;
    LOGD("update storage_next_index = %016" PRIx64 "\n", self->privkeys._next_storage_index);
    return true;
}


bool HIDDEN ln_signer_keys_update_force(ln_self_t *self, uint64_t Index)
{
    LOGD("shachain index = %" PRIu64 "\n", Index);
    return create_per_commit_secret(self, self->privkeys.per_commitment_secret, self->funding_local.pubkeys.per_commitment_point, Index);
}


bool HIDDEN ln_signer_create_prev_per_commit_secret(const ln_self_t *self, uint8_t *pSecret, uint8_t *pPerCommitPt)
{
    if (self->privkeys._next_storage_index + 2 <= LN_SECRET_INDEX_INIT) {
        //  現在の funding_local.keys[LN_BASEPOINT_IDX_PER_COMMIT]はself->storage_next_indexから生成されていて、「次のper_commitment_secret」になる。
        //  最後に使用した値は self->storage_next_index + 1で、これが「現在のper_commitment_secret」になる。
        //  そのため、「1つ前のper_commitment_secret」は self->storage_next_index + 2 となる。
        return create_per_commit_secret(self, pSecret, pPerCommitPt, self->privkeys._next_storage_index + 2);
    } else {
        memset(pSecret, 0x00, BTC_SZ_PRIVKEY);
        if (pPerCommitPt != NULL) {
            memcpy(pPerCommitPt, self->funding_local.pubkeys.per_commitment_point, BTC_SZ_PUBKEY);
        }
        return true;
    }
}


bool HIDDEN ln_signer_get_revoke_secret(const ln_self_t *self, btc_keys_t *pKeys, const uint8_t *pPerCommit, const uint8_t *pRevokedSec)
{
    if (!ln_derkey_revocation_privkey(pKeys->priv, self->funding_local.pubkeys.keys[LN_BASEPOINT_IDX_REVOCATION],
        pPerCommit, self->privkeys.keys[LN_BASEPOINT_IDX_REVOCATION], pRevokedSec)) return false;
    return btc_keys_priv2pub(pKeys->pub, pKeys->priv);
}


bool HIDDEN ln_signer_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const ln_derkey_privkeys_t *pPrivKey, int Index)
{
    return btc_sig_sign(pSig, pTxHash, pPrivKey->keys[Index]);
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


bool HIDDEN ln_signer_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const ln_derkey_privkeys_t *pPrivKey, int Index)
{
    return btc_sig_sign_rs(pRS, pTxHash, pPrivKey->keys[Index]);
}


bool HIDDEN ln_signer_tolocal_key(const ln_self_t *self, btc_keys_t *pKey, bool bRevoked)
{
    if (bRevoked) {
        return ln_signer_get_revoke_secret(self, pKey, 
            self->funding_remote.pubkeys.per_commitment_point, self->revoked_sec.buf);
    } else {
        return get_secret(self, pKey, LN_BASEPOINT_IDX_DELAYED,
            self->funding_local.pubkeys.per_commitment_point);
    }
}


bool HIDDEN ln_signer_toremote_key(const ln_self_t *self, btc_keys_t *pKey)
{
    return get_secret(self, pKey, LN_BASEPOINT_IDX_PAYMENT,
        self->funding_remote.pubkeys.per_commitment_point);
}


bool HIDDEN ln_signer_htlc_localkey(const ln_self_t *self, btc_keys_t *pKey)
{
    return get_secret(self, pKey, LN_BASEPOINT_IDX_HTLC,
        self->funding_local.pubkeys.per_commitment_point);
}


bool HIDDEN ln_signer_htlc_remotekey(const ln_self_t *self, btc_keys_t *pKey)
{
    return get_secret(self, pKey, LN_BASEPOINT_IDX_HTLC,
        self->funding_remote.pubkeys.per_commitment_point);
}


bool HIDDEN ln_signer_tolocal_tx(
    const ln_self_t *self, btc_tx_t *pTx, utl_buf_t *pSig, uint64_t Value,
    const utl_buf_t *pWitScript, bool bRevoked)
{
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGE("fail: invalid vin/vout\n");
        return false;
    }

    btc_keys_t key;
    if (!ln_signer_tolocal_key(self, &key, bRevoked)) return false;

    uint8_t hash[BTC_SZ_HASH256];
    if (!btc_sw_sighash_p2wsh_wit(pTx, hash,
        0, //only one vin
        Value, pWitScript)) return false;
    return btc_sig_sign(pSig, hash, key.priv);
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** 指定したper_commit_secret取得
 *
 * @param[in,out]   self            チャネル情報
 * @param[out]      pSecret         per_commit_secret
 * @param[in]       Offset          storage_next_indexからのオフセット値
 */
static bool create_per_commit_secret(const ln_self_t *self, uint8_t *pSecret, uint8_t *pPerCommitPt, uint64_t Index)
{
    /*void*/ ln_derkey_storage_create_secret(pSecret, self->privkeys._storage_seed, Index);
    uint8_t pub[BTC_SZ_PUBKEY];
    if (!btc_keys_priv2pub(pub, pSecret)) return false;
    if (pPerCommitPt != NULL) {
        memcpy(pPerCommitPt, pub, BTC_SZ_PUBKEY);
    }

    LOGD("PER_COMMIT_SEC(%016" PRIx64 "): ", Index);
    DUMPD(pSecret, BTC_SZ_PRIVKEY);
    LOGD("       PER_COMMIT_PT: ");
    DUMPD(pub, BTC_SZ_PUBKEY);
    return true;
}


static bool get_secret(const ln_self_t *self, btc_keys_t *pKeys, int Index, const uint8_t *pPerCommit)
{
    if (!ln_derkey_privkey(pKeys->priv, self->funding_local.pubkeys.keys[Index],
        pPerCommit, self->privkeys.keys[Index])) return false;
    return btc_keys_priv2pub(pKeys->pub, pKeys->priv);
}
