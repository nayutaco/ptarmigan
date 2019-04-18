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
/** @file   ln_derkey_ex.c
 *  @brief  ln_derkey_ex
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "btc_crypto.h"

#include "ln_derkey.h"
#include "ln_derkey_ex.h"


/**************************************************************************
 * macros
 **************************************************************************/
/**************************************************************************
 * prototypes
 **************************************************************************/
/**************************************************************************
 * public functions
 **************************************************************************/

bool HIDDEN ln_derkey_init(ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys)
{
    if (!ln_derkey_local_init(pLocalKeys)) return false;
    /*void*/ ln_derkey_remote_init(pRemoteKeys);
    return true;
}


void HIDDEN ln_derkey_term(ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys)
{
    /*void*/ ln_derkey_local_term(pLocalKeys);
    /*void*/ ln_derkey_remote_term(pRemoteKeys);
}


bool HIDDEN ln_derkey_local_init(ln_derkey_local_keys_t *pKeys)
{
    memset(pKeys, 0xcc, sizeof(ln_derkey_local_keys_t));
    pKeys->next_storage_index = LN_SECRET_INDEX_INIT;
    if (!btc_rng_rand(pKeys->storage_seed, LN_SZ_SEED)) return false;
    for (int lp = LN_BASEPOINT_IDX_FUNDING; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        if (!btc_keys_create_priv(pKeys->secrets[lp])) return false;
    }
    if (!ln_derkey_local_priv2pub(pKeys)) return false;
    if (!ln_derkey_local_storage_update_per_commitment_point(pKeys)) return false;
    return true;
}


void HIDDEN ln_derkey_local_term(ln_derkey_local_keys_t *pKeys)
{
    memset(pKeys, 0x00, sizeof(ln_derkey_local_keys_t));
}


bool HIDDEN ln_derkey_local_priv2pub(ln_derkey_local_keys_t *pKeys)
{
    for (int lp = LN_BASEPOINT_IDX_FUNDING; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        if (!btc_keys_priv2pub(pKeys->basepoints[lp], pKeys->secrets[lp])) return false;
    }
    return true;
}


bool HIDDEN ln_derkey_local_storage_update_per_commitment_point(ln_derkey_local_keys_t *pKeys)
{
    /*void*/ ln_derkey_storage_create_secret(
        pKeys->per_commitment_secret, pKeys->storage_seed, pKeys->next_storage_index);
    if (!btc_keys_priv2pub(pKeys->per_commitment_point, pKeys->per_commitment_secret)) return false;
    pKeys->next_storage_index--;
    return true;
}


bool HIDDEN ln_derkey_local_storage_update_per_commitment_point_force(ln_derkey_local_keys_t *pKeys, uint64_t Index)
{
    /*void*/ ln_derkey_storage_create_secret(
        pKeys->per_commitment_secret, pKeys->storage_seed, Index);
    if (!btc_keys_priv2pub(pKeys->per_commitment_point, pKeys->per_commitment_secret)) return false;
    //pKeys.next_storage_index--;
    return true;
}


void HIDDEN ln_derkey_local_storage_create_per_commitment_secret(const ln_derkey_local_keys_t *pKeys, uint8_t *pSecret, uint64_t Index)
{
    /*void*/ ln_derkey_storage_create_secret(pSecret, pKeys->storage_seed, Index);
}


bool HIDDEN ln_derkey_local_storage_create_prev_per_commitment_secret(const ln_derkey_local_keys_t *pKeys, uint8_t *pSecret, uint8_t *pPerCommitPt)
{
    if (ln_derkey_local_storage_get_prev_index(pKeys)) {
        /*void*/ ln_derkey_local_storage_create_per_commitment_secret(
            pKeys, pSecret, ln_derkey_local_storage_get_prev_index(pKeys));
        if (pPerCommitPt) {
            if (!btc_keys_priv2pub(pPerCommitPt, pSecret)) return false;
        }
    } else {
        memset(pSecret, 0x00, BTC_SZ_PRIVKEY);
        if (pPerCommitPt) {
            memcpy(pPerCommitPt, pKeys->per_commitment_point, BTC_SZ_PUBKEY);
        }
    }
    return true;
}


bool HIDDEN ln_derkey_local_storage_create_second_prev_per_commitment_secret(const ln_derkey_local_keys_t *pKeys, uint8_t *pSecret, uint8_t *pPerCommitPt)
{
    uint64_t storage_index = pKeys->next_storage_index + 3;
    if (storage_index <= LN_SECRET_INDEX_INIT) {
        /*void*/ ln_derkey_local_storage_create_per_commitment_secret(
            pKeys, pSecret, storage_index);
        if (pPerCommitPt) {
            if (!btc_keys_priv2pub(pPerCommitPt, pSecret)) return false;
        }
    } else {
        memset(pSecret, 0x00, BTC_SZ_PRIVKEY);
        if (pPerCommitPt) {
            memcpy(pPerCommitPt, pKeys->per_commitment_point, BTC_SZ_PUBKEY);
        }
    }
    return true;
}


uint64_t ln_derkey_local_storage_get_prev_index(const ln_derkey_local_keys_t *pKeys)
{
    if (pKeys->next_storage_index + 2 > LN_SECRET_INDEX_INIT) {
        //0 is a valid index, but it is too far, it is not realistic, so it is returned as an invalid value
        return 0;
    }
    return pKeys->next_storage_index + 2;
}


uint64_t ln_derkey_local_storage_get_current_index(const ln_derkey_local_keys_t *pKeys)
{
    if (pKeys->next_storage_index + 1 > LN_SECRET_INDEX_INIT) {
        //0 is a valid index, but it is too far, it is not realistic, so it is returned as an invalid value
        return 0;
    }
    return pKeys->next_storage_index + 1;
}


uint64_t ln_derkey_local_storage_get_next_index(const ln_derkey_local_keys_t *pKeys)
{
    return pKeys->next_storage_index;
}


void HIDDEN ln_derkey_remote_init(ln_derkey_remote_keys_t *pKeys)
{
    memset(pKeys, 0xcc, sizeof(ln_derkey_remote_keys_t));
    ln_derkey_remote_storage_init(pKeys);
}


void HIDDEN ln_derkey_remote_term(ln_derkey_remote_keys_t *pKeys)
{
    memset(pKeys, 0x00, sizeof(ln_derkey_remote_keys_t));
}


void HIDDEN ln_derkey_remote_storage_init(ln_derkey_remote_keys_t *pKeys)
{
    ln_derkey_storage_init(&pKeys->storage);
    pKeys->next_storage_index = LN_SECRET_INDEX_INIT;
}


bool HIDDEN ln_derkey_remote_storage_insert_per_commitment_secret(ln_derkey_remote_keys_t *pKeys, const uint8_t *pSecret)
{
    if (!ln_derkey_storage_insert_secret(&pKeys->storage, pSecret, pKeys->next_storage_index)) return false;
    pKeys->next_storage_index--;
    return true;
}


bool HIDDEN ln_derkey_remote_storage_get_secret(
    const ln_derkey_remote_keys_t *pKeys, uint8_t *pSecret, uint64_t Index)
{
    return ln_derkey_storage_get_secret(pSecret, &pKeys->storage, Index);
}


uint64_t ln_derkey_remote_storage_get_current_index(const ln_derkey_remote_keys_t *pKeys)
{
    return pKeys->next_storage_index + 1;
}


uint64_t ln_derkey_remote_storage_get_next_index(const ln_derkey_remote_keys_t *pKeys)
{
    return pKeys->next_storage_index;
}


bool HIDDEN ln_derkey_local_update_script_pubkeys(
    ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys)
{
    //pubkey (for `to_remote` output)
    //LOGD("pubkey\n");
    if (!ln_derkey_pubkey(
        pLocalKeys->script_pubkeys[LN_SCRIPT_IDX_PUBKEY],
        pRemoteKeys->basepoints[LN_BASEPOINT_IDX_PAYMENT],
        pLocalKeys->per_commitment_point)) return false;

    //local_htlckey
    //LOGD("local_htlckey\n");
    if (!ln_derkey_pubkey(
        pLocalKeys->script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
        pLocalKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pLocalKeys->per_commitment_point)) return false;

    //remote_htlckey
    //LOGD("remote_htlckey\n");
    if (!ln_derkey_pubkey(
        pLocalKeys->script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
        pRemoteKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pLocalKeys->per_commitment_point)) return false;

    //local_delayedkey
    //LOGD("delayedkey\n");
    if (!ln_derkey_pubkey(
        pLocalKeys->script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pLocalKeys->basepoints[LN_BASEPOINT_IDX_DELAYED],
        pLocalKeys->per_commitment_point)) return false;

    //revocationkey
    //LOGD("revocationkey\n");
    if (!ln_derkey_revocation_pubkey(
        pLocalKeys->script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pRemoteKeys->basepoints[LN_BASEPOINT_IDX_REVOCATION],
        pLocalKeys->per_commitment_point)) return false;

    return true;
}


bool HIDDEN ln_derkey_remote_update_script_pubkeys(
    ln_derkey_remote_keys_t *pRemoteKeys, ln_derkey_local_keys_t *pLocalKeys)
{
    //pubkey (for `to_remote` output)
    //LOGD("pubkey\n");
    if (!ln_derkey_pubkey(
        pRemoteKeys->script_pubkeys[LN_SCRIPT_IDX_PUBKEY],
        pLocalKeys->basepoints[LN_BASEPOINT_IDX_PAYMENT],
        pRemoteKeys->per_commitment_point)) return false;

    //local_htlckey
    //LOGD("local_htlckey\n");
    if (!ln_derkey_pubkey(
        pRemoteKeys->script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
        pRemoteKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pRemoteKeys->per_commitment_point)) return false;

    //remote_htlckey
    //LOGD("remote_htlckey\n");
    if (!ln_derkey_pubkey(
        pRemoteKeys->script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
        pLocalKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pRemoteKeys->per_commitment_point)) return false;

    //local_delayedkey
    //LOGD("delayedkey\n");
    if (!ln_derkey_pubkey(
        pRemoteKeys->script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pRemoteKeys->basepoints[LN_BASEPOINT_IDX_DELAYED],
        pRemoteKeys->per_commitment_point)) return false;

    //revocationkey
    //LOGD("revocationkey\n");
    if (!ln_derkey_revocation_pubkey(
        pRemoteKeys->script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pLocalKeys->basepoints[LN_BASEPOINT_IDX_REVOCATION],
        pRemoteKeys->per_commitment_point)) return false;

    return true;
}


//https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation
bool HIDDEN ln_derkey_update_script_pubkeys(
    ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys)
{
    if (!ln_derkey_local_update_script_pubkeys(pLocalKeys, pRemoteKeys)) return false;
    if (!ln_derkey_remote_update_script_pubkeys(pRemoteKeys, pLocalKeys)) return false;
    return true;
}


bool HIDDEN ln_derkey_local_restore(ln_derkey_local_keys_t *pKeys)
{
    //basepoints
    if (!ln_derkey_local_priv2pub(pKeys)) return false;
    //per_commitment_secret, per_commitment_point
    if (!ln_derkey_local_storage_update_per_commitment_point_force(
        pKeys, ln_derkey_local_storage_get_current_index(pKeys))) return false;
    return true;
}


bool HIDDEN ln_derkey_remote_restore(ln_derkey_remote_keys_t *pKeys)
{
    (void)pKeys;
    //nothing
    return true;
}


bool HIDDEN ln_derkey_restore(ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys)
{
    if (!ln_derkey_local_restore(pLocalKeys)) return false;
    if (!ln_derkey_remote_restore(pRemoteKeys)) return false;
    if (!ln_derkey_update_script_pubkeys(pLocalKeys, pRemoteKeys)) return false;
    return true;
}


/********************************************************************
 * private functions
 ********************************************************************/
