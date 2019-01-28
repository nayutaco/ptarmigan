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

bool HIDDEN ln_derkey_privkeys_init(ln_derkey_privkeys_t *pPrivKeys, const uint8_t *pSeed)
{
    memset(pPrivKeys, 0xcc, sizeof(ln_derkey_privkeys_t));
    pPrivKeys->_next_storage_index = LN_SECRET_INDEX_INIT;
    memcpy(pPrivKeys->_storage_seed, pSeed, LN_SZ_SEED);
    for (int lp = LN_BASEPOINT_IDX_FUNDING; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        if (!btc_keys_create_priv(pPrivKeys->secrets[lp])) return false;
    }
    //per_commitment_secret
    return true;
}


void HIDDEN ln_derkey_privkeys_term(ln_derkey_privkeys_t *pPrivKeys)
{
    memset(pPrivKeys, 0x00, sizeof(ln_derkey_privkeys_t));
}


uint64_t ln_derkey_privkeys_get_prev_storage_index(const ln_derkey_privkeys_t *pPrivKeys)
{
    if (pPrivKeys->_next_storage_index + 2 > LN_SECRET_INDEX_INIT) {
        //0 is a valid index, but it is too far, it is not realistic, so it is returned as an invalid value
        return 0;
    }
    return pPrivKeys->_next_storage_index + 2;
}


uint64_t ln_derkey_privkeys_get_current_storage_index(const ln_derkey_privkeys_t *pPrivKeys)
{
    if (pPrivKeys->_next_storage_index + 1 > LN_SECRET_INDEX_INIT) {
        //0 is a valid index, but it is too far, it is not realistic, so it is returned as an invalid value
        return 0;
    }
    return pPrivKeys->_next_storage_index + 1;
}


uint64_t ln_derkey_privkeys_get_next_storage_index(const ln_derkey_privkeys_t *pPrivKeys)
{
    return pPrivKeys->_next_storage_index;
}


//https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation
bool HIDDEN ln_derkey_update_scriptkeys(
    ln_derkey_script_pubkeys_t *pLocalScriptPubKeys,
    ln_derkey_script_pubkeys_t *pRemoteScriptPubKeys,
    ln_derkey_pubkeys_t *pLocalPubKeys,
    ln_derkey_pubkeys_t *pRemotePubKeys)
{
    //
    //local commitment transaction
    //

    //localpubkey (for `to_remote` output)
    //LOGD("local: localpubkey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_PUBKEY],
        pRemotePubKeys->basepoints[LN_BASEPOINT_IDX_PAYMENT],
        pLocalPubKeys->per_commitment_point)) return false;

    //local_htlckey
    //LOGD("local: local_htlckey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
        pLocalPubKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pLocalPubKeys->per_commitment_point)) return false;

    //remote_htlckey
    //LOGD("local: remote_htlckey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
        pRemotePubKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pLocalPubKeys->per_commitment_point)) return false;

    //local_delayedkey
    //LOGD("local: delayedkey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_DELAYEDKEY],
        pLocalPubKeys->basepoints[LN_BASEPOINT_IDX_DELAYED],
        pLocalPubKeys->per_commitment_point)) return false;

    //revocationkey
    //LOGD("local: revocationkey\n");
    if (!ln_derkey_revocation_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pRemotePubKeys->basepoints[LN_BASEPOINT_IDX_REVOCATION],
        pLocalPubKeys->per_commitment_point)) return false;


    //
    //remote commitment transaction
    //

    //remotepubkey (for `to_remote` output)
    //LOGD("remote: remotepubkey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_PUBKEY],
        pLocalPubKeys->basepoints[LN_BASEPOINT_IDX_PAYMENT],
        pRemotePubKeys->per_commitment_point)) return false;

    //local_htlckey
    //LOGD("remote: local_htlckey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
        pRemotePubKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pRemotePubKeys->per_commitment_point)) return false;

    //remote_htlckey
    //LOGD("remote: remote_htlckey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
        pLocalPubKeys->basepoints[LN_BASEPOINT_IDX_HTLC],
        pRemotePubKeys->per_commitment_point)) return false;

    //remote_delayedkey
    //LOGD("remote: remote_delayedkey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_DELAYEDKEY],
        pRemotePubKeys->basepoints[LN_BASEPOINT_IDX_DELAYED],
        pRemotePubKeys->per_commitment_point)) return false;

    //revocationkey
    //LOGD("remote: revocationkey\n");
    if (!ln_derkey_revocation_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_REVOCATIONKEY],
        pLocalPubKeys->basepoints[LN_BASEPOINT_IDX_REVOCATION],
        pRemotePubKeys->per_commitment_point)) return false;

    return true;
}


/********************************************************************
 * private functions
 ********************************************************************/
