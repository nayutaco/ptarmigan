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

//  localkey, remotekey, local_delayedkey, remote_delayedkey
//      pubkey = basepoint + SHA256(per_commitment_point || basepoint)*G
//
//  revocationkey
//      revocationkey = revocation_basepoint * SHA256(revocation_basepoint || per_commitment_point) + per_commitment_point*SHA256(per_commitment_point || revocation_basepoint)
//
bool HIDDEN ln_derkey_update_scriptkeys(
    ln_derkey_script_pubkeys_t *pLocalScriptPubKeys,
    ln_derkey_script_pubkeys_t *pRemoteScriptPubKeys,
    ln_derkey_pubkeys_t *pLocalPubKeys,
    ln_derkey_pubkeys_t *pRemotePubKeys)
{
    //
    //local
    //

    //remotekey = local per_commitment_point & remote payment
    //LOGD("local: remotekey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_REMOTEKEY],
        pRemotePubKeys->keys[LN_BASEPOINT_IDX_PAYMENT],
        pLocalPubKeys->per_commitment_point)) return false;

    //delayedkey = local per_commitment_point & local delayed_payment
    //LOGD("local: delayedkey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_DELAYED],
        pLocalPubKeys->keys[LN_BASEPOINT_IDX_DELAYED],
        pLocalPubKeys->per_commitment_point)) return false;

    //revocationkey = remote per_commitment_point & local revocation_basepoint
    //LOGD("local: revocationkey\n");
    if (!ln_derkey_revocation_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_REVOCATION],
        pRemotePubKeys->keys[LN_BASEPOINT_IDX_REVOCATION],
        pLocalPubKeys->per_commitment_point)) return false;

    //local_htlckey = local per_commitment_point & local htlc_basepoint
    //LOGD("local: local_htlckey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_LOCALHTLCKEY],
        pLocalPubKeys->keys[LN_BASEPOINT_IDX_HTLC],
        pLocalPubKeys->per_commitment_point)) return false;

    //remote_htlckey = local per_commitment_point & remote htlc_basepoint
    //LOGD("local: remote_htlckey\n");
    if (!ln_derkey_pubkey(
        pLocalScriptPubKeys->keys[LN_SCRIPT_IDX_REMOTEHTLCKEY],
        pRemotePubKeys->keys[LN_BASEPOINT_IDX_HTLC],
        pLocalPubKeys->per_commitment_point)) return false;


    //
    //remote
    //

    //remotekey = remote per_commitment_point & local payment
    //LOGD("remote: remotekey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_REMOTEKEY],
        pLocalPubKeys->keys[LN_BASEPOINT_IDX_PAYMENT],
        pRemotePubKeys->per_commitment_point)) return false;

    //delayedkey = remote per_commitment_point & remote delayed_payment
    //LOGD("remote: delayedkey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_DELAYED],
        pRemotePubKeys->keys[LN_BASEPOINT_IDX_DELAYED],
        pRemotePubKeys->per_commitment_point)) return false;

    //revocationkey = local per_commitment_point & remote revocation_basepoint
    //LOGD("remote: revocationkey\n");
    if (!ln_derkey_revocation_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_REVOCATION],
        pLocalPubKeys->keys[LN_BASEPOINT_IDX_REVOCATION],
        pRemotePubKeys->per_commitment_point)) return false;

    //local_htlckey = remote per_commitment_point & remote htlc_basepoint
    //LOGD("remote: local_htlckey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_LOCALHTLCKEY],
        pRemotePubKeys->keys[LN_BASEPOINT_IDX_HTLC],
        pRemotePubKeys->per_commitment_point)) return false;

    //remote_htlckey = remote per_commitment_point & local htlc_basepoint
    //LOGD("remote: remote_htlckey\n");
    if (!ln_derkey_pubkey(
        pRemoteScriptPubKeys->keys[LN_SCRIPT_IDX_REMOTEHTLCKEY],
        pLocalPubKeys->keys[LN_BASEPOINT_IDX_HTLC],
        pRemotePubKeys->per_commitment_point)) return false;

    return true;
}


/********************************************************************
 * private functions
 ********************************************************************/
