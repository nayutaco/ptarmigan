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
/** @file   ln_derkey_ex.h
 *  @brief  ln_derkey_ex
 */
#ifndef LN_DERKEY_EX_H__
#define LN_DERKEY_EX_H__

#include <stdint.h>
#include <stdbool.h>

#include <btc_keys.h>


/********************************************************************
 * macros
 ********************************************************************/

#define LN_SZ_SEED                      (32)        ///< (size) seed


#define LN_BASEPOINT_IDX_FUNDING        (0)         ///< commitment tx署名用
#define LN_BASEPOINT_IDX_REVOCATION     (1)         ///< revocation_basepoint
#define LN_BASEPOINT_IDX_PAYMENT        (2)         ///< payment_basepoint
#define LN_BASEPOINT_IDX_DELAYED        (3)         ///< delayed_payment_basepoint
#define LN_BASEPOINT_IDX_HTLC           (4)         ///< htlc_basepoint
#define LN_BASEPOINT_IDX_NUM            (LN_BASEPOINT_IDX_HTLC + 1)

///< per_commitment_point
///<   commitment_signed:               next_per_commitment_point
///<   funding_created/funding_signed:  first_per_commitment_point
///<   unilateral close:                per_commitment_point
///<   revoked transaction close:       per_commitment_point


#define LN_SCRIPT_IDX_PUBKEY            (0)         ///< pubkey
#define LN_SCRIPT_IDX_LOCAL_HTLCKEY     (1)         ///< local_htlckey
#define LN_SCRIPT_IDX_REMOTE_HTLCKEY    (2)         ///< remote_htlckey
#define LN_SCRIPT_IDX_DELAYEDKEY        (3)         ///< delayedkey
#define LN_SCRIPT_IDX_REVOCATIONKEY     (4)         ///< revocationkey
#define LN_SCRIPT_IDX_NUM               (LN_SCRIPT_IDX_REVOCATIONKEY + 1)


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    uint8_t     basepoints[LN_BASEPOINT_IDX_NUM][BTC_SZ_PUBKEY];
    uint8_t     per_commitment_point[BTC_SZ_PUBKEY];
    uint8_t     prev_per_commitment_point[BTC_SZ_PUBKEY];
} ln_derkey_pubkeys_t;


typedef struct {
    uint8_t     secrets[LN_BASEPOINT_IDX_NUM][BTC_SZ_PRIVKEY];
    uint64_t    _next_storage_index;
    uint8_t     _storage_seed[LN_SZ_SEED];
    uint8_t     per_commitment_secret[BTC_SZ_PRIVKEY];
} ln_derkey_local_privkeys_t;


typedef struct {
    uint8_t     keys[LN_SCRIPT_IDX_NUM][BTC_SZ_PUBKEY];
} ln_derkey_script_pubkeys_t;


/********************************************************************
 * prototypes
 ********************************************************************/

bool HIDDEN ln_derkey_local_privkeys_init(ln_derkey_local_privkeys_t *pPrivKeys, const uint8_t *pSeed);


void HIDDEN ln_derkey_local_privkeys_term(ln_derkey_local_privkeys_t *pPrivKeys);


uint64_t ln_derkey_local_privkeys_get_prev_storage_index(const ln_derkey_local_privkeys_t *pPrivKeys);


uint64_t ln_derkey_local_privkeys_get_current_storage_index(const ln_derkey_local_privkeys_t *pPrivKeys);


uint64_t ln_derkey_local_privkeys_get_next_storage_index(const ln_derkey_local_privkeys_t *pPrivKeys);


bool HIDDEN ln_derkey_update_scriptkeys(
    ln_derkey_script_pubkeys_t *pLocalScriptPubKeys,
    ln_derkey_pubkeys_t *pLocalPubKeys,
    ln_derkey_pubkeys_t *pRemotePubKeys);


bool HIDDEN ln_derkey_update_scriptkeys_2(
    ln_derkey_script_pubkeys_t *pLocalScriptPubKeys,
    ln_derkey_script_pubkeys_t *pRemoteScriptPubKeys,
    ln_derkey_pubkeys_t *pLocalPubKeys,
    ln_derkey_pubkeys_t *pRemotePubKeys);


#endif /* LN_DERKEY_EX_H__ */
