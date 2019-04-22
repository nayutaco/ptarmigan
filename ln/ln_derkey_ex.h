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

#include "btc_keys.h"

#include "ln_derkey.h"


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
    //channel (priv)
    uint8_t     secrets[LN_BASEPOINT_IDX_NUM][BTC_SZ_PRIVKEY]; //save db
    uint8_t     storage_seed[LN_SZ_SEED]; //save db

    //channel (pub)
    uint8_t     basepoints[LN_BASEPOINT_IDX_NUM][BTC_SZ_PUBKEY];


    //commit_tx (priv)
    uint64_t    next_storage_index; //save db
    uint8_t     per_commitment_secret[BTC_SZ_PRIVKEY];


    //commit_tx (pub)
    uint8_t     per_commitment_point[BTC_SZ_PUBKEY];
    uint8_t     script_pubkeys[LN_SCRIPT_IDX_NUM][BTC_SZ_PUBKEY];
} ln_derkey_local_keys_t;


typedef struct {
    //channel (pub)
    uint8_t     basepoints[LN_BASEPOINT_IDX_NUM][BTC_SZ_PUBKEY]; //save db

    //channel & commit_tx (priv)
    uint64_t    next_storage_index; //save db
    ln_derkey_storage_t     storage; //save db

    //commit_tx (pub)
    uint8_t     per_commitment_point[BTC_SZ_PUBKEY]; //save db
    uint8_t     prev_per_commitment_point[BTC_SZ_PUBKEY]; //save db
    uint8_t     script_pubkeys[LN_SCRIPT_IDX_NUM][BTC_SZ_PUBKEY];
} ln_derkey_remote_keys_t;


/********************************************************************
 * prototypes
 ********************************************************************/

bool HIDDEN ln_derkey_init(ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys);


void HIDDEN ln_derkey_term(ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys);


bool HIDDEN ln_derkey_local_init(ln_derkey_local_keys_t *pKeys);


void HIDDEN ln_derkey_local_term(ln_derkey_local_keys_t *pKeys);


bool HIDDEN ln_derkey_local_priv2pub(ln_derkey_local_keys_t *pKeys);


bool HIDDEN ln_derkey_local_storage_update_per_commitment_point(ln_derkey_local_keys_t *pKeys);


bool HIDDEN ln_derkey_local_storage_update_per_commitment_point_force(ln_derkey_local_keys_t *pKeys, uint64_t Index);


void HIDDEN ln_derkey_local_storage_create_per_commitment_secret(const ln_derkey_local_keys_t *pKeys, uint8_t *pSecret, uint64_t Index);


/** 1つ前のper_commit_secret取得
 *
 * @param[in,out]   pChannel        チャネル情報
 * @param[out]      pSecret         1つ前のper_commitment_secret
 * @param[in,out]   pPerCommitPt    1つ前のper_commitment_point or NULL
 */
bool HIDDEN ln_derkey_local_storage_create_prev_per_commitment_secret(const ln_derkey_local_keys_t *pKeys, uint8_t *pSecret, uint8_t *pPerCommitPt);


//for resending `revoke_and_ack`
//  as we updated index at the first `revoke_and_ack`
bool HIDDEN ln_derkey_local_storage_create_second_prev_per_commitment_secret(const ln_derkey_local_keys_t *pKeys, uint8_t *pSecret, uint8_t *pPerCommitPt);


uint64_t ln_derkey_local_storage_get_prev_index(const ln_derkey_local_keys_t *pKeys);


uint64_t ln_derkey_local_storage_get_current_index(const ln_derkey_local_keys_t *pKeys);


uint64_t ln_derkey_local_storage_get_next_index(const ln_derkey_local_keys_t *pKeys);


void HIDDEN ln_derkey_remote_init(ln_derkey_remote_keys_t *pKeys);


void HIDDEN ln_derkey_remote_term(ln_derkey_remote_keys_t *pKeys);


void HIDDEN ln_derkey_remote_storage_init(ln_derkey_remote_keys_t *pKeys);


bool HIDDEN ln_derkey_remote_storage_insert_per_commitment_secret(
    ln_derkey_remote_keys_t *pKeys, const uint8_t *pSecret);


bool HIDDEN ln_derkey_remote_storage_get_secret(
    const ln_derkey_remote_keys_t *pKeys, uint8_t *pSecret, uint64_t Index);


uint64_t ln_derkey_remote_storage_get_current_index(const ln_derkey_remote_keys_t *pKeys);


uint64_t ln_derkey_remote_storage_get_next_index(const ln_derkey_remote_keys_t *pKeys);


bool HIDDEN ln_derkey_local_update_script_pubkeys(
    ln_derkey_local_keys_t *pLocalKeys, const ln_derkey_remote_keys_t *pRemoteKeys);


bool HIDDEN ln_derkey_remote_update_script_pubkeys(
    ln_derkey_remote_keys_t *pRemoteKeys, const ln_derkey_local_keys_t *pLocalKeys);


bool HIDDEN ln_derkey_update_script_pubkeys(
    ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys);


bool HIDDEN ln_derkey_local_restore(ln_derkey_local_keys_t *pKeys);


bool HIDDEN ln_derkey_remote_restore(ln_derkey_remote_keys_t *pKeys);


bool HIDDEN ln_derkey_restore(ln_derkey_local_keys_t *pLocalKeys, ln_derkey_remote_keys_t *pRemoteKeys);


#endif /* LN_DERKEY_EX_H__ */
