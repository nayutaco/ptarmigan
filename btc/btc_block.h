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
/** @file   btc_block.h
 *  @brief  btc_block
 */
#ifndef BTC_BLOCK_H__
#define BTC_BLOCK_H__

#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#include "btc.h"
#include "btc_crypto.h"
#include "btc_segwit_addr.h"


/**************************************************************************
 *typedefs
 **************************************************************************/

typedef struct btc_block_param_t {
    const char              *chain_name;
    btc_block_chain_t       chain;
    bool                    is_test;
    const uint8_t           genesis_hash[BTC_SZ_HASH256];
    const uint8_t           pref[BTC_PREF_MAX];
    uint8_t                 wif;
    const char              *segwit_hrp;
    ln_invoice_hrptype_t    invoice_hrp_type;
    uint16_t                rpcport;
#ifdef USE_ELEMENTS
    const uint8_t           asset[BTC_SZ_HASH256];
#endif
} btc_block_param_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** get chain
 *
 * @param[in]   pGenesisHash
 * @return      chain
 */
btc_block_chain_t btc_block_get_chain(const uint8_t *pGenesisHash);


/** get genesis hash
 *
 * @param[in]   chain
 * @return      genesis hash | NULL
 */
const uint8_t *btc_block_get_genesis_hash(btc_block_chain_t chain);


/** get block parameter from chain
 * 
 */
const btc_block_param_t *btc_block_get_param_from_chain(btc_block_chain_t chain);


/** get block parameter from chain_name
 * 
 */
const btc_block_param_t *btc_block_get_param_from_name(const char *pChainName);



/** get block parameter from hrp_type
 * 
 */
const btc_block_param_t *btc_block_get_param_from_hrptype(ln_invoice_hrptype_t hrp_type);


/** get block parameter from index
 * 
 */
const btc_block_param_t *btc_block_get_param_from_index(uint8_t Index);


/** get real chain name from common chain name
 * 
 *      "mainnet" ==> "main"
 *      "testnet" ==> "test"
 *      other     ==> same chain name
 */
const char *btc_block_get_real_chainname(const char *pChainName);

#endif /* BTC_BLOCK_H__ */
