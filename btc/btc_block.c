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
/** @file   btc_block.c
 *  @brief  btc_block
 */
#include <sys/stat.h>
#include <sys/types.h>

#include "utl_dbg.h"

#include "btc_crypto.h"
#include "btc_local.h"
#include "btc_block.h"


/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * private variables
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

/**************************************************************************
 *const variables
 **************************************************************************/

// https://github.com/lightningnetwork/lightning-rfc/issues/237
// https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
static const uint8_t M_GENESIS_HASH_BTCMAIN[] = {
    // bitcoin mainnet
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_GENESIS_HASH_BTCTEST[] = {
    // bitcoin testnet
    0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
    0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
    0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
    0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_GENESIS_HASH_BTCREGTEST[] = {
    // bitcoin regtest
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
    0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
    0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
};


/**************************************************************************
 * public functions
 **************************************************************************/

btc_block_chain_t btc_block_get_chain(const uint8_t *pGenesisHash)
{
    if (memcmp(pGenesisHash, M_GENESIS_HASH_BTCMAIN, BTC_SZ_HASH256) == 0) {
        LOGD("  bitcoin mainnet\n");
        return BTC_BLOCK_CHAIN_BTCMAIN;
    } else if (memcmp(pGenesisHash, M_GENESIS_HASH_BTCTEST, BTC_SZ_HASH256) == 0) {
        LOGD("  bitcoin testnet\n");
        return BTC_BLOCK_CHAIN_BTCTEST;
    } else if (memcmp(pGenesisHash, M_GENESIS_HASH_BTCREGTEST, BTC_SZ_HASH256) == 0) {
        LOGD("  bitcoin regtest\n");
        return BTC_BLOCK_CHAIN_BTCREGTEST;
    }
    LOGD("  unknown genesis hash\n");
    return BTC_BLOCK_CHAIN_UNKNOWN;
}


const uint8_t *btc_block_get_genesis_hash(btc_block_chain_t chain)
{
    switch (chain) {
    case BTC_BLOCK_CHAIN_BTCMAIN:
        return M_GENESIS_HASH_BTCMAIN;
    case BTC_BLOCK_CHAIN_BTCTEST:
        return M_GENESIS_HASH_BTCTEST;
    case BTC_BLOCK_CHAIN_BTCREGTEST:
        return M_GENESIS_HASH_BTCREGTEST;
    default:
        LOGD("unknown chain: %02x\n", chain);
    }
    return NULL;
}


/**************************************************************************
 * package functions
 **************************************************************************/

/**************************************************************************
 * package functions
 **************************************************************************/

/**************************************************************************
 * private functions
 **************************************************************************/

