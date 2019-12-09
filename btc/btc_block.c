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
/** @file   btc_block.c
 *  @brief  btc_block
 */
#include <sys/stat.h>
#include <sys/types.h>

#include "utl_dbg.h"

#include "btc_crypto.h"
#include "btc_local.h"
#include "btc_block.h"
#include "btc_segwit_addr.h"


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
 * const variables
 **************************************************************************/

static const btc_block_param_t BTC_BLOCK_PARAM[] = {
#if defined(USE_BITCOIN)
    {
        .chain_name = "mainnet",
        .chain = BTC_BLOCK_CHAIN_BTCMAIN,
        .is_test = false,
        .genesis_hash = {
            // bitcoin mainnet
            0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
            0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
            0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
            0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
        },
        .pref = {
            0x00,   //BTC_PREF_P2PKH
            0x05,   //BTC_PREF_P2SH
            0x06,   //BTC_PREF_ADDRVER
            0x0a,   //BTC_PREF_ADDRVER_SH
        },
        .wif = 0x80,
        .segwit_hrp = "bc",
        .invoice_hrp_type = LN_INVOICE_MAINNET,
        .rpcport = 8332,
    },
    {
        .chain_name = "testnet",
        .chain = BTC_BLOCK_CHAIN_BTCTEST,
        .is_test = true,
        .genesis_hash = {
            // bitcoin testnet
            0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
            0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
            0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
            0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
        },
        .pref = {
            0x6f,   //BTC_PREF_P2PKH
            0xc4,   //BTC_PREF_P2SH
            0x03,   //BTC_PREF_ADDRVER
            0x28,   //BTC_PREF_ADDRVER_SH
        },
        .wif = 0xef,
        .segwit_hrp = "tb",
        .invoice_hrp_type = LN_INVOICE_TESTNET,
        .rpcport = 18332,
    },
    {
        .chain_name = "regtest",
        .chain = BTC_BLOCK_CHAIN_BTCREGTEST,
        .is_test = true,
        .genesis_hash = {
            // bitcoin regtest
            0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
            0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
            0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
            0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
        },
        .pref = {
            0x6f,   //BTC_PREF_P2PKH
            0xc4,   //BTC_PREF_P2SH
            0x03,   //BTC_PREF_ADDRVER
            0x28,   //BTC_PREF_ADDRVER_SH
        },
        .wif = 0xef,
        .segwit_hrp = "bcrt",
        .invoice_hrp_type = LN_INVOICE_REGTEST,
        .rpcport = 18443,
    },
#elif defined(USE_ELEMENTS)
    {
        .chain_name = "liquidv1",
        .chain = BTC_BLOCK_CHAIN_LIQUIDV1,
        .is_test = false,
        .genesis_hash = {
            // liquidv1
            // $ e-cli getblockhash 0
            // 1466275836220db2944ca059a3a10ef6fd2ea684b0688d2c379296888a206003
            0x14, 0x66, 0x27, 0x58, 0x36, 0x22, 0x0d, 0xb2,
            0x94, 0x4c, 0xa0, 0x59, 0xa3, 0xa1, 0x0e, 0xf6,
            0xfd, 0x2e, 0xa6, 0x84, 0xb0, 0x68, 0x8d, 0x2c,
            0x37, 0x92, 0x96, 0x88, 0x8a, 0x20, 0x60, 0x03,
        },
        .pref = {
            0x39,   //BTC_PREF_P2PKH
            0x27,   //BTC_PREF_P2SH
            0x06,   //BTC_PREF_ADDRVER
            0x0a,   //BTC_PREF_ADDRVER_SH
        },
        .wif = 0x80,
        .segwit_hrp = "ex",
        .invoice_hrp_type = LN_INVOICE_LIQUID,
        .rpcport = 7041,

        // Elements
        .asset = {
            // liquidv1 - "bitcoin" asset
            // $ e-cli dumpassetlabels
            // {
            //   "bitcoin": "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d"
            // }
            0x6d, 0x52, 0x1c, 0x38, 0xec, 0x1e, 0xa1, 0x57,
            0x34, 0xae, 0x22, 0xb7, 0xc4, 0x60, 0x64, 0x41,
            0x28, 0x29, 0xc0, 0xd0, 0x57, 0x9f, 0x0a, 0x71,
            0x3d, 0x1c, 0x04, 0xed, 0xe9, 0x79, 0x02, 0x6f,
        },
    },
    {
        .chain_name = "liquidregtest",
        .chain = BTC_BLOCK_CHAIN_LIQREGTEST,
        .is_test = true,
        .genesis_hash = {
            // liquidregtest
            // $ e-cli getblockhash 0
            // 4b63ad88eba362859d016d6e8f74a93403283f79e2e7694ef55b9c7367feed33
            0x4b, 0x63, 0xad, 0x88, 0xeb, 0xa3, 0x62, 0x85,
            0x9d, 0x01, 0x6d, 0x6e, 0x8f, 0x74, 0xa9, 0x34,
            0x03, 0x28, 0x3f, 0x79, 0xe2, 0xe7, 0x69, 0x4e,
            0xf5, 0x5b, 0x9c, 0x73, 0x67, 0xfe, 0xed, 0x33,
        },
        .pref = {
            0xeb,   //BTC_PREF_P2PKH
            0x4b,   //BTC_PREF_P2SH
            0x03,   //BTC_PREF_ADDRVER
            0x28,   //BTC_PREF_ADDRVER_SH
        },
        .wif = 0xef,
        .segwit_hrp = "ert",
        .invoice_hrp_type = LN_INVOICE_ELEMENTS,
        .rpcport = 18443,

        // Elements
        .asset = {
            // liquidregtest - "bitcoin" asset
            // $ e-cli dumpassetlabels
            // {
            // "bitcoin": "e92abec3915196b0858900ddc754107326fc597dfdf8975412d4d5e290e92057"
            // }
            0x57, 0x20, 0xe9, 0x90, 0xe2, 0xd5, 0xd4, 0x12,
            0x54, 0x97, 0xf8, 0xfd, 0x7d, 0x59, 0xfc, 0x26,
            0x73, 0x10, 0x54, 0xc7, 0xdd, 0x00, 0x89, 0x85,
            0xb0, 0x96, 0x51, 0x91, 0xc3, 0xbe, 0x2a, 0xe9,
        },
    },
    {
        .chain_name = "testchain1",
        .chain = BTC_BLOCK_CHAIN_TESTCHAIN1,
        .is_test = true,
        .genesis_hash = { //same endian
            0x6e, 0xef, 0xff, 0x2d, 0xca, 0xd9, 0x69, 0x2a,
            0xd6, 0x3a, 0xb9, 0x6c, 0x79, 0xcc, 0xb5, 0xc6,
            0x7d, 0x6a, 0x07, 0x3a, 0xd2, 0xca, 0x18, 0x5d,
            0x3f, 0x0a, 0x93, 0x33, 0xcd, 0xb8, 0xa6, 0x09,
        },
        .pref = {
            0xeb,   //BTC_PREF_P2PKH
            0x4b,   //BTC_PREF_P2SH
            0x03,   //BTC_PREF_ADDRVER
            0x28,   //BTC_PREF_ADDRVER_SH
        },
        .wif = 0xef,
        .segwit_hrp = "ert",
        .invoice_hrp_type = LN_INVOICE_ELEMENTS,
        .rpcport = 18443,

        // Elements
        .asset = { //reversed endian
            0xb5, 0xfd, 0xef, 0xed, 0x78, 0xc7, 0xc0, 0x07,
            0x0d, 0x8e, 0xee, 0x87, 0x78, 0x05, 0x2d, 0x70,
            0x9b, 0x56, 0x27, 0x34, 0xa9, 0x6d, 0xf0, 0x71,
            0x25, 0x9e, 0x98, 0x0f, 0x0c, 0x3d, 0xfd, 0xb4,
        },
    },
#endif
};


/**************************************************************************
 * public functions
 **************************************************************************/

btc_block_chain_t btc_block_get_chain(const uint8_t *pGenesisHash)
{
    for (size_t lp = 0; lp < ARRAY_SIZE(BTC_BLOCK_PARAM); lp++) {
        if (memcmp(pGenesisHash, BTC_BLOCK_PARAM[lp].genesis_hash, BTC_SZ_HASH256) == 0) {
            LOGD("  %s\n", BTC_BLOCK_PARAM[lp].chain_name);
            return BTC_BLOCK_PARAM[lp].chain;
        }
    }
    LOGE("  unknown genesis hash: ");
    DUMPD(pGenesisHash, BTC_SZ_HASH256);
    return BTC_BLOCK_CHAIN_UNKNOWN;
}


const uint8_t *btc_block_get_genesis_hash(btc_block_chain_t chain)
{
    for (size_t lp = 0; lp < ARRAY_SIZE(BTC_BLOCK_PARAM); lp++) {
        if (chain == BTC_BLOCK_PARAM[lp].chain) {
            LOGD("  %s\n", BTC_BLOCK_PARAM[lp].chain_name);
            return BTC_BLOCK_PARAM[lp].genesis_hash;
        }
    }
    LOGE("unknown chain: %02x\n", chain);
    return NULL;
}


const btc_block_param_t *btc_block_get_param_from_chain(btc_block_chain_t chain)
{
    for (size_t lp = 0; lp < ARRAY_SIZE(BTC_BLOCK_PARAM); lp++) {
        if (chain == BTC_BLOCK_PARAM[lp].chain) {
            LOGD("  %s\n", BTC_BLOCK_PARAM[lp].chain_name);
            return &BTC_BLOCK_PARAM[lp];
        }
    }
    LOGE("unknown chain: %02x\n", chain);
    return NULL;
}


const btc_block_param_t *btc_block_get_param_from_name(const char *pChainName)
{
    for (size_t lp = 0; lp < ARRAY_SIZE(BTC_BLOCK_PARAM); lp++) {
        if (strcmp(pChainName, BTC_BLOCK_PARAM[lp].chain_name) == 0) {
            LOGD("  %s\n", BTC_BLOCK_PARAM[lp].chain_name);
            return &BTC_BLOCK_PARAM[lp];
        }
    }
    LOGE("unknown chain: %s\n", pChainName);
    return NULL;
}


const btc_block_param_t *btc_block_get_param_from_hrptype(ln_invoice_hrptype_t hrp_type)
{
    for (size_t lp = 0; lp < ARRAY_SIZE(BTC_BLOCK_PARAM); lp++) {
        if (hrp_type == BTC_BLOCK_PARAM[lp].invoice_hrp_type) {
            LOGD("  %s\n", BTC_BLOCK_PARAM[lp].chain_name);
            return &BTC_BLOCK_PARAM[lp];
        }
    }
    LOGE("unknown hrp type: %d\n", hrp_type);
    return NULL;
}


const btc_block_param_t *btc_block_get_param_from_index(uint8_t Index)
{
    if (Index >= ARRAY_SIZE(BTC_BLOCK_PARAM)) {
        return NULL;
    }
    return &BTC_BLOCK_PARAM[Index];
}


const char *btc_block_get_real_chainname(const char *pChainName)
{
    if (strcmp(pChainName, "mainnet") == 0) {
        return "main";
    } else if (strcmp(pChainName, "testnet") == 0) {
        return "test";
    } else {
        return pChainName;
    }
}


/**************************************************************************
 * package functions
 **************************************************************************/

/**************************************************************************
 * private functions
 **************************************************************************/

