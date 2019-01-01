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
/** @file   btc_block.h
 *  @brief  btc_block
 */
#ifndef BTC_BLOCK_H__
#define BTC_BLOCK_H__

#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>


/**************************************************************************
 * typedefs
 **************************************************************************/

//XXX:
/** @enum   btc_chain_t
 *  @brief  blockchain種別
 */
typedef enum {
    BTC_UNKNOWN,
    BTC_MAINNET,          ///< mainnet
    BTC_TESTNET           ///< testnet, regtest
} btc_chain_t;


/** @enum btc_block_chain_t */
typedef enum {
    BTC_BLOCK_CHAIN_UNKNOWN,            ///< unknown chain
    BTC_BLOCK_CHAIN_BTCMAIN,            ///< Bitcoin mainnet
    BTC_BLOCK_CHAIN_BTCTEST,            ///< Bitcoin testnet
    BTC_BLOCK_CHAIN_BTCREGTEST,         ///< Bitcoin regtest
} btc_block_chain_t;


/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * package variables
 **************************************************************************/

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


#endif /* BTC_BLOCK_H__ */
