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
/** @file   btc.h
 *  @brief  bitcoin offline API header
 */
#ifndef BTC_H__
#define BTC_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "utl_common.h"
#include "utl_buf.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

// btc_block_param_t.pref[BTC_PREF_MAX]
#define BTC_PREF_P2PKH          (0)             ///< Prefix: P2PKH
#define BTC_PREF_P2SH           (1)             ///< Prefix: P2SH
#define BTC_PREF_ADDRVER        (2)             ///< Prefix: Address Version
#define BTC_PREF_ADDRVER_SH     (3)             ///< Prefix: Address Version(Script)
#define BTC_PREF_MAX            (4)             ///< pref[] size

#define BTC_PREF_P2WPKH         (4)             ///< Prefix: Native Pay-to-Witness-Public-Key-Hash
#define BTC_PREF_P2WSH          (5)             ///< Prefix: Native Pay-to-Witness-Script-Hash

#define BTC_DUST_LIMIT          ((uint64_t)546) ///< voutに指定できるamountの下限[satoshis]
                                                // 2018/02/11 17:54(JST)
                                                // https://github.com/bitcoin/bitcoin/blob/fe53d5f3636aed064823bc220d828c7ff08d1d52/src/test/transaction_tests.cpp#L695
                                                //
                                                // https://github.com/bitcoin/bitcoin/blob/5961b23898ee7c0af2626c46d5d70e80136578d3/src/policy/policy.cpp#L52-L55


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    BTC_MBTC2SATOSHI
 *  @brief  mBTCをsatochi変換
 */
#define BTC_MBTC2SATOSHI(mbtc)      ((uint64_t)((mbtc) * 100000 + 0.5))


/** @def    BTC_BTC2SATOSHI
 *  @brief  BTCをsatochi変換
 */
#define BTC_BTC2SATOSHI(btc)        ((uint64_t)((btc) * (uint64_t)100000000 + 0.5))


/** @def    BTC_SATOSHI2MBTC
 *  @brief  satoshiをmBTC変換
 */
#define BTC_SATOSHI2MBTC(stc)       ((double)(stc) / 100000)


/** @def    BTC_SATOSHI2BTC
 *  @brief  satoshiをBTC変換
 */
#define BTC_SATOSHI2BTC(stc)        ((double)(stc) / (double)100000000)


/** @def    BTC_IS_DUST
 *  @brief  amountが支払いに使用できないDUSTかどうかチェックする(true:支払えない)
 */
#define BTC_IS_DUST(amount)         (BTC_DUST_LIMIT > (amount))


#if defined(USE_BITCOIN)
#define BTC_UNIT    "BTC"
#elif defined(USE_ELEMENTS)
#define BTC_UNIT    "ELE"
#endif


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @enum btc_block_chain_t */
typedef enum {
    BTC_BLOCK_CHAIN_UNKNOWN,            ///< unknown chain
    BTC_BLOCK_CHAIN_BTCMAIN,            ///< Bitcoin mainnet
    BTC_BLOCK_CHAIN_BTCTEST,            ///< Bitcoin testnet
    BTC_BLOCK_CHAIN_BTCREGTEST,         ///< Bitcoin regtest
    BTC_BLOCK_CHAIN_LIQUIDV1,           ///< liquidv1
    BTC_BLOCK_CHAIN_LIQREGTEST,         ///< liquidregtest
    BTC_BLOCK_CHAIN_TESTCHAIN1,         ///< testchain1
} btc_block_chain_t;


typedef struct btc_block_param_t btc_block_param_t;


/**************************************************************************
 * package variables
 **************************************************************************/

extern bool     HIDDEN mNativeSegwit;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 初期化
 *
 * @param[in]       chain           BTC_BLOCK_CHAIN_BTCMAIN/BTCTEST/BTCREGTEST
 * @param[in]       bSegNative      true:segwit native transaction
 */
bool btc_init(btc_block_chain_t net, bool bSegNative);


/** 終了
 *
 *
 */
void btc_term(void);


/** btc is initialized
 * 
 * @retval  true    initialized
 */
bool btc_is_initialized(void);


/** get current block parameter
 * 
 */
const btc_block_param_t *btc_get_param(void);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_H__ */
