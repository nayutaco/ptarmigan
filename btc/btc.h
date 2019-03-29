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

#define BTC_PREF_CHAIN          (0)             ///< Prefix: 1:mainnet, 2:testnet
#define BTC_PREF_WIF            (1)             ///< Prefix: WIF
#define BTC_PREF_P2PKH          (2)             ///< Prefix: P2PKH
#define BTC_PREF_P2SH           (3)             ///< Prefix: P2SH
#define BTC_PREF_ADDRVER        (4)             ///< Prefix: Address Version
#define BTC_PREF_ADDRVER_SH     (5)             ///< Prefix: Address Version(Script)
#define BTC_PREF_MAX            (6)             ///< 内部管理用
#define BTC_PREF_P2WPKH         (7)             ///< Prefix: Native Pay-to-Witness-Public-Key-Hash
#define BTC_PREF_P2WSH          (8)             ///< Prefix: Native Pay-to-Witness-Script-Hash
#define BTC_PREF_CHAINDETAIL    (9)             ///< mainnet/testnet/regtest

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


/**************************************************************************
 * typedefs
 **************************************************************************/

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
 * package variables
 **************************************************************************/

extern uint8_t  HIDDEN mPref[BTC_PREF_MAX];
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


/** blockchain種別取得
 *
 */
btc_chain_t btc_get_chain(void);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_H__ */
