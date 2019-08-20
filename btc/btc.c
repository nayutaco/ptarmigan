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
/** @file   btc.c
 *  @brief  bitcoin offline API
 */
#include <unistd.h>

//#include "mbedtls/version.h"

#include "utl_common.h"

#include "btc_local.h"
#include "btc.h"
#include "btc_crypto.h"

#ifndef __ORDER_LITTLE_ENDIAN__
#error Only Little Endian
#endif


/**************************************************************************
 * macros
 **************************************************************************/


/**************************************************************************
 * package variables
 **************************************************************************/

uint8_t HIDDEN  mPref[BTC_PREF_MAX];        ///< prefix関連
bool HIDDEN     mNativeSegwit = true;       ///< true:segwitのトランザクションをnativeで生成


/**************************************************************************
 * private variables
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_init(btc_block_chain_t chain, bool bSegNative)
{
    bool ret = false;

    if (mPref[BTC_PREF_WIF]) {
        LOGE("multiple init\n");
        assert(0);
        return false;
    }

    mPref[BTC_PREF_CHAINDETAIL] = chain;
    switch (chain) {
    case BTC_BLOCK_CHAIN_BTCMAIN:
        LOGD("$$$[mainnet]\n");
        mPref[BTC_PREF_CHAIN] = (uint8_t)BTC_MAINNET;
        mPref[BTC_PREF_WIF] = 0x80;
        mPref[BTC_PREF_P2PKH] = 0x00;
        mPref[BTC_PREF_P2SH] = 0x05;
        mPref[BTC_PREF_ADDRVER] = 0x06;
        mPref[BTC_PREF_ADDRVER_SH] = 0x0a;
        ret = true;
        break;
    case BTC_BLOCK_CHAIN_BTCTEST:
    case BTC_BLOCK_CHAIN_BTCREGTEST:
        LOGD("$$$[testnet/regtest]\n");
        mPref[BTC_PREF_CHAIN] = (uint8_t)BTC_TESTNET;
        mPref[BTC_PREF_WIF] = 0xef;
        mPref[BTC_PREF_P2PKH] = 0x6f;
        mPref[BTC_PREF_P2SH] = 0xc4;
        mPref[BTC_PREF_ADDRVER] = 0x03;
        mPref[BTC_PREF_ADDRVER_SH] = 0x28;
        ret = true;
        break;
    default:
        LOGE("fail: unknown chain\n");
        assert(0);
        break;
    }

    mNativeSegwit = bSegNative;

    if (ret) {
        ret = btc_rng_init();
    }

//#ifdef PTARM_DEBUG
//    char mbedver[18];
//    mbedtls_version_get_string_full(mbedver); //XXX: mbed
//    LOGD("%s\n", mbedver);

//    //TODO: テスト用
//    if (!ret) {
//        abort();
//    }
//#endif  //PTARM_DEBUG

    return ret;
}


void btc_term(void)
{
    mPref[BTC_PREF_WIF] = BTC_UNKNOWN;
    btc_rng_free();
}


btc_chain_t btc_get_chain(void)
{
    return (btc_chain_t)mPref[BTC_PREF_CHAIN];
}
