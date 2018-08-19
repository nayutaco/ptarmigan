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
/** @file   btc.c
 *  @brief  bitcoinトランザクション計算
 *  @author ueno@nayuta.co
 */
#include <unistd.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/version.h"

#include "btc_local.h"

#ifndef __ORDER_LITTLE_ENDIAN__
#error Only Little Endian
#endif


/**************************************************************************
 * macros
 **************************************************************************/

#define M_RNG_INIT      (const unsigned char *)"btc_personalization", 19


/**************************************************************************
 * package variables
 **************************************************************************/

uint8_t HIDDEN  mPref[BTC_PREF_MAX];      ///< prefix関連
bool HIDDEN     mNativeSegwit;              ///< true:segwitのトランザクションをnativeで生成

//この辺りはグローバル変数にしておくとマルチスレッドで危険かもしれない
#ifdef PTARM_USE_RNG
mbedtls_ctr_drbg_context HIDDEN mRng;
#endif  //PTARM_USE_RNG


/**************************************************************************
 * private variables
 **************************************************************************/

#ifdef PTARM_USE_RNG
static mbedtls_entropy_context mEntropy;
#endif  //PTARM_USE_RNG


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_init(btc_chain_t chain, bool bSegNative)
{
    bool ret = false;

    if (mPref[BTC_PREF_WIF]) {
        LOGD("multiple init\n");
        assert(0);
        return false;
    }

    mPref[BTC_PREF] = (uint8_t)chain;
    switch (chain) {
    case BTC_TESTNET:
        //LOGD("[testnet]\n");
        mPref[BTC_PREF_WIF] = 0xef;
        mPref[BTC_PREF_P2PKH] = 0x6f;
        mPref[BTC_PREF_P2SH] = 0xc4;
        mPref[BTC_PREF_ADDRVER] = 0x03;
        mPref[BTC_PREF_ADDRVER_SH] = 0x28;
        ret = true;
        break;
    case BTC_MAINNET:
        LOGD("[mainnet]\n");
        mPref[BTC_PREF_WIF] = 0x80;
        mPref[BTC_PREF_P2PKH] = 0x00;
        mPref[BTC_PREF_P2SH] = 0x05;
        mPref[BTC_PREF_ADDRVER] = 0x06;
        mPref[BTC_PREF_ADDRVER_SH] = 0x0a;
        ret = true;
        break;
    default:
        LOGD("unknown chain\n");
        assert(0);
    }

    mNativeSegwit = bSegNative;

#ifdef PTARM_USE_RNG
    if (ret) {
        mbedtls_entropy_init(&mEntropy);
        mbedtls_ctr_drbg_init(&mRng);
        int retval = mbedtls_ctr_drbg_seed(&mRng , mbedtls_entropy_func, &mEntropy, M_RNG_INIT);
        if (retval == 0) {
            mbedtls_ctr_drbg_set_prediction_resistance(&mRng, MBEDTLS_CTR_DRBG_PR_ON);
        } else {
            ret = false;
        }
    }
#endif

//#ifdef PTARM_DEBUG
//    char mbedver[18];
//    mbedtls_version_get_string_full(mbedver);
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
}


btc_chain_t btc_get_chain(void)
{
    return (btc_chain_t)mPref[BTC_PREF];
}
