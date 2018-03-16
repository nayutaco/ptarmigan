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
/** @file   ucoin.c
 *  @brief  bitcoinトランザクション計算
 *  @author ueno@nayuta.co
 */
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/version.h"

#include "ucoin_local.h"

#ifndef __ORDER_LITTLE_ENDIAN__
#error Only Little Endian
#endif


/**************************************************************************
 * macros
 **************************************************************************/

#define M_RNG_INIT      (const unsigned char *)"ucoin_personalization", 21


/**************************************************************************
 * package variables
 **************************************************************************/

uint8_t HIDDEN  mPref[UCOIN_PREF_MAX];      ///< prefix関連
bool HIDDEN     mNativeSegwit;              ///< true:segwitのトランザクションをnativeで生成

//この辺りはグローバル変数にしておくとマルチスレッドで危険かもしれない
#ifdef UCOIN_USE_RNG
mbedtls_ctr_drbg_context HIDDEN mRng;
#endif  //UCOIN_USE_RNG


/**************************************************************************
 * private variables
 **************************************************************************/

#ifdef UCOIN_USE_RNG
static mbedtls_entropy_context mEntropy;
#endif  //UCOIN_USE_RNG


/**************************************************************************
 * public functions
 **************************************************************************/

bool ucoin_init(ucoin_chain_t chain, bool bSegNative)
{
    bool ret = false;

    if (mPref[UCOIN_PREF_WIF]) {
        DBG_PRINTF("multiple init\n");
        assert(0);
        return false;
    }

    mPref[UCOIN_PREF] = (uint8_t)chain;
    switch (chain) {
    case UCOIN_TESTNET:
        //DBG_PRINTF("[testnet]\n");
        mPref[UCOIN_PREF_WIF] = 0xef;
        mPref[UCOIN_PREF_P2PKH] = 0x6f;
        mPref[UCOIN_PREF_P2SH] = 0xc4;
        mPref[UCOIN_PREF_ADDRVER] = 0x03;
        mPref[UCOIN_PREF_ADDRVER_SH] = 0x28;
        ret = true;
        break;
    case UCOIN_MAINNET:
        DBG_PRINTF("[mainnet]\n");
        mPref[UCOIN_PREF_WIF] = 0x80;
        mPref[UCOIN_PREF_P2PKH] = 0x00;
        mPref[UCOIN_PREF_P2SH] = 0x05;
        mPref[UCOIN_PREF_ADDRVER] = 0x06;
        mPref[UCOIN_PREF_ADDRVER_SH] = 0x0a;
        ret = true;
        break;
    default:
        DBG_PRINTF("unknown chain\n");
        assert(0);
    }

    mNativeSegwit = bSegNative;

#ifdef UCOIN_USE_RNG
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

//#ifdef UCOIN_DEBUG
//    char mbedver[18];
//    mbedtls_version_get_string_full(mbedver);
//    DBG_PRINTF("%s\n", mbedver);

//    //TODO: テスト用
//    if (!ret) {
//        abort();
//    }
//#endif  //UCOIN_DEBUG

    return ret;
}


void ucoin_term(void)
{
    mPref[UCOIN_PREF_WIF] = UCOIN_UNKNOWN;
    //DBG_PRINTF("\n");
}


ucoin_chain_t ucoin_get_chain(void)
{
    return (ucoin_chain_t)mPref[UCOIN_PREF];
}
