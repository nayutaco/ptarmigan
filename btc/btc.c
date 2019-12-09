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
#include "btc_block.h"

#ifndef __ORDER_LITTLE_ENDIAN__
#error Only Little Endian
#endif


/**************************************************************************
 * macros
 **************************************************************************/


/**************************************************************************
 * package variables
 **************************************************************************/

bool HIDDEN     mNativeSegwit = true;       ///< true:segwitのトランザクションをnativeで生成


/**************************************************************************
 * private variables
 **************************************************************************/

static bool mInitialized;
static btc_block_chain_t mChain;
static const btc_block_param_t *mCurrentChain;


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_init(btc_block_chain_t chain, bool bSegNative)
{
    bool ret = true;

    if (mInitialized) {
        LOGE("multiple init\n");
        assert(0);
        return false;
    }
    mCurrentChain = btc_block_get_param_from_chain(chain);
    if (mCurrentChain == NULL) {
        LOGE("unknown chain\n");
        assert(0);
        return false;
    }

    mChain = chain;
    mNativeSegwit = bSegNative;
    ret = btc_rng_init();

    if (ret) {
        mInitialized = true;
    }
    return ret;
}


void btc_term(void)
{
    btc_rng_free();
    mInitialized = false;
}


bool btc_is_initialized(void)
{
    return mInitialized;
}


const btc_block_param_t *btc_get_param(void)
{
    return mCurrentChain;
}
