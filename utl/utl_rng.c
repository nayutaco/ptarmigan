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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#ifndef PTARM_NO_USE_RNG
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#endif

#include "utl_rng.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_RNG_APP_SPECIFIC_DATA_STR     "ptarmigan@nayuta"


/**************************************************************************
 * private variables
 **************************************************************************/

#ifndef PTARM_NO_USE_RNG
static mbedtls_entropy_context  mEntropy;
static mbedtls_ctr_drbg_context mRng;
#endif


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_rng_init()
{
#ifndef PTARM_NO_USE_RNG
    mbedtls_entropy_init(&mEntropy);
    mbedtls_ctr_drbg_init(&mRng);

    //XXX: TODO: we not set the device-specific identifier yet
    if (mbedtls_ctr_drbg_seed(&mRng, mbedtls_entropy_func, &mEntropy,
        (const unsigned char *)M_RNG_APP_SPECIFIC_DATA_STR, strlen(M_RNG_APP_SPECIFIC_DATA_STR))) return false;

    mbedtls_ctr_drbg_set_prediction_resistance(&mRng, MBEDTLS_CTR_DRBG_PR_ON);
#endif
    return true;
}


bool utl_rng_rand(uint8_t *pData, uint16_t Len)
{
#ifndef PTARM_NO_USE_RNG
    if (mbedtls_ctr_drbg_random(&mRng, pData, Len)) return false;
#else
    for (uint16_t lp = 0; lp < Len; lp++) {
        pData[lp] = (uint8_t)(rand() % 256);
    }
#endif
    return true;
}

void utl_rng_free()
{
#ifndef PTARM_NO_USE_RNG
    mbedtls_entropy_free(&mEntropy);
    mbedtls_ctr_drbg_free(&mRng);
#endif
}
