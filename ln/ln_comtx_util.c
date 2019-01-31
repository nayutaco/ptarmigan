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
/** @file   ln_comtx_util.c
 *  @brief  ln_comtx_ex
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "mbedtls/sha256.h"
//#include "mbedtls/ripemd160.h"
//#include "mbedtls/ecp.h"

#include "btc_keys.h"

#include "ln_comtx_util.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SZ_OBSCURED_COMMIT_NUM            (6)


/**************************************************************************
 * prototypes
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

uint64_t HIDDEN ln_comtx_calc_obscured_commit_num_base(const uint8_t *pOpenPayBasePt, const uint8_t *pAcceptPayBasePt)
{
    uint64_t obs = 0;
    uint8_t base[32];
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pOpenPayBasePt, BTC_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pAcceptPayBasePt, BTC_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base);
    mbedtls_sha256_free(&ctx);

    for (int lp = 0; lp < M_SZ_OBSCURED_COMMIT_NUM; lp++) {
        obs <<= 8;
        obs |= base[sizeof(base) - M_SZ_OBSCURED_COMMIT_NUM + lp];
    }

    return obs;
}


uint64_t HIDDEN ln_comtx_calc_obscured_commit_num(uint64_t ObscuredCommitNumBase, uint64_t CommitNum)
{
    return ObscuredCommitNumBase ^ CommitNum;
}


/********************************************************************
 * private functions
 ********************************************************************/
