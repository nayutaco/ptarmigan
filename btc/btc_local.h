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
/** @file   btc_local.h
 *  @brief  libbtc内インターフェース
 *  @author ueno@nayuta.co
 */
#ifndef BTC_LOCAL_H__
#define BTC_LOCAL_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef PTARM_USE_RNG
#include "mbedtls/ctr_drbg.h"
#endif  //PTARM_USE_RNG

#include "btc.h"
#define LOG_TAG "BTC"
#include "utl_log.h"


/**************************************************************************
 * macros
 **************************************************************************/


/**************************************************************************
 * macro functions
 **************************************************************************/


/**************************************************************************
 * package variables
 **************************************************************************/

extern uint8_t  mPref[BTC_PREF_MAX];
extern bool     mNativeSegwit;
#ifdef PTARM_USE_RNG
extern mbedtls_ctr_drbg_context mRng;
#endif  //PTARM_USE_RNG


/**************************************************************************
 * prototypes
 **************************************************************************/


#endif /* BTC_LOCAL_H__ */
