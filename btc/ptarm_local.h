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
/** @file   ptarm_local.h
 *  @brief  libbtc内インターフェース
 *  @author ueno@nayuta.co
 */
#ifndef PTARM_LOCAL_H__
#define PTARM_LOCAL_H__

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

#include "ptarm.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define HIDDEN __attribute__((visibility("hidden")))
#define CONST_CAST      /* const外しキャストを検索しやすくするため */


/**************************************************************************
 * macro functions
 **************************************************************************/

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))  ///< 配列要素数

#ifdef PTARM_DEBUG
#include "utl_log.h"
#define LOG_TAG "BTC"

#define LOGV(...)       utl_log_write(UTL_LOG_PRI_VERBOSE, __FILE__, __LINE__, 1, LOG_TAG, __func__, __VA_ARGS__)
#define DUMPV(dt,ln)    utl_log_dump(UTL_LOG_PRI_VERBOSE, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, ln)
#define TXIDV(dt)       utl_log_dump_rev(UTL_LOG_PRI_VERBOSE, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, PTARM_SZ_TXID)

#define LOGD(...)       utl_log_write(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 1, LOG_TAG, __func__, __VA_ARGS__)
#define LOGD2(...)      utl_log_write(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 0, LOG_TAG, __func__, __VA_ARGS__)
#define DUMPD(dt,ln)    utl_log_dump(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, ln)
#define TXIDD(dt)       utl_log_dump_rev(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, PTARM_SZ_TXID)

#else //PTARM_DEBUG
#define LOGV(...)       //none
#define DUMPV(...)      //none
#define TXIDV(...)      //none

#define LOGD(...)       //none
#define LOGD2(...)      //none
#define DUMPD(...)      //none
#define TXIDD(...)      //none
#endif //PTARM_DEBUG


#ifdef PTARM_DEBUG_MEM
#define M_MALLOC(a)         utl_dbg_malloc(a); LOGD("M_MALLOC:%d\n", utl_dbg_malloc_cnt());       ///< malloc(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#define M_REALLOC(a,b)      utl_dbg_realloc(a,b); LOGD("M_REALLOC:%d\n", utl_dbg_malloc_cnt());   ///< realloc(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#define M_CALLOC(a,b)       utl_dbg_calloc(a,b); LOGD("M_CALLOC:%d\n", utl_dbg_malloc_cnt());       ///< realloc(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#define M_FREE(ptr)         { utl_dbg_free(ptr); ptr = NULL; LOGD("M_FREE:%d\n", utl_dbg_malloc_cnt()); }     ///< free(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#else   //PTARM_DEBUG_MEM
#define M_MALLOC            malloc
#define M_REALLOC           realloc
#define M_CALLOC            calloc
#define M_FREE(ptr)         { free(ptr); ptr = NULL; }
#endif  //PTARM_DEBUG_MEM


/**************************************************************************
 * package variables
 **************************************************************************/

extern uint8_t  mPref[PTARM_PREF_MAX];
extern bool     mNativeSegwit;
#ifdef PTARM_USE_RNG
extern mbedtls_ctr_drbg_context mRng;
#endif  //PTARM_USE_RNG


/**************************************************************************
 * prototypes
 **************************************************************************/


#endif /* PTARM_LOCAL_H__ */
