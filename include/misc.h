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
#ifndef MISC_H__
#define MISC_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

#include <syslog.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define SYSLOG_ERR(format, ...)  { DBG_PRINTF(format, ##__VA_ARGS__); DBG_PRINTF2("\n"); syslog(LOG_ERR, format, ##__VA_ARGS__); }
#define SYSLOG_WARN(format, ...) { DBG_PRINTF(format, ##__VA_ARGS__); DBG_PRINTF2("\n"); syslog(LOG_WARNING, format, ##__VA_ARGS__); }
#define SYSLOG_INFO(format, ...) { DBG_PRINTF(format, ##__VA_ARGS__); DBG_PRINTF2("\n"); syslog(LOG_INFO, format, ##__VA_ARGS__); }

#ifdef APP_DEBUG_MEM
#define APP_MALLOC(a)       misc_dbg_malloc(a); DBG_PRINTF("APP_MALLOC:%d\n", misc_dbg_malloc_cnt());          ///< malloc(カウント付き)(APP_DEBUG_MEM定義時のみ有効)
//#define APP_REALLOC         misc_dbg_realloc        ///< realloc(カウント付き)(APP_DEBUG_MEM定義時のみ有効)
//#define APP_CALLOC          misc_dbg_calloc         ///< realloc(カウント付き)(APP_DEBUG_MEM定義時のみ有効)
#define APP_FREE(ptr)       { misc_dbg_free(ptr); ptr = NULL; DBG_PRINTF("APP_FREE:%d\n", misc_dbg_malloc_cnt());}        ///< free(カウント付き)(APP_DEBUG_MEM定義時のみ有効)
#else   //APP_DEBUG_MEM
#define APP_MALLOC          malloc
//#define APP_REALLOC         realloc
//#define APP_CALLOC          calloc
#define APP_FREE            free
#endif  //APP_DEBUG_MEM


/**************************************************************************
 * prototypes
 **************************************************************************/

static inline void misc_msleep(unsigned long slp) {
    struct timespec req = { 0, (long)(slp * 1000000UL) };
    nanosleep(&req, NULL);
}

void misc_bin2str(char *pStr, const uint8_t *pBin, uint16_t BinLen);
void misc_bin2str_rev(char *pStr, const uint8_t *pBin, uint16_t BinLen);
bool misc_str2bin(uint8_t *pBin, uint16_t BinLen, const char *pStr);
bool misc_str2bin_rev(uint8_t *pBin, uint16_t BinLen, const char *pStr);

#ifdef APP_DEBUG_MEM
void *misc_dbg_malloc(size_t size);
//void *misc_dbg_realloc(void *ptr, size_t size);
//void *misc_dbg_calloc(size_t blk, size_t size);
void misc_dbg_free(void *ptr);
int misc_dbg_malloc_cnt(void);
#endif  //APP_DEBUG_MEM

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* MISC_H__ */
