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
/**
 * @file    utl_str.h
 * @brief   utl_str
 */
#ifndef UTL_STR_H__
#define UTL_STR_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


/**************************************************************************
 * types
 **************************************************************************/

/** @struct utl_str_t
 *  @brief  string buffer
 *
 */
typedef struct {
    char            *buf;       ///< buffer
} utl_str_t;

/**************************************************************************
 * prototypes
 **************************************************************************/

/** convert string to uint16_t
 *
 * @param[out]  n       uint16_t number
 * @param[in]   s       string
 * @retval      true    success
 */
bool utl_str_scan_u16(uint16_t *n, const char *s);


/** convert string to uint32_t
 *
 * @param[out]  n       uint32_t number
 * @param[in]   s       string
 * @retval      true    success
 */
bool utl_str_scan_u32(uint32_t *n, const char *s);


/** init #utl_str_t
 *
 * @param[in,out]   x   object
 */
void utl_str_init(utl_str_t *x);


/** append string
 *
 * @param[out]  x   object
 */
bool utl_str_append(utl_str_t *x, const char *s);


/** get string
 *
 * @param[in]   x   object
 */
const char *utl_str_get(utl_str_t *x);


/** free #utl_str_t
 *
 * @param[in]   x   object
 */
void utl_str_free(utl_str_t *x);


/** 16進数文字列から変換
 *
 * @param[out]      pBin        変換結果
 * @param[out]      BinLen      pBin長
 * @param[out]      pStr        元データ
 */
bool utl_str_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr);


/** 16進数文字列から変換(エンディアン反転)
 *
 * @param[out]      pBin        変換結果(エンディアン反転)
 * @param[out]      BinLen      pBin長
 * @param[out]      pStr        元データ
 */
bool utl_str_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr);


/** 16進数文字列に変換
 *
 * @param[out]      pStr        変換結果
 * @param[in]       pBin        元データ
 * @param[in]       BinLen      pBin長
 */
void utl_str_bin2str(char *pStr, const uint8_t *pBin, uint32_t BinLen);


/** 16進数文字列に変換(エンディアン反転)
 *
 * @param[out]      pStr        変換結果(エンディアン反転)
 * @param[in]       pBin        元データ
 * @param[in]       BinLen      pBin長
 */
void utl_str_bin2str_rev(char *pStr, const uint8_t *pBin, uint32_t BinLen);


/** value -> string in base 10
 *
 * @param[out]      pStr        string
 * @param[in]       pSize       size of the stirng
 * @param[in]       Value       value
 * @return      true        success
 *
 * @note
 *      - if Value==0, then return "0"
 */
bool utl_str_itoa(char *pStr, uint32_t Size, uint64_t Value);


/** copy null-terminated string to the buffer and fill zeros
 *
 * @param[out]      pDst        string
 * @param[in]       pSrc        null-terminated string
 * @param[in]       Size        size of the buffer
 * @return      true        success
 */
bool utl_str_copy_and_fill_zeros(char *pDst, const char *pSrc, uint32_t Size);


/** make null-terminated string from non-null-terminated string
 *
 * @param[out]      pBuf        buffer of the null-terminated string
 * @param[in]       pBufSize    size of the buffer
 * @param[in]       pData       non-null-terminated string data
 * @param[in]       pDataSize   size of the non-null-terminated string data
 * @return      true        success
 */
bool utl_str_copy_and_append_zero(char *pBuf, uint32_t BufSize, const uint8_t *pData, uint32_t DataSize);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_STR_H__ */
