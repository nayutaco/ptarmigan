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
 * @file    utl_misc.h
 * @brief   utl_miscellaneous
 */
#ifndef UTL_MISC_H__
#define UTL_MISC_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define UTL_SZ_DTSTR          (19)            ///< サイズ:utl_misc_strftime()  // 2018/06/12 09:36:36


/**************************************************************************
 * prototypes
 **************************************************************************/

/** sleep millisecond
 *
 * @param[in]   slp     スリープする時間[msec]
 */
static inline void utl_misc_msleep(unsigned long slp) {
    struct timespec req = { 0, (long)(slp * 1000000UL) };
    nanosleep(&req, NULL);
}

/** 16進数文字列から変換
 *
 * @param[out]      pBin        変換結果
 * @param[out]      BinLen      pBin長
 * @param[out]      pStr        元データ
 */
bool utl_misc_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr);


/** 16進数文字列から変換(エンディアン反転)
 *
 * @param[out]      pBin        変換結果(エンディアン反転)
 * @param[out]      BinLen      pBin長
 * @param[out]      pStr        元データ
 */
bool utl_misc_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr);


/** 現在日時取得
 *
 * @param[out]      pDateTime       現在日時
 * @param[in]       Len             pDataTimeバッファサイズ
 */
void utl_misc_datetime(char *pDateTime, size_t Len);


/** 全データが0x00かのチェック
 *
 * @param[in]       pData               チェック対象
 * @param[in]       Len                 pData長
 * @retval  true    全データが0x00
 */
bool utl_misc_all_zero(const void *pData, size_t Len);


/** 16進数文字列に変換
 *
 * @param[out]      pStr        変換結果
 * @param[in]       pBin        元データ
 * @param[in]       BinLen      pBin長
 */
void utl_misc_bin2str(char *pStr, const uint8_t *pBin, uint32_t BinLen);


/** 16進数文字列に変換(エンディアン反転)
 *
 * @param[out]      pStr        変換結果(エンディアン反転)
 * @param[in]       pBin        元データ
 * @param[in]       BinLen      pBin長
 */
void utl_misc_bin2str_rev(char *pStr, const uint8_t *pBin, uint32_t BinLen);


/** 日時文字列
 *
 */
void utl_misc_strftime(char *pTmStr, uint32_t Tm);


/** convert uint8_t[] --> uint16_t
 * 
 * @param[in]   pData       big endian
 * @return  uint16_t
 */
uint16_t utl_misc_be16(const uint8_t *pData);


/** convert uint8_t[] --> uint32_t
 * 
 * @param[in]   pData       big endian
 * @return  uint32_t
 */
uint32_t utl_misc_be32(const uint8_t *pData);


/** convert uint8_t[] --> uint64_t
 * 
 * @param[in]   pData       big endian
 * @return  uint64_t
 */
uint64_t utl_misc_be64(const uint8_t *pData);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_MISC_H__ */
