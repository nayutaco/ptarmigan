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
/** @file   utl_dbg.h
 *  @brief  utl_dbg
 *
 * @note
 *      - utl_dbg
 */
#ifndef UTL_DBG_H__
#define UTL_DBG_H__

#include <stdint.h>
#include <stdbool.h>

#include "utl_common.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * prototypes
 **************************************************************************/

#ifdef PTARM_DEBUG_MEM
void *utl_dbg_malloc(size_t Size, const char* pFname, int Line, const char *pFunc);
void *utl_dbg_realloc(void *pBuf, size_t Size, const char* pFname, int Line, const char *pFunc);
void *utl_dbg_calloc(size_t Block, size_t Size, const char* pFname, int Line, const char *pFunc);
char *utl_dbg_strdup(const char *pStr, const char* pFname, int Line, const char *pFunc);
void utl_dbg_free(void *pBuf, const char* pFname, int Line, const char *pFunc);

/** (デバッグ用)malloc残数取得
 * utlライブラリ内でmalloc()した回数からfree()した回数を返す。<br/>
 * PTARM_DEBUG_MEM 定義時のみ有効で、未定義の場合は常に-1を返す。
 *
 * @return  malloc残数
 */
int utl_dbg_malloc_cnt(void);
void utl_dbg_malloc_cnt_reset(void);


#define UTL_DBG_MALLOC(a)           utl_dbg_malloc(a, __FILE__, __LINE__, __func__);        ///< malloc(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#define UTL_DBG_REALLOC(a,b)        utl_dbg_realloc(a, b, __FILE__, __LINE__, __func__);    ///< realloc(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#define UTL_DBG_CALLOC(a,b)         utl_dbg_calloc(a, b, __FILE__, __LINE__, __func__);     ///< realloc(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#define UTL_DBG_STRDUP(a)           utl_dbg_strdup(a, __FILE__, __LINE__, __func__);        ///< strdup(カウント付き)(PTARM_DEBUG_MEM定義時のみ有効)
#define UTL_DBG_FREE(ptr)           { utl_dbg_free(ptr, __FILE__, __LINE__, __func__); ptr = NULL; }    ///< free(カウン>ト付き)(PTARM_DEBUG_MEM定義時のみ有効)
#else   //PTARM_DEBUG_MEM
#define UTL_DBG_MALLOC              malloc
#define UTL_DBG_REALLOC             realloc
#define UTL_DBG_CALLOC              calloc
#define UTL_DBG_STRDUP              strdup
#define UTL_DBG_FREE(ptr)           { free(ptr); ptr = NULL; }

#endif  //PTARM_DEBUG_MEM


#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
/** uint8[]の内容をFILE*出力
 *
 * @param[in]       fp          出力先
 * @param[in]       pData       対象データ
 * @param[in]       Len         pData長
 */
void utl_dbg_dump(FILE *fp, const uint8_t *pData, uint32_t Len, bool bLf);
#else
#define utl_dbg_dump(...)
#endif  //PTARM_USE_PRINTFUNC



#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* UTL_DBG_H__ */
