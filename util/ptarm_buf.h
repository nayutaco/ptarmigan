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
/** @file   ptarm_buf.h
 *  @brief  ptarm_buf
 *  @author ueno@nayuta.co
 *
 * @note
 *      - ptarm_buf
 */
#ifndef PTARM_BUF_H__
#define PTARM_BUF_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define PTARM_BUF_INIT          { (uint8_t *)NULL, (uint32_t)0 }


/**************************************************************************
 * types
 **************************************************************************/

/** @struct ptarm_buf_t
 *  @brief  バッファ管理構造体
 *
 */
typedef struct {
    uint8_t         *buf;       ///< バッファ(malloc前提)
    uint32_t        len;        ///< bufサイズ
} ptarm_buf_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** #ptarm_buf_t 初期化
 *
 * @param[in,out]   pBuf    処理対象
 */
void ptarm_buf_init(ptarm_buf_t *pBuf);


/** #ptarm_buf_t のメモリ解放
 *
 * @param[in,out]   pBuf    処理対象
 */
void ptarm_buf_free(ptarm_buf_t *pBuf);


/** #ptarm_buf_t へのメモリ確保
 *
 * @param[out]      pBuf        処理対象
 * @param[in]       Size        確保するメモリサイズ
 *
 * @note
 *      - #ptarm_buf_init()の代わりに使用できるが、元の領域は解放しない
 */
void ptarm_buf_alloc(ptarm_buf_t *pBuf, uint32_t Size);


/** #ptarm_buf_t へのメモリ再確保
 *
 * @param[out]      pBuf        処理対象
 * @param[in]       Size        確保するメモリサイズ
 */
void ptarm_buf_realloc(ptarm_buf_t *pBuf, uint32_t Size);


/** #ptarm_buf_t へのメモリ確保及びデータコピー
 *
 * @param[out]      pBuf        処理対象
 * @param[in]       pData       対象データ
 * @param[in]       Len         pData長
 *
 * @note
 *      - #ptarm_buf_init()の代わりに使用できるが、元の領域は解放しない
 */
void ptarm_buf_alloccopy(ptarm_buf_t *pBuf, const uint8_t *pData, uint32_t Len);


/** #ptarm_buf_t の比較
 *
 * @param[in]       pBuf1       比較対象1
 * @param[in]       pBuf2       比較対象2
 * @retval      true        一致
 */
bool ptarm_buf_cmp(const ptarm_buf_t *pBuf1, const ptarm_buf_t *pBuf2);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* PTARM_BUF_H__ */
