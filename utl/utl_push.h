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
/** @file   utl_push.h
 *  @brief  utl_push
 *
 * @note
 *      - utl_push
 *
 */
#ifndef UTL_PUSH_H__
#define UTL_PUSH_H__

#include <stdint.h>
#include <stdbool.h>

#include <utl_buf.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * types
 **************************************************************************/

/** @struct     utl_push_t
 *  @brief      PUSH管理構造体
 */
typedef struct {
    uint32_t        pos;            ///< 次書込み位置
    utl_buf_t       *data;          ///< 更新対象
} utl_push_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** utl_push_t初期化
 *
 * @param[out]  pPush       処理対象
 * @param[in]   pBuf        更新していくutl_buf_t
 * @param[in]   Size        初期サイズ
 *
 * @note
 *      - データ追加時に初期サイズより領域が必要になれば拡張しているが、
 *          realloc()を繰り返すことになるので、必要なサイズ以上を確保した方が望ましい。
 *      - pDataは解放せず初期化して使用するため、必要なら先に解放すること。
 */
void utl_push_init(utl_push_t *pPush, utl_buf_t *pBuf, uint32_t Size);


/** データ追加
 *
 * @param[out]  pPush       処理対象
 * @param[in]   pData       追加データ
 * @param[in]   Len         pData長
 *
 * @note
 *      - 初期化時のサイズからあふれる場合、realloc()して拡張する。
 *      - そのまま追加するため、OP_PUSHDATAxなどは呼び出し元で行うこと。
 */
void utl_push_data(utl_push_t *pPush, const void *pData, uint32_t Len);


/** Push unsigned integer to the stack
 *
 * As a result `Value` will be 2-6 bytes on the stack.<br>
 * Integers on the stack are interpreted as a signed.<br>
 * However, only unsigned integers (0-549755813887) can be pushed by this function.
 *
 * @param[out]  pPush       処理対象
 * @param[in]   Value       追加データ(0-549755813887)
 * @retval      true    success
 */
bool utl_push_value(utl_push_t *pPush, uint64_t Value);


/** サイズ調整
 *
 * utl_buf_tのサイズをutl_push_tで管理しているサイズにあわせる。
 *
 * @param[out]  pPush       処理対象
 */
void utl_push_trim(utl_push_t *pPush);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* UTL_PUSH_H__ */
