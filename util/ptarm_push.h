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
/** @file   ptarm_push.h
 *  @brief  ptarm_push
 *  @author ueno@nayuta.co
 *
 * @note
 *      - ptarm_push
 *
 */
#ifndef PTARM_PUSH_H__
#define PTARM_PUSH_H__

#include <stdint.h>
#include <stdbool.h>

#include <ptarm_buf.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * types
 **************************************************************************/

/** @struct     ptarm_push_t
 *  @brief      PUSH管理構造体
 */
typedef struct {
    uint32_t        pos;            ///< 次書込み位置
    ptarm_buf_t     *data;          ///< 更新対象
} ptarm_push_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** ptarm_push_t初期化
 *
 * @param[out]  pPush       処理対象
 * @param[in]   pBuf        更新していくptarm_buf_t
 * @param[in]   Size        初期サイズ
 *
 * @note
 *      - データ追加時に初期サイズより領域が必要になれば拡張しているが、
 *          realloc()を繰り返すことになるので、必要なサイズ以上を確保した方が望ましい。
 *      - pDataは解放せず初期化して使用するため、必要なら先に解放すること。
 */
void ptarm_push_init(ptarm_push_t *pPush, ptarm_buf_t *pBuf, uint32_t Size);


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
void ptarm_push_data(ptarm_push_t *pPush, const void *pData, uint32_t Len);


/** スタックへの値追加(符号無し)
 *
 * 1～5バイトの範囲で値を追加する。<br/>
 * スタックの値は符号ありとして処理されるが、Valueは符号無しのみとする。
 *
 * @param[out]  pPush       処理対象
 * @param[in]   Value       追加データ(符号無し)
 *
 * @attention
 *      - 符号ありの値をキャストしても符号無しとして扱う。
 */
void ptarm_push_value(ptarm_push_t *pPush, uint64_t Value);


/** サイズ調整
 *
 * ptarm_buf_tのサイズをptarm_push_tで管理しているサイズにあわせる。
 *
 * @param[out]  pPush       処理対象
 */
void ptarm_push_trim(ptarm_push_t *pPush);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* PTARM_PUSH_H__ */
