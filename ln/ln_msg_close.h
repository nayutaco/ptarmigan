/*
 *  Copyright (C) 2017 Ptarmigan Project
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
/** @file   ln_msg_close.h
 *  @brief  [LN]Close関連
 */
#ifndef LN_MSG_CLOSE_H__
#define LN_MSG_CLOSE_H__

#include <stdbool.h>

#include "utl_buf.h"
#include "utl_common.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct ln_msg_shutdown_t
 *  @brief  shutdown
 */
typedef struct {
    //type: 38 (shutdown)
    //data:
    //  [32:channel_id]
    //  [2:len]
    //  [len:scriptpubkey]

    const uint8_t   *p_channel_id;
    uint16_t        len;
    const uint8_t   *p_scriptpubkey;
} ln_msg_shutdown_t;


/** @struct ln_msg_closing_signed_t
 *  @brief  closing_signed
 */
typedef struct {
    //type: 39 (closing_signed)
    //data:
    //  [32:channel_id]
    //  [8:fee_satoshis]
    //  [64:signature]

    const uint8_t   *p_channel_id;
    uint64_t        fee_satoshis;
    const uint8_t   *p_signature;
} ln_msg_closing_signed_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** shutdown生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_shutdown_write(utl_buf_t *pBuf, const ln_msg_shutdown_t *pMsg);


/** shutdown読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_shutdown_read(ln_msg_shutdown_t *pMsg, const uint8_t *pData, uint16_t Len);


/** closing_signed生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_closing_signed_write(utl_buf_t *pBuf, const ln_msg_closing_signed_t *pMsg);


/** closing_signed読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_closing_signed_read(ln_msg_closing_signed_t *pMsg, const uint8_t *pData, uint16_t Len);

#endif /* LN_MSG_CLOSE_H__ */
