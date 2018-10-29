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
/** @file   ln_msg_establish.h
 *  @brief  [LN]Establish関連
 */
#ifndef LN_MSG_ESTABLISH_H__
#define LN_MSG_ESTABLISH_H__

#include <stdbool.h>

#include "utl_buf.h"

#include "ln.h"


/********************************************************************
 * prototypes
 ********************************************************************/

/** open_channel生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_open_channel_create(utl_buf_t *pBuf, const ln_open_channel_t *pMsg);


/** open_channel読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_open_channel_read(ln_open_channel_t *pMsg, const uint8_t *pData, uint16_t Len);


/** accept_channel生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_accept_channel_create(utl_buf_t *pBuf, const ln_accept_channel_t *pMsg);


/** accept_channel読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_accept_channel_read(ln_accept_channel_t *pMsg, const uint8_t *pData, uint16_t Len);


/** funding_created生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_created_create(utl_buf_t *pBuf, const ln_funding_created_t *pMsg);


/** funding_created読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_created_read(ln_funding_created_t *pMsg, const uint8_t *pData, uint16_t Len);


/** funding_signed生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_signed_create(utl_buf_t *pBuf, const ln_funding_signed_t *pMsg);


/** funding_signed読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_signed_read(ln_funding_signed_t *pMsg, const uint8_t *pData, uint16_t Len);


/** funding_locked生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_locked_create(utl_buf_t *pBuf, const ln_funding_locked_t *pMsg);


/** funding_locked読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_locked_read(ln_funding_locked_t *pMsg, const uint8_t *pData, uint16_t Len);


/** channel_reestablish生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_reestablish_create(utl_buf_t *pBuf, const ln_channel_reestablish_t *pMsg);


/** channel_reestablish読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_reestablish_read(ln_channel_reestablish_t *pMsg, const uint8_t *pData, uint16_t Len);

#endif /* LN_MSG_ESTABLISH_H__ */
