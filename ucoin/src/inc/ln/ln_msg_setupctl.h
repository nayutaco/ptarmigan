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
/** @file   ln_msg_setupctl.h
 *  @brief  [LN]Setup/Control関連
 *  @author ueno@nayuta.co
 */
#ifndef LN_MSG_SETUPCTL_H__
#define LN_MSG_SETUPCTL_H__

#include "ln_local.h"


/********************************************************************
 * prototypes
 ********************************************************************/

/** init生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_init_create(ucoin_buf_t *pBuf, const ln_init_t *pMsg);


/** init読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_init_read(ln_init_t *pMsg, const uint8_t *pData, uint16_t Len);


/** error読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_error_read(void *pMsg, const uint8_t *pData, uint16_t Len);


/** ping生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_ping_create(ucoin_buf_t *pBuf, const ln_ping_t *pMsg);


/** ping読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_ping_read(ln_ping_t *pMsg, const uint8_t *pData, uint16_t Len);


/** pong生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_pong_create(ucoin_buf_t *pBuf, const ln_pong_t *pMsg);


/** pong読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_pong_read(ln_pong_t *pMsg, const uint8_t *pData, uint16_t Len);

#endif /* LN_MSG_SETUPCTL_H__ */
