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
/** @file   ln_msg_close.h
 *  @brief  [LN]Close関連
 *  @author ueno@nayuta.co
 */
#ifndef LN_MSG_CLOSE_H__
#define LN_MSG_CLOSE_H__

#include "ln_local.h"


/********************************************************************
 * prototypes
 ********************************************************************/

/** shutdown生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_shutdown_create(ptarm_buf_t *pBuf, const ln_shutdown_t *pMsg);


/** shutdown読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_shutdown_read(ln_shutdown_t *pMsg, const uint8_t *pData, uint16_t Len);


/** closing_signed生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_closing_signed_create(ptarm_buf_t *pBuf, const ln_closing_signed_t *pMsg);


/** closing_signed読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_closing_signed_read(ln_closing_signed_t *pMsg, const uint8_t *pData, uint16_t Len);

#endif /* LN_MSG_CLOSE_H__ */
