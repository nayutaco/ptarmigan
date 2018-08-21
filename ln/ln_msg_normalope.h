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
/** @file   ln_msg_normalope.h
 *  @brief  [LN]Normal Operation関連
 *  @author ueno@nayuta.co
 */
#ifndef LN_MSG_NORMALOPE_H__
#define LN_MSG_NORMALOPE_H__

#include <stdbool.h>

#include "utl_buf.h"

#include "ln.h"


/********************************************************************
 * prototypes
 ********************************************************************/

/** update_add_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_add_htlc_create(utl_buf_t *pBuf, const ln_update_add_htlc_t *pMsg);


/** update_add_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_add_htlc_read(ln_update_add_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fulfill_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fulfill_htlc_create(utl_buf_t *pBuf, const ln_update_fulfill_htlc_t *pMsg);


/** update_fulfill_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fulfill_htlc_read(ln_update_fulfill_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fail_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_htlc_create(utl_buf_t *pBuf, const ln_update_fail_htlc_t *pMsg);


/** update_fail_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_htlc_read(ln_update_fail_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** commit_signed生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_commit_signed_create(utl_buf_t *pBuf, const ln_commit_signed_t *pMsg);


/** commit_signed読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_commit_signed_read(ln_commit_signed_t *pMsg, const uint8_t *pData, uint16_t Len);


/** revoke_and_ack生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_revoke_and_ack_create(utl_buf_t *pBuf, const ln_revoke_and_ack_t *pMsg);


/** revoke_and_ack読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_revoke_and_ack_read(ln_revoke_and_ack_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fee生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fee_create(utl_buf_t *pBuf, const ln_update_fee_t *pMsg);


/** update_fee読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fail_malformed_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_malformed_htlc_create(utl_buf_t *pBuf, const ln_update_fail_malformed_htlc_t *pMsg);


/** update_fail_malformed_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_malformed_htlc_read(ln_update_fail_malformed_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);

#endif /* LN_MSG_NORMALOPE_H__ */
