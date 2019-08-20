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
/** @file   ln_msg_x_normalope.h
 *  @brief  [LN]Normal Operation関連
 */
#ifndef LN_MSG_X_NORMALOPE_H__
#define LN_MSG_X_NORMALOPE_H__

#include <stdbool.h>

#include "utl_buf.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     ln_msg_x_update_add_htlc_t
 *  @brief      update_add_htlc
 */
typedef struct {
    //type: 128 (update_add_htlc)
    //data:
    //  [8:amount_msat]
    //  [32:payment_hash]
    //  [4:cltv_expiry]
    //  [8:amt_to_forward]
    //  [4:outgoing_cltv_value]
    //  [1366:onion_routing_packet]

    uint64_t        amount_msat;
    const uint8_t   *p_payment_hash;
    uint32_t        cltv_expiry;
    uint64_t        amt_to_forward;
    uint32_t        outgoing_cltv_value;
    const uint8_t   *p_onion_routing_packet;
} ln_msg_x_update_add_htlc_t;


/** @struct     ln_msg_x_update_fulfill_htlc_t
 *  @brief      update_fulfill_htlc
 */
typedef struct {
    //type: 130 (update_fulfill_htlc)
    //data:
    //  [32:payment_preimage]

    const uint8_t   *p_payment_preimage;
} ln_msg_x_update_fulfill_htlc_t;


/** @struct     ln_msg_x_update_fail_htlc_t
 *  @brief      update_fail_htlc
 */
typedef struct {
    //type: 131 (update_fail_htlc)
    //data:
    //  [2:len]
    //  [len:reason]

    uint16_t        len;
    const uint8_t   *p_reason;
} ln_msg_x_update_fail_htlc_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** update_add_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_update_add_htlc_write(utl_buf_t *pBuf, const ln_msg_x_update_add_htlc_t *pMsg);


/** update_add_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_update_add_htlc_read(ln_msg_x_update_add_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fulfill_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_update_fulfill_htlc_write(utl_buf_t *pBuf, const ln_msg_x_update_fulfill_htlc_t *pMsg);


/** update_fulfill_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_update_fulfill_htlc_read(ln_msg_x_update_fulfill_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fail_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_update_fail_htlc_write(utl_buf_t *pBuf, const ln_msg_x_update_fail_htlc_t *pMsg);


/** update_fail_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_update_fail_htlc_read(ln_msg_x_update_fail_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


#endif /* LN_MSG_X_NORMALOPE_H__ */
