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
 */
#ifndef LN_MSG_NORMALOPE_H__
#define LN_MSG_NORMALOPE_H__

#include <stdbool.h>

#include "utl_buf.h"

#include "ln.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     ln_msg_update_add_htlc_t
 *  @brief      update_add_htlc
 */
typedef struct {
    //type: 128 (update_add_htlc)
    //data:
    //  [32:channel_id]
    //  [8:id]
    //  [8:amount_msat]
    //  [32:payment_hash]
    //  [4:cltv_expiry]
    //  [1366:onion_routing_packet]

    const uint8_t   *p_channel_id;
    uint64_t        id;
    uint64_t        amount_msat;
    const uint8_t   *p_payment_hash;
    uint32_t        cltv_expiry;
    const uint8_t   *p_onion_routing_packet;
} ln_msg_update_add_htlc_t;


/** @struct     ln_msg_update_fulfill_htlc_t
 *  @brief      update_fulfill_htlc
 */
typedef struct {
    //type: 130 (update_fulfill_htlc)
    //data:
    //  [32:channel_id]
    //  [8:id]
    //  [32:payment_preimage]

    const uint8_t   *p_channel_id;
    uint64_t        id;
    const uint8_t   *p_payment_preimage;
} ln_msg_update_fulfill_htlc_t;


/** @struct     ln_msg_update_fail_htlc_t
 *  @brief      update_fail_htlc
 */
typedef struct {
    //type: 131 (update_fail_htlc)
    //data:
    //  [32:channel_id]
    //  [8:id]
    //  [2:len]
    //  [len:reason]

    const uint8_t   *p_channel_id;
    uint64_t        id;
    uint16_t        len;
    const uint8_t   *p_reason;
} ln_msg_update_fail_htlc_t;


/** @struct     ln_msg_update_fail_malformed_htlc_t
 *  @brief      update_fail_malformed_htlc
 */
typedef struct {
    //type: 135 (update_fail_malformed_htlc)
    //data:
    //  [32:channel_id]
    //  [8:id]
    //  [32:sha256_of_onion]
    //  [2:failure_code]

    const uint8_t   *p_channel_id;
    uint64_t        id;
    const uint8_t   *p_sha256_of_onion;
    uint16_t        failure_code;
} ln_msg_update_fail_malformed_htlc_t;


/** @struct     ln_msg_commitment_signed_t
 *  @brief      commitment_signed
 */
typedef struct {
    //type: 132 (commitment_signed)
    //data:
    //  [32:channel_id]
    //  [64:signature]
    //  [2:num_htlcs]
    //  [num_htlcs*64:htlc_signature]

    const uint8_t   *p_channel_id;
    const uint8_t   *p_signature;
    uint16_t        num_htlcs;
    const uint8_t   *p_htlc_signature;
} ln_msg_commitment_signed_t;


/** @struct     ln_revoke_and_ack_t
 *  @brief      revoke_and_ack
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint8_t     *p_per_commit_secret;               ///< 32: 古いper-commiment-secret
    uint8_t     *p_per_commitpt;                    ///< 33: 新しいper-commtment-point
} ln_revoke_and_ack_t;


/** @struct     ln_update_fee_t
 *  @brief      update_fee
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint32_t    feerate_per_kw;                     ///< 4:  feerate-per-kw
} ln_update_fee_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** update_add_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_add_htlc_write(utl_buf_t *pBuf, const ln_msg_update_add_htlc_t *pMsg);


/** update_add_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_add_htlc_read(ln_msg_update_add_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fulfill_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fulfill_htlc_write(utl_buf_t *pBuf, const ln_msg_update_fulfill_htlc_t *pMsg);


/** update_fulfill_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fulfill_htlc_read(ln_msg_update_fulfill_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fail_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_htlc_write(utl_buf_t *pBuf, const ln_msg_update_fail_htlc_t *pMsg);


/** update_fail_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_htlc_read(ln_msg_update_fail_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** update_fail_malformed_htlc生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_malformed_htlc_write(utl_buf_t *pBuf, const ln_msg_update_fail_malformed_htlc_t *pMsg);


/** update_fail_malformed_htlc読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fail_malformed_htlc_read(ln_msg_update_fail_malformed_htlc_t *pMsg, const uint8_t *pData, uint16_t Len);


/** commit_signed生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_commitment_signed_write(utl_buf_t *pBuf, const ln_msg_commitment_signed_t *pMsg);


/** commit_signed読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_commitment_signed_read(ln_msg_commitment_signed_t *pMsg, const uint8_t *pData, uint16_t Len);


/** revoke_and_ack生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_revoke_and_ack_write(utl_buf_t *pBuf, const ln_revoke_and_ack_t *pMsg);


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
bool HIDDEN ln_msg_update_fee_write(utl_buf_t *pBuf, const ln_update_fee_t *pMsg);


/** update_fee読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len);


#endif /* LN_MSG_NORMALOPE_H__ */
