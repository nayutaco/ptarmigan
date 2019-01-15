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

#include "utl_common.h"
#include "utl_buf.h"

//#include "ln.h"

/**************************************************************************
 * macros
 **************************************************************************/

#define LN_FUNDIDX_MAX                  (6)         ///< 管理用 //XXX:


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct ln_msg_open_channel_t
 *  @brief  open_channel
 */
typedef struct {
    //type: 32 (open_channel)
    //data:
    //  [32:chain_hash]
    //  [32:temporary_channel_id]
    //  [8:funding_satoshis]
    //  [8:push_msat]
    //  [8:dust_limit_satoshis]
    //  [8:max_htlc_value_in_flight_msat]
    //  [8:channel_reserve_satoshis]
    //  [8:htlc_minimum_msat]
    //  [4:feerate_per_kw]
    //  [2:to_self_delay]
    //  [2:max_accepted_htlcs]
    //  [33:funding_pubkey]
    //  [33:revocation_basepoint]
    //  [33:payment_basepoint]
    //  [33:delayed_payment_basepoint]
    //  [33:htlc_basepoint]
    //  [33:first_per_commitment_point]
    //  [1:channel_flags]
    //  [2:shutdown_len] (option_upfront_shutdown_script)
    //  [shutdown_len:shutdown_scriptpubkey] (option_upfront_shutdown_script)

    const uint8_t   *p_chain_hash;
    const uint8_t   *p_temporary_channel_id;
    uint64_t        funding_satoshis;
    uint64_t        push_msat;
    uint64_t        dust_limit_satoshis;
    uint64_t        max_htlc_value_in_flight_msat;
    uint64_t        channel_reserve_satoshis;
    uint64_t        htlc_minimum_msat;
    uint32_t        feerate_per_kw;
    uint16_t        to_self_delay;
    uint16_t        max_accepted_htlcs;
    const uint8_t   *p_funding_pubkey;
    const uint8_t   *p_revocation_basepoint;
    const uint8_t   *p_payment_basepoint;
    const uint8_t   *p_delayed_payment_basepoint;
    const uint8_t   *p_htlc_basepoint;
    const uint8_t   *p_first_per_commitment_point;
    const uint8_t   *p_channel_flags;
    uint16_t        shutdown_len;
    const uint8_t   *p_shutdown_scriptpubkey;
} ln_msg_open_channel_t;


/** @struct ln_msg_accept_channel_t
 *  @brief  accept_channel
 */
typedef struct {
    //type: 33 (accept_channel)
    //data:
    //  [32:temporary_channel_id]
    //  [8:dust_limit_satoshis]
    //  [8:max_htlc_value_in_flight_msat]
    //  [8:channel_reserve_satoshis]
    //  [8:htlc_minimum_msat]
    //  [4:minimum_depth]
    //  [2:to_self_delay]
    //  [2:max_accepted_htlcs]
    //  [33:funding_pubkey]
    //  [33:revocation_basepoint]
    //  [33:payment_basepoint]
    //  [33:delayed_payment_basepoint]
    //  [33:htlc_basepoint]
    //  [33:first_per_commitment_point]
    //  [2:shutdown_len] (option_upfront_shutdown_script)
    //  [shutdown_len:shutdown_scriptpubkey] (option_upfront_shutdown_script)

    const uint8_t   *p_temporary_channel_id;
    uint64_t        dust_limit_satoshis;
    uint64_t        max_htlc_value_in_flight_msat;
    uint64_t        channel_reserve_satoshis;
    uint64_t        htlc_minimum_msat;
    uint32_t        minimum_depth;
    uint16_t        to_self_delay;
    uint16_t        max_accepted_htlcs;
    const uint8_t   *p_funding_pubkey;
    const uint8_t   *p_revocation_basepoint;
    const uint8_t   *p_payment_basepoint;
    const uint8_t   *p_delayed_payment_basepoint;
    const uint8_t   *p_htlc_basepoint;
    const uint8_t   *p_first_per_commitment_point;
    uint16_t        shutdown_len;
    const uint8_t   *p_shutdown_scriptpubkey;
} ln_msg_accept_channel_t;


/** @struct ln_msg_funding_created_t
 *  @brief  funding_created
 */
typedef struct {
    //type: 34 (funding_created)
    //data:
    //  [32:temporary_channel_id]
    //  [32:funding_txid]
    //  [2:funding_output_index]
    //  [64:signature]

    const uint8_t   *p_temporary_channel_id;
    const uint8_t   *p_funding_txid;
    uint16_t        funding_output_index;
    const uint8_t   *p_signature;
} ln_msg_funding_created_t;


/** @struct ln_msg_funding_signed_t
 *  @brief  funding_signed
 */
typedef struct {
    //type: 35 (funding_signed)
    //data:
    //  [32:channel_id]
    //  [64:signature]

    const uint8_t   *p_channel_id;
    const uint8_t   *p_signature;
} ln_msg_funding_signed_t;


/** @struct ln_msg_funding_locked_t
 *  @brief  funding_locked
 */
typedef struct {
    //type: 36 (funding_locked)
    //data:
    //  [32:channel_id]
    //  [33:next_per_commitment_point]

    const uint8_t   *p_channel_id;
    const uint8_t   *p_next_per_commitment_point;
} ln_msg_funding_locked_t;


/** @struct     ln_channel_reestablish_t
 *  @brief      channel_reestablish
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    next_local_commitment_number;       ///< 8:  next_local_commitment_number
    uint64_t    next_remote_revocation_number;      ///< 8:  next_remote_revocation_number
    bool        option_data_loss_protect;           ///< true:your_last_per_commitment_secretとmy_current_per_commitment_pointが有効
    uint8_t     *p_your_last_per_commitment_secret; ///< 32: your_last_per_commitment_secret
    uint8_t     *p_my_current_per_commitment_point; ///< 33: my_current_per_commitment_point
} ln_channel_reestablish_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** open_channel生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_open_channel_write(utl_buf_t *pBuf, const ln_msg_open_channel_t *pMsg);


/** open_channel読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_open_channel_read(ln_msg_open_channel_t *pMsg, const uint8_t *pData, uint16_t Len);


/** accept_channel生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_accept_channel_write(utl_buf_t *pBuf, const ln_msg_accept_channel_t *pMsg);


/** accept_channel読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_accept_channel_read(ln_msg_accept_channel_t *pMsg, const uint8_t *pData, uint16_t Len);


/** funding_created生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_created_write(utl_buf_t *pBuf, const ln_msg_funding_created_t *pMsg);


/** funding_created読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_created_read(ln_msg_funding_created_t *pMsg, const uint8_t *pData, uint16_t Len);


/** funding_signed生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_signed_write(utl_buf_t *pBuf, const ln_msg_funding_signed_t *pMsg);


/** funding_signed読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_signed_read(ln_msg_funding_signed_t *pMsg, const uint8_t *pData, uint16_t Len);


/** funding_locked生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_locked_write(utl_buf_t *pBuf, const ln_msg_funding_locked_t *pMsg);


/** funding_locked読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_funding_locked_read(ln_msg_funding_locked_t *pMsg, const uint8_t *pData, uint16_t Len);


/** channel_reestablish生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_reestablish_write(utl_buf_t *pBuf, const ln_channel_reestablish_t *pMsg);


/** channel_reestablish読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_reestablish_read(ln_channel_reestablish_t *pMsg, const uint8_t *pData, uint16_t Len);


#endif /* LN_MSG_ESTABLISH_H__ */
