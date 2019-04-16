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
/** @file   ln_normalope.h
 *  @brief  ln_normalope
 */
#ifndef LN_NORMALOPE_H__
#define LN_NORMALOPE_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln.h"
#include "ln_msg_normalope.h"

//XXX: unit test


/********************************************************************
 * prototypes
 ********************************************************************/

bool HIDDEN ln_update_add_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fulfill_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fail_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_commitment_signed_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_revoke_and_ack_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fee_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fail_malformed_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);


bool ln_set_add_htlc_send_origin(
    uint64_t NextShortChannelId, uint64_t PrevShortChannelId, uint64_t PrevHtlcId,
    uint64_t AmountMsat, const uint8_t *pPaymentHash, uint32_t CltvExpiry, const uint8_t *pOnionRoutingPacket);

/** update_fulfill_htlc設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           HtlcId          htlc id
 * @param[in]           pPreimage       payment_preimage
 * @retval      true    成功
 */
bool ln_fulfill_htlc_set(ln_channel_t *pChannel, uint64_t HtlcId, const uint8_t *pPreimage);


/** update_fail_htlc設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           HtlcId          htlc id
 * @param[in]           UpdateType      
 * @param[in]           pReason         reason
 * @note
 *      - onion_routing_packetと共用のため、onion_routingは消える
 */
bool ln_fail_htlc_set(ln_channel_t *pChannel, uint64_t HtlcId, uint8_t UpdateType, const utl_buf_t *pReason);


/** before channel_reestablish
 *
 * @param[in,out]       pChannel        channel info
 */
void ln_channel_reestablish_before(ln_channel_t *pChannel);


/** after channel_reestablish
 *
 * @param[in,out]       pChannel        channel info
 */
void ln_channel_reestablish_after(ln_channel_t *pChannel);


#endif /* LN_NORMALOPE_H__ */
