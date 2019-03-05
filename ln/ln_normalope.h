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


/** update_add_htlc設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[out]          pHtlcId         生成したHTLCのid
 * @param[out]          pReason         (非NULLかつ戻り値がfalse)onion reason
 * @param[in]           pPacket         onion packet
 * @param[in]           AmountMsat      送金額[msat]
 * @param[in]           CltvValue       CLTV値(絶対値)
 * @param[in]           pPaymentHash    PaymentHash(SHA256:32byte)
 * @param[in]           PrevShortChannelId      転送元short_channel_id(ない場合は0)
 * @param[in]           PrevHtlcIdx           転送元updates[]index(ない場合は0)
 * @param[in]           pSharedSecrets  保存する共有秘密鍵集(NULL:未保存)
 * @retval      true    成功
 * @note
 *      - prev_short_channel_id はfullfillの通知先として使用する
 */
bool ln_set_add_htlc_send(
    ln_channel_t *pChannel, uint64_t *pHtlcId, utl_buf_t *pReason, const uint8_t *pPacket,
    uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash,
    uint64_t PrevShortChannelId, uint16_t PrevHtlcIdx, const utl_buf_t *pSharedSecrets);

bool ln_set_add_htlc_send_fwd(
    ln_channel_t *pChannel, uint64_t *pHtlcId, utl_buf_t *pReason, uint16_t *pNextUpdateIdx,
    const uint8_t *pPacket, uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash,
    uint64_t PrevShortChannelId, uint16_t PrevHtlcIdx, const utl_buf_t *pSharedSecrets);

void ln_add_htlc_start_fwd(ln_channel_t *pChannel, uint16_t NextHtlcIdx);


/** update_fulfill_htlc設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           HtlcIdx         index of the htlcs
 * @param[in]           pPreimage       payment_preimage
 * @retval      true    成功
 */
bool ln_fulfill_htlc_set(ln_channel_t *pChannel, uint16_t HtlcIdx, const uint8_t *pPreimage);


/** update_fail_htlc設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           HtlcIdx         index of the htlcs
 * @param[in]           UpdateType      
 * @param[in]           pReason         reason
 * @note
 *      - onion_routing_packetと共用のため、onion_routingは消える
 */
bool ln_fail_htlc_set(ln_channel_t *pChannel, uint16_t HtlcIdx, uint8_t UpdateType, const utl_buf_t *pReason);


/** channel_reestablishメッセージ交換後
 *
 * @param[in,out]       pChannel        channel info
 */
void ln_channel_reestablish_after(ln_channel_t *pChannel);


#endif /* LN_NORMALOPE_H__ */
