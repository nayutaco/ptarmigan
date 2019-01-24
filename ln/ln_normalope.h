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



/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    LN_HTLC_EMPTY(htlc)
 *  @brief  ln_update_add_htlc_tの空き
 *  @note
 *      - HTLCの空き場所を探している場合には、(amount_msat != 0)も同時にチェックする
 */
#define LN_HTLC_EMPTY(htlc)     \
            ( ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_NONE) && \
            ((htlc)->amount_msat == 0) )

/** @def    LN_HTLC_ENABLE(htlc)
 *  @brief  ln_update_add_htlc_tとして有効
 *  @note
 *      - (amount_msat != 0)で判定していたが、update_add_htlcの転送の場合、
 *          update_add_htlc受信時に転送先にパラメータを全部設定して待たせておき、
 *          revoke_and_ackが完了してから指示だけを出すようにしたかった。
 */
//#define LN_HTLC_ENABLE(htlc)    ((htlc)->stat.flag.addhtlc != LN_ADDHTLC_NONE)
#define LN_HTLC_ENABLE(htlc)    (!LN_HTLC_EMPTY(htlc))


/********************************************************************
 * prototypes
 ********************************************************************/

bool HIDDEN ln_update_add_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fulfill_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fail_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_commitment_signed_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_revoke_and_ack_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fee_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_update_fail_malformed_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);


/** update_add_htlc設定
 *
 * @param[in,out]       self            channel info
 * @param[out]          pHtlcId         生成したHTLCのid
 * @param[out]          pReason         (非NULLかつ戻り値がfalse)onion reason
 * @param[in]           pPacket         onion packet
 * @param[in]           AmountMsat      送金額[msat]
 * @param[in]           CltvValue       CLTV値(絶対値)
 * @param[in]           pPaymentHash    PaymentHash(SHA256:32byte)
 * @param[in]           PrevShortChannelId   転送元short_channel_id(ない場合は0)
 * @param[in]           PrevIdx         転送元cnl_add_htlc[]index(ない場合は0)
 * @param[in]           pSharedSecrets  保存する共有秘密鍵集(NULL:未保存)
 * @retval      true    成功
 * @note
 *      - prev_short_channel_id はfullfillの通知先として使用する
 */
bool ln_add_htlc_set(ln_self_t *self,
            uint64_t *pHtlcId,
            utl_buf_t *pReason,
            const uint8_t *pPacket,
            uint64_t AmountMsat,
            uint32_t CltvValue,
            const uint8_t *pPaymentHash,
            uint64_t PrevShortChannelId,
            uint16_t PrevIdx,
            const utl_buf_t *pSharedSecrets);


bool ln_add_htlc_set_fwd(ln_self_t *self,
            uint64_t *pHtlcId,
            utl_buf_t *pReason,
            uint16_t *pNextIdx,
            const uint8_t *pPacket,
            uint64_t AmountMsat,
            uint32_t CltvValue,
            const uint8_t *pPaymentHash,
            uint64_t PrevShortChannelId,
            uint16_t PrevIdx,
            const utl_buf_t *pSharedSecrets);


void ln_add_htlc_start_fwd(ln_self_t *self, uint16_t Idx);


/** update_fulfill_htlc設定
 *
 * @param[in,out]       self            channel info
 * @param[in]           Idx             設定するHTLCの内部管理index値
 * @param[in]           pPreImage       payment_preimage
 * @retval      true    成功
 */
bool ln_fulfill_htlc_set(ln_self_t *self, uint16_t Idx, const uint8_t *pPreImage);


/** update_fail_htlc設定
 *
 * @param[in,out]       self            channel info
 * @param[in]           Idx             index
 * @param[in]           pReason         reason
 * @note
 *      - onion_routing_packetと共用のため、onion_routingは消える
 */
bool ln_fail_htlc_set(ln_self_t *self, uint16_t Idx, const utl_buf_t *pReason);


bool ln_fail_htlc_set_bwd(ln_self_t *self, uint16_t Idx, const utl_buf_t *pReason);


/** update_fail_htlc転送
 *
 *
 */
void ln_del_htlc_start_bwd(ln_self_t *self, uint16_t Idx);


/** update_feeメッセージ作成
 *
 * @param[in,out]       self            channel info
 * @param[out]          pUpdFee         生成したupdate_feeメッセージ
 * @param[in]           FeeratePerKw    更新後のfeerate_per_kw
 */
bool ln_update_fee_create(ln_self_t *self, utl_buf_t *pUpdFee, uint32_t FeeratePerKw);


/** channel_reestablishメッセージ交換後
 *
 * @param[in,out]       self            channel info
 */
void ln_channel_reestablish_after(ln_self_t *self);


#endif /* LN_NORMALOPE_H__ */
