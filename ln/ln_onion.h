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
/** @file   ln_onion.h
 *  @brief  ONION関連
 */
#ifndef LN_ONION_H__
#define LN_ONION_H__

#include "utl_push.h"

#include "btc_keys.h"


/********************************************************************
 * macros
 ********************************************************************/

#define LN_HOP_MAX                      (20)        ///< onion hop max


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct     ln_hop_datain_t
 *  @brief      ONIONパケット生成情報
 */
typedef struct {
    uint64_t            short_channel_id;               ///< short_channel_id
    uint64_t            amt_to_forward;                 ///< update_add_htlcのamount-msat
    uint32_t            outgoing_cltv_value;            ///< update_add_htlcのcltv-expiry
    uint8_t             pubkey[BTC_SZ_PUBKEY];          ///< ノード公開鍵(node_id)
} ln_hop_datain_t;


/** @struct     ln_hop_dataout_t
 *  @brief      ONIONパケット解析情報
 */
typedef struct {
    bool                b_exit;                         ///< true:送金先, false:中継
    uint64_t            short_channel_id;               ///< short_channel_id
    uint64_t            amt_to_forward;                 ///< update_add_htlcのamount-msat
    uint32_t            outgoing_cltv_value;            ///< update_add_htlcのcltv-expiry
} ln_hop_dataout_t;


/** @struct     ln_onion_err_t
 *  @brief      ONIONエラーreason解析
 */
typedef struct {
    uint16_t            reason;
    void                *p_data;
} ln_onion_err_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** ONIONパラメータ復元
 *
 * @param[out]      pNextPacket         次に送るONIONパケット[LN_SZ_ONION_ROUTE]
 * @param[out]      pNextData           復元情報
 * @param[out]      pSharedSecret       共有秘密鍵
 * @param[out]      pPushReason         reason(戻り値がfalse時)
 * @param[in]       pPacket             解析するONIONパケット
 * @param[in]       pOnionPrivKey       自ノード秘密鍵?
 * @param[in]       pAssocData          Associated Data
 * @param[in]       AssocLen            pAssocData長
 * @retval      true    成功
 * @note
 *      - pNextData->b_exitがtrueの場合、pNextPacketは無効
 *      - pNextPacketとpPacketに同じアドレスを指定できる
 */
bool HIDDEN ln_onion_read_packet(uint8_t *pNextPacket, ln_hop_dataout_t *pNextData,
            utl_buf_t *pSharedSecret,
            utl_push_t *pPushReason,
            const uint8_t *pPacket,
            const uint8_t *pAssocData, int AssocLen);


/** ONIONパケット生成
 *
 * @param[out]      pPacket             ONIONパケット[LN_SZ_ONION_ROUTE]
 * @param[out]      pSecrets            全shared secret(#ln_onion_failure_read()用)
 * @param[in]       pHopData            HOPデータ
 * @param[in]       NumHops             pHopData数
 * @param[in]       pSessionKey         セッション鍵[BTC_SZ_PRIVKEY]
 * @param[in]       pAssocData          Associated Data
 * @param[in]       AssocLen            pAssocData長
 * @retval      true    成功
 */
bool ln_onion_create_packet(uint8_t *pPacket,
            utl_buf_t *pSecrets,
            const ln_hop_datain_t *pHopData,
            int NumHops,
            const uint8_t *pSessionKey,
            const uint8_t *pAssocData, int AssocLen);


/** ONION failureパケット生成
 *
 * @param[out]      pNextPacket         ONION failureパケット
 * @param[in]       pSharedSecret       shared secret
 * @param[in]       pReason             Failure Message(BOLT#4)
 *
 * @note
 *      - https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#failure-messages
 */
void ln_onion_failure_create(utl_buf_t *pNextPacket,
            const utl_buf_t *pSharedSecret,
            const utl_buf_t *pReason);


/** ONION failure転送パケット生成
 *
 * @param[out]      pNextPacket         ONION failure転送パケット
 * @param[in]       pSharedSecret       shared secret
 * @param[in]       pPacket             受信したONION failureパケット
 */
void ln_onion_failure_forward(utl_buf_t *pNextPacket,
            const utl_buf_t *pSharedSecret,
            const utl_buf_t *pPacket);


/** ONION failureパケット解析
 *
 * @param[out]      pReason             Failure Message
 * @param[out]      pHop                エラー元までのノード数(0は相手ノード)
 * @param[in]       pSharedSecrets      ONIONパケット生成自の全shared secret(#ln_onion_create_packet())
 * @param[in]       pPacket             受信したONION failureパケット
 * @retval  true    成功
 */
bool ln_onion_failure_read(utl_buf_t *pReason,
            int *pHop,
            const utl_buf_t *pSharedSecrets,
            const utl_buf_t *pPacket);


/** ONION failure reason解析
 *
 * @param[out]      pOnionErr
 * @param[in]       pReason
 * @retval  true    成功
 */
bool ln_onion_read_err(ln_onion_err_t *pOnionErr, const utl_buf_t *pReason);


/** set onion reaon: temporary node failure
 *
 * @param[out]      pReason
 */
void ln_onion_create_reason_temp_node(utl_buf_t *pReason);


/** set onion reaon: permanent node failure
 *
 * @param[out]      pReason
 */
void ln_onion_create_reason_perm_node(utl_buf_t *pReason);


/** ONION failure reason文字列取得
 *
 * @param[in]       pOnionErr
 * @return  エラー文字列(呼び元でfree()すること)
 */
char *ln_onion_get_errstr(const ln_onion_err_t *pOnionErr);


#endif /* LN_ONION_H__ */
