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
/** @file   ln_msg_anno.h
 *  @brief  [LN]Announce関連
 */
#ifndef LN_MSG_ANNO_H__
#define LN_MSG_ANNO_H__

#include "ln.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     ln_msg_announcement_signatures_t
 *  @brief      announcement_signatures
 */
typedef struct {
    //type: 259 (announcement_signatures)
    //data:
    //  [32:channel_id]
    //  [8:short_channel_id]
    //  [64:node_signature]
    //  [64:bitcoin_signature]

    const uint8_t   *p_channel_id;
    uint64_t        short_channel_id;
    const uint8_t   *p_node_signature;
    const uint8_t   *p_bitcoin_signature;
} ln_msg_announcement_signatures_t;


/** @struct     ln_msg_channel_announcement_t
 *  @brief      channel_announcement
 */
typedef struct {
    //type: 256 (channel_announcement)
    //data:
    //  [64:node_signature_1]
    //  [64:node_signature_2]
    //  [64:bitcoin_signature_1]
    //  [64:bitcoin_signature_2]
    //  [2:len]
    //  [len:features]
    //  [32:chain_hash]
    //  [8:short_channel_id]
    //  [33:node_id_1]
    //  [33:node_id_2]
    //  [33:bitcoin_key_1]
    //  [33:bitcoin_key_2]

    const uint8_t   *p_node_signature_1;
    const uint8_t   *p_node_signature_2;
    const uint8_t   *p_bitcoin_signature_1;
    const uint8_t   *p_bitcoin_signature_2;
    uint16_t        len;
    const uint8_t   *p_features;
    const uint8_t   *p_chain_hash;
    uint64_t        short_channel_id;
    const uint8_t   *p_node_id_1;
    const uint8_t   *p_node_id_2;
    const uint8_t   *p_bitcoin_key_1;
    const uint8_t   *p_bitcoin_key_2;
} ln_msg_channel_announcement_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** write announcement_signatures
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_announcement_signatures_write(utl_buf_t *pBuf, const ln_msg_announcement_signatures_t *pMsg);


/** read announcement_signatures
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * @retval  true    成功
 */
bool HIDDEN ln_msg_announcement_signatures_read(ln_msg_announcement_signatures_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write channel_announcement
 *
 * @param[out]      pBuf        生成データ
 * @param[in]       pMsg        元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_announcement_write(utl_buf_t *pBuf, const ln_msg_channel_announcement_t *pMsg);


/** read channel_announcement
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_channel_announcement_read(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len);


/** sign channel_announcement
 *
 */
bool HIDDEN ln_msg_channel_announcement_sign(uint8_t *pData, uint16_t Len, const uint8_t *pBtcPrivKey, btc_script_pubkey_order_t Sort);


/** verify channel_announcement
 *
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_announcement_verify(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len); //XXX: not used


/** print channel_announcement
 *
 */
bool HIDDEN ln_msg_channel_announcement_print(const uint8_t *pData, uint16_t Len);


/** print channel_update
 *
 */
void HIDDEN ln_msg_cnl_update_print(const ln_cnl_update_t *pMsg);


/** write node_announcement
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_node_announce_write(utl_buf_t *pBuf, const ln_node_announce_t *pMsg);


/** read node_announcement
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_node_announce_read(ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len);


/** sign node_announcement
 *
 */
bool HIDDEN ln_msg_node_announce_sign(uint8_t *pData, uint16_t Len);


/** vefiry node_announcement
 *
 */
bool HIDDEN ln_msg_node_announce_verify(const ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write channel_update
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_update_write(utl_buf_t *pBuf, const ln_cnl_update_t *pMsg);


/** read channel_update
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t Len);


/** sign channel_update
 *
 */
bool HIDDEN ln_msg_cnl_update_sign(uint8_t *pData, uint16_t Len);


/** verify channel_update
 *
 * @param[in]       pNodePubKey 公開鍵(node_id)
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_update_verify(const uint8_t *pNodePubKey, const uint8_t *pData, uint16_t Len);


/** announcement_signaturesの署名アドレス取得 //XXX:
 *
 */
void HIDDEN ln_msg_get_anno_signs(uint8_t *pData, uint8_t **pp_sig_node, uint8_t **pp_sig_btc, bool bLocal, btc_script_pubkey_order_t Sort);


/** short_channel_id書き換え //XXX:
 *
 */
bool HIDDEN ln_msg_channel_announcement_update_short_channel_id(uint8_t *pData, uint64_t ShortChannelId);

#endif /* LN_MSG_ANNO_H__ */
