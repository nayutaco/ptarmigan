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


/********************************************************************
 * prototypes
 ********************************************************************/

/** write channel_announcement
 *
 * @param[out]      pBuf        生成データ
 * @param[in]       pMsg        元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_announce_write(utl_buf_t *pBuf, const ln_cnl_announce_t *pMsg);


/** read channel_announcement
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_cnl_announce_read(ln_cnl_announce_t *pMsg, const uint8_t *pData, uint16_t Len);


/** sign channel_announcement
 *
 */
bool HIDDEN ln_msg_cnl_announce_sign(uint8_t *pData, uint16_t Len, const uint8_t *pBtcPrivKey, btc_script_pubkey_order_t Sort);


/** verify channel_announcement
 *
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_announce_verify(ln_cnl_announce_t *pMsg, const uint8_t *pData, uint16_t Len); //XXX: not used


/** print channel_announcement
 *
 */
void HIDDEN ln_msg_cnl_announce_print(const uint8_t *pData, uint16_t Len);


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


/** write announcement_signatures
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_announce_signs_write(utl_buf_t *pBuf, const ln_announce_signs_t *pMsg);


/** announcement_signaturesのshort_channel_idのみ取得 //XXX:
 *
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * @return      short_channel_id
 */
uint64_t HIDDEN ln_msg_announce_signs_read_short_cnl_id(const uint8_t *pData, uint16_t Len, const uint8_t *pChannelId);


/** read announcement_signatures
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * @retval  true    成功
 */
bool HIDDEN ln_msg_announce_signs_read(ln_announce_signs_t *pMsg, const uint8_t *pData, uint16_t Len);


/** announcement_signaturesの署名アドレス取得 //XXX:
 *
 */
void HIDDEN ln_msg_get_anno_signs(uint8_t *pData, uint8_t **pp_sig_node, uint8_t **pp_sig_btc, bool bLocal, btc_script_pubkey_order_t Sort);


/** short_channel_id書き換え //XXX:
 *
 */
bool HIDDEN ln_msg_cnl_announce_update_short_cnl_id(uint8_t *pData, uint64_t ShortChannelId);

#endif /* LN_MSG_ANNO_H__ */
