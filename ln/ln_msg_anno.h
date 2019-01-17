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

/** channel_announcement生成
 *
 * @param[out]      pBuf        生成データ
 * @param[in]       pMsg        元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_announce_write(utl_buf_t *pBuf, const ln_cnl_announce_t *pMsg);


/** channel_announcement読込み(verify無し)
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool ln_msg_cnl_announce_read(ln_cnl_announce_t *pMsg, const uint8_t *pData, uint16_t Len);


/** channel_announcement署名verify
 *
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_announce_verify(ln_cnl_announce_t *pMsg, const uint8_t *pData, uint16_t Len); //XXX: not used


/** [デバッグ]channel_announcementデバッグ出力
 *
 */
void HIDDEN ln_msg_cnl_announce_print(const uint8_t *pData, uint16_t Len);


/** sign channel_announcement
 *
 */
bool HIDDEN ln_msg_cnl_announce_sign(uint8_t *pData, uint16_t Len, const uint8_t *pBtcPrivKey, btc_script_pubkey_order_t Sort);


/** [デバッグ]channel_updateデバッグ出力
 *
 */
 void HIDDEN ln_msg_cnl_update_print(const ln_cnl_update_t *pMsg);


/** node_announcement生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_node_announce_write(utl_buf_t *pBuf, const ln_node_announce_t *pMsg);


/** node_announcement読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool ln_msg_node_announce_read(ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len);


/** channel_update生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_update_write(utl_buf_t *pBuf, const ln_cnl_update_t *pMsg);


/** channel_update読込み(verify無し)
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t Len);


/** channel_update署名verify
 *
 * @param[in]       pPubkey 公開鍵(node_id)
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_update_verify(const uint8_t *pPubkey, const uint8_t *pData, uint16_t Len);


/** announcement_signatures生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_announce_signs_write(utl_buf_t *pBuf, const ln_announce_signs_t *pMsg);


/** announcement_signaturesのshort_channel_idのみ取得
 *
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * @return      short_channel_id
 */
uint64_t HIDDEN ln_msg_announce_signs_read_short_cnl_id(const uint8_t *pData, uint16_t Len, const uint8_t *pChannelId);


/** announcement_signatures読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * @retval  true    成功
 * @note
 *      pMsg->short_channel_idに0以外を設定しておくと、不一致時にfalseを返す
 */
bool HIDDEN ln_msg_announce_signs_read(ln_announce_signs_t *pMsg, const uint8_t *pData, uint16_t Len);


/** announcement_signaturesの署名アドレス取得
 *
 */
void HIDDEN ln_msg_get_anno_signs(uint8_t *pData, uint8_t **pp_sig_node, uint8_t **pp_sig_btc, bool bLocal, btc_script_pubkey_order_t Sort);


/** short_channel_id書き換え
 *
 */
bool HIDDEN ln_msg_cnl_announce_update_short_cnl_id(uint8_t *pData, uint64_t ShortChannelId);

#endif /* LN_MSG_ANNO_H__ */
