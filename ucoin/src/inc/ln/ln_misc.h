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
/** @file   ln_misc.h
 *  @brief  [LN]雑多
 *  @author ueno@nayuta.co
 */
#ifndef LN_MISC_H__
#define LN_MISC_H__

#include "ln_local.h"


/**************************************************************************
 * prototypes
 **************************************************************************/


/** 8bit値の書込み
 *
 * @param[out]      pPush       書込み先
 * @param[in]       Value       8bit値
 */
void HIDDEN ln_misc_push8(ucoin_push_t *pPush, uint8_t Value);


/** 16bit BE値の書込み
 *
 * @param[out]      pPush       書込み先
 * @param[in]       Value       16bit値
 */
void HIDDEN ln_misc_push16be(ucoin_push_t *pPush, uint16_t Value);


/** 32bit BE値の書込み
 *
 * @param[out]      pPush       書込み先
 * @param[in]       Value       32bit値
 */
void HIDDEN ln_misc_push32be(ucoin_push_t *pPush, uint32_t Value);


/** 64bit BE値の書込み
 *
 * @param[out]      pPush       書込み先
 * @param[in]       Value       64bit値
 */
void HIDDEN ln_misc_push64be(ucoin_push_t *pPush, uint64_t Value);


/** LenバイトをBigEndianで書込む
 *
 *
 */
void HIDDEN ln_misc_setbe(uint8_t *pBuf, const void *pData, size_t Len);


/** DER形式秘密鍵を64byte展開
 *
 * @param[out]      pSig        展開先(64byte)
 * @param[in]       pBuf        DER形式秘密鍵
 * @retval      true    成功
 * @note
 *      - SIGHASH_ALLのチェックは行わない
 */
bool HIDDEN ln_misc_sigtrim(uint8_t *pSig, const uint8_t *pBuf);


/** 64bit形式秘密鍵をDER形式展開
 *
 * @param[out]      pSig        展開先(DER形式秘密鍵)
 * @param[in]       pBuf        64byte形式秘密鍵
 * @note
 *      - SIGHASH_ALLを付加する
 */
void HIDDEN ln_misc_sigexpand(ucoin_buf_t *pSig, const uint8_t *pBuf);


/** スクリプト用鍵生成/更新
 *
 * @param[in,out]   pLocal
 * @param[in,out]   pRemote
 * @note
 *      - per-commit-secret/per-commit-basepointが変更された場合に呼び出す想定
 */
void HIDDEN ln_misc_update_scriptkeys(ln_funding_local_data_t *pLocal, ln_funding_remote_data_t *pRemote);


/** channel_id生成
 *
 * @param[out]      pChannelId      生成結果
 * @param[in]       pTxid           funding-txのTXID
 * @param[in]       Index           funding-txの2-of-2 vout index
 */
void HIDDEN ln_misc_calc_channel_id(uint8_t *pChannelId, const uint8_t *pTxid, uint16_t Index);


/** short_channel_id生成
 *
 * @param[in]       Height          funding_txが取り込まれたブロックのブロック高
 * @param[in]       BIndex          funding_txが取り込まれたブロック中でのindex
 * @param[in]       VIndex          funding-txの2-of-2 vout index
 */
uint64_t HIDDEN ln_misc_calc_short_channel_id(uint32_t Height, uint32_t BIndex, uint32_t VIndex);


/** short_channel_idパラメータ取得
 *
 * @param[out]      pHeight         ブロック高
 * @param[out]      pBIndex         ブロック中でのindex
 * @param[out]      pVIndex         funding-txの2-of-2 vout index
 */
void HIDDEN ln_misc_get_short_channel_id_param(uint32_t *pHeight, uint32_t *pBIndex, uint32_t *pVIndex, uint64_t short_channel_id);

#endif /* LN_MISC_H__ */
