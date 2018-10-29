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
/** @file   btc_local.h
 *  @brief  libbtc内インターフェース
 */
#ifndef BTC_LOCAL_H__
#define BTC_LOCAL_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef PTARM_USE_RNG
#include "mbedtls/ctr_drbg.h"
#endif  //PTARM_USE_RNG

#include "utl_common.h"
#include "btc.h"
#define LOG_TAG "BTC"
#include "utl_log.h"


/**************************************************************************
 * macros
 **************************************************************************/


/**************************************************************************
 * macro functions
 **************************************************************************/


/**************************************************************************
 * package variables
 **************************************************************************/

extern uint8_t  HIDDEN mPref[BTC_PREF_MAX];
extern bool     HIDDEN mNativeSegwit;
#ifdef PTARM_USE_RNG
extern mbedtls_ctr_drbg_context HIDDEN mRng;
#endif  //PTARM_USE_RNG


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 圧縮された公開鍵をkeypairに展開する
 *
 * @param[in]       pPubKey     圧縮された公開鍵
 * @return      0   成功
 * @note
 *      - https://bitcointalk.org/index.php?topic=644919.0
 *      - https://gist.github.com/flying-fury/6bc42c8bb60e5ea26631
 */
int HIDDEN btcl_util_set_keypair(void *pKeyPair, const uint8_t *pPubKey);


/** PubKeyHashをBitcoinアドレスに変換
 *
 * @param[out]      pAddr           変換後データ(BTC_SZ_ADDR_MAX以上のサイズを想定)
 * @param[in]       pPubKeyHash     対象データ(最大BTC_SZ_PUBKEY)
 * @param[in]       Prefix          BTC_PREF_xxx
 * @note
 *      - Prefixが #BTC_PREF_NATIVE の場合、pPubKeyHashはwitness program(20byte)
 *      - Prefixが #BTC_PREF_NATIVE_SH の場合、pPubKeyHashはwitness program(32byte)
 */
bool HIDDEN btcl_util_keys_pkh2addr(char *pAddr, const uint8_t *pPubKeyHash, uint8_t Prefix);


/** トランザクションデータ作成
 *
 * @param[out]      pBuf            変換後データ
 * @param[in]       pTx             対象データ
 * @param[in]       enableSegWit    false:pTxがsegwitでも、witnessを作らない(TXID計算用)
 *
 * @note
 *      - 動的にメモリ確保するため、pBufは使用後 #utl_buf_free()で解放すること
 *      - vin cntおよびvout cntは 252までしか対応しない(varint型の1byteまで)
 */
bool HIDDEN btcl_util_create_tx(utl_buf_t *pBuf, const btc_tx_t *pTx, bool enableSegWit);


/** vout追加(pubkey)
 *
 */
void HIDDEN btcl_util_add_vout_pub(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey, uint8_t Pref);


/** vout追加(pubkeyhash)
 *
 */
void HIDDEN btcl_util_add_vout_pkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash, uint8_t Pref);


/** varint型のデータ長サイズ取得
 *
 * @param[in]   Len         データ長(16bit長まで)
 * @return      varint型のデータ長サイズ
 *
 * @note
 *      - 補足:<br/>
 *          varint型はデータ長＋データという構成になっているが、データ長のサイズが可変になっている。<br/>
 *          データ長が0～0xfcまでは1バイト、0xfd～0xffffまでは3バイト、などとなる。<br/>
 *              https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
 */
int HIDDEN btcl_util_get_varint_len(uint32_t Len);


/** varint型のデータ長設定
 *
 * @param[out]      pData       設定先
 * @param[in]       pOrg        データ先頭(isScript==trueのみ)
 * @param[in]       Len         pOrg長
 * @param[in]       isScript    true:スクリプト作成中
 * @return      varintデータ長サイズ
 *
 * @note
 *      - pDataにvarint型のデータ長だけ書込む。pDataから戻り値だけ進んだところにpOrgを書込むとよい。
 */
int HIDDEN btcl_util_set_varint_len(uint8_t *pData, const uint8_t *pOrg, uint32_t Len, bool isScript);

#endif /* BTC_LOCAL_H__ */
