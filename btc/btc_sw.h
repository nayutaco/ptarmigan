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
/** @file   btc_sw.h
 *  @brief  btc_sw
 */
#ifndef BTC_SW_H__
#define BTC_SW_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"

#include "btc_tx.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_WITPROG_P2WPKH   (2 + BTC_SZ_HASH160)    ///< サイズ: witnessProgram(P2WPKH)
#define BTC_SZ_WITPROG_P2WSH    (2 + BTC_SZ_HASH256)    ///< サイズ: witnessProgram(P2WSH)


/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * typedefs
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

/** P2WPKHのvout追加(pubkey)
 *
 * @param[in,out]   pTx
 * @param[in]       Value
 * @param[in]       pPubKey
 */
bool btc_sw_add_vout_p2wpkh_pub(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey);


/** P2WPKHのvout追加(pubKeyHash)
 *
 * @param[in,out]   pTx
 * @param[in]       Value
 * @param[in]       pPubKeyHash
 * @retval      true    成功
 */
bool btc_sw_add_vout_p2wpkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash);


/** P2WSHのvout追加(witnessScript)
 *
 * @param[in,out]   pTx
 * @param[in]       Value
 * @param[in]       pWitScript
 * @retval      true    成功
 *
 */
bool btc_sw_add_vout_p2wsh_wit(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pWitScript);


/** P2WPKH署名計算で使用するScript Code取得(vin)
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pVin            対象vin
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_sw_scriptcode_p2wpkh_vin(utl_buf_t *pScriptCode, const btc_vin_t *pVin);


/** P2WSH署名計算で使用するScript Code取得(vin)
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pVin            対象vin
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_sw_scriptcode_p2wsh_vin(utl_buf_t *pScriptCode, const btc_vin_t *pVin);


/** segwitトランザクション署名用ハッシュ値計算
 *
 * @param[out]      pTxHash             署名に使用するハッシュ値(BTC_SZ_HASH256)
 * @param[in]       pTx                 署名対象のトランザクションデータ
 * @param[in]       Index               署名するINPUTのindex番号
 * @param[in]       Value               署名するINPUTのvalue[単位:satoshi]
 * @param[in]       pScriptCode         Script Code
 * @retval  false   pTxがトランザクションとして不正
 *
 */
bool btc_sw_sighash(uint8_t *pTxHash, const btc_tx_t *pTx, uint32_t Index, uint64_t Value,
                const utl_buf_t *pScriptCode);


/** P2WPKHのwitness作成
 *
 * @param[in,out]   pTx         対象トランザクション
 * @param[in]       Index       対象vinのIndex
 * @param[in]       pSig        署名
 * @param[in]       pPubKey     公開鍵
 *
 * @note
 *      - pSigはコピーするため解放はpTxで管理しない。
 *      - mNativeSegwitがfalseの場合、scriptSigへの追加も行う
 */
bool btc_sw_set_vin_p2wpkh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSig, const uint8_t *pPubKey);


/** P2WPSHのscriptSig作成
 *
 * @param[in,out]   pTx         対象トランザクション
 * @param[in]       Index       対象vinのIndex
 * @param[in]       pWits       witnessScript
 * @param[in]       Num         pWitの数
 *
 * @note
 *      - pWitはコピーするため解放はpTxで管理しない。
 */
bool btc_sw_set_vin_p2wsh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pWits[], int Num);


/** P2WPKH署名チェック
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       Value           該当するvinのvalue
 * @param[in]       pPubKeyHash     該当するvinのPubKeyHash(P2SH)
 * @return      true:チェックOK
 *
 * @note
 *      - pPubKeyHashは、pTxの署名部分が持つ公開鍵から生成したPubKeyHashと比較する
 */
bool btc_sw_verify_p2wpkh(const btc_tx_t *pTx, uint32_t Index, uint64_t Value, const uint8_t *pPubKeyHash);


/** P2WPKH署名チェック(アドレス)
 *
 * @param[in]       pTx     チェック対象
 * @param[in]       Index   対象vin
 * @param[in]       Value   該当するvinのvalue
 * @param[in]       pAddr   Bitcoinアドレス
 * @return      true:チェックOK
 */
bool btc_sw_verify_p2wpkh_addr(const btc_tx_t *pTx, uint32_t Index, uint64_t Value, const char *pAddr);


/** 2-of-2 multisigの署名チェック
 *
 */
bool btc_sw_verify_2of2(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pVout);


#if 0   //今のところ使い道がない
bool btc_sw_wtxid(uint8_t *pWTxId, const btc_tx_t *pTx);
bool btc_sw_is_segwit(const btc_tx_t *pTx);
#endif  //0


//XXX:
/** witnessScriptをPubKeyHash(P2SH)変換
 *
 *
 */
void btc_sw_wit2prog_p2wsh(uint8_t *pWitProg, const utl_buf_t *pWitScript);


//////////////////////
//UTIL
//////////////////////

//XXX:
/** PubKeyHash(P2PKH)をPubKeyHash(P2WPKH)に変換
 *
 * [00][14][pubKeyHash] --> HASH160
 *
 * @param[out]      pWPubKeyHash    変換後データ(#BTC_SZ_HASH_MAX)
 * @param[in]       pPubKeyHash     対象データ(#BTC_SZ_HASH_MAX)
 */
void btc_util_create_pkh2wpkh(uint8_t *pWPubKeyHash, const uint8_t *pPubKeyHash);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_SW_H__ */
