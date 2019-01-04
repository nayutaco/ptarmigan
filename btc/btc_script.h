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
/** @file   btc_script.h
 *  @brief  btc_script
 */
#ifndef BTC_SCRIPT_H__
#define BTC_SCRIPT_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"

#include "btc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_WITPROG_P2WPKH   (2 + BTC_SZ_HASH160)    ///< サイズ: witnessProgram(P2WPKH)
#define BTC_SZ_WITPROG_P2WSH    (2 + BTC_SZ_HASH256)    ///< サイズ: witnessProgram(P2WSH)


/**************************************************************************
 * macro functions
 **************************************************************************/


/**************************************************************************
 * package variables
 **************************************************************************/


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 種類に応じたscriptPubKey設定
 *
 * @param[out]      pScriptPk
 * @param[in]       pPubKeyHash
 * @param[in]       Prefix
 * @return      true:success
 */
bool btc_scriptpk_create(utl_buf_t *pScriptPk, const uint8_t *pPubKeyHash, int Prefix);


//XXX: comment
bool btc_scriptsig_create_p2pkh(utl_buf_t *pScriptSig, const utl_buf_t *pSig, const uint8_t *pPubKey);
bool btc_scriptsig_create_p2sh_multisig(utl_buf_t *pScriptSig, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem);
bool btc_scriptsig_create_p2sh_p2wpkh(utl_buf_t *pScriptSig, const uint8_t *pPubKey);
bool btc_scriptsig_create_p2sh_p2wsh(utl_buf_t *pScriptSig, const utl_buf_t *pWitScript);
bool btc_scriptsig_create_p2wsh(utl_buf_t *pScriptSig, const utl_buf_t *pWitScript);
//XXX: comment
bool btc_scriptsig_sign_p2pkh(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey);
//XXX: comment
bool btc_scriptsig_verify_p2pkh(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPubKeyHash);
bool btc_scriptsig_verify_p2pkh_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);
bool btc_scriptsig_verify_p2pkh_addr(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const char *pAddr);
bool btc_scriptsig_verify_p2sh_multisig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pScriptHash);
bool btc_scriptsig_verify_p2sh_multisig_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);
bool btc_scriptsig_verify_p2sh_multisig_addr(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const char *pAddr);
//XXX: comment
bool btc_witness_create_p2wpkh(utl_buf_t **pWitness, uint32_t *pWitItemCnt, const utl_buf_t *pSig, const uint8_t *pPubKey);
bool btc_witness_create_p2wsh(utl_buf_t **ppWitness, uint32_t *pWitItemCnt, const utl_buf_t *pWitness[], int Num);
//XXX: comment
bool btc_witness_verify_p2wsh_2of2(utl_buf_t *pWitness, uint32_t WitItemCnt, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);


/** P2WPKH署名計算で使用するScript Code取得
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pPubKey         公開鍵
 * @retval      true    成功
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_scriptcode_p2wpkh(utl_buf_t *pScriptCode, const uint8_t *pPubKey);


/** P2WSH署名計算で使用するScript Code取得
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pWitScript      witnessScript
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_scriptcode_p2wsh(utl_buf_t *pScriptCode, const utl_buf_t *pWitScript);


#ifdef PTARM_USE_PRINTFUNC
/** スクリプトの内容表示
 *
 * @param[in]       pData       表示対象
 * @param[in]       Len         pData長
 */
void btc_script_print(const uint8_t *pData, uint16_t Len);
#else
#define btc_tx_print(...)             //nothing
#define btc_tx_print_raw(...)          //nothing
#define btc_script_print(...)         //nothing
#define btc_extkey_print(...)    //nothing
#endif  //PTARM_USE_PRINTFUNC


#endif /* BTC_SCRIPT_H__ */
