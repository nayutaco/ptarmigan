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
/** @file   btc.h
 *  @brief  bitcoin offline API header
 */
#ifndef BTC_SIG_H__
#define BTC_SIG_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"

#include "btc_keys.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_FIELD            (32)                ///< secp256k1の世界
#define BTC_SZ_SIGN_RS          (64)                ///< サイズ:RS形式の署名
#define BTC_SZ_SIGN_DER_MAX     (73)                ///< DER format max

#define SIGHASH_ALL             (0x01)


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 署名計算
 *
 * @param[out]      pSig        署名結果
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPrivKey    秘密鍵
 * @return          true        成功
 *
 * @note
 *      - pSigは、成功かどうかにかかわらず#utl_buf_init()される
 *      - 成功時、pSigは #utl_buf_alloccopy() でメモリ確保するので、使用後は #utl_buf_free()で解放すること
 */
bool btc_sig_sign(utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPrivKey);


/** 署名計算(r/s)
 *
 * @param[out]      pRS         署名結果rs[64]
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPrivKey    秘密鍵
 * @return          true        成功
 */
bool btc_sig_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPrivKey);


/** 署名チェック
 *
 * @param[in]       pSig        署名(ハッシュタイプあり)
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPubKey     公開鍵
 * @return          true:チェックOK
 *
 * @note
 *      - pSigの末尾にハッシュタイプが入っていること
 */
bool btc_sig_verify(const utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPubKey);


/** 署名チェック
 *
 * @param[in]       pSig        署名(ハッシュタイプあり)
 * @param[in]       Len         length of pSig
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPubKey     公開鍵
 * @return          true:チェックOK
 *
 * @note
 *      - pSigの末尾にハッシュタイプが入っていること
 */
bool btc_sig_verify_2(const uint8_t *pSig, uint32_t Len, const uint8_t *pTxHash, const uint8_t *pPubKey);


/** 署名チェック(r/s)
 *
 * @param[in]       pRS         署名rs[64]
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPubKey     公開鍵
 * @return          true:チェックOK
 */
bool btc_sig_verify_rs(const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPubKey);


/** 公開鍵復元
 *
 * @param[out]      pPubKey
 * @param[in]       RecId       recovery ID
 * @param[in]       pRS
 * @param[in]       pTxHash
 * @retval      true    成功
 */
bool btc_sig_recover_pubkey(uint8_t *pPubKey, int RecId, const uint8_t *pRS, const uint8_t *pTxHash);


/** 公開鍵復元ID取得
 *
 * @param[out]      pRecId      recovery ID
 * @param[in]       pPubKey
 * @param[in]       pRS
 * @param[in]       pTxHash
 * @retval      true    成功
 */
bool btc_sig_recover_pubkey_id(int *pRecId, const uint8_t *pPubKey, const uint8_t *pRS, const uint8_t *pTxHash);


//XXX:
/** DER-format sig to RS-format(64bytes)
 *
 * @param[out]      pRs         RS-format 64bytes
 * @param[in]       pDer        DER-format sig
 * @param[in]       Len         length of DER-format sig
 * @retval          true        success
 */
bool btc_sig_der2rs(uint8_t *pRs, const uint8_t *pDer, uint32_t Len);


//XXX:
/** RS-format(64bytes) sig to DER-format
 *
 * @param[out]      pDer        DER-format sig
 * @param[in]       pSig        RS-format 64bytes
 * @note
 *      - append a sig hash type (SIGHASH_ALL)
 */
bool btc_sig_rs2der(utl_buf_t *pDer, const uint8_t *pRs);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_SIG_H__ */
