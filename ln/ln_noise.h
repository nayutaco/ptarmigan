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
/** @file   ln_noise.h
 *  @brief  [LN]noise関連
 */
#ifndef LN_NOISE_H__
#define LN_NOISE_H__

#include "btc_keys.h"


/** @struct ln_noise_ctx_t
 *  @brief  BOLT#8 protocol
 */
typedef struct {
    uint8_t         key[BTC_SZ_PRIVKEY];            ///< key
    uint64_t        nonce;                          ///< nonce
    uint8_t         ck[BTC_SZ_HASH256];             ///< chainkey
} ln_noise_ctx_t;


/** @struct ln_noise_t
 *  @brief  BOLT#8 protocol
 */
typedef struct {
    ln_noise_ctx_t      send_ctx;                     ///< [NOIS_01]noise protocol
    ln_noise_ctx_t      recv_ctx;                     ///< [NOIS_02]noise protocol
    void            *p_handshake;                   ///< [NOIS_03]
} ln_noise_t;

/********************************************************************
 * prototypes
 ********************************************************************/

/** noise handshake初期化
 *
 * @param[in,out]       pCtx        channel情報
 * @param[in]           pNodeId     送信側:接続先ノードID, 受信側:NULL
 * @retval      true    成功
 */
bool ln_noise_handshake_init(ln_noise_t *pCtx, const uint8_t *pNodeId);


/** noise handshake開始
 *
 * @param[in,out]       pCtx        channel情報
 * @param[out]          pBuf        送信データ(Act One)
 * @param[in]           pNodeId     接続先ノードID(受信側はNULL)
 * @retval      true    成功
 * @attention
 *      - #ln_noise_handshake_init() で送信側になっていること
 */
bool ln_noise_handshake_start(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pNodeId);


/** noise handshake受信
 *
 * @param[in,out]       pCtx        channel情報
 * @param[out]          pBuf        送信データ(Act Two/Three)
 * @retval      true    成功
 */
bool ln_noise_handshake_recv(ln_noise_t *pCtx, utl_buf_t *pBuf);


/** noise handshake状態取得
 *
 * @param[in,out]       pCtx        channel情報
 * @retval      true    handshake中
 * @retval      false   未handshake or handshake済み
 * @note
 *      - #ln_noise_handshake_init() すると handshake中になる
 */
bool ln_noise_handshake_state(ln_noise_t *pCtx);


/** noise handshakeメモリ解放
 *
 * @note
 *      - handshakeを中断した場合に呼び出す
 */
void ln_noise_handshake_free(ln_noise_t *pCtx);


/**
 *
 */
bool ln_noise_enc(ln_noise_t *pCtx, utl_buf_t *pBufEnc, const utl_buf_t *pBufIn);


/**
 *
 */
uint16_t ln_noise_dec_len(ln_noise_t *pCtx, const uint8_t *pData, uint16_t Len);


/**
 *
 */
bool ln_noise_dec_msg(ln_noise_t *pCtx, utl_buf_t *pBuf);


#endif /* LN_NOISE_H__ */
