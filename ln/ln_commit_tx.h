/*
 *  Copyright (C) 2019, Nayuta, Inc. All Rights Reserved
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
/** @file   ln_commit_tx.h
 *  @brief  commitment transaction
 */
#ifndef LN_COMMIT_TX_H__
#define LN_COMMIT_TX_H__

#include "ln.h"
#include "ln_commit_tx_util.h"


/** create local commitment transaction
 *
 * 自分用(自分が送信することができる)commit_txの署名および受信署名のverifyを行う。
 * また、unilateral closeする際に必要となるデータを作成する。
 *      - funding_created/funding_signed受信による署名verify
 *      - commitment_signed受信による署名verify
 *      - 自分がunilateral closeを行った際に取り戻すtx作成
 *          - to_local output
 *          - 各HTLC output
 *
 *   1. to_local script作成
 *   2. HTLC情報設定
 *   3. commit_tx作成 + 署名 + txid計算
 *   4. commit_txの送金先処理
 *   5. メモリ解放
 *
 * @param[in,out]       pChannel
 * @param[in,out]       pCommitInfo
 * @param[out]          pClose              非NULL:自分がunilateral closeした情報を返す
 * @param[in]           pHtlcSigs           commitment_signedで受信したHTLCの署名(NULL時はHTLC署名無し)
 * @param[in]           NumHtlcSigs         pHtlcSigsの署名数
 * @retval      true    成功
 * @note
 *      - pubkeys[LN_BASEPOINT_IDX_PER_COMMIT]にはCommitNumに対応するper_commitment_pointが入っている前提。
 */
bool HIDDEN ln_commit_tx_create_local(
    ln_channel_t *pChannel,
    ln_commit_info_t *pCommitInfo,
    ln_close_force_t *pClose,
    const uint8_t (*pHtlcSigs)[LN_SZ_SIGNATURE],
    uint16_t NumHtlcSigs);


/** create commitment transaction info
 *
 * @param[in,out]       pCommitTxInfo
 * @param[in]           pCommitInfo
 * @param[in]           pUpdateInfo
 * @param[in]           bLocal
 * @retval              true        success
 */
bool HIDDEN ln_commit_tx_info_create(
    ln_commit_tx_info_t *pCommitTxInfo,
    const ln_commit_info_t *pCommitInfo,
    const ln_update_info_t *pUpdateInfo,
    bool bLocal);


void HIDDEN ln_commit_tx_info_free(ln_commit_tx_info_t *pCommitTxInfo);


/** 相手用 commitment transaction作成
 *
 * 相手用(相手が送信することができる)commit_txの署名、および関連するトランザクションの署名を行う。
 *      - funding_created/funding_singed用の署名作成
 *      - commitment_signed用の署名作成
 *      - 相手がunilateral closeを行った際に取り戻すtx作成
 *          - to_remote output
 *          - 各HTLC output
 *
 * 作成した署名は、To-LocalはpChannel->commit_info_remote.remote_sigに、HTLCはpChannel->update_info.htlcs[].remote_sig 代入する
 *
 *   1. to_local script作成
 *   2. HTLC情報設定
 *          - 相手がugly closeした場合のためにpreimage_hashをDB保存
 *   3. commit_tx作成 + 署名 + txid計算
 *   4. commit_txの送金先処理
 *   5. メモリ解放
 *
 * @param[in,out]       pChannel
 * @param[in,out]       pCommitInfoRemote
 * @param[out]          pClose              非NULL:相手がunilateral closeした場合の情報を返す
 * @param[out]          ppHtlcSigs          commitment_signed送信用署名(NULLの場合は代入しない)
 * @retval  true    成功
 */
bool HIDDEN ln_commit_tx_create_remote(
    const ln_channel_t *pChannel,
    ln_commit_info_t *pCommitInfoRemote,
    ln_close_force_t *pClose,
    uint8_t (**ppHtlcSigs)[LN_SZ_SIGNATURE]);


/** P2WSH署名 - 2-of-2 トランザクション更新
 *
 * @param[in,out]   pTx         TX情報
 * @param[in]       Index
 * @param[in]       KeyOrder
 * @param[in]       pSig1
 * @param[in]       pSig2
 * @param[in]       pWitScript
 * @retval          true        success
 *
 * @note
 *      - pTx
 *      - #btc_script_2of2_create_redeem_sorted()の公開鍵順序と、pSig1, pSig2の順序は同じにすること。
 *          例えば、先に自分のデータ、後に相手のデータ、など。
 */
bool ln_commit_tx_set_vin_p2wsh_2of2(
    btc_tx_t *pTx,
    int Index,
    btc_script_pubkey_order_t KeyOrder,
    const utl_buf_t *pSig1,
    const utl_buf_t *pSig2,
    const utl_buf_t *pWitScript);


bool ln_commit_tx_set_vin_p2wsh_2of2_rs(
    btc_tx_t *pTx,
    int Index,
    btc_script_pubkey_order_t KeyOrder,
    const uint8_t *pSig1,
    const uint8_t *pSig2,
    const utl_buf_t *pWitScript);


void HIDDEN ln_commit_tx_rewind_one_commit_remote(
    ln_commit_info_t *pCommitInfo, ln_update_info_t *pUpdateInfo);


#endif /* LN_COMMIT_TX_H__ */
