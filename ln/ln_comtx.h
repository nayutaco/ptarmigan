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
/** @file   ln_comtx.h
 *  @brief  commitment transaction
 */
#ifndef LN_COMTX_H__
#define LN_COMTX_H__


/** 自分用commitment transaction作成
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
 * @param[in,out]       self
 * @param[out]          pClose              非NULL:自分がunilateral closeした情報を返す
 * @param[in]           pHtlcSigs         commitment_signedで受信したHTLCの署名(NULL時はHTLC署名無し)
 * @param[in]           HtlcSigsNum       pHtlcSigsの署名数
 * @param[in]           CommitNum           計算に使用するcommitment_number
 * @param[in]           ToSelfDelay       remoteのToSelfDelay
 * @param[in]           DustLimitSat      localのDustLimitSat
 * @retval      true    成功
 * @note
 *      - pubkeys[MSG_FUNDIDX_PER_COMMIT]にはCommitNumに対応するper_commitment_pointが入っている前提。
 */
bool HIDDEN ln_comtx_create_to_local(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *pHtlcSigs,
                    uint8_t HtlcSigsNum,
                    uint64_t CommitNum,
                    uint32_t ToSelfDelay,
                    uint64_t DustLimitSat);


/** 相手用 commitment transaction作成
 *
 * 相手用(相手が送信することができる)commit_txの署名、および関連するトランザクションの署名を行う。
 *      - funding_created/funding_singed用の署名作成
 *      - commitment_signed用の署名作成
 *      - 相手がunilateral closeを行った際に取り戻すtx作成
 *          - to_remote output
 *          - 各HTLC output
 *
 * 作成した署名は、To-Localはself->commit_remote.signatureに、HTLCはself->cnl_add_htlc[].signature 代入する
 *
 *   1. to_local script作成
 *   2. HTLC情報設定
 *          - 相手がugly closeした場合のためにpreimage_hashをDB保存
 *   3. commit_tx作成 + 署名 + txid計算
 *   4. commit_txの送金先処理
 *   5. メモリ解放
 *
 * @param[in,out]       self
 * @param[out]          pClose              非NULL:相手がunilateral closeした場合の情報を返す
 * @param[out]          ppHtlcSigs        commitment_signed送信用署名(NULLの場合は代入しない)
 * @retval  true    成功
 */
bool HIDDEN ln_comtx_create_to_remote(const ln_self_t *self,
                    ln_commit_data_t *pCommit,
                    ln_close_force_t *pClose,
                    uint8_t **ppHtlcSigs,
                    uint64_t CommitNum);


/** P2WSH署名 - 2-of-2 トランザクション更新
 *
 * @param[in,out]   pTx         TX情報
 * @param[in]       Index
 * @param[in]       Sort
 * @param[in]       pSig1
 * @param[in]       pSig2
 * @param[in]       pWit2of2
 * @return      true:成功
 *
 * @note
 *      - pTx
 *      - #btc_redeem_create_2of2_sorted()の公開鍵順序と、pSig1, pSig2の順序は同じにすること。
 *          例えば、先に自分のデータ、後に相手のデータ、など。
 */
bool HIDDEN ln_comtx_set_vin_p2wsh_2of2(btc_tx_t *pTx, int Index, btc_keys_order_t Sort,
                    const utl_buf_t *pSig1,
                    const utl_buf_t *pSig2,
                    const utl_buf_t *pWit2of2);


#endif /* LN_COMTX_H__ */
