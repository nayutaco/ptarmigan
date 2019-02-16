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
/** @file   ln_comtx_util.h
 *  @brief  ln_comtx_util
 */
#ifndef LN_COMTX_INFO_H__
#define LN_COMTX_INFO_H__

#include <stdint.h>
#include <stdbool.h>

#include "utl_common.h"

#include "btc_sw.h"

#include "ln_derkey_ex.h"

//XXX: unit test


/********************************************************************
 * macros
 ********************************************************************/

/** @def    LN_SEQUENCE(obs)
 *  @brief  obscured commitment numberから<sequence>算出
 */
#define LN_SEQUENCE(obs)        ((uint32_t)(0x80000000 | (((obs) >> 24) & 0xffffff))) //[0x80][upper 3bytes]


/** @def    LN_LOCKTIME(obs)
 *  @brief  obscured commitment numberから<locktime>算出
 */
#define LN_LOCKTIME(obs)        ((uint32_t)(0x20000000 | ((obs) & 0xffffff)))         //[0x20][lower 3bytes]


/********************************************************************
 * typedefs
 ********************************************************************/

/** @enum   ln_comtx_output_type_t
 *  @brief  commitment transaction output type
 */
typedef enum {
    LN_COMTX_OUTPUT_TYPE_NONE,                              ///< 未設定
    LN_COMTX_OUTPUT_TYPE_OFFERED,                           ///< Offered HTLC
    LN_COMTX_OUTPUT_TYPE_RECEIVED,                          ///< Received HTLC
    LN_COMTX_OUTPUT_TYPE_TO_LOCAL    = UINT16_MAX - 1,      ///< vout=to_local
    LN_COMTX_OUTPUT_TYPE_TO_REMOTE   = UINT16_MAX,          ///< vout=to_remote
} ln_comtx_output_type_t;


/** @struct ln_comtx_base_fee_info_t
 *  @brief  base fee info
 */
typedef struct {
    uint32_t        feerate_per_kw;                 ///< [IN]1000byte辺りのsatoshi
    uint64_t        dust_limit_satoshi;             ///< [IN]dust_limit_satoshi

    uint64_t        htlc_success_fee;               ///< [CALC]HTLC success Transaction FEE
    uint64_t        htlc_timeout_fee;               ///< [CALC]HTLC timeout Transaction FEE
    uint64_t        commit_fee;                     ///< [CALC]Commitment Transaction FEE
    uint64_t        _rough_actual_fee;              ///< [CALC] XXX: this is not actual fee. Trimmed to_local/to_remote are not reflected
} ln_comtx_base_fee_info_t;


/** @struct ln_comtx_htlc_info_t
 *  @brief  HTLC情報
 */
typedef struct {
    ln_comtx_output_type_t  type;                   ///< HTLC種別
    uint16_t        add_htlc_idx;                   ///< 対応するpChannel->cnl_add_htlc[]のindex値
    uint32_t        cltv_expiry;                    ///< cltv_expiry
    uint64_t        amount_msat;                    ///< amount_msat
    const uint8_t   *payment_hash;                  ///< preimage hash
    utl_buf_t       wit_script;                     ///< witness script
} ln_comtx_htlc_info_t;


/** @struct ln_comtx_info_t
 *  @brief  Commitment Transaction生成用情報
 */
typedef struct {
    uint64_t                    local_msat;
    uint64_t                    remote_msat;
    struct {
        const uint8_t           *txid;                  ///< funding txid
        uint32_t                txid_index;             ///< funding txid index
        uint64_t                satoshi;                ///< funding satoshi
        const utl_buf_t         *p_wit_script;          ///< funding tx witness script
    } fund;
    struct {
        uint64_t                satoshi;                ///< local satoshi
        utl_buf_t               wit_script;             ///< to-local witness script
    } to_local;
    struct {
        uint64_t                satoshi;                ///< remote satoshi
        const uint8_t           *pubkey;                ///< remote pubkey(to-remote用)
    } to_remote;
    uint64_t                    obscured_commit_num;    ///< Obscured Commitment Number
    ln_comtx_htlc_info_t        **pp_htlc_info;         ///< HTLC infos
    uint16_t                    num_htlc_infos;          ///< num of HTLC infos
    uint16_t                    num_htlc_outputs;       ///< num of HTLC (non-trimmed) outputs
    ln_comtx_base_fee_info_t    base_fee_info;
    bool                        b_trimmed;              ///< trimmed?
} ln_comtx_info_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** Obscured Commitment Number計算
 *
 * @param[in]       pOpenPayBasePt     payment_basepoint from open_channel
 * @param[in]       pAcceptPayBasePt   payment_basepoint from accept_channel
 * @return      Obscured Commitment Number Base
 */
uint64_t HIDDEN ln_comtx_calc_obscured_commit_num_mask(const uint8_t *pOpenPayBasePt, const uint8_t *pAcceptPayBasePt);


uint64_t HIDDEN ln_comtx_calc_obscured_commit_num(uint64_t ObscuredCommitNumBase, uint64_t CommitNum);


uint64_t HIDDEN ln_comtx_calc_commit_num_from_tx(uint32_t Sequence, uint32_t Locktime, uint64_t ObscuredCommitNumBase);


/** HTLC情報初期化
 *
 *
 */
void HIDDEN ln_comtx_htlc_info_init(ln_comtx_htlc_info_t *pHtlcInfo);


/** HTLC情報初期化
 *
 *
 */
void HIDDEN ln_comtx_htlc_info_free(ln_comtx_htlc_info_t *pHtlcInfo);


/** calc base fee
 *
 * feerate_per_kw, dust_limit_satoshiおよびHTLC情報から、HTLCおよびcommit txのFEEを算出する。
 *
 * @param[in,out]   pBaseFeeInfo    FEE情報
 * @param[in]       ppHtlcInfo      HTLC情報ポインタ配列
 * @param[in]       Num             HTLC数
 *
 * @note
 *      - pFeeInfoにfeerate_per_kwとdust_limit_satoshiを代入しておくこと
 */
void HIDDEN ln_comtx_base_fee_calc(
    ln_comtx_base_fee_info_t *pBaseFeeInfo,
    const ln_comtx_htlc_info_t **ppHtlcInfo,
    int Num);


/** Commitment Transaction作成
 *
 * @param[out]      pTx         TX情報
 * @param[out]      pSig        local署名
 * @param[in]       pComTxInfoTrimmed   Commitment Transaction情報
 * @param[in]       pLocalKeys
 * @return      true:成功
 */
bool HIDDEN ln_comtx_create(
    btc_tx_t *pTx, utl_buf_t *pSig, const ln_comtx_info_t *pComTxInfoTrimmed, const ln_derkey_local_keys_t *pLocalKeys);


bool HIDDEN ln_comtx_create_rs(
    btc_tx_t *pTx, uint8_t *pSig, const ln_comtx_info_t *pComTxInfoTrimmed, const ln_derkey_local_keys_t *pLocalKeys);


void HIDDEN ln_comtx_info_sub_fee_and_trim_outputs(ln_comtx_info_t *pComTxInfo, bool ToLocalIsFounder);


uint16_t HIDDEN ln_comtx_info_get_num_htlc_outputs(ln_comtx_info_t *pComTxInfoTrimmed);


#endif /* LN_COMTX_INFO_H__ */
