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
/** @file   ln_funding_info.h
 *  @brief  ln_funding
 */
#ifndef LN_FUNDING_INFO_H__
#define LN_FUNDING_INFO_H__

#include <stdint.h>
#include <stdbool.h>

#include "btc_tx.h"
#include "btc_script.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define LN_FUNDING_SATOSHIS_MIN         (1000)      ///< minimum funding_sat(BOLTに規定はない)
#define LN_FUNDING_SATOSHIS_MAX         (0x1000000 - 1) //2^24-1


#define LN_FUNDING_ROLE_FUNDEE                      (0x00)
#define LN_FUNDING_ROLE_FUNDER                      (0x01)


#define LN_FUNDING_STATE_STATE_NO_ANNO_CH           (1 << 0)    ///< 1:announcement_signatures未送信(後で送信する) / 0:announcement_signatures送信不要 or 送信済み(もう送信しない)
#define LN_FUNDING_STATE_STATE_FUNDING              (1 << 1)    ///< 1:open_channel -> funding_lockedまで
#define LN_FUNDING_STATE_STATE_OPENED               (1 << 7)    ///< 1:opened


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef uint8_t ln_funding_role_t;


typedef uint8_t ln_funding_state_t;


/** @struct ln_funding_info_t
 *  @brief  funding info
 */
typedef struct {
    ln_funding_role_t           role;
    ln_funding_state_t          state;
    uint8_t                     txid[BTC_SZ_TXID];      ///< funding-tx TXID
    uint16_t                    txindex;                ///< funding-tx index
    utl_buf_t                   wit_script;             ///< Witness Script of vout (2-of-2)
    btc_script_pubkey_order_t   key_order;              ///< key order of 2-of-2
    uint64_t                    funding_satoshis;       ///< funding_satoshis
    btc_tx_t                    tx_data;                ///< funding_tx
    uint32_t                    minimum_depth;          ///< minimum_depth
} ln_funding_info_t;


/**************************************************************************
 * public functions
 **************************************************************************/

void ln_funding_info_set_txid(ln_funding_info_t *pFundingInfo, const uint8_t *pTxid);


/** funding_txのTXID取得
 *
 * @param[in]           pFundingInfo        funding info
 * @return      funding_txのTXID
 */
const uint8_t *ln_funding_info_txid(const ln_funding_info_t *pFundingInfo);


/** funding_txのTXINDEX取得
 *
 * @param[in]           pFundingInfo        funding info
 * @return      funding_txのTXINDEX
 */
uint32_t ln_funding_info_txindex(const ln_funding_info_t *pFundingInfo);


const utl_buf_t *ln_funding_info_wit_script(const ln_funding_info_t *pFundingInfo);


/** minimum_depth
 *
 * @param[in]           pFundingInfo        funding info
 * @return      accept_channelで受信したminimum_depth
 */
uint32_t ln_funding_info_minimum_depth(const ln_funding_info_t *pFundingInfo);


/** funderかどうか
 *
 * @param[in]           pFundingInfo        funding info
 * @retval      true    funder
 * @retval      false   fundee
 */
bool ln_funding_info_is_funder(const ln_funding_info_t *pFundingInfo, bool bLocal);


/** funding中かどうか
 *
 * @param[in]           pFundingInfo        funding info
 * @retval      true    fundingしている
 * @retval      false   fundingしていない(未funding or funding済み)
 */
bool ln_funding_info_funding_now(const ln_funding_info_t *pFundingInfo);


/** funding_tx
 *
 * @param[in]           pFundingInfo        funding info
 * @return      funding_tx
 */
const btc_tx_t *ln_funding_info_tx(const ln_funding_info_t *pFundingInfo);


#endif /* LN_FUNDING_INFO_H__ */
