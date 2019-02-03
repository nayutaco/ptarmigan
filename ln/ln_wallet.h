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
/** @file   ln_wallet.h
 *  @brief  ln_wallet
 */
#ifndef LN_WALLET_H__
#define LN_WALLET_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln_htlctx.h"
#include "ln.h"
//XXX: unit test

/********************************************************************
 * prototypes
 ********************************************************************/

/** to_localをwalletに保存する情報作成
 *
 *  btc_tx_tフォーマットだが、blockchainに展開できるデータではない
 *      - vin: pTxid:Index, witness([0]=secret
 *      - vout: input value
 *
 * @param[in]           pChannel        channel info
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount
 * @param[in]           ToSelfDelay     to_self_delay
 * @param[in]           pScript         送金先スクリプト
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @param[in]           bRevoked        true:revoked transaction close対応
 * @retval  true    成功
 */
bool ln_wallet_create_to_local(
    const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value, uint32_t ToSelfDelay,
    const utl_buf_t *pScript, const uint8_t *pTxid, int Index, bool bRevoked);


/** to_remoteをwalletに保存する情報作成
 *
 *  btc_tx_tフォーマットだが、blockchainに展開できるデータではない
 *      - vin: pTxid:Index, witness([0]=secret
 *      - vout: input value
 *
 * @param[in]           pChannel        channel info
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @retval  true    成功
 * @note
 *  - 処理の都合上utl_tx_tの形を取るが、展開してはいけない
 *      - vin: pTxid:Index
 *      - vout: value, secret
 */
bool ln_wallet_create_to_remote(
    const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value, const uint8_t *pTxid, int Index);


bool HIDDEN ln_wallet_script_to_local_set_vin0(
    btc_tx_t *pTx, const btc_keys_t *pKey, const utl_buf_t *pWitScript, bool bRevoked);


bool HIDDEN ln_wallet_script_to_remote_set_vin0(btc_tx_t *pTx, const btc_keys_t *pKey);


bool HIDDEN ln_wallet_htlctx_set_vin(
    btc_tx_t *pTx,
    const uint8_t *pHtlcPrivKey,
    const uint8_t *pPreimage,
    const utl_buf_t *pWitScript,
    ln_htlctx_sig_type_t HtlcSigType);


#endif /* LN_WALLET_H__ */
