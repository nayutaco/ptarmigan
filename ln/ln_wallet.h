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
/** @file   ln_wallet.h
 *  @brief  ln_wallet
 */
#ifndef LN_WALLET_H__
#define LN_WALLET_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln_htlc_tx.h"


/********************************************************************
 * prototypes
 ********************************************************************/

/** to_localをwalletに保存する情報作成
 *
 *  btc_tx_tフォーマットだが、blockchainに展開できるデータではない
 *      - vin: pTxid:Index, witness([0]=secret
 *      - vout: input value
 *
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount
 * @param[in]           ToSelfDelay     to_self_delay
 * @param[in]           pWitScript      送金先スクリプト
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @param[in]           pKeysLocal      local keys
 * @param[in]           pKeysRemote     remote keys
 * @param[in]           pRevokedPerCommitSecOrNull  secret for revoked transaction close or NULL
 * @retval  true    成功
 */
bool ln_wallet_create_to_local(
    btc_tx_t *pTx, uint64_t Value, uint32_t ToSelfDelay,
    const utl_buf_t *pWitScript, const uint8_t *pTxid, int Index,
    const ln_derkey_local_keys_t *pKeysLocal, const ln_derkey_remote_keys_t *pKeysRemote,
    const uint8_t *pRevokedPerCommitSecOrNull);


/** to_remoteをwalletに保存する情報作成
 *
 *  btc_tx_tフォーマットだが、blockchainに展開できるデータではない
 *      - vin: pTxid:Index, witness([0]=secret
 *      - vout: input value
 *
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @param[in]           pKeysLocal      local keys
 * @param[in]           pKeysRemote     remote keys
 * @retval  true    成功
 * @note
 *  - 処理の都合上utl_tx_tの形を取るが、展開してはいけない
 *      - vin: pTxid:Index
 *      - vout: value, secret
 */
bool ln_wallet_create_to_remote(
    btc_tx_t *pTx, uint64_t Value,
    const uint8_t *pTxid, int Index,
    const ln_derkey_local_keys_t *pKeysLocal, const ln_derkey_remote_keys_t *pKeysRemote);


bool HIDDEN ln_wallet_script_to_local_set_vin0(
    btc_tx_t *pTx, const btc_keys_t *pKey, const utl_buf_t *pWitScript, bool bRevoked);


bool HIDDEN ln_wallet_script_to_remote_set_vin0(btc_tx_t *pTx, const btc_keys_t *pKey);


bool HIDDEN ln_wallet_htlc_tx_set_vin0(
    btc_tx_t *pTx,
    const uint8_t *pHtlcPrivKey,
    const uint8_t *pPreimage,
    const utl_buf_t *pWitScript,
    ln_htlc_tx_sig_type_t HtlcSigType);


#endif /* LN_WALLET_H__ */
