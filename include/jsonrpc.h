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
#ifndef JSONRPC_H__
#define JSONRPC_H__

#include "ucoind.h"


/********************************************************************
 * prototypes
 ********************************************************************/

/** jsonrpc初期化
 *
 */
void jsonrpc_init(const rpc_conf_t *pRpcConf);


/** jsonrpc終了
 *
 */
void jsonrpc_term(void);


/** [bitcoin rpc]getblockcount
 *
 * @retval      -1以外      現在のblock count
 * @retval      -1          取得失敗
 */
int jsonrpc_getblockcount(void);


/** [bitcoin rpc]confirmation数取得
 *
 * @param[in]   pTxid
 * @retval      -1以外      confirmation数
 * @retval      -1          取得失敗
 */
int jsonrpc_get_confirmation(const uint8_t *pTxid);


/** [bitcoin rpc]short_channel_idの計算に使用するパラメータ取得
 *
 * @param[out]  pBHeight    block height
 * @param[out]  pBIndex     block index
 * @param[in]   pTxid
 * @retval  true        取得成功
 */
bool jsonrpc_get_short_channel_param(int *pBHeight, int *pBIndex, const uint8_t *pTxid);


/** [bitcoin rpc]sendrawtransaction
 *
 * @param[out]  pTxid       取得したTXID(戻り値がtrue時)
 * @param[in]   pData       送信データ
 * @param[in]   Len         pData長
 * @retval  true        送信成功
 */
bool jsonrpc_sendraw_tx(uint8_t *pTxid, const uint8_t *pData, uint16_t Len);


/** [bitcoin rpc]getrawtransaction
 *
 * @param[out]  pTx         トランザクション情報
 * @param[in]   pTxid       取得するTXID
 * @retval  true        取得成功
 */
bool jsonrpc_getraw_tx(ucoin_tx_t *pTx, const uint8_t *pTxid);


/** [bitcoin rpc]gettxout
 *
 * @param[out]  *pSat           UINT64_MAX以外:取得したamount[satoshi], UINT64_MAX:取得失敗
 * @param[in]   pTxid
 * @param[in]   Txidx
 * @retval  true        取得成功
 * @note
 *      - gettxoutはunspentであるvoutのみ使用可能
 */
bool jsonrpc_getxout(uint64_t *pSat, const uint8_t *pTxid, int Txidx);


/** [bitcoin rpc]getnewaddress
 *
 * @param[out]  pAddr       生成したアドレス
 * @retval  true        取得成功
 */
bool jsonrpc_getnewaddress(char *pAddr);


/** [bitcoin rpc]dumpprivkey
 *
 * @param[out]  pWif        取得したWIF形式
 * @param[in]   pAddr       アドレス
 * @retval  true        取得成功
 */
bool jsonrpc_dumpprivkey(char *pWif, const char *pAddr);

#endif /* JSONRPC_H__ */
