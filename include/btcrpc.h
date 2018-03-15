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
#ifndef BTCRPC_H__
#define BTCRPC_H__

#include "ucoind.h"


/********************************************************************
 * macros
 ********************************************************************/

#define BTCRPC_ERR_MISSING_INPUT            (-25)
#define BTCRPC_ERR_ALREADY_BLOCK            (-27)


/********************************************************************
 * prototypes
 ********************************************************************/

/** jsonrpc初期化
 *
 */
void btcprc_init(const rpc_conf_t *pRpcConf);


/** jsonrpc終了
 *
 */
void btcprc_term(void);


/** [bitcoin rpc]getblockcount
 *
 * @retval      -1以外      現在のblock count
 * @retval      -1          取得失敗
 */
int btcprc_getblockcount(void);


/** [bitcoin rpc]blockhash取得
 *
 * @param[out]  pHash       取得したBlockHash
 * @param[in]   Height      取得するBlock Height
 * @retval  true        取得成功
 */
bool btcprc_getblockhash(uint8_t *pHash, int Height);


/** [bitcoin rpc]confirmation数取得
 *
 * @param[in]   pTxid
 * @return      confirmation数
 * @note
 *      - 取得自体が失敗した場合でも0を返す
 */
uint32_t btcprc_get_confirmation(const uint8_t *pTxid);


/** [bitcoin rpc]short_channel_idの計算に使用するパラメータ取得
 *
 * @param[out]  pBHeight    block height
 * @param[out]  pBIndex     block index(pTxidの位置)
 * @param[in]   pTxid       検索するTXID
 * @retval  true        取得成功
 */
bool btcprc_get_short_channel_param(int *pBHeight, int *pBIndex, const uint8_t *pTxid);


/** [bitcoin rpc]short_channel_idパラメータから得たTXIDのunspent状態取得
 *
 * @param[in]   BHeight     block height
 * @param[in]   BIndex      block index
 * @param@in]   VIndex      vout index
 * @retval  true        unspent状態
 * @retval  false       spent状態
 */
bool btcprc_is_short_channel_unspent(int BHeight, int BIndex, int VIndex);


/** [bitcoin rpc]blockからvin[0]が一致するtransactionを検索
 *
 * @param[out]  pTx         トランザクション情報
 * @param[in]   BHeight     block height
 * @param[in]   pTxid       検索するするTXID(バイト列)
 * @param@in]   VIndex      vout index
 * @retval  true        検索成功
 * @note
 *      - 検索するvinはvin_cnt==1のみ
 */
bool btcprc_search_txid_block(ucoin_tx_t *pTx, int BHeight, const uint8_t *pTxid, uint32_t VIndex);


/** [bitcoin rpc]blockからvoutが一致するtransactionを検索
 * @param[out]  pTxBuf      トランザクション情報(ucoin_tx_tの配列を保存する)
 * @param[in]   BHeight     block height
 * @param@in]   pVout       vout
 * @retval  true        検索成功
 */
bool btcprc_search_vout_block(ucoin_buf_t *pTxBuf, int BHeight, const ucoin_buf_t *pVout);


bool btcprc_signraw_tx(ucoin_tx_t *pTx, const uint8_t *pData, size_t Len);


/** [bitcoin rpc]sendrawtransaction
 *
 * @param[out]  pTxid       取得したTXID(戻り値がtrue時)
 * @param[out]  pCode       結果コード
 * @param[in]   pData       送信データ
 * @param[in]   Len         pData長
 * @retval  true        送信成功
 */
bool btcprc_sendraw_tx(uint8_t *pTxid, int *pCode, const uint8_t *pData, uint32_t Len);


/** [bitcoin rpc]getrawtransaction
 *
 * @param[out]  pTx         トランザクション情報
 * @param[in]   pTxid       取得するTXID(バイト列)
 * @retval  true        取得成功
 */
bool btcprc_getraw_tx(ucoin_tx_t *pTx, const uint8_t *pTxid);


/** [bitcoin rpc]getrawtransaction
 *
 * @param[out]  pTx         トランザクション情報
 * @param[in]   txid        取得するTXID(文字列)
 * @retval  true        取得成功
 */
bool btcprc_getraw_txstr(ucoin_tx_t *pTx, const char *txid);


/** [bitcoin rpc]gettxout
 *
 * @param[out]  pUnspent        true:未使用
 * @param[out]  pSat            UINT64_MAX以外:取得したamount[satoshi], UINT64_MAX:取得失敗
 * @param[in]   pTxid
 * @param[in]   Txidx
 * @retval  true        取得成功
 * @note
 *      - gettxoutはunspentであるvoutのみ使用可能
 */
bool btcprc_getxout(bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, int Txidx);


/** [bitcoin rpc]getnewaddress
 *
 * @param[out]  pAddr       生成したアドレス
 * @retval  true        取得成功
 */
bool btcprc_getnewaddress(char *pAddr);


/** [bitcoin rpc]dumpprivkey
 *
 * @param[out]  pWif        取得したWIF形式
 * @param[in]   pAddr       アドレス
 * @retval  true        取得成功
 */
//bool btcprc_dumpprivkey(char *pWif, const char *pAddr);


/** [bitcoin rpc]estimatefee
 *
 * @param[out]  pFeeSatoshi estimated fee-per-kilobytes[satoshi]
 * @param[in]   予想するブロック数
 * @retval  true        取得成功
 */
bool btcprc_estimatefee(uint64_t *pFeeSatoshi, int nBlocks);

#endif /* BTCRPC_H__ */
