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

#include "ptarmd.h"


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
 * @retval  true        初期化成功
 */
bool btcrpc_init(const rpc_conf_t *pRpcConf);


/** jsonrpc終了
 *
 */
void btcrpc_term(void);


/** [bitcoin IF]getblockcount
 *
 * @retval  true        取得成功
 */
bool btcrpc_getblockcount(int32_t *pBlkCnt);


/** [bitcoin IF]genesis blockhash取得
 *
 * @param[out]  pHash       取得したBlockHash
 * @retval  true        取得成功
 */
bool btcrpc_getgenesisblock(uint8_t *pHash);


/** [bitcoin IF]funding_txのconfirmation数取得
 *
 * @param[in]   self        取得対象のchannel
 * @param[out]  confirmation数
 * @retval  true        取得成功
 */
bool btcrpc_get_confirm(uint32_t *pConfirm, const uint8_t *pTxid);


/** [bitcoin IF]short_channel_idの計算に使用するパラメータ取得
 *
 * @param[in]   self
 * @param[out]  pBHeight    block height
 * @param[out]  pBIndex     block index(pTxidの位置)
 * @param[out]  pMinedHash  miningされたblock hash
 * @param[in]   pTxid       検索するTXID
 * @retval  true        取得成功
 */
bool btcrpc_get_short_channel_param(const ln_self_t *self, int *pBHeight, int *pBIndex, uint8_t *pMinedHash, const uint8_t *pTxid);


#ifndef USE_SPV
/** [bitcoin IF]short_channel_idパラメータからtxid取得
 *
 * @param[out]  pTxid       該当するtxid
 * @param[in]   BHeight     block height
 * @param[in]   BIndex      block index
 * @retval  true        取得成功
 */
bool btcrpc_gettxid_from_short_channel(uint8_t *pTxid, int BHeight, int BIndex);
#endif


/** [bitcoin IF]複数blockからvin[0]のoutpointが一致するトランザクションを検索
 *
 * @param[out]  pTx         トランザクション情報
 * @param[in]   Blks        検索対象とする過去ブロック数
 * @param[in]   pTxid       検索するTXID
 * @param[in]   VIndex      vout index
 * @retval  true    検索成功
 * @retval  false   検索失敗 or bitcoindエラー
 * @note
 *      - 検索するvinはvin_cnt==1のみ
 */
bool btcrpc_search_outpoint(btc_tx_t *pTx, uint32_t Blks, const uint8_t *pTxid, uint32_t VIndex);


/** [bitcoin IF]複数blockからvout[0]のscriptPubKeyが一致するトランザクションを検索
 *
 * @param[out]  pTxBuf      トランザクション情報(btc_tx_tの配列を保存する)
 * @param[in]   Blks        検索対象とする過去ブロック数
 * @param[in]   pVout       検索するscriptPubKey配列(utl_buf_tの配列)
 * @retval  true    検索成功
 * @retval  false   検索失敗 or bitcoindエラー
 * @note
 *      - pTxBufの扱いに注意すること
 *          - 成功時、btc_tx_tが複数入っている可能性がある(個数は、pTxBuf->len / sizeof(btc_tx_t))
 *          - クリアする場合、各btc_tx_tをクリア後、utl_buf_tをクリアすること
 *      - 内部処理(getrawtransaction)に失敗した場合でも、処理を継続する
 */
bool btcrpc_search_vout(utl_buf_t *pTxBuf, uint32_t Blks, const utl_buf_t *pVout);


/** [bitcoin IF]signrawtransaction
 * @param[out]  pTx         トランザクション情報
 * @param[in]   pData       [bitcoind]トランザクションRAWデータ, [SPV]scriptPubKey
 * @param[in]   Len         pData長
 * @param[in]   Amount      送金額(bitcoindの場合は無視)
 * @retval  true        成功
 * @note
 *      - funding_txへの署名を想定(scriptPubKeyは2-of-2)
 *      - pTxは戻り値がtrueの場合のみ更新する
 */
bool btcrpc_signraw_tx(btc_tx_t *pTx, const uint8_t *pData, size_t Len, uint64_t Amount);


/** [bitcoin IF]sendrawtransaction
 *
 * @param[out]  pTxid       取得したTXID(戻り値がtrue時)
 * @param[out]  pCode       結果コード(BTCRPC_ERR_xxx)
 * @param[in]   pRawData    トランザクションRAWデータ
 * @param[in]   Len         pRawData長
 * @retval  true        送信成功
 */
bool btcrpc_sendraw_tx(uint8_t *pTxid, int *pCode, const uint8_t *pRawData, uint32_t Len);


/** [bitcoin IF]トランザクション展開済み確認
 *
 * @param[in]   pTxid       取得するTXID(バイト列)
 * @retval  true        トランザクション展開済み(mempool含む)
 */
bool btcrpc_is_tx_broadcasted(const uint8_t *pTxid);


/** [bitcoin IF]vout unspent確認
 *
 * @param[out]  pUnspent        (成功 and 非NULL時)true:unspent
 * @param[out]  pSat            (成功 and 非NULL時)取得したamount[satoshi]
 * @param[in]   pTxid
 * @param[in]   VIndex
 * @retval  true        取得成功
 */
bool btcrpc_check_unspent(bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex);


/** [bitcoin IF]getnewaddress
 *
 * @param[out]  pAddr       address
 * @retval  true        取得成功
 */
bool btcrpc_getnewaddress(char pAddr[BTC_SZ_ADDR_MAX]);


/** [bitcoin IF]estimatefee
 *
 * @param[out]  pFeeSatoshi estimated fee-per-kilobytes[satoshi]
 * @param[in]   予想するブロック数
 * @retval  true        取得成功
 */
bool btcrpc_estimatefee(uint64_t *pFeeSatoshi, int nBlocks);


#ifndef USE_SPV
#else
/** [bitcoin IF]channel追加
 * DBから復元することを想定している。
 * 必要であればbtcrpc_set_fundingtx()を内部で呼び出す。
 *
 * @param[in]   self
 * @param[in]   shortChannelId  short_channel_id(-1:デフォルト値)
 * @param[in]   pTxBuf          raw funding_tx(NULL:デフォルト値)
 * @param[in]   Len             pTx長(pTxBuf==NULL:デフォルト値)
 * @param[in]   bUnspent        true:funding_txがunspent(pTxBuf==NULL:デフォルト値)
 * @param[in]   pMinedHash      funding_txがマイニングされたblock hash(NULL:デフォルト値)
 */
void btcrpc_add_channel(const ln_self_t *self, uint64_t shortChannelId, const uint8_t *pTxBuf, uint32_t Len, bool bUnspent, const uint8_t *pMinedHash);


/** [bitcoin IF]funding_tx通知
 * funding_tx展開直後に呼び出す。
 *
 * @param[in]   pTxBuf
 * @param[in]   Len
 */
void btcrpc_set_fundingtx(const ln_self_t *self, const uint8_t *pTxBuf, uint32_t Len);


/** [bitcoin IF]監視TXID設定
 *
 * @param[in]   self
 */
void btcrpc_set_committxid(const ln_self_t *self);
#endif

#endif /* BTCRPC_H__ */
