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


/********************************************************************
 * prototypes
 ********************************************************************/

/** initialize bitcoin access
 *
 * @retval  true        success
 */
bool btcrpc_init(const rpc_conf_t *pRpcConf);


/** terminate bitcoin access
 *
 */
void btcrpc_term(void);


/** [bitcoin IF]getblockcount
 *
 * @param[out]  *pBlockCount    current block count
 * @retval  true        success
 */
bool btcrpc_getblockcount(int32_t *pBlockCount);


/** [bitcoin IF]get genesis blockhash
 *
 * @param[out]  pHash       genesis blockhash
 * @retval  true        success
 */
bool btcrpc_getgenesisblock(uint8_t *pHash);


/** [bitcoin IF]transaction confirmation
 *
 * @param[out]  pConfm      confirmations(on success)
 * @param[in]   pTxid       target TXID
 * @retval  true        success
 * @retval  false       fail
 */
bool btcrpc_get_confirmations(uint32_t *pConfm, const uint8_t *pTxid);


/** [bitcoin IF]get short_channel_id calculation parameter
 *
 * @param[in]   pPeerId
 * @param[out]  pBHeight    block height
 * @param[out]  pBIndex     block index
 * @param[out]  pMinedHash  mined blockhash
 * @param[in]   pTxid       target TXID
 * @retval  true        success
 */
bool btcrpc_get_short_channel_param(const uint8_t *pPeerId, int32_t *pBHeight, int32_t *pBIndex, uint8_t *pMinedHash, const uint8_t *pTxid);


/** [bitcoin IF]get TXID from short_channel_id parameter
 *
 * @param[out]  pTxid       TXID
 * @param[in]   BHeight     block height
 * @param[in]   BIndex      block index
 * @retval  true        success
 */
bool btcrpc_gettxid_from_short_channel(uint8_t *pTxid, int BHeight, int BIndex);


/** [bitcoin IF]search outpoint matched transaction from blocks
 *
 * @param[out]  pTx         transaction
 * @param[in]   Blks        number of blocks
 * @param[in]   pTxid       search vin[0]
 * @param[in]   VIndex      vout index
 * @retval  true        success
 * @retval  false   search fail or bitcoind error
 * @note
 *      - search only pTxid.vin_cnt equals 1
 */
bool btcrpc_search_outpoint(btc_tx_t *pTx, uint32_t Blks, const uint8_t *pTxid, uint32_t VIndex);


/** [bitcoin IF]search transactions matched scriptPubKey from blocks
 *
 * @param[out]  pTxBuf      transaction array(pTxBuf->buf = btc_tx_t[])
 * @param[in]   Blks        number of blocks
 * @param[in]   pVout       search scriptPubKey array(pVout->buf = utl_buf_t[])
 * @retval  true        success
 * @retval  false   search fail or bitcoind error
 * @attention
 *      - be caseful of pTxBuf.
 *          - number of transactions equal `pTxBuf->len / sizeof(btc_tx_t)`.
 *          - after using, clear each `btc_tx_t` and clear `utl_buf_t`
 *      - process continue if getrawtransaction failed
 */
bool btcrpc_search_vout(utl_buf_t *pTxBuf, uint32_t Blks, const utl_buf_t *pVout);


/** [bitcoin IF]signrawtransaction for funding transaction
 * @param[in,out]  pTx      (in)[SPV]vout[0]=scriptPubKey, (out)signed transaction
 * @param[in]   pData       [bitcoind]raw transaction, [SPV]ignore
 * @param[in]   Len         [bitcoind]pData length, [SPV]ignore
 * @param[in]   Amount      [bitcoind]fundin amount, [SPV]ignore
 * @retval  true        success
 */
bool btcrpc_sign_fundingtx(btc_tx_t *pTx, const uint8_t *pData, uint32_t Len, uint64_t Amount);


/** [bitcoin IF]sendrawtransaction
 *
 * @param[out]  pTxid       sent TXID
 * @param[out]  pCode       (unused)error code(if not NULL)
 * @param[in]   pRawData    raw transaction data
 * @param[in]   Len         pRawData length
 * @retval  true        success
 */
bool btcrpc_send_rawtx(uint8_t *pTxid, int *pCode, const uint8_t *pRawData, uint32_t Len);


/** [bitcoin IF]check TXID is broadcasted
 *
 * @param[in]   pTxid       TXID
 * @retval  true        broadcasted(including mempool)
 */
bool btcrpc_is_tx_broadcasted(const uint8_t *pTxid);


/** [bitcoin IF]vout unspent確認
 *
 * @param[out]  pUnspent        (success and not NULL)true:unspent
 * @param[out]  pSat            [bitcoind](success and not NULL)amount[satoshi]
 * @param[in]   pTxid
 * @param[in]   VIndex
 * @retval  true        success
 */
bool btcrpc_check_unspent(const uint8_t *pPeerId, bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex);


/** [bitcoin IF]getnewaddress
 *
 * @param[out]  pAddr       address
 * @retval  true        success
 */
bool btcrpc_getnewaddress(char pAddr[BTC_SZ_ADDR_STR_MAX + 1]);


/** [bitcoin IF]estimatefee
 *
 * @param[out]  pFeeSatoshi estimated fee-per-kilobytes[satoshi]
 * @param[in]   nBlocks     blocks
 * @retval  true        success
 */
bool btcrpc_estimatefee(uint64_t *pFeeSatoshi, int nBlocks);


/** [bitcoin IF]set blockhash at node creation
 * 
 * @param[in]   pHash   blockhash
 * @note
 *  - limitation going backwards for searching blocks in bitcoinj
 */
void btcrpc_set_creationhash(const uint8_t *pHash);


/** [bitcoin IF]add channel information
 *
 * @param[in]   pPeerId
 * @param[in]   ShortChannelId  (not change if 0)
 * @param[in]   pFundingTxid    funding txid
 * @param[in]   FundingIdx      funding vout index
 * @param[in]   pRedeemScript   funding_txのvout
 * @param[in]   pMinedHash      funding_tx mined blockhash(not change if NULL)
 * @param[in]   LastConfirm     last checked funding_tx confirmation
 */
void btcrpc_set_channel(const uint8_t *pPeerId,
                uint64_t ShortChannelId,
                const uint8_t *pFundingTxid,
                int FundingIdx,
                const utl_buf_t *pRedeemScript,
                const uint8_t *pMinedHash,
                uint32_t LastConfirm);


/** [bitcoin IF]delete channel watching
 * delete watch channel added by #btcrpc_set_channel()
 *
 * @param[in]   pPeerId
 */
void btcrpc_del_channel(const uint8_t *pPeerId);


/** [bitcoin IF]set monitoring TXID(commitment transaction)
 *
 * @param[in]   pChannel
 */
void btcrpc_set_committxid(const ln_channel_t *pChannel);


/** [bitcoin IF]getbalance
 *
 * @param[out]  pAmount
 * @retval  true        success
 */
bool btcrpc_get_balance(uint64_t *pAmount);


/** [bitcoin IF]send all amounts
 * 
 * @param[out]  pTxid
 * @param[in]   pAddr
 * @retval  true        success
 */
bool btcrpc_empty_wallet(uint8_t *pTxid, const char *pAddr);

#endif /* BTCRPC_H__ */
