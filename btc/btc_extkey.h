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
/** @file   btc_extkey.h
 *  @brief  btc_extkey
 */
#ifndef BTC_EXTKEY_H__
#define BTC_EXTKEY_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "btc_keys.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_EXTKEY_SEED      (64)                ///< サイズ:拡張鍵seed
#define BTC_SZ_EXTKEY           (82)                ///< サイズ:拡張鍵
#define BTC_SZ_CHAINCODE        (32)                ///< サイズ:拡張鍵chaincode
#define BTC_SZ_EXTKEY_ADDR_MAX  (112)               ///< サイズ:拡張鍵アドレス長上限

#define BTC_EXTKEY_PRIV         (0)             ///< 拡張鍵種別:秘密鍵
#define BTC_EXTKEY_PUB          (1)             ///< 拡張鍵種別:公開鍵
#define BTC_EXTKEY_HARDENED     ((uint32_t)0x80000000)  ///< 拡張鍵:hardened
#define BTC_EXTKEY_BIP_EXTERNAL (0)             ///< BIP44 Change: external chain
#define BTC_EXTKEY_BIP_INTERNAL (1)             ///< BIP44 Change: internal chain(change addresses)
#define BTC_EXTKEY_BIP_SKIP     ((uint32_t)-1)  ///< BIP44: account以降かchange以降をskipする


/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     btc_extkey_t
 *  @brief      Extended Key管理構造体
 */
typedef struct {
    uint8_t     type;                           ///<
    uint8_t     depth;                          ///<
    uint32_t    fingerprint;                    ///<
    uint32_t    child_number;                   ///<
    uint8_t     chain_code[BTC_SZ_CHAINCODE];   ///<
    uint8_t     key[BTC_SZ_PUBKEY];             ///< typeがBTC_EXTKEY_PRIVの場合、先頭の32byteが有効
} btc_extkey_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

#ifdef BTC_ENABLE_GEN_MNEMONIC
/** generate mnemonic 24words
 *
 * @return  mnemonic 24words
 * @note
 *      - call #UTL_DBG_FREE() after use
 */
char *btc_extkey_generate_mnemonic24(void);
#endif  //BTC_ENABLE_GEN_MNEMONIC

/** mnemonic words --> seed[BTC_SZ_EXTKEY_SEED]
 *
 */
bool btc_extkey_mnemonic2seed(uint8_t *pSeed, const char *pWord, const char *pPass);


/** generate BIP32 extended key
 *
 * if Type == #BTC_EXTKEY_PRIV && pSeed == NULL:<br>
 *     parent private key(pKey) --> generate child private/public keys<br>
 * if Type == #BTC_EXTKEY_PRIV && pSeed != NULL:<br>
 *     root seed(pSeed) --> generate master private/public keys<br>
 * if Type == #BTC_EXTKEY_PUB:<br>
 *     parent public key(pKey) --> generate child public keys<br>
 * copy the generated key to pExtKey->key according to the type
 *
 * @param[out]      pExtKey           extended key
 * @param[in]       Type            extended key type
 * @param[in]       Depth           depth
 * @param[in]       ChildNum        child number
 * @param[in]       pKey            parent key
 * @param[in]       pSeed           root seed
 * @param[in]       SzSeed          root seed size
 * @return       true:success
 */
bool btc_extkey_generate(btc_extkey_t *pExtKey, uint8_t Type, uint8_t Depth, uint32_t ChildNum,
        const uint8_t *pKey,
        const uint8_t *pSeed, int SzSeed);


/** BIP44形式拡張鍵構造体初期化
 *
 * @param[out]      pExtKey           拡張鍵構造体(depth2～4)
 * @param[in]       pSeed           拡張鍵seed(BTC_SZ_EXTKEY_SEED)
 * @param[in]       Account         0～。BTC_EXTKEY_BIP_SKIPの場合、"m/44'/coin_type'"までで終わる。
 * @param[in]       Change          BTC_EXTKEY_BIP_EXTERNAL or BTC_EXTKEY_BIP_INTERNAL。
 *                                  BTC_EXTKEY_BIP_SKIPの場合、"m/44'/coin_type'/account"までで終わる。
 * @retval  true    成功
 */
bool btc_extkey_bip44_init(btc_extkey_t *pExtKey, const uint8_t *pSeed, uint32_t Account, uint32_t Change);


/** BIP44形式拡張鍵構造体準備
 *
 * @param[in,out]   pExtKey           [in]depth0 [out]拡張鍵構造体(depth2～4)
 * @param[in]       Account         0～。BTC_EXTKEY_BIP_SKIPの場合、"m/44'/coin_type'"までで終わる。
 * @param[in]       Change          BTC_EXTKEY_BIP_EXTERNAL or BTC_EXTKEY_BIP_INTERNAL。
 *                                  BTC_EXTKEY_BIP_SKIPの場合、"m/44'/coin_type'/account"までで終わる。
 * @retval  true    成功
 */
bool btc_extkey_bip44_prepare(btc_extkey_t *pExtKey, uint32_t Account, uint32_t Change);


/** BIP49形式拡張鍵構造体初期化
 *
 * @param[out]      pExtKey           拡張鍵構造体(depth2～4)
 * @param[in]       pSeed           拡張鍵seed(BTC_SZ_EXTKEY_SEED)
 * @param[in]       Account         0～。BTC_EXTKEY_BIP_SKIPの場合、"m/49'/coin_type'"までで終わる。
 * @param[in]       Change          BTC_EXTKEY_BIP_EXTERNAL or BTC_EXTKEY_BIP_INTERNAL。
 *                                  BTC_EXTKEY_BIP_SKIPの場合、"m/49'/coin_type'/account"までで終わる。
 * @retval  true    成功
 */
bool btc_extkey_bip49_init(btc_extkey_t *pExtKey, const uint8_t *pSeed, uint32_t Account, uint32_t Change);


/** BIP49形式拡張鍵構造体準備
 *
 * @param[in,out]   pExtKey           [in]depth0 [out]拡張鍵構造体(depth2～4)
 * @param[in]       Account         0～。BTC_EXTKEY_BIP_SKIPの場合、"m/49'/coin_type'"までで終わる。
 * @param[in]       Change          BTC_EXTKEY_BIP_EXTERNAL or BTC_EXTKEY_BIP_INTERNAL。
 *                                  BTC_EXTKEY_BIP_SKIPの場合、"m/49'/coin_type'/account"までで終わる。
 * @retval  true    成功
 */
bool btc_extkey_bip49_prepare(btc_extkey_t *pExtKey, uint32_t Account, uint32_t Change);


/** BIP44/49形式拡張鍵構造体生成
 *
 * @param[out]      pExtKeyOut        拡張鍵構造体(depth4)
 * @param[in]       pExtKeyIn         拡張鍵構造体(depth4)
 * @param[in]       Account         0～
 * @retval  true    成功
 * @note
 *      - 繰り返し使用する場合、pExtKeyInの値を変更しないこと
 */
bool btc_extkey_bip_generate(btc_extkey_t *pExtKeyOut, const btc_extkey_t *pExtKeyIn, uint32_t Index);


/** 拡張鍵データ作成
 *
 * #btc_extkey_generate()で生成した拡張鍵構造体
 *
 * @param[out]      pData       鍵データ
 * @param[out]      pAddr       非NULL:鍵アドレス文字列(NULL時は生成しない)
 * @param[in]       pExtKey       生成元情報
 */
bool btc_extkey_create_data(uint8_t *pData, char *pAddr, const btc_extkey_t *pExtKey);


/** 拡張鍵データ読込み
 *
 * @param[out]  pExtKey       拡張鍵構造体
 * @param[in]   pData       鍵データ(Base58CHKデコード後)
 * @param[in]   Len         pData長
 * @return      true:成功
 */
bool btc_extkey_read(btc_extkey_t *pExtKey, const uint8_t *pData, int Len);


/** 拡張鍵読込み
 *
 * @param[out]  pExtKey       拡張鍵構造体
 * @param[in]   pXAddr      鍵データ(Base58CHK文字列)
 * @return      true:成功
 */
bool btc_extkey_read_addr(btc_extkey_t *pExtKey, const char *pXAddr);


#ifdef PTARM_USE_PRINTFUNC
/** 拡張鍵の内容表示
 *
 * @param[in]       pExtKey       拡張鍵構造体
 */
void btc_extkey_print(const btc_extkey_t *pExtKey);
#else
#define btc_extkey_print(...)
#endif  //PTARM_USE_PRINTFUNC


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_EXTKEY_H__ */
