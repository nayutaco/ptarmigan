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
/** @file   btc_keys.h
 *  @brief  btc_keys
 */
#ifndef BTC_KEYS_H__
#define BTC_KEYS_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"

#include "btc.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_PRIVKEY          (32)                ///< サイズ:非公開鍵
#define BTC_SZ_PUBKEY           (33)                ///< サイズ:圧縮された公開鍵
#define BTC_SZ_PUBKEY_UNCOMP    (65)                ///< サイズ:圧縮されていない公開鍵
#define BTC_SZ_ADDR_STR_MAX     (90)                ///< サイズ:Bitcoinアドレス(26-35)(BECH32:90)
#define BTC_SZ_WIF_STR_MAX      (55)                ///< サイズ:秘密鍵のWIF(上限不明)


/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     btc_keys_t
 *  @brief      key information
 */
typedef struct {
    uint8_t     priv[BTC_SZ_PRIVKEY];           ///< private key
    uint8_t     pub[BTC_SZ_PUBKEY];             ///< public key
} btc_keys_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** WIF形式秘密鍵をRAW形式に変換
 *
 * @param[out]      pPrivKey        変換後データ(#BTC_SZ_PRIVKEY)
 * @param[out]      pChain          WIFのblockchain種別
 * @param[in]       pWifPriv        対象データ(WIF compressed, \0 terminate)
 * @return      true:成功
 */
bool btc_keys_wif2priv(uint8_t *pPrivKey, btc_chain_t *pChain, const char *pWifPriv);


/** RAW秘密鍵をWIF形式秘密鍵に変換
 *
 * @param[out]      pWifPriv        WIF compressed(#BTC_SZ_WIF_STR_MAX+1)
 * @param[in]       pPrivKey
 * @return      true:成功
 */
bool btc_keys_priv2wif(char *pWifPriv, const uint8_t *pPrivKey);


/** 秘密鍵を公開鍵に変換
 *
 * @param[out]      pPubKey         変換後データ(#BTC_SZ_PUBKEY)
 * @param[in]       pPrivKey        対象データ(#BTC_SZ_PRIVKEY)
 *
 * @note
 *      - pPubKeyは圧縮された公開鍵になる
 */
bool btc_keys_priv2pub(uint8_t *pPubKey, const uint8_t *pPrivKey);


/** 公開鍵をBitcoinアドレス(P2PKH)に変換
 *
 * @param[out]      pAddr           変換後データ(#BTC_SZ_ADDR_STR_MAX+1)
 * @param[in]       pPubKey         対象データ(#BTC_SZ_PUBKEY)
 */
bool btc_keys_pub2p2pkh(char *pAddr, const uint8_t *pPubKey);


/** 公開鍵をBitcoinアドレス(P2WPKH or P2SH-P2WPKH)に変換
 *
 * @param[out]      pWAddr          変換後データ(#BTC_SZ_ADDR_STR_MAX+1)
 * @param[in]       pPubKey         対象データ(#BTC_SZ_PUBKEY)
 *
 * @note
 *      - if mNativeSegwit == true then P2WPKH
 *      - if mNativeSegwit == false then P2SH-P2WPKH
 */
bool btc_keys_pub2p2wpkh(char *pWAddr, const uint8_t *pPubKey);


/** P2PKHをBitcoinアドレス(P2WPKH or P2SH-P2WPKH)に変換
 *
 * @param[out]      pWAddr          変換後データ(#BTC_SZ_ADDR_STR_MAX+1)
 * @param[in]       pAddr           対象データ
 *
 * @note
 *      - if mNativeSegwit == true then P2WPKH
 *      - if mNativeSegwit == false then P2SH-P2WPKH
 */
bool btc_keys_addr2p2wpkh(char *pWAddr, const char *pAddr);


/** Witness ScriptをBitcoinアドレス(P2WSH or P2SH-P2WSH)に変換
 *
 * @param[out]      pWAddr          変換後データ(#BTC_SZ_ADDR_STR_MAX+1)
 * @param[in]       pRedeem         対象データ
 *
 * @note
 *      - if mNativeSegwit == true then P2WSH
 *      - if mNativeSegwit == false then P2SH-P2WSH
 */
bool btc_keys_wit2waddr(char *pWAddr, const utl_buf_t *pWitnessScript);


/** uncompress public key
 *
 * @param[out]  pUncomp     uncompressed public key(#BTC_SZ_PUBKEY_UNCOMP-1, no prefix)
 * @param[in]   pPubKey     compressed public key(#BTC_SZ_PUBKEY, prefixed)
 */
bool btc_keys_uncomp_pub(uint8_t *pUncomp, const uint8_t *pPubKey);


/** 秘密鍵の範囲チェック
 *
 * @param[in]   pPrivKey    チェック対象
 * @retval  true    正常
 */
bool btc_keys_check_priv(const uint8_t *pPrivKey);


/** 公開鍵のチェック
 *
 * @param[in]       pPubKey     チェック対象
 * @return      true:SECP256K1の公開鍵としては正当
 */
bool btc_keys_check_pub(const uint8_t *pPubKey);


/** BitcoinアドレスからHash(PKH/SH/WPKH/WSH)を求める
 *
 * @param[out]      pHash           Hash(#BTC_SZ_HASH_MAX)
 * @param[out]      pPrefix         pAddrの種類(BTC_PREF_xxx)
 * @param[in]       pAddr           Bitcoinアドレス
 * @return      true:成功
 *
 * @note
 *      - if pPrefix == #BTC_PREF_P2PKH then length of pHash is #BTC_SZ_HASH160
 *      - if pPrefix == #BTC_PREF_P2SH then length of pHash is #BTC_SZ_HASH160
 *      - if pPrefix == #BTC_PREF_P2WPKH then length of pHash is #BTC_SZ_HASH160
 *      - if pPrefix == #BTC_PREF_P2WSH then length of pHash is #BTC_SZ_HASH256
 */
bool btc_keys_addr2hash(uint8_t *pHash, int *pPrefix, const char *pAddr);


/** BitcoinアドレスからscriptPubKeyを求める
 *
 * @param[out]  pScriptPk   scriptPubKey
 * @param[in]   pAddr       Bitcoinアドレス
 * @return      true:成功
 */
bool btc_keys_addr2spk(utl_buf_t *pScriptPk, const char *pAddr);


/** scriptPubKeyからBitcoinアドレスを求める
 *
 * @param[out]  pAddr       Bitcoinアドレス(#BTC_SZ_ADDR_STR_MAX+1)
 * @param[in]   pScriptPk   scriptPubKey
 * @return      true:成功
 */
bool btc_keys_spk2addr(char *pAddr, const utl_buf_t *pScriptPk);


/** extract keys from WIF
 *
 * @param[out]      pKeys           keys
 * @param[out]      pChain          chain
 * @param[in]       pWifPriv        WIF compressed formatted private key
 * @return      true    success
 */
bool btc_keys_wif2keys(btc_keys_t *pKeys, btc_chain_t *pChain, const char *pWifPriv);


/** generate private key from RNG
 *
 * @param[out]      pPriv           private key
 * @return      true    success
 */
bool btc_keys_create_priv(uint8_t *pPriv);


/** generate keys from RNG
 *
 * @param[out]      pKeys           鍵情報
 * @return      true    成功
 */
bool btc_keys_create(btc_keys_t *pKeys);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_KEYS_H__ */
