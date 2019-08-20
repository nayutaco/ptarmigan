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
/** @file   btc_script.h
 *  @brief  btc_script
 */
#ifndef BTC_SCRIPT_H__
#define BTC_SCRIPT_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"

#include "btc.h"
#include "btc_keys.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_WITPROG_P2WPKH   (2 + BTC_SZ_HASH160)    ///< サイズ: witnessProgram(P2WPKH)
#define BTC_SZ_WITPROG_P2WSH    (2 + BTC_SZ_HASH256)    ///< サイズ: witnessProgram(P2WSH)
#define BTC_SZ_2OF2             (1 + 1 + BTC_SZ_PUBKEY + 1 + BTC_SZ_PUBKEY + 1 + 1) ///< OP_m 0x21 [pub1] 0x21 [pub2] OP_n OP_CHKMULTISIG

//for string format
#define BTC_OP_0                "\x00"          ///< OP_0
#define BTC_OP_PUSHDATA1        "\x4c"          ///< OP_PUSHDATA1
#define BTC_OP_PUSHDATA2        "\x4d"          ///< OP_PUSHDATA2
#define BTC_OP_2                "\x52"          ///< OP_2
#define BTC_OP_IF               "\x63"          ///< OP_IF
#define BTC_OP_NOTIF            "\x64"          ///< OP_NOTIF
#define BTC_OP_ELSE             "\x67"          ///< OP_ELSE
#define BTC_OP_ENDIF            "\x68"          ///< OP_ENDIF
#define BTC_OP_RETURN           "\x6a"          ///< OP_RETURN
#define BTC_OP_2DROP            "\x6d"          ///< OP_2DROP
#define BTC_OP_DROP             "\x75"          ///< OP_DROP
#define BTC_OP_DUP              "\x76"          ///< OP_DUP
#define BTC_OP_SWAP             "\x7c"          ///< OP_SWAP
#define BTC_OP_SIZE             "\x82"          ///< OP_SIZE
#define BTC_OP_EQUAL            "\x87"          ///< OP_EQUAL
#define BTC_OP_EQUALVERIFY      "\x88"          ///< OP_EQUALVERIFY
#define BTC_OP_ADD              "\x93"          ///< OP_ADD
#define BTC_OP_CHECKSIG         "\xac"          ///< OP_CHECKSIG
#define BTC_OP_CHECKMULTISIG    "\xae"          ///< OP_CHECKMULTISIG
#define BTC_OP_CLTV             "\xb1"          ///< OP_CHECKLOCKTIMEVERIFY
#define BTC_OP_CSV              "\xb2"          ///< OP_CHECKSEQUENCEVERIFY
#define BTC_OP_HASH160          "\xa9"          ///< OP_HASH160
#define BTC_OP_HASH256          "\xaa"          ///< OP_HASH256

#define BTC_OP_SZ1              "\x01"          ///< 1byte値
#define BTC_OP_SZ20             "\x14"          ///< 20byte値
#define BTC_OP_SZ32             "\x20"          ///< 32byte値
#define BTC_OP_SZ_PUBKEY        "\x21"          ///< 33byte値

#define OP_0                    (0x00)
#define OP_PUSHDATA1            (0x4c)
#define OP_PUSHDATA2            (0x4d)
#define OP_PUSHDATA3            (0x4e)
#define OP_1NEGATE              (0x4f)
#define OP_1                    (0x51)
#define OP_2                    (0x52)
#define OP_16                   (0x60)
#define OP_IF                   (0x63)
#define OP_NOTIF                (0x64)
#define OP_ELSE                 (0x67)
#define OP_ENDIF                (0x68)
#define OP_RETURN               (0x6a)
#define OP_2DROP                (0x6d)
#define OP_DROP                 (0x75)
#define OP_DUP                  (0x76)
#define OP_SWAP                 (0x7c)
#define OP_SIZE                 (0x82)
#define OP_EQUAL                (0x87)
#define OP_EQUALVERIFY          (0x88)
#define OP_ADD                  (0x93)
#define OP_CHECKSIG             (0xac)
#define OP_CHECKMULTISIG        (0xae)
#define OP_CHECKLOCKTIMEVERIFY  (0xb1)
#define OP_CHECKSEQUENCEVERIFY  (0xb2)
#define OP_HASH160              (0xa9)
#define OP_HASH256              (0xaa)

#define OP_X                    (0x50)  //0x50はOP_RESERVEDだが、ここでは足し算して使う用途
#define OP_X_PUSHDATA_MIN       (0x01)
#define OP_X_PUSHDATA_MAX       (0x4b)

#define BTC_OFFSET_WITPROG      (2)     ///witnessProgram中のscriptPubKey位置


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    BTC_VOUT2PKH_P2PKH
 *  @brief  scriptPubKey(P2PKH)からPubKeyHashアドレス位置算出
 */
#define BTC_VOUT2PKH_P2PKH(script)  ((script) + 4)


/** @def    BTC_VOUT2PKH_P2SH
 *  @brief  scriptPubKey(P2SH)からPubKeyHashアドレス位置算出
 */
#define BTC_VOUT2PKH_P2SH(script)   ((script) + 2)


/**************************************************************************
 * package variables
 **************************************************************************/

/**************************************************************************
 * typedefs
 **************************************************************************/

/** @enum   btc_script_pubkey_order_t
 *  @brief  order of the keys
 */
typedef enum {
    BTC_SCRYPT_PUBKEY_ORDER_ASC,             ///< ascending order
    BTC_SCRYPT_PUBKEY_ORDER_OTHER            ///< other
} btc_script_pubkey_order_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

//XXX: comment
/** 種類に応じたscriptPubKey設定
 *
 * @param[out]      pScriptPk
 * @param[in]       pPubKeyHash
 * @param[in]       Prefix
 * @return      true:success
 */
bool btc_script_scriptpk_create(utl_buf_t *pScriptPk, const uint8_t *pPubKeyHash, int Prefix);
bool btc_script_scriptpk_is_op_return(const utl_buf_t *pScriptPk);
int btc_script_scriptpk_prefix(const uint8_t **ppHash, const utl_buf_t *pScriptPk);


//XXX: comment
bool btc_script_p2pkh_create_scriptsig(utl_buf_t *pScriptSig, const utl_buf_t *pSig, const uint8_t *pPubKey);


//XXX: comment
bool btc_script_p2sh_p2wpkh_create_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pPubKey);
bool btc_script_p2sh_p2wpkh_create_redeem(utl_buf_t *pRedeem, const uint8_t *pPubKey);
bool btc_script_p2sh_p2wpkh_create_redeem_pkh(utl_buf_t *pRedeem, const uint8_t *pPubKeyHash);
/** PubKeyHash(P2WPKH)をScriptHash(P2SH)に変換
 *
 * [00][14][pubKeyHash] --> HASH160
 *
 * @param[out]      pScriptHash     変換後データ(#BTC_SZ_HASH_MAX)
 * @param[in]       pPubKeyHash     対象データ(#BTC_SZ_HASH_MAX)
 */
bool btc_script_p2sh_p2wpkh_create_scripthash_pkh(uint8_t *pScriptHash, const uint8_t *pPubKeyHash);


//XXX: comment
bool btc_script_p2sh_p2wsh_create_scriptsig(utl_buf_t *pScriptSig, const utl_buf_t *pWitScript);


//XXX: comment
bool btc_script_p2sh_multisig_create_scriptsig(utl_buf_t *pScriptSig, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem);
bool btc_script_p2sh_multisig_create_redeem(utl_buf_t *pRedeem, const uint8_t *pPubKeys[], uint8_t Num, uint8_t M);
bool btc_script_p2sh_multisig_verify_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pScriptHash);
bool btc_script_p2sh_multisig_verify_scriptsig_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);


//XXX: comment
bool btc_script_2of2_create_redeem(utl_buf_t *pRedeem, const uint8_t *pPubKey1, const uint8_t *pPubKey2);
/** #btc_script_2of2_create_redeem() with the sorted pubKeys
 *
 * @param[out]      pRedeem     2-of-2 redeem script
 * @param[out]      pOrder       ソート結果(#btc_script_pubkey_order_t)
 * @param[in]       pPubKey1    public key 1
 * @param[in]       pPubKey2    public key 1
 *
 * @note
 *      - if *pOrder == BTC_SCRYPT_PUBKEY_ORDER_ASC, then pPubKey1, pPbuKey2
 *      - if *pOrder != BTC_SCRYPT_PUBKEY_ORDER_ASC, then pPubKey2, pPbuKey1
 */
bool btc_script_2of2_create_redeem_sorted(utl_buf_t *pRedeem, btc_script_pubkey_order_t *pOrder, const uint8_t *pPubKey1, const uint8_t *pPubKey2);


//XXX: comment
bool btc_script_p2pkh_sign_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey);
bool btc_script_p2pkh_verify_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPubKeyHash);
bool btc_script_p2pkh_verify_scriptsig_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);


//XXX: comment
bool btc_script_p2wpkh_create_witness(utl_buf_t **pWitness, uint32_t *pWitItemCnt, const utl_buf_t *pSig, const uint8_t *pPubKey);
/** P2WPKH署名計算で使用するScript Code取得
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pPubKey         公開鍵
 * @retval      true    成功
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_script_p2wpkh_create_scriptcode(utl_buf_t *pScriptCode, const uint8_t *pPubKey);


//XXX: comment
bool btc_script_p2wsh_create_scriptpk(utl_buf_t *pScriptPk, const utl_buf_t *pWitScript);
bool btc_script_p2wsh_create_witness(utl_buf_t **ppWitness, uint32_t *pWitItemCnt, const utl_buf_t *pWitness[], int Num);
/** P2WSH署名計算で使用するScript Code取得
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pWitScript      witnessScript
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_script_p2wsh_create_scriptcode(utl_buf_t *pScriptCode, const utl_buf_t *pWitScript);


//XXX: comment
bool btc_script_p2wsh_2of2_verify_witness(utl_buf_t *pWitness, uint32_t WitItemCnt, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);


#ifdef PTARM_USE_PRINTFUNC
/** スクリプトの内容表示
 *
 * @param[in]       pData       表示対象
 * @param[in]       Len         pData長
 */
void btc_script_print(const uint8_t *pData, uint16_t Len);
#else
#define btc_script_print(...)
#endif  //PTARM_USE_PRINTFUNC


#endif /* BTC_SCRIPT_H__ */
