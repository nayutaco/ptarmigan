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
/** @file   btc.h
 *  @brief  bitcoin offline API header
 */
#ifndef BTC_H__
#define BTC_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_PREF_CHAIN          (0)             ///< Prefix: 1:mainnet, 2:testnet
#define BTC_PREF_WIF            (1)             ///< Prefix: WIF
#define BTC_PREF_P2PKH          (2)             ///< Prefix: P2PKH
#define BTC_PREF_P2SH           (3)             ///< Prefix: P2SH
#define BTC_PREF_ADDRVER        (4)             ///< Prefix: Address Version
#define BTC_PREF_ADDRVER_SH     (5)             ///< Prefix: Address Version(Script)
#define BTC_PREF_MAX            (6)             ///< 内部管理用
#define BTC_PREF_P2WPKH         (7)             ///< Prefix: Native Pay-to-Witness-Public-Key-Hash
#define BTC_PREF_P2WSH          (8)             ///< Prefix: Native Pay-to-Witness-Script-Hash

//連結させるため文字列にしている
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

#define BTC_DUST_LIMIT          ((uint64_t)546) ///< voutに指定できるamountの下限[satoshis]
                                                // 2018/02/11 17:54(JST)
                                                // https://github.com/bitcoin/bitcoin/blob/fe53d5f3636aed064823bc220d828c7ff08d1d52/src/test/transaction_tests.cpp#L695
                                                //
                                                // https://github.com/bitcoin/bitcoin/blob/5961b23898ee7c0af2626c46d5d70e80136578d3/src/policy/policy.cpp#L52-L55

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

#define OP_x                    (0x50)  //0x50はOP_RESERVEDだが、ここでは足し算して使う用途
#define _OP_PUSHDATA_X_MIN      (0x01)
#define _OP_PUSHDATA_X_MAX      (0x4b)

#define VARINT_1BYTE_MAX        (0xfc)
#define VARINT_3BYTE_MIN        (0xfd)

#define BTC_OFFSET_WITPROG      (2)         ///witnessProgram中のscriptPubKey位置


/**************************************************************************
 * macro functions
 **************************************************************************/

//XXX:
/** @def    BTC_MBTC2SATOSHI
 *  @brief  mBTCをsatochi変換
 */
#define BTC_MBTC2SATOSHI(mbtc)      ((uint64_t)((mbtc) * 100000 + 0.5))

/** @def    BTC_BTC2SATOSHI
 *  @brief  BTCをsatochi変換
 */
#define BTC_BTC2SATOSHI(btc)        ((uint64_t)((btc) * (uint64_t)100000000 + 0.5))

/** @def    BTC_SATOSHI2MBTC
 *  @brief  satoshiをmBTC変換
 */
#define BTC_SATOSHI2MBTC(stc)       ((double)(stc) / 100000)

/** @def    BTC_SATOSHI2BTC
 *  @brief  satoshiをBTC変換
 */
#define BTC_SATOSHI2BTC(stc)        ((double)(stc) / (double)100000000)

/** @def    BTC_VOUT2PKH_P2PKH
 *  @brief  scriptPubKey(P2PKH)からPubKeyHashアドレス位置算出
 */
#define BTC_VOUT2PKH_P2PKH(script)  ((script) + 4)

/** @def    BTC_VOUT2PKH_P2SH
 *  @brief  scriptPubKey(P2SH)からPubKeyHashアドレス位置算出
 */
#define BTC_VOUT2PKH_P2SH(script)   ((script) + 2)

/** @def    BTC_IS_DUST
 *  @brief  amountが支払いに使用できないDUSTかどうかチェックする(true:支払えない)
 */
#define BTC_IS_DUST(amount)         (BTC_DUST_LIMIT > (amount))


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @enum   btc_chain_t
 *  @brief  blockchain種別
 */
typedef enum {
    BTC_UNKNOWN,
    BTC_MAINNET,          ///< mainnet
    BTC_TESTNET           ///< testnet, regtest
} btc_chain_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 初期化
 *
 * @param[in]       chain           BTC_MAINNET / BTC_TESTNET
 * @param[in]       bSegNative      true:segwit native transaction
 */
bool btc_init(btc_chain_t net, bool bSegNative);


/** 終了
 *
 *
 */
void btc_term(void);


/** blockchain種別取得
 *
 */
btc_chain_t btc_get_chain(void);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_H__ */
