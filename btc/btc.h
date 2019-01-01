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

#include "btc_keys.h"
#include "btc_block.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_FIELD            (32)                ///< secp256k1の世界
#define BTC_SZ_HASH160          (20)                ///< サイズ:HASH160
#define BTC_SZ_HASH256          (32)                ///< サイズ:HASH256
#define BTC_SZ_HASH_MAX         (BTC_SZ_HASH256)    ///< サイズ:Hashの最大値
#define BTC_SZ_TXID             (32)                ///< サイズ:TXID
#define BTC_SZ_SIGN_RS          (64)                ///< サイズ:RS形式の署名
#define BTC_SZ_2OF2             (1 + 1 + BTC_SZ_PUBKEY + 1 + BTC_SZ_PUBKEY + 1 + 1) ///< OP_m 0x21 [pub1] 0x21 [pub2] OP_n OP_CHKMULTISIG

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

#define BTC_TX_VERSION_INIT             (2)
#define BTC_TX_INIT                     { BTC_TX_VERSION_INIT, 0, (btc_vin_t *)NULL, 0, (btc_vout_t *)NULL, 0 }
#define BTC_TX_SEQUENCE                 ((uint32_t)0xffffffff)
#define BTC_TX_LOCKTIME_LIMIT           ((uint32_t)500000000)
#define BTC_TX_PUBKEYS_PER_MULTISIG_MAX (20)

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

#define SIGHASH_ALL             (0x01)

#define VARINT_1BYTE_MAX        (0xfc)
#define VARINT_3BYTE_MIN        (0xfd)

#define BTC_OFFSET_WITPROG      (2)         ///witnessProgram中のscriptPubKey位置

/**************************************************************************
 * macro functions
 **************************************************************************/

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

/** @enum   btc_tx_valid_t
 *  @brief  #btc_tx_is_valid()
 */
typedef enum {
    BTC_TXVALID_OK,
    BTC_TXVALID_ARG_NULL,
    BTC_TXVALID_VERSION_BAD,
    BTC_TXVALID_VIN_NONE,
    BTC_TXVALID_VIN_NULL,
    BTC_TXVALID_VIN_WIT_NULL,
    BTC_TXVALID_VIN_WIT_BAD,
    BTC_TXVALID_VOUT_NONE,
    BTC_TXVALID_VOUT_NULL,
    BTC_TXVALID_VOUT_SPKH_NONE,
    BTC_TXVALID_VOUT_VALUE_BAD,
} btc_tx_valid_t;


/** @struct btc_vin_t
 *  @brief  VIN管理構造体
 */
typedef struct {
    uint8_t     txid[BTC_SZ_TXID];      ///< [outpoint]TXID(Little Endian)
    uint32_t    index;                  ///< [outpoint]index
    utl_buf_t   script;                 ///< scriptSig
    uint32_t    wit_item_cnt;           ///< witness数(0のとき、witnessは無視)
    utl_buf_t   *witness;               ///< witness(配列的に使用する)
    uint32_t    sequence;               ///< sequence
} btc_vin_t;


/** @struct btc_vout_t
 *  @brief  VOUT管理構造体
 */
typedef struct {
    uint64_t    value;                  ///< value[単位:satoshi]
    utl_buf_t   script;                 ///< scriptPubKey
    uint8_t     opt;                    ///< 付加情報(ln用)
                                        //      ln_script_htlctx_create()でln_htlctype_tに設定
                                        //      ln_script_committx_create()でln_tx_cmt_t.pp_htlcinfo[]のindex値(or LN_HTLCTYPE_TOLOCAL/REMOTE)に設定
} btc_vout_t;


/** @struct btc_tx_t
 *  @brief  TX管理構造体
 */
typedef struct {
    int32_t     version;        ///< TX version

    uint32_t    vin_cnt;        ///< vin数(0のとき、vinは無視)
    btc_vin_t   *vin;           ///< vin(配列的に使用する)

    uint32_t    vout_cnt;       ///< vout数(0のとき、voutは無視)
    btc_vout_t  *vout;          ///< vout(配列的に使用する)

    uint32_t    locktime;       ///< locktime
} btc_tx_t;


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



//////////////////////
//TX
//////////////////////

/** #btc_tx_t の初期化
 *
 * @param[out]      pTx         対象データ
 *
 * @note
 *      - versionは2で初期化する(OP_CSVやOP_CLTVを使用する場合が多いため)
 */
void btc_tx_init(btc_tx_t *pTx);


/** #btc_tx_t のメモリ解放
 *
 * @param[in,out]   pTx     処理対象
 *
 * @note
 *      - vin, vout, witnessに確保されたメモリを解放する
 *      - メモリ解放以外の値(version, locktime)は維持する。
 */
void btc_tx_free(btc_tx_t *pTx);


/** トランザクションの正統性チェック
 *
 * @param[in]   pTx         チェック対象
 * @return  チェック結果
 * @note
 *      - 署名やスクリプトの正統性ではなく、形として正しいかどうかだけをチェックする
 */
btc_tx_valid_t btc_tx_is_valid(const btc_tx_t *pTx);


/** add vin(no scriptSig) to tx
 *
 * @param[in,out]   pTx         追加対象
 * @param[in]       pTxId       追加するvinのTXID(Little Endian)(#BTC_SZ_TXID)
 * @param[in]       Index       追加するvinのindex
 * @return          追加した #btc_vin_t のアドレス
 *
 * @attention
 *      - realloc()するため、取得したアドレスは次に #btc_tx_add_vin()しても有効なのか確実ではない。
 *          すぐに使用してアドレスは保持しないこと。
 * @note
 *      - realloc()するため、事前のfree処理は不要
 *      - sequenceは0xFFFFFFFFで初期化している
 *      - scriptSigは空のため、戻り値を使って #utl_buf_alloccopy()でコピーすることを想定している
 */
btc_vin_t *btc_tx_add_vin(btc_tx_t *pTx, const uint8_t *pTxId, uint32_t Index);


/** add witness to vin
 *
 * @param[in,out]   pVin        追加対象
 * @return          追加したwitnessのアドレス
 *
 * @note
 *      - realloc()するため、事前のfree処理は不要
 *      - witnessは空のため、戻り値を使って #utl_buf_alloccopy()でコピーすることを想定している
 */
utl_buf_t *btc_tx_add_wit(btc_vin_t *pVin);


/** add vout(no scriptPubKey) to tx
 *
 * @param[in,out]   pTx         追加対象
 * @param[in]       Value       追加したvoutのvalue(単位:satoshi)
 * @return          追加した #btc_vout_t のアドレス
 *
 * @note
 *      - realloc()するため、事前のfree処理は不要
 *      - scriptPubKeyは空のため、戻り値を使って #utl_buf_alloccopy()でコピーすることを想定している
 */
btc_vout_t *btc_tx_add_vout(btc_tx_t *pTx, uint64_t Value);


/** add vout with addr
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pAddr(P2PKH/P2SH/P2WPKH/P2WSH)
 * @return      true:success
 */
bool btc_tx_add_vout_addr(btc_tx_t *pTx, uint64_t Value, const char *pAddr);


/** add vout with scriptPubKey
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pScriptPk
 * @return      true:success
 */
bool btc_tx_add_vout_spk(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pScriptPk);


/** add P2PKH-vout with pubKeyHash
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pPubKeyHash
 * @return      true:success
 */
bool btc_tx_add_vout_p2pkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash);


/** create scriptPubKey
 *
 * @param[out]      pBuf        scriptPubKey
 * @param[in]       pAddr       Bitcoinアドレス
 * @return      true:success
 */
bool btc_tx_create_spk(utl_buf_t *pBuf, const char *pAddr);


/** create P2PKH-scriptPubKey
 *
 * @param[out]      pBuf        scriptPubKey
 * @param[in]       pAddr       Bitcoinアドレス
 * @return      true:success
 *
 * @note
 *      - 署名用にINPUT txのscriptPubKeyが必要だが、TXデータを持たず、P2PKHだからBitcoinアドレスから生成しよう、という場合に使用する
 */
bool btc_tx_create_spk_p2pkh(utl_buf_t *pBuf, const char *pAddr);


/** add P2PKH-vout with address
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pAddr       Bitcoinアドレス(P2PKH)
 */
bool btc_tx_add_vout_p2pkh_addr(btc_tx_t *pTx, uint64_t Value, const char *pAddr);


/** add P2SH-vout with scriptHash
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pPubKeyHash
 *
 */
bool btc_tx_add_vout_p2sh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pScriptHash);


/** add P2SH-vout with address
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pAddr       Bitcoinアドレス(P2SH)
 */
bool btc_tx_add_vout_p2sh_addr(btc_tx_t *pTx, uint64_t Value, const char *pAddr);


/** add P2SH-vout with redeemScript
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pRedeem     redeemScript
 */
bool btc_tx_add_vout_p2sh_redeem(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pRedeem);


/** set P2PKH-vin scriptSig with pubKey
 *
 * @param[in,out]   pTx         対象トランザクション
 * @param[in]       Index       対象vinのIndex
 * @param[in]       pSig        署名
 * @param[in]       pPubKey     公開鍵
 *
 * @note
 *      - 対象のvinは既に追加されていること(addではなく、置き換える動作)
 */
bool btc_tx_set_vin_p2pkh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSig, const uint8_t *pPubKey);


/** set P2SH-vin scriptSig with multisig and redeemScript
 *
 * @param[in,out]   pTx         対象トランザクション
 * @param[in]       Index       対象vinのIndex
 * @param[in]       pSigs       署名
 * @param[in]       Num         pSigsの数
 * @param[in]       pRedeem     redeemScript
 *
 * @note
 *      - 対象のvinは既に追加されていること(addではなく、置き換える動作)
 */
bool btc_tx_set_vin_p2sh_multisig(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem);


/* convert tx from data array to #btc_tx_t
 *
 * @param[out]      pTx         変換後データ
 * @param[in]       pData       トランザクションデータ
 * @param[in]       Len         pData長
 * @return          変換結果
 *
 * @note
 *      - 動的にメモリ確保するため、#btc_tx_free()を呼ぶこと
 */
bool btc_tx_read(btc_tx_t *pTx, const uint8_t *pData, uint32_t Len);


/** convert tx from #btc_tx_t to data array
 *
 * @param[in]       pTx         対象データ
 * @param[out]      pBuf        変換後データ
 *
 * @note
 *      - 動的にメモリ確保するため、pBufは使用後 #utl_buf_free()で解放すること
 *      - vin cntおよびvout cntは 252までしか対応しない(varint型の1byteまで)
 */
bool btc_tx_write(const btc_tx_t *pTx, utl_buf_t *pBuf);


/** 非segwitトランザクション署名用ハッシュ値計算
 *
 * @param[in,out]   pTx             元になるトランザクション
 * @param[out]      pTxHash         ハッシュ値[BTC_SZ_HASH256]
 * @param[in]       pScriptPks      [P2PKH]scriptPubKeyの配列, [P2SH]redeemScriptの配列
 * @param[in]       Num             pScriptPkの要素数(pTxのvin_cntと同じ)
 *
 * @note
 *      - pTxは一時的に内部で更新される
 *      - pTxのvin[x].scriptは #btc_tx_free()で解放される
 *      - ハッシュはSIGHASHALL
 *      - vinにscriptPubKeyを記入するので、先に #btc_tx_add_vin()しておくこと
 */
bool btc_tx_sighash(btc_tx_t *pTx, uint8_t *pTxHash, const utl_buf_t *pScriptPks[], uint32_t Num);


/** 署名計算
 *
 * @param[out]      pSig        署名結果
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPrivKey    秘密鍵
 * @return          true        成功
 *
 * @note
 *      - pSigは、成功かどうかにかかわらず#utl_buf_init()される
 *      - 成功時、pSigは #utl_buf_alloccopy() でメモリ確保するので、使用後は #utl_buf_free()で解放すること
 */
bool btc_sig_sign(utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPrivKey);


/** 署名計算(r/s)
 *
 * @param[out]      pRS         署名結果rs[64]
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPrivKey    秘密鍵
 * @return          true        成功
 */
bool btc_sig_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPrivKey);


/** 署名チェック
 *
 * @param[in]       pSig        署名(ハッシュタイプあり)
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPubKey     公開鍵
 * @return          true:チェックOK
 *
 * @note
 *      - pSigの末尾にハッシュタイプが入っていること
 */
bool btc_sig_verify(const utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPubKey);


/** 署名チェック
 *
 * @param[in]       pSig        署名(ハッシュタイプあり)
 * @param[in]       Len         length of pSig
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPubKey     公開鍵
 * @return          true:チェックOK
 *
 * @note
 *      - pSigの末尾にハッシュタイプが入っていること
 */
bool btc_sig_verify_2(const uint8_t *pSig, uint32_t Len, const uint8_t *pTxHash, const uint8_t *pPubKey);


/** 署名チェック(r/s)
 *
 * @param[in]       pRS         署名rs[64]
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPubKey     公開鍵
 * @return          true:チェックOK
 */
bool btc_sig_verify_rs(const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPubKey);


/** P2PKH署名書込み
 *
 * @param[in,out]   pTx             署名書込み先トランザクション
 * @param[in]       Index           署名するINPUTのindex番号
 * @param[in]       pTxHash         トランザクションハッシュ値
 * @param[in]       pPrivKey        秘密鍵
 * @param[in]       pPubKey         公開鍵(NULLの場合、内部で計算する)
 * @return      true    成功
 *
 * @note
 *      - #btc_sig_sign()と#btc_tx_set_vin_p2pkh()をまとめて実施
 *      - pPubKeyは、既にあるなら計算を省略したいので引数にしている
 *          - 使ってみて、計算済みになることが少ないなら、引数から削除する予定
 */
bool btc_tx_sign_p2pkh(btc_tx_t *pTx, uint32_t Index,
        const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey);


/** P2PKH署名チェック
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pPubKeyHash     チェック用PubKeyHash
 * @return      true:チェックOK
 *
 * @note
 *      - pPubKeyHashは署名とセットになっている公開鍵がvinのTXID/indexのものかをチェックするためのもの。
 *          よって、署名されたトランザクションから計算して引数にするのはよくない。
 */
bool btc_tx_verify_p2pkh(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash);


/** P2PKH署名チェック(scriptPubKey)
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pScriptPk       scriptPubKey
 * @return      true:チェックOK
 *
 * @note
 *      - pScriptPkは署名とセットになっている公開鍵がvinのTXID/indexのものかをチェックするためのもの。
 *          よって、署名されたトランザクションから計算して引数にするのはよくない。
 */
bool btc_tx_verify_p2pkh_spk(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);


/** P2PKH署名チェック(アドレス)
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pAddr           Bitcoinアドレス
 * @return      true:チェックOK
 *
 * @note
 *      - pAddrは署名とセットになっている公開鍵がvinのTXID/indexのものかをチェックするためのもの。
 *          よって、署名されたトランザクションから計算して引数にするのはよくない。
 */
bool btc_tx_verify_p2pkh_addr(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const char *pAddr);


/** MultiSig(P2SH)署名チェック
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pScriptHash     redeem script hash
 * @return      true:チェックOK
 */
bool btc_tx_verify_p2sh_multisig(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pScriptHash);


/** P2SH署名チェック(scriptPubKey)
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pScriptPk       scriptPubKey
 * @return      true:チェックOK
 */
bool btc_tx_verify_p2sh_multisig_spk(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk);


/** P2SH署名チェック(アドレス)
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pAddr           Bitcoinアドレス
 * @return      true:チェックOK
 */
bool btc_tx_verify_p2sh_multisig_addr(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const char *pAddr);


/** 公開鍵復元
 *
 * @param[out]      pPubKey
 * @param[in]       RecId       recovery ID
 * @param[in]       pRS
 * @param[in]       pTxHash
 * @retval      true    成功
 */
bool btc_sig_recover_pubkey(uint8_t *pPubKey, int RecId, const uint8_t *pRS, const uint8_t *pTxHash);


/** 公開鍵復元ID取得
 *
 * @param[out]      pRecId      recovery ID
 * @param[in]       pPubKey
 * @param[in]       pRS
 * @param[in]       pTxHash
 * @retval      true    成功
 */
bool btc_sig_recover_pubkey_id(int *pRecId, const uint8_t *pPubKey, const uint8_t *pRS, const uint8_t *pTxHash);

/** TXID計算
 *
 * @param[in]   pTx         対象トランザクション
 * @param[out]  pTxId       計算結果(Little Endian)
 *
 * @note
 *      - pTxIdにはLittleEndianで出力される
 *      - pTxがsegwitの場合もTXIDが出力される
 */
bool btc_tx_txid(const btc_tx_t *pTx, uint8_t *pTxId);


/** TXID計算(raw data)
 *
 * @param[out]  pTxId       計算結果(Little Endian)
 * @param[in]   pTxRaw      対象トランザクション
 *
 * @note
 *      - pTxIdにはLittleEndianで出力される
 *      - pTxがsegwitの場合、WTXIDで出力される
 */
bool btc_tx_txid_raw(uint8_t *pTxId, const utl_buf_t *pTxRaw);


/** vsize取得
 *
 * @param[in]   pData
 * @param[in]   Len
 * @retval  != 0    vbyte
 * @retval  == 0    エラー
 */
uint32_t btc_tx_get_vbyte_raw(const uint8_t *pData, uint32_t Len);


//////////////////////
//SW
//////////////////////

/** P2WPKHのvout追加(pubkey)
 *
 * @param[in,out]   pTx
 * @param[in]       Value
 * @param[in]       pPubKey
 */
bool btc_sw_add_vout_p2wpkh_pub(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey);


/** P2WPKHのvout追加(pubKeyHash)
 *
 * @param[in,out]   pTx
 * @param[in]       Value
 * @param[in]       pPubKeyHash
 * @retval      true    成功
 */
bool btc_sw_add_vout_p2wpkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash);


/** P2WSHのvout追加(witnessScript)
 *
 * @param[in,out]   pTx
 * @param[in]       Value
 * @param[in]       pWitScript
 * @retval      true    成功
 *
 */
bool btc_sw_add_vout_p2wsh_wit(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pWitScript);


/** P2WPKH署名計算で使用するScript Code取得(vin)
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pVin            対象vin
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_sw_scriptcode_p2wpkh_vin(utl_buf_t *pScriptCode, const btc_vin_t *pVin);


/** P2WSH署名計算で使用するScript Code取得(vin)
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pVin            対象vin
 *
 * @note
 *      - pScriptCodeは使用後に #utl_buf_free()で解放すること
 */
bool btc_sw_scriptcode_p2wsh_vin(utl_buf_t *pScriptCode, const btc_vin_t *pVin);


/** segwitトランザクション署名用ハッシュ値計算
 *
 * @param[out]      pTxHash             署名に使用するハッシュ値(BTC_SZ_HASH256)
 * @param[in]       pTx                 署名対象のトランザクションデータ
 * @param[in]       Index               署名するINPUTのindex番号
 * @param[in]       Value               署名するINPUTのvalue[単位:satoshi]
 * @param[in]       pScriptCode         Script Code
 * @retval  false   pTxがトランザクションとして不正
 *
 */
bool btc_sw_sighash(uint8_t *pTxHash, const btc_tx_t *pTx, uint32_t Index, uint64_t Value,
                const utl_buf_t *pScriptCode);


/** P2WPKHのwitness作成
 *
 * @param[in,out]   pTx         対象トランザクション
 * @param[in]       Index       対象vinのIndex
 * @param[in]       pSig        署名
 * @param[in]       pPubKey     公開鍵
 *
 * @note
 *      - pSigはコピーするため解放はpTxで管理しない。
 *      - mNativeSegwitがfalseの場合、scriptSigへの追加も行う
 */
bool btc_sw_set_vin_p2wpkh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSig, const uint8_t *pPubKey);


/** P2WPSHのscriptSig作成
 *
 * @param[in,out]   pTx         対象トランザクション
 * @param[in]       Index       対象vinのIndex
 * @param[in]       pWits       witnessScript
 * @param[in]       Num         pWitの数
 *
 * @note
 *      - pWitはコピーするため解放はpTxで管理しない。
 */
bool btc_sw_set_vin_p2wsh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pWits[], int Num);


/** P2WPKH署名チェック
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       Value           該当するvinのvalue
 * @param[in]       pPubKeyHash     該当するvinのPubKeyHash(P2SH)
 * @return      true:チェックOK
 *
 * @note
 *      - pPubKeyHashは、pTxの署名部分が持つ公開鍵から生成したPubKeyHashと比較する
 */
bool btc_sw_verify_p2wpkh(const btc_tx_t *pTx, uint32_t Index, uint64_t Value, const uint8_t *pPubKeyHash);


/** P2WPKH署名チェック(アドレス)
 *
 * @param[in]       pTx     チェック対象
 * @param[in]       Index   対象vin
 * @param[in]       Value   該当するvinのvalue
 * @param[in]       pAddr   Bitcoinアドレス
 * @return      true:チェックOK
 */
bool btc_sw_verify_p2wpkh_addr(const btc_tx_t *pTx, uint32_t Index, uint64_t Value, const char *pAddr);


/** 2-of-2 multisigの署名チェック
 *
 */
bool btc_sw_verify_2of2(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pVout);


#if 0   //今のところ使い道がない
bool btc_sw_wtxid(uint8_t *pWTxId, const btc_tx_t *pTx);
bool btc_sw_is_segwit(const btc_tx_t *pTx);
#endif  //0


/** witnessScriptをPubKeyHash(P2SH)変換
 *
 *
 */
void btc_sw_wit2prog_p2wsh(uint8_t *pWitProg, const utl_buf_t *pWitScript);


//////////////////////
//UTIL
//////////////////////

/** P2PKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       pKeys
 * @return      true:成功
 */
bool btc_util_sign_p2pkh(btc_tx_t *pTx, uint32_t Index, const btc_keys_t *pKeys);


/** P2PKH署名チェック
 *
 * @param[in,out]   pTx         一時的に更新する
 * @param[in]       Index
 * @param[in]       pAddrVout   チェック用
 * @return      true:成功
 */
bool btc_util_verify_p2pkh(btc_tx_t *pTx, uint32_t Index, const char *pAddrVout);


/** P2WPKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - #btc_init()の設定で署名する
 */
bool btc_util_sign_p2wpkh(btc_tx_t *pTx, uint32_t Index, uint64_t Value, const btc_keys_t *pKeys);


/** P2WSH署名 - Phase1: トランザクションハッシュ作成
 *
 * @param[in]       pTx
 * @param[out]      pTxHash
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pWitScript
 * @retval  false   pTxがトランザクションとして不正
 */
bool btc_util_calc_sighash_p2wsh(const btc_tx_t *pTx, uint8_t *pTxHash, uint32_t Index, uint64_t Value,
                    const utl_buf_t *pWitScript);


/** P2WSH署名 - Phase2: 署名作成
 *
 * @param[out]      pSig
 * @param[in]       pTxHash
 * @param[in]       pKeys
 * @return      true:成功
 */
bool btc_util_sign_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const btc_keys_t *pKeys);


/** P2WSH署名 - Phase2: 署名作成(R/S)
 *
 * @param[out]      pRS
 * @param[in]       pTxHash
 * @param[in]       pKeys
 * @return      true:成功
 */
bool btc_util_sign_p2wsh_rs(uint8_t *pRS, const uint8_t *pTxHash, const btc_keys_t *pKeys);


/** トランザクションをBIP69に従ってソートする
 *
 * @param[in,out]   pTx     処理対象のトランザクション
 */
void btc_util_sort_bip69(btc_tx_t *pTx);


/** RIPMED160計算
 *
 * @param[out]      pRipemd160      演算結果(BTC_SZ_RIPEMD160以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void btc_util_ripemd160(uint8_t *pRipemd160, const uint8_t *pData, uint16_t Len);


/** SHA256計算
 *
 * @param[out]      pSha256         演算結果(BTC_SZ_SHA256以上のサイズが必要)
 * @param[in]       pData           元データ
 * @param[in]       Len             pData長
 */
void btc_util_sha256(uint8_t *pSha256, const uint8_t *pData, uint16_t Len);


/** HASH160計算
 *
 * @param[out]      pHash160        演算結果(BTC_SZ_HASH160以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void btc_util_hash160(uint8_t *pHash160, const uint8_t *pData, uint16_t Len);


/** HASH256計算
 *
 * @param[out]      pHash256        演算結果(BTC_SZ_HASH256以上のサイズが必要)
 * @param[in]       pData           対象データ
 * @param[in]       Len             pDatat長
 */
void btc_util_hash256(uint8_t *pHash256, const uint8_t *pData, uint16_t Len);


/** HASH256計算(連結)
 *
 * @param[out]      pHash256        演算結果(BTC_SZ_HASH256以上のサイズが必要)
 * @param[in]       pData1          対象データ1
 * @param[in]       Len1            pData1長
 * @param[in]       pData2          対象データ2
 * @param[in]       Len2            pData2長
 */
void btc_util_sha256cat(uint8_t *pSha256, const uint8_t *pData1, uint16_t Len1, const uint8_t *pData2, uint16_t Len2);


/** 圧縮公開鍵を非圧縮公開鍵展開
 *
 * @param[out]  point       非圧縮公開鍵座標
 * @param[in]   pPubKey     圧縮公開鍵
 * @return      0...正常
 *
 * @note
 *      - https://gist.github.com/flying-fury/6bc42c8bb60e5ea26631
 */
int btc_util_ecp_point_read_binary2(void *pPoint, const uint8_t *pPubKey);


/** PubKeyHash(P2PKH)をPubKeyHash(P2WPKH)に変換
 *
 * [00][14][pubKeyHash] --> HASH160
 *
 * @param[out]      pWPubKeyHash    変換後データ(#BTC_SZ_HASH_MAX)
 * @param[in]       pPubKeyHash     対象データ(#BTC_SZ_HASH_MAX)
 */
void btc_util_create_pkh2wpkh(uint8_t *pWPubKeyHash, const uint8_t *pPubKeyHash);


/**
 * pPubKeyOut = pPubKeyIn + pA * G
 *
 */
int btc_util_ecp_muladd(uint8_t *pResult, const uint8_t *pPubKeyIn, const void *pA);


/**
 * pResult = pPubKey * pMul
 *
 */
bool btc_util_mul_pubkey(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pMul, int MulLen);


#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
void btc_util_dumpbin(FILE *fp, const uint8_t *pData, uint32_t Len, bool bLf);
void btc_util_dumptxid(FILE *fp, const uint8_t *pTxid);
#else
#define btc_util_dumpbin(...)     //nothing
#define btc_util_dumptxid(...)    //nothing
#endif  //PTARM_USE_PRINTFUNC


#ifdef PTARM_USE_PRINTFUNC
//////////////////////
//PRINT
//////////////////////

/** #btc_tx_t の内容表示
 *
 * @param[in]       pTx     表示対象
 */
void btc_tx_print(const btc_tx_t *pTx);


/** トランザクションの内容表示
 *
 * @param[in]       pData       表示対象
 * @param[in]       Len         pDatat長
 */
void btc_tx_print_raw(const uint8_t *pData, uint32_t Len);


#else
#define btc_tx_print(...)             //nothing
#define btc_tx_print_raw(...)          //nothing
#endif  //PTARM_USE_PRINTFUNC


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_H__ */
