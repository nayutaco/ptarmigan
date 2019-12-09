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
/** @file   btc.h
 *  @brief  bitcoin offline API header
 */
#ifndef BTC_TX_H__
#define BTC_TX_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"

#include "btc_keys.h"
#include "btc_crypto.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define BTC_SZ_TXID                     (32)                ///< サイズ:TXID

#define BTC_TX_VERSION_INIT             (2)
#define BTC_TX_INIT                     { BTC_TX_VERSION_INIT, 0, (btc_vin_t *)NULL, 0, (btc_vout_t *)NULL, 0 }
#define BTC_TX_SEQUENCE                 ((uint32_t)0xffffffff)
#define BTC_TX_LOCKTIME_LIMIT           ((uint32_t)500000000)
#define BTC_TX_PUBKEYS_PER_MULTISIG_MAX (20)

#ifdef USE_ELEMENTS
#define BTC_TX_ELE_VOUT_VER_NULL        (0x00)
#define BTC_TX_ELE_VOUT_VER_EXPLICIT    (0x01)

#define BTC_TX_ELE_VOUT_ADDR            (1)
#define BTC_TX_ELE_VOUT_DATA            (2)
#define BTC_TX_ELE_VOUT_BURN            (3)
#define BTC_TX_ELE_VOUT_FEE             (4)

#define BTC_TX_ELE_IDX_ISSUANCE         ((uint32_t)0x80000000)
#define BTC_TX_ELE_IDX_PEGIN            ((uint32_t)0x40000000)
#endif


/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * typedefs
 **************************************************************************/

//XXX:
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
#ifdef USE_ELEMENTS
    bool        issuance;
    bool        pegin;
#endif
} btc_vin_t;


/** @struct btc_vout_t
 *  @brief  VOUT管理構造体
 */
typedef struct {
    uint64_t    value;                  ///< value[単位:satoshi]
    utl_buf_t   script;                 ///< scriptPubKey
    uint16_t    opt;                    ///< 付加情報(ln用)
                                        //  ln_htlc_tx_create()でln_commit_tx_output_type_tに設定
                                        //  ln_commit_tx_create()でln_tx_cmt_t.pp_htlc_info[]のindex値
                                        //  (or LN_COMMIT_TX_OUTPUT_TYPE_TO_LOCAL/REMOTE)に設定
#ifdef USE_ELEMENTS
    uint8_t     asset[BTC_SZ_HASH256];
    uint8_t     type;
#endif
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
 *      - UTL_DBG_REALLOC()するため、取得したアドレスは次に #btc_tx_add_vin()しても有効なのか確実ではない。
 *          すぐに使用してアドレスは保持しないこと。
 * @note
 *      - UTL_DBG_REALLOC()するため、事前のUTL_DBG_FREE()処理は不要
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
 *      - UTL_DBG_REALLOC()するため、事前のUTL_DBG_FREE()処理は不要
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
 *      - UTL_DBG_REALLOC()するため、事前のUTL_DBG_FREE()処理は不要
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


/** add FEE vout(for Elements)
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @return      true:success
 * @note
 *      - ignore if defined USE_BITCOIN
 */
bool btc_tx_add_vout_fee(btc_tx_t *pTx, uint64_t Value);


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
 *      - 動的にメモリ確保するため、pBufは使用後 #UTL_DBG_FREE()で解放すること
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
bool btc_tx_sign_p2pkh(btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey);


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


/** weight取得
 *
 * @param[in]   pData
 * @param[in]   Len
 * @retval  != 0    weight
 * @retval  == 0    エラー
 */
uint32_t btc_tx_get_weight_raw(const uint8_t *pData, uint32_t Len);


/** BIP69 sort(vins and vouts)
 *
 * @param[in,out]   pTx     transaction for sort
 * @note
 *      - (Elements)vout fee add after calling btc_tx_sort_bip69() for c-lightning
 */
void btc_tx_sort_bip69(btc_tx_t *pTx);


#ifdef PTARM_USE_PRINTFUNC
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
#define btc_tx_print(...)
#define btc_tx_print_raw(...)
#endif  //PTARM_USE_PRINTFUNC


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_TX_H__ */
