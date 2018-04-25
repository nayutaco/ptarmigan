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
/** @file   ucoin.h
 *  @brief  bitcoinトランザクション計算
 *  @author ueno@nayuta.co
 *
 * @note
 *      - 公開不要なAPIも多数あるが、今は整理しない
 *      - 制限事項多し
 *          - Little Endian環境のみ
 *          - あまりエラーを返さず、abortする
 *          - vinなどvarint型のものは、だいたい1byte分(スクリプトは受け付けるつもり)
 */
#ifndef UCOIN_H__
#define UCOIN_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define UCOIN_USE_PRINTFUNC     //出力有効

#define UCOIN_SZ_FIELD          (32)            ///< secp256k1の世界
#define UCOIN_SZ_RIPEMD160      (20)            ///< サイズ:RIPEMD160
#define UCOIN_SZ_HASH160        (20)            ///< サイズ:HASH160
#define UCOIN_SZ_SHA256         (32)            ///< サイズ:SHA256
#define UCOIN_SZ_HASH256        (32)            ///< サイズ:HASH256
#define UCOIN_SZ_PRIVKEY        (32)            ///< サイズ:非公開鍵
#define UCOIN_SZ_PUBKEY         (33)            ///< サイズ:圧縮された公開鍵
#define UCOIN_SZ_PUBKEY_UNCOMP  (64)            ///< サイズ:圧縮されていない公開鍵
#define UCOIN_SZ_PUBKEYHASH     (20)            ///< サイズ:PubKeyHash
#define UCOIN_SZ_ADDR_MAX       (35 + 1)        ///< サイズ:Bitcoinアドレス(26-35)
#define UCOIN_SZ_WIF_MAX        (55 + 1)        ///< サイズ:秘密鍵のWIF(上限不明)
#define UCOIN_SZ_TXID           (32)            ///< サイズ:TXID
#define UCOIN_SZ_SIGHASH        (32)            ///< サイズ:Signature計算用のトランザクションHASH
#define UCOIN_SZ_SIGN_RS        (64)            ///< サイズ:RS形式の署名
#define UCOIN_SZ_EKEY           (82)            ///< サイズ:拡張鍵
#define UCOIN_SZ_CHAINCODE      (32)            ///< サイズ:拡張鍵chaincode
#define UCOIN_SZ_EKEY_ADDR_MAX  (112 + 1)       ///< サイズ:拡張鍵アドレス長上限

#define UCOIN_PREF              (0)             ///< Prefix: 1:mainnet, 2:testnet
#define UCOIN_PREF_WIF          (1)             ///< Prefix: WIF
#define UCOIN_PREF_P2PKH        (2)             ///< Prefix: P2PKH
#define UCOIN_PREF_P2SH         (3)             ///< Prefix: P2SH
#define UCOIN_PREF_ADDRVER      (4)             ///< Prefix: Address Version
#define UCOIN_PREF_ADDRVER_SH   (5)             ///< Prefix: Address Version(Script)
#define UCOIN_PREF_MAX          (6)             ///< 内部管理用
#define UCOIN_PREF_NATIVE       (7)             ///< Prefix: native Witness
#define UCOIN_PREF_NATIVE_SH    (8)             ///< Prefix: native Witness(Script)

#define UCOIN_EKEY_PRIV         (0)             ///< 拡張鍵種別:秘密鍵
#define UCOIN_EKEY_PUB          (1)             ///< 拡張鍵種別:公開鍵
#define UCOIN_EKEY_HARDENED     ((uint32_t)0x80000000)  ///< 拡張鍵:hardened

#define UCOIN_OP_0              "\x00"          ///< OP_0
#define UCOIN_OP_2              "\x52"          ///< OP_2
#define UCOIN_OP_HASH160        "\xa9"          ///< OP_HASH160
#define UCOIN_OP_EQUAL          "\x87"          ///< OP_EQUAL
#define UCOIN_OP_EQUALVERIFY    "\x88"          ///< OP_EQUALVERIFY
#define UCOIN_OP_PUSHDATA1      "\x4c"          ///< OP_PUSHDATA1
#define UCOIN_OP_PUSHDATA2      "\x4d"          ///< OP_PUSHDATA2
#define UCOIN_OP_CHECKSIG       "\xac"          ///< OP_CHECKSIG
#define UCOIN_OP_CHECKMULTISIG  "\xae"          ///< OP_CHECKMULTISIG
#define UCOIN_OP_CLTV           "\xb1"          ///< OP_CHECKLOCKTIMEVERIFY
#define UCOIN_OP_CSV            "\xb2"          ///< OP_CHECKSEQUENCEVERIFY
#define UCOIN_OP_DROP           "\x75"          ///< OP_DROP
#define UCOIN_OP_2DROP          "\x6d"          ///< OP_2DROP
#define UCOIN_OP_DUP            "\x76"          ///< OP_DUP
#define UCOIN_OP_IF             "\x63"          ///< OP_IF
#define UCOIN_OP_NOTIF          "\x64"          ///< OP_NOTIF
#define UCOIN_OP_ELSE           "\x67"          ///< OP_ELSE
#define UCOIN_OP_ENDIF          "\x68"          ///< OP_ENDIF
#define UCOIN_OP_SWAP           "\x7c"          ///< OP_SWAP
#define UCOIN_OP_ADD            "\x93"          ///< OP_ADD
#define UCOIN_OP_SIZE           "\x82"          ///< OP_SIZE
#define UCOIN_OP_SZ1            "\x01"          ///< 1byte値
#define UCOIN_OP_SZ20           "\x14"          ///< 20byte値
#define UCOIN_OP_SZ32           "\x20"          ///< 32byte値
#define UCOIN_OP_SZ_PUBKEY      "\x21"          ///< 33byte値

#define UCOIN_DUST_LIMIT        ((uint64_t)546) ///< voutに指定できるamountの下限[satoshis]
                                                // 2018/02/11 17:54(JST)
                                                // https://github.com/bitcoin/bitcoin/blob/fe53d5f3636aed064823bc220d828c7ff08d1d52/src/test/transaction_tests.cpp#L695
                                                //
                                                // https://github.com/bitcoin/bitcoin/blob/5961b23898ee7c0af2626c46d5d70e80136578d3/src/policy/policy.cpp#L52-L55

#define UCOIN_TX_VERSION_INIT   (2)

#define UCOIN_BUF_INIT          { (uint8_t *)NULL, (uint32_t)0 }
#define UCOIN_TX_INIT           { UCOIN_TX_VERSION_INIT, 0, (ucoin_vin_t *)NULL, 0, (ucoin_vout_t *)NULL, 0 }


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    UCOIN_MBTC2SATOSHI
 *  @brief  mBTCをsatochi変換
 */
#define UCOIN_MBTC2SATOSHI(mbtc)        ((uint64_t)((mbtc) * 100000 + 0.5))

/** @def    UCOIN_BTC2SATOSHI
 *  @brief  BTCをsatochi変換
 */
#define UCOIN_BTC2SATOSHI(mbtc)         ((uint64_t)((mbtc) * (uint64_t)100000000 + 0.5))

/** @def    UCOIN_SATOSHI2MBTC
 *  @brief  satoshiをmBTC変換
 */
#define UCOIN_SATOSHI2MBTC(stc)         ((double)(stc) / 100000)

/** @def    UCOIN_SATOSHI2BTC
 *  @brief  satoshiをBTC変換
 */
#define UCOIN_SATOSHI2BTC(stc)          ((double)(stc) / (double)100000000)

/** @def    UCOIN_VOUT2PKH_P2PKH
 *  @brief  scriptPubKey(P2PKH)からPubKeyHashアドレス位置算出
 */
#define UCOIN_VOUT2PKH_P2PKH(script)    ((script) + 4)

/** @def    UCOIN_VOUT2PKH_P2SH
 *  @brief  scriptPubKey(P2SH)からPubKeyHashアドレス位置算出
 */
#define UCOIN_VOUT2PKH_P2SH(script)     ((script) + 2)

/** @def    UCOIN_IS_DUST
 *  @brief  amountが支払いに使用できないDUSTかどうかチェックする(true:支払えない)
 */
#define UCOIN_IS_DUST(amount)           (UCOIN_DUST_LIMIT > (amount))


/**************************************************************************
 * types
 **************************************************************************/

/** @enum   ucoin_chain_t
 *  @brief  blockchain種別
 */
typedef enum {
    UCOIN_UNKNOWN,
    UCOIN_MAINNET,          ///< mainnet
    UCOIN_TESTNET           ///< testnet, regtest
} ucoin_chain_t;


/** @struct ucoin_buf_t
 *  @brief  バッファ管理構造体
 *
 */
typedef struct {
    uint8_t         *buf;       ///< バッファ(malloc前提)
    uint32_t        len;        ///< bufサイズ
} ucoin_buf_t;


/** @struct     ucoin_push_t
 *  @brief      PUSH管理構造体
 */
typedef struct {
    uint32_t        pos;            ///< 次書込み位置
    ucoin_buf_t     *data;          ///< 更新対象
} ucoin_push_t;


/** @struct     ucoin_ekey_t
 *  @brief      Extended Key管理構造体
 */
typedef struct {
    uint8_t     type;                               ///<
    uint8_t     depth;                              ///<
    uint32_t    fingerprint;                        ///<
    uint32_t    child_number;                       ///<
    uint8_t     chain_code[UCOIN_SZ_CHAINCODE];     ///<
    uint8_t     key[UCOIN_SZ_PUBKEY];               ///<
} ucoin_ekey_t;


/** @struct     ucoin_util_keys_t
 *  @brief      鍵情報
 */
typedef struct {
    uint8_t     priv[UCOIN_SZ_PRIVKEY];             ///< 秘密鍵
    uint8_t     pub[UCOIN_SZ_PUBKEY];               ///< 公開鍵
} ucoin_util_keys_t;


/** @struct ucoin_vin_t
 *  @brief  VIN管理構造体
 */
typedef struct {
    uint8_t         txid[UCOIN_SZ_TXID];    ///< [outpoint]TXID
    uint32_t        index;                  ///< [outpoint]index
    ucoin_buf_t     script;                 ///< scriptSig
    uint32_t        wit_cnt;                ///< witness数(0のとき、witnessは無視)
    ucoin_buf_t     *witness;               ///< witness(配列的に使用する)
    uint32_t        sequence;               ///< sequence
} ucoin_vin_t;


/** @struct ucoin_vout_t
 *  @brief  VOUT管理構造体
 */
typedef struct {
    uint64_t        value;                  ///< value[単位:satoshi]
    ucoin_buf_t     script;                 ///< scriptPubKey
    uint8_t         opt;                    ///< 付加情報(ln用)
                                            //      ln_create_htlc_tx()でln_htlctype_tに設定
                                            //      ln_create_commit_tx()でln_tx_cmt_t.pp_htlcinfo[]のindex値(or LN_HTLCTYPE_TOLOCAL/REMOTE)に設定
} ucoin_vout_t;


/** @struct ucoin_tx_t
 *  @brief  TX管理構造体
 */
typedef struct {
    uint32_t        version;        ///< TX version

    uint32_t        vin_cnt;        ///< vin数(0のとき、vinは無視)
    ucoin_vin_t     *vin;           ///< vin(配列的に使用する)

    uint32_t        vout_cnt;       ///< vout数(0のとき、voutは無視)
    ucoin_vout_t    *vout;          ///< vout(配列的に使用する)

    uint32_t        locktime;       ///< locktime
} ucoin_tx_t;


/** @enum   ucoin_keys_sort_t
 *  @brief  鍵ソート結果
 */
typedef enum {
    UCOIN_KEYS_SORT_ASC,            ///< 順番が昇順
    UCOIN_KEYS_SORT_OTHER           ///< それ以外
} ucoin_keys_sort_t;


/** @enum ucoin_genesis_t */
typedef enum {
    UCOIN_GENESIS_UNKNOWN,          ///< 不明
    UCOIN_GENESIS_BTCMAIN,          ///< Bitcoin mainnet
    UCOIN_GENESIS_BTCTEST,          ///< Bitcoin testnet
    UCOIN_GENESIS_BTCREGTEST,       ///< Bitcoin regtest
} ucoin_genesis_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 初期化
 *
 * @param[in]       chain           UCOIN_MAINNET / UCOIN_TESTNET
 * @param[in]       bSegNative      true:segwit native transaction
 */
bool ucoin_init(ucoin_chain_t net, bool bSegNative);


/** 終了
 *
 *
 */
void ucoin_term(void);


/** blockchain種別取得
 *
 */
ucoin_chain_t ucoin_get_chain(void);


//////////////////////
//KEYS
//////////////////////

/** WIF形式秘密鍵をRAW形式に変換
 *
 * @param[out]      pPrivKey        変換後データ(UCOIN_SZ_PRIVKEY以上のサイズが必要)
 * @param[out]      pChain          WIFのblockchain種別
 * @param[in]       pWifPriv        対象データ(\0 terminate)
 * @return      true:成功
 *
 * @note
 *      - #ucoin_init()の設定と一致しない場合、abortする
 */
bool ucoin_keys_wif2priv(uint8_t *pPrivKey, ucoin_chain_t *pChain, const char *pWifPriv);


/** RAW秘密鍵をWI形式秘密鍵に変換
 *
 * @param[out]      pWifPriv
 * @param[in]       pPrivKey
 * @return      true:成功
 */
bool ucoin_keys_priv2wif(char *pWifPriv, const uint8_t *pPrivKey);


/** 秘密鍵を公開鍵に変換
 *
 * @param[out]      pPubKey         変換後データ(UCOIN_SZ_PUBKEY以上のサイズが必要)
 * @param[in]       pPrivKey        対象データ(UCOIN_SZ_PRIVKEY)
 *
 * @note
 *      - pPubKeyは圧縮された公開鍵になる
 */
bool ucoin_keys_priv2pub(uint8_t *pPubKey, const uint8_t *pPrivKey);


/** 公開鍵をBitcoinアドレス(P2PKH)に変換
 *
 * @param[out]      pAddr           変換後データ(#UCOIN_SZ_ADDR_MAX 以上のサイズを想定)
 * @param[in]       pPubKey         対象データ(UCOIN_SZ_PUBKEY)
 */
bool ucoin_keys_pub2p2pkh(char *pAddr, const uint8_t *pPubKey);


/** 公開鍵をBitcoinアドレス(P2WPKH)に変換
 *
 * @param[out]      pWAddr          変換後データ(UCOIN_SZ_WPKHADDR以上のサイズを想定)
 * @param[in]       pPubKey         対象データ(UCOIN_SZ_PUBKEY)
 */
bool ucoin_keys_pub2p2wpkh(char *pWAddr, const uint8_t *pPubKey);


/** P2PKHからP2WPKHへの変換
 *
 * @param[out]      pWAddr
 * @param[in]       pAddr
 */
bool ucoin_keys_addr2p2wpkh(char *pWAddr, const char *pAddr);


/** witnessScriptをBitcoinアドレスに変換
 *
 * @param[out]      pWAddr          変換後データ
 * @param[in]       pWitScript      対象データ
 *
 * @note
 *      - pWAddrのサイズは、native=#UCOIN_SZ_WSHADDR, 非native=#UCOIN_SZ_ADDR_MAX 以上にすること
 */
bool ucoin_keys_wit2waddr(char *pWAddr, const ucoin_buf_t *pWitScript);


/** 圧縮された公開鍵を展開
 *
 * @param[out]  pUncomp     展開後の公開鍵
 * @param[in]   pPubKey     圧縮された公開鍵
 *
 * @note
 *      - pUncompは使用後に #ucoin_buf_free()で解放すること
 */
bool ucoin_keys_pubuncomp(uint8_t *pUncomp, const uint8_t *pPubKey);


/** 秘密鍵の範囲チェック
 *
 * @param[in]   pPrivKey    チェック対象
 * @retval  true    正常
 */
bool ucoin_keys_chkpriv(const uint8_t *pPrivKey);


/** 公開鍵のチェック
 *
 * @param[in]       pPubKey     チェック対象
 * @return      true:SECP256K1の公開鍵としては正当
 */
bool ucoin_keys_chkpub(const uint8_t *pPubKey);


/** MultiSig 2-of-2スキームのredeem scriptを作成
 * @code
 *  OP_2
 *      21 (pubkey1[33])
 *      21 (pubkey2[33])
 *  OP_2
 *  OP_CHECKMULTISIG
 * @endcode
 *
 * @param[out]      pRedeem     2-of-2 redeem script
 * @param[in]       pPubKey1    公開鍵1
 * @param[in]       pPubKey2    公開鍵2
 *
 * @note
 *      - 公開鍵の順番は pPubKey1, pPubKey2 の順
 */
bool ucoin_keys_create2of2(ucoin_buf_t *pRedeem, const uint8_t *pPubKey1, const uint8_t *pPubKey2);


/** M-of-Nスキームのredeem script作成
 *
 * @param[out]      pRedeem
 * @param[in]       pPubKeys
 * @param[in]       Num
 * @param[in]       M
 *
 * @note
 *      - 公開鍵はソートしない
 */
bool ucoin_keys_createmulti(ucoin_buf_t *pRedeem, const uint8_t *pPubKeys[], int Num, int M);


/** BitcoinアドレスからPubKeyHashを求める
 *
 * @param[out]      pPubKeyHash     PubKeyHash
 * @param[out]      pPrefix         pAddrの種類(UCOIN_PREF_xxx)
 * @param[in]       pAddr           Bitcoinアドレス
 * @return      true:成功
 */
bool ucoin_keys_addr2pkh(uint8_t *pPubKeyHash, int *pPrefix, const char *pAddr);


/** BitcoinアドレスからscriptPubKeyを求める
 *
 * @param[out]  pScriptPk   scriptPubKey
 * @param[in]   pAddr       Bitcoinアドレス
 * @return      true:成功
 */
bool ucoin_keys_addr2spk(ucoin_buf_t *pScriptPk, const char *pAddr);


//////////////////////
//BUF
//////////////////////


/** #ucoin_buf_t 初期化
 *
 * @param[in,out]   pBuf    処理対象
 */
void ucoin_buf_init(ucoin_buf_t *pBuf);


/** #ucoin_buf_t のメモリ解放
 *
 * @param[in,out]   pBuf    処理対象
 */
void ucoin_buf_free(ucoin_buf_t *pBuf);


/** #ucoin_buf_t へのメモリ確保
 *
 * @param[out]      pBuf        処理対象
 * @param[in]       Size        確保するメモリサイズ
 *
 * @note
 *      - #ucoin_buf_init()の代わりに使用できるが、元の領域は解放しない
 */
void ucoin_buf_alloc(ucoin_buf_t *pBuf, uint32_t Size);


/** #ucoin_buf_t へのメモリ確保及びデータコピー
 *
 * @param[out]      pBuf        処理対象
 * @param[in]       pData       対象データ
 * @param[in]       Len         pData長
 *
 * @note
 *      - #ucoin_buf_init()の代わりに使用できるが、元の領域は解放しない
 */
void ucoin_buf_alloccopy(ucoin_buf_t *pBuf, const uint8_t *pData, uint32_t Len);


/** #ucoin_buf_t の比較
 *
 * @param[in]       pBuf1       比較対象1
 * @param[in]       pBuf2       比較対象2
 * @retval      true        一致
 */
bool ucoin_buf_cmp(const ucoin_buf_t *pBuf1, const ucoin_buf_t *pBuf2);


//////////////////////
//TX
//////////////////////

/** #ucoin_tx_t の初期化
 *
 * @param[out]      pTx         対象データ
 *
 * @note
 *      - versionは2で初期化する(OP_CSVやOP_CLTVを使用する場合が多いため)
 */
void ucoin_tx_init(ucoin_tx_t *pTx);


/** #ucoin_tx_t のメモリ解放
 *
 * @param[in,out]   pTx     処理対象
 *
 * @note
 *      - vin, vout, witnessに確保されたメモリを解放する
 *      - メモリ解放以外の値(version, locktime)は維持する。
 */
void ucoin_tx_free(ucoin_tx_t *pTx);


/** #ucoin_vin_t の追加
 *
 * @param[in,out]   pTx         追加対象
 * @param[in]       pTxId       追加するvinのTXID(Little Endian)
 * @param[in]       Index       追加するvinのindex
 * @return          追加した #ucoin_vin_t のアドレス
 *
 * @attention
 *      - realloc()するため、取得したアドレスは次に #ucoin_tx_add_vin()しても有効なのか確実ではない。
 *          すぐに使用してアドレスは保持しないこと。
 * @note
 *      - realloc()するため、事前のfree処理は不要
 *      - sequenceは0xFFFFFFFFで初期化している
 *      - scriptSigは空のため、戻り値を使って #ucoin_buf_alloccopy()でコピーすることを想定している
 */
ucoin_vin_t *ucoin_tx_add_vin(ucoin_tx_t *pTx, const uint8_t *pTxId, int Index);


/** witnessの追加
 *
 * @param[in,out]   pVin        追加対象
 * @return          追加したwitnessのアドレス
 *
 * @note
 *      - realloc()するため、事前のfree処理は不要
 *      - witnessは空のため、戻り値を使って #ucoin_buf_alloccopy()でコピーすることを想定している
 */
ucoin_buf_t *ucoin_tx_add_wit(ucoin_vin_t *pVin);


/** #ucoin_vout_t の追加
 *
 * @param[in,out]   pTx         追加対象
 * @param[in]       Value       追加したvoutのvalue(単位:satoshi)
 * @return          追加した #ucoin_vout_t のアドレス
 *
 * @note
 *      - realloc()するため、事前のfree処理は不要
 *      - scriptPubKeyは空のため、戻り値を使って #ucoin_buf_alloccopy()でコピーすることを想定している
 */
ucoin_vout_t *ucoin_tx_add_vout(ucoin_tx_t *pTx, uint64_t Value);


/** vout追加
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pAddr
 * @return      trueのみ
 *
 * @note
 *      - pAddrで自動判別(P2PKH, P2SH, P2WPKH)
 */
bool ucoin_tx_add_vout_addr(ucoin_tx_t *pTx, uint64_t Value, const char *pAddr);


/** vout追加
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pPubKeyHash
 * @param[in]           Pref
 * @return      trueのみ
 */
bool ucoin_tx_add_vout_pkh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash, uint8_t Pref);


/** 標準P2PKHのvout追加
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pPubKeyHash
 * @return      trueのみ
 */
bool ucoin_tx_add_vout_p2pkh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash);


/** scriptPubKeyのデータを設定する
 *
 * @param[out]      pBuf        生成したscriptPubKey
 * @param[in]       pAddr       Bitcoinアドレス
 * @return      true:成功
 */
bool ucoin_tx_create_vout(ucoin_buf_t *pBuf, const char *pAddr);


/** scriptPubKey(P2PKH)のデータを設定する
 *
 * @param[out]      pBuf        生成したscriptPubKey(P2PKH)
 * @param[in]       pAddr       Bitcoinアドレス
 * @return      true:成功
 *
 * @note
 *      - 署名用にINPUT txのscriptPubKeyが必要だが、TXデータを持たず、P2PKHだからBitcoinアドレスから生成しよう、という場合に使用する
 */
bool ucoin_tx_create_vout_p2pkh(ucoin_buf_t *pBuf, const char *pAddr);


/** 標準P2PKHのvout追加(アドレス)
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pAddr       Bitcoinアドレス(P2PKH)
 */
bool ucoin_tx_add_vout_p2pkh_addr(ucoin_tx_t *pTx, uint64_t Value, const char *pAddr);


/** 標準P2SHのvout追加
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pPubKeyHash
 *
 */
bool ucoin_tx_add_vout_p2sh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash);


/** 標準P2SHのvout追加(アドレス)
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pAddr       Bitcoinアドレス(P2SH)
 */
bool ucoin_tx_add_vout_p2sh_addr(ucoin_tx_t *pTx, uint64_t Value, const char *pAddr);


/** 標準P2SHのvout追加(redeemScript)
 *
 * @param[in,out]       pTx
 * @param[in]           Value
 * @param[in]           pRedeem     redeemScript
 */
bool ucoin_tx_add_vout_p2sh_redeem(ucoin_tx_t *pTx, uint64_t Value, const ucoin_buf_t *pRedeem);


/** P2PKHのscriptSig作成
 *
 * @param[in,out]   pTx         対象トランザクション
 * @param[in]       Index       対象vinのIndex
 * @param[in]       pSig        署名
 * @param[in]       pPubKey     公開鍵
 *
 * @note
 *      - 対象のvinは既に追加されていること(addではなく、置き換える動作)
 */
bool ucoin_tx_set_vin_p2pkh(ucoin_tx_t *pTx, int Index, const ucoin_buf_t *pSig, const uint8_t *pPubKey);


/** P2SHのscriptSig作成
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
bool ucoin_tx_set_vin_p2sh(ucoin_tx_t *pTx, int Index, const ucoin_buf_t *pSigs[], int Num, const ucoin_buf_t *pRedeem);


/** トランザクションデータを #ucoin_tx_t に変換
 *
 * @param[out]      pTx         変換後データ
 * @param[in]       pData       トランザクションデータ
 * @param[in]       Len         pData長
 * @return          変換結果
 *
 * @note
 *      - 動的にメモリ確保するため、#ucoin_tx_free()を呼ぶこと
 */
bool ucoin_tx_read(ucoin_tx_t *pTx, const uint8_t *pData, uint32_t Len);


/** トランザクションデータ作成
 *
 * @param[out]      pBuf        変換後データ
 * @param[in]       pTx         対象データ
 *
 * @note
 *      - 動的にメモリ確保するため、pBufは使用後 #ucoin_buf_free()で解放すること
 *      - vin cntおよびvout cntは 252までしか対応しない(varint型の1byteまで)
 */
bool ucoin_tx_create(ucoin_buf_t *pBuf, const ucoin_tx_t *pTx);


/** 非segwitトランザクション署名用ハッシュ値計算
 *
 * @param[out]      pTxHash         ハッシュ値[UCOIN_SZ_SIGHASH]
 * @param[in,out]   pTx             元になるトランザクション
 * @param[in]       pScriptPks      [P2PKH]scriptPubKeyの配列, [P2SH]redeemScriptの配列
 * @param[in]       Num             pScriptPkの要素数(pTxのvin_cntと同じ)
 *
 * @note
 *      - pTxは一時的に内部で更新される
 *      - pTxのvin[x].scriptは #ucoin_tx_free()で解放される
 *      - ハッシュはSIGHASHALL
 *      - vinにscriptPubKeyを記入するので、先に #ucoin_tx_add_vin()しておくこと
 */
bool ucoin_tx_sighash(uint8_t *pTxHash, ucoin_tx_t *pTx, const ucoin_buf_t *pScriptPks[], uint32_t Num);


/** 署名計算
 *
 * @param[out]      pSig        署名結果
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPrivKey    秘密鍵
 * @return          true        成功
 *
 * @note
 *      - pSigは、成功かどうかにかかわらず#ucoin_buf_init()される
 *      - 成功時、pSigは #ucoin_buf_alloccopy() でメモリ確保するので、使用後は #ucoin_buf_free()で解放すること
 */
bool ucoin_tx_sign_(ucoin_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPrivKey);
static inline bool ucoin_tx_sign__(ucoin_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPrivKey, const char *fname, unsigned int line) {
    fprintf(stderr, "[%s][%u]ucoin_tx_sign:GOGO\n", fname, line);
    return ucoin_tx_sign_(pSig, pTxHash, pPrivKey);
}
#define ucoin_tx_sign(a,b,c)  ucoin_tx_sign__(a,b,c, __FILE__, __LINE__)


/** 署名計算(r/s)
 *
 * @param[out]      pRS         署名結果rs[64]
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPrivKey    秘密鍵
 * @return          true        成功
 */
bool ucoin_tx_sign_rs_(uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPrivKey);
static inline bool ucoin_tx_sign_rs__(uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPrivKey, const char *fname, unsigned int line) {
    fprintf(stderr, "[%s][%u]ucoin_tx_sign_rs:GOGO\n", fname, line);
    return ucoin_tx_sign_rs_(pRS, pTxHash, pPrivKey);
}
#define ucoin_tx_sign_rs(a,b,c)  ucoin_tx_sign_rs__(a,b,c, __FILE__, __LINE__)


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
bool ucoin_tx_verify(const ucoin_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPubKey);


/** 署名チェック(r/s)
 *
 * @param[in]       pRS         署名rs[64]
 * @param[in]       pTxHash     トランザクションハッシュ
 * @param[in]       pPubKey     公開鍵
 * @return          true:チェックOK
 */
bool ucoin_tx_verify_rs(const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPubKey);


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
 *      - #ucoin_tx_sign()と#ucoin_tx_set_vin_p2pkh()をまとめて実施
 *      - pPubKeyは、既にあるなら計算を省略したいので引数にしている
 *          - 使ってみて、計算済みになることが少ないなら、引数から削除する予定
 */
bool ucoin_tx_sign_p2pkh(ucoin_tx_t *pTx, int Index,
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
bool ucoin_tx_verify_p2pkh(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash);


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
bool ucoin_tx_verify_p2pkh_spk(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const ucoin_buf_t *pScriptPk);


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
bool ucoin_tx_verify_p2pkh_addr(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const char *pAddr);


/** MultiSig(P2SH)署名チェック
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pPubKeyHash     PubKeyHash
 * @return      true:チェックOK
 */
bool ucoin_tx_verify_multisig(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash);


/** P2SH署名チェック(scriptPubKey)
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pScriptPk       scriptPubKey
 * @return      true:チェックOK
 */
bool ucoin_tx_verify_p2sh_spk(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const ucoin_buf_t *pScriptPk);


/** P2SH署名チェック(アドレス)
 *
 * @param[in]       pTx             チェック対象
 * @param[in]       Index           対象vin
 * @param[in]       pTxHash         ハッシュ値
 * @param[in]       pAddr           Bitcoinアドレス
 * @return      true:チェックOK
 */
bool ucoin_tx_verify_p2sh_addr(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const char *pAddr);


/** 公開鍵復元
 *
 * @param[out]      pPubKey
 * @param[in]       RecId       recovery ID
 * @param[in]       pRS
 * @param[in]       pTxHash
 * @retval      true    成功
 */
bool ucoin_tx_recover_pubkey(uint8_t *pPubKey, int RecId, const uint8_t *pRS, const uint8_t *pTxHash);


/** 公開鍵復元ID取得
 *
 * @param[out]      pRecId      recovery ID
 * @param[in]       pPubKey
 * @param[in]       pRS
 * @param[in]       pTxHash
 * @retval      true    成功
 */
bool ucoin_tx_recover_pubkey_id(int *pRecId, const uint8_t *pPubKey, const uint8_t *pRS, const uint8_t *pTxHash);

/** TXID計算
 *
 * @param[out]  pTxId       計算結果(Little Endian)
 * @param[in]   pTx         対象トランザクション
 *
 * @note
 *      - pTxIdにはLittleEndianで出力される
 *      - pTxがsegwitの場合もTXIDが出力される
 */
bool ucoin_tx_txid(uint8_t *pTxId, const ucoin_tx_t *pTx);


/** TXID計算(raw data)
 *
 * @param[out]  pTxId       計算結果(Little Endian)
 * @param[in]   pTxRaw      対象トランザクション
 *
 * @note
 *      - pTxIdにはLittleEndianで出力される
 *      - pTxがsegwitの場合、WTXIDで出力される
 */
bool ucoin_tx_txid_raw(uint8_t *pTxId, const ucoin_buf_t *pTxRaw);


/** vsize取得
 * 
 * @param[in]   pData
 * @param[in]   Len
 * @retval  != 0    vbyte
 * @retval  == 0    エラー
 */
uint32_t ucoin_tx_get_vbyte_raw(const uint8_t *pData, uint32_t Len);


//////////////////////
//SW
//////////////////////

/** P2WPKHのvout追加
 *
 */
void ucoin_sw_add_vout_p2wpkh_pub(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey);


/** P2WPKHのvout追加
 *
 */
void ucoin_sw_add_vout_p2wpkh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash);


/** P2WSHのvout追加(witnessScript)
 *
 *
 */
void ucoin_sw_add_vout_p2wsh(ucoin_tx_t *pTx, uint64_t Value, const ucoin_buf_t *pWitScript);


/** P2WPKH署名計算で使用するScript Code取得
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pPubKey         公開鍵
 *
 * @note
 *      - pScriptCodeは使用後に #ucoin_buf_free()で解放すること
 */
void ucoin_sw_scriptcode_p2wpkh(ucoin_buf_t *pScriptCode, const uint8_t *pPubKey);


/** P2WPKH署名計算で使用するScript Code取得(vin)
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pVin            対象vin
 *
 * @note
 *      - pScriptCodeは使用後に #ucoin_buf_free()で解放すること
 */
bool ucoin_sw_scriptcode_p2wpkh_vin(ucoin_buf_t *pScriptCode, const ucoin_vin_t *pVin);


/** P2WSH署名計算で使用するScript Code取得
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pWit            witnessScript
 *
 * @note
 *      - pScriptCodeは使用後に #ucoin_buf_free()で解放すること
 */
void ucoin_sw_scriptcode_p2wsh(ucoin_buf_t *pScriptCode, const ucoin_buf_t *pWit);


/** P2WSH署名計算で使用するScript Code取得(vin)
 *
 * @param[out]      pScriptCode     P2WPKH用Script Code
 * @param[in]       pVin            対象vin
 *
 * @note
 *      - pScriptCodeは使用後に #ucoin_buf_free()で解放すること
 */
bool ucoin_sw_scriptcode_p2wsh_vin(ucoin_buf_t *pScriptCode, const ucoin_vin_t *pVin);


/** segwitトランザクション署名用ハッシュ値計算
 *
 * @param[out]      pTxHash             署名に使用するハッシュ値(UCOIN_SZ_HASH256)
 * @param[in]       pTx                 署名対象のトランザクションデータ
 * @param[in]       Index               署名するINPUTのindex番号
 * @param[in]       Value               署名するINPUTのvalue[単位:satoshi]
 * @param[in]       pScriptCode         Script Code
 *
 */
void ucoin_sw_sighash(uint8_t *pTxHash, const ucoin_tx_t *pTx, int Index, uint64_t Value,
                const ucoin_buf_t *pScriptCode);


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
bool ucoin_sw_set_vin_p2wpkh(ucoin_tx_t *pTx, int Index, const ucoin_buf_t *pSig, const uint8_t *pPubKey);


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
bool ucoin_sw_set_vin_p2wsh(ucoin_tx_t *pTx, int Index, const ucoin_buf_t *pWits[], int Num);


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
bool ucoin_sw_verify_p2wpkh(const ucoin_tx_t *pTx, int Index, uint64_t Value, const uint8_t *pPubKeyHash);


/** P2WPKH署名チェック(アドレス)
 *
 * @param[in]       pTx     チェック対象
 * @param[in]       Index   対象vin
 * @param[in]       Value   該当するvinのvalue
 * @param[in]       pAddr   Bitcoinアドレス
 * @return      true:チェックOK
 */
bool ucoin_sw_verify_p2wpkh_addr(const ucoin_tx_t *pTx, int Index, uint64_t Value, const char *pAddr);


/** 2-of-2 multisigの署名チェック
 *
 */
bool ucoin_sw_verify_2of2(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const ucoin_buf_t *pVout);


#if 0   //今のところ使い道がない
bool ucoin_sw_wtxid(uint8_t *pWTxId, const ucoin_tx_t *pTx);
bool ucoin_sw_is_segwit(const ucoin_tx_t *pTx);
#endif  //0


/** witnessScriptをPubKeyHash(P2SH)変換
 *
 *
 */
void ucoin_sw_wit2prog_p2wsh(uint8_t *pWitProg, const ucoin_buf_t *pWitScript);


//////////////////////
//PUSH
//////////////////////

/** ucoin_push_t初期化
 *
 * @param[out]  pPush       処理対象
 * @param[in]   pBuf        更新していくucoin_buf_t
 * @param[in]   Size        初期サイズ
 *
 * @note
 *      - データ追加時に初期サイズより領域が必要になれば拡張しているが、
 *          realloc()を繰り返すことになるので、必要なサイズ以上を確保した方が望ましい。
 *      - pDataは解放せず初期化して使用するため、必要なら先に解放すること。
 */
void ucoin_push_init(ucoin_push_t *pPush, ucoin_buf_t *pBuf, uint32_t Size);


/** データ追加
 *
 * @param[out]  pPush       処理対象
 * @param[in]   pData       追加データ
 * @param[in]   Len         pData長
 *
 * @note
 *      - 初期化時のサイズからあふれる場合、realloc()して拡張する。
 *      - そのまま追加するため、OP_PUSHDATAxなどは呼び出し元で行うこと。
 */
void ucoin_push_data(ucoin_push_t *pPush, const void *pData, uint32_t Len);


/** スタックへの値追加(符号無し)
 *
 * 1～5バイトの範囲で値を追加する。<br/>
 * スタックの値は符号ありとして処理されるが、Valueは符号無しのみとする。
 *
 * @param[out]  pPush       処理対象
 * @param[in]   Value       追加データ(符号無し)
 *
 * @attention
 *      - 符号ありの値をキャストしても符号無しとして扱う。
 */
void ucoin_push_value(ucoin_push_t *pPush, uint64_t Value);


/** サイズ調整
 *
 * ucoin_buf_tのサイズをucoin_push_tで管理しているサイズにあわせる。
 *
 * @param[out]  pPush       処理対象
 */
void ucoin_push_trim(ucoin_push_t *pPush);


//////////////////////
//EKEY
//////////////////////

/** 拡張鍵作成準備
 *
 * pPrivKeyが非NULL かつ pEKey->typeが #UCOIN_EKEY_PRIV の場合、以下のいずれかを行う。<br/>
 *      - pSeedが非NULL: Master秘密鍵とMaster公開鍵を生成<br/>
 *      - pSeedがNULL: 子秘密鍵と子公開鍵を生成<br/>
 * pEKey->typeが #UCOIN_EKEY_PUB の場合、子公開鍵を生成する。
 *
 * @param[in,out]   pEKey           拡張鍵構造体(type, depth, child_numberを設定しておく)
 * @param[in]       pPrivKey        親秘密鍵(NULL: 子公開鍵)
 * @param[in]       pPubKey         親公開鍵
 * @param[in]       pSeed           非NULL: Master / NULL: 子鍵
 * @param[in]       SzSeed          pSeedサイズ
 * @return      true:成功
 */
bool ucoin_ekey_prepare(ucoin_ekey_t *pEKey, uint8_t *pPrivKey, uint8_t *pPubKey, const uint8_t *pSeed, int SzSeed);


/** 拡張鍵生成
 *
 * @param[out]      pData       鍵データ
 * @param[out]      pAddr       非NULL:鍵アドレス文字列(NULL時は生成しない)
 * @param[in]       pEKey       生成元情報
 */
bool ucoin_ekey_create(uint8_t *pData, char *pAddr, const ucoin_ekey_t *pEKey);


/** 拡張鍵読込み
 *
 * @param[out]  pEKey       拡張鍵構造体
 * @param[in]   pData       鍵データ(Base58CHKデコード後)
 * @param[in]   Len         pData長
 * @return      true:成功
 */
bool ucoin_ekey_read(ucoin_ekey_t *pEKey, const uint8_t *pData, int Len);


/** 拡張鍵読込み
 *
 * @param[out]  pEKey       拡張鍵構造体
 * @param[in]   pXAddr      鍵データ(Base58CHK文字列)
 * @return      true:成功
 */
bool ucoin_ekey_read_addr(ucoin_ekey_t *pEKey, const char *pXAddr);


//////////////////////
//UTIL
//////////////////////

/** 乱数生成
 *
 * @param[out]      pData
 * @param[in]       Len         生成するサイズ
 */
void ucoin_util_random(uint8_t *pData, uint16_t Len);


/** WIFからの鍵生成
 *
 * @param[out]      pKeys           鍵情報
 * @param[out]      pChain          WIF種別
 * @param[in]       pWifPriv        WIF形式秘密鍵
 * @return      true    成功
 */
bool ucoin_util_wif2keys(ucoin_util_keys_t *pKeys, ucoin_chain_t *pChain, const char *pWifPriv);


/** 乱数での秘密鍵生成
 *
 * @param[out]      pPriv           秘密鍵
 */
void ucoin_util_createprivkey(uint8_t *pPriv);


/** 乱数での鍵生成
 *
 * @param[out]      pKeys           鍵情報
 * @return      true    成功
 */
bool ucoin_util_createkeys(ucoin_util_keys_t *pKeys);


/** #ucoin_keys_create2of2()のソートあり版
 *
 * @param[out]      pRedeem     2-of-2 redeem script
 * @param[out]      pSort       ソート結果
 * @param[in]       pPubKey1    公開鍵1
 * @param[in]       pPubKey2    公開鍵2
 *
 * @note
 *      - 公開鍵の順番は昇順
 */
bool ucoin_util_create2of2(ucoin_buf_t *pRedeem, ucoin_keys_sort_t *pSort, const uint8_t *pPubKey1, const uint8_t *pPubKey2);


/** P2PKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       pKeys
 * @return      true:成功
 */
bool ucoin_util_sign_p2pkh(ucoin_tx_t *pTx, int Index, const ucoin_util_keys_t *pKeys);


/** P2PKH署名チェック
 *
 * @param[in,out]   pTx         一時的に更新する
 * @param[in]       Index
 * @param[in]       pAddrVout   チェック用
 * @return      true:成功
 */
bool ucoin_util_verify_p2pkh(ucoin_tx_t *pTx, int Index, const char *pAddrVout);


/** P2WPKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - #ucoin_init()の設定で署名する
 */
bool ucoin_util_sign_p2wpkh(ucoin_tx_t *pTx, int Index, uint64_t Value, const ucoin_util_keys_t *pKeys);


/** P2WSH署名 - Phase1: トランザクションハッシュ作成
 *
 * @param[out]      pTxHash
 * @param[in]       pTx
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pWitScript
 */
void ucoin_util_calc_sighash_p2wsh(uint8_t *pTxHash, const ucoin_tx_t *pTx, int Index, uint64_t Value,
                    const ucoin_buf_t *pWitScript);


/** P2WSH署名 - Phase2: 署名作成
 *
 * @param[out]      pSig
 * @param[in]       pTxHash
 * @param[in]       pKeys
 * @return      true:成功
 */
bool ucoin_util_sign_p2wsh(ucoin_buf_t *pSig, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys);


/** P2WSH署名 - Phase2: 署名作成(R/S)
 *
 * @param[out]      pRS
 * @param[in]       pTxHash
 * @param[in]       pKeys
 * @return      true:成功
 */
bool ucoin_util_sign_p2wsh_rs(uint8_t *pRS, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys);


/** トランザクションをBIP69に従ってソートする
 *
 * @param[in,out]   pTx     処理対象のトランザクション
 */
void ucoin_util_sort_bip69(ucoin_tx_t *pTx);


/** ブロックチェーン種別取得
 *
 * @param[in]       pGenesisHash
 * @return      ブロックチェーン種別
 */
ucoin_genesis_t ucoin_util_get_genesis(const uint8_t *pGenesisHash);


/** ブロックチェーンハッシュ取得
 *
 * @param[in]       Kind
 * @return      ブロックチェーンハッシュ(未知のKindの場合はNULL)
 */
const uint8_t *ucoin_util_get_genesis_block(ucoin_genesis_t Kind);


#if defined(UCOIN_USE_PRINTFUNC) || defined(UCOIN_DEBUG)
void ucoin_util_dumpbin(FILE *fp, const uint8_t *pData, uint32_t Len, bool bLf);
void ucoin_util_dumptxid(FILE *fp, const uint8_t *pTxid);
#endif  //UCOIN_USE_PRINTFUNC


#ifdef UCOIN_USE_PRINTFUNC
//////////////////////
//PRINT
//////////////////////

/** #ucoin_tx_t の内容表示
 *
 * @param[in]       pTx     表示対象
 */
void ucoin_print_tx(const ucoin_tx_t *pTx);


/** トランザクションの内容表示
 *
 * @param[in]       pData       表示対象
 * @param[in]       Len         pDatat長
 */
void ucoin_print_rawtx(const uint8_t *pData, uint32_t Len);


/** スクリプトの内容表示
 *
 * @param[in]       pData       表示対象
 * @param[in]       Len         pData長
 */
void ucoin_print_script(const uint8_t *pData, uint16_t Len);


/** 拡張鍵の内容表示
 *
 * @param[in]       pEKey       拡張鍵構造体
 */
void ucoin_print_extendedkey(const ucoin_ekey_t *pEKey);
#endif  //UCOIN_USE_PRINTFUNC


#ifdef UCOIN_DEBUG_MEM
//////////////////////
//DBG
//////////////////////

/** (デバッグ用)malloc残数取得
 * ucoinライブラリ内でmalloc()した回数からfree()した回数を返す。<br/>
 * UCOIN_DEBUG_MEM 定義時のみ有効で、未定義の場合は常に-1を返す。
 *
 * @return  malloc残数
 */
int ucoin_dbg_malloc_cnt(void);
#endif  //UCOIN_DEBUG_MEM

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* UCOIN_H__ */
