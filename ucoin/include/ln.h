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
/** @file   ln.h
 *  @brief  Lightning
 *  @author ueno@nayuta.co
 *  @todo
 *      - 外部公開するAPIや構造体を整理する
 */
#ifndef LN_H__
#define LN_H__

#include <stdint.h>
#include <stdbool.h>

#include "ucoin.h"
#include "ln_err.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define LN_SZ_CHANNEL_ID                (32)        ///< サイズ:channel_id
#define LN_SZ_SHORT_CHANNEL_ID          (8)         ///< サイズ:short_channel_id
#define LN_SZ_SIGNATURE                 UCOIN_SZ_SIGN_RS    ///< サイズ:署名
#define LN_SZ_HASH                      (32)        ///< サイズ:xxx-hash
#define LN_SZ_PREIMAGE                  (32)        ///< サイズ:preimage
#define LN_SZ_SEED                      (32)        ///< サイズ:seed
#define LN_SZ_ONION_ROUTE               (1366)      ///< サイズ:onion-routing-packet
#define LN_SZ_ALIAS                     (32)        ///< サイズ:alias長
#define LN_SZ_NOISE_HEADER              (sizeof(uint16_t) + 16)     ///< サイズ:noiseパケットヘッダ
#define LN_SZ_GFLEN_MAX                 (4)         ///< init.gflen最大
#define LN_SZ_LFLEN_MAX                 (4)         ///< init.lflen最大

#define LN_FUNDIDX_MAX                  (6)         ///< 管理用
#define LN_SCRIPTIDX_MAX                (5)         ///< 管理用
#define LN_HTLC_MAX                     (6)         ///< 自分のHTLC数   TODO:暫定
                                                    //      max_accepted_htlcsとして使用する
                                                    //      相手の分も同じ分しか用意していない
                                                    //      相手からの要求はmax_accepted_htlcsまでしか受け入れないので、
                                                    //      こちらから要求しなければ済む話である。
#define LN_NODE_MAX                     (5)         ///< 保持するノード情報数   TODO:暫定
#define LN_CHANNEL_MAX                  (10)        ///< 保持するチャネル情報数 TODO:暫定
#define LN_HOP_MAX                      (20)        ///< onion hop数
#define LN_FEERATE_PER_KW               (500)       ///< estimate feeできなかった場合のfeerate_per_kw
#define LN_BLK_FEEESTIMATE              (6)         ///< estimatefeeのブロック数(2以上)
#define LN_MIN_FINAL_CLTV_EXPIRY        (9)         ///< min_final_cltv_expiryのデフォルト値
#define LN_INVOICE_EXPIRY               (3600)      ///< invoice expiryのデフォルト値

#define LN_FEE_COMMIT_BASE              (724ULL)    ///< commit_tx base fee

// ln_update_add_htlc_t.flag用
#define LN_HTLC_FLAG_IS_RECV(f)         ((f) & LN_HTLC_FLAG_RECV)   ///< true:Received HTLC / false:Offered HTLC
#define LN_HTLC_FLAG_SEND               (0x00)                      ///< Offered HTLC(add_htlcを送信した)
#define LN_HTLC_FLAG_RECV               (0x01)                      ///< Received HTLC(add_htlcを受信した)

// node_announcement address descriptor
#define LN_NODEDESC_NONE                (0)         ///< padding. data = none (length 0)
#define LN_NODEDESC_IPV4                (1)         ///< ipv4. data = [4:ipv4_addr][2:port] (length 6)
#define LN_NODEDESC_IPV6                (2)         ///< ipv6. data = [16:ipv6_addr][2:port] (length 18)
#define LN_NODEDESC_ONIONV2             (3)         ///< tor v2 onion service. data = [10:onion_addr][2:port] (length 12)
#define LN_NODEDESC_ONIONV3             (4)         ///< tor v3 onion service. data [35:onion_addr][2:port] (length 37)
#define LN_NODEDESC_MAX                 LN_NODEDESC_ONIONV3

// self->fund_flag
#define LN_FUNDFLAG_FUNDER              (0x01)      ///< true:funder / false:fundee
#define LN_FUNDFLAG_ANNO_CH             (0x02)      ///< open_channel.channel_flags.announce_channel
#define LN_FUNDFLAG_FUNDING             (0x04)      ///< 1:open_channel～funding_lockedまで
#define LN_FUNDFLAG_CLOSE               (0x08)      ///< 1:funding_txがspentになっている

// channel_update.flags
#define LN_CNLUPD_FLAGS_DIRECTION       (0x0001)    ///< b0: direction
#define LN_CNLUPD_FLAGS_DISABLE         (0x0002)    ///< b1: disable

// ln_close_force_t.p_tx, p_htlc_idxのインデックス値
#define LN_CLOSE_IDX_COMMIT             (0)         ///< commit_tx
#define LN_CLOSE_IDX_TOLOCAL            (1)         ///< to_local tx
#define LN_CLOSE_IDX_TOREMOTE           (2)         ///< to_remote tx
#define LN_CLOSE_IDX_HTLC               (3)         ///< HTLC tx

// revoked transaction closeされたときの self->p_revoked_vout, p_revoked_witのインデックス値
#define LN_RCLOSE_IDX_TOLOCAL           (0)         ///< to_local
#define LN_RCLOSE_IDX_TOREMOTE          (1)         ///< to_remote
#define LN_RCLOSE_IDX_HTLC              (2)         ///< HTLC

#define LN_UGLY_NORMAL                              ///< payment_hashを保存するタイプ
                                                    ///< コメントアウトするとDB保存しなくなるが、revoked transaction closeから取り戻すために
                                                    ///< 相手のアクションが必要となる


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    LN_SEQUENCE(obs)
 *  @brief  obscured commitment numberから<sequence>算出
 */
#define LN_SEQUENCE(obs)        ((uint32_t)(0x80000000 | (((obs) >> 24) & 0xffffff))) //[0x80][上位3byte]


/** @def    LN_LOCKTIME(obs)
 *  @brief  obscured commitment numberから<locktime>算出
 */
#define LN_LOCKTIME(obs)        ((uint32_t)(0x20000000 | ((obs) & 0xffffff)))         //[0x20][下位3byte]


/** @def    LN_SATOSHI2MSAT(obs)
 *  @brief  satoshiをmsat(milli-satoshi)変換
 */
#define LN_SATOSHI2MSAT(sat)    ((uint64_t)(sat) * (uint64_t)1000)


/** @def    LN_MSAT2SATOSHI(obs)
 *  @brief  msat(milli-satoshi)をsatoshi変換
 */
#define LN_MSAT2SATOSHI(msat)   ((msat) / 1000)


//
// [ucoincli -d]マクロがtrueになるのが通常動作とする
//

// 1: update_fulfill_htlcを返さない
#define LN_DBG_FULFILL()        ((ln_get_debug() & 0x01) == 0)
// 2: closeでclosing_txを展開しない
#define LN_DBG_CLOSING_TX()     ((ln_get_debug() & 0x02) == 0)
// 4: HTLC scriptでpreimageが一致しても不一致とみなす
#define LN_DBG_MATCH_PREIMAGE() ((ln_get_debug() & 0x04) == 0)
// 8: monitoringで未接続ノードに接続しに行かない
#define LN_DBG_NODE_AUTO_CONNECT() ((ln_get_debug() & 0x08) == 0)


/********************************************************************
 * typedefs
 ********************************************************************/

//forward definition
struct ln_self_t;
typedef struct ln_self_t ln_self_t;


/** @enum   ln_cb_t
 *  @brief  コールバック理由
 */
typedef enum {
    LN_CB_ERROR,                ///< エラー通知
    LN_CB_INIT_RECV,            ///< init受信通知
    LN_CB_REESTABLISH_RECV,     ///< channel_reestablish受信通知
    LN_CB_SIGN_FUNDINGTX_REQ,   ///< funding_tx署名要求
    LN_CB_FUNDINGTX_WAIT,       ///< funding_tx安定待ち要求
    LN_CB_FUNDINGLOCKED_RECV,   ///< funding_locked受信通知
    LN_CB_CHANNEL_ANNO_RECV,    ///< channel_announcement受信通知
    LN_CB_NODE_ANNO_RECV,       ///< node_announcement受信通知
    LN_CB_ANNO_SIGSED,          ///< announcement_signatures完了通知
    LN_CB_ADD_HTLC_RECV_PREV,   ///< update_add_htlc処理前通知
    LN_CB_ADD_HTLC_RECV,        ///< update_add_htlc受信通知
    LN_CB_FULFILL_HTLC_RECV,    ///< update_fulfill_htlc受信通知
    LN_CB_FAIL_HTLC_RECV,       ///< update_fail_htlc受信通知
    LN_CB_COMMIT_SIG_RECV_PREV, ///< commitment_signed処理前通知
    LN_CB_COMMIT_SIG_RECV,      ///< commitment_signed受信通知
    LN_CB_HTLC_CHANGED,         ///< HTLC変化通知
    LN_CB_SHUTDOWN_RECV,        ///< shutdown受信通知
    LN_CB_CLOSED_FEE,           ///< closing_signed受信通知(FEE不一致)
    LN_CB_CLOSED,               ///< closing_signed受信通知(FEE一致)
    LN_CB_SEND_REQ,             ///< peerへの送信要求
    LN_CB_MAX,
} ln_cb_t;


/** @typedef    ln_callback_t
 *  @brief      通知コールバック関数
 */
typedef void (*ln_callback_t)(ln_self_t*, ln_cb_t, void *);


/**************************************************************************
 * typedefs : HTLC
 **************************************************************************/

/** @enum   ln_htlctype_t
 *  @brief  HTLC種別
 */
typedef enum {
    LN_HTLCTYPE_NONE,                               ///< 未設定
    LN_HTLCTYPE_OFFERED,                            ///< Offered HTLC
    LN_HTLCTYPE_RECEIVED,                           ///< Received HTLC
    LN_HTLCTYPE_TOLOCAL     = 0xfe,                 ///< vout=to_local
    LN_HTLCTYPE_TOREMOTE    = 0xff                  ///< vout=to_remote
} ln_htlctype_t;


/** @struct ln_feeinfo_t
 *  @brief  FEE情報
 */
typedef struct {
    uint32_t        feerate_per_kw;                 ///< [IN]1000byte辺りのsatoshi
    uint64_t        dust_limit_satoshi;             ///< [IN]dust_limit_satoshi

    uint64_t        htlc_success;                   ///< [CALC]HTLC success Transaction FEE
    uint64_t        htlc_timeout;                   ///< [CALC]HTLC timeout Transaction FEE
    uint64_t        commit;                         ///< [CALC]Commitment Transaction FEE
} ln_feeinfo_t;


/** @struct ln_htlcinfo_t
 *  @brief  HTLC情報
 */
typedef struct {
    ln_htlctype_t           type;                   ///< HTLC種別
    uint32_t                expiry;                 ///< Expiry
    uint64_t                amount_msat;            ///< amount_msat
    const uint8_t           *preimage_hash;         ///< preimageをHASH160したデータ
    ucoin_buf_t             script;                 ///< スクリプト
} ln_htlcinfo_t;


/** @struct ln_tx_cmt_t
 *  @brief  Commitment Transaction生成用情報
 */
typedef struct {
    struct {
        const uint8_t       *txid;              ///< funding txid
        uint32_t            txid_index;         ///< funding txid index
        uint64_t            satoshi;            ///< funding satoshi
        const ucoin_buf_t   *p_script;          ///< funding script
        ucoin_util_keys_t   *p_keys;            ///< funding local keys(remoteは署名をもらう)
    } fund;

    struct {
        uint64_t            satoshi;            ///< local satoshi
        const ucoin_buf_t   *p_script;          ///< to-local script
    } local;
    struct {
        uint64_t            satoshi;            ///< remote satoshi
        const uint8_t       *pubkey;            ///< remote pubkey(to-remote用)
    } remote;

    uint64_t                obscured;           ///< Obscured Commitment Number(ln_calc_obscured_txnum())
    ln_feeinfo_t            *p_feeinfo;         ///< FEE情報
    ln_htlcinfo_t           **pp_htlcinfo;      ///< HTLC情報ポインタ配列(htlcinfo_num個分)
    uint8_t                 htlcinfo_num;       ///< HTLC数
} ln_tx_cmt_t;


/** @struct ln_derkey_storage
 *  @brief  per-commitment secret storage
 *      https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#efficient-per-commitment-secret-storage
 */
typedef struct {
    struct {
        uint8_t     secret[UCOIN_SZ_PRIVKEY];   ///< secret
        uint64_t    index;                      ///< index
    } storage[49];
} ln_derkey_storage;


/**************************************************************************
 * typedefs : Establish channel
 **************************************************************************/

/// @addtogroup channel_establish
/// @{

/** @struct ln_open_channel_t
 *  @brief  [Establish]open_channel
 */
typedef struct {
    uint64_t    funding_sat;                        ///< 8 : funding-satoshis
    uint64_t    push_msat;                          ///< 8 : push-msat
    uint64_t    dust_limit_sat;                     ///< 8 : dust-limit-satoshis
    uint64_t    max_htlc_value_in_flight_msat;      ///< 8 : max-htlc-value-in-flight-msat
    uint64_t    channel_reserve_sat;                ///< 8 : channel-reserve-satoshis
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc-minimum-msat
    uint32_t    feerate_per_kw;                     ///< 4 : feerate-per-kw
    uint16_t    to_self_delay;                      ///< 2 : to-self-delay
    uint16_t    max_accepted_htlcs;                 ///< 2 : max-accepted-htlcs

    uint8_t     *p_temp_channel_id;                 ///< 32: temporary-channel-id
    uint8_t     *p_pubkeys[LN_FUNDIDX_MAX];         ///< 33: [0]funding-pubkey
                                                    ///< 33: [1]revocation-basepoint
                                                    ///< 33: [2]payment-basepoint
                                                    ///< 33: [3]delayed-payment-basepoint
                                                    ///< 33: [4]first-per-commitment-point
    uint8_t     channel_flags;                      ///< 1 : [1]channel_flags
} ln_open_channel_t;


/** @struct ln_accept_channel_t
 *  @brief  [Establish]accept_channel
 */
typedef struct {
    uint64_t    dust_limit_sat;                     ///< 8 : dust-limit-satoshis
    uint64_t    max_htlc_value_in_flight_msat;      ///< 8 : max-htlc-value-in-flight-msat
    uint64_t    channel_reserve_sat;                ///< 8 : channel-reserve-satoshis
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc-minimum-msat
    uint32_t    min_depth;                          ///< 4 : minimum-depth(acceptのみ)
    uint16_t    to_self_delay;                      ///< 2 : to-self-delay
    uint16_t    max_accepted_htlcs;                 ///< 2 : max-accepted-htlcs

    uint8_t     *p_temp_channel_id;                 ///< 32: temporary-channel-id
    uint8_t     *p_pubkeys[LN_FUNDIDX_MAX];         ///< 33: [0]funding-pubkey
                                                    ///< 33: [1]revocation-basepoint
                                                    ///< 33: [2]payment-basepoint
                                                    ///< 33: [3]delayed-payment-basepoint
                                                    ///< 33: [4]first-per-commitment-point
} ln_accept_channel_t;


/** @struct ln_funding_created_t
 *  @brief  [Establish]funding_created
 */
typedef struct {
    uint16_t    funding_output_idx;                 ///< 2:  funding-output-index

    uint8_t     *p_temp_channel_id;                 ///< 32: temporary-channel-id
    uint8_t     *p_funding_txid;                    ///< 32: funding-txid
    uint8_t     *p_signature;                       ///< 64: signature
} ln_funding_created_t;


/** @struct ln_funding_signed_t
 *  @brief  [Establish]funding_signed
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint8_t     *p_signature;                       ///< 64: signature
} ln_funding_signed_t;


/** @struct ln_funding_locked_t
 *  @brief  [Establish]funding_locked
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint8_t     *p_per_commitpt;                    ///< 33: next-per-commitment-point
} ln_funding_locked_t;


/** @struct ln_fundin_t
 *  @brief  open_channelでのfund_in情報
 *  @note
 *      - open_channelする方が #ln_establish_t .p_fundinに設定して使う
 */
typedef struct {
    uint8_t                     txid[UCOIN_SZ_TXID];            ///< 2-of-2へ入金するTXID
    int32_t                     index;                          ///< 未設定時(channelを開かれる方)は-1
    uint64_t                    amount;                         ///< 2-of-2へ入金するtxのvout amount
    char                        change_addr[UCOIN_SZ_ADDR_MAX]; ///< 2-of-2へ入金したお釣りの送金先アドレス(未使用時:NULL)
} ln_fundin_t;


/** @struct ln_establish_prm_t
 *  @brief  Establish関連のパラメータ
 *  @note
 *      - #ln_set_establish()で初期化する
 */
typedef struct {
    uint64_t    dust_limit_sat;                     ///< 8 : dust-limit-satoshis
    uint64_t    max_htlc_value_in_flight_msat;      ///< 8 : max-htlc-value-in-flight-msat
    uint64_t    channel_reserve_sat;                ///< 8 : channel-reserve-satoshis
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc-minimum-msat
    uint16_t    to_self_delay;                      ///< 2 : to-self-delay
    uint16_t    max_accepted_htlcs;                 ///< 2 : max-accepted-htlcs
    uint32_t    min_depth;                          ///< 4 : minimum-depth(acceptのみ)
} ln_establish_prm_t;


/** @struct ln_establish_t
 *  @brief  [Establish]ワーク領域
 */
typedef struct {
    ln_open_channel_t           cnl_open;                       ///< 送信 or 受信したopen_channel
    ln_accept_channel_t         cnl_accept;                     ///< 送信 or 受信したaccept_channel
    ln_funding_created_t        cnl_funding_created;            ///< 送信 or 受信したfunding_created
    ln_funding_signed_t         cnl_funding_signed;             ///< 送信 or 受信したfunding_signed

    ln_fundin_t                 *p_fundin;                      ///< 非NULL:open_channel側
    ln_establish_prm_t          estprm;                         ///< channel establish parameter
} ln_establish_t;

/// @}


/**************************************************************************
 * typedefs : Channel Close
 **************************************************************************/

/// @addtogroup channel_close
/// @{

/** @struct ln_shutdown_t
 *  @brief  [Close]shutdown
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    ucoin_buf_t *p_scriptpk;                        ///< len: scriptpubkey
} ln_shutdown_t;


/** @struct ln_closing_signed_t
 *  @brief  [Close]closing_signed
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    fee_sat;                            ///< 8:  fee-satoshis
    uint8_t     *p_signature;                       ///< 64: signature
} ln_closing_signed_t;


/** @struct ln_close_force_t
 *  @brief  [Close]Unilateral Close / Revoked Transaction Close用
 *  @note
 *      - p_tx, p_htlc_idxのインデックス値
 *          - commit_tx: LN_CLOSE_IDX_COMMIT
 *          - to_local output: LN_CLOSE_IDX_TOLOCAL
 *          - to_remote output: LN_CLOSE_IDX_TOREMOTE
 *          - HTLC: LN_CLOSE_IDX_HTLC～
 */
typedef struct {
    int             num;                            ///< p_bufのtransaction数
    ucoin_tx_t      *p_tx;                          ///< [0]commit_tx [1]to_local [2]to_remote [3-]HTLC
    uint8_t         *p_htlc_idx;                    ///< [0,1,2]ignore [3-]self->cnl_add_htlc[]のhtlc_idx
    ucoin_buf_t     tx_buf;                         ///< HTLC Timeout/Successから取り戻すTX
} ln_close_force_t;

/// @}


/**************************************************************************
 * typedefs : Normal Operation
 **************************************************************************/

/// @addtogroup normal_operation
/// @{

/** @struct     ln_update_add_htlc_t
 *  @brief      update_add_htlc
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    id;                                 ///< 8:  id
    uint64_t    amount_msat;                        ///< 8:  amount-msat
    uint32_t    cltv_expiry;                        ///< 4:  cltv-expirty
    uint8_t     payment_sha256[LN_SZ_HASH];         ///< 32: payment-hash
    uint8_t     *p_onion_route;                     ///< 1366: onion-routing-packet
    //inner
    uint8_t     flag;                               ///< LN_HTLC_FLAG_xxx
    //fulfillで戻す
    uint8_t     signature[LN_SZ_SIGNATURE];         ///< 受信した最新のHTLC署名
                                                    //      相手がunilateral close後にHTLC-txを送信しなかった場合に使用する
    uint64_t    prev_short_channel_id;              ///< 転送元short_channel_id
    uint64_t    prev_id;                            ///< 転送元id
    //failで戻す
    ucoin_buf_t shared_secret;                      ///< failuremsg暗号化用
} ln_update_add_htlc_t;


/** @struct     ln_update_fulfill_htlc_t
 *  @brief      update_fulfill_htlc
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    id;                                 ///< 8:  id
    uint8_t     *p_payment_preimage;                ///< 32: payment-preimage
} ln_update_fulfill_htlc_t;


/** @struct     ln_update_fail_htlc_t
 *  @brief      update_fail_htlc
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    id;                                 ///< 8:  id
    ucoin_buf_t *p_reason;                          ///< onion failure packet
} ln_update_fail_htlc_t;


/** @struct     ln_commit_signed_t
 *  @brief      commitment_signed
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint8_t     *p_signature;                       ///< 64: signature
    uint16_t    num_htlcs;                          ///< 2:  num-htlcs
    uint8_t     *p_htlc_signature;                  ///< num-htlcs*64: htlc-signature
} ln_commit_signed_t;


/** @struct     ln_revoke_and_ack_t
 *  @brief      revoke_and_ack
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint8_t     *p_per_commit_secret;               ///< 32: 古いper-commiment-secret
    uint8_t     *p_per_commitpt;                    ///< 33: 新しいper-commtment-point
} ln_revoke_and_ack_t;


/** @struct     ln_update_fee_t
 *  @brief      update_fee
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint32_t    feerate_per_kw;                     ///< 4:  feerate-per-kw
} ln_update_fee_t;


/** @struct     ln_update_fail_malformed_htlc_t
 *  @brief      update_fail_malformed_htlc
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    id;                                 ///< 8:  id
    uint8_t     *p_sha256_onion;                    ///< 32: sha256-of-onion
    uint16_t    failure_code;                       ///< 2:  failure-code
} ln_update_fail_malformed_htlc_t;


/** @struct     ln_channel_reestablish_t
 *  @brief      channel_reestablish
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    next_local_commitment_number;       ///< 8:  next_local_commitment_number
    uint64_t    next_remote_revocation_number;      ///< 8:  next_remote_revocation_number
} ln_channel_reestablish_t;

/// @}


/**************************************************************************
 * typedefs : Setup/Control
 **************************************************************************/

/// @addtogroup setup_control
/// @{

/** @struct     ln_init_t
 *  @brief      init
 */
typedef struct {
    ucoin_buf_t globalfeatures;                     ///< gflen: globalfeatures
    ucoin_buf_t localfeatures;                      ///< lflen: localfeatures
} ln_init_t;


/** @struct     ln_ping_t
 *  @brief      ping
 */
typedef struct {
    uint16_t    num_pong_bytes;                     ///< 2: num_pong_bytes
    uint16_t    byteslen;                           ///< 2: byteslen
} ln_ping_t;


/** @struct     ln_pong_t
 *  @brief      pong
 *  @note
 *      - byteslenはpingのnum_pong_bytesと同じにする
 */
typedef struct {
    uint16_t    byteslen;                           ///< 2: byteslen
} ln_pong_t;


/** @struct     ln_error_t
 *  @brief      error
 */
typedef struct {
    uint16_t    len;                                ///< 2: byteslen
    char        *p_data;                            ///< エラー文字列(\0あり)
} ln_error_t;

/// @}


/**************************************************************************
 * typedefs : Announcement
 **************************************************************************/

/// @addtogroup announcement
/// @{

/** @struct     ln_cnl_announce_t
 *  @brief      channel_announcement
 */
typedef struct {
//    uint8_t     *p_node_signature1;                 ///< 64: node_signature_1
//    uint8_t     *p_node_signature2;                 ///< 64: node_signature_2
//    uint8_t     *p_btc_signature1;                  ///< 64: bitcoin_signature_1
//    uint8_t     *p_btc_signature2;                  ///< 64: bitcoin_signature_2
    uint64_t    short_channel_id;                   ///< 8:  short_channel_id
//    uint8_t     *p_node_id1;                        ///< 33: node_id_1
//    uint8_t     *p_node_id2;                        ///< 33: node_id_2
//    uint8_t     *p_btc_key1;                        ///< 33: bitcoin_key_1
//    uint8_t     *p_btc_key2;                        ///< 33: bitcoin_key_2
//    uint8_t     features;                           ///< 1:  features

    const uint8_t           *p_my_node_pub;
    const ucoin_util_keys_t *p_my_funding;
    const uint8_t           *p_peer_node_pub;
    const uint8_t           *p_peer_funding_pub;
    uint8_t                 *p_peer_node_sign;
    uint8_t                 *p_peer_btc_sign;
    ucoin_keys_sort_t       sort;                   ///< peerのln_node_announce_t.sort
} ln_cnl_announce_create_t;


typedef struct {
    uint64_t    short_channel_id;                   ///< 8:  short_channel_id
    uint8_t     node_id1[UCOIN_SZ_PUBKEY];          ///< 33: node_id_1
    uint8_t     node_id2[UCOIN_SZ_PUBKEY];          ///< 33: node_id_2
    uint8_t     btc_key1[UCOIN_SZ_PUBKEY];          ///< 33: bitcoin_key_1
    uint8_t     btc_key2[UCOIN_SZ_PUBKEY];          ///< 33: bitcoin_key_2
} ln_cnl_announce_read_t;


/** @struct     ln_nodeaddr_t
 *  @brief      node_announcementのアドレス情報
 */
typedef struct {
    uint8_t         type;                       ///< 1:address descriptor(LN_NODEDESC_xxx)
    uint16_t        port;
    union {
        uint8_t     addr[1];

        struct {
            uint8_t     addr[4];
        } ipv4;

        struct {
            uint8_t     addr[16];
        } ipv6;

        struct {
            uint8_t     addr[10];
        } onionv2;

        struct {
            uint8_t     addr[35];
        } onionv3;
    }               addrinfo;
} ln_nodeaddr_t;


/** @struct     ln_node_announce_t
 *  @brief      node_announcement
 */
typedef struct {
//    uint8_t             *p_signature;               ///< 64: signature
    uint32_t            timestamp;                  ///< 4:  timestamp
    uint8_t             *p_node_id;                 ///< 33: node_id
    char                *p_alias;                   ///< 32: alias
    uint8_t             rgbcolor[3];                ///< 3:  rgbcolor
//    uint8_t     features;                           ///< 1:  features
    ln_nodeaddr_t       addr;

    //受信したデータ用
    ucoin_keys_sort_t   sort;                       ///< 自ノードとのソート結果(ASC=自ノードが先)
} ln_node_announce_t;


/** @struct     ln_cnl_update_t
 *  @brief      channel_update
 */
typedef struct {
    //uint8_t     signature[LN_SZ_SIGNATURE];         ///< 64: signature
    uint64_t    short_channel_id;                   ///< 8:  short_channel_id
    uint32_t    timestamp;                          ///< 4:  timestamp
    uint16_t    flags;                              ///< 2:  flags
    uint16_t    cltv_expiry_delta;                  ///< 2:  cltv_expiry_delta
    uint64_t    htlc_minimum_msat;                  ///< 8:  htlc_minimum_msat
    uint32_t    fee_base_msat;                      ///< 4:  fee_base_msat
    uint32_t    fee_prop_millionths;                ///< 4:  fee_proportional_millionths
} ln_cnl_update_t;


/** @struct     ln_announce_signs_t
 *  @brief      announcement_signatures
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel-id
    uint64_t    short_channel_id;                   ///< 8:  short_channel_id
    uint8_t     *p_node_signature;                  ///< 64: node_signature
    uint8_t     *p_btc_signature;                   ///< 64: bitcoin_signature
} ln_announce_signs_t;


/** @struct     ln_anno_prm_t
 *  @brief      announce関連のパラメータ
 */
typedef struct {
    //channel_update
    uint16_t    cltv_expiry_delta;                  ///< 2 : cltv_expiry_delta
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc_minimum_msat
    uint32_t    fee_base_msat;                      ///< 4 : fee_base_msat
    uint32_t    fee_prop_millionths;                ///< 4 : fee_proportional_millionths
} ln_anno_prm_t;

/// @}


/**************************************************************************
 * typedefs : onion
 **************************************************************************/

/// @addtogroup onion
/// @{

/** @struct     ln_hop_datain_t
 *  @brief      ONIONパケット生成情報
 */
typedef struct {
    uint64_t            short_channel_id;               ///< short_channel_id
    uint64_t            amt_to_forward;                 ///< update_add_htlcのamount-msat
    uint32_t            outgoing_cltv_value;            ///< update_add_htlcのcltv-expiry
    uint8_t             pubkey[UCOIN_SZ_PUBKEY];        ///< ノード公開鍵(node_id)
} ln_hop_datain_t;


/** @struct     ln_hop_dataout_t
 *  @brief      ONIONパケット解析情報
 */
typedef struct {
    bool                b_exit;                         ///< true:送金先, false:中継
    uint64_t            short_channel_id;               ///< short_channel_id
    uint64_t            amt_to_forward;                 ///< update_add_htlcのamount-msat
    uint32_t            outgoing_cltv_value;            ///< update_add_htlcのcltv-expiry
} ln_hop_dataout_t;

/// @}


/**************************************************************************
 * typedefs : コールバック用
 **************************************************************************/

/** @struct ln_cb_funding_sign_t
 *  @brief  funding_tx署名要求(#LN_CB_SIGN_FUNDINGTX_REQ)
 */
typedef struct {
    ucoin_tx_t              *p_tx;
    bool                    ret;        //署名結果
} ln_cb_funding_sign_t;


/** @struct ln_cb_funding_t
 *  @brief  funding_tx安定待ち要求(#LN_CB_FUNDINGTX_WAIT) / Establish完了通知(#LN_CB_ESTABLISHED)
 */
typedef struct {
    const ucoin_tx_t        *p_tx_funding;              ///< funding_tx
    const uint8_t           *p_txid;                    ///< funding txid
    bool                    b_send;                     ///< true:funding_txを送信する
    bool                    annosigs;                   ///< true:announce_signaturesを送信する
} ln_cb_funding_t;


/** @struct ln_cb_add_htlc_recv_t
 *  @brief  update_add_htlc受信通知(#LN_CB_ADD_HTLC_RECV)
 */
typedef struct {
    bool                        ok;                     ///< true:アプリ層処理OK
    uint64_t                    id;                     ///< HTLC id
    const uint8_t               *p_payment_hash;        ///< self->cnl_add_htlc[idx].payment_sha256
    const ln_hop_dataout_t      *p_hop;                 ///< onion解析結果
    uint64_t                    amount_msat;            ///< self->cnl_add_htlc[idx].amount_msat
    uint32_t                    cltv_expiry;            ///< self->cnl_add_htlc[idx].cltv_expiry
    uint8_t                     *p_onion_route;         ///< 変換後onionパケット(self->cnl_add_htlc[idx].p_onion_route)
    const ucoin_buf_t           *p_shared_secret;       ///< onion shared secret
} ln_cb_add_htlc_recv_t;


/** @struct ln_cb_fulfill_htlc_recv_t
 *  @brief  update_fulfill_htlc受信通知(#LN_CB_FULFILL_HTLC_RECV)
 */
typedef struct {
    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    const uint8_t           *p_preimage;            ///< update_fulfill_htlcで受信したpreimage(スタック)
    uint64_t                id;                     ///< HTLC id
} ln_cb_fulfill_htlc_recv_t;


/** @struct ln_cb_fail_htlc_recv_t
 *  @brief  update_fail_htlc受信通知(#LN_CB_FAIL_HTLC_RECV)
 */
typedef struct {
    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    const ucoin_buf_t       *p_reason;              ///< reason
    const ucoin_buf_t       *p_shared_secret;       ///< shared secret
    uint64_t                prev_id;                ///< 戻すHTLC id
    uint64_t                orig_id;                ///< 元のHTLC id
    const uint8_t           *p_payment_hash;        ///< payment_hash
} ln_cb_fail_htlc_recv_t;


///** @struct ln_cb_commsig_recv_t
// *  @brief  commitment_signed受信通知(#LN_CB_COMMIT_SIG_RECV)
// *  @todo
// *      - アプリ側も似たような情報を持っているので、まとめたいが方法が見つかっていない
// */
//typedef struct {
//    bool                    unlocked;               ///< true:送金処理完了
//} ln_cb_commsig_recv_t;


///** @struct ln_cb_htlc_changed_t
// *  @brief  revoke_and_ack受信通知(#LN_CB_HTLC_CHANGED)
// */
//typedef struct {
//    bool                    unlocked;               ///< true:着金処理完了
//} ln_cb_htlc_changed_t;


/** @struct ln_cb_closed_fee_t
 *  @brief  FEE不一致なおclosing_signed受信(#LN_CB_CLOSED_FEE)
 */
typedef struct {
    uint64_t                fee_sat;                ///< 受信したfee
} ln_cb_closed_fee_t;


/** @struct ln_cb_closed_t
 *  @brief  Mutual Close完了通知(#LN_CB_CLOSED)
 */
typedef struct {
    const ucoin_buf_t       *p_tx_closing;          ///< ブロックチェーンに公開するtx
} ln_cb_closed_t;


/** @struct ln_cb_anno_sigs_t
 *  @brief  announcement_signatures
 */
typedef struct {
    const ucoin_buf_t       *p_buf_bolt;            ///< 受信したannouncement_signatures
    uint8_t                 sort;
} ln_cb_anno_sigs_t;


/** @struct ln_cb_channel_anno_recv_t
 *  @brief  channel_announcement受信通知(#LN_CB_CHANNEL_ANNO_RECV)
 */
typedef struct {
    uint64_t                short_channel_id;
    bool                    is_unspent;
} ln_cb_channel_anno_recv_t;


/**************************************************************************
 * typedefs : 管理データ
 **************************************************************************/

/// @addtogroup channel_mng
/// @{

/** @struct ln_node_info_t
 *  @brief  announceノード情報
 *  @todo
 *      - channel_announcementに耐えられるようにすべきだが、まだ至っていない
 */
typedef struct {
    uint8_t                 node_id[UCOIN_SZ_PUBKEY];           ///< ノードID
    char                    alias[LN_SZ_ALIAS];                 ///< 名前
    ucoin_keys_sort_t       sort;                               ///< 自ノードの順番
                                                                // #UCOIN_KEYS_SORT_ASC : 自ノードが先
                                                                // #UCOIN_KEYS_SORT_OTHER : 他ノードが先
} ln_node_info_t;


/** @struct ln_node_t
 *  @brief  ノード情報
 */
typedef struct {
    ucoin_util_keys_t           keys;                           ///< node鍵
    uint8_t                     features;                       ///< localfeatures
    char                        alias[LN_SZ_ALIAS];             ///< ノード名(\0 terminate)
    ln_nodeaddr_t               addr;                           ///< ノードアドレス
} ln_node_t;


/** @struct ln_funding_local_data_t
 *  @brief  自ノードfunding情報
 */
typedef struct {
    uint8_t             txid[UCOIN_SZ_TXID];                    ///< funding-tx TXID
    uint16_t            txindex;                                ///< funding-tx index

    //MSG_FUNDIDX_xxx
    ucoin_util_keys_t   keys[LN_FUNDIDX_MAX];
    //MSG_SCRIPTIDX_xxx
    uint8_t             scriptpubkeys[LN_SCRIPTIDX_MAX][UCOIN_SZ_PUBKEY];   ///< script用PubKey
} ln_funding_local_data_t;


/** @struct ln_funding_remote_data_t
 *  @brief  他ノードfunding情報
 */
typedef struct {
    //MSG_FUNDIDX_xxx
    uint8_t             pubkeys[LN_FUNDIDX_MAX][UCOIN_SZ_PUBKEY];   ///< 相手から受信した公開鍵
    uint8_t             prev_percommit[UCOIN_SZ_PUBKEY];            ///< 1つ前のper_commit_point
    //MSG_SCRIPTIDX_xxx
    uint8_t             scriptpubkeys[LN_SCRIPTIDX_MAX][UCOIN_SZ_PUBKEY];   ///< script用PubKey
} ln_funding_remote_data_t;


/** @struct ln_commit_data_t
 *  @brief  commitment transaction用情報
 */
typedef struct {
    uint32_t            accept_htlcs;                   ///< accept_htlcs
    uint32_t            to_self_delay;                  ///< to_self_delay
    uint64_t            minimum_msat;                   ///< minimum_msat
    uint64_t            in_flight_msat;                 ///< in_flight_msat
    uint64_t            dust_limit_sat;                 ///< dust_limit_sat
    uint8_t             signature[LN_SZ_SIGNATURE];     ///< 署名
                                                        // localには相手に送信する署名
                                                        // remoteには相手から受信した署名
    uint8_t             txid[UCOIN_SZ_TXID];            ///< txid
    uint16_t            htlc_num;                       ///< commit_tx中のHTLC数
} ln_commit_data_t;


/** @struct ln_noise_t
 *  @brief  BOLT#8 protocol
 */
typedef struct {
    uint8_t         key[UCOIN_SZ_PRIVKEY];          ///< key
    uint64_t        nonce;                          ///< nonce
    uint8_t         ck[UCOIN_SZ_SHA256];            ///< chainkey
} ln_noise_t;


/** @struct     ln_self_t
 *  @brief      チャネル情報
 */
struct ln_self_t {
    uint8_t                     peer_node_id[UCOIN_SZ_PUBKEY];  ///< 接続先ノード

    //key storage
    uint64_t                    storage_index;                  ///< 現在のindex
    uint8_t                     storage_seed[LN_SZ_SEED];       ///< ユーザから指定されたseed
    ln_derkey_storage           peer_storage;                   ///< key storage(peer)
    uint64_t                    peer_storage_index;             ///< 現在のindex(peer)

    //funding
    uint8_t                     fund_flag;                      ///< none/funder/fundee
    ln_funding_local_data_t     funding_local;                  ///< funding情報:local
    ln_funding_remote_data_t    funding_remote;                 ///< funding情報:remote
    uint64_t                    obscured;                       ///< commitment numberをXORするとobscured commitment numberになる値。
                                                                // 0の場合、1回でもclosing_signed受信した
    ucoin_buf_t                 redeem_fund;                    ///< 2-of-2のredeemScript
    ucoin_keys_sort_t           key_fund_sort;                  ///< 2-of-2のソート順(local, remoteを正順とした場合)
    ucoin_tx_t                  tx_funding;                     ///< funding_tx
    ln_establish_t              *p_establish;                   ///< Establishワーク領域
    uint32_t                    min_depth;                      ///< minimum_depth

    //announce
    uint8_t                     anno_flag;                      ///< announcement_signaturesなど
    ln_anno_prm_t               anno_prm;                       ///< announcementパラメータ
    ucoin_buf_t                 cnl_anno;                       ///< 自channel_announcement

    //msg:init
    uint8_t                     init_flag;                      ///< INIT_FLAG_xxx
    uint8_t                     lfeature_remote;                ///< initで取得したlocalfeature

    //msg:close
    ucoin_tx_t                  tx_closing;                     ///< closing_tx
    uint8_t                     shutdown_flag;                  ///< shutdownフラグ(M_SHDN_FLAG_xxx)。 b1:受信済み b0:送信済み
    uint64_t                    close_fee_sat;                  ///< closing_txのFEE
    uint64_t                    close_last_fee_sat;             ///< 最後に送信したclosing_txのFEE
    ucoin_buf_t                 shutdown_scriptpk_local;        ///< close時の送金先(local)
    ucoin_buf_t                 shutdown_scriptpk_remote;       ///< mutual close時の送金先(remote)
    ucoin_buf_t                 *p_revoked_vout;                ///< revoked transaction close時に検索するvoutスクリプト([0]は必ずto_local系)
    ucoin_buf_t                 *p_revoked_wit;                 ///< revoked transaction close時のwitnessスクリプト
    ln_htlctype_t               *p_revoked_type;                ///< p_revoked_vout/p_revoked_witに対応するtype
    ucoin_buf_t                 revoked_sec;                    ///< revoked transaction close時のremote per_commit_sec
    uint16_t                    revoked_num;                    ///< revoked_cntの初期値+1([0]にto_local系を入れるため)
    uint16_t                    revoked_cnt;                    ///< 取り戻す必要があるvout数
    uint32_t                    revoked_chk;                    ///< 最後にチェックしたfunding_txのconfirmation数

    //msg:normal operation
    uint16_t                    htlc_num;                       ///< HTLC数
    uint64_t                    commit_num;                     ///< commitment_signed送信後にインクリメントする48bitカウンタ(0～)
                                                                ///<    next_local_commitment_numberに相当する
    uint64_t                    revoke_num;                     ///< revoke_and_ack送信後にインクリメントする48bitカウンタ(0～)
    uint64_t                    remote_commit_num;              ///< commitment_signed受信時にインクリメントする48bitカウンタ(0～)
                                                                ///<    next_remote_revocation_numberに相当する
    uint64_t                    remote_revoke_num;              ///< revoke_and_ack受信時にインクリメントする48bitカウンタ(0～)
    uint64_t                    htlc_id_num;                    ///< update_add_htlcで使うidの管理
    uint64_t                    our_msat;                       ///< 自分の持ち分
    uint64_t                    their_msat;                     ///< 相手の持ち分
    uint8_t                     channel_id[LN_SZ_CHANNEL_ID];   ///< channel_id
    uint64_t                    short_channel_id;               ///< short_channel_id
    ln_update_add_htlc_t        cnl_add_htlc[LN_HTLC_MAX];      ///< 追加したHTLC

    //ping pong
    uint16_t                    missing_pong_cnt;               ///< ping送信に対してpongを受信しなかった回数
    uint16_t                    last_num_pong_bytes;            ///< 最後にping送信したlast_num_pong_bytes

    //commitment transaction情報(local/remote)
    ln_commit_data_t            commit_local;                   ///< local commit_tx用
    ln_commit_data_t            commit_remote;                  ///< remote commit_tx用
    //commitment transaction情報(固有)
    uint64_t                    funding_sat;                    ///< funding_satoshis
    uint32_t                    feerate_per_kw;                 ///< feerate_per_kw

    ////////////////////////////////////////////////

    //noise protocol
    ln_noise_t                  noise_send;                     ///< noise protocol
    ln_noise_t                  noise_recv;                     ///< noise protocol
    void                        *p_handshake;

    //last error
    int                         err;                            ///< error code(ln_err.h)

    //for app
    ln_callback_t               p_callback;                     ///< 通知コールバック
    void                        *p_param;                       ///< ユーザ用
};

/// @}


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 初期化
 *
 * 鍵関係を、ストレージを含めて初期化している。
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pSeed           per-commit-secret生成用
 * @param[in]           pAnnoPrm        announcementパラメータ
 * @param[in]           pFunc           通知用コールバック関数
 * @retval      true    成功
 */
bool ln_init(ln_self_t *self, const uint8_t *pSeed, const ln_anno_prm_t *pAnnoPrm, ln_callback_t pFunc);


/** 終了
 *
 * @param[in,out]       self            channel情報
 */
void ln_term(ln_self_t *self);


/** Genesis Block Hash設定
 *
 * @param[in]       pHash               Genesis Block Hash
 * @attention
 *      - JSON-RPCのgetblockhashで取得した値はエンディアンが逆転しているため、
 *          設定する場合にはエンディアンを逆にして pHashに与えること。
 *          https://github.com/lightningnetwork/lightning-rfc/issues/237
 */
void ln_set_genesishash(const uint8_t *pHash);


/** Genesis Block Hash取得
 *
 * @return      #ln_set_genesishash()で設定したGenesis Block Hash
 */
const uint8_t* ln_get_genesishash(void);


/** Channel Establish設定
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pNodeId         Establish先(NULL可)
 * @param[in]           pEstPrm         Establishパラメータ
 * @retval      true    成功
 * @note
 *      - pEstablishは接続完了まで保持すること
 */
bool ln_set_establish(ln_self_t *self, const uint8_t *pNodeId, const ln_establish_prm_t *pEstPrm);


/** short_channel_id情報設定
 *
 * @param[in,out]       self            channel情報
 * @param[in]           Height          funding_txが入ったブロック height
 * @param[in]           Index           funding_txのTXIDが入っているindex
 * @param[in]           FundingIndex    funding_tx vout in channel
 * @note
 *      - #LN_CB_FUNDINGTX_WAIT でコールバックされた後、安定後に呼び出すこと
 */
void ln_set_short_channel_id_param(ln_self_t *self, uint32_t Height, uint32_t Index, uint32_t FundingIndex);


/** short_channel_id情報取得
 *
 * @param[out]          pHeight     funding_txが入ったブロック height
 * @param[out]          pIndex      funding_txのTXIDが入っているindex
 * @param[out]          pVIndex     funding_txとして使用するvout index
 */
void ln_get_short_channel_id_param(uint32_t *pHeight, uint32_t *pIndex, uint32_t *pVIndex, uint64_t short_channel_id);


/** shutdown時の出力先設定(pubkey)
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pShutdownPubkey shutdown時のscriptPubKey用公開鍵
 * @param[in]           ShutdownPref    pShutdownPubkey用(UCOIN_PREF_P2PKH or UCOIN_PREF_NATIVE)
 * @retval      true    成功
 * @note
 *      - #ln_set_shutdown_vout_pubkey()か #ln_set_shutdown_vout_addr()のどちらかを設定する。
 */
bool ln_set_shutdown_vout_pubkey(ln_self_t *self, const uint8_t *pShutdownPubkey, int ShutdownPref);


/** shutdown時の出力先設定(address)
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pAddr           shutdown時のアドレス
 * @retval      true    成功
 * @note
 *      - #ln_set_shutdown_vout_pubkey()か #ln_set_shutdown_vout_addr()のどちらかを設定する。
 */
bool ln_set_shutdown_vout_addr(ln_self_t *self, const char *pAddr);


/** noise handshake開始
 *
 * @param[in,out]       self        channel情報
 * @param[out]          pBuf        送信データ
 * @param[in]           pNodeId     送信側:接続先ノードID, 受信側:NULL
 * @retval      true    成功
 */
bool ln_handshake_start(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pNodeId);


/** noise handshake受信
 *
 * @param[in,out]       self        channel情報
 * @param[out]          pCont       true:次も受信を継続する(戻り値がtrue時のみ有効)
 * @param[in,out]       pBuf        in:受信データ, out:送信データ
 * @retval      true    成功
 */
bool ln_handshake_recv(ln_self_t *self, bool *pCont, ucoin_buf_t *pBuf);


/** noise protocol encode
 *
 * @param[in,out]       self        channel情報
 * @param[out]          pBufEnc     エンコード後データ
 * @param[in]           pBufIn      変換前データ(平BOLT)
 * @retval      true    成功
 */
bool ln_noise_enc(ln_self_t *self, ucoin_buf_t *pBufEnc, const ucoin_buf_t *pBufIn);


/** noise protocol decode(length)
 *
 * @param[in,out]       self        channel情報
 * @param[in]           pData       変換前データ(Length部)
 * @param[in]           Len         pData長
 * @retval      非0 次に受信すべきデータ長
 * @retval      0   失敗
 * @note
 *      - 平BOLT==>noise protocolエンコード==>送信 - - - 受信→noise protocolデコード==>平BOLT
 *      - noise protocolでエンコードされたデータはMACが付いているため、実データより16byte大きくなっている
 *      - 戻り値のデータ長分を受信し、受信したデータを #ln_noise_dec_msg() に渡してデコードする。
 */
uint16_t ln_noise_dec_len(ln_self_t *self, const uint8_t *pData, uint16_t Len);


/** noise protocol decode(message)
 *
 * @param[in,out]       self        channel情報
 * @param[in,out]       pBuf        [in]変換前データ, [out]デコード後データ(平BOLT)
 * @retval      true    成功
 */
bool ln_noise_dec_msg(ln_self_t *self, ucoin_buf_t *pBuf);


/** Lightningメッセージ受信処理
 *
 * @param[in,out]       self        channel情報
 * @param[in]           pData       受信データ
 * @param[in]           Len         pData長
 * @retval      true    解析成功
 */
bool ln_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);


/** 定期フラグ回収処理
 * どこかのタイミングで行う必要があるが、即時行うようなタイミングがないかもしれない処理。
 * 将来的には ln.c で吸収すべきと考えている。
 *      - funding_locked交換
 *      - announcement_signatures交換
 *
 * @param[in,out]       self        channel情報
 */
void ln_flag_proc(ln_self_t *self);


/** initメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pInit           initメッセージ
 * @param[in]           bHaveCnl        true:チャネル開設済み
 * retval       true    成功
 */
bool ln_create_init(ln_self_t *self, ucoin_buf_t *pInit, bool bHaveCnl);


/** channel_reestablishメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pReEst          channel_reestablishメッセージ
 * retval       true    成功
 */
bool ln_create_channel_reestablish(ln_self_t *self, ucoin_buf_t *pReEst);

bool ln_check_need_funding_locked(const ln_self_t *self);
bool ln_create_funding_locked(ln_self_t *self, ucoin_buf_t *pLocked);


/********************************************************************
 * Establish関係
 ********************************************************************/

/** open_channelメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pOpen           生成したopen_channelメッセージ
 * @param[in]           pFundin         fund-in情報
 * @param[in]           FundingSat      fundingするamount[satoshi]
 * @param[in]           PushSat         push_msatするamount[satoshi]
 * @param[in]           FeeRate         feerate_per_kw
 * retval       true    成功
 */
bool ln_create_open_channel(ln_self_t *self, ucoin_buf_t *pOpen,
            const ln_fundin_t *pFundin, uint64_t FundingSat, uint64_t PushSat, uint32_t FeeRate);



/** open_channelのchannel_flags.announce_channelのクリア
 *
 * @param[in]           self            channel情報
 */
void ln_open_announce_channel_clr(ln_self_t *self);


/** announcement_signatures作成およびchannel_announcementの一部(peer署名無し)生成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pBufAnnoSigns   生成したannouncement_signaturesメッセージ
 * @retval      ture    成功
 * @note
 *      - チャネルのどちらかでもinitのlocalfeaturesでchannels_publicを持っていない場合は失敗する。
 *      - Establish完了以降に呼び出すこと。
 */
bool ln_create_announce_signs(ln_self_t *self, ucoin_buf_t *pBufAnnoSigns);


/** channel_update更新
 * 送信済みのchannel_updateと現在のパラメータを比較し、相違があれば作成する
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pCnlUpd         生成したchannel_updateメッセージ
 * @retval      ture    更新あり
 */
//bool ln_update_channel_update(ln_self_t *self, ucoin_buf_t *pCnlUpd);


/** closing transactionのFEE設定
 *
 * @param[in,out]       self            channel情報
 * @param[in]           Fee             FEE
 */
void ln_update_shutdown_fee(ln_self_t *self, uint64_t Fee);


/** shutdownメッセージ作成
 *
 * @param[in,out]       self        channel情報
 * @param[out]          pShutdown   生成したshutdownメッセージ
 * @retval      ture    成功
 * @note
 *      - scriptPubKeyは #ln_init()で指定したアドレスを使用する
 */
bool ln_create_shutdown(ln_self_t *self, ucoin_buf_t *pShutdown);


/** close中状態に遷移させる
 *
 * @param[in,out]       self        channel情報
 */
void ln_goto_closing(ln_self_t *self, void *pDbParam);


/** 送信用unilateral closeトランザクション作成
 *
 * @param[in]           self        channel情報
 * @param[out]          pClose      生成したトランザクション
 * @retval      ture    成功
 * @note
 *      - pCloseは @ln_free_close_force_tx()で解放すること
 */
bool ln_create_close_force_tx(ln_self_t *self, ln_close_force_t *pClose);


/** 相手からcloseされたcommit_txを復元
 *
 * @param[in]           self        channel情報
 * @param[out]          pClose      生成したトランザクション
 * @retval      ture    成功
 * @note
 *      - pCloseは @ln_free_close_force_tx()で解放すること
 */
bool ln_create_closed_tx(ln_self_t *self, ln_close_force_t *pClose);


/** ln_close_force_tのメモリ解放
 *
 * @param[out]          pClose      ln_create_close_force_tx()やln_create_closed_tx()で生成したデータ
 */
void ln_free_close_force_tx(ln_close_force_t *pClose);


/** revoked transaction close(ugly way)の対処
 *
 * @param[in,out]       self        channel情報
 * @param[in]           pRevokedTx  revoked transaction
 * @param[in,out]       pDbParam    DBパラメータ
 * @retval      ture    成功
 * @note
 *      - self->vout にto_localのscriptPubKeyを設定する(HTLC Timeout/Successの取り戻しにも使用する)
 *      - self->wit にto_localのwitnessProgramを設定する
 */
bool ln_close_ugly(ln_self_t *self, const ucoin_tx_t *pRevokedTx, void *pDbParam);


/** update_add_htlcメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pAdd            生成したupdate_add_htlcメッセージ
 * @param[out]          pHtlcId         生成したHTLCのid
 * @param[in]           pPacket         onion packet
 * @param[in]           amount_msat     送金額[msat]
 * @param[in]           cltv_value      CLTV値
 * @param[in]           pPaymentHash    PaymentHash(SHA256:32byte)
 * @param[in]           prev_short_channel_id   転送元short_channel_id(ない場合は0)
 * @param[in]           prev_id                 転送元id
 * @param[in]           pSharedSecrets  保存する共有秘密鍵集(NULL:未保存)
 * @retval      true    成功
 * @note
 *      - prev_short_channel_id はfullfillの通知先として使用する
 */
bool ln_create_add_htlc(ln_self_t *self,
            ucoin_buf_t *pAdd,
            uint64_t *pHtlcId,
            const uint8_t *pPacket,
            uint64_t amount_msat,
            uint32_t cltv_value,
            const uint8_t *pPaymentHash,
            uint64_t prev_short_channel_id,
            uint64_t prev_id,
            const ucoin_buf_t *pSharedSecrets);


/** update_fulfill_htlcメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pFulfill        生成したupdate_fulfill_htlcメッセージ
 * @param[in]           id              HTLC id
 * @param[in]           pPreImage       反映するHTLCのpayment-preimage
 * @retval      true    成功
 */
bool ln_create_fulfill_htlc(ln_self_t *self, ucoin_buf_t *pFulfill, uint64_t id, const uint8_t *pPreImage);


/** update_fail_htlcメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pFail           生成したupdate_fail_htlcメッセージ
 * @param[in]           id              HTLC id
 * @param[in]           pReason         失敗理由
 * @retval      true    成功
 */
bool ln_create_fail_htlc(ln_self_t *self, ucoin_buf_t *pFail, uint64_t id, const ucoin_buf_t *pReason);


/** commitment_signature作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pCommSig        生成したcommitment_signatureメッセージ
 * @retval      true    成功
 */
bool ln_create_commit_signed(ln_self_t *self, ucoin_buf_t *pCommSig);


/** ping作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pPing           生成したpingメッセージ
 * @retval      true    成功
 */
bool ln_create_ping(ln_self_t *self, ucoin_buf_t *pPing);


/** pong作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pPong           生成したpongメッセージ
 * @param[in]           NumPongBytes    pingのnum_pong_bytes
 * @retval      true    成功
 */
bool ln_create_pong(ln_self_t *self, ucoin_buf_t *pPong, uint16_t NumPongBytes);


/** to_local用トランザクション作成(署名まで実施)
 *
 * @param[in]           self            channel情報
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount(ここからfeeを内部で引く)
 * @param[in]           to_self_delay   to_self_delay
 * @param[in]           pScript         送金先スクリプト
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @param[in]           bRevoked        true:revoked transaction close対応
 * @retval  true    成功
 *
 */
bool ln_create_tolocal_spent(const ln_self_t *self, ucoin_tx_t *pTx, uint64_t Value, uint32_t to_self_delay,
                const ucoin_buf_t *pScript, const uint8_t *pTxid, int Index, bool bRevoked);


/** to_remote用トランザクション作成(署名まで実施)
 *
 * @param[in]           self            channel情報
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount(ここからfeeを内部で引く)
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @retval  true    成功
 */
bool ln_create_toremote_spent(const ln_self_t *self, ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pTxid, int Index);


/** revoked HTLC Txから取り戻すトランザクション作成
 *
 *
 */
bool ln_create_revokedhtlc_spent(const ln_self_t *self, ucoin_tx_t *pTx, uint64_t Value,
                int WitIndex, const uint8_t *pTxid, int Index);


/** PreImageハッシュ計算
 *
 * @param[out]      pHash               計算結果(LN_SZ_HASH)
 * @param[in]       pPreImage           計算元(LN_SZ_PREIMAGE)
 */
void ln_calc_preimage_hash(uint8_t *pHash, const uint8_t *pPreImage);


/********************************************************************
 * inline展開用
 ********************************************************************/

/** channel_id取得
 *
 * @param[in]           self            channel情報
 * @return      channel_id
 */
static inline const uint8_t *ln_channel_id(const ln_self_t *self) {
    return self->channel_id;
}


/** short_channel_id取得
 *
 * @param[in]           self            channel情報
 * @return      short_channel_id
 */
static inline uint64_t ln_short_channel_id(const ln_self_t *self) {
    return self->short_channel_id;
}


/** short_channel_idクリア
 *
 * short_channel_idを0にする.
 *
 * @param[in,out]       self            channel情報
 */
static inline void ln_short_channel_id_clr(ln_self_t *self) {
    self->short_channel_id = 0;
}


/** アプリ用パラメータポインタ取得
 *
 * @param[in,out]       self            channel情報
 * @return      アプリ用パラメータ(非const)
 */
static inline void *ln_get_param(ln_self_t *self) {
    return self->p_param;
}


/** our_msat取得
 *
 * @param[in]           self            channel情報
 * @return      自channelのmilli satoshi
 */
static inline uint64_t ln_our_msat(const ln_self_t *self) {
    return self->our_msat;
}


/** their_msat取得
 *
 * @param[in]           self            channel情報
 * @return      他channelのmilli satoshi
 */
static inline uint64_t ln_their_msat(const ln_self_t *self) {
    return self->their_msat;
}


/** HTLC数取得
 *
 * @param[in]           self            channel情報
 * @return      HTLC数
 */
static inline uint16_t ln_htlc_num(const ln_self_t *self) {
    return self->htlc_num;
}


/** funding_txのTXID取得
 *
 * @param[in]           self            channel情報
 * @return      funding_txのTXID
 */
static inline const uint8_t *ln_funding_txid(const ln_self_t *self) {
    return self->funding_local.txid;
}


/** funding_txのTXINDEX取得
 *
 * @param[in]           self            channel情報
 * @return      funding_txのTXINDEX
 */
static inline uint32_t ln_funding_txindex(const ln_self_t *self) {
    return self->funding_local.txindex;
}


/** minimum_depth
 *
 * @param[in]           self            channel情報
 * @return      accept_channelで受信したminimum_depth
 */
static inline uint32_t ln_minimum_depth(const ln_self_t *self) {
    return self->min_depth;
}


/** funderかどうか
 *
 * @param[in]           self            channel情報
 * @retval      true    funder
 * @retval      false   fundee
 */
static inline bool ln_is_funder(const ln_self_t *self) {
    return (self->fund_flag & LN_FUNDFLAG_FUNDER);
}


/** funding中かどうか
 *
 * @param[in]           self            channel情報
 * @retval      true    fundingしている
 * @retval      false   fundingしていない(未funding or funding済み)
 */
static inline bool ln_is_funding(const ln_self_t *self) {
    return (self->fund_flag & LN_FUNDFLAG_FUNDING);
}


/**
 * 
 * @param[in]           feerate_kb  bitcoindから取得したfeerate/KB
 * @retval          feerate_per_kw
 */
static inline uint32_t ln_calc_feerate_per_kw(uint64_t feerate_kb) {
    return (uint32_t)(feerate_kb / 4);
}


/** feerate_per_kw取得
 *
 * @param[in]           self            channel情報
 * @return      feerate_per_kw
 */
static inline uint32_t ln_feerate_per_kw(ln_self_t *self) {
    return self->feerate_per_kw;
}


/** feerate_per_kw設定
 *
 * @param[out]          self            channel情報
 * @param[in]           feerate         設定値
 */
static inline void ln_set_feerate(ln_self_t *self, uint32_t feerate) {
    self->feerate_per_kw = feerate;
}


/** 初期closing_tx FEE取得
 *
 * @param[in,out]       self            channel情報
 * @return      fee[satoshis]
 */
static inline uint64_t ln_calc_max_closing_fee(const ln_self_t *self) {
    return (LN_FEE_COMMIT_BASE * self->feerate_per_kw / 1000);
}


/** closing_signed受信歴取得
 *
 * @param[in]           self            channel情報
 * @retval      true    closing_signedを受信したことがある
 */
static inline bool ln_is_closing_signed_recvd(const ln_self_t *self) {
    return (self->obscured == 0);
}


/** commit_local取得
 *
 * @param[in]           self            channel情報
 * @retval      commit_local情報
 */
static inline const ln_commit_data_t *ln_commit_local(const ln_self_t *self) {
    return &self->commit_local;
}


/** commit_remote取得
 *
 * @param[in]           self            channel情報
 * @retval      commit_remote情報
 */
static inline const ln_commit_data_t *ln_commit_remote(const ln_self_t *self) {
    return &self->commit_remote;
}


/** shutdown時のlocal scriptPubKey取得
 *
 * @param[in]           self            channel情報
 * @retval      local scriptPubKey
 */
static inline const ucoin_buf_t *ln_shutdown_scriptpk_local(const ln_self_t *self) {
    return &self->shutdown_scriptpk_local;
}


/** shutdown時のremote scriptPubKey取得
 *
 * @param[in]           self            channel情報
 * @retval      remote scriptPubKey
 */
static inline const ucoin_buf_t *ln_shutdown_scriptpk_remote(const ln_self_t *self) {
    return &self->shutdown_scriptpk_remote;
}


/**
 *
 *
 */
static inline const ln_update_add_htlc_t *ln_update_add_htlc(const ln_self_t *self, int htlc_idx) {
    return &self->cnl_add_htlc[htlc_idx];
}


/**
 *
 * @note
 *      - HTLC Success Txではない時のUnlockになる
 *            -----------------------------------------------------
 *            <remote_htlcsig>
 *            <payment_preimage> ★
 *            -----------------------------------------------------
 *            # To you with revocation key
 *            OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationkey))> OP_EQUAL
 *            OP_IF
 *                OP_CHECKSIG
 *            OP_ELSE
 *                <remote_htlckey> OP_SWAP OP_SIZE 32 OP_EQUAL
 *                OP_NOTIF
 *                    # To me via HTLC-timeout transaction (timelocked).
 *                    OP_DROP 2 OP_SWAP <local_htlckey> 2 OP_CHECKMULTISIG
 *                OP_ELSE
 *                    # To you with preimage.
 *                    OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *                    OP_CHECKSIG
 *                OP_ENDIF
 *            OP_ENDIF
 *            -----------------------------------------------------
 */
static inline const ucoin_buf_t *ln_preimage_local(const ucoin_tx_t *pTx) {
    return (pTx->vin[0].wit_cnt == 3) ? &pTx->vin[0].witness[1] : NULL;
}


/**
 *
 * @note
 *      - HTLC Success Tx時のUnlockになる
 *            -----------------------------------------------------
 *            0
 *            <remote_htlcsig>
 *            <local_htlcsig>
 *            <payment_preimage> ★
 *            -----------------------------------------------------
 *            # To you with revocation key
 *            OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationkey))> OP_EQUAL
 *            OP_IF
 *                OP_CHECKSIG
 *            OP_ELSE
 *                <remote_htlckey> OP_SWAP OP_SIZE 32 OP_EQUAL
 *                OP_IF
 *                    # To me via HTLC-success transaction.
 *                    OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *                    2 OP_SWAP <local_htlckey> 2 OP_CHECKMULTISIG
 *                OP_ELSE
 *                    # To you after timeout.
 *                    OP_DROP <locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *                    OP_CHECKSIG
 *                OP_ENDIF
 *            OP_ENDIF
 *            -----------------------------------------------------
 */
static inline const ucoin_buf_t *ln_preimage_remote(const ucoin_tx_t *pTx) {
    return (pTx->vin[0].wit_cnt == 5) ? &pTx->vin[0].witness[3] : NULL;
}


/** revoked transaction closeされた後の残取り戻し数
 *
 * @param[in]           self            channel情報
 * @retval      残取り戻し数
 */
static inline uint16_t ln_revoked_cnt(const ln_self_t *self) {
    return self->revoked_cnt;
}


/** revoked transaction closeされた後の残取り戻しチェック
 *
 * @param[in,out]       self            channel情報
 * @retval      true        取り戻し完了
 */
static inline bool ln_revoked_cnt_dec(ln_self_t *self) {
    self->revoked_cnt--;
    return self->revoked_cnt == 0;
}


/** revoked transaction closeされた後のfunding_tx confirmation数更新
 *
 * @param[out]          self            channel情報
 * @param[in]           confm           confirmation数
 */
static inline void ln_set_revoked_confm(ln_self_t *self, uint32_t confm) {
    self->revoked_chk = confm;
}


/** ln_revoked_confm()で保存した値の取得
 *
 * @param[in]           self            channel情報
 * @return      ln_revoked_confm()で保存したconfirmation数
 */
static inline uint32_t ln_revoked_confm(const ln_self_t *self) {
    return self->revoked_chk;
}


/** revoked vout
 * @param[in]           self            channel情報
 * @return      revoked transaction後に監視するvoutスクリプト
 */
static inline const ucoin_buf_t* ln_revoked_vout(const ln_self_t *self) {
    return self->p_revoked_vout;
}


/** revoked witness script
 * @param[in]           self            channel情報
 * @return      revoked transaction後に取り戻す際のunlocking witness script
 */
static inline const ucoin_buf_t* ln_revoked_wit(const ln_self_t *self) {
    return self->p_revoked_wit;
}


/** open_channelのchannel_flags.announce_channel
 *
 * @param[in]           self            channel情報
 * @return      open_channelのchannel_flags.announce_channel
 * @note
 *      - This indicates whether the initiator of the funding flow
 *          wishes to advertise this channel publicly to the network
 *          as detailed within BOLT #7.
 */
static inline bool ln_open_announce_channel(const ln_self_t *self) {
    return (self->fund_flag & LN_FUNDFLAG_ANNO_CH);
}


/** 他ノードID取得
 *
 * @param[in]           self            channel情報
 * @return      自channelの他node_id
 */
static inline const uint8_t *ln_their_node_id(const ln_self_t *self) {
    return self->peer_node_id;
}


/** cltv_expiry_delta取得
 *
 * @param[in]           self            channel情報
 * @return      cltv_expiry_delta
 */
static inline uint32_t ln_cltv_expily_delta(const ln_self_t *self) {
    return self->anno_prm.cltv_expiry_delta;
}


/** 転送FEE計算
 *
 * @param[in]           self            channel情報
 * @param[in]           amount          転送amount_msat
 * @return      転送FEE(msat)
 */
static inline uint64_t ln_forward_fee(const ln_self_t *self, uint64_t amount) {
    return (uint64_t)self->anno_prm.fee_base_msat + (amount * (uint64_t)self->anno_prm.fee_prop_millionths / (uint64_t)1000000);
}


/**
 *
 * @retval      0:node_1, 1:node_2
 */
static inline int ln_cnlupd_direction(const ln_cnl_update_t *pCnlUpd) {
    return pCnlUpd->flags & LN_CNLUPD_FLAGS_DIRECTION;
}


/**
 *
 * @retval      true    disableフラグが立っていない
 */
static inline bool ln_cnlupd_enable(const ln_cnl_update_t *pCnlUpd) {
    return !(pCnlUpd->flags & LN_CNLUPD_FLAGS_DISABLE);
}


/********************************************************************
 * NODE
 ********************************************************************/

/** ノードアドレス取得
 *
 * @return      ノードアドレス(非const)
 */
ln_nodeaddr_t *ln_node_addr(void);


char *ln_node_alias(void);


const uint8_t *ln_node_getid(void);

/** ノード情報初期化
 *
 * @param[in]       Features        ?
 */
bool ln_node_init(uint8_t Features);


/** ノード情報終了
 */
void ln_node_term(void);


/** channel情報検索(node_idから)
 *
 *      self DBから、channelの相手になっているpeerのnode_idが一致するselfを検索する。
 *      一致した場合、pSelfにDB保存しているデータを返す。
 *
 * @param[out]      self                検索成功時、pSelfが非NULLであればコピーする
 * @param[in]       pNodeId             検索する相手チャネルnode_id
 * @retval      true        検索成功
 */
bool ln_node_search_channel(ln_self_t *self, const uint8_t *pNodeId);


/** node_announcement検索(node_idから)
 *
 * @param[out]      pNodeAnno           取得したnode_announcement
 * @param[in]       pNodeId             検索するnode_id
 * @retval      true        検索成功
 */
bool ln_node_search_nodeanno(ln_node_announce_t *pNodeAnno, const uint8_t *pNodeId);


/********************************************************************
 * ONION
 ********************************************************************/

/** ONIONパケット生成
 *
 * @param[out]      pPacket             ONIONパケット[LN_SZ_ONION_ROUTE]
 * @param[out]      pSecrets            全shared secret(#ln_onion_failure_read()用)
 * @param[in]       pHopData            HOPデータ
 * @param[in]       NumHops             pHopData数
 * @param[in]       pSessionKey         セッション鍵[UCOIN_SZ_PRIVKEY]
 * @param[in]       pAssocData          Associated Data
 * @param[in]       AssocLen            pAssocData長
 * @retval      true    成功
 */
bool ln_onion_create_packet(uint8_t *pPacket,
            ucoin_buf_t *pSecrets,
            const ln_hop_datain_t *pHopData,
            int NumHops,
            const uint8_t *pSessionKey,
            const uint8_t *pAssocData, int AssocLen);


/** ONION failureパケット生成
 *
 * @param[out]      pNextPacket         ONION failureパケット
 * @param[in]       pSharedSecret       shared secret
 * @param[in]       pReason             Failure Message(BOLT#4)
 *
 * @note
 *      - https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#failure-messages
 */
void ln_onion_failure_create(ucoin_buf_t *pNextPacket,
            const ucoin_buf_t *pSharedSecret,
            const ucoin_buf_t *pReason);


/** ONION failure転送パケット生成
 *
 * @param[out]      pNextPacket         ONION failure転送パケット
 * @param[in]       pSharedSecret       shared secret
 * @param[in]       pPacket             受信したONION failureパケット
 */
void ln_onion_failure_forward(ucoin_buf_t *pNextPacket,
            const ucoin_buf_t *pSharedSecret,
            const ucoin_buf_t *pPacket);


/** ONION failureパケット解析
 *
 * @param[out]      pReason             Failure Message
 * @param[out]      pHop                エラー元までのノード数(0は相手ノード)
 * @param[in]       pSharedSecrets      ONIONパケット生成自の全shared secret(#ln_onion_create_packet())
 * @param[in]       pPacket             受信したONION failureパケット
 */
bool ln_onion_failure_read(ucoin_buf_t *pReason,
            int *pHop,
            const ucoin_buf_t *pSharedSecrets,
            const ucoin_buf_t *pPacket);


/********************************************************************
 * misc
 ********************************************************************/

/** BOLTメッセージ名取得
 *
 * @param[in]   type        BOLT message type
 * @return          message name
 */
const char *ln_misc_msgname(uint16_t Type);

/** 16bit BE値の読込み
 *
 * @param[in]       pPush       読込み元
 * @return      16bit値
 */
uint16_t ln_misc_get16be(const uint8_t *pData);


/** 32bit BE値の読込み
 *
 * @param[in]       pPush       読込み元
 * @return      32bit値
 */
uint32_t ln_misc_get32be(const uint8_t *pData);


/** 64bit BE値の読込み
 *
 * @param[in]       pPush       読込み元
 * @return      64bit値
 */
uint64_t ln_misc_get64be(const uint8_t *pData);


/********************************************************************
 * デバッグ
 ********************************************************************/

void ln_set_debug(unsigned long debug);
unsigned long ln_get_debug(void);


#ifdef UCOIN_USE_PRINTFUNC

/** [デバッグ用]鍵情報出力
 *
 * @param[in]   fp
 * @param[in]   pLocal
 * @param[in]   pRemote
 */
void ln_print_keys(FILE *fp, const ln_funding_local_data_t *pLocal, const ln_funding_remote_data_t *pRemote);
#endif

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* LN_H__ */
