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
 */
#ifndef LN_H__
#define LN_H__

#include <stdint.h>
#include <stdbool.h>

#include "utl_common.h"

#include "btc.h"
#include "btc_crypto.h"
#include "btc_sig.h"
#include "btc_tx.h"
#include "btc_script.h"

#include "ln_err.h"
#include "ln_msg_establish.h"
#include "ln_msg_anno.h"
#include "ln_onion.h"
#include "ln_derkey.h"
#include "ln_noise.h"
#include "ln_node.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define LN_PORT_DEFAULT                 (9735)

#define LN_SZ_CHANNEL_ID                (32)        ///< (size) channel_id
#define LN_SZ_SHORT_CHANNEL_ID          (8)         ///< (size) short_channel_id
#define LN_SZ_SHORTCHANNELID_STR        (127)       ///< (size) short_channel_id string
#define LN_SZ_SIGNATURE                 BTC_SZ_SIGN_RS    ///< (size) signature
#define LN_SZ_ALIAS_STR                 (32)        ///< (size) node alias //XXX:
#define LN_SZ_PREIMAGE                  (32)        ///< (size) preimage
#define LN_SZ_SEED                      (32)        ///< (size) seed
#define LN_SZ_ONION_ROUTE               (1366)      ///< (size) onion-routing-packet
#define LN_SZ_NOISE_HEADER              (sizeof(uint16_t) + 16)     ///< (size) noise packet header
#define LN_SZ_FUNDINGTX_VSIZE           (177)       ///< (size) funding_txのvsize(nested in BIP16 P2SH format)
#define LN_SZ_ERRMSG                    (256)       ///< (size) last error string


#define LN_ANNOSIGS_CONFIRM             (6)         ///< announcement_signaturesを送信するconfirmation
#define LN_FUNDIDX_MAX                  (6)         ///< 管理用
#define LN_SCRIPTIDX_MAX                (5)         ///< 管理用
#define LN_HTLC_MAX                     (6)         ///< 自分のHTLC数   TODO:暫定
                                                    //      max_accepted_htlcsとして使用する
                                                    //      相手の分も同じ分しか用意していない
                                                    //      相手からの要求はmax_accepted_htlcsまでしか受け入れないので、
                                                    //      こちらから要求しなければ済む話である。
#define LN_NODE_MAX                     (5)         ///< 保持するノード情報数   TODO:暫定
#define LN_CHANNEL_MAX                  (10)        ///< 保持するチャネル情報数 TODO:暫定
#define LN_FEERATE_PER_KW               (500)       ///< estimate feeできなかった場合のfeerate_per_kw
#define LN_FEERATE_PER_KW_MIN           (253)       ///< feerate_per_kwの下限
                                                    // https://github.com/ElementsProject/lightning/blob/86290b54d49d183e49f905be6a18bfc65612580e/lightningd/chaintopology.c#L298
#define LN_BLK_FEEESTIMATE              (6)         ///< estimatefeeのブロック数(2以上)
#define LN_MIN_FINAL_CLTV_EXPIRY        (9)         ///< min_final_cltv_expiryのデフォルト値
#define LN_INVOICE_EXPIRY               (3600)      ///< invoice expiryのデフォルト値
#define LN_FUNDSAT_MIN                  (1000)      ///< minimum funding_sat(BOLTに規定はない)

#define LN_FEE_COMMIT_BASE              (724ULL)    ///< commit_tx base fee

// ln_htlcflag_t.addhtlc
#define LN_ADDHTLC_NONE                 (0x00)
#define LN_ADDHTLC_OFFER                (0x01)      ///< Offered HTLC
#define LN_ADDHTLC_RECV                 (0x02)      ///< Received HTLC

// ln_htlcflag_t.delhtlc, fin_delhtlc
#define LN_DELHTLC_NONE                 (0x00)
#define LN_DELHTLC_FULFILL              (0x01)      ///< update_fulfill_htlc/update_fail_htlc/update_fail_malformed_htlc送信済み
#define LN_DELHTLC_FAIL                 (0x02)      ///< update_fail_htlc
#define LN_DELHTLC_MALFORMED            (0x03)      ///< update_fail_malformed_htlc

// channel_update.channel_flags
#define LN_CNLUPD_CHFLAGS_DIRECTION     (0x01)      ///< b0: direction
#define LN_CNLUPD_CHFLAGS_DISABLE       (0x02)      ///< b1: disable

// ln_self_t.shutdown_flag
#define LN_SHDN_FLAG_SEND               (0x01)      ///< shutdown送信済み
#define LN_SHDN_FLAG_RECV               (0x02)      ///< shutdown受信済み

// ln_close_force_t.p_tx, p_htlc_idxのインデックス値
#define LN_CLOSE_IDX_COMMIT             (0)         ///< commit_tx
#define LN_CLOSE_IDX_TOLOCAL            (1)         ///< to_local tx
#define LN_CLOSE_IDX_TOREMOTE           (2)         ///< to_remote tx
#define LN_CLOSE_IDX_HTLC               (3)         ///< HTLC tx
#define LN_CLOSE_IDX_NONE               ((uint8_t)0xff)

// self.anno_flag
#define LN_ANNO_FLAG_END                (0x80)      ///< 1:announcement_signatures交換済み

//self.fund_flag
#define LN_FUNDFLAG_FUNDER              (1 << 0)    ///< 1:funder / 0:fundee
#define LN_FUNDFLAG_NO_ANNO_CH          (1 << 1)    ///< 1:announcement_signatures未送信 / 0:announcement_signatures送信不要 or 送信済み
#define LN_FUNDFLAG_FUNDING             (1 << 2)    ///< 1:open_channel～funding_lockedまで
#define LN_FUNDFLAG_OPENED              (1 << 7)    ///< 1:opened

// revoked transaction closeされたときの self->p_revoked_vout, p_revoked_witのインデックス値
#define LN_RCLOSE_IDX_TOLOCAL           (0)         ///< to_local
#define LN_RCLOSE_IDX_TOREMOTE          (1)         ///< to_remote
#define LN_RCLOSE_IDX_HTLC              (2)         ///< HTLC

#define LN_UGLY_NORMAL                              ///< payment_hashを保存するタイプ
                                                    ///< コメントアウトするとDB保存しなくなるが、revoked transaction closeから取り戻すために
                                                    ///< 相手のアクションが必要となる

#define LN_INIT_LF_OPT_DATALOSS_REQ     (1 << 0)    ///< option_data_loss_protect
#define LN_INIT_LF_OPT_DATALOSS         (1 << 1)    ///< option_data_loss_protect
#define LN_INIT_LF_ROUTE_SYNC           (1 << 3)    ///< initial_routing_sync
#define LN_INIT_LF_OPT_UPF_SHDN_REQ     (1 << 4)    ///< option_upfront_shutdown_script
#define LN_INIT_LF_OPT_UPF_SHDN         (1 << 5)    ///< option_upfront_shutdown_script
#define LN_INIT_LF_OPT_GSP_QUERY_REQ    (1 << 6)    ///< gossip_queries
#define LN_INIT_LF_OPT_GSP_QUERY        (1 << 7)    ///< gossip_queries

//XXX:
#define LN_MAX_ACCEPTED_HTLCS_MAX       (483)
#define LN_NUM_PONG_BYTES_MAX           (65532 - 1)
#define LN_FUNDING_SATOSHIS_MAX         (0x1000000 - 1) //2^24-1


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
// [ptarmcli --debug]true:通常動作(false:デバッグ動作)
//

// 0x01: update_fulfill_htlcを返さない
#define LN_DBG_FULFILL() ((ln_debug_get() & 0x01) == 0)
// 0x02: closeでclosing_txを展開しない
#define LN_DBG_CLOSING_TX() ((ln_debug_get() & 0x02) == 0)
// 0x04: HTLC scriptでpreimageが一致しても不一致とみなす
#define LN_DBG_MATCH_PREIMAGE() ((ln_debug_get() & 0x04) == 0)
// 0x08: monitoringで未接続ノードに接続しに行かない
#define LN_DBG_NODE_AUTO_CONNECT() ((ln_debug_get() & 0x08) == 0)
// 0x10: onionのrealmを不正な値にする
#define LN_DBG_ONION_CREATE_NORMAL_REALM() ((ln_debug_get() & 0x10) == 0)
// 0x20: onionのversionを不正な値にする
#define LN_DBG_ONION_CREATE_NORMAL_VERSION() ((ln_debug_get() & 0x20) == 0)
// 0x40: update_fulfill_htlcを戻すときに相手が見つからない
#define LN_DBG_FULFILL_BWD() ((ln_debug_get() & 0x40) == 0)

#define M_DB_SELF_SAVE(self)    { bool ret = ln_db_self_save(self); LOGD("ln_db_self_save()=%d\n", ret); }
#define M_DB_SECRET_SAVE(self)  { bool ret = ln_db_secret_save(self); LOGD("ln_db_secret_save()=%d\n", ret); }

#if !defined(M_DBG_VERBOSE) && !defined(PTARM_USE_PRINTFUNC)
#define M_DBG_PRINT_TX(tx)      //NONE
//#define M_DBG_PRINT_TX(tx)    LOGD(""); btc_tx_print(tx)
#define M_DBG_PRINT_TX2(tx)     //NONE
#else
#define M_DBG_PRINT_TX(tx)      LOGD("\n"); btc_tx_print(tx)
#define M_DBG_PRINT_TX2(tx)     LOGD("\n"); btc_tx_print(tx)
#endif  //M_DBG_VERBOSE

#define M_DBG_COMMITHTLC
#ifdef M_DBG_COMMITHTLC
#define M_DBG_COMMITNUM(self) { LOGD("----- debug commit_num -----\n"); ln_dbg_commitnum(self); }
#define M_DBG_HTLCFLAG(htlc) dbg_htlcflag(htlc)
#define M_DBG_HTLCFLAGALL(self) dbg_htlcflagall(self)
#else
#define M_DBG_COMMITNUM(self)   //none
#define M_DBG_HTLCFLAG(htlc)    //none
#define M_DBG_HTLCFLAGALL(self) //none
#endif


/********************************************************************
 * typedefs
 ********************************************************************/

//forward definition
struct ln_self_t;
typedef struct ln_self_t ln_self_t;


/** @enum   ln_status_t
 *  @brief  ln_self_t.status
 */
typedef enum {
    LN_STATUS_NONE = 0,
    LN_STATUS_ESTABLISH = 1,        ///< establish
    LN_STATUS_NORMAL = 2,           ///< normal operation
    LN_STATUS_CLOSE_WAIT = 3,       ///< shutdown received or sent
    LN_STATUS_CLOSE_SPENT = 4,      ///< funding_tx is spent but not in block
    LN_STATUS_CLOSE_MUTUAL = 5,     ///< mutual close
    LN_STATUS_CLOSE_UNI_LOCAL = 6,  ///< unilateral close(from local)
    LN_STATUS_CLOSE_UNI_REMOTE = 7, ///< unilateral close(from remote)
    LN_STATUS_CLOSE_REVOKED = 8     ///< revoked transaction close(from remote)
} ln_status_t;


/** @enum   ln_fundflag_t
 *  @brief  self->fund_flag
 *  @note   LN_FUNDFLAG_xxx
 */
typedef uint8_t ln_fundflag_t;


/** @enum   ln_cb_t
 *  @brief  コールバック理由
 */
typedef enum {
    LN_CB_QUIT,                 ///< チャネルを停止(closeはしない)
    LN_CB_ERROR,                ///< エラー通知
    LN_CB_INIT_RECV,            ///< init受信通知
    LN_CB_REESTABLISH_RECV,     ///< channel_reestablish受信通知
    LN_CB_SIGN_FUNDINGTX_REQ,   ///< funding_tx署名要求
    LN_CB_FUNDINGTX_WAIT,       ///< funding_tx安定待ち要求
    LN_CB_FUNDINGLOCKED_RECV,   ///< funding_locked受信通知
    LN_CB_UPDATE_ANNODB,        ///< announcement DB更新通知
    LN_CB_ADD_HTLC_RECV_PREV,   ///< update_add_htlc処理前通知
    LN_CB_ADD_HTLC_RECV,        ///< update_add_htlc受信通知
    LN_CB_FWD_ADDHTLC_START,    ///< update_add_htlc転送開始
    LN_CB_BWD_DELHTLC_START,    ///< HTLC削除処理開始
    LN_CB_FULFILL_HTLC_RECV,    ///< update_fulfill_htlc受信通知
    LN_CB_FAIL_HTLC_RECV,       ///< update_fail_htlc受信通知
    LN_CB_REV_AND_ACK_EXCG,     ///< revoke_and_ack交換通知
    LN_CB_PAYMENT_RETRY,        ///< 送金リトライ
    LN_CB_UPDATE_FEE_RECV,      ///< update_fee受信通知
    LN_CB_SHUTDOWN_RECV,        ///< shutdown受信通知
    LN_CB_CLOSED_FEE,           ///< closing_signed受信通知(FEE不一致)
    LN_CB_CLOSED,               ///< closing_signed受信通知(FEE一致)
    LN_CB_SEND_REQ,             ///< peerへの送信要求
    LN_CB_SEND_QUEUE,           ///< 送信キュー保存(廃止予定)
    LN_CB_GET_LATEST_FEERATE,   ///< feerate_per_kw取得要求
    LN_CB_GETBLOCKCOUNT,        ///< getblockcount
    LN_CB_PONG_RECV,            ///< pong received
    LN_CB_MAX,
} ln_cb_t;


/** @typedef    ln_callback_t
 *  @brief      通知コールバック関数
 *  @note
 *      - p_paramで渡すデータを上位層で保持しておきたい場合、コピーを取ること
 */
typedef void (*ln_callback_t)(ln_self_t *self, ln_cb_t type, void *p_param);


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


/** @struct ln_fundin_t
 *  @brief  open_channelでのfund_in情報
 *  @note
 *      - open_channelする方が #ln_establish_t .p_fundinに設定して使う
 */
typedef struct {
    uint8_t                     txid[BTC_SZ_TXID];              ///< 2-of-2へ入金するTXID
    int32_t                     index;                          ///< 未設定時(channelを開かれる方)は-1
    uint64_t                    amount;                         ///< 2-of-2へ入金するtxのvout amount
    utl_buf_t                   change_spk;                     ///< 2-of-2へ入金したお釣りの送金先ScriptPubkey
} ln_fundin_t;


/** @struct ln_establish_prm_t
 *  @brief  Establish関連のパラメータ
 *  @note
 *      - #ln_establish_alloc()で初期化する
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
    ln_fundin_t                 *p_fundin;                      ///< 非NULL:open_channel側
    ln_establish_prm_t          estprm;                         ///< channel establish parameter
} ln_establish_t;

/// @}


/**************************************************************************
 * typedefs : Channel Close
 **************************************************************************/

/// @addtogroup channel_close
/// @{

/** @struct ln_close_force_t
 *  @brief  [Close]Unilateral Close / Revoked Transaction Close用
 *  @note
 *      - p_tx, p_htlc_idxの添字
 *          - commit_tx: LN_CLOSE_IDX_COMMIT
 *          - to_local output: LN_CLOSE_IDX_TOLOCAL
 *          - to_remote output: LN_CLOSE_IDX_TOREMOTE
 *          - HTLC: LN_CLOSE_IDX_HTLC～
 */
typedef struct {
    int             num;                            ///< p_txのtransaction数
    btc_tx_t        *p_tx;                          ///< トランザクション
                                                    ///<    添字:[0]commit_tx [1]to_local [2]to_remote [3-]HTLC
    uint8_t         *p_htlc_idx;                    ///< self->cnl_add_htlc[]のhtlc_idx
                                                    ///<    添字:[3]以上で有効
    utl_buf_t       tx_buf;                         ///< HTLC Timeout/Successから取り戻すTX
} ln_close_force_t;

/// @}


/**************************************************************************
 * typedefs : Normal Operation
 **************************************************************************/

/** @struct ln_htlcflag_t
 *  @brief  HTLC管理フラグ
 *  @note
 *      - uint16_tとunionする場合がある
 */
typedef struct {
    unsigned        addhtlc     : 2;    ///< LN_ADDHTLC_OFFER/RECV
    unsigned        delhtlc     : 2;    ///< LN_DELHTLC_FULFILL/FAIL/MALFORMED
    unsigned        updsend     : 1;    ///< 1:update message sent
    unsigned        comsend     : 1;    ///< 1:commitment_signed sent
    unsigned        revrecv     : 1;    ///< 1:revoke_and_ack received
    unsigned        comrecv     : 1;    ///< 1:commitment_signed received
    unsigned        revsend     : 1;    ///< 1:revoke_and_ack sent
    unsigned        fin_delhtlc : 2;    ///< flag.addhtlc == RECV
                                        //      update_add_htlc受信 && final node時、irrevocably committed後のflag.delhtlc
    unsigned        updwait     : 1;    ///< 1:update message received
    unsigned        Reserved    : 4;
} ln_htlcflag_t;

#define LN_HTLCFLAG_MASK_HTLC       (0x000f)    ///< addhtlc, delhtlc
#define LN_HTLCFLAG_MASK_UPDSEND    (0x0010)    ///< updsend
#define LN_HTLCFLAG_MASK_COMSIG1    (0x0060)    ///< comsend, revrecv
#define LN_HTLCFLAG_MASK_COMSIG2    (0x0180)    ///< comrecv, revsend
#define LN_HTLCFLAG_MASK_COMSIG     ((LN_HTLCFLAG_MASK_COMSIG1 | LN_HTLCFLAG_MASK_COMSIG2))    ///< comsned, revrecv, comrecv, revsend
#define LN_HTLCFLAG_MASK_FINDELHTLC (0x0600)    ///< fin_delhtlc
#define LN_HTLCFLAG_MASK_UPDWAIT    (0x0800)    ///< updwait
#define LN_HTLCFLAG_MASK_ALL        (LN_HTLCFLAG_MASK_FINDELHTLC | LN_HTLCFLAG_MASK_COMSIG | LN_HTLCFLAG_MASK_UPDSEND | LN_HTLCFLAG_MASK_HTLC)
#define LN_HTLCFLAG_SFT_ADDHTLC(a)      ((uint16_t)(a))
#define LN_HTLCFLAG_SFT_DELHTLC(a)      ((uint16_t)(a) << 2)
#define LN_HTLCFLAG_SFT_UPDSEND         ((uint16_t)1 << 4)
#define LN_HTLCFLAG_SFT_COMSEND         ((uint16_t)1 << 5)
#define LN_HTLCFLAG_SFT_REVRECV         ((uint16_t)1 << 6)
#define LN_HTLCFLAG_SFT_COMRECV         ((uint16_t)1 << 7)
#define LN_HTLCFLAG_SFT_REVSEND         ((uint16_t)1 << 8)
#define LN_HTLCFLAG_SFT_FINDELHTLC(a)   ((uint16_t)(a) << 9)
#define LN_HTLCFLAG_SFT_UPDRECV         ((uint16_t)1 << 11)
#define LN_HTLCFLAG_SFT_TIMEOUT         (LN_HTLCFLAG_SFT_REVSEND | LN_HTLCFLAG_SFT_COMRECV | LN_HTLCFLAG_SFT_REVRECV | LN_HTLCFLAG_SFT_COMSEND | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_OFFER))


/** @struct     ln_update_add_htlc_t
 *  @brief      update_add_htlc
 */
typedef struct {
    uint8_t     *p_channel_id;                      ///< 32: channel_id
    uint64_t    id;                                 ///< 8:  id
    uint64_t    amount_msat;                        ///< 8:  amount_msat
    uint32_t    cltv_expiry;                        ///< 4:  cltv_expirty
    uint8_t     payment_sha256[BTC_SZ_HASH256];     ///< 32: payment_hash //XXX:
    utl_buf_t   buf_payment_preimage;               ///< 32: payment_preimage
    utl_buf_t   buf_onion_reason;                   ///<
                                                    //  update_add_htlc
                                                    //      1366: onion_routing_packet
                                                    //          final node: length == 0
                                                    //  update_fail_htlc
                                                    //      len:  reason
    //inner
    union {
        uint16_t        bits;
        ln_htlcflag_t   flag;                       ///< LN_HTLC_FLAG_xxx
    } stat;
    uint64_t        next_short_channel_id;          ///< flag.addhtlc == OFFER
                                                    //      update_add_htlc受信 && hop node時、irrevocably committed後の通知先
    uint16_t        next_idx;
    //fulfillで戻す
    uint8_t     signature[LN_SZ_SIGNATURE];         ///< 受信した最新のHTLC署名
                                                    //      相手がunilateral close後にHTLC-txを送信しなかった場合に使用する
    uint64_t    prev_short_channel_id;              ///< 転送元short_channel_id
                                                    //      origin/final node: == 0
    uint16_t    prev_idx;                           ///< 転送元cnl_add_htlc[]index
    //failで戻す
    utl_buf_t   buf_shared_secret;                  ///< failuremsg暗号化用
} ln_update_add_htlc_t;


/**************************************************************************
 * typedefs : Announcement
 **************************************************************************/

/// @addtogroup announcement
/// @{

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
 * typedefs : コールバック用
 **************************************************************************/

/** @struct ln_cb_funding_sign_t
 *  @brief  funding_tx署名要求(#LN_CB_SIGN_FUNDINGTX_REQ)
 */
typedef struct {
    btc_tx_t                *p_tx;
    uint64_t                amount;     //(SPV未使用)fund-inするamount[satoshi]
    bool                    ret;        //署名結果
} ln_cb_funding_sign_t;


/** @struct ln_cb_funding_t
 *  @brief  funding_tx安定待ち要求(#LN_CB_FUNDINGTX_WAIT) / Establish完了通知(#LN_CB_ESTABLISHED)
 */
typedef struct {
    const btc_tx_t          *p_tx_funding;              ///< funding_tx
    const uint8_t           *p_txid;                    ///< funding txid
    bool                    b_send;                     ///< true:funding_txを送信する
    bool                    annosigs;                   ///< true:announce_signaturesを送信する
    bool                    b_result;                   ///< true:funding_tx送信成功
} ln_cb_funding_t;


/** @struct ln_cb_add_htlc_recv_prev_t
 *  @brief  update_add_htlc受信 前処理(#LN_CB_ADD_HTLC_RECV_PREV)
 */
typedef struct {
    uint64_t                next_short_channel_id;
    const ln_self_t         *p_next_self;
} ln_cb_add_htlc_recv_prev_t;


/** @enum   ln_cb_add_htlc_result_t
 *  @brief  result of update_add_htlc processing
 */
typedef enum {
    LN_CB_ADD_HTLC_RESULT_OK,           ///< transfer update_add_htlc or backward update_fulfill_htlc
    LN_CB_ADD_HTLC_RESULT_FAIL,         ///< backward update_fail_htlc
    LN_CB_ADD_HTLC_RESULT_MALFORMED,    ///< backward update_fail_malformed_htlc
} ln_cb_add_htlc_result_t;


/** @struct ln_cb_add_htlc_recv_t
 *  @brief  update_add_htlc受信通知(#LN_CB_ADD_HTLC_RECV)
 */
typedef struct {
    bool                        ret;                    ///< callback処理結果
    uint64_t                    id;                     ///< HTLC id
    const uint8_t               *p_payment;             ///< payment_hash
    const ln_hop_dataout_t      *p_hop;                 ///< onion解析結果
    uint64_t                    amount_msat;            ///< self->cnl_add_htlc[idx].amount_msat
    uint32_t                    cltv_expiry;            ///< self->cnl_add_htlc[idx].cltv_expiry
    uint16_t                    idx;                    ///< self->cnl_add_htlc[idx]
    utl_buf_t                   *p_onion_reason;        ///< 変換後onionパケット(ok==true) or fail reason(ok==false)
    const utl_buf_t             *p_shared_secret;       ///< onion shared secret
} ln_cb_add_htlc_recv_t;


typedef struct {
    uint64_t                    short_channel_id;
    uint16_t                    idx;
} ln_cb_fwd_add_htlc_t;


typedef struct {
    uint64_t                    short_channel_id;
    uint16_t                    idx;
    uint8_t                     fin_delhtlc;
} ln_cb_bwd_del_htlc_t;


/** @struct ln_cb_fulfill_htlc_recv_t
 *  @brief  update_fulfill_htlc受信通知(#LN_CB_FULFILL_HTLC_RECV)
 */
typedef struct {
    bool                    ret;                    ///< callback処理結果
    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    uint16_t                prev_idx;               ///< self->cnl_add_htlc[idx]
    const uint8_t           *p_preimage;            ///< update_fulfill_htlcで受信したpreimage(スタック)
    uint64_t                id;                     ///< HTLC id
    uint64_t                amount_msat;            ///< HTLC amount
} ln_cb_fulfill_htlc_recv_t;


/** @struct ln_cb_fail_htlc_recv_t
 *  @brief  update_fail_htlc受信通知(#LN_CB_FAIL_HTLC_RECV)
 */
typedef struct {
    bool                    result;

    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    const utl_buf_t         *p_reason;              ///< reason
    const utl_buf_t         *p_shared_secret;       ///< shared secret
    uint16_t                prev_idx;               ///< self->cnl_add_htlc[idx]
    uint64_t                orig_id;                ///< 元のHTLC id
    const uint8_t           *p_payment_hash;        ///< payment_hash
    uint16_t                malformed_failure;      ///< !0: malformed_htlcのfailure_code
} ln_cb_fail_htlc_recv_t;


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
    bool                    result;                 ///< true:closing_tx展開成功
    const utl_buf_t         *p_tx_closing;          ///< ブロックチェーンに公開するtx
} ln_cb_closed_t;


/** @struct ln_cb_anno_sigs_t
 *  @brief  announcement_signatures
 */
typedef struct {
    const utl_buf_t         *p_buf_bolt;            ///< 受信したannouncement_signatures
    uint8_t                 sort;
} ln_cb_anno_sigs_t;


/** @struct ln_cb_update_annodb_anno_t
 *  @brief  announcement DB更新通知値
 */
typedef enum {
    LN_CB_UPDATE_ANNODB_NONE,
    LN_CB_UPDATE_ANNODB_CNL_ANNO,       //channel_announcement
    LN_CB_UPDATE_ANNODB_CNL_UPD,        //channel_update
    LN_CB_UPDATE_ANNODB_NODE_ANNO,      //node_announcement
} ln_cb_update_annodb_anno_t;


/** @struct ln_cb_update_annodb_t
 *  @brief  announcement DB更新通知(#LN_CB_UPDATE_ANNODB)
 */
typedef struct {
    ln_cb_update_annodb_anno_t      anno;
} ln_cb_update_annodb_t;


/** @struct ln_cb_pong_recv_t
 *  @brief  pong received(#LN_CB_PONG_RECV)
 */
typedef struct {
    bool                            result;         //true: lnapp check OK
    uint16_t                        byteslen;       //pong.byteslen
    const uint8_t                   *p_ignored;     //pong.ignored
} ln_cb_pong_recv_t;


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
    uint8_t                     node_id[BTC_SZ_PUBKEY];         ///< ノードID
    char                        alias[LN_SZ_ALIAS_STR + 1];     ///< 名前
    btc_script_pubkey_order_t   sort;                           ///< ノードの順番
                                                            // #BTC_SCRYPT_PUBKEY_ORDER_ASC : 自ノードが先
                                                            // #BTC_SCRYPT_PUBKEY_ORDER_OTHER : 他ノードが先
} ln_node_info_t;


/** @struct ln_funding_local_data_t
 *  @brief  自ノードfunding情報
 */
typedef struct {
    uint8_t             txid[BTC_SZ_TXID];              ///< funding-tx TXID
    uint16_t            txindex;                        ///< funding-tx index

    //MSG_FUNDIDX_xxx
    uint8_t             pubkeys[LN_FUNDIDX_MAX][BTC_SZ_PUBKEY];         ///< 自分の公開鍵
    //MSG_SCRIPTIDX_xxx
    uint8_t             scriptpubkeys[LN_SCRIPTIDX_MAX][BTC_SZ_PUBKEY]; ///< script用PubKey
} ln_funding_local_data_t;


/** @struct ln_funding_remote_data_t
 *  @brief  他ノードfunding情報
 */
typedef struct {
    //MSG_FUNDIDX_xxx
    uint8_t             pubkeys[LN_FUNDIDX_MAX][BTC_SZ_PUBKEY];     ///< 相手から受信した公開鍵
    uint8_t             prev_percommit[BTC_SZ_PUBKEY];              ///< 1つ前のper_commit_point
    //MSG_SCRIPTIDX_xxx
    uint8_t             scriptpubkeys[LN_SCRIPTIDX_MAX][BTC_SZ_PUBKEY]; ///< script用PubKey
} ln_funding_remote_data_t;


/** @struct ln_commit_data_t
 *  @brief  commitment transaction用情報
 */
typedef struct {
    uint64_t            dust_limit_sat;                 ///< dust_limit_satoshis
    uint64_t            max_htlc_value_in_flight_msat;  ///< max_htlc_value_in_flight_msat
    uint64_t            channel_reserve_sat;            ///< channel_reserve_satoshis
    uint64_t            htlc_minimum_msat;              ///< htlc_minimum_msat
    uint16_t            to_self_delay;                  ///< to_self_delay
    uint16_t            max_accepted_htlcs;             ///< max_accepted_htlcs

    uint8_t             signature[LN_SZ_SIGNATURE];     ///< 署名
                                                        // localには相手に送信する署名
                                                        // remoteには相手から受信した署名
    uint8_t             txid[BTC_SZ_TXID];              ///< txid
    uint16_t            htlc_num;                       ///< commit_tx中のHTLC数
    uint64_t            commit_num;                     ///< commitment_number
                                                        //      commit_local:  commitment_signed受信後、インクリメント
                                                        //      commit_remote: commitment_signed送信後、インクリメント
    uint64_t            revoke_num;                     ///< 最後にrevoke_and_ack送信した時のcommitment_number
                                                        //      commit_local:  revoke_and_ack送信後、commit_local.commit_num - 1を代入
                                                        //      commit_remote: revoke_and_ack受信後、self->commit_remote.commit_num - 1を代入
} ln_commit_data_t;


typedef struct {
    uint64_t                    storage_index;                  ///< 自分のstorage_index
                                                                //      鍵生成してからデクリメントするため、次に生成する際のindexを指している。
                                                                //      初期値は0xFFFFFFFFFFFF(48bit)。
                                                                //      初回のcommit_txは0xFF...FFで作成することになる。
    uint8_t                     storage_seed[LN_SZ_SEED];       ///< ユーザから指定されたseed

    uint8_t                     priv[LN_FUNDIDX_MAX][BTC_SZ_PRIVKEY];
} ln_self_priv_t;


/** @struct     ln_self_t
 *  @brief      チャネル情報
 */
struct ln_self_t {
    //connect
    uint8_t                     peer_node_id[BTC_SZ_PUBKEY];    ///< [CONN_01]接続先ノード
    ln_node_addr_t               last_connected_addr;            ///< [CONN_02]最後に接続したIP address
    ln_status_t                 status;                         ///< [CONN_03]状態

    //key storage
    ln_derkey_storage_t         peer_storage;                   ///< [KEYS_01]key storage(peer)
    uint64_t                    peer_storage_index;             ///< [KEYS_02]storage index(peer)
    ln_self_priv_t              priv_data;                      ///< [KEYS_03]secret情報

    //funding
    ln_fundflag_t               fund_flag;                      ///< [FUND_01]none/funder/fundee
    ln_funding_local_data_t     funding_local;                  ///< [FUND_02]funding情報:local
    ln_funding_remote_data_t    funding_remote;                 ///< [FUND_03]funding情報:remote
    uint64_t                    obscured;                       ///< [FUND_04]commitment numberをXORするとobscured commitment numberになる値。
                                                                    // 0の場合、1回でもclosing_signed受信した
    utl_buf_t                   redeem_fund;                    ///< [FUND_05]2-of-2のredeemScript
    btc_script_pubkey_order_t   key_fund_sort;                  ///< [FUND_06]2-of-2のソート順(local, remoteを正順とした場合)
    btc_tx_t                    tx_funding;                     ///< [FUND_07]funding_tx
    ln_establish_t              establish;                      ///< [FUND_08]Establishワーク領域
    uint32_t                    min_depth;                      ///< [FUND_09]minimum_depth
    uint8_t                     funding_bhash[BTC_SZ_HASH256];  ///< [FUNDSPV_01]funding_txがマイニングされたblock hash
    uint32_t                    last_confirm;                   ///< [FUNDSPV_02]confirmation at calling btcrpc_set_channel()

    //msg:announce
    uint8_t                     anno_flag;                      ///< [ANNO_01]announcement_signaturesなど
    ln_anno_prm_t               anno_prm;                       ///< [ANNO_02]announcementパラメータ
    utl_buf_t                   cnl_anno;                       ///< [ANNO_03]自channel_announcement

    //msg:establish
    uint8_t                     init_flag;                      ///< [INIT_01]initフラグ(M_INIT_FLAG_xxx)
    uint8_t                     lfeature_local;                 ///< [INIT_02]initで送信したlocalfeature
    uint8_t                     lfeature_remote;                ///< [INIT_03]initで取得したlocalfeature
    uint64_t                    reest_commit_num;               ///< [INIT_04]channel_reestablish.next_local_commitment_number
    uint64_t                    reest_revoke_num;               ///< [INIT_05]channel_reestablish.next_remote_revocation_number

    //msg:close
    btc_tx_t                    tx_closing;                     ///< [CLSE_02]closing_tx
    uint8_t                     shutdown_flag;                  ///< [CLSE_03]shutdownフラグ(M_SHDN_FLAG_xxx)
    uint64_t                    close_fee_sat;                  ///< [CLSE_04]closing_txのFEE
    uint64_t                    close_last_fee_sat;             ///< [CLSE_05]最後に送信したclosing_txのFEE
    utl_buf_t                   shutdown_scriptpk_local;        ///< [CLSE_06]close時の送金先(local)
    utl_buf_t                   shutdown_scriptpk_remote;       ///< [CLSE_07]mutual close時の送金先(remote)
    //revoked
    utl_buf_t                   *p_revoked_vout;                ///< [REVK_01]revoked transaction close時に検索するvoutスクリプト([0]は必ずto_local系)
    utl_buf_t                   *p_revoked_wit;                 ///< [REVK_02]revoked transaction close時のwitnessスクリプト
    ln_htlctype_t               *p_revoked_type;                ///< [REVK_03]p_revoked_vout/p_revoked_witに対応するtype
    utl_buf_t                   revoked_sec;                    ///< [REVK_04]revoked transaction close時のremote per_commit_sec
    uint16_t                    revoked_num;                    ///< [REVK_05]revoked_cnt+1([0]にto_local系を入れるため)
    uint16_t                    revoked_cnt;                    ///< [REVK_06]取り戻す必要があるvout数
    uint32_t                    revoked_chk;                    ///< [REVK_07]最後にチェックしたfunding_txのconfirmation数

    //msg:normal operation
    uint64_t                    htlc_id_num;                    ///< [NORM_01]update_add_htlcで使うidの管理
    uint64_t                    our_msat;                       ///< [NORM_02]自分の持ち分
    uint64_t                    their_msat;                     ///< [NORM_03]相手の持ち分
    uint8_t                     channel_id[LN_SZ_CHANNEL_ID];   ///< [NORM_04]channel_id
    uint64_t                    short_channel_id;               ///< [NORM_05]short_channel_id
    ln_update_add_htlc_t        cnl_add_htlc[LN_HTLC_MAX];      ///< [NORM_06]追加したHTLC

    //commitment transaction(local/remote)
    ln_commit_data_t            commit_local;                   ///< [COMM_01]local commit_tx用
    ln_commit_data_t            commit_remote;                  ///< [COMM_02]remote commit_tx用
    //commitment transaction(固有)
    uint64_t                    funding_sat;                    ///< [COMM_03]funding_satoshis
    uint32_t                    feerate_per_kw;                 ///< [COMM_04]feerate_per_kw

    //noise protocol
    ln_noise_t                  noise;                          ///< [NOIS_01]noise protocol

    //last error
    int                         err;                            ///< [ERRO_01]error code(ln_err.h)
    char                        err_msg[LN_SZ_ERRMSG];          ///< [ERRO_02]]エラーメッセージ

    //for app
    ln_callback_t               p_callback;                     ///< [APPS_01]通知コールバック
    void                        *p_param;                       ///< [APPS_02]ユーザ用
};

/// @}


/**************************************************************************
 * prototypes
 **************************************************************************/

/** 初期化
 *
 * 鍵関係を、ストレージを含めて初期化している。
 *
 * @param[in,out]       self            channel info
 * @param[in]           pSeed           per-commit-secret生成用
 * @param[in]           pAnnoPrm        announcementパラメータ
 * @param[in]           pFunc           通知用コールバック関数
 * @retval      true    成功
 */
bool ln_init(ln_self_t *self, const uint8_t *pSeed, const ln_anno_prm_t *pAnnoPrm, ln_callback_t pFunc);


/** 終了
 *
 * @param[in,out]       self            channel info
 */
void ln_term(ln_self_t *self);


/** load status from DB
 *
 * @param[in,out]       self            channel info
 * @return      load result
 */
bool ln_status_load(ln_self_t *self);


/** get status string
 *
 * @param[in]           self            channel info
 * @return  status
 */
const char *ln_status_string(const ln_self_t *self);


/** Genesis Block Hash設定
 *
 * @param[in]       pHash               Genesis Block Hash
 * @attention
 *      - JSON-RPCのgetblockhashで取得した値はエンディアンが逆転しているため、
 *          設定する場合にはエンディアンを逆にして pHashに与えること。
 *          https://github.com/lightningnetwork/lightning-rfc/issues/237
 */
void ln_genesishash_set(const uint8_t *pHash);


/** Genesis Block Hash取得
 *
 * @return      #ln_genesishash_set()で設定したGenesis Block Hash
 */
const uint8_t* ln_genesishash_get(void);


/** set BlockHash on node creation time(SPV only)
 *
 */
void ln_creationhash_set(const uint8_t *pHash);


/** get BlockHash on node creation time(SPV only)
 *
 */
const uint8_t *ln_creationhash_get(void);


/** peer node_id設定
 *
 * @param[in,out]       self            channel info
 */
void ln_peer_set_nodeid(ln_self_t *self, const uint8_t *pNodeId);


/** Channel Establish設定
 *
 * @param[in,out]       self            channel info
 * @param[in]           pEstPrm         Establishパラメータ
 * @retval      true    成功
 * @note
 *      - pEstablishは接続完了まで保持すること
 */
bool ln_establish_alloc(ln_self_t *self, const ln_establish_prm_t *pEstPrm);


/** #ln_establish_alloc()で確保したメモリを解放する
 *
 * @param[in,out]       self            channel info
 * @note
 *      - lnapp.cでfunding済みだった場合に呼ばれる想定
 */
void ln_establish_free(ln_self_t *self);


/** short_channel_id情報設定
 *
 * @param[in,out]       self            channel info
 * @param[in]           Height          funding_txが入ったブロック height
 * @param[in]           Index           funding_txのTXIDが入っているindex
 * @note
 *  - save DB if self->short_channel_id == 0
 */
void ln_short_channel_id_set_param(ln_self_t *self, uint32_t Height, uint32_t Index);


/** short_channel_id情報取得
 *
 * @param[out]          pHeight     funding_txが入ったブロック height
 * @param[out]          pBIndex      funding_txのTXIDが入っているindex
 * @param[out]          pVIndex     funding_txとして使用するvout index
 * @param[in]           ShortChannelId  short_channel_id
 */
void ln_short_channel_id_get_param(uint32_t *pHeight, uint32_t *pBIndex, uint32_t *pVIndex, uint64_t ShortChannelId);


/** short_channel_id情報設定
 *
 * @param[in,out]       self            channel info
 * @param[in]           pMinedHash      funding_txがマイニングされたblock hash
 */
void ln_funding_blockhash_set(ln_self_t *self, const uint8_t *pMinedHash);


/** get BOLT short_channel_id string
 *
 * @param[out]  pStr            return value(length > LN_SZ_SHORTCHANNELID_STR)
 * @param[in]   ShortChannelId  short_channel_id
 */
void ln_short_channel_id_string(char *pStr, uint64_t ShortChannelId);


/** shutdown時の出力先設定(address)
 *
 * @param[in,out]       self            channel info
 * @param[in]           pScriptPk       shutdown時の送金先ScriptPubKey
 */
void ln_shutdown_set_vout_addr(ln_self_t *self, const utl_buf_t *pScriptPk);


/** noise handshake開始
 *
 * @param[in,out]       self            channel info
 * @param[out]          pBuf        送信データ
 * @param[in]           pNodeId     送信側:接続先ノードID, 受信側:NULL
 * @retval      true    成功
 */
bool ln_handshake_start(ln_self_t *self, utl_buf_t *pBuf, const uint8_t *pNodeId);


/** noise handshake受信
 *
 * @param[in,out]       self            channel info
 * @param[out]          pCont       true:次も受信を継続する(戻り値がtrue時のみ有効)
 * @param[in,out]       pBuf        in:受信データ, out:送信データ
 * @retval      true    成功
 */
bool ln_handshake_recv(ln_self_t *self, bool *pCont, utl_buf_t *pBuf);


/** noise handshakeメモリ解放
 *
 * @param[in,out]       self            channel info
 * @note
 *      - handshakeを中断した場合に呼び出す
 */
void ln_handshake_free(ln_self_t *self);


/** Lightningメッセージ受信処理
 *
 * @param[in,out]       self            channel info
 * @param[in]           pData       受信データ
 * @param[in]           Len         pData長
 * @retval      true    解析成功
 */
bool ln_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);


/** 受信アイドル処理
 * Normal Operationの処理を進める
 *
 * @param[in,out]       self            channel info
 * @param[in]           FeeratePerKw    latest feerate_per_kw
 */
void ln_recv_idle_proc(ln_self_t *self, uint32_t FeeratePerKw);


/** 接続直後のfunding_locked必要性チェック
 *
 * @param[in]           self            channel info
 * @retval  true    funding_lockedの送信必要あり
 */
bool ln_funding_locked_check_need(const ln_self_t *self);


//XXX:
void ln_callback(ln_self_t *self, ln_cb_t Req, void *pParam);
bool ln_check_channel_id(const uint8_t *recv_id, const uint8_t *mine_id);
void ln_dbg_commitnum(const ln_self_t *self);
btc_script_pubkey_order_t ln_node_id_sort(const ln_self_t *self, const uint8_t *pNodeId);
uint8_t ln_sort_to_dir(btc_script_pubkey_order_t Sort);


/********************************************************************
 * Establish関係
 ********************************************************************/

/** channel_id生成
 *
 * @param[out]      pChannelId      生成結果
 * @param[in]       pTxid           funding-txのTXID
 * @param[in]       Index           funding-txの2-of-2 vout index
 */
void HIDDEN ln_channel_id_calc(uint8_t *pChannelId, const uint8_t *pTxid, uint16_t Index);


/** 相手のchannel_update取得
 *
 * DBから検索し、見つからなければfalseを返す
 *
 * @param[in]           self            channel info
 * @param[out]          pCnlUpd     検索したchannel_updateパケット
 * @param[out]          pMsg        (非NULL)pCnlUpdデコード結果
 * @retval      ture    成功
 */
bool ln_channel_update_get_peer(const ln_self_t *self, utl_buf_t *pCnlUpd, ln_msg_channel_update_t *pMsg);


/** [routing用]channel_updateデータ解析
 *
 * @param[out]          pUpd
 * @param[in]           pData
 * @param[in]           Len
 * @retval      true    解析成功
 */
bool ln_channel_update_get_params(ln_msg_channel_update_t *pUpd, const uint8_t *pData, uint16_t Len);


/********************************************************************
 * Close関係
 ********************************************************************/

/** closing transactionのFEE設定
 *
 * @param[in,out]       self            channel info
 * @param[in]           Fee             FEE
 */
void ln_shutdown_update_fee(ln_self_t *self, uint64_t Fee);


/** close中状態に遷移させる
 *
 * @param[in,out]       self            channel info
 */
void ln_close_change_stat(ln_self_t *self, const btc_tx_t *pCloseTx, void *pDbParam);


/** local unilateral closeトランザクション作成
 *
 * @param[in,out]       self            channel info
 * @param[out]          pClose      生成したトランザクション
 * @retval      ture    成功
 * @note
 *      - pCloseは @ln_close_free_forcetx()で解放すること
 */
bool ln_close_create_unilateral_tx(ln_self_t *self, ln_close_force_t *pClose);


/** 相手からcloseされたcommit_txを復元
 *
 * @param[in,out]       self            channel info
 * @param[out]          pClose      生成したトランザクション
 * @retval      ture    成功
 * @note
 *      - pCloseは @ln_close_free_forcetx()で解放すること
 */
bool ln_close_create_tx(ln_self_t *self, ln_close_force_t *pClose);


/** ln_close_force_tのメモリ解放
 *
 * @param[in,out]       pClose      ln_close_create_unilateral_tx()やln_create_closed_tx()で生成したデータ
 */
void ln_close_free_forcetx(ln_close_force_t *pClose);


/** revoked transaction close(ugly way)の対処
 *
 * @param[in,out]       self            channel info
 * @param[in]           pRevokedTx  revoked transaction
 * @param[in,out]       pDbParam    DBパラメータ
 * @retval      ture    成功
 * @note
 *      - self->vout にto_localのscriptPubKeyを設定する(HTLC Timeout/Successの取り戻しにも使用する)
 *      - self->wit にto_localのwitnessProgramを設定する
 */
bool ln_close_remoterevoked(ln_self_t *self, const btc_tx_t *pRevokedTx, void *pDbParam);


/********************************************************************
 * others
 ********************************************************************/

/** to_localをwalletに保存する情報作成
 *
 *  btc_tx_tフォーマットだが、blockchainに展開できるデータではない
 *      - vin: pTxid:Index, witness([0]=secret
 *      - vout: input value
 *
 * @param[in]           self            channel info
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount
 * @param[in]           ToSelfDelay     to_self_delay
 * @param[in]           pScript         送金先スクリプト
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @param[in]           bRevoked        true:revoked transaction close対応
 * @retval  true    成功
 */
bool ln_wallet_create_tolocal(const ln_self_t *self, btc_tx_t *pTx, uint64_t Value, uint32_t ToSelfDelay,
                const utl_buf_t *pScript, const uint8_t *pTxid, int Index, bool bRevoked);


/** to_remoteをwalletに保存する情報作成
 *
 *  btc_tx_tフォーマットだが、blockchainに展開できるデータではない
 *      - vin: pTxid:Index, witness([0]=secret
 *      - vout: input value
 *
 * @param[in]           self            channel info
 * @param[out]          pTx             生成結果
 * @param[in]           Value           vinとなるamount
 * @param[in]           pTxid           vinとなるoutpointのtxid
 * @param[in]           Index           vinとなるoutpointのindex
 * @retval  true    成功
 * @note
 *  - 処理の都合上utl_tx_tの形を取るが、展開してはいけない
 *      - vin: pTxid:Index
 *      - vout: value, secret
 */
bool ln_wallet_create_toremote(
            const ln_self_t *self, btc_tx_t *pTx, uint64_t Value,
            const uint8_t *pTxid, int Index);


/** revoked HTLC Txから取り戻すトランザクション作成
 *
 * @param[in]           self            channel info
 *
 */
bool ln_revokedhtlc_create_spenttx(const ln_self_t *self, btc_tx_t *pTx, uint64_t Value,
                int WitIndex, const uint8_t *pTxid, int Index);


/** PreImageハッシュ計算
 *
 * @param[out]      pHash               計算結果(BTC_SZ_HASH256)
 * @param[in]       pPreImage           計算元(LN_SZ_PREIMAGE)
 */
void ln_preimage_hash_calc(uint8_t *pHash, const uint8_t *pPreImage);


/** channel_announcementデータ解析
 *
 * @param[out]  p_short_channel_id
 * @param[out]  pNodeId1
 * @param[out]  pNodeId2
 * @param[in]   pData
 * @param[in]   Len
 * @retval  true        解析成功
 */
bool ln_getids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len);


/** 最後に接続したアドレス保存
 *
 * @param[in,out]       self            channel info
 */
void ln_last_connected_addr_set(ln_self_t *self, const ln_node_addr_t *pAddr);


/********************************************************************
 * getter/setter
 ********************************************************************/

/** channel_id取得
 *
 * @param[in]           self            channel info
 * @return      channel_id
 */
const uint8_t *ln_channel_id(const ln_self_t *self);


uint64_t HIDDEN ln_short_channel_id_calc(uint32_t Height, uint32_t BIndex, uint32_t VIndex);


/** short_channel_id取得
 *
 * @param[in]           self            channel info
 * @return      short_channel_id
 */
uint64_t ln_short_channel_id(const ln_self_t *self);


/** short_channel_idクリア
 *
 * short_channel_idを0にする.
 *
 * @param[in,out]       self            channel info
 */
void ln_short_channel_id_clr(ln_self_t *self);


/** アプリ用パラメータポインタ取得
 *
 * @param[in,out]       self            channel info
 * @return      アプリ用パラメータ(非const)
 */
void *ln_get_param(ln_self_t *self);


/** get status
 *
 * @param[in]           self            channel info
 * @return  status
 */
ln_status_t ln_status_get(const ln_self_t *self);


/** is closing ?
 *
 * @param[in]           self            channel info
 * @retval  true    closing now
 */
bool ln_status_is_closing(const ln_self_t *self);


/** our_msat取得
 *
 * @param[in]           self            channel info
 * @return      自channelのmilli satoshi
 */
uint64_t ln_our_msat(const ln_self_t *self);


/** their_msat取得
 *
 * @param[in]           self            channel info
 * @return      他channelのmilli satoshi
 */
uint64_t ln_their_msat(const ln_self_t *self);


/** funding_txのTXID取得
 *
 * @param[in]           self            channel info
 * @return      funding_txのTXID
 */
const uint8_t *ln_funding_txid(const ln_self_t *self);


/** funding_txのTXINDEX取得
 *
 * @param[in]           self            channel info
 * @return      funding_txのTXINDEX
 */
uint32_t ln_funding_txindex(const ln_self_t *self);


const utl_buf_t *ln_funding_redeem(const ln_self_t *self);


/** minimum_depth
 *
 * @param[in]           self            channel info
 * @return      accept_channelで受信したminimum_depth
 */
uint32_t ln_minimum_depth(const ln_self_t *self);


/** funderかどうか
 *
 * @param[in]           self            channel info
 * @retval      true    funder
 * @retval      false   fundee
 */
bool ln_is_funder(const ln_self_t *self);


/** funding中かどうか
 *
 * @param[in]           self            channel info
 * @retval      true    fundingしている
 * @retval      false   fundingしていない(未funding or funding済み)
 */
bool ln_is_funding(const ln_self_t *self);


/** funding_tx
 *
 * @param[in]           self            channel info
 * @return      funding_tx
 */
const btc_tx_t *ln_funding_tx(const ln_self_t *self);


/** funding_txがマイニングされたblock hash
 *
 * @param[in]           self            channel info
 * @return      block hash
 */
const uint8_t *ln_funding_blockhash(const ln_self_t *self);


uint32_t ln_last_conf_get(const ln_self_t *self);


void ln_last_conf_set(ln_self_t *self, uint32_t Conf);


/** initial_routing_sync動作が必要かどうか
 *
 * @param[in]           self            channel info
 * @retval  true    必要:保持しているchannel情報を送信する
 */
bool ln_need_init_routing_sync(const ln_self_t *self);


/** announcement_signatures交換済みかどうか
 *
 * @param[in]           self            channel info
 * @retval      true    announcement_signatures交換済み
 * @retval      false   announcement_signatures未交換
 */
bool ln_is_announced(const ln_self_t *self);


/** estimatesmartfee --> feerate_per_kw
 *
 * @param[in]           feerate_kb  bitcoindから取得したfeerate/KB
 * @return          feerate_per_kw
 */
uint32_t ln_feerate_per_kw_calc(uint64_t feerate_kb);


/** feerate_per_kw --> fee
 *
 * @param[in]           vsize
 * @param[in]           feerate_per_kw
 * @return          feerate_per_byte
 */
uint64_t ln_calc_fee(uint32_t vsize, uint64_t feerate_kw);


/** feerate_per_kw取得
 *
 * @param[in]           self            channel info
 * @return      feerate_per_kw
 */
uint32_t ln_feerate_per_kw(const ln_self_t *self);


/** feerate_per_kw設定
 *
 * @param[in]           self            channel info
 * @param[in]           FeeratePerKw    設定値
 */
void ln_feerate_per_kw_set(ln_self_t *self, uint32_t FeeratePerKw);


/** funding_txの予想されるfee(+α)取得
 *
 * @param[in]   FeeratePerKw        feerate_per_kw(open_channelのパラメータと同じ)
 * @return  estimate fee[satoshis]
 * @note
 *      - 現在(2018/04/03)のptarmiganが生成するfunding_txは177byteで、それに+αしている
 */
uint64_t ln_estimate_fundingtx_fee(uint32_t FeeratePerKw);


/** 初期commit_tx FEE取得
 *
 * @param[in]   FeeratePerKw        feerate_per_kw(open_channelのパラメータと同じ)
 * @return      fee[satoshis]
 */
uint64_t ln_estimate_initcommittx_fee(uint32_t FeeratePerKw);


/** `shutdown` message sent
 *
 * @param[in]           self            channel info
 * @retval      true    `shutdown` has sent
 */
bool ln_is_shutdown_sent(const ln_self_t *self);


/** 初期closing_tx FEE取得
 *
 * @param[in]           self            channel info
 * @return      fee[satoshis]
 */
uint64_t ln_closing_signed_initfee(const ln_self_t *self);


/** commit_local取得
 *
 * @param[in]           self            channel info
 * @return      commit_local情報
 */
const ln_commit_data_t *ln_commit_local(const ln_self_t *self);


/** commit_remote取得
 *
 * @param[in]           self            channel info
 * @return      commit_remote情報
 */
const ln_commit_data_t *ln_commit_remote(const ln_self_t *self);


/** shutdown時のlocal scriptPubKey取得
 *
 * @param[in]           self            channel info
 * @return      local scriptPubKey
 */
const utl_buf_t *ln_shutdown_scriptpk_local(const ln_self_t *self);


/** shutdown時のremote scriptPubKey取得
 *
 * @param[in]           self            channel info
 * @return      remote scriptPubKey
 */
const utl_buf_t *ln_shutdown_scriptpk_remote(const ln_self_t *self);


/** add_htlc構造体取得
 *
 * @param[in]           self            channel info
 * @param[in]           htlc_idx        index値
 * @retval      非NULL  add_htlc構造体
 * @retval      NULL    index不正
 */
const ln_update_add_htlc_t *ln_update_add_htlc(const ln_self_t *self, uint16_t htlc_idx);


/** Offered HTLCがTimeoutしているかどうか
 *
 * @param[in]           self            channel info
 * @retval      true    Timeoutしている
 * @note
 *      - addhtlc == OFFERED
 *      - delhtlc == none
 *      - updsend == true
 *      - comsend, revrecv, comrecv, revsend == true
 *      - fin_delhtlc == none
 *      - cltv_expiry <= current blockcount
 */
bool ln_is_offered_htlc_timeout(const ln_self_t *self, uint16_t htlc_idx, uint32_t BlkCnt);


/** トランザクションがHTLC Success Txの場合、preimageを取得
 *
 * @param[in]   tx
 * @retval  非NULL      preimage
 * @retval  NULL        -
 *
 * @note
 *      - HTLC Success Tx時のUnlockになる
 *          - https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#received-htlc-outputs
 *          - https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#htlc-timeout-and-htlc-success-transactions
 *            -----------------------------------------------------
 *            0
 *            <remotehtlcsig>
 *            <localhtlcsig>
 *            <payment_preimage> ★
 *            -----------------------------------------------------
 *            # To remote node with revocation key
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
const utl_buf_t *ln_preimage_remote(const btc_tx_t *pTx);


/** revoked transaction closeされた後の残取り戻し数
 *
 * @param[in]           self            channel info
 * @return      残取り戻し数
 */
uint16_t ln_revoked_cnt(const ln_self_t *self);


/** revoked transaction closeされた後の残取り戻しチェック
 *
 * @param[in,out]       self            channel info
 * @retval      true        取り戻し完了
 */
bool ln_revoked_cnt_dec(ln_self_t *self);


/** revoked transaction closeされた後の取り戻し数
 *
 * @param[in]           self            channel info
 * @return      取り戻し数
 */
uint16_t ln_revoked_num(const ln_self_t *self);


/** revoked transaction closeされた後のfunding_tx confirmation数更新
 *
 * @param[in,out]       self            channel info
 * @param[in]           confm           confirmation数
 */
void ln_set_revoked_confm(ln_self_t *self, uint32_t confm);


/** ln_revoked_confm()で保存した値の取得
 *
 * @param[in]           self            channel info
 * @return      ln_revoked_confm()で保存したconfirmation数
 */
uint32_t ln_revoked_confm(const ln_self_t *self);


/** revoked vout
 * @param[in]           self            channel info
 * @return      revoked transaction後に監視するvoutスクリプト
 */
const utl_buf_t* ln_revoked_vout(const ln_self_t *self);


/** revoked witness script
 * @param[in]           self            channel info
 * @return      revoked transaction後に取り戻す際のunlocking witness script
 */
const utl_buf_t* ln_revoked_wit(const ln_self_t *self);


/** open_channelのchannel_flags.announce_channel
 *
 * @param[in]           self            channel info
 * @return      open_channelのchannel_flags.announce_channel
 * @note
 *      - This indicates whether the initiator of the funding flow
 *          wishes to advertise this channel publicly to the network
 *          as detailed within BOLT #7.
 */
bool ln_open_channel_announce(const ln_self_t *self);


/** 他ノードID取得
 *
 * @param[in]           self            channel info
 * @return      自channelの他node_id
 */
const uint8_t *ln_their_node_id(const ln_self_t *self);


/** cltv_expiry_delta取得
 *
 * @param[in]           self            channel info
 * @return      cltv_expiry_delta
 */
uint32_t ln_cltv_expily_delta(const ln_self_t *self);


/** 転送FEE計算
 *
 * @param[in]           self            channel info
 * @param[in]           AmountMsat      転送amount_msat
 * @return      転送FEE(msat)
 * @note
 *      - fee_prop_millionths is a proportion (ppm)
 */
uint64_t ln_forward_fee(const ln_self_t *self, uint64_t AmountMsat);


/** 最後に接続したIPアドレス
 *
 * @param[in]           self            channel info
 */
const ln_node_addr_t *ln_last_connected_addr(const ln_self_t *self);


/** 最後に発生したエラー番号
 *
 * @param[in]           self            channel info
 * @return      エラー番号(ln_err.h)
 */
int ln_err(const ln_self_t *self);


/** 最後に発生したエラー情報
 *
 * @param[in]           self            channel info
 * @return      エラー情報文字列
 */
const char *ln_errmsg(const ln_self_t *self);


/** [channel_update]direction取得
 *
 * @retval      0   node_1
 * @retval      1   node_2
 */
int ln_cnlupd_direction(const ln_msg_channel_update_t *pCnlUpd);


/** [channel_update]disableフラグ取得
 *
 * @retval      true    disableフラグが立っていない
 */
bool ln_cnlupd_enable(const ln_msg_channel_update_t *pCnlUpd);


/********************************************************************
 * NODE
 ********************************************************************/

/** ノードアドレス取得
 *
 * @return      ノードアドレス(非const)
 */
ln_node_addr_t *ln_node_addr(void);


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
 * @param[out]      pNodeAnnoBuf        取得したnode_announcement
 * @param[in]       pNodeId             検索するnode_id
 * @retval      true        検索成功
 */
bool ln_node_search_nodeanno(ln_msg_node_announcement_t *pNodeAnno, utl_buf_t *pNodeAnnoBuf, const uint8_t *pNodeId);


/** nodeが所有しているour_msatの合計
 *
 * @return  our_msatの合計[msatoshis]
 */
uint64_t ln_node_total_msat(void);


/********************************************************************
 * XXX:
 ********************************************************************/

/** スクリプト用鍵生成/更新
 *
 * @param[in,out]   pLocal
 * @param[in,out]   pRemote
 * @note
 *      - per-commit-secret/per-commit-basepointが変更された場合に呼び出す想定
 */
void HIDDEN ln_update_scriptkeys(ln_funding_local_data_t *pLocal, ln_funding_remote_data_t *pRemote);


/********************************************************************
 * デバッグ
 ********************************************************************/

void ln_debug_set(unsigned long debug);
unsigned long ln_debug_get(void);


#ifdef PTARM_USE_PRINTFUNC

/** [デバッグ用]鍵情報出力
 *
 * @param[in]   pLocal
 * @param[in]   pRemote
 */
void ln_print_keys(const ln_funding_local_data_t *pLocal, const ln_funding_remote_data_t *pRemote);
#else
#define ln_print_keys(...)      //nothing
#endif

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* LN_H__ */
