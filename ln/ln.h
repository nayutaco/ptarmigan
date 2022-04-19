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
/** @file   ln.h
 *  @brief  Lightning
 */
#ifndef LN_H__
#define LN_H__

#include <stdint.h>
#include <stdbool.h>
#include <sys/queue.h>

#include "utl_common.h"

#include "btc.h"
#include "btc_block.h"
#include "btc_crypto.h"
#include "btc_sig.h"
#include "btc_tx.h"
#include "btc_script.h"

#include "ln_err.h"
#include "ln_msg_establish.h"
#include "ln_msg_anno.h"
#include "ln_onion.h"
#include "ln_derkey.h"
#include "ln_derkey_ex.h"
#include "ln_node.h"
#include "ln_script.h"
#include "ln_update.h"
#include "ln_cb.h"
#include "ln_common.h"
#include "ln_funding_info.h"
#include "ln_commit_info.h"
#include "ln_update_info.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define LN_PORT_DEFAULT                 (9735)

#define LN_SZ_CHANNEL_ID                (32)        ///< (size) channel_id
#define LN_SZ_CHANNEL_ID_STR            (LN_SZ_CHANNEL_ID * 2)  ///< (size) channel_id
#define LN_SZ_SHORT_CHANNEL_ID          (8)         ///< (size) short_channel_id
#define LN_SZ_SHORT_CHANNEL_ID_STR      (127)       ///< (size) short_channel_id string
#define LN_SZ_ALIAS_STR                 (32)        ///< (size) node alias //XXX:
#define LN_SZ_PREIMAGE                  (32)        ///< (size) preimage
#define LN_SZ_ONION_ROUTE               (1366)      ///< (size) onion-routing-packet
#define LN_SZ_NOISE_HEADER              (sizeof(uint16_t) + 16)     ///< (size) noise packet header
#define LN_SZ_FUNDINGTX_VSIZE           (177)       ///< (size) funding_txのvsize(nested in BIP16 P2SH format)
#define LN_SZ_ERRMSG                    (256)       ///< (size) last error string


#define LN_ANNOSIGS_CONFIRM             (6)         ///< announcement_signaturesを送信するconfirmation
#define LN_FEERATE_PER_KW               (500)       ///< estimate feeできなかった場合のfeerate_per_kw
#define LN_FEERATE_PER_KW_MIN           (253)       ///< feerate_per_kwの下限
                                                    // https://github.com/ElementsProject/lightning/blob/86290b54d49d183e49f905be6a18bfc65612580e/lightningd/chaintopology.c#L298
#define LN_BLK_FEEESTIMATE              (6)         ///< estimatefeeのブロック数(2以上)
#define LN_MIN_FINAL_CLTV_EXPIRY        (9)         ///< min_final_cltv_expiryのデフォルト値
#define LN_INVOICE_EXPIRY               (3600)      ///< invoice expiryのデフォルト値
#define LN_INVOICE_EXPIRY_MIN           (60)        ///< invoice expiry minimum

#if defined(USE_BITCOIN)
// BOLT3: https://github.com/lightningnetwork/lightning-rfc/blob/8555709811e6b2326f80dc479021b161e850bf03/03-transactions.md#fee-calculation
#define LN_FEE_COMMIT_BASE_WEIGHT       (724ULL)    ///< commit_tx base weight for the fee calculation
#define LN_FEE_COMMIT_HTLC_WEIGHT       (172ULL)
#elif defined(USE_ELEMENTS)
// https://github.com/cdecker/lightning/blob/8aca09597ee26af75c0d3111aac2a98875ffabd7/common/initial_commit_tx.h#L44-L62
#define LN_FEE_COMMIT_BASE_WEIGHT       (1194ULL)   ///< commit_tx base weight for the fee calculation
#define LN_FEE_COMMIT_HTLC_WEIGHT       (312ULL)
#endif

// channel_update.channel_flags
#define LN_CNLUPD_CHFLAGS_DIRECTION     (0x01)      ///< b0: direction
#define LN_CNLUPD_CHFLAGS_DISABLE       (0x02)      ///< b1: disable

// ln_channel_t.shutdown_flag
#define LN_SHDN_FLAG_WAIT_SEND_SHDN     (0x01)      ///< waiting to send shutdown
#define LN_SHDN_FLAG_SEND_SHDN          (0x02)      ///< shutdown sent
#define LN_SHDN_FLAG_RECV_SHDN          (0x04)      ///< shutdown received
#define LN_SHDN_FLAG_WAIT_SEND_CLSN     (0x08)      ///< waiting to closing_signed
#define LN_SHDN_FLAG_SEND_CLSN          (0x10)      ///< closing_signed sent

// ln_close_force_t.p_tx, p_htlc_idxsのインデックス値
#define LN_CLOSE_IDX_COMMIT             (0)         ///< commit_tx
#define LN_CLOSE_IDX_TO_LOCAL           (1)         ///< to_local tx
#define LN_CLOSE_IDX_TO_REMOTE          (2)         ///< to_remote tx
#define LN_CLOSE_IDX_HTLC               (3)         ///< HTLC tx
#define LN_CLOSE_IDX_NONE               UINT16_MAX

// channel.anno_flag
#define LN_ANNO_FLAG_END                (0x80)      ///< 1:announcement_signatures交換済み

// revoked transaction closeされたときの pChannel->p_revoked_vout, p_revoked_witのインデックス値
#define LN_RCLOSE_IDX_TO_LOCAL           (0)         ///< to_local
#define LN_RCLOSE_IDX_TO_REMOTE          (1)         ///< to_remote
#define LN_RCLOSE_IDX_HTLC               (2)         ///< HTLC

//requires / supports feature
#define LN_INIT_LF_OPT_DATALOSS_REQ     (1 << 0)    ///< option_data_loss_protect
#define LN_INIT_LF_OPT_DATALOSS         (1 << 1)    ///< option_data_loss_protect
#define LN_INIT_LF_ROUTE_SYNC_REQ       (1 << 2)    ///< [NO]initial_routing_sync
#define LN_INIT_LF_ROUTE_SYNC           (1 << 3)    ///< initial_routing_sync
#define LN_INIT_LF_OPT_UPF_SHDN_REQ     (1 << 4)    ///< option_upfront_shutdown_script
#define LN_INIT_LF_OPT_UPF_SHDN         (1 << 5)    ///< option_upfront_shutdown_script
#define LN_INIT_LF_OPT_GSP_QUERY_REQ    (1 << 6)    ///< gossip_queries
#define LN_INIT_LF_OPT_GSP_QUERY        (1 << 7)    ///< gossip_queries
#define LN_INIT_LF_OPT_VAR_ONION_REQ    (1 << 8)    ///< var_onion_optin
#define LN_INIT_LF_OPT_VAR_ONION        (1 << 9)    ///< var_onion_optin
#define LN_INIT_LF_OPT_GQUERY_EX_REQ    (1 << 10)   ///< gossip_queries_ex
#define LN_INIT_LF_OPT_GQUERY_EX        (1 << 11)   ///< gossip_queries_ex
#define LN_INIT_LF_OPT_STATIC_RKEY_REQ  (1 << 12)   ///< option_static_remotekey
#define LN_INIT_LF_OPT_STATIC_RKEY      (1 << 13)   ///< option_static_remotekey
#define LN_INIT_LF_OPT_15_14_REQ        (1 << 14)   ///< RFU bit 15/14

#define LN_INIT_LF_OPT_GSP_QUERIES      (LN_INIT_LF_OPT_GSP_QUERY_REQ | LN_INIT_LF_OPT_GSP_QUERY)
#define LN_INIT_LF_OPT_STATIC_RKEYS     (LN_INIT_LF_OPT_STATIC_RKEY_REQ | LN_INIT_LF_OPT_STATIC_RKEY)

//XXX:
#define LN_MAX_ACCEPTED_HTLCS_MAX       (483)
#define LN_NUM_PONG_BYTES_MAX           (65532 - 1)


/**************************************************************************
 * macro functions
 **************************************************************************/

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

#define M_DB_CHANNEL_SAVE(pChannel) { bool ret = ln_db_channel_save(pChannel); LOGD("ln_db_channel_save()=%d\n", ret); if (!ret) { abort();} }
#define M_DB_SECRET_SAVE(pChannel)  { bool ret = ln_db_secret_save(pChannel); LOGD("ln_db_secret_save()=%d\n", ret); if (!ret) { abort();} }

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
#else
#define LN_DBG_COMMIT_NUM_PRINT(pChannel)   //none
#endif


/********************************************************************
 * typedefs
 ********************************************************************/

//forward definition
struct ln_channel_t;
typedef struct ln_channel_t ln_channel_t;


/** @enum   ln_status_t
 *  @brief  ln_channel_t.status
 */
typedef enum {
    LN_STATUS_NONE = 0,
    LN_STATUS_ESTABLISH,                    ///< establish
    LN_STATUS_NORMAL_OPE,                   ///< normal operation
    LN_STATUS_CLOSE_WAIT,                   ///< `closing_signed`s were received and sent with the same fee
    LN_STATUS_CLOSE_MUTUAL,                 ///< mutual close
    LN_STATUS_CLOSE_UNI_LOCAL,              ///< unilateral close (from local)
    LN_STATUS_CLOSE_UNI_REMOTE_LAST,        ///< unilateral close (from remote last commit tx)
    LN_STATUS_CLOSE_UNI_REMOTE_SECOND_LAST, ///< unilateral close (from remote second last commit tx)
    LN_STATUS_CLOSE_REVOKED,                ///< revoked transaction close (from remote)
    LN_STATUS_CLOSE_UNKNOWN,                ///< unknown close (trouble)
    LN_STATUS_CLOSED                        ///< closed
} ln_status_t;


/**************************************************************************
 * typedefs : HTLC
 **************************************************************************/

/** @struct ln_establish_param_t
 *  @brief  Establish関連のパラメータ
 *  @note
 *      - #ln_establish_alloc()で初期化する
 */
typedef struct {
    uint64_t    dust_limit_sat;                     ///< 8 : dust-limit-satoshis
    uint64_t    max_htlc_value_in_flight_msat;      ///< 8 : max-htlc-value-in-flight-msat
    uint64_t    channel_reserve_sat;                ///< 8 : channel-reserve-satoshis
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc-minimum-msat
    uint16_t    to_self_delay;                      ///< 2 : to_self_delay
    uint16_t    max_accepted_htlcs;                 ///< 2 : max-accepted-htlcs
    uint32_t    min_depth;                          ///< 4 : minimum-depth(acceptのみ)
} ln_establish_param_t;


/** @struct ln_establish_t
 *  @brief  [Establish]ワーク領域
 */
typedef struct {
    ln_establish_param_t        param;              ///< channel establish parameter
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
 *      - p_tx, p_htlc_idxsの添字
 *          - commit_tx: LN_CLOSE_IDX_COMMIT
 *          - spending from to_local output tx: LN_CLOSE_IDX_TO_LOCAL
 *          - spending from to_remote output tx: LN_CLOSE_IDX_TO_REMOTE
 *          - HTLC_tx: LN_CLOSE_IDX_HTLC～
 * 
 *      - tx_buf.buf = btc_tx_t pointer array(len = tx_buf.size / sizeof(btc_tx_t*)
 *          - spending from HTLC_tx tx
 */
typedef struct {
    int             num;                            ///< p_txのtransaction数
    btc_tx_t        *p_tx;                          ///< トランザクション
                                                    ///<    添字:[0]commit_tx [1]to_local [2]to_remote [3-]HTLC
    uint16_t        *p_htlc_idxs;                   ///< pChannel->update_info.htlcs[]のidx
                                                    ///<    添字:[3]以上で有効
    utl_buf_t       tx_buf;                         ///< HTLC Timeout/Successから取り戻すTX
} ln_close_force_t;

/// @}


/**************************************************************************
 * typedefs : Announcement
 **************************************************************************/

/// @addtogroup announcement
/// @{

/** @struct     ln_anno_param_t
 *  @brief      announcement parameter
 *  @note
 *      - lnapp has default parameter(initialize on node startup)
 */
typedef struct {
    //channel_update
    uint16_t    cltv_expiry_delta;                  ///< 2 : cltv_expiry_delta
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc_minimum_msat
    uint32_t    fee_base_msat;                      ///< 4 : fee_base_msat
    uint32_t    fee_prop_millionths;                ///< 4 : fee_proportional_millionths
} ln_anno_param_t;


/** @struct     ln_anno_encoded_ids_t
 *  @brief      encided_short_ids list
 */
typedef struct ln_anno_encoded_ids_t {
    SLIST_ENTRY(ln_anno_encoded_ids_t) list;
    utl_buf_t               encoded_short_ids;
} ln_anno_encoded_ids_t;

SLIST_HEAD(ln_anno_encoded_ids_head_t, ln_anno_encoded_ids_t);


/** @typedef    ln_gossip_query_t
 *  @brief
 */
typedef struct {
    struct {
        //for sending query_channel_range
        uint32_t        first_blocknum;

        /**
         * 0の場合、query_channel_rangeの送信可
         * BOLT#07:
         *  MUST NOT send this if it has sent a previous query_channel_range to this peer and not received all reply_channel_range replies.
         */
        uint32_t        rest_blocks;

        //for sending query_short_channel_ids
        //  1. 受信したreply_channel_rangeのencoded_short_idsを展開する
        //  2. 展開したencoded_short_idsを、1回に受信できるサイズにしてsend_encoded_idsに積む
        struct ln_anno_encoded_ids_head_t   send_encoded_ids;

        /**
         * for sending query_short_channel_ids
         * BOLT#07:
         *  MUST NOT send query_short_channel_ids if it has sent a previous query_short_channel_ids to this peer and not received reply_short_channel_ids_end.
         */
        bool            wait_query_short_channel_ids_end;   //true:reply_short_channel_ids_end待ち
                                                            // == can't send query_short_channel_ids
    } request;

    //for receiving query_channel_range
    //  query_channel_rangeを1回受信すると、その範囲のreply_channel_rangeを返す。
    //  reply_channel_rangeは複数回に分ける可能性がある(サイズ次第)。
    //  ここでは、query_channel_range受信時にp_reply_rangeを全部準備する想定。
    //  sent_reply_range_numは送信ごとにインクリメントし、reply_range_numと等しくなれば全送信完了。
    //
    // uint32_t        sent_reply_range_num;   ///< sent reply_channel_range count
    // uint32_t        reply_range_num;        ///< p_reply_range count
    // struct {
    //     uint32_t        id_num;             ///< p_encoded_ids size
    //     uint8_t         *p_encoded_ids;     ///< encoded_short_ids
    // } *p_reply_range;

    //for receiving query_short_channel_ids
    //  query_short_channel_idsを1回受信すると、その分のannouncementを送信し、
    //      最後にreply_short_channel_idsを送信する。
    //      可能性として、query_short_channel_idsで要求された個数よりも
    //          現状の数が少ないことがありうる(closeされた場合など)。
    //      その場合はsent_reply_anno_numを進めて続けるので、どちらかといえばindexか？
    // uint32_t        sent_reply_anno_num;    ///< sent announcement count
    // uint32_t        reply_anno_num;         ///< p_reply_short_ids count
    // uint64_t        *p_reply_short_ids;     ///< decoded short_channel_ids

} ln_gossip_query_t;

/// @}


/**************************************************************************
 * typedefs : 管理データ
 **************************************************************************/

/// @addtogroup channel_mng
/// @{


/** @struct     ln_channel_t
 *  @brief      チャネル情報
 */
struct ln_channel_t {
    //connect
    uint8_t                     peer_node_id[BTC_SZ_PUBKEY];    ///< [CONN_01]接続先ノード
    ln_node_addr_t              last_connected_addr;            ///< [CONN_02]最後に接続したIP address
    ln_status_t                 status;                         ///< [CONN_03]状態

    //key storage
    ln_derkey_local_keys_t      keys_local;                     ///< [KEYS_01]local keys
    ln_derkey_remote_keys_t     keys_remote;                    ///< [KEYS_02]remote keys
    bool                        keys_static_remotekey;          ///< [KEYS_03]static_remotekey

    //funding
    ln_funding_info_t           funding_info;                   ///< [FUND_01]funding info
    ln_establish_t              establish;                      ///< [FUND_02]Establishワーク領域
    uint8_t                     funding_blockhash[BTC_SZ_HASH256];      ///< [FUNDSPV_01]funding_txがマイニングされたblock hash
    uint32_t                    funding_last_confirm;                   ///< [FUNDSPV_02]last unspent funding_tx confirmation
                                                                        //      update: funding_unspent()

    //msg:announce
    uint8_t                     anno_flag;                      ///< [ANNO_01]announcement_signaturesなど
    ln_anno_param_t             anno_param;                     ///< [ANNO_02]announcementパラメータ
    utl_buf_t                   cnl_anno;                       ///< [ANNO_03]自channel_announcement

    //msg:establish
    uint16_t                    init_flag;                      ///< [INIT_01]initフラグ(M_INIT_FLAG_xxx)
    uint16_t                    lfeature_local;                 ///< [INIT_02]initで送信したfeature
    uint16_t                    lfeature_remote;                ///< [INIT_03]initで取得したfeature
    uint64_t                    reest_next_local_commit_num;    ///< [INIT_04]channel_reestablish.next_local_commitment_number
    uint64_t                    reest_next_remote_revoke_num;   ///< [INIT_05]channel_reestablish.next_remote_revocation_number

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
    ln_commit_tx_output_type_t  *p_revoked_type;                ///< [REVK_03]p_revoked_vout/p_revoked_witに対応するtype
    utl_buf_t                   revoked_sec;                    ///< [REVK_04]revoked transaction close時のremote per_commit_sec
    uint16_t                    revoked_num;                    ///< [REVK_05]revoked_cnt+1([0]にto_local系を入れるため)
    uint16_t                    revoked_cnt;                    ///< [REVK_06]取り戻す必要があるvout数
    uint32_t                    revoked_chk;                    ///< [REVK_07]最後にチェックしたfunding_txのconfirmation数

    //msg:normal operation
    uint8_t                     channel_id[LN_SZ_CHANNEL_ID];   ///< [NORM_01]channel_id
    uint64_t                    short_channel_id;               ///< [NORM_02]short_channel_id
    ln_update_info_t            update_info;                    ///< [NORM_03]

    //commitment transaction(local/remote)
    ln_commit_info_t            commit_info_local;              ///< [COMM_01]local commit_tx用
    ln_commit_info_t            commit_info_remote;             ///< [COMM_02]remote commit_tx用
    uint8_t                     prev_remote_commit_txid[BTC_SZ_TXID];
                                                                ///< [COMM_03]previous remote commit tx's txid (for second last remote unilateral close)

    //gossip_queries
    ln_gossip_query_t           gossip_query;                   ///< [GQRY_01]gossip_queries

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
 * @param[in,out]       pChannel        channel info
 * @param[in]           pAnnoParam      announcementパラメータ
 * @param[in]           pPeerNodeId
 * @param[in]           pFunc           通知用コールバック関数
 * @param[in]           pParam
 * @retval      true    成功
 */
bool ln_init(
    ln_channel_t *pChannel, const ln_anno_param_t *pAnnoParam,
    const uint8_t *pPeerNodeId, ln_callback_t pFunc, void *pParam);


/** 終了
 *
 * @param[in,out]       pChannel        channel info
 */
void ln_term(ln_channel_t *pChannel);


/** load status from DB
 *
 * @param[in,out]       pChannel        channel info
 * @return      load result
 */
bool ln_status_load(ln_channel_t *pChannel);


/** get status string
 *
 * @param[in]           pChannel        channel info
 * @return  status
 */
const char *ln_status_string(const ln_channel_t *pChannel);


/** Genesis Block Hash設定
 *
 * @param[in]       pHash               Genesis Block Hash
 * @return          blockchain type
 * @attention
 *      - JSON-RPCのgetblockhashで取得した値はエンディアンが逆転しているため、
 *          設定する場合にはエンディアンを逆にして pHashに与えること。
 *          https://github.com/lightningnetwork/lightning-rfc/issues/237
 */
btc_block_chain_t ln_genesishash_set(const uint8_t *pHash);


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
 * @param[in,out]       pChannel        channel info
 */
void ln_peer_set_node_id(ln_channel_t *pChannel, const uint8_t *pNodeId);


/** Channel Establish設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           pParam          Establishパラメータ
 * @retval      true    成功
 * @note
 *      - pEstablishは接続完了まで保持すること
 */
bool ln_establish_alloc(ln_channel_t *pChannel, const ln_establish_param_t *pParam);


/** #ln_establish_alloc()で確保したメモリを解放する
 *
 * @param[in,out]       pChannel        channel info
 * @note
 *      - lnapp.cでfunding済みだった場合に呼ばれる想定
 */
void ln_establish_free(ln_channel_t *pChannel);


/** short_channel_id情報設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           Height          funding_txが入ったブロック height
 * @param[in]           Index           funding_txのTXIDが入っているindex
 * @note
 *  - save DB if pChannel->short_channel_id == 0
 */
void ln_short_channel_id_set_param(ln_channel_t *pChannel, uint32_t Height, uint32_t Index);


/** short_channel_id情報設定
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           pBlockHash      funding_txがマイニングされたblock hash
 */
void ln_funding_blockhash_set(ln_channel_t *pChannel, const uint8_t *pBlockHash);


/** short_channel_id情報取得
 *
 * @param[out]          pHeight     funding_txが入ったブロック height
 * @param[out]          pBIndex     funding_txのTXIDが入っているindex
 * @param[out]          pVIndex     funding_txとして使用するvout index
 * @param[in]           ShortChannelId  short_channel_id
 */
void ln_short_channel_id_get_param(uint32_t *pHeight, uint32_t *pBIndex, uint32_t *pVIndex, uint64_t ShortChannelId);


/** get BOLT short_channel_id string
 *
 * @param[out]  pStr            return value(length > LN_SZ_SHORT_CHANNEL_ID_STR)
 * @param[in]   ShortChannelId  short_channel_id
 */
void ln_short_channel_id_string(char *pStr, uint64_t ShortChannelId);


/** shutdown時の出力先設定(address)
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           pScriptPk       shutdown時の送金先ScriptPubKey
 */
void ln_shutdown_set_vout_addr(ln_channel_t *pChannel, const utl_buf_t *pScriptPk);


/** Lightningメッセージ受信処理
 *
 * @param[in,out]       pChannel    channel info
 * @param[in]           pData       受信データ
 * @param[in]           Len         pData長
 * @retval      true    解析成功
 */
bool ln_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);


/** 受信アイドル処理
 * Normal Operationの処理を進める
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           FeeratePerKw    latest feerate_per_kw
 */
void ln_idle_proc(ln_channel_t *pChannel, uint32_t FeeratePerKw);


void ln_idle_proc_inactive(ln_channel_t *pChannel);


/** origin/final nodeアイドル処理
 * Normal Operationの処理を進める
 *
 * @param[in,out]       pChannel        channel info
 */
void ln_idle_proc_origin(ln_channel_t *pChannel);


/** 接続直後のfunding_locked必要性チェック
 *
 * @param[in]           pChannel        channel info
 * @retval  true    funding_lockedの送信必要あり
 */
bool ln_funding_locked_needs(const ln_channel_t *pChannel);


//XXX:
void ln_callback(ln_channel_t *pChannel, ln_cb_type_t Req, void *pParam);
bool ln_check_channel_id(const uint8_t *recv_id, const uint8_t *mine_id);
void ln_dbg_commitnum(const ln_channel_t *pChannel);
btc_script_pubkey_order_t ln_node_id_order(const ln_channel_t *pChannel, const uint8_t *pNodeId);
uint8_t ln_order_to_dir(btc_script_pubkey_order_t Order);


/** revoked transaction close用のスクリプトバッファ確保
 *
 */
void HIDDEN ln_revoked_buf_alloc(ln_channel_t *pChannel);


/** revoked transaction close用のスクリプトバッファ解放
 *
 */
void HIDDEN ln_revoked_buf_free(ln_channel_t *pChannel);


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
 * @param[in]           pChannel    channel info
 * @param[out]          pCnlUpd     検索したchannel_updateパケット
 * @param[out]          pMsg        (非NULL)pCnlUpdデコード結果
 * @retval      true    成功
 */
bool ln_channel_update_get_peer(const ln_channel_t *pChannel, utl_buf_t *pCnlUpd, ln_msg_channel_update_t *pMsg);


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
 * @param[in,out]       pChannel    channel info
 * @param[in]           Fee         FEE
 */
void ln_shutdown_update_fee(ln_channel_t *pChannel, uint64_t Fee);


/** close中状態に遷移させる
 *
 * @param[in,out]       pChannel    channel info
 */
void ln_close_change_stat(ln_channel_t *pChannel, const btc_tx_t *pCloseTx, void *pDbParam);


/** local unilateral closeトランザクション作成
 *
 * @param[in,out]       pChannel    channel info
 * @param[out]          pClose      生成したトランザクション
 * @retval      true    成功
 * @note
 *      - pCloseは @ln_close_free_forcetx()で解放すること
 */
bool ln_close_create_unilateral_tx(ln_channel_t *pChannel, ln_close_force_t *pClose);


/** 相手からcloseされたcommit_txを復元
 *
 * @param[in,out]       pChannel    channel info
 * @param[out]          pClose      生成したトランザクション
 * @retval      true    成功
 * @note
 *      - pCloseは @ln_close_free_forcetx()で解放すること
 */
bool ln_close_create_tx(ln_channel_t *pChannel, ln_close_force_t *pClose);


/** ln_close_force_tのメモリ解放
 *
 * @param[in,out]       pClose      ln_close_create_unilateral_tx()やln_create_closed_tx()で生成したデータ
 */
void ln_close_free_forcetx(ln_close_force_t *pClose);


/** revoked transaction close(ugly way)の対処
 *
 * @param[in,out]       pChannel    channel info
 * @param[in]           pRevokedTx  revoked transaction
 * @param[in,out]       pDbParam    DBパラメータ
 * @retval      true    成功
 * @note
 *      - pChannel->vout にto_localのscriptPubKeyを設定する(HTLC Timeout/Successの取り戻しにも使用する)
 *      - pChannel->wit にto_localのwitnessProgramを設定する
 */
bool ln_close_remote_revoked(ln_channel_t *pChannel, const btc_tx_t *pRevokedTx, void *pDbParam);


/********************************************************************
 * others
 ********************************************************************/

/** revoked HTLC Txから取り戻すトランザクション作成
 *
 * @param[in]           pChannel        channel info
 *
 */
bool ln_revokedhtlc_create_spenttx(const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value,
                int WitIndex, const uint8_t *pTxid, int Index);


/** Preimageハッシュ計算
 *
 * @param[out]      pHash               計算結果(BTC_SZ_HASH256)
 * @param[in]       pPreimage           計算元(LN_SZ_PREIMAGE)
 */
void ln_payment_hash_calc(uint8_t *pHash, const uint8_t *pPreimage);


/** channel_announcementデータ解析
 *
 * @param[out]  p_short_channel_id
 * @param[out]  pNodeId1
 * @param[out]  pNodeId2
 * @param[in]   pData
 * @param[in]   Len
 * @retval  true        解析成功
 */
bool ln_get_ids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len);


/** 最後に接続したアドレス保存
 *
 * @param[in,out]       pChannel        channel info
 */
void ln_last_connected_addr_set(ln_channel_t *pChannel, const ln_node_addr_t *pAddr);


/********************************************************************
 * getter/setter
 ********************************************************************/

/** channel_id取得
 *
 * @param[in]           pChannel        channel info
 * @return      channel_id
 */
const uint8_t *ln_channel_id(const ln_channel_t *pChannel);


uint64_t HIDDEN ln_short_channel_id_calc(uint32_t Height, uint32_t BIndex, uint32_t VIndex);


/** short_channel_id取得
 *
 * @param[in]           pChannel        channel info
 * @return      short_channel_id
 */
uint64_t ln_short_channel_id(const ln_channel_t *pChannel);


/** short_channel_idクリア
 *
 * short_channel_idを0にする.
 *
 * @param[in,out]       pChannel        channel info
 */
void ln_short_channel_id_clr(ln_channel_t *pChannel);


/** アプリ用パラメータポインタ取得
 *
 * @param[in,out]       pChannel        channel info
 * @return      アプリ用パラメータ(非const)
 */
void *ln_get_param(ln_channel_t *pChannel);


/** set status
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           status          new status
 * @return  true:success
 */
bool ln_status_set(ln_channel_t *pChannel, ln_status_t status);


/** get status
 *
 * @param[in]           pChannel        channel info
 * @return  status
 */
ln_status_t ln_status_get(const ln_channel_t *pChannel);


/** is closing ?
 *
 * @param[in]           pChannel        channel info
 * @retval  true    closing now
 */
bool ln_status_is_closing(const ln_channel_t *pChannel);


/** is closed ?
 *
 * @param[in]           pChannel        channel info
 * @retval  true    funding_tx is spent
 */
bool ln_status_is_closed(const ln_channel_t *pChannel);


/** get local_msat
 *
 * @param[in]           pChannel        channel info
 * @return      local m-satoshi
 */
uint64_t ln_local_msat(const ln_channel_t *pChannel);


/** get remote_msat
 *
 * @param[in]           pChannel        channel info
 * @return      remote m-satoshi
 */
uint64_t ln_remote_msat(const ln_channel_t *pChannel);


/** get payable local msat
 *
 * (local msat) - (remote channel_reserve_sat)
 *
 * @param[in]           pChannel        channel info
 * @return      local payable m-satoshi
 */
uint64_t ln_local_payable_msat(const ln_channel_t *pChannel);


/** get payable remote msat
 *
 * (remote msat) - (local channel_reserve_sat)
 *
 * @param[in]           pChannel        channel info
 * @return      remote payable m-satoshi
 */
uint64_t ln_remote_payable_msat(const ln_channel_t *pChannel);


/** funding_txがマイニングされたblock hash
 *
 * @param[in]           pChannel        channel info
 * @return      block hash
 */
const uint8_t *ln_funding_blockhash(const ln_channel_t *pChannel);


uint32_t ln_funding_last_confirm_get(const ln_channel_t *pChannel);


void ln_funding_last_confirm_set(ln_channel_t *pChannel, uint32_t Conf);


bool ln_announcement_is_gossip_query(const ln_channel_t *pChannel);


/** initial_routing_sync動作が必要かどうか
 *
 * @param[in]           pChannel        channel info
 * @retval  true    必要:保持しているchannel情報を送信する
 */
bool ln_need_init_routing_sync(const ln_channel_t *pChannel);


/** announcement_signatures交換済みかどうか
 *
 * @param[in]           pChannel        channel info
 * @retval      true    announcement_signatures交換済み
 * @retval      false   announcement_signatures未交換
 */
bool ln_is_announced(const ln_channel_t *pChannel);


/** get feerate_per_kw limit
 * 
 */
void ln_feerate_limit_get(uint32_t *pMin, uint32_t *pMax, uint32_t feerate_per_kw);


/** set feerate_per_kw limit percent
 * 
 */
void ln_feerate_limit_set(uint16_t Min, uint16_t Max);


/** estimatesmartfee --> feerate_per_kw
 *
 * @param[in]           feerate_kb  bitcoindから取得したfeerate/KB
 * @return          feerate_per_kw
 * @note
 *      - #LN_FEERATE_PER_KW_MIN未満になる場合、#LN_FEERATE_PER_KW_MINを返す
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
 * @param[in]           pChannel        channel info
 * @return      feerate_per_kw
 */
uint32_t ln_feerate_per_kw(const ln_channel_t *pChannel);


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
 * @param[in]           pChannel        channel info
 * @retval      true    `shutdown` has sent
 */
bool ln_is_shutdown_sent(const ln_channel_t *pChannel);


/** 初期closing_tx FEE取得
 *
 * @param[in]           pChannel        channel info
 * @return      fee[satoshis]
 */
uint64_t ln_closing_signed_initfee(const ln_channel_t *pChannel);


/** commit_info_local取得
 *
 * @param[in]           pChannel        channel info
 * @return      commit_info_local情報
 */
const ln_commit_info_t *ln_commit_info_local(const ln_channel_t *pChannel);


/** commit_info_remote取得
 *
 * @param[in]           pChannel        channel info
 * @return      commit_info_remote情報
 */
const ln_commit_info_t *ln_commit_info_remote(const ln_channel_t *pChannel);


/** shutdown時のlocal scriptPubKey取得
 *
 * @param[in]           pChannel        channel info
 * @return      local scriptPubKey
 */
const utl_buf_t *ln_shutdown_scriptpk_local(const ln_channel_t *pChannel);


/** shutdown時のremote scriptPubKey取得
 *
 * @param[in]           pChannel        channel info
 * @return      remote scriptPubKey
 */
const utl_buf_t *ln_shutdown_scriptpk_remote(const ln_channel_t *pChannel);


/** update構造体取得
 *
 * @param[in]           pChannel        channel info
 * @param[in]           UpdateIdx       index of the updates
 * @retval      非NULL  update構造体
 * @retval      NULL    index不正
 */
const ln_update_t *ln_update(const ln_channel_t *pChannel, uint16_t UpdateIdx);


/** htlc構造体取得
 *
 * @param[in]           pChannel        channel info
 * @param[in]           HtlcIdx         index of the htlcs
 * @retval      非NULL  htlc構造体
 * @retval      NULL    index不正
 */
const ln_htlc_t *ln_htlc(const ln_channel_t *pChannel, uint16_t HtlcIdx);


/** Offered HTLCがTimeoutしているかどうか
 *
 * @param[in]           pChannel        channel info
 * @retval      true    Timeoutしている
 */
bool ln_is_offered_htlc_timeout(const ln_channel_t *pChannel, uint16_t UpdateIdx, uint32_t BlockCount);


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
 * @param[in]           pChannel        channel info
 * @return      残取り戻し数
 */
uint16_t ln_revoked_cnt(const ln_channel_t *pChannel);


/** revoked transaction closeされた後の残取り戻しチェック
 *
 * @param[in,out]       pChannel        channel info
 * @retval      true        取り戻し完了
 */
bool ln_revoked_cnt_dec(ln_channel_t *pChannel);


/** revoked transaction closeされた後の取り戻し数
 *
 * @param[in]           pChannel        channel info
 * @return      取り戻し数
 */
uint16_t ln_revoked_num(const ln_channel_t *pChannel);


/** revoked transaction closeされた後のfunding_tx confirmation数更新
 *
 * @param[in,out]       pChannel        channel info
 * @param[in]           confm           confirmation数
 */
void ln_set_revoked_confm(ln_channel_t *pChannel, uint32_t confm);


/** ln_revoked_confm()で保存した値の取得
 *
 * @param[in]           pChannel        channel info
 * @return      ln_revoked_confm()で保存したconfirmation数
 */
uint32_t ln_revoked_confm(const ln_channel_t *pChannel);


/** revoked vout
 * @param[in]           pChannel        channel info
 * @return      revoked transaction後に監視するvoutスクリプト
 */
const utl_buf_t* ln_revoked_vout(const ln_channel_t *pChannel);


/** revoked witness script
 * @param[in]           pChannel        channel info
 * @return      revoked transaction後に取り戻す際のunlocking witness script
 */
const utl_buf_t* ln_revoked_wit(const ln_channel_t *pChannel);


/** open_channelのchannel_flags.announce_channel
 *
 * @param[in]           pChannel        channel info
 * @return      open_channelのchannel_flags.announce_channel
 * @note
 *      - This indicates whether the initiator of the funding flow
 *          wishes to advertise this channel publicly to the network
 *          as detailed within BOLT #7.
 */
bool ln_open_channel_announce(const ln_channel_t *pChannel);


/** 他ノードID取得
 *
 * @param[in]           pChannel        channel info
 * @return      自channelの他node_id
 */
const uint8_t *ln_remote_node_id(const ln_channel_t *pChannel);


/** 最後に接続したIPアドレス
 *
 * @param[in]           pChannel        channel info
 */
const ln_node_addr_t *ln_last_connected_addr(const ln_channel_t *pChannel);


/** 最後に発生したエラー番号
 *
 * @param[in]           pChannel        channel info
 * @return      エラー番号(ln_err.h)
 */
int ln_err(const ln_channel_t *pChannel);


/** 最後に発生したエラー情報
 *
 * @param[in]           pChannel        channel info
 * @return      エラー情報文字列
 */
const char *ln_errmsg(const ln_channel_t *pChannel);


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

/** get node address
 *
 * @return      node address info
 */
const ln_node_addr_t *ln_node_addr(void);


/** get node alias
 *
 */
const char *ln_node_alias(void);


const uint8_t *ln_node_get_id(void);

/** initialize node
 *
 * @param[in]   pNode       initialize data
 *
 * @note
 *      - pNode->keys not used
 */
bool ln_node_init(const ln_node_t *pNode);


/** ノード情報終了
 */
void ln_node_term(void);


/** is private node
 *
 */
bool ln_node_is_private(void);



/** channel情報検索(node_idから)
 *
 *      pChannel DBから、channelの相手になっているpeerのnode_idが一致するchannelを検索する。
 *      一致した場合、pChannelにDB保存しているデータを返す。
 *
 * @param[out]      pChannel            検索成功時、pChannelが非NULLであればコピーする
 * @param[in]       pNodeId             検索する相手チャネルnode_id
 * @retval      true        検索成功
 */
bool ln_node_search_channel(ln_channel_t *pChannel, const uint8_t *pNodeId);


/** node_announcement検索(node_idから)
 *
 * @param[out]      pNodeAnno           取得したnode_announcement
 * @param[out]      pNodeAnnoBuf        取得したnode_announcement
 * @param[in]       pNodeId             検索するnode_id
 * @retval      true        検索成功
 */
bool ln_node_search_nodeanno(ln_msg_node_announcement_t *pNodeAnno, utl_buf_t *pNodeAnnoBuf, const uint8_t *pNodeId);


/** nodeが所有しているlocal_msatの合計
 *
 * @return  local_msatの合計[msatoshis]
 */
uint64_t ln_node_total_msat(void);


/********************************************************************
 * XXX:
 ********************************************************************/

//XXX: depends on `ln_channel_t`
bool ln_wallet_create_to_local_2(
    const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value, uint32_t ToSelfDelay,
    const utl_buf_t *pWitScript, const uint8_t *pTxid, int Index, bool bRevoked);


//XXX: depends on `ln_channel_t`
bool ln_wallet_create_to_remote_2(
    const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value, const uint8_t *pTxid, int Index);


/********************************************************************
 * デバッグ
 ********************************************************************/

void ln_debug_set(unsigned long debug);
unsigned long ln_debug_get(void);


#ifdef PTARM_USE_PRINTFUNC
/** [デバッグ用]鍵情報出力
 *
 */
void ln_print_keys(const ln_channel_t *pChannel);


void ln_print_keys_2(
    const ln_funding_info_t *pFundingInfo, const ln_derkey_local_keys_t *pKeysLocal,
    const ln_derkey_remote_keys_t *pKeysRemote);
#else
#define ln_print_keys(...)      //nothing
#define ln_print_keys_2(...)    //nothing
#endif


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* LN_H__ */
