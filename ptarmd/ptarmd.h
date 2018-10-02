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
/** @file   ptarmd.h
 *  @brief  ptarmd daemon header
 */
#ifndef PTARMD_H__
#define PTARMD_H__

#include <stdint.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif


#include "utl_misc.h"
#define LOG_TAG "APP"
#include "utl_log.h"
#include "utl_dbg.h"
#include "ln.h"


/********************************************************************
 * macros
 ********************************************************************/

#define SZ_RPC_USER                 (64)        ///< RPCUSER
#define SZ_RPC_PASSWD               (64)        ///< RPCPASSWORD
#define SZ_RPC_URL                  (256)       ///< URL

#define SZ_IPV4_LEN                 INET_ADDRSTRLEN     ///< IPv4長
#define SZ_IPV4_LEN_STR             "15"                ///< IPv4長(sprintf用)
#define SZ_CONN_STR                 (INET6_ADDRSTRLEN + 1 + 5)   ///< <IP len>:<port>

#define TM_WAIT_CONNECT             (10)        ///< client socket接続待ち[sec]

#define FNAME_CONN_LOG              "connect.log"
#define FNAME_EVENT_LOG             "event.log"
#define FNAME_EVENTCH_LOG           "evt_%s.log"
#define FNAME_FMT_NODECONF          "ptarm_%s.conf"

//need update ptarmd_error_str()
#define RPCERR_ERROR                (-10000)
#define RPCERR_NOCONN               (-10001)
#define RPCERR_ALCONN               (-10002)
#define RPCERR_NOCHANN              (-10003)
#define RPCERR_PARSE                (-10004)
#define RPCERR_NOINIT               (-10005)
#define RPCERR_BLOCKCHAIN           (-10006)

#define RPCERR_NODEID               (-20000)
#define RPCERR_NOOPEN               (-20001)
#define RPCERR_ALOPEN               (-20002)
#define RPCERR_FULLCLI              (-20003)
#define RPCERR_SOCK                 (-20004)
#define RPCERR_CONNECT              (-20005)
#define RPCERR_PEER_ERROR           (-20006)
#define RPCERR_OPENING              (-20007)

#define RPCERR_FUNDING              (-21000)

#define RPCERR_INVOICE_FULL         (-22000)
#define RPCERR_INVOICE_ERASE        (-22001)
#define RPCERR_INVOICE_FAIL         (-22002)
#define RPCERR_INVOICE_OUTDATE      (-22003)

#define RPCERR_CLOSE_START          (-25000)
#define RPCERR_CLOSE_FAIL           (-25001)

#define RPCERR_PAY_STOP             (-26000)
#define RPCERR_NOROUTE              (-26001)
#define RPCERR_PAYFAIL              (-26002)
#define RPCERR_PAY_RETRY            (-26003)
#define RPCERR_TOOMANYHOP           (-26004)


#define PREIMAGE_NUM        (10)        ///< 保持できるpreimage数(server/clientそれぞれ)


/********************************************************************
 * macros functions
 ********************************************************************/


/********************************************************************
 * typedefs
 ********************************************************************/

/** @enum   trans_cmd_t
 *  @brief  時間差処理要求
 *  @note
 *      - 要求が発生するタイミングと実行するタイミングをずらす場合に使用する。
 *      - 主に、BOLTメッセージ受信(update_add/fulfill/fail_htlc)を別チャネルに転送するために用いる。
 */
typedef enum {
    //外部用
    TRANSCMD_NONE,                  ///< 要求無し

    TRANSCMD_PAYRETRY,              ///< 支払いのリトライ

    //内部用
    TRANSCMD_ANNOSIGNS,             ///< announcement_signatures送信要求
    TRANSCMD_HTLCCHECK,             ///< HTLC check(消化できていないHTLCを反映する)
} trans_cmd_t;


/** @struct     peer_conn_t
 *  @brief      peer接続情報
 *  @note
 *      - #peer_conf_t と同じ構造だが、別にしておく(統合する可能性あり)
 */
typedef struct {
    //peer
    char        ipaddr[SZ_IPV4_LEN + 1];
    uint16_t    port;
    uint8_t     node_id[BTC_SZ_PUBKEY];
} peer_conn_t;


/** @struct     funding_conf_t
 *  @brief      funding情報
 */
typedef struct {
    uint8_t         txid[BTC_SZ_TXID];
    int             txindex;
    uint64_t        funding_sat;
    uint64_t        push_sat;
    uint32_t        feerate_per_kw;
} funding_conf_t;


/** @struct     payment_conf_t
 *  @brief      送金情報(test用)
 */
typedef struct {
    uint8_t             payment_hash[LN_SZ_HASH];
    uint8_t             hop_num;
    ln_hop_datain_t     hop_datain[1 + LN_HOP_MAX];     //先頭は送信者
} payment_conf_t;


/** @struct     rpc_conf_t
 *  @brief      bitcoind情報
 */
typedef struct {
    char            rpcuser[SZ_RPC_USER];
    char            rpcpasswd[SZ_RPC_PASSWD];
    char            rpcurl[SZ_RPC_URL];
    uint16_t        rpcport;
} rpc_conf_t;


/** @struct     peer_conf_t
 *  @brief      peer node接続情報
 *  @note
 *      - #peer_conn_t と同じ構造だが、別にしておく
 */
typedef struct {
    char            ipaddr[SZ_IPV4_LEN + 1];
    uint16_t        port;
    uint8_t         node_id[BTC_SZ_PUBKEY];
} peer_conf_t;


/** @struct     anno_conf_t
 *  @brief      announcement情報
 */
typedef struct {
    uint16_t        cltv_expiry_delta;              ///< 2:  cltv_expiry_delta
    uint64_t        htlc_minimum_msat;              ///< 8:  htlc_minimum_msat
    uint32_t        fee_base_msat;                  ///< 4:  fee_base_msat
    uint32_t        fee_prop_millionths;            ///< 4:  fee_proportional_millionths
} anno_conf_t;


/** @struct     channel_conf_t
 *  @brief      channel設定情報
 */
typedef struct {
    uint64_t    dust_limit_sat;                     ///< 8 : dust-limit-satoshis
    uint64_t    max_htlc_value_in_flight_msat;      ///< 8 : max-htlc-value-in-flight-msat
    uint64_t    channel_reserve_sat;                ///< 8 : channel-reserve-satoshis
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc-minimum-msat
    uint16_t    to_self_delay;                      ///< 2 : to-self-delay
    uint16_t    max_accepted_htlcs;                 ///< 2 : max-accepted-htlcs
    uint32_t    min_depth;                          ///< 4 : minimum-depth(acceptのみ)

    uint8_t     localfeatures;                      ///< init.localfeatures
} channel_conf_t;


/** @struct bwd_proc_fulfill_t
 *  @brief  fulfill_htlc巻き戻しデータ
 */
typedef struct {
    uint64_t    id;
    uint64_t    prev_short_channel_id;
    uint8_t     preimage[LN_SZ_PREIMAGE];
} bwd_proc_fulfill_t;


/** @struct bwd_proc_fail_t
 *  @brief  fail_htlc巻き戻しデータ
 */
typedef struct {
    uint64_t    id;
    uint64_t    prev_short_channel_id;
    utl_buf_t   reason;
    utl_buf_t   shared_secret;
    bool        b_first;            ///< true:fail発生元
} bwd_proc_fail_t;


struct lnapp_conf_t;
typedef struct lnapp_conf_t lnapp_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** start
 * 
 */
int ptarmd_start(uint16_t my_rpcport);


/** stop all threads
 * 
 */
void ptarmd_stop(void);


/** ノード内転送
 *
 */
bool ptarmd_transfer_channel(uint64_t ShortChannelId, trans_cmd_t Cmd, utl_buf_t *pBuf);


/** preimage操作排他開始
 *
 */
void ptarmd_preimage_lock(void);


/** preimage操作排他解除
 *
 */
void ptarmd_preimage_unlock(void);


/** 接続済みlnapp検索
 *
 */
lnapp_conf_t *ptarmd_search_connected_cnl(uint64_t short_channel_id);


/** ノード接続失敗リスト追加
 *
 */
void ptarmd_nodefail_add(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc);


/** ノード接続失敗リスト検索
 *
 * @retval  true        リスト登録済み
 */
bool ptarmd_nodefail_get(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc);


/** エラー文字列取得
 *
 * @param[in]       ErrCode     エラー番号
 * @return      エラー文字列
 * @note
 *      - エラー文字列はstrdup()しているため、呼び元でfree()すること
 */
char *ptarmd_error_str(int ErrCode);


#ifdef __cplusplus
}
#endif

#endif /* PTARMD_H__ */
