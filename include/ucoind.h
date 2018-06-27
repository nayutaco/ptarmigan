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
/** @file   ucoind.h
 *  @brief  ucoind daemon header
 */
#ifndef UCOIND_H__
#define UCOIND_H__

#include <stdint.h>

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif


static inline int tid() {
    return (int)syscall(SYS_gettid);
}

#include "misc.h"
#include "ln.h"


/********************************************************************
 * macros
 ********************************************************************/

#define SZ_RPC_USER                 (64)        ///< RPCUSER
#define SZ_RPC_PASSWD               (64)        ///< RPCPASSWORD
#define SZ_RPC_URL                  (256)       ///< URL

#define SZ_SOCK_SERVER_MAX          (10)        ///< 接続可能max(server)
#define SZ_SOCK_CLIENT_MAX          (10)        ///< 接続可能max(client)

#define SZ_IPV4_LEN                 INET_ADDRSTRLEN     ///< IPv4長
#define SZ_IPV4_LEN_STR             "15"                ///< IPv4長(sprintf用)
#define SZ_CONN_STR                 (INET6_ADDRSTRLEN + 1 + 5)   ///< <IP len>:<port>

#define TM_WAIT_CONNECT             (10)        ///< client socket接続待ち[sec]

#define FNAME_CONN_LOG              "connect.log"
#define FNAME_EVENT_LOG             "event.log"
#define FNAME_EVENTCH_LOG           "evt_%s.log"
#define FNAME_FMT_NODECONF          "ptarm_%s.conf"


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

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))

#define PRINTOUT        stderr

#if 1
//#define DEBUGTRACE

#ifdef UCOIN_USE_ULOG
#include "ulog.h"
#define LOGV(...)       ulog_write(ULOG_PRI_VERBOSE, __FILE__, __LINE__, 1, "APP", __func__, __VA_ARGS__)
#define DUMPV(dt,ln)    ulog_dump(ULOG_PRI_VERBOSE, __FILE__, __LINE__, 0, "APP", __func__, dt, ln)
#define TXIDV(dt)       ulog_dump_rev(ULOG_PRI_VERBOSE, __FILE__, __LINE__, 0, "APP", __func__, dt, UCOIN_SZ_TXID)

#define LOGD(...)       ulog_write(ULOG_PRI_DBG, __FILE__, __LINE__, 1, "APP", __func__, __VA_ARGS__)
#define LOGD2(...)      ulog_write(ULOG_PRI_DBG, __FILE__, __LINE__, 0, "APP", __func__, __VA_ARGS__)
#define DUMPD(dt,ln)    ulog_dump(ULOG_PRI_DBG, __FILE__, __LINE__, 0, "APP", __func__, dt, ln)
#define TXIDD(dt)       ulog_dump_rev(ULOG_PRI_DBG, __FILE__, __LINE__, 0, "APP", __func__, dt, UCOIN_SZ_TXID)

#else   //UCOIN_USE_ULOG
#define DEBUGOUT        stderr

/// @def    LOGV(format, ...)
/// @brief  デバッグ出力(UCOIN_DEBUG定義時のみ有効)
#define LOGV(format, ...) {fprintf(DEBUGOUT, "%lu[%d]%s[%s:%d]", (unsigned long)time(NULL), tid(), __func__, __FILE__, __LINE__); fprintf(DEBUGOUT, format, ##__VA_ARGS__);}
#define DUMPV(dt,ln)        ucoin_util_dumpbin(DEBUGOUT, dt, ln, true)
#define TXIDV(dt)           {ucoin_util_dumptxid(DEBUGOUT, dt); fprintf(DEBUGOUT, "\n");}
/// @def    LOGD(format, ...)
/// @brief  デバッグ出力(UCOIN_DEBUG定義時のみ有効)
#define LOGD(format, ...) {fprintf(DEBUGOUT, "%lu[%d]%s[%s:%d]", (unsigned long)time(NULL), tid(), __func__, __FILE__, __LINE__); fprintf(DEBUGOUT, format, ##__VA_ARGS__);}
#define LOGD2(format, ...) {fprintf(DEBUGOUT, format, ##__VA_ARGS__);}

/// @def    DUMPD(dt,ln)
/// @brief  ダンプ出力(UCOIN_DEBUG定義時のみ有効)
#define DUMPD(dt,ln)      ucoin_util_dumpbin(DEBUGOUT, dt, ln, true)
#define TXIDD(dt)        {ucoin_util_dumptxid(DEBUGOUT, dt); fprintf(DEBUGOUT, "\n");}

#endif  //UCOIN_USE_ULOG

#ifdef DEBUGTRACE
#define DBGTRACE_BEGIN      {fprintf(stderr, "[%d]%s[%s:%d]BEGIN\n", tid(), __func__, __FILE__, __LINE__);}
#define DBGTRACE_END        {fprintf(stderr, "[%d]%s[%s:%d]END\n", tid(), __func__, __FILE__, __LINE__);}
#else
#define DBGTRACE_BEGIN
#define DBGTRACE_END
#endif

#else //UCOIN_DEBUG
#define LOGV(...)       //none
#define DUMPV(...)      //none
#define TXIDV(...)      //none

#define LOGD(...)     //none
#define LOGD2(...)    //none
#define DUMPD(...)        //none
#define TXIDD(...)       //none
#define DBGTRACE_BEGIN
#define DBGTRACE_END

#endif //UCOIN_DEBUG


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

    TRANSCMD_ADDHTLC,               ///< update_add_htlc転送
    TRANSCMD_FULFILL,               ///< update_fulfill_htlc転送
    TRANSCMD_FAIL,                  ///< update_fail_htlc転送
    TRANSCMD_PAYRETRY,              ///< 支払いのリトライ

    //内部用
    TRANSCMD_ANNOSIGNS,             ///< announcement_signatures送信要求
} trans_cmd_t;


/** @struct     daemon_connect_t
 *  @brief      daemon接続情報
 *  @note
 *      - #peer_conf_t と同じ構造だが、別にしておく(統合する可能性あり)
 */
typedef struct {
    //peer
    char        ipaddr[SZ_IPV4_LEN + 1];
    uint16_t    port;
    uint8_t     node_id[UCOIN_SZ_PUBKEY];
} daemon_connect_t;


/** @struct     funding_conf_t
 *  @brief      funding情報
 */
typedef struct {
    uint8_t         txid[UCOIN_SZ_TXID];
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
 *      - #daemon_connect_t と同じ構造だが、別にしておく
 */
typedef struct {
    char            ipaddr[SZ_IPV4_LEN + 1];
    uint16_t        port;
    uint8_t         node_id[UCOIN_SZ_PUBKEY];
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


/** @struct     establish_conf_t
 *  @brief      establish channel情報
 */
typedef struct {
    uint64_t    dust_limit_sat;                     ///< 8 : dust-limit-satoshis
    uint64_t    max_htlc_value_in_flight_msat;      ///< 8 : max-htlc-value-in-flight-msat
    uint64_t    channel_reserve_sat;                ///< 8 : channel-reserve-satoshis
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc-minimum-msat
    uint16_t    to_self_delay;                      ///< 2 : to-self-delay
    uint16_t    max_accepted_htlcs;                 ///< 2 : max-accepted-htlcs
    uint32_t    min_depth;                          ///< 4 : minimum-depth(acceptのみ)
} establish_conf_t;


/** @struct fwd_proc_add_t
 *  @brief  add_htlc転送データ
 *  @note
 *      - 転送元情報は、fulfill_htlc/fail_htlcの戻し用に self->cnl_add_htlc[]に保持する
 */
typedef struct {
    uint8_t     onion_route[LN_SZ_ONION_ROUTE];     ///< 送信:onion
    uint64_t    amt_to_forward;                     ///< 送信:amt_to_forward
    uint32_t    outgoing_cltv_value;                ///< 送信:cltv
    uint8_t     payment_hash[LN_SZ_HASH];           ///< 送信:payment_hash
    uint64_t    next_short_channel_id;              ///< 送信:short_chennl_id
    uint64_t    prev_short_channel_id;              ///< 転送元:short_channel_id
    uint64_t    prev_id;                            ///< 転送元:HTLC id
    ucoin_buf_t shared_secret;                      ///< add_htlc失敗:reason用
} fwd_proc_add_t;


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
    ucoin_buf_t reason;
    ucoin_buf_t shared_secret;
    bool        b_first;            ///< true:fail発生元
} bwd_proc_fail_t;


struct lnapp_conf_t;
typedef struct lnapp_conf_t lnapp_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** ノード内転送
 *
 */
bool ucoind_transfer_channel(uint64_t ShortChannelId, trans_cmd_t Cmd, ucoin_buf_t *pBuf);


/** preimage操作排他開始
 *
 */
void ucoind_preimage_lock(void);


/** preimage操作排他解除
 *
 */
void ucoind_preimage_unlock(void);


/** 接続済みlnapp検索
 *
 */
lnapp_conf_t *ucoind_search_connected_cnl(uint64_t short_channel_id);


/** ucoind実行パス取得
 *
 */
// const char *ucoind_get_exec_path(void);


/** ノード接続失敗リスト追加
 *
 */
void ucoind_nodefail_add(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc);


/** ノード接続失敗リスト検索
 *
 * @retval  true        リスト登録済み
 */
bool ucoind_nodefail_get(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc);


/** エラー文字列取得
 *
 * @param[in]       ErrCode     エラー番号
 * @return      エラー文字列
 * @note
 *      - エラー文字列はstrdup()しているため、呼び元でfree()すること
 */
char *ucoind_error_str(int ErrCode);


#ifdef __cplusplus
}
#endif

#endif /* UCOIND_H__ */
