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


// JSON-RPCエラー

#define RPCERR_ERROR                (-10000)
#define RPCERR_ERROR_STR            "error"
#define RPCERR_NOCONN               (-10001)
#define RPCERR_NOCONN_STR           "not connected"
#define RPCERR_ALCONN               (-10002)
#define RPCERR_ALCONN_STR           "already connected"
#define RPCERR_NOCHANN              (-10003)
#define RPCERR_NOCHANN_STR          "no channel"
#define RPCERR_PARSE                (-10004)
#define RPCERR_PARSE_STR            "parse param"
#define RPCERR_NOINIT               (-10005)
#define RPCERR_NOINIT_STR           "no init or init not end"

#define RPCERR_NODEID               (-20000)
#define RPCERR_NODEID_STR           "invalid node_id"
#define RPCERR_NOOPEN               (-20001)
#define RPCERR_NOOPEN_STR           "channel not open"
#define RPCERR_ALOPEN               (-20002)
#define RPCERR_ALOPEN_STR           "channel already opened"
#define RPCERR_FULLCLI              (-20003)
#define RPCERR_FULLCLI_STR          "client full"
#define RPCERR_SOCK                 (-20004)
#define RPCERR_SOCK_STR             "socket"
#define RPCERR_CONNECT              (-20005)
#define RPCERR_CONNECT_STR          "connect"
#define RPCERR_PEER_ERROR           (-20006)
#define RPCERR_OPENING              (-20007)
#define RPCERR_OPENING_STR          "funding now"

#define RPCERR_FUNDING              (-21000)
#define RPCERR_FUNDING_STR          "fail funding"

#define RPCERR_INVOICE_FULL         (-22000)
#define RPCERR_INVOICE_FULL_STR     "invoice full"
#define RPCERR_INVOICE_ERASE        (-22001)
#define RPCERR_INVOICE_ERASE_STR    "fail: erase invoice"

#define RPCERR_CLOSE_START          (-25000)
#define RPCERR_CLOSE_START_STR      "fail start closing"
#define RPCERR_CLOSE_FAIL           (-25001)
#define RPCERR_CLOSE_FAIL_STR       "fail unilateral close"

#define RPCERR_PAY_STOP             (-26000)
#define RPCERR_PAY_STOP_STR         "stop payment"
#define RPCERR_NOROUTE              (-26001)
#define RPCERR_NOROUTE_STR          "fail routing"
#define RPCERR_PAYFAIL              (-26002)


#define PREIMAGE_NUM        (10)        ///< 保持できるpreimage数


/********************************************************************
 * macros functions
 ********************************************************************/

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))

#define PRINTOUT        stderr

#if 1
#define DEBUGOUT        stderr
#define DEBUGTRACE

/// @def    DBG_PRINTF(format, ...)
/// @brief  デバッグ出力(UCOIN_DEBUG定義時のみ有効)
#define DBG_PRINTF(format, ...) {fprintf(DEBUGOUT, "%ld[%d]%s[%s:%d]", (unsigned long)time(NULL), tid(), __func__, __FILE__, __LINE__); fprintf(DEBUGOUT, format, ##__VA_ARGS__);}
#define DBG_PRINTF2(format, ...) {fprintf(DEBUGOUT, format, ##__VA_ARGS__);}

/// @def    DUMPBIN(dt,ln)
/// @brief  ダンプ出力(UCOIN_DEBUG定義時のみ有効)
#define DUMPBIN(dt,ln)      ucoin_util_dumpbin(DEBUGOUT, dt, ln, true)
#define DUMPTXID(dt)        {ucoin_util_dumptxid(DEBUGOUT, dt); fprintf(DEBUGOUT, "\n");}
#ifdef DEBUGTRACE
#define DBGTRACE_BEGIN      {fprintf(stderr, "[%d]%s[%s:%d]BEGIN\n", tid(), __func__, __FILE__, __LINE__);}
#define DBGTRACE_END        {fprintf(stderr, "[%d]%s[%s:%d]END\n", tid(), __func__, __FILE__, __LINE__);}
#else
#define DBGTRACE_BEGIN
#define DBGTRACE_END
#endif

#else //UCOIN_DEBUG

#define DBG_PRINTF(...)     //none
#define DBG_PRINTF2(...)    //none
#define DUMPBIN(...)        //none
#define DBGTRACE_BEGIN
#define DBGTRACE_END

#endif //UCOIN_DEBUG


/********************************************************************
 * typedefs
 ********************************************************************/

//daemonへの指示
typedef enum {
    DCMD_NONE,
    DCMD_CONNECT,       ///< チャネル接続
    DCMD_CREATE,        ///< チャネル作成
    DCMD_CLOSE,         ///< チャネル閉鎖
    DCMD_PREIMAGE,      ///< payment_preimage作成
    DCMD_PAYMENT_HASH,  ///< payment_hash表示
    DCMD_PAYMENT,       ///< payment
    DCMD_SHOW_LIST,     ///< channel一覧
    DCMD_STOP,          ///< ucoind停止
} daemoncmd_t;


typedef struct {
    //peer
    char        ipaddr[16];
    uint16_t    port;
    uint8_t     node_id[UCOIN_SZ_PUBKEY];
} daemon_connect_t;


typedef struct {
    uint8_t         txid[UCOIN_SZ_TXID];
    int             txindex;
    char            signaddr[UCOIN_SZ_ADDR_MAX];
    uint64_t        funding_sat;
    uint64_t        push_sat;
    uint32_t        feerate_per_kw;
} funding_conf_t;


typedef struct {
    uint8_t             payment_hash[LN_SZ_HASH];
    uint8_t             hop_num;
    ln_hop_datain_t     hop_datain[1 + LN_HOP_MAX];     //先頭は送信者
} payment_conf_t;


typedef struct {
    char            rpcuser[SZ_RPC_USER];
    char            rpcpasswd[SZ_RPC_PASSWD];
    char            rpcurl[SZ_RPC_URL];
    uint16_t        rpcport;
} rpc_conf_t;


typedef struct {
    char            ipaddr[16];
    uint16_t        port;
    char            name[32];
    uint8_t         node_id[UCOIN_SZ_PUBKEY];
} peer_conf_t;


typedef struct {
    uint16_t        cltv_expiry_delta;              ///< 2:  cltv_expiry_delta
    uint64_t        htlc_minimum_msat;              ///< 8:  htlc_minimum_msat
    uint32_t        fee_base_msat;                  ///< 4:  fee_base_msat
    uint32_t        fee_prop_millionths;            ///< 4:  fee_proportional_millionths
} anno_conf_t;


typedef struct {
    uint64_t    dust_limit_sat;                     ///< 8 : dust-limit-satoshis
    uint64_t    max_htlc_value_in_flight_msat;      ///< 8 : max-htlc-value-in-flight-msat
    uint64_t    channel_reserve_sat;                ///< 8 : channel-reserve-satoshis
    uint64_t    htlc_minimum_msat;                  ///< 8 : htlc-minimum-msat
    uint16_t    to_self_delay;                      ///< 2 : to-self-delay
    uint16_t    max_accepted_htlcs;                 ///< 2 : max-accepted-htlcs
    uint32_t    min_depth;                          ///< 4 : minimum-depth(acceptのみ)
} establish_conf_t;


typedef struct {
    uint8_t     onion_route[LN_SZ_ONION_ROUTE];
    uint64_t    amt_to_forward;
    uint32_t    outgoing_cltv_value;
    uint8_t     payment_hash[LN_SZ_HASH];
    uint64_t    next_short_channel_id;
    uint64_t    prev_short_channel_id;
    uint64_t    prev_id;
    ucoin_buf_t shared_secret;
} fwd_proc_add_t;


struct lnapp_conf_t;
typedef struct lnapp_conf_t lnapp_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

const uint8_t *ucoind_nodeid(void);
uint16_t ucoind_nodeport(void);
const ucoin_util_keys_t *ucoind_nodekeys(void);

bool ucoind_forward_payment(fwd_proc_add_t *p_add);
bool ucoind_backward_fulfill(const ln_cb_fulfill_htlc_recv_t *p_fulfill);
bool ucoind_backward_fail(const ln_cb_fail_htlc_recv_t *pFail);

void ucoind_preimage_lock(void);
void ucoind_preimage_unlock(void);

lnapp_conf_t *ucoind_search_connected_cnl(uint64_t short_channel_id);

const char *ucoind_get_exec_path(void);

#endif /* UCOIND_H__ */
