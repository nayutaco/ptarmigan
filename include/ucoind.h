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

#define DEFAULT_PORT    (54321)
#define UCOINDDIR       ".ucoind"
#define FTOK_FNAME      "msgq"
#define FTOK_CHAR       'b'
#define SZ_BUF          (2000)
#define SZ_RESBUF       (2000)  //TODO: "uconcli -l"で返すレスポンスサイズを考慮すること
                                //  1行180byte程度で接続ノード数分返す
#define MTYPE_CLI2D     (1)     //ucoincli --> ucoind
#define MTYPE_D2CLI     (2)     //ucoind   --> ucoincli

#define SZ_RPC_USER     (64)
#define SZ_RPC_PASSWD   (64)
#define SZ_RPC_URL      (256)

#define FNAME_LEN           (50)
#define FNAME_DIR           "amount"
#define FNAME_AMOUNT_FMT    FNAME_DIR "/amount.%" PRIx64


/********************************************************************
 * macros functions
 ********************************************************************/

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))


#ifdef __ORDER_LITTLE_ENDIAN__
//little endian!
#define CHG_ENDIAN2(to,from)    { (to) = (((from) & 0xff) << 8)  | ((from) >> 8); }
#define CHG_ENDIAN4(to,from)    { (to) = (((from) & 0xff) << 24) | (((from) & 0xff00) <<  8) | (((from) & 0xff0000) >>  8) | (((from) & 0xff000000) >> 24); }
#define CHG_ENDIAN8(to,from)    { (to) = (uint64_t)((((uint64_t)(from) & 0xff) << 56) | (((uint64_t)(from) & 0xff00) << 40) | (((uint64_t)(from) & 0xff0000) << 24) | (((uint64_t)(from) & 0xff000000) <<  8) | (((uint64_t)(from) & 0xff00000000) >> 8) | (((uint64_t)(from) & 0xff0000000000) >> 24) | (((uint64_t)(from) & 0xff000000000000) >> 40) | (((uint64_t)(from) & 0xff00000000000000) >> 56)); }
#else
//big endian...
#define CHG_ENDIAN2(to,from)    { (to) = (from); }
#define CHG_ENDIAN4(to,from)    { (to) = (from); }
#define CHG_ENDIAN8(to,from)    { (to) = (from); }
#endif

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
#define DUMPBIN(dt,ln)      misc_dumpbin(DEBUGOUT, dt, ln)

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

//メッセージ種別
typedef enum {
    MSG_BOLT,       //直接BOLTのメッセージとして送信する
    MSG_DAEMON,     //daemonへの指示
} my_msgtype_t;


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
} my_daemoncmd_t;

typedef struct {
    uint16_t        len;
    uint8_t         msg[SZ_BUF];
} msg_bolt_t;


typedef struct {
    //peer
    char        ipaddr[16];
    uint16_t    port;
    uint8_t     node_id[UCOIN_SZ_PUBKEY];
} daemon_connect_t;


typedef struct {
    ln_fundin_t         fundin;
    ucoin_util_keys_t   fundin_keys;
    char                chargeaddr[UCOIN_SZ_ADDR_MAX];
} opening_t;


typedef struct {
    uint8_t         txid[UCOIN_SZ_TXID];
    int             txindex;
    char            signaddr[UCOIN_SZ_ADDR_MAX];
    uint64_t        funding_sat;
    uint64_t        push_sat;
    opening_t       *p_opening;
} funding_conf_t;


typedef struct {
    uint8_t             payment_hash[LN_SZ_HASH];
    uint8_t             hop_num;
    ln_hop_datain_t     hop_datain[1 + LN_HOP_MAX];     //先頭は送信者
} payment_conf_t;


typedef struct {
    daemon_connect_t    conn;       //必ず1番目に置くこと
    funding_conf_t      funding;
} daemon_funding_t;

typedef struct {
    daemon_connect_t    conn;       //必ず1番目に置くこと
    uint64_t            amount;
} daemon_invoice_t;

typedef struct {
    daemon_connect_t    conn;       //必ず1番目に置くこと
    payment_conf_t      payment;
} daemon_payment_t;


typedef struct {
    my_daemoncmd_t cmd;

    union {
        daemon_connect_t    connect;
        daemon_funding_t    funding;
        daemon_invoice_t    invoice;
        daemon_payment_t    payment;
    } params;
} msg_daemon_t;


typedef struct {
    my_msgtype_t    type;
    union {
        //MSG_BOLT用
        msg_bolt_t bolt;

        //MSG_DAEMON用
        msg_daemon_t daemon;
    } cmd;
} payload_t;


//message queue用
typedef struct {
    long        mtype;
    payload_t   payload;
} msgbuf_t;

typedef struct {
    long        mtype;
    char        mtext[SZ_RESBUF];
} msgres_t;


typedef struct {
    uint16_t        port;
    char            name[32];
    char            wif[UCOIN_SZ_WIF_MAX];
} node_conf_t;


typedef struct {
    char            rpcuser[SZ_RPC_USER];
    char            rpcpasswd[SZ_RPC_PASSWD];
    char            rpcurl[SZ_RPC_URL];
} rpc_conf_t;


typedef struct {
    char            ipaddr[16];
    uint16_t        port;
    char            name[32];
    uint8_t         node_id[UCOIN_SZ_PUBKEY];
} peer_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

bool pay_forward(const ln_cb_add_htlc_recv_t *p_add, uint64_t prev_short_channel_id);
bool fulfill_backward(const ln_cb_fulfill_htlc_recv_t *p_fulfill);

#endif /* UCOIND_H__ */
