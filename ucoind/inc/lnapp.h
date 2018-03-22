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
/** @file   lnapp.h
 *  @brief  lnapp header
 */
#ifndef LNAPP_H__
#define LNAPP_H__

#include <pthread.h>

#define USE_LINUX_LIST
#ifdef USE_LINUX_LIST
#include <sys/queue.h>
#endif  //USE_LINUX_LIST

#include "ucoind.h"
#include "conf.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define APP_FWD_PROC_MAX        (5)         ///< 他スレッドからの処理要求キュー数
                                            ///< TODO: オーバーフローチェックはしていない


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct cJSON cJSON;
typedef struct queue_fulfill_t queue_fulfill_t;


/** @enum   recv_proc_t
 *  @brief  処理要求
 */
typedef enum {
    //外部用
    FWD_PROC_NONE,                  ///< 要求無し

    FWD_PROC_ADD,                   ///< update_add_htlc転送
    FWD_PROC_FULFILL,               ///< update_fulfill_htlc転送
    FWD_PROC_FAIL,                  ///< update_fail_htlc転送

    //内部用
    INNER_SEND_ANNO_SIGNS,          ///< announcement_signatures送信要求
} recv_proc_t;


typedef struct routelist_t {
#ifdef USE_LINUX_LIST
    LIST_ENTRY(routelist_t) list;
    payment_conf_t          route;
#else   //USE_LINUX_LIST
    struct routelist_t      *p_next;    ///< list構造
    payment_conf_t          *p_route;   ///< APP_MALLOC()にて確保
#endif  //USE_LINUX_LIST
    uint64_t                htlc_id;    ///< 該当するhtlc id
} routelist_t;


#ifdef USE_LINUX_LIST
LIST_HEAD(listhead_t, routelist_t);
#endif


/** @struct lnapp_conf_t
 *  @brief  アプリ側のチャネル管理情報
 */
typedef struct lnapp_conf_t {
    //p2p_svr/cli用
    volatile int    sock;
    pthread_t       th;
    char            conn_str[15 + 1 + 5 + 1];     // client <ipaddr>:<port>

    //制御内容通知
    bool            initiator;                  ///< true:Noise Protocolのinitiator
    uint8_t         node_id[UCOIN_SZ_PUBKEY];   ///< 接続先(initiator==true時)
    daemoncmd_t     cmd;                        ///< ucoincliからの処理要求

    //lnappワーク
    volatile bool   loop;                   ///< true:channel動作中
    ln_self_t       *p_self;                ///< channelのコンテキスト

    bool            initial_routing_sync;   ///< init.localfeaturesのinitial_routing_sync
    uint8_t         ping_counter;           ///< 無送受信時にping送信するカウンタ(カウントアップ)
    bool            funding_waiting;        ///< true:funding_txの安定待ち
    uint32_t        funding_confirm;        ///< funding_txのconfirmation数
    uint8_t         flag_ope;               ///< normal operation中フラグ
    uint8_t         flag_recv;              ///< 受信済み

    pthread_cond_t  cond;           ///< muxの待ち合わせ
    pthread_mutex_t mux;            ///< 処理待ち合わせ用のmutex
    pthread_mutex_t mux_proc;       ///< 処理中のmutex
    pthread_mutex_t mux_send;       ///< socket送信中のmutex
    pthread_mutex_t mux_fulque;     ///< update_fulfill_htlcキュー用mutex

    //他スレッドからの転送処理要求
    uint8_t         fwd_proc_rpnt;  ///< fwd_procの読込み位置
    uint8_t         fwd_proc_wpnt;  ///< fwd_procの書込み位置
    struct {
        recv_proc_t cmd;            ///< 要求
        uint16_t    len;            ///< p_data長
        void        *p_data;        ///< mallocで確保
    } fwd_proc[APP_FWD_PROC_MAX];

    //fulfillキュー
    queue_fulfill_t *p_fulfill_queue;

    //payment
#ifdef USE_LINUX_LIST
    struct listhead_t routing_head;
#else   //USE_LINUX_LIST
    routelist_t     *p_routing;
#endif  //USE_LINUX_LIST

    //last send announcement
    uint64_t        last_anno_cnl;                      ///< 最後にannouncementしたchannel
    uint8_t         last_anno_node[UCOIN_SZ_PUBKEY];    ///< 最後にannouncementしたnode

    int             err;            ///< last error
    char            *p_errstr;      ///< last error string

} lnapp_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** [lnapp]初期化
 *
 */
void lnapp_init(void);


/** [lnapp]開始
 *
 */
void lnapp_start(lnapp_conf_t *pAppConf);


/** [lnapp]停止
 *
 */
void lnapp_stop(lnapp_conf_t *pAppConf);


/** [lnapp]チャネル接続開始
 *
 */
bool lnapp_funding(lnapp_conf_t *pAppConf, const funding_conf_t *pFunding);


/** [lnapp]送金開始
 *
 */
bool lnapp_payment(lnapp_conf_t *pAppConf, payment_conf_t *pPay);


/** [lnapp]送金転送
 *
 */
bool lnapp_forward_payment(lnapp_conf_t *pAppConf, fwd_proc_add_t *pAdd);


/** [lnapp]送金反映
 *
 */
bool lnapp_backward_fulfill(lnapp_conf_t *pAppConf, const ln_cb_fulfill_htlc_recv_t *pFulFill);


/** [lnapp]送金エラー
 *
 */
bool lnapp_backward_fail(lnapp_conf_t *pAppConf, const ln_cb_fail_htlc_recv_t *pFail, bool bFirst);


/** [lnapp]チャネル閉鎖
 *
 */
bool lnapp_close_channel(lnapp_conf_t *pAppConf);


/** [lnapp]チャネル閉鎖(強制)
 *
 */
bool lnapp_close_channel_force(const uint8_t *pNodeId);


/** [lnapp]short_channel_idに対応するlnappか
 *
 */
bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id);


/** [lnapp]lnapp出力
 *
 */
void lnapp_show_self(const lnapp_conf_t *pAppConf, cJSON *pResult, const char *pSvrCli);


/** [lnapp]現在のcommit_tx出力
 *
 */
bool lnapp_get_committx(lnapp_conf_t *pAppConf, cJSON *pResult);


/** [lnapp]ループ状態取得
 *
 */
bool lnapp_is_looping(const lnapp_conf_t *pAppConf);


/** [lnapp]初期化済み状態取得
 *
 */
bool lnapp_is_inited(const lnapp_conf_t *pAppConf);

#endif /* LNAPP_H__ */
