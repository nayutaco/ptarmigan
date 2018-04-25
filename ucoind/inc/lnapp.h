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
#include <sys/queue.h>

#include "ucoind.h"
#include "conf.h"


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct cJSON cJSON;

/** @struct     transferlist_t
 *  @brief      update_add_htlc, update_fulfill_htlc, update_fail_htlcの転送リスト
 */
typedef struct transferlist_t {
    LIST_ENTRY(transferlist_t) list;
    trans_cmd_t     cmd;            ///< 要求
    ucoin_buf_t     buf;            ///< 転送先で送信するパケット用パラメータ
} transferlist_t;


typedef struct routelist_t {
    LIST_ENTRY(routelist_t) list;
    payment_conf_t          route;
    uint64_t                htlc_id;    ///< 該当するhtlc id
} routelist_t;


LIST_HEAD(transferlisthead_t, transferlist_t);
LIST_HEAD(routelisthead_t, routelist_t);


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
    uint8_t         flag_recv;              ///< 受信済み

    //排他制御
    //  これ以外に、ucoind全体として mMuxNode とフラグmFlagNode がある。
    pthread_cond_t  cond;           ///< muxの待ち合わせ
    pthread_mutex_t mux;            ///< 処理待ち合わせ用のmutex
    pthread_mutex_t mux_proc;       ///< BOLT受信処理中のmutex
    pthread_mutex_t mux_send;       ///< socket送信中のmutex
    pthread_mutex_t mux_revack;     ///< revoke_and_ack後キュー用mutex
    pthread_mutex_t mux_rcvidle;    ///< 受信アイドル時キュー用mutex

    struct transferlisthead_t   revack_head;    //revoke_and_ack後キュー
    struct transferlisthead_t   rcvidle_head;   //受信アイドル時キュー
    struct routelisthead_t      payroute_head;  //payment

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


/** [lnapp]解放
 *
 */
void lnapp_term(void);


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
bool lnapp_payment(lnapp_conf_t *pAppConf, const payment_conf_t *pPay);

/** [lnapp]channel間処理転送
 *
 */
void lnapp_transfer_channel(lnapp_conf_t *pAppConf, trans_cmd_t Cmd, ucoin_buf_t *pBuf);


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
