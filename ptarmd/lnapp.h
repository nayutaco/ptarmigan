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

#include "ptarmd.h"
#include "conf.h"


#ifdef __cplusplus
extern "C" {
#endif


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct cJSON cJSON;

/** @struct     routelist_t
 *  @brief      送金情報リスト
 */
typedef struct routelist_t {
    LIST_ENTRY(routelist_t) list;
    payment_conf_t          route;
    uint64_t                htlc_id;    ///< 該当するhtlc id
} routelist_t;

LIST_HEAD(routelisthead_t, routelist_t);


/** @struct     pinglist_t
 *  @brief      ping.num_pong_bytes list
 */
typedef struct ponglist_t {
    LIST_ENTRY(ponglist_t) list;
    uint16_t                num_pong_bytes;
} ponglist_t;

LIST_HEAD(ponglisthead_t, ponglist_t);


//XXX: comment
typedef enum lnapp_state_t {
    LNAPP_STATE_NONE,
    LNAPP_STATE_INIT = 0x01,
    LNAPP_STATE_INACTIVE = 0x02,
    LNAPP_STATE_ACTIVE = 0x04,
    LNAPP_STATE_CLOSED = 0x08,
    LNAPP_STATE_EXISTS =
        LNAPP_STATE_INIT |LNAPP_STATE_INACTIVE | LNAPP_STATE_ACTIVE | LNAPP_STATE_CLOSED,
} lnapp_state_t;


/** @struct lnapp_conf_t
 *  @brief  アプリ側のチャネル管理情報
 */
typedef struct lnapp_conf_t {
    //XXX: init param
    uint8_t             node_id[BTC_SZ_PUBKEY]; ///< 接続先(initiator==true時)

    //init
    lnapp_state_t       state;
    uint32_t            ref_counter;
    ln_channel_t        channel;                ///< channelのコンテキスト

    pthread_cond_t      cond;                   ///< muxの待ち合わせ
    pthread_mutex_t     mux;                    ///< 処理待ち合わせ用のmutex
    pthread_mutex_t     mux_channel;            ///< ln_channel_t処理中のmutex
    pthread_mutex_t     mux_send;               ///< socket送信中のmutex

    //XXX: start param
    bool                initiator;                  ///< true:Noise Protocol handshakeのinitiator
    volatile int        sock;                       ///< -1:socket未接続
    char                conn_str[SZ_CONN_STR + 1];  ///< 接続成功ログ/接続失敗リスト用
    uint16_t            conn_port;                  ///< 接続成功ログ/接続失敗リスト用
    ptarmd_routesync_t  routesync;                  ///< local routing_sync
    ln_noise_t          noise;

    //XXX: start
    volatile bool       active;                 ///< true:channel動作中
    volatile uint8_t    flag_recv;              ///< 受信フラグ(M_FLAGRECV_xxx)
    int                 ping_counter;           ///< 無送受信時にping送信するカウンタ(カウントアップ)

    bool                funding_waiting;        ///< true:funding_txの安定待ち
    uint32_t            funding_confirm;        ///< funding_txのconfirmation数

    uint64_t            last_anno_cnl;          ///< [#send_channel_anno()]最後にannouncementしたchannel
    bool                annosig_send_req;       ///< true: open_channel.announce_channel=1 and announcement_signatures not send
    bool                annodb_updated;         ///< true: flag to notify annodb update
    bool                annodb_cont;            ///< true: announcement連続送信中
    time_t              annodb_stamp;           ///< last annodb_updated change time

    uint64_t            dummy_htlc_id;          //XXX: save db
    uint32_t            feerate_per_kw;

    struct routelisthead_t  payroute_head;      //payment
    struct ponglisthead_t   pong_head;          //pong.num_pong_bytes

    int                 err;                    ///< last error
    char                *p_errstr;              ///< last error string(UTL_DBG_MALLOC)

    //XXX: create and join
    pthread_t           th;                     ///< pthread id
} lnapp_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

void lnapp_global_init(void);


bool lnapp_handshake(peer_conn_handshake_t *pConnHandshake);


void lnapp_init(lnapp_conf_t *pAppConf);


void lnapp_term(lnapp_conf_t *pAppConf);


void lnapp_conf_init(lnapp_conf_t *pAppConf, const uint8_t *pPeerNodeId);
void lnapp_conf_term(lnapp_conf_t *pAppConf);
void lnapp_conf_start(
    lnapp_conf_t *pAppConf, bool Initiator, int Sock, const char *pConnStr, uint16_t ConnPort,
    ptarmd_routesync_t Routesync, ln_noise_t Noise);
void lnapp_conf_stop(lnapp_conf_t *pAppConf);


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
bool lnapp_funding(lnapp_conf_t *pAppConf, const funding_conf_t *pFundingConf);


/*******************************************
 * 送金
 *******************************************/

/** [lnapp]check pong list
 *
 *  @retval     true    not receive pong against previous ping sending.
 */
bool lnapp_check_ponglist(const lnapp_conf_t *pAppConf);


/** [lnapp]送金開始
 *
 */
bool lnapp_payment(lnapp_conf_t *pAppConf, const payment_conf_t *pPay, const char **ppResult);


/*******************************************
 * close関連
 *******************************************/

/** [lnapp]チャネル閉鎖
 *
 */
bool lnapp_close_channel(lnapp_conf_t *pAppConf);


/** [lnapp]チャネル閉鎖(強制)
 *
 */
bool lnapp_close_channel_force(const uint8_t *pNodeId);


/*******************************************
 * fee関連
 *******************************************/

/** [lnapp]feerate_per_kw更新
 *
 * @param[in,out]   pAppConf
 * @param[in]       FeeratePerKw
 */
void lnapp_set_feerate(lnapp_conf_t *pAppConf, uint32_t FeeratePerKw);


/*******************************************
 * その他
 *******************************************/

/** [lnapp]short_channel_idに対応するlnappか
 *
 */
bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id);


/** [lnapp]lnapp出力
 *
 */
void lnapp_show_channel(const lnapp_conf_t *pAppConf, cJSON *pResult);


/** [lnapp]現在のcommit_tx出力
 *
 * @param[in]   bLocal      true:local unilateral close
 */
bool lnapp_get_committx(lnapp_conf_t *pAppConf, cJSON *pResult, bool bLocal);


/** [lnapp]ループ状態取得
 *
 * @retval  true        channel active
 */
bool lnapp_is_active(const lnapp_conf_t *pAppConf);


/** [lnapp]接続済み状態取得
 *
 * @retval  true        init message exchanged
 */
bool lnapp_is_connected(const lnapp_conf_t *pAppConf);


/** [lnapp]初期化済み状態取得
 *
 * @retval  true        init/channel_reestablish/funding_locked message exchanged
 */
bool lnapp_is_inited(const lnapp_conf_t *pAppConf);


#ifdef __cplusplus
}
#endif

#endif /* LNAPP_H__ */
