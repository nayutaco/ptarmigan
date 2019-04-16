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

/** @file   lnapp.c
 *  @brief  channel処理
 *  @note   <pre>
 *                +-----------------------------------------------+
 *      p2p--->   | channel thread                                |
 *                |                                               |
 *                +--+-------+-------------------+----------------+
 *            create |       | create            | create
 *                   v       v                   v
 *      +-------------+     +-------------+     +-------------+
 *      | recv thread |     | poll thread |     | anno thread |
 *      |             |     |             |     |             |
 *      +-------------+     +-------------+     +-------------+
 * </pre>
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <assert.h>

#include "cJSON.h"

#define LOG_TAG     "lnapp"
#include "utl_log.h"
#include "utl_addr.h"
#include "utl_time.h"
#include "utl_int.h"
#include "utl_str.h"
#include "utl_mem.h"
#include "utl_thread.h"

#include "btc_crypto.h"
#include "btc_script.h"

#include "ln_msg_setupctl.h"
#include "ln_setupctl.h"
#include "ln_establish.h"
#include "ln_close.h"
#include "ln_normalope.h"
#include "ln_anno.h"
#include "ln_noise.h"
#include "ln_msg.h"

#include "ptarmd.h"
#include "cmd_json.h"
#include "lnapp.h"
#include "lnapp_cb.h"
#include "lnapp_util.h"
#include "lnapp_manager.h"
#include "conf.h"
#include "btcrpc.h"
#include "ln_db.h"
#include "monitoring.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_WAIT_POLL_SEC         (10)        //監視スレッドの待ち間隔[sec]
#define M_WAIT_PING_SEC         (60)        //ping送信待ち[sec](pingは30秒以上の間隔をあけること)
#define M_WAIT_ANNO_SEC         (1)         //監視スレッドでのannounce処理間隔[sec]
#define M_WAIT_ANNO_LONG_SEC    (30)        //監視スレッドでのannounce処理間隔(長めに空ける)[sec]
#define M_WAIT_RECV_TO_MSEC     (50)        //socket受信待ちタイムアウト[msec]
#define M_WAIT_RECV_MSG_MSEC    (500)       //message受信監視周期[msec]
#define M_WAIT_RECV_THREAD_MSEC (100)       //recv_thread開始待ち[msec]
#define M_WAIT_RESPONSE_MSEC    (10000)     //受信待ち[msec]
#define M_WAIT_CHANREEST_MSEC   (3600000)   //channel_reestablish受信待ち[msec]

//lnapp_conf_t.flag_recv
#define M_FLAGRECV_INIT             (0x01)  ///< receive init
#define M_FLAGRECV_INIT_EXCHANGED   (0x02)  ///< exchange init
#define M_FLAGRECV_REESTABLISH      (0x04)  ///< receive channel_reestablish
#define M_FLAGRECV_FUNDINGLOCKED    (0x08)  ///< receive funding locked
#define M_FLAGRECV_END              (0x80)  ///< 初期化完了

#define M_ANNO_UNIT             (10)        ///< 1回のanno_proc()での処理単位
#define M_RECVIDLE_RETRY_MAX    (5)         ///< 受信アイドル時キュー処理のリトライ最大

#define M_PING_CNT              (M_WAIT_PING_SEC / M_WAIT_POLL_SEC)
#define M_MISSING_PONG          (60)        ///< not ping reply

#define M_ERRSTR_REASON                 "fail: %s (hop=%d)(suggest:%s)"
#define M_ERRSTR_CANNOTDECODE           "fail: result cannot decode"
#define M_ERRSTR_CANNOTSTART            "fail: can't start payment(local_msat=%" PRIu64 ", amt_to_forward=%" PRIu64 ")"

#define M_SZ_SCRIPT_PARAM       (512)

#if 1
#define DBGTRACE_BEGIN  LOGD("BEGIN\n");
#define DBGTRACE_END    LOGD("END\n");
#else
#define DBGTRACE_BEGIN
#define DBGTRACE_END
#endif


/********************************************************************
 * static variables
 ********************************************************************/

static volatile bool        mLoop;          //true:チャネル有効

static ln_anno_param_t        mAnnoParam;       ///< announcementパラメータ


/********************************************************************
 * prototypes
 ********************************************************************/

static bool wait_peer_connected(lnapp_conf_t *p_conf);
static bool noise_handshake(lnapp_conf_t *p_conf);
static bool set_short_channel_id(lnapp_conf_t *p_conf);
static bool exchange_init(lnapp_conf_t *p_conf);
static bool exchange_reestablish(lnapp_conf_t *p_conf);
static bool exchange_funding_locked(lnapp_conf_t *p_conf);
static bool send_open_channel(lnapp_conf_t *p_conf, const funding_conf_t *pFundingConf);

static void *thread_recv_start(void *pArg);
static uint16_t recv_peer(lnapp_conf_t *p_conf, uint8_t *pBuf, uint16_t Len, uint32_t ToMsec);

static void *thread_poll_start(void *pArg);
static void poll_ping(lnapp_conf_t *p_conf);
static void poll_funding_wait(lnapp_conf_t *p_conf);
static void poll_normal_operating(lnapp_conf_t *p_conf);
static void send_cnlupd_before_announce(lnapp_conf_t *p_conf);
static bool send_announcement_signatures(lnapp_conf_t *p_conf);

static void *thread_anno_start(void *pArg);
static bool anno_proc(lnapp_conf_t *p_conf);
static bool anno_send(
    lnapp_conf_t *p_conf, uint64_t short_channel_id, const utl_buf_t *p_buf_cnl,
    void *p_cur_cnl, void *p_cur_node, void *p_cur_infocnl, void *p_cur_infonode);
static bool anno_prev_check(uint64_t short_channel_id, uint32_t timestamp);
static bool anno_send_cnl(lnapp_conf_t *p_conf, uint64_t short_channel_id, char type, void *p_cur_infocnl, const utl_buf_t *p_buf_cnl);
static bool anno_send_node(lnapp_conf_t *p_conf, void *p_cur_node, void *p_cur_infonode, const utl_buf_t *p_buf_cnl);

static void load_channel_settings(lnapp_conf_t *p_conf);
static void load_announce_settings(void);

static void recv_idle_proc(lnapp_conf_t *p_conf);

static bool getnewaddress(utl_buf_t *pBuf);
static bool check_unspent_short_channel_id(uint64_t ShortChannelId);

static void show_channel_have_chan(const lnapp_conf_t *pAppConf, cJSON *result);
static void show_channel_fundwait(const lnapp_conf_t *pAppConf, cJSON *result);

static bool handshake_start(lnapp_conf_t *pConf, utl_buf_t *pBuf, const uint8_t *pNodeId);
static bool handshake_recv(lnapp_conf_t *pConf, bool *pCont, utl_buf_t *pBuf);
static void handshake_free(lnapp_conf_t *pConf);


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_global_init(void)
{
    //announcementデフォルト値
    load_announce_settings();
}


void lnapp_conf_init(
    lnapp_conf_t *pAppConf, const uint8_t *pPeerNodeId, void *(*pThreadChannelStart)(void *pArg))
{
    memset(pAppConf, 0x00, sizeof(lnapp_conf_t));

    memcpy(pAppConf->node_id, pPeerNodeId, BTC_SZ_PUBKEY);
    pAppConf->enabled = true;
    pAppConf->ref_counter = 0;
    ln_init(&pAppConf->channel, &mAnnoParam, pPeerNodeId, lnapp_notify_cb, pAppConf);

    pthread_cond_init(&pAppConf->cond, NULL);
    pthread_mutex_init(&pAppConf->mux_th, NULL);
    pthread_mutex_t mux_conf = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
    memcpy(&pAppConf->mux_conf, &mux_conf, sizeof(mux_conf));
    pthread_mutex_init(&pAppConf->mux_send, NULL);

    load_channel_settings(pAppConf);

    pAppConf->p_thread_channel_start = pThreadChannelStart;
}


void lnapp_conf_term(lnapp_conf_t *pAppConf)
{
    ln_term(&pAppConf->channel);

    pthread_cond_destroy(&pAppConf->cond);
    pthread_mutex_destroy(&pAppConf->mux_th);
    pthread_mutex_destroy(&pAppConf->mux_conf);
    pthread_mutex_destroy(&pAppConf->mux_send);

    memset(pAppConf, 0x00, sizeof(lnapp_conf_t));
}


void lnapp_conf_start(
    lnapp_conf_t *pAppConf, bool Initiator, int Sock, const char *pConnStr, uint16_t ConnPort,
    ptarmd_routesync_t Routesync, ln_noise_t Noise)
{
    pAppConf->initiator = Initiator;
    pAppConf->sock = Sock;
    strncpy(pAppConf->conn_str, pConnStr, SZ_CONN_STR);
    pAppConf->conn_port = ConnPort;
    pAppConf->noise = Noise;
    pAppConf->routesync = Routesync;

    pAppConf->active = true;
    pAppConf->flag_recv = 0;
    pAppConf->ping_counter = 1;   //send soon

    pAppConf->funding_waiting = false;
    pAppConf->funding_confirm = 0;

    pAppConf->last_anno_cnl = 0;
    pAppConf->annosig_send_req = false;
    pAppConf->annodb_updated = false;
    pAppConf->annodb_cont = false;
    pAppConf->annodb_stamp = 0;

    pAppConf->feerate_per_kw = 0;

    LIST_INIT(&pAppConf->pong_head);

    pAppConf->err = 0;
    pAppConf->p_errstr = NULL;

    pAppConf->channel.init_flag = 0;
}


void lnapp_conf_stop(lnapp_conf_t *pAppConf)
{
    pAppConf->active = false;

    ponglist_t *p = LIST_FIRST(&pAppConf->pong_head);
    while (p) {
        ponglist_t *p_bak = p;
        p = LIST_NEXT(p, list);
        UTL_DBG_FREE(p_bak);
    }

    UTL_DBG_FREE(pAppConf->p_errstr);
}


bool lnapp_handshake(peer_conn_handshake_t *pConnHandshake)
{
    bool ret = false;

    lnapp_conf_t conf; //dummy
    lnapp_conf_init(&conf, pConnHandshake->conn.node_id, NULL);
    ln_init(&conf.channel, NULL, NULL, NULL, NULL);

    conf.active = true;
    conf.sock = pConnHandshake->sock;
    conf.initiator = pConnHandshake->initiator;

    LOGD("wait peer connected...\n");
    if (!wait_peer_connected(&conf)) {
        goto LABEL_EXIT;
    }

    strcpy(conf.conn_str, pConnHandshake->conn.ipaddr);
    conf.conn_port = pConnHandshake->conn.port;
    conf.routesync = pConnHandshake->conn.routesync;

    if (!noise_handshake(&conf)) {
        ptarmd_nodefail_add(
            conf.node_id, conf.conn_str, conf.conn_port, LN_ADDR_DESC_TYPE_IPV4);
        goto LABEL_EXIT;
    }

    (void)ptarmd_nodefail_get(
        conf.node_id, conf.conn_str, conf.conn_port, LN_ADDR_DESC_TYPE_IPV4, true);

    LOGD("connected peer(sock=%d): ", conf.sock);
    DUMPD(conf.node_id, BTC_SZ_PUBKEY);
    fprintf(stderr, "connected peer: ");
    utl_dbg_dump(stderr, conf.node_id, BTC_SZ_PUBKEY, true);

    memcpy(pConnHandshake->conn.node_id, conf.node_id, BTC_SZ_PUBKEY);
    pConnHandshake->noise = conf.noise;

    ret = true;

LABEL_EXIT:
    ln_term(&conf.channel);
    lnapp_conf_term(&conf);
    return ret;
}


void lnapp_start(lnapp_conf_t *pAppConf)
{
    pthread_mutex_lock(&pAppConf->mux_th);
    if (pAppConf->th) {
        LOGE("fail: ???\n");
    } else {
        pAppConf->active = true;
        pthread_create(&pAppConf->th, NULL, pAppConf->p_thread_channel_start, pAppConf);
    }
    pthread_mutex_unlock(&pAppConf->mux_th);
}


void lnapp_stop(lnapp_conf_t *pAppConf)
{
    LOGD("$$$ stop\n");
    pthread_mutex_lock(&pAppConf->mux_conf);
    if (pAppConf->th) {
        LOGD("stop lnapp: sock=%d\n", pAppConf->sock);
        fprintf(stderr, "stop: ");
        utl_dbg_dump(stderr, pAppConf->node_id, BTC_SZ_PUBKEY, true);
        pAppConf->active = false;
        pthread_cond_signal(&pAppConf->cond);
        LOGD("=========================================\n");
        LOGD("=  CHANNEL THREAD END: %016" PRIx64 " =\n", ln_short_channel_id(&pAppConf->channel));
        LOGD("=========================================\n");
        LOGD("$$$ stopped\n");
    }
    pthread_mutex_unlock(&pAppConf->mux_conf);

    //wait for the thread to finish

    pthread_mutex_lock(&pAppConf->mux_th);
    if (pAppConf->th) {
        pthread_join(pAppConf->th, NULL);
        LOGD("join: lnapp\n");
        pAppConf->th = 0;
    }
    pthread_mutex_unlock(&pAppConf->mux_th);
}


bool lnapp_funding(lnapp_conf_t *pAppConf, const funding_conf_t *pFundingConf)
{
    if ((!pAppConf->active) || !lnapp_is_inited(pAppConf)) {
        //LOGD("This AppConf not working\n");
        return false;
    }

    LOGD("start: Establish\n");
    bool ret = send_open_channel(pAppConf, pFundingConf);

    return ret;
}


/*******************************************
 * 送金
 *******************************************/

//pingを送信した直後で呼ばれることもあるため、1回分まではtrueとみなす。
bool lnapp_check_ponglist(const lnapp_conf_t *pAppConf)
{
    int pongcnt = 0;

    ponglist_t *p = LIST_FIRST(&pAppConf->pong_head);
    while (p != NULL) {
        pongcnt++;
        if (pongcnt > 1) {
            return false;
        }
        p = LIST_NEXT(p, list);
    }
    return true;
}


/*******************************************
 * close関連
 *******************************************/

bool lnapp_close_channel(lnapp_conf_t *pAppConf)
{
    bool ret = false;

    if (!pAppConf->active) {
        //LOGD("This AppConf not working\n");
        return false;
    }

    DBGTRACE_BEGIN

    pthread_mutex_lock(&pAppConf->mux_conf);

    ln_channel_t *p_channel = &pAppConf->channel;

    if (ln_status_is_closing(p_channel)) {
        LOGE("fail: already closing\n");
        goto LABEL_EXIT;
    }

    lnapp_show_channel_param(p_channel, stderr, "close channel", __LINE__);

    const char *p_str;
    if (ln_shutdown_send(p_channel)) {
        p_str = "close: good way(local) start";
    } else {
        p_str = "fail close: good way(local) start";
    }
    ptarmd_eventlog(ln_channel_id(p_channel), p_str);

    ret = true;

LABEL_EXIT:
    pthread_mutex_unlock(&pAppConf->mux_conf);
    DBGTRACE_END

    return ret;
}


bool lnapp_close_channel_force(const uint8_t *pNodeId)
{
    bool ret;
    ln_channel_t channel;

    ln_init(&channel, &mAnnoParam, NULL, NULL, NULL);

    ret = ln_node_search_channel(&channel, pNodeId);
    if (!ret) {
        return false;
    }
    if (ln_status_is_closing(&channel)) {
        LOGE("fail: already closing\n");
        return false;
    }

    LOGD("close: bad way(local): htlc=%d\n", ln_commit_info_local(&channel)->num_htlc_outputs);
    ptarmd_eventlog(ln_channel_id(&channel), "close: bad way(local)");
    (void)monitor_close_unilateral_local(&channel, NULL);

    return true;
}


/*******************************************
 * fee関連
 *******************************************/

void lnapp_set_feerate(lnapp_conf_t *pAppConf, uint32_t FeeratePerKw)
{
    if ((pAppConf->flag_recv & M_FLAGRECV_END) == 0) {
        return;
    }

    if ((FeeratePerKw >= LN_FEERATE_PER_KW_MIN) && (pAppConf->feerate_per_kw != FeeratePerKw)) {
        pAppConf->feerate_per_kw = FeeratePerKw;    //use #recv_idle_proc()
        LOGD("feerate_per_kw=%" PRIu32 "\n", pAppConf->feerate_per_kw);
    }
}


/*******************************************
 * その他
 *******************************************/

bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id)
{
    if (!pAppConf->active) {
        //LOGD("This AppConf not working\n");
        return false;
    }

    return (short_channel_id == ln_short_channel_id(&pAppConf->channel));
}


void lnapp_show_channel(const lnapp_conf_t *pAppConf, cJSON *pResult)
{
    const ln_channel_t *p_channel = &pAppConf->channel;
    char str[256];

    cJSON *result = cJSON_CreateObject();
    if (pAppConf->active) {
        if (pAppConf->initiator) {
            cJSON_AddItemToObject(result, "role", cJSON_CreateString("client"));
        } else {
            cJSON_AddItemToObject(result, "role", cJSON_CreateString("server"));
        }
    } else {
        cJSON_AddItemToObject(result, "role", cJSON_CreateString("none"));
    }
    cJSON_AddItemToObject(result, "status", cJSON_CreateString(ln_status_string(p_channel)));
    //peer node_id
    utl_str_bin2str(str, ln_remote_node_id(p_channel), BTC_SZ_PUBKEY);
    cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));

    if (ln_short_channel_id(p_channel)) {
        show_channel_have_chan(pAppConf, result);
    } else if (pAppConf->funding_waiting) {
        show_channel_fundwait(pAppConf, result);
    } else {
        //
    }

    if ((pAppConf->err != 0) && (pAppConf->p_errstr != NULL)) {
        cJSON_AddItemToObject(result, "last_app_errmsg", cJSON_CreateString(pAppConf->p_errstr));
    }
    if (ln_err(p_channel) != 0) {
        cJSON_AddItemToObject(result, "last_lib_errmsg", cJSON_CreateString(ln_errmsg(p_channel)));
    }
    cJSON_AddItemToArray(pResult, result);
}


/** ln_channel_t内容表示(デバッグ用)
 *
 */
void lnapp_show_channel_param(const ln_channel_t *pChannel, FILE *fp, const char *msg, int line)
{
    LOGD("=(%s:%d)=============================================\n", msg, line);
    if (ln_short_channel_id(pChannel)) {
        LOGD("short_channel_id: %016" PRIx64 "\n", ln_short_channel_id(pChannel));
        LOGD("local_msat:  %" PRIu64 "\n", ln_local_msat(pChannel));
        LOGD("remote_msat: %" PRIu64 "\n", ln_remote_msat(pChannel));
        for (uint16_t lp = 0; lp < LN_UPDATE_MAX; lp++) {
            const ln_update_t *p_update = ln_update(pChannel, lp);
            if (!LN_UPDATE_USED(p_update)) continue;
            if (p_update->type != LN_UPDATE_TYPE_ADD_HTLC) continue;
            const ln_htlc_t *p_htlc = ln_htlc(pChannel, p_update->type_specific_idx);
            LOGD("  HTLC[%u]\n", lp);
            LOGD("    htlc id= %" PRIu64 "\n", p_htlc->id);
            LOGD("    cltv_expiry= %" PRIu32 "\n", p_htlc->cltv_expiry);
            LOGD("    amount_msat= %" PRIu64 "\n", p_htlc->amount_msat);
            if (!p_htlc->neighbor_short_channel_id) continue;
            if (LN_UPDATE_OFFERED(p_update)) {
                LOGD("    from:        HTLC id=%" PRIx64 ", %016" PRIx64 "\n",
                    p_htlc->neighbor_id, p_htlc->neighbor_short_channel_id);
            } else if (LN_UPDATE_RECEIVED(p_update)) {
                LOGD("    to:          HTLC id=%" PRIx64 ", %016" PRIx64 "\n",
                    p_htlc->neighbor_id, p_htlc->neighbor_short_channel_id);
            }
        }

        //コンソールログ
        fprintf(fp, "=%s:%d==================\n", msg, line);
        fprintf(fp, "short_channel_id: %016" PRIx64 "\n", ln_short_channel_id(pChannel));
        fprintf(fp, "local_msat:  %" PRIu64 "\n", ln_local_msat(pChannel));
        fprintf(fp, "remote_msat: %" PRIu64 "\n", ln_remote_msat(pChannel));
    } else {
        LOGD("no channel\n");
    }
    LOGD("=(%s:%d)=============================================\n", msg, line);
}


bool lnapp_is_active(const lnapp_conf_t *pAppConf)
{
    return pAppConf->active;
}


bool lnapp_is_connected(const lnapp_conf_t *pAppConf)
{
    return (pAppConf->flag_recv & M_FLAGRECV_INIT) == M_FLAGRECV_INIT;
}


bool lnapp_is_inited(const lnapp_conf_t *pAppConf)
{
    return (pAppConf->flag_recv & M_FLAGRECV_END) == M_FLAGRECV_END;
}


/********************************************************************
 * [THREAD]channel
 ********************************************************************/

/** channel thread entry point
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
void *lnapp_thread_channel_start(void *pArg)
{
    bool    ret;
    int     retval;
    bool    b_channelreestablished = false;

    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;
    ln_channel_t *p_channel = &p_conf->channel;

    LOGD("[THREAD]ln_channel_t initialize\n");

    pthread_t   th_recv;        //peer受信
    pthread_t   th_poll;        //トランザクション監視
    pthread_t   th_anno;        //announce

    p_conf->feerate_per_kw = ln_feerate_per_kw(p_channel);

    ln_status_t stat = ln_status_get(p_channel);

    //peer受信スレッド
    pthread_create(&th_recv, NULL, &thread_recv_start, p_conf);

    //監視スレッド
    pthread_create(&th_poll, NULL, &thread_poll_start, p_conf);

    //announceスレッド
    pthread_create(&th_anno, NULL, &thread_anno_start, p_conf);

    //BOLTメッセージ
    //  以下のパターンがあり得る
    //      - チャネル関係にないnode_idと接続した
    //          init交換
    //      - チャネル関係にある相手と接続した
    //          init交換
    //          channel_reestablish交換
    //          (funding_locked交換)

    //init送受信
    ret = exchange_init(p_conf);
    if (ret) {
        LOGD("exchange: init\n");
    } else {
        LOGE("fail: exchange init\n");
        goto LABEL_JOIN;
    }
    p_conf->flag_recv |= M_FLAGRECV_INIT_EXCHANGED;

    //送金先
    if (ln_shutdown_scriptpk_local(p_channel)->len == 0) {
        utl_buf_t buf = UTL_BUF_INIT;
        ret = getnewaddress(&buf);
        if (!ret) {
            LOGE("fail: create address\n");
            goto LABEL_JOIN;
        }
        ln_shutdown_set_vout_addr(p_channel, &buf);
        utl_buf_free(&buf);
    }

    // Establishチェック
    if (stat >= LN_STATUS_ESTABLISH) {
        // DBにchannel_id登録済み
        // →funding_txは展開されている
        LOGD("have channel\n");

        if (!ln_status_is_closing(p_channel)) {
            if (stat == LN_STATUS_NORMAL) {
                // funding_txはブロックに入ってminimum_depth以上経過している
                LOGD("$$$ Established\n");
                ln_establish_free(p_channel);
            } else {
                // funding_txはminimum_depth未満
                LOGD("$$$ funding_tx in mempool\n");
                TXIDD(ln_funding_info_txid(&p_channel->funding_info));

                p_conf->funding_waiting = true;
            }

            ln_node_addr_t conn_addr;
            ret = utl_addr_ipv4_str2bin(conn_addr.addr, p_conf->conn_str);
            if (ret) {
                conn_addr.type = LN_ADDR_DESC_TYPE_IPV4;
                conn_addr.port = p_conf->conn_port;
                ln_last_connected_addr_set(p_channel, &conn_addr);
            }

            ln_channel_reestablish_before(p_channel);
            b_channelreestablished = exchange_reestablish(p_conf);
            if (b_channelreestablished) {
                LOGD("exchange: channel_reestablish\n");
            } else {
                LOGE("fail: exchange channel_reestablish\n");
                goto LABEL_JOIN;
            }
        } else {
            const char *p_str = ln_status_string(p_channel);
            LOGD("$$$ now closing: %s\n", p_str);
        }
    } else {
        // channel_idはDB未登録
        // →ユーザの指示待ち
        LOGD("no channel_id\n");
    }

    if (!p_conf->active) {
        LOGE("fail: loop ended: %016" PRIx64 "\n", ln_short_channel_id(p_channel));
        goto LABEL_JOIN;
    }

    //force send ping
    poll_ping(p_conf);

    if (ln_funding_locked_check_need(p_channel)) {
        //funding_locked交換
        ret = exchange_funding_locked(p_conf);
        if (!ret) {
            LOGE("fail: exchange funding_locked\n");
            goto LABEL_JOIN;
        }
    }

    p_conf->annosig_send_req = ln_open_channel_announce(p_channel);

    if (b_channelreestablished) {
        ln_channel_reestablish_after(p_channel);
    }

    if (ln_is_shutdown_sent(p_channel)) {
        //BOLT02
        //  upon reconnection:
        //    if it has sent a previous shutdown:
        //      MUST retransmit shutdown.
        if (!ln_shutdown_send(p_channel)) {
            LOGE("fail: shutdown\n");
        }
    }

    //初期化完了
    LOGD("*** message inited ***\n");
    p_conf->flag_recv |= M_FLAGRECV_END;

    // send `channel_update` for private/before publish channel
    send_cnlupd_before_announce(p_conf);

#ifdef USE_GQUERY
    ret = ln_query_channel_range_send(p_channel, 0, UINT32_MAX);
    if (ret) {
        (void)ln_gossip_timestamp_filter_send(p_channel);
    } else {
        LOGE("fail: ln_query_channel_range_send\n");
    }
#endif  //USE_GQUERY

    {
        // method: connected
        // $1: short_channel_id
        // $2: node_id
        // $3: peer_id
        // $4: recieved_localfeatures
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_channel));
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
        char peer_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(peer_id, p_conf->node_id, BTC_SZ_PUBKEY);
        char param[M_SZ_SCRIPT_PARAM];
        snprintf(param, sizeof(param), "%s %s "
                    "%s %d",
                    str_sci, node_id,
                    peer_id,
                    p_channel->lfeature_remote);
        ptarmd_call_script(PTARMD_EVT_CONNECTED, param);

        FILE *fp = fopen(FNAME_CONN_LOG, "a");
        if (fp) {
            char time[UTL_SZ_TIME_FMT_STR + 1];
            fprintf(fp, "[%s]OK: %s@%s:%" PRIu16 "\n", utl_time_str_time(time), peer_id, p_conf->conn_str, p_conf->conn_port);
            fclose(fp);
        }
    }

    pthread_mutex_lock(&p_conf->mux_conf);
    while (p_conf->active) {
        LOGD("loop...\n");

        //mainloop待ち合わせ(*2)
        pthread_cond_wait(&p_conf->cond, &p_conf->mux_conf);
    }
    pthread_mutex_unlock(&p_conf->mux_conf);

LABEL_JOIN:
    LOGD("stop threads...\n");
    pthread_join(th_recv, NULL);
    pthread_join(th_poll, NULL);
    pthread_join(th_anno, NULL);
    LOGD("join: recv, poll, anno\n");

    LOGD("close sock=%d...\n", p_conf->sock);
    retval = close(p_conf->sock);
    if (retval < 0) {
        LOGD("socket close: %s", strerror(errno));
    }

    LOGD("$$$ stop channel[%016" PRIx64 "]\n", ln_short_channel_id(p_channel));

    // method: disconnect
    // $1: short_channel_id
    // $2: node_id
    // $3: peer_id
    char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
    ln_short_channel_id_string(str_sci, ln_short_channel_id(p_channel));
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
    char peer_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_str_bin2str(peer_id, p_conf->node_id, BTC_SZ_PUBKEY);
    char param[M_SZ_SCRIPT_PARAM];
    snprintf(param, sizeof(param), "%s %s "
                "%s",
                str_sci, node_id,
                peer_id);
    ptarmd_call_script(PTARMD_EVT_DISCONNECTED, param);

    //クリア
    lnapp_conf_stop(p_conf);

    //XXX:
    p_conf->sock = -1;

    lnapp_manager_free_node_ref(p_conf);

    LOGD("[exit]lnapp thread\n");
    return NULL;
}


/** channel thread entry point
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
void *lnapp_thread_channel_origin_start(void *pArg)
{
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;

    LOGD("\n");

    //pthread_mutex_lock(&p_conf->mux_conf);
    while (p_conf->active) {
        ln_idle_proc_origin(&p_conf->channel);
        utl_thread_msleep(M_WAIT_RECV_TO_MSEC); //XXX: we should use `pthread_cond_wait`
    }
    //pthread_mutex_unlock(&p_conf->mux_conf);

    lnapp_conf_stop(p_conf);
    lnapp_manager_free_node_ref(p_conf);
    LOGD("[exit]lnapp origin thread\n");
    return NULL;
}


/********************************************************************
 * private functions
 ********************************************************************/

//peer(server)への接続確立を待つ
static bool wait_peer_connected(lnapp_conf_t *p_conf)
{
    //socketへの書き込みが可能になり、かつ
    // エラーが発生していないことを確認する

    struct pollfd fds;
    fds.fd = p_conf->sock;
    fds.events = POLLOUT;
    int polr = poll(&fds, 1, M_WAIT_RECV_TO_MSEC);
    if (polr <= 0) {
        LOGE("fail poll: %s\n", strerror(errno));
        return false;
    }

    int optval;
    socklen_t optlen = sizeof(optval);
    int retval = getsockopt(p_conf->sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
    if (retval != 0) {
        LOGE("fail getsockopt: %s\n", strerror(errno));
        return false;
    }
    if (optval) {
        LOGE("fail getsockopt: optval: %s\n", strerror(optval));
        return false;
    }

    return true;
}


/** Noise Protocol Handshake(同期処理)
 *
 */
static bool noise_handshake(lnapp_conf_t *p_conf)
{
    bool result = false;
    bool ret;
    utl_buf_t buf = UTL_BUF_INIT;
    uint8_t rbuf[66];
    bool b_cont;
    uint16_t len_msg;

    if (p_conf->initiator) {
        //initiatorはnode_idを知っている

        //send: act one
        ret = handshake_start(p_conf, &buf, p_conf->node_id);
        if (!ret) {
            LOGE("fail: ln_handshake_start\n");
            goto LABEL_EXIT;
        }
        LOGD("** SEND act one **\n");
        ret = lnapp_send_peer_raw(p_conf, &buf);
        if (!ret) {
            LOGE("fail: socket write\n");
            goto LABEL_EXIT;
        }

        //recv: act two
        LOGD("** RECV act two... **\n");
        len_msg = recv_peer(p_conf, rbuf, 50, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            goto LABEL_EXIT;
        }
        LOGD("** RECV act two ! **\n");
        utl_buf_free(&buf);
        utl_buf_alloccopy(&buf, rbuf, 50);
        ret = handshake_recv(p_conf, &b_cont, &buf);
        if (!ret || b_cont) {
            LOGE("fail: ln_handshake_recv1\n");
            goto LABEL_EXIT;
        }
        //send: act three
        LOGD("** SEND act three **\n");
        ret = lnapp_send_peer_raw(p_conf, &buf);
        if (!ret) {
            LOGE("fail: socket write\n");
            goto LABEL_EXIT;
        }

        result = true;
   } else {
        //responderはnode_idを知らない

        //recv: act one
        ret = handshake_start(p_conf, &buf, NULL);
        if (!ret) {
            LOGE("fail: ln_handshake_start\n");
            goto LABEL_EXIT;
        }
        LOGD("** RECV act one... **\n");
        len_msg = recv_peer(p_conf, rbuf, 50, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            goto LABEL_EXIT;
        }
        LOGD("** RECV act one ! **\n");
        utl_buf_alloccopy(&buf, rbuf, 50);
        ret = handshake_recv(p_conf, &b_cont, &buf);
        if (!ret || !b_cont) {
            LOGE("fail: ln_handshake_recv1\n");
            goto LABEL_EXIT;
        }
        //send: act two
        LOGD("** SEND act two **\n");
        ret = lnapp_send_peer_raw(p_conf, &buf);
        if (!ret) {
            LOGE("fail: socket write\n");
            goto LABEL_EXIT;
        }

        //recv: act three
        LOGD("** RECV act three... **\n");
        len_msg = recv_peer(p_conf, rbuf, 66, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            goto LABEL_EXIT;
        }
        LOGD("** RECV act three ! **\n");
        utl_buf_free(&buf);
        utl_buf_alloccopy(&buf, rbuf, 66);
        ret = handshake_recv(p_conf, &b_cont, &buf);
        if (!ret || b_cont) {
            LOGE("fail: ln_handshake_recv2\n");
            goto LABEL_EXIT;
        }

        if (buf.len != BTC_SZ_PUBKEY) {
            LOGE("fail: peer node_id\n");
            goto LABEL_EXIT;
        }

        memcpy(p_conf->node_id, buf.buf, BTC_SZ_PUBKEY);

        result = true;
    }

LABEL_EXIT:
    LOGD("noise handshake: %d\n", result);
    utl_buf_free(&buf);
    handshake_free(p_conf);

    return result;
}


/** blockchainからのshort_channel_id計算および保存
 *
 * @retval  true    OK
 */
static bool set_short_channel_id(lnapp_conf_t *p_conf)
{
    int32_t bheight = 0;
    int32_t bindex = 0;
    uint8_t mined_hash[BTC_SZ_HASH256];
    bool ret = btcrpc_get_short_channel_param(
        ln_remote_node_id(&p_conf->channel), &bheight, &bindex, mined_hash,
        ln_funding_info_txid(&p_conf->channel.funding_info));
    if (ret) {
        LOGD("bindex=%d, bheight=%d\n", bindex, bheight);
        ln_short_channel_id_set_param(&p_conf->channel, bheight, bindex);
        ln_funding_blockhash_set(&p_conf->channel, mined_hash);
        ln_db_forward_add_htlc_create(ln_short_channel_id(&p_conf->channel));
        ln_db_forward_del_htlc_create(ln_short_channel_id(&p_conf->channel));
        ln_db_channel_owned_save(ln_short_channel_id(&p_conf->channel));
        LOGD("short_channel_id = %016" PRIx64 "(%d)\n", ln_short_channel_id(&p_conf->channel), ret);
    }

    return ret;
}


/** init交換
 *
 * @retval  true    init交換完了
 */
static bool exchange_init(lnapp_conf_t *p_conf)
{
    if (!ln_init_send(&p_conf->channel, p_conf->routesync == PTARMD_ROUTESYNC_INIT, true)) {
        LOGE("fail: create\n");
        return false;
    }

    //コールバックでのINIT受信通知待ち
    LOGD("wait: init\n");
    uint32_t count = M_WAIT_RESPONSE_MSEC / M_WAIT_RECV_MSG_MSEC;
    while (p_conf->active && (count > 0) && ((p_conf->flag_recv & M_FLAGRECV_INIT) == 0)) {
        utl_thread_msleep(M_WAIT_RECV_MSG_MSEC);
        count--;
    }
    LOGD("loop:%d, count:%d, flag_recv=%02x\n", p_conf->active, count, p_conf->flag_recv);

    if (ln_announcement_is_gossip_query(&p_conf->channel)) {
        LOGD("$$$ gossip_queries\n");

        //未送信のものはすべて送信するか、今までのものは全部送信しないのか -> 後者を採用
        ln_db_annoinfos_add_node_id(p_conf->node_id);
    } else {
        bool del_sendinfo = ln_need_init_routing_sync(&p_conf->channel);
        LOGD("$$$ initial_routing_sync local=%s, remote=%s\n",
            ((p_conf->routesync == PTARMD_ROUTESYNC_INIT) ? "YES" : "no"),
            (del_sendinfo) ? "YES" : "no");
        if (del_sendinfo) {
            //send all range

            //annoinfo情報削除(node_id指定, short_channel_idすべて)
            LOGD("remove announcement sent info\n");
            ln_db_annoinfos_del_node_id(p_conf->node_id, NULL, 0);
        } else {
            //only new received
            ln_db_annoinfos_add_node_id(p_conf->node_id);
        }
    }
    return p_conf->active && ((p_conf->flag_recv & M_FLAGRECV_INIT) != 0);
}


/** channel_reestablish交換
 *
 * @retval  true    channel_reestablish交換完了
 */
static bool exchange_reestablish(lnapp_conf_t *p_conf)
{
    if (!ln_channel_reestablish_send(&p_conf->channel)) {
        LOGE("fail: create\n");
        return false;
    }

    //コールバックでのchannel_reestablish受信通知待ち
    LOGD("wait: channel_reestablish\n");
    uint32_t count = M_WAIT_CHANREEST_MSEC / M_WAIT_RECV_MSG_MSEC;
    while (p_conf->active && (count > 0) && ((p_conf->flag_recv & M_FLAGRECV_REESTABLISH) == 0)) {
        utl_thread_msleep(M_WAIT_RECV_MSG_MSEC);
        count--;
    }
    LOGD("loop:%d, count:%d, flag_recv=%02x\n", p_conf->active, count, p_conf->flag_recv);
    return p_conf->active && ((p_conf->flag_recv & M_FLAGRECV_REESTABLISH) != 0);
}


/** funding_locked交換
 *
 * @retval  true    funding_locked交換完了
 */
static bool exchange_funding_locked(lnapp_conf_t *p_conf)
{
    if (!ln_funding_locked_send(&p_conf->channel)) {
        LOGE("fail: send\n");
        return false;
    }

    //コールバックでのfunding_locked受信通知待ち
    LOGD("wait: funding_locked\n");
    while (p_conf->active && ((p_conf->flag_recv & M_FLAGRECV_FUNDINGLOCKED) == 0)) {
        utl_thread_msleep(M_WAIT_RECV_MSG_MSEC);
    }
    LOGD("exchange: funding_locked\n");

    //set short_channel_id
    (void)set_short_channel_id(p_conf);

    // method: established
    // $1: short_channel_id
    // $2: node_id
    // $3: local_msat
    // $4: funding_txid
    char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
    char txidstr[BTC_SZ_TXID * 2 + 1];
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    char param[M_SZ_SCRIPT_PARAM];
    uint64_t total_amount = ln_node_total_msat();

    ln_short_channel_id_string(str_sci, ln_short_channel_id(&p_conf->channel));
    utl_str_bin2str_rev(txidstr, ln_funding_info_txid(&p_conf->channel.funding_info), BTC_SZ_TXID);
    utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
    snprintf(param, sizeof(param), "%s %s "
                "%" PRIu64 " "
                "%s",
                str_sci, node_id,
                total_amount,
                txidstr);
    ptarmd_call_script(PTARMD_EVT_ESTABLISHED, param);

    return true;
}


/** open_channel送信
 *
 */
static bool send_open_channel(lnapp_conf_t *p_conf, const funding_conf_t *pFundingConf)
{
    ln_fundin_t fundin;
    utl_buf_init(&fundin.change_spk);

    //Establish開始
    LOGD("  funding_sat: %" PRIu64 "\n", pFundingConf->funding_sat);
    LOGD("  push_msat: %" PRIu64 "\n", pFundingConf->push_msat);

    bool ret = getnewaddress(&fundin.change_spk);
    if (!ret) {
        LOGE("fail: getnewaddress\n");
        return false;
    }

    bool unspent;
#if defined(USE_BITCOIND)
    //事前にfund-in txがunspentかどうかチェックしようとしている。
    //SPVの場合は1st Layerの処理も内部で行うので、チェック不要。
    ret = btcrpc_check_unspent(NULL, &unspent, &fundin.amount, pFundingConf->txid, pFundingConf->txindex);
    LOGD("ret=%d, unspent=%d, fundin.amount=%" PRIu64 "\n", ret, unspent, fundin.amount);
#elif defined(USE_BITCOINJ)
    //内部でfund-in txを生成するため、チェック不要
    unspent = true;
    ret = true;
#endif
    if (ret && unspent) {
        uint32_t feerate_kw;
        if (pFundingConf->feerate_per_kw == 0) {
            feerate_kw = monitor_btc_feerate_per_kw();
        } else {
            feerate_kw = pFundingConf->feerate_per_kw;
        }
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_kw);

#if defined(USE_BITCOIND)
        //bitcoindはptarmdがfunding_txを作るため、fee計算する
        uint64_t estfee = ln_estimate_fundingtx_fee(feerate_kw);
        LOGD("estimate funding_tx fee: %" PRIu64 "\n", estfee);
        if (fundin.amount < pFundingConf->funding_sat + estfee) {
            //amountが足りないと思われる
            LOGE("fail: amount too short\n");
            LOGD("  %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", fundin.amount, pFundingConf->funding_sat, estfee);
            return false;
        }

        memcpy(fundin.txid, pFundingConf->txid, BTC_SZ_TXID);
        fundin.index = pFundingConf->txindex;
#elif defined(USE_BITCOINJ)
        //funding_txをbitcoinjが作るため、fundin未使用
        memset(&fundin, 0, sizeof(fundin));
#endif

        pthread_mutex_lock(&p_conf->mux_conf);
        ret = ln_open_channel_send(&p_conf->channel,
                        &fundin,
                        pFundingConf->funding_sat,
                        pFundingConf->push_msat,
                        feerate_kw,
                        pFundingConf->priv_channel);
        pthread_mutex_unlock(&p_conf->mux_conf);
        if (ret) {
            LOGD("SEND: open_channel\n");
        } else {
            LOGE("fail: open_channel\n");
        }
    } else {
        LOGD("through: check_unspent: ");
        TXIDD(pFundingConf->txid);
    }

    return ret;
}


/********************************************************************
 * [THREAD]receive
 ********************************************************************/

/** receive thread entry point
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
static void *thread_recv_start(void *pArg)
{
    utl_buf_t buf_recv = UTL_BUF_INIT;
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;

    LOGD("[THREAD]recv initialize: %d\n", p_conf->active);

    //init受信待ちの準備時間を設ける
    utl_thread_msleep(M_WAIT_RECV_THREAD_MSEC);

    while (p_conf->active) {
        bool ret = true;

        //noise packet データ長
        uint8_t head[LN_SZ_NOISE_HEADER];
        uint16_t len = recv_peer(p_conf, head, LN_SZ_NOISE_HEADER, 0);
        if (len == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            lnapp_stop_threads(p_conf);
            break;
        }
        assert(len == LN_SZ_NOISE_HEADER);
        if (len == LN_SZ_NOISE_HEADER) {
            len = ln_noise_dec_len(&p_conf->noise, head, len);
        } else {
            break;
        }

        utl_buf_alloc(&buf_recv, len);
        uint16_t len_msg = recv_peer(p_conf, buf_recv.buf, len, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            lnapp_stop_threads(p_conf);
            break;
        }
        if (len_msg == len) {
            buf_recv.len = len;
            ret = ln_noise_dec_msg(&p_conf->noise, &buf_recv);
            if (!ret) {
                LOGD("DECODE: loop end\n");
                lnapp_stop_threads(p_conf);
            }
        } else {
            break;
        }

        if (ret) {
            //LOGD("type=%02x%02x\n", buf_recv.buf[0], buf_recv.buf[1]);
            pthread_mutex_lock(&p_conf->mux_conf);
            uint16_t type = utl_int_pack_u16be(buf_recv.buf);
            LOGD("[RECV]type=%04x(%s): sock=%d, Len=%d\n", type, ln_msg_name(type), p_conf->sock, buf_recv.len);
            ret = ln_recv(&p_conf->channel, buf_recv.buf, buf_recv.len);
            //LOGD("ln_recv() result=%d\n", ret);
            if (!ret) {
                LOGD("DISC: fail recv message\n");
                lnapp_close_channel_force(ln_remote_node_id(&p_conf->channel));
                lnapp_stop_threads(p_conf);
            }
            if ((p_conf->active) && (type == MSGTYPE_INIT)) {
                LOGD("$$$ init exchange...\n");
                uint32_t count = M_WAIT_RESPONSE_MSEC / M_WAIT_RECV_MSG_MSEC;
                while (p_conf->active && (count > 0) && ((p_conf->flag_recv & M_FLAGRECV_INIT_EXCHANGED) == 0)) {
                    utl_thread_msleep(M_WAIT_RECV_MSG_MSEC);
                    count--;
                }
                if (count > 0) {
                    LOGD("$$$ init exchanged\n");
                } else {
                    LOGE("fail: init exchange timeout\n");
                    lnapp_stop_threads(p_conf);
                }
            }
            //LOGD("mux_conf: end\n");
            pthread_mutex_unlock(&p_conf->mux_conf);
        }
        utl_buf_free(&buf_recv);
    }

    LOGD("[exit]recv thread\n");

    return NULL;
}


/** 受信処理
 *
 * @param[in]   ToMsec      受信タイムアウト(0の場合、タイムアウト無し)
 * @note
 *      - called by #thread_recv_start(), #noise_handshake()
 */
static uint16_t recv_peer(lnapp_conf_t *p_conf, uint8_t *pBuf, uint16_t Len, uint32_t ToMsec)
{
    struct pollfd fds;
    uint16_t len = 0;
    ToMsec /= M_WAIT_RECV_TO_MSEC;

    //LOGD("sock=%d\n", p_conf->sock);

    while (p_conf->active && (Len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLIN;
        int polr = poll(&fds, 1, M_WAIT_RECV_TO_MSEC);
        if (polr < 0) {
            LOGD("poll: %s\n", strerror(errno));
            break;
        } else if (polr == 0) {
            //timeout

            // 受信アイドル処理
            recv_idle_proc(p_conf);

            if (ToMsec > 0) {
                ToMsec--;
                if (ToMsec == 0) {
                    LOGD("Timeout\n");
                    break;
                }
            }
        } else {
            if (fds.revents & POLLIN) {
                ssize_t n = read(p_conf->sock, pBuf, Len);
                if (n > 0) {
                    Len -= n;
                    len += n;
                    pBuf += n;
                } else if (n == 0) {
                    LOGE("fail: timeout(len=%d, reqLen=%d)\n", len, Len);
                    break;
                } else {
                    LOGE("fail: %s(%016" PRIx64 ")\n", strerror(errno), ln_short_channel_id(&p_conf->channel));
                    len = 0;
                    break;
                }
            }
        }
    }

    return len;
}


/********************************************************************
 * [THREAD]polling
 ********************************************************************/

/** polling thread entry point
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
static void *thread_poll_start(void *pArg)
{
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;

    LOGD("[THREAD]poll initialize: %d\n", p_conf->active);

    while (p_conf->active) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < M_WAIT_POLL_SEC; lp++) {
            sleep(1);
            if (!p_conf->active) {
                break;
            }
        }

        if ((p_conf->flag_recv & M_FLAGRECV_INIT) == 0) {
            //まだ接続していない
            continue;
        }

        poll_ping(p_conf);

        if (ln_status_get(&p_conf->channel) < LN_STATUS_ESTABLISH) {
            //fundingしていない
            continue;
        }

        uint32_t bak_conf = p_conf->funding_confirm;
        bool b_get = btcrpc_get_confirmations(&p_conf->funding_confirm, ln_funding_info_txid(&p_conf->channel.funding_info));
        if (b_get) {
            if (bak_conf != p_conf->funding_confirm) {
                const uint8_t *oldhash = ln_funding_blockhash(&p_conf->channel);
                if (utl_mem_is_all_zero(oldhash, BTC_SZ_HASH256)) {
                    int32_t bheight = 0;
                    int32_t bindex = 0;
                    uint8_t mined_hash[BTC_SZ_HASH256];
                    bool ret = btcrpc_get_short_channel_param(
                        ln_remote_node_id(&p_conf->channel), &bheight, &bindex, mined_hash, ln_funding_info_txid(&p_conf->channel.funding_info));
                    if (ret) {
                        //mined block hash
                        ln_funding_blockhash_set(&p_conf->channel, mined_hash);
                    }
                }

                LOGD2("***********************************\n");
                LOGD2("* CONFIRMATION: %d\n", p_conf->funding_confirm);
                LOGD2("*    funding_txid: ");
                TXIDD(ln_funding_info_txid(&p_conf->channel.funding_info));
                LOGD2("***********************************\n");
            }
        } else {
            //LOGD("funding_tx not detect: ");
            //TXIDD(ln_funding_info_txid(&p_conf->channel));
        }

        //funding_tx
        if (p_conf->funding_waiting) {
            //funding_tx確定待ち(確定後はEstablishシーケンスの続きを行う)
            poll_funding_wait(p_conf);
        } else {
            //Normal Operation中
            poll_normal_operating(p_conf);
        }

        if (!send_announcement_signatures(p_conf)) {
            break;
        }
    }

    LOGD("[exit]poll thread\n");

    return NULL;
}


static void poll_ping(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    bool sendping = false;
    int pongcnt = 0;

    //未送受信の状態が続いたらping送信する
    p_conf->ping_counter--;
    if (p_conf->ping_counter <= 0) {
        //check missing pong
        ponglist_t *p = LIST_FIRST(&p_conf->pong_head);
        while (p != NULL) {
            pongcnt++;
            //LOGD("  [%d]%" PRIu16 "\n", pongcnt, p->num_pong_bytes);
            p = LIST_NEXT(p, list);
        }
        if (pongcnt > 0) {
            LOGD("ping: missing pong=%d\n", pongcnt);
        }
        if (pongcnt < M_MISSING_PONG) {
            sendping = true;
        } else {
            LOGE("fail: too many missing pong\n");
            lnapp_stop_threads(p_conf);
        }
    }
    if (sendping) {
        uint8_t pinglen;
        uint8_t ponglen;

        // https://github.com/lightningnetwork/lightning-rfc/issues/373
        btc_rng_rand(&ponglen, sizeof(ponglen));
        btc_rng_rand(&pinglen, sizeof(pinglen));
        //add head num_pong_bytes
        ponglist_t *pl = (ponglist_t *)UTL_DBG_MALLOC(sizeof(ponglist_t));
        pl->num_pong_bytes = ponglen;
        //LOGD("   add pong bytes=%" PRIu16 "\n", ponglen);
        LIST_INSERT_HEAD(&p_conf->pong_head, pl, list);
        p_conf->ping_counter = M_PING_CNT;
        if (!ln_ping_send(&p_conf->channel, pinglen, ponglen)) {
            LOGE("fail: send ping\n");
            lnapp_stop_threads(p_conf);
            return;
        }
    }

    //DBGTRACE_END
}


//funding_tx確定待ち
static void poll_funding_wait(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    if (p_conf->funding_confirm >= ln_funding_info_minimum_depth(&p_conf->channel.funding_info)) {
        LOGD("confirmation OK: %d\n", p_conf->funding_confirm);
        //funding_tx確定
        bool ret = set_short_channel_id(p_conf);
        if (ret) {
            ret = exchange_funding_locked(p_conf);
            assert(ret);

            // send `channel_update` for private/before publish channel
            send_cnlupd_before_announce(p_conf);

            char close_addr[BTC_SZ_ADDR_STR_MAX + 1];
            ret = btc_keys_spk2addr(close_addr, ln_shutdown_scriptpk_local(&p_conf->channel));
            if (!ret) {
                utl_str_bin2str(close_addr,
                        ln_shutdown_scriptpk_local(&p_conf->channel)->buf,
                        ln_shutdown_scriptpk_local(&p_conf->channel)->len);
            }

            char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
            ln_short_channel_id_string(str_sci, ln_short_channel_id(&p_conf->channel));
            ptarmd_eventlog(ln_channel_id(&p_conf->channel),
                    "funding_locked: short_channel_id=%s, close_addr=%s",
                    str_sci, close_addr);

            p_conf->funding_waiting = false;
        } else {
            LOGE("fail: set_short_channel_id()\n");
        }
    } else {
        LOGD("confirmation waiting...: %d/%d\n",
            p_conf->funding_confirm, ln_funding_info_minimum_depth(&p_conf->channel.funding_info));
    }

    //DBGTRACE_END
}


static bool send_announcement_signatures(lnapp_conf_t *p_conf)
{
    //announcement_signatures
    //  監視周期によっては funding_confirmが minimum_depth と M_ANNOSIGS_CONFIRMの
    //  両方を満たす可能性があるため、先に poll_funding_wait()を行って pChannel->cnl_anno の準備を済ませる。
    //  BOLT#7: announcement_signaturesは最低でも 6confirmations必要
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#requirements
    if (!p_conf->annosig_send_req) return true;
    if (p_conf->funding_confirm < LN_ANNOSIGS_CONFIRM) return true;
    if (p_conf->funding_confirm <
        ln_funding_info_minimum_depth(&p_conf->channel.funding_info)) return true;

    pthread_mutex_lock(&p_conf->mux_conf);
    bool ret = ln_announcement_signatures_send(&p_conf->channel);
    if (!ret) {
        LOGE("fail: create announcement_signatures\n");
        lnapp_stop_threads(p_conf);
    }
    pthread_mutex_unlock(&p_conf->mux_conf);
    p_conf->annosig_send_req = false;
    return ret;
}


//Normal Operation中
static void poll_normal_operating(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    bool ret = ln_status_load(&p_conf->channel);
    if (!ret || ln_status_is_closed(&p_conf->channel)) {
        //ループ解除
        LOGD("funding_tx is spent: %016" PRIx64 "\n", ln_short_channel_id(&p_conf->channel));
        lnapp_stop_threads(p_conf);
    }

    //DBGTRACE_END
}


/** announcement前のchannel_update送信
 *      https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001220.html
 *
 */
static void send_cnlupd_before_announce(lnapp_conf_t *p_conf)
{
    ln_channel_t *p_channel = &p_conf->channel;

    pthread_mutex_lock(&p_conf->mux_conf);
    if ((ln_short_channel_id(p_channel) != 0) && !ln_is_announced(p_channel)) {
        //チャネル作成済み && announcement未交換
        /*ignore*/ ln_channel_update_send(p_channel);
    }
    pthread_mutex_unlock(&p_conf->mux_conf);
}


/********************************************************************
 * announceスレッド
 ********************************************************************/

/** announceスレッド開始
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
static void *thread_anno_start(void *pArg)
{
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;
    int slp = M_WAIT_ANNO_SEC;

    LOGD("[THREAD]anno initialize: %d\n", p_conf->active);

    while (p_conf->active) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < slp; lp++) {
            sleep(1);
            if (!p_conf->active) {
                break;
            }
            if (p_conf->annodb_updated) {
                break;
            }
        }

        if ((p_conf->flag_recv & M_FLAGRECV_END) == 0) {
            //まだ接続完了していない
            continue;
        }
        time_t now = utl_time_time();
        if (p_conf->annodb_updated && p_conf->annodb_cont && (now - p_conf->annodb_stamp < LNAPP_WAIT_ANNO_HYSTER_SEC)) {
            LOGD("skip\n");
            continue;
        }

        bool retcnl = anno_proc(p_conf);
        if (retcnl) {
            //channel_listの最後まで見終わった
            if (p_conf->annodb_updated) {
                //annodb was updated, so anno_proc() will be done again.
                // since updating annodb may have been in the middle of anno_proc().
                p_conf->annodb_updated = false;
                slp = M_WAIT_ANNO_SEC;
            } else {
                //次までを長くあける
                slp = M_WAIT_ANNO_LONG_SEC;
            }
        } else {
            //channel_listの途中-->すぐに続きを行う
            slp = M_WAIT_ANNO_SEC;
        }
    }

    LOGD("[exit]anno thread\n");

    return NULL;
}


/** channel_announcement/channel_update/node_announcement送信
 *
 * 接続先へ未送信のchannel_announcement/channel_updateを送信する。
 * 一度にすべて送信するとDBのロック期間が長くなるため、
 * 最大M_ANNO_UNITパケットまで送信を行い、残りは次回呼び出しに行う。
 *
 * @param[in,out]   p_conf  lnapp情報
 * @retval  true    リストの最後まで終わった
 */
static bool anno_proc(lnapp_conf_t *p_conf)
{
    bool ret;
    int anno_cnt = 0;
    uint64_t short_channel_id = 0;
    void *p_cur_cnl = NULL;         //channel
    void *p_cur_node = NULL;        //node_announcement
    void *p_cur_infocnl = NULL;     //channel送信済みDB
    void *p_cur_infonode = NULL;    //node_announcement送信済みDB

    LOGD("BEGIN: last=%" PRIx64 "\n", p_conf->last_anno_cnl);

    ret = ln_db_anno_transaction();
    if (!ret) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    ret = ln_db_anno_cur_open(&p_cur_cnl, LN_DB_CUR_CNLANNO);
    if (!ret) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_anno_cur_open(&p_cur_node, LN_DB_CUR_NODEANNO);
    if (!ret) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_anno_cur_open(&p_cur_infocnl, LN_DB_CUR_CNLANNO_INFO);
    if (!ret) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_anno_cur_open(&p_cur_infonode, LN_DB_CUR_NODEANNO_INFO);
    if (!ret) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //これ以降、short_channel_id に 0以外の値が入っている状態で LABEL_EXITに到達すると、
    //  そのshort_channel_idに関する channel_announcement, channel_update は削除される。

    while (p_conf->active) {
        char type;
        uint32_t timestamp;
        utl_buf_t buf_cnl = UTL_BUF_INIT;

        ret = ln_db_cnlanno_cur_get(p_cur_cnl, &short_channel_id, &type, &timestamp, &buf_cnl);
        if (!ret) {
            //次回は最初から検索する
            LOGD("annolist end\n");
            p_conf->last_anno_cnl = 0;
            utl_buf_free(&buf_cnl);
            break;
        }
        if (type != LN_DB_CNLANNO_ANNO) {
            //BOLT#7: Pruning the Network View
            if ((type == LN_DB_CNLANNO_UPD0) || (type == LN_DB_CNLANNO_UPD1)) {
                uint64_t now = (uint64_t)utl_time_time();
                if (ln_db_cnlupd_need_to_prune(now, timestamp)) {
                    ln_db_cnlanno_cur_del(p_cur_cnl);
                }
            }
            //LOGD("continue1: %" PRIx64 ":%c\n", short_channel_id, type);
            utl_buf_free(&buf_cnl);
            continue;
        }
        if (p_conf->last_anno_cnl != 0) {
            //前回の続きであれば、次のshort_channel_idになるまで進める
            if (p_conf->last_anno_cnl == short_channel_id) {
                //1回だけ多く回すと、次回はここをスルーする
                //LOGD("match\n");
                p_conf->last_anno_cnl = 0;
            }
            utl_buf_free(&buf_cnl);
            continue;
        }

        //buf_cnlにはshort_channel_idのchannel_announcement packetが入っている

        bool unspent = check_unspent_short_channel_id(short_channel_id);
        if (!unspent) {
            //SPENTであれば削除
            LOGD("pre_chan: delete all channel %016" PRIx64 "\n", short_channel_id);
            utl_buf_free(&buf_cnl);
            goto LABEL_EXIT;
        }

        ret = anno_send(p_conf, short_channel_id, &buf_cnl, p_cur_cnl, p_cur_node, p_cur_infocnl, p_cur_infonode);
        utl_buf_free(&buf_cnl);
        if (ret) {
            anno_cnt++;
            if (anno_cnt > M_ANNO_UNIT) {
                LOGD("annolist next\n");
                p_conf->last_anno_cnl = short_channel_id;
                break;
            }
        }
    }
    short_channel_id = 0;

LABEL_EXIT:
    if (p_cur_infonode != NULL) {
        ln_db_anno_cur_close(p_cur_infonode);
    }
    if (p_cur_infocnl != NULL) {
        ln_db_anno_cur_close(p_cur_infocnl);
    }
    if (p_cur_node != NULL) {
        ln_db_anno_cur_close(p_cur_node);
    }
    if (p_cur_cnl != NULL) {
        ln_db_anno_cur_close(p_cur_cnl);
    }

    ln_db_anno_commit(true);
    if (short_channel_id != 0) {
        (void)ln_db_cnlanno_del(short_channel_id);
    }

    LOGD("END: %016" PRIx64 "\n", p_conf->last_anno_cnl);
    return p_conf->last_anno_cnl == 0;
}


/** send announcements
 *  channel_announcement, channel_update(dir=0,1), node_announcement(0,1)
 *
 * @param[in]   p_conf
 * @param[in]   short_channel_id
 * @param[in]   p_buf_cnl               channel_announcement packet
 * @param[in]   p_cur_cnl               DB
 * @param[in]   p_cur_node              DB
 * @param[in]   p_cur_infocnl           DB
 * @param[in]   p_cur_infonode          DB
 * @retval  true    sent announcement
 * @retval  false   not send
 */
static bool anno_send(
    lnapp_conf_t *p_conf,
    uint64_t short_channel_id,
    const utl_buf_t *p_buf_cnl,
    void *p_cur_cnl,
    void *p_cur_node,
    void *p_cur_infocnl,
    void *p_cur_infonode)
{
    char type;
    uint32_t timestamp;
    int cnt_upd = 0;
    utl_buf_t buf_upd[2] = { UTL_BUF_INIT, UTL_BUF_INIT };  //channel_update(dir=0,1)
    for (size_t lp = 0; lp < ARRAY_SIZE(buf_upd); lp++) {
        uint64_t sci;
        bool ret = ln_db_cnlanno_cur_get(p_cur_cnl, &sci, &type, &timestamp, &buf_upd[lp]);
        if (ret && (sci == short_channel_id) && (type == (char)(LN_DB_CNLANNO_UPD0 + lp))) {
            ret = anno_prev_check(short_channel_id, timestamp);
            if (ret) {
                cnt_upd++;
            } else {
                LOGD("pre_upd: delete channel_update %016" PRIx64 " %c\n", short_channel_id, type);
                //channel_updateをDBから削除
                ln_db_cnlanno_cur_del(p_cur_cnl);
                utl_buf_free(&buf_upd[lp]);
            }
        } else if (!ret) {
            LOGD("annolist end\n");
            p_conf->last_anno_cnl = 0;
            break;
        } else {
            //LOGD("back\n");
            ret = ln_db_cnlanno_cur_back(p_cur_cnl);
            utl_buf_free(&buf_upd[lp]);
        }
    }
    if (cnt_upd > 0) {
        //channel_announcement
        anno_send_cnl(p_conf, short_channel_id, LN_DB_CNLANNO_ANNO, p_cur_infocnl, p_buf_cnl);

        //channel_update
        for (size_t lp = 0; lp < ARRAY_SIZE(buf_upd); lp++) {
            if (buf_upd[lp].len > 0) {
                anno_send_cnl(p_conf, short_channel_id, LN_DB_CNLANNO_UPD0 + lp, p_cur_infocnl, &buf_upd[lp]);
            } else {
                LOGD("skip: type=%c\n", LN_DB_CNLANNO_UPD0 + lp);
            }
        }

        //node_announcement
        anno_send_node(p_conf, p_cur_node, p_cur_infonode, p_buf_cnl);
    } else {
        LOGD("skip channel: %" PRIx64 "\n", short_channel_id);
    }
    for (size_t lp = 0; lp < ARRAY_SIZE(buf_upd); lp++) {
        utl_buf_free(&buf_upd[lp]);
    }

    return cnt_upd > 0;
}


/** channel_update事前チェック
 *
 * @param[in]       short_channel_id        target short_channel_id
 * @param[in]       timestamp               channel_announcement saved time
 * @retval  true        nothing to do
 * @retval  false       channel_updateを削除してよい
 */
static bool anno_prev_check(uint64_t short_channel_id, uint32_t timestamp)
{
    bool ret = true;

    if (ln_db_channel_owned_check(short_channel_id)) {
        return true;
    }

    //BOLT#7: Pruning the Network View
    uint64_t now = (uint64_t)utl_time_time();
    if (ln_db_cnlupd_need_to_prune(now, timestamp)) {
        //古いため送信しない
        char time[UTL_SZ_TIME_FMT_STR + 1];
        LOGD("older channel_update: prune(%016" PRIx64 "): %s(now=%" PRIu32 ", tm=%" PRIu32 ")\n", short_channel_id, utl_time_fmt(time, timestamp), now, timestamp);
        ret = false;
    }

    return ret;
}


/**
 *
 * @return  送信数
 */
static bool anno_send_cnl(lnapp_conf_t *p_conf, uint64_t short_channel_id, char type, void *p_cur_infocnl, const utl_buf_t *p_buf_cnl)
{
    bool chk = ln_db_cnlanno_info_search_node_id(p_cur_infocnl, short_channel_id, type, ln_remote_node_id(&p_conf->channel));
    if (!chk) {
        LOGD("send channel_%c: %016" PRIx64 "\n", type, short_channel_id);
        lnapp_send_peer_noise(p_conf, p_buf_cnl);
        ln_db_cnlanno_info_add_node_id(p_cur_infocnl, short_channel_id, type, false, ln_remote_node_id(&p_conf->channel));
        chk = true;
    } else {
        //LOGD("CHAN already sent: short_channel_id=%016" PRIx64 ", type:%c\n", short_channel_id, type);
    }
    return chk;
}


/**
 *
 * @return  送信数
 */
static bool anno_send_node(lnapp_conf_t *p_conf, void *p_cur_node, void *p_cur_infonode, const utl_buf_t *p_buf_cnl)
{
    uint64_t short_channel_id;
    uint8_t node[2][BTC_SZ_PUBKEY];
    bool ret = ln_get_ids_cnl_anno(&short_channel_id, node[0], node[1], p_buf_cnl->buf, p_buf_cnl->len);
    if (!ret) {
        return false;
    }

    utl_buf_t buf_node = UTL_BUF_INIT;

    for (int lp = 0; lp < 2; lp++) {
        ret = ln_db_nodeanno_info_search_node_id(p_cur_infonode, node[lp], ln_remote_node_id(&p_conf->channel));
        if (!ret) {
            ret = ln_db_nodeanno_cur_load(p_cur_node, &buf_node, NULL, node[lp]);
            if (ret) {
                LOGD("send node_anno(%d): ", lp);
                DUMPD(node[lp], BTC_SZ_PUBKEY);
                lnapp_send_peer_noise(p_conf, &buf_node);
                utl_buf_free(&buf_node);
                ln_db_nodeanno_info_add_node_id(p_cur_infonode, node[lp], false, ln_remote_node_id(&p_conf->channel));
            }
        } else {
            //LOGD("NODE already sent: short_channel_id=%016" PRIx64 ", node%d\n", short_channel_id, lp);
        }
    }
    return true;
}


/********************************************************************
 * その他
 ********************************************************************/

/** Channel情報設定
 *
 * @param[in,out]       p_conf
 */
static void load_channel_settings(lnapp_conf_t *p_conf)
{
    bool ret = ln_establish_alloc(&p_conf->channel, ptarmd_get_establish_param());
    if (!ret) {
        LOGE("fail: set establish\n");
        assert(ret);
    }
}


/** Announcement初期値
 *
 */
static void load_announce_settings(void)
{
    anno_conf_t aconf;
    conf_anno_init(&aconf);
    (void)conf_anno_load(FNAME_CONF_ANNO, &aconf);
    mAnnoParam.cltv_expiry_delta = aconf.cltv_expiry_delta;
    mAnnoParam.htlc_minimum_msat = aconf.htlc_minimum_msat;
    mAnnoParam.fee_base_msat = aconf.fee_base_msat;
    mAnnoParam.fee_prop_millionths = aconf.fee_prop_millionths;
}


/**************************************************************************
 * 受信アイドル時処理
 **************************************************************************/


/** 処理要求キューの処理実施
 *
 * 受信処理のアイドル時(タイムアウトした場合)に呼び出される。
 */
static void recv_idle_proc(lnapp_conf_t *p_conf)
{
    pthread_mutex_lock(&p_conf->mux_conf);

    if ((p_conf->flag_recv & M_FLAGRECV_END) == M_FLAGRECV_END) {
        ln_idle_proc(&p_conf->channel, p_conf->feerate_per_kw);
    }

    pthread_mutex_unlock(&p_conf->mux_conf);
}


static bool getnewaddress(utl_buf_t *pBuf)
{
    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    if (!btcrpc_getnewaddress(addr)) {
        return false;
    }
    return btc_keys_addr2spk(pBuf, addr);
}


/** short_channel_idのfunding_tx未使用チェック
 *
 * @param[in]   ShortChannelId      short_channel_id
 * @retval  true    funding_tx未使用
 * @note
 *      - close済みのchannelについてはannouncementしない方がよいのでは無いかと考えて行っている処理。
 *      - SPVでは処理負荷が重たいため、やらない。
 */
static bool check_unspent_short_channel_id(uint64_t ShortChannelId)
{
#ifdef USE_BITCOIND
    bool ret;
    uint32_t bheight;
    uint32_t bindex;
    uint32_t vindex;
    bool unspent;
    uint8_t txid[BTC_SZ_TXID];

    ln_short_channel_id_get_param(&bheight, &bindex, &vindex, ShortChannelId);
    ret = btcrpc_gettxid_from_short_channel(txid, bheight, bindex);
    if (ret) {
        ret = btcrpc_check_unspent(NULL, &unspent, NULL, txid, vindex);
    }
    if (!(ret && unspent)) {
        LOGD("already spent : %016" PRIx64 "(height=%" PRIu32 ", bindex=%" PRIu32 ", txindex=%" PRIu32 ")\n", ShortChannelId, bheight, bindex, vindex);
    }

    return ret && unspent;
#else
    (void)ShortChannelId;

    return true;
#endif
}


static void show_channel_have_chan(const lnapp_conf_t *pAppConf, cJSON *result)
{
    const ln_channel_t *p_channel = &pAppConf->channel;
    char str[256];

    //channel_id
    utl_str_bin2str(str, ln_channel_id(p_channel), LN_SZ_CHANNEL_ID);
    cJSON_AddItemToObject(result, "channel_id", cJSON_CreateString(str));
    //short_channel_id
    char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
    ln_short_channel_id_string(str_sci, ln_short_channel_id(p_channel));
    cJSON_AddItemToObject(result, "short_channel_id", cJSON_CreateString(str_sci));
    //funding_tx
    utl_str_bin2str_rev(str, ln_funding_info_txid(&p_channel->funding_info), BTC_SZ_TXID);
    cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
    cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_info_txindex(&p_channel->funding_info)));
    //confirmation
    uint32_t confirm;
    bool b_get = btcrpc_get_confirmations(&confirm, ln_funding_info_txid(&p_channel->funding_info));
    if (b_get) {
        cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
    }
    //feerate_per_kw
    cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate_per_kw(p_channel)));

    //local
    cJSON *local = cJSON_CreateObject();
    //local_msat
    cJSON_AddItemToObject(local, "msatoshi", cJSON_CreateNumber64(ln_local_msat(p_channel)));
    //commit_num(local)
    cJSON_AddItemToObject(local, "commit_num", cJSON_CreateNumber(ln_commit_info_local(p_channel)->commit_num));
    //num_htlc_outputs(local)
    cJSON_AddItemToObject(local, "num_htlc_outputs", cJSON_CreateNumber(ln_commit_info_local(p_channel)->num_htlc_outputs));
    cJSON_AddItemToObject(result, "local", local);

    //remote
    cJSON *remote = cJSON_CreateObject();
    //remote_msat
    cJSON_AddItemToObject(remote, "msatoshi", cJSON_CreateNumber64(ln_remote_msat(p_channel)));
    //commit_num(remote)
    cJSON_AddItemToObject(remote, "commit_num", cJSON_CreateNumber(ln_commit_info_remote(p_channel)->commit_num));
    //num_htlc_outputs(remote)
    cJSON_AddItemToObject(remote, "num_htlc_outputs", cJSON_CreateNumber(ln_commit_info_remote(p_channel)->num_htlc_outputs));
    cJSON_AddItemToObject(result, "remote", remote);

    //XXX: bug
    //  don't compare with the number of HTLC outputs but HTLCs (including trimmed ones)
    if (ln_commit_info_local(p_channel)->num_htlc_outputs) {
        cJSON *htlcs = cJSON_CreateArray();
        for (int lp = 0; lp < LN_UPDATE_MAX; lp++) {
            const ln_update_t *p_update = ln_update(p_channel, lp);
            if (!LN_UPDATE_USED(p_update)) continue;
            if (p_update->type != LN_UPDATE_TYPE_ADD_HTLC) continue;
            const ln_htlc_t *p_htlc = ln_htlc(p_channel, p_update->type_specific_idx);
            cJSON *htlc = cJSON_CreateObject();
            const char *p_type;
            if (LN_UPDATE_OFFERED(p_update)) {
                p_type = "offered";
            } else if (LN_UPDATE_RECEIVED(p_update)) {
                p_type = "received";
            } else {
                p_type = "unknown";
            }
            cJSON_AddItemToObject(htlc, "type", cJSON_CreateString(p_type));
            cJSON_AddItemToObject(htlc, "htlc id", cJSON_CreateNumber64(p_htlc->id));
            cJSON_AddItemToObject(htlc, "amount_msat", cJSON_CreateNumber(p_htlc->amount_msat));
            cJSON_AddItemToObject(htlc, "cltv_expiry", cJSON_CreateNumber(p_htlc->cltv_expiry));
            const char *p_role;
            if (p_htlc->neighbor_short_channel_id) {
                p_role = "hop";
            } else {
                if (LN_UPDATE_OFFERED(p_update)) {
                    p_role = "origin node";
                } else if (LN_UPDATE_RECEIVED(p_update)) {
                    p_role = "final node";
                } else {
                    p_role = "unknown";
                }
            }
            cJSON_AddItemToObject(htlc, "role", cJSON_CreateString(p_role));
            if (p_htlc->neighbor_short_channel_id) {
                char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
                ln_short_channel_id_string(str_sci, p_htlc->neighbor_short_channel_id);
                if (LN_UPDATE_OFFERED(p_update)) {
                    cJSON_AddItemToObject(htlc, "from", cJSON_CreateString(str_sci));
                } else if (LN_UPDATE_RECEIVED(p_update)) {
                    cJSON_AddItemToObject(htlc, "to", cJSON_CreateString(str_sci));
                }
            }
            cJSON_AddItemToArray(htlcs, htlc);
        }
        cJSON_AddItemToObject(result, "htlc", htlcs);
    }
}


static void show_channel_fundwait(const lnapp_conf_t *pAppConf, cJSON *result)
{
    const ln_channel_t *p_channel = &pAppConf->channel;
    char str[256];

    //channel_id
    utl_str_bin2str(str, ln_channel_id(p_channel), LN_SZ_CHANNEL_ID);
    cJSON_AddItemToObject(result, "channel_id", cJSON_CreateString(str));
    //funding_tx
    utl_str_bin2str_rev(str, ln_funding_info_txid(&p_channel->funding_info), BTC_SZ_TXID);
    cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
    cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_info_txindex(&p_channel->funding_info)));
    //confirmation
    uint32_t confirm;
    bool b_get = btcrpc_get_confirmations(&confirm, ln_funding_info_txid(&p_channel->funding_info));
    if (b_get) {
        cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
    }
    //minimum_depth
    cJSON_AddItemToObject(result, "minimum_depth", cJSON_CreateNumber(ln_funding_info_minimum_depth(&p_channel->funding_info)));
    //feerate_per_kw
    cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate_per_kw(p_channel)));
}


static bool handshake_start(lnapp_conf_t *pConf, utl_buf_t *pBuf, const uint8_t *pNodeId)
{
    if (!ln_noise_handshake_init(&pConf->noise, pNodeId)) return false;
    if (pNodeId != NULL) {
        if (!ln_noise_handshake_start(&pConf->noise, pBuf, pNodeId)) return false;
    }
    return true;
}


static bool handshake_recv(lnapp_conf_t *pConf, bool *pCont, utl_buf_t *pBuf)
{
    if (!ln_noise_handshake_recv(&pConf->noise, pBuf)) return false;
    //continue?
    *pCont = ln_noise_handshake_state(&pConf->noise);
    return true;
}


static void handshake_free(lnapp_conf_t *pConf)
{
    ln_noise_handshake_free(&pConf->noise);
}

