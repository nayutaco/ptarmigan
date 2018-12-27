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
 * p2p_svr/cli--->| channel thread                                |
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
#include <stdarg.h>
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

#include "utl_addr.h"
#include "utl_time.h"
#include "utl_rng.h"

#include "ptarmd.h"
#include "cmd_json.h"
#include "lnapp.h"
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
#define M_WAIT_ANNO_HYSTER_SEC  (1)         //announce DBが更新されて展開するまでの最低空き時間[sec]
#define M_WAIT_RECV_TO_MSEC     (50)        //socket受信待ちタイムアウト[msec]
#define M_WAIT_SEND_TO_MSEC     (500)       //socket送信待ちタイムアウト[msec]
#define M_WAIT_SEND_WAIT_MSEC   (100)       //socket送信で一度に送信できなかった場合の待ち時間[msec]
#define M_WAIT_RECV_MSG_MSEC    (500)       //message受信監視周期[msec]
#define M_WAIT_RECV_THREAD_MSEC (100)       //recv_thread開始待ち[msec]
#define M_WAIT_RESPONSE_MSEC    (10000)     //受信待ち[msec]
#define M_WAIT_CHANREEST_MSEC   (3600000)   //channel_reestablish受信待ち[msec]

#define M_ANNO_UNIT             (50)       ///< 1回のsend_announcement()での処理単位
#define M_RECVIDLE_RETRY_MAX    (5)         ///< 受信アイドル時キュー処理のリトライ最大

#define M_ERRSTR_REASON                 "fail: %s (hop=%d)(suggest:%s)"
#define M_ERRSTR_CANNOTDECODE           "fail: result cannot decode"
#define M_ERRSTR_CANNOTSTART            "fail: can't start payment(our_msat=%" PRIu64 ", amt_to_forward=%" PRIu64 ")"

#if 1
#define DBGTRACE_BEGIN  LOGD("BEGIN\n");
#define DBGTRACE_END    LOGD("END\n");
#else
#define DBGTRACE_BEGIN
#define DBGTRACE_END
#endif


/********************************************************************
 * typedefs
 ********************************************************************/

//lnapp_conf_t.flag_recv
enum {
    RECV_MSG_INIT           = 0x01,     ///< init
    RECV_MSG_REESTABLISH    = 0x02,     ///< channel_reestablish
    RECV_MSG_FUNDINGLOCKED  = 0x04,     ///< funding locked
    RECV_MSG_END            = 0x80,     ///< 初期化完了
};


/********************************************************************
 * static variables
 ********************************************************************/

static volatile bool        mLoop;          //true:チャネル有効

static ln_anno_prm_t        mAnnoPrm;       ///< announcementパラメータ


/********************************************************************
 * prototypes
 ********************************************************************/

static void *thread_main_start(void *pArg);
static bool wait_peer_connected(lnapp_conf_t *p_conf);
static bool noise_handshake(lnapp_conf_t *p_conf);
static bool set_short_channel_id(lnapp_conf_t *p_conf);
static bool exchange_init(lnapp_conf_t *p_conf);
static bool exchange_reestablish(lnapp_conf_t *p_conf);
static bool exchange_funding_locked(lnapp_conf_t *p_conf);
static bool send_open_channel(lnapp_conf_t *p_conf, const funding_conf_t *pFunding);

static void *thread_recv_start(void *pArg);
static uint16_t recv_peer(lnapp_conf_t *p_conf, uint8_t *pBuf, uint16_t Len, uint32_t ToMsec);

static void *thread_poll_start(void *pArg);
static void poll_ping(lnapp_conf_t *p_conf);
static void poll_funding_wait(lnapp_conf_t *p_conf);
static void poll_normal_operating(lnapp_conf_t *p_conf);
static void send_cnlupd_before_announce(lnapp_conf_t *p_conf);

static void *thread_anno_start(void *pArg);
static bool send_announcement(lnapp_conf_t *p_conf);
static bool send_anno_pre_chan(uint64_t short_channel_id);
static bool send_anno_pre_upd(uint64_t short_channel_id, uint32_t timestamp, uint64_t last_short_channel_id);
static int send_anno_cnl(lnapp_conf_t *p_conf, char type, void *p_cur_infocnl, const utl_buf_t *p_buf_cnl);
static int send_anno_node(lnapp_conf_t *p_conf, void *p_cur_node, void *p_cur_infonode, const utl_buf_t *p_buf_cnl);

static void notify_cb(ln_self_t *self, ln_cb_t reason, void *p_param);
static void cb_channel_quit(lnapp_conf_t *p_conf, void *p_param);
static void cb_error_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_init_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_channel_reestablish_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_tx_sign(lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_tx_wait(lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_locked(lnapp_conf_t *p_conf, void *p_param);
static void cb_update_anno_db(lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv_prev(lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static bool cbsub_add_htlc_finalnode(lnapp_conf_t *p_conf, ln_cb_add_htlc_recv_t *p_addhtlc);
static bool cbsub_add_htlc_forward(lnapp_conf_t *p_conf, ln_cb_add_htlc_recv_t *p_addhtlc);
static void cb_fwd_addhtlc_start(lnapp_conf_t *p_conf, void *p_param);
static void cb_bwd_delhtlc_start(lnapp_conf_t *p_conf, void *p_param);
static void cb_fulfill_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cbsub_fulfill_backwind(lnapp_conf_t *p_conf, const ln_cb_fulfill_htlc_recv_t *p_fulfill);
static void cbsub_fulfill_originnode(lnapp_conf_t *p_conf, const ln_cb_fulfill_htlc_recv_t *p_fulfill);
static void cb_fail_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cbsub_fail_backwind(lnapp_conf_t *p_conf, const ln_cb_fail_htlc_recv_t *p_fail);
static void cbsub_fail_originnode(lnapp_conf_t *p_conf, const ln_cb_fail_htlc_recv_t *p_fail);
static void cb_rev_and_ack_excg(lnapp_conf_t *p_conf, void *p_param);
static void cb_payment_retry(lnapp_conf_t *p_conf, void *p_param);
static void cb_update_fee_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_shutdown_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_closed_fee(lnapp_conf_t *p_conf, void *p_param);
static void cb_closed(lnapp_conf_t *p_conf, void *p_param);
static void cb_send_req(lnapp_conf_t *p_conf, void *p_param);
static void cb_send_queue(lnapp_conf_t *p_conf, void *p_param);
static void cb_set_latest_feerate(lnapp_conf_t *p_conf, void *p_param);
static void cb_getblockcount(lnapp_conf_t *p_conf, void *p_param);

static void stop_threads(lnapp_conf_t *p_conf);
static bool send_peer_raw(lnapp_conf_t *p_conf, const utl_buf_t *pBuf);
static bool send_peer_noise(lnapp_conf_t *p_conf, const utl_buf_t *pBuf);

static void load_channel_settings(lnapp_conf_t *p_conf);
static void load_announce_settings(void);

static void set_lasterror(lnapp_conf_t *p_conf, int Err, const char *pErrStr);

static void rcvidle_push(lnapp_conf_t *p_conf, rcvidle_cmd_t Cmd, utl_buf_t *pBuf);
static void rcvidle_pop_and_exec(lnapp_conf_t *p_conf);
static void rcvidle_clear(lnapp_conf_t *p_conf);
static bool rcvidle_announcement_signs(lnapp_conf_t *p_conf);

static void payroute_push(lnapp_conf_t *p_conf, const payment_conf_t *pPayConf, uint64_t HtlcId);
static const payment_conf_t* payroute_get(lnapp_conf_t *p_conf, uint64_t HtlcId);
static void payroute_del(lnapp_conf_t *p_conf, uint64_t HtlcId);
static void payroute_clear(lnapp_conf_t *p_conf);
static void payroute_print(lnapp_conf_t *p_conf);
#ifndef USE_SPV
static bool check_unspent_short_channel_id(uint64_t ShortChannelId);
#endif

static void send_queue_push(lnapp_conf_t *p_conf, const utl_buf_t *pBuf);
static void send_queue_flush(lnapp_conf_t *p_conf);
static void send_queue_clear(lnapp_conf_t *p_conf);

static bool getnewaddress(utl_buf_t *pBuf);

static void show_self_param(const ln_self_t *self, FILE *fp, const char *msg, int line);


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_start(lnapp_conf_t *pAppConf)
{
    pthread_create(&pAppConf->th, NULL, &thread_main_start, pAppConf);
}


void lnapp_stop(lnapp_conf_t *pAppConf)
{
    if (pAppConf->th != 0) {
        LOGD("stop lnapp: sock=%d\n", pAppConf->sock);
        fprintf(stderr, "stop: ");
        btc_util_dumpbin(stderr, pAppConf->node_id, BTC_SZ_PUBKEY, true);

        stop_threads(pAppConf);
        pthread_join(pAppConf->th, NULL);
        pAppConf->th = 0;
        fprintf(stderr, "joined\n");
    }
}


bool lnapp_funding(lnapp_conf_t *pAppConf, const funding_conf_t *pFunding)
{
    if ((!pAppConf->loop) || !lnapp_is_inited(pAppConf)) {
        //LOGD("This AppConf not working\n");
        return false;
    }

    LOGD("start: Establish\n");
    bool ret = send_open_channel(pAppConf, pFunding);

    return ret;
}


/*******************************************
 * 送金
 *******************************************/

//初回ONIONパケット作成
bool lnapp_payment(lnapp_conf_t *pAppConf, const payment_conf_t *pPay)
{
    if (!pAppConf->loop || !lnapp_is_inited(pAppConf)) {
        //LOGD("This AppConf not working\n");
        return false;
    }
    if (ln_status_get(pAppConf->p_self) != LN_STATUS_NORMAL) {
        LOGD("not Normal Operation status\n");
        return false;
    }

    DBGTRACE_BEGIN

    pthread_mutex_lock(&pAppConf->mux_self);

    bool ret = false;
    uint8_t session_key[BTC_SZ_PRIVKEY];
    ln_self_t *p_self = pAppConf->p_self;
    uint8_t onion[LN_SZ_ONION_ROUTE];
    utl_buf_t secrets = UTL_BUF_INIT;

    if (pPay->hop_datain[0].short_channel_id != ln_short_channel_id(p_self)) {
        LOGD("short_channel_id mismatch\n");
        LOGD("fail: short_channel_id mismatch\n");
        LOGD("    hop  : %016" PRIx64 "\n", pPay->hop_datain[0].short_channel_id);
        LOGD("    mine : %016" PRIx64 "\n", ln_short_channel_id(p_self));
        ln_db_routeskip_save(pPay->hop_datain[0].short_channel_id, false);   //恒久的
        goto LABEL_EXIT;
    }

    //amount, CLTVチェック(最後の値はチェックしない)
    for (int lp = 1; lp < pPay->hop_num - 1; lp++) {
        if (pPay->hop_datain[lp - 1].amt_to_forward < pPay->hop_datain[lp].amt_to_forward) {
            LOGD("[%d]amt_to_forward larger than previous (%" PRIu64 " < %" PRIu64 ")\n",
                    lp,
                    pPay->hop_datain[lp - 1].amt_to_forward,
                    pPay->hop_datain[lp].amt_to_forward);
            goto LABEL_EXIT;
        }
        if (pPay->hop_datain[lp - 1].outgoing_cltv_value <= pPay->hop_datain[lp].outgoing_cltv_value) {
            LOGD("[%d]outgoing_cltv_value larger than previous (%" PRIu32 " < %" PRIu32 ")\n",
                    lp,
                    pPay->hop_datain[lp - 1].outgoing_cltv_value,
                    pPay->hop_datain[lp].outgoing_cltv_value);
            goto LABEL_EXIT;
        }
    }

    utl_rng_rand(session_key, sizeof(session_key));
    //hop_datain[0]にこのchannel情報を置いているので、ONIONにするのは次から
    ret = ln_onion_create_packet(onion, &secrets, &pPay->hop_datain[1], pPay->hop_num - 1,
                        session_key, pPay->payment_hash, BTC_SZ_HASH256);
    if (!ret) {
        goto LABEL_EXIT;
    }

    uint64_t htlc_id;
    ret = ln_add_htlc_set(p_self,
                        &htlc_id,
                        NULL,
                        onion,
                        pPay->hop_datain[0].amt_to_forward,
                        pPay->hop_datain[0].outgoing_cltv_value,
                        pPay->payment_hash,
                        0,      //origin node
                        0,
                        &secrets);
    utl_buf_free(&secrets);
    if (ret) {
        //再routing用に送金経路を保存
        payroute_push(pAppConf, pPay, htlc_id);
    } else {
        //our_msatが足りない場合もこのルート
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    if (ret) {
        LOGD("payment start\n");
        show_self_param(p_self, stderr, "payment start", __LINE__);

        // method: payment
        // $1: short_channel_id
        // $2: node_id
        // $3: amt_to_forward
        // $4: outgoing_cltv_value
        // $5: payment_hash
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(pAppConf->p_self));
        char hashstr[BTC_SZ_HASH256 * 2 + 1];
        utl_misc_bin2str(hashstr, pPay->payment_hash, BTC_SZ_HASH256);
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%s %s "
                    "%" PRIu64 " "
                    "%" PRIu32 " "
                    "%s",
                    str_sci, node_id,
                    pPay->hop_datain[0].amt_to_forward,
                    pPay->hop_datain[0].outgoing_cltv_value,
                    hashstr);
        ptarmd_call_script(PTARMD_EVT_PAYMENT, param);

        lnapp_save_event(ln_channel_id(pAppConf->p_self),
            "[SEND]add_htlc: HTLC id=%" PRIu64 ", amount_msat=%" PRIu64 ", cltv=%d",
                    htlc_id,
                    pPay->hop_datain[0].amt_to_forward,
                    pPay->hop_datain[0].outgoing_cltv_value);
    } else {
        LOGD("fail\n");
        // char errstr[512];
        // sprintf(errstr, M_ERRSTR_CANNOTSTART,
        //             ln_our_msat(pAppConf->p_self),
        //             pPay->hop_datain[0].amt_to_forward);
        // set_lasterror(pAppConf, RPCERR_PAYFAIL, errstr);

        // //ルートが見つからなくなるまでリトライする
        // ln_db_routeskip_save(ln_short_channel_id(pAppConf->p_self), true);   //一時的
        // cmd_json_pay_retry(pPay->payment_hash);
        // ret = true;         //再送はtrue
    }
    pthread_mutex_unlock(&pAppConf->mux_self);

    DBGTRACE_END

    return ret;
}


/*******************************************
 * 転送/巻き戻しのための lnappコンテキスト移動
 *      転送/巻き戻しを行うため、lnappをまたぐ必要がある。
 *      pthreadがlnappで別になるため、受信スレッドのidle処理を介して移動させる。
 *******************************************/

void lnapp_transfer_channel(lnapp_conf_t *pAppConf, rcvidle_cmd_t Cmd, utl_buf_t *pBuf)
{
    DBGTRACE_BEGIN

    rcvidle_push(pAppConf, Cmd, pBuf);

    DBGTRACE_END
}


/*******************************************
 * close関連
 *******************************************/

bool lnapp_close_channel(lnapp_conf_t *pAppConf)
{
    if (!pAppConf->loop) {
        //LOGD("This AppConf not working\n");
        return false;
    }

    DBGTRACE_BEGIN

    pthread_mutex_lock(&pAppConf->mux_self);

    bool ret = false;
    utl_buf_t buf_bolt = UTL_BUF_INIT;
    ln_self_t *p_self = pAppConf->p_self;

    if (ln_status_is_closing(p_self)) {
        LOGD("fail: already closing\n");
        goto LABEL_EXIT;
    }

    //feeと送金先
    cb_shutdown_recv(pAppConf, NULL);

    show_self_param(p_self, stderr, "close channel", __LINE__);

    const char *p_str;
    ret = ln_shutdown_create(p_self, &buf_bolt);
    if (ret) {
        send_peer_noise(pAppConf, &buf_bolt);
        utl_buf_free(&buf_bolt);

        p_str = "close: good way(local) start";
    } else {
        p_str = "fail close: good way(local) start";
    }
    lnapp_save_event(ln_channel_id(p_self), p_str);

LABEL_EXIT:
    pthread_mutex_unlock(&pAppConf->mux_self);
    DBGTRACE_END

    return ret;
}


bool lnapp_close_channel_force(const uint8_t *pNodeId)
{
    bool ret;
    ln_self_t *p_self = (ln_self_t *)UTL_DBG_MALLOC(sizeof(ln_self_t));

    //announcementデフォルト値
    load_announce_settings();
    ln_init(p_self, NULL, &mAnnoPrm, NULL);

    ret = ln_node_search_channel(p_self, pNodeId);
    if (!ret) {
        return false;
    }
    if (ln_status_is_closing(p_self)) {
        LOGD("fail: already closing\n");
        UTL_DBG_FREE(p_self);
        return false;
    }

    LOGD("close: bad way(local): htlc=%d\n", ln_commit_local(p_self)->htlc_num);
    lnapp_save_event(ln_channel_id(p_self), "close: bad way(local)");
    (void)monitor_close_unilateral_local(p_self, NULL);
    UTL_DBG_FREE(p_self);

    return true;
}


/*******************************************
 * fee関連
 *******************************************/

bool lnapp_send_updatefee(lnapp_conf_t *pAppConf, uint32_t FeeratePerKw)
{
    if (!pAppConf->loop) {
        //LOGD("This AppConf not working\n");
        return false;
    }

    DBGTRACE_BEGIN
    pthread_mutex_lock(&pAppConf->mux_self);

    bool ret;
    utl_buf_t buf_bolt = UTL_BUF_INIT;
    ln_self_t *p_self = pAppConf->p_self;

    ret = ln_update_fee_create(p_self, &buf_bolt, FeeratePerKw);
    if (ret) {
        uint32_t oldrate = ln_feerate_per_kw(p_self);
        ln_feerate_per_kw_set(p_self, FeeratePerKw);
        send_peer_noise(pAppConf, &buf_bolt);
        utl_buf_free(&buf_bolt);
        lnapp_save_event(ln_channel_id(p_self),
                "updatefee send: %" PRIu32 " --> %" PRIu32,
                oldrate, FeeratePerKw);
    } else {
        lnapp_save_event(ln_channel_id(p_self), "fail updatefee");
    }

    pthread_mutex_unlock(&pAppConf->mux_self);
    DBGTRACE_END

    return ret;
}


/*******************************************
 * その他
 *******************************************/

bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id)
{
    if (!pAppConf->loop) {
        //LOGD("This AppConf not working\n");
        return false;
    }

    return (short_channel_id == ln_short_channel_id(pAppConf->p_self));
}


void lnapp_show_self(const lnapp_conf_t *pAppConf, cJSON *pResult, const char *pSvrCli)
{
    if ((!pAppConf->loop) || (pAppConf->sock < 0)) {
        return;
    }

    ln_self_t *p_self = pAppConf->p_self;

    cJSON *result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, "role", cJSON_CreateString(pSvrCli));

    if (p_self && ln_short_channel_id(p_self)) {
        char str[256];

        const char *p_status = ln_status_string(p_self);
        cJSON_AddItemToObject(result, "status", cJSON_CreateString(p_status));

        //peer node_id
        utl_misc_bin2str(str, ln_their_node_id(p_self), BTC_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //channel_id
        utl_misc_bin2str(str, ln_channel_id(p_self), LN_SZ_CHANNEL_ID);
        cJSON_AddItemToObject(result, "channel_id", cJSON_CreateString(str));
        //short_channel_id
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_self));
        cJSON_AddItemToObject(result, "short_channel_id", cJSON_CreateString(str_sci));
        //funding_tx
        utl_misc_bin2str_rev(str, ln_funding_txid(p_self), BTC_SZ_TXID);
        cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
        cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_txindex(p_self)));
        //confirmation
        uint32_t confirm;
        bool b_get = btcrpc_get_confirm(&confirm, ln_funding_txid(p_self));
        if (b_get) {
            cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
        }
        //feerate_per_kw
        cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate_per_kw(p_self)));

        //our
        cJSON *our = cJSON_CreateObject();
        //our_msat
        cJSON_AddItemToObject(our, "msatoshi", cJSON_CreateNumber64(ln_our_msat(p_self)));
        //commit_num(local)
        cJSON_AddItemToObject(our, "commit_num", cJSON_CreateNumber(ln_commit_local(p_self)->commit_num));
        //htlc_num(local)
        cJSON_AddItemToObject(our, "htlc_num", cJSON_CreateNumber(ln_commit_local(p_self)->htlc_num));
        cJSON_AddItemToObject(result, "our", our);

        //their
        cJSON *their = cJSON_CreateObject();
        //their_msat
        cJSON_AddItemToObject(their, "msatoshi", cJSON_CreateNumber64(ln_their_msat(p_self)));
        //commit_num(remote)
        cJSON_AddItemToObject(their, "commit_num", cJSON_CreateNumber(ln_commit_remote(p_self)->commit_num));
        //htlc_num(remote)
        cJSON_AddItemToObject(their, "htlc_num", cJSON_CreateNumber(ln_commit_remote(p_self)->htlc_num));
        cJSON_AddItemToObject(result, "their", their);

        if (ln_commit_local(p_self)->htlc_num != 0) {
            cJSON *htlcs = cJSON_CreateArray();
            for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
                const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(p_self, lp);
                if (LN_HTLC_ENABLE(p_htlc)) {
                    cJSON *htlc = cJSON_CreateObject();
                    const char *p_type;
                    switch (p_htlc->stat.flag.addhtlc) {
                    case LN_ADDHTLC_OFFER:
                        p_type = "offered";
                        break;
                    case LN_ADDHTLC_RECV:
                        p_type = "received";
                        break;
                    case LN_ADDHTLC_NONE:
                    default:
                        p_type = "unknown";
                        break;
                    }
                    cJSON_AddItemToObject(htlc, "type", cJSON_CreateString(p_type));
                    cJSON_AddItemToObject(htlc, "htlc id", cJSON_CreateNumber64(p_htlc->id));
                    cJSON_AddItemToObject(htlc, "amount_msat", cJSON_CreateNumber(p_htlc->amount_msat));
                    cJSON_AddItemToObject(htlc, "cltv_expiry", cJSON_CreateNumber(p_htlc->cltv_expiry));
                    if (p_htlc->prev_short_channel_id != 0) {
                        if (p_htlc->prev_short_channel_id == UINT64_MAX) {
                            cJSON_AddItemToObject(htlc, "role", cJSON_CreateString("final node"));
                        } else {
                            char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
                            ln_short_channel_id_string(str_sci, p_htlc->prev_short_channel_id);
                            cJSON_AddItemToObject(htlc, "from", cJSON_CreateString(str_sci));
                        }
                    }
                    cJSON_AddItemToArray(htlcs, htlc);
                }
            }
            cJSON_AddItemToObject(result, "htlc", htlcs);
        }
    } else if (p_self && pAppConf->funding_waiting) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("wait_minimum_depth"));

        //peer node_id
        utl_misc_bin2str(str, ln_their_node_id(p_self), BTC_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //channel_id
        utl_misc_bin2str(str, ln_channel_id(p_self), LN_SZ_CHANNEL_ID);
        cJSON_AddItemToObject(result, "channel_id", cJSON_CreateString(str));
        //funding_tx
        utl_misc_bin2str_rev(str, ln_funding_txid(p_self), BTC_SZ_TXID);
        cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
        cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_txindex(p_self)));
        //confirmation
        uint32_t confirm;
        bool b_get = btcrpc_get_confirm(&confirm, ln_funding_txid(p_self));
        if (b_get) {
            cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
        }
        //minimum_depth
        cJSON_AddItemToObject(result, "minimum_depth", cJSON_CreateNumber(ln_minimum_depth(p_self)));
        //feerate_per_kw
        cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate_per_kw(p_self)));
    } else if (p_self && ln_is_funding(p_self)) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("fund_waiting"));

        //peer node_id
        utl_misc_bin2str(str, pAppConf->node_id, BTC_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
    } else if (btc_keys_chkpub(pAppConf->node_id)) {
        char str[256];

        const char *p_conn;
        if (lnapp_is_inited(pAppConf)) {
            p_conn = "connected";
        } else {
            p_conn = "wait_connection";
        }
        cJSON_AddItemToObject(result, "status", cJSON_CreateString(p_conn));

        //peer node_id
        utl_misc_bin2str(str, pAppConf->node_id, BTC_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
    } else {
        cJSON_AddItemToObject(result, "status", cJSON_CreateString("disconnected"));
    }
    if ((pAppConf->err != 0) && (pAppConf->p_errstr != NULL)) {
        cJSON_AddItemToObject(result, "last_app_errmsg", cJSON_CreateString(pAppConf->p_errstr));
    }
    if (ln_err(p_self) != 0) {
        cJSON_AddItemToObject(result, "last_lib_errmsg", cJSON_CreateString(ln_errmsg(p_self)));
    }
    cJSON_AddItemToArray(pResult, result);
}


bool lnapp_get_committx(lnapp_conf_t *pAppConf, cJSON *pResult, bool bLocal)
{
    LOGD("bLocal=%d\n", bLocal);

    pthread_mutex_lock(&pAppConf->mux_self);
    ln_close_force_t close_dat;
    bool ret;
    if (bLocal) {
        ret = ln_close_create_unilateral_tx(pAppConf->p_self, &close_dat);
    } else {
        ret = ln_close_create_tx(pAppConf->p_self, &close_dat);
    }
    if (ret) {
        cJSON *result = cJSON_CreateObject();
        utl_buf_t buf = UTL_BUF_INIT;

#if 1
        if (close_dat.p_tx[LN_CLOSE_IDX_COMMIT].vout_cnt > 0) {
            btc_tx_create(&buf, &close_dat.p_tx[LN_CLOSE_IDX_COMMIT]);
            char *transaction = (char *)UTL_DBG_MALLOC(buf.len * 2 + 1);        //UTL_DBG_FREE: この中
            utl_misc_bin2str(transaction, buf.buf, buf.len);
            utl_buf_free(&buf);

            cJSON_AddItemToObject(result, "committx", cJSON_CreateString(transaction));
            UTL_DBG_FREE(transaction);
        }
#else
        for (int lp = 0; lp < close_dat.num; lp++) {
            if (close_dat.p_tx[lp].vout_cnt > 0) {
                btc_tx_create(&buf, &close_dat.p_tx[lp]);
                char *transaction = (char *)UTL_DBG_MALLOC(buf.len * 2 + 1);        //UTL_DBG_FREE: この中
                utl_misc_bin2str(transaction, buf.buf, buf.len);
                utl_buf_free(&buf);

                char title[10];
                if (lp == LN_CLOSE_IDX_COMMIT) {
                    strcpy(title, "committx");
                } else if (lp == LN_CLOSE_IDX_TOLOCAL) {
                    strcpy(title, "to_local");
                } else if (lp == LN_CLOSE_IDX_TOREMOTE) {
                    strcpy(title, "to_remote");
                } else {
                    sprintf(title, "htlc%d", lp - LN_CLOSE_IDX_HTLC);
                }
                cJSON_AddItemToObject(result, title, cJSON_CreateString(transaction));
                UTL_DBG_FREE(transaction);
            }
        }

        int num = close_dat.tx_buf.len / sizeof(btc_tx_t);
        btc_tx_t *p_tx = (btc_tx_t *)close_dat.tx_buf.buf;
        for (int lp = 0; lp < num; lp++) {
            btc_tx_create(&buf, &p_tx[lp]);
            char *transaction = (char *)UTL_DBG_MALLOC(buf.len * 2 + 1);    //UTL_DBG_FREE: この中
            utl_misc_bin2str(transaction, buf.buf, buf.len);
            utl_buf_free(&buf);

            cJSON_AddItemToObject(result, "htlc_out", cJSON_CreateString(transaction));
            UTL_DBG_FREE(transaction);
        }
#endif
        const char *p_title = (bLocal) ? "local" : "remote";
        cJSON_AddItemToObject(pResult, p_title, result);

        ln_close_free_forcetx(&close_dat);
    }
    pthread_mutex_unlock(&pAppConf->mux_self);

    return ret;
}


bool lnapp_is_looping(const lnapp_conf_t *pAppConf)
{
    return pAppConf->loop;
}


bool lnapp_is_inited(const lnapp_conf_t *pAppConf)
{
    return (pAppConf->flag_recv & RECV_MSG_END) == RECV_MSG_END;
}


void lnapp_save_event(const uint8_t *pChannelId, const char *pFormat, ...)
{
    char fname[256];

    if (pChannelId != NULL) {
        char chanid[LN_SZ_CHANNEL_ID * 2 + 1];
        utl_misc_bin2str(chanid, pChannelId, LN_SZ_CHANNEL_ID);
        sprintf(fname, FNAME_CHANNEL_LOG, chanid);
    } else {
        sprintf(fname, FNAME_EVENT_LOG);
    }
    FILE *fp = fopen(fname, "a");
    if (fp != NULL) {
        char time[UTL_SZ_TIME_FMT_STR + 1];
        fprintf(fp, "[%s]", utl_time_str_time(time));

        va_list ap;
        va_start(ap, pFormat);
        vfprintf(fp, pFormat, ap);
        va_end(ap);

        fprintf(fp, "\n");
        fclose(fp);
    }
}


/********************************************************************
 * private functions
 ********************************************************************/

/********************************************************************
 * [THREAD]channel
 ********************************************************************/

/** channel thread entry point
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
static void *thread_main_start(void *pArg)
{
    bool ret;
    int retval;
    bool detect;
    bool isync;
    bool b_channelreestablished = false;

    LOGD("[THREAD]ln_self_t initialize\n");

    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;
    ln_self_t *p_self = (ln_self_t *)UTL_DBG_MALLOC(sizeof(ln_self_t));

    p_self->p_param = p_conf;

    load_announce_settings();

    //スレッド
    pthread_t   th_recv;        //peer受信
    pthread_t   th_poll;        //トランザクション監視
    pthread_t   th_anno;        //announce

    //seed作成(後でDB読込により上書きされる可能性あり)
    uint8_t seed[LN_SZ_SEED];
    utl_rng_rand(seed, LN_SZ_SEED);
    ln_init(p_self, seed, &mAnnoPrm, notify_cb);

    p_conf->p_self = p_self;
    p_conf->ping_counter = 0;
    p_conf->funding_waiting = false;
    p_conf->funding_confirm = 0;
    p_conf->flag_recv = 0;
    p_conf->last_anno_cnl = 0;
    p_conf->annodb_updated = false;
    p_conf->annodb_cont = false;
    p_conf->annodb_stamp = 0;
    p_conf->err = 0;
    p_conf->p_errstr = NULL;
    utl_buf_init(&p_conf->buf_sendque);
    LIST_INIT(&p_conf->rcvidle_head);
    LIST_INIT(&p_conf->payroute_head);

    pthread_cond_init(&p_conf->cond, NULL);
    pthread_mutex_init(&p_conf->mux, NULL);
    pthread_mutex_init(&p_conf->mux_send, NULL);
    pthread_mutex_init(&p_conf->mux_rcvidle, NULL);
    pthread_mutex_init(&p_conf->mux_sendque, NULL);
    {
        pthread_mutex_t mux_self = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
        memcpy(&p_conf->mux_self, &mux_self, sizeof(mux_self));
    }

    p_conf->loop = true;

    LOGD("wait peer connected...\n");
    ret = wait_peer_connected(p_conf);
    if (!ret) {
        goto LABEL_SHUTDOWN;
    }

    //noise protocol handshake
    ret = noise_handshake(p_conf);
    if (!ret) {
        //ノード接続失敗リストに追加
        ptarmd_nodefail_add(p_conf->node_id, p_conf->conn_str, p_conf->conn_port, LN_NODEDESC_IPV4);
        goto LABEL_SHUTDOWN;
    }

    //失敗リストに乗っている可能性があるため、削除
    (void)ptarmd_nodefail_get(p_conf->node_id, p_conf->conn_str, p_conf->conn_port, LN_NODEDESC_IPV4, true);

    LOGD("connected peer(sock=%d): ", p_conf->sock);
    DUMPD(p_conf->node_id, BTC_SZ_PUBKEY);
    fprintf(stderr, "connected peer: ");
    btc_util_dumpbin(stderr, p_conf->node_id, BTC_SZ_PUBKEY, true);

    //init交換前に設定する(open_channelの受信に間に合わない場合あり issue #351)
    ln_peer_set_nodeid(p_self, p_conf->node_id);
    load_channel_settings(p_conf);

    /////////////////////////
    // handshake完了
    //      server動作時、p_conf->node_idに相手node_idが入っている
    /////////////////////////

    //p_conf->node_idがchannel情報を持っているかどうか。
    //持っている場合、selfにDBから読み込みまで行われている。
    detect = ln_node_search_channel(p_self, p_conf->node_id);
    if (detect && ln_status_is_closing(p_self)) {
        LOGD("$$$ closing channel: %016" PRIx64 "\n", ln_short_channel_id(p_self));
        goto LABEL_SHUTDOWN;
    }

    //
    //selfへの設定はこれ以降に行う
    //

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
        LOGD("fail: exchange init\n");
        goto LABEL_JOIN;
    }

    isync = ln_need_init_routing_sync(p_self);
    if (isync) {
        //annoinfo情報削除(node_id指定)
        LOGD("initial_routing_sync ON\n");
        ln_db_annoinfos_del(p_conf->node_id);
    }

    //送金先
    if (ln_shutdown_scriptpk_local(p_self)->len == 0) {
        utl_buf_t buf = UTL_BUF_INIT;
        ret = getnewaddress(&buf);
        if (!ret) {
            LOGD("fail: create address\n");
            goto LABEL_JOIN;
        }
        ln_shutdown_set_vout_addr(p_self, &buf);
        utl_buf_free(&buf);
    }

    // Establishチェック
    if (detect) {
        // DBにchannel_id登録済み
        // →funding_txは展開されている
        //
        // selfの主要なデータはDBから読込まれている(copy_channel() : ln_node.c)
        LOGD("have channel\n");

        if (!ln_status_is_closing(p_self)) {
            if (ln_status_get(p_self) == LN_STATUS_NORMAL) {
                // funding_txはブロックに入ってminimum_depth以上経過している
                LOGD("$$$ Established\n");
                ln_establish_free(p_self);
            } else {
                // funding_txはminimum_depth未満
                LOGD("$$$ funding_tx in mempool\n");
                TXIDD(ln_funding_txid(p_self));

                p_conf->funding_waiting = true;
            }

            ln_nodeaddr_t conn_addr;
            ret = utl_addr_ipv4_str2bin(conn_addr.addrinfo.ipv4.addr, p_conf->conn_str);
            if (ret) {
                conn_addr.type = LN_NODEDESC_IPV4;
                conn_addr.port = p_conf->conn_port;
                ln_last_connected_addr_set(p_self, &conn_addr);
            }

            b_channelreestablished = exchange_reestablish(p_conf);
            if (b_channelreestablished) {
                LOGD("exchange: channel_reestablish\n");
            } else {
                LOGD("fail: exchange channel_reestablish\n");
                goto LABEL_JOIN;
            }

#ifndef USE_SPV
#else
            //NOTE:
            //  This process take a lot of time.
            //  `init` and `channel_reestablish` require response quickly.
            btcrpc_set_channel(ln_their_node_id(p_self),
                    ln_short_channel_id(p_self),
                    ln_funding_txid(p_self),
                    ln_funding_txindex(p_self),
                    ln_funding_redeem(p_self),
                    ln_funding_blockhash(p_self));
#endif
        } else {
            const char *p_str = ln_status_string(p_self);
            LOGD("$$$ now closing: %s\n", p_str);
        }
    } else {
        // channel_idはDB未登録
        // →ユーザの指示待ち
        LOGD("no channel_id\n");
    }

    if (!p_conf->loop) {
        LOGD("fail: loop ended: %016" PRIx64 "\n", ln_short_channel_id(p_self));
        goto LABEL_JOIN;
    }

    //初期化完了
    LOGD("*** message inited ***\n");
    p_conf->flag_recv |= RECV_MSG_END;

    if (ln_funding_locked_check_need(p_self)) {
        //funding_locked交換
        ret = exchange_funding_locked(p_conf);
        if (!ret) {
            LOGD("fail: exchange funding_locked\n");
            goto LABEL_JOIN;
        }
    }

    if (b_channelreestablished) {
        ln_channel_reestablish_after(p_self);
    }

    if (ln_is_shutdown_sent(p_self)) {
        //BOLT02
        //  upon reconnection:
        //    if it has sent a previous shutdown:
        //      MUST retransmit shutdown.
        utl_buf_t buf_sdn = UTL_BUF_INIT;
        bool ret = ln_shutdown_create(p_self, &buf_sdn);
        if (ret) {
            send_peer_noise(p_conf, &buf_sdn);
        } else {
            LOGD("fail: shutdown\n");
        }
        utl_buf_free(&buf_sdn);
    }

    // flush buffered BOLT message
    send_queue_flush(p_conf);

    // send `channel_update` for private/before publish channel
    send_cnlupd_before_announce(p_conf);

    {
        // method: connected
        // $1: short_channel_id
        // $2: node_id
        // $3: peer_id
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_self));
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        char peer_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(peer_id, p_conf->node_id, BTC_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%s %s "
                    "%s",
                    str_sci, node_id,
                    peer_id);
        ptarmd_call_script(PTARMD_EVT_CONNECTED, param);

        FILE *fp = fopen(FNAME_CONN_LOG, "a");
        if (fp) {
            char time[UTL_SZ_TIME_FMT_STR + 1];
            fprintf(fp, "[%s]OK: %s@%s:%" PRIu16 "\n", utl_time_str_time(time), peer_id, p_conf->conn_str, p_conf->conn_port);
            fclose(fp);
        }
    }

    pthread_mutex_lock(&p_conf->mux);
    while (p_conf->loop) {
        LOGD("loop...\n");

        //mainloop待ち合わせ(*2)
        pthread_cond_wait(&p_conf->cond, &p_conf->mux);
    }
    pthread_mutex_unlock(&p_conf->mux);

LABEL_JOIN:
    LOGD("stop threads...\n");
    stop_threads(p_conf);
    pthread_join(th_recv, NULL);
    pthread_join(th_poll, NULL);
    pthread_join(th_anno, NULL);

LABEL_SHUTDOWN:
    LOGD("shutdown: sock=%d...\n", p_conf->sock);
    retval = close(p_conf->sock);
    if (retval < 0) {
        LOGD("socket close: %s", strerror(errno));
    }

    LOGD("stop channel[%016" PRIx64 "]\n", ln_short_channel_id(p_self));

    if (ln_short_channel_id(p_self) != 0) {
        // method: disconnect
        // $1: short_channel_id
        // $2: node_id
        // $3: peer_id
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_self));
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        char peer_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(peer_id, p_conf->node_id, BTC_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%s %s "
                    "%s",
                    str_sci, node_id,
                    peer_id);
        ptarmd_call_script(PTARMD_EVT_DISCONNECTED, param);
    }

    //クリア
    UTL_DBG_FREE(p_conf->p_errstr);
    ln_term(p_self);
    payroute_clear(p_conf);
    rcvidle_clear(p_conf);
    send_queue_clear(p_conf);
    p_conf->sock = -1;
    p_conf->loop = false;
    UTL_DBG_FREE(p_self);

    pthread_mutex_destroy(&p_conf->mux_sendque);
    pthread_mutex_destroy(&p_conf->mux_rcvidle);
    pthread_mutex_destroy(&p_conf->mux_send);
    pthread_mutex_destroy(&p_conf->mux_self);
    pthread_mutex_destroy(&p_conf->mux);
    pthread_cond_destroy(&p_conf->cond);

    while (p_conf->payroute_head.lh_first != NULL) {
        LIST_REMOVE(p_conf->payroute_head.lh_first, list);
    }
    while (p_conf->rcvidle_head.lh_first != NULL) {
        LIST_REMOVE(p_conf->rcvidle_head.lh_first, list);
    }
    utl_buf_free(&p_conf->buf_sendque);

    LOGD("[exit]lnapp thread\n");

    return NULL;
}


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
        LOGD("fail poll: %s\n", strerror(errno));
        return false;
    }

    int optval;
    socklen_t optlen = sizeof(optval);
    int retval = getsockopt(p_conf->sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
    if (retval != 0) {
        LOGD("fail getsockopt: %s\n", strerror(errno));
        return false;
    }
    if (optval) {
        LOGD("fail getsockopt: optval: %s\n", strerror(optval));
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
        ret = ln_handshake_start(p_conf->p_self, &buf, p_conf->node_id);
        if (!ret) {
            LOGD("fail: ln_handshake_start\n");
            goto LABEL_EXIT;
        }
        LOGD("** SEND act one **\n");
        ret = send_peer_raw(p_conf, &buf);
        if (!ret) {
            LOGD("fail: socket write\n");
            goto LABEL_EXIT;
        }

        //recv: act two
        LOGD("** RECV act two... **\n");
        len_msg = recv_peer(p_conf, rbuf, 50, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            stop_threads(p_conf);
            goto LABEL_EXIT;
        }
        LOGD("** RECV act two ! **\n");
        utl_buf_free(&buf);
        utl_buf_alloccopy(&buf, rbuf, 50);
        ret = ln_handshake_recv(p_conf->p_self, &b_cont, &buf);
        if (!ret || b_cont) {
            LOGD("fail: ln_handshake_recv1\n");
            goto LABEL_EXIT;
        }
        //send: act three
        LOGD("** SEND act three **\n");
        ret = send_peer_raw(p_conf, &buf);
        if (!ret) {
            LOGD("fail: socket write\n");
            goto LABEL_EXIT;
        }

        result = true;
   } else {
        //responderはnode_idを知らない

        //recv: act one
        ret = ln_handshake_start(p_conf->p_self, &buf, NULL);
        if (!ret) {
            LOGD("fail: ln_handshake_start\n");
            goto LABEL_EXIT;
        }
        LOGD("** RECV act one... **\n");
        len_msg = recv_peer(p_conf, rbuf, 50, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            stop_threads(p_conf);
            goto LABEL_EXIT;
        }
        LOGD("** RECV act one ! **\n");
        utl_buf_alloccopy(&buf, rbuf, 50);
        ret = ln_handshake_recv(p_conf->p_self, &b_cont, &buf);
        if (!ret || !b_cont) {
            LOGD("fail: ln_handshake_recv1\n");
            goto LABEL_EXIT;
        }
        //send: act two
        LOGD("** SEND act two **\n");
        ret = send_peer_raw(p_conf, &buf);
        if (!ret) {
            LOGD("fail: socket write\n");
            goto LABEL_EXIT;
        }

        //recv: act three
        LOGD("** RECV act three... **\n");
        len_msg = recv_peer(p_conf, rbuf, 66, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            stop_threads(p_conf);
            goto LABEL_EXIT;
        }
        LOGD("** RECV act three ! **\n");
        utl_buf_free(&buf);
        utl_buf_alloccopy(&buf, rbuf, 66);
        ret = ln_handshake_recv(p_conf->p_self, &b_cont, &buf);
        if (!ret || b_cont) {
            LOGD("fail: ln_handshake_recv2\n");
            goto LABEL_EXIT;
        }

        //bufには相手のnode_idが返ってくる
        if (buf.len == BTC_SZ_PUBKEY) {
            //既に接続済みのlnappがある場合、そちらを切断させる
            //  socket切断を識別できないまま再接続されることがあるため
            lnapp_conf_t *p_exist_conf = ptarmd_search_connected_nodeid(buf.buf);
            if (p_exist_conf != NULL) {
                LOGD("stop already connected lnapp\n");
                lnapp_stop(p_exist_conf);
            }

            memcpy(p_conf->node_id, buf.buf, BTC_SZ_PUBKEY);

            result = true;
        }
    }

LABEL_EXIT:
    LOGD("noise handshake: %d\n", result);
    utl_buf_free(&buf);
    ln_handshake_free(p_conf->p_self);

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
    bool ret = btcrpc_get_short_channel_param(ln_their_node_id(p_conf->p_self), &bheight, &bindex, mined_hash, ln_funding_txid(p_conf->p_self));
    if (ret) {
        LOGD("bindex=%d, bheight=%d\n", bindex, bheight);
        ln_short_channel_id_set_param(p_conf->p_self, bheight, bindex);
        ln_funding_blockhash_set(p_conf->p_self, mined_hash);
        ln_db_annoown_save(ln_short_channel_id(p_conf->p_self));
        LOGD("short_channel_id = %016" PRIx64 "(%d)\n", ln_short_channel_id(p_conf->p_self), ret);
    }

    return ret;
}


/** init交換
 *
 * @retval  true    init交換完了
 */
static bool exchange_init(lnapp_conf_t *p_conf)
{
    utl_buf_t buf_bolt = UTL_BUF_INIT;

    bool ret = ln_init_create(p_conf->p_self, &buf_bolt, p_conf->routesync == PTARMD_ROUTESYNC_INIT, true);     //channel announceあり
    if (!ret) {
        LOGD("fail: create\n");
        return false;
    }
    send_peer_noise(p_conf, &buf_bolt);
    utl_buf_free(&buf_bolt);

    //コールバックでのINIT受信通知待ち
    LOGD("wait: init\n");
    uint32_t count = M_WAIT_RESPONSE_MSEC / M_WAIT_RECV_MSG_MSEC;
    while (p_conf->loop && (count > 0) && ((p_conf->flag_recv & RECV_MSG_INIT) == 0)) {
        utl_misc_msleep(M_WAIT_RECV_MSG_MSEC);
        count--;
    }
    LOGD("loop:%d, count:%d, flag_recv=%02x\n", p_conf->loop, count, p_conf->flag_recv);
    return p_conf->loop && ((p_conf->flag_recv & RECV_MSG_INIT) != 0);
}


/** channel_reestablish交換
 *
 * @retval  true    channel_reestablish交換完了
 */
static bool exchange_reestablish(lnapp_conf_t *p_conf)
{
    utl_buf_t buf_bolt = UTL_BUF_INIT;

    bool ret = ln_channel_reestablish_create(p_conf->p_self, &buf_bolt);
    if (!ret) {
        LOGD("fail: create\n");
        return false;
    }
    send_peer_noise(p_conf, &buf_bolt);
    utl_buf_free(&buf_bolt);

    //コールバックでのchannel_reestablish受信通知待ち
    LOGD("wait: channel_reestablish\n");
    uint32_t count = M_WAIT_CHANREEST_MSEC / M_WAIT_RECV_MSG_MSEC;
    while (p_conf->loop && (count > 0) && ((p_conf->flag_recv & RECV_MSG_REESTABLISH) == 0)) {
        utl_misc_msleep(M_WAIT_RECV_MSG_MSEC);
        count--;
    }
    LOGD("loop:%d, count:%d, flag_recv=%02x\n", p_conf->loop, count, p_conf->flag_recv);
    return p_conf->loop && ((p_conf->flag_recv & RECV_MSG_REESTABLISH) != 0);
}


/** funding_locked交換
 *
 * @retval  true    funding_locked交換完了
 */
static bool exchange_funding_locked(lnapp_conf_t *p_conf)
{
    utl_buf_t buf_bolt = UTL_BUF_INIT;

    bool ret = ln_funding_locked_create(p_conf->p_self, &buf_bolt);
    if (!ret) {
        LOGD("fail: create\n");
        return false;
    }
    send_peer_noise(p_conf, &buf_bolt);
    utl_buf_free(&buf_bolt);

    //コールバックでのfunding_locked受信通知待ち
    LOGD("wait: funding_locked\n");
    while (p_conf->loop && ((p_conf->flag_recv & RECV_MSG_FUNDINGLOCKED) == 0)) {
        utl_misc_msleep(M_WAIT_RECV_MSG_MSEC);
    }
    LOGD("exchange: funding_locked\n");

    //set short_channel_id
    (void)set_short_channel_id(p_conf);

    // method: established
    // $1: short_channel_id
    // $2: node_id
    // $3: our_msat
    // $4: funding_txid
    char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
    ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
    char txidstr[BTC_SZ_TXID * 2 + 1];
    utl_misc_bin2str_rev(txidstr, ln_funding_txid(p_conf->p_self), BTC_SZ_TXID);
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
    char param[256];
        sprintf(param, "%s %s "
                "%" PRIu64 " "
                "%s",
                str_sci, node_id,
                ln_node_total_msat(),
                txidstr);
    ptarmd_call_script(PTARMD_EVT_ESTABLISHED, param);

    return true;
}


/** open_channel送信
 *
 */
static bool send_open_channel(lnapp_conf_t *p_conf, const funding_conf_t *pFunding)
{
    ln_fundin_t fundin;
    utl_buf_init(&fundin.change_spk);

    //Establish開始
    LOGD("  funding_sat: %" PRIu64 "\n", pFunding->funding_sat);
    LOGD("  push_sat: %" PRIu64 "\n", pFunding->push_sat);

    bool ret = getnewaddress(&fundin.change_spk);
    if (!ret) {
        LOGD("fail: getnewaddress\n");
        return false;
    }

    bool unspent;
#ifndef USE_SPV
    //事前にfund-in txがunspentかどうかチェックしようとしている。
    //SPVの場合は1st Layerの処理も内部で行うので、チェック不要。
    ret = btcrpc_check_unspent(NULL, &unspent, &fundin.amount, pFunding->txid, pFunding->txindex);
    LOGD("ret=%d, unspent=%d, fundin.amount=%" PRIu64 "\n", ret, unspent, fundin.amount);
#else
    //SPVの場合、内部でfund-in txを生成するため、チェック不要
    unspent = true;
    ret = true;
#endif
    if (ret && unspent) {
        uint32_t feerate_kw;
        if (pFunding->feerate_per_kw == 0) {
            feerate_kw = monitoring_get_latest_feerate_kw();
        } else {
            feerate_kw = pFunding->feerate_per_kw;
        }
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_kw);

#ifndef USE_SPV
        //bitcoindはptarmdがfunding_txを作るため、fee計算する
        uint64_t estfee = ln_estimate_fundingtx_fee(feerate_kw);
        LOGD("estimate funding_tx fee: %" PRIu64 "\n", estfee);
        if (fundin.amount < pFunding->funding_sat + estfee) {
            //amountが足りないと思われる
            LOGD("fail: amount too short\n");
            LOGD("  %" PRIu64 " < %" PRIu64 " + %" PRIu64 "\n", fundin.amount, pFunding->funding_sat, estfee);
            return false;
        }

        memcpy(fundin.txid, pFunding->txid, BTC_SZ_TXID);
        fundin.index = pFunding->txindex;
#else
        //SPVの場合、funding_txをSPVが作るため、fundin未使用
        memset(&fundin, 0, sizeof(fundin));
#endif

        utl_buf_t buf_bolt = UTL_BUF_INIT;
        ret = ln_open_channel_create(p_conf->p_self, &buf_bolt,
                        &fundin,
                        pFunding->funding_sat,
                        pFunding->push_sat,
                        feerate_kw);
        if (ret) {
            LOGD("SEND: open_channel\n");
            send_peer_noise(p_conf, &buf_bolt);
        }
        utl_buf_free(&buf_bolt);
    } else {
        LOGD("fail through: check_unspent: ");
        TXIDD(pFunding->txid);
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
    utl_buf_t buf_recv;
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;

    LOGD("[THREAD]recv initialize\n");

    //init受信待ちの準備時間を設ける
    utl_misc_msleep(M_WAIT_RECV_THREAD_MSEC);

    while (p_conf->loop) {
        bool ret = true;

        //noise packet データ長
        uint8_t head[LN_SZ_NOISE_HEADER];
        uint16_t len = recv_peer(p_conf, head, LN_SZ_NOISE_HEADER, 0);
        if (len == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            stop_threads(p_conf);
            break;
        }
        assert(len == LN_SZ_NOISE_HEADER);
        if (len == LN_SZ_NOISE_HEADER) {
            len = ln_noise_dec_len(p_conf->p_self, head, len);
        } else {
            break;
        }

        utl_buf_alloc(&buf_recv, len);
        uint16_t len_msg = recv_peer(p_conf, buf_recv.buf, len, M_WAIT_RESPONSE_MSEC);
        if (len_msg == 0) {
            //peerから切断された
            LOGD("DISC: loop end\n");
            stop_threads(p_conf);
            break;
        }
        if (len_msg == len) {
            buf_recv.len = len;
            ret = ln_noise_dec_msg(p_conf->p_self, &buf_recv);
            if (!ret) {
                LOGD("DECODE: loop end\n");
                stop_threads(p_conf);
            }

            //ping送信待ちカウンタ
            //p_conf->ping_counter = 0;
        } else {
            break;
        }

        if (ret) {
            //LOGD("type=%02x%02x\n", buf_recv.buf[0], buf_recv.buf[1]);
            pthread_mutex_lock(&p_conf->mux_self);
            uint16_t type = ln_misc_get16be(buf_recv.buf);
            LOGD("[RECV]type=%04x(%s): sock=%d, Len=%d\n", type, ln_misc_msgname(type), p_conf->sock, buf_recv.len);
            ret = ln_recv(p_conf->p_self, buf_recv.buf, buf_recv.len);
            //LOGD("ln_recv() result=%d\n", ret);
            if (!ret) {
                LOGD("DISC: fail recv message\n");
                lnapp_close_channel_force(ln_their_node_id(p_conf->p_self));
                stop_threads(p_conf);
                break;
            }
            //LOGD("mux_self: end\n");
            pthread_mutex_unlock(&p_conf->mux_self);
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

    while (p_conf->loop && (Len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLIN;
        int polr = poll(&fds, 1, M_WAIT_RECV_TO_MSEC);
        if (polr < 0) {
            LOGD("poll: %s\n", strerror(errno));
            break;
        } else if (polr == 0) {
            //timeout

            // 受信アイドル処理
            rcvidle_pop_and_exec(p_conf);

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
                    LOGD("fail: timeout(len=%d, reqLen=%d)\n", len, Len);
                    break;
                } else {
                    LOGD("fail: %s(%016" PRIx64 ")\n", strerror(errno), ln_short_channel_id(p_conf->p_self));
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

    LOGD("[THREAD]poll initialize\n");

    while (p_conf->loop) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < M_WAIT_POLL_SEC; lp++) {
            sleep(1);
            if (!p_conf->loop) {
                break;
            }
        }
        if (p_conf->p_self == NULL) {
            break;
        }

        if ((p_conf->flag_recv & RECV_MSG_INIT) == 0) {
            //まだ接続していない
            continue;
        }

        poll_ping(p_conf);

        if (utl_misc_is_all_zero(ln_funding_txid(p_conf->p_self), BTC_SZ_TXID)) {
            //fundingしていない
            continue;
        }

        uint32_t bak_conf = p_conf->funding_confirm;
        bool b_get = btcrpc_get_confirm(&p_conf->funding_confirm, ln_funding_txid(p_conf->p_self));
        if (b_get) {
            if (bak_conf != p_conf->funding_confirm) {
#ifndef USE_SPV
#else
                const uint8_t *oldhash = ln_funding_blockhash(p_conf->p_self);
                if (utl_misc_is_all_zero(oldhash, BTC_SZ_HASH256)) {
                    int32_t bheight = 0;
                    int32_t bindex = 0;
                    uint8_t mined_hash[BTC_SZ_HASH256];
                    bool ret = btcrpc_get_short_channel_param(ln_their_node_id(p_conf->p_self), &bheight, &bindex, mined_hash, ln_funding_txid(p_conf->p_self));
                    if (ret) {
                        //mined block hash
                        ln_funding_blockhash_set(p_conf->p_self, mined_hash);
                    }
                }

                btcrpc_set_channel(ln_their_node_id(p_conf->p_self),
                        ln_short_channel_id(p_conf->p_self),
                        ln_funding_txid(p_conf->p_self),
                        ln_funding_txindex(p_conf->p_self),
                        ln_funding_redeem(p_conf->p_self),
                        ln_funding_blockhash(p_conf->p_self));
#endif

                LOGD2("***********************************\n");
                LOGD2("* CONFIRMATION: %d\n", p_conf->funding_confirm);
                LOGD2("*    funding_txid: ");
                TXIDD(ln_funding_txid(p_conf->p_self));
                LOGD2("***********************************\n");
            }
        } else if (!b_get) {
            //LOGD("funding_tx not detect: ");
            //TXIDD(ln_funding_txid(p_conf->p_self));
        } else {
            continue;
        }

        //funding_tx
        if (p_conf->funding_waiting) {
            //funding_tx確定待ち(確定後はEstablishシーケンスの続きを行う)
            poll_funding_wait(p_conf);
        } else {
            //Normal Operation中
            poll_normal_operating(p_conf);
        }

        //announcement_signatures
        //  監視周期によっては funding_confirmが minimum_depth と M_ANNOSIGS_CONFIRMの
        //  両方を満たす可能性があるため、先に poll_funding_wait()を行って self->cnl_anno の準備を済ませる。
        if ( ln_open_channel_announce(p_conf->p_self) &&
             (p_conf->funding_confirm >= LN_ANNOSIGS_CONFIRM) &&
             (p_conf->funding_confirm >= ln_minimum_depth(p_conf->p_self)) ) {
            // BOLT#7: announcement_signaturesは最低でも 6confirmations必要
            //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#requirements
            utl_buf_t buf = UTL_BUF_INIT;
            rcvidle_push(p_conf, RCVIDLE_ANNOSIGNS, &buf);
            ln_open_channel_clr_announce(p_conf->p_self);
        }
    }

    LOGD("[exit]poll thread\n");

    return NULL;
}


static void poll_ping(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    //未送受信の状態が続いたらping送信する
    p_conf->ping_counter++;
    //LOGD("ping_counter=%d\n", p_conf->ping_counter);
    if (p_conf->ping_counter >= M_WAIT_PING_SEC / M_WAIT_POLL_SEC) {
        utl_buf_t buf_ping = UTL_BUF_INIT;

        bool ret = ln_ping_create(p_conf->p_self, &buf_ping);
        if (ret) {
            send_peer_noise(p_conf, &buf_ping);
            utl_buf_free(&buf_ping);
        } else {
            LOGD("pong not respond\n");
            stop_threads(p_conf);
        }
    }

    //DBGTRACE_END
}


//funding_tx確定待ち
static void poll_funding_wait(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    if (p_conf->funding_confirm >= ln_minimum_depth(p_conf->p_self)) {
        LOGD("confirmation OK: %d\n", p_conf->funding_confirm);
        //funding_tx確定
        bool ret = set_short_channel_id(p_conf);
        if (ret) {
            ret = exchange_funding_locked(p_conf);
            assert(ret);

            // send `channel_update` for private/before publish channel
            send_cnlupd_before_announce(p_conf);

            char close_addr[BTC_SZ_ADDR_STR_MAX + 1];
            ret = btc_keys_spk2addr(close_addr, ln_shutdown_scriptpk_local(p_conf->p_self));
            if (!ret) {
                utl_misc_bin2str(close_addr,
                        ln_shutdown_scriptpk_local(p_conf->p_self)->buf,
                        ln_shutdown_scriptpk_local(p_conf->p_self)->len);
            }

            char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
            ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
            lnapp_save_event(ln_channel_id(p_conf->p_self),
                    "funding_locked: short_channel_id=%s, close_addr=%s",
                    str_sci, close_addr);

            p_conf->funding_waiting = false;
        } else {
            LOGD("fail: set_short_channel_id()\n");
        }
    } else {
        LOGD("confirmation waiting...: %d/%d\n", p_conf->funding_confirm, ln_minimum_depth(p_conf->p_self));
    }

    //DBGTRACE_END
}


//Normal Operation中
static void poll_normal_operating(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    bool ret = ln_status_load(p_conf->p_self);
    if (ret && ln_status_is_closing(p_conf->p_self)) {
        //ループ解除
        LOGD("funding_tx is spent: %016" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));
        stop_threads(p_conf);
    }

    //DBGTRACE_END
}


/** announcement前のchannel_update送信
 *      https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001220.html
 *
 */
static void send_cnlupd_before_announce(lnapp_conf_t *p_conf)
{
    ln_self_t *p_self = p_conf->p_self;

    pthread_mutex_lock(&p_conf->mux_self);
    if ((ln_short_channel_id(p_self) != 0) && !ln_is_announced(p_self)) {
        //チャネル作成済み && announcement未交換
        utl_buf_t buf_bolt = UTL_BUF_INIT;
        bool ret = ln_channel_update_create(p_self, &buf_bolt);
        if (ret) {
            send_peer_noise(p_conf, &buf_bolt);
            utl_buf_free(&buf_bolt);
        }
    }
    pthread_mutex_unlock(&p_conf->mux_self);
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

    LOGD("[THREAD]anno initialize\n");

    while (p_conf->loop) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < slp; lp++) {
            sleep(1);
            if (!p_conf->loop) {
                break;
            }
            if (p_conf->annodb_updated) {
                break;
            }
        }

        if ((p_conf->flag_recv & RECV_MSG_END) == 0) {
            //まだ接続完了していない
            continue;
        }
        time_t now = time(NULL);
        if (p_conf->annodb_updated && p_conf->annodb_cont && (now - p_conf->annodb_stamp < M_WAIT_ANNO_HYSTER_SEC)) {
            LOGD("skip\n");
            continue;
        }

        bool retcnl = send_announcement(p_conf);
        if (retcnl) {
            //channel_listの最後まで見終わった
            if (p_conf->annodb_updated) {
                //annodb was updated, so send_announcement() will be done again.
                // since updating annodb may have been in the middle of send_announcement().
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
static bool send_announcement(lnapp_conf_t *p_conf)
{
    bool ret;
    int anno_cnt = 0;
    uint64_t short_channel_id = 0;
    void *p_cur_cnl = NULL;         //channel
    void *p_cur_node = NULL;        //node_announcement
    void *p_cur_infocnl = NULL;     //channel送信済みDB
    void *p_cur_infonode = NULL;    //node_announcement送信済みDB
    utl_buf_t buf_cnl = UTL_BUF_INIT;
    char type;

    LOGD("BEGIN\n");

    ret = ln_db_anno_transaction();
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }

    ret = ln_db_anno_cur_open(&p_cur_cnl, LN_DB_CUR_CNL);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_anno_cur_open(&p_cur_node, LN_DB_CUR_NODE);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_anno_cur_open(&p_cur_infocnl, LN_DB_CUR_INFOCNL);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_anno_cur_open(&p_cur_infonode, LN_DB_CUR_INFONODE);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }

    if (p_conf->last_anno_cnl != 0) {
        //前回のところまで検索する
        while ((ret = ln_db_annocnl_cur_get(p_cur_cnl, &short_channel_id, &type, NULL, &buf_cnl))) {
            if (short_channel_id == p_conf->last_anno_cnl) {
                //この時点でcursorは次に進んでいる
                (void)ln_db_annocnl_cur_getback(p_cur_cnl, &short_channel_id, &type, NULL, &buf_cnl);
                break;
            }
            utl_buf_free(&buf_cnl);
        }
    }
    utl_buf_free(&buf_cnl);

    //これ以降、short_channel_id に 0以外の値が入っている状態で LABEL_EXITに到達すると、
    //  そのshort_channel_idに関する channel_announcement, channel_update は削除される。

    uint32_t timestamp;
    while ((ret = ln_db_annocnl_cur_get(p_cur_cnl, &short_channel_id, &type, &timestamp, &buf_cnl))) {
        if (!p_conf->loop) {
            break;
        }

        //事前チェック
        if (type == LN_DB_CNLANNO_ANNO) {
            p_conf->last_annocnl_sci = short_channel_id;    //channel_updateだけを送信しないようにするため

            //  DBを長時間ロックする可能性があるので、送信しなくてもカウントする
            if (anno_cnt >= M_ANNO_UNIT) {
                break;
            }

            ret = send_anno_pre_chan(short_channel_id);
            if (!ret) {
                LOGD("pre_chan: delete all channel %016" PRIx64 "\n", short_channel_id);
                goto LABEL_EXIT;
            }
        } else if ((type == LN_DB_CNLANNO_UPD1) || (type == LN_DB_CNLANNO_UPD2)) {
            ret = send_anno_pre_upd(short_channel_id, timestamp, p_conf->last_annocnl_sci);
            if (!ret) {
                LOGD("pre_upd: delete channel_update %016" PRIx64 " %c\n", short_channel_id, (char)type);

                //channel_updateをDBから削除
                (void)ln_db_annocnl_cur_del(p_cur_cnl);

                short_channel_id = 0;       //channel自体は削除しない
                goto LABEL_EXIT;
            }
        } else {
            //nothing
        }

        //取得したchannel_announcementのshort_channel_idに一致するものは送信する
        if (p_conf->last_annocnl_sci == short_channel_id) {
            //channel_announcement/channel_update送信済みDB検索
            bool chk = ln_db_annocnlinfo_search_nodeid(p_cur_infocnl, short_channel_id, type, ln_their_node_id(p_conf->p_self));
            if (!chk) {
                //channel_announcement, channel_update
                anno_cnt += send_anno_cnl(p_conf, type, p_cur_infocnl, &buf_cnl);
            } else {
                //LOGD("already sent: short_channel_id=%016" PRIx64 ", type:%c\n", short_channel_id, type);
            }
            if (type == LN_DB_CNLANNO_ANNO) {
                //channel_announcementの送信にかかわらず、未送信のnode_announcementは送信する
                anno_cnt += send_anno_node(p_conf, p_cur_node, p_cur_infonode, &buf_cnl);
            }

            //処理数カウント
            //  DBを長時間ロックする可能性があるので、送信しなくてもカウントする(whileから抜けるのは)
            anno_cnt++;
        } else {
            //channel_announcementが無いchannel_updateの場合
            LOGV("skip channel_%c: last=%016" PRIx64 " / get=%016" PRIx64 "\n", type, p_conf->last_annocnl_sci, short_channel_id);
        }
        utl_buf_free(&buf_cnl);
    }
    if (ret) {
        //次回は続きから始める
        p_conf->last_anno_cnl = short_channel_id;
    } else {
        //リストの最後まで終わったら、また先頭から始める
        LOGV("end of channel list\n");
        p_conf->last_anno_cnl = 0;
    }

    short_channel_id = 0;

LABEL_EXIT:
    utl_buf_free(&buf_cnl);

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
        (void)ln_db_annocnlall_del(short_channel_id);
    }

    LOGD("END: %016" PRIx64 "\n", p_conf->last_anno_cnl);
    return p_conf->last_anno_cnl == 0;
}


/** channel_announcement事前チェック
 *
 * @retval  true        none
 * @retval  false       channel情報を削除してよい
 */
static bool send_anno_pre_chan(uint64_t short_channel_id)
{
    bool ret = true;

#ifndef USE_SPV
    bool unspent = check_unspent_short_channel_id(short_channel_id);
    if (!unspent) {
        //使用済みのため、DBから削除
        LOGD("closed channel: %016" PRIx64 "\n", short_channel_id);
        ret = false;
    }
#else
    (void)short_channel_id;
#endif

    return ret;
}


/** channel_update事前チェック
 *
 * @retval  true        none
 * @retval  false       channel_updateを削除してよい
 */
static bool send_anno_pre_upd(uint64_t short_channel_id, uint32_t timestamp, uint64_t last_short_channel_id)
{
    bool ret = true;

    //BOLT#7: Pruning the Network View
    uint64_t now = (uint64_t)time(NULL);
    if (ln_db_annocnlupd_is_prune(now, timestamp)) {
        //古いため送信しない
        char time[UTL_SZ_TIME_FMT_STR + 1];
        LOGD("older channel_update: prune(%016" PRIx64 "): %s(now=%" PRIu32 ", tm=%" PRIu32 ")\n", short_channel_id, utl_time_fmt(time, timestamp), now, timestamp);
        ret = false;
    }

    //
    if (ret && (short_channel_id != last_short_channel_id)) {
        if (!ln_db_annoown_check(short_channel_id)) {
            //自ノードではないchannel_announcementを持たないchannel_updateのため、削除する
            LOGD("orphan channel_update: prune(%016" PRIx64 ")\n", short_channel_id);
            ret = false;
        }
    }

    return ret;
}


/**
 *
 * @return  送信数
 */
static int send_anno_cnl(lnapp_conf_t *p_conf, char type, void *p_cur_infocnl, const utl_buf_t *p_buf_cnl)
{
    int cnt = 0;
    LOGD("send channel_%c: %016" PRIx64 "\n", type, p_conf->last_annocnl_sci);
    send_peer_noise(p_conf, p_buf_cnl);
    cnt = 2;
    ln_db_annocnlinfo_add_nodeid(p_cur_infocnl, p_conf->last_annocnl_sci, type, false, ln_their_node_id(p_conf->p_self));
    return cnt;
}


/**
 *
 * @return  送信数
 */
static int send_anno_node(lnapp_conf_t *p_conf, void *p_cur_node, void *p_cur_infonode, const utl_buf_t *p_buf_cnl)
{
    uint64_t short_channel_id;
    uint8_t node[2][BTC_SZ_PUBKEY];
    bool ret = ln_getids_cnl_anno(&short_channel_id, node[0], node[1], p_buf_cnl->buf, p_buf_cnl->len);
    if (!ret) {
        return 0;
    }

    int cnt = 1;
    utl_buf_t buf_node = UTL_BUF_INIT;

    for (int lp = 0; lp < 2; lp++) {
        ret = ln_db_annonodinfo_search_nodeid(p_cur_infonode, node[lp], ln_their_node_id(p_conf->p_self));
        if (!ret) {
            ret = ln_db_annonod_cur_load(p_cur_node, &buf_node, NULL, node[lp]);
            if (ret) {
                LOGD("send node_anno: ");
                DUMPD(node[lp], BTC_SZ_PUBKEY);
                send_peer_noise(p_conf, &buf_node);
                utl_buf_free(&buf_node);
                cnt += 2;
                ln_db_annonodinfo_add_nodeid(p_cur_infonode, node[lp], false, ln_their_node_id(p_conf->p_self));
            }
        }
    }
    return cnt;
}


/**************************************************************************
 * コールバック処理
 **************************************************************************/

//コールバック分岐
static void notify_cb(ln_self_t *self, ln_cb_t reason, void *p_param)
{
    //DBGTRACE_BEGIN

    lnapp_conf_t *p_conf = (lnapp_conf_t *)ln_get_param(self);

    const struct {
        const char *p_msg;
        void (*func)(lnapp_conf_t *p_conf, void *p_param);
    } MAP[] = {
        { "  LN_CB_QUIT: channel quit", cb_channel_quit },
        { "  LN_CB_ERROR: error receive", cb_error_recv },
        { "  LN_CB_INIT_RECV: init receive", cb_init_recv },
        { "  LN_CB_REESTABLISH_RECV: channel_reestablish receive", cb_channel_reestablish_recv },
        { "  LN_CB_SIGN_FUNDINGTX_REQ: funding_tx sign request", cb_funding_tx_sign },
        { "  LN_CB_FUNDINGTX_WAIT: funding_tx confirmation wait request", cb_funding_tx_wait },
        { "  LN_CB_FUNDINGLOCKED_RECV: funding_locked receive", cb_funding_locked },
        { NULL/*"  LN_CB_UPDATE_ANNODB: announcement DB update"*/, cb_update_anno_db },
        { "  LN_CB_ADD_HTLC_RECV_PREV: update_add_htlc pre-process", cb_add_htlc_recv_prev },
        { "  LN_CB_ADD_HTLC_RECV: update_add_htlc receive", cb_add_htlc_recv },
        { "  LN_CB_FWD_ADDHTLC_START: update_add_htlc forward", cb_fwd_addhtlc_start },
        { "  LN_CB_BWD_DELHTLC_START: delete htlc", cb_bwd_delhtlc_start },
        { "  LN_CB_FULFILL_HTLC_RECV: update_fulfill_htlc receive", cb_fulfill_htlc_recv },
        { "  LN_CB_FAIL_HTLC_RECV: update_fail_htlc receive", cb_fail_htlc_recv },
        { "  LN_CB_REV_AND_ACK_EXCG: revoke_and_ack exchange", cb_rev_and_ack_excg },
        { "  LN_CB_PAYMENT_RETRY: payment retry", cb_payment_retry},
        { "  LN_CB_UPDATE_FEE_RECV: update_fee receive", cb_update_fee_recv },
        { "  LN_CB_SHUTDOWN_RECV: shutdown receive", cb_shutdown_recv },
        { "  LN_CB_CLOSED_FEE: closing_signed receive(not same fee)", cb_closed_fee },
        { "  LN_CB_CLOSED: closing_signed receive(same fee)", cb_closed },
        { "  LN_CB_SEND_REQ: send request", cb_send_req },
        { "  LN_CB_SEND_QUEUE: add send queue", cb_send_queue },
        { "  LN_CB_SET_LATEST_FEERATE: feerate_per_kw update", cb_set_latest_feerate },
        { "  LN_CB_GETBLOCKCOUNT: getblockcount", cb_getblockcount },
    };

    if (reason < LN_CB_MAX) {
        if (MAP[reason].p_msg != NULL) {
            LOGD("%s\n", MAP[reason].p_msg);
        }
        (*MAP[reason].func)(p_conf, p_param);
    } else {
        LOGD("fail: invalid reason: %d\n", reason);
    }

    //DBGTRACE_END
}


static void cb_channel_quit(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    LOGD("quit channel\n");

    stop_threads(p_conf);
}


//LN_CB_ERROR: error受信
static void cb_error_recv(lnapp_conf_t *p_conf, void *p_param)
{
    const ln_error_t *p_err = (const ln_error_t *)p_param;

    bool b_alloc = false;
    char *p_msg = p_err->p_data;
    for (uint16_t lp = 0; lp < p_err->len; lp++) {
        if (!isprint(p_err->p_data[lp])) {
            //表示できない文字が入っている場合はダンプ出力
            b_alloc = true;
            p_msg = (char *)UTL_DBG_MALLOC(p_err->len * 2 + 1);
            utl_misc_bin2str(p_msg, (const uint8_t *)p_err->p_data, p_err->len);
            break;
        }
    }
    set_lasterror(p_conf, RPCERR_PEER_ERROR, p_msg);
    lnapp_save_event(p_err->p_channel_id, "error message: %s", p_msg);
    if (b_alloc) {
        UTL_DBG_FREE(p_msg);
    }

    if (p_conf->funding_waiting) {
        LOGD("stop funding by error\n");
        p_conf->funding_waiting = false;
    }

    stop_threads(p_conf);
}


//LN_CB_INIT_RECV: init受信
static void cb_init_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    p_conf->initial_routing_sync = *(bool *)p_param;

    //init受信待ち合わせ解除(*1)
    p_conf->flag_recv |= RECV_MSG_INIT;
}


//LN_CB_REESTABLISH_RECV: channel_reestablish受信
static void cb_channel_reestablish_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    //channel_reestablish受信待ち合わせ解除(*3)
    p_conf->flag_recv |= RECV_MSG_REESTABLISH;
}


//LN_CB_SIGN_FUNDINGTX_REQ: funding_tx署名要求
static void cb_funding_tx_sign(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    DBGTRACE_BEGIN

    ln_cb_funding_sign_t *p_sig = (ln_cb_funding_sign_t *)p_param;

    utl_buf_t buf_tx = UTL_BUF_INIT;
    btc_tx_create(&buf_tx, p_sig->p_tx);
    p_sig->ret = btcrpc_sign_rawtx(p_sig->p_tx, buf_tx.buf, buf_tx.len, p_sig->amount);
    utl_buf_free(&buf_tx);
}


//LN_CB_FUNDINGTX_WAIT: funding_txのconfirmation待ち開始
static void cb_funding_tx_wait(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_funding_t *p = (ln_cb_funding_t *)p_param;

    if (p->b_send) {
        uint8_t txid[BTC_SZ_TXID];

        utl_buf_t buf_tx = UTL_BUF_INIT;
        btc_tx_create(&buf_tx, p->p_tx_funding);

        p->b_result = btcrpc_send_rawtx(txid, NULL, buf_tx.buf, buf_tx.len);
        if (p->b_result) {
            LOGD("$$$ broadcast funding_tx\n");
        }
        utl_buf_free(&buf_tx);
    } else {
        p->b_result = true;
    }

    if (p->b_result) {
        //fundingの監視は thread_poll_start()に任せる
        TXIDD(ln_funding_txid(p_conf->p_self));
        p_conf->funding_waiting = true;

#ifndef USE_SPV
#else
        btcrpc_set_channel(ln_their_node_id(p_conf->p_self),
                ln_short_channel_id(p_conf->p_self),
                ln_funding_txid(p_conf->p_self),
                ln_funding_txindex(p_conf->p_self),
                ln_funding_redeem(p_conf->p_self),
                ln_funding_blockhash(p_conf->p_self));
#endif

        const char *p_str;
        if (ln_is_funder(p_conf->p_self)) {
            p_str = "funder";
        } else {
            p_str = "fundee";
        }
        char str_peerid[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(str_peerid, ln_their_node_id(p_conf->p_self), BTC_SZ_PUBKEY);
        lnapp_save_event(ln_channel_id(p_conf->p_self),
                "open: funding wait start(%s): peer_id=%s",
                p_str, str_peerid);
    } else {
        LOGE("fail: broadcast\n");
        lnapp_save_event(ln_channel_id(p_conf->p_self),
                "fail: broadcast funding_tx\n");
        stop_threads(p_conf);
    }

    ln_nodeaddr_t conn_addr;
    bool ret = utl_addr_ipv4_str2bin(conn_addr.addrinfo.ipv4.addr, p_conf->conn_str);
    if (ret) {
        conn_addr.type = LN_NODEDESC_IPV4;
        conn_addr.port = p_conf->conn_port;
        ln_last_connected_addr_set(p_conf->p_self, &conn_addr);
    }

    DBGTRACE_END
}


//LN_CB_FUNDINGLOCKED_RECV: funding_locked受信通知
static void cb_funding_locked(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    if ((p_conf->flag_recv & RECV_MSG_REESTABLISH) == 0) {
        //channel establish時のfunding_locked
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
        lnapp_save_event(ln_channel_id(p_conf->p_self),
                "open: recv funding_locked short_channel_id=%s",
                str_sci);
    }

    //funding_locked受信待ち合わせ解除(*4)
    p_conf->flag_recv |= RECV_MSG_FUNDINGLOCKED;
}


//LN_CB_UPDATE_ANNODB: announcement DB更新通知
static void cb_update_anno_db(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    ln_cb_update_annodb_t *p_anno = (ln_cb_update_annodb_t *)p_param;

    if (p_anno->anno != LN_CB_UPDATE_ANNODB_NONE) {
        LOGD("update anno db: %d\n", (int)p_anno->anno);
        p_conf->annodb_updated = true;
    }
    if (p_anno->anno == LN_CB_UPDATE_ANNODB_CNL_ANNO) {
        time_t now = time(NULL);
        if (now - p_conf->annodb_stamp < M_WAIT_ANNO_HYSTER_SEC) {
            //announcement連続受信中とみなす
            p_conf->annodb_cont = true;
        } else {
            p_conf->annodb_cont = false;
        }
        p_conf->annodb_stamp = now;
        LOGD("annodb_stamp: %u\n", p_conf->annodb_stamp);
    }
}


//LN_CB_ADD_HTLC_RECV_PREV: update_add_htlc受信(前処理)
//  BOLT4チェックをするために転送先チャネルを取得する
static void cb_add_htlc_recv_prev(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;

    DBGTRACE_BEGIN

    ln_cb_add_htlc_recv_prev_t *p_prev = (ln_cb_add_htlc_recv_prev_t *)p_param;

    //転送先取得
    lnapp_conf_t *p_appconf = ptarmd_search_transferable_cnl(p_prev->next_short_channel_id);
    if (p_appconf != NULL) {
        LOGD("get forwarding lnapp\n");
        p_prev->p_next_self = p_appconf->p_self;
    } else {
        LOGD("fail: no forwarding\n");
        p_prev->p_next_self = NULL;
    }

    DBGTRACE_END
}


/** LN_CB_ADD_HTLC_RECV: update_add_htlc受信(後処理)
 *
 * add_htlc受信後は、以下のどれかになる。
 *      - add_htlcがOK
 *          - 自分がfinal node --> fulfill_htlcを巻き戻していく
 *          - else             --> add_htlcを転送する
 *      - add_htlcがNG
 *          - fail_htlcを巻き戻していく
 */
static void cb_add_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_add_htlc_recv_t *p_addhtlc = (ln_cb_add_htlc_recv_t *)p_param;
    const char *p_stat;
    char str_stat[256];

    ptarmd_preimage_lock();
    if (p_addhtlc->p_hop->b_exit) {
        //final node
        p_stat = "final node";
        LOGD("final node\n");
        p_addhtlc->ret = cbsub_add_htlc_finalnode(p_conf, p_addhtlc);
    } else {
        //別channelにupdate_add_htlcを転送する(メッセージ送信は受信アイドル処理で行う)
        snprintf(str_stat, sizeof(str_stat), "-->[fwd]0x%016" PRIx64 ", cltv=%d",
                p_addhtlc->p_hop->short_channel_id,
                p_addhtlc->p_hop->outgoing_cltv_value);
        p_stat = str_stat;
        LOGD("forward\n");
        p_addhtlc->ret = cbsub_add_htlc_forward(p_conf, p_addhtlc);
    }
    ptarmd_preimage_unlock();

    lnapp_save_event(ln_channel_id(p_conf->p_self),
            "[RECV]add_htlc: %s(HTLC id=%" PRIu64 ", amount_msat=%" PRIu64 ", cltv=%d)",
                p_stat,
                p_addhtlc->id,
                p_addhtlc->amount_msat,
                p_addhtlc->cltv_expiry);

    DBGTRACE_END
}


//cb_add_htlc_recv(): final node
static bool cbsub_add_htlc_finalnode(lnapp_conf_t *p_conf, ln_cb_add_htlc_recv_t *p_addhtlc)
{
    char str_payhash[BTC_SZ_HASH256 * 2 + 1];
    utl_misc_bin2str(str_payhash, p_addhtlc->p_payment, BTC_SZ_HASH256);
    lnapp_save_event(NULL,
            "payment final node: payment_hash=%s short_channel_id=%016" PRIx64,
            str_payhash, ln_short_channel_id(p_conf->p_self));
    return true;
}


//cb_add_htlc_recv(): forward
static bool cbsub_add_htlc_forward(lnapp_conf_t *p_conf, ln_cb_add_htlc_recv_t *p_addhtlc)
{
    bool ret = false;
    utl_buf_t reason = UTL_BUF_INIT;
    lnapp_conf_t *p_nextconf = ptarmd_search_transferable_cnl(p_addhtlc->p_hop->short_channel_id);
    if (p_nextconf != NULL) {
        uint64_t htlc_id;
        uint16_t next_idx;
        pthread_mutex_lock(&p_nextconf->mux_self);
        ret = ln_add_htlc_set_fwd(p_nextconf->p_self,
                            &htlc_id,
                            &reason,
                            &next_idx,
                            p_addhtlc->p_onion_reason->buf,
                            p_addhtlc->p_hop->amt_to_forward,
                            p_addhtlc->p_hop->outgoing_cltv_value,
                            p_addhtlc->p_payment,
                            ln_short_channel_id(p_conf->p_self),     //hop
                            p_addhtlc->idx,
                            p_addhtlc->p_shared_secret);
        //utl_buf_free(&pFwdAdd->shared_secret);  //ln.cで管理するため、freeさせない
        if (ret) {
            p_addhtlc->idx = next_idx;
        } else {
            LOGD("fail forward\n");
        }
        pthread_mutex_unlock(&p_nextconf->mux_self);
    }

    if (ret) {
        // method: forward
        // $1: short_channel_id
        // $2: node_id
        // $3: amt_to_forward
        // $4: outgoing_cltv_value
        // $5: payment_hash
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
        char hashstr[BTC_SZ_HASH256 * 2 + 1];
        utl_misc_bin2str(hashstr, p_addhtlc->p_payment, BTC_SZ_HASH256);
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%s %s "
                    "%" PRIu64 " "
                    "%" PRIu32 " "
                    "%s",
                    str_sci, node_id,
                    p_addhtlc->p_hop->amt_to_forward,
                    p_addhtlc->p_hop->outgoing_cltv_value,
                    hashstr);
        ptarmd_call_script(PTARMD_EVT_FORWARD, param);

        lnapp_save_event(ln_channel_id(p_nextconf->p_self),
            "[SEND]add_htlc: amount_msat=%" PRIu64 ", cltv=%d",
                    p_addhtlc->p_hop->amt_to_forward,
                    p_addhtlc->p_hop->outgoing_cltv_value);
    } else if (reason.len == 0) {
        //エラーだがreasonが未設定
        LOGD("fail: temporary_node_failure\n");
        ln_onion_create_reason_temp_node(&reason);
        ln_fail_htlc_set(p_conf->p_self, p_addhtlc->idx, &reason);
    } else {
        //none
        LOGD("fail\n");
    }
    utl_buf_free(&reason);

    return ret;
}


/** LN_CB_FWD_ADDHTLC_START: update_add_htlc転送指示
 *
 */
static void cb_fwd_addhtlc_start(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;

    DBGTRACE_BEGIN

    ln_cb_fwd_add_htlc_t *p_fwd = (ln_cb_fwd_add_htlc_t *)p_param;

    lnapp_conf_t *p_nextconf = ptarmd_search_transferable_cnl(p_fwd->short_channel_id);
    if (p_nextconf != NULL) {
        pthread_mutex_lock(&p_nextconf->mux_self);
        ln_add_htlc_start_fwd(p_nextconf->p_self, p_fwd->idx);
        pthread_mutex_unlock(&p_nextconf->mux_self);
    }

    DBGTRACE_END
}


/** LN_CB_BWD_DELHTLC_START: update_add_htlc転送指示
 *
 */
static void cb_bwd_delhtlc_start(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_bwd_del_htlc_t *p_bwd = (ln_cb_bwd_del_htlc_t *)p_param;
    lnapp_save_event(NULL,
            "delte HTLC: short_channel_id=%016" PRIx64 "fin_delhtlc=%d",
            ln_short_channel_id(p_conf->p_self), p_bwd->fin_delhtlc);

    DBGTRACE_END
}


//LN_CB_FULFILL_HTLC_RECV: update_fulfill_htlc受信
static void cb_fulfill_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_fulfill_htlc_recv_t *p_fulfill = (const ln_cb_fulfill_htlc_recv_t *)p_param;
    const char *p_stat;
    char str_stat[256];

    if (p_fulfill->prev_short_channel_id != 0) {
        LOGD("backwind: id=%" PRIu64 ", prev_short_channel_id=%016" PRIx64 "\n", p_fulfill->id, p_fulfill->prev_short_channel_id);
        snprintf(str_stat, sizeof(str_stat), "-->[fwd]%016" PRIx64, p_fulfill->prev_short_channel_id);
        p_stat = str_stat;

        cbsub_fulfill_backwind(p_conf, p_fulfill);
    } else {
        LOGD("origin node\n");
        p_stat = "origin node";

        cbsub_fulfill_originnode(p_conf, p_fulfill);
    }

    lnapp_save_event(ln_channel_id(p_conf->p_self),
        "[RECV]fulfill_htlc: %s(HTLC id=%" PRIu64 ")",
                p_stat,
                p_fulfill->id);

    DBGTRACE_END
}


//cb_fulfill_htlc_recv(): 巻き戻し
static void cbsub_fulfill_backwind(lnapp_conf_t *p_conf, const ln_cb_fulfill_htlc_recv_t *p_fulfill)
{
    (void)p_conf;

    if (!LN_DBG_FULFILL()) {
        LOGD("DBG: no fulfill mode\n");
        return;
    }

    bool ret = false;
    lnapp_conf_t *p_prevconf = ptarmd_search_transferable_cnl(p_fulfill->prev_short_channel_id);
    if (p_prevconf != NULL) {
        pthread_mutex_lock(&p_prevconf->mux_self);
        ret = ln_fulfill_htlc_set(p_prevconf->p_self, p_fulfill->prev_idx, p_fulfill->p_preimage);
        pthread_mutex_unlock(&p_prevconf->mux_self);
    }
    if (ret) {
        show_self_param(p_conf->p_self, stderr, "fulfill_htlc send", __LINE__);

        // method: fulfill
        // $1: short_channel_id
        // $2: node_id
        // $3: payment_hash
        // $4: payment_preimage
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
        char hashstr[BTC_SZ_HASH256 * 2 + 1];
        uint8_t payment_hash[BTC_SZ_HASH256];
        ln_preimage_hash_calc(payment_hash, p_fulfill->p_preimage);
        utl_misc_bin2str(hashstr, payment_hash, BTC_SZ_HASH256);
        char imgstr[LN_SZ_PREIMAGE * 2 + 1];
        utl_misc_bin2str(imgstr, p_fulfill->p_preimage, LN_SZ_PREIMAGE);
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%s %s "
                    "%s "
                    "%s",
                    str_sci, node_id,
                    hashstr,
                    imgstr);
        ptarmd_call_script(PTARMD_EVT_FULFILL, param);

        lnapp_save_event(ln_channel_id(p_prevconf->p_self),
            "[SEND]fulfill_htlc: HTLC id=%" PRIu64,
                    p_fulfill->id);
    } else {
        //TODO:戻す先がない場合の処理(#366)
        LOGD("fail backward\n");
    }
}


//cb_fulfill_htlc_recv(): origin node
static void cbsub_fulfill_originnode(lnapp_conf_t *p_conf, const ln_cb_fulfill_htlc_recv_t *p_fulfill)
{
    payroute_del(p_conf, p_fulfill->id);

    uint8_t hash[BTC_SZ_HASH256];
    ln_preimage_hash_calc(hash, p_fulfill->p_preimage);
    cmd_json_pay_result(hash, "success");
    ln_db_invoice_del(hash);
}


//LN_CB_FAIL_HTLC_RECV: update_fail_htlc受信
static void cb_fail_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_fail_htlc_recv_t *p_fail = (const ln_cb_fail_htlc_recv_t *)p_param;
    const char *p_stat;
    char str_stat[256];

    if (p_fail->prev_short_channel_id != 0) {
        LOGD("backwind fail_htlc: prev_idx=%" PRIu16 ", prev_short_channel_id=%016" PRIx64 ")\n", p_fail->prev_idx, p_fail->prev_short_channel_id);
        snprintf(str_stat, sizeof(str_stat), "-->%016" PRIx64, p_fail->prev_short_channel_id);
        p_stat = str_stat;

        cbsub_fail_backwind(p_conf, p_fail);
    } else {
        LOGD("origin node\n");
        p_stat = "origin node";

        cbsub_fail_originnode(p_conf, p_fail);
    }

    lnapp_save_event(ln_channel_id(p_conf->p_self),
        "[RECV]fail_htlc: %s(HTLC id=%" PRIu64 ")",
                p_stat,
                p_fail->orig_id);

    DBGTRACE_END
}


//cb_fail_htlc_recv(): 巻き戻し
static void cbsub_fail_backwind(lnapp_conf_t *p_conf, const ln_cb_fail_htlc_recv_t *p_fail)
{
    (void)p_conf;

    if (!LN_DBG_FULFILL()) {
        LOGD("DBG: no fulfill mode\n");
        return;
    }

    bool ret = false;
    lnapp_conf_t *p_prevconf = ptarmd_search_transferable_cnl(p_fail->prev_short_channel_id);
    if (p_prevconf != NULL) {
        pthread_mutex_lock(&p_prevconf->mux_self);
        ret = ln_fail_htlc_set(p_prevconf->p_self, p_fail->prev_idx, p_fail->p_reason);
        if (!ret) {
            //TODO:戻す先がない場合の処理(#366)
            LOGD("fail backward\n");
        }
        pthread_mutex_unlock(&p_prevconf->mux_self);
    }
    if (ret) {
        show_self_param(p_conf->p_self, stderr, "fail_htlc send", __LINE__);

        // method: fail
        // $1: short_channel_id
        // $2: node_id
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%s %s ",
                    str_sci, node_id);
        ptarmd_call_script(PTARMD_EVT_FAIL, param);
    }
}


//cb_fail_htlc_recv(): final node
static void cbsub_fail_originnode(lnapp_conf_t *p_conf, const ln_cb_fail_htlc_recv_t *p_fail)
{
    utl_buf_t reason = UTL_BUF_INIT;
    int hop;
    bool ret;
    if (p_fail->malformed_failure == 0) {
        // update_fail_htlc
        ret = ln_onion_failure_read(&reason, &hop, p_fail->p_shared_secret, p_fail->p_reason);
    } else {
        // update_fail_malformed_htlc
        uint16_t failure_code = utl_misc_be16(p_fail->p_reason->buf);
        ret = (failure_code == p_fail->malformed_failure);
        utl_buf_alloccopy(&reason, p_fail->p_reason->buf, p_fail->p_reason->len);
        hop = 0;
    }
    if (ret) {
        LOGD("  failure reason= ");
        DUMPD(reason.buf, reason.len);

        payroute_print(p_conf);

        ln_onion_err_t onionerr;
        ret = ln_onion_read_err(&onionerr, &reason);  //onionerr.p_dataはmallocされる
        bool btemp = false;
        if (ret) {
            switch (onionerr.reason) {
            case LNONION_TMP_NODE_FAIL:
            case LNONION_TMP_CHAN_FAIL:
            case LNONION_AMT_BELOW_MIN:
                LOGD("add skip route: temporary\n");
                btemp = true;
                break;
            default:
                break;
            }
        }

        //失敗したと思われるshort_channel_idをrouting除外登録
        //      route.hop_datain[0]は自分、[1]が相手
        //      hopの0は相手
        char suggest[LN_SZ_SHORTCHANNELID_STR + 1];
        const payment_conf_t *p_payconf = payroute_get(p_conf, p_fail->orig_id);
        if (p_payconf != NULL) {
            if (hop == p_payconf->hop_num - 2) {
                //送金先がエラーを返した
                strcpy(suggest, "final node");
            } else if (hop < p_payconf->hop_num - 2) {
                //途中がエラーを返した
                // LOGD2("hop=%d\n", hop);
                // for (int lp = 0; lp < p_payconf.hop_num; lp++) {
                //     LOGD2("[%d]%" PRIu64 "\n", lp, p_payconf->hop_datain[lp].short_channel_id);
                // }

                uint64_t short_channel_id = p_payconf->hop_datain[hop + 1].short_channel_id;
                ln_short_channel_id_string(suggest, short_channel_id);
                ln_db_routeskip_save(short_channel_id, btemp);
            } else {
                strcpy(suggest, "invalid");
            }
        } else {
            strcpy(suggest, "?");
        }
        LOGD("suggest: %s\n", suggest);

        char errstr[512];
        char *reasonstr = ln_onion_get_errstr(&onionerr);
        sprintf(errstr, M_ERRSTR_REASON, reasonstr, hop, suggest);
        set_lasterror(p_conf, RPCERR_PAYFAIL, errstr);
        cmd_json_pay_result(p_fail->p_payment_hash, errstr);
        free(reasonstr);
        free(onionerr.p_data);
    } else {
        //デコード失敗
        set_lasterror(p_conf, RPCERR_PAYFAIL, M_ERRSTR_CANNOTDECODE);
    }
    payroute_del(p_conf, p_fail->orig_id);
}


//LN_CB_REV_AND_ACK_EXCG: revoke_and_ack交換通知
static void cb_rev_and_ack_excg(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    // method: htlc_changed
    // $1: short_channel_id
    // $2: node_id
    // $3: our_msat
    char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
    ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
    char param[256];
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
    sprintf(param, "%s %s "
                "%" PRIu64,
                str_sci, node_id,
                ln_node_total_msat());
    ptarmd_call_script(PTARMD_EVT_HTLCCHANGED, param);

    show_self_param(p_conf->p_self, stderr, "revoke_and_ack", __LINE__);

    DBGTRACE_END
}


//LN_CB_PAYMENT_RETRY: 送金リトライ
static void cb_payment_retry(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;

    DBGTRACE_BEGIN

    const uint8_t *p_hash = (const uint8_t *)p_param;
    cmd_json_pay_retry(p_hash);
}


//LN_CB_UPDATE_FEE_RECV: update_fee受信
static void cb_update_fee_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    uint32_t oldrate = *(const uint32_t *)p_param;

    lnapp_save_event(ln_channel_id(p_conf->p_self),
            "updatefee recv: feerate_per_kw=%" PRIu32 " --> %" PRIu32,
            oldrate, ln_feerate_per_kw(p_conf->p_self));
}


//LN_CB_SHUTDOWN_RECV: shutdown受信
static void cb_shutdown_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    //fee and addr
    //   fee_satoshis lower than or equal to the base fee of the final commitment transaction
    uint64_t commit_fee = ln_closing_signed_initfee(p_conf->p_self);
    ln_shutdown_update_fee(p_conf->p_self, commit_fee);

    lnapp_save_event(ln_channel_id(p_conf->p_self), "close: recv shutdown");
}


//LN_CB_CLOSED_FEE: closing_signed受信(FEE不一致)
static void cb_closed_fee(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_closed_fee_t *p_closed_fee = (const ln_cb_closed_fee_t *)p_param;
    LOGD("received fee: %" PRIu64 "\n", p_closed_fee->fee_sat);

#warning How to decide shutdown fee
    ln_shutdown_update_fee(p_conf->p_self, p_closed_fee->fee_sat);
}


//LN_CB_CLOSED: closing_singed受信(FEE一致)
//  コールバック後、selfはクリアされる
static void cb_closed(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_closed_t *p_closed = (ln_cb_closed_t *)p_param;

    if (LN_DBG_CLOSING_TX()) {
        //closing_txを展開
        uint8_t txid[BTC_SZ_TXID];
        p_closed->result = btcrpc_send_rawtx(txid, NULL, p_closed->p_tx_closing->buf, p_closed->p_tx_closing->len);
        if (p_closed->result) {
            LOGD("$$$ broadcast\n");
        } else {
            LOGE("fail: broadcast\n");
            assert(0);
        }

        // method: closed
        // $1: short_channel_id
        // $2: node_id
        // $3: closing_txid
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
        char param[256];
        char txidstr[BTC_SZ_TXID * 2 + 1];
        utl_misc_bin2str_rev(txidstr, txid, BTC_SZ_TXID);
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        sprintf(param, "%s %s "
                    "%s",
                    str_sci, node_id,
                    txidstr);
        ptarmd_call_script(PTARMD_EVT_CLOSED, param);
    } else {
        LOGD("DBG: no send closing_tx mode\n");
    }
    lnapp_save_event(ln_channel_id(p_conf->p_self), "close: good way: end");

    DBGTRACE_END
}


//LN_CB_SEND_REQ: BOLTメッセージ送信要求
static void cb_send_req(lnapp_conf_t *p_conf, void *p_param)
{
    utl_buf_t *p_buf = (utl_buf_t *)p_param;
    (void)send_peer_noise(p_conf, p_buf);
}


//LN_CB_SEND_QUEUE: BOLTメッセージをキュー保存
static void cb_send_queue(lnapp_conf_t *p_conf, void *p_param)
{
    utl_buf_t *p_buf = (utl_buf_t *)p_param;

    pthread_mutex_lock(&p_conf->mux_sendque);
    send_queue_push(p_conf, p_buf);
    pthread_mutex_unlock(&p_conf->mux_sendque);
}


//LN_CB_SET_LATEST_FEERATE: estimatesmartfeeによるfeerate_per_kw更新(DB保存しない)
static void cb_set_latest_feerate(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;

    uint32_t feerate_kw = monitoring_get_latest_feerate_kw();
    ln_feerate_per_kw_set(p_conf->p_self, feerate_kw);
}


//LN_CB_GETBLOCKCOUNT
static void cb_getblockcount(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;

    int32_t *p_height = (int32_t *)p_param;
    bool ret = btcrpc_getblockcount(p_height);
    if (ret) {
        LOGD("block count=%" PRId32 "\n", *p_height);
    } else {
        *p_height = 0;
    }
}


/********************************************************************
 * スレッド共通処理
 ********************************************************************/

//スレッドループ停止
static void stop_threads(lnapp_conf_t *p_conf)
{
    if (p_conf->loop) {
        p_conf->loop = false;
        //mainloop待ち合わせ解除(*2)
        pthread_cond_signal(&p_conf->cond);
        LOGD("=========================================\n");
        LOGD("=  CHANNEL THREAD END: %016" PRIx64 " =\n", ln_short_channel_id(p_conf->p_self));
        LOGD("=========================================\n");
    }
}


//peer送信(そのまま送信)
static bool send_peer_raw(lnapp_conf_t *p_conf, const utl_buf_t *pBuf)
{
    struct pollfd fds;
    ssize_t len = pBuf->len;
    while ((p_conf->loop) && (len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLOUT;
        int polr = poll(&fds, 1, M_WAIT_SEND_TO_MSEC);
        if (polr <= 0) {
            LOGD("fail poll: %s\n", strerror(errno));
            break;
        }
        ssize_t sz = write(p_conf->sock, pBuf->buf, len);
        if (sz < 0) {
            LOGD("fail write: %s\n", strerror(errno));
            break;
        }
        len -= sz;
        if (len > 0) {
            utl_misc_msleep(M_WAIT_SEND_WAIT_MSEC);
        }
    }

    return len == 0;
}


//peer送信(Noise Protocol送信)
static bool send_peer_noise(lnapp_conf_t *p_conf, const utl_buf_t *pBuf)
{
    uint16_t type = ln_misc_get16be(pBuf->buf);
    LOGD("[SEND]type=%04x(%s): sock=%d, Len=%d\n", type, ln_misc_msgname(type), p_conf->sock, pBuf->len);

    pthread_mutex_lock(&p_conf->mux_send);

    utl_buf_t buf_enc;
    struct pollfd fds;
    ssize_t len = -1;

    bool ret = ln_noise_enc(p_conf->p_self, &buf_enc, pBuf);
    if (!ret) {
        LOGD("fail: noise encode\n");
        goto LABEL_EXIT;
    }

    len = buf_enc.len;
    while ((p_conf->loop) && (len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLOUT;
        int polr = poll(&fds, 1, M_WAIT_SEND_TO_MSEC);
        if (polr <= 0) {
            LOGD("fail poll: %s\n", strerror(errno));
            break;
        }
        ssize_t sz = write(p_conf->sock, buf_enc.buf, len);
        if (sz < 0) {
            LOGD("fail write: %s\n", strerror(errno));
            stop_threads(p_conf);
            break;
        }
        len -= sz;
        if (len > 0) {
            utl_misc_msleep(M_WAIT_SEND_WAIT_MSEC);
        }
    }
    utl_buf_free(&buf_enc);

    //ping送信待ちカウンタ
    p_conf->ping_counter = 0;

LABEL_EXIT:
    pthread_mutex_unlock(&p_conf->mux_send);
    return len == 0;
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
    bool ret = ln_establish_alloc(p_conf->p_self, ptarmd_get_establishprm());
    if (!ret) {
        LOGD("fail: set establish\n");
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
    (void)conf_anno_load("anno.conf", &aconf);
    mAnnoPrm.cltv_expiry_delta = aconf.cltv_expiry_delta;
    mAnnoPrm.htlc_minimum_msat = aconf.htlc_minimum_msat;
    mAnnoPrm.fee_base_msat = aconf.fee_base_msat;
    mAnnoPrm.fee_prop_millionths = aconf.fee_prop_millionths;
}


/** エラー文字列設定
 *
 */
static void set_lasterror(lnapp_conf_t *p_conf, int Err, const char *pErrStr)
{
    p_conf->err = Err;
    if (p_conf->p_errstr != NULL) {
        free(p_conf->p_errstr);
        p_conf->p_errstr = NULL;
    }
    if ((Err != 0) && (pErrStr != NULL)) {
        size_t len_max = strlen(pErrStr) + 128;
        p_conf->p_errstr = (char *)UTL_DBG_MALLOC(len_max);        //UTL_DBG_FREE: thread_main_start()
        strcpy(p_conf->p_errstr, pErrStr);
        LOGD("$$$[ERROR RECEIVED] %s\n", p_conf->p_errstr);

        // method: error
        // $1: short_channel_id
        // $2: node_id
        // $3: err_str
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_conf->p_self));
        char *param = (char *)UTL_DBG_MALLOC(len_max);      //UTL_DBG_FREE: この中
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
        sprintf(param, "%s %s "
                    "\"%s\"",
                    str_sci, node_id,
                    p_conf->p_errstr);
        ptarmd_call_script(PTARMD_EVT_ERROR, param);
        UTL_DBG_FREE(param);        //UTL_DBG_MALLOC: この中
    }
}


/**************************************************************************
 * 受信アイドル時処理
 *
 *      - update_add_htlc受信によるupdate_add_htlcの転送(中継node)
 *      - update_add_htlc受信によるupdate_fulfill_htlcの巻き戻し(last node)
 *      - update_add_htlc受信によるupdate_fail_htlcの巻き戻し(last node)
 *      - announcement_signatures
 **************************************************************************/

/** [受信アイドル]push
 *
 * 受信アイドル時に行いたい処理をリングバッファにためる。
 * 主に、update_add/fulfill/fail_htlcの転送・巻き戻し処理に使われる。
 */
static void rcvidle_push(lnapp_conf_t *p_conf, rcvidle_cmd_t Cmd, utl_buf_t *pBuf)
{
    pthread_mutex_lock(&p_conf->mux_rcvidle);

    rcvidlelist_t *p_rcvidle = (rcvidlelist_t *)UTL_DBG_MALLOC(sizeof(rcvidlelist_t));       //UTL_DBG_FREE: rcvidle_pop_and_exec()
    p_rcvidle->cmd = Cmd;
    if (pBuf != NULL) {
        memcpy(&p_rcvidle->buf, pBuf, sizeof(utl_buf_t));
    } else {
        utl_buf_init(&p_rcvidle->buf);
    }
    LIST_INSERT_HEAD(&p_conf->rcvidle_head, p_rcvidle, list);

    pthread_mutex_unlock(&p_conf->mux_rcvidle);
}


/** 処理要求キューの処理実施
 *
 * 受信処理のアイドル時(タイムアウトした場合)に呼び出される。
 */
static void rcvidle_pop_and_exec(lnapp_conf_t *p_conf)
{
    pthread_mutex_lock(&p_conf->mux_rcvidle);

    pthread_mutex_lock(&p_conf->mux_self);
    ln_recv_idle_proc(p_conf->p_self);
    pthread_mutex_unlock(&p_conf->mux_self);

    struct rcvidlelist_t *p_rcvidle = LIST_FIRST(&p_conf->rcvidle_head);
    if (p_rcvidle == NULL) {
        //empty
        pthread_mutex_unlock(&p_conf->mux_rcvidle);
        return;
    }

    bool ret = false;

    switch (p_rcvidle->cmd) {
    case RCVIDLE_ANNOSIGNS:
        LOGD("RCVIDLE_ANNOSIGNS\n");
        ret = rcvidle_announcement_signs(p_conf);
        break;
    default:
        break;
    }
    if (ret) {
        //解放
        LIST_REMOVE(p_rcvidle, list);
        utl_buf_free(&p_rcvidle->buf);       //UTL_DBG_MALLOC: change_context()
        UTL_DBG_FREE(p_rcvidle);            //UTL_DBG_MALLOC: rcvidle_push
    } else {
        LOGD("retry\n");
    }

    pthread_mutex_unlock(&p_conf->mux_rcvidle);
}


/** 受信アイドル時キューの全削除
 *
 */
static void rcvidle_clear(lnapp_conf_t *p_conf)
{
    rcvidlelist_t *p = LIST_FIRST(&p_conf->rcvidle_head);
    while (p != NULL) {
        rcvidlelist_t *tmp = LIST_NEXT(p, list);
        LIST_REMOVE(p, list);
        utl_buf_free(&p->buf);
        UTL_DBG_FREE(p);
        p = tmp;
    }
}


static bool rcvidle_announcement_signs(lnapp_conf_t *p_conf)
{
    utl_buf_t buf_bolt = UTL_BUF_INIT;

    pthread_mutex_lock(&p_conf->mux_self);
    bool ret = ln_announce_signs_create(p_conf->p_self, &buf_bolt);
    if (ret) {
        send_peer_noise(p_conf, &buf_bolt);
        utl_buf_free(&buf_bolt);
    } else {
        LOGD("fail: create announcement_signatures\n");
        stop_threads(p_conf);
    }
    pthread_mutex_unlock(&p_conf->mux_self);

    return ret;
}


/*******************************************
 * 送金情報リスト
 *******************************************/

/** 送金情報リストに追加
 *
 * 送金エラーが発生した場合、reasonからどのnodeがエラーを返したか分かる。
 * forward nodeがエラーを返した場合には、そのchannelを除外して再routingさせたい。
 * (final nodeがエラーを返した場合には再送しても仕方が無い)。
 *
 * リストにしたのは、複数の送金が行われることを考慮したため。
 *
 * @param[in,out]       p_conf
 * @param[in]           pPayConf        送金情報(内部でコピー)
 * @param[in]           HtlcId          HTLC id
 */
static void payroute_push(lnapp_conf_t *p_conf, const payment_conf_t *pPayConf, uint64_t HtlcId)
{
    routelist_t *rt = (routelist_t *)UTL_DBG_MALLOC(sizeof(routelist_t));       //UTL_DBG_FREE: payroute_del()

    memcpy(&rt->route, pPayConf, sizeof(payment_conf_t));
    rt->htlc_id = HtlcId;
    LIST_INSERT_HEAD(&p_conf->payroute_head, rt, list);
    LOGD("htlc_id: %" PRIu64 "\n", HtlcId);

    payroute_print(p_conf);
}


/** 送金情報リスト取得
 *
 * update_add_htlcの送信元がupdate_fail_htlcを受信した際、
 * #payroute_push() で保持していたルート情報とreasonから、どのchannelで失敗したかを判断するために使用する。
 * 自分がupdate_add_htlcの送信元の場合だけリストに保持している。
 *
 * @param[in]       p_conf
 * @param[in]       HtlcId
 */
static const payment_conf_t* payroute_get(lnapp_conf_t *p_conf, uint64_t HtlcId)
{
    LOGD("START:htlc_id: %" PRIu64 "\n", HtlcId);

    routelist_t *p = LIST_FIRST(&p_conf->payroute_head);
    while (p != NULL) {
        LOGD("htlc_id: %" PRIu64 "\n", p->htlc_id);
        if (p->htlc_id == HtlcId) {
            LOGD("HIT:htlc_id: %" PRIu64 "\n", HtlcId);
            break;
        }
        p = LIST_NEXT(p, list);
    }
    if (p != NULL) {
        return &p->route;
    } else {
        return NULL;
    }
}


/** 送金情報リスト削除
 *
 * udpate_add_htlc送信元が追加するリストから、指定したHTLC idの情報を削除する。
 *      - update_fulfill_htlc受信
 *      - update_fail_htlc受信
 *
 * @param[in,out]   p_conf
 * @param[in]       HtlcId
 */
static void payroute_del(lnapp_conf_t *p_conf, uint64_t HtlcId)
{
    struct routelist_t *p;

    p = LIST_FIRST(&p_conf->payroute_head);
    while (p != NULL) {
        if (p->htlc_id == HtlcId) {
            LOGD("htlc_id: %" PRIu64 "\n", HtlcId);
            break;
        }
        p = LIST_NEXT(p, list);
    }
    if (p != NULL) {
        LIST_REMOVE(p, list);
        UTL_DBG_FREE(p);
    }

    payroute_print(p_conf);
}


/** 送金情報リストの全削除
 *
 */
static void payroute_clear(lnapp_conf_t *p_conf)
{
    routelist_t *p;

    p = LIST_FIRST(&p_conf->payroute_head);
    while (p != NULL) {
        LOGD("[%d]htlc_id: %" PRIu64 "\n", __LINE__, p->htlc_id);
        routelist_t *tmp = LIST_NEXT(p, list);
        LIST_REMOVE(p, list);
        UTL_DBG_FREE(p);
        p = tmp;
    }
}


/** 送金情報リスト表示
 *
 */
static void payroute_print(lnapp_conf_t *p_conf)
{
    routelist_t *p;

    LOGD("------------------------------------\n");
    p = LIST_FIRST(&p_conf->payroute_head);
    while (p != NULL) {
        LOGD("htlc_id: %" PRIu64 "\n", p->htlc_id);
        p = LIST_NEXT(p, list);
    }
    LOGD("------------------------------------\n");
}


/**
 *
 * @param[in,out]       p_conf
 * @param[in]           pBuf        追加対象
 * @note
 *      - pBufはshallow copyするため、呼び元でfreeしないこと
 */
static void send_queue_push(lnapp_conf_t *p_conf, const utl_buf_t *pBuf)
{
    LOGD("data=");
    DUMPD(pBuf->buf, pBuf->len);

    //add queue before noise encoded data
    size_t len = p_conf->buf_sendque.len / sizeof(utl_buf_t);
    LOGD("que=%p, bytes=%d\n", p_conf->buf_sendque.buf, p_conf->buf_sendque.len);
    utl_buf_realloc(&p_conf->buf_sendque, sizeof(utl_buf_t) * (len + 1));
    memcpy(p_conf->buf_sendque.buf + sizeof(utl_buf_t) * len, pBuf, sizeof(utl_buf_t));
    LOGD("que=%p, bytes=%d\n", p_conf->buf_sendque.buf, p_conf->buf_sendque.len);

    for (size_t lp = 0; lp < p_conf->buf_sendque.len / sizeof(utl_buf_t); lp++) {
        const utl_buf_t *p = (const utl_buf_t *)(p_conf->buf_sendque.buf + lp * sizeof(utl_buf_t));
        LOGD("buf[%d]=", lp);
        DUMPD(p->buf, p->len);
    }
}


static void send_queue_flush(lnapp_conf_t *p_conf)
{
    if (p_conf->buf_sendque.len == 0) {
        return;
    }

    size_t len = p_conf->buf_sendque.len / sizeof(utl_buf_t);
    for (size_t lp = 0; lp < len; lp++) {
        uint8_t *p = p_conf->buf_sendque.buf + sizeof(utl_buf_t) * lp;
        send_peer_noise(p_conf, (utl_buf_t *)p);
        utl_buf_free((utl_buf_t *)p);
    }
    utl_buf_free(&p_conf->buf_sendque);
}


static void send_queue_clear(lnapp_conf_t *p_conf)
{
    if (p_conf->buf_sendque.len == 0) {
        return;
    }

    size_t len = p_conf->buf_sendque.len / sizeof(utl_buf_t);
    for (size_t lp = 0; lp < len; lp++) {
        uint8_t *p = p_conf->buf_sendque.buf + sizeof(utl_buf_t) * lp;
        utl_buf_free((utl_buf_t *)p);
    }
    utl_buf_free(&p_conf->buf_sendque);
}


static bool getnewaddress(utl_buf_t *pBuf)
{
    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    if (!btcrpc_getnewaddress(addr)) {
        return false;
    }
    return btc_keys_addr2spk(pBuf, addr);
}


#ifndef USE_SPV
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
}
#endif


/** ln_self_t内容表示(デバッグ用)
 *
 */
static void show_self_param(const ln_self_t *self, FILE *fp, const char *msg, int line)
{
    LOGD("=(%s:%d)=============================================\n", msg, line);
    if (ln_short_channel_id(self)) {
        LOGD("short_channel_id: %016" PRIx64 "\n", ln_short_channel_id(self));
        LOGD("our_msat:   %" PRIu64 "\n", ln_our_msat(self));
        LOGD("their_msat: %" PRIu64 "\n", ln_their_msat(self));
        for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
            const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, lp);
            if (LN_HTLC_ENABLE(p_htlc)) {
                LOGD("  HTLC[%d]\n", lp);
                LOGD("    htlc id= %" PRIu64 "\n", p_htlc->id);
                LOGD("    cltv_expiry= %" PRIu32 "\n", p_htlc->cltv_expiry);
                LOGD("    amount_msat= %" PRIu64 "\n", p_htlc->amount_msat);
                if (p_htlc->prev_short_channel_id) {
                    LOGD("    from:        cnl_add_htlc[%d]%016" PRIx64 "\n", p_htlc->prev_idx, p_htlc->prev_short_channel_id);
                }
            }
        }

        //コンソールログ
        fprintf(fp, "=%s:%d==================\n", msg, line);
        fprintf(fp, "short_channel_id: %016" PRIx64 "\n", ln_short_channel_id(self));
        fprintf(fp, "our_msat:   %" PRIu64 "\n", ln_our_msat(self));
        fprintf(fp, "their_msat: %" PRIu64 "\n", ln_their_msat(self));
    } else {
        LOGD("no channel\n");
    }
    LOGD("=(%s:%d)=============================================\n", msg, line);
}
