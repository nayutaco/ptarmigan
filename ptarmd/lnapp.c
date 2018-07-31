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

#define M_WAIT_MUTEX_SEC        (1)         //mMuxNodeのロック解除待ち間隔[sec]
#define M_WAIT_POLL_SEC         (10)        //監視スレッドの待ち間隔[sec]
#define M_WAIT_PING_SEC         (60)        //ping送信待ち[sec](pingは30秒以上の間隔をあけること)
#define M_WAIT_ANNO_SEC         (1)         //監視スレッドでのannounce処理間隔[sec]
#define M_WAIT_ANNO_LONG_SEC    (30)        //監視スレッドでのannounce処理間隔(長めに空ける)[sec]
#define M_WAIT_MUTEX_MSEC       (100)       //mMuxNodeのロック解除待ち間隔[msec]
#define M_WAIT_RECV_MULTI_MSEC  (1000)      //複数パケット受信した時の処理間隔[msec]
#define M_WAIT_RECV_TO_MSEC     (100)       //socket受信待ちタイムアウト[msec]
#define M_WAIT_SEND_WAIT_MSEC   (10)        //socket送信で一度に送信できなかった場合の待ち時間[msec]
#define M_WAIT_RECV_MSG_MSEC    (500)       //message受信監視周期[msec]
#define M_WAIT_RECV_THREAD      (100)       //recv_thread開始待ち[msec]
#define M_WAIT_RESPONSE_MSEC    (10000)     //受信待ち[msec]
#define M_WAIT_CHANREEST_MSEC   (3600000)   //channel_reestablish受信待ち[msec]

#define M_ANNO_UNIT             (3)         ///< 1回のannouncementで送信する数
#define M_RECVIDLE_RETRY_MAX    (5)         ///< 受信アイドル時キュー処理のリトライ最大

#define M_ERRSTR_REASON                 "fail: %s (hop=%d)(suggest:%s)"
#define M_ERRSTR_CANNOTDECODE           "fail: result cannot decode"
#define M_ERRSTR_CANNOTSTART            "fail: can't start payment(our_msat=%" PRIu64 ", amt_to_forward=%" PRIu64 ")"

#define M_SCRIPT_DIR            "./script/"

#define M_FLAG_MASK(flag, mask) (((flag) & (mask)) == (mask))

#ifdef DEBUGTRACE
#define DBGTRACE_BEGIN  LOGD("BEGIN\n");
#define DBGTRACE_END    LOGD("END\n");
#else
#define DBGTRACE_BEGIN
#define DBGTRACE_END
#endif


/********************************************************************
 * typedefs
 ********************************************************************/

//event
typedef enum {
    EVT_ERROR,
    EVT_CONNECTED,
    EVT_ESTABLISHED,
    EVT_PAYMENT,
    EVT_FORWARD,
    EVT_FULFILL,
    EVT_FAIL,
    EVT_HTLCCHANGED,
    EVT_CLOSED
} event_t;


//lnapp_conf_t.flag_recv
enum {
    RECV_MSG_INIT           = 0x01,     ///< init
    RECV_MSG_REESTABLISH    = 0x02,     ///< channel_reestablish
    RECV_MSG_FUNDINGLOCKED  = 0x04,     ///< funding locked
    RECV_MSG_END            = 0x80,     ///< 初期化完了
};


/** @enum   node_flag_t
 *  @brief  状態フラグ
 *
 * BOLTメッセージの送受信でフラグを立てていく。
 * スレッド間で並列できない処理がある場合の排他にも用いる。
 *
 * ADDHTLC_SEND --> commitment_signed受信 : offered HTLC追加完了
 * ADDHTLC_RECV --> COMSIG_RECV --> revoke_and_ack受信 : received HTLC追加完了
 * FULFILL_SEND --> commitment_signed受信 : fulfill完了(received HTLC)
 * FULFILL_RECV --> COMSIG_RECV --> revoke_nad_ack受信 : fulfill完了(offered HTLC)
 * FAIL_SEND --> commitment_signed受信 : fail完了(received HTLC)
 * FAIL_RECV --> COMSIG_RECV --> revoke_nad_ack受信 : fail完了(offered HTLC)
 */
typedef enum {
    FLAGNODE_NONE           = 0x0000,
    FLAGNODE_PAYMENT        = 0x0001,   ///< 送金開始

    FLAGNODE_ADDHTLC_SEND   = 0x0002,   ///< update_add_htlc送信
    FLAGNODE_ADDHTLC_RECV   = 0x0004,   ///< update_add_htlc受信
    FLAGNODE_UPDFEE_SEND    = 0x0008,   ///< update_fee送信
    FLAGNODE_UPDFEE_RECV    = 0x0010,   ///< update_fee受信

    FLAGNODE_FULFILL_SEND   = 0x0100,   ///< update_fulfill_htlc送信
    FLAGNODE_FULFILL_RECV   = 0x0200,   ///< update_fulfill_htlc受信
    FLAGNODE_FAIL_SEND      = 0x0400,   ///< update_fail_htlc送信
    FLAGNODE_FAIL_RECV      = 0x0800,   ///< update_fail_htlc受信
} node_flag_t;


/********************************************************************
 * static variables
 ********************************************************************/

static volatile bool        mLoop;          //true:チャネル有効

static ln_anno_prm_t        mAnnoPrm;       ///< announcementパラメータ

//シーケンスのmutex
//  PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NPでの初期化は関数内でしか行えない
static pthread_mutexattr_t  mMuxAttr;
static pthread_mutex_t      mMuxNode;
static volatile node_flag_t mFlagNode;


static const char *kSCRIPT[] = {
    //EVT_ERROR
    M_SCRIPT_DIR "error.sh",
    //EVT_CONNECTED
    M_SCRIPT_DIR "connected.sh",
    //EVT_ESTABLISHED
    M_SCRIPT_DIR "established.sh",
    //EVT_PAYMENT,
    M_SCRIPT_DIR "payment.sh",
    //EVT_FORWARD,
    M_SCRIPT_DIR "forward.sh",
    //EVT_FULFILL,
    M_SCRIPT_DIR "fulfill.sh",
    //EVT_FAIL,
    M_SCRIPT_DIR "fail.sh",
    //EVT_HTLCCHANGED,
    M_SCRIPT_DIR "htlcchanged.sh",
    //EVT_CLOSED
    M_SCRIPT_DIR "closed.sh"
};


/********************************************************************
 * prototypes
 ********************************************************************/

static void *thread_main_start(void *pArg);
static bool noise_handshake(lnapp_conf_t *p_conf);
static bool check_short_channel_id(lnapp_conf_t *p_conf);
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
static bool get_short_channel_id(lnapp_conf_t *p_conf);

static void *thread_anno_start(void *pArg);

static bool fwd_payment_forward(lnapp_conf_t *p_conf, fwd_proc_add_t *pFwdAdd, ptarm_buf_t *pReason);
static bool fwd_fulfill_backwind(lnapp_conf_t *p_conf, bwd_proc_fulfill_t *pBwdFulfill);
static bool fwd_fail_backwind(lnapp_conf_t *p_conf, bwd_proc_fail_t *pBwdFail);

static void notify_cb(ln_self_t *self, ln_cb_t reason, void *p_param);
static void cb_error_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_init_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_channel_reestablish_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_tx_sign(lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_tx_wait(lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_locked(lnapp_conf_t *p_conf, void *p_param);
static void cb_channel_anno_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_update_anno_db(lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv_prev(lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_fulfill_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_fail_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_commit_sig_recv_prev(lnapp_conf_t *p_conf, void *p_param);
static void cb_commit_sig_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_rev_and_ack_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_update_fee_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_shutdown_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_closed_fee(lnapp_conf_t *p_conf, void *p_param);
static void cb_closed(lnapp_conf_t *p_conf, void *p_param);
static void cb_send_req(lnapp_conf_t *p_conf, void *p_param);
static void cb_send_queue(lnapp_conf_t *p_conf, void *p_param);
static void cb_set_latest_feerate(lnapp_conf_t *p_conf, void *p_param);
static void cb_getblockcount(lnapp_conf_t *p_conf, void *p_param);

static void stop_threads(lnapp_conf_t *p_conf);
static bool wait_peer_connected(lnapp_conf_t *p_conf);
static bool send_peer_raw(lnapp_conf_t *p_conf, const ptarm_buf_t *pBuf);
static bool send_peer_noise(lnapp_conf_t *p_conf, const ptarm_buf_t *pBuf);
static bool send_announcement(lnapp_conf_t *p_conf);
static bool send_anno_pre_chan(uint64_t short_channel_id);
static bool send_anno_pre_upd(uint64_t short_channel_id, uint32_t timestamp);
static void send_anno_cnl(lnapp_conf_t *p_conf, char type, void *p_db, const ptarm_buf_t *p_buf_cnl);
static void send_anno_node(lnapp_conf_t *p_conf, void *p_db, const ptarm_buf_t *p_buf_cnl);
static void send_cnlupd_before_announce(lnapp_conf_t *p_conf);

static void load_channel_settings(lnapp_conf_t *p_conf);
static void load_announce_settings(void);

static void nodeflag_set(node_flag_t Flag);
static void nodeflag_unset(node_flag_t Flag);
static void call_script(event_t event, const char *param);
static void set_onionerr_str(char *pStr, const ln_onion_err_t *pOnionErr);
static void set_lasterror(lnapp_conf_t *p_conf, int Err, const char *pErrStr);

static void revack_push(lnapp_conf_t *p_conf, trans_cmd_t Cmd, ptarm_buf_t *pBuf);
static void revack_pop_and_exec(lnapp_conf_t *p_conf);
static void revack_clear(lnapp_conf_t *p_conf);

static void rcvidle_push(lnapp_conf_t *p_conf, trans_cmd_t Cmd, ptarm_buf_t *pBuf);
static void rcvidle_pop_and_exec(lnapp_conf_t *p_conf);
static void rcvidle_clear(lnapp_conf_t *p_conf);

static void payroute_push(lnapp_conf_t *p_conf, const payment_conf_t *pPayConf, uint64_t HtlcId);
static const payment_conf_t* payroute_get(lnapp_conf_t *p_conf, uint64_t HtlcId);
static void payroute_del(lnapp_conf_t *p_conf, uint64_t HtlcId);
static void payroute_clear(lnapp_conf_t *p_conf);
static void payroute_print(lnapp_conf_t *p_conf);
#ifndef USE_SPV
static bool check_unspent_short_channel_id(uint64_t ShortChannelId);
#endif

static void send_queue_push(lnapp_conf_t *p_conf, const ptarm_buf_t *pBuf);
static void send_queue_flush(lnapp_conf_t *p_conf);
static void send_queue_clear(lnapp_conf_t *p_conf);

static void show_self_param(const ln_self_t *self, FILE *fp, const char *msg, int line);


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_init(void)
{
    pthread_mutexattr_init(&mMuxAttr);
    pthread_mutexattr_settype(&mMuxAttr, PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&mMuxNode, &mMuxAttr);
    mFlagNode = FLAGNODE_NONE;
}


void lnapp_term(void)
{
    pthread_mutexattr_destroy(&mMuxAttr);
    pthread_mutex_destroy(&mMuxNode);
}


void lnapp_start(lnapp_conf_t *pAppConf)
{
    pthread_create(&pAppConf->th, NULL, &thread_main_start, pAppConf);
}


void lnapp_stop(lnapp_conf_t *pAppConf)
{
    fprintf(stderr, "stop: ");
    ptarm_util_dumpbin(stderr, pAppConf->node_id, PTARM_SZ_PUBKEY, true);

    stop_threads(pAppConf);
    pthread_join(pAppConf->th, NULL);
    fprintf(stderr, "joined\n");
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
    if (ln_get_status(pAppConf->p_self) != LN_STATUS_NORMAL) {
        LOGD("not Normal Operation status\n");
        return false;
    }

    pthread_mutex_lock(&mMuxNode);
    if (mFlagNode != FLAGNODE_NONE) {
        //何かしているのであれば送金開始できない
        LOGD("now paying...[%x]\n", mFlagNode);
        pthread_mutex_unlock(&mMuxNode);
        return false;
    }
    mFlagNode = FLAGNODE_PAYMENT | FLAGNODE_ADDHTLC_SEND;
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %02x\n", mFlagNode);

    DBGTRACE_BEGIN

    bool ret = false;
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;
    uint8_t session_key[PTARM_SZ_PRIVKEY];
    ln_self_t *p_self = pAppConf->p_self;

    if (pPay->hop_datain[0].short_channel_id != ln_short_channel_id(p_self)) {
        LOGD("short_channel_id mismatch\n");
        LOGD("fail: short_channel_id mismatch\n");
        LOGD("    hop  : %" PRIx64 "\n", pPay->hop_datain[0].short_channel_id);
        LOGD("    mine : %" PRIx64 "\n", ln_short_channel_id(p_self));
        ln_db_annoskip_save(pPay->hop_datain[0].short_channel_id, false);   //恒久的
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

    ptarm_util_random(session_key, sizeof(session_key));
    //hop_datain[0]にこのchannel情報を置いているので、ONIONにするのは次から
    uint8_t onion[LN_SZ_ONION_ROUTE];
    ptarm_buf_t secrets = PTARM_BUF_INIT;
    ret = ln_onion_create_packet(onion, &secrets, &pPay->hop_datain[1], pPay->hop_num - 1,
                        session_key, pPay->payment_hash, LN_SZ_HASH);
    if (!ret) {
        goto LABEL_EXIT;
    }

    show_self_param(p_self, stderr, "prev payment", __LINE__);

    uint64_t htlc_id;
    ret = ln_create_add_htlc(p_self,
                        &buf_bolt,
                        &htlc_id,
                        NULL,
                        onion,
                        pPay->hop_datain[0].amt_to_forward,
                        pPay->hop_datain[0].outgoing_cltv_value,
                        pPay->payment_hash,
                        0,
                        0,
                        &secrets);
    ptarm_buf_free(&secrets);
    if (ret) {
        //再routing用に送金経路を保存
        payroute_push(pAppConf, pPay, htlc_id);
    } else {
        //our_msatが足りない場合もこのルート
        goto LABEL_EXIT;
    }
    send_peer_noise(pAppConf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);

    //add送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_self, &buf_bolt);
    if (!ret) {
        goto LABEL_EXIT;
    }
    send_peer_noise(pAppConf, &buf_bolt);

LABEL_EXIT:
    ptarm_buf_free(&buf_bolt);
    if (ret) {
        show_self_param(p_self, stderr, "payment start", __LINE__);

        // method: payment
        // $1: short_channel_id
        // $2: node_id
        // $3: amt_to_forward
        // $4: outgoing_cltv_value
        // $5: payment_hash
        char hashstr[LN_SZ_HASH * 2 + 1];
        ptarm_util_bin2str(hashstr, pPay->payment_hash, LN_SZ_HASH);
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s "
                    "%" PRIu64 " "
                    "%" PRIu32 " "
                    "%s",
                    ln_short_channel_id(pAppConf->p_self), node_id,
                    pPay->hop_datain[0].amt_to_forward,
                    pPay->hop_datain[0].outgoing_cltv_value,
                    hashstr);
        call_script(EVT_PAYMENT, param);
    } else {
        // LOGD("fail --> retry\n");
        // char errstr[512];
        // sprintf(errstr, M_ERRSTR_CANNOTSTART,
        //             ln_our_msat(pAppConf->p_self),
        //             pPay->hop_datain[0].amt_to_forward);
        // set_lasterror(pAppConf, RPCERR_PAYFAIL, errstr);

        // //ルートが見つからなくなるまでリトライする
        // ln_db_annoskip_save(ln_short_channel_id(pAppConf->p_self), true);   //一時的
        // cmd_json_pay_retry(pPay->payment_hash);
        // ret = true;         //再送はtrue
        nodeflag_unset(~FLAGNODE_NONE);
    }

    DBGTRACE_END

    LOGD("  -->mFlagNode %d\n", mFlagNode);
    return ret;
}


/*******************************************
 * 転送/巻き戻しのための lnappコンテキスト移動
 *
 *      転送/巻き戻しを行うため、lnappをまたぐ必要がある。
 *      pthreadがlnappで別になるため、受信スレッドのidle処理を介して移動させる。
 *
 *      この経路を使うのは、以下のタイミングになる。
 *          - update_add_htlc転送 : revoke_and_ack後(add_htlc転送は、add_htlc受信以外に無い)
 *          - update_fulfill_htlc巻き戻し
 *              - payee : revoke_and_ack後(add_htlc受信)
 *              - それ以外 : update_fulfill_htlc受信後(fulfill_htlc受信)
 *          - update_fail_htlc巻き戻し
 *              - payee : revoke_and_ack後(add_htlc受信)
 *              - それ以外 : update_fulfill_htlc/update_fail_htlc受信後(fail_htlc受信)
 *
 * update_add_htlc受信後に転送/巻き戻しを行う場合、revoke_and_ack受信まで待つ必要があるため、
 * 一旦 lnapp.p_revackq にためている。
 * それ以降はrevoke_and_ackを待つ必要がないため、以下のAPIを直接呼び出す。
 *
 * TODO:
 *  - update_fulfill_htlc受信によって、update_fail_htlcを巻き戻す可能性はあるか？
 *  - update_fail_htlc受信は、update_fail_htlc巻き戻し以外になることはあり得るか？
 *******************************************/

void lnapp_transfer_channel(lnapp_conf_t *pAppConf, trans_cmd_t Cmd, ptarm_buf_t *pBuf)
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

    bool ret;
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;
    ln_self_t *p_self = pAppConf->p_self;

    if (ln_is_closing(p_self)) {
        LOGD("fail: already closing\n");
        return false;
    }

    //feeと送金先
    cb_shutdown_recv(pAppConf, NULL);

    show_self_param(p_self, stderr, "close channel", __LINE__);

    const char *p_str;
    ret = ln_create_shutdown(p_self, &buf_bolt);
    if (ret) {
        send_peer_noise(pAppConf, &buf_bolt);
        ptarm_buf_free(&buf_bolt);

        p_str = "close: good way(local) start";
    } else {
        p_str = "fail close: good way(local) start";
    }
    misc_save_event(ln_channel_id(p_self), p_str);

    DBGTRACE_END

    return ret;
}


bool lnapp_close_channel_force(const uint8_t *pNodeId)
{
    bool ret;
    ln_self_t *p_self = (ln_self_t *)APP_MALLOC(sizeof(ln_self_t));

    //announcementデフォルト値
    load_announce_settings();
    ln_init(p_self, NULL, &mAnnoPrm, NULL);

    ret = ln_node_search_channel(p_self, pNodeId);
    if (!ret) {
        return false;
    }
    if (ln_is_closing(p_self)) {
        LOGD("fail: already closing\n");
        APP_FREE(p_self);
        return false;
    }

    LOGD("close: bad way(local): htlc=%d\n", ln_commit_local(p_self)->htlc_num);
    misc_save_event(ln_channel_id(p_self), "close: bad way(local)");
    (void)monitor_close_unilateral_local(p_self, NULL);
    APP_FREE(p_self);

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

    pthread_mutex_lock(&mMuxNode);
    if (mFlagNode != FLAGNODE_NONE) {
        //何かしているのであればupdate_feeできない
        LOGD("now paying...[%x]\n", mFlagNode);
        pthread_mutex_unlock(&mMuxNode);
        return false;
    }
    mFlagNode = FLAGNODE_UPDFEE_SEND;
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %02x\n", mFlagNode);

    DBGTRACE_BEGIN

    bool ret;
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;
    ln_self_t *p_self = pAppConf->p_self;

    ret = ln_create_update_fee(p_self, &buf_bolt, FeeratePerKw);
    if (ret) {
        uint32_t oldrate = ln_feerate_per_kw(p_self);
        ln_set_feerate_per_kw(p_self, FeeratePerKw);
        send_peer_noise(pAppConf, &buf_bolt);
        ptarm_buf_free(&buf_bolt);
        misc_save_event(ln_channel_id(p_self),
                "updatefee send: %" PRIu32 " --> %" PRIu32,
                oldrate, FeeratePerKw);

        //update_fee送信する場合はcommitment_signedも送信する
        ret = ln_create_commit_signed(p_self, &buf_bolt);
        if (ret) {
            send_peer_noise(pAppConf, &buf_bolt);
            ptarm_buf_free(&buf_bolt);
        }

    } else {
        misc_save_event(ln_channel_id(p_self), "fail updatefee");
    }

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

        const char *p_status;
        ln_status_t stat = ln_get_status(p_self);
        switch (stat) {
        case LN_STATUS_ESTABLISH:
            p_status = "establishing";
            break;
        case LN_STATUS_NORMAL:
            p_status = "established";
            break;
        case LN_STATUS_CLOSING:
            p_status = "closing";
            break;
        default:
            p_status = "none";
            break;
        }
        cJSON_AddItemToObject(result, "status", cJSON_CreateString(p_status));

        //peer node_id
        ptarm_util_bin2str(str, p_self->peer_node_id, PTARM_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //channel_id
        ptarm_util_bin2str(str, ln_channel_id(pAppConf->p_self), LN_SZ_CHANNEL_ID);
        cJSON_AddItemToObject(result, "channel_id", cJSON_CreateString(str));
        //short_channel_id
        sprintf(str, "%016" PRIx64, ln_short_channel_id(p_self));
        cJSON_AddItemToObject(result, "short_channel_id", cJSON_CreateString(str));
        //funding_tx
        ptarm_util_bin2str_rev(str, ln_funding_txid(pAppConf->p_self), PTARM_SZ_TXID);
        cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
        cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_txindex(pAppConf->p_self)));
        //confirmation
        uint32_t confirm = btcrpc_get_funding_confirm(pAppConf->p_self);
        if (confirm != 0) {
            cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
        }
        //our_msat
        cJSON_AddItemToObject(result, "our_msat", cJSON_CreateNumber64(ln_our_msat(p_self)));
        //their_msat
        cJSON_AddItemToObject(result, "their_msat", cJSON_CreateNumber64(ln_their_msat(p_self)));
        //feerate_per_kw
        cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate_per_kw(pAppConf->p_self)));
        //htlc
        cJSON_AddItemToObject(result, "htlc_num", cJSON_CreateNumber(ln_htlc_num(pAppConf->p_self)));
        //commit_num(local)
        cJSON_AddItemToObject(result, "our_commit_num", cJSON_CreateNumber(ln_commit_local(pAppConf->p_self)->commit_num));
        //commit_num(remote)
        cJSON_AddItemToObject(result, "their_commit_num", cJSON_CreateNumber(ln_commit_remote(pAppConf->p_self)->commit_num));
    } else if (p_self && pAppConf->funding_waiting) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("wait_minimum_depth"));

        //peer node_id
        ptarm_util_bin2str(str, p_self->peer_node_id, PTARM_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //channel_id
        ptarm_util_bin2str(str, ln_channel_id(pAppConf->p_self), LN_SZ_CHANNEL_ID);
        cJSON_AddItemToObject(result, "channel_id", cJSON_CreateString(str));
        //funding_tx
        ptarm_util_bin2str_rev(str, ln_funding_txid(pAppConf->p_self), PTARM_SZ_TXID);
        cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
        cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_txindex(pAppConf->p_self)));
        //confirmation
        uint32_t confirm = btcrpc_get_funding_confirm(pAppConf->p_self);
        if (confirm > 0) {
            cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
        }
        //minimum_depth
        cJSON_AddItemToObject(result, "minimum_depth", cJSON_CreateNumber(ln_minimum_depth(pAppConf->p_self)));
        //feerate_per_kw
        cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate_per_kw(pAppConf->p_self)));
    } else if (p_self && ln_is_funding(p_self)) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("fund_waiting"));

        //peer node_id
        ptarm_util_bin2str(str, pAppConf->node_id, PTARM_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
    } else if (ptarm_keys_chkpub(pAppConf->node_id)) {
        char str[256];

        const char *p_conn;
        if (lnapp_is_inited(pAppConf)) {
            p_conn = "connected";
        } else {
            p_conn = "wait_connection";
        }
        cJSON_AddItemToObject(result, "status", cJSON_CreateString(p_conn));

        //peer node_id
        ptarm_util_bin2str(str, pAppConf->node_id, PTARM_SZ_PUBKEY);
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
    ln_close_force_t close_dat;
    bool ret;
    if (bLocal) {
        ret = ln_create_close_unilateral_tx(pAppConf->p_self, &close_dat);
    } else {
        ret = ln_create_closed_tx(pAppConf->p_self, &close_dat);
    }
    if (ret) {
        cJSON *result = cJSON_CreateObject();
        ptarm_buf_t buf = PTARM_BUF_INIT;

        for (int lp = 0; lp < close_dat.num; lp++) {
            if (close_dat.p_tx[lp].vout_cnt > 0) {
                ptarm_tx_create(&buf, &close_dat.p_tx[lp]);
                char *transaction = (char *)APP_MALLOC(buf.len * 2 + 1);        //APP_FREE: この中
                ptarm_util_bin2str(transaction, buf.buf, buf.len);
                ptarm_buf_free(&buf);

                char title[10];
                if (lp == LN_CLOSE_IDX_COMMIT) {
                    strcpy(title, "committx");
                } else if (lp == LN_CLOSE_IDX_TOLOCAL) {
                    strcpy(title, "to_local");
                } else if (lp == LN_CLOSE_IDX_TOREMOTE) {
                    strcpy(title, "to_remote???");
                } else {
                    sprintf(title, "htlc%d", lp - LN_CLOSE_IDX_HTLC);
                }
                cJSON_AddItemToObject(result, title, cJSON_CreateString(transaction));
                APP_FREE(transaction);
            }
        }

        int num = close_dat.tx_buf.len / sizeof(ptarm_tx_t);
        ptarm_tx_t *p_tx = (ptarm_tx_t *)close_dat.tx_buf.buf;
        for (int lp = 0; lp < num; lp++) {
            ptarm_tx_create(&buf, &p_tx[lp]);
            char *transaction = (char *)APP_MALLOC(buf.len * 2 + 1);    //APP_FREE: この中
            ptarm_util_bin2str(transaction, buf.buf, buf.len);
            ptarm_buf_free(&buf);

            cJSON_AddItemToObject(result, "htlc_out", cJSON_CreateString(transaction));
            APP_FREE(transaction);
        }
        const char *p_title = (bLocal) ? "local" : "remote";
        cJSON_AddItemToObject(pResult, p_title, result);

        ln_free_close_force_tx(&close_dat);
    }

#if 0   //相手側のcommit_txは署名を持たないため正しく出力できない
    ret = ln_create_closed_tx(pAppConf->p_self, &close_dat);
    if (ret) {
        cJSON *result_remote = cJSON_CreateObject();
        ptarm_buf_t buf = PTARM_BUF_INIT;

        for (int lp = 0; lp < close_dat.num; lp++) {
            if (close_dat.p_tx[lp].vout_cnt > 0) {
                ptarm_tx_create(&buf, &close_dat.p_tx[lp]);
                char *transaction = (char *)APP_MALLOC(buf.len * 2 + 1);        //APP_FREE: この中
                ptarm_util_bin2str(transaction, buf.buf, buf.len);
                ptarm_buf_free(&buf);

                char title[10];
                if (lp == 0) {
                    strcpy(title, "committx");
                } else if (lp == 1) {
                    strcpy(title, "to_local");
                } else {
                    sprintf(title, "htlc%d", lp - 1);
                }
                cJSON_AddItemToObject(result_remote, title, cJSON_CreateString(transaction));
                APP_FREE(transaction);
            }
        }
        cJSON_AddItemToObject(pResult, "remote", result_remote);

        ln_free_close_force_tx(&close_dat);
    }
#endif

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


/********************************************************************
 * private functions
 ********************************************************************/

/********************************************************************
 * メインスレッド
 *
 *  チャネル処理のメインスレッド
 *  他ノードへの接続が開始されると生成され、
 ********************************************************************/

/** チャネル用スレッド
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
static void *thread_main_start(void *pArg)
{
    bool ret;
    int retval;

    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;
    ln_self_t *p_self = (ln_self_t *)APP_MALLOC(sizeof(ln_self_t));

    p_self->p_param = p_conf;

    load_announce_settings();

    //スレッド
    pthread_t   th_peer;        //peer受信
    pthread_t   th_poll;        //トランザクション監視
    pthread_t   th_anno;        //announce

    //seed作成(後でDB読込により上書きされる可能性あり)
    uint8_t seed[LN_SZ_SEED];
    LOGD("ln_self_t initialize\n");
    ptarm_util_random(seed, LN_SZ_SEED);
    ln_init(p_self, seed, &mAnnoPrm, notify_cb);

    p_conf->p_self = p_self;
    p_conf->ping_counter = 0;
    p_conf->funding_waiting = false;
    p_conf->funding_confirm = 0;
    p_conf->flag_recv = 0;
    p_conf->last_anno_cnl = 0;
    p_conf->annodb_updated = false;
    p_conf->err = 0;
    p_conf->p_errstr = NULL;
    ptarm_buf_init(&p_conf->buf_sendque);
    LIST_INIT(&p_conf->revack_head);
    LIST_INIT(&p_conf->rcvidle_head);
    LIST_INIT(&p_conf->payroute_head);

    pthread_cond_init(&p_conf->cond, NULL);
    pthread_mutex_init(&p_conf->mux, NULL);
    pthread_mutex_init(&p_conf->mux_proc, NULL);
    pthread_mutex_init(&p_conf->mux_send, NULL);
    pthread_mutex_init(&p_conf->mux_revack, NULL);
    pthread_mutex_init(&p_conf->mux_rcvidle, NULL);
    pthread_mutex_init(&p_conf->mux_sendque, NULL);

    p_conf->loop = true;

    LOGD("wait peer connected...");
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

    LOGD("connected peer: ");
    DUMPD(p_conf->node_id, PTARM_SZ_PUBKEY);
    fprintf(stderr, "connected peer: ");
    ptarm_util_dumpbin(stderr, p_conf->node_id, PTARM_SZ_PUBKEY, true);

    //init交換前に設定する(open_channelの受信に間に合わない場合あり issue #351)
    ln_set_peer_nodeid(p_self, p_conf->node_id);
    load_channel_settings(p_conf);

#ifndef USE_SPV
#else
    ptarm_buf_t txbuf = PTARM_BUF_INIT;
    const uint8_t *p_bhash;

    ptarm_tx_create(&txbuf, ln_funding_tx(p_conf->p_self));
    p_bhash = ln_funding_blockhash(p_conf->p_self);
    btcrpc_add_channel(p_conf->p_self, ln_short_channel_id(p_conf->p_self), txbuf.buf, txbuf.len, !ln_is_closing(p_conf->p_self), p_bhash);
    ptarm_buf_free(&txbuf);
#endif

    /////////////////////////
    // handshake完了
    //      server動作時、p_conf->node_idに相手node_idが入っている
    /////////////////////////

    //p_conf->node_idがchannel情報を持っているかどうか。
    //持っている場合、selfにDBから読み込みまで行われている。
    bool detect = ln_node_search_channel(p_self, p_conf->node_id);

    //
    //selfへの設定はこれ以降に行う
    //

    //peer受信スレッド
    pthread_create(&th_peer, NULL, &thread_recv_start, p_conf);

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
    if (!ret || (!p_conf->loop)) {
        LOGD("fail: exchange init\n");
        goto LABEL_JOIN;
    }
    LOGD("init交換完了\n");

    //annoinfo情報削除
    ln_db_annoinfo_del(p_conf->node_id);

    //送金先
    if (ln_shutdown_scriptpk_local(p_self)->len == 0) {
        ptarm_buf_t buf = PTARM_BUF_INIT;
        ret = btcrpc_getnewaddress(&buf);
        if (!ret) {
            LOGD("fail: create address\n");
            goto LABEL_JOIN;
        }
        ln_set_shutdown_vout_addr(p_self, &buf);
        ptarm_buf_free(&buf);
    }

    // Establishチェック
    if (detect) {
        // DBにchannel_id登録済み
        // →funding_txは展開されている
        //
        // selfの主要なデータはDBから読込まれている(copy_channel() : ln_node.c)

        //short_channel_idチェック
        ret = check_short_channel_id(p_conf);
        if (!ret) {
            LOGD("fail: check_short_channel_id\n");
            goto LABEL_JOIN;
        }

        if (ln_short_channel_id(p_self) != 0) {
            // funding_txはブロックに入ってminimum_depth以上経過している
            LOGD("Establish済み\n");
            ln_free_establish(p_self);
        } else {
            // funding_txはminimum_depth未満
            LOGD("funding_tx監視開始\n");
            TXIDD(ln_funding_txid(p_self));

            p_conf->funding_waiting = true;
        }

        ret = exchange_reestablish(p_conf);
        if (!ret) {
            LOGD("fail: exchange channel_reestablish\n");
            goto LABEL_JOIN;
        }
        LOGD("reestablish交換完了\n");
    } else {
        // channel_idはDB未登録
        // →ユーザの指示待ち
        LOGD("Establish待ち\n");
    }

    if (!p_conf->loop) {
        LOGD("fail: loop ended: %" PRIx64 "\n", ln_short_channel_id(p_self));
        goto LABEL_JOIN;
    }

    //初期化完了
    LOGD("*** message inited ***\n");
    p_conf->flag_recv |= RECV_MSG_END;

    if (ln_check_need_funding_locked(p_self)) {
        //funding_locked交換
        ret = exchange_funding_locked(p_conf);
        if (!ret) {
            LOGD("fail: exchange funding_locked\n");
            goto LABEL_JOIN;
        }
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
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        char peer_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(peer_id, p_conf->node_id, PTARM_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s "
                    "%s",
                    ln_short_channel_id(p_self), node_id,
                    peer_id);
        call_script(EVT_CONNECTED, param);

        FILE *fp = fopen(FNAME_CONN_LOG, "a");
        if (fp) {
            char date[50];
            misc_datetime(date, sizeof(date));
            fprintf(fp, "[%s]OK: %s@%s:%" PRIu16 "\n", date, peer_id, p_conf->conn_str, p_conf->conn_port);
            fclose(fp);
        }
    }

    while (p_conf->loop) {
        LOGD("loop...\n");
        pthread_mutex_lock(&p_conf->mux);

        //mainloop待ち合わせ(*2)
        pthread_cond_wait(&p_conf->cond, &p_conf->mux);

        pthread_mutex_unlock(&p_conf->mux);
    }

LABEL_JOIN:
    stop_threads(p_conf);
    pthread_join(th_peer, NULL);
    pthread_join(th_poll, NULL);
    pthread_join(th_anno, NULL);
    LOGD("loop end\n");

LABEL_SHUTDOWN:
    retval = close(p_conf->sock);
    if (retval < 0) {
        LOGD("socket close: %s", strerror(errno));
    }

    LOGD("[exit]channel thread [%016" PRIx64 "]\n", ln_short_channel_id(p_self));

    //クリア
    APP_FREE(p_conf->p_errstr);
    ln_term(p_self);
    payroute_clear(p_conf);
    rcvidle_clear(p_conf);
    revack_clear(p_conf);
    send_queue_clear(p_conf);
    memset(p_conf, 0, sizeof(lnapp_conf_t));
    p_conf->sock = -1;
    APP_FREE(p_self);

    return NULL;
}


/** Noise Protocol Handshake(同期処理)
 *
 */
static bool noise_handshake(lnapp_conf_t *p_conf)
{
    bool result = false;
    bool ret;
    ptarm_buf_t buf = PTARM_BUF_INIT;
    uint8_t rbuf[66];
    bool b_cont;
    uint16_t len_msg;

    // 今ひとつだが、同期でやってしまう
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
        ptarm_buf_free(&buf);
        ptarm_buf_alloccopy(&buf, rbuf, 50);
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
        ptarm_buf_alloccopy(&buf, rbuf, 50);
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
        ptarm_buf_free(&buf);
        ptarm_buf_alloccopy(&buf, rbuf, 66);
        ret = ln_handshake_recv(p_conf->p_self, &b_cont, &buf);
        if (!ret || b_cont) {
            LOGD("fail: ln_handshake_recv2\n");
            goto LABEL_EXIT;
        }

        //bufには相手のnode_idが返ってくる
        assert(buf.len == PTARM_SZ_PUBKEY);
        memcpy(p_conf->node_id, buf.buf, PTARM_SZ_PUBKEY);

        result = true;
    }

LABEL_EXIT:
    LOGD("noise handshake: %d\n", result);
    ptarm_buf_free(&buf);
    ln_handshake_free(p_conf->p_self);

    return result;
}


/** short_channel_idチェック
 *      blockchainからshort_channel_idを計算し、self->short_channel_idに設定する。
 *      もし以前に設定した値と異なるようであれば、エラーと見なす。
 *
 * @retval  true    チェックOK(short_channel_idが設定できなかった場合も含む)
 */
static bool check_short_channel_id(lnapp_conf_t *p_conf)
{
    bool ret = true;

    uint32_t confirm = btcrpc_get_funding_confirm(p_conf->p_self);
    if (confirm > 0) {
        p_conf->funding_confirm = confirm;
        uint64_t short_channel_id = ln_short_channel_id(p_conf->p_self);
        ret = get_short_channel_id(p_conf);
        if (ret) {
            if ((short_channel_id != 0) && (short_channel_id != ln_short_channel_id(p_conf->p_self))) {
                LOGD("FATAL: short_channel_id mismatch\n");
                LOGD("  DB: %016" PRIu64 "\n", short_channel_id);
                LOGD("  BC: %016" PRIu64 "\n", ln_short_channel_id(p_conf->p_self));
                ret = false;
            } else {
                //以前と同じ値か、新規で取得した
            }
        } else {
            LOGD("fail: calc short_channel_id\n");
        }
    } else {
        //まだfunding_txがブロックに入っていない or bitcoind error
    }

    return ret;
}


/** init交換
 *
 * @retval  true    init交換完了
 */
static bool exchange_init(lnapp_conf_t *p_conf)
{
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;

    bool ret = ln_create_init(p_conf->p_self, &buf_bolt, true);     //channel announceあり
    if (!ret) {
        LOGD("fail: create\n");
        return false;
    }
    send_peer_noise(p_conf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);

    //コールバックでのINIT受信通知待ち
    LOGD("wait: init\n");
    uint32_t count = M_WAIT_RESPONSE_MSEC / M_WAIT_RECV_MSG_MSEC;
    while (p_conf->loop && (count > 0) && ((p_conf->flag_recv & RECV_MSG_INIT) == 0)) {
        misc_msleep(M_WAIT_RECV_MSG_MSEC);
        count--;
    }
    ret = (count > 0);
    if (ret) {
        LOGD("exchange: init\n");
    }

    return count > 0;
}


/** channel_reestablish交換
 *
 * @retval  true    channel_reestablish交換完了
 */
static bool exchange_reestablish(lnapp_conf_t *p_conf)
{
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;

    bool ret = ln_create_channel_reestablish(p_conf->p_self, &buf_bolt);
    if (!ret) {
        LOGD("fail: create\n");
        return false;
    }
    send_peer_noise(p_conf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);

    //コールバックでのchannel_reestablish受信通知待ち
    LOGD("wait: channel_reestablish\n");
    uint32_t count = M_WAIT_CHANREEST_MSEC / M_WAIT_RECV_MSG_MSEC;
    while (p_conf->loop && (count > 0) && ((p_conf->flag_recv & RECV_MSG_REESTABLISH) == 0)) {
        misc_msleep(M_WAIT_RECV_MSG_MSEC);
        count--;
    }
    ret = (count > 0);
    if (!ret) {
        LOGD("fail: channel_reestablish timeout: %" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));
    }

    return ret;
}


/** funding_locked交換
 *
 * @retval  true    funding_locked交換完了
 */
static bool exchange_funding_locked(lnapp_conf_t *p_conf)
{
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;

    bool ret = ln_create_funding_locked(p_conf->p_self, &buf_bolt);
    if (!ret) {
        LOGD("fail: create\n");
        return false;
    }
    send_peer_noise(p_conf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);

    //コールバックでのfunding_locked受信通知待ち
    //uint32_t count = M_WAIT_RESPONSE_MSEC / M_WAIT_RECV_MSG_MSEC;
    LOGD("wait: funding_locked\n");
    while (p_conf->loop && ((p_conf->flag_recv & RECV_MSG_FUNDINGLOCKED) == 0)) {
        misc_msleep(M_WAIT_RECV_MSG_MSEC);
    }
    LOGD("exchange: funding_locked\n");
    ln_set_status(p_conf->p_self, LN_STATUS_NORMAL);

    check_short_channel_id(p_conf);

    // method: established
    // $1: short_channel_id
    // $2: node_id
    // $3: our_msat
    // $4: funding_txid
    char txidstr[PTARM_SZ_TXID * 2 + 1];
    ptarm_util_bin2str_rev(txidstr, ln_funding_txid(p_conf->p_self), PTARM_SZ_TXID);
    char node_id[PTARM_SZ_PUBKEY * 2 + 1];
    ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
    char param[256];
    sprintf(param, "%" PRIx64 " %s "
                "%" PRIu64 " "
                "%s",
                ln_short_channel_id(p_conf->p_self), node_id,
                ln_node_total_msat(),
                txidstr);
    call_script(EVT_ESTABLISHED, param);

    return true;
}


/** open_channel送信
 *
 */
static bool send_open_channel(lnapp_conf_t *p_conf, const funding_conf_t *pFunding)
{
    ln_fundin_t fundin;
    ptarm_buf_init(&fundin.change_spk);

    //Establish開始
    LOGD("  funding_sat: %" PRIu64 "\n", pFunding->funding_sat);
    LOGD("  push_sat: %" PRIu64 "\n", pFunding->push_sat);

    bool ret = btcrpc_getnewaddress(&fundin.change_spk);
    if (!ret) {
        LOGD("fail: getnewaddress\n");
        return false;
    }

    bool unspent;
#ifndef USE_SPV
    //事前にfund-in txがunspentかどうかチェックしようとしている。
    //SPVの場合は1st Layerの処理も内部で行うので、チェック不要。
    ret = btcrpc_check_unspent(&unspent, &fundin.amount, pFunding->txid, pFunding->txindex);
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

        memcpy(fundin.txid, pFunding->txid, PTARM_SZ_TXID);
        fundin.index = pFunding->txindex;
#else
        //SPVの場合、funding_txをSPVが作るため、fundin未使用
        memset(&fundin, 0, sizeof(fundin));
#endif

        ptarm_buf_t buf_bolt = PTARM_BUF_INIT;
        ret = ln_create_open_channel(p_conf->p_self, &buf_bolt,
                        &fundin,
                        pFunding->funding_sat,
                        pFunding->push_sat,
                        feerate_kw);
        if (ret) {
            LOGD("SEND: open_channel\n");
            send_peer_noise(p_conf, &buf_bolt);
        }
        ptarm_buf_free(&buf_bolt);
    } else {
        LOGD("fail through: btcrpc_check_unspent: ");
        TXIDD(pFunding->txid);
    }

    return ret;
}


/********************************************************************
 * 受信スレッド
 ********************************************************************/

/** peerからの受信スレッド
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
static void *thread_recv_start(void *pArg)
{
    ptarm_buf_t buf_recv;
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;

    //init受信待ちの準備時間を設ける
    misc_msleep(M_WAIT_RECV_THREAD);

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

        ptarm_buf_alloc(&buf_recv, len);
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
            pthread_mutex_lock(&p_conf->mux_proc);
            uint16_t type = ln_misc_get16be(buf_recv.buf);
            LOGV("[RECV]type=%04x(%s): sock=%d, Len=%d\n", type, ln_misc_msgname(type), p_conf->sock, buf_recv.len);
            ret = ln_recv(p_conf->p_self, buf_recv.buf, buf_recv.len);
            //LOGD("ln_recv() result=%d\n", ret);
            if (!ret) {
                LOGD("DISC: fail recv message\n");
                lnapp_close_channel_force(ln_their_node_id(p_conf->p_self));
                stop_threads(p_conf);
                break;
            }
            //LOGD("mux_proc: end\n");
            pthread_mutex_unlock(&p_conf->mux_proc);
        }
        ptarm_buf_free(&buf_recv);
    }

    LOGD("[exit]recv thread\n");

    return NULL;
}


/** 受信処理
 *
 * @param[in]   ToMsec      受信タイムアウト(0の場合、タイムアウト無し)
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
            //  処理要求があれば受け付ける
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
                    LOGD("EOF(len=%d)\n", len);
                    break;
                } else {
                    LOGD("fail: %s(%" PRIx64 ")\n", strerror(errno), ln_short_channel_id(p_conf->p_self));
                    len = 0;
                    break;
                }
            }
        }
    }

    return len;
}


/********************************************************************
 * 監視スレッド
 ********************************************************************/

/** 監視スレッド開始
 *
 * @param[in,out]   pArg    lnapp_conf_t*
 */
static void *thread_poll_start(void *pArg)
{
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;

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

        uint32_t bak_conf = p_conf->funding_confirm;
        uint32_t confirm = btcrpc_get_funding_confirm(p_conf->p_self);
        if (confirm > 0) {
            p_conf->funding_confirm = confirm;
            if (bak_conf != p_conf->funding_confirm) {
                LOGD2("***********************************\n");
                LOGD2("* CONFIRMATION: %d\n", p_conf->funding_confirm);
                LOGD2("*    funding_txid: ");
                TXIDD(ln_funding_txid(p_conf->p_self));
                LOGD2("***********************************\n");
            }
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
        if ( ln_open_announce_channel(p_conf->p_self) &&
             (p_conf->funding_confirm >= LN_ANNOSIGS_CONFIRM) &&
             (p_conf->funding_confirm >= ln_minimum_depth(p_conf->p_self)) ) {
            // BOLT#7: announcement_signaturesは最低でも 6confirmations必要
            //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#requirements
            ptarm_buf_t buf = PTARM_BUF_INIT;
            rcvidle_push(p_conf, TRANSCMD_ANNOSIGNS, &buf);
            ln_open_announce_channel_clr(p_conf->p_self);
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
        ptarm_buf_t buf_ping = PTARM_BUF_INIT;

        bool ret = ln_create_ping(p_conf->p_self, &buf_ping);
        if (ret) {
            send_peer_noise(p_conf, &buf_ping);
            ptarm_buf_free(&buf_ping);
        } else {
            //LOGD("pong not respond\n");
            //stop_threads(p_conf);
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
        bool ret = check_short_channel_id(p_conf);
        if (ret) {
            ret = exchange_funding_locked(p_conf);
            assert(ret);

            // send `channel_update` for private/before publish channel
            send_cnlupd_before_announce(p_conf);

            char close_addr[PTARM_SZ_ADDR_MAX];
            ret = ptarm_keys_spk2addr(close_addr, ln_shutdown_scriptpk_local(p_conf->p_self));
            if (!ret) {
                ptarm_util_bin2str(close_addr,
                        ln_shutdown_scriptpk_local(p_conf->p_self)->buf,
                        ln_shutdown_scriptpk_local(p_conf->p_self)->len);
            }

            misc_save_event(ln_channel_id(p_conf->p_self),
                    "funding_locked: short_channel_id=%" PRIx64 ", close_addr=%s",
                    ln_short_channel_id(p_conf->p_self), close_addr);
        } else {
            LOGD("fail: btcrpc_get_short_channel_param()\n");
        }

        p_conf->funding_waiting = false;
    } else {
        LOGD("confirmation waiting...: %d/%d\n", p_conf->funding_confirm, ln_minimum_depth(p_conf->p_self));
    }

    //DBGTRACE_END
}


//Normal Operation中
static void poll_normal_operating(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    //funding_tx使用チェック
    bool unspent;
    bool ret = btcrpc_check_unspent(&unspent, NULL, ln_funding_txid(p_conf->p_self), ln_funding_txindex(p_conf->p_self));
    if (ret && !unspent) {
        //ループ解除
        LOGD("funding_tx is spent.\n");
        ln_set_status(p_conf->p_self, LN_STATUS_CLOSING);
        stop_threads(p_conf);
    }

    //DBGTRACE_END
}


/** blockchainからのshort_channel_id計算
 *
 * @retval  true    OK
 */
static bool get_short_channel_id(lnapp_conf_t *p_conf)
{
    int bheight = 0;
    int bindex = 0;
    uint8_t mined_hash[PTARM_SZ_SHA256];
    bool ret = btcrpc_get_short_channel_param(p_conf->p_self, &bheight, &bindex, mined_hash, ln_funding_txid(p_conf->p_self));
    if (ret) {
        //LOGD("bindex=%d, bheight=%d\n", bindex, bheight);
        ret = ln_set_short_channel_id_param(p_conf->p_self, bheight, bindex, ln_funding_txindex(p_conf->p_self), mined_hash);
        LOGD("short_channel_id = %016" PRIx64 "(%d)\n", ln_short_channel_id(p_conf->p_self), ret);
    }

    return ret;
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

        bool retcnl = send_announcement(p_conf);
        if (retcnl) {
            if (p_conf->annodb_updated) {
                //annodb was updated, so send_announcement() will be done again.
                // since updating annodb may have been in the middle of send_announcement().
                p_conf->annodb_updated = false;
                slp = M_WAIT_ANNO_SEC;
            } else {
                slp = M_WAIT_ANNO_LONG_SEC;
            }
        } else {
            slp = M_WAIT_ANNO_SEC;
        }
    }

    LOGD("[exit]anno thread\n");

    return NULL;
}


/********************************************************************
 * 転送/巻き戻し処理
 ********************************************************************/

/** 前channelからのupdate_add_htlc転送要求実施
 *
 * update_add_htlcの転送は、update_add_htlc受信以外に発生しない。
 * タイミングはrevoke_and_ack後になるため、受信時には lnapp.p_revackqにため、
 * revoke_and_ack後に #lnapp_forward_payment()で lnapp.rcvidleにためる。
 * その後、転送先の #rcvidle_pop_and_exec()から呼び出される。
 *
 * @param[in,out]   p_conf
 * @param[in,out]   pFwdAdd
 * @param[out]      pReason
 */
static bool fwd_payment_forward(lnapp_conf_t *p_conf, fwd_proc_add_t *pFwdAdd, ptarm_buf_t *pReason)
{
    DBGTRACE_BEGIN

    bool ret;
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;

    nodeflag_set(FLAGNODE_ADDHTLC_SEND);

    uint64_t htlc_id;
    ret = ln_create_add_htlc(p_conf->p_self,
                        &buf_bolt,
                        &htlc_id,
                        pReason,
                        pFwdAdd->onion_route,
                        pFwdAdd->amt_to_forward,
                        pFwdAdd->outgoing_cltv_value,
                        pFwdAdd->payment_hash,
                        pFwdAdd->prev_short_channel_id,
                        pFwdAdd->prev_id,
                        &pFwdAdd->shared_secret);
    //ptarm_buf_free(&pFwdAdd->shared_secret);  //ln.cで管理するため、freeさせない
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }
    send_peer_noise(p_conf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);

    //add送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_conf->p_self, &buf_bolt);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }
    send_peer_noise(p_conf, &buf_bolt);

LABEL_EXIT:
    ptarm_buf_free(&buf_bolt);

    if (ret) {
        // method: forward
        // $1: short_channel_id
        // $2: node_id
        // $3: amt_to_forward
        // $4: outgoing_cltv_value
        // $5: payment_hash
        char hashstr[LN_SZ_HASH * 2 + 1];
        ptarm_util_bin2str(hashstr, pFwdAdd->payment_hash, LN_SZ_HASH);
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s "
                    "%" PRIu64 " "
                    "%" PRIu32 " "
                    "%s",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    pFwdAdd->amt_to_forward,
                    pFwdAdd->outgoing_cltv_value,
                    hashstr);
        call_script(EVT_FORWARD, param);
    } else if (pReason->len == 0) {
        //エラーだがreasonが未設定
        LOGD("fail: temporary_node_failure\n");
        ln_create_reason_temp_node(pReason);
    } else {
        //none
        LOGD("fail\n");
    }

    DBGTRACE_END

    return ret;
}


/** update_fulfill_htlc巻き戻し要求実施
 *
 * update_fulfill_htlcの巻き戻しは、以下の2パターンがある。
 *      - final nodeが update_add_htlc受信
 *      - forwarding nodeが update_fulfill_htlc受信
 *
 * 前者の場合、revoke_and_ackまで待つ必要があるため、受信時には lnapp.p_revackqにため、
 * revoke_and_ack後に #lnapp_forward_payment()で lnapp.rcvidleにためる。
 * その後、転送先の #rcvidle_pop_and_exec()から呼び出される。
 *
 * 後者の場合、待つ必要がないため、update_fulfill_htlc受信で lnapp.rcvidleにためる。
 * その後、転送先の #rcvidle_pop_and_exec()から呼び出される。
 */
static bool fwd_fulfill_backwind(lnapp_conf_t *p_conf, bwd_proc_fulfill_t *pBwdFulfill)
{
    DBGTRACE_BEGIN

    bool ret;
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;

    show_self_param(p_conf->p_self, stderr, "prev fulfill_htlc", __LINE__);

    LOGD("id= %" PRIu64 "\n", pBwdFulfill->id);
    LOGD("preimage= ");
    DUMPD(pBwdFulfill->preimage, LN_SZ_PREIMAGE);

    ret = ln_create_fulfill_htlc(p_conf->p_self, &buf_bolt,
                            pBwdFulfill->id, pBwdFulfill->preimage);
    assert(ret);
    send_peer_noise(p_conf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);
    nodeflag_set(FLAGNODE_FULFILL_SEND);

    //fulfill送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_conf->p_self, &buf_bolt);
    assert(ret);
    send_peer_noise(p_conf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);

    if (ret) {
        show_self_param(p_conf->p_self, stderr, "fulfill_htlc send", __LINE__);

        // method: fulfill
        // $1: short_channel_id
        // $2: node_id
        // $3: payment_hash
        // $4: payment_preimage
        char hashstr[LN_SZ_HASH * 2 + 1];
        uint8_t payment_hash[LN_SZ_HASH];
        ln_calc_preimage_hash(payment_hash, pBwdFulfill->preimage);
        ptarm_util_bin2str(hashstr, payment_hash, LN_SZ_HASH);
        char imgstr[LN_SZ_PREIMAGE * 2 + 1];
        ptarm_util_bin2str(imgstr, pBwdFulfill->preimage, LN_SZ_PREIMAGE);
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s "
                    "%s "
                    "%s",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    hashstr,
                    imgstr);
        call_script(EVT_FULFILL, param);
    }

    DBGTRACE_END

    return ret;
}


/** update_fail_htlc巻き戻し要求実施
 *
 * update_fail_htlcの巻き戻しは、以下の2パターンがある。
 *      - final nodeが update_add_htlc受信
 *      - forwarding nodeが update_fulfill_htlc受信 or update_fail_htlc受信
 *
 * 前者の場合、revoke_and_ackまで待つ必要があるため、受信時には lnapp.p_revackqにため、
 * revoke_and_ack後に #lnapp_forward_payment()で lnapp.rcvidleにためる。
 * その後、転送先の #rcvidle_pop_and_exec()から呼び出される。
 *
 * 後者の場合、待つ必要がないため、update_fulfill/fail_htlc受信で lnapp.rcvidleにためる。
 * その後、転送先の #rcvidle_pop_and_exec()から呼び出される。
 */
static bool fwd_fail_backwind(lnapp_conf_t *p_conf, bwd_proc_fail_t *pBwdFail)
{
    DBGTRACE_BEGIN

    bool ret = false;
    ptarm_buf_t buf_bolt = PTARM_BUF_INIT;

    show_self_param(p_conf->p_self, stderr, "prev fail_htlc", __LINE__);

    LOGD("id= %" PRIx64 "\n", pBwdFail->id);
    LOGD("reason= ");
    DUMPD(pBwdFail->reason.buf, pBwdFail->reason.len);
    LOGD("shared secret= ");
    DUMPD(pBwdFail->shared_secret.buf, pBwdFail->shared_secret.len);
    LOGD("first= %s\n", (pBwdFail->b_first) ? "true" : "false");

    ptarm_buf_t buf_reason = PTARM_BUF_INIT;
    if (pBwdFail->b_first) {
        ln_onion_failure_create(&buf_reason, &pBwdFail->shared_secret, &pBwdFail->reason);
    } else {
        ln_onion_failure_forward(&buf_reason, &pBwdFail->shared_secret, &pBwdFail->reason);
    }
    ret = ln_create_fail_htlc(p_conf->p_self, &buf_bolt, pBwdFail->id, &buf_reason);
    assert(ret);

    send_peer_noise(p_conf, &buf_bolt);
    ptarm_buf_free(&buf_bolt);

    //fail送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_conf->p_self, &buf_bolt);
    if (ret) {
        send_peer_noise(p_conf, &buf_bolt);
        ptarm_buf_free(&buf_bolt);
        nodeflag_set(FLAGNODE_FAIL_SEND);

        show_self_param(p_conf->p_self, stderr, "fail_htlc send", __LINE__);

        // method: fail
        // $1: short_channel_id
        // $2: node_id
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s",
                    ln_short_channel_id(p_conf->p_self), node_id);
        call_script(EVT_FAIL, param);
    }

    DBGTRACE_END

    return ret;
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
        //    LN_CB_ERROR,                ///< エラー通知
        //    LN_CB_INIT_RECV,            ///< init受信通知
        //    LN_CB_REESTABLISH_RECV,     ///< channel_reestablish受信通知
        //    LN_CB_SIGN_FUNDINGTX_REQ,   ///< funding_tx署名要求
        //    LN_CB_FUNDINGTX_WAIT,       ///< funding_tx安定待ち要求
        //    LN_CB_FUNDINGLOCKED_RECV,   ///< funding_locked受信通知
        //    LN_CB_CHANNEL_ANNO_RECV,    ///< channel_announcement受信
        //    LN_CB_UPDATE_ANNODB,        ///< announcement DB更新通知
        //    LN_CB_ADD_HTLC_RECV_PREV,   ///< update_add_htlc処理前通知
        //    LN_CB_ADD_HTLC_RECV,        ///< update_add_htlc受信通知
        //    LN_CB_FULFILL_HTLC_RECV,    ///< update_fulfill_htlc受信通知
        //    LN_CB_FAIL_HTLC_RECV,       ///< update_fail_htlc受信通知
        //    LN_CB_COMMIT_SIG_RECV_PREV, ///< commitment_signed処理前通知
        //    LN_CB_COMMIT_SIG_RECV,      ///< commitment_signed受信通知
        //    LN_CB_REV_AND_ACK_RECV,     ///< revoke_and_ack受信通知
        //    LN_CB_UPDATE_FEE_RECV,      ///< update_fee受信通知
        //    LN_CB_SHUTDOWN_RECV,        ///< shutdown受信通知
        //    LN_CB_CLOSED_FEE,           ///< closing_signed受信通知(FEE不一致)
        //    LN_CB_CLOSED,               ///< closing_signed受信通知(FEE一致)
        //    LN_CB_SEND_REQ,             ///< peerへの送信要求
        //    LN_CB_SEND_QUEUE,           ///< 送信データをキュー保存
        //    LN_CB_SET_LATEST_FEERATE,   ///< feerate_per_kw更新要求
        //    LN_CB_GETBLOCKCOUNT,        ///< getblockcount

        { "  LN_CB_ERROR: エラー有り", cb_error_recv },
        { "  LN_CB_INIT_RECV: init受信", cb_init_recv },
        { "  LN_CB_REESTABLISH_RECV: channel_reestablish受信", cb_channel_reestablish_recv },
        { "  LN_CB_SIGN_FUNDINGTX_REQ: funding_tx署名要求", cb_funding_tx_sign },
        { "  LN_CB_FUNDINGTX_WAIT: funding_tx confirmation待ち要求", cb_funding_tx_wait },
        { "  LN_CB_FUNDINGLOCKED_RECV: funding_locked受信通知", cb_funding_locked },
        { NULL/*"  LN_CB_CHANNEL_ANNO_RECV: channel_announcement受信"*/, cb_channel_anno_recv },
        { NULL/*"  LN_CB_UPDATE_ANNODB: announcement DB更新通知"*/, cb_update_anno_db },
        { "  LN_CB_ADD_HTLC_RECV_PREV: update_add_htlc処理前", cb_add_htlc_recv_prev },
        { "  LN_CB_ADD_HTLC_RECV: update_add_htlc受信", cb_add_htlc_recv },
        { "  LN_CB_FULFILL_HTLC_RECV: update_fulfill_htlc受信", cb_fulfill_htlc_recv },
        { "  LN_CB_FAIL_HTLC_RECV: update_fail_htlc受信", cb_fail_htlc_recv },
        { "  LN_CB_COMMIT_SIG_RECV_PREV: commitment_signed処理前", cb_commit_sig_recv_prev },
        { "  LN_CB_COMMIT_SIG_RECV: commitment_signed受信通知", cb_commit_sig_recv },
        { "  LN_CB_REV_AND_ACK_RECV: revoke_and_ack受信", cb_rev_and_ack_recv },
        { "  LN_CB_UPDATE_FEE_RECV: update_fee受信", cb_update_fee_recv },
        { "  LN_CB_SHUTDOWN_RECV: shutdown受信", cb_shutdown_recv },
        { "  LN_CB_CLOSED_FEE: closing_signed受信(FEE不一致)", cb_closed_fee },
        { "  LN_CB_CLOSED: closing_signed受信(FEE一致)", cb_closed },
        { "  LN_CB_SEND_REQ: 送信要求", cb_send_req },
        { "  LN_CB_SEND_QUEUE: 送信キュー", cb_send_queue },
        { "  LN_CB_SET_LATEST_FEERATE: feerate_per_kw更新", cb_set_latest_feerate },
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
            p_msg = (char *)APP_MALLOC(p_err->len * 2 + 1);
            ptarm_util_bin2str(p_msg, (const uint8_t *)p_err->p_data, p_err->len);
            break;
        }
    }
    set_lasterror(p_conf, RPCERR_PEER_ERROR, p_msg);
    misc_save_event(p_err->channel_id, "error message: %s", p_msg);
    if (b_alloc) {
        APP_FREE(p_msg);
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

    ptarm_buf_t buf_tx = PTARM_BUF_INIT;
    ptarm_tx_create(&buf_tx, p_sig->p_tx);
    p_sig->ret = btcrpc_signraw_tx(p_sig->p_tx, buf_tx.buf, buf_tx.len, p_sig->amount);
    ptarm_buf_free(&buf_tx);
}


//LN_CB_FUNDINGTX_WAIT: funding_txのconfirmation待ち開始
static void cb_funding_tx_wait(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_funding_t *p = (ln_cb_funding_t *)p_param;

    if (p->b_send) {
        uint8_t txid[PTARM_SZ_TXID];
        ptarm_buf_t buf_tx = PTARM_BUF_INIT;

        ptarm_tx_create(&buf_tx, p->p_tx_funding);
        p->b_result = btcrpc_sendraw_tx(txid, NULL, buf_tx.buf, buf_tx.len);
        if (p->b_result) {
            btcrpc_set_fundingtx(p_conf->p_self, buf_tx.buf, buf_tx.len);
        }
        ptarm_buf_free(&buf_tx);
    } else {
        p->b_result = true;
    }

    if (p->b_result) {
        //fundingの監視は thread_poll_start()に任せる
        LOGD("funding_tx監視開始: ");
        TXIDD(ln_funding_txid(p_conf->p_self));
        p_conf->funding_waiting = true;

        const char *p_str;
        if (ln_is_funder(p_conf->p_self)) {
            p_str = "funder";
        } else {
            p_str = "fundee";
        }
        char str_peerid[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(str_peerid, ln_their_node_id(p_conf->p_self), PTARM_SZ_PUBKEY);
        misc_save_event(ln_channel_id(p_conf->p_self),
                "open: funding wait start(%s): peer_id=%s",
                p_str, str_peerid);
    } else {
        LOGD("fail: send funding_tx\n");
        misc_save_event(ln_channel_id(p_conf->p_self),
                "fail: sendrawtransaction\n");
        stop_threads(p_conf);
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
        misc_save_event(ln_channel_id(p_conf->p_self),
                "open: recv funding_locked short_channel_id=%0" PRIx64,
                ln_short_channel_id(p_conf->p_self));
    }

    //funding_locked受信待ち合わせ解除(*4)
    p_conf->flag_recv |= RECV_MSG_FUNDINGLOCKED;
}


//LN_CB_CHANNEL_ANNO_RECV: channel_announcement受信
//  short_channel_idがcloseしているかチェックする
static void cb_channel_anno_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    //DBGTRACE_BEGIN

#ifndef USE_SPV
    ln_cb_channel_anno_recv_t *p = (ln_cb_channel_anno_recv_t *)p_param;
    p->is_unspent = check_unspent_short_channel_id(p->short_channel_id);
#else
    (void)p_param;
#endif

    //DBGTRACE_END
}


//LN_CB_UPDATE_ANNODB: announcement DB更新通知
static void cb_update_anno_db(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf; (void)p_param;

    LOGD("update anno db\n");
    p_conf->annodb_updated = true;
}


//LN_CB_ADD_HTLC_RECV_PREV: update_add_htlc受信(前処理)
static void cb_add_htlc_recv_prev(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;

    DBGTRACE_BEGIN

    ln_cb_add_htlc_recv_prev_t *p_prev = (ln_cb_add_htlc_recv_prev_t *)p_param;

    //転送先取得
    lnapp_conf_t *p_appconf = ptarmd_search_connected_cnl(p_prev->next_short_channel_id);
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
 *
 * revoke_and_ack交換まで待つため、 #revack_push() で貯めておく
 *      --> #cb_rev_and_ack_recv() で続きを行う
 */
static void cb_add_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_add_htlc_recv_t *p_addhtlc = (ln_cb_add_htlc_recv_t *)p_param;

    nodeflag_set(FLAGNODE_ADDHTLC_RECV);

    ptarmd_preimage_lock();
    if (p_addhtlc->ok) {
        LOGD("check OK\n");
        if (p_addhtlc->p_hop->b_exit) {
            //final node
            LOGD("final node\n");

            if (LN_DBG_FULFILL()) {
                //同一channelにupdate_fulfill_htlcを折り返す

                //backwind fulfill情報
                ptarm_buf_t buf;
                ptarm_buf_alloc(&buf, sizeof(bwd_proc_fulfill_t));
                bwd_proc_fulfill_t *p_bwd_fulfill = (bwd_proc_fulfill_t *)buf.buf;  //キュー処理後に解放

                p_bwd_fulfill->id = p_addhtlc->id;
                p_bwd_fulfill->prev_short_channel_id = 0;   //同一channelへの送信になるため、検索不要
                memcpy(p_bwd_fulfill->preimage, p_addhtlc->p_payment, LN_SZ_PREIMAGE);
                revack_push(p_conf, TRANSCMD_FULFILL, &buf);

                //preimageを使い終わったら消す
                ln_db_preimg_del(p_addhtlc->p_payment);

                //
                char str_payhash[LN_SZ_HASH * 2 + 1];
                ptarm_util_bin2str(str_payhash, p_addhtlc->p_payment, LN_SZ_HASH);
                misc_save_event(NULL,
                        "payment fulfill: payment_hash=%s short_channel_id=%" PRIx64,
                        str_payhash, ln_short_channel_id(p_conf->p_self));
            } else {
                LOGD("DBG: no fulfill mode\n");
            }
        } else {
            //別channelにupdate_add_htlcを転送する
            LOGD("forward\n");

            //forward add_htlc情報
            ptarm_buf_t buf;
            ptarm_buf_alloc(&buf, sizeof(fwd_proc_add_t));
            fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)buf.buf;  //キュー処理後に解放

            memcpy(p_fwd_add->onion_route, p_addhtlc->p_onion_route, LN_SZ_ONION_ROUTE);
            p_fwd_add->amt_to_forward = p_addhtlc->p_hop->amt_to_forward;
            p_fwd_add->outgoing_cltv_value = p_addhtlc->p_hop->outgoing_cltv_value;
            p_fwd_add->next_short_channel_id = p_addhtlc->p_hop->short_channel_id;
            memcpy(p_fwd_add->payment_hash, p_addhtlc->p_payment, LN_SZ_HASH);
            ptarm_buf_alloccopy(&p_fwd_add->shared_secret, p_addhtlc->p_shared_secret->buf, p_addhtlc->p_shared_secret->len);   // freeなし: lnで管理
            p_fwd_add->prev_short_channel_id = ln_short_channel_id(p_conf->p_self);
            p_fwd_add->prev_id = p_addhtlc->id;
            revack_push(p_conf, TRANSCMD_ADDHTLC, &buf);
        }
    } else {
        //同一channelにupdate_fail_htlcを折り返す
        LOGD("fail\n");

        //backwind fail情報
        ptarm_buf_t buf;
        ptarm_buf_alloc(&buf, sizeof(bwd_proc_fail_t));
        bwd_proc_fail_t *p_bwd_fail = (bwd_proc_fail_t *)buf.buf;  //キュー処理後に解放

        p_bwd_fail->id = p_addhtlc->id;
        p_bwd_fail->prev_short_channel_id = 0;
        ptarm_buf_alloccopy(&p_bwd_fail->shared_secret, p_addhtlc->p_shared_secret->buf, p_addhtlc->p_shared_secret->len);
        ptarm_buf_alloccopy(&p_bwd_fail->reason, p_addhtlc->reason.buf, p_addhtlc->reason.len);
        p_bwd_fail->b_first = true;
        revack_push(p_conf, TRANSCMD_FAIL, &buf);
    }
    ptarmd_preimage_unlock();

    DBGTRACE_END
}


//LN_CB_FULFILL_HTLC_RECV: update_fulfill_htlc受信
static void cb_fulfill_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    DBGTRACE_BEGIN

    const ln_cb_fulfill_htlc_recv_t *p_fulfill = (const ln_cb_fulfill_htlc_recv_t *)p_param;

    LOGD("mFlagNode %02x\n", mFlagNode);
    while (p_conf->loop) {
        pthread_mutex_lock(&mMuxNode);
        //PAYMENT以外の状態がなくなるまで待つ
        if ((mFlagNode & ~FLAGNODE_PAYMENT) == 0) {
            mFlagNode |= FLAGNODE_FULFILL_RECV;
            break;
        }
        pthread_mutex_unlock(&mMuxNode);
        misc_msleep(M_WAIT_MUTEX_MSEC);
    }

    if (p_fulfill->prev_short_channel_id != 0) {
        //巻き戻し
        LOGD("backwind: %" PRIx64 ", id=%" PRIx64 "\n", p_fulfill->prev_short_channel_id, p_fulfill->id);

        if (LN_DBG_FULFILL()) {
            ptarm_buf_t buf;
            ptarm_buf_alloc(&buf, sizeof(bwd_proc_fulfill_t));
            bwd_proc_fulfill_t *p_bwd_fulfill = (bwd_proc_fulfill_t *)buf.buf;

            p_bwd_fulfill->id = p_fulfill->id;
            p_bwd_fulfill->prev_short_channel_id = p_fulfill->prev_short_channel_id;
            memcpy(p_bwd_fulfill->preimage, p_fulfill->p_preimage, LN_SZ_PREIMAGE);
            bool ret = ptarmd_transfer_channel(p_fulfill->prev_short_channel_id, TRANSCMD_FULFILL, &buf);
            if (!ret) {
                //TODO:戻す先がない場合の処理(#366)
                LOGD("fail: cannot backwind\n");
            }
        } else {
            LOGD("DBG: no fulfill mode\n");
        }
    } else {
        //送金元
        LOGD("payer node\n");
        payroute_del(p_conf, p_fulfill->id);

        uint8_t hash[LN_SZ_HASH];
        ln_calc_preimage_hash(hash, p_fulfill->p_preimage);
        ln_db_invoice_del(hash);
    }
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %02x\n", mFlagNode);

    DBGTRACE_END
}


//LN_CB_FAIL_HTLC_RECV: update_fail_htlc受信
static void cb_fail_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_fail_htlc_recv_t *p_fail = (const ln_cb_fail_htlc_recv_t *)p_param;
    bool retry = false;

    LOGD("mFlagNode %02x\n", mFlagNode);
    while (p_conf->loop) {
        pthread_mutex_lock(&mMuxNode);
        //PAYMENT以外の状態がなくなるまで待つ
        if ((mFlagNode & ~FLAGNODE_PAYMENT) == 0) {
            mFlagNode |= FLAGNODE_FAIL_RECV;
            break;
        }
        pthread_mutex_unlock(&mMuxNode);
        misc_msleep(M_WAIT_MUTEX_MSEC);
    }

    if (p_fail->prev_short_channel_id != 0) {
        //フラグを立てて、相手の受信スレッドで処理してもらう
        LOGD("fail戻す: %" PRIx64 ", id=%" PRIx64 "\n", p_fail->prev_short_channel_id, p_fail->prev_id);

        ptarm_buf_t buf;
        ptarm_buf_alloc(&buf, sizeof(bwd_proc_fail_t));
        bwd_proc_fail_t *p_bwd_fail = (bwd_proc_fail_t *)buf.buf;

        p_bwd_fail->id = p_fail->prev_id;
        p_bwd_fail->prev_short_channel_id = p_fail->prev_short_channel_id;
        ptarm_buf_alloccopy(&p_bwd_fail->reason, p_fail->p_reason->buf, p_fail->p_reason->len);
        ptarm_buf_alloccopy(&p_bwd_fail->shared_secret, p_fail->p_shared_secret->buf, p_fail->p_shared_secret->len);
        p_bwd_fail->b_first = false;
        bool ret = ptarmd_transfer_channel(p_fail->prev_short_channel_id, TRANSCMD_FAIL, &buf);
        if (!ret) {
            //TODO:戻す先がない場合の処理(#366)
            LOGD("戻せない\n");
        }
    } else {
        LOGD("ここまで\n");

        ptarm_buf_t reason = PTARM_BUF_INIT;
        int hop;
        bool ret = ln_onion_failure_read(&reason, &hop, p_fail->p_shared_secret, p_fail->p_reason);
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
            char suggest[64];
            const payment_conf_t *p_payconf = payroute_get(p_conf, p_fail->orig_id);
            if (p_payconf != NULL) {
                if (hop == p_payconf->hop_num - 2) {
                    //送金先がエラーを返した？
                    strcpy(suggest, "payee");
                } else if (hop < p_payconf->hop_num - 2) {
                    //途中がエラーを返した
                    // LOGD2("hop=%d\n", hop);
                    // for (int lp = 0; lp < p_payconf.hop_num; lp++) {
                    //     LOGD2("[%d]%" PRIu64 "\n", lp, p_payconf->hop_datain[lp].short_channel_id);
                    // }

                    uint64_t short_channel_id = p_payconf->hop_datain[hop + 1].short_channel_id;
                    sprintf(suggest, "%016" PRIx64, short_channel_id);
                    ln_db_annoskip_save(short_channel_id, btemp);
                    retry = true;
                } else {
                    strcpy(suggest, "invalid");
                }
            } else {
                strcpy(suggest, "?");
            }
            LOGD("suggest: %s\n", suggest);

            char errstr[512];
            char reasonstr[128];
            set_onionerr_str(reasonstr, &onionerr);
            sprintf(errstr, M_ERRSTR_REASON, reasonstr, hop, suggest);
            set_lasterror(p_conf, RPCERR_PAYFAIL, errstr);

            free(onionerr.p_data);
        } else {
            //デコード失敗
            set_lasterror(p_conf, RPCERR_PAYFAIL, M_ERRSTR_CANNOTDECODE);
        }
        payroute_del(p_conf, p_fail->orig_id);
        if (retry) {
            LOGD("pay retry: ");
            DUMPD(p_fail->p_payment_hash, LN_SZ_HASH);

            ptarm_buf_t buf;
            ptarm_buf_alloccopy(&buf, p_fail->p_payment_hash, LN_SZ_HASH);  //キュー処理後に解放
            revack_push(p_conf, TRANSCMD_PAYRETRY, &buf);
        } else {
            ln_db_invoice_del(p_fail->p_payment_hash);
        }
    }
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %02x\n", mFlagNode);

    DBGTRACE_END
}


//LN_CB_COMMIT_SIG_RECV_PREV": commitment_signed受信(前処理)
static void cb_commit_sig_recv_prev(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf; (void)p_param;
}


//LN_CB_COMMIT_SIG_RECV: commitment_signed受信
static void cb_commit_sig_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf; (void)p_param;

    pthread_mutex_lock(&mMuxNode);
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %02x\n", mFlagNode);
}


/** LN_CB_REV_AND_ACK_RECV: revoke_and_ack受信通知
 */
static void cb_rev_and_ack_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    bool scr = true;   //true: call_script()

    pthread_mutex_lock(&mMuxNode);
    LOGD("mFlagNode: %02x\n", mFlagNode);

    uint64_t total_amount = ln_node_total_msat();

    if (mFlagNode & FLAGNODE_PAYMENT) {
        //payer
        mFlagNode &= ~FLAGNODE_PAYMENT;
        if (M_FLAG_MASK(mFlagNode, FLAGNODE_ADDHTLC_SEND) || M_FLAG_MASK(mFlagNode, FLAGNODE_ADDHTLC_RECV) ) {
            //送金中
            LOGD("PAYMENT: htlc added\n");
            mFlagNode = FLAGNODE_PAYMENT;
        } else if ( M_FLAG_MASK(mFlagNode, FLAGNODE_FULFILL_SEND) || M_FLAG_MASK(mFlagNode, FLAGNODE_FULFILL_RECV) ) {
            //送金完了
            LOGD("PAYMENT: htlc fulfilled\n");
            misc_save_event(NULL,
                    "payment success: short_channel_id=%" PRIx64 " total_msat=%" PRIu64 "(our_msat=%" PRIu64 " their_msat=%" PRIu64 ")",
                    ln_short_channel_id(p_conf->p_self), total_amount, ln_our_msat(p_conf->p_self), ln_their_msat(p_conf->p_self));
            mFlagNode = FLAGNODE_NONE;
        } else if ( M_FLAG_MASK(mFlagNode, FLAGNODE_FAIL_SEND) || M_FLAG_MASK(mFlagNode, FLAGNODE_FAIL_RECV)) {
            //送金失敗
            LOGD("PAYMENT: fail_htlc\n");
            mFlagNode = FLAGNODE_NONE;
        } else {
            //それ以外
            scr = false;
            LOGD("PAYMENT: other\n");
            mFlagNode = FLAGNODE_NONE;
        }
    } else if (mFlagNode & (FLAGNODE_UPDFEE_SEND | FLAGNODE_UPDFEE_RECV)) {
        //update_fee
        LOGD("UPDATE_FEE\n");
        misc_save_event(ln_channel_id(p_conf->p_self),
                "fee updated: short_channel_id=%" PRIx64 " feerate_per_kw=%" PRIu32,
                ln_short_channel_id(p_conf->p_self), ln_feerate_per_kw(p_conf->p_self));
        mFlagNode = FLAGNODE_NONE;
    } else {
        //非payer
        if (M_FLAG_MASK(mFlagNode, FLAGNODE_ADDHTLC_SEND) || M_FLAG_MASK(mFlagNode, FLAGNODE_ADDHTLC_RECV) ) {
            //送金中
            LOGD("FORWARD: htlc added\n");
            mFlagNode = FLAGNODE_NONE;
        } else if ( M_FLAG_MASK(mFlagNode, FLAGNODE_FULFILL_SEND) || M_FLAG_MASK(mFlagNode, FLAGNODE_FULFILL_RECV) ) {
            //送金完了
            LOGD("FORWARD: htlc fulfilled\n");
            misc_save_event(NULL,
                    "forward success: short_channel_id=%" PRIx64 " total_msat=%" PRIu64 "(our_msat=%" PRIu64 " their_msat=%" PRIu64 ")",
                    ln_short_channel_id(p_conf->p_self), total_amount, ln_our_msat(p_conf->p_self), ln_their_msat(p_conf->p_self));
            mFlagNode = FLAGNODE_NONE;
        } else if ( M_FLAG_MASK(mFlagNode, FLAGNODE_FAIL_SEND) || M_FLAG_MASK(mFlagNode, FLAGNODE_FAIL_RECV)) {
            //送金失敗
            LOGD("FORWARD: fail_htlc\n");
            mFlagNode = FLAGNODE_NONE;
        } else {
            //それ以外
            scr = false;
            LOGD("FORWARD: other\n");
            mFlagNode = FLAGNODE_NONE;
        }
    }
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %d\n", mFlagNode);

    //要求がキューに積んであれば処理する
    revack_pop_and_exec(p_conf);

    if (scr) {
        // method: htlc_changed
        // $1: short_channel_id
        // $2: node_id
        // $3: our_msat
        // $4: htlc_num
        char param[256];
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        sprintf(param, "%" PRIx64 " %s "
                    "%" PRIu64 " "
                    "%d",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    ln_node_total_msat(),
                    ln_htlc_num(p_conf->p_self));
        call_script(EVT_HTLCCHANGED, param);
    }

    show_self_param(p_conf->p_self, stderr, "revoke_and_ack", __LINE__);

    DBGTRACE_END
}


//LN_CB_UPDATE_FEE_RECV: update_fee受信
static void cb_update_fee_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    uint32_t oldrate = *(const uint32_t *)p_param;

    nodeflag_set(FLAGNODE_UPDFEE_RECV);

    misc_save_event(ln_channel_id(p_conf->p_self),
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
    uint64_t commit_fee = ln_calc_max_closing_fee(p_conf->p_self);
    ln_update_shutdown_fee(p_conf->p_self, commit_fee);

    misc_save_event(ln_channel_id(p_conf->p_self), "close: recv shutdown");
}


//LN_CB_CLOSED_FEE: closing_signed受信(FEE不一致)
static void cb_closed_fee(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_closed_fee_t *p_closed_fee = (const ln_cb_closed_fee_t *)p_param;
    LOGD("received fee: %" PRIu64 "\n", p_closed_fee->fee_sat);

#warning How to decide shutdown fee
    ln_update_shutdown_fee(p_conf->p_self, p_closed_fee->fee_sat);
}


//LN_CB_CLOSED: closing_singed受信(FEE一致)
//  コールバック後、selfはクリアされる
static void cb_closed(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_closed_t *p_closed = (const ln_cb_closed_t *)p_param;

    if (LN_DBG_CLOSING_TX()) {
        //closing_txを展開
        LOGD("send closing tx\n");

        uint8_t txid[PTARM_SZ_TXID];
        bool ret = btcrpc_sendraw_tx(txid, NULL, p_closed->p_tx_closing->buf, p_closed->p_tx_closing->len);
        if (!ret) {
            LOGD("btcrpc_sendraw_tx\n");
            assert(0);
        }
        LOGD("closing_txid: ");
        TXIDD(txid);

        // method: closed
        // $1: short_channel_id
        // $2: node_id
        // $3: closing_txid
        char param[256];
        char txidstr[PTARM_SZ_TXID * 2 + 1];
        ptarm_util_bin2str_rev(txidstr, txid, PTARM_SZ_TXID);
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        sprintf(param, "%" PRIx64 " %s "
                    "%s",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    txidstr);
        call_script(EVT_CLOSED, param);
    } else {
        LOGD("DBG: no send closing_tx mode\n");
    }
    misc_save_event(ln_channel_id(p_conf->p_self), "close: good way: end");

    DBGTRACE_END
}


//LN_CB_SEND_REQ: BOLTメッセージ送信要求
static void cb_send_req(lnapp_conf_t *p_conf, void *p_param)
{
    ptarm_buf_t *p_buf = (ptarm_buf_t *)p_param;
    send_peer_noise(p_conf, p_buf);
}


//LN_CB_SEND_QUEUE: BOLTメッセージをキュー保存
static void cb_send_queue(lnapp_conf_t *p_conf, void *p_param)
{
    ptarm_buf_t *p_buf = (ptarm_buf_t *)p_param;

    pthread_mutex_lock(&p_conf->mux_sendque);
    send_queue_push(p_conf, p_buf);
    pthread_mutex_unlock(&p_conf->mux_sendque);
}


//LN_CB_SET_LATEST_FEERATE: estimatesmartfeeによるfeerate_per_kw更新(DB保存しない)
static void cb_set_latest_feerate(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;

    uint32_t feerate_kw = monitoring_get_latest_feerate_kw();
    ln_set_feerate_per_kw(p_conf->p_self, feerate_kw);
}


//LN_CB_GETBLOCKCOUNT
static void cb_getblockcount(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;

    int32_t *p_height = (int32_t *)p_param;
    *p_height = btcrpc_getblockcount();
    LOGD("block count=%" PRId32 "\n", *p_height);
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
        LOGD("disconnect channel: %016" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));
        LOGD("===================================\n");
        LOGD("=  CHANNEL THREAD END             =\n");
        LOGD("===================================\n");
    }
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
        LOGD("poll: %s\n", strerror(errno));
        return false;
    }

    int optval;
    socklen_t optlen = sizeof(optval);
    int retval = getsockopt(p_conf->sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
    if (retval != 0) {
        LOGD("getsockopt: %s\n", strerror(errno));
        return false;
    }
    if (optval) {
        LOGD("getsockopt: optval: %s\n", strerror(optval));
        return false;
    }

    return true;
}


//peer送信(そのまま送信)
static bool send_peer_raw(lnapp_conf_t *p_conf, const ptarm_buf_t *pBuf)
{
    struct pollfd fds;
    ssize_t len = pBuf->len;
    while ((p_conf->loop) && (len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLOUT;
        int polr = poll(&fds, 1, M_WAIT_RECV_TO_MSEC);
        if (polr <= 0) {
            LOGD("poll: %s\n", strerror(errno));
            break;
        }
        ssize_t sz = write(p_conf->sock, pBuf->buf, len);
        if (sz < 0) {
            LOGD("write: %s\n", strerror(errno));
            break;
        }
        len -= sz;
        misc_msleep(M_WAIT_SEND_WAIT_MSEC);
    }

    return len == 0;
}


//peer送信(Noise Protocol送信)
static bool send_peer_noise(lnapp_conf_t *p_conf, const ptarm_buf_t *pBuf)
{
    uint16_t type = ln_misc_get16be(pBuf->buf);
    LOGV("[SEND]type=%04x(%s): sock=%d, Len=%d\n", type, ln_misc_msgname(type), p_conf->sock, pBuf->len);

    pthread_mutex_lock(&p_conf->mux_send);

    ptarm_buf_t buf_enc;
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
        int polr = poll(&fds, 1, M_WAIT_RECV_TO_MSEC);
        if (polr <= 0) {
            LOGD("poll: %s\n", strerror(errno));
            break;
        }
        ssize_t sz = write(p_conf->sock, buf_enc.buf, len);
        if (sz < 0) {
            LOGD("write: %s\n", strerror(errno));
            stop_threads(p_conf);
            break;
        }
        len -= sz;
        misc_msleep(M_WAIT_SEND_WAIT_MSEC);
    }
    ptarm_buf_free(&buf_enc);

    //ping送信待ちカウンタ
    p_conf->ping_counter = 0;

LABEL_EXIT:
    pthread_mutex_unlock(&p_conf->mux_send);
    return len == 0;
}


/********************************************************************
 * announcement展開
 ********************************************************************/

/** channel_announcement/channel_update/node_announcement送信
 *
 * 接続先へ未送信のchannel_announcement/channel_updateを送信する。
 * 一度にすべて送信するとDBのロック期間が長くなるため、
 * 最大M_ANNO_UNITパケットまで送信を行い、残りは次回呼び出しに行う。
 *
 * channel_announcementに含まれていないnode_announcementは
 *
 * @param[in,out]   p_conf  lnapp情報
 * @retval  true    リストの最後まで終わった
 */
static bool send_announcement(lnapp_conf_t *p_conf)
{
    bool ret;
    int anno_cnt = 0;
    uint64_t short_channel_id = 0;

    LOGD("BEGIN\n");

    void *p_db_cnl = NULL;
    void *p_db_node = NULL;
    ret = ln_db_node_cur_transaction(&p_db_cnl, LN_DB_TXN_CNL, NULL);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_node_cur_transaction(&p_db_node, LN_DB_TXN_NODE, p_db_cnl);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }

    ptarm_buf_t buf_cnl = PTARM_BUF_INIT;
    void *p_cur;
    ret = ln_db_annocnl_cur_open(&p_cur, p_db_cnl);
    if (!ret) {
        LOGD("fail\n");
        goto LABEL_EXIT;
    }

    char type;
    if (p_conf->last_anno_cnl != 0) {
        //前回のところまで検索する
        while ((ret = ln_db_annocnl_cur_get(p_cur, &short_channel_id, &type, NULL, &buf_cnl))) {
            if (short_channel_id == p_conf->last_anno_cnl) {
                break;
            }
            ptarm_buf_free(&buf_cnl);
        }
    }
    ptarm_buf_free(&buf_cnl);

    uint32_t timestamp;
    while ((ret = ln_db_annocnl_cur_get(p_cur, &short_channel_id, &type, &timestamp, &buf_cnl))) {
        if (!p_conf->loop) {
            break;
        }

        //事前チェック
        if (type == LN_DB_CNLANNO_ANNO) {
            p_conf->last_annocnl_sci = short_channel_id;    //channel_updateだけを送信しないようにするため
            ret = send_anno_pre_chan(short_channel_id);
            if (!ret) {
                goto LABEL_EXIT;
            }
        } else if ((type == LN_DB_CNLANNO_UPD1) || (type == LN_DB_CNLANNO_UPD2)) {
            ret = send_anno_pre_upd(short_channel_id, timestamp);
            if (!ret) {
                goto LABEL_EXIT;
            }
        } else {
            //nothing
        }

        //取得したchannel_announcementのshort_channel_idに一致するものは送信する
        if (p_conf->last_annocnl_sci == short_channel_id) {
            bool chk = ln_db_annocnls_search_nodeid(p_db_cnl, short_channel_id, type, ln_their_node_id(p_conf->p_self));
            if (!chk) {
                send_anno_cnl(p_conf, type, p_db_cnl, &buf_cnl);

                //送信数カウント
                anno_cnt++;
            }
            if (type == LN_DB_CNLANNO_ANNO) {
                //channel_announcementの送信にかかわらず、未送信のnode_announcementは送信する
                send_anno_node(p_conf, p_db_node, &buf_cnl);
            }

            if (anno_cnt >= M_ANNO_UNIT) {
                //占有しないよう、一度に全部は送信しない
                break;
            }
        } else {
            //channel_announcementが無いchannel_updateの場合
            LOGD("skip channel_%c: last=%016" PRIx64 " / get=%016" PRIx64 "\n", type, p_conf->last_annocnl_sci, short_channel_id);
        }
        ptarm_buf_free(&buf_cnl);
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
    ptarm_buf_free(&buf_cnl);
    if (p_cur != NULL) {
        ln_db_annocnl_cur_close(p_cur);
    }
    if (p_db_cnl != NULL) {
        ln_db_node_cur_commit(p_db_cnl);
    }
    if (short_channel_id != 0) {
        (void)ln_db_annocnlall_del(short_channel_id);
    }

    LOGD("END\n");
    return p_conf->last_anno_cnl == 0;
}


static bool send_anno_pre_chan(uint64_t short_channel_id)
{
    bool ret = true;

#ifndef USE_SPV
    bool unspent = check_unspent_short_channel_id(short_channel_id);
    if (!unspent) {
        //使用済みのため、DBから削除
        LOGD("closed channel: %0" PRIx64 "\n", short_channel_id);
        ret = false;
    }
#else
    (void)short_channel_id;
#endif

    return ret;
}


static bool send_anno_pre_upd(uint64_t short_channel_id, uint32_t timestamp)
{
    bool ret = true;

    //BOLT#7: Pruning the Network View
    uint64_t now = (uint64_t)time(NULL);
    if (ln_db_annocnlupd_is_prune(now, timestamp)) {
        //古いため、DBから削除
        char tmstr[PTARM_SZ_DTSTR + 1];
        ptarm_util_strftime(tmstr, timestamp);
        LOGD("older channel: prune(%0" PRIx64 "): %s\n", short_channel_id, tmstr);
        ret = false;
    }

    return ret;
}


static void send_anno_cnl(lnapp_conf_t *p_conf, char type, void *p_db, const ptarm_buf_t *p_buf_cnl)
{
    LOGV("send channel_%c: %016" PRIx64 "\n", type, p_conf->last_annocnl_sci);
#ifdef DEVELOPER_MODE
    ln_msg_cnl_announce_print(p_buf_cnl->buf, p_buf_cnl->len);
#endif
    send_peer_noise(p_conf, p_buf_cnl);
    ln_db_annocnls_add_nodeid(p_db, p_conf->last_annocnl_sci, type, false, ln_their_node_id(p_conf->p_self));
}


static void send_anno_node(lnapp_conf_t *p_conf, void *p_db, const ptarm_buf_t *p_buf_cnl)
{
    uint64_t short_channel_id;
    uint8_t node[2][PTARM_SZ_PUBKEY];
    bool ret = ln_getids_cnl_anno(&short_channel_id, node[0], node[1], p_buf_cnl->buf, p_buf_cnl->len);
    if (!ret) {
        return;
    }

    ptarm_buf_t buf_node = PTARM_BUF_INIT;

    for (int lp = 0; lp < 2; lp++) {
        ret = ln_db_annonod_search_nodeid(p_db, node[lp], ln_their_node_id(p_conf->p_self));
        if (!ret) {
            ret = ln_db_annonod_load(&buf_node, NULL, node[lp], p_db);
            if (ret) {
                LOGV("send node_anno: ");
                DUMPV(node[lp], PTARM_SZ_PUBKEY);
                send_peer_noise(p_conf, &buf_node);
                ptarm_buf_free(&buf_node);

                ln_db_annonod_add_nodeid(p_db, node[lp], false, ln_their_node_id(p_conf->p_self));
            }
        }
    }
}


/** announcement前のchannel_update送信
 *      https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001220.html
 *
 */
static void send_cnlupd_before_announce(lnapp_conf_t *p_conf)
{
    ln_self_t *p_self = p_conf->p_self;

    if ((ln_short_channel_id(p_self) != 0) && !ln_is_announced(p_self)) {
        //チャネル作成済み && announcement未交換
        ptarm_buf_t buf_bolt = PTARM_BUF_INIT;
        bool ret = ln_create_channel_update(p_self, &buf_bolt);
        if (ret) {
            send_peer_noise(p_conf, &buf_bolt);
            ptarm_buf_free(&buf_bolt);
        }
    }
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
    channel_conf_t econf;
    ln_establish_prm_t estprm;

    conf_channel_init(&econf);
    (void)conf_channel_load("channel.conf", &econf);
    estprm.dust_limit_sat = econf.dust_limit_sat;
    estprm.max_htlc_value_in_flight_msat = econf.max_htlc_value_in_flight_msat;
    estprm.channel_reserve_sat = econf.channel_reserve_sat;
    estprm.htlc_minimum_msat = econf.htlc_minimum_msat;
    estprm.to_self_delay = econf.to_self_delay;
    estprm.max_accepted_htlcs = econf.max_accepted_htlcs;
    estprm.min_depth = econf.min_depth;

    ln_set_init_localfeatures(econf.localfeatures);
    bool ret = ln_set_establish(p_conf->p_self, &estprm);
    assert(ret);
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


/** mFlagNode フラグの変更(OR処理)
 *
 * FLAGNODE_PAYMENTが立っていないことを確認
 */
static void nodeflag_set(node_flag_t Flag)
{
    LOGD("mFlagNode %d\n", mFlagNode);
    uint32_t count = M_WAIT_RESPONSE_MSEC / M_WAIT_MUTEX_MSEC;
    while (count) {
        pthread_mutex_lock(&mMuxNode);
        //ここで PAYMENTがある場合もブロックすると、デッドロックする可能性あり
        if ((mFlagNode & ~FLAGNODE_PAYMENT) == 0) {
            break;
        }
        pthread_mutex_unlock(&mMuxNode);
        misc_msleep(M_WAIT_MUTEX_MSEC);
        count--;
    }
    mFlagNode |= Flag;
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %d\n", mFlagNode);
}


/** mFlagNode フラグの解除
 *
 *
 */
static void nodeflag_unset(node_flag_t Flag)
{
    pthread_mutex_lock(&mMuxNode);
    mFlagNode &= ~Flag;
    pthread_mutex_unlock(&mMuxNode);
    LOGD("  -->mFlagNode %d\n", mFlagNode);
}


/** イベント発生によるスクリプト実行
 *
 *
 */
static void call_script(event_t event, const char *param)
{
    LOGD("event=0x%02x\n", (int)event);

    struct stat buf;
    int ret = stat(kSCRIPT[event], &buf);
    if ((ret == 0) && (buf.st_mode & S_IXUSR)) {
        char *cmdline = (char *)APP_MALLOC(128 + strlen(param));    //APP_FREE: この中
        sprintf(cmdline, "%s %s", kSCRIPT[event], param);
        LOGD("cmdline: %s\n", cmdline);
        system(cmdline);
        APP_FREE(cmdline);      //APP_MALLOC: この中
    }
}


/** onion fail reason文字列設定
 *
 *
 */
static void set_onionerr_str(char *pStr, const ln_onion_err_t *pOnionErr)
{
    const struct {
        uint16_t err;
        const char *str;
    } ONIONERR[] = {
        { LNONION_INV_REALM, "invalid realm" },
        { LNONION_TMP_NODE_FAIL, "temporary_node_failure" },
        { LNONION_PERM_NODE_FAIL, "permanent_node_failure" },
        { LNONION_REQ_NODE_FTR_MISSING, "required_node_feature_missing" },
        { LNONION_INV_ONION_VERSION, "invalid_onion_version" },
        { LNONION_INV_ONION_HMAC, "invalid_onion_hmac" },
        { LNONION_INV_ONION_KEY, "invalid_onion_key" },
        { LNONION_TMP_CHAN_FAIL, "temporary_channel_failure" },
        { LNONION_PERM_CHAN_FAIL, "permanent_channel_failure" },
        { LNONION_REQ_CHAN_FTR_MISSING, "required_channel_feature_missing" },
        { LNONION_UNKNOWN_NEXT_PEER, "unknown_next_peer" },
        { LNONION_AMT_BELOW_MIN, "amount_below_minimum" },
        { LNONION_FEE_INSUFFICIENT, "fee_insufficient" },
        { LNONION_INCORR_CLTV_EXPIRY, "incorrect_cltv_expiry" },
        { LNONION_EXPIRY_TOO_SOON, "expiry_too_soon" },
        { LNONION_UNKNOWN_PAY_HASH, "unknown_payment_hash" },
        { LNONION_INCORR_PAY_AMT, "incorrect_payment_amount" },
        { LNONION_FINAL_EXPIRY_TOO_SOON, "final_expiry_too_soon" },
        { LNONION_FINAL_INCORR_CLTV_EXP, "final_incorrect_cltv_expiry" },
        { LNONION_FINAL_INCORR_HTLC_AMT, "final_incorrect_htlc_amount" },
        { LNONION_CHAN_DISABLE, "channel_disabled" },
        { LNONION_EXPIRY_TOO_FAR, "expiry_too_far" },
    };

    const char *p_str = NULL;
    for (size_t lp = 0; lp < ARRAY_SIZE(ONIONERR); lp++) {
        if (pOnionErr->reason == ONIONERR[lp].err) {
            p_str = ONIONERR[lp].str;
            break;
        }
    }
    if (p_str != NULL) {
        strcpy(pStr, p_str);
    } else {
        sprintf(pStr, "unknown reason[%04x]", pOnionErr->reason);
    }
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
        p_conf->p_errstr = (char *)APP_MALLOC(len_max);        //APP_FREE: thread_main_start()
        strcpy(p_conf->p_errstr, pErrStr);
        LOGD("%s\n", p_conf->p_errstr);

        // method: error
        // $1: short_channel_id
        // $2: node_id
        // $3: err_str
        char *param = (char *)APP_MALLOC(len_max);      //APP_FREE: この中
        char node_id[PTARM_SZ_PUBKEY * 2 + 1];
        ptarm_util_bin2str(node_id, ln_node_getid(), PTARM_SZ_PUBKEY);
        sprintf(param, "%" PRIx64 " %s "
                    "\"%s\"",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    p_conf->p_errstr);
        call_script(EVT_ERROR, param);
        APP_FREE(param);        //APP_MALLOC: この中
    }
}



/**************************************************************************
 * revoke_and_ack受信後処理
 *
 * update_add/fulfill/fail_htlcは、revoke_and_ackの交換まで待たないと
 * 送信できない仕様になっている(fulfillとfailは、addと混在できない場合のみ)。
 * よって、以下の場合に本APIでキューにため、revoke_and_ack受信まで処理を遅延させる。
 *      - update_add_htlc受信によるupdate_add_htlcの転送(中継node)
 *      - update_add_htlc受信によるupdate_fulfill_htlcの巻き戻し(last node)
 *      - update_add_htlc受信によるupdate_fail_htlcの巻き戻し(last node)
 *      - 送金失敗によるリトライ
 **************************************************************************/

/** [revoke_and_ack受信後]キューpush
 *
 * @note
 *      - pBufは処理後に解放するため、呼び元では解放しないこと
 */
static void revack_push(lnapp_conf_t *p_conf, trans_cmd_t Cmd, ptarm_buf_t *pBuf)
{
    pthread_mutex_lock(&p_conf->mux_revack);

    transferlist_t *p_revack = (transferlist_t *)APP_MALLOC(sizeof(transferlist_t));       //APP_FREE: revack_pop_and_exec()

    p_revack->cmd = Cmd;
    memcpy(&p_revack->buf, pBuf, sizeof(ptarm_buf_t));
    LIST_INSERT_HEAD(&p_conf->revack_head, p_revack, list);

    pthread_mutex_unlock(&p_conf->mux_revack);
}


/** [revoke_and_ack受信後]キューpop
 *
 */
static void revack_pop_and_exec(lnapp_conf_t *p_conf)
{
    pthread_mutex_lock(&p_conf->mux_revack);

    struct transferlist_t *p_revack = LIST_FIRST(&p_conf->revack_head);

    if (p_revack == NULL) {
        //empty
        pthread_mutex_unlock(&p_conf->mux_revack);
        return;
    }

    ptarm_buf_t *p_fail_ss = NULL;
    uint64_t fail_id;
    ptarm_buf_t fail_reason = PTARM_BUF_INIT;

    switch (p_revack->cmd) {
    case TRANSCMD_ADDHTLC:
        LOGD("TRANSCMD_ADDHTLC\n");
        {
            //別チャネルの受信アイドル時キューにupdate_add_htlc要求する
            fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)p_revack->buf.buf;

            bool ret = ptarmd_transfer_channel(p_fwd_add->next_short_channel_id, p_revack->cmd, &p_revack->buf);
            if (!ret) {
                //add_htlc時に ptarmd_search_connected_cnl()でチェックしているので、
                //ここまでに接続が切れたか、受信アイドル時キューへの追加に失敗した場合
                LOGD("fail: forwarding\n");

                //update_fail_htlc準備
                p_fail_ss = &p_fwd_add->shared_secret;
                fail_id = p_fwd_add->prev_id;
                ln_create_reason_temp_node(&fail_reason);
            }
        }
        break;
    case TRANSCMD_FULFILL:
        //自チャネルの受信アイドル時キューにupdate_fulfill_htlc要求する。
        //revoke_and_ack後キューにupdate_fulfill_htlc要求が入るのは、last nodeの場合のみ。
        //update_fulfill_htlcの巻き戻しは受信アイドル時キューに要求するため、ここは通らない。
        LOGD("TRANSCMD_FULFILL\n");
        lnapp_transfer_channel(p_conf, TRANSCMD_FULFILL, &p_revack->buf);
        break;
    case TRANSCMD_FAIL:
        //自チャネルの受信アイドル時キューにupdate_fail_htlc要求する。
        //このルートは、update_add_htlc受信をln.cがNG判定した場合となる。
        //update_fail_htlcの巻き戻しは受信アイドル時キューに要求するため、ここは通らない。
        LOGD("TRANSCMD_FAIL\n");
        {
            bwd_proc_fail_t *p_bwd_fail = (bwd_proc_fail_t *)p_revack->buf.buf;

            p_fail_ss = &p_bwd_fail->shared_secret;
            fail_id = p_bwd_fail->id;
            memcpy(&fail_reason, &p_bwd_fail->reason, sizeof(ptarm_buf_t));
            ptarm_buf_init(&p_bwd_fail->reason);
        }
        break;
    case TRANSCMD_PAYRETRY:
        LOGD("TRANSCMD_PAYRETRY\n");
        cmd_json_pay_retry(p_revack->buf.buf);
        break;
    default:
        break;
    }
    if (p_fail_ss != NULL) {
        //自チャネルの受信アイドル時キューにupdate_fail_htlc要求する
        ptarm_buf_t buf;
        ptarm_buf_alloc(&buf, sizeof(bwd_proc_fail_t));
        bwd_proc_fail_t *p_bwd_fail = (bwd_proc_fail_t *)buf.buf;

        p_bwd_fail->id = fail_id;
        memcpy(&p_bwd_fail->reason, &fail_reason, sizeof(ptarm_buf_t));        //shallow copy
        memcpy(&p_bwd_fail->shared_secret, p_fail_ss, sizeof(ptarm_buf_t));    //shallow copy
        p_bwd_fail->prev_short_channel_id = 0;
        p_bwd_fail->b_first = true;
        LOGD("  --> fail_htlc(id=%" PRIu64 ")\n", p_bwd_fail->id);
        lnapp_transfer_channel(p_conf, TRANSCMD_FAIL, &buf);
        ptarm_buf_free(&p_revack->buf);     //もう使用しないため解放
    }

    LIST_REMOVE(p_revack, list);
    //ptarm_buf_free(&p_revack->buf);   //rcvidleに引き渡されたので解放しない
    APP_FREE(p_revack);

    pthread_mutex_unlock(&p_conf->mux_revack);
}


/** revoke_and_ack後キューの全削除
 *
 */
static void revack_clear(lnapp_conf_t *p_conf)
{
    transferlist_t *p = LIST_FIRST(&p_conf->revack_head);
    while (p != NULL) {
        transferlist_t *tmp = LIST_NEXT(p, list);
        LIST_REMOVE(p, list);
        ptarm_buf_free(&p->buf);
        APP_FREE(p);
        p = tmp;
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
static void rcvidle_push(lnapp_conf_t *p_conf, trans_cmd_t Cmd, ptarm_buf_t *pBuf)
{
    pthread_mutex_lock(&p_conf->mux_rcvidle);

    transferlist_t *p_rcvidle = (transferlist_t *)APP_MALLOC(sizeof(transferlist_t));       //APP_FREE: revack_pop_and_exec()

    p_rcvidle->cmd = Cmd;
    memcpy(&p_rcvidle->buf, pBuf, sizeof(ptarm_buf_t));
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

    struct transferlist_t *p_rcvidle = LIST_FIRST(&p_conf->rcvidle_head);
    if (p_rcvidle == NULL) {
        //empty
        pthread_mutex_unlock(&p_conf->mux_rcvidle);
        return;
    }

    bool ret = false;

    switch (p_rcvidle->cmd) {
    case TRANSCMD_ADDHTLC:
        //update_add_htlc送信
        LOGD("TRANSCMD_ADDHTLC\n");
        {
            fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)p_rcvidle->buf.buf;
            ptarm_buf_t reason = PTARM_BUF_INIT;
            ret = fwd_payment_forward(p_conf, p_fwd_add, &reason);
            if (ret) {
                //解放
                ptarm_buf_free(&p_fwd_add->shared_secret);
            } else {
                LOGD("fail forward\n");
                ptarm_buf_t buf;
                ptarm_buf_alloc(&buf, sizeof(bwd_proc_fail_t));
                bwd_proc_fail_t *p_bwd_fail = (bwd_proc_fail_t *)buf.buf;

                p_bwd_fail->id = p_fwd_add->prev_id;
                p_bwd_fail->prev_short_channel_id = p_fwd_add->prev_short_channel_id;
                memcpy(&p_bwd_fail->reason, &reason, sizeof(ptarm_buf_t));                //shallow copy
                memcpy(&p_bwd_fail->shared_secret, &p_fwd_add->shared_secret, sizeof(ptarm_buf_t));  //shallow copy
                p_bwd_fail->b_first = true;
                ret = ptarmd_transfer_channel(p_fwd_add->prev_short_channel_id, TRANSCMD_FAIL, &buf);
            }
        }
        break;
    case TRANSCMD_FULFILL:
        //update_fulfill_htlc送信
        LOGD("TRANSCMD_FULFILL\n");
        {
            bwd_proc_fulfill_t *p_bwd_fulfill = (bwd_proc_fulfill_t *)p_rcvidle->buf.buf;
            ret = fwd_fulfill_backwind(p_conf, p_bwd_fulfill);
        }
        break;
    case TRANSCMD_FAIL:
        //update_fail_htlc送信
        LOGD("TRANSCMD_FAIL\n");
        {
            bwd_proc_fail_t *p_bwd_fail = (bwd_proc_fail_t *)p_rcvidle->buf.buf;
            ret = fwd_fail_backwind(p_conf, p_bwd_fail);
            if (ret) {
                //解放
                ptarm_buf_free(&p_bwd_fail->reason);
                ptarm_buf_free(&p_bwd_fail->shared_secret);
            }
        }
        break;
    case TRANSCMD_ANNOSIGNS:
        {
            ptarm_buf_t buf_bolt = PTARM_BUF_INIT;

            LOGD("TRANSCMD_ANNOSIGNS\n");
            ret = ln_create_announce_signs(p_conf->p_self, &buf_bolt);
            if (ret) {
                send_peer_noise(p_conf, &buf_bolt);
                ptarm_buf_free(&buf_bolt);
            } else {
                LOGD("fail: create announcement_signatures\n");
                stop_threads(p_conf);
            }
        }
        break;
    default:
        break;
    }
    if (ret) {
        //解放
        LIST_REMOVE(p_rcvidle, list);
        ptarm_buf_free(&p_rcvidle->buf);       //APP_MALLOC: change_context()
        APP_FREE(p_rcvidle);            //APP_MALLOC: rcvidle_push
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
    transferlist_t *p = LIST_FIRST(&p_conf->rcvidle_head);
    while (p != NULL) {
        transferlist_t *tmp = LIST_NEXT(p, list);
        LIST_REMOVE(p, list);
        ptarm_buf_free(&p->buf);
        APP_FREE(p);
        p = tmp;
    }
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
    routelist_t *rt = (routelist_t *)APP_MALLOC(sizeof(routelist_t));       //APP_FREE: payroute_del()

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
        APP_FREE(p);
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
        APP_FREE(p);
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
static void send_queue_push(lnapp_conf_t *p_conf, const ptarm_buf_t *pBuf)
{
    //add queue before noise encoded data
    size_t len = p_conf->buf_sendque.len / sizeof(ptarm_buf_t);
    ptarm_buf_realloc(&p_conf->buf_sendque, sizeof(ptarm_buf_t) * (len + 1));
    memcpy(p_conf->buf_sendque.buf + sizeof(ptarm_buf_t) * len, pBuf->buf, pBuf->len);
}


static void send_queue_flush(lnapp_conf_t *p_conf)
{
    if (p_conf->buf_sendque.len == 0) {
        return;
    }

    size_t len = p_conf->buf_sendque.len / sizeof(ptarm_buf_t);
    for (size_t lp = 0; lp < len; lp++) {
        uint8_t *p = p_conf->buf_sendque.buf + sizeof(ptarm_buf_t) * lp;
        send_peer_noise(p_conf, (ptarm_buf_t *)p);
        ptarm_buf_free((ptarm_buf_t *)p);
    }
    ptarm_buf_free(&p_conf->buf_sendque);
}


static void send_queue_clear(lnapp_conf_t *p_conf)
{
    if (p_conf->buf_sendque.len == 0) {
        return;
    }

    size_t len = p_conf->buf_sendque.len / sizeof(ptarm_buf_t);
    for (size_t lp = 0; lp < len; lp++) {
        uint8_t *p = p_conf->buf_sendque.buf + sizeof(ptarm_buf_t) * lp;
        ptarm_buf_free((ptarm_buf_t *)p);
    }
    ptarm_buf_free(&p_conf->buf_sendque);
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
    uint8_t txid[PTARM_SZ_TXID];

    ln_get_short_channel_id_param(&bheight, &bindex, &vindex, ShortChannelId);
    ret = btcrpc_gettxid_from_short_channel(txid, bheight, bindex);
    if (ret) {
        ret = btcrpc_check_unspent(&unspent, NULL, txid, vindex);
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
        LOGD("short_channel_id: %0" PRIx64 "\n", ln_short_channel_id(self));
        LOGD("our_msat:   %" PRIu64 "\n", ln_our_msat(self));
        LOGD("their_msat: %" PRIu64 "\n", ln_their_msat(self));
        LOGD("HTLC num: %" PRIu16 "\n", ln_htlc_num(self));
        for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
            const ln_update_add_htlc_t *p_add = &self->cnl_add_htlc[lp];
            if (p_add->amount_msat > 0) {
                LOGD("  HTLC[%d]\n", lp);
                LOGD("    flag= %02x\n", p_add->flag);
                LOGD("      id= %" PRIx64 "\n", p_add->id);
                LOGD("    amount_msat= %" PRIu64 "\n", p_add->amount_msat);
                if (p_add->prev_short_channel_id) {
                    LOGD("    from:        %" PRIx64 ": %" PRIu64 "\n", p_add->prev_short_channel_id, p_add->prev_id);
                }
            }
        }

        //コンソールログ
        fprintf(fp, "=%s:%d==================\n", msg, line);
        fprintf(fp, "short_channel_id: %0" PRIx64 "\n", ln_short_channel_id(self));
        fprintf(fp, "our_msat:   %" PRIu64 "\n", ln_our_msat(self));
        fprintf(fp, "their_msat: %" PRIu64 "\n", ln_their_msat(self));
        fprintf(fp, "HTLC num: %" PRIu16 "\n\n\n", ln_htlc_num(self));
    } else {
        LOGD("no channel\n");
    }
    LOGD("=(%s:%d)=============================================\n", msg, line);
}
