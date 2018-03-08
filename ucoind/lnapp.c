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
#include <assert.h>

#define USE_LINUX_LIST
#ifdef USE_LINUX_LIST
#include <sys/queue.h>
#endif  //USE_LINUX_LIST

#include "cJSON.h"

#include "ucoind.h"
#include "cmd_json.h"
#include "lnapp.h"
#include "conf.h"
#include "btcrpc.h"
#include "ln_db.h"

#include "monitoring.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_WAIT_MUTEX_SEC        (1)         //mMuxSeqのロック解除待ち間隔[sec]
#define M_WAIT_POLL_SEC         (10)        //監視スレッドの待ち間隔[sec]
#define M_WAIT_PING_SEC         (60)        //ping送信待ち[sec](pingは30秒以上の間隔をあけること)
#define M_WAIT_ANNO_SEC         (1)         //監視スレッドでのannounce処理間隔[sec]
#define M_WAIT_MUTEX_MSEC       (100)       //mMuxSeqのロック解除待ち間隔[msec]
#define M_WAIT_RECV_MULTI_MSEC  (1000)      //複数パケット受信した時の処理間隔[msec]
#define M_WAIT_RECV_TO_MSEC     (100)       //socket受信待ちタイムアウト[msec]
#define M_WAIT_SEND_WAIT_MSEC   (10)        //socket送信で一度に送信できなかった場合の待ち時間[msec]

//デフォルト値
//  announcement
#define M_CLTV_EXPIRY_DELTA             (36)
#define M_HTLC_MINIMUM_MSAT_ANNO        (0)
#define M_FEE_BASE_MSAT                 (10)
#define M_FEE_PROP_MILLIONTHS           (100)

//  establish
#define M_DUST_LIMIT_SAT                (546)
#define M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT (INT64_MAX)
#define M_CHANNEL_RESERVE_SAT           (700)
#define M_HTLC_MINIMUM_MSAT_EST         (0)
#define M_TO_SELF_DELAY                 (40)
#define M_MAX_ACCEPTED_HTLCS            (LN_HTLC_MAX)
#define M_MIN_DEPTH                     (1)

#define M_ANNOSIGS_CONFIRM      (6)         ///< announcement_signaturesを送信するconfirmation
                                            //      BOLT仕様は6

//lnapp_conf_t.flag_ope
#define OPE_COMSIG_SEND         (0x01)      ///< commitment_signed受信済み

//lnapp_conf_t.flag_recv
#define RECV_MSG_INIT           (0x01)      ///< init
#define RECV_MSG_REESTABLISH    (0x02)      ///< channel_reestablish
#define RECV_MSG_END            (0x80)      ///< 初期化完了

#define M_SCRIPT_DIR            "./script/"

#define M_ANNO_UNIT             (3)         ///< 1回のsend_channel_anno()/send_node_anno()で送信する数


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    uint64_t    id;
    uint8_t     preimage[LN_SZ_PREIMAGE];
} fwd_proc_fulfill_t;


typedef struct {
    uint64_t    id;
    ucoin_buf_t reason;
    ucoin_buf_t shared_secret;
    bool        b_first;            ///< fail発生元
} fwd_proc_fail_t;


typedef struct queue_fulfill_t {
    enum {
        QTYPE_FWD_ADD_HTLC,             ///< add_htlcの転送
        QTYPE_BWD_FULFILL_HTLC,         ///< fulfill_htlcの転送
        QTYPE_BWD_FAIL_HTLC,            ///< fail_htlcの転送
        QTYPE_PAY_RETRY                 ///< 支払いのリトライ
    }               type;
    uint64_t        id;                     ///< add_htlc: short_channel_id
                                            ///< fulfill_htlc, fail_htlc: HTLC id
    ucoin_buf_t     buf;
    struct queue_fulfill_t  *p_next;
} queue_fulfill_t;


//event
typedef enum {
    M_EVT_ERROR,
    M_EVT_CONNECTED,
    M_EVT_ESTABLISHED,
    M_EVT_PAYMENT,
    M_EVT_FORWARD,
    M_EVT_FULFILL,
    M_EVT_FAIL,
    M_EVT_HTLCCHANGED,
    M_EVT_CLOSED
} event_t;


/********************************************************************
 * static variables
 ********************************************************************/

static volatile bool        mLoop;          //true:チャネル有効

static ln_node_t            *mpNode;
static ln_anno_prm_t        mAnnoPrm;       ///< announcementパラメータ

//シーケンスのmutex
static pthread_mutexattr_t  mMuxAttr;
static pthread_mutex_t      mMuxSeq;
static volatile enum {
    MUX_NONE,
    MUX_PAYMENT=0x01,               ///< 送金開始
    MUX_CHG_HTLC=0x02,              ///< HTLC変更中
    MUX_COMSIG=0x04,                ///< Commitment Signed処理中
} mMuxTiming;


static const char *M_SCRIPT[] = {
    //M_EVT_ERROR
    M_SCRIPT_DIR "error.sh",
    //M_EVT_CONNECTED
    M_SCRIPT_DIR "connected.sh",
    //M_EVT_ESTABLISHED
    M_SCRIPT_DIR "established.sh",
    //M_EVT_PAYMENT,
    M_SCRIPT_DIR "payment.sh",
    //M_EVT_FORWARD,
    M_SCRIPT_DIR "forward.sh",
    //M_EVT_FULFILL,
    M_SCRIPT_DIR "fulfill.sh",
    //M_EVT_FAIL,
    M_SCRIPT_DIR "fail.sh",
    //M_EVT_HTLCCHANGED,
    M_SCRIPT_DIR "htlcchanged.sh",
    //M_EVT_CLOSED
    M_SCRIPT_DIR "closed.sh"
};


/********************************************************************
 * prototypes
 ********************************************************************/

static void *thread_main_start(void *pArg);
static bool noise_handshake(lnapp_conf_t *p_conf);
static bool send_reestablish(lnapp_conf_t *p_conf);
static bool send_open_channel(lnapp_conf_t *p_conf, const funding_conf_t *pFunding);

static void *thread_recv_start(void *pArg);
static void recv_node_proc(lnapp_conf_t *p_conf);
static uint16_t recv_peer(lnapp_conf_t *p_conf, uint8_t *pBuf, uint16_t Len);

static void *thread_poll_start(void *pArg);
static void poll_ping(lnapp_conf_t *p_conf);
static void poll_funding_wait(lnapp_conf_t *p_conf);
static void poll_normal_operating(lnapp_conf_t *p_conf);

static void *thread_anno_start(void *pArg);

static bool set_request_recvproc(lnapp_conf_t *p_conf, recv_proc_t cmd, uint16_t Len, void *pData);

static bool fwd_payment_forward(lnapp_conf_t *p_conf, fwd_proc_add_t *p_fwd_add);
static bool fwd_fulfill_backward(lnapp_conf_t *p_conf, fwd_proc_fulfill_t *p_fwd_fulfill);
static bool fwd_fail_backward(lnapp_conf_t *p_conf, fwd_proc_fail_t *p_fwd_fail);

static void notify_cb(ln_self_t *self, ln_cb_t reason, void *p_param);
static void cb_error_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_init_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_channel_reestablish_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_find_index_wif_req(lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_tx_wait(lnapp_conf_t *p_conf, void *p_param);
static void cb_established(lnapp_conf_t *p_conf, void *p_param);
static void cb_channel_anno_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_node_anno_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_short_channel_id_upd(lnapp_conf_t *p_conf, void *p_param);
static void cb_anno_signsed(lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv_prev(lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_fulfill_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_fail_htlc_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_commit_sig_recv_prev(lnapp_conf_t *p_conf, void *p_param);
static void cb_commit_sig_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_htlc_changed(lnapp_conf_t *p_conf, void *p_param);
static void cb_shutdown_recv(lnapp_conf_t *p_conf, void *p_param);
static void cb_closed_fee(lnapp_conf_t *p_conf, void *p_param);
static void cb_closed(lnapp_conf_t *p_conf, void *p_param);
static void cb_send_req(lnapp_conf_t *p_conf, void *p_param);

static void stop_threads(lnapp_conf_t *p_conf);
static void send_peer_raw(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf);
static void send_peer_noise(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf);
static void send_channel_anno(lnapp_conf_t *p_conf);
static void send_node_anno(lnapp_conf_t *p_conf);

static void set_establish_default(lnapp_conf_t *p_conf, const uint8_t *pNodeId);
static void set_changeaddr(ln_self_t *self, uint64_t commit_fee);
static void wait_mutex_lock(uint8_t Flag);
static void wait_mutex_unlock(uint8_t Flag);
static void push_queue(lnapp_conf_t *p_conf, queue_fulfill_t *pFulfill);
static queue_fulfill_t *pop_queue(lnapp_conf_t *p_conf);
static void call_script(event_t event, const char *param);
static void set_onionerr_str(char *pStr, const ucoin_buf_t *pBuf);
static void set_lasterror(lnapp_conf_t *p_conf, int Err, const char *pErrStr);
static void show_self_param(const ln_self_t *self, FILE *fp, int line);

static void add_routelist(lnapp_conf_t *p_conf, const payment_conf_t *pPayConf, uint64_t HtlcId);
static const payment_conf_t* get_routelist(lnapp_conf_t *p_conf, uint64_t HtlcId);
static void del_routelist(lnapp_conf_t *p_conf, uint64_t HtlcId);
#ifdef USE_LINUX_LIST
static void print_routelist(lnapp_conf_t *p_conf);
static void clear_routelist(lnapp_conf_t *p_conf);
#endif
static void push_pay_retry_queue(lnapp_conf_t *p_conf, const uint8_t *pPayHash);
static void pay_retry(const uint8_t *pPayHash);


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_init(ln_node_t *pNode)
{
    mpNode = pNode;

    pthread_mutexattr_init(&mMuxAttr);
    pthread_mutexattr_settype(&mMuxAttr, PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&mMuxSeq, &mMuxAttr);
    mMuxTiming = MUX_NONE;
}


void lnapp_start(lnapp_conf_t *pAppConf)
{
    pthread_create(&pAppConf->th, NULL, &thread_main_start, pAppConf);
}


void lnapp_stop(lnapp_conf_t *pAppConf)
{
    pAppConf->loop = false;
}


bool lnapp_funding(lnapp_conf_t *pAppConf, const funding_conf_t *pFunding)
{
    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    DBG_PRINTF("Establish開始\n");
    send_open_channel(pAppConf, pFunding);

    return true;
}


//初回ONIONパケット作成
bool lnapp_payment(lnapp_conf_t *pAppConf, payment_conf_t *pPay)
{
    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    pthread_mutex_lock(&pAppConf->mux_proc);
    pthread_mutex_lock(&mMuxSeq);
    if (mMuxTiming) {
        SYSLOG_ERR("%s(): now paying...[%x]", __func__, mMuxTiming);
        pthread_mutex_unlock(&mMuxSeq);
        pthread_mutex_unlock(&pAppConf->mux_proc);
        return false;
    }
    mMuxTiming |= MUX_PAYMENT | MUX_CHG_HTLC;
    pthread_mutex_unlock(&mMuxSeq);

    DBGTRACE_BEGIN

    bool ret = false;
    bool retry = false;
    ucoin_buf_t buf_bolt;
    uint8_t session_key[UCOIN_SZ_PRIVKEY];
    ln_self_t *p_self = pAppConf->p_self;

    ucoin_buf_init(&buf_bolt);
    if (pPay->hop_datain[0].short_channel_id != ln_short_channel_id(p_self)) {
        SYSLOG_ERR("%s(): short_channel_id mismatch", __func__);
        fprintf(PRINTOUT, "fail: short_channel_id mismatch\n");
        fprintf(PRINTOUT, "    hop  : %" PRIx64 "\n", pPay->hop_datain[0].short_channel_id);
        fprintf(PRINTOUT, "    mine : %" PRIx64 "\n", ln_short_channel_id(p_self));
        ln_db_annoskip_save(pPay->hop_datain[0].short_channel_id);
        retry = true;
        goto LABEL_EXIT;
    }

    //amount, CLTVチェック(最後の値はチェックしない)
    for (int lp = 1; lp < pPay->hop_num - 1; lp++) {
        if (pPay->hop_datain[lp - 1].amt_to_forward < pPay->hop_datain[lp].amt_to_forward) {
            SYSLOG_ERR("%s(): [%d]amt_to_forward larger than previous (%" PRIu64 " < %" PRIu64 ")",
                    __func__, lp,
                    pPay->hop_datain[lp - 1].amt_to_forward,
                    pPay->hop_datain[lp].amt_to_forward);
            goto LABEL_EXIT;
        }
        if (pPay->hop_datain[lp - 1].outgoing_cltv_value <= pPay->hop_datain[lp].outgoing_cltv_value) {
            SYSLOG_ERR("%s(): [%d]outgoing_cltv_value larger than previous (%" PRIu32 " < %" PRIu32 ")",
                    __func__, lp,
                    pPay->hop_datain[lp - 1].outgoing_cltv_value,
                    pPay->hop_datain[lp].outgoing_cltv_value);
            goto LABEL_EXIT;
        }
    }

    ucoin_util_random(session_key, sizeof(session_key));
    //hop_datain[0]にこのchannel情報を置いているので、ONIONにするのは次から
    uint8_t onion[LN_SZ_ONION_ROUTE];
    ucoin_buf_t secrets;
    ret = ln_onion_create_packet(onion, &secrets, &pPay->hop_datain[1], pPay->hop_num - 1,
                        session_key, pPay->payment_hash, LN_SZ_HASH);
    assert(ret);

    show_self_param(p_self, PRINTOUT, __LINE__);

    uint64_t htlc_id;
    ret = ln_create_add_htlc(p_self,
                        &buf_bolt,
                        &htlc_id,
                        onion,
                        pPay->hop_datain[0].amt_to_forward,
                        pPay->hop_datain[0].outgoing_cltv_value,
                        pPay->payment_hash,
                        0,
                        0,
                        &secrets);  //secretsはln.cで管理するので、ここでは解放しない
    if (ret) {
        add_routelist(pAppConf, pPay, htlc_id);
    } else {
        goto LABEL_EXIT;
    }
    send_peer_noise(pAppConf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //add送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_self, &buf_bolt);
    if (!ret) {
        goto LABEL_EXIT;
    }
    send_peer_noise(pAppConf, &buf_bolt);
    pAppConf->flag_ope |= OPE_COMSIG_SEND;

LABEL_EXIT:
    ucoin_buf_free(&buf_bolt);
    if (ret) {
        show_self_param(p_self, PRINTOUT, __LINE__);

        // method: payment
        // $1: short_channel_id
        // $2: node_id
        // $3: amt_to_forward
        // $4: outgoing_cltv_value
        // $5: payment_hash
        char hashstr[LN_SZ_HASH * 2 + 1];
        misc_bin2str(hashstr, pPay->payment_hash, LN_SZ_HASH);
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
        misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s "
                    "%" PRIu64 " "
                    "%" PRIu32 " "
                    "%s",
                    ln_short_channel_id(pAppConf->p_self), node_id,
                    pPay->hop_datain[0].amt_to_forward,
                    pPay->hop_datain[0].outgoing_cltv_value,
                    hashstr);
        call_script(M_EVT_PAYMENT, param);
    } else {
        DBG_PRINTF("fail\n");
        if (retry) {
            pay_retry(pPay->payment_hash);
        }
        mMuxTiming = 0;
    }

    DBG_PRINTF("mux_proc: end\n");
    pthread_mutex_unlock(&pAppConf->mux_proc);
    DBGTRACE_END

    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);
    return ret;
}


//受信スレッド経由で関数呼び出しされる
bool lnapp_forward_payment(lnapp_conf_t *pAppConf, fwd_proc_add_t *pAdd)
{
    DBGTRACE_BEGIN

    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    //pAddは自動で解放されるためコピーする
    fwd_proc_add_t *p_add = (fwd_proc_add_t *)APP_MALLOC(sizeof(fwd_proc_add_t));       //APP_FREE: recv_node_proc()
    memcpy(p_add, pAdd, sizeof(fwd_proc_add_t));

    //DBG_PRINTF("------------------------------: %p\n", p_add);
    //DBG_PRINTF("fwd_proc_add_t.amt_to_forward= %" PRIu64 "\n", p_add->amt_to_forward);
    //DBG_PRINTF("fwd_proc_add_t.outgoing_cltv_value= %d\n", (int)p_add->outgoing_cltv_value);
    //DBG_PRINTF("fwd_proc_add_t.next_short_channel_id= %" PRIx64 "\n", p_add->next_short_channel_id);       //next
    //DBG_PRINTF("fwd_proc_add_t.prev_short_channel_id= %" PRIx64 "\n", p_add->prev_short_channel_id);       //next
    //DBG_PRINTF("short_channel_id= %" PRIx64 "\n", ln_short_channel_id(pAppConf->p_self));       //next
    //DBG_PRINTF("------------------------------\n");

    //処理は、thread_recv_start()のスレッドで行う(コンテキスト切り替えのため)
    return set_request_recvproc(pAppConf, FWD_PROC_ADD, (uint16_t)sizeof(fwd_proc_add_t), p_add);
}


//受信スレッド経由で関数呼び出しされる
bool lnapp_backward_fulfill(lnapp_conf_t *pAppConf, const ln_cb_fulfill_htlc_recv_t *pFulFill)
{
    DBGTRACE_BEGIN

    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    fwd_proc_fulfill_t *p_fwd_fulfill = (fwd_proc_fulfill_t *)APP_MALLOC(sizeof(fwd_proc_fulfill_t));   //APP_FREE: fwd_fulfill_backward()
    p_fwd_fulfill->id = pFulFill->id;
    memcpy(p_fwd_fulfill->preimage, pFulFill->p_preimage, LN_SZ_PREIMAGE);

    return set_request_recvproc(pAppConf, FWD_PROC_FULFILL, (uint16_t)sizeof(fwd_proc_fulfill_t), p_fwd_fulfill);
}


bool lnapp_backward_fail(lnapp_conf_t *pAppConf, const ln_cb_fail_htlc_recv_t *pFail, bool bFirst)
{
    DBGTRACE_BEGIN

    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    DBG_PRINTF("reason= ");
    DUMPBIN(pFail->p_reason->buf, pFail->p_reason->len);
    DBG_PRINTF("shared secret= ");
    DUMPBIN(pFail->p_shared_secret->buf, pFail->p_shared_secret->len);
    DBG_PRINTF("first= %s\n", (bFirst) ? "true" : "false");

    fwd_proc_fail_t *p_fwd_fail = (fwd_proc_fail_t *)APP_MALLOC(sizeof(fwd_proc_fail_t));   //APP_FREE: fwd_fail_backward()
    p_fwd_fail->id = pFail->prev_id;
    ucoin_buf_alloccopy(&p_fwd_fail->reason, pFail->p_reason->buf, pFail->p_reason->len);
    ucoin_buf_alloccopy(&p_fwd_fail->shared_secret,     //APP_FREE:fwd_fail_backward()
                            pFail->p_shared_secret->buf, pFail->p_shared_secret->len);
    p_fwd_fail->b_first = bFirst;

    return set_request_recvproc(pAppConf, FWD_PROC_FAIL, (uint16_t)sizeof(fwd_proc_fail_t), p_fwd_fail);
}


bool lnapp_close_channel(lnapp_conf_t *pAppConf)
{
    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    DBG_PRINTF("mux_proc: prev\n");
    pthread_mutex_lock(&pAppConf->mux_proc);
    DBG_PRINTF("mux_proc: after\n");

    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ln_self_t *p_self = pAppConf->p_self;

    //feeと送金先
    cb_shutdown_recv(pAppConf, NULL);

    show_self_param(p_self, PRINTOUT, __LINE__);

    ucoin_buf_init(&buf_bolt);
    ret = ln_create_shutdown(p_self, &buf_bolt);
    if (ret) {
        send_peer_noise(pAppConf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);

        if (ret) {
            show_self_param(p_self, PRINTOUT, __LINE__);
        }
    }

    DBG_PRINTF("mux_proc: end\n");
    pthread_mutex_unlock(&pAppConf->mux_proc);
    DBGTRACE_END

    return ret;
}


bool lnapp_close_channel_force(const uint8_t *pNodeId)
{
    bool ret;
    ln_self_t my_self;

    memset(&my_self, 0, sizeof(my_self));

    //announcementデフォルト値
    anno_conf_t aconf;
    ret = load_anno_conf("anno.conf", &aconf);
    if (ret) {
        mAnnoPrm.cltv_expiry_delta = aconf.cltv_expiry_delta;
        mAnnoPrm.htlc_minimum_msat = aconf.htlc_minimum_msat;
        mAnnoPrm.fee_base_msat = aconf.fee_base_msat;
        mAnnoPrm.fee_prop_millionths = aconf.fee_prop_millionths;
    } else {
        mAnnoPrm.cltv_expiry_delta = M_CLTV_EXPIRY_DELTA;
        mAnnoPrm.htlc_minimum_msat = M_HTLC_MINIMUM_MSAT_ANNO;
        mAnnoPrm.fee_base_msat = M_FEE_BASE_MSAT;
        mAnnoPrm.fee_prop_millionths = M_FEE_PROP_MILLIONTHS;
    }
    ln_init(&my_self, mpNode, NULL, &mAnnoPrm, NULL);

    ret = ln_node_search_channel(&my_self, pNodeId);
    if (!ret) {
        return false;
    }

    SYSLOG_WARN("close: bad way(local): htlc=%d\n", ln_commit_local(&my_self)->htlc_num);
    (void)monitor_close_unilateral_local(&my_self, NULL);

    return true;
}


bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id)
{
    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    return (short_channel_id == ln_short_channel_id(pAppConf->p_self));
}


void lnapp_show_self(const lnapp_conf_t *pAppConf, cJSON *pResult)
{
    if ((!pAppConf->loop) || (pAppConf->sock < 0)) {
        return;
    }

    ln_self_t *p_self = pAppConf->p_self;

    cJSON *result = cJSON_CreateObject();

    if (p_self && ln_short_channel_id(p_self)) {
        //show_self_param(p_self, PRINTOUT, __LINE__);

        char str[256];

        const char *p_status;
        if (p_self->fund_flag & LN_FUNDFLAG_CLOSE) {
            p_status = "closing";
        } else {
            p_status = "established";
        }
        cJSON_AddItemToObject(result, "status", cJSON_CreateString(p_status));

        //peer node_id
        misc_bin2str(str, p_self->peer_node_id, UCOIN_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //channel_id
        misc_bin2str(str, ln_channel_id(pAppConf->p_self), LN_SZ_CHANNEL_ID);
        cJSON_AddItemToObject(result, "channel_id", cJSON_CreateString(str));
        //short_channel_id
        sprintf(str, "%016" PRIx64, ln_short_channel_id(p_self));
        cJSON_AddItemToObject(result, "short_channel_id", cJSON_CreateString(str));
        //funding_tx
        misc_bin2str_rev(str, ln_funding_txid(pAppConf->p_self), UCOIN_SZ_TXID);
        cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
        cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_txindex(pAppConf->p_self)));
        //confirmation
        uint32_t confirm = btcprc_get_confirmation(ln_funding_txid(pAppConf->p_self));
        cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
        //our_msat
        cJSON_AddItemToObject(result, "our_msat", cJSON_CreateNumber64(ln_our_msat(p_self)));
        //their_msat
        cJSON_AddItemToObject(result, "their_msat", cJSON_CreateNumber64(ln_their_msat(p_self)));
        //feerate_per_kw
        cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate(pAppConf->p_self)));
        //htlc
        cJSON_AddItemToObject(result, "htlc_num", cJSON_CreateNumber(ln_htlc_num(pAppConf->p_self)));
    } else if (pAppConf->funding_waiting) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("wait_minimum_depth"));

        //peer node_id
        misc_bin2str(str, p_self->peer_node_id, UCOIN_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //funding_tx
        misc_bin2str_rev(str, ln_funding_txid(pAppConf->p_self), UCOIN_SZ_TXID);
        cJSON_AddItemToObject(result, "funding_tx", cJSON_CreateString(str));
        cJSON_AddItemToObject(result, "funding_vout", cJSON_CreateNumber(ln_funding_txindex(pAppConf->p_self)));
        //confirmation
        uint32_t confirm = btcprc_get_confirmation(ln_funding_txid(pAppConf->p_self));
        cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
        //minimum_depth
        cJSON_AddItemToObject(result, "minimum_depth", cJSON_CreateNumber(pAppConf->funding_min_depth));
        //feerate_per_kw
        cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber(ln_feerate(pAppConf->p_self)));
    } else if (p_self && ln_is_funding(p_self)) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("fund_waiting"));

        //peer node_id
        misc_bin2str(str, pAppConf->node_id, UCOIN_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
    } else if (ucoin_keys_chkpub(pAppConf->node_id)) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("connected"));

        //peer node_id
        misc_bin2str(str, pAppConf->node_id, UCOIN_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
    } else {
        cJSON_AddItemToObject(result, "status", cJSON_CreateString("disconnected"));
    }
    if ((pAppConf->err != 0) && (pAppConf->p_errstr != NULL)) {
        cJSON_AddItemToObject(result, "last_errmsg", cJSON_CreateString(pAppConf->p_errstr));
    }
    cJSON_AddItemToArray(pResult, result);
}


bool lnapp_get_committx(lnapp_conf_t *pAppConf, cJSON *pResult)
{
    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return false;
    }

    ln_close_force_t close_dat;
    bool ret = ln_create_close_force_tx(pAppConf->p_self, &close_dat);
    if (ret) {
        ucoin_buf_t buf;

        for (int lp = 0; lp < close_dat.num; lp++) {
            if (close_dat.p_tx[lp].vout_cnt > 0) {
                ucoin_tx_create(&buf, &close_dat.p_tx[lp]);
                char *transaction = (char *)APP_MALLOC(buf.len * 2 + 1);        //APP_FREE: この中
                misc_bin2str(transaction, buf.buf, buf.len);
                ucoin_buf_free(&buf);

                char title[10];
                if (lp == 0) {
                    strcpy(title, "committx");
                } else if (lp == 1) {
                    strcpy(title, "to_local");
                } else {
                    sprintf(title, "htlc%d", lp - 1);
                }
                cJSON_AddItemToObject(pResult, title, cJSON_CreateString(transaction));
                APP_FREE(transaction);
            }
        }

        int num = close_dat.tx_buf.len / sizeof(ucoin_tx_t);
        ucoin_tx_t *p_tx = (ucoin_tx_t *)close_dat.tx_buf.buf;
        for (int lp = 0; lp < num; lp++) {
            ucoin_tx_create(&buf, &p_tx[lp]);
            char *transaction = (char *)APP_MALLOC(buf.len * 2 + 1);    //APP_FREE: この中
            misc_bin2str(transaction, buf.buf, buf.len);
            ucoin_buf_free(&buf);

            cJSON_AddItemToObject(pResult, "htlc_out", cJSON_CreateString(transaction));
            APP_FREE(transaction);
        }

        ln_free_close_force_tx(&close_dat);
    }

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
    ln_self_t my_self;

    my_self.p_param = p_conf;

    anno_conf_t aconf;
    ret = load_anno_conf("anno.conf", &aconf);
    if (ret) {
        mAnnoPrm.cltv_expiry_delta = aconf.cltv_expiry_delta;
        mAnnoPrm.htlc_minimum_msat = aconf.htlc_minimum_msat;
        mAnnoPrm.fee_base_msat = aconf.fee_base_msat;
        mAnnoPrm.fee_prop_millionths = aconf.fee_prop_millionths;
    } else {
        mAnnoPrm.cltv_expiry_delta = M_CLTV_EXPIRY_DELTA;
        mAnnoPrm.htlc_minimum_msat = M_HTLC_MINIMUM_MSAT_ANNO;
        mAnnoPrm.fee_base_msat = M_FEE_BASE_MSAT;
        mAnnoPrm.fee_prop_millionths = M_FEE_PROP_MILLIONTHS;
    }

    //スレッド
    pthread_t   th_peer;        //peer受信
    pthread_t   th_poll;        //トランザクション監視

    //seed作成(後でDB読込により上書きされる可能性あり)
    uint8_t seed[LN_SZ_SEED];
    DBG_PRINTF("ln_self_t initialize");
    ucoin_util_random(seed, LN_SZ_SEED);
    ln_init(&my_self, mpNode, seed, &mAnnoPrm, notify_cb);

    p_conf->p_self = &my_self;
    p_conf->ping_counter = 0;
    p_conf->funding_waiting = false;
    p_conf->funding_confirm = 0;
    p_conf->fwd_proc_rpnt = 0;
    p_conf->fwd_proc_wpnt = 0;
    p_conf->flag_recv = 0;
    p_conf->last_anno_cnl = 0;
    p_conf->last_anno_node[0] = 0;      //pubkeyなので、0にはならない
    p_conf->err = 0;
    p_conf->p_errstr = NULL;
#ifdef USE_LINUX_LIST
    LIST_INIT(&p_conf->routing_head);
#else   //USE_LINUX_LIST
    p_conf->p_routing = NULL;
#endif  //USE_LINUX_LIST

    pthread_cond_init(&p_conf->cond, NULL);
    pthread_mutex_init(&p_conf->mux, NULL);
    pthread_mutex_init(&p_conf->mux_proc, NULL);
    pthread_mutex_init(&p_conf->mux_send, NULL);
    pthread_mutex_init(&p_conf->mux_fulque, NULL);

    p_conf->loop = true;

    //noise protocol handshake
    ret = noise_handshake(p_conf);
    if (!ret) {
        goto LABEL_SHUTDOWN;
    }

    DBG_PRINTF("connected peer: ");
    DUMPBIN(p_conf->node_id, UCOIN_SZ_PUBKEY);

    /////////////////////////
    // handshake完了
    //      server動作時、p_conf->node_idに相手node_idが入っている
    /////////////////////////

    //p_conf->node_idがchannel情報を持っているかどうか。
    //持っている場合、my_selfにDBから読み込みまで行われている。
    bool detect = ln_node_search_channel(&my_self, p_conf->node_id);

    //
    //my_selfへの設定はこれ以降に行う
    //

    //peer受信スレッド
    pthread_create(&th_peer, NULL, &thread_recv_start, p_conf);

    //監視スレッド
    pthread_create(&th_poll, NULL, &thread_poll_start, p_conf);

    //announceスレッド
    pthread_create(&th_poll, NULL, &thread_anno_start, p_conf);


    //init送受信
    {
        ucoin_buf_t buf_bolt;
        ucoin_buf_init(&buf_bolt);
        ret = ln_create_init(&my_self, &buf_bolt, detect);
        if (!ret) {
            goto LABEL_JOIN;
        }
        send_peer_noise(p_conf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    }

    //コールバックでのINIT受信通知待ち
    pthread_mutex_lock(&p_conf->mux);
    while (p_conf->loop && ((p_conf->flag_recv & RECV_MSG_INIT) == 0)) {
        //init受信待ち合わせ(*1)
        DBG_PRINTF("init wait...\n");
        pthread_cond_wait(&p_conf->cond, &p_conf->mux);
        DBG_PRINTF("init received\n");
    }
    pthread_mutex_unlock(&p_conf->mux);
    DBG_PRINTF("init交換完了\n\n");

    //送金先
    char payaddr[UCOIN_SZ_ADDR_MAX];
    btcprc_getnewaddress(payaddr);
    ln_set_shutdown_vout_addr(&my_self, payaddr);

    // Establishチェック
    if (detect) {
        //既にチャネルあり
        //my_selfの主要なデータはDBから読込まれている(copy_channel() : ln_node.c)
        if (ln_short_channel_id(&my_self) != 0) {
            DBG_PRINTF("Establish済み : %d\n", p_conf->cmd);
        } else {
            DBG_PRINTF("funding_tx監視開始\n");
            DUMPTXID(ln_funding_txid(&my_self));

            set_establish_default(p_conf, p_conf->node_id);
            p_conf->funding_min_depth = ln_minimum_depth(&my_self);
            p_conf->funding_waiting = true;
        }
        send_reestablish(p_conf);
        DBG_PRINTF("reestablish交換完了\n\n");
    } else {
        DBG_PRINTF("Establish待ち\n");
        set_establish_default(p_conf, p_conf->node_id);
    }

    //初期化完了
    DBG_PRINTF("\n\n*** message inited ***\n\n\n");
    p_conf->flag_recv |= RECV_MSG_END;

    // method: connected
    // $1: short_channel_id
    // $2: node_id
    // $3: peer_id
    // $4: JSON-RPC port
    char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
    misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
    char peer_id[UCOIN_SZ_PUBKEY * 2 + 1];
    misc_bin2str(peer_id, p_conf->node_id, UCOIN_SZ_PUBKEY);
    char param[256];
    sprintf(param, "%" PRIx64 " %s "
                "%s "
                "%" PRIu16,
                ln_short_channel_id(&my_self), node_id,
                peer_id,
                cmd_json_get_port());
    call_script(M_EVT_CONNECTED, param);

    while (p_conf->loop) {
        DBG_PRINTF("loop...\n");
        show_self_param(&my_self, PRINTOUT, __LINE__);
        pthread_mutex_lock(&p_conf->mux);

        //待ち合わせ解除(*2)
        pthread_cond_wait(&p_conf->cond, &p_conf->mux);

        pthread_mutex_unlock(&p_conf->mux);
    }

LABEL_JOIN:
    stop_threads(p_conf);
    pthread_join(th_peer, NULL);
    pthread_join(th_poll, NULL);
    DBG_PRINTF("loop end\n");

LABEL_SHUTDOWN:
    retval = shutdown(p_conf->sock, SHUT_RDWR);
    if (retval < 0) {
        SYSLOG_ERR("%s(): shutdown: %s", __func__, strerror(errno));
    }

    SYSLOG_WARN("[exit]channel thread [%016" PRIx64 "]\n", ln_short_channel_id(&my_self));

    //クリア
    APP_FREE(p_conf->p_errstr);
    for (int lp = 0; lp < APP_FWD_PROC_MAX; lp++) {
        APP_FREE(p_conf->fwd_proc[lp].p_data);
    }
    ln_term(&my_self);
    clear_routelist(p_conf);
    memset(p_conf, 0, sizeof(lnapp_conf_t));
    p_conf->sock = -1;

    return NULL;
}


/** Noise Protocol Handshake(同期処理)
 *
 */
static bool noise_handshake(lnapp_conf_t *p_conf)
{
    bool ret;
    ucoin_buf_t buf;
    uint8_t rbuf[66];
    bool b_cont;

    ucoin_buf_init(&buf);

    // 今ひとつだが、同期でやってしまう
    if (p_conf->initiator) {
        //initiatorはnode_idを知っている

        //send: act one
        ret = ln_handshake_start(p_conf->p_self, &buf, p_conf->node_id);
        if (!ret) {
            DBG_PRINTF("fail: ln_handshake_start\n");
            goto LABEL_FAIL;
        }
        DBG_PRINTF("** SEND act one **\n");
        send_peer_raw(p_conf, &buf);

        //recv: act two
        DBG_PRINTF("** RECV act two... **\n");
        recv_peer(p_conf, rbuf, 50);
        DBG_PRINTF("** RECV act two ! **\n");
        ucoin_buf_free(&buf);
        ucoin_buf_alloccopy(&buf, rbuf, 50);
        ret = ln_handshake_recv(p_conf->p_self, &b_cont, &buf);
        if (!ret || b_cont) {
            DBG_PRINTF("fail: ln_handshake_recv1\n");
            goto LABEL_FAIL;
        }
        //send: act three
        DBG_PRINTF("** SEND act three **\n");
        send_peer_raw(p_conf, &buf);
        ucoin_buf_free(&buf);
   } else {
        //responderはnode_idを知らない

        //recv: act one
        ret = ln_handshake_start(p_conf->p_self, &buf, NULL);
        if (!ret) {
            DBG_PRINTF("fail: ln_handshake_start\n");
            goto LABEL_FAIL;
        }
        DBG_PRINTF("** RECV act one... **\n");
        recv_peer(p_conf, rbuf, 50);
        DBG_PRINTF("** RECV act one ! **\n");
        ucoin_buf_alloccopy(&buf, rbuf, 50);
        ret = ln_handshake_recv(p_conf->p_self, &b_cont, &buf);
        if (!ret || !b_cont) {
            DBG_PRINTF("fail: ln_handshake_recv1\n");
            goto LABEL_FAIL;
        }
        //send: act two
        DBG_PRINTF("** SEND act two **\n");
        send_peer_raw(p_conf, &buf);

        //recv: act three
        DBG_PRINTF("** RECV act three... **\n");
        recv_peer(p_conf, rbuf, 66);
        DBG_PRINTF("** RECV act three ! **\n");
        ucoin_buf_free(&buf);
        ucoin_buf_alloccopy(&buf, rbuf, 66);
        ret = ln_handshake_recv(p_conf->p_self, &b_cont, &buf);
        if (!ret || b_cont) {
            DBG_PRINTF("fail: ln_handshake_recv2\n");
            goto LABEL_FAIL;
        }

        //bufには相手のnode_idが返ってくる
        assert(buf.len == UCOIN_SZ_PUBKEY);
        memcpy(p_conf->node_id, buf.buf, UCOIN_SZ_PUBKEY);

        ucoin_buf_free(&buf);
    }

    DBG_PRINTF("noise handshaked\n");
    return true;

LABEL_FAIL:
    DBG_PRINTF("fail: noise handshaked\n");
    return false;
}


static bool send_reestablish(lnapp_conf_t *p_conf)
{
    //channel_reestablish送信
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    bool ret = ln_create_channel_reestablish(p_conf->p_self, &buf_bolt);
    assert(ret);

    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //コールバックでのchannel_reestablish受信通知待ち
    pthread_mutex_lock(&p_conf->mux);
    if (p_conf->loop && ((p_conf->flag_recv & RECV_MSG_REESTABLISH) == 0)) {
        //channel_reestablish受信待ち合わせ(*3)
        DBG_PRINTF("channel_reestablish wait...\n");
        pthread_cond_wait(&p_conf->cond, &p_conf->mux);
        DBG_PRINTF("channel_reestablish received\n");
    }
    pthread_mutex_unlock(&p_conf->mux);
    DBG_PRINTF("channel_reestablish交換完了\n\n");

    return ret;
}


/** open_channel送信
 *
 */
static bool send_open_channel(lnapp_conf_t *p_conf, const funding_conf_t *pFunding)
{
    //Establish開始
    DBG_PRINTF("  signaddr: %s\n", pFunding->signaddr);
    DBG_PRINTF("  funding_sat: %" PRIu64 "\n", pFunding->funding_sat);
    DBG_PRINTF("  push_sat: %" PRIu64 "\n", pFunding->push_sat);

    //open_channel
    char wif[UCOIN_SZ_WIF_MAX];
    char changeaddr[UCOIN_SZ_WSHADDR];
    uint64_t fundin_sat;

    bool ret = btcprc_dumpprivkey(wif, pFunding->signaddr);
    if (ret) {
        ret = btcprc_getnewaddress(changeaddr);
    } else {
        SYSLOG_ERR("%s(): btcprc_dumpprivkey", __func__);
    }
    assert(ret);

    bool unspent = true;
    if (ret) {
        ret = btcprc_getxout(&unspent, &fundin_sat, pFunding->txid, pFunding->txindex);
        DBG_PRINTF("ret=%d, unspent=%d\n", ret, unspent);
    } else {
        SYSLOG_ERR("%s(): btcprc_getnewaddress", __func__);
    }
    if (ret && unspent) {
        uint64_t feerate;
        if (pFunding->feerate_per_kw == 0) {
            //estimate fee
            bool ret = btcprc_estimatefee(&feerate, LN_BLK_FEEESTIMATE);
            //BOLT#2
            //  feerate_per_kw indicates the initial fee rate by 1000-weight
            //  (ie. 1/4 the more normally-used 'feerate per kilobyte')
            //  which this side will pay for commitment and HTLC transactions
            //  as described in BOLT #3 (this can be adjusted later with an update_fee message).
            feerate = (uint32_t)(feerate / 4);
            if (!ret) {
            // https://github.com/nayutaco/ptarmigan/issues/46
            DBG_PRINTF("fail: estimatefee\n");
            feerate = LN_FEERATE_PER_KW;
            }
        } else {
            feerate = pFunding->feerate_per_kw;
        }
        DBG_PRINTF2("feerate_per_kw=%" PRIu64 "\n", feerate);

        ln_fundin_t fundin;
        memcpy(fundin.txid, pFunding->txid, UCOIN_SZ_TXID);
        fundin.index = pFunding->txindex;
        fundin.amount = fundin_sat;
        fundin.p_change_pubkey = NULL;
        fundin.p_change_addr = strdup(changeaddr);      //下位層でfreeする
        ucoin_chain_t chain;
        ucoin_util_wif2keys(&fundin.keys, &chain, wif);
        assert(ucoin_get_chain() == chain);
        fundin.b_native = false;        //fundin_txの送金先アドレスのsegwit具合
                                        //  false: nested in BIP16
                                        //      bitcoind v0.15ではsegwitアドレスをaddwitnessaddressで行っている

        DBG_PRINTF("open_channel: fund_in amount=%" PRIu64 "\n", fundin_sat);
        ucoin_buf_t buf_bolt;
        ucoin_buf_init(&buf_bolt);
        ret = ln_create_open_channel(p_conf->p_self, &buf_bolt,
                        &fundin,
                        pFunding->funding_sat,
                        pFunding->push_sat,
                        (uint32_t)feerate);
        assert(ret);

        DBG_PRINTF("SEND: open_channel\n");
        send_peer_noise(p_conf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    } else {
        SYSLOG_WARN("fail through: btcprc_getxout");
        DUMPTXID(pFunding->txid);
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
    ucoin_buf_t buf_recv;
    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;

    while (p_conf->loop) {
        bool ret = true;

        //noise packet データ長
        uint8_t head[LN_SZ_NOISE_HEADER];
        uint16_t len = recv_peer(p_conf, head, LN_SZ_NOISE_HEADER);
        if (len == 0) {
            //peerから切断された
            DBG_PRINTF("DISC: loop end\n");
            stop_threads(p_conf);
            break;
        }
        assert(len == LN_SZ_NOISE_HEADER);
        if (len == LN_SZ_NOISE_HEADER) {
            len = ln_noise_dec_len(p_conf->p_self, head, len);
        } else {
            break;
        }

        ucoin_buf_alloc(&buf_recv, len);
        uint16_t len_msg = recv_peer(p_conf, buf_recv.buf, len);
        if (len_msg == 0) {
            //peerから切断された
            DBG_PRINTF("DISC: loop end\n");
            stop_threads(p_conf);
            break;
        }
        if (len_msg == len) {
            buf_recv.len = len;
            ret = ln_noise_dec_msg(p_conf->p_self, &buf_recv);
            if (!ret) {
                DBG_PRINTF("DECODE: loop end\n");
                stop_threads(p_conf);
            }

            //ping送信待ちカウンタ
            //p_conf->ping_counter = 0;
        } else {
            break;
        }

        if (ret) {
            //DBG_PRINTF("type=%02x%02x\n", buf_recv.buf[0], buf_recv.buf[1]);
            pthread_mutex_lock(&p_conf->mux_proc);
            ret = ln_recv(p_conf->p_self, buf_recv.buf, buf_recv.len);
            //DBG_PRINTF("ln_recv() result=%d\n", ret);
            if (!ret) {
                DBG_PRINTF("DISC: fail recv message\n");
                lnapp_close_channel_force(ln_their_node_id(p_conf->p_self));
                stop_threads(p_conf);
                break;
            }
            //DBG_PRINTF("mux_proc: end\n");
            pthread_mutex_unlock(&p_conf->mux_proc);
        }
        ucoin_buf_free(&buf_recv);
    }

    SYSLOG_WARN("[exit]recv thread\n");

    return NULL;
}


//ノードからの要求
//  他の処理も加わりそうなので、あとで名称変更する可能性あり
static void recv_node_proc(lnapp_conf_t *p_conf)
{
    bool ret = false;

    //DBG_PRINTF("[%d:%d]get p_data(%d)=", p_conf->fwd_proc_rpnt, p_conf->fwd_proc[p_conf->fwd_proc_rpnt].cmd, p_conf->fwd_proc[p_conf->fwd_proc_rpnt].len);
    //DUMPBIN((uint8_t *)p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data, p_conf->fwd_proc[p_conf->fwd_proc_rpnt].len);
    //DBG_PRINTF("p_conf->fwd_proc_rpnt=%d\n", p_conf->fwd_proc_rpnt);
    switch (p_conf->fwd_proc[p_conf->fwd_proc_rpnt].cmd) {
    case FWD_PROC_ADD:
        DBG_PRINTF("FWD_PROC_ADD\n");
        ret = fwd_payment_forward(p_conf, (fwd_proc_add_t *)p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);
        break;
    case FWD_PROC_FULFILL:
        DBG_PRINTF("FWD_PROC_FULFILL\n");
        ret = fwd_fulfill_backward(p_conf, (fwd_proc_fulfill_t *)p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);
        break;
    case FWD_PROC_FAIL:
        DBG_PRINTF("FWD_PROC_FAIL\n");
        ret = fwd_fail_backward(p_conf, (fwd_proc_fail_t *)p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);
        break;
    case INNER_SEND_ANNO_SIGNS:
        {
            ucoin_buf_t buf_bolt;

            DBG_PRINTF("INNER_SEND_ANNO_SIGNS\n");
            ucoin_buf_init(&buf_bolt);
            ret = ln_create_announce_signs(p_conf->p_self, &buf_bolt);
            if (ret) {
                send_peer_noise(p_conf, &buf_bolt);
                ucoin_buf_free(&buf_bolt);
            }
        }
        break;
    default:
        break;
    }
    if (ret) {
        //解放
        p_conf->fwd_proc[p_conf->fwd_proc_rpnt].cmd = FWD_PROC_NONE;
        APP_FREE(p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);       //APP_MALLOC: lnapp_forward_payment()
        p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data = NULL;
        p_conf->fwd_proc_rpnt = (p_conf->fwd_proc_rpnt + 1) % APP_FWD_PROC_MAX;
    }
}


/** 受信処理
 *
 */
static uint16_t recv_peer(lnapp_conf_t *p_conf, uint8_t *pBuf, uint16_t Len)
{
    ssize_t n = 0;
    struct pollfd fds;
    uint16_t len = 0;

    //DBG_PRINTF("sock=%d\n", p_conf->sock);

    while (p_conf->loop && (Len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLIN;
        int polr = poll(&fds, 1, M_WAIT_RECV_TO_MSEC);
        if (polr < 0) {
            SYSLOG_ERR("%s(): poll: %s", __func__, strerror(errno));
            break;
        } else if (polr == 0) {
            //timeout
            //  処理要求があれば受け付ける
            if (p_conf->fwd_proc_rpnt != p_conf->fwd_proc_wpnt) {
                recv_node_proc(p_conf);
            }
            //フラグを立てた処理を回収
            ln_flag_proc(p_conf->p_self);
        } else {
            if (fds.revents & POLLIN) {
                n = read(p_conf->sock, pBuf, Len);
                if (n == 0) {
                    SYSLOG_WARN("peer disconnected\n");
                    len = 0;
                    break;
                }
                Len -= n;
                len += n;
                pBuf += n;
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
        if (!p_conf->loop || (p_conf->p_self == NULL)) {
            break;
        }

        if ((p_conf->flag_recv & RECV_MSG_INIT) == 0) {
            //まだ接続していない
            continue;
        }

        poll_ping(p_conf);

        uint32_t bak_conf = p_conf->funding_confirm;
        p_conf->funding_confirm = btcprc_get_confirmation(ln_funding_txid(p_conf->p_self));
        if (bak_conf != p_conf->funding_confirm) {
            DBG_PRINTF2("\n***********************************\n");
            DBG_PRINTF2("* CONFIRMATION: %d\n", p_conf->funding_confirm);
            DBG_PRINTF2("*    funding_txid: ");
            DUMPTXID(ln_funding_txid(p_conf->p_self));
            DBG_PRINTF2("***********************************\n\n");
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
             (p_conf->funding_confirm >= M_ANNOSIGS_CONFIRM) &&
             (p_conf->funding_confirm >= p_conf->funding_min_depth) ) {
            // BOLT#7: announcement_signaturesは最低でも 6confirmations必要
            //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#requirements
            set_request_recvproc(p_conf, INNER_SEND_ANNO_SIGNS, 0, NULL);
            ln_open_announce_channel_clr(p_conf->p_self);
            ln_db_self_save(p_conf->p_self);
        }
    }

    SYSLOG_WARN("[exit]poll thread\n");

    return NULL;
}


static void poll_ping(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    //未送受信の状態が続いたらping送信する
    p_conf->ping_counter++;
    //DBG_PRINTF("ping_counter=%d\n", p_conf->ping_counter);
    if (p_conf->ping_counter >= M_WAIT_PING_SEC / M_WAIT_POLL_SEC) {
        ucoin_buf_t buf_ping;

        ucoin_buf_init(&buf_ping);
        bool ret = ln_create_ping(p_conf->p_self, &buf_ping);
        if (ret) {
            send_peer_noise(p_conf, &buf_ping);
            ucoin_buf_free(&buf_ping);
        } else {
            //SYSLOG_ERR("%s(): pong not respond", __func__);
            //stop_threads(p_conf);
        }
    }

    //DBGTRACE_END
}


//funding_tx確定待ち
static void poll_funding_wait(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    ln_self_t *self = p_conf->p_self;

    if (p_conf->funding_confirm >= p_conf->funding_min_depth) {
        DBG_PRINTF("confirmation OK: %d\n", p_conf->funding_confirm);
        p_conf->funding_waiting = false;    //funding_tx確定
    } else {
        DBG_PRINTF("confirmation waiting...: %d/%d\n", p_conf->funding_confirm, p_conf->funding_min_depth);
    }

    if (!p_conf->funding_waiting) {
        //funding_tx確定

        //  short_channel_id
        //      [0-2]funding_txが入ったブロック height
        //      [3-5]funding_txのTXIDが入っているindex
        //      [6-7]funding_txのvout index
        int bheight = 0;
        int bindex = 0;
        bool ret = btcprc_get_short_channel_param(&bheight, &bindex, ln_funding_txid(p_conf->p_self));
        if (ret) {
            fprintf(PRINTOUT, "bindex=%d, bheight=%d\n", bindex, bheight);
            ln_set_short_channel_id_param(self, bheight, bindex, ln_funding_txindex(p_conf->p_self));

            //安定後
            ret = ln_funding_tx_stabled(self);
            assert(ret);
        } else {
            DBG_PRINTF("fail: btcprc_get_short_channel_param()\n");
        }
    }

    //DBGTRACE_END
}


//Normal Operation中
static void poll_normal_operating(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    //funding_tx使用チェック
    bool unspent;
    uint64_t sat;
    bool ret = btcprc_getxout(&unspent, &sat, ln_funding_txid(p_conf->p_self), ln_funding_txindex(p_conf->p_self));
    if (ret && !unspent) {
        //ループ解除
        DBG_PRINTF("funding_tx is spent.\n");
        stop_threads(p_conf);
    }

    //DBGTRACE_END
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

    while (p_conf->loop) {
        sleep(M_WAIT_ANNO_SEC);

        if (!p_conf->loop) {
            break;
        }

        if ((p_conf->flag_recv & RECV_MSG_END) == 0) {
            //まだ接続完了していない
            continue;
        }

        //未送信channel_announcementチェック
        send_channel_anno(p_conf);

        //未送信node_announcementチェック
        send_node_anno(p_conf);
    }

    SYSLOG_WARN("[exit]anno thread\n");

    return NULL;
}


/**************************************************************************
 * 受信スレッドへの処理実行要求
 **************************************************************************/

/** 処理要求キュー処理
 *
 */
static bool set_request_recvproc(lnapp_conf_t *p_conf, recv_proc_t cmd, uint16_t Len, void *pData)
{
    //追い越しチェック
    uint8_t next_wpnt = (p_conf->fwd_proc_wpnt + 1) % APP_FWD_PROC_MAX;
    if (p_conf->fwd_proc_rpnt == next_wpnt) {
        //NG
        SYSLOG_ERR("%s(): process buffer full", __func__);
        return false;
    }

    p_conf->fwd_proc[p_conf->fwd_proc_wpnt].cmd = cmd;
    p_conf->fwd_proc[p_conf->fwd_proc_wpnt].len = Len;
    p_conf->fwd_proc[p_conf->fwd_proc_wpnt].p_data = pData;

    //DBG_PRINTF("[%d:%d]set p_data(%d)=", p_conf->fwd_proc_wpnt, p_conf->fwd_proc[p_conf->fwd_proc_wpnt].cmd, p_conf->fwd_proc[p_conf->fwd_proc_wpnt].len);
    //DUMPBIN((uint8_t *)p_conf->fwd_proc[p_conf->fwd_proc_wpnt].p_data, p_conf->fwd_proc[p_conf->fwd_proc_wpnt].len);

    p_conf->fwd_proc_wpnt = next_wpnt;

    return true;
}


/********************************************************************
 * 転送処理
 ********************************************************************/

// 別ノードからの update_add_htlc
static bool fwd_payment_forward(lnapp_conf_t *p_conf, fwd_proc_add_t *p_fwd_add)
{
    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);

    wait_mutex_lock(MUX_CHG_HTLC);

    //DBG_PRINTF("------------------------------: %p\n", p_fwd_add);
    //DBG_PRINTF("fwd_proc_add_t.amt_to_forward= %" PRIu64 "\n", p_fwd_add->amt_to_forward);
    //DBG_PRINTF("fwd_proc_add_t.outgoing_cltv_value= %d\n", (int)p_fwd_add->outgoing_cltv_value);
    //DBG_PRINTF("fwd_proc_add_t.next_short_channel_id= %" PRIx64 "\n", p_fwd_add->next_short_channel_id);
    //DBG_PRINTF("fwd_proc_add_t.prev_short_channel_id= %" PRIx64 "\n", p_fwd_add->prev_short_channel_id);
    //DBG_PRINTF("short_channel_id= %" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));         //current
    //DBG_PRINTF("------------------------------\n");
    uint64_t htlc_id;
    ret = ln_create_add_htlc(p_conf->p_self,
                        &buf_bolt,
                        &htlc_id,
                        p_fwd_add->onion_route,
                        p_fwd_add->amt_to_forward,
                        p_fwd_add->outgoing_cltv_value,
                        p_fwd_add->payment_hash,
                        p_fwd_add->prev_short_channel_id,
                        p_fwd_add->prev_id,
                        &p_fwd_add->shared_secret);
    //ucoin_buf_free(&p_fwd_add->shared_secret);  //ln.cで管理するため、freeさせない
    if (!ret) {
        DBG_PRINTF("fail\n");
        goto LABEL_EXIT;
    }
    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //add送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_conf->p_self, &buf_bolt);
    if (!ret) {
        DBG_PRINTF("fail\n");
        goto LABEL_EXIT;
    }
    send_peer_noise(p_conf, &buf_bolt);
    p_conf->flag_ope |= OPE_COMSIG_SEND;

LABEL_EXIT:
    ucoin_buf_free(&buf_bolt);

    if (ret) {
        // method: forward
        // $1: short_channel_id
        // $2: node_id
        // $3: amt_to_forward
        // $4: outgoing_cltv_value
        // $5: payment_hash
        char hashstr[LN_SZ_HASH * 2 + 1];
        misc_bin2str(hashstr, p_fwd_add->payment_hash, LN_SZ_HASH);
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
        misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s "
                    "%" PRIu64 " "
                    "%" PRIu32 " "
                    "%s",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    p_fwd_add->amt_to_forward,
                    p_fwd_add->outgoing_cltv_value,
                    hashstr);
        call_script(M_EVT_FORWARD, param);
    }

    DBGTRACE_END

    return true;    //true:キュー解放
}


// 別ノードからの update_fullfil_htlc
static bool fwd_fulfill_backward(lnapp_conf_t *p_conf, fwd_proc_fulfill_t *p_fwd_fulfill)
{
    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);

    show_self_param(p_conf->p_self, PRINTOUT, __LINE__);

    DBG_PRINTF("id= %" PRIu64 "\n", p_fwd_fulfill->id);
    DBG_PRINTF("preimage= ");
    DUMPBIN(p_fwd_fulfill->preimage, LN_SZ_PREIMAGE);

    ret = ln_create_fulfill_htlc(p_conf->p_self, &buf_bolt,
                            p_fwd_fulfill->id, p_fwd_fulfill->preimage);
    assert(ret);
    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //fulfill送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_conf->p_self, &buf_bolt);
    assert(ret);
    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);
    p_conf->flag_ope |= OPE_COMSIG_SEND;

    if (ret) {
        show_self_param(p_conf->p_self, PRINTOUT, __LINE__);

        // method: fulfill
        // $1: short_channel_id
        // $2: node_id
        // $3: payment_hash
        // $4: payment_preimage
        char hashstr[LN_SZ_HASH * 2 + 1];
        uint8_t payment_hash[LN_SZ_HASH];
        ln_calc_preimage_hash(payment_hash, p_fwd_fulfill->preimage);
        misc_bin2str(hashstr, payment_hash, LN_SZ_HASH);
        char imgstr[LN_SZ_PREIMAGE * 2 + 1];
        misc_bin2str(imgstr, p_fwd_fulfill->preimage, LN_SZ_PREIMAGE);
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
        misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s "
                    "%s "
                    "%s",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    hashstr,
                    imgstr);
        call_script(M_EVT_FULFILL, param);
    }

    DBGTRACE_END

    return true;    //true:キュー解放
}


// 別ノードからの update_fail_htlc
static bool fwd_fail_backward(lnapp_conf_t *p_conf, fwd_proc_fail_t *p_fwd_fail)
{
    DBGTRACE_BEGIN

    bool ret = false;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);

    show_self_param(p_conf->p_self, PRINTOUT, __LINE__);

    DBG_PRINTF("id= %" PRIx64 "\n", p_fwd_fail->id);
    DBG_PRINTF("reason= ");
    DUMPBIN(p_fwd_fail->reason.buf, p_fwd_fail->reason.len);
    DBG_PRINTF("shared secret= ");
    DUMPBIN(p_fwd_fail->shared_secret.buf, p_fwd_fail->shared_secret.len);
    DBG_PRINTF("first= %s\n", (p_fwd_fail->b_first) ? "true" : "false");

    ucoin_buf_t buf_reason;
    if (p_fwd_fail->b_first) {
        ln_onion_failure_create(&buf_reason, &p_fwd_fail->shared_secret, &p_fwd_fail->reason);
    } else {
        ln_onion_failure_forward(&buf_reason, &p_fwd_fail->shared_secret, &p_fwd_fail->reason);
    }
    ret = ln_create_fail_htlc(p_conf->p_self, &buf_bolt, p_fwd_fail->id, &buf_reason);
    assert(ret);

    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);
    ucoin_buf_free(&p_fwd_fail->reason);
    ucoin_buf_free(&p_fwd_fail->shared_secret);

    //fail送信する場合はcommitment_signedも送信する
    ret = ln_create_commit_signed(p_conf->p_self, &buf_bolt);
    assert(ret);
    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);
    p_conf->flag_ope |= OPE_COMSIG_SEND;

    if (ret) {
        show_self_param(p_conf->p_self, PRINTOUT, __LINE__);

        // method: fail
        // $1: short_channel_id
        // $2: node_id
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
        misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
        char param[256];
        sprintf(param, "%" PRIx64 " %s",
                    ln_short_channel_id(p_conf->p_self), node_id);
        call_script(M_EVT_FAIL, param);
    }

    DBGTRACE_END

    return true;    //true:キュー解放
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
        //    LN_CB_FINDINGWIF_REQ,       ///< funding鍵設定要求
        //    LN_CB_FUNDINGTX_WAIT,       ///< funding_tx安定待ち要求
        //    LN_CB_ESTABLISHED,          ///< Establish完了通知
        //    LN_CB_CHANNEL_ANNO_RECV,    ///< channel_announcement受信
        //    LN_CB_NODE_ANNO_RECV,       ///< node_announcement受信通知
        //    LN_CB_SHT_CNL_ID_UPDATE,    ///< short_chennel_id更新
        //    LN_CB_ANNO_SIGSED,          ///< announcement_signatures完了通知
        //    LN_CB_ADD_HTLC_RECV_PREV,   ///< update_add_htlc処理前通知
        //    LN_CB_ADD_HTLC_RECV,        ///< update_add_htlc受信通知
        //    LN_CB_FULFILL_HTLC_RECV,    ///< update_fulfill_htlc受信通知
        //    LN_CB_FAIL_HTLC_RECV,       ///< update_fail_htlc受信通知
        //    LN_CB_COMMIT_SIG_RECV_PREV, ///< commitment_signed処理前通知
        //    LN_CB_COMMIT_SIG_RECV,      ///< commitment_signed受信通知
        //    LN_CB_HTLC_CHANGED,         ///< HTLC変化通知
        //    LN_CB_SHUTDOWN_RECV,        ///< shutdown受信通知
        //    LN_CB_CLOSED_FEE,           ///< closing_signed受信通知(FEE不一致)
        //    LN_CB_CLOSED,               ///< closing_signed受信通知(FEE一致)
        //    LN_CB_SEND_REQ,             ///< peerへの送信要求

        { "  LN_CB_ERROR: エラー有り", cb_error_recv },
        { "  LN_CB_INIT_RECV: init受信", cb_init_recv },
        { "  LN_CB_REESTABLISH_RECV: channel_reestablish受信", cb_channel_reestablish_recv },
        { "  LN_CB_FINDINGWIF_REQ: funding_tx WIF要求", cb_find_index_wif_req },
        { "  LN_CB_FUNDINGTX_WAIT: funding_tx confirmation待ち要求", cb_funding_tx_wait },
        { "  LN_CB_ESTABLISHED: Establish完了", cb_established },
        { NULL/*"  LN_CB_CHANNEL_ANNO_RECV: channel_announcement受信"*/, cb_channel_anno_recv },
        { NULL/*"  LN_CB_NODE_ANNO_RECV: node_announcement受信通知"*/, cb_node_anno_recv },
        { "  LN_CB_SHT_CNL_ID_UPDATE: short_chennel_id更新", cb_short_channel_id_upd },
        { "  LN_CB_ANNO_SIGSED: announcement_signatures完了", cb_anno_signsed },
        { "  LN_CB_ADD_HTLC_RECV_PREV: update_add_htlc処理前", cb_add_htlc_recv_prev },
        { "  LN_CB_ADD_HTLC_RECV: update_add_htlc受信", cb_add_htlc_recv },
        { "  LN_CB_FULFILL_HTLC_RECV: update_fulfill_htlc受信", cb_fulfill_htlc_recv },
        { "  LN_CB_FAIL_HTLC_RECV: update_fail_htlc受信", cb_fail_htlc_recv },
        { "  LN_CB_COMMIT_SIG_RECV_PREV: commitment_signed処理前", cb_commit_sig_recv_prev },
        { "  LN_CB_COMMIT_SIG_RECV: commitment_signed受信通知", cb_commit_sig_recv },
        { "  LN_CB_HTLC_CHANGED: HTLC変化", cb_htlc_changed },
        { "  LN_CB_SHUTDOWN_RECV: shutdown受信", cb_shutdown_recv },
        { "  LN_CB_CLOSED_FEE: closing_signed受信(FEE不一致)", cb_closed_fee },
        { "  LN_CB_CLOSED: closing_signed受信(FEE一致)", cb_closed },
        { "  LN_CB_SEND_REQ: 送信要求", cb_send_req },
    };

    if (reason < LN_CB_MAX) {
        if (MAP[reason].p_msg != NULL) {
            DBG_PRINTF("%s\n", MAP[reason].p_msg);
        }
        (*MAP[reason].func)(p_conf, p_param);
    } else {
        DBG_PRINTF("fail: invalid reason: %d\n", reason);
    }

    //DBGTRACE_END
}


//LN_CB_ERROR: error受信
static void cb_error_recv(lnapp_conf_t *p_conf, void *p_param)
{
    const ln_error_t *p_err = (const ln_error_t *)p_param;

    set_lasterror(p_conf, RPCERR_PEER_ERROR, p_err->p_data);
}


//LN_CB_INIT_RECV: init受信
static void cb_init_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    p_conf->initial_routing_sync = *(bool *)p_param;

    //待ち合わせ解除(*1)
    p_conf->flag_recv |= RECV_MSG_INIT;
    pthread_cond_signal(&p_conf->cond);
}


//LN_CB_REESTABLISH_RECV: channel_reestablish受信
static void cb_channel_reestablish_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    //待ち合わせ解除(*3)
    p_conf->flag_recv |= RECV_MSG_REESTABLISH;
    pthread_cond_signal(&p_conf->cond);
}


//LN_CB_FINDINGWIF_REQ: WIF要求
static void cb_find_index_wif_req(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    bool ret;

    //2-of-2の片方(wifはcommit_txの署名用)
    char funding_addr[UCOIN_SZ_ADDR_MAX];
    ret = btcprc_getnewaddress(funding_addr);
    assert(ret);
    fprintf(PRINTOUT, "fundingaddr %s\n", funding_addr);

    char wif[UCOIN_SZ_WIF_MAX];
    ret = btcprc_dumpprivkey(wif, funding_addr);
    assert(ret);

    ret = ln_set_funding_wif(p_conf->p_self, wif);
    assert(ret);
    memset(wif, 0, sizeof(wif));

    DBGTRACE_END
}


//LN_CB_FUNDINGTX_WAIT: funding_txのconfirmation待ち開始
static void cb_funding_tx_wait(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_funding_t *p = (const ln_cb_funding_t *)p_param;

    if (p->b_send) {
        uint8_t txid[UCOIN_SZ_TXID];
        ucoin_buf_t buf_tx;

        ucoin_buf_init(&buf_tx);
        ucoin_tx_create(&buf_tx, p->p_tx_funding);
        bool ret = btcprc_sendraw_tx(txid, NULL, buf_tx.buf, buf_tx.len);
        if (ret) {
            DBG_PRINTF("OK\n");
        } else {
            DBG_PRINTF("NG\n");
            exit(-1);
        }
        ucoin_buf_free(&buf_tx);
    }

    //DB保存
    ln_db_self_save(p_conf->p_self);

    //fundingの監視は thread_poll_start()に任せる
    DBG_PRINTF("funding_tx監視開始\n");
    DUMPTXID(ln_funding_txid(p_conf->p_self));
    p_conf->funding_min_depth = ln_minimum_depth(p_conf->p_self);
    p_conf->funding_waiting = true;

    DBGTRACE_END
}


//LN_CB_ESTABLISHED: funding_locked送受信済み
static void cb_established(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    SYSLOG_INFO("Established[%" PRIx64 "]: our_msat=%" PRIu64 ", their_msat=%" PRIu64, ln_short_channel_id(p_conf->p_self), ln_our_msat(p_conf->p_self), ln_their_msat(p_conf->p_self));

    // method: established
    // $1: short_channel_id
    // $2: node_id
    // $3: our_msat
    // $4: funding_txid
    char txidstr[UCOIN_SZ_TXID * 2 + 1];
    misc_bin2str_rev(txidstr, ln_funding_txid(p_conf->p_self), UCOIN_SZ_TXID);
    char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
    misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
    char param[256];
    sprintf(param, "%" PRIx64 " %s "
                "%" PRIu64 " "
                "%s",
                ln_short_channel_id(p_conf->p_self), node_id,
                ln_our_msat(p_conf->p_self),
                txidstr);
    call_script(M_EVT_ESTABLISHED, param);

    DBGTRACE_END
}


//LN_CB_CHANNEL_ANNO_RECV: channel_announcement受信
static void cb_channel_anno_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    //DBGTRACE_BEGIN

    ln_cb_channel_anno_recv_t *p = (ln_cb_channel_anno_recv_t *)p_param;

    uint32_t bheight;
    uint32_t bindex;
    uint32_t vindex;
    ln_get_short_channel_id_param(&bheight, &bindex, &vindex, p->short_channel_id);

    p->is_unspent = btcprc_is_short_channel_unspent(bheight, bindex, vindex);
    if (!p->is_unspent) {
        DBG_PRINTF("fail: already spent : %016" PRIx64 "\n", p->short_channel_id);
    }

    //DBGTRACE_END
}


//LN_CB_NODE_ANNO_RECV: node_announcement受信
static void cb_node_anno_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf; (void)p_param;
    //const ln_node_announce_t *p_nodeanno = (const ln_node_announce_t *)p_param;

    ////peer config file
    //char node_id[UCOIN_SZ_PUBKEY * 2 + 1];

    //misc_bin2str(node_id, p_nodeanno->p_node_id, UCOIN_SZ_PUBKEY);

    //FILE *fp = fopen(node_id, "w");
    //if (fp) {

    //    fclose(fp);
    //}
}


//announcement_signatures受信時に short_channel_idが取得できていなかった場合
static void cb_short_channel_id_upd(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    //self->short_chennel_id更新
    while (p_conf->funding_confirm < p_conf->funding_min_depth) {
        p_conf->funding_confirm = btcprc_get_confirmation(ln_funding_txid(p_conf->p_self));
        DBG_PRINTF("confimation=%d / %d\n", p_conf->funding_confirm, p_conf->funding_min_depth);
        if (p_conf->funding_confirm < p_conf->funding_min_depth) {
            sleep(M_WAIT_POLL_SEC);
        }
    }
    poll_funding_wait(p_conf);

    DBGTRACE_END
}


//LN_CB_ANNO_SIGSED: announcement_signatures送受信完了
static void cb_anno_signsed(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_anno_sigs_t *p = (ln_cb_anno_sigs_t *)p_param;

    bool ret;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);

    //channel_announcement
    ret = ln_db_annocnl_load(&buf_bolt, ln_short_channel_id(p_conf->p_self));
    if (ret) {
        DBG_PRINTF("send: my channel_annoucnement\n");
        send_peer_noise(p_conf, &buf_bolt);
    } else {
        DBG_PRINTF("err\n");
    }
    ucoin_buf_free(&buf_bolt);

    //channel_update
    uint32_t timestamp;
    ret = ln_db_annocnlupd_load(&buf_bolt, &timestamp, ln_short_channel_id(p_conf->p_self), p->sort);
    if (ret) {
        DBG_PRINTF("send: my channel_update\n");
        send_peer_noise(p_conf, &buf_bolt);
    } else {
        DBG_PRINTF("err\n");
    }
    ucoin_buf_free(&buf_bolt);

    DBGTRACE_END
}


//LN_CB_ADD_HTLC_RECV_PREV: update_add_htlc受信(前処理)
static void cb_add_htlc_recv_prev(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf; (void)p_param;
    DBGTRACE_BEGIN
    wait_mutex_lock(MUX_CHG_HTLC);
    DBGTRACE_END
}


//LN_CB_ADD_HTLC_RECV: update_add_htlc受信(後処理)
static void cb_add_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    //p_add->okはfalseになっている
    DBGTRACE_BEGIN

    ln_cb_add_htlc_recv_t *p_add = (ln_cb_add_htlc_recv_t *)p_param;

    DBG_PRINTF("mMuxTiming %d\n", mMuxTiming);
    DBG_PRINTF2("  id=%" PRIu64 "\n", p_add->id);

    DBG_PRINTF2("  %s\n", (p_add->p_hop->b_exit) ? "intended recipient" : "forwarding HTLCs");
    //転送先
    DBG_PRINTF2("  FWD: short_channel_id: %" PRIx64 "\n", p_add->p_hop->short_channel_id);
    DBG_PRINTF2("  FWD: amt_to_forward: %" PRIu64 "\n", p_add->p_hop->amt_to_forward);
    DBG_PRINTF2("  FWD: outgoing_cltv_value: %d\n", p_add->p_hop->outgoing_cltv_value);
    DBG_PRINTF2("  -------\n");
    //自分への通知
    int height = btcprc_getblockcount();
    DBG_PRINTF2("  amount_msat: %" PRIu64 "\n", p_add->amount_msat);
    DBG_PRINTF2("  cltv_expiry: %d\n", p_add->cltv_expiry);
    DBG_PRINTF2("  my fee : %" PRIu64 "\n", (uint64_t)(p_add->amount_msat - p_add->p_hop->amt_to_forward));
    DBG_PRINTF2("  cltv_expiry - outgoing_cltv_value(%" PRIu32") = %d\n",  p_add->p_hop->outgoing_cltv_value, p_add->cltv_expiry - p_add->p_hop->outgoing_cltv_value);
    DBG_PRINTF2("  cltv_expiry - height(%d) = %d\n", height, p_add->cltv_expiry - height);

    ucoind_preimage_lock();
    if (p_add->p_hop->b_exit) {
        //自分宛
        DBG_PRINTF("自分宛\n");

        SYSLOG_INFO("arrive: %" PRIx64 "(%" PRIu64 " msat)", ln_short_channel_id(p_conf->p_self), p_add->amount_msat);

        //preimage-hashチェック
        uint8_t preimage[LN_SZ_PREIMAGE];
        uint64_t amount;
        uint8_t preimage_hash[LN_SZ_HASH];

        void *p_cur;
        bool ret = ln_db_preimg_cur_open(&p_cur);
        while (ret) {
            ret = ln_db_preimg_cur_get(p_cur, preimage, &amount);
            if (ret) {
                ln_calc_preimage_hash(preimage_hash, preimage);
                if (memcmp(preimage_hash, p_add->p_payment_hash, LN_SZ_HASH) == 0) {
                    //一致
                    break;
                }
            }
        }
        ln_db_preimg_cur_close(p_cur);

        if (ret) {
            //last nodeチェック
            // https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md#payload-for-the-last-node
            //    * outgoing_cltv_value is set to the final expiry specified by the recipient
            //    * amt_to_forward is set to the final amount specified by the recipient
            if ( (p_add->p_hop->amt_to_forward == p_add->amount_msat) &&
                 //(p_add->p_hop->outgoing_cltv_value == ln_cltv_expily_delta(p_conf->p_self)) &&
                 (p_add->p_hop->outgoing_cltv_value == p_add->cltv_expiry)  ) {
                DBG_PRINTF("last node OK\n");
            } else {
                SYSLOG_ERR("%s(): last node check", __func__);
                DBG_PRINTF("%" PRIu64 " --- %" PRIu64 "\n", p_add->p_hop->amt_to_forward, p_add->amount_msat);
                DBG_PRINTF("%" PRIu32 " --- %" PRIu32 "\n", p_add->p_hop->outgoing_cltv_value, ln_cltv_expily_delta(p_conf->p_self));
                ret = false;
            }
        } else {
            DBG_PRINTF("fail: preimage mismatch\n");
            DUMPBIN(p_add->p_payment_hash, LN_SZ_HASH);
        }
        if (ret) {
            if (LN_DBG_FULFILL()) {
                //キューにためる(fulfill)
                queue_fulfill_t *fulfill = (queue_fulfill_t *)APP_MALLOC(sizeof(queue_fulfill_t));  //APP_FREE: cb_htlc_changed()
                fulfill->type = QTYPE_BWD_FULFILL_HTLC;
                fulfill->id = p_add->id;
                ucoin_buf_alloccopy(&fulfill->buf, preimage, LN_SZ_PREIMAGE);
                push_queue(p_conf, fulfill);

                //preimageを使い終わったら消す
                ln_db_preimg_del(preimage);
            } else {
                DBG_PRINTF("DBG: no fulfill mode\n");
            }

            //アプリ判定はOK
            p_add->ok = true;
        } else {
            SYSLOG_ERR("%s(): payment stop", __func__);

            //キューにためる(fail)
            queue_fulfill_t *fulfill = (queue_fulfill_t *)APP_MALLOC(sizeof(queue_fulfill_t));  //APP_FREE: cb_htlc_changed()
            fulfill->type = QTYPE_BWD_FAIL_HTLC;
            fulfill->id = p_add->id;
            ucoin_buf_alloccopy(&fulfill->buf, p_add->p_shared_secret->buf, p_add->p_shared_secret->len);
            push_queue(p_conf, fulfill);
        }
    } else {
        //転送
        SYSLOG_INFO("forward: %" PRIx64 "(%" PRIu64 " msat) --> %" PRIx64 "(%" PRIu64 " msat)", ln_short_channel_id(p_conf->p_self), p_add->amount_msat, p_add->p_hop->short_channel_id, p_add->p_hop->amt_to_forward);

        //キューにためる(add)
        queue_fulfill_t *fulfill = (queue_fulfill_t *)APP_MALLOC(sizeof(queue_fulfill_t));      //APP_FREE: cb_htlc_changed()
        fulfill->type = QTYPE_FWD_ADD_HTLC;
        fulfill->id = p_add->id;
        //forward情報
        ucoin_buf_alloc(&fulfill->buf, sizeof(fwd_proc_add_t));
        fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)fulfill->buf.buf;
        memcpy(p_fwd_add->onion_route, p_add->p_onion_route, LN_SZ_ONION_ROUTE);
        p_fwd_add->amt_to_forward = p_add->p_hop->amt_to_forward;
        p_fwd_add->outgoing_cltv_value = p_add->p_hop->outgoing_cltv_value;
        p_fwd_add->next_short_channel_id = p_add->p_hop->short_channel_id;
        p_fwd_add->prev_short_channel_id = ln_short_channel_id(p_conf->p_self);
        p_fwd_add->prev_id = p_add->id;
        memcpy(p_fwd_add->payment_hash, p_add->p_payment_hash, LN_SZ_HASH);
        ucoin_buf_alloccopy(&p_fwd_add->shared_secret, p_add->p_shared_secret->buf, p_add->p_shared_secret->len);   // freeなし: lnで管理

        push_queue(p_conf, fulfill);
        p_add->ok = true;
        //DBG_PRINTF("------------------------------: %p\n", p_fwd_add);
        //DBG_PRINTF("fwd_proc_add_t.amt_to_forward= %" PRIu64 "\n", p_fwd_add->amt_to_forward);
        //DBG_PRINTF("fwd_proc_add_t.outgoing_cltv_value= %d\n", (int)p_fwd_add->outgoing_cltv_value);
        //DBG_PRINTF("fwd_proc_add_t.next_short_channel_id= %" PRIx64 "\n", p_fwd_add->next_short_channel_id);  //next
        //DBG_PRINTF("fwd_proc_add_t.prev_short_channel_id= %" PRIx64 "\n", p_fwd_add->prev_short_channel_id);  //next
        //DBG_PRINTF("short_channel_id= %" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));         //current
        //DBG_PRINTF("------------------------------\n");
    }
    ucoind_preimage_unlock();

    wait_mutex_unlock(MUX_CHG_HTLC);

    DBGTRACE_END
}


//LN_CB_FULFILL_HTLC_RECV: update_fulfill_htlc受信
static void cb_fulfill_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    DBGTRACE_BEGIN

    const ln_cb_fulfill_htlc_recv_t *p_fulfill = (const ln_cb_fulfill_htlc_recv_t *)p_param;

    DBG_PRINTF("mMuxTiming %d\n", mMuxTiming);
    while (true) {
        pthread_mutex_lock(&mMuxSeq);
        //ここで PAYMENTがある場合もブロックすると、デッドロックする可能性あり
        if ((mMuxTiming & ~MUX_PAYMENT) == 0) {
            break;
        }
        pthread_mutex_unlock(&mMuxSeq);
        misc_msleep(M_WAIT_MUTEX_MSEC);
    }

    if (p_fulfill->prev_short_channel_id != 0) {
        //フラグを立てて、相手の受信スレッドで処理してもらう
        DBG_PRINTF("戻す: %" PRIx64 ", id=%" PRIx64 "\n", p_fulfill->prev_short_channel_id, p_fulfill->id);
        ucoind_backward_fulfill(p_fulfill);
    } else {
        DBG_PRINTF("ここまで\n");
        del_routelist(p_conf, p_fulfill->id);

        uint8_t hash[LN_SZ_HASH];
        ln_calc_preimage_hash(hash, p_fulfill->p_preimage);
        ln_db_annoskip_invoice_del(hash);
    }
    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);

    DBGTRACE_END
}


//LN_CB_FAIL_HTLC_RECV: update_fail_htlc受信
static void cb_fail_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_fail_htlc_recv_t *p_fail = (const ln_cb_fail_htlc_recv_t *)p_param;
    bool retry = false;

    DBG_PRINTF("mMuxTiming %d\n", mMuxTiming);
    while (true) {
        pthread_mutex_lock(&mMuxSeq);
        //ここで PAYMENTがある場合もブロックすると、デッドロックする可能性あり
        if ((mMuxTiming & ~MUX_PAYMENT) == 0) {
            break;
        }
        pthread_mutex_unlock(&mMuxSeq);
        misc_msleep(M_WAIT_MUTEX_MSEC);
    }

    if (p_fail->prev_short_channel_id != 0) {
        //フラグを立てて、相手の受信スレッドで処理してもらう
        DBG_PRINTF("fail戻す: %" PRIx64 ", id=%" PRIx64 "\n", p_fail->prev_short_channel_id, p_fail->prev_id);
        ucoind_backward_fail(p_fail);
    } else {
        DBG_PRINTF("ここまで\n");
        mMuxTiming &= ~MUX_PAYMENT;

        ucoin_buf_t reason;
        int hop;
        ucoin_buf_init(&reason);
        bool ret = ln_onion_failure_read(&reason, &hop, p_fail->p_shared_secret, p_fail->p_reason);
        if (ret) {
            DBG_PRINTF("  failure reason= ");
            DUMPBIN(reason.buf, reason.len);

            print_routelist(p_conf);

            //失敗したと思われるshort_channel_idを登録
            //      route.hop_datain[0]は自分、[1]が相手
            //      hopの0は相手
            char suggest[64];
            const payment_conf_t *p_payconf = get_routelist(p_conf, p_fail->orig_id);
            if (p_payconf != NULL) {
                if (hop == p_payconf->hop_num - 2) {
                    //送金先がエラーを返した？
                    strcpy(suggest, "payee");
                } else if (hop < p_payconf->hop_num - 2) {
                    //途中がエラーを返した
                    // DBG_PRINTF2("hop=%d\n", hop);
                    // for (int lp = 0; lp < p_payconf.hop_num; lp++) {
                    //     DBG_PRINTF2("[%d]%" PRIu64 "\n", lp, p_payconf->hop_datain[lp].short_channel_id);
                    // }

                    uint64_t short_channel_id = p_payconf->hop_datain[hop + 1].short_channel_id;
                    sprintf(suggest, "%016" PRIx64, short_channel_id);
                    ln_db_annoskip_save(short_channel_id);
                    retry = true;
                } else {
                    strcpy(suggest, "invalid");
                }
            } else {
                strcpy(suggest, "?");
            }
            DBG_PRINTF("suggest: %s\n", suggest);

            char errstr[512];
            char reasonstr[128];
            set_onionerr_str(reasonstr, &reason);
            sprintf(errstr, "fail reason:%s (hop=%d)(suggest:%s)", reasonstr, hop, suggest);
            set_lasterror(p_conf, RPCERR_PAYFAIL, errstr);
        } else {
            //デコード失敗
            set_lasterror(p_conf, RPCERR_PAYFAIL, "fail result cannot decode");
        }
        del_routelist(p_conf, p_fail->orig_id);
        if (retry) {
            push_pay_retry_queue(p_conf, p_fail->p_payment_hash);
        } else {
            ln_db_annoskip_invoice_del(p_fail->p_payment_hash);
        }
    }
    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);

    DBGTRACE_END
}


//LN_CB_COMMIT_SIG_RECV_PREV": commitment_signed受信(前処理)
static void cb_commit_sig_recv_prev(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf; (void)p_param;
    DBGTRACE_BEGIN
    wait_mutex_lock(MUX_COMSIG);
    DBGTRACE_END
}


//LN_CB_COMMIT_SIG_RECV: commitment_signed受信
static void cb_commit_sig_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;

    pthread_mutex_lock(&mMuxSeq);
    DBG_PRINTF("mMuxTiming: %d\n", mMuxTiming);
    if (p_conf->flag_ope & OPE_COMSIG_SEND) {
        //commitment_signedは送信済み
        p_conf->flag_ope &= ~OPE_COMSIG_SEND;
    } else {
        //commitment_signed未送信
        ucoin_buf_t buf_bolt;

        ucoin_buf_init(&buf_bolt);
        bool ret = ln_create_commit_signed(p_conf->p_self, &buf_bolt);
        if (ret) {
            send_peer_noise(p_conf, &buf_bolt);
        } else {
#warning エラー処理
        }
        ucoin_buf_free(&buf_bolt);
    }

    //DB保存
    ln_db_self_save(p_conf->p_self);

    mMuxTiming &= ~(MUX_PAYMENT | MUX_COMSIG);
    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);
}


//LN_CB_HTLC_CHANGED: revoke_and_ack受信
static void cb_htlc_changed(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    SYSLOG_INFO("HTLC[%" PRIx64 "]: our msat=%" PRIu64 ", their_msat=%" PRIu64, ln_short_channel_id(p_conf->p_self), ln_our_msat(p_conf->p_self), ln_their_msat(p_conf->p_self));

    pthread_mutex_lock(&mMuxSeq);
    DBG_PRINTF("mMuxTiming: %d\n", mMuxTiming);
    if (p_conf->flag_ope & OPE_COMSIG_SEND) {
        mMuxTiming &= ~MUX_CHG_HTLC;
    } else {
        //fulfill要求があれば送信要求する
        queue_fulfill_t *p = pop_queue(p_conf);
        if (p != NULL) {
            ucoin_buf_t *p_fail_ss = NULL;
            switch (p->type) {
            case QTYPE_FWD_ADD_HTLC:
                {
                    fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)p->buf.buf;

                    // DBG_PRINTF("------------------------------: %p\n", p_fwd_add);
                    // DBG_PRINTF("fwd_proc_add_t.amt_to_forward= %" PRIu64 "\n", p_fwd_add->amt_to_forward);
                    // DBG_PRINTF("fwd_proc_add_t.outgoing_cltv_value= %d\n", (int)p_fwd_add->outgoing_cltv_value);
                    // DBG_PRINTF("fwd_proc_add_t.next_short_channel_id= %" PRIx64 "\n", p_fwd_add->next_short_channel_id);      //current
                    // DBG_PRINTF("fwd_proc_add_t.prev_short_channel_id= %" PRIx64 "\n", p_fwd_add->prev_short_channel_id);      //current
                    // DBG_PRINTF("short_channel_id= %" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));         //prev
                    // DBG_PRINTF("shared_secret= ");
                    // DUMPBIN(p_fwd_add->shared_secret.buf, p_fwd_add->shared_secret.len);
                    // DBG_PRINTF("------------------------------\n");
                    // DBG_PRINTF("  --> forward add(sci=%" PRIx64 ")\n", p_fwd_add->next_short_channel_id);
                    bool ret = ucoind_forward_payment(p_fwd_add);
                    if (ret) {
                        DBG_PRINTF("転送した\n");
                    } else {
                        DBG_PRINTF("転送失敗\n");
                        SYSLOG_ERR("%s(): forward", __func__);

                        //update_fail_htlc準備
                        p_fail_ss = &p_fwd_add->shared_secret;
                    }
                }
                break;
            case QTYPE_BWD_FULFILL_HTLC:
                {
                    ln_cb_fulfill_htlc_recv_t fulfill;

                    fulfill.id = p->id;
                    fulfill.p_preimage = p->buf.buf;
                    DBG_PRINTF("  --> backward fulfill(id=%" PRId64 ")\n", fulfill.id);
                    lnapp_backward_fulfill(p_conf, &fulfill);
                }
                break;
            case QTYPE_BWD_FAIL_HTLC:
                p_fail_ss = &p->buf;
                break;
            case QTYPE_PAY_RETRY:
                {
                    //リトライ
                    char *p_invoice;
                    bool ret = ln_db_annoskip_invoice_load(&p_invoice, p->buf.buf);     //p_invoiceはmalloc()
                    if (ret) {
                        DBG_PRINTF("invoice:%s\n", p_invoice);
                        char *json = (char *)APP_MALLOC(8192);      //APP_FREE: この中
                        strcpy(json, "{\"method\":\"routepay\",\"params\":");
                        strcat(json, p_invoice);
                        strcat(json, "}");
                        int retval = misc_sendjson(json, "127.0.0.1", cmd_json_get_port());
                        DBG_PRINTF("retval=%d\n", retval);
                        APP_FREE(json);     //APP_MALLOC: この中
                        free(p_invoice);
                    }
                }
                break;
            default:
                break;
            }
            if (p_fail_ss != NULL) {
                ln_cb_fail_htlc_recv_t fail;
#warning reasonダミー
                const uint8_t dummy_reason_data[] = { 0x20, 0x02 };
                const ucoin_buf_t dummy_reason = { (uint8_t *)dummy_reason_data, sizeof(dummy_reason_data) };

                fail.prev_id = p->id;
                fail.orig_id = (uint64_t)-1;
                fail.p_reason = &dummy_reason;
                fail.p_shared_secret = p_fail_ss;
                DBG_PRINTF("  --> fail_htlc(id=%" PRIu64 ")\n", fail.prev_id);
                lnapp_backward_fail(p_conf, &fail, true);
            }
            ucoin_buf_free(&p->buf);
            APP_FREE(p);
        }
    }

    //DB保存
    ln_db_self_save(p_conf->p_self);

    // method: htlc_changed
    // $1: short_channel_id
    // $2: node_id
    // $3: our_msat
    // $4: htlc_num
    char param[256];
    char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
    misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
    sprintf(param, "%" PRIx64 " %s "
                "%" PRIu64 " "
                "%d",
                ln_short_channel_id(p_conf->p_self), node_id,
                ln_our_msat(p_conf->p_self),
                ln_htlc_num(p_conf->p_self));
    call_script(M_EVT_HTLCCHANGED, param);

    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);

    DBGTRACE_END
}


//LN_CB_SHUTDOWN_RECV: shutdown受信
static void cb_shutdown_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    //fee and addr
    //   fee_satoshis lower than or equal to the base fee of the final commitment transaction
    uint64_t commit_fee = ln_calc_max_closing_fee(p_conf->p_self);
    set_changeaddr(p_conf->p_self, commit_fee);
}


//LN_CB_CLOSED_FEE: closing_signed受信(FEE不一致)
static void cb_closed_fee(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_closed_fee_t *p_closed_fee = (const ln_cb_closed_fee_t *)p_param;
    DBG_PRINTF("received fee: %" PRIu64 "\n", p_closed_fee->fee_sat);

#warning FEEの決め方
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
        DBG_PRINTF("send closing tx\n");

        uint8_t txid[UCOIN_SZ_TXID];
        bool ret = btcprc_sendraw_tx(txid, NULL, p_closed->p_tx_closing->buf, p_closed->p_tx_closing->len);
        if (!ret) {
            SYSLOG_ERR("%s(): btcprc_sendraw_tx", __func__);
            assert(0);
        }
        DBG_PRINTF("closing_txid: ");
        DUMPTXID(txid);

        // method: closed
        // $1: short_channel_id
        // $2: node_id
        // $3: closing_txid
        char param[256];
        char txidstr[UCOIN_SZ_TXID * 2 + 1];
        misc_bin2str_rev(txidstr, txid, UCOIN_SZ_TXID);
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
        misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
        sprintf(param, "%" PRIx64 " %s "
                    "%s",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    txidstr);
        call_script(M_EVT_CLOSED, param);
    } else {
        DBG_PRINTF("DBG: no send closing_tx mode\n");
    }

    DBGTRACE_END
}


//LN_CB_SEND_REQ: BOLTメッセージ送信要求
static void cb_send_req(lnapp_conf_t *p_conf, void *p_param)
{
    ucoin_buf_t *p_buf = (ucoin_buf_t *)p_param;
    send_peer_noise(p_conf, p_buf);
}


/********************************************************************
 * スレッド共通処理
 ********************************************************************/

//スレッドループ停止
static void stop_threads(lnapp_conf_t *p_conf)
{
    if (p_conf->loop) {
        p_conf->loop = false;
        //待ち合わせ解除(*2)
        pthread_cond_signal(&p_conf->cond);
        SYSLOG_WARN("close channel: %" PRIx64, ln_short_channel_id(p_conf->p_self));
        DBG_PRINTF("===================================\n");
        DBG_PRINTF("=  CHANNEL THREAD END             =\n");
        DBG_PRINTF("===================================\n");
    }
}


//peer送信(そのまま送信)
static void send_peer_raw(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf)
{
    ssize_t len = pBuf->len;
    while (true) {
        ssize_t sz = write(p_conf->sock, pBuf->buf, len);
        len -= sz;
        if (len == 0) {
            break;
        }
        misc_msleep(M_WAIT_SEND_WAIT_MSEC);
    }
}


//peer送信(Noise Protocol送信)
static void send_peer_noise(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf)
{
    DBG_PRINTF("type=%02x%02x: sock=%d, Len=%d\n", pBuf->buf[0], pBuf->buf[1], p_conf->sock, pBuf->len);

    pthread_mutex_lock(&p_conf->mux_send);
    ucoin_buf_t buf_enc;
    bool ret = ln_noise_enc(p_conf->p_self, &buf_enc, pBuf);
    pthread_mutex_unlock(&p_conf->mux_send);
    assert(ret);

    ssize_t len = buf_enc.len;
    while (true) {
        ssize_t sz = write(p_conf->sock, buf_enc.buf, len);
        len -= sz;
        if (len == 0) {
            break;
        }
        misc_msleep(M_WAIT_SEND_WAIT_MSEC);
    }
    ucoin_buf_free(&buf_enc);

    //ping送信待ちカウンタ
    p_conf->ping_counter = 0;
}


/********************************************************************
 * announcement展開
 ********************************************************************/

/** channel_announcement/channel_update送信
 *
 * 接続先へ未送信のchannel_announcement/channel_updateを送信する。
 * 一度にすべて送信するとDBのロック期間が長くなるため、
 * 最大M_ANNO_UNITパケットまで送信を行い、残りは次回呼び出しに行う。
 *
 * @param[in,out]   p_conf  lnapp情報
 */
static void send_channel_anno(lnapp_conf_t *p_conf)
{
    bool ret;
    int anno_cnt = 0;

    //DBG_PRINTF("BEGIN\n");

    void *p_db;
    ret = ln_db_node_cur_transaction(&p_db, LN_DB_TXN_CNL);
    if (!ret) {
        DBG_PRINTF("fail\n");
        goto LABEL_EXIT;
    }

    void *p_cur;
    ret = ln_db_annocnl_cur_open(&p_cur, p_db);
    if (ret) {
        uint64_t short_channel_id;
        char type;
        ucoin_buf_t buf_cnl;

        ucoin_buf_init(&buf_cnl);

        if (p_conf->last_anno_cnl != 0) {
            //前回のところまで検索する
            while ((ret = ln_db_annocnl_cur_get(p_cur, &short_channel_id, &type, NULL, &buf_cnl))) {
                if (short_channel_id == p_conf->last_anno_cnl) {
                    break;
                }
                ucoin_buf_free(&buf_cnl);
            }
        }
        ucoin_buf_free(&buf_cnl);

        while ((ret = ln_db_annocnl_cur_get(p_cur, &short_channel_id, &type, NULL, &buf_cnl))) {
            if (!p_conf->loop) {
                break;
            }

            bool chk = ln_db_annocnls_search_nodeid(p_db, short_channel_id, type, ln_their_node_id(p_conf->p_self));
            if (!chk) {
                DBG_PRINTF("send channel_%c: %016" PRIx64 "\n", type, short_channel_id);
                send_peer_noise(p_conf, &buf_cnl);
                ln_db_annocnls_add_nodeid(p_db, short_channel_id, type, false, ln_their_node_id(p_conf->p_self));
            } else {
                //DBG_PRINTF("not send channel_%c: %016" PRIx64 "\n", type, short_channel_id);
            }
            ucoin_buf_free(&buf_cnl);

            anno_cnt++;
            if (anno_cnt >= M_ANNO_UNIT) {
                break;
            }
        }
        if (ret) {
            p_conf->last_anno_cnl = short_channel_id;
        } else {
            p_conf->last_anno_cnl = 0;
        }
    } else {
        //DBG_PRINTF("no channel_announce DB\n");
    }
    if (p_cur) {
        ln_db_annocnl_cur_close(p_cur);
    }

    ln_db_node_cur_commit(p_db);

LABEL_EXIT:
    //DBG_PRINTF("END\n");
    ;
}


/** node_announcement送信
 *
 * 接続先へ未送信のnode_announcementを送信する。
 * 一度にすべて送信するとDBのロック期間が長くなるため、
 * 最大M_ANNO_UNITパケットまで送信を行い、残りは次回呼び出しに行う。
 *
 * @param[in,out]   p_conf  lnapp情報
 */
static void send_node_anno(lnapp_conf_t *p_conf)
{
    bool ret;
    int anno_cnt = 0;

    //DBG_PRINTF("BEGIN\n");

    void *p_db;
    ret = ln_db_node_cur_transaction(&p_db, LN_DB_TXN_NODE);
    if (!ret) {
        DBG_PRINTF("fail\n");
        goto LABEL_EXIT;
    }

    void *p_cur;
    ret = ln_db_annonod_cur_open(&p_cur, p_db);
    if (ret) {
        ucoin_buf_t buf_node;
        uint32_t timestamp;
        uint8_t nodeid[UCOIN_SZ_PUBKEY];

        ucoin_buf_init(&buf_node);

        if (p_conf->last_anno_node[0] != 0) {
            //前回のところまで検索する
            while ((ret = ln_db_annonod_cur_get(p_cur, &buf_node, &timestamp, nodeid))) {
                if (memcmp(nodeid, p_conf->last_anno_node, UCOIN_SZ_PUBKEY) == 0) {
                    break;
                }
                ucoin_buf_free(&buf_node);
            }
        }
        ucoin_buf_free(&buf_node);

        while ((ret = ln_db_annonod_cur_get(p_cur, &buf_node, &timestamp, nodeid))) {
            if (!p_conf->loop) {
                break;
            }

            bool chk = ln_db_annonod_search_nodeid(p_db, nodeid, ln_their_node_id(p_conf->p_self));
            if (!chk) {
                DBG_PRINTF("send node_anno: ");
                DUMPBIN(nodeid, UCOIN_SZ_PUBKEY);
                send_peer_noise(p_conf, &buf_node);
                ln_db_annonod_add_nodeid(p_db, nodeid, false, ln_their_node_id(p_conf->p_self));
            } else {
                //DBG_PRINTF("not send node_anno: ");
                //DUMPBIN(nodeid, UCOIN_SZ_PUBKEY);
            }
            ucoin_buf_free(&buf_node);

            anno_cnt++;
            if (anno_cnt >= M_ANNO_UNIT) {
                break;
            }
        }
        if (ret) {
            memcpy(p_conf->last_anno_node, nodeid, UCOIN_SZ_PUBKEY);
        } else {
            p_conf->last_anno_node[0] = 0;
        }
    } else {
        DBG_PRINTF("no node_announce DB\n");
    }
    if (p_cur) {
        ln_db_annonod_cur_close(p_cur);
    }

    ln_db_node_cur_commit(p_db);

LABEL_EXIT:
    //DBG_PRINTF("END\n");
    ;
}


/********************************************************************
 * その他
 ********************************************************************/

/** Establish情報設定
 *
 * @param[in,out]       p_conf
 * @param[in]           pNodeId     Establish先(NULL可のはず)
 */
static void set_establish_default(lnapp_conf_t *p_conf, const uint8_t *pNodeId)
{
    bool ret;
    establish_conf_t econf;
    ln_establish_prm_t estprm;

    ret = load_establish_conf("establish.conf", &econf);
    if (ret) {
        estprm.dust_limit_sat = econf.dust_limit_sat;
        estprm.max_htlc_value_in_flight_msat = econf.max_htlc_value_in_flight_msat;
        estprm.channel_reserve_sat = econf.channel_reserve_sat;
        estprm.htlc_minimum_msat = econf.htlc_minimum_msat;
        estprm.to_self_delay = econf.to_self_delay;
        estprm.max_accepted_htlcs = econf.max_accepted_htlcs;
        estprm.min_depth = econf.min_depth;
    } else {
        estprm.dust_limit_sat = M_DUST_LIMIT_SAT;
        estprm.max_htlc_value_in_flight_msat = M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT;
        estprm.channel_reserve_sat = M_CHANNEL_RESERVE_SAT;
        estprm.htlc_minimum_msat = M_HTLC_MINIMUM_MSAT_EST;
        estprm.to_self_delay = M_TO_SELF_DELAY;
        estprm.max_accepted_htlcs = M_MAX_ACCEPTED_HTLCS;
        estprm.min_depth = M_MIN_DEPTH;
    }

    ret = ln_set_establish(p_conf->p_self, pNodeId, &estprm);
    assert(ret);
}


/** お釣りアドレス設定
 *
 * bitcoindにアドレスを作成する
 */
static void set_changeaddr(ln_self_t *self, uint64_t commit_fee)
{
    ln_update_shutdown_fee(self, commit_fee);
}


static void wait_mutex_lock(uint8_t Flag)
{
    DBG_PRINTF("mMuxTiming %d\n", mMuxTiming);
    while (true) {
        pthread_mutex_lock(&mMuxSeq);
        //ここで PAYMENTがある場合もブロックすると、デッドロックする可能性あり
        if ((mMuxTiming & ~MUX_PAYMENT) == 0) {
            break;
        }
        pthread_mutex_unlock(&mMuxSeq);
        misc_msleep(M_WAIT_MUTEX_MSEC);
    }
    mMuxTiming |= Flag;
    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);
}


static void wait_mutex_unlock(uint8_t Flag)
{
    pthread_mutex_lock(&mMuxSeq);
    mMuxTiming &= ~Flag;
    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);
}


static void push_queue(lnapp_conf_t *p_conf, queue_fulfill_t *pFulfill)
{
    pthread_mutex_lock(&p_conf->mux_fulque);

    queue_fulfill_t *p = p_conf->p_fulfill_queue;
    queue_fulfill_t *q = p;
    while (p != NULL) {
        q = p;
        p = p->p_next;
    }
    if (q == NULL) {
        //最初からNULL
        p_conf->p_fulfill_queue = pFulfill;
    } else {
        q->p_next = pFulfill;
    }
    pFulfill->p_next = NULL;

    pthread_mutex_unlock(&p_conf->mux_fulque);
}


static queue_fulfill_t *pop_queue(lnapp_conf_t *p_conf)
{
    pthread_mutex_lock(&p_conf->mux_fulque);

    queue_fulfill_t *p = p_conf->p_fulfill_queue;
    if ((p != NULL) && (p->p_next != NULL)) {
        p_conf->p_fulfill_queue = p->p_next;
    } else {
        p_conf->p_fulfill_queue = NULL;
    }

    pthread_mutex_unlock(&p_conf->mux_fulque);
    return p;
}


/** イベント発生によるスクリプト実行
 *
 *
 */
static void call_script(event_t event, const char *param)
{
    DBG_PRINTF("event=0x%02x\n", (int)event);

    struct stat buf;
    int ret = stat(M_SCRIPT[event], &buf);
    if ((ret == 0) && (buf.st_mode & S_IXUSR)) {
        char *cmdline = (char *)APP_MALLOC(128 + strlen(param));    //APP_FREE: この中
        sprintf(cmdline, "%s %s", M_SCRIPT[event], param);
        DBG_PRINTF("cmdline: %s\n", cmdline);
        system(cmdline);
        APP_FREE(cmdline);      //APP_MALLOC: この中
    }
}


/** onion fail reason文字列設定
 *
 *
 */
static void set_onionerr_str(char *pStr, const ucoin_buf_t *pBuf)
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
    };

    uint16_t err_reason = ((uint16_t)pBuf->buf[0] << 8) | pBuf->buf[1];
    const char *p_str = NULL;
    for (size_t lp = 0; lp < ARRAY_SIZE(ONIONERR); lp++) {
        if (err_reason == ONIONERR[lp].err) {
            p_str = ONIONERR[lp].str;
            break;
        }
    }
    if (p_str != NULL) {
        strcpy(pStr, p_str);
    } else {
        sprintf(pStr, "unknown reason[%04x]", err_reason);
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
        char date[50];
        struct tm tmval;
        time_t now = time(NULL);
        size_t len_max = sizeof(date) + strlen(pErrStr) + 128;

        gmtime_r(&now, &tmval);
        strftime(date, sizeof(date), "%d %b %Y %T %z", &tmval);

        p_conf->p_errstr = (char *)APP_MALLOC(len_max);        //APP_FREE: thread_main_start()
        sprintf(p_conf->p_errstr, "[%s]%s", date, pErrStr);
        DBG_PRINTF("%s\n", p_conf->p_errstr);

        // method: error
        // $1: short_channel_id
        // $2: node_id
        // $3: err_str
        char *param = (char *)APP_MALLOC(len_max);      //APP_FREE: この中
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
        misc_bin2str(node_id, ln_node_get()->keys.pub, UCOIN_SZ_PUBKEY);
        sprintf(param, "%" PRIx64 " %s "
                    "\"%s\"",
                    ln_short_channel_id(p_conf->p_self), node_id,
                    p_conf->p_errstr);
        call_script(M_EVT_ERROR, param);
        APP_FREE(param);        //APP_MALLOC: この中
    }
}



static void add_routelist(lnapp_conf_t *p_conf, const payment_conf_t *pPayConf, uint64_t HtlcId)
{
#ifdef USE_LINUX_LIST
    routelist_t *rt = (routelist_t *)APP_MALLOC(sizeof(routelist_t));       //APP_FREE: del_routelist()

    rt->route = *pPayConf;
    rt->htlc_id = HtlcId;
    LIST_INSERT_HEAD(&p_conf->routing_head, rt, list);
    DBG_PRINTF("htlc_id: %" PRIu64 "\n", HtlcId);

    print_routelist(p_conf);
#else
    if (p_conf->routing == NULL) {
        p_conf->routing = (routelist_t *)APP_MALLOC(sizeof(routelist_t));
    }

    routelist_t *route = p_conf->routing;

    while (route->p_next != NULL) {
        DBG_PRINTF("htlc_id: %" PRIu64 "\n", route->htlc_id);
        route = route->p_next;
    }
    if (route->p_route != NULL) {
        route->p_next = (routelist_t *)APP_MALLOC(sizeof(routelist_t));
        route = route->p_next;
    }
    route->p_route = (payment_conf_t *)APP_MALLOC(sizeof(payment_conf_t));
    memcpy(route->p_route, pPayConf, sizeof(payment_conf_t));
    route->htlc_id = HtlcId;
    route->p_next = NULL;
#endif
}


static const payment_conf_t* get_routelist(lnapp_conf_t *p_conf, uint64_t HtlcId)
{
#ifdef USE_LINUX_LIST
    routelist_t *p;
    DBG_PRINTF("START:htlc_id: %" PRIu64 "\n", HtlcId);

    p = LIST_FIRST(&p_conf->routing_head);
    while (p != NULL) {
        DBG_PRINTF("htlc_id: %" PRIu64 "\n", p->htlc_id);
        if (p->htlc_id == HtlcId) {
            DBG_PRINTF("HIT:htlc_id: %" PRIu64 "\n", HtlcId);
            break;
        }
        p = LIST_NEXT(p, list);
    }
    if (p != NULL) {
        return &p->route;
    } else {
        return NULL;
    }
#else
    if (p_conf->routing == NULL) {
        return NULL;
    }

    routelist_t *route = p_conf->routing;

    while (route->p_route != NULL) {
        DBG_PRINTF("[%d]htlc_id: %" PRIu64 "\n", __LINE__, p->htlc_id);
        if (route->htlc_id == HtlcId) {
            DBG_PRINTF("*[%d]GET htlc_id: %" PRIu64 "\n", __LINE__, p->htlc_id);
            break;
        }
        if (route->p_next == NULL) {
            DBG_PRINTF("[%d]not found\n", __LINE__);
            return NULL;
        }
        route = route->p_next;
    }

    return route->p_route;
#endif
}


static void del_routelist(lnapp_conf_t *p_conf, uint64_t HtlcId)
{
#ifdef USE_LINUX_LIST
    struct routelist_t *p;

    p = LIST_FIRST(&p_conf->routing_head);
    while (p != NULL) {
        if (p->htlc_id == HtlcId) {
            DBG_PRINTF("htlc_id: %" PRIu64 "\n", HtlcId);
            break;
        }
        p = LIST_NEXT(p, list);
    }
    if (p != NULL) {
        LIST_REMOVE(p, list);
        APP_FREE(p);
    }

    print_routelist(p_conf);
#else
    if (p_conf->routing == NULL) {
        return;
    }

    routelist_t *route = p_conf->routing;
    routelist_t *prev_route = NULL;

    while (route->p_route != NULL) {
        DBG_PRINTF("[%d]htlc_id: %" PRIu64 "\n", __LINE__, route->htlc_id);
        if (route->htlc_id == HtlcId) {
            DBG_PRINTF("*[%d]htlc_id: %" PRIu64 "\n", __LINE__, route->htlc_id);
            break;
        }
        if (route->p_next == NULL) {
            DBG_PRINTF("[%d]not found\n", __LINE__);
            return;
        }
        prev_route = route;
        route = route->p_next;
    }

    if (route->p_route != NULL) {
        DBG_PRINTF("*[%d]DEL htlc_id: %" PRIu64 "\n", __LINE__, route->htlc_id);
        APP_FREE(route->p_route);
        route->p_route = NULL;
        if (prev_route != NULL) {
            //前がある
            prev_route->p_next = route->p_next;
        } else {
            p_conf->routing = route->p_next;
        }
        if (route != p_conf->routing) {
            APP_FREE(route);
        }
    }
#endif
}

#ifdef USE_LINUX_LIST
static void print_routelist(lnapp_conf_t *p_conf)
{
    routelist_t *p;

    DBG_PRINTF("------------------------------------\n");
    p = LIST_FIRST(&p_conf->routing_head);
    while (p != NULL) {
        DBG_PRINTF("htlc_id: %" PRIu64 "\n", p->htlc_id);
        p = LIST_NEXT(p, list);
    }
    DBG_PRINTF("------------------------------------\n");
}


static void clear_routelist(lnapp_conf_t *p_conf)
{
    routelist_t *p;

    p = LIST_FIRST(&p_conf->routing_head);
    while (p != NULL) {
        DBG_PRINTF("[%d]htlc_id: %" PRIu64 "\n", __LINE__, p->htlc_id);
        routelist_t *tmp = LIST_NEXT(p, list);
        LIST_REMOVE(p, list);
        APP_FREE(p);
        p = tmp;
    }
}
#endif


/** キューに追加(送金リトライ)
 *
 * @param[in,out]       p_conf
 * @param[in]           pPayHash
 */
static void push_pay_retry_queue(lnapp_conf_t *p_conf, const uint8_t *pPayHash)
{
    //キューにためる(payment retry)
    DBG_PRINTF("payment_hash: ");
    DUMPBIN(pPayHash, LN_SZ_HASH);

    queue_fulfill_t *fulfill = (queue_fulfill_t *)APP_MALLOC(sizeof(queue_fulfill_t));      //APP_FREE: cb_htlc_changed()
    fulfill->type = QTYPE_PAY_RETRY;
    fulfill->id = 0;
    ucoin_buf_alloccopy(&fulfill->buf, pPayHash, LN_SZ_HASH);
    push_queue(p_conf, fulfill);
}


/** 送金リトライ要求
 *
 * @param[in]   pPayHash
 */
static void pay_retry(const uint8_t *pPayHash)
{
    char *p_invoice;
    bool ret = ln_db_annoskip_invoice_load(&p_invoice, pPayHash);     //p_invoiceはmalloc()される
    if (ret) {
        DBG_PRINTF("invoice:%s\n", p_invoice);
        char *json = (char *)APP_MALLOC(8192);      //APP_FREE: この中
        strcpy(json, "{\"method\":\"routepay\",\"params\":");
        strcat(json, p_invoice);
        strcat(json, "}");
        int retval = misc_sendjson(json, "127.0.0.1", cmd_json_get_port());
        DBG_PRINTF("retval=%d\n", retval);
        APP_FREE(json);     //APP_MALLOC: この中
        free(p_invoice);
    }

}


/** ln_self_t内容表示(デバッグ用)
 *
 */
static void show_self_param(const ln_self_t *self, FILE *fp, int line)
{
    fprintf(fp, "\n\n=(%" PRIx64 ")============================================= %p\n", ln_short_channel_id(self), self);
    if (ln_short_channel_id(self)) {
        fprintf(fp, "short_channel_id: %0" PRIx64 "\n", ln_short_channel_id(self));
        fprintf(fp, "my node_id:   ");
        fprintf(fp, "peer node_id: ");
        ucoin_util_dumpbin(fp, self->peer_node_id, UCOIN_SZ_PUBKEY, true);
        fprintf(fp, "our_msat:   %" PRIu64 "\n", ln_our_msat(self));
        fprintf(fp, "their_msat: %" PRIu64 "\n", ln_their_msat(self));
        for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
            const ln_update_add_htlc_t *p_add = &self->cnl_add_htlc[lp];
            if (p_add->amount_msat > 0) {
                fprintf(fp, "  HTLC[%d]\n", lp);
                fprintf(fp, "    flag= %02x\n", p_add->flag);
                fprintf(fp, "      id= %" PRIx64 "\n", p_add->id);
                fprintf(fp, "    amount_msat= %" PRIu64 "\n", p_add->amount_msat);
                if (p_add->prev_short_channel_id) {
                    fprintf(fp, "    from:        %" PRIx64 ": %" PRIu64 "\n", p_add->prev_short_channel_id, p_add->prev_id);
                }
            }
        }
    } else {
        fprintf(fp, "no channel\n");
    }
    fprintf(fp, "=(%d)=============================================\n\n\n", line);
}
