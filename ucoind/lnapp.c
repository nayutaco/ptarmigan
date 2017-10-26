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
 *  @note
 *                +-------------+  create
 *                | main thread |<-------- p2p_svr/cli
 *                |             |
 *                +--+-------+--+
 *            create |       | create
 *                   v       v
 *      +-------------+     +-------------+
 *      | recv thread |     | poll thread |
 *      |             |     |             |
 *      +-------------+     +-------------+
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

#include "cJSON.h"

#include "ucoind.h"
#include "lnapp.h"
#include "conf.h"
#include "jsonrpc.h"
#include "ln_db.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_WAIT_MUTEX_SEC        (1)         //mMuxSeqのロック解除待ち間隔[sec]
#define M_WAIT_POLL_SEC         (10)        //監視スレッドの待ち間隔[sec]
#define M_WAIT_PING_SEC         (60)        //ping送信待ち[sec](pingは30秒以上の間隔をあけること)
#define M_WAIT_ANNO_SEC         (30)        //監視スレッドでのannounce処理間隔[sec]
#define M_WAIT_MUTEX_MSEC       (100)       //mMuxSeqのロック解除待ち間隔[msec]
#define M_WAIT_RECV_MULTI_MSEC  (1000)      //複数パケット受信した時の処理間隔[msec]
#define M_WAIT_RECV_TO_MSEC     (100)       //socket受信待ちタイムアウト[msec]

//デフォルト値
//  announcement
#define M_CLTV_EXPIRY_DELTA             (36)
#define M_HTLC_MINIMUM_MSAT_ANNO        (0)
#define M_FEE_BASE_MSAT                 (10)
#define M_FEE_PROP_MILLIONTHS           (100)

//  establish
#define M_DUST_LIMIT_SAT                (546)
#define M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT (UINT64_MAX)
#define M_CHANNEL_RESERVE_SAT           (700)
#define M_HTLC_MINIMUM_MSAT_EST         (0)
#define M_FEERATE_PER_KW                (7500)
#define M_TO_SELF_DELAY                 (40)
#define M_MAX_ACCEPTED_HTLCS            (LN_HTLC_MAX)
#define M_MIN_DEPTH                     (1)

#define M_ANNOSIGS_CONFIRM      (6)         ///< announcement_signaturesを送信するconfirmation
                                            //      BOLT仕様は6

#define M_BLK_FEEESTIMATE       (6)         ///< estimatefeeのブロック数(2以上)

//lnapp_conf_t.flag_ope
#define OPE_COMSIG_SEND         (0x01)      ///< commitment_signed受信済み

#define M_SCRIPT_DIR            "./script/"

#if 1

#define MM_MALLOC(sz)       malloc(sz)
#define MM_FREE(p)          free(p)

#else

static int sss_cnt;
#define MM_MALLOC(sz)       ucoin_dbg_malloc(sz, __LINE__)
#define MM_FREE(p)          ucoin_dbg_free(p, __LINE__)

void *ucoin_dbg_malloc(size_t size, int line)
{
    void *p = malloc(size);
    if (p) {
        sss_cnt++;
        printf("[%d]DBGmalloc: %p(%d)\n", line, p, sss_cnt);
    }
    return p;
}


void ucoin_dbg_free(void *ptr, int line)
{
    if (ptr) {
        sss_cnt--;
        printf("[%d]DBGfree: %p(%d)\n", line, ptr, sss_cnt);
    }
    free(ptr);
}
#endif

/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
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
        QTYPE_FWD_ADD_HTLC,
        QTYPE_BWD_FULFILL_HTLC,
        QTYPE_BWD_FAIL_HTLC
    }               type;
    uint64_t        id;                     ///< add_htlc: short_channel_id
                                            ///< fulfill_htlc, fail_htlc: HTLC id
    ucoin_buf_t     buf;
    struct queue_fulfill_t  *p_next;
} queue_fulfill_t;


//event
typedef enum {
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

static volatile bool    mLoop;              //true:チャネル有効

static ln_node_t        *mpNode;
static ln_anno_default_t    mAnnoDef;       ///< announcementデフォルト値

//シーケンスのmutex
static pthread_mutexattr_t mMuxAttr;
static pthread_mutex_t mMuxSeq;
static volatile enum {
    MUX_NONE,
    MUX_PAYMENT=0x01,               ///< 送金開始
    MUX_CHG_HTLC=0x02,              ///< HTLC変更中
    MUX_COMSIG=0x04,                ///< Commitment Signed処理中
    //MUX_SEND_FULFILL_HTLC=0x40,     ///< fulfill_htlc送信済み
    //MUX_RECV_FULFILL_HTLC=0x80,     ///< fulfill_htlc受信済み
} mMuxTiming;


static const char *M_SCRIPT[] = {
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
static bool send_open_channel(lnapp_conf_t *p_conf);

static void *thread_recv_start(void *pArg);
static void recv_node_proc(lnapp_conf_t *p_conf);
static uint16_t recv_peer(lnapp_conf_t *p_conf, uint8_t *pBuf, uint16_t Len);

static void *thread_poll_start(void *pArg);
static void poll_ping(lnapp_conf_t *p_conf);
static void poll_funding_wait(lnapp_conf_t *p_conf);
static void poll_normal_operating(lnapp_conf_t *p_conf);

static bool set_request_recvproc(lnapp_conf_t *p_conf, recv_proc_t cmd, uint16_t Len, void *pData);

static bool fwd_payment_forward(lnapp_conf_t *pAppConf);
static bool fwd_fulfill_backward(lnapp_conf_t *pAppConf);
static bool fwd_fail_backward(lnapp_conf_t *pAppConf);

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
static void cb_closed(lnapp_conf_t *p_conf, void *p_param);
static void cb_send_req(lnapp_conf_t *p_conf, void *p_param);

static void stop_threads(lnapp_conf_t *p_conf);
static void send_peer_raw(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf);
static void send_peer_noise(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf);
static void send_channel_anno(lnapp_conf_t *p_conf, bool force);
static void send_node_anno(lnapp_conf_t *p_conf, bool force);

static bool db_del_channel(ln_self_t *self, bool bRemove);

static void set_establish_default(lnapp_conf_t *p_conf, const uint8_t *pNodeId);
static void set_changeaddr(ln_self_t *self, uint64_t commit_fee);
static void wait_mutex_lock(uint8_t Flag);
static void wait_mutex_unlock(uint8_t Flag);
static void push_queue(lnapp_conf_t *p_conf, queue_fulfill_t *pFulfill);
static queue_fulfill_t *pop_queue(lnapp_conf_t *p_conf);
static void call_script(event_t event, const char *param);
static void show_self_param(const ln_self_t *self, FILE *fp, int line);


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

    mkdir(FNAME_DIR, 0755);
}


void lnapp_start(lnapp_conf_t *pAppConf)
{
    pthread_create(&pAppConf->th, NULL, &thread_main_start, pAppConf);
}


void lnapp_stop(lnapp_conf_t *pAppConf)
{
    pAppConf->loop = false;
}


//初回ONIONパケット作成
bool lnapp_payment(lnapp_conf_t *pAppConf, const payment_conf_t *pPay)
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
    ucoin_buf_t buf_bolt;
    uint8_t session_key[UCOIN_SZ_PRIVKEY];
    ln_self_t *p_self = pAppConf->p_self;

    ucoin_buf_init(&buf_bolt);
    if (pPay->hop_datain[0].short_channel_id != ln_short_channel_id(p_self)) {
        SYSLOG_ERR("%s(): short_channel_id mismatch", __func__);
        fprintf(PRINTOUT, "fail: short_channel_id mismatch\n");
        fprintf(PRINTOUT, "    hop  : %" PRIx64 "\n", pPay->hop_datain[0].short_channel_id);
        fprintf(PRINTOUT, "    mine : %" PRIx64 "\n", ln_short_channel_id(p_self));
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

    ret = ln_create_add_htlc(p_self, &buf_bolt,
                        onion,
                        pPay->hop_datain[0].amt_to_forward,
                        pPay->hop_datain[0].outgoing_cltv_value,
                        pPay->payment_hash,
                        0,
                        &secrets);  //secretsはln.cで管理するので、ここでは解放しない
    if (!ret) {
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
        // $2: amt_to_forward
        // $3: outgoing_cltv_value
        // $4: payment_hash
        char param[256];
        sprintf(param, "%" PRIu64 " %" PRIu64 " %" PRIu32 " ",
                    ln_short_channel_id(pAppConf->p_self),
                    pPay->hop_datain[0].amt_to_forward,
                    pPay->hop_datain[0].outgoing_cltv_value);
        misc_bin2str(param + strlen(param), pPay->payment_hash, LN_SZ_HASH);
        call_script(M_EVT_PAYMENT, param);
    } else {
        DBG_PRINTF("fail\n");
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
    fwd_proc_add_t *p_add = (fwd_proc_add_t *)MM_MALLOC(sizeof(fwd_proc_add_t));
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

    fwd_proc_fulfill_t *p_fwd_fulfill = (fwd_proc_fulfill_t *)MM_MALLOC(sizeof(fwd_proc_fulfill_t));   //free: fwd_fulfill_backward()
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

    fwd_proc_fail_t *p_fwd_fail = (fwd_proc_fail_t *)MM_MALLOC(sizeof(fwd_proc_fail_t));   //free: fwd_fail_backward()
    p_fwd_fail->id = pFail->id;
    ucoin_buf_alloccopy(&p_fwd_fail->reason, pFail->p_reason->buf, pFail->p_reason->len);
    ucoin_buf_alloccopy(&p_fwd_fail->shared_secret,
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

    if (p_self->htlc_num != 0) {
        SYSLOG_ERR("%s(): you have some HTLCs", __func__);
        return false;
    }

    //feeと送金先
    cb_shutdown_recv(pAppConf, NULL);

    show_self_param(p_self, PRINTOUT, __LINE__);

    ucoin_buf_init(&buf_bolt);
    ret = ln_create_shutdown(p_self, &buf_bolt);
    assert(ret);

    send_peer_noise(pAppConf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //TODO: shutdownを送信した方がclosing transactionを公開する
    pAppConf->shutdown_sent = true;

    if (ret) {
        show_self_param(p_self, PRINTOUT, __LINE__);
    }

    DBG_PRINTF("mux_proc: end\n");
    pthread_mutex_unlock(&pAppConf->mux_proc);
    DBGTRACE_END

    return ret;
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
    if (!pAppConf->loop) {
        //DBG_PRINTF("This AppConf not working\n");
        return;
    }

    ln_self_t *p_self = pAppConf->p_self;

    cJSON *result = cJSON_CreateObject();

    if (p_self && ln_short_channel_id(p_self)) {
        show_self_param(p_self, PRINTOUT, __LINE__);

        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("established"));

        //peer node_id
        misc_bin2str(str, p_self->peer_node.node_id, UCOIN_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //funding_tx
        misc_bin2str_rev(str, ln_funding_txid(pAppConf->p_self), UCOIN_SZ_TXID);
        cJSON_AddItemToObject(result, "fundindg_tx", cJSON_CreateString(str));
        //confirmation
        uint32_t confirm = jsonrpc_get_confirmation(ln_funding_txid(pAppConf->p_self));
        cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));

        //short_channel_id
        sprintf(str, "%016" PRIx64, ln_short_channel_id(p_self));
        cJSON_AddItemToObject(result, "short_channel_id", cJSON_CreateString(str));
        //our_msat
        cJSON_AddItemToObject(result, "our_msat", cJSON_CreateNumber64(ln_our_msat(p_self)));
        //their_msat
        cJSON_AddItemToObject(result, "their_msat", cJSON_CreateNumber64(ln_their_msat(p_self)));
    } else if (pAppConf->funding_waiting) {
        char str[256];

        cJSON_AddItemToObject(result, "status", cJSON_CreateString("wait_minimum_depth"));

        //peer node_id
        misc_bin2str(str, p_self->peer_node.node_id, UCOIN_SZ_PUBKEY);
        cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(str));
        //funding_tx
        misc_bin2str_rev(str, ln_funding_txid(pAppConf->p_self), UCOIN_SZ_TXID);
        cJSON_AddItemToObject(result, "fundindg_tx", cJSON_CreateString(str));
        //confirmation
        uint32_t confirm = jsonrpc_get_confirmation(ln_funding_txid(pAppConf->p_self));
        cJSON_AddItemToObject(result, "confirmation", cJSON_CreateNumber(confirm));
    } else {
        cJSON_AddItemToObject(result, "status", cJSON_CreateString("disconnected"));
    }
    cJSON_AddItemToArray(pResult, result);
}


bool lnapp_is_looping(const lnapp_conf_t *pAppConf)
{
    return pAppConf->loop;
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

    //announcementデフォルト値
    anno_conf_t aconf;
    ret = load_anno_conf("anno.conf", &aconf);
    if (ret) {
        mAnnoDef.cltv_expiry_delta = aconf.cltv_expiry_delta;
        mAnnoDef.htlc_minimum_msat = aconf.htlc_minimum_msat;
        mAnnoDef.fee_base_msat = aconf.fee_base_msat;
        mAnnoDef.fee_prop_millionths = aconf.fee_prop_millionths;
    } else {
        mAnnoDef.cltv_expiry_delta = M_CLTV_EXPIRY_DELTA;
        mAnnoDef.htlc_minimum_msat = M_HTLC_MINIMUM_MSAT_ANNO;
        mAnnoDef.fee_base_msat = M_FEE_BASE_MSAT;
        mAnnoDef.fee_prop_millionths = M_FEE_PROP_MILLIONTHS;
    }

    //スレッド
    pthread_t   th_peer;        //peer受信
    pthread_t   th_poll;        //トランザクション監視

    if ((p_conf->cmd == DCMD_NONE) || (p_conf->cmd == DCMD_CREATE)) {
        uint8_t     seed[UCOIN_SZ_PRIVKEY];

        //seed作成
        SYSLOG_INFO("ln_self_t initialize");
        do {
            ucoin_util_random(seed, UCOIN_SZ_PRIVKEY);
        } while (!ucoin_keys_chkpriv(seed));
        ln_init(&my_self, mpNode, seed, &mAnnoDef, notify_cb);
    } else {
        ln_init(&my_self, mpNode, NULL, &mAnnoDef, notify_cb);
    }

    p_conf->p_self = &my_self;
    p_conf->p_establish = NULL;
    p_conf->last_cnl_anno_sent = 0;
    p_conf->last_node_anno_sent = 0;
    p_conf->ping_counter = 0;
    p_conf->first = true;
    p_conf->shutdown_sent = false;
    p_conf->funding_waiting = false;
    p_conf->funding_confirm = 0;

    pthread_cond_init(&p_conf->cond, NULL);
    pthread_mutex_init(&p_conf->mux, NULL);
    pthread_mutex_init(&p_conf->mux_proc, NULL);
    pthread_mutex_init(&p_conf->mux_send, NULL);
    pthread_mutex_init(&p_conf->mux_fulque, NULL);

    p_conf->fwd_proc_rpnt = 0;
    p_conf->fwd_proc_wpnt = 0;
    p_conf->loop = true;

    //noise protocol handshake
    ret = noise_handshake(p_conf);
    if (!ret) {
        goto LABEL_SHUTDOWN;
    }

    /////////////////////////
    // handshake完了
    //      server動作時、p_conf->node_idに相手node_idが入っている
    /////////////////////////

    bool detect = false;
    if (p_conf->cmd != DCMD_CREATE) {
        //既存チャネル接続の可能性あり
        detect = ln_node_search_channel_id(&my_self, p_conf->node_id);
        if (detect) {
            DBG_PRINTF("    チャネルDB読込み\n");
        } else {
            DBG_PRINTF("    新規\n");
        }
        DUMPBIN(p_conf->node_id, UCOIN_SZ_PUBKEY);
    }
    if (!ret) {
        goto LABEL_SHUTDOWN;
    }

    //
    //my_selfへの設定はこれ以降に行う
    //

    //peer受信スレッド
    pthread_create(&th_peer, NULL, &thread_recv_start, p_conf);

    //監視対象の有無にかかわらず立ち上げておく
    pthread_create(&th_poll, NULL, &thread_poll_start, p_conf);


    //init送受信
    {
        ucoin_buf_t buf_bolt;
        ucoin_buf_init(&buf_bolt);
        ret = ln_create_init(&my_self, &buf_bolt);
        if (!ret) {
            goto LABEL_JOIN;
        }
        send_peer_noise(p_conf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    }

    //コールバックでのINIT受信通知待ち
    pthread_mutex_lock(&p_conf->mux);
    while (p_conf->loop && p_conf->first) {
        //init受信待ち合わせ(*1)
        pthread_cond_wait(&p_conf->cond, &p_conf->mux);
    }
    pthread_mutex_unlock(&p_conf->mux);
    DBG_PRINTF("init交換完了\n\n");


    // Establishチェック
    if ((p_conf->initiator) && (p_conf->cmd == DCMD_CREATE)) {
        DBG_PRINTF("Establish開始\n");
        set_establish_default(p_conf, p_conf->node_id);
        send_open_channel(p_conf);
    } else {
        if (detect) {
            if (ln_short_channel_id(p_conf->p_self) != 0) {
                DBG_PRINTF("Establish済み : %d\n", p_conf->cmd);
                send_reestablish(p_conf);
                DBG_PRINTF("reestablish交換完了\n\n");

                //channel_update更新
                ucoin_buf_t buf_upd;
                ucoin_buf_init(&buf_upd);
                ret = ln_update_channel_update(p_conf->p_self, &buf_upd);
                if (ret) {
                    send_peer_noise(p_conf, &buf_upd);
                } else {
                    DBG_PRINTF("channel_announcement再送\n");
                    send_channel_anno(p_conf, true);
                }
                ucoin_buf_free(&buf_upd);
            } else {
                DBG_PRINTF("funding_tx監視開始\n");
                DUMPTXID(ln_funding_txid(p_conf->p_self));

                set_establish_default(p_conf, p_conf->node_id);
                p_conf->funding_min_depth = ln_minimum_depth(p_conf->p_self);
                p_conf->funding_waiting = true;
            }
        } else {
            DBG_PRINTF("Establish待ち\n");
            set_establish_default(p_conf, p_conf->node_id);
        }
    }

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
    if (p_conf->p_funding) {
        MM_FREE(p_conf->p_funding);
    }
    if (p_conf->p_establish) {
        MM_FREE(p_conf->p_establish);
    }
    for (int lp = 0; lp < APP_FWD_PROC_MAX; lp++) {
        MM_FREE(p_conf->fwd_proc[lp].p_data);
    }
    ln_term(p_conf->p_self);
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
    p_conf->p_establish = NULL;

    //channel_reestablish送信
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    bool ret = ln_create_channel_reestablish(p_conf->p_self, &buf_bolt);
    assert(ret);

    //待ち合わせ解除(*3)用
    p_conf->first = true;

    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //コールバックでのchannel_reestablish受信通知待ち
    DBG_PRINTF("channel_reestablish受信\n");
    pthread_mutex_lock(&p_conf->mux);
    while (p_conf->loop && p_conf->first) {
        //channel_reestablish受信待ち合わせ(*3)
        pthread_cond_wait(&p_conf->cond, &p_conf->mux);
    }
    pthread_mutex_unlock(&p_conf->mux);

    return ret;
}


/** open_channel送信
 *
 */
static bool send_open_channel(lnapp_conf_t *p_conf)
{
    p_conf->p_funding->p_opening = (opening_t *)MM_MALLOC(sizeof(opening_t));  //free: cb_established()

    //Establish開始
    DBG_PRINTF("  signaddr: %s\n", p_conf->p_funding->signaddr);
    DBG_PRINTF("  funding_sat: %" PRIu64 "\n", p_conf->p_funding->funding_sat);
    DBG_PRINTF("  push_sat: %" PRIu64 "\n", p_conf->p_funding->push_sat);

    //open_channel
    char wif[UCOIN_SZ_WIF_MAX];
    uint64_t fundin_sat;

    bool ret = jsonrpc_dumpprivkey(wif, p_conf->p_funding->signaddr);
    if (ret) {
        ret = jsonrpc_getnewaddress(p_conf->p_funding->p_opening->chargeaddr);
    } else {
        SYSLOG_ERR("%s(): jsonrpc_dumpprivkey", __func__);
    }
    assert(ret);

    if (ret) {
        //TODO: unspentしか成功しないので、再開にうまく利用できないものか
        ret = jsonrpc_getxout(&fundin_sat, p_conf->p_funding->txid, p_conf->p_funding->txindex);
    } else {
        SYSLOG_ERR("%s(): jsonrpc_getnewaddress", __func__);
    }
    if (ret) {
        //estimate fee
        uint64_t feerate;
        bool ret = jsonrpc_estimatefee(&feerate, M_BLK_FEEESTIMATE);
        //BOLT#2
        //  feerate_per_kw indicates the initial fee rate by 1000-weight
        //  (ie. 1/4 the more normally-used 'feerate per kilobyte')
        //  which this side will pay for commitment and HTLC transactions
        //  as described in BOLT #3 (this can be adjusted later with an update_fee message).
        feerate = (uint32_t)(feerate / 4);
#warning issue#46
        if (!ret || (feerate < M_FEERATE_PER_KW)) {
            // https://github.com/nayutaco/ptarmigan/issues/46
            DBG_PRINTF("fee_per_rate is too low? :%lu\n", feerate);
            feerate = M_FEERATE_PER_KW;
        }
        DBG_PRINTF2("estimatefee=%" PRIu64 "\n", feerate);

        ucoin_util_wif2keys(&p_conf->p_funding->p_opening->fundin_keys, wif);
        //TODO: データ構造に無駄が多い
        //      スタックに置けないものを詰めていったせいだが、整理したいところだ。
        //
        //p_conf->p_funding以下のアドレスを下位層に渡しているので、
        //Establishが完了するまでメモリを解放しないこと
        p_conf->p_funding->p_opening->fundin.p_txid = p_conf->p_funding->txid;
        p_conf->p_funding->p_opening->fundin.index = p_conf->p_funding->txindex;
        p_conf->p_funding->p_opening->fundin.amount = fundin_sat;
        p_conf->p_funding->p_opening->fundin.p_change_pubkey = NULL;
        p_conf->p_funding->p_opening->fundin.p_change_addr = p_conf->p_funding->p_opening->chargeaddr;
        p_conf->p_funding->p_opening->fundin.p_keys = &p_conf->p_funding->p_opening->fundin_keys;
        p_conf->p_funding->p_opening->fundin.b_native = false;        //nested in BIP16

        DBG_PRINTF("open_channel: fund_in amount=%" PRIu64 "\n", fundin_sat);
        ucoin_buf_t buf_bolt;
        ucoin_buf_init(&buf_bolt);
        ret = ln_create_open_channel(p_conf->p_self, &buf_bolt,
                        &p_conf->p_funding->p_opening->fundin,
                        p_conf->p_funding->funding_sat,
                        p_conf->p_funding->push_sat,
                        (uint32_t)feerate);
        assert(ret);

        DBG_PRINTF("SEND: oepn_channel\n");
        send_peer_noise(p_conf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    } else {
        SYSLOG_WARN("fail through: jsonrpc_getxout");
        DUMPTXID(p_conf->p_funding->txid);
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
            p_conf->ping_counter = 0;
        } else {
            break;
        }

        if (ret) {
            DBG_PRINTF("type=%02x%02x\n", buf_recv.buf[0], buf_recv.buf[1]);
            pthread_mutex_lock(&p_conf->mux_proc);
            ret = ln_recv(p_conf->p_self, buf_recv.buf, buf_recv.len);
            DBG_PRINTF("ln_recv() result=%d\n", ret);
            assert(ret);
            DBG_PRINTF("mux_proc: end\n");
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
        ret = fwd_payment_forward(p_conf);
        break;
    case FWD_PROC_FULFILL:
        DBG_PRINTF("FWD_PROC_FULFILL\n");
        ret = fwd_fulfill_backward(p_conf);
        break;
    case FWD_PROC_FAIL:
        DBG_PRINTF("FWD_PROC_FAIL\n");
        ret = fwd_fail_backward(p_conf);
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

                set_request_recvproc(p_conf, INNER_SEND_ANNOUNCEMENT, 0, NULL);
            }
        }
        break;
    case INNER_SEND_ANNOUNCEMENT:
        DBG_PRINTF("INNER_SEND_ANNOUNCEMENT\n");
        send_channel_anno(p_conf, true);
        //send_node_anno(p_conf, true);
        ret = true;
        break;
    default:
        break;
    }
    if (ret) {
        //解放
        p_conf->fwd_proc[p_conf->fwd_proc_rpnt].cmd = FWD_PROC_NONE;
        MM_FREE(p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);
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

    DBG_PRINTF("sock=%d\n", p_conf->sock);

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
    int counter = M_WAIT_ANNO_SEC / M_WAIT_POLL_SEC;

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

        if (p_conf->first) {
            //まだ接続していない
            continue;
        }

        poll_ping(p_conf);

        uint32_t bak_conf = p_conf->funding_confirm;
        p_conf->funding_confirm = jsonrpc_get_confirmation(ln_funding_txid(p_conf->p_self));
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
            //  https://github.com/nayuta-ueno/lightning-rfc/blob/master/07-routing-gossip.md#requirements
            set_request_recvproc(p_conf, INNER_SEND_ANNO_SIGNS, 0, NULL);
            ln_open_announce_channel_clr(p_conf->p_self);
            ln_db_save_channel(p_conf->p_self);
        }

        counter++;
        if (counter > M_WAIT_ANNO_SEC / M_WAIT_POLL_SEC) {
            if (!p_conf->funding_waiting) {
                //未送信channel_announcementチェック
                send_channel_anno(p_conf, false);
            }
            //未送信node_announcementチェック
            send_node_anno(p_conf, false);

            counter = 0;
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
    if (p_conf->ping_counter >= M_WAIT_PING_SEC / M_WAIT_POLL_SEC) {
        ucoin_buf_t buf_ping;

        ucoin_buf_init(&buf_ping);
        bool ret = ln_create_ping(p_conf->p_self, &buf_ping);
        if (ret) {
            send_peer_noise(p_conf, &buf_ping);
            ucoin_buf_free(&buf_ping);
        } else {
            SYSLOG_ERR("%s(): pong not respond", __func__);
            stop_threads(p_conf);
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
        bool ret = jsonrpc_get_short_channel_param(&bheight, &bindex, ln_funding_txid(p_conf->p_self));
        if (ret) {
            fprintf(PRINTOUT, "bindex=%d, bheight=%d\n", bindex, bheight);
            ln_set_short_channel_id_param(self, bheight, bindex);

            //安定後
            ret = ln_funding_tx_stabled(self);
            assert(ret);
        } else {
            DBG_PRINTF("fail: jsonrpc_get_short_channel_param()\n");
        }
    }

    //DBGTRACE_END
}


//Normal Operation中
static void poll_normal_operating(lnapp_conf_t *p_conf)
{
    //DBGTRACE_BEGIN

    //funding_tx使用チェック
    uint64_t sat;
    bool ret = jsonrpc_getxout(&sat, ln_funding_txid(p_conf->p_self), ln_funding_txindex(p_conf->p_self));
    if (!ret) {
#warning Mutual Closeしか用意していないため、このルートは現在通らない
        //gettxoutはunspentを返すので、取得失敗→closing_txとして使用されたとみなす
        SYSLOG_WARN("POLL: fail gettxout for funding_tx !!!!!\n");
        DBG_PRINTF("txid: ");
        DUMPBIN(ln_funding_txid(p_conf->p_self), UCOIN_SZ_TXID);
        DBG_PRINTF("txindex: %d\n", ln_funding_txindex(p_conf->p_self));

        if (p_conf->funding_confirm > 0) {
            //正常:gettransactionもOKなので、削除可能
            db_del_channel(p_conf->p_self, false);
        } else {
            //異常:gettransactionできないので、outpointが存在しない？
            SYSLOG_ERR("%s(): POLL gettransaction ????", __func__);
        }

        //ループ解除
        stop_threads(p_conf);
        return;
    }

    //DBGTRACE_END
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
static bool fwd_payment_forward(lnapp_conf_t *p_conf)
{
    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)(p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);

    wait_mutex_lock(MUX_CHG_HTLC);

    show_self_param(p_conf->p_self, PRINTOUT, __LINE__);

    //DBG_PRINTF("------------------------------: %p\n", p_fwd_add);
    //DBG_PRINTF("fwd_proc_add_t.amt_to_forward= %" PRIu64 "\n", p_fwd_add->amt_to_forward);
    //DBG_PRINTF("fwd_proc_add_t.outgoing_cltv_value= %d\n", (int)p_fwd_add->outgoing_cltv_value);
    //DBG_PRINTF("fwd_proc_add_t.next_short_channel_id= %" PRIx64 "\n", p_fwd_add->next_short_channel_id);
    //DBG_PRINTF("fwd_proc_add_t.prev_short_channel_id= %" PRIx64 "\n", p_fwd_add->prev_short_channel_id);
    //DBG_PRINTF("short_channel_id= %" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));         //current
    //DBG_PRINTF("------------------------------\n");
    ret = ln_create_add_htlc(p_conf->p_self, &buf_bolt,
                        p_fwd_add->onion_route,
                        p_fwd_add->amt_to_forward,
                        p_fwd_add->outgoing_cltv_value,
                        p_fwd_add->payment_hash,
                        p_fwd_add->prev_short_channel_id,
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

    //free(p_fwd_add);    //malloc: lnapp_forward_payment()-->recv_node_proc()で解放

    if (ret) {
        // method: forward
        // $1: short_channel_id
        // $2: amt_to_forward
        // $3: outgoing_cltv_value
        // $4: payment_hash
        char param[256];
        sprintf(param, "%" PRIu64 " %" PRIu64 " %" PRIu32 " ",
                    ln_short_channel_id(p_conf->p_self),
                    p_fwd_add->amt_to_forward,
                    p_fwd_add->outgoing_cltv_value);
        misc_bin2str(param + strlen(param), p_fwd_add->payment_hash, LN_SZ_HASH);
        call_script(M_EVT_FORWARD, param);
    }

    DBGTRACE_END

    return ret;
}


// 別ノードからの update_fullfil_htlc
static bool fwd_fulfill_backward(lnapp_conf_t *p_conf)
{
    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    fwd_proc_fulfill_t *p_fwd_fulfill = (fwd_proc_fulfill_t *)(p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);

    show_self_param(p_conf->p_self, PRINTOUT, __LINE__);

    DBG_PRINTF("preimage= ");
    DUMPBIN(p_fwd_fulfill->preimage, LN_SZ_PREIMAGE);

    ret = ln_create_fulfill_htlc(p_conf->p_self, &buf_bolt, p_fwd_fulfill->preimage);
    assert(ret);
    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);
    //free(p_fwd_fulfill);        //malloc: lnapp_backward_fulfill()-->recv_node_proc()で解放

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
        // $2: payment_preimage
        // $3: payment_hash
        char param[256];
        sprintf(param, "%" PRIu64 " ",
                    ln_short_channel_id(p_conf->p_self));
        misc_bin2str(param + strlen(param), p_fwd_fulfill->preimage, LN_SZ_PREIMAGE);

        uint8_t payment_hash[LN_SZ_HASH];
        ln_calc_preimage_hash(payment_hash, p_fwd_fulfill->preimage);
        strcat(param, " ");
        misc_bin2str(param + strlen(param), payment_hash, LN_SZ_HASH);
        call_script(M_EVT_FULFILL, param);
    }

    DBGTRACE_END

    return ret;
}


// 別ノードからの update_fail_htlc
static bool fwd_fail_backward(lnapp_conf_t *p_conf)
{
    DBGTRACE_BEGIN

    bool ret = false;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    fwd_proc_fail_t *p_fwd_fail = (fwd_proc_fail_t *)(p_conf->fwd_proc[p_conf->fwd_proc_rpnt].p_data);

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
    //free(p_fwd_fail);       //malloc: lnapp_backward_fail()-->recv_node_proc()で解放

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
        char param[256];
        sprintf(param, "%" PRIu64,
                    ln_short_channel_id(p_conf->p_self));
        call_script(M_EVT_FAIL, param);
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
    DBGTRACE_BEGIN

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
        //    LN_CB_CLOSED,               ///< closing_signed受信通知
        //    LN_CB_SEND_REQ,             ///< peerへの送信要求

        { "  LN_CB_ERROR: エラー有り", cb_error_recv },
        { "  LN_CB_INIT_RECV: init受信", cb_init_recv },
        { "  LN_CB_REESTABLISH_RECV: channel_reestablish受信", cb_channel_reestablish_recv },
        { "  LN_CB_FINDINGWIF_REQ: funding_tx WIF要求", cb_find_index_wif_req },
        { "  LN_CB_FUNDINGTX_WAIT: funding_tx confirmation待ち要求", cb_funding_tx_wait },
        { "  LN_CB_ESTABLISHED: Establish完了", cb_established },
        { "  LN_CB_CHANNEL_ANNO_RECV: channel_announcement受信", cb_channel_anno_recv },
        { "  LN_CB_NODE_ANNO_RECV: node_announcement受信通知", cb_node_anno_recv },
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
        { "  LN_CB_CLOSED: closing_signed受信", cb_closed },
        { "  LN_CB_SEND_REQ: 送信要求", cb_send_req },
    };

    if (reason < LN_CB_MAX) {
        DBG_PRINTF("%s\n", MAP[reason].p_msg);
        (*MAP[reason].func)(p_conf, p_param);
    } else {
        DBG_PRINTF("fail: invalid reason: %d\n", reason);
    }

    DBGTRACE_END
}


//LN_CB_ERROR: error受信
static void cb_error_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf; (void)p_param;
    DBG_PRINTF("no implemented\n");
    assert(0);
}


//LN_CB_INIT_RECV: init受信
static void cb_init_recv(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_init_t *p = (const ln_init_t *)p_param;

    DBG_PRINTF("globalfeatures: ");
    DUMPBIN(p->globalfeatures.buf, p->globalfeatures.len);
    DBG_PRINTF("localfeatures: ");
    DUMPBIN(p->localfeatures.buf, p->localfeatures.len);

    //init受信時に初期化
    p_conf->first = false;
    p_conf->shutdown_sent = false;

    //待ち合わせ解除(*1)
    pthread_cond_signal(&p_conf->cond);
}


//LN_CB_REESTABLISH_RECV: channel_reestablish受信
static void cb_channel_reestablish_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    //待ち合わせ解除(*3)
    p_conf->first = false;
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
    ret = jsonrpc_getnewaddress(funding_addr);
    assert(ret);
    fprintf(PRINTOUT, "fundingaddr %s\n", funding_addr);

    char wif[UCOIN_SZ_WIF_MAX];
    ret = jsonrpc_dumpprivkey(wif, funding_addr);
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
        bool ret = jsonrpc_sendraw_tx(txid, buf_tx.buf, buf_tx.len);
        if (ret) {
            DBG_PRINTF("OK\n");
        } else {
            DBG_PRINTF("NG\n");
            exit(-1);
        }
        ucoin_buf_free(&buf_tx);
    }

    //DB保存
    ln_db_save_channel(p_conf->p_self);

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

    if (p_conf->p_establish != NULL) {
        DBG_PRINTF("free establish buffer\n");
        MM_FREE(p_conf->p_establish);      //malloc: set_establish_default()
        p_conf->p_establish = NULL;
    } else {
        DBG_PRINTF("no establish buffer\n");
    }

    //下位層に渡したアドレスを解放
    if (p_conf->p_funding != NULL) {
        if (p_conf->cmd == DCMD_CREATE) {
            //ucoindで DCMD_CREATE の場合に mallocしている
            MM_FREE(p_conf->p_funding->p_opening);     //malloc: send_open_channel()
        }
        free(p_conf->p_funding);
        p_conf->p_funding = NULL;
    }

    //DB保存
    ln_db_save_channel(p_conf->p_self);

    SYSLOG_INFO("Established[%" PRIx64 "]: our_msat=%" PRIu64 ", their_msat=%" PRIu64, ln_short_channel_id(p_conf->p_self), ln_our_msat(p_conf->p_self), ln_their_msat(p_conf->p_self));

    char fname[FNAME_LEN];
    sprintf(fname, FNAME_AMOUNT_FMT, ln_short_channel_id(p_conf->p_self));
    FILE *fp = fopen(fname, "w");
    show_self_param(p_conf->p_self, fp, 0);
    fclose(fp);

    // method: established
    // $1: short_channel_id
    // $2: our_msat
    // $3: funding_txid
    char param[256];
    sprintf(param, "%" PRIu64 " %" PRIu64 " ",
                ln_short_channel_id(p_conf->p_self),
                ln_our_msat(p_conf->p_self));
    misc_bin2str_rev(param + strlen(param), ln_funding_txid(p_conf->p_self), UCOIN_SZ_TXID);
    call_script(M_EVT_ESTABLISHED, param);

    DBGTRACE_END
}


//LN_CB_CHANNEL_ANNO_RECV: channel_announcement受信
static void cb_channel_anno_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    DBGTRACE_BEGIN

    ln_cb_channel_anno_recv_t *p = (ln_cb_channel_anno_recv_t *)p_param;

    uint32_t bheight;
    uint32_t bindex;
    uint32_t vindex;
    ln_get_short_channel_id_param(&bheight, &bindex, &vindex, p->short_channel_id);

    bool unspent = jsonrpc_is_short_channel_unspent(bheight, bindex, vindex);
    if (!unspent) {
        DBG_PRINTF("fail: already spent : %016" PRIx64 "\n", p->short_channel_id);
        return;
    }
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
        p_conf->funding_confirm = jsonrpc_get_confirmation(ln_funding_txid(p_conf->p_self));
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
    ret = ln_db_load_anno_channel(&buf_bolt, ln_short_channel_id(p_conf->p_self));
    if (ret) {
        send_peer_noise(p_conf, &buf_bolt);
    } else {
        DBG_PRINTF("err\n");
    }
    ucoin_buf_free(&buf_bolt);

    //channel_update
    ret = ln_db_load_anno_channel_upd(&buf_bolt, ln_short_channel_id(p_conf->p_self), p->sort);
    if (ret) {
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

    if (p_add->amount_msat) {
        //
        //転送https://github.com/lightningnetwork/lightning-rfc
        //

        DBG_PRINTF2("  b_exit: %d\n", p_add->p_hop->b_exit);
        //転送先
        DBG_PRINTF2("  FWD: short_channel_id: %" PRIx64 "\n", p_add->p_hop->short_channel_id);
        DBG_PRINTF2("  FWD: amt_to_forward: %" PRIu64 "\n", p_add->p_hop->amt_to_forward);
        DBG_PRINTF2("  FWD: outgoing_cltv_value: %d\n", p_add->p_hop->outgoing_cltv_value);
        DBG_PRINTF2("  -------\n");
        //自分への通知
        DBG_PRINTF2("  amount_msat: %" PRIu64 "\n", p_add->amount_msat);
        DBG_PRINTF2("  cltv_expiry: %d\n", p_add->cltv_expiry);
        DBG_PRINTF2("  my fee : %" PRIu64 "\n", (uint64_t)(p_add->amount_msat - p_add->p_hop->amt_to_forward));
        DBG_PRINTF2("  cltv_delta : %" PRIu32 " - %" PRIu32" = %d\n", p_add->cltv_expiry, p_add->p_hop->outgoing_cltv_value, p_add->cltv_expiry - p_add->p_hop->outgoing_cltv_value);

        preimage_lock();
        if (p_add->p_hop->b_exit) {
            //自分宛
            DBG_PRINTF("自分宛\n");

            SYSLOG_INFO("arrive: %" PRIx64 "(%" PRIu64 " msat)", ln_short_channel_id(p_conf->p_self), p_add->amount_msat);

            //preimage-hashチェック
            uint8_t preimage_hash[LN_SZ_HASH];
            const preimage_t *p_preimage;

            int lp;
            for (lp = 0; lp < PREIMAGE_NUM; lp++) {
                p_preimage = preimage_get(lp);
                if (p_preimage->use) {
                    ln_calc_preimage_hash(preimage_hash, p_preimage->preimage);
                    if (memcmp(preimage_hash, p_add->p_payment_hash, LN_SZ_HASH) == 0) {
                        //一致
                        break;
                    }
                }
            }
            if (lp < PREIMAGE_NUM) {
                //last nodeチェック
                // https://github.com/nayuta-ueno/lightning-rfc/blob/master/04-onion-routing.md#payload-for-the-last-node
                //    * outgoing_cltv_value is set to the final expiry specified by the recipient
                //    * amt_to_forward is set to the final amount specified by the recipient
#if 0
                if ( (p_add->p_hop->amt_to_forward == p_preimage->amount) &&
                     (p_add->p_hop->outgoing_cltv_value == ln_cltv_expily_delta(p_conf->p_self)) ) {
#else
                if ( (p_add->p_hop->amt_to_forward == p_preimage->amount) &&
                     (p_add->p_hop->amt_to_forward == p_add->amount_msat) &&
                     //(p_add->p_hop->outgoing_cltv_value == ln_cltv_expily_delta(p_conf->p_self)) &&
                     (p_add->p_hop->outgoing_cltv_value == p_add->cltv_expiry)  ) {
#endif
                    DBG_PRINTF("last node OK\n");
                } else {
                    SYSLOG_ERR("%s(): last node check", __func__);
                    DBG_PRINTF("%" PRIu64 " != %" PRIu64 "\n", p_add->p_hop->amt_to_forward, p_preimage->amount);
                    //DBG_PRINTF("%" PRIu32 " != %" PRIu32 "\n", p_add->p_hop->outgoing_cltv_value, ln_cltv_expily_delta(p_conf->p_self));
                    lp = PREIMAGE_NUM;
                }
            } else {
                DBG_PRINTF("fail: preimage mismatch\n");
                DUMPBIN(p_add->p_payment_hash, LN_SZ_HASH);
            }
            if (lp < PREIMAGE_NUM) {
                //キューにためる(fulfill)
                queue_fulfill_t *fulfill = (queue_fulfill_t *)MM_MALLOC(sizeof(queue_fulfill_t));
                fulfill->type = QTYPE_BWD_FULFILL_HTLC;
                fulfill->id = p_add->id;
                ucoin_buf_alloccopy(&fulfill->buf, p_preimage->preimage, LN_SZ_PREIMAGE);
                push_queue(p_conf, fulfill);

                //preimageを使い終わったら消す
                preimage_clear(lp);

                //アプリ判定はOK
                p_add->ok = true;
            } else {
                SYSLOG_ERR("%s(): payment stop", __func__);

                //キューにためる(fail)
                queue_fulfill_t *fulfill = (queue_fulfill_t *)MM_MALLOC(sizeof(queue_fulfill_t));
                fulfill->type = QTYPE_BWD_FAIL_HTLC;
                fulfill->id = p_add->id;
                ucoin_buf_alloccopy(&fulfill->buf, p_add->p_shared_secret->buf, p_add->p_shared_secret->len);
                push_queue(p_conf, fulfill);
            }
        } else {
            //転送
            SYSLOG_INFO("forward: %" PRIx64 "(%" PRIu64 " msat) --> %" PRIx64 "(%" PRIu64 " msat)", ln_short_channel_id(p_conf->p_self), p_add->amount_msat, p_add->p_hop->short_channel_id, p_add->p_hop->amt_to_forward);

            //キューにためる(add)
            queue_fulfill_t *fulfill = (queue_fulfill_t *)MM_MALLOC(sizeof(queue_fulfill_t));
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
            memcpy(p_fwd_add->payment_hash, p_add->p_payment_hash, LN_SZ_HASH);
            ucoin_buf_alloccopy(&p_fwd_add->shared_secret, p_add->p_shared_secret->buf, p_add->p_shared_secret->len);

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
        preimage_unlock();
    }

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
        //mMuxTiming |= MUX_RECV_FULFILL_HTLC | MUX_SEND_FULFILL_HTLC;

        //フラグを立てて、相手の受信スレッドで処理してもらう
        DBG_PRINTF("戻す: %" PRIx64 ", id=%" PRIx64 "\n", p_fulfill->prev_short_channel_id, p_fulfill->id);
        backward_fulfill(p_fulfill);
    } else {
        //mMuxTiming |= MUX_RECV_FULFILL_HTLC;
        DBG_PRINTF("ここまで\n");
    }
    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);

    DBGTRACE_END
}


//LN_CB_FAIL_HTLC_RECV: update_fail_htlc受信
static void cb_fail_htlc_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_conf;
    DBGTRACE_BEGIN

    const ln_cb_fail_htlc_recv_t *p_fail = (const ln_cb_fail_htlc_recv_t *)p_param;

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
        DBG_PRINTF("fail戻す: %" PRIx64 ", id=%" PRIx64 "\n", p_fail->prev_short_channel_id, p_fail->id);
        backward_fail(p_fail);
    } else {
        DBG_PRINTF("ここまで\n");
        mMuxTiming &= ~MUX_PAYMENT;

        ucoin_buf_t reason;
        ucoin_buf_init(&reason);
        bool ret = ln_onion_failure_read(&reason, p_fail->p_shared_secret, p_fail->p_reason);
        assert(ret);

        DBG_PRINTF("  failure reason= ");
        DUMPBIN(reason.buf, reason.len);
    }
    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);

    DBGTRACE_END
}


//LN_CB_COMMIT_SIG_RECV_PREV: commitment_signed受信(前処理)
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
    ln_db_save_channel(p_conf->p_self);

    char fname[FNAME_LEN];
    sprintf(fname, FNAME_AMOUNT_FMT, ln_short_channel_id(p_conf->p_self));
    FILE *fp = fopen(fname, "w");
    show_self_param(p_conf->p_self, PRINTOUT, __LINE__);
    show_self_param(p_conf->p_self, fp, 0);
    fclose(fp);

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
            switch (p->type) {
            case QTYPE_FWD_ADD_HTLC:
                {
                    fwd_proc_add_t *p_add;

                    p_add = (fwd_proc_add_t *)p->buf.buf;
                    //DBG_PRINTF("------------------------------: %p\n", p_add);
                    //DBG_PRINTF("fwd_proc_add_t.amt_to_forward= %" PRIu64 "\n", p_add->amt_to_forward);
                    //DBG_PRINTF("fwd_proc_add_t.outgoing_cltv_value= %d\n", (int)p_add->outgoing_cltv_value);
                    //DBG_PRINTF("fwd_proc_add_t.next_short_channel_id= %" PRIx64 "\n", p_add->next_short_channel_id);      //current
                    //DBG_PRINTF("fwd_proc_add_t.prev_short_channel_id= %" PRIx64 "\n", p_add->prev_short_channel_id);      //current
                    //DBG_PRINTF("short_channel_id= %" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));         //prev
                    //DBG_PRINTF("------------------------------\n");
                    DBG_PRINTF("  --> forward add(sci=%" PRIx64 ")\n", p_add->next_short_channel_id);
                    bool ret = forward_payment(p_add);
                    if (ret) {
                        DBG_PRINTF("転送した\n");
                    } else {
                        DBG_PRINTF("転送失敗\n");
                        SYSLOG_ERR("%s(): forward", __func__);
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
                {
                    ln_cb_fail_htlc_recv_t fail;
#warning reasonダミー
                    const uint8_t dummy_reason_data[] = { 0x20, 0x02 };
                    const ucoin_buf_t dummy_reason = { (uint8_t *)dummy_reason_data, sizeof(dummy_reason_data) };

                    fail.id = p->id;
                    fail.p_reason = &dummy_reason;
                    fail.p_shared_secret = &p->buf;
                    DBG_PRINTF("  --> fail_htlc(id=%" PRId64 ")\n", fail.id);
                    lnapp_backward_fail(p_conf, &fail, true);
                }
                break;
            default:
                break;
            }
            ucoin_buf_free(&p->buf);
            MM_FREE(p);
        }
    }

    //DB保存
    ln_db_save_channel(p_conf->p_self);

    char fname[FNAME_LEN];
    sprintf(fname, FNAME_AMOUNT_FMT, ln_short_channel_id(p_conf->p_self));
    FILE *fp = fopen(fname, "w");
    show_self_param(p_conf->p_self, PRINTOUT, __LINE__);
    show_self_param(p_conf->p_self, fp, 0);
    fclose(fp);

    pthread_mutex_unlock(&mMuxSeq);
    DBG_PRINTF("  -->mMuxTiming %d\n", mMuxTiming);

    // method: htlc_changed
    // $1: short_channel_id
    // $2: our_msat
    // $3: htlc_num
    char param[256];
    sprintf(param, "%" PRIu64 " %" PRIu64 " %d",
                ln_short_channel_id(p_conf->p_self),
                ln_our_msat(p_conf->p_self),
                ln_htlc_num(p_conf->p_self));
    call_script(M_EVT_HTLCCHANGED, param);

    DBGTRACE_END
}


//LN_CB_SHUTDOWN_RECV: shutdown受信
static void cb_shutdown_recv(lnapp_conf_t *p_conf, void *p_param)
{
    (void)p_param;
    DBGTRACE_BEGIN

    //fee and addr
    //   fee_satoshis lower than or equal to the base fee of the final commitment transaction
    uint64_t commit_fee = ln_calc_default_closing_fee(p_conf->p_self);
    set_changeaddr(p_conf->p_self, commit_fee);
}


//LN_CB_CLOSED: closing_singed受信
//  コールバック後、selfはクリアされる
static void cb_closed(lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_closed_t *p_closed = (const ln_cb_closed_t *)p_param;
    uint8_t txid[UCOIN_SZ_TXID];

    if (p_conf->shutdown_sent) {
        //TODO: shutdownを送信した方がclosing transactionを公開する
        DBG_PRINTF("send closing tx\n");
        p_conf->shutdown_sent = false;

        bool ret = jsonrpc_sendraw_tx(txid, p_closed->p_tx_closing->buf, p_closed->p_tx_closing->len);
        if (ret) {
            DBG_PRINTF("OK\n");
        } else {
            SYSLOG_ERR("%s(): jsonrpc_sendraw_tx", __func__);
            assert(0);
        }
    } else {
        //処理の都合上、shutdownを受信した方はここでclosing_signedを送信する
        send_peer_noise(p_conf, p_closed->p_buf_bolt);

        DBG_PRINTF("wait closing tx\n");
        ucoin_tx_t tx;
        ucoin_tx_init(&tx);
        ucoin_tx_read(&tx, p_closed->p_tx_closing->buf, p_closed->p_tx_closing->len);
        ucoin_tx_txid(txid, &tx);
        ucoin_tx_free(&tx);
    }

    DBG_PRINTF("closing_txid: ");
    DUMPTXID(txid);

    // method: closed
    // $1: short_channel_id
    // $2: closing_txid
    char param[256];
    sprintf(param, "%" PRIu64 " ",
                ln_short_channel_id(p_conf->p_self));
    misc_bin2str_rev(param + strlen(param), txid, UCOIN_SZ_TXID);
    call_script(M_EVT_CLOSED, param);

#warning 現在はMutual Closeしかないため、DBから削除する
    db_del_channel(p_conf->p_self, true);

    //これ以上やることは無いので、channelスレッドは終了する
    stop_threads(p_conf);

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
    ssize_t sz = write(p_conf->sock, pBuf->buf, pBuf->len);
    DBG_PRINTF("Len=%d:  sent=%d\n", pBuf->len, (int)sz);
    if (sz < 0) {
        SYSLOG_ERR("%s(): send_peer_raw: %s", __func__, strerror(errno));
        assert(0);
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

    ssize_t sz = write(p_conf->sock, buf_enc.buf, buf_enc.len);
    if (sz != buf_enc.len) {
        SYSLOG_ERR("%s(): send_peer_noise: %s", __func__, strerror(errno));
        assert(0);
    }
    ucoin_buf_free(&buf_enc);

    //ping送信待ちカウンタ
    p_conf->ping_counter = 0;
}


static void send_channel_anno(lnapp_conf_t *p_conf, bool force)
{
    if (force) {
        DBG_PRINTF("force send\n");
    }

    //  DBからは、
    //      sinfo→channel_announcement→channel_update(1)→channel_update(2)
    //  の順で取得できることを前提とする
    void *p_cur;
    bool ret = ln_db_cursor_anno_channel_open(&p_cur);
    if (ret) {
        uint64_t short_channel_id;
        uint64_t target_sci = 0;        //対象short_channel_id
        char type = ' ';
        ucoin_buf_t buf_cnl;
        ln_db_channel_sinfo sinfo;
        bool forcebak = force;

        //DBG_PRINTF("current: %016" PRIx64 "\n", ln_short_channel_id(p_conf->p_self));

        ucoin_buf_init(&buf_cnl);
        memset(&sinfo, 0, sizeof(sinfo));
        while (ln_db_cursor_anno_channel_get(p_cur, &short_channel_id, &type, &buf_cnl)) {
            //DBG_PRINTF("short_channel_id= %016" PRIx64 "\n", short_channel_id);
            //DBG_PRINTF("type=%c\n", type);
            switch (type) {
            case LN_DB_CNLANNO_SINFO:
                //sinfo
                memcpy(&sinfo, buf_cnl.buf, buf_cnl.len);
                target_sci = short_channel_id;
                //DBG_PRINTF("  target sci= %016" PRIx64 "\n", target_sci);
                //DBG_PRINTF("  send_nodeid= ");
                //DUMPBIN(sinfo.send_nodeid, UCOIN_SZ_PUBKEY);
                //DBG_PRINTF("  peer nodeid= ");
                //DUMPBIN(ln_their_node_id(p_conf->p_self), UCOIN_SZ_PUBKEY);
                //DBG_PRINTF("  last_cnl_anno_sent : %" PRIu32 "\n", p_conf->last_cnl_anno_sent);
                //if ( ( (memcmp(sinfo.send_nodeid, ln_their_node_id(p_conf->p_self), UCOIN_SZ_PUBKEY) == 0) ||
                //       (target_sci == ln_short_channel_id(p_conf->p_self)) ) ) {
                //    //送信元と同じshort_channel_idの情報であれば、配信不要
                //    force = false;
                //}
                break;
            case LN_DB_CNLANNO_ANNO:
                if (force || (p_conf->last_cnl_anno_sent <= sinfo.channel_anno)) {
                    if (target_sci == short_channel_id) {
                        DBG_PRINTF("send channel_anno: %016" PRIx64 "\n", target_sci);
                        send_peer_noise(p_conf, &buf_cnl);
                    } else {
                        DBG_PRINTF("  sci mismatch: %016" PRIx64 " != %016" PRIx64 "\n", target_sci, short_channel_id);
                    }
                } else {
                    //DBG_PRINTF("  sinfo.channel_anno : %" PRIu32 "\n", sinfo.channel_anno);
                }
                break;
            case LN_DB_CNLANNO_UPD1:
                if (force || (p_conf->last_cnl_anno_sent <= sinfo.channel_upd[0])) {
                    if (target_sci == short_channel_id) {
                        DBG_PRINTF("send channel_upd1: %016" PRIx64 "\n", target_sci);
                        send_peer_noise(p_conf, &buf_cnl);
                    } else {
                        DBG_PRINTF("  sci mismatch: %016" PRIx64 " != %016" PRIx64 "\n", target_sci, short_channel_id);
                    }
                } else {
                    //DBG_PRINTF("  sinfo.channel_upd[0] : %" PRIu32 "\n", sinfo.channel_upd[0]);
                }
                break;
            case LN_DB_CNLANNO_UPD2:
                if (force || (p_conf->last_cnl_anno_sent <= sinfo.channel_upd[1])) {
                    if (target_sci == short_channel_id) {
                        DBG_PRINTF("send channel_upd2: %016" PRIx64 "\n", target_sci);
                        send_peer_noise(p_conf, &buf_cnl);
                    } else {
                        DBG_PRINTF("  sci mismatch: %016" PRIx64 " != %016" PRIx64 "\n", target_sci, short_channel_id);
                    }
                } else {
                    //DBG_PRINTF("  sinfo.channel_upd[1] : %" PRIu32 "\n", sinfo.channel_upd[1]);
                }

                //クリア
                target_sci = 0;
                type = ' ';
                memset(&sinfo, 0, sizeof(sinfo));
                force = forcebak;
                break;
            default:
                assert(0);
                break;
            }
            ucoin_buf_free(&buf_cnl);
        }
        p_conf->last_cnl_anno_sent = (uint32_t)time(NULL);
    } else {
        DBG_PRINTF("no channel_announce DB\n");
    }
    if (p_cur) {
        ln_db_cursor_anno_channel_close(p_cur);
    }
}


static void send_node_anno(lnapp_conf_t *p_conf, bool force)
{
    void *p_cur;
    bool ret = ln_db_cursor_anno_node_open(&p_cur);
    if (ret) {
        ucoin_buf_t buf_node;
        uint32_t timestamp;
        uint8_t send_nodeid[UCOIN_SZ_PUBKEY];
        uint8_t nodeid[UCOIN_SZ_PUBKEY];
        bool forcebak = force;

        ucoin_buf_init(&buf_node);
        while (ln_db_cursor_anno_node_get(p_cur, &buf_node, &timestamp, send_nodeid, nodeid)) {
            //if ( ( (memcmp(send_nodeid, ln_their_node_id(p_conf->p_self), UCOIN_SZ_PUBKEY) == 0) ||
            //       (memcmp(nodeid, ln_their_node_id(p_conf->p_self), UCOIN_SZ_PUBKEY) == 0) ) ) {
            //    //送信元と同じか、送信元自身であれば、配信不要
            //    force = false;
            //}
            if (force || (p_conf->last_node_anno_sent <= timestamp)) {
                DBG_PRINTF("  send_nodeid= ");
                DUMPBIN(send_nodeid, UCOIN_SZ_PUBKEY);
                DBG_PRINTF("  nodeid= ");
                DUMPBIN(nodeid, UCOIN_SZ_PUBKEY);
                DBG_PRINTF("  peer nodeid= ");
                DUMPBIN(ln_their_node_id(p_conf->p_self), UCOIN_SZ_PUBKEY);
                DBG_PRINTF("  last_node_anno_sent : %" PRIu32 "\n", p_conf->last_node_anno_sent);
                DBG_PRINTF("  timestamp           : %" PRIu32 "\n", timestamp);

                DBG_PRINTF("send node_anno\n");
                send_peer_noise(p_conf, &buf_node);
            }
            ucoin_buf_free(&buf_node);
            force = forcebak;
        }
        p_conf->last_node_anno_sent = (uint32_t)time(NULL);
    } else {
        DBG_PRINTF("no node_announce DB\n");
    }
    if (p_cur) {
        ln_db_cursor_anno_node_close(p_cur);
    }
}


/**************************************************************************
 * DB関連
 **************************************************************************/

/** DB削除
 *
 * @param[in]   self
 * @param[in]   bRemove     true: DB削除 / false: 削除フラグのみ
 * @note
 *      - ノード情報からの削除は、closing_signed受信時に行っている(LN_CB_CLOSEDコールバック)
 */
static bool db_del_channel(ln_self_t *self, bool bRemove)
{
    DBGTRACE_BEGIN

    bool ret;

    if (bRemove) {
        ret = ln_db_del_channel(self);
        assert(ret);
    } else {
        ln_short_channel_id_clr(self);      //削除フラグ代わり
        ln_db_save_channel(self);
        ret = true;
    }

    DBGTRACE_END

    return ret;
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
    ln_est_default_t defval;

    ret = load_establish_conf("establish.conf", &econf);
    if (ret) {
        defval.dust_limit_sat = econf.dust_limit_sat;
        defval.max_htlc_value_in_flight_msat = econf.max_htlc_value_in_flight_msat;
        defval.channel_reserve_sat = econf.channel_reserve_sat;
        defval.htlc_minimum_msat = econf.htlc_minimum_msat;
        defval.to_self_delay = econf.to_self_delay;
        defval.max_accepted_htlcs = econf.max_accepted_htlcs;
        defval.min_depth = econf.min_depth;
    } else {
        defval.dust_limit_sat = M_DUST_LIMIT_SAT;
        defval.max_htlc_value_in_flight_msat = M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT;
        defval.channel_reserve_sat = M_CHANNEL_RESERVE_SAT;
        defval.htlc_minimum_msat = M_HTLC_MINIMUM_MSAT_EST;
        defval.to_self_delay = M_TO_SELF_DELAY;
        defval.max_accepted_htlcs = M_MAX_ACCEPTED_HTLCS;
        defval.min_depth = M_MIN_DEPTH;
    }

    p_conf->p_establish = (ln_establish_t *)MM_MALLOC(sizeof(ln_establish_t));     //free: cb_established()
    ret = ln_set_establish(p_conf->p_self, p_conf->p_establish, pNodeId, &defval);
    assert(ret);
}


/** お釣りアドレス設定
 *
 * bitcoindにアドレスを作成する
 */
static void set_changeaddr(ln_self_t *self, uint64_t commit_fee)
{
    char changeaddr[UCOIN_SZ_ADDR_MAX];
    jsonrpc_getnewaddress(changeaddr);
    DBG_PRINTF("closing change addr : %s\n", changeaddr);
    ln_set_shutdown_vout_addr(self, changeaddr);
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


static void call_script(event_t event, const char *param)
{
    DBG_PRINTF("event=0x%02x\n", (int)event);

    struct stat buf;
    int ret = stat(M_SCRIPT[event], &buf);
    if ((ret == 0) && (buf.st_mode & S_IXUSR)) {
        char cmdline[512];

        sprintf(cmdline, "%s %s", M_SCRIPT[event], param);
        DBG_PRINTF("cmdline: %s\n", cmdline);
        system(cmdline);
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
        if (self->p_node) {
            ucoin_util_dumpbin(fp, self->p_node->keys.pub, UCOIN_SZ_PUBKEY, true);
        } else {
            fprintf(fp, "(none)\n");
        }
        fprintf(fp, "peer node_id: ");
        ucoin_util_dumpbin(fp, self->peer_node.node_id, UCOIN_SZ_PUBKEY, true);
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
                    fprintf(fp, "    from:        %" PRIx64 "\n", p_add->prev_short_channel_id);
                }
            }
        }
    } else {
        fprintf(fp, "no channel\n");
    }
    fprintf(fp, "=(%d)=============================================\n\n\n", line);
}
