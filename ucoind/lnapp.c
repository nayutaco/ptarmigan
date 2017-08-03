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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>


#define UCOIN_USE_PRINTFUNC
#include "ucoind.h"
#include "lnapp.h"
#include "conf.h"
#include "jsonrpc.h"

#include "ln_db_lmdb.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_NODE_ANNO_SPAN        (600)       //node_annoucementを送信する最短間隔[sec]

#define M_WAIT_MUTEX_SEC        (1)         //mMuxSeqのロック解除待ち間隔[sec]
#define M_WAIT_POLL_SEC         (60)        //監視スレッドの待ち間隔[sec]
#define M_WAIT_CLOSE_SEC        (10)        //mutual close後の待ち時間[sec]
#define M_WAIT_MUTEX_MSEC       (100)       //mMuxSeqのロック解除待ち間隔[msec]
#define M_WAIT_RECV_MULTI_MSEC  (1000)      //複数パケット受信した時の処理間隔[msec]

#define M_LMDB_ENV              "./dbucoin"     ///< LMDB名
#define M_CHANNEL_NAME          "cnl_%" PRIx64  ///< チャネル名(主にDBで使用する想定)


#define M_PREIMAGE_NUM          (10)        ///< 保持できるpreimage数

#define M_SHUTDOWN_FEE          UCOIN_MBTC2SATOSHI(0.1)     ///< shutdown時のFEE

//デフォルト値変更
#define M_DUST_LIMIT_SAT                (0)
//#define M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT (UINT64_MAX)
//#define M_CHANNEL_RESERVE_SAT           (700)
//#define M_HTLC_MINIMUM_MSAT             (9000)
//#define M_FEERATE_PER_KW                (1500)
//#define M_TO_SELF_DELAY                 (90)
//#define M_MAX_ACCEPTED_HTLCS            (LN_HTLC_MAX)
#define M_MIN_DEPTH                     (1)

#define M_CLOSE_CONFIRM (1)     // TODO: close後のconfirmationだが、待つ必要はあるか？

#define M_FWD_PROC_MAX          (5)         ///< 他スレッドからの処理要求キュー数
                                            ///< TODO: オーバーフローチェックはしていない


//#define M_TEST_PAYHASH          // fulfill送信時にpayment_hashをクリアしない(連続テスト用)


/********************************************************************
 * typedefs
 ********************************************************************/


typedef struct {
    bool            use;
    uint8_t         preimage[LN_SZ_PREIMAGE];
} preimage_t;

/** @struct work_t
 *  @brief  チャネル管理情報
 */
typedef struct {
    ln_self_t       *p_self;
    lnapp_conf_t    *p_conf;
    ln_establish_t  *p_establish;

    uint32_t        last_node_anno_sent;    //最後に送信したnode_announcementのEPOCH TIME
    volatile bool   loop;                   //true:動作中
    bool            first;                  //false:node_announcement受信済み
    bool            shutdown_sent;

    bool            funding_waiting;        //true:funding_txの安定待ち
    uint8_t         funding_txid[UCOIN_SZ_TXID];
    uint32_t        funding_min_depth;

    preimage_t      preimage[M_PREIMAGE_NUM];

    //callback待ち合わせ
    pthread_cond_t  cond;
    pthread_mutex_t mux;
    ln_cb_t         callback_msg;

    //db
    MDB_txn         *txn;
    MDB_dbi         dbi;
    char            cnl_name[32];

    //処理中のmutex
    pthread_mutex_t mux_proc;

    //他スレッドからの転送処理要求
    uint8_t         fwd_proc_rpnt;  //fwd_procの読込み位置
    uint8_t         fwd_proc_wpnt;  //fwd_procの書込み位置
    struct {
        enum {
            //外部用
            FWD_PROC_NONE,
            FWD_PROC_ADD,

            //内部用
            INNER_SEND_ANNO_SIGNS,

            //
            FWD_PROC_FULFILL
        } cmd;
        uint16_t    len;
        void        *p_data;        //mallocで確保し、使用後にfreeする
    } fwd_proc[M_FWD_PROC_MAX];
} work_t;


typedef struct {
    uint8_t     onion_route[LN_SZ_ONION_ROUTE];
    uint64_t    amt_to_forward;
    uint32_t    outgoing_cltv_value;
    uint8_t     payment_hash[LN_SZ_HASH];
    uint64_t    short_channel_id;
} fwd_proc_add_t;


typedef struct {
    uint64_t    id;
    uint8_t     preimage[LN_SZ_PREIMAGE];
} fwd_proc_fulfill_t;


/********************************************************************
 * static variables
 ********************************************************************/

static volatile bool    mLoop;               //

static ln_node_t    mNode;

//LMDB
static MDB_env      *mpDbEnv = NULL;


//シーケンスのmutex
pthread_mutexattr_t mMuxAttr;
pthread_mutex_t mMuxSeq;
volatile enum {
    MUX_NONE,
    MUX_SEND_FULFILL_HTLC = 1,
    MUX_RECV_FULFILL_HTLC = 2,
    MUX_PAYMENT = 4,
} mMuxTiming;


/********************************************************************
 * prototypes
 ********************************************************************/

static void *thread_main_start(void *pArg);
static bool noise_handshake(lnapp_conf_t *p_conf, ln_self_t *self);

static void *thread_recv_start(void *pArg);
static uint16_t recv_peer(lnapp_conf_t *p_conf, uint8_t *pBuf, uint16_t Len);

static void *thread_poll_start(void *pArg);

static bool fwd_payment_forward(lnapp_conf_t *pAppConf);
static bool fwd_fulfill_backward(lnapp_conf_t *pAppConf);

static void notify_cb(ln_self_t *self, ln_cb_t reason, void *p_param);
static void cb_error_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_init_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_channel_reestablish_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_find_index_wif_req(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_funding_tx_wait(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_established(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_node_anno_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_anno_signs_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv_prev(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_add_htlc_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_fulfill_htlc_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_htlc_changed(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_closed(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_send_req(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
static void cb_commit_sig_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);

static void stop_threads(work_t *p_work);
static void send_peer_raw(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf);
static void send_peer_noise(lnapp_conf_t *p_conf, ucoin_buf_t *pBuf);
static void funding_wait(lnapp_conf_t *p_conf);

static void lmdb_load_node(const node_conf_t *pNodeConf);
static void lmdb_save_node(MDB_txn *txn);
static bool lmdb_load_channel(ln_self_t *self, const char *pName);
static bool lmdb_save_channel(const ln_self_t *self, const char *pName);
static void lmdb_del_channel(ln_self_t *self, const char *pName, bool bRemove);

static void set_establish_default(ln_self_t *self, work_t *p_work, const uint8_t *pNodeId);
static void set_changeaddr(ln_self_t *self);
static void show_self_param(const ln_self_t *self, FILE *fp, int line);


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_init(const node_conf_t *pNodeConf)
{
    //lmdbのopenは複数呼ばないでenvを共有する
    if (mpDbEnv == NULL) {
        int ret;

        ret = mdb_env_create(&mpDbEnv);
        assert(ret == 0);
        ret = mdb_env_set_maxdbs(mpDbEnv, 1);
        assert(ret == 0);
        mkdir(M_LMDB_ENV, 0755);
        ret = mdb_env_open(mpDbEnv, M_LMDB_ENV, MDB_FIXEDMAP, 0664);
        assert(ret == 0);
    }

    //node読込み
    lmdb_load_node(pNodeConf);

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
    work_t *p_work = (work_t *)pAppConf->p_work;
    if (p_work != NULL) {
        p_work->loop = false;
    }
}


bool lnapp_have_channel(const uint8_t *pNodeId)
{
    return ln_node_search_short_cnl_id(&mNode, pNodeId) != 0;
}


void lnapp_add_preimage(lnapp_conf_t *pAppConf, char *pResMsg)
{
    DBGTRACE_BEGIN

    work_t *p_work = (work_t *)pAppConf->p_work;

    int lp;
    for (lp = 0; lp < M_PREIMAGE_NUM; lp++) {
        if (!p_work->preimage[lp].use) {
            p_work->preimage[lp].use = true;
            ucoin_util_random(p_work->preimage[lp].preimage, LN_SZ_PREIMAGE);
            break;
        }
    }

    if (lp < M_PREIMAGE_NUM) {
        uint8_t preimage_hash[LN_SZ_HASH];
        ln_calc_preimage_hash(preimage_hash, p_work->preimage[lp].preimage);
        fprintf(PRINTOUT, "payment_preimage= ");
        misc_dumpbin(PRINTOUT, p_work->preimage[lp].preimage, LN_SZ_PREIMAGE);
        fprintf(PRINTOUT, "payment_hash[%d]= ", lp);
        misc_dumpbin(PRINTOUT, preimage_hash, sizeof(preimage_hash));
        char str[3];
        strcpy(pResMsg, "hash=");
        for (int lp2 = 0; lp2 < LN_SZ_PREIMAGE; lp2++) {
            sprintf(str, "%02x", preimage_hash[lp2]);
            strcat(pResMsg, str);
        }
    } else {
        SYSLOG_ERR("%s(): no empty place", __func__);
        fprintf(PRINTOUT, "fail: no empty place\n");
    }

    DBGTRACE_END
}


void lnapp_show_payment_hash(lnapp_conf_t *pAppConf)
{
    work_t *p_work = (work_t *)pAppConf->p_work;

    uint8_t preimage_hash[LN_SZ_HASH];

    for (int lp = 0; lp < M_PREIMAGE_NUM; lp++) {
        if (p_work->preimage[lp].use) {
            ln_calc_preimage_hash(preimage_hash, p_work->preimage[lp].preimage);
            fprintf(PRINTOUT, "[%2d] ", lp);
            misc_dumpbin(PRINTOUT, preimage_hash, sizeof(preimage_hash));
        }
    }
}


//初回ONIONパケット作成
bool lnapp_payment(lnapp_conf_t *pAppConf, const payment_conf_t *pPay)
{
    DBG_PRINTF("mux_proc: prev\n");
    work_t *p_work = (work_t *)pAppConf->p_work;
    pthread_mutex_lock(&p_work->mux_proc);
    pthread_mutex_lock(&mMuxSeq);
    if (mMuxTiming) {
        SYSLOG_ERR("%s(): stop payment...[%x]", __func__, mMuxTiming);
        pthread_mutex_unlock(&mMuxSeq);
        pthread_mutex_unlock(&p_work->mux_proc);
        return true;
    }
    mMuxTiming |= MUX_PAYMENT;
    DBG_PRINTF("mMuxTiming after: %x\n", mMuxTiming);
    pthread_mutex_unlock(&mMuxSeq);

    DBG_PRINTF("mux_proc: after\n");

    DBGTRACE_BEGIN

    bool ret = false;
    ucoin_buf_t buf_bolt;
    uint8_t session_key[UCOIN_SZ_PRIVKEY];
    ln_self_t *p_self = p_work->p_self;

    if (pPay->hop_datain[0].short_channel_id != p_self->short_channel_id) {
        SYSLOG_ERR("%s(): short_channel_id mismatch", __func__);
        fprintf(PRINTOUT, "fail: short_channel_id mismatch\n");
        fprintf(PRINTOUT, "    hop  : %" PRIx64 "\n", pPay->hop_datain[0].short_channel_id);
        fprintf(PRINTOUT, "    mine : %" PRIx64 "\n", p_self->short_channel_id);
        goto LABEL_EXIT;
    }

    //amount, CLTVチェック(最後の値はチェックしない)
    for (int lp = 1; lp < pPay->hop_num - 1; lp++) {
#warning 各ノードの転送FEEは計算に含めていない
        if (pPay->hop_datain[lp - 1].amt_to_forward < pPay->hop_datain[lp].amt_to_forward) {
            SYSLOG_ERR("%s(): [%d]amt_to_forward larger than previous (%" PRIu64 " < %" PRIu64 ")",
                    __func__, lp,
                    pPay->hop_datain[lp - 1].amt_to_forward,
                    pPay->hop_datain[lp].amt_to_forward);
            goto LABEL_EXIT;
        }
#warning BOLT#7のcltv_expiry_delta未対応(同じ値は認めない)
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
    ret = ln_onion_create_packet(p_self, onion, &pPay->hop_datain[1], pPay->hop_num - 1, session_key, NULL, 0);
    assert(ret);

    show_self_param(p_self, PRINTOUT, __LINE__);

    ucoin_buf_init(&buf_bolt);
    ret = ln_create_add_htlc(p_self, &buf_bolt,
                        onion,
                        pPay->hop_datain[0].amt_to_forward,
                        pPay->hop_datain[0].outgoing_cltv_value,
                        pPay->payment_hash,
                        0);
    assert(ret);

    send_peer_noise(pAppConf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

LABEL_EXIT:
    if (ret) {
        show_self_param(p_self, PRINTOUT, __LINE__);
    } else {
        mMuxTiming &= ~MUX_PAYMENT;
    }

    DBG_PRINTF("mux_proc: end\n");
    pthread_mutex_unlock(&p_work->mux_proc);
    DBGTRACE_END

    return ret;
}


//受信スレッド経由で関数呼び出しされる
bool lnapp_payment_forward(lnapp_conf_t *pAppConf, const ln_cb_add_htlc_recv_t *pAdd, uint64_t prev_short_channel_id)
{
    DBGTRACE_BEGIN

    //処理は、thread_recv_start()のスレッドで行う(コンテキスト切り替えのため)

    fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)malloc(sizeof(fwd_proc_add_t));
    memcpy(p_fwd_add->onion_route, pAdd->p_onion_route, LN_SZ_ONION_ROUTE);
    p_fwd_add->amt_to_forward = pAdd->p_hop->amt_to_forward;
    p_fwd_add->outgoing_cltv_value = pAdd->p_hop->outgoing_cltv_value;
    memcpy(p_fwd_add->payment_hash, pAdd->p_payment_hash, LN_SZ_HASH);
    p_fwd_add->short_channel_id = prev_short_channel_id;

    work_t *p_work = (work_t *)pAppConf->p_work;

    //追い越しチェック
    uint8_t next_wpnt = (p_work->fwd_proc_wpnt + 1) % M_FWD_PROC_MAX;
    if (p_work->fwd_proc_rpnt == next_wpnt) {
        //NG
        SYSLOG_ERR("%s(): process buffer full", __func__);
        assert(0);
    }

    p_work->fwd_proc[p_work->fwd_proc_wpnt].cmd = FWD_PROC_ADD;
    p_work->fwd_proc[p_work->fwd_proc_wpnt].len = sizeof(fwd_proc_add_t);
    p_work->fwd_proc[p_work->fwd_proc_wpnt].p_data = p_fwd_add;
    p_work->fwd_proc_wpnt = next_wpnt;

    DBGTRACE_END
    return true;
}


//受信スレッド経由で関数呼び出しされる
bool lnapp_fulfill_backward(lnapp_conf_t *pAppConf, const ln_cb_fulfill_htlc_recv_t *pFulFill)
{
    DBGTRACE_BEGIN

    fwd_proc_fulfill_t *p_fwd_fulfill = (fwd_proc_fulfill_t *)malloc(sizeof(fwd_proc_fulfill_t));
    p_fwd_fulfill->id = pFulFill->id;
    memcpy(p_fwd_fulfill->preimage, pFulFill->p_preimage, LN_SZ_PREIMAGE);

    work_t *p_work = (work_t *)pAppConf->p_work;

    //追い越しチェック
    uint8_t next_wpnt = (p_work->fwd_proc_wpnt + 1) % M_FWD_PROC_MAX;
    if (p_work->fwd_proc_rpnt == next_wpnt) {
        //NG
        SYSLOG_ERR("%s(): process buffer full", __func__);
        assert(0);
    }

    p_work->fwd_proc[p_work->fwd_proc_wpnt].cmd = FWD_PROC_FULFILL;
    p_work->fwd_proc[p_work->fwd_proc_wpnt].len = sizeof(fwd_proc_fulfill_t);
    p_work->fwd_proc[p_work->fwd_proc_wpnt].p_data = p_fwd_fulfill;
    p_work->fwd_proc_wpnt = next_wpnt;

    DBGTRACE_END

    return true;
}


//受信スレッド経由で関数呼び出しされる
static bool req_send_anno_signs(work_t *p_work)
{
    DBGTRACE_BEGIN

    //追い越しチェック
    uint8_t next_wpnt = (p_work->fwd_proc_wpnt + 1) % M_FWD_PROC_MAX;
    if (p_work->fwd_proc_rpnt == next_wpnt) {
        //NG
        SYSLOG_ERR("%s(): process buffer full", __func__);
        assert(0);
    }

    p_work->fwd_proc[p_work->fwd_proc_wpnt].cmd = INNER_SEND_ANNO_SIGNS;
    p_work->fwd_proc[p_work->fwd_proc_wpnt].len = 0;
    p_work->fwd_proc[p_work->fwd_proc_wpnt].p_data = NULL;
    p_work->fwd_proc_wpnt = next_wpnt;

    DBGTRACE_END

    return true;
}


bool lnapp_close_channel(lnapp_conf_t *pAppConf)
{
    DBG_PRINTF("mux_proc: prev\n");
    work_t *p_work = (work_t *)pAppConf->p_work;
    pthread_mutex_lock(&p_work->mux_proc);
    DBG_PRINTF("mux_proc: after\n");

    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ln_self_t *p_self = p_work->p_self;

    if (p_self->htlc_num != 0) {
        SYSLOG_ERR("%s(): you have some HTLCs", __func__);
        return false;
    }

    show_self_param(p_self, PRINTOUT, __LINE__);

    ucoin_buf_init(&buf_bolt);
    ret = ln_create_shutdown(p_self, &buf_bolt);
    assert(ret);

    send_peer_noise(pAppConf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //TODO: shutdownを送信した方がclosing transactionを公開する
    p_work->shutdown_sent = true;

    if (ret) {
        show_self_param(p_self, PRINTOUT, __LINE__);
    }

    DBG_PRINTF("mux_proc: end\n");
    pthread_mutex_unlock(&p_work->mux_proc);
    DBGTRACE_END

    return ret;
}


bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id)
{
    if (pAppConf->p_work == NULL) {
        return false;
    }

    const work_t *p_work = (work_t *)pAppConf->p_work;
    return (p_work->p_self != NULL) && (short_channel_id == p_work->p_self->short_channel_id);
}


void lnapp_show_self(const lnapp_conf_t *pAppConf, char *pResMsg)
{
    if (pAppConf->p_work == NULL) {
        return;
    }

    ln_self_t *p_self = ((work_t *)pAppConf->p_work)->p_self;

    if ((p_self) && (p_self->short_channel_id)) {
        show_self_param(p_self, PRINTOUT, __LINE__);

        //次の更新でバッファを超えそうであれば終了する
        //ルーティングが自動生成できるようになれば、このコマンド自体不要だろう
        if (strlen(pResMsg) > SZ_RESBUF - 200) {
            SYSLOG_ERR("%s(): low buffer", __func__);
            assert(0);
        }

        //ucoincli用メッセージ
        char str[256];

        //my node_id
        for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
            sprintf(str, "%02x", p_self->p_node->keys.pub[lp]);
            strcat(pResMsg, str);
        }
        strcat(pResMsg, ",");
        //peer node_id
        for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
            sprintf(str, "%02x", p_self->p_node->node_info[p_self->node_idx].node_id[lp]);
            strcat(pResMsg, str);
        }
        //short_channel_id
        sprintf(str, ",%" PRIx64, p_self->short_channel_id);
        strcat(pResMsg, str);
        //our_msat
        sprintf(str, ",%" PRIu64, p_self->our_msat);
        strcat(pResMsg, str);
        //their_msat
        sprintf(str, ",%" PRIu64 "\n", p_self->their_msat);
        strcat(pResMsg, str);
    }
}


bool lnapp_is_looping(const lnapp_conf_t *pAppConf)
{
    work_t *p_work = (work_t *)pAppConf->p_work;
    if (p_work != NULL) {
        return p_work->loop;
    }
    return false;
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
 */
static void *thread_main_start(void *pArg)
{
    bool ret;
    int retval;

    lnapp_conf_t *p_conf = (lnapp_conf_t *)pArg;
    ln_self_t my_self;

    ucoin_buf_t buf_bolt;

    //スレッド
    pthread_t   th_peer;        //peer受信
    pthread_t   th_poll;        //トランザクション監視

    //lpapp作業用
    work_t      *val_work = (work_t *)malloc(sizeof(work_t));
    memset(val_work, 0, sizeof(work_t));

    p_conf->p_work = val_work;
    ucoin_buf_init(&buf_bolt);

    if ((p_conf->cmd == DCMD_NONE) || (p_conf->cmd == DCMD_CREATE)) {
        uint8_t     seed[UCOIN_SZ_PRIVKEY];

        //seed作成
        SYSLOG_INFO("ln_self_t initialize");
        do {
            ucoin_util_random(seed, UCOIN_SZ_PRIVKEY);
        } while (!ucoin_keys_chkpriv(seed));
        strcpy(val_work->cnl_name, "create");
        ln_init(&my_self, &mNode, seed, notify_cb);
    } else {
        //既存チャネル接続
        uint64_t short_channel_id = ln_node_search_short_cnl_id(&mNode, p_conf->node_id);
        if (short_channel_id != 0) {
            if (short_channel_id != 0) {
                DBG_PRINTF("    チャネルDB読込み: %" PRIx64 "\n", short_channel_id);
                sprintf(val_work->cnl_name, M_CHANNEL_NAME, short_channel_id);
                ln_init(&my_self, &mNode, NULL, notify_cb);
                ret = lmdb_load_channel(&my_self, val_work->cnl_name);
                assert(ret);
            }
        } else {
            SYSLOG_ERR("%s(): node_id not found", __func__);
            DUMPBIN(p_conf->node_id, UCOIN_SZ_PUBKEY);
        }
        if (my_self.short_channel_id == 0) {
            SYSLOG_ERR("%s(): not found", __func__);
            return NULL;
        }
    }

    //close時のお釣り先
    set_changeaddr(&my_self);

    //コールバック・受信スレッド用
    my_self.p_param = p_conf;

    val_work->p_conf = p_conf;
    pthread_mutex_init(&val_work->mux, NULL);
    pthread_cond_init(&val_work->cond, NULL);
    val_work->funding_waiting = false;
    val_work->first = true;
    val_work->last_node_anno_sent = 0;       //最後に送信したnode_announcementのEPOCH TIME
    val_work->p_establish = NULL;
    val_work->p_self = &my_self;
    pthread_mutex_init(&val_work->mux_proc, NULL);
    for (int lp = 0; lp < M_PREIMAGE_NUM; lp++) {
        val_work->preimage[lp].use = false;
    }
    val_work->loop = true;           //全体で使用する

    //noise protocol handshake
    noise_handshake(p_conf, &my_self);

    /////////////////////////
    // handshake完了
    /////////////////////////

    if ((p_conf->cmd != DCMD_NONE) && (p_conf->cmd != DCMD_CREATE)) {
        //既存チャネル接続の可能性あり
        uint64_t short_channel_id = ln_node_search_short_cnl_id(&mNode, p_conf->node_id);
        if (short_channel_id != 0) {
            if (short_channel_id != 0) {
                DBG_PRINTF("    チャネルDB読込み: %" PRIx64 "\n", short_channel_id);
                sprintf(val_work->cnl_name, M_CHANNEL_NAME, short_channel_id);
                ln_init(&my_self, &mNode, NULL, notify_cb);
                ret = lmdb_load_channel(&my_self, val_work->cnl_name);
                assert(ret);
            }
        } else {
            SYSLOG_ERR("%s(): node_id not found", __func__);
            DUMPBIN(p_conf->node_id, UCOIN_SZ_PUBKEY);
        }
    }


    pthread_create(&th_peer, NULL, &thread_recv_start, p_conf);

    //監視対象の有無にかかわらず立ち上げておく
    pthread_create(&th_poll, NULL, &thread_poll_start, p_conf);


    //init送受信
    //  noise protocol handshakeは3通信のため、
    //      initiator送信-->resonder送信-->initiator送信
    //  で終わるため、次の送信はresponderからになる。
    //  BOLTとして取り決めはないのだが、そうするしかないだろう。
    //
    //  ただ、そういうシーケンスを固定した作りは危険なので、
    //  init受信は通常の受信スレッドに任せる方が安全かもしれない。
#if 1
    DBG_PRINTF("init送信 sock=%d\n", p_conf->sock);

    //init送信
    ret = ln_create_init(&my_self, &buf_bolt);
    assert(ret);
    send_peer_noise(p_conf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //コールバックでのINIT受信通知待ち
    DBG_PRINTF("init受信待ち...\n");
    pthread_mutex_lock(&val_work->mux);
    while (val_work->loop && val_work->first) {
        //init受信待ち合わせ(*1)
        pthread_cond_wait(&val_work->cond, &val_work->mux);
    }
    pthread_mutex_unlock(&val_work->mux);
    DBG_PRINTF("init受信済み\n");
#else
    if (!p_conf->initiator) {
        //responder
        DBG_PRINTF("init送信 sock=%d\n", p_conf->sock);

        ////peerの受信準備待ち
        //misc_msleep(500);

        //init送信
        ret = ln_create_init(&my_self, &buf_bolt);
        assert(ret);
        send_peer_noise(p_conf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);

        //コールバックでのINIT受信通知待ち
        DBG_PRINTF("init受信\n");
        pthread_mutex_lock(&val_work->mux);
        while (val_work->loop && (val_work->callback_msg != LN_CB_INIT_RECV)) {
            //init受信待ち合わせ(*1)
            pthread_cond_wait(&val_work->cond, &val_work->mux);
        }
        pthread_mutex_unlock(&val_work->mux);

        ////node_announcement送信
        //val_work->last_node_anno_sent = (uint32_t)time(NULL);
        //ret = ln_create_node_announce(&mNode, &buf_bolt, val_work->last_node_anno_sent);
        //assert(ret);
        //send_peer_noise(p_conf, &buf_bolt);
        //ucoin_buf_free(&buf_bolt);
    } else {
        //initiator
        //コールバックでのINIT受信通知待ち
        DBG_PRINTF("init受信\n");
        pthread_mutex_lock(&val_work->mux);
        while (val_work->loop && (val_work->callback_msg != LN_CB_INIT_RECV)) {
            //init受信待ち合わせ(*1)
            pthread_cond_wait(&val_work->cond, &val_work->mux);
        }
        pthread_mutex_unlock(&val_work->mux);

        //init送信
        DBG_PRINTF("init送信\n");
        ret = ln_create_init(&my_self, &buf_bolt);
        assert(ret);
        send_peer_noise(p_conf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    }
#endif

    DBG_PRINTF("init交換完了\n\n");

    if ((p_conf->cmd == DCMD_CREATE) && (val_work->p_establish == NULL)) {
        DBG_PRINTF("Establish準備\n");
        set_establish_default(&my_self, val_work, p_conf->node_id);
    } else {
        if (val_work->p_establish != NULL) {
            DBG_PRINTF("Establish済み : %d\n", p_conf->cmd);
            val_work->p_establish = NULL;

            //peerの受信準備待ち
            misc_msleep(500);

            //channel_reestablish送信
            ret = ln_create_channel_reestablish(&my_self, &buf_bolt);
            assert(ret);

            send_peer_noise(p_conf, &buf_bolt);
            ucoin_buf_free(&buf_bolt);

            //コールバックでのchannel_reestablish受信通知待ち
            DBG_PRINTF("channel_reestablish受信\n");
            pthread_mutex_lock(&val_work->mux);
            val_work->callback_msg = LN_CB_MAX;
            while (val_work->loop && (val_work->callback_msg != LN_CB_REESTABLISH_RECV)) {
                //channel_reestablish受信待ち合わせ(*3)
                pthread_cond_wait(&val_work->cond, &val_work->mux);
            }
            pthread_mutex_unlock(&val_work->mux);
        } else {
            DBG_PRINTF("Establish待ち\n");
            set_establish_default(&my_self, val_work, NULL);
        }
    }

    if ((p_conf->initiator) && (p_conf->cmd == DCMD_CREATE)) {
        //チャネルを作る場合、initiatorからアクションを起こすことになると考える。
        //当初、チャネルを作っていない相手に対してnode_announcementを送ってくるかと思ったが、
        //lndではそうしていない。

        //今の作りでは、initiatorは init受信後に open_channelを送信することになるため、
        //少し時間を空けている。
        misc_msleep(500);

        p_conf->p_funding->p_opening = (opening_t *)malloc(sizeof(opening_t));

        //Establish開始
        DBG_PRINTF("Establish開始\n");
        DBG_PRINTF("  signaddr: %s\n", p_conf->p_funding->signaddr);
        DBG_PRINTF("  funding_sat: %" PRIu64 "\n", p_conf->p_funding->funding_sat);
        DBG_PRINTF("  push_sat: %" PRIu64 "\n", p_conf->p_funding->push_sat);

        //node_announcement受信待ち
#if 0
        pthread_mutex_lock(&val_work->mux);
        val_work->callback_msg = LN_CB_MAX;
        while (val_work->loop && (val_work->callback_msg != LN_CB_NODE_ANNO_RECV)) {
            //node_announcement受信待ち(*2)
            pthread_cond_wait(&val_work->cond, &val_work->mux);
        }
        pthread_mutex_unlock(&val_work->mux);
#else
#warning lndがそうなっていないので、コメントアウト
#endif

        //open_channel
        char wif[UCOIN_SZ_WIF_MAX];
        uint64_t fundin_sat;

        ret = jsonrpc_dumpprivkey(wif, p_conf->p_funding->signaddr);
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
            ucoin_util_wif2keys(&p_conf->p_funding->p_opening->fundin_keys, wif);
            //TODO: データ構造に無駄が多い
            //      スタックに置けないものを詰めていったせいだが、整理したいところだ。
            p_conf->p_funding->p_opening->fundin.p_txid = p_conf->p_funding->txid;
            p_conf->p_funding->p_opening->fundin.index = p_conf->p_funding->txindex;
            p_conf->p_funding->p_opening->fundin.amount = fundin_sat;
            p_conf->p_funding->p_opening->fundin.p_change_pubkey = NULL;
            p_conf->p_funding->p_opening->fundin.p_change_addr = p_conf->p_funding->p_opening->chargeaddr;
            p_conf->p_funding->p_opening->fundin.p_keys = &p_conf->p_funding->p_opening->fundin_keys;
            p_conf->p_funding->p_opening->fundin.b_native = false;        //nested in BIP16

            DBG_PRINTF("open_channel: fund_in amount=%" PRIu64 "\n", fundin_sat);
            ret = ln_create_open_channel(&my_self, &buf_bolt, &p_conf->p_funding->p_opening->fundin,
                            p_conf->p_funding->funding_sat, p_conf->p_funding->push_sat);
            assert(ret);

            DBG_PRINTF("SEND: oepn_channel\n");
            send_peer_noise(p_conf, &buf_bolt);
            ucoin_buf_free(&buf_bolt);
        } else {
            SYSLOG_WARN("fail through: jsonrpc_getxout");
            misc_print_txid(p_conf->p_funding->txid);

            //fund-inが既に
        }
    }

    while (val_work->loop) {
        DBG_PRINTF("wait...\n");
        show_self_param(&my_self, PRINTOUT, __LINE__);
        pthread_mutex_lock(&val_work->mux);
        pthread_cond_wait(&val_work->cond, &val_work->mux);
        pthread_mutex_unlock(&val_work->mux);
    }

    pthread_join(th_peer, NULL);
    pthread_join(th_poll, NULL);
    DBG_PRINTF("loop end\n");

    retval = shutdown(p_conf->sock, SHUT_RDWR);
    if (retval < 0) {
        SYSLOG_ERR("%s(): shutdown: %s", __func__, strerror(errno));
    }
    p_conf->sock = -1;

    SYSLOG_WARN("[exit]channel thread [%s]\n", val_work->cnl_name);
    memset(val_work, 0, sizeof(work_t));
    free(val_work);

    return NULL;
}


static bool noise_handshake(lnapp_conf_t *p_conf, ln_self_t *self)
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
        ret = ln_handshake_start(self, &buf, p_conf->node_id);
        assert(ret);
        DBG_PRINTF("** SEND act one **\n");
        send_peer_raw(p_conf, &buf);

        //recv: act two
        DBG_PRINTF("** RECV act two... **\n");
        recv_peer(p_conf, rbuf, 50);
        DBG_PRINTF("** RECV act two ! **\n");
        ucoin_buf_free(&buf);
        ucoin_buf_alloccopy(&buf, rbuf, 50);
        ret = ln_handshake_recv(self, &b_cont, &buf, p_conf->node_id);
        assert(ret);
        assert(!b_cont);
        //send: act three
        DBG_PRINTF("** SEND act three **\n");
        send_peer_raw(p_conf, &buf);
        ucoin_buf_free(&buf);
   } else {
        //responderはnode_idを知らない

        //recv: act one
        ret = ln_handshake_start(self, &buf, NULL);
        assert(ret);
        DBG_PRINTF("** RECV act one... **\n");
        recv_peer(p_conf, rbuf, 50);
        DBG_PRINTF("** RECV act one ! **\n");
        ucoin_buf_alloccopy(&buf, rbuf, 50);
        ret = ln_handshake_recv(self, &b_cont, &buf, NULL);
        assert(ret);
        assert(b_cont);
        //send: act two
        DBG_PRINTF("** SEND act two **\n");
        send_peer_raw(p_conf, &buf);

        //recv: act three
        DBG_PRINTF("** RECV act three... **\n");
        recv_peer(p_conf, rbuf, 66);
        DBG_PRINTF("** RECV act three ! **\n");
        ucoin_buf_free(&buf);
        ucoin_buf_alloccopy(&buf, rbuf, 66);
        ret = ln_handshake_recv(self, &b_cont, &buf, NULL);
        assert(ret);
        assert(!b_cont);

        //bufには相手のnode_idが返ってくる
        assert(buf.len == UCOIN_SZ_PUBKEY);
        memcpy(p_conf->node_id, buf.buf, UCOIN_SZ_PUBKEY);

        ucoin_buf_free(&buf);
    }

    DBG_PRINTF("noise handshaked\n");
    return true;
}


/********************************************************************
 * 受信スレッド
 ********************************************************************/

static void *thread_recv_start(void *pArg)
{
    ucoin_buf_t buf_recv;
    ucoin_buf_t buf_bolt;
    lnapp_conf_t *p_conf= (lnapp_conf_t *)pArg;
    work_t *p_work = (work_t *)p_conf->p_work;

    ucoin_buf_init(&buf_bolt);

    while (p_work->loop) {
        //noise packet データ長
        uint8_t head[LN_SZ_NOISE_HEADER];
        uint16_t len = recv_peer(p_conf, head, LN_SZ_NOISE_HEADER);
        if (len == 0) {
            //peerから切断された
            DBG_PRINTF("DISC: loop end\n");
            stop_threads(p_work);
            break;
        }
        assert(len == LN_SZ_NOISE_HEADER);
        if (len == LN_SZ_NOISE_HEADER) {
            len = ln_noise_dec_len(p_work->p_self, head, len);
        } else {
            break;
        }

        ucoin_buf_alloc(&buf_recv, len);
        uint16_t len_msg = recv_peer(p_conf, buf_recv.buf, len);
        if (len_msg == 0) {
            //peerから切断された
            DBG_PRINTF("DISC: loop end\n");
            stop_threads(p_work);
            break;
        }
        if (len_msg == len) {
            buf_recv.len = len;
            bool ret = ln_noise_dec_msg(p_work->p_self, &buf_recv);
            assert(ret);
        } else {
            break;
        }

        DBG_PRINTF("type=%02x%02x\n", buf_recv.buf[0], buf_recv.buf[1]);
        pthread_mutex_lock(&p_work->mux_proc);
        bool ret = ln_recv(p_work->p_self, &buf_bolt, buf_recv.buf, buf_recv.len);
        DBG_PRINTF("ln_recv() result=%d\n", ret);
        assert(ret);
        DBG_PRINTF("mux_proc: end\n");
        pthread_mutex_unlock(&p_work->mux_proc);

        if (buf_bolt.len > 0) {
            send_peer_noise(p_conf, &buf_bolt);
            ucoin_buf_free(&buf_bolt);
        }
        ucoin_buf_free(&buf_recv);
    }

    SYSLOG_WARN("[exit]recv thread\n");

    return NULL;
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

    work_t *p_work = (work_t *)p_conf->p_work;
    while (p_work->loop && (Len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLIN;
        int polr = poll(&fds, 1, 100);
        if (polr < 0) {
            SYSLOG_ERR("%s(): poll: %s", __func__, strerror(errno));
            break;
        } else if (polr == 0) {
            //timeout
            //  処理要求があれば受け付ける
            if (p_work->fwd_proc_rpnt != p_work->fwd_proc_wpnt) {
                bool ret = false;
                switch (p_work->fwd_proc[p_work->fwd_proc_rpnt].cmd) {
                case FWD_PROC_ADD:
                    ret = fwd_payment_forward(p_conf);
                    break;
                case FWD_PROC_FULFILL:
                    ret = fwd_fulfill_backward(p_conf);
                    break;
                case INNER_SEND_ANNO_SIGNS:
                    {
                        ucoin_buf_t buf_bolt;

                        ucoin_buf_init(&buf_bolt);
                        ret = ln_create_announce_signs(p_work->p_self, &buf_bolt);
                        send_peer_noise(p_conf, &buf_bolt);
                        ucoin_buf_free(&buf_bolt);
                    }
                    break;
                default:
                    break;
                }
                if (ret) {
                    //解放
                    p_work->fwd_proc[p_work->fwd_proc_rpnt].cmd = FWD_PROC_NONE;
                    free(p_work->fwd_proc[p_work->fwd_proc_rpnt].p_data);
                    p_work->fwd_proc[p_work->fwd_proc_rpnt].p_data = NULL;
                    p_work->fwd_proc_rpnt = (p_work->fwd_proc_rpnt + 1) % M_FWD_PROC_MAX;
                }
            }
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
            }
        }
    }

    return len;
}


/********************************************************************
 * 監視スレッド
 ********************************************************************/

static void *thread_poll_start(void *pArg)
{
    lnapp_conf_t *p_conf= (lnapp_conf_t *)pArg;
    work_t *p_work = (work_t *)p_conf->p_work;

    while (p_work->loop) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < M_WAIT_POLL_SEC; lp++) {
            sleep(1);
            if (!p_work->loop) {
                break;
            }
        }
        if (!p_work->loop || (p_work->p_self == NULL)) {
            break;
        }

        if (p_work->first) {
            //まだ接続していない
            continue;
        }

        //pingは30秒以上の間隔をあける
#if (M_WAIT_POLL_SEC <= 30)
#error A node SHOULD NOT send ping messages more often than once every 30 seconds
#endif
        if (p_conf->initiator) {
            //initを送信した側がpingを送信することにする(funding_tx待ちの間はping/pongする)
            ucoin_buf_t buf_ping;

            ucoin_buf_init(&buf_ping);
            int ret = ln_create_ping(p_work->p_self, &buf_ping);
            if (!ret) {
                SYSLOG_ERR("%s(): pong not respond", __func__);

                //ループ解除
                stop_threads(p_work);
                break;
            }
            send_peer_noise(p_conf, &buf_ping);
            ucoin_buf_free(&buf_ping);
        }

        //funding_tx
        if (p_work->funding_waiting) {
            //funding_tx確定待ち(確定後はEstablishシーケンスの続きを行う)
            funding_wait(p_conf);
        } else {
            //funding_tx使用チェック
            uint64_t sat;
            bool ret = jsonrpc_getxout(&sat, p_work->p_self->funding_local.funding_txid, p_work->p_self->funding_local.funding_txindex);
            if (!ret) {
#warning Mutual Closeしか用意していないため、このルートは現在通らない
                SYSLOG_WARN("POLL: fail gettxout for funding_tx !!!!!\n");

                //gettxoutはunspentを返すので、取得失敗→closing_txとして使用されたとみなす
                ret = jsonrpc_get_confirmation(p_work->p_self->funding_local.funding_txid);
                if (ret) {
                    //正常:gettransactionもOKなので、削除可能
                    lmdb_del_channel(p_work->p_self, p_work->cnl_name, false);
                    lmdb_save_node(NULL);
                } else {
                    //異常:gettransactionできないので、outpointが存在しない？
                    SYSLOG_ERR("%s(): POLL gettransaction ????", __func__);
                }

                //ループ解除
                stop_threads(p_work);
            }
        }
    }

    SYSLOG_WARN("[exit]poll thread\n");

    return NULL;
}


/********************************************************************
 * 転送処理
 ********************************************************************/

static bool fwd_payment_forward(lnapp_conf_t *pAppConf)
{
    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    work_t *p_work = (work_t *)pAppConf->p_work;
    fwd_proc_add_t *p_fwd_add = (fwd_proc_add_t *)(p_work->fwd_proc[p_work->fwd_proc_rpnt].p_data);

    show_self_param(p_work->p_self, PRINTOUT, __LINE__);

    ret = ln_create_add_htlc(p_work->p_self, &buf_bolt,
                        p_fwd_add->onion_route,
                        p_fwd_add->amt_to_forward,
                        p_fwd_add->outgoing_cltv_value,
                        p_fwd_add->payment_hash,
                        p_fwd_add->short_channel_id);
    assert(ret);

    send_peer_noise(pAppConf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    if (ret) {
        show_self_param(p_work->p_self, PRINTOUT, __LINE__);
    }

    DBGTRACE_END

    return ret;
}


static bool fwd_fulfill_backward(lnapp_conf_t *pAppConf)
{
    DBGTRACE_BEGIN

    bool ret;
    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    work_t *p_work = (work_t *)pAppConf->p_work;
    fwd_proc_fulfill_t *p_fwd_fulfill = (fwd_proc_fulfill_t *)(p_work->fwd_proc[p_work->fwd_proc_rpnt].p_data);

    show_self_param(p_work->p_self, PRINTOUT, __LINE__);

    DBG_PRINTF("id= %" PRIx64 "\n", p_fwd_fulfill->id);
    DBG_PRINTF("preimage= ");
    DUMPBIN(p_fwd_fulfill->preimage, LN_SZ_PREIMAGE);
    ret = ln_create_fulfill_htlc(p_work->p_self, &buf_bolt,
                            p_fwd_fulfill->id, p_fwd_fulfill->preimage);
    assert(ret);

    send_peer_noise(pAppConf, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    if (ret) {
        show_self_param(p_work->p_self, PRINTOUT, __LINE__);
    }

    DBGTRACE_END

    return ret;
}


/**************************************************************************
 * コールバック処理
 **************************************************************************/

static void notify_cb(ln_self_t *self, ln_cb_t reason, void *p_param)
{
    DBGTRACE_BEGIN

    lnapp_conf_t *p_conf = (lnapp_conf_t *)self->p_param;
    work_t *p_work = (work_t *)p_conf->p_work;
    assert(p_work);
    p_work->callback_msg = reason;

    const struct {
        const char *p_msg;
        void (*func)(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param);
    } MAP[] = {
        //    LN_CB_ERROR,                ///< エラー通知
        //    LN_CB_INIT_RECV,            ///< init受信通知
        //    LN_CB_REESTABLISH_RECV,     ///< channel_reestablish受信通知
        //    LN_CB_FINDINGWIF_REQ,       ///< funding鍵設定要求
        //    LN_CB_FUNDINGTX_WAIT,       ///< funding_tx安定待ち要求
        //    LN_CB_ESTABLISHED,          ///< Establish完了通知
        //    LN_CB_ADD_HTLC_RECV_PREV,   ///< update_add_htlc処理前通知
        //    LN_CB_NODE_ANNO_RECV,       ///< node_announcement受信通知
        //    LN_CB_ANNO_SIGNS_RECV,      ///< announcement_signatures受信通知
        //    LN_CB_ADD_HTLC_RECV,        ///< update_add_htlc受信通知
        //    LN_CB_FULFILL_HTLC_RECV,    ///< update_fulfill_htlc受信通知
        //    LN_CB_HTLC_CHANGED,         ///< HTLC変化通知
        //    LN_CB_CLOSED,               ///< closing_signed受信通知
        //    LN_CB_SEND_REQ,             ///< peerへの送信要求
        //    LN_CB_COMMIT_SIG_RECV,

        { "  LN_CB_ERROR: エラー有り", cb_error_recv },
        { "  LN_CB_INIT_RECV: init受信", cb_init_recv },
        { "  LN_CB_REESTABLISH_RECV: channel_reestablish受信", cb_channel_reestablish_recv },
        { "  LN_CB_FINDINGWIF_REQ: funding_tx WIF要求", cb_find_index_wif_req },
        { "  LN_CB_FUNDINGTX_WAIT: funding_tx confirmation待ち要求", cb_funding_tx_wait },
        { "  LN_CB_ESTABLISHED: Establish完了", cb_established },
        { "  LN_CB_NODE_ANNO_RECV: node_announcement受信", cb_node_anno_recv },
        { "  LN_CB_ANNO_SIGNS_RECV: announcement_signatures受信", cb_anno_signs_recv },
        { "  LN_CB_ADD_HTLC_RECV_PREV: update_add_htlc処理前", cb_add_htlc_recv_prev },
        { "  LN_CB_ADD_HTLC_RECV: update_add_htlc受信", cb_add_htlc_recv },
        { "  LN_CB_FULFILL_HTLC_RECV: update_fulfill_htlc受信", cb_fulfill_htlc_recv },
        { "  LN_CB_HTLC_CHANGED: HTLC変化", cb_htlc_changed },
        { "  LN_CB_CLOSED: closing_signed受信", cb_closed },
        { "  LN_CB_SEND_REQ: 送信要求", cb_send_req },
        { "  LN_CB_COMMIT_SIG_RECV: commitment_signed受信通知", cb_commit_sig_recv },
    };

    if (reason < LN_CB_MAX) {
        DBG_PRINTF("%s\n", MAP[reason].p_msg);
        (*MAP[reason].func)(self, p_work, p_conf, p_param);
    } else {
        DBG_PRINTF("fail: invalid reason: %d\n", reason);
    }

    DBGTRACE_END
}


static void cb_error_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBG_PRINTF("no implemented\n");
    assert(0);
}


static void cb_init_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    //init受信時に初期化
    p_work->first = false;
    p_work->shutdown_sent = false;

    //待ち合わせ解除(*1)
    pthread_cond_signal(&p_work->cond);
}


static void cb_channel_reestablish_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    //待ち合わせ解除(*3)
    pthread_cond_signal(&p_work->cond);
}


static void cb_find_index_wif_req(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
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

    ln_set_funding_wif(self, wif);
    memset(wif, 0, sizeof(wif));

    DBGTRACE_END
}


static void cb_funding_tx_wait(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_funding_t *p_funding = (const ln_cb_funding_t *)p_param;

    if (p_funding->b_send) {
        uint8_t txid[UCOIN_SZ_TXID];
        ucoin_buf_t buf_tx;

        ucoin_buf_init(&buf_tx);
        ucoin_tx_create(&buf_tx, p_funding->p_tx_funding);
        bool ret = jsonrpc_sendraw_tx(txid, buf_tx.buf, buf_tx.len);
        if (ret) {
            DBG_PRINTF("OK\n");
        } else {
            DBG_PRINTF("NG\n");
            exit(-1);
        }
        ucoin_buf_free(&buf_tx);
        //DBG_PRINTF("[self->funding]");
        //misc_print_txid(p_funding->p_txid);
        //DBG_PRINTF("[sendrawtransaction]");
        //misc_print_txid(txid);
    }

    //fundingの監視は thread_poll_start()に任せる
    DBG_PRINTF("funding_tx監視開始\n");
    memcpy(p_work->funding_txid, p_funding->p_txid, UCOIN_SZ_TXID);
    p_work->funding_min_depth = p_funding->min_depth;
    p_work->funding_waiting = true;

    DBGTRACE_END
}


static void cb_established(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_funding_t *p_funding = (const ln_cb_funding_t *)p_param;

    sprintf(p_work->cnl_name, M_CHANNEL_NAME, self->short_channel_id);
    if (p_work->p_establish != NULL) {
        free(p_work->p_establish);
        p_work->p_establish = NULL;
    }

    //チャネルDB保存
    bool ret = lmdb_save_channel(self, p_work->cnl_name);
    assert(ret);
    lmdb_save_node(NULL);

    if (p_conf->p_funding != NULL) {
        DBG_PRINTF("*** free input memory ***\n");
        if (p_conf->cmd == DCMD_CREATE) {
            free(p_conf->p_funding->p_opening);
        }
        free(p_conf->p_funding);
        p_conf->p_funding = NULL;
    }

    if (p_funding->annosigs) {
        //annotation_signatures送信要求
        req_send_anno_signs(p_work);
    } else {
        DBG_PRINTF("チャネルアナウンス無し\n");
    }

    SYSLOG_INFO("Established[%" PRIx64 "]: our_msat=%" PRIu64 ", their_msat=%" PRIu64, self->short_channel_id, self->our_msat, self->their_msat);

    char fname[FNAME_LEN];
    sprintf(fname, FNAME_AMOUNT_FMT, self->short_channel_id);
    FILE *fp = fopen(fname, "w");
    show_self_param(self, fp, 0);
    fclose(fp);

    DBGTRACE_END
}


static void cb_node_anno_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    ln_cb_node_anno_recv_t *p = (ln_cb_node_anno_recv_t *)p_param;
    DBG_PRINTF("    anno node_id:");
    DUMPBIN(p->p_node_id, UCOIN_SZ_PUBKEY);
    DBG_PRINTF("    want node_id:");
    DUMPBIN(p_conf->node_id, UCOIN_SZ_PUBKEY);

#if 1
    if (p_work->first) {
        DBG_PRINTF("init後の初回node_announcement受信\n");

        if (p_conf->initiator) {
            //initを投げた場合は、期待するnode_idかどうかチェックする
            int cmp = memcmp(p_conf->node_id, p->p_node_id, UCOIN_SZ_PUBKEY);
            if (cmp != 0) {
                //TODO: 不一致
                DBG_PRINTF("NOT wanted node_id !!\n");
            } else {
                //一致
                DBG_PRINTF("match: node_id !\n");
            }
        } else {
            //initを受けた方は、接続先node_idとして保存する
            //TODO: 他ノード情報も同じ経路でやってくるので、見分ける必要あり
            memcpy(p_conf->node_id, p->p_node_id, UCOIN_SZ_PUBKEY);
        }
        p_work->first = false;
    } else {
        //TODO:
    }
#endif

    //ノードDB更新
    lmdb_save_node(NULL);

    //チャネルを開いているノードであれば、DBから読込む
    if (self->short_channel_id == 0) {
        uint64_t short_channel_id = p->short_channel_id;
        if (short_channel_id) {
            //チャネルDB読込み
            DBG_PRINTF("    チャネルDB読込み: %" PRIx64 "\n", short_channel_id);
            sprintf(p_work->cnl_name, M_CHANNEL_NAME, short_channel_id);
            bool ret = lmdb_load_channel(self, p_work->cnl_name);
            if (!ret) {
                //読み込めなかった場合は、既にDB削除済み
                SYSLOG_ERR("%s(): no channel in DB[%" PRIx64 "]", __func__, short_channel_id);
                stop_threads(p_work);
            }
            if (self->short_channel_id == 0) {
                //読込み成功してshort_channel_idが0の場合は、おそらく削除フラグ済み
                SYSLOG_ERR("%s(): short_channel_id is 0", __func__);
                stop_threads(p_work);
            }
        } else {
            DBG_PRINTF("    該当するnode_id情報なし\n");

            if (p_work->p_establish == NULL) {
                DBG_PRINTF("Establish準備\n");
                set_establish_default(self, p_work, NULL);
            }
        }
    }

    if (self->short_channel_id != 0) {
        SYSLOG_INFO("connect channel: %" PRIx64, self->short_channel_id);
    }

    uint32_t now = (uint32_t)time(NULL);
    DBG_PRINTF("p_work->last_node_anno_sent=%d\n", p_work->last_node_anno_sent);
    if (now - p_work->last_node_anno_sent > M_NODE_ANNO_SPAN) {
        //最後に送信したnode_announcementから時間が経っていたら、投げ返す
        p_work->last_node_anno_sent = now;
        ucoin_buf_t buf_bolt;
        ucoin_buf_init(&buf_bolt);
        bool ret = ln_create_node_announce(&mNode, &buf_bolt, now);
        assert(ret);

        send_peer_noise(p_conf, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    }

#if 0
    //待ち合わせ解除(*2)
    pthread_cond_signal(&p_work->cond);
#else
#warning lndがそうなっていないので、コメントアウト
#endif

    DBGTRACE_END
}


static void cb_anno_signs_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    bool ret;

    //チャネルDB保存
    ret = lmdb_save_channel(self, p_work->cnl_name);
    assert(ret);
    lmdb_save_node(NULL);

    //if (!p_conf->initiator) {
    //    //announcement_signaturesを投げ返す
    //    DBG_PRINTF("announcement_signatures返信\n");
    //    ucoin_buf_t buf_bolt;

    //    ucoin_buf_init(&buf_bolt);
    //    ret = ln_create_announce_signs(self, &buf_bolt);
    //    assert(ret);

    //    send_peer_noise(p_conf, &buf_bolt);
    //    ucoin_buf_free(&buf_bolt);

    //    //TODO: 投げ返し合戦にならないようにチェックが必要
    //}

    DBGTRACE_END
}


static void cb_add_htlc_recv_prev(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    //ここで PAYMENTがある場合もブロックすると、デッドロックする可能性あり
    while (mMuxTiming & ~MUX_PAYMENT) {
        DBG_PRINTF("wait: forward...[%d]\n", mMuxTiming);
        sleep(M_WAIT_MUTEX_SEC);
    }

    show_self_param(self, PRINTOUT, __LINE__);

    DBGTRACE_END
}


static void cb_add_htlc_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    bool ret;
    ln_cb_add_htlc_recv_t *p_add = (ln_cb_add_htlc_recv_t *)p_param;

    DBG_PRINTF("mMuxTiming %d\n", mMuxTiming);
    DBG_PRINTF2("  b_exit: %d\n", p_add->p_hop->b_exit);
    DBG_PRINTF2("   id=%" PRIx64 "\n", p_add->id);
    DBG_PRINTF2("  short_channel_id: %" PRIx64 "\n", p_add->p_hop->short_channel_id);
    DBG_PRINTF2("  amt_to_forward: %" PRIu64 "\n", p_add->p_hop->amt_to_forward);
    DBG_PRINTF2("  outgoing_cltv_value: %d\n", p_add->p_hop->outgoing_cltv_value);
    DBG_PRINTF2("  -------\n");
    DBG_PRINTF2("  amount_msat: %" PRIu64 "\n", p_add->amount_msat);
    DBG_PRINTF2("  cltv_expiry: %d\n", p_add->cltv_expiry);

    if (p_add->p_hop->b_exit) {
        //自分宛
        DBG_PRINTF("自分宛\n");
        p_add->ok = false;

        SYSLOG_INFO("arrive: %" PRIx64 "(%" PRIu64 " msat)", self->short_channel_id, p_add->amount_msat);

        //preimage-hashチェック
        uint8_t preimage_hash[LN_SZ_HASH];

        int lp;
        for (lp = 0; lp < M_PREIMAGE_NUM; lp++) {
            if (p_work->preimage[lp].use) {
                ln_calc_preimage_hash(preimage_hash, p_work->preimage[lp].preimage);
                if (memcmp(preimage_hash, p_add->p_payment_hash, LN_SZ_HASH) == 0) {
                    //一致
                    break;
                }
            }
        }
        if (lp < M_PREIMAGE_NUM) {
            //last nodeチェック
            // https://github.com/nayuta-ueno/lightning-rfc/blob/master/04-onion-routing.md#payload-for-the-last-node
            if ( (p_add->p_hop->amt_to_forward == p_add->amount_msat) &&
                 (p_add->p_hop->outgoing_cltv_value == p_add->cltv_expiry) ) {
                DBG_PRINTF("last node OK\n");
            } else {
                SYSLOG_ERR("%s(): last node check", __func__);
                lp = M_PREIMAGE_NUM;
            }
        }
        if (lp < M_PREIMAGE_NUM) {
            //fulfillを返す
            ucoin_buf_t     buf_bolt;
            ucoin_buf_init(&buf_bolt);
            ret = ln_create_fulfill_htlc(self, &buf_bolt, p_add->id, p_work->preimage[lp].preimage);
            assert(ret);

            pthread_mutex_lock(&mMuxSeq);
            mMuxTiming |= MUX_SEND_FULFILL_HTLC;
            DBG_PRINTF("mMuxTiming after: %d\n", mMuxTiming);
            pthread_mutex_unlock(&mMuxSeq);

            send_peer_noise(p_conf, &buf_bolt);
            ucoin_buf_free(&buf_bolt);

            //preimageを使い終わったら消す
#ifndef M_TEST_PAYHASH
            p_work->preimage[lp].use = false;
            memset(p_work->preimage[lp].preimage, 0, LN_SZ_PREIMAGE);
#else
#warning M_TEST_PAYHASH:preimageを消していない
#endif  //M_TEST_PAYHASH
            p_add->ok = true;
        } else {
            SYSLOG_ERR("%s(): payment_hash mismatch", __func__);
        }
    } else {
        //転送
        SYSLOG_INFO("forward: %" PRIx64 "(%" PRIu64 " msat) --> %" PRIx64 "(%" PRIu64 " msat)", self->short_channel_id, p_add->amount_msat, p_add->p_hop->short_channel_id, p_add->p_hop->amt_to_forward);
        bool ret = pay_forward(p_add, self->short_channel_id);
        if (ret) {
            DBG_PRINTF("転送した\n");
        } else {
            DBG_PRINTF("転送失敗\n");
            SYSLOG_ERR("%s(): forward", __func__);
        }
        p_add->ok = ret;
    }
    show_self_param(self, PRINTOUT, __LINE__);

    DBGTRACE_END
}


static void cb_fulfill_htlc_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_fulfill_htlc_recv_t *p_fulfill = (const ln_cb_fulfill_htlc_recv_t *)p_param;

    DBG_PRINTF("mMuxTiming [%d]\n", mMuxTiming);
    while (true) {
        pthread_mutex_lock(&mMuxSeq);
        if ((mMuxTiming & ~MUX_PAYMENT) == 0) {
            break;
        }
        DBG_PRINTF("@\n");
        pthread_mutex_unlock(&mMuxSeq);
        misc_msleep(M_WAIT_MUTEX_MSEC);
    }
    DBG_PRINTF("mMuxTiming after1: %d\n", mMuxTiming);

    if (p_fulfill->prev_short_channel_id != 0) {
        mMuxTiming |= MUX_RECV_FULFILL_HTLC | MUX_SEND_FULFILL_HTLC;

        //フラグを立てて、相手の受信スレッドで処理してもらう
        DBG_PRINTF("戻す: %" PRIx64 ", id=%" PRIx64 "\n", p_fulfill->prev_short_channel_id, p_fulfill->id);
        fulfill_backward(p_fulfill);
    } else {
        mMuxTiming |= MUX_RECV_FULFILL_HTLC;
        DBG_PRINTF("ここまで\n");
    }
    DBG_PRINTF("mMuxTiming after2: %d\n", mMuxTiming);
    pthread_mutex_unlock(&mMuxSeq);

    show_self_param(self, PRINTOUT, __LINE__);

    DBGTRACE_END
}


static void cb_htlc_changed(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_htlc_changed_t *p_changed = (const ln_cb_htlc_changed_t *)p_param;

    SYSLOG_INFO("HTLC[%" PRIx64 "]: our msat=%" PRIu64 ", their_msat=%" PRIu64, self->short_channel_id, self->our_msat, self->their_msat);

    char fname[FNAME_LEN];
    sprintf(fname, FNAME_AMOUNT_FMT, self->short_channel_id);
    FILE *fp = fopen(fname, "w");
    show_self_param(self, fp, 0);
    fclose(fp);

    pthread_mutex_lock(&mMuxSeq);
    DBG_PRINTF("mMuxTiming: %d\n", mMuxTiming);
    if (p_changed->unlocked && (mMuxTiming & MUX_SEND_FULFILL_HTLC)) {
        //update_fulfill_htlc送信でlockした場合は、revoke_and_ack受信時にunlock
        mMuxTiming &= ~(MUX_SEND_FULFILL_HTLC | MUX_PAYMENT);
        DBG_PRINTF("mMuxTiming after: %d\n", mMuxTiming);
        bool ret = lmdb_save_channel(self, p_work->cnl_name);
        assert(ret);
    }
    pthread_mutex_unlock(&mMuxSeq);

    DBGTRACE_END
}


//closing_singed受信後
//  コールバック後、selfはクリアされる
static void cb_closed(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    DBGTRACE_BEGIN

    const ln_cb_closed_t *p_closed = (const ln_cb_closed_t *)p_param;
    uint8_t txid[UCOIN_SZ_TXID];

    //mNodeからはチャネルの接続情報を消しているため、保存する
    lmdb_save_node(NULL);

    //ucoin_print_rawtx(p_closed->p_tx_closing->buf, p_closed->p_tx_closing->len);

    if (p_work->shutdown_sent) {
        //TODO: shutdownを送信した方がclosing transactionを公開する
        DBG_PRINTF("send closing tx\n");
        p_work->shutdown_sent = false;

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
    misc_print_txid(txid);

#warning 現在はMutual Closeしかないため、DBから削除する
    lmdb_del_channel(p_work->p_self, p_work->cnl_name, true);

    //これ以上やることは無いので、channelスレッドは終了する
    sleep(M_WAIT_CLOSE_SEC);
    stop_threads(p_work);

    DBGTRACE_END
}


static void cb_send_req(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    ucoin_buf_t *p_buf = (ucoin_buf_t *)p_param;
    send_peer_noise(p_conf, p_buf);
}


static void cb_commit_sig_recv(ln_self_t *self, work_t *p_work, lnapp_conf_t *p_conf, void *p_param)
{
    const ln_cb_commsig_recv_t *p_commsig = (const ln_cb_commsig_recv_t *)p_param;

    pthread_mutex_lock(&mMuxSeq);
    DBG_PRINTF("mMuxTiming: %d\n", mMuxTiming);

    if (p_commsig->unlocked && (mMuxTiming & MUX_RECV_FULFILL_HTLC)) {
        //update_fulfill_htlc受信でlockした場合は、commitment_signed受信時にunlock
        mMuxTiming &= ~(MUX_RECV_FULFILL_HTLC | MUX_PAYMENT);
        DBG_PRINTF("mMuxTiming after: %d\n", mMuxTiming);

        bool ret = lmdb_save_channel(self, p_work->cnl_name);
        assert(ret);
    }
    pthread_mutex_unlock(&mMuxSeq);
}


/********************************************************************
 * スレッド共通処理
 ********************************************************************/

//スレッドループ停止
static void stop_threads(work_t *p_work)
{
    if (p_work->loop) {
        p_work->loop = false;
        pthread_cond_signal(&p_work->cond);
        SYSLOG_WARN("close channel: %" PRIx64, p_work->p_self->short_channel_id);
        DBG_PRINTF("===================================\n");
        DBG_PRINTF("=  CHANNEL THREAD END             =\n");
        DBG_PRINTF("===================================\n");
    }
}


static void send_peer_raw(lnapp_conf_t *p_conf, const ucoin_buf_t *pBuf)
{
    ssize_t sz = write(p_conf->sock, pBuf->buf, pBuf->len);
    DBG_PRINTF("Len=%d:  sent=%d\n", pBuf->len, (int)sz);
    if (sz < 0) {
        SYSLOG_ERR("%s(): send_peer_raw: %s", __func__, strerror(errno));
        assert(0);
    }
}


//@attention
//  - pBufは破壊される(noise protocolで暗号化される)
static void send_peer_noise(lnapp_conf_t *p_conf, ucoin_buf_t *pBuf)
{
    DBG_PRINTF("type=%02x%02x: sock=%d, Len=%d\n", pBuf->buf[0], pBuf->buf[1], p_conf->sock, pBuf->len);

    //ln_noise_enc()はpBufを更新する
    bool ret = ln_noise_enc(((work_t *)p_conf->p_work)->p_self, pBuf);
    assert(ret);

    ssize_t sz = write(p_conf->sock, pBuf->buf, pBuf->len);
    DBG_PRINTF("  sent=%d\n", (int)sz);
    if (sz < 0) {
        SYSLOG_ERR("%s(): send_peer_noise: %s", __func__, strerror(errno));
        assert(0);
    }
}


static void funding_wait(lnapp_conf_t *p_conf)
{
    DBGTRACE_BEGIN

    work_t *p_work = (work_t *)p_conf->p_work;
    ln_self_t *self = p_work->p_self;

    DBG_PRINTF("funding_txid: ");
    misc_print_txid(p_work->funding_txid);

    int confirm = jsonrpc_get_confirmation(p_work->funding_txid);
    if (confirm < 0) {
        DBG_PRINTF("fail: get confirmation\n");
    } else if (confirm >= p_work->funding_min_depth) {
        DBG_PRINTF("conrimation OK: %d\n", confirm);
        p_work->funding_waiting = false;    //funding_tx確定
    } else {
        DBG_PRINTF("confirmation waiting...: %d/%d\n", confirm, p_work->funding_min_depth);
    }

    if (!p_work->funding_waiting) {
        //funding_tx確定

        //  short_channel_id
        //      [0-2]funding_txが入ったブロック height
        //      [3-5]funding_txのTXIDが入っているindex
        //      [6-7]funding_txのvout index
        int bheight = 0;
        int bindex = 0;
        bool ret = jsonrpc_get_short_channel_param(&bheight, &bindex, p_work->funding_txid);
        if (ret) {
            fprintf(PRINTOUT, "bindex=%d, bheight=%d\n", bindex, bheight);
        } else {
            DBG_PRINTF("fail: jsonrpc_get_short_channel_param()\n");
        }
        ln_set_funding_info(self, bheight, bindex);

        //安定後
        ucoin_buf_t buf_bolt;
        ucoin_buf_init(&buf_bolt);
        bool bret = ln_funding_tx_stabled(self, &buf_bolt);
        assert(bret);

        if (buf_bolt.len != 0) {
            //open_channel送信側はfunding_lockedを送信する
            send_peer_noise(p_conf, &buf_bolt);
            ucoin_buf_free(&buf_bolt);
        }
    }

    DBGTRACE_END
}


/**************************************************************************
 * DB関連
 *
 * environment: dbucon
 * dbname
 *      * node_id : 16進数を文字列にしたもの(66文字)
 *      * channel name : チャネル名(cnl + short_channel_id)
 *
 *  各dbの keyおよび dataについては ucoin の ln_db_lmdb.c 参照
 *
 **************************************************************************/

static void lmdb_load_node(const node_conf_t *pNodeConf)
{
    DBGTRACE_BEGIN

    int retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    assert(retval == 0);

    ucoin_util_keys_t keys;
    ucoin_util_wif2keys(&keys, pNodeConf->wif);
    char name[UCOIN_SZ_PUBKEY * 2 + 1];
    misc_bin2str(name, keys.pub, UCOIN_SZ_PUBKEY);
    retval = mdb_dbi_open(txn, name, 0, &dbi);
    if (retval == 0) {
        //DBに情報あり
        DBG_PRINTF("load node info from DB [%s].\n", name);

        bool ret = ln_db_load_node(&mNode, txn, &dbi);
        assert(ret);

        mdb_txn_abort(txn);
        mdb_dbi_close(mpDbEnv, dbi);

    } else {
        //DBに情報無し
        DBG_PRINTF("create node info [%s].\n", name);

        ln_node_init(&mNode, pNodeConf->wif, pNodeConf->name, 0);

        lmdb_save_node(txn);
    }

    ln_print_node(&mNode);

    DBGTRACE_END
}


// txnがNULLの場合、内部でmdb_txn_begin()する。
// すなわち、mdb_txn_begin()している場合はそのtxnを、していない場合はNULLを指定する。
static void lmdb_save_node(MDB_txn *txn)
{
    DBGTRACE_BEGIN

    int retval;
    MDB_dbi     dbi;

    if (txn == NULL) {
        retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
        assert(retval == 0);
    }

    char name[UCOIN_SZ_PUBKEY * 2 + 1];
    misc_bin2str(name, mNode.keys.pub, UCOIN_SZ_PUBKEY);
    DBG_PRINTF("save node info to DB [%s].\n", name);
    retval = mdb_dbi_open(txn, name, MDB_CREATE, &dbi);
    assert(retval == 0);

    bool ret = ln_db_save_node(&mNode, txn, &dbi);
    assert(ret);

    mdb_txn_commit(txn);
    mdb_dbi_close(mpDbEnv, dbi);

    //ln_print_node(&mNode);

    DBGTRACE_END
}


//チャネル名を指定して読込む
static bool lmdb_load_channel(ln_self_t *self, const char *pName)
{
    DBGTRACE_BEGIN

    int retval;
    MDB_txn     *txn;
    MDB_dbi     dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        SYSLOG_ERR("%s(): mdb_txn_begin", __func__);
        return false;
    }
    retval = mdb_dbi_open(txn, pName, 0, &dbi);
    if (retval != 0) {
        SYSLOG_ERR("%s(): mdb_dbi_open: %s", __func__, pName);
        return false;
    }

    bool ret = ln_db_load_channel(self, txn, &dbi);

    if (ret) {
        //TODO: close時のお釣り先は固定がよい？
        set_changeaddr(self);
    }

    mdb_txn_abort(txn);

    DBGTRACE_END

    return ret;
}


static bool lmdb_save_channel(const ln_self_t *self, const char *pName)
{
    DBGTRACE_BEGIN

    int retval;
    MDB_txn *txn;
    MDB_dbi dbi;

    retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
    if (retval != 0) {
        SYSLOG_ERR("%s(): mdb_txn_begin", __func__);
        return false;
    }
    retval = mdb_dbi_open(txn, pName, MDB_CREATE, &dbi);
    if (retval != 0) {
        SYSLOG_ERR("%s(): mdb_dbi_open: %s", __func__, pName);
        return false;
    }

    bool ret = ln_db_save_channel(self, txn, &dbi);

    mdb_txn_commit(txn);
    mdb_dbi_close(mpDbEnv, dbi);

    if (ret) {
        show_self_param(self, PRINTOUT, __LINE__);
    }

    DBGTRACE_END

    return ret;
}


/*
 * bRemove==true: DB削除 / false: 削除フラグのみ
 *
 * ノード情報からの削除は、closing_signed受信時に行っている(LN_CB_CLOSEDコールバック)
 */
static void lmdb_del_channel(ln_self_t *self, const char *pName, bool bRemove)
{
    DBGTRACE_BEGIN

    if (bRemove) {
        int retval;
        MDB_txn *txn;
        MDB_dbi dbi;

        retval = mdb_txn_begin(mpDbEnv, NULL, 0, &txn);
        assert(retval == 0);
        retval = mdb_dbi_open(txn, pName, MDB_CREATE, &dbi);
        assert(retval == 0);
        retval = mdb_drop(txn, dbi, 1);

        mdb_txn_commit(txn);

        show_self_param(self, PRINTOUT, __LINE__);
    } else {
        self->short_channel_id = 0;     //削除フラグ代わり
        lmdb_save_channel(self, pName);
    }

    DBGTRACE_END
}


/********************************************************************
 * その他
 ********************************************************************/

/** Establish情報設定
 *
 * @param[in,out]       self
 * @param[in,out]       p_work
 * @param[in]           pNodeId     Establish先(NULL可のはず)
 */
static void set_establish_default(ln_self_t *self, work_t *p_work, const uint8_t *pNodeId)
{
    p_work->p_establish = (ln_establish_t *)malloc(sizeof(ln_establish_t));
    bool ret = ln_set_establish(self, p_work->p_establish, pNodeId);
    assert(ret);

#ifdef M_DUST_LIMIT_SAT
    p_work->p_establish->defval.dust_limit_sat = M_DUST_LIMIT_SAT;
#endif
#ifdef M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT
    p_work->p_establish->defval.max_htlc_value_in_flight_msat = M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT;
#endif
#ifdef M_CHANNEL_RESERVE_SAT
    p_work->p_establish->defval.channel_reserve_sat = M_CHANNEL_RESERVE_SAT;
#endif
#ifdef M_HTLC_MINIMUM_MSAT
    p_work->p_establish->defval.htlc_minimum_msat = M_HTLC_MINIMUM_MSAT;
#endif
#ifdef M_FEERATE_PER_KW
    p_work->p_establish->defval.feerate_per_kw = M_FEERATE_PER_KW;
#endif
#ifdef M_TO_SELF_DELAY
    p_work->p_establish->defval.to_self_delay = M_TO_SELF_DELAY;
#endif
#ifdef M_MAX_ACCEPTED_HTLCS
    p_work->p_establish->defval.max_accepted_htlcs = M_MAX_ACCEPTED_HTLCS;
#endif
#ifdef M_MIN_DEPTH
    p_work->p_establish->defval.min_depth = M_MIN_DEPTH;
#endif
}


static void set_changeaddr(ln_self_t *self)
{
    char changeaddr[UCOIN_SZ_ADDR_MAX];
    jsonrpc_getnewaddress(changeaddr);
    DBG_PRINTF("closing change addr : %s\n", changeaddr);
    ln_set_shutdown_vout_addr(self, changeaddr);
    ln_update_shutdown_fee(self, M_SHUTDOWN_FEE);
}


static void show_self_param(const ln_self_t *self, FILE *fp, int line)
{
    fprintf(fp, "\n\n=(%" PRIx64 ")============================================= %p\n", self->short_channel_id, self);
    if (self->short_channel_id) {
        fprintf(fp, "short_channel_id: %0" PRIx64 "\n", self->short_channel_id);
        fprintf(fp, "my node_id:   ");
        if (self->p_node) {
            misc_dumpbin(fp, self->p_node->keys.pub, UCOIN_SZ_PUBKEY);
        } else {
            fprintf(fp, "(none)\n");
        }
        fprintf(fp, "peer node_id: ");
        if (self->node_idx != -1) {
            misc_dumpbin(fp, self->p_node->node_info[self->node_idx].node_id, UCOIN_SZ_PUBKEY);
        } else {
            fprintf(fp, "(none)\n");
        }
        fprintf(fp, "our_msat:   %" PRIu64 "\n", self->our_msat);
        fprintf(fp, "their_msat: %" PRIu64 "\n", self->their_msat);
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
    fprintf(fp, "=(%d)======================================================\n\n\n", line);
}
