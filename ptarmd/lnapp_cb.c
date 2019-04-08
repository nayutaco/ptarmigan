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
 * prototypes
 ********************************************************************/

static void cb_channel_quit(lnapp_conf_t *pConf, void *pParam);
static void cb_error_recv(lnapp_conf_t *pConf, void *pParam);
static void cb_init_recv(lnapp_conf_t *pConf, void *pParam);
static void cb_channel_reestablish_recv(lnapp_conf_t *pConf, void *pParam);
static void cb_funding_tx_sign(lnapp_conf_t *pConf, void *pParam);
static void cb_funding_tx_wait(lnapp_conf_t *pConf, void *pParam);
static void cb_funding_locked(lnapp_conf_t *pConf, void *pParam);
static void cb_update_anno_db(lnapp_conf_t *pConf, void *pParam);
static void cb_add_htlc_recv(lnapp_conf_t *pConf, void *pParam);
static void cb_fulfill_htlc_recv(lnapp_conf_t *pConf, void *pParam);
static void cbsub_fulfill_backwind(lnapp_conf_t *pConf, ln_cb_param_notify_fulfill_htlc_recv_t *pCbParam);
static void cbsub_fulfill_originnode(lnapp_conf_t *pConf, ln_cb_param_notify_fulfill_htlc_recv_t *pCbParam);
static void cb_bwd_delhtlc_start(lnapp_conf_t *pConf, void *pParam);
static void cbsub_fail_backwind(lnapp_conf_t *pConf, ln_cb_param_start_bwd_del_htlc_t *pCbParam);
static void cbsub_fail_originnode(lnapp_conf_t *pConf, ln_cb_param_start_bwd_del_htlc_t *pCbParam);
static void cb_rev_and_ack_excg(lnapp_conf_t *pConf, void *pParam);
static void cb_payment_retry(lnapp_conf_t *pConf, void *pParam);
static void cb_update_fee_recv(lnapp_conf_t *pConf, void *pParam);
static void cb_shutdown_recv(lnapp_conf_t *pConf, void *pParam);
static void cb_closed_fee(lnapp_conf_t *pConf, void *pParam);
static void cb_closed(lnapp_conf_t *pConf, void *pParam);
static void cb_send_req(lnapp_conf_t *pConf, void *pParam);
static void cb_get_latest_feerate(lnapp_conf_t *pConf, void *pParam);
static void cb_getblockcount(lnapp_conf_t *pConf, void *pParam);
static void cb_pong_recv(lnapp_conf_t *pConf, void *pParam);


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_notify_cb(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam)
{
    //DBGTRACE_BEGIN

    lnapp_conf_t *p_conf = (lnapp_conf_t*)pCommonParam;
    void *p_param = pTypeSpecificParam;

    const struct {
        const char *p_msg;
        void (*func)(lnapp_conf_t *p_conf, void *p_param);
    } MAP[] = {
        { "  LN_CB_TYPE_STOP_CHANNEL: channel quit", cb_channel_quit },
        { "  LN_CB_TYPE_NOTIFY_ERROR: error receive", cb_error_recv },
        { "  LN_CB_TYPE_NOTIFY_INIT_RECV: init receive", cb_init_recv },
        { "  LN_CB_TYPE_NOTIFY_REESTABLISH_RECV: channel_reestablish receive", cb_channel_reestablish_recv },
        { "  LN_CB_TYPE_SIGN_FUNDING_TX: funding_tx sign request", cb_funding_tx_sign },
        { "  LN_CB_TYPE_WAIT_FUNDING_TX: funding_tx confirmation wait request", cb_funding_tx_wait },
        { "  LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV: funding_locked receive", cb_funding_locked },
        { NULL/*"  LN_CB_TYPE_NOTIFY_ANNODB_UPDATE: announcement DB update"*/, cb_update_anno_db },

        { "  LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV: update_add_htlc receive", cb_add_htlc_recv },
        { "  LN_CB_TYPE_START_BWD_DEL_HTLC: delete htlc", cb_bwd_delhtlc_start },
        { "  LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV: update_fulfill_htlc receive", cb_fulfill_htlc_recv },

        { "  LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE: revoke_and_ack exchange", cb_rev_and_ack_excg },
        { "  LN_CB_TYPE_RETRY_PAYMENT: payment retry", cb_payment_retry},
        { "  LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV: update_fee receive", cb_update_fee_recv },
        { "  LN_CB_TYPE_NOTIFY_SHUTDOWN_RECV: shutdown receive", cb_shutdown_recv },
        { "  LN_CB_TYPE_UPDATE_CLOSING_FEE: closing_signed receive(not same fee)", cb_closed_fee },
        { "  LN_CB_TYPE_NOTIFY_CLOSING_END: closing_signed receive(same fee)", cb_closed },
        { "  LN_CB_TYPE_SEND_MESSAGE: send request", cb_send_req },
        { "  LN_CB_TYPE_GET_LATEST_FEERATE: get feerate_per_kw", cb_get_latest_feerate },
        { "  LN_CB_TYPE_GET_BLOCK_COUNT: getblockcount", cb_getblockcount },
        { "  LN_CB_TYPE_NOTIFY_PONG_RECV: pong receive", cb_pong_recv },
    };

    if (Type < LN_CB_TYPE_MAX) {
        if (MAP[Type].p_msg != NULL) {
            LOGD("%s\n", MAP[Type].p_msg);
        }
        (*MAP[Type].func)(p_conf, p_param);
    } else {
        LOGE("fail: invalid Type: %d\n", Type);
    }

    //DBGTRACE_END
}


static void cb_channel_quit(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;
    LOGD("stop channel\n");

    lnapp_stop_threads(pConf);
}


//LN_CB_TYPE_NOTIFY_ERROR: error受信
static void cb_error_recv(lnapp_conf_t *pConf, void *pParam)
{
    const ln_msg_error_t *p_msg = (const ln_msg_error_t *)pParam;
    const uint8_t *p_channel_id;
    if ( (ln_short_channel_id(&pConf->channel) == 0) ||
          utl_mem_is_all_zero(p_msg->p_channel_id, LN_SZ_CHANNEL_ID) ) {
        p_channel_id = NULL;
    } else {
        p_channel_id = p_msg->p_channel_id;
    }


    bool b_printable = true;
    for (uint16_t lp = 0; lp < p_msg->len; lp++) {
        if (!isprint(p_msg->p_data[lp])) {
            b_printable = false;
            break;
        }
    }
    if (b_printable) {
        char *p_data = (char *)UTL_DBG_MALLOC(p_msg->len + 1);
        memcpy(p_data, p_msg->p_data, p_msg->len);
        p_data[p_msg->len] = '\0';
        lnapp_set_last_error(pConf, RPCERR_PEER_ERROR, p_data);
        ptarmd_eventlog(p_channel_id, "error message(ascii): %s", p_data);
        UTL_DBG_FREE(p_data);
    } else {
        char *p_data = (char *)UTL_DBG_MALLOC(p_msg->len * 2 + 1);
        utl_str_bin2str(p_data, (const uint8_t *)p_msg->p_data, p_msg->len);
        lnapp_set_last_error(pConf, RPCERR_PEER_ERROR, p_data);
        ptarmd_eventlog(p_channel_id, "error message(dump): %s", p_data);
        UTL_DBG_FREE(p_data);
    }

    if (pConf->funding_waiting) {
        LOGD("stop funding by error\n");
        pConf->funding_waiting = false;
    }

    lnapp_stop_threads(pConf);
}


//LN_CB_TYPE_NOTIFY_INIT_RECV: init受信
static void cb_init_recv(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;
    DBGTRACE_BEGIN

    //init受信待ち合わせ解除(*1)
    pConf->flag_recv |= M_FLAGRECV_INIT;
}


//LN_CB_TYPE_NOTIFY_REESTABLISH_RECV: channel_reestablish受信
static void cb_channel_reestablish_recv(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;
    DBGTRACE_BEGIN

    //channel_reestablish受信待ち合わせ解除(*3)
    pConf->flag_recv |= M_FLAGRECV_REESTABLISH;
}


//LN_CB_TYPE_SIGN_FUNDING_TX: funding_tx署名要求
static void cb_funding_tx_sign(lnapp_conf_t *pConf, void *pParam)
{
    (void)pConf;
    DBGTRACE_BEGIN

    ln_cb_param_sign_funding_tx_t *p_cb_param = (ln_cb_param_sign_funding_tx_t *)pParam;

    p_cb_param->ret = btcrpc_sign_fundingtx(
        p_cb_param->p_tx, p_cb_param->buf_tx.buf,
        p_cb_param->buf_tx.len, p_cb_param->fundin_amount);
}


//LN_CB_TYPE_WAIT_FUNDING_TX: funding_txのconfirmation待ち開始
static void cb_funding_tx_wait(lnapp_conf_t *pConf, void *pParam)
{
    DBGTRACE_BEGIN

    ln_cb_param_wait_funding_tx_t *p_cb_param = (ln_cb_param_wait_funding_tx_t *)pParam;

    if (p_cb_param->b_send) {
        uint8_t txid[BTC_SZ_TXID];

        utl_buf_t buf_tx = UTL_BUF_INIT;
        btc_tx_write(p_cb_param->p_tx_funding, &buf_tx);

        p_cb_param->ret = btcrpc_send_rawtx(txid, NULL, buf_tx.buf, buf_tx.len);
        if (p_cb_param->ret) {
            LOGD("$$$ broadcast funding_tx\n");
        } else {
            LOGE("fail: broadcast funding_tx, but should ignore it\n");
            p_cb_param->ret = true;
        }
        utl_buf_free(&buf_tx);
    } else {
        p_cb_param->ret = true;
    }

    if (p_cb_param->ret) {
        //fundingの監視は thread_poll_start()に任せる
        LOGD("$$$ watch funding_txid: ");
        TXIDD(ln_funding_info_txid(&pConf->channel.funding_info));
        pConf->funding_waiting = true;

        btcrpc_set_channel(
            ln_remote_node_id(&pConf->channel),
            ln_short_channel_id(&pConf->channel),
            ln_funding_info_txid(&pConf->channel.funding_info),
            ln_funding_info_txindex(&pConf->channel.funding_info),
            ln_funding_info_wit_script(&pConf->channel.funding_info),
            ln_funding_blockhash(&pConf->channel),
            ln_funding_last_confirm_get(&pConf->channel));

        const char *p_str;
        if (ln_funding_info_is_funder(&pConf->channel.funding_info, true)) {
            p_str = "funder";
        } else {
            p_str = "fundee";
        }
        char str_peerid[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(str_peerid, ln_remote_node_id(&pConf->channel), BTC_SZ_PUBKEY);
        ptarmd_eventlog(
            ln_channel_id(&pConf->channel),
            "open: funding wait start(%s): peer_id=%s",
            p_str, str_peerid);

        pConf->annosig_send_req = ln_open_channel_announce(&pConf->channel);
        pConf->feerate_per_kw = ln_feerate_per_kw(&pConf->channel);
    } else {
        LOGE("fail: broadcast\n");
        ptarmd_eventlog(
            ln_channel_id(&pConf->channel),
            "fail: broadcast funding_tx\n");
        lnapp_stop_threads(pConf);
    }

    ln_node_addr_t conn_addr;
    bool ret = utl_addr_ipv4_str2bin(conn_addr.addr, pConf->conn_str);
    if (ret) {
        conn_addr.type = LN_ADDR_DESC_TYPE_IPV4;
        conn_addr.port = pConf->conn_port;
        ln_last_connected_addr_set(&pConf->channel, &conn_addr);
    }

    DBGTRACE_END
}


//LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV: funding_locked受信通知
static void cb_funding_locked(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;
    DBGTRACE_BEGIN

    if ((pConf->flag_recv & M_FLAGRECV_REESTABLISH) == 0) {
        //channel establish時のfunding_locked
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
        ptarmd_eventlog(
            ln_channel_id(&pConf->channel),
            "open: recv funding_locked short_channel_id=%s",
            str_sci);
    }

    //funding_locked受信待ち合わせ解除(*4)
    pConf->flag_recv |= M_FLAGRECV_FUNDINGLOCKED;
}


//LN_CB_TYPE_NOTIFY_ANNODB_UPDATE: announcement DB更新通知
static void cb_update_anno_db(lnapp_conf_t *pConf, void *pParam)
{
    (void)pConf;
    ln_cb_param_notify_annodb_update_t *p_cb_param = (ln_cb_param_notify_annodb_update_t *)pParam;

    if (p_cb_param->type != LN_CB_ANNO_TYPE_NONE) {
        LOGD("update anno db: %d\n", (int)p_cb_param->type);
        pConf->annodb_updated = true;
    }
    if (p_cb_param->type == LN_CB_ANNO_TYPE_CNL_ANNO) {
        time_t now = utl_time_time();
        if (now - pConf->annodb_stamp < LNAPP_WAIT_ANNO_HYSTER_SEC) {
            //announcement連続受信中とみなす
            pConf->annodb_cont = true;
        } else {
            pConf->annodb_cont = false;
        }
        pConf->annodb_stamp = now;
        LOGD("annodb_stamp: %u\n", pConf->annodb_stamp);
    }
}


/** LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV: update_add_htlc受信(後処理)
 *
 * add_htlc受信後は、以下のどれかになる。
 *      - add_htlcがOK
 *          - 自分がfinal node --> fulfill_htlcを巻き戻していく
 *          - else             --> add_htlcを転送する
 *      - add_htlcがNG
 *          - fail_htlcを巻き戻していく
 */
static void cb_add_htlc_recv(lnapp_conf_t *pConf, void *pParam)
{
    DBGTRACE_BEGIN

    ln_cb_param_nofity_add_htlc_recv_t *p_cb_param = (ln_cb_param_nofity_add_htlc_recv_t *)pParam;
    const char *p_info;
    char str_stat[256];

    if (p_cb_param->next_short_channel_id) {
        LOGD("forward\n");

        snprintf(
            str_stat, sizeof(str_stat), "-->[fwd]0x%016" PRIx64 ", cltv=%d",
            p_cb_param->next_short_channel_id,
            p_cb_param->p_forward_param->outgoing_cltv_value);
        p_info = str_stat;

        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
        char str_hash[BTC_SZ_HASH256 * 2 + 1];
        utl_str_bin2str(str_hash, p_cb_param->p_payment_hash, BTC_SZ_HASH256);
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
        char param[M_SZ_SCRIPT_PARAM];
        snprintf(
            param, sizeof(param), "%s %s %" PRIu64 " %" PRIu32 " %s",
            str_sci, node_id, p_cb_param->p_forward_param->amt_to_forward,
            p_cb_param->p_forward_param->outgoing_cltv_value, str_hash);
        ptarmd_call_script(PTARMD_EVT_FORWARD, param);

#if 0 //XXX: channel_id   
        ptarmd_eventlog(
            ln_channel_id(&p_nextconf->channel),
            "[SEND]add_htlc: amount_msat=%" PRIu64 ", cltv=%d",
            p_cb_param->p_forward_param->amt_to_forward,
            p_cb_param->p_forward_param->outgoing_cltv_value);
#endif

        p_cb_param->ret = true;
    } else {
        LOGD("final node\n");

        p_info = "final node";
        p_cb_param->ret = true;

        char str_payment_hash[BTC_SZ_HASH256 * 2 + 1];
        utl_str_bin2str(str_payment_hash, p_cb_param->p_payment_hash, BTC_SZ_HASH256);
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
        ptarmd_eventlog(NULL, "payment final node: payment_hash=%s, short_channel_id=%s", str_payment_hash, str_sci);
    }

    ptarmd_eventlog(
        ln_channel_id(&pConf->channel),
        "[RECV]add_htlc: %s(HTLC id=%" PRIu64 ", amount_msat=%" PRIu64 ", cltv=%d)",
        p_info, p_cb_param->prev_htlc_id,
        p_cb_param->amount_msat, p_cb_param->cltv_expiry);

    DBGTRACE_END
}


//LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV: update_fulfill_htlc受信
static void cb_fulfill_htlc_recv(lnapp_conf_t *pConf, void *pParam)
{
    DBGTRACE_BEGIN

    ln_cb_param_notify_fulfill_htlc_recv_t *p_cb_param = (ln_cb_param_notify_fulfill_htlc_recv_t *)pParam;
    const char *p_info;
    char str_stat[256];

    if (p_cb_param->prev_short_channel_id) {
        LOGD("backwind: prev_htlc_id=%" PRIu64 ", prev_short_channel_id=%016" PRIx64 "\n",
            p_cb_param->prev_htlc_id, p_cb_param->prev_short_channel_id);
        snprintf(str_stat, sizeof(str_stat), "-->[fwd]%016" PRIx64, p_cb_param->prev_short_channel_id);
        p_info = str_stat;
        cbsub_fulfill_backwind(pConf, p_cb_param);
    } else {
        LOGD("origin node\n");
        p_info = "origin node";
        cbsub_fulfill_originnode(pConf, p_cb_param);
    }

    ptarmd_eventlog(ln_channel_id(&pConf->channel),
        "[RECV]fulfill_htlc: %s(HTLC id=%" PRIu64 "): %s",
            p_info,
            p_cb_param->prev_htlc_id,
            ((p_cb_param->ret) ? "success" : "fail"));

    DBGTRACE_END
}


//cb_fulfill_htlc_recv(): 巻き戻し
static void cbsub_fulfill_backwind(lnapp_conf_t *pConf, ln_cb_param_notify_fulfill_htlc_recv_t *pCbParam)
{
    (void)pConf;

    lnapp_conf_t *p_prev_conf = ptarmd_search_transferable_channel(pCbParam->prev_short_channel_id);
    if (p_prev_conf) {
        lnapp_show_channel_param(&pConf->channel, stderr, "fulfill_htlc send", __LINE__);

        // method: fulfill
        // $1: short_channel_id
        // $2: node_id
        // $3: payment_hash
        // $4: payment_preimage
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
        char str_hash[BTC_SZ_HASH256 * 2 + 1];
        uint8_t payment_hash[BTC_SZ_HASH256];
        ln_payment_hash_calc(payment_hash, pCbParam->p_preimage);
        utl_str_bin2str(str_hash, payment_hash, BTC_SZ_HASH256);
        char str_preimage[LN_SZ_PREIMAGE * 2 + 1];
        utl_str_bin2str(str_preimage, pCbParam->p_preimage, LN_SZ_PREIMAGE);
        char str_node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(str_node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
        char param[M_SZ_SCRIPT_PARAM];
        snprintf(
            param, sizeof(param), "%s %s %s %s",
            str_sci, str_node_id, str_hash, str_preimage);
        ptarmd_call_script(PTARMD_EVT_FULFILL, param);

        ptarmd_eventlog(
            ln_channel_id(&p_prev_conf->channel),
            "[SEND]fulfill_htlc: HTLC id=%" PRIu64,
            pCbParam->prev_htlc_id);

        pCbParam->ret = true;

        lnapp_manager_free_node_ref(p_prev_conf);
    }
}


//cb_fulfill_htlc_recv(): origin node
static void cbsub_fulfill_originnode(lnapp_conf_t *pConf, ln_cb_param_notify_fulfill_htlc_recv_t *pCbParam)
{
    (void)pConf;

    if (!lnapp_payment_route_del(pCbParam->prev_htlc_id)) {
        LOGE("fail: ???\n");
    }

    uint8_t hash[BTC_SZ_HASH256];
    ln_payment_hash_calc(hash, pCbParam->p_preimage);
    cmd_json_pay_result(hash, pCbParam->p_preimage, "success");
    ln_db_invoice_del(hash);
    ln_db_route_skip_work(false);
    pCbParam->ret = true;

    //log
    char str_payment_hash[BTC_SZ_HASH256 * 2 + 1];
    utl_str_bin2str(str_payment_hash, hash, BTC_SZ_HASH256);
    ptarmd_eventlog(NULL, "payment fulfill[id=%" PRIu64 "]: payment_hash=%s, amount_msat=%" PRIu64,
        pCbParam->prev_htlc_id, str_payment_hash, pCbParam->amount_msat);
}


/** LN_CB_TYPE_START_BWD_DEL_HTLC: update_fail_htlc転送指示
 *
 */
static void cb_bwd_delhtlc_start(lnapp_conf_t *pConf, void *pParam)
{
    DBGTRACE_BEGIN

    ln_cb_param_start_bwd_del_htlc_t *p_cb_param = (ln_cb_param_start_bwd_del_htlc_t *)pParam;
    const char *p_info;
    char str_stat[256];

    if (p_cb_param->prev_short_channel_id) {
        LOGD("backwind fail_htlc: prev_htlc_id=%" PRIu64 ", prev_short_channel_id=%016" PRIx64 ")\n",
            p_cb_param->prev_htlc_id, p_cb_param->prev_short_channel_id);
        snprintf(str_stat, sizeof(str_stat), "-->%016" PRIx64, p_cb_param->prev_short_channel_id);
        p_info = str_stat;
        cbsub_fail_backwind(pConf, p_cb_param);
    } else {
        LOGD("origin node\n");
        p_info = "origin node";
        cbsub_fail_originnode(pConf, p_cb_param);
    }

    if (p_cb_param->ret) {
        lnapp_show_channel_param(&pConf->channel, stderr, "fail_htlc send", __LINE__);

        // method: fail
        // $1: short_channel_id
        // $2: node_id
        // $3: info
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
        char str_node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(str_node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
        char param[M_SZ_SCRIPT_PARAM];
        snprintf(
            param, sizeof(param), "%s %s \"%s\"",
            str_sci, str_node_id, p_info);
        ptarmd_call_script(PTARMD_EVT_FAIL, param);
    }

    ptarmd_eventlog(
        ln_channel_id(&pConf->channel),
        "[RECV]fail_htlc: %s(HTLC id=%" PRIu64 ")",
        p_info, p_cb_param->prev_htlc_id);

    DBGTRACE_END
}


static void cbsub_fail_backwind(lnapp_conf_t *pConf, ln_cb_param_start_bwd_del_htlc_t *pCbParam)
{
    (void)pConf;

    bool ret = false;
    lnapp_conf_t *p_prev_conf = ptarmd_search_transferable_channel(pCbParam->prev_short_channel_id);
    if (p_prev_conf) {
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
        ptarmd_eventlog(
            NULL, "delete HTLC: short_channel_id=%s, fin_type=%d",
            str_sci, pCbParam->update_type);

        ret = true;

        lnapp_manager_free_node_ref(p_prev_conf);
    } else {
        LOGE("fail: short_channel_id not found(%016" PRIx64 ")\n", pCbParam->prev_short_channel_id);
    }
    pCbParam->ret = ret;
}


static void cbsub_fail_originnode(lnapp_conf_t *pConf, ln_cb_param_start_bwd_del_htlc_t *pCbParam)
{
    utl_buf_t reason = UTL_BUF_INIT;
    int hop;
    bool ret = false;
    if (pCbParam->fail_malformed_failure_code == 0) {
        // update_fail_htlc
        utl_buf_t shared_secrets = UTL_BUF_INIT;
        if (ln_db_payment_shared_secrets_load(&shared_secrets, pCbParam->prev_htlc_id)) {
            if (!ln_db_payment_shared_secrets_del(pCbParam->prev_htlc_id)) {
                LOGE("fail: ???\n");
            }
            ret = ln_onion_failure_read(&reason, &hop, &shared_secrets, pCbParam->p_reason);
        } else {
            LOGE("fail: ???\n");
        }
    } else {
        // update_fail_malformed_htlc
        uint16_t failure_code = utl_int_pack_u16be(pCbParam->p_reason->buf);
        ret = (failure_code == pCbParam->fail_malformed_failure_code);
        utl_buf_alloccopy(&reason, pCbParam->p_reason->buf, pCbParam->p_reason->len);
        hop = 0;
    }
    pCbParam->ret = ret;

    if (ret) {
        LOGD("  failure reason= ");
        DUMPD(reason.buf, reason.len);

        ln_onion_err_t onionerr;
        ret = ln_onion_read_err(&onionerr, &reason);  //onionerr.p_data = UTL_DBG_MALLOC()
        bool btemp = true;
        if (ret) {
            switch (onionerr.reason) {
            case LNONION_PERM_NODE_FAIL:
            case LNONION_PERM_CHAN_FAIL:
            case LNONION_CHAN_DISABLE:
                LOGD("add skip route: permanently\n");
                btemp = false;
                break;
            default:
                break;
            }
        }

        //失敗したと思われるshort_channel_idをrouting除外登録
        //  route.hop_datain
        //      [0]自分(update_add_htlcのパラメータ)
        //      [1]最初のONIONデータ
        //      ...
        //      [hop_num - 2]payeeへの最終OINONデータ
        //      [hop_num - 1]ONIONの終端データ(short_channel_id=0, cltv_expiryとamount_msatはupdate_add_htlcと同じ)
        char suggest[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        payment_conf_t payconf;
        if (lnapp_payment_route_load(&payconf, pCbParam->prev_htlc_id)) {
            // for (int lp = 0; lp < p_payconf->hop_num; lp++) {
            //     LOGD("@@@[%d]%016" PRIx64 ", %" PRIu64 ", %" PRIu32 "\n",
            //             lp,
            //             payconf.hop_datain[lp].short_channel_id,
            //             payconf.hop_datain[lp].amt_to_forward,
            //             payconf.hop_datain[lp].outgoing_cltv_value);
            // }
            uint64_t short_channel_id = 0;
            if (hop == payconf.hop_num - 2) {
                //payeeは自分がINとなるchannelを失敗したとみなす
                short_channel_id = payconf.hop_datain[payconf.hop_num - 2].short_channel_id;
            } else if (hop < payconf.hop_num - 2) {
                short_channel_id = payconf.hop_datain[hop + 1].short_channel_id;
            } else {
                LOGE("fail: invalid result\n");
                strcpy(suggest, "invalid");
            }
            if (short_channel_id != 0) {
                ln_db_route_skip_save(short_channel_id, btemp);
                ln_short_channel_id_string(suggest, short_channel_id);
                pCbParam->ret = true;
            }
        } else {
            LOGE("fail: ???\n");
            strcpy(suggest, "?");
        }

        char errstr[512];
        char *reasonstr = ln_onion_get_errstr(&onionerr);
        snprintf(errstr, sizeof(errstr), M_ERRSTR_REASON, reasonstr, hop, suggest);
        LOGE("fail: %s\n", errstr);
        cmd_json_pay_result(pCbParam->p_payment_hash, NULL, errstr);
        UTL_DBG_FREE(reasonstr);
        UTL_DBG_FREE(onionerr.p_data);
    } else {
        //デコード失敗
        lnapp_set_last_error(pConf, RPCERR_PAYFAIL, M_ERRSTR_CANNOTDECODE);
    }
    if (!lnapp_payment_route_del(pCbParam->prev_htlc_id)) {
        LOGE("fail: ???\n");
    }
}


//LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE: revoke_and_ack交換通知
static void cb_rev_and_ack_excg(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;
    DBGTRACE_BEGIN

    // method: htlc_changed
    // $1: short_channel_id
    // $2: node_id
    // $3: local_msat
    char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
    char param[M_SZ_SCRIPT_PARAM];
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    uint64_t total_amount = ln_node_total_msat();

    ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
    utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
    snprintf(param, sizeof(param), "%s %s "
                "%" PRIu64,
                str_sci, node_id,
                total_amount);
    ptarmd_call_script(PTARMD_EVT_HTLCCHANGED, param);

    lnapp_show_channel_param(&pConf->channel, stderr, "revoke_and_ack", __LINE__);

    ptarmd_eventlog(NULL, "exchanged revoke_and_ack: total_msat=%" PRIu64, total_amount);

    DBGTRACE_END
}


//LN_CB_TYPE_RETRY_PAYMENT: 送金リトライ
static void cb_payment_retry(lnapp_conf_t *pConf, void *pParam)
{
    (void)pConf;

    DBGTRACE_BEGIN

    const uint8_t *p_hash = (const uint8_t *)pParam;
    cmd_json_pay_retry(p_hash);
}


//LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV: update_fee受信
static void cb_update_fee_recv(lnapp_conf_t *pConf, void *pParam)
{
    DBGTRACE_BEGIN

    uint32_t oldrate = *(const uint32_t *)pParam;

    ptarmd_eventlog(ln_channel_id(&pConf->channel),
            "updatefee recv: feerate_per_kw=%" PRIu32 " --> %" PRIu32,
            oldrate, ln_feerate_per_kw(&pConf->channel));
}


//LN_CB_TYPE_NOTIFY_SHUTDOWN_RECV: shutdown受信
static void cb_shutdown_recv(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;
    DBGTRACE_BEGIN

    ptarmd_eventlog(ln_channel_id(&pConf->channel), "close: recv shutdown");
}


//LN_CB_TYPE_UPDATE_CLOSING_FEE: closing_signed受信(FEE不一致)
static void cb_closed_fee(lnapp_conf_t *pConf, void *pParam)
{
    DBGTRACE_BEGIN

    const ln_cb_param_update_closing_fee_t *p_cb_param = (const ln_cb_param_update_closing_fee_t *)pParam;
    LOGD("received fee: %" PRIu64 "\n", p_cb_param->fee_sat);

    //ToDo: How to decide shutdown fee
    ln_shutdown_update_fee(&pConf->channel, p_cb_param->fee_sat);
}


//LN_CB_TYPE_NOTIFY_CLOSING_END: closing_singed受信(FEE一致)
//  コールバック後、p_channelはクリアされる
static void cb_closed(lnapp_conf_t *pConf, void *pParam)
{
    DBGTRACE_BEGIN

    ln_cb_param_notify_closing_end_t *p_cb_param = (ln_cb_param_notify_closing_end_t *)pParam;

    if (LN_DBG_CLOSING_TX()) {
        //closing_txを展開
        uint8_t txid[BTC_SZ_TXID];
        p_cb_param->result = btcrpc_send_rawtx(txid, NULL, p_cb_param->p_tx_closing->buf, p_cb_param->p_tx_closing->len);
        if (p_cb_param->result) {
            LOGD("$$$ broadcast\n");

            // method: closed
            // $1: short_channel_id
            // $2: node_id
            // $3: closing_txid
            char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
            ln_short_channel_id_string(str_sci, ln_short_channel_id(&pConf->channel));
            char param[M_SZ_SCRIPT_PARAM];
            char txidstr[BTC_SZ_TXID * 2 + 1];
            utl_str_bin2str_rev(txidstr, txid, BTC_SZ_TXID);
            char node_id[BTC_SZ_PUBKEY * 2 + 1];
            utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
            snprintf(param, sizeof(param), "%s %s "
                        "%s",
                        str_sci, node_id,
                        txidstr);
            ptarmd_call_script(PTARMD_EVT_CLOSED, param);
            ptarmd_eventlog(NULL, "close: good way: %s", txidstr);

            lnapp_stop_threads(pConf);
        } else {
            LOGE("fail: broadcast\n");
        }
    } else {
        LOGD("DBG: no send closing_tx mode\n");
    }
    ptarmd_eventlog(ln_channel_id(&pConf->channel), "close: good way: end");

    DBGTRACE_END
}


//LN_CB_TYPE_SEND_MESSAGE: BOLTメッセージ送信要求
static void cb_send_req(lnapp_conf_t *pConf, void *pParam)
{
    utl_buf_t *p_buf = (utl_buf_t *)pParam;
    (void)lnapp_send_peer_noise(pConf, p_buf);
}


//LN_CB_TYPE_GET_LATEST_FEERATE: estimatesmartfeeによるfeerate_per_kw取得
static void cb_get_latest_feerate(lnapp_conf_t *pConf, void *pParam)
{
    uint32_t *p_rate = (uint32_t *)pParam;
    *p_rate = pConf->feerate_per_kw;
}


//LN_CB_TYPE_GET_BLOCK_COUNT
static void cb_getblockcount(lnapp_conf_t *pConf, void *pParam)
{
    (void)pConf;

    int32_t *p_height = (int32_t *)pParam;
    bool ret = monitor_btc_getblockcount(p_height);
    if (ret) {
        LOGD("block count=%" PRId32 "\n", *p_height);
    } else {
        LOGE("fail: get block count\n");
        *p_height = 0;
    }
}


//LN_CB_TYPE_NOTIFY_PONG_RECV
static void cb_pong_recv(lnapp_conf_t *pConf, void *pParam)
{
    ln_cb_param_notify_pong_recv_t *p_cb_param = (ln_cb_param_notify_pong_recv_t *)pParam;

    //compare oldest num_pong_bytes
    ponglist_t *p_tail = NULL;
    ponglist_t *p = LIST_FIRST(&pConf->pong_head);
    while (p != NULL) {
        p_tail = p;
        p = LIST_NEXT(p, list);
    }
    if (p_tail != NULL) {
        if (p_tail->num_pong_bytes == p_cb_param->byteslen) {
            //OK
            LOGD("pong OK\n");
            p_cb_param->ret = true;
        } else {
            //num_pong_bytes mismatch
            LOGE("fail: num_pong_bytes mismatch\n");
            lnapp_stop_threads(pConf);
        }
        LIST_REMOVE(p_tail, list);
        UTL_DBG_FREE(p_tail);
    } else {
        //unknown pong
        LOGE("fail: I don't send ping\n");
        lnapp_stop_threads(pConf);
    }
}
