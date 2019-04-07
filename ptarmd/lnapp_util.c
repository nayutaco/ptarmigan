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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>

#include "cJSON.h"

#define LOG_TAG     "lnapp"
#include "utl_log.h"
#include "utl_time.h"
#include "utl_thread.h"
#include "utl_int.h"

#include "btc_crypto.h"

#include "ln_msg.h"

#include "ptarmd.h"
#include "p2p.h"
#include "lnapp.h"
#include "lnapp_util.h"
#include "lnapp_manager.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_WAIT_SEND_TO_MSEC     (500)       //socket送信待ちタイムアウト[msec]
#define M_WAIT_SEND_WAIT_MSEC   (100)       //socket送信で一度に送信できなかった場合の待ち時間[msec]


/********************************************************************
 * public functions
 ********************************************************************/

//スレッドループ停止
void lnapp_stop_threads(lnapp_conf_t *p_conf)
{
    LOGD("$$$ stop\n");
    pthread_mutex_lock(&p_conf->mux_conf);
    if (p_conf->active) {
        p_conf->active = false;
        //mainloop待ち合わせ解除(*2)
        pthread_cond_signal(&p_conf->cond);
        LOGD("=========================================\n");
        LOGD("=  CHANNEL THREAD END: %016" PRIx64 " =\n", ln_short_channel_id(&p_conf->channel));
        LOGD("=========================================\n");
    }
    pthread_mutex_unlock(&p_conf->mux_conf);
    LOGD("$$$ stopped\n");
}


//peer送信(そのまま送信)
bool lnapp_send_peer_raw(lnapp_conf_t *p_conf, const utl_buf_t *pBuf)
{
    struct pollfd fds;
    ssize_t len = pBuf->len;
    while ((p_conf->active) && (len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLOUT;
        int polr = poll(&fds, 1, M_WAIT_SEND_TO_MSEC);
        if (polr <= 0) {
            LOGE("fail poll: %s\n", strerror(errno));
            break;
        }
        ssize_t sz = write(p_conf->sock, pBuf->buf, len);
        if (sz < 0) {
            LOGE("fail write: %s\n", strerror(errno));
            break;
        }
        len -= sz;
        if (len > 0) {
            utl_thread_msleep(M_WAIT_SEND_WAIT_MSEC);
        }
    }

    return len == 0;
}


//peer送信(Noise Protocol送信)
bool lnapp_send_peer_noise(lnapp_conf_t *p_conf, const utl_buf_t *pBuf)
{
    uint16_t type = utl_int_pack_u16be(pBuf->buf);
    LOGD("[SEND]type=%04x(%s): sock=%d, Len=%d\n", type, ln_msg_name(type), p_conf->sock, pBuf->len);

    pthread_mutex_lock(&p_conf->mux_send);

    utl_buf_t buf_enc = UTL_BUF_INIT;
    struct pollfd fds;
    ssize_t len = -1;

    bool ret = ln_noise_enc(&p_conf->noise, &buf_enc, pBuf);
    if (!ret) {
        LOGE("fail: noise encode\n");
        goto LABEL_EXIT;
    }

    len = buf_enc.len;
    while ((p_conf->active) && (len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLOUT;
        int polr = poll(&fds, 1, M_WAIT_SEND_TO_MSEC);
        if (polr <= 0) {
            LOGE("fail poll: %s\n", strerror(errno));
            break;
        }
        ssize_t sz = write(p_conf->sock, buf_enc.buf, len);
        if (sz < 0) {
            LOGE("fail write: %s\n", strerror(errno));
            lnapp_stop_threads(p_conf);
            break;
        }
        len -= sz;
        if (len > 0) {
            utl_thread_msleep(M_WAIT_SEND_WAIT_MSEC);
        }
    }
    utl_buf_free(&buf_enc);

LABEL_EXIT:
    pthread_mutex_unlock(&p_conf->mux_send);
    return len == 0;
}


#if 0
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
void lnapp_payroute_push(lnapp_conf_t *p_conf, const payment_conf_t *pPayConf, uint64_t HtlcId)
{
    routelist_t *rt = (routelist_t *)UTL_DBG_MALLOC(sizeof(routelist_t));       //UTL_DBG_FREE: lnapp_payroute_del()

    memcpy(&rt->route, pPayConf, sizeof(payment_conf_t));
    rt->htlc_id = HtlcId;
    LIST_INSERT_HEAD(&p_conf->payroute_head, rt, list);
    LOGD("htlc_id: %" PRIu64 "\n", HtlcId);

    lnapp_payroute_print(p_conf);
}


/** 送金情報リスト取得
 *
 * update_add_htlcの送信元がupdate_fail_htlcを受信した際、
 * #lnapp_payroute_push() で保持していたルート情報とreasonから、どのchannelで失敗したかを判断するために使用する。
 * 自分がupdate_add_htlcの送信元の場合だけリストに保持している。
 *
 * @param[in]       p_conf
 * @param[in]       HtlcId
 */
const payment_conf_t* lnapp_payroute_get(lnapp_conf_t *p_conf, uint64_t HtlcId)
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
 * update_add_htlc送信元が追加するリストから、指定したHTLC idの情報を削除する。
 *      - update_fulfill_htlc受信
 *      - update_fail_htlc受信
 *
 * @param[in,out]   p_conf
 * @param[in]       HtlcId
 */
void lnapp_payroute_del(lnapp_conf_t *p_conf, uint64_t HtlcId)
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

    lnapp_payroute_print(p_conf);
}


/** 送金情報リストの全削除
 *
 */
void lnapp_payroute_clear(lnapp_conf_t *p_conf)
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
void lnapp_payroute_print(lnapp_conf_t *p_conf)
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
#endif


bool lnapp_payment_route_save(uint64_t PaymentId, const payment_conf_t *pConf)
{
    return ln_db_payment_route_save(PaymentId, (const uint8_t *)pConf->hop_datain, pConf->hop_num * sizeof(ln_hop_datain_t));
}


bool lnapp_payment_route_load(payment_conf_t *pConf, uint64_t PaymentId)
{
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_db_payment_route_load(&buf, PaymentId)) {
        LOGE("fail: ???\n");
        return false;
    }
    if (buf.len % sizeof(ln_hop_datain_t)) {
        LOGE("fail: ???\n");
        utl_buf_free(&buf);
        return false;
    }
    pConf->hop_num = buf.len / sizeof(ln_hop_datain_t);
    memcpy(pConf->hop_datain, buf.buf, buf.len);
    utl_buf_free(&buf);
    return true;
}


bool lnapp_payment_route_del(uint64_t PaymentId)
{
    return ln_db_payment_route_del(PaymentId);
}




/** エラー文字列設定
 *
 */
void lnapp_set_last_error(lnapp_conf_t *p_conf, int Err, const char *pErrStr)
{
    p_conf->err = Err;
    if (p_conf->p_errstr != NULL) {
        UTL_DBG_FREE(p_conf->p_errstr);
        p_conf->p_errstr = NULL;
    }
    if ((Err != 0) && (pErrStr != NULL)) {
        size_t len_max = strlen(pErrStr) + 128;
        p_conf->p_errstr = (char *)UTL_DBG_MALLOC(len_max);        //UTL_DBG_FREE: thread_channel_start()
        strcpy(p_conf->p_errstr, pErrStr);
        LOGD("$$$[ERROR RECEIVED] %s\n", p_conf->p_errstr);

        // method: error
        // $1: short_channel_id
        // $2: node_id
        // $3: err_str
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&p_conf->channel));
        char *param = (char *)UTL_DBG_MALLOC(len_max);      //UTL_DBG_FREE: この中
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
        snprintf(param, len_max, "%s %s "
                    "\"%s\"",
                    str_sci, node_id,
                    p_conf->p_errstr);
        ptarmd_call_script(PTARMD_EVT_ERROR, param);
        UTL_DBG_FREE(param);        //UTL_DBG_MALLOC: この中
    }
}


