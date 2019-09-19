/*
 *  Copyright (C) 2017 Ptarmigan Project
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
 * prototypes
 ********************************************************************/

#ifdef M_DEBUG_ANNO
extern void ln_print_announce(const uint8_t *pData, uint16_t Len);
#endif  //M_DEBUG_ANNO


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
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(&p_conf->channel));
        LOGD("=========================================\n");
        LOGD("=  CHANNEL THREAD END: %016" PRIx64 "(%s)\n", ln_short_channel_id(&p_conf->channel), str_sci);
        LOGD("=========================================\n");
        LOGD("    sock=%d\n", p_conf->sock);
        LOGD("    node_id=");
        DUMPD(p_conf->node_id, BTC_SZ_PUBKEY);
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
    uint16_t type = ln_msg_type(NULL, pBuf->buf, pBuf->len);
    LOGD("[SEND]type=%04x(%s): sock=%d, Len=%d\n", type, ln_msg_name(type), p_conf->sock, pBuf->len);

#ifdef M_DEBUG_ANNO
    if ((0x0100 <= type) && (type <= 0x0102)) {
        ln_print_announce(pBuf->buf, pBuf->len);
    }
#endif  //M_DEBUG_ANNO

    pthread_mutex_lock(&p_conf->mux_send); //lock mux_send

    utl_buf_t buf_enc = UTL_BUF_INIT;
    struct pollfd fds;
    ssize_t len = -1;

    bool ret = ln_noise_enc(&p_conf->noise, &buf_enc, pBuf);
    if (!ret) {
        LOGE("fail: noise encode\n");
        goto LABEL_ERROR;
    }

    len = buf_enc.len;
    while ((p_conf->active) && (len > 0)) {
        fds.fd = p_conf->sock;
        fds.events = POLLOUT;
        int polr = poll(&fds, 1, M_WAIT_SEND_TO_MSEC);
        if (polr <= 0) {
            LOGE("fail: poll %s\n", strerror(errno));
            goto LABEL_ERROR;
        }
        ssize_t sz = write(p_conf->sock, buf_enc.buf, len);
        if (sz < 0) {
            LOGE("fail: write %s\n", strerror(errno));
            goto LABEL_ERROR;
        }
        len -= sz;
        if (len > 0) {
            utl_thread_msleep(M_WAIT_SEND_WAIT_MSEC);
        }
    }

    pthread_mutex_unlock(&p_conf->mux_send);
    utl_buf_free(&buf_enc);
    return true;

LABEL_ERROR:
    pthread_mutex_unlock(&p_conf->mux_send); //unlock mux_send
    utl_buf_free(&buf_enc);
    return false;
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


