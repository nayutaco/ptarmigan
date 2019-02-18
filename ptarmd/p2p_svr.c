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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <poll.h>
#include <fcntl.h>
#include <assert.h>

#include "cJSON.h"

#define LOG_TAG     "p2p_svr"
#include "utl_log.h"

#include "ptarmd.h"
#include "p2p_svr.h"
#include "lnapp.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_SOCK_SERVER_MAX           MAX_CHANNELS        ///< 接続可能max(server)
#define M_TIMEOUT_MSEC              (500)               ///< poll timeout[msec]


/********************************************************************
 * static variables
 ********************************************************************/

static lnapp_conf_t     mAppConf[M_SOCK_SERVER_MAX];
volatile bool           mLoop = true;


/********************************************************************
 * prototypes
 ********************************************************************/


/********************************************************************
 * public functions
 ********************************************************************/

//ソケット接続用スレッド
void *p2p_svr_start(void *pArg)
{
    (void)pArg;

    int ret;
    int sock = -1;
    struct sockaddr_in sv_addr, cl_addr;

    LOGD("[THREAD]svr initialize\n");

    memset(&mAppConf, 0, sizeof(mAppConf));
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        mAppConf[lp].sock = -1;
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOGE("socket error: %s\n", strerror(errno));
        goto LABEL_EXIT;
    }
    int optval = 1;

    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (ret < 0) {
        LOGE("setsockopt: %s\n", strerror(errno));
        goto LABEL_EXIT;
    }

    socklen_t optlen = sizeof(optval);
    ret = getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen);
    if (ret < 0) {
        LOGE("getsokopt: %s\n", strerror(errno));
        goto LABEL_EXIT;
    }
    fcntl(sock, F_SETFL, O_NONBLOCK);

    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sv_addr.sin_port = htons(ln_node_addr()->port);
    ret = bind(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    if (ret < 0) {
        LOGE("bind: %s\n", strerror(errno));
        goto LABEL_EXIT;
    }
    ret = listen(sock, 1);
    if (ret < 0) {
        LOGE("listen: %s\n", strerror(errno));
        goto LABEL_EXIT;
    }
    fprintf(stderr, "listening...\n");

    struct pollfd fds;
    while (mLoop) {
        fds.fd = sock;
        fds.events = POLLIN;
        int polr = poll(&fds, 1, M_TIMEOUT_MSEC);
        if (polr < 0) {
            LOGD("poll: %s\n", strerror(errno));
            continue;
        } else if (polr == 0) {
            //timeout
            continue;
        } else {
            //継続
        }
        if (!mLoop) {
            LOGD("stop\n");
            break;
        }

        int idx;
        for (idx = 0; idx < (int)ARRAY_SIZE(mAppConf); idx++) {
            if (mAppConf[idx].sock == -1) {
                break;
            }
        }
        if (idx < (int)ARRAY_SIZE(mAppConf)) {
            socklen_t cl_len = sizeof(cl_addr);
            //fprintf(stderr, "accept...\n");
            mAppConf[idx].sock = accept(sock, (struct sockaddr *)&cl_addr, &cl_len);
            if (mAppConf[idx].sock < 0) {
                LOGE("accept: %s\n", strerror(errno));
                break;
            }
            if (!mLoop) {
                LOGD("stop\n");
                close(mAppConf[idx].sock);
                break;
            }

            //スレッド起動
            mAppConf[idx].initiator = false;        //Noise Protocolの Act One受信
            memset(mAppConf[idx].node_id, 0, BTC_SZ_PUBKEY);
            inet_ntop(AF_INET, (struct in_addr *)&cl_addr.sin_addr, mAppConf[idx].conn_str, SZ_CONN_STR);
            mAppConf[idx].conn_port = ntohs(cl_addr.sin_port);

            LOGD("[server]connect from addr=%s, port=%d\n", mAppConf[idx].conn_str, mAppConf[idx].conn_port);
            //fprintf(stderr, "[server]accepted(%d) socket=%d, addr=%s, port=%d\n", idx, mAppConf[idx].sock, mAppConf[idx].conn_str, mAppConf[idx].conn_port);

            lnapp_start(&mAppConf[idx]);
        } else {
            //空き無し
            int delsock = accept(sock, NULL, NULL);
            close(delsock);
            LOGE("no empty socket\n");
        }
    }

LABEL_EXIT:
    if (sock > 0) {
        close(sock);
    }
    LOGD("[exit]p2p_svr thread: sock=%d\n", sock);
    ptarmd_stop();

    return NULL;
}


void p2p_svr_stop_all(void)
{
    LOGD("stop\n");
    mLoop = false;
    for (int lp = 0; lp < M_SOCK_SERVER_MAX; lp++) {
        if (mAppConf[lp].sock != -1) {
            lnapp_stop(&mAppConf[lp]);
        }
    }
}


lnapp_conf_t *p2p_svr_search_node(const uint8_t *pNodeId)
{
    lnapp_conf_t *p_appconf = NULL;
    int lp;
    for (lp = 0; lp < M_SOCK_SERVER_MAX; lp++) {
        if (mAppConf[lp].loop && (memcmp(pNodeId, mAppConf[lp].node_id, BTC_SZ_PUBKEY) == 0)) {
            //LOGD("found: server %d\n", lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }

    return p_appconf;
}


lnapp_conf_t *p2p_svr_search_short_channel_id(uint64_t short_channel_id)
{
    lnapp_conf_t *p_appconf = NULL;
    for (int lp = 0; lp < M_SOCK_SERVER_MAX; lp++) {
        if (mAppConf[lp].loop && (lnapp_match_short_channel_id(&mAppConf[lp], short_channel_id))) {
            //LOGD("found: server[%016" PRIx64 "] %d\n", short_channel_id, lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }
    //LOGD("p_appconf= %p\n", p_appconf);

    return p_appconf;
}


int p2p_svr_connected_peer(void)
{
    int cnt = 0;
    for (int lp = 0; lp < M_SOCK_SERVER_MAX; lp++) {
        if (lnapp_is_looping(&mAppConf[lp])) {
            cnt++;
        }
    }
    return cnt;
}


void p2p_svr_show_channel(cJSON *pResult)
{
    for (int lp = 0; lp < M_SOCK_SERVER_MAX; lp++) {
        lnapp_show_channel(&mAppConf[lp], pResult, "server");
    }
}


bool p2p_svr_is_looping(void)
{
    bool ret = false;
    int connects = 0;

    for (int lp = 0; lp < M_SOCK_SERVER_MAX; lp++) {
        if (mAppConf[lp].sock != -1) {
            connects++;
            ret = lnapp_is_looping(&mAppConf[lp]);
            if (ret) {
                break;
            }
        }
    }
    if (connects == 0) {
        ret = true;
    }

    return ret;
}
