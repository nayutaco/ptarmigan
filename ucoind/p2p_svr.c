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

#include "ucoind.h"
#include "p2p_svr.h"
#include "lnapp.h"


/********************************************************************
 * static variables
 ********************************************************************/

static lnapp_conf_t     mAppConf[SZ_SOCK_SERVER_MAX];
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
    int sock;
    struct sockaddr_in sv_addr, cl_addr;

    memset(&mAppConf, 0, sizeof(mAppConf));
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        mAppConf[lp].sock = -1;
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SYSLOG_ERR("%s(): socket error: %s", __func__, strerror(errno));
        goto LABEL_EXIT;
    }
    int optval = 1;

    ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (ret < 0) {
        SYSLOG_ERR("%s(): setsockopt: %s", __func__, strerror(errno));
        goto LABEL_EXIT;
    }

    socklen_t optlen = sizeof(optval);
    ret = getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen);
    if (ret < 0) {
        SYSLOG_ERR("%s(): getsokopt: %s", __func__, strerror(errno));
        goto LABEL_EXIT;
    }
    fcntl(sock, F_SETFL, O_NONBLOCK);

    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sv_addr.sin_port = htons(ln_node_addr()->port);
    ret = bind(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    if (ret < 0) {
        SYSLOG_ERR("%s(): bind: %s", __func__, strerror(errno));
        goto LABEL_EXIT;
    }
    ret = listen(sock, 1);
    if (ret < 0) {
        SYSLOG_ERR("%s(): listen: %s", __func__, strerror(errno));
        goto LABEL_EXIT;
    }
    fprintf(PRINTOUT, "listening...\n");

    struct pollfd fds;
    while (mLoop) {
        fds.fd = sock;
        fds.events = POLLIN;
        int polr = poll(&fds, 1, 500);
        if (polr < 0) {
            SYSLOG_ERR("%s(): poll: %s", __func__, strerror(errno));
            continue;
        } else if (polr == 0) {
            //timeout
            continue;
        } else {
            //継続
        }

        int idx;
        for (idx = 0; idx < (int)ARRAY_SIZE(mAppConf); idx++) {
            if (mAppConf[idx].sock == -1) {
                break;
            }
        }
        if (idx < (int)ARRAY_SIZE(mAppConf)) {
            socklen_t cl_len = sizeof(cl_addr);
            fprintf(PRINTOUT, "accept...\n");
            mAppConf[idx].sock = accept(sock, (struct sockaddr *)&cl_addr, &cl_len);
            fprintf(PRINTOUT, "accepted[%d]\n", idx);
            if (mAppConf[idx].sock < 0) {
                SYSLOG_ERR("%s(): accept: %s", __func__, strerror(errno));
                goto LABEL_EXIT;
            }
            fprintf(PRINTOUT, "connect from addr=%s, port=%d\n", inet_ntoa(cl_addr.sin_addr), ntohs(cl_addr.sin_port));

            //スレッド起動
            mAppConf[idx].initiator = false;        //Noise Protocolの Act One受信
            memset(mAppConf[idx].node_id, 0, UCOIN_SZ_PUBKEY);
            mAppConf[idx].cmd = DCMD_NONE;
            sprintf(mAppConf[idx].conn_str, "%s:%d", inet_ntoa(cl_addr.sin_addr), ntohs(cl_addr.sin_port));

            lnapp_start(&mAppConf[idx]);
        } else {
            //空き無し
            int delsock = accept(sock, NULL, NULL);
            close(delsock);
            SYSLOG_ERR("no empty socket");
        }
    }

LABEL_EXIT:
    return NULL;
}


void p2p_svr_stop_all(void)
{
    for (int lp = 0; lp < SZ_SOCK_SERVER_MAX; lp++) {
        if (mAppConf[lp].sock != -1) {
            lnapp_stop(&mAppConf[lp]);
        }
    }
    mLoop = false;
}


lnapp_conf_t *p2p_svr_search_node(const uint8_t *pNodeId)
{
    lnapp_conf_t *p_appconf = NULL;
    int lp;
    for (lp = 0; lp < SZ_SOCK_SERVER_MAX; lp++) {
        if (mAppConf[lp].loop && (memcmp(pNodeId, mAppConf[lp].node_id, UCOIN_SZ_PUBKEY) == 0)) {
            //DBG_PRINTF("found: server %d\n", lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }

    return p_appconf;
}


lnapp_conf_t *p2p_svr_search_short_channel_id(uint64_t short_channel_id)
{
    lnapp_conf_t *p_appconf = NULL;
    for (int lp = 0; lp < SZ_SOCK_SERVER_MAX; lp++) {
        if (mAppConf[lp].loop && (lnapp_match_short_channel_id(&mAppConf[lp], short_channel_id))) {
            //DBG_PRINTF("found: server[%" PRIx64 "] %d\n", short_channel_id, lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }
    //DBG_PRINTF("p_appconf= %p\n", p_appconf);

    return p_appconf;
}


void p2p_svr_show_self(cJSON *pResult)
{
    for (int lp = 0; lp < SZ_SOCK_SERVER_MAX; lp++) {
        lnapp_show_self(&mAppConf[lp], pResult, "server");
    }
}


bool p2p_svr_is_looping(void)
{
    bool ret = false;
    int connects = 0;

    for (int lp = 0; lp < SZ_SOCK_SERVER_MAX; lp++) {
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
