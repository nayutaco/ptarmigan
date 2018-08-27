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
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>

#include "cJSON.h"

#include "ptarmd.h"
#include "p2p_cli.h"
#include "lnapp.h"


/********************************************************************
 * static variables
 ********************************************************************/

static lnapp_conf_t     mAppConf[SZ_SOCK_CLIENT_MAX];

static peer_conn_t mLastPeerConn;
pthread_mutex_t mMuxLastPeerConn = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


/********************************************************************
 * prototypes
 ********************************************************************/


/********************************************************************
 * public functions
 ********************************************************************/

void p2p_cli_init(void)
{
    memset(&mAppConf, 0, sizeof(mAppConf));
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        mAppConf[lp].sock = -1;
    }
}


bool p2p_cli_start(const peer_conn_t *pConn, jrpc_context *ctx)
{
    bool bret = false;
    int ret;
    int idx;
    struct sockaddr_in sv_addr;

    if (!btc_keys_chkpub(pConn->node_id)) {
        LOGD("invalid node_id\n");
        ctx->error_code = RPCERR_NODEID;
        ctx->error_message = ptarmd_error_str(RPCERR_NODEID);
        goto LABEL_EXIT;
    }

    for (idx = 0; idx < (int)ARRAY_SIZE(mAppConf); idx++) {
        if (mAppConf[idx].sock == -1) {
            break;
        }
    }
    if (idx >= (int)ARRAY_SIZE(mAppConf)) {
        LOGD("client full\n");
        ctx->error_code = RPCERR_FULLCLI;
        ctx->error_message = ptarmd_error_str(RPCERR_FULLCLI);
        goto LABEL_EXIT;
    }

    mAppConf[idx].sock = socket(PF_INET, SOCK_STREAM, 0);
    if (mAppConf[idx].sock < 0) {
        LOGD("socket\n");
        ctx->error_code = RPCERR_SOCK;
        ctx->error_message = ptarmd_error_str(RPCERR_SOCK);
        goto LABEL_EXIT;
    }
    fcntl(mAppConf[idx].sock, F_SETFL, O_NONBLOCK);

    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(pConn->ipaddr);
    sv_addr.sin_port = htons(pConn->port);
    errno = 0;
    ret = connect(mAppConf[idx].sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    if ((ret < 0) && (errno == EINPROGRESS)) {
        //timeout check
        struct pollfd fds;
        fds.fd = mAppConf[idx].sock;
        fds.events = POLLIN | POLLOUT;
        int polr = poll(&fds, 1, TM_WAIT_CONNECT * 1000);
        if (polr > 0) {
            ret = 0;
        } else {
            LOGD("poll: %s\n", strerror(errno));
        }
    }
    if (ret < 0) {
        LOGD("connect: %s\n", strerror(errno));
        ctx->error_code = RPCERR_CONNECT;
        ctx->error_message = ptarmd_error_str(RPCERR_CONNECT);
        close(mAppConf[idx].sock);
        mAppConf[idx].sock = -1;

        FILE *fp = fopen(FNAME_CONN_LOG, "a");
        if (fp) {
            char peer_id[BTC_SZ_PUBKEY * 2 + 1];
            utl_misc_bin2str(peer_id, pConn->node_id, BTC_SZ_PUBKEY);

            char date[50];
            utl_misc_datetime(date, sizeof(date));
            fprintf(fp, "[%s]fail: %s@%s:%" PRIu16 "\n", date, peer_id, pConn->ipaddr, pConn->port);
            fclose(fp);
        }

        //ノード接続失敗リストに追加(自動接続回避用)
        ptarmd_nodefail_add(pConn->node_id, pConn->ipaddr, pConn->port, LN_NODEDESC_IPV4);

        goto LABEL_EXIT;
    }
    LOGD("connected: sock=%d\n", mAppConf[idx].sock);

    fprintf(stderr, "[client]connected: %s:%d\n", pConn->ipaddr, pConn->port);
    fprintf(stderr, "[client]node_id=");
    btc_util_dumpbin(stderr, pConn->node_id, BTC_SZ_PUBKEY, true);

    //スレッド起動
    mAppConf[idx].initiator = true;         //Noise Protocolの Act One送信
    memcpy(mAppConf[idx].node_id, pConn->node_id, BTC_SZ_PUBKEY);
    //mAppConf[idx].cmd = DCMD_CONNECT;
    strcpy(mAppConf[idx].conn_str, pConn->ipaddr);
    mAppConf[idx].conn_port = pConn->port;

    //store for reconnection
    if (!p2p_cli_store_peer_conn(pConn)) {
        LOGD("fail: store peer conn");
    }

    lnapp_start(&mAppConf[idx]);
    bret = true;

LABEL_EXIT:
    return bret;
}


void p2p_cli_stop_all(void)
{
    for (int lp = 0; lp < SZ_SOCK_CLIENT_MAX; lp++) {
        if (mAppConf[lp].sock != -1) {
            lnapp_stop(&mAppConf[lp]);
        }
    }
}


lnapp_conf_t *p2p_cli_search_node(const uint8_t *pNodeId)
{
    lnapp_conf_t *p_appconf = NULL;
    int lp;
    for (lp = 0; lp < SZ_SOCK_CLIENT_MAX; lp++) {
        if (mAppConf[lp].loop && (memcmp(pNodeId, mAppConf[lp].node_id, BTC_SZ_PUBKEY) == 0)) {
            //LOGD("found: client %d\n", lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }

    return p_appconf;
}


lnapp_conf_t *p2p_cli_search_short_channel_id(uint64_t short_channel_id)
{
    lnapp_conf_t *p_appconf = NULL;
    for (int lp = 0; lp < SZ_SOCK_CLIENT_MAX; lp++) {
        if (mAppConf[lp].loop && (lnapp_match_short_channel_id(&mAppConf[lp], short_channel_id))) {
            //LOGD("found: client[%016" PRIx64 "] %d\n", short_channel_id, lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }
    //LOGD("p_appconf= %p\n", p_appconf);

    return p_appconf;
}


void p2p_cli_show_self(cJSON *pResult)
{
    for (int lp = 0; lp < SZ_SOCK_CLIENT_MAX; lp++) {
        lnapp_show_self(&mAppConf[lp], pResult, "client");
    }
}


bool p2p_cli_is_looping(void)
{
    bool ret = false;
    int connects = 0;

    for (int lp = 0; lp < SZ_SOCK_CLIENT_MAX; lp++) {
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


bool p2p_cli_store_peer_conn(const peer_conn_t* pPeerConn)
{
    pthread_mutex_lock(&mMuxLastPeerConn);
    mLastPeerConn = *pPeerConn;
    pthread_mutex_unlock(&mMuxLastPeerConn);

    return true;
}


bool p2p_cli_load_peer_conn(peer_conn_t* pPeerConn, const uint8_t *pNodeId)
{
    bool ret = false;

    pthread_mutex_lock(&mMuxLastPeerConn);
    if (memcmp(mLastPeerConn.node_id, pNodeId, BTC_SZ_PUBKEY) == 0) {
        *pPeerConn = mLastPeerConn;
        ret = true;
    }
    pthread_mutex_unlock(&mMuxLastPeerConn);

    return ret;
}

