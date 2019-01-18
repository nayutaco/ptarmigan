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

#define LOG_TAG     "p2p_cli"
#include "utl_log.h"
#include "utl_time.h"

#include "btc_crypto.h"

#include "ptarmd.h"
#include "p2p_cli.h"
#include "lnapp.h"


/********************************************************************
 * macros
 ********************************************************************/

#define SZ_SOCK_CLIENT_MAX          MAX_CHANNELS        ///< 接続可能max(client)


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


bool p2p_cli_connect_test(const char *pIpAddr, uint16_t Port)
{
    bool ret = false;
    struct sockaddr_in sv_addr;

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        LOGD("socket\n");
        goto LABEL_EXIT;
    }

    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(pIpAddr);
    sv_addr.sin_port = htons(Port);
    errno = 0;
    ret = (connect(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr)) == 0);

LABEL_EXIT:
    close(sock);
    return ret;
}


bool p2p_cli_start(const peer_conn_t *pConn, int *pErrCode)
{
    bool bret = false;
    int ret;
    int idx;
    int sock = -1;
    struct sockaddr_in sv_addr;

    if (!btc_keys_check_pub(pConn->node_id)) {
        LOGD("invalid node_id\n");
        *pErrCode = RPCERR_NODEID;
        goto LABEL_EXIT;
    }
    lnapp_conf_t *p_conf = ptarmd_search_connected_nodeid(pConn->node_id);
    if (p_conf != NULL) {
        LOGE("fail: already connected.\n");
        *pErrCode = RPCERR_ALCONN;
        goto LABEL_EXIT;
    }

    for (idx = 0; idx < (int)ARRAY_SIZE(mAppConf); idx++) {
        if (mAppConf[idx].sock == -1) {
            break;
        }
    }
    if (idx >= (int)ARRAY_SIZE(mAppConf)) {
        LOGD("client full\n");
        *pErrCode = RPCERR_FULLCLI;
        goto LABEL_EXIT;
    }

    mAppConf[idx].sock = socket(PF_INET, SOCK_STREAM, 0);
    if (mAppConf[idx].sock < 0) {
        LOGD("socket\n");
        *pErrCode = RPCERR_SOCK;
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
        *pErrCode = RPCERR_CONNECT;
        close(mAppConf[idx].sock);
        mAppConf[idx].sock = -1;

        FILE *fp = fopen(FNAME_CONN_LOG, "a");
        if (fp) {
            char peer_id[BTC_SZ_PUBKEY * 2 + 1];
            utl_str_bin2str(peer_id, pConn->node_id, BTC_SZ_PUBKEY);

            char time[UTL_SZ_TIME_FMT_STR + 1];
            fprintf(fp, "[%s]fail: %s@%s:%" PRIu16 "\n", utl_time_str_time(time), peer_id, pConn->ipaddr, pConn->port);
            fclose(fp);
        }

        //ノード接続失敗リストに追加(自動接続回避用)
        ptarmd_nodefail_add(pConn->node_id, pConn->ipaddr, pConn->port, LN_ADDR_DESC_TYPE_IPV4);

        goto LABEL_EXIT;
    }
    sock = mAppConf[idx].sock;
    LOGD("connected: sock=%d\n", sock);

    fprintf(stderr, "[client]connected: %s:%d\n", pConn->ipaddr, pConn->port);
    fprintf(stderr, "[client]node_id=");
    utl_dbg_dump(stderr, pConn->node_id, BTC_SZ_PUBKEY, true);

    //スレッド起動
    mAppConf[idx].initiator = true;         //Noise Protocolの Act One送信
    memcpy(mAppConf[idx].node_id, pConn->node_id, BTC_SZ_PUBKEY);
    //mAppConf[idx].cmd = DCMD_CONNECT;
    strcpy(mAppConf[idx].conn_str, pConn->ipaddr);
    mAppConf[idx].conn_port = pConn->port;
    mAppConf[idx].routesync = pConn->routesync;

    //store for reconnection
    if (!p2p_cli_store_peer_conn(pConn)) {
        LOGE("fail: store peer conn");
    }

    lnapp_start(&mAppConf[idx]);
    bret = true;

LABEL_EXIT:
    LOGD("[exit]p2p_cli: sock=%d\n", sock);
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


int p2p_cli_connected_peer(void)
{
    int cnt = 0;
    for (int lp = 0; lp < SZ_SOCK_CLIENT_MAX; lp++) {
        if (lnapp_is_looping(&mAppConf[lp])) {
            cnt++;
        }
    }
    return cnt;
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

