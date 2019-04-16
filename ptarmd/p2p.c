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

#define LOG_TAG     "p2p"
#include "utl_log.h"
#include "utl_time.h"

#include "btc_crypto.h"

#include "ptarmd.h"
#include "p2p.h"
#include "lnapp.h"
#include "lnapp_manager.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_TIMEOUT_MSEC              (TM_WAIT_CONNECT * 1000)    ///< poll timeout[msec]


/********************************************************************
 * static variables
 ********************************************************************/

volatile bool           mActive = true;


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    uint64_t short_channel_id;
    uint8_t node_id[BTC_SZ_PUBKEY];
    bool found;
} param_search_node_t;


/********************************************************************
 * prototypes
 ********************************************************************/

static void search_node_by_short_channel_id(lnapp_conf_t *pConf, void *pParam);
static void show_channel(lnapp_conf_t *pConf, void *pParam);


/********************************************************************
 * public functions
 ********************************************************************/

bool p2p_connect_test(const char *pIpAddr, uint16_t Port)
{
    bool ret = false;
    struct sockaddr_in sv_addr;

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        LOGE("socket\n");
        goto LABEL_EXIT;
    }

    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(pIpAddr);
    sv_addr.sin_port = htons(Port);
    errno = 0;
    int retval = connect(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    int bak_errno = errno;
    if (retval) {
        LOGE("connect: %s\n", strerror(bak_errno));
    }
    ret = (retval == 0);

LABEL_EXIT:
    close(sock);
    return ret;
}


bool p2p_initiator_start(const peer_conn_t *pConn, int *pErrCode)
{
    bool bret = false;
    int ret;
    int sock = -1;
    struct sockaddr_in sv_addr;

    if (!btc_keys_check_pub(pConn->node_id)) {
        LOGD("invalid node_id\n");
        *pErrCode = RPCERR_NODEID;
        goto LABEL_EXIT;
    }
    lnapp_conf_t *p_conf = ptarmd_search_connected_node_id(pConn->node_id);
    if (p_conf) {
        LOGE("fail: already connected.\n");
        *pErrCode = RPCERR_ALCONN;
        lnapp_manager_free_node_ref(p_conf);
        goto LABEL_EXIT;
    }

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        LOGE("socket\n");
        *pErrCode = RPCERR_SOCK;
        goto LABEL_EXIT;
    }
    fcntl(sock, F_SETFL, O_NONBLOCK);

    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(pConn->ipaddr);
    sv_addr.sin_port = htons(pConn->port);
    errno = 0;
    ret = connect(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    if ((ret < 0) && (errno == EINPROGRESS)) {
        //timeout check
        struct pollfd fds;
        fds.fd = sock;
        fds.events = POLLIN | POLLOUT;
        int polr = poll(&fds, 1, M_TIMEOUT_MSEC);
        if (polr > 0) {
            ret = 0;
        } else {
            LOGE("poll: %s\n", strerror(errno));
        }
    }
    if (ret < 0) {
        LOGE("connect: %s\n", strerror(errno));
        *pErrCode = RPCERR_CONNECT;
        close(sock);
        sock = -1;

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
    LOGD("connected: sock=%d\n", sock);

    fprintf(stderr, "[client]connected: %s:%d\n", pConn->ipaddr, pConn->port);
    fprintf(stderr, "[client]node_id=");
    utl_dbg_dump(stderr, pConn->node_id, BTC_SZ_PUBKEY, true);

    peer_conn_handshake_t conn_handshake;
    conn_handshake.initiator = true;
    conn_handshake.sock = sock;
    conn_handshake.conn = *pConn;
    if (!lnapp_handshake(&conn_handshake)) {
        LOGE("fail: handshake\n");
        *pErrCode = RPCERR_CONNECT;
        goto LABEL_EXIT;
    }

    p_conf = lnapp_manager_get_node(conn_handshake.conn.node_id);
    if (p_conf) {
        if (ln_status_is_closing(&p_conf->channel)) {
            LOGD("fail: closing channel: %016" PRIx64 "\n", ln_short_channel_id(&p_conf->channel));
            lnapp_manager_free_node_ref(p_conf);
            *pErrCode = RPCERR_NOOPEN;
            goto LABEL_EXIT;
        }
        lnapp_stop(p_conf);
    } else {
        LOGD("new node: ");
        DUMPD(conn_handshake.conn.node_id, BTC_SZ_PUBKEY);
        p_conf = lnapp_manager_get_new_node(conn_handshake.conn.node_id, lnapp_thread_channel_start);
        if (!p_conf) {
            LOGE("fail: get_node_node\n");
            *pErrCode = RPCERR_FULLCLI;
            goto LABEL_EXIT;
        }
    }

    lnapp_conf_start(
        p_conf, conn_handshake.initiator, conn_handshake.sock, pConn->ipaddr, pConn->port,
        pConn->routesync, conn_handshake.noise);
    lnapp_start(p_conf);

    bret = true;

LABEL_EXIT:
    LOGD("[exit]p2p: sock=%d\n", sock);
    if (!bret && sock != -1) {
        close(sock);
    }
    return bret;
}


//ソケット接続用スレッド
void *p2p_listener_start(void *pArg)
{
    (void)pArg;

    int ret;
    int sock = -1;
    struct sockaddr_in sv_addr, cl_addr;

    LOGD("[THREAD]listener initialize\n");

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
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
    while (mActive) {
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
        if (!mActive) {
            LOGD("stop\n");
            break;
        }

        socklen_t cl_len = sizeof(cl_addr);
        //fprintf(stderr, "accept...\n");
        int sock_2 = accept(sock, (struct sockaddr *)&cl_addr, &cl_len);
        if (sock_2 == -1) {
            LOGE("accept: %s\n", strerror(errno));
            continue;
        }
        if (!mActive) {
            LOGD("stop\n");
            close(sock_2);
            break;
        }

        char    conn_str[SZ_CONN_STR + 1];
        inet_ntop(AF_INET, (struct in_addr *)&cl_addr.sin_addr, conn_str, SZ_CONN_STR);
        LOGD("[server]connect from addr=%s, port=%d\n", conn_str, ntohs(cl_addr.sin_port));
        //fprintf(stderr, "[server]accepted(%d) socket=%d, addr=%s, port=%d\n", idx, mAppConf[idx].sock, mAppConf[idx].conn_str, mAppConf[idx].conn_port);

        peer_conn_handshake_t conn_handshake;
        conn_handshake.initiator = false;
        conn_handshake.sock = sock_2;
        memset(&conn_handshake.conn, 0x00, sizeof(conn_handshake.conn));
        if (!lnapp_handshake(&conn_handshake)) {
            LOGE("fail: handshake\n");
            close(sock_2);
            continue;
        }

        lnapp_conf_t *p_conf;
        p_conf = lnapp_manager_get_node(conn_handshake.conn.node_id);
        if (p_conf) {
            if (ln_status_is_closing(&p_conf->channel)) {
                LOGD("fail: closing channel: %016" PRIx64 "\n", ln_short_channel_id(&p_conf->channel));
                lnapp_manager_free_node_ref(p_conf);
                close(sock_2);
                continue;
            }
            lnapp_stop(p_conf);
        } else {
            LOGD("new node: ");
            DUMPD(conn_handshake.conn.node_id, BTC_SZ_PUBKEY);
            p_conf = lnapp_manager_get_new_node(conn_handshake.conn.node_id, lnapp_thread_channel_start);
            if (!p_conf) {
                LOGE("fail: get_node_node\n");
                close(sock_2);
                continue;
            }
        }

        lnapp_conf_start(p_conf, conn_handshake.initiator, conn_handshake.sock,
            conn_str, (uint16_t)ntohs(cl_addr.sin_port),
            conn_handshake.conn.routesync, conn_handshake.noise);
        lnapp_start(p_conf);
    }

LABEL_EXIT:
    if (sock != -1) {
        close(sock);
    }
    LOGD("[exit]p2p thread: sock=%d\n", sock);
    ptarmd_stop();
    return NULL;
}


void p2p_stop(void)
{
    LOGD("stop\n");
    mActive = false;
}


lnapp_conf_t *p2p_search_active_node(const uint8_t *pNodeId)
{
    lnapp_conf_t *p_conf = lnapp_manager_get_node(pNodeId);
    if (!p_conf) return NULL;
    pthread_mutex_lock(&p_conf->mux_conf);
    if (!p_conf->active) {
        pthread_mutex_unlock(&p_conf->mux_conf);
        lnapp_manager_free_node_ref(p_conf);
        return NULL;
    }
    pthread_mutex_unlock(&p_conf->mux_conf);
    return p_conf;
}


lnapp_conf_t *p2p_search_active_channel(uint64_t short_channel_id)
{
    param_search_node_t param;
    param.short_channel_id = short_channel_id;
    param.found = false;

    lnapp_manager_each_node(search_node_by_short_channel_id, &param);
    if (!param.found) return NULL;

    return p2p_search_active_node(param.node_id);
}

void p2p_show_channel(cJSON *pResult)
{
    lnapp_manager_each_node(show_channel, pResult);
}


/********************************************************************
 * private functions
 ********************************************************************/

static void search_node_by_short_channel_id(lnapp_conf_t *pConf, void *pParam)
{
    param_search_node_t *p_param = (param_search_node_t *)pParam;
    if (p_param->found) return;

    pthread_mutex_lock(&pConf->mux_conf);
    bool ret = lnapp_match_short_channel_id(pConf, p_param->short_channel_id);
    pthread_mutex_unlock(&pConf->mux_conf);
    if (ret) {
        p_param->found = true;
        memcpy(p_param->node_id, pConf->node_id, BTC_SZ_PUBKEY);
    }
}


static void show_channel(lnapp_conf_t *pConf, void *pParam)
{
    cJSON *pResult = (cJSON *)pParam;
    pthread_mutex_lock(&pConf->mux_conf);
    lnapp_show_channel(pConf, pResult);
    pthread_mutex_unlock(&pConf->mux_conf);
}

