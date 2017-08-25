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
#include <assert.h>

#include "ucoind.h"
#include "p2p_cli.h"
#include "lnapp.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_SOCK_MAX          (2)


/********************************************************************
 * static variables
 ********************************************************************/

static lnapp_conf_t     mAppConf[M_SOCK_MAX];


/********************************************************************
 * prototypes
 ********************************************************************/


/********************************************************************
 * public functions
 ********************************************************************/

void p2p_cli_init(void)
{
    for (int lp = 0; lp < ARRAY_SIZE(mAppConf); lp++) {
        mAppConf[lp].sock = -1;
    }
}


void p2p_cli_start(my_daemoncmd_t Cmd, const daemon_connect_t *pConn, void *pParam, const uint8_t *pNodeId, char *pResMsg)
{
    int ret;
    struct sockaddr_in sv_addr;

    if (!ucoin_keys_chkpub(pConn->node_id)) {
        SYSLOG_ERR("%s(): invalid node_id", __func__);
        strcpy(pResMsg, "error: invalid node_id");
        return;
    }
    bool haveCnl = (ln_node_search_short_cnl_id(pNodeId, pConn->node_id) != 0);
    if (((pParam == NULL) && !haveCnl) || ((pParam != NULL) && haveCnl)) {
        //接続しようとしてチャネルを開いていないか、開設しようとしてチャネルが開いている
        DBG_PRINTF("pParam=%p, haveCnl=%d\n", pParam, haveCnl);
        if (pParam == NULL) {
            SYSLOG_ERR("%s(): channel not open", __func__);
            strcpy(pResMsg, "error: channel not open");
        } else {
            SYSLOG_ERR("%s(): channel already opened", __func__);
            strcpy(pResMsg, "error: channel already opened");
        }
        return;
    }

    int idx;
    for (idx = 0; idx < ARRAY_SIZE(mAppConf); idx++) {
        if (mAppConf[idx].sock == -1) {
            break;
        }
    }
    if (idx >= ARRAY_SIZE(mAppConf)) {
        SYSLOG_ERR("%s(): client full", __func__);
        strcpy(pResMsg, "error: client full");
        return;
    }

    fprintf(PRINTOUT, "connect: %s:%d\n", pConn->ipaddr, pConn->port);
    fprintf(PRINTOUT, "node_id=");
    for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        fprintf(PRINTOUT, "%02x", pConn->node_id[lp]);
    }
    fprintf(PRINTOUT, "\n");

    mAppConf[idx].sock = socket(PF_INET, SOCK_STREAM, 0);
    if (mAppConf[idx].sock < 0) {
        SYSLOG_ERR("%s(): socket", __func__);
        strcpy(pResMsg, "error: socket: ");
        strcpy(pResMsg, strerror(errno));
        goto LABEL_EXIT;
    }

    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(pConn->ipaddr);
    sv_addr.sin_port = htons(pConn->port);
    ret = connect(mAppConf[idx].sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    if (ret < 0) {
        SYSLOG_ERR("%s(): connect", __func__);
        strcpy(pResMsg, "error: connect: ");
        strcpy(pResMsg, strerror(errno));
        goto LABEL_EXIT;
    }
    DBG_PRINTF("connected: sock=%d\n", mAppConf[idx].sock);

    //スレッド起動
    mAppConf[idx].initiator = true;         //init送信
    memcpy(mAppConf[idx].node_id, pConn->node_id, UCOIN_SZ_PUBKEY);
    mAppConf[idx].cmd = Cmd;
    mAppConf[idx].p_funding = (funding_conf_t *)pParam;

    lnapp_start(&mAppConf[idx]);
    strcpy(pResMsg, "progressing...");

LABEL_EXIT:
    ;
}


void p2p_cli_stop_all(void)
{
    for (int lp = 0; lp < M_SOCK_MAX; lp++) {
        if (mAppConf[lp].sock != -1) {
            lnapp_stop(&mAppConf[lp]);
        }
    }
}


lnapp_conf_t *p2p_cli_search_node(const uint8_t *pNodeId)
{
    lnapp_conf_t *p_appconf = NULL;
    int lp;
    for (lp = 0; lp < M_SOCK_MAX; lp++) {
        if (mAppConf[lp].loop && (memcmp(pNodeId, mAppConf[lp].node_id, UCOIN_SZ_PUBKEY) == 0)) {
            DBG_PRINTF("found: client %d\n", lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }

    return p_appconf;
}


lnapp_conf_t *p2p_cli_search_short_channel_id(uint64_t short_channel_id)
{
    lnapp_conf_t *p_appconf = NULL;
    for (int lp = 0; lp < M_SOCK_MAX; lp++) {
        if (mAppConf[lp].loop && (lnapp_match_short_channel_id(&mAppConf[lp], short_channel_id))) {
            DBG_PRINTF("found: client[%" PRIx64 "] %d\n", short_channel_id, lp);
            p_appconf = &mAppConf[lp];
            break;
        }
    }
    DBG_PRINTF("p_appconf= %p\n", p_appconf);

    return p_appconf;
}


void p2p_cli_show_self(char *pResMsg)
{
    for (int lp = 0; lp < M_SOCK_MAX; lp++) {
        lnapp_show_self(&mAppConf[lp], pResMsg);
    }
}


bool p2p_cli_is_looping(void)
{
    bool ret = false;
    int connects = 0;

    for (int lp = 0; lp < M_SOCK_MAX; lp++) {
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


/********************************************************************
 * private functions
 ********************************************************************/
