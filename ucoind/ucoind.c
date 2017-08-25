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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#define UCOIN_USE_PRINTFUNC
#include "ucoind.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "jsonrpc.h"
#include "conf.h"
#include "misc.h"


/********************************************************************
 * static variables
 ********************************************************************/

static ln_node_t    mNode;


/********************************************************************
 * prototypes
 ********************************************************************/

static int msg_recv(uint16_t Port);
static int exec_cmd(const msgbuf_t *pMsg, char *pResMsg);
static int exec_cmd_bolt(const msg_bolt_t *pBolt, char *pResMsg);
static int exec_cmd_daemon(const msg_daemon_t *pDaemon, char *pResMsg);
static lnapp_conf_t *search_connected_lnapp(const uint8_t *p_node_id);


/********************************************************************
 * public functions
 ********************************************************************/

int main(int argc, char *argv[])
{
    if (argc < 2) {
        goto LABEL_EXIT;
    }

    ucoin_init(UCOIN_TESTNET, true);

    if ((argc == 2) && (strcmp(argv[1], "wif") == 0)) {
        uint8_t priv[UCOIN_SZ_PRIVKEY];
        do {
            ucoin_util_random(priv, UCOIN_SZ_PRIVKEY);
        } while (!ucoin_keys_chkpriv(priv));

        char wif[UCOIN_SZ_WIF_MAX];
        ucoin_keys_priv2wif(wif, priv);
        printf("wif=%s\n", wif);

        ucoin_term();
        return 0;
    }

    //syslog
    openlog("ucoind", LOG_CONS, LOG_USER);

    rpc_conf_t rpc_conf;
    node_conf_t node_conf;
    bool bret = load_node_conf(argv[1], &node_conf, &rpc_conf);
    if (!bret) {
        goto LABEL_EXIT;
    }

    if ((argc == 3) && (strcmp(argv[2], "id") == 0)) {
        ucoin_util_keys_t keys;
        ucoin_util_wif2keys(&keys, node_conf.wif);
        for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
            printf("%02x", keys.pub[lp]);
        }
        printf("\n");

        ucoin_term();
        return 0;
    }

    p2p_cli_init();
    jsonrpc_init(&rpc_conf);

    //bitcoind起動確認
    int count = jsonrpc_getblockcount();
    if (count == -1) {
        DBG_PRINTF("fail: bitcoin getblockcount(maybe cannot connect bitcoind)\n");
        return -1;
    }

    //node情報読込み
    ln_node_init(&mNode, node_conf.wif, node_conf.name, 0);
    ln_print_node(&mNode);
    lnapp_init(&mNode);

    //接続待ち受け用
    pthread_t th_svr;
    pthread_create(&th_svr, NULL, &p2p_svr_start, &node_conf.port);

    SYSLOG_INFO("start");

    //ucoincli受信用
    msg_recv(node_conf.port);

    //待ち合わせ
    pthread_join(th_svr, NULL);
    //pthread_join(th_fu, NULL);
    DBG_PRINTF("%s exit\n", argv[0]);

    SYSLOG_INFO("end");

    return 0;

LABEL_EXIT:
    fprintf(PRINTOUT, "[usage]\n\t%s <node.conf>\n\n", argv[0]);
    return -1;
}


bool pay_forward(const ln_cb_add_htlc_recv_t *p_add, uint64_t prev_short_channel_id)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", p_add->p_hop->short_channel_id);

    //socketが開いているか検索
    p_appconf = p2p_cli_search_short_channel_id(p_add->p_hop->short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_short_channel_id(p_add->p_hop->short_channel_id);
    }
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_payment_forward(p_appconf, p_add, prev_short_channel_id);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


bool fulfill_backward(const ln_cb_fulfill_htlc_recv_t *pFulFill)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", pFulFill->prev_short_channel_id);

    //socketが開いているか検索
    p_appconf = p2p_cli_search_short_channel_id(pFulFill->prev_short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_short_channel_id(pFulFill->prev_short_channel_id);
    }
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_fulfill_backward(p_appconf, pFulFill);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

static int msg_recv(uint16_t Port)
{
    int retval = -1;
    int ret;
    msgbuf_t buf;
    msgres_t res;
    int msqid;
    key_t key;
    char wkdir[50];
    char fname[50];


    sprintf(wkdir, "%s/%s", getenv("HOME"), UCOINDDIR);
    ret = mkdir(wkdir, 0755);
    if (!ret) {
        DBG_PRINTF("create dir: %s\n", wkdir);
    }

    sprintf(fname, "%s/%s%d.dat", wkdir, FTOK_FNAME, Port);
    //fprintf(PRINTOUT, "resmsg: %s\n", fname);
    unlink(fname);
    int fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) {
        SYSLOG_ERR("msg open: %s", strerror(errno));
        goto LABEL_EXIT;
    }

    if ((key = ftok(fname, FTOK_CHAR)) == -1) {
        SYSLOG_ERR("msg ftok: %s", strerror(errno));
        goto LABEL_EXIT;
    }

    if ((msqid = msgget(key, 0644 | IPC_CREAT)) == -1) {
        SYSLOG_ERR("msgget: %s", strerror(errno));
        goto LABEL_EXIT;
    }

    fprintf(PRINTOUT, "ucoind started.\n");
    while (p2p_svr_is_looping() || p2p_cli_is_looping()) {
        if (msgrcv(msqid, &buf, sizeof(payload_t), MTYPE_CLI2D, 0) == -1) {
            SYSLOG_ERR("msgrcv: %s", strerror(errno));
            goto LABEL_EXIT;
        }

        res.mtype = MTYPE_D2CLI;
        res.mtext[0] = '\0';
        ret = exec_cmd(&buf, res.mtext);
        if (msgsnd(msqid, &res, sizeof(res.mtext), 0) == -1) {
            SYSLOG_ERR("msgsnd: %s", strerror(errno));
            exit(-1);
        }
        if (ret != 0) {
            DBG_PRINTF("ret=%d\n", ret);
            break;
        }
    }

    fprintf(PRINTOUT, "ucoind end.\n");
    if (msgctl(msqid, IPC_RMID, NULL) == -1) {
        SYSLOG_ERR("msgctl: %s", strerror(errno));
        goto LABEL_EXIT;
    }

    unlink(fname);
    retval = 0;

LABEL_EXIT:
    return retval;
}


static int exec_cmd(const msgbuf_t *pMsg, char *pResMsg)
{
    int retval = -1;

    switch (pMsg->payload.type) {
    case MSG_BOLT:
        retval = exec_cmd_bolt(&pMsg->payload.cmd.bolt, pResMsg);
        break;
    case MSG_DAEMON:
        retval = exec_cmd_daemon(&pMsg->payload.cmd.daemon, pResMsg);
        break;
    default:
        SYSLOG_ERR("unknown type[%d]\n", pMsg->payload.type);
        break;
    }

    return retval;
}


static int exec_cmd_bolt(const msg_bolt_t *pBolt, char *pResMsg)
{
    fprintf(PRINTOUT, "exec_cmd_bolt\n");
    return -1;
}


static int exec_cmd_daemon(const msg_daemon_t *pDaemon, char *pResMsg)
{
    int retval = -1;

    fprintf(PRINTOUT, "\n\n-----------------------------------------------------\n");
    switch (pDaemon->cmd) {
    case DCMD_CONNECT:
        {
            const daemon_connect_t *p_conn = &pDaemon->params.connect;

            fprintf(PRINTOUT, "<connect>\n");
            SYSLOG_INFO("connect");

            //socketが開いているか検索
            lnapp_conf_t *p_appconf = search_connected_lnapp(p_conn->node_id);
            if (p_appconf == NULL) {
                p2p_cli_start(pDaemon->cmd, p_conn, NULL, ln_node_id(&mNode), pResMsg);
            } else {
                SYSLOG_ERR("already connected");
                strcpy(pResMsg, "error: already connected");
            }
            retval = 0;
        }
        break;
    case DCMD_CREATE:
        {
            funding_conf_t *p_fund = (funding_conf_t *)malloc(sizeof(funding_conf_t));
            memcpy(p_fund, &pDaemon->params.funding.funding, sizeof(funding_conf_t));
            print_funding_conf(p_fund);

            fprintf(PRINTOUT, "<create>\n");
            SYSLOG_INFO("create");

            p2p_cli_start(pDaemon->cmd, &pDaemon->params.funding.conn, p_fund, ln_node_id(&mNode), pResMsg);
            retval = 0;
        }
        break;
    case DCMD_CLOSE:
        {
            bool ret;
            const daemon_connect_t *p_conn = &pDaemon->params.connect;

            fprintf(PRINTOUT, "<close>\n");
            SYSLOG_INFO("close");

            //socketが開いているか検索
            lnapp_conf_t *p_appconf = search_connected_lnapp(p_conn->node_id);
            if (p_appconf != NULL) {
                ret = lnapp_close_channel(p_appconf);
            } else {
                //どちらでも開いていない
                SYSLOG_ERR("no socket: DCMD_CLOSE");
                strcpy(pResMsg, "error: not connected");
               ret = false;
            }
            if (!ret) {
                SYSLOG_ERR("DCMD_CLOSE");
            }
            retval = 0;
        }
        break;
    case DCMD_PREIMAGE:
        {
            const daemon_connect_t *p_conn = &pDaemon->params.connect;

            fprintf(PRINTOUT, "<preimage>\n");
            SYSLOG_INFO("preimage");

            lnapp_conf_t *p_appconf = search_connected_lnapp(p_conn->node_id);
            if (p_appconf != NULL) {
                lnapp_add_preimage(p_appconf, pResMsg);
            }
            retval = 0;
        }
        break;
    case DCMD_PAYMENT_HASH:
        {
            const daemon_connect_t *p_conn = &pDaemon->params.connect;

            fprintf(PRINTOUT, "<payment_hash>\n");
            SYSLOG_INFO("payment_hash");

            lnapp_conf_t *p_appconf = search_connected_lnapp(p_conn->node_id);
            if (p_appconf != NULL) {
                lnapp_show_payment_hash(p_appconf);
            } else {
                strcpy(pResMsg, "error: not connected");
            }
            retval = 0;
        }
        break;
    case DCMD_PAYMENT:
        {
            bool ret;
            const payment_conf_t *p_pay = &pDaemon->params.payment.payment;
            print_payment_conf(p_pay);

            fprintf(PRINTOUT, "<payment>\n");
            SYSLOG_INFO("payment");

            //socketが開いているか検索
            lnapp_conf_t *p_appconf = search_connected_lnapp(p_pay->hop_datain[1].pubkey);
            if (p_appconf != NULL) {
                ret = lnapp_payment(p_appconf, p_pay);
            } else {
                //どちらでも開いていない
                SYSLOG_ERR("no socket: DCMD_PAYMENT");
                strcpy(pResMsg, "error: not connected");
                //p2p_cli_start(pDaemon->cmd, &pDaemon->params.payment.conn, p_pay, pResMsg);
                ret = false;
            }
            if (!ret) {
                SYSLOG_ERR("fail: DCMD_PAYMENT");
            }
            retval = 0;
        }
        break;
    case DCMD_SHOW_LIST:
        {
            strcpy(pResMsg, "node_id: ");
            misc_bin2str(pResMsg + 9, ln_node_id(&mNode), UCOIN_SZ_PUBKEY);
            strcat(pResMsg, "\n\n");
        }
        fprintf(PRINTOUT, "<connected channel list>\n");
        p2p_svr_show_self(pResMsg);
        p2p_cli_show_self(pResMsg);
        retval = 0;
        break;
    case DCMD_STOP:
    default:
        fprintf(PRINTOUT, "<stop>\n");
        SYSLOG_INFO("stop");
        p2p_svr_stop_all();
        p2p_cli_stop_all();
        break;
    }
    fprintf(PRINTOUT, "-----------------------------------------------------\n\n");

    return retval;
}


static lnapp_conf_t *search_connected_lnapp(const uint8_t *p_node_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_cli_search_node(p_node_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_node(p_node_id);
    }
    return p_appconf;
}
