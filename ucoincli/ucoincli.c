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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>


#include "ucoind.h"
#include "conf.h"
#include "misc.h"


#define M_OPTIONS_INIT  (0xff)


/********************************************************************
 * prototypes
 ********************************************************************/

static int msg_send(const msgbuf_t *pMsg, uint16_t Port);


/********************************************************************
 * public functions
 ********************************************************************/

int main(int argc, char *argv[])
{
    msgbuf_t buf;
    //msg_bolt_t *p_bolt = &buf.payload.cmd.bolt;
    msg_daemon_t *p_daemon = &buf.payload.cmd.daemon;

    ucoin_init(UCOIN_TESTNET, true);

    buf.mtype = MTYPE_CLI2D;

    int opt;
    uint8_t options = M_OPTIONS_INIT;
    while ((opt = getopt(argc, argv, "hqlc:f:i:mp:x")) != -1) {
        switch (opt) {
        case 'h':
            options = 0;
            break;
        case 'q':
            //ucoind停止
            if (options > 1) {
                buf.payload.type = MSG_DAEMON;
                p_daemon->cmd = DCMD_STOP;
                options = 1;
                //printf("<stop>\n");
            }
            break;
        case 'l':
            //channel一覧
            if (options == M_OPTIONS_INIT) {
                buf.payload.type = MSG_DAEMON;
                p_daemon->cmd = DCMD_SHOW_LIST;
                options = 5;
            }
            break;
        case 'c':
            //接続先(c,f,p共通)
            //      peer.conf
            if (options > 200) {
                daemon_connect_t *p_conn = &p_daemon->params.connect;
                peer_conf_t peer;
                bool bret = load_peer_conf(optarg, &peer);
                if (bret) {
                    //peer.conf
                    strcpy(p_conn->ipaddr, peer.ipaddr);
                    p_conn->port = peer.port;
                    memcpy(p_conn->node_id, peer.node_id, UCOIN_SZ_PUBKEY);

                    buf.payload.type = MSG_DAEMON;
                    p_daemon->cmd = DCMD_CONNECT;
                    options = 200;
                } else {
                    printf("fail: peer configuration file\n");
                    options = 0;
                }
            }
            break;
        case 'f':
            //funding情報
            //      funding.conf
            if (options == 200) {
                daemon_funding_t *p_fund = &p_daemon->params.funding;
                bool bret = load_funding_conf(optarg, &p_fund->funding);
                if (bret) {
                    buf.payload.type = MSG_DAEMON;
                    p_daemon->cmd = DCMD_CREATE;
                    options = 2;
                } else {
                    printf("fail: funding configuration file\n");
                    options = 0;
                }
            } else {
                printf("-f need -c option before\n");
                options = 0;
            }
            break;
        case 'i':
            //payment_preimage作成
            if (options == 200) {
                daemon_invoice_t *p_inv = &p_daemon->params.invoice;
                errno = 0;
                p_inv->amount = (uint64_t)strtoull(optarg, NULL, 10);
                if (errno == 0) {
                    buf.payload.type = MSG_DAEMON;
                    p_daemon->cmd = DCMD_PREIMAGE;
                    options = 3;
                } else {
                    printf("fail: funding configuration file\n");
                    options = 0;
                }
            }
            break;
        case 'm':
            //payment-hash表示
            if (options == 200) {
                buf.payload.type = MSG_DAEMON;
                p_daemon->cmd = DCMD_PAYMENT_HASH;
                options = 3;
            }
            break;
        case 'p':
            //payment
            //      payment.conf
            if (options == 200) {
                daemon_payment_t *p_pay = &p_daemon->params.payment;
                bool bret = load_payment_conf(optarg, &p_pay->payment);
                if (bret) {
                    buf.payload.type = MSG_DAEMON;
                    p_daemon->cmd = DCMD_PAYMENT;
                    options = 3;
                } else {
                    printf("fail: payment configuration file\n");
                    options = 0;
                }
            } else {
                printf("-f need -c option before\n");
                options = 0;
            }
            break;
        case 'x':
            //mutual close
            if (options == 200) {
                buf.payload.type = MSG_DAEMON;
                p_daemon->cmd = DCMD_CLOSE;
                options = 4;
            } else {
                printf("-x need -c option before\n");
                options = 0;
            }
            break;
        case ':':
            printf("need value: %c\n", optopt);
            options = 1;
            break;
        case '?':
            printf("unknown option: %c\n", optopt);
            /* THROUGH FALL */
        default:
            options = 0;
            break;
        }
    }

    if ((options == M_OPTIONS_INIT) || (options == 0) || (optind >= argc)) {
        printf("[usage]\n");
        printf("\t%s <options> <port>\n", argv[0]);
        printf("\t\t-h : help\n");
        printf("\t\t-q : quit ucoind\n");
        printf("\t\t-l : list channels\n");
        printf("\t\t-c <node.conf> : connect node\n");
        printf("\t\t-f <fund.conf> : funding(need -c)\n");
        printf("\t\t-i : add preimage, and show payment_hash(need -c)\n");
        printf("\t\t-m : show payment_hashs(need -c)\n");
        printf("\t\t-p <payment.conf> : payment(need -c)\n");
        printf("\t\t-x : mutual close(need -c)\n");
        return -1;
    }

    uint16_t port = (uint16_t)atoi(argv[optind]);

    msg_send(&buf, port);

    ucoin_term();

    return 0;
}


/********************************************************************
 * private functions
 ********************************************************************/

static int msg_send(const msgbuf_t *pMsg, uint16_t Port)
{
    int retval = -1;
    int msqid;
    key_t key;
    char wkdir[50];
    char fname[50];
    msgres_t res;

    sprintf(wkdir, "%s/%s", getenv("HOME"), UCOINDDIR);
    sprintf(fname, "%s/%s%d.dat", wkdir, FTOK_FNAME, Port);
    //printf("msg: %s\n", fname);
    if ((key = ftok(fname, FTOK_CHAR)) == -1) {
        perror("ftok");
        goto LABEL_EXIT;
    }

    if ((msqid = msgget(key, 0644)) == -1) {
        perror("msgget");
        goto LABEL_EXIT;
    }

    if (msgsnd(msqid, pMsg, sizeof(payload_t), 0) == -1) {
        perror("msgsnd");
    }

    if (msgrcv(msqid, &res, sizeof(res.mtext), MTYPE_D2CLI, 0) == -1) {
        perror("msgrcv");
        goto LABEL_EXIT;
    }
    if (strlen(res.mtext) > 0) {
        printf("%s\n", res.mtext);
    }

    retval = 0;

LABEL_EXIT:
    return retval;
}
