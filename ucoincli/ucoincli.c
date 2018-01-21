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
//#include <sys/types.h>
//#include <sys/stat.h>
#include <unistd.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>

#include <jansson.h>

#include "ucoind.h"
#include "conf.h"
#include "misc.h"


#define M_OPTIONS_INIT  (0xff)
#define M_OPTIONS_CONN  (0xf0)
#define M_OPTIONS_EXEC  (2)
#define M_OPTIONS_STOP  (1)
#define M_OPTIONS_HELP  (0)
#define BUFFER_SIZE     (256 * 1024)

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    char    *p_data;
    int     pos;
} write_result_t;


static char         mPeerAddr[INET6_ADDRSTRLEN];
static uint16_t     mPeerPort;
static char         mPeerNodeId[UCOIN_SZ_PUBKEY * 2 + 1];
static char         mBuf[BUFFER_SIZE];


/********************************************************************
 * prototypes
 ********************************************************************/

static void stop_rpc(char *pJson);
static void getinfo_rpc(char *pJson);
static void connect_rpc(char *pJson);
static void fund_rpc(char *pJson, const funding_conf_t *pFund);
static void invoice_rpc(char *pJson, uint64_t Amount, bool conn);
static void listinvoice_rpc(char *pJson);
static void payment_rpc(char *pJson, const payment_conf_t *pPay);
static void close_rpc(char *pJson);
static void debug_rpc(char *pJson, int debug);
static void getcommittx_rpc(char *pJson);

static int msg_send(char *pRecv, const char *pSend, const char *pAddr, uint16_t Port, bool bSend);


/********************************************************************
 * public functions
 ********************************************************************/

int main(int argc, char *argv[])
{
#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    ucoin_init(UCOIN_MAINNET, true);
#elif NETKIND==1
    ucoin_init(UCOIN_TESTNET, true);
#endif

    bool conn = false;
    const char *p_addr = NULL;
    char addr[256];
    bool b_send = true;
    int opt;
    uint8_t options = M_OPTIONS_INIT;
    while ((opt = getopt(argc, argv, "htqlc:f:i:mp:xga:d:")) != -1) {
        switch (opt) {
        case 'h':
            options = M_OPTIONS_HELP;
            break;
        case 't':
            //JSONデータを表示させるのみで送信しない
            b_send = false;
            break;
        case 'a':
            //指示するucoindのIPアドレス指定
            strcpy(addr, optarg);
            p_addr = addr;
            break;
        case 'd':
            //デバッグ
            debug_rpc(mBuf, (int)strtol(optarg, NULL, 10));
            options = M_OPTIONS_EXEC;
            break;

        //
        // -c不要
        //
        case 'q':
            //ucoind停止
            if (options > M_OPTIONS_STOP) {
                stop_rpc(mBuf);
                options = M_OPTIONS_STOP;
            } else {
                printf("fail: too many options\n");
                options = M_OPTIONS_HELP;
            }
            break;
        case 'l':
            //channel一覧
            if (options == M_OPTIONS_INIT) {
                getinfo_rpc(mBuf);
                options = M_OPTIONS_EXEC;
            }
            break;
        case 'i':
            //payment_preimage作成
            errno = 0;
            uint64_t amount = (uint64_t)strtoull(optarg, NULL, 10);
            if (errno == 0) {
                invoice_rpc(mBuf, amount, conn);
                conn = false;
                options = M_OPTIONS_EXEC;
            } else {
                printf("fail: funding configuration file\n");
                options = M_OPTIONS_HELP;
            }
            break;
        case 'm':
            //payment-hash表示
            if (options == M_OPTIONS_INIT) {
                listinvoice_rpc(mBuf);
                options = M_OPTIONS_EXEC;
            } else {
                printf("fail: too many options\n");
                options = M_OPTIONS_HELP;
            }
            break;
        case 'p':
            //payment
            if (options == M_OPTIONS_INIT) {
                payment_conf_t payconf;
                const char *path = strtok(optarg, ",");
                const char *hash = strtok(NULL, ",");
                bool bret = load_payment_conf(path, &payconf);
                if (hash) {
                    bret &= misc_str2bin(payconf.payment_hash, LN_SZ_HASH, hash);
                }
                if (bret) {
                    payment_rpc(mBuf, &payconf);
                    options = M_OPTIONS_EXEC;
                } else {
                    printf("fail: payment configuration file\n");
                    options = M_OPTIONS_HELP;
                }
            } else {
                printf("-f need -c option before\n");
                options = M_OPTIONS_HELP;
            }
            break;

        //
        // -c必要
        //
        case 'c':
            //接続先(c,f共通)
            if (options > M_OPTIONS_CONN) {
                peer_conf_t peer;
                bool bret = load_peer_conf(optarg, &peer);
                if (bret) {
                    //peer.conf
                    conn = true;
                    strcpy(mPeerAddr, peer.ipaddr);
                    mPeerPort = peer.port;
                    misc_bin2str(mPeerNodeId, peer.node_id, UCOIN_SZ_PUBKEY);
                    options = M_OPTIONS_CONN;
                } else {
                    printf("fail: peer configuration file\n");
                    options = M_OPTIONS_HELP;
                }
            } else {
                printf("fail: too many options\n");
                options = M_OPTIONS_HELP;
            }
            break;
        case 'f':
            //funding情報
            if (options == M_OPTIONS_CONN) {
                funding_conf_t fundconf;
                bool bret = load_funding_conf(optarg, &fundconf);
                if (bret) {
                    conn = false;
                    fund_rpc(mBuf, &fundconf);
                    options = M_OPTIONS_EXEC;
                } else {
                    printf("fail: funding configuration file\n");
                    options = M_OPTIONS_HELP;
                }
            } else {
                printf("-f need -c option before\n");
                options = M_OPTIONS_HELP;
            }
            break;
        case 'x':
            //mutual close
            if (options == M_OPTIONS_CONN) {
                conn = false;
                close_rpc(mBuf);
                options = M_OPTIONS_EXEC;
            } else {
                printf("-x need -c option before\n");
                options = M_OPTIONS_HELP;
            }
            break;
        case 'g':
            //getcommittx
            if (options == M_OPTIONS_CONN) {
                conn = false;
                getcommittx_rpc(mBuf);
                options = M_OPTIONS_EXEC;
            } else {
                printf("-g need -c option before\n");
                options = M_OPTIONS_HELP;
            }
            break;

        //
        // other
        //
        case ':':
            printf("need value: %c\n", optopt);
            options = M_OPTIONS_HELP;
            break;
        case '?':
            printf("unknown option: %c\n", optopt);
            /* THROUGH FALL */
        default:
            options = M_OPTIONS_HELP;
            break;
        }
    }

    if ((options == M_OPTIONS_INIT) || (options == M_OPTIONS_HELP) || (optind >= argc)) {
        printf("[usage]\n");
        printf("\t%s <-t> <options> <JSON-RPC port(not ucoind port)>\n", argv[0]);
        printf("\t\t-h : help\n");
        printf("\t\t-t : test(not send command)\n");
        printf("\t\t-q : quit ucoind\n");
        printf("\t\t-l : list channels\n");
        printf("\t\t-i <amount_msat> : add preimage, and show payment_hash\n");
        printf("\t\t-p <payment.conf>,<paymenet_hash> : payment(don't put a space before or after the comma)\n");
        printf("\t\t-m : show payment_hashs\n");
        printf("\t\t-c <peer.conf> : connect node\n");
        printf("\t\t-c <peer.conf> -f <fund.conf> : funding\n");
        printf("\t\t-c <peer.conf> -x : mutual close channel\n");
        // printf("\n");
        // printf("\t\t-d <value> : [debug]debug option\n");
        // printf("\t\t-c <node.conf> -g : [debug]get commitment transaction\n");
        return -1;
    }

    if (conn) {
        connect_rpc(mBuf);
    }

    uint16_t port = (uint16_t)atoi(argv[optind]);

    int ret = msg_send(mBuf, mBuf, p_addr, port, b_send);

    ucoin_term();

    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

static void stop_rpc(char *pJson)
{
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "stop") M_NEXT
            M_QQ("params") ":[]"
        "}");
}


static void getinfo_rpc(char *pJson)
{
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "getinfo") M_NEXT
            M_QQ("params") ":[]"
        "}");
}


static void connect_rpc(char *pJson)
{
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "connect") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort);
}


static void fund_rpc(char *pJson, const funding_conf_t *pFund)
{
    char txid[UCOIN_SZ_TXID * 2 + 1];

    misc_bin2str_rev(txid, pFund->txid, UCOIN_SZ_TXID);
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "fund") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d,"
                //txid, txindex, signaddr, funding_sat, push_sat
                M_QQ("%s") ",%d," M_QQ("%s") ",%" PRIu64 ",%" PRIu64
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort,
            txid, pFund->txindex, pFund->signaddr, pFund->funding_sat, pFund->push_sat);
}


static void invoice_rpc(char *pJson, uint64_t Amount, bool conn)
{
    if (conn) {
        snprintf(pJson, BUFFER_SIZE,
            "{"
                M_STR("method", "invoice") M_NEXT
                M_QQ("params") ":[ "
                    //peer_nodeid, peer_addr, peer_port
                    M_QQ("%s") "," M_QQ("%s") ",%d,"
                    //invoice
                    "%" PRIu64
                " ]"
            "}",
                mPeerNodeId, mPeerAddr, mPeerPort, Amount);
    } else {
        snprintf(pJson, BUFFER_SIZE,
            "{"
                M_STR("method", "invoice") M_NEXT
                M_QQ("params") ":[ "
                    //invoice
                    "%" PRIu64
                " ]"
            "}",
                Amount);
    }
}


static void listinvoice_rpc(char *pJson)
{
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "listinvoice") M_NEXT
            M_QQ("params") ":[]"
        "}");
}


static void payment_rpc(char *pJson, const payment_conf_t *pPay)
{
    char payhash[LN_SZ_HASH * 2 + 1];
    //node_id(33*2),short_channel_id(8*2),amount(21),cltv(5)
    char forward[UCOIN_SZ_PUBKEY*2 + sizeof(uint64_t)*2 + 21 + 5 + 50];

    misc_bin2str(payhash, pPay->payment_hash, LN_SZ_HASH);
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "pay") M_NEXT
            M_QQ("params") ":[ "
                //payment_hash, hop_num
                M_QQ("%s") ",%d, [\n",
            payhash, pPay->hop_num);

    for (int lp = 0; lp < pPay->hop_num; lp++) {
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];

        misc_bin2str(node_id, pPay->hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY);
        snprintf(forward, sizeof(forward), "[" M_QQ("%s") "," M_QQ("%" PRIx64) ",%" PRIu64 ",%d]",
                node_id,
                pPay->hop_datain[lp].short_channel_id,
                pPay->hop_datain[lp].amt_to_forward,
                pPay->hop_datain[lp].outgoing_cltv_value
        );
        strcat(pJson, forward);
        if (lp != pPay->hop_num - 1) {
            strcat(pJson, ",");
        }
    }
    strcat(pJson, "] ]}");
}


static void close_rpc(char *pJson)
{
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "close") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort);
}


static void debug_rpc(char *pJson, int debug)
{
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "debug") M_NEXT
            M_QQ("params") ":[ %d ]"
        "}", debug);
}


static void getcommittx_rpc(char *pJson)
{
    snprintf(pJson, BUFFER_SIZE,
        "{"
            M_STR("method", "getcommittx") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort);
}


static int msg_send(char *pRecv, const char *pSend, const char *pAddr, uint16_t Port, bool bSend)
{
    int retval = -1;

    if (bSend) {
        struct sockaddr_in sv_addr;

        fprintf(stderr, "%s\n", pSend);
        int sock = socket(PF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return retval;
        }
        memset(&sv_addr, 0, sizeof(sv_addr));
        sv_addr.sin_family = AF_INET;
        if (pAddr == NULL) {
            sv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        } else {
            sv_addr.sin_addr.s_addr = inet_addr(pAddr);
        }
        sv_addr.sin_port = htons(Port);
        retval = connect(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
        if (retval < 0) {
            close(sock);
            return retval;
        }
        write(sock, pSend, strlen(pSend));
        ssize_t len = read(sock, pRecv, BUFFER_SIZE);
        if (len > 0) {
            retval = -1;
            pRecv[len] = '\0';
            printf("%s\n", pRecv);

            json_t *p_root;
            json_error_t error;
            p_root = json_loads(pRecv, 0, &error);
            if (p_root) {
                json_t *p_result;
                p_result = json_object_get(p_root, "result");
                if (p_result) {
                    //戻り値正常
                    retval = 0;
                }
            }
        }
        close(sock);
    } else {
        fprintf(stdout, "%s\n", pSend);
        retval = 0;
    }

    return retval;
}
