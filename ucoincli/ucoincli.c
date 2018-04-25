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
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <jansson.h>

#include "ucoind.h"
#include "conf.h"
#include "misc.h"
#include "segwit_addr.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_OPTIONS_INIT  (0xff)
#define M_OPTIONS_CONN  (0xf0)
#define M_OPTIONS_EXEC  (2)
#define M_OPTIONS_STOP  (1)
#define M_OPTIONS_HELP  (0)
#define M_OPTIONS_ERR   (-1)

#define BUFFER_SIZE     (256 * 1024)

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value


#define M_CHK_INIT      {\
    if (*pOption != M_OPTIONS_INIT) {           \
        printf("fail: too many options\n");     \
        *pOption = M_OPTIONS_HELP;              \
        return;                                 \
    }                                           \
}

#define M_CHK_CONN      {\
    if (*pOption != M_OPTIONS_CONN) {           \
        printf("need -c option first\n");       \
        *pOption = M_OPTIONS_HELP;              \
        return;                                 \
    }                                           \
}


/**************************************************************************
 * static variables
 **************************************************************************/

static char         mPeerAddr[INET6_ADDRSTRLEN];
static uint16_t     mPeerPort;
static char         mPeerNodeId[UCOIN_SZ_PUBKEY * 2 + 1];
static char         mBuf[BUFFER_SIZE];
static bool         mTcpSend;
static char         mAddr[256];


/********************************************************************
 * prototypes
 ********************************************************************/

static void optfunc_conn_param(int *pOption, bool *pConn);
static void optfunc_help(int *pOption, bool *pConn);
static void optfunc_test(int *pOption, bool *pConn);
static void optfunc_addr(int *pOption, bool *pConn);
static void optfunc_getinfo(int *pOption, bool *pConn);
static void optfunc_disconnect(int *pOption, bool *pConn);
static void optfunc_funding(int *pOption, bool *pConn);
static void optfunc_invoice(int *pOption, bool *pConn);
static void optfunc_erase(int *pOption, bool *pConn);
static void optfunc_listinvoice(int *pOption, bool *pConn);
static void optfunc_payment(int *pOption, bool *pConn);
static void optfunc_routepay(int *pOption, bool *pConn);
static void optfunc_close(int *pOption, bool *pConn);
static void optfunc_getlasterr(int *pOption, bool *pConn);
static void optfunc_debug(int *pOption, bool *pConn);
static void optfunc_getcommittx(int *pOption, bool *pConn);
static void optfunc_disable_autoconn(int *pOption, bool *pConn);
static void optfunc_remove_channel(int *pOption, bool *pConn);

static void connect_rpc(void);
static void stop_rpc(void);

static int msg_send(char *pRecv, const char *pSend, const char *pAddr, uint16_t Port, bool bSend);


static const struct {
    char        opt;
    void        (*func)(int *pOption, bool *pConn);
} OPTION_FUNCS[] = {
    { 'h', optfunc_help },
    { 't', optfunc_test },
    { 'a', optfunc_addr },
    { 'd', optfunc_debug },
    { 'q', optfunc_disconnect },
    { 'l', optfunc_getinfo },
    { 'i', optfunc_invoice },
    { 'e', optfunc_erase },
    { 'm', optfunc_listinvoice },
    { 'p', optfunc_payment },
    { 'r', optfunc_routepay },
    { 's', optfunc_disable_autoconn },
    { 'X', optfunc_remove_channel },
    { 'c', optfunc_conn_param },
    { 'f', optfunc_funding },
    { 'x', optfunc_close },
    { 'w', optfunc_getlasterr },
    { 'g', optfunc_getcommittx },
};


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

    int option = M_OPTIONS_INIT;
    bool conn = false;
    mAddr[0] = '\0';
    mTcpSend = true;
    int opt;
    while ((opt = getopt(argc, argv, "htq::lc:f:i:e:mp:r:xX:s:gwa:d:")) != -1) {
        for (size_t lp = 0; lp < ARRAY_SIZE(OPTION_FUNCS); lp++) {
            if (opt == OPTION_FUNCS[lp].opt) {
                (*OPTION_FUNCS[lp].func)(&option, &conn);
                break;
            }
        }
    }

    if (option == M_OPTIONS_ERR) {
        return -1;
    }
    if ((option == M_OPTIONS_INIT) || (option == M_OPTIONS_HELP) || (!conn && (option == M_OPTIONS_CONN))) {
        printf("[usage]\n");
        printf("\t%s [-t] [OPTIONS...] [JSON-RPC port(not ucoind port)]\n", argv[0]);
        printf("\t\t-h : help\n");
        printf("\t\t-t : test(not send command)\n");
        printf("\t\t-q : quit ucoind\n");
        printf("\t\t-l : list channels\n");
        printf("\t\t-i AMOUNT_MSAT : add preimage, and show payment_hash\n");
        printf("\t\t-e PAYMENT_HASH : erase payment_hash\n");
        printf("\t\t-e ALL : erase all payment_hash\n");
        printf("\t\t-r BOLT#11_INVOICE[,ADDITIONAL AMOUNT_MSAT][,ADDITIONAL MIN_FINAL_CLTV_EXPIRY] : payment(don't put a space before or after the comma)\n");
        printf("\t\t-m : show payment_hashs\n");
        printf("\t\t-s<1 or 0> : 1=stop auto channel connect\n");
        printf("\t\t-c PEER.CONF : connect node\n");
        printf("\t\t-c PEER NODE_ID or PEER.CONF -f FUND.CONF : funding\n");
        printf("\t\t-c PEER NODE_ID or PEER.CONF -x : mutual/unilateral close channel\n");
        printf("\t\t-c PEER NODE_ID or PEER.CONF -w : get last error\n");
        printf("\t\t-c PEER NODE_ID or PEER.CONF -q : disconnect node\n");
        printf("\n");
        // printf("\t\t-a <IP address> : [debug]JSON-RPC send address\n");
        printf("\t\t-d VALUE : [debug]debug option\n");
        printf("\t\t\tb0 ... no update_fulfill_htlc\n");
        printf("\t\t\tb1 ... no closing transaction\n");
        printf("\t\t\tb2 ... force payment_preimage mismatch\n");
        printf("\t\t\tb3 ... no node auto connect\n");
        printf("\t\t-c PEER NODE_ID or PEER.CONF -g : [debug]get commitment transaction\n");
        printf("\t\t-X CHANNEL_ID : [debug]delete channel from DB\n");
        return -1;
    }

    if (conn) {
        connect_rpc();
    }

    uint16_t port;
    if (optind == argc) {
        port = 9736;
    } else {
        port = (uint16_t)atoi(argv[optind]);
    }

    int ret = msg_send(mBuf, mBuf, mAddr, port, mTcpSend);

    ucoin_term();

    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

static void optfunc_conn_param(int *pOption, bool *pConn)
{
    if (*pOption != M_OPTIONS_INIT) {
        printf("fail: '-c' must first\n");
        *pOption = M_OPTIONS_HELP;
        return;
    }

    size_t optlen = strlen(optarg);
    peer_conf_t peer;
    bool bret = load_peer_conf(optarg, &peer);
    if (bret) {
        //peer.conf
        *pConn = true;
        strcpy(mPeerAddr, peer.ipaddr);
        mPeerPort = peer.port;
        misc_bin2str(mPeerNodeId, peer.node_id, UCOIN_SZ_PUBKEY);
        *pOption = M_OPTIONS_CONN;
    } else if (optlen >= (UCOIN_SZ_PUBKEY * 2 + 1 + 7 + 1 + 1)) {
        // <pubkey>@<ipaddr>:<port>
        // (33 * 2)@x.x.x.x:x
        int results = sscanf(optarg, "%66s@%15[^:]:%" SCNu16,
            mPeerNodeId,
            mPeerAddr,
            &mPeerPort);
        printf("id: %s\n", mPeerNodeId);
        printf("addr: %s\n", mPeerAddr);
        printf("port: %" PRIu16 "\n", mPeerPort);
        if (results == 3) {
            *pConn = true;
            *pOption = M_OPTIONS_CONN;
        } else {
            printf("fail: peer configuration file\n");
            *pOption = M_OPTIONS_HELP;
        }
    } else if (optlen == UCOIN_SZ_PUBKEY * 2) {
        //node_idを直で指定した可能性あり(connectとしては使用できない)
        strcpy(mPeerAddr, "0.0.0.0");
        mPeerPort = 0;
        strcpy(mPeerNodeId, optarg);
        *pOption = M_OPTIONS_CONN;
    } else {
        printf("fail: peer configuration file\n");
        *pOption = M_OPTIONS_HELP;
    }
}


static void optfunc_help(int *pOption, bool *pConn)
{
    (void)pConn;

    *pOption = M_OPTIONS_HELP;
}


static void optfunc_test(int *pOption, bool *pConn)
{
    (void)pOption; (void)pConn;

    mTcpSend = false;
}


static void optfunc_addr(int *pOption, bool *pConn)
{
    (void)pOption; (void)pConn;

    strcpy(mAddr, optarg);
}


static void optfunc_getinfo(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "getinfo") M_NEXT
            M_QQ("params") ":[]"
        "}");

    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_disconnect(int *pOption, bool *pConn)
{
    if (*pOption == M_OPTIONS_CONN) {
        //特定接続を切る
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "disconnect") M_NEXT
                M_QQ("params") ":[ "
                    //peer_nodeid, peer_addr, peer_port
                    M_QQ("%s") "," M_QQ("%s") ",%d"
                " ]"
            "}",
                mPeerNodeId, mPeerAddr, mPeerPort);

        *pOption = M_OPTIONS_EXEC;
        *pConn = false;
    } else {
        //ucoind終了
        stop_rpc();
        *pOption = M_OPTIONS_STOP;
    }
}


static void optfunc_funding(int *pOption, bool *pConn)
{
    M_CHK_CONN

    funding_conf_t fundconf;
    bool bret = load_funding_conf(optarg, &fundconf);
    if (bret) {
        char txid[UCOIN_SZ_TXID * 2 + 1];

        misc_bin2str_rev(txid, fundconf.txid, UCOIN_SZ_TXID);
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "fund") M_NEXT
                M_QQ("params") ":[ "
                    //peer_nodeid, peer_addr, peer_port
                    M_QQ("%s") "," M_QQ("%s") ",%d,"
                    //txid, txindex, signaddr, funding_sat, push_sat
                    M_QQ("%s") ",%d," M_QQ("%s") ",%" PRIu64 ",%" PRIu64 ",%" PRIu32
                " ]"
            "}",
                mPeerNodeId, mPeerAddr, mPeerPort,
                txid, fundconf.txindex, fundconf.signaddr,
                fundconf.funding_sat, fundconf.push_sat, fundconf.feerate_per_kw);

        *pConn = false;
        *pOption = M_OPTIONS_EXEC;
    } else {
        printf("fail: funding configuration file\n");
        *pOption = M_OPTIONS_HELP;
    }
}


static void optfunc_invoice(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    errno = 0;
    uint64_t amount = (uint64_t)strtoull(optarg, NULL, 10);
    if (errno == 0) {
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "invoice") M_NEXT
                M_QQ("params") ":[ "
                    //invoice
                    "%" PRIu64
                " ]"
            "}",
                amount);

        *pOption = M_OPTIONS_EXEC;
    } else {
        printf("fail: errno=%s\n", strerror(errno));
        *pOption = M_OPTIONS_ERR;
    }
}


static void optfunc_erase(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    const char *pPaymentHash = NULL;
    if (strcmp(optarg, "ALL") == 0) {
        pPaymentHash = "";
    } else if (strlen(optarg) == LN_SZ_HASH * 2) {
        pPaymentHash = optarg;
    } else {
        //error
    }
    if (pPaymentHash != NULL) {
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "eraseinvoice") M_NEXT
                M_QQ("params") ":[ "
                    M_QQ("%s")
                " ]"
            "}",
                pPaymentHash);

        *pOption = M_OPTIONS_EXEC;
    } else {
        printf("fail: invalid param\n");
        *pOption = M_OPTIONS_ERR;
    }
}


static void optfunc_listinvoice(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "listinvoice") M_NEXT
            M_QQ("params") ":[]"
        "}");
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_payment(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    payment_conf_t payconf;
    const char *path = strtok(optarg, ",");
    const char *hash = strtok(NULL, ",");
    bool bret = load_payment_conf(path, &payconf);
    if (hash) {
        bret &= misc_str2bin(payconf.payment_hash, LN_SZ_HASH, hash);
    }
    if (!bret) {
        printf("fail: payment configuration file\n");
        *pOption = M_OPTIONS_ERR;
        return;
    }

    char payhash[LN_SZ_HASH * 2 + 1];
    //node_id(33*2),short_channel_id(8*2),amount(21),cltv(5)
    char forward[UCOIN_SZ_PUBKEY*2 + sizeof(uint64_t)*2 + 21 + 5 + 50];

    misc_bin2str(payhash, payconf.payment_hash, LN_SZ_HASH);
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "pay") M_NEXT
            M_QQ("params") ":[ "
                //payment_hash, hop_num
                M_QQ("%s") ",%d, [\n",
            payhash, payconf.hop_num);

    for (int lp = 0; lp < payconf.hop_num; lp++) {
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];

        misc_bin2str(node_id, payconf.hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY);
        snprintf(forward, sizeof(forward), "[" M_QQ("%s") "," M_QQ("%" PRIx64) ",%" PRIu64 ",%d]",
                node_id,
                payconf.hop_datain[lp].short_channel_id,
                payconf.hop_datain[lp].amt_to_forward,
                payconf.hop_datain[lp].outgoing_cltv_value
        );
        strcat(mBuf, forward);
        if (lp != payconf.hop_num - 1) {
            strcat(mBuf, ",");
        }
    }
    strcat(mBuf, "] ]}");

    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_routepay(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    ln_invoice_t invoice_data;
    const char *invoice = strtok(optarg, ",");
    const char *amount_msat = strtok(NULL, ",");
    const char *cltv_offset = strtok(NULL, ",");
    bool bret = ln_invoice_decode(&invoice_data, invoice);
    if (!bret) {
        printf("fail: decode BOLT#11 invoice\n");
        *pOption = M_OPTIONS_ERR;
        return;
    }

    printf("---------------------------------\n");
    switch (invoice_data.hrp_type) {
    case LN_INVOICE_MAINNET:
        printf("blockchain: bitcoin mainnet\n");
        printf("fail: mainnet payment not supported yet.\n");
        *pOption = M_OPTIONS_ERR;
        break;
    case LN_INVOICE_TESTNET:
        printf("blockchain: bitcoin testnet\n");
        break;
    case LN_INVOICE_REGTEST:
        printf("blockchain: bitcoin regtest\n");
        break;
    default:
        printf("unknown hrp_type\n");
        *pOption = M_OPTIONS_ERR;
    }
    printf("amount_msat=%" PRIu64 "\n", invoice_data.amount_msat);
    time_t tm = (time_t)invoice_data.timestamp;
    printf("timestamp= %" PRIu64 " : %s", (uint64_t)invoice_data.timestamp, ctime(&tm));
    printf("min_final_cltv_expiry=%u\n", invoice_data.min_final_cltv_expiry);
    printf("payee=");
    for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        printf("%02x", invoice_data.pubkey[lp]);
    }
    printf("\n");
    printf("payment_hash=");
    for (int lp = 0; lp < UCOIN_SZ_SHA256; lp++) {
        printf("%02x", invoice_data.payment_hash[lp]);
    }
    printf("\n");
    printf("---------------------------------\n");
    if (amount_msat != NULL) {
        errno = 0;
        uint64_t add_msat = (uint64_t)strtoull(amount_msat, NULL, 10);
        if (errno == 0) {
            invoice_data.amount_msat += add_msat;
            printf("additional amount_msat=%" PRIu64 "\n", add_msat);
            printf("---------------------------------\n");
        } else {
            printf("fail: errno=%s\n", strerror(errno));
            *pOption = M_OPTIONS_ERR;
        }
        if (invoice_data.amount_msat & 0xffffffff00000000ULL) {
            //BOLT#2
            //  MUST set the four most significant bytes of amount_msat to 0.
            printf("fail: amount_msat too large\n");
            *pOption = M_OPTIONS_ERR;
        }
    }
    if (cltv_offset != NULL) {
        errno = 0;
        uint32_t add_cltv = (uint32_t)strtoull(cltv_offset, NULL, 10);
        if (errno == 0) {
            invoice_data.min_final_cltv_expiry += add_cltv;
            printf("additional min_final_cltv_expiry=%" PRIu32 "\n", add_cltv);
            printf("---------------------------------\n");
        } else {
            printf("fail: errno=%s\n", strerror(errno));
            *pOption = M_OPTIONS_ERR;
        }
    }
    if (*pOption != M_OPTIONS_ERR) {
        if (invoice_data.amount_msat > 0) {
            char payhash[LN_SZ_HASH * 2 + 1];
            char payee[UCOIN_SZ_PUBKEY * 2 + 1];

            misc_bin2str(payhash, invoice_data.payment_hash, LN_SZ_HASH);
            misc_bin2str(payee, invoice_data.pubkey, UCOIN_SZ_PUBKEY);

            snprintf(mBuf, BUFFER_SIZE,
                "{"
                    M_STR("method", "routepay") M_NEXT
                    M_QQ("params") ":[ "
                        //payment_hash, amount_msat, payee, payer
                        M_QQ("%s") ",%" PRIu64 "," M_QQ("%s") "," M_QQ("") ",%" PRIu32 "]}",
                    payhash, invoice_data.amount_msat, payee, invoice_data.min_final_cltv_expiry);

            *pOption = M_OPTIONS_EXEC;
        } else {
            printf("fail: pay amount_msat is 0\n");
            *pOption = M_OPTIONS_ERR;
        }
    }
}


static void optfunc_close(int *pOption, bool *pConn)
{
    M_CHK_CONN

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "close") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort);

    *pConn = false;
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_getlasterr(int *pOption, bool *pConn)
{
    M_CHK_CONN

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "getlasterror") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort);

    *pConn = false;
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_debug(int *pOption, bool *pConn)
{
    (void)pConn;

    int debug = (int)strtol(optarg, NULL, 10);
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "debug") M_NEXT
            M_QQ("params") ":[ %d ]"
        "}", debug);

    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_getcommittx(int *pOption, bool *pConn)
{
    M_CHK_CONN

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "getcommittx") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort);

    *pConn = false;
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_disable_autoconn(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    if ((strlen(optarg) == 1) && ((optarg[0] == '1') || (optarg[0] == '0'))) {
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "disautoconn") M_NEXT
                M_QQ("params") ":[ \"%s\" ]"
            "}", optarg);

        *pOption = M_OPTIONS_EXEC;
    } else {
        printf("fail: invalid option\n");
        *pOption = M_OPTIONS_HELP;
    }
}


static void optfunc_remove_channel(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    if (strlen(optarg) != LN_SZ_CHANNEL_ID * 2) {
        printf("fail: invalid option: %s\n", optarg);
        *pOption = M_OPTIONS_HELP;
        return;
    }

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "removechannel") M_NEXT
            M_QQ("params") ":[ "
                M_QQ("%s")
            " ]"
        "}",
            optarg);

    *pOption = M_OPTIONS_EXEC;
}


static void connect_rpc(void)
{
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "connect") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort);
}


static void stop_rpc(void)
{
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "stop") M_NEXT
            M_QQ("params") ":[]"
        "}");
}


static int msg_send(char *pRecv, const char *pSend, const char *pAddr, uint16_t Port, bool bSend)
{
    int retval = -1;

    if (bSend) {
        struct sockaddr_in sv_addr;

        //fprintf(stderr, "%s\n", pSend);
        int sock = socket(PF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return retval;
        }
        memset(&sv_addr, 0, sizeof(sv_addr));
        sv_addr.sin_family = AF_INET;
        if (strlen(pAddr) == 0) {
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
        fprintf(stdout, "sendto: %s:%" PRIu16 "\n", (strlen(pAddr) != 0) ? pAddr : "localhost", Port);
        fprintf(stdout, "%s\n", pSend);
        retval = 0;
    }

    return retval;
}
