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
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <jansson.h>

#define LOG_TAG     "ptarmcli"
#include "utl_log.h"
#include "utl_dbg.h"
#include "utl_str.h"
#include "utl_time.h"

#include "ln_invoice.h"

#include "ptarmd.h"
#include "conf_cli.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_OPTIONS_INIT  (0xff)
#define M_OPTIONS_CONN  (0xf0)
#define M_OPTIONS_EXEC  (2)
#define M_OPTIONS_STOP  (1)
#define M_OPTIONS_HELP  (0)
#define M_OPTIONS_ERR   (-1)

#define M_OPT_SETFEERATE            '\x01'
#define M_OPT_ESTIMATEFUNDINGFEE    '\x02'
#define M_OPT_GETNEWADDRESS         '\x03'
#define M_OPT_GETBALANCE            '\x04'
#define M_OPT_EMPTYWALLET           '\x05'
#define M_OPT_INITROUTESYNC         '\x06'
#define M_OPT_PAYTOWALLET           '\x07'
#define M_OPT_NOINITROUTESYNC       '\x08'
#define M_OPT_PRIVCHANNEL           '\x09'
#define M_OPT_DEBUG                 '\x1f'

#define BUFFER_SIZE     (256 * 1024)

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value


#define M_CHK_INIT      {\
    if (*pOption != M_OPTIONS_INIT) {           	\
        fprintf(stderr, "fail: too many options\n");   	\
        *pOption = M_OPTIONS_HELP;              	\
        return;                                 	\
    }                                           	\
}

#define M_CHK_CONN      {\
    if (*pOption != M_OPTIONS_CONN) {           	\
        fprintf(stderr, "fail: need -c option first\n");\
        *pOption = M_OPTIONS_HELP;              	\
        return;                                 	\
    }                                           	\
}


/**************************************************************************
 * static variables
 **************************************************************************/

static char         mPeerAddr[INET6_ADDRSTRLEN];
static uint16_t     mPeerPort;
static char         mPeerNodeId[BTC_SZ_PUBKEY * 2 + 1];
static char         mBuf[BUFFER_SIZE];
static bool         mTcpSend;
static char         mAddr[256];
static char         mErrStr[256];
static uint8_t      mInitRouteSync;
static uint8_t      mPrivChannel;


/********************************************************************
 * prototypes
 ********************************************************************/

static void optfunc_help(int *pOption, bool *pConn);
static void optfunc_test(int *pOption, bool *pConn);
static void optfunc_addr(int *pOption, bool *pConn);
static void optfunc_conn_param(int *pOption, bool *pConn);
static void optfunc_getinfo(int *pOption, bool *pConn);
static void optfunc_disconnect(int *pOption, bool *pConn);
static void optfunc_getnewaddress(int *pOption, bool *pConn);
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
static void optfunc_setfeerate(int *pOption, bool *pConn);
static void optfunc_estimatefundingfee(int *pOption, bool *pConn);
static void optfunc_walletback(int *pOption, bool *pConn);
static void optfunc_getbalance(int *pOption, bool *pConn);
static void optfunc_emptywallet(int *pOption, bool *pConn);
static void optfunc_initroutesync(int *pOption, bool *pConn);
static void optfunc_noinitroutesync(int *pOption, bool *pConn);
static void optfunc_privchannel(int *pOption, bool *pConn);

static void connect_rpc(void);
static void stop_rpc(void);
static void routepay(int *pOption);

static int msg_send(char *pRecv, const char *pSend, const char *pAddr, uint16_t Port, bool bSend);


static const struct {
    char        opt;
    void        (*func)(int *pOption, bool *pConn);
} OPTION_FUNCS[] = {
    { 'h', optfunc_help },
    { 't', optfunc_test },
    { 'a', optfunc_addr },

    { 'c', optfunc_conn_param },
    { 'l', optfunc_getinfo },
    { 'q', optfunc_disconnect },
    { 'f', optfunc_funding },
    { 'i', optfunc_invoice },
    { 'e', optfunc_erase },
    { 'm', optfunc_listinvoice },
    { 'p', optfunc_payment },
    { 'r', optfunc_routepay },
    { 'x', optfunc_close },
    { 'w', optfunc_getlasterr },
    { 'g', optfunc_getcommittx },
    { 's', optfunc_disable_autoconn },
    { 'X', optfunc_remove_channel },

    //long opt
    { M_OPT_SETFEERATE,         optfunc_setfeerate },
    { M_OPT_ESTIMATEFUNDINGFEE, optfunc_estimatefundingfee },
    { M_OPT_GETNEWADDRESS,      optfunc_getnewaddress },
    { M_OPT_GETBALANCE,         optfunc_getbalance },
    { M_OPT_EMPTYWALLET,        optfunc_emptywallet },
    { M_OPT_INITROUTESYNC,      optfunc_initroutesync },
    { M_OPT_PAYTOWALLET,        optfunc_walletback },
    { M_OPT_NOINITROUTESYNC,    optfunc_noinitroutesync },
    { M_OPT_PRIVCHANNEL,        optfunc_privchannel },
    //
    { M_OPT_DEBUG,              optfunc_debug },
};


/********************************************************************
 * public functions
 ********************************************************************/

int main(int argc, char *argv[])
{
    const struct option OPTIONS[] = {
        { "setfeerate", required_argument, NULL, M_OPT_SETFEERATE },
        { "estimatefundingfee", optional_argument, NULL, M_OPT_ESTIMATEFUNDINGFEE },
        { "getnewaddress", no_argument, NULL, M_OPT_GETNEWADDRESS },
        { "getbalance", no_argument, NULL, M_OPT_GETBALANCE },
        { "paytowallet", optional_argument, NULL, M_OPT_PAYTOWALLET },
        { "emptywallet", required_argument, NULL, M_OPT_EMPTYWALLET },
        { "initroutesync", no_argument, NULL, M_OPT_INITROUTESYNC },
        { "private", no_argument, NULL, M_OPT_PRIVCHANNEL },
        { "debug", required_argument, NULL, M_OPT_DEBUG },
        { 0, 0, 0, 0 }
    };

    int option = M_OPTIONS_INIT;
    bool conn = false;
    mAddr[0] = '\0';
    mTcpSend = true;
    mInitRouteSync = PTARMD_ROUTESYNC_DEFAULT;
    mPrivChannel = 0;
    int opt;
    while ((opt = getopt_long(argc, argv, "c:hta:l::q::f:i:e:mp:r:R:x::wg::s:X:", OPTIONS, NULL)) != -1) {
        for (size_t lp = 0; lp < ARRAY_SIZE(OPTION_FUNCS); lp++) {
            if (opt == OPTION_FUNCS[lp].opt) {
                (*OPTION_FUNCS[lp].func)(&option, &conn);
                break;
            }
        }
    }

    if (option == M_OPTIONS_ERR) {
        fprintf(stderr, "{ " M_QQ("error") ": {" M_QQ("code") ": -1," M_QQ("message") ":" M_QQ("%s") "} }\n", mErrStr);
        return -1;
    }
    if ((option == M_OPTIONS_INIT) || (option == M_OPTIONS_HELP) || (!conn && (option == M_OPTIONS_CONN))) {
        fprintf(stderr, "[usage]\n");
        fprintf(stderr, "\t%s [-t] [OPTIONS...] [JSON-RPC port(not ptarmd port)]\n", argv[0]);
        fprintf(stderr, "\t\t-h : help\n");
        fprintf(stderr, "\t\t-t : test(not send command)\n");
        fprintf(stderr, "\t\t-q : quit ptarmd\n");
        fprintf(stderr, "\t\t-l : list channels\n");
        fprintf(stderr, "\t\t--estimatefundingfee[=FEERATE_PER_KW]: estimate fee amount to funding\n");
        fprintf(stderr, "\n");

        fprintf(stderr, "\tCONNECT:\n");
        fprintf(stderr, "\t\t-c PEER_NODE_ID@IPADDR:PORT [--initroutesync]: connect node\n");
#if defined(USE_BITCOIND)
        fprintf(stderr, "\t\t-c PEER NODE_ID -f FUND.CONF [--private]: funding\n");
#elif defined(USE_BITCOINJ)
        fprintf(stderr, "\t\t-c PEER NODE_ID -f AMOUNT_SATOSHIS [--private]: funding\n");
#endif
        fprintf(stderr, "\t\t-c PEER NODE_ID -x : mutual close channel\n");
        fprintf(stderr, "\t\t-c PEER NODE_ID -xforce: unilateral close channel\n");
        fprintf(stderr, "\t\t-c PEER NODE_ID -w : get last error\n");
        fprintf(stderr, "\t\t-c PEER NODE_ID -q : disconnect node\n");
        fprintf(stderr, "\n");

        fprintf(stderr, "\tPAYMENT:\n");
        fprintf(stderr, "\t\t-i AMOUNT_MSAT : add preimage, and show payment_hash\n");
        fprintf(stderr, "\t\t-e PAYMENT_HASH : erase payment_hash\n");
        fprintf(stderr, "\t\t-e ALL : erase all payment_hash\n");
        fprintf(stderr, "\t\t-r BOLT#11_INVOICE[,ADDITIONAL AMOUNT_MSAT] : payment(don't put a space before or after the comma)\n");
        fprintf(stderr, "\t\t-m : show payment_hashs\n");
        fprintf(stderr, "\n");

        fprintf(stderr, "\tWALLET:\n");
#ifdef USE_BITCOINJ
        fprintf(stderr, "\t\t--getnewaddress : get wallet address(for fund-in)\n");
        fprintf(stderr, "\t\t--getbalance : get available Bitcoin balance\n");
        fprintf(stderr, "\t\t--emptywallet BITCOIN_ADDRESS : send all Bitcoin balance\n");
#endif
        fprintf(stderr, "\t\t--paytowallet[=1 or 0] : 1:send from unilateral closed wallet to 1st layer wallet, 0:only show transaction\n");
        fprintf(stderr, "\n");

        fprintf(stderr, "\tDEBUG:\n");
        // fprintf(stderr, "\t\t-a <IP address> : JSON-RPC send address\n");
        fprintf(stderr, "\t\t--debug VALUE : debug option\n");
        fprintf(stderr, "\t\t\tb0 ... no update_fulfill_htlc\n");
        fprintf(stderr, "\t\t\tb1 ... no closing transaction\n");
        fprintf(stderr, "\t\t\tb2 ... force payment_preimage mismatch\n");
        fprintf(stderr, "\t\t\tb3 ... no node auto connect\n");
        fprintf(stderr, "\t\t-c PEER NODE_ID -g : get commitment transaction\n");
        fprintf(stderr, "\t\t-X CHANNEL_ID : delete channel from DB\n");
        fprintf(stderr, "\t\t-s<1 or 0> : 1=stop auto channel connect\n");
        fprintf(stderr, "\t\t--setfeerate FEERATE_PER_KW : set feerate_per_kw\n");
        return -1;
    }

    //utl_log_init_stdout();
    if (conn) {
        connect_rpc();
    }
    uint16_t port = 0;
    if (optind == argc) {
        if (ln_db_have_dbdir()) {
            char wif[BTC_SZ_WIF_STR_MAX + 1] = "";
            char alias[LN_SZ_ALIAS_STR + 1] = "";

            (void)ln_db_init(wif, alias, &port, false);
            if (port != 0) {
                port++;
            }
        }
        if (port == 0) {
            port = 9736;
        }
    } else {
        port = (uint16_t)atoi(argv[optind]);
    }

    int ret = msg_send(mBuf, mBuf, mAddr, port, mTcpSend);

    return ret;
}


/********************************************************************
 * commands
 ********************************************************************/

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


static void optfunc_conn_param(int *pOption, bool *pConn)
{
    if (*pOption != M_OPTIONS_INIT) {
        fprintf(stderr, "fail: '-c' must first\n");
        *pOption = M_OPTIONS_HELP;
        return;
    }

    size_t optlen = strlen(optarg);
    peer_conf_t peer;
    conf_peer_init(&peer);
    bool bret = conf_peer_load(optarg, &peer);
    if (bret) {
        //peer.conf
        *pConn = true;
        strcpy(mPeerAddr, peer.ipaddr);
        mPeerPort = peer.port;
        utl_str_bin2str(mPeerNodeId, peer.node_id, BTC_SZ_PUBKEY);
        *pOption = M_OPTIONS_CONN;
    } else if (optlen >= (BTC_SZ_PUBKEY * 2 + 1 + 7 + 1 + 1)) {
        ln_node_conn_t node_conn;
        bool dec_ret = ln_node_addr_dec(&node_conn, optarg);
        if (dec_ret) {
            utl_str_bin2str(mPeerNodeId, node_conn.node_id, BTC_SZ_PUBKEY);
            strcpy(mPeerAddr, node_conn.addr);
            mPeerPort = node_conn.port;
            *pConn = true;
            *pOption = M_OPTIONS_CONN;
        } else {
            fprintf(stderr, "fail: peer configuration file\n");
            *pOption = M_OPTIONS_HELP;
        }
    } else if (optlen == BTC_SZ_PUBKEY * 2) {
        //node_idだけ指定した可能性あり(connectとしては使用できない)
        strcpy(mPeerAddr, "0.0.0.0");
        mPeerPort = 0;
        strcpy(mPeerNodeId, optarg);
        *pOption = M_OPTIONS_CONN;
    } else {
        fprintf(stderr, "fail: peer configuration file\n");
        *pOption = M_OPTIONS_HELP;
    }
}


static void optfunc_getinfo(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    strncpy(mBuf,
        "{" M_STR("method", "getinfo") M_NEXT M_QQ("params") ":[",
        BUFFER_SIZE);
    if ((optarg != NULL) && (strlen(optarg) > 0)) {
        int level = atoi(optarg);
        if (level != 0) {
            strncat(mBuf, optarg, BUFFER_SIZE);
        }
    }
    strncat(mBuf, "]}", BUFFER_SIZE);

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
        //ptarmd終了
        stop_rpc();
        *pOption = M_OPTIONS_STOP;
    }
}


static void optfunc_getnewaddress(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "getnewaddress") M_NEXT
            M_QQ("params") ":[]"
        "}");
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_funding(int *pOption, bool *pConn)
{
    M_CHK_CONN

    bool bret = false;
    funding_conf_t fundconf;
    conf_funding_init(&fundconf);
#ifdef USE_BITCOIND
    bret = conf_funding_load(optarg, &fundconf);
#endif
    if (!bret) {
        //SPVの場合、funding_satoshisだけの指定でも受け付けられる
        const char *param = strtok(optarg, ",");
        char *endp = NULL;
        fundconf.funding_sat = (uint64_t)strtoul(param, &endp, 10);
        if ((endp != NULL) && (*endp != 0x00)) {
            //変換失敗
            LOGE("fail: *endp = %p(%02x)\n", endp, *endp);
        } else {
            bret = true;
        }
        param = strtok(NULL, ",");
        if ((param != NULL) && (*param != '\0')) {
            fundconf.push_sat = (uint64_t)strtoul(param, &endp, 10);
            if ((endp != NULL) && (*endp != 0x00)) {
                //変換失敗(push_msatはエラーになっても気にしない)
                LOGE("fail: *endp = %p(%02x)\n", endp, *endp);
            }
        }
    }
    if (bret) {
        char txid[BTC_SZ_TXID * 2 + 1];

        utl_str_bin2str_rev(txid, fundconf.txid, BTC_SZ_TXID);
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "fund") M_NEXT
                M_QQ("params") ":[ "
                    //peer_nodeid, peer_addr, peer_port
                    M_QQ("%s") "," M_QQ("%s") ",%d,"
                    //txid, txindex, funding_sat, push_sat, feerate_per_kw
                    M_QQ("%s") ",%d,%" PRIu64 ",%" PRIu64 ",%" PRIu32
                    ",%d"
                " ]"
            "}",
                mPeerNodeId, mPeerAddr, mPeerPort,
                txid, fundconf.txindex, fundconf.funding_sat, fundconf.push_sat, fundconf.feerate_per_kw,
                mPrivChannel);

        *pConn = false;
        *pOption = M_OPTIONS_EXEC;
    } else {
        fprintf(stderr, "fail: funding configuration file\n");
        *pOption = M_OPTIONS_HELP;
    }
}


static void optfunc_invoice(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    errno = 0;
    const char *param = strtok(optarg, ",");
    uint64_t amount = (uint64_t)strtoull(param, NULL, 10);
    uint32_t min_final_cltv_expiry = 0;
    if (errno == 0) {
        param = strtok(NULL, ",");
        if ((param != NULL) && (*param != '\0')) {
            min_final_cltv_expiry = (uint32_t)strtoul(param, NULL, 10);
        }
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "invoice") M_NEXT
                M_QQ("params") ":[ "
                    //invoice
                    "%" PRIu64 ",%" PRIu32
                " ]"
            "}",
                amount, min_final_cltv_expiry);

        *pOption = M_OPTIONS_EXEC;
    } else {
        sprintf(mErrStr, "%s", strerror(errno));
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
    } else if (strlen(optarg) == BTC_SZ_HASH256 * 2) {
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
        strcpy(mErrStr, "invalid param");
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
    conf_payment_init(&payconf);
    bool bret = conf_payment_load(path, &payconf);
    if (hash) {
        bret &= utl_str_str2bin(payconf.payment_hash, BTC_SZ_HASH256, hash);
    }
    if (!bret) {
        strcpy(mErrStr, "payment configuration file");
        *pOption = M_OPTIONS_ERR;
        return;
    }

    char payhash[BTC_SZ_HASH256 * 2 + 1];
    //node_id(33*2),short_channel_id(8*2),amount(21),cltv(5)
    char forward[BTC_SZ_PUBKEY*2 + sizeof(uint64_t)*2 + 21 + 5 + 50];

    utl_str_bin2str(payhash, payconf.payment_hash, BTC_SZ_HASH256);
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "PAY") M_NEXT
            M_QQ("params") ":[ "
                //payment_hash, hop_num
                M_QQ("%s") ",%d, [\n",
            payhash, payconf.hop_num);

    for (int lp = 0; lp < payconf.hop_num; lp++) {
        char node_id[BTC_SZ_PUBKEY * 2 + 1];

        utl_str_bin2str(node_id, payconf.hop_datain[lp].pubkey, BTC_SZ_PUBKEY);
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


/* BOLT#11 invoiceによる支払い
 */
static void optfunc_routepay(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    routepay(pOption);
}


static void optfunc_close(int *pOption, bool *pConn)
{
    M_CHK_CONN

    if (optarg != NULL) {
        if (strcmp(optarg, "force") != 0) {
            strcpy(mErrStr, "invalid option");
            *pOption = M_OPTIONS_ERR;
            return;
        }
    }

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "close") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d%s"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort, (optarg == NULL) ? "" : ",\"force\"");

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

    int val = 0;
    if (optarg != NULL) {
        val = (int)strtol(optarg, NULL, 10);
    }
    const char *p_opt;
    if (val == 0) {
        p_opt = "";
    } else {
        p_opt = ",1";
    }

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "getcommittx") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d%s"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort, p_opt);

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
        fprintf(stderr, "fail: invalid option\n");
        *pOption = M_OPTIONS_HELP;
    }
}


static void optfunc_remove_channel(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    if (strlen(optarg) != LN_SZ_CHANNEL_ID * 2) {
        fprintf(stderr, "fail: invalid option: %s\n", optarg);
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


static void optfunc_setfeerate(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    errno = 0;
    uint64_t feerate_per_kw = strtoull(optarg, NULL, 10);
    if (feerate_per_kw > UINT32_MAX) {
        strcpy(mErrStr, "feerate_per_kw too high");
        *pOption = M_OPTIONS_ERR;
        return;
    }
    if (errno == 0) {
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "setfeerate") M_NEXT
                M_QQ("params") ":[ "
                    //feerate_per_kw
                    "%" PRIu32
                " ]"
            "}",
                (uint32_t)feerate_per_kw);

        *pOption = M_OPTIONS_EXEC;
    } else {
        sprintf(mErrStr, "%s", strerror(errno));
        *pOption = M_OPTIONS_ERR;
    }
}


static void optfunc_estimatefundingfee(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    errno = 0;
    uint64_t feerate_per_kw = 0;
    if ((optarg != NULL) && (optarg[0] != '\0')) {
        feerate_per_kw = strtoull(optarg, NULL, 10);
        if (feerate_per_kw > UINT32_MAX) {
            strcpy(mErrStr, "feerate_per_kw too high");
            *pOption = M_OPTIONS_ERR;
            return;
        }
        if (errno != 0) {
            sprintf(mErrStr, "%s", strerror(errno));
            *pOption = M_OPTIONS_ERR;
            return;
        }
    }
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "estimatefundingfee") M_NEXT
            M_QQ("params") ":[ "
                //feerate_per_kw
                "%" PRIu32
            " ]"
        "}",
            (uint32_t)feerate_per_kw);

    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_walletback(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    uint32_t to_send = 0;
    uint32_t feerate_per_kw = 0;
    if (optarg != NULL) {
        const char *p = strtok(optarg, ",");
        (void)utl_str_scan_u32(&to_send, p);
        p = strtok(NULL, ",");
        if (p != NULL) {
            (void)utl_str_scan_u32(&feerate_per_kw, p);
        }
    }
    if ((feerate_per_kw != 0) && (feerate_per_kw < LN_FEERATE_PER_KW_MIN)) {
        strcpy(mErrStr, "feerate_per_kw too low");
        *pOption = M_OPTIONS_ERR;
        return;
    }

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "walletback") M_NEXT
            M_QQ("params") ":[ %" PRIu32 ", %" PRIu32 " ]"
        "}", to_send, feerate_per_kw);

    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_getbalance(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "getbalance") M_NEXT
            M_QQ("params") ":[]"
        "}");
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_emptywallet(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "emptywallet") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") "]"
        "}", optarg);
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_initroutesync(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_CONN

    mInitRouteSync = PTARMD_ROUTESYNC_INIT;
}


static void optfunc_noinitroutesync(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_CONN

    mInitRouteSync = PTARMD_ROUTESYNC_NONE;
}


static void optfunc_privchannel(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_CONN

    mPrivChannel = 1;
}


/********************************************************************
 * others
 ********************************************************************/

static void connect_rpc(void)
{
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "connect") M_NEXT
            M_QQ("params") ":[ "
                //peer_nodeid, peer_addr, peer_port
                M_QQ("%s") "," M_QQ("%s") ",%d,%d"
            " ]"
        "}",
            mPeerNodeId, mPeerAddr, mPeerPort, mInitRouteSync);
}


static void stop_rpc(void)
{
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "stop") M_NEXT
            M_QQ("params") ":[]"
        "}");
}


/**
 *  @param[out]     pOption
 */
static void routepay(int *pOption)
{
    const char *invoice = strtok(optarg, ",");
    const char *add_amount_str = strtok(NULL, ",");


/////////////////////

    //確認用のログ出力
    ln_invoice_t *p_invoice_data = NULL;
    bool bret = ln_invoice_decode(&p_invoice_data, invoice);
    if (!bret) {
        sprintf(mErrStr, "fail decode invoice");
        *pOption = M_OPTIONS_ERR;
        return;
    }

    printf("---------------------------------\n");
    switch (p_invoice_data->hrp_type) {
    case LN_INVOICE_MAINNET:
        printf("blockchain: bitcoin mainnet\n");
        break;
    case LN_INVOICE_TESTNET:
        printf("blockchain: bitcoin testnet\n");
        break;
    case LN_INVOICE_REGTEST:
        printf("blockchain: bitcoin regtest\n");
        break;
    default:
        printf("unknown hrp_type\n");
    }
    printf("amount_msat=%" PRIu64 "\n", p_invoice_data->amount_msat);
    time_t tm = (time_t)p_invoice_data->timestamp;
    char time[UTL_SZ_TIME_FMT_STR + 1];
    printf("timestamp= %" PRIu64 " : %s\n", (uint64_t)p_invoice_data->timestamp, utl_time_fmt(time, tm));
    printf("min_final_cltv_expiry=%u\n", p_invoice_data->min_final_cltv_expiry);
    printf("payee=");
    for (int lp = 0; lp < BTC_SZ_PUBKEY; lp++) {
        printf("%02x", p_invoice_data->pubkey[lp]);
    }
    printf("\n");
    printf("payment_hash=");
    for (int lp = 0; lp < BTC_SZ_HASH256; lp++) {
        printf("%02x", p_invoice_data->payment_hash[lp]);
    }
    printf("\n");
    if (p_invoice_data->r_field_num > 0) {
        for (int lp = 0; lp < p_invoice_data->r_field_num; lp++) {
            printf("    ------------------------\n");
            printf("    ");
            for (int lp2 = 0; lp2 < BTC_SZ_PUBKEY; lp2++) {
                printf("%02x", p_invoice_data->r_field[lp].node_id[lp2]);
            }
            printf("\n");
            printf("    short_channel_id=%016" PRIx64 "\n", p_invoice_data->r_field[lp].short_channel_id);
            printf("    fee_base_msat=%" PRIu32 "\n", p_invoice_data->r_field[lp].fee_base_msat);
            printf("    fee_proportional_millionths=%" PRIu32 "\n", p_invoice_data->r_field[lp].fee_prop_millionths);
            printf("    cltv_expiry_delta=%" PRIu16 "\n", p_invoice_data->r_field[lp].cltv_expiry_delta);
        }
        printf("    ------------------------\n");
    }
    printf("---------------------------------\n");

////////////////////

    uint64_t add_amount_msat = 0;
    if (add_amount_str != NULL) {
        //additional amount_msat
        //  invoiceで要求されたamountに追加で支払えるようにしている
        errno = 0;
        add_amount_msat = (uint64_t)strtoull(add_amount_str, NULL, 10);
        if (errno != 0) {
            sprintf(mErrStr, "%s", strerror(errno));
            *pOption = M_OPTIONS_ERR;
        }
    }

    if (*pOption != M_OPTIONS_ERR) {
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "routepay") M_NEXT
                M_QQ("params") ":[ "
                    //bolt11, add_amount_msat
                    M_QQ("%s") ",%" PRIu64 "]}",
                invoice, add_amount_msat);

        *pOption = M_OPTIONS_EXEC;
    }
}


static int msg_send(char *pRecv, const char *pSend, const char *pAddr, uint16_t Port, bool bSend)
{
    int retval = -1;

    if (bSend) {
        struct sockaddr_in sv_addr;

        //fprintf(stderr, "%s\n", pSend);
        int sock = socket(PF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            fprintf(stderr, "fail socket: %s\n", strerror(errno));
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
            fprintf(stderr, "fail connect: %s\n", strerror(errno));
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
        } else if (len < 0) {
            fprintf(stderr, "fail read: %s\n", strerror(errno));
        }
        close(sock);
    } else {
        printf("sendto: %s:%" PRIu16 "\n", (strlen(pAddr) != 0) ? pAddr : "localhost", Port);
        printf("%s\n", pSend);
        retval = 0;
    }

    return retval;
}
