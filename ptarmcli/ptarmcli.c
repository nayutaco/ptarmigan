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
#include <libgen.h>

#include <jansson.h>

#define LOG_TAG     "ptarmcli"
#include "utl_log.h"
#include "utl_dbg.h"
#include "utl_str.h"
#include "utl_time.h"
#include "utl_mem.h"

#include "ln_invoice.h"

#include "ptarmd.h"
#include "conf_cli.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_OPTSTRING     "c:hta:l::q::f:i:e:mp:r:R:x::wg::s:X:"

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
#define M_OPT_LISTPAYMENT           '\x0a'
#define M_OPT_REMOVEPAYMENT         '\x0b'
#define M_OPT_DECODEINVOICE         '\x0c'
#define M_OPT_DEBUG                 '\x1f'

#define BUFFER_SIZE     (256 * 1024)

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value

#ifdef USE_BITCOIND
#define M_TMPFUNDCONF       "fundtmp.conf"
#endif

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

static void print_help(void);
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
static void optfunc_listpayment(int *pOption, bool *pConn);
static void optfunc_removepayment(int *pOption, bool *pConn);
static void optfunc_decodeinvoice(int *pOption, bool *pConn);

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
    { M_OPT_LISTPAYMENT,        optfunc_listpayment },
    { M_OPT_REMOVEPAYMENT,      optfunc_removepayment },
    { M_OPT_DECODEINVOICE,      optfunc_decodeinvoice },
    //
    { M_OPT_DEBUG,              optfunc_debug },
};


/********************************************************************
 * public functions
 ********************************************************************/

int main(int argc, char *argv[])
{
    const struct option OPTIONS[] = {
        { "help", no_argument, NULL, 'h' },
        { "stop", no_argument, NULL, 'q' },
        { "getinfo", no_argument, NULL, 'l' },
        { "setfeerate", required_argument, NULL, M_OPT_SETFEERATE },
        { "estimatefundingfee", optional_argument, NULL, M_OPT_ESTIMATEFUNDINGFEE },
        { "getnewaddress", no_argument, NULL, M_OPT_GETNEWADDRESS },
        { "getbalance", no_argument, NULL, M_OPT_GETBALANCE },
        { "paytowallet", optional_argument, NULL, M_OPT_PAYTOWALLET },
        { "emptywallet", required_argument, NULL, M_OPT_EMPTYWALLET },
        { "initroutesync", no_argument, NULL, M_OPT_INITROUTESYNC },
        { "private", no_argument, NULL, M_OPT_PRIVCHANNEL },
        { "sendpayment", required_argument, NULL, 'r' },
        { "listpayment", no_argument, NULL, M_OPT_LISTPAYMENT },
        { "removepayment", required_argument, NULL, M_OPT_REMOVEPAYMENT },
        { "createinvoice", required_argument, NULL, 'i' },
        { "listinvoice", no_argument, NULL, 'm' },
        { "removeinvoice", required_argument, NULL, 'e' },
        { "decodeinvoice", required_argument, NULL, M_OPT_DECODEINVOICE },
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
    while ((opt = getopt_long(argc, argv, M_OPTSTRING, OPTIONS, NULL)) != -1) {
        if (opt == M_OPT_PRIVCHANNEL) {
            optfunc_privchannel(&option, &conn);
            break;
        } else if (opt == '?') {
            print_help();
            return -1;
        }
    }

    //ref. http://man7.org/linux/man-pages/man3/getopt.3.html#NOTES
    optind = 0;

    while ((opt = getopt_long(argc, argv, M_OPTSTRING, OPTIONS, NULL)) != -1) {
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
        print_help();
        return -1;
    }

    //utl_log_init_stdout();
    if (conn) {
        connect_rpc();
    }
    uint16_t port = 0;
    if (optind == argc) {
        if (ln_db_have_db_dir()) {
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


static void print_help(void)
{
    fprintf(stderr, "[usage]\n");
    fprintf(stderr, "\tptarmcli [OPTIONS...] [JSON-RPC port(not ptarmd port)]\n");
    fprintf(stderr, "\t\t--help,-h : help\n");
    fprintf(stderr, "\t\t--stop,-q : quit ptarmd\n");
    fprintf(stderr, "\t\t--getinfo,-l : list channels\n");
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

    fprintf(stderr, "\tINVOICE:\n");
    fprintf(stderr, "\t\t--createinvoice AMOUNT_MSAT : create invoice and add list\n");
    fprintf(stderr, "\t\t--decodeinvoice BOLT11_INVOICE : decode invoice\n");
    fprintf(stderr, "\t\t--listinvoice : list created invoices\n");
    fprintf(stderr, "\t\t--removeinvoice PAYMENT_HASH or ALL : erase payment_hash\n");
    fprintf(stderr, "\tPAYMENT:\n");
    fprintf(stderr, "\t\t--sendpayment BOLT#11_INVOICE[,ADDITIONAL AMOUNT_MSAT] : payment(don't put a space before or after the comma)\n");
    fprintf(stderr, "\t\t--listpayment : list payments\n");
    fprintf(stderr, "\t\t--removepayment PAYMENT_ID : remove a payment from the payment list\n");
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
                    //peer_node_id, peer_addr, peer_port
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
    bool bitcoindconf_fail = bret;
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
            fundconf.push_msat = (uint64_t)strtoul(param, &endp, 10);
            if ((endp != NULL) && (*endp != 0x00)) {
                //変換失敗(push_msatはエラーになっても気にしない)
                //LOGE("fail: *endp = %p(%02x)\n", endp, *endp);
            }
        }
        param = strtok(NULL, ",");
        if ((param != NULL) && (*param != '\0')) {
            fundconf.feerate_per_kw = (uint64_t)strtoul(param, &endp, 10);
            if ((endp != NULL) && (*endp != 0x00)) {
                //変換失敗(feerate_per_kwはエラーになっても気にしない)
                //LOGE("fail: *endp = %p(%02x)\n", endp, *endp);
            }
        }
    }
#ifdef USE_BITCOIND
    if (!bitcoindconf_fail) {
        LOGD("execute script\n");

        ssize_t buff_len;
        char exec_path[PATH_MAX];
        if((buff_len = readlink("/proc/self/exe", exec_path, sizeof(exec_path) - 1)) != -1) {
            exec_path[buff_len] = '\0';
            dirname(exec_path);
        }

        size_t sclen = strlen(exec_path) + 128;
        char *cmdline = (char *)UTL_DBG_MALLOC(sclen);  //UTL_DBG_FREE: この中
        snprintf(cmdline, sclen, "python3 %s/pay_fundin.py %" PRIu64 " %" PRIu64 " " M_TMPFUNDCONF,
                    exec_path,
                    fundconf.funding_sat,
                    fundconf.push_msat);
        fprintf(stderr, "cmdline: %s\n", cmdline);
        system(cmdline);
        UTL_DBG_FREE(cmdline);      //UTL_DBG_MALLOC: この中
        bret = conf_funding_load(M_TMPFUNDCONF, &fundconf);
        unlink(M_TMPFUNDCONF);
    }
#endif
    if (bret) {
        char txid[BTC_SZ_TXID * 2 + 1];

        utl_str_bin2str_rev(txid, fundconf.txid, BTC_SZ_TXID);
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "fund") M_NEXT
                M_QQ("params") ":[ "
                    //peer_node_id, peer_addr, peer_port
                    M_QQ("%s") "," M_QQ("%s") ",%d,"
                    //txid, txindex, funding_sat, push_msat, feerate_per_kw
                    M_QQ("%s") ",%d,%" PRIu64 ",%" PRIu64 ",%" PRIu32
                    //is_private
                    ",%d"
                " ]"
            "}",
                mPeerNodeId, mPeerAddr, mPeerPort,
                txid, fundconf.txindex, fundconf.funding_sat, fundconf.push_msat, fundconf.feerate_per_kw,
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


static void optfunc_decodeinvoice(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "decodeinvoice") M_NEXT
            M_QQ("params") ":[ "
                M_QQ("%s")
            " ]"
        "}",
            optarg);

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

    char payment_hash[BTC_SZ_HASH256 * 2 + 1];
    //node_id(33*2),short_channel_id(8*2),amount(21),cltv(5)
    char forward[BTC_SZ_PUBKEY*2 + sizeof(uint64_t)*2 + 21 + 5 + 50];

    utl_str_bin2str(payment_hash, payconf.payment_hash, BTC_SZ_HASH256);
    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "PAY") M_NEXT
            M_QQ("params") ":[ "
                //payment_hash, num_hops
                M_QQ("%s") ",%d, [\n",
            payment_hash, payconf.num_hops);

    for (int lp = 0; lp < payconf.num_hops; lp++) {
        char node_id[BTC_SZ_PUBKEY * 2 + 1];

        utl_str_bin2str(node_id, payconf.hop_datain[lp].pubkey, BTC_SZ_PUBKEY);
        snprintf(forward, sizeof(forward), "[" M_QQ("%s") "," M_QQ("%" PRIx64) ",%" PRIu64 ",%d]",
                node_id,
                payconf.hop_datain[lp].short_channel_id,
                payconf.hop_datain[lp].amt_to_forward,
                payconf.hop_datain[lp].outgoing_cltv_value
        );
        strcat(mBuf, forward);
        if (lp != payconf.num_hops - 1) {
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
                //peer_node_id, peer_addr, peer_port
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
                //peer_node_id, peer_addr, peer_port
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
                //peer_node_id, peer_addr, peer_port
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
    (void)pOption; (void)pConn;
    mPrivChannel = 1;
}


static void optfunc_listpayment(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    snprintf(mBuf, BUFFER_SIZE,
        "{"
            M_STR("method", "listpayment") M_NEXT
            M_QQ("params") ":[]"
        "}");
    *pOption = M_OPTIONS_EXEC;
}


static void optfunc_removepayment(int *pOption, bool *pConn)
{
    (void)pConn;

    M_CHK_INIT

    if (!optarg) {
        strcpy(mErrStr, "invalid option");
        *pOption = M_OPTIONS_ERR;
        return;
    }

    errno = 0;
    const char *param = strtok(optarg, ",");
    uint64_t payment_id = (uint64_t)strtoull(param, NULL, 10);
    if (errno == 0) {
        snprintf(mBuf, BUFFER_SIZE,
            "{"
                M_STR("method", "removepayment") M_NEXT
                M_QQ("params") ":[ "
                    "%" PRIu64
                " ]"
            "}",
                payment_id);

        *pOption = M_OPTIONS_EXEC;
    } else {
        sprintf(mErrStr, "%s", strerror(errno));
        *pOption = M_OPTIONS_ERR;
    }
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
                //peer_node_id, peer_addr, peer_port
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
