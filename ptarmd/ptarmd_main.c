/*
 *  Copyright (C) 2017 Ptarmigan Project
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
/** @file   ptarmd_main.c
 *  @brief  ptarmd entry point
 */
#include <stdio.h>
#include <pthread.h>
#include <getopt.h>
#include <signal.h>

#define LOG_TAG     "ptarmd_main"
#include "utl_log.h"
#include "utl_addr.h"
#include "utl_net.h"

#include "ptarmd.h"
#include "conf.h"
#include "btcrpc.h"

//version
#include "../boost/boost/version.hpp"
#include "curl/curlver.h"
#include "mbedtls/version.h"
#include "event.h"
#include "jansson.h"
#include "lmdb.h"
#include "zlib.h"
#include "../version.h"
#include "ln_version.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_OPTSTRING     "p:n:a:c:d:xNhv"

#define M_OPT_CLEARCHANNELDB            '\x10'
#define M_OPT_BITCOINRPCUSER            '\x11'
#define M_OPT_BITCOINRPCPASSWORD        '\x12'
#define M_OPT_BITCOINRPCURL             '\x13'
#define M_OPT_BITCOINRPCPORT            '\x14'
#define M_OPT_ANNOUNCEIP_FORCE          '\x15'


/********************************************************************
 * prototypes
 ********************************************************************/

static void reset_getopt(void);
static void sig_set_catch_sigs(sigset_t *pSigSet);
static void *sig_handler_start(void *pArg);
static void show_version(void);


/********************************************************************
 * entry point
 ********************************************************************/

int main(int argc, char *argv[])
{
    bool bret;
    rpc_conf_t rpc_conf;
    ln_node_t node = LN_NODE_INIT;
    int opt;
    uint16_t my_rpcport = 0;
    bool announceip_force = false;
#if defined(USE_BITCOIND)
    char bitcoinconf[PATH_MAX] = "";
    char bitcoinrpcuser[SZ_RPC_USER + 1] = "";
    char bitcoinrpcpassword[SZ_RPC_PASSWD + 1] = "";
    char bitcoinrpcurl[SZ_RPC_URL + 1] = "";
    uint16_t bitcoinrpcport = 0;
#endif

    const struct option OPTIONS[] = {
        { "network", required_argument, NULL, 'N' },
        { "port", required_argument, NULL, 'p' },
        { "alias", required_argument, NULL, 'n' },
#if defined(USE_BITCOIND)
        { "conf", required_argument, NULL, 'c' },
        { "announceip", required_argument, NULL, 'a' },
        { "announceip_force", no_argument, NULL, M_OPT_ANNOUNCEIP_FORCE },
#endif
        { "datadir", required_argument, NULL, 'd' },
        { "color", required_argument, NULL, 'C' },
        { "rpcport", required_argument, NULL, 'P' },
        { "version", no_argument, NULL, 'v' },
        { "clear_channel_db", no_argument, NULL, M_OPT_CLEARCHANNELDB },
#if defined(USE_BITCOIND)
        { "bitcoinrpcuser", required_argument, NULL, M_OPT_BITCOINRPCUSER },
        { "bitcoinrpcpassword", required_argument, NULL, M_OPT_BITCOINRPCPASSWORD },
        { "bitcoinrpcurl", required_argument, NULL, M_OPT_BITCOINRPCURL },
        { "bitcoinrpcport", required_argument, NULL, M_OPT_BITCOINRPCPORT },
#endif
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 }
    };

    bret = ptarmd_execpath_set();
    if (!bret) {
        fprintf(stderr, "fail: %s\n", ptarmd_execpath_get());
        exit(-1);
    }

    //`d` option is used to change working directory.
    // It is done at the beginning of this process.
    while ((opt = getopt_long(argc, argv, M_OPTSTRING, OPTIONS, NULL)) != -1) {
        switch (opt) {
        case 'd':
            if (chdir(optarg) != 0) {
                fprintf(stderr, "fail: change the working directory\n");
                return -1;
            }
            break;
        case 'p':
            //port num
            node.addr.port = (uint16_t)atoi(optarg);
            break;
#if defined(USE_BITCOIND)
        case M_OPT_ANNOUNCEIP_FORCE:
            announceip_force = true;
            break;
#endif
        case '?':
            //invalid option
            return -1;
        default:
            break;
        }
    }
    reset_getopt();

#ifdef ENABLE_PLOG_TO_STDOUT
    utl_log_init_stdout();
#else
    utl_log_init();
#endif


    conf_btcrpc_init(&rpc_conf);
    btc_block_chain_t chain = BTC_BLOCK_CHAIN_BTCMAIN;

    char prompt[5];
    while ((opt = getopt_long(argc, argv, M_OPTSTRING, OPTIONS, NULL)) != -1) {
        switch (opt) {
        //case 'd':
        //    //`d` option is used to change working directory.
        //    // It is done at the beginning of this process.
        //    break;
        case 'n':
            //node name(alias)
            if (strlen(optarg) > LN_SZ_ALIAS_STR) {
                fprintf(stderr, "fail(-n): alias too long\n");
                return -1;
            }
            strncpy(node.alias, optarg, LN_SZ_ALIAS_STR);
            node.alias[LN_SZ_ALIAS_STR] = '\0';
            break;
        case 'a':
            //ip address
            {
                uint8_t ipbin[LN_ADDR_DESC_ADDR_LEN_IPV4];
                bool addrret = utl_addr_ipv4_str2bin(ipbin, optarg);
                if (!addrret) {
                    LOGD("resolve..\n");
                    char ip_str[SZ_CONN_STR + 1];
                    addrret = utl_net_resolve(ip_str, optarg, node.addr.port);
                    if (addrret) {
                        addrret = utl_addr_ipv4_str2bin(ipbin, ip_str);
                    }
                }
                if (!addrret) {
                    fprintf(stderr, "fail(--announceip): invalid address format\n");
                    return -1;
                }
                node.addr.type = LN_ADDR_DESC_TYPE_IPV4;
                memcpy(node.addr.addr, ipbin, sizeof(ipbin));
                if (announceip_force || utl_net_ipv4_addr_is_routable(node.addr.addr)) {
                    LOGD("announce ipv4=");
                    DUMPD(node.addr.addr, sizeof(node.addr.addr));
                } else {
                    fprintf(stderr, "fail(--announceip): not routable address\n");
                    return -1;
                }
            }
            break;
        case 'c':
#if defined(USE_BITCOIND)
            if (strlen(optarg) > sizeof(bitcoinconf) - 1) {
                fprintf(stderr, "fail: conf file path too long.\n");
                return -1;
            }
            strncpy(bitcoinconf, optarg, sizeof(bitcoinconf) - 1);
            bitcoinconf[sizeof(bitcoinconf) - 1] = '\0';
#endif
            break;
        case 'N':
            //network
            if (strcmp(optarg, "mainnet") == 0) {
                chain = BTC_BLOCK_CHAIN_BTCMAIN;
            } else if (strcmp(optarg, "testnet") == 0) {
                chain = BTC_BLOCK_CHAIN_BTCTEST;
            } else if (strcmp(optarg, "regtest") == 0) {
                chain = BTC_BLOCK_CHAIN_BTCREGTEST;
            } else {
                goto LABEL_EXIT;
            }
            break;
        case 'P':
            //my rpcport num
            my_rpcport = (uint16_t)atoi(optarg);
            break;
        case 'C':
            bret = false;
            if (strlen(optarg) == 6) {
                bret = utl_str_str2bin(node.color, sizeof(node.color), optarg);
            }
            if (!bret) {
                fprintf(stderr, "fail: invalid color(%s).\n", optarg);
                return -1;
            }
            break;
        case 'v':
            show_version();
            exit(0);
        case 'h':
            //help
            goto LABEL_EXIT;
        case M_OPT_CLEARCHANNELDB:
            //clear_channel_db
            printf("!!!!!!!!!!!!!!\n");
            printf("!!! DANGER !!!\n");
            printf("!!!!!!!!!!!!!!\n\n");
            printf("This command delete all channel data from DB.\n");
            printf("Do you execute ? : (YES or no)\n");
            {
                char *ret = fgets(prompt, sizeof(prompt), stdin);
                if ((ret != NULL) && (memcmp(prompt, "YES\n", 4) == 0)) {
                    (void)ln_db_reset();
                } else {
                    printf("canceled.\n");
                }
            }
            return 0;
#if defined(USE_BITCOIND)
        case M_OPT_BITCOINRPCUSER:
            if (strlen(optarg) > sizeof(bitcoinrpcuser) - 1) {
                fprintf(stderr, "fail: RPCUSER too long.\n");
                return -1;
            }
            strncpy(bitcoinrpcuser, optarg, sizeof(bitcoinrpcuser) - 1);
            bitcoinrpcuser[sizeof(bitcoinrpcuser) - 1] = '\0';
            break;
        case M_OPT_BITCOINRPCPASSWORD:
            if (strlen(optarg) > sizeof(bitcoinrpcpassword) - 1) {
                fprintf(stderr, "fail: RPCPASSWORD too long.\n");
                return -1;
            }
            strncpy(bitcoinrpcpassword, optarg, sizeof(bitcoinrpcpassword) - 1);
            bitcoinrpcpassword[sizeof(bitcoinrpcpassword) - 1] = '\0';
            break;
        case M_OPT_BITCOINRPCURL:
            if (strlen(optarg) > sizeof(bitcoinrpcurl) - 1) {
                fprintf(stderr, "fail: RPCURL too long.\n");
                return -1;
            }
            strncpy(bitcoinrpcurl, optarg, sizeof(bitcoinrpcurl) - 1);
            bitcoinrpcurl[sizeof(bitcoinrpcurl) - 1] = '\0';
            break;
        case M_OPT_BITCOINRPCPORT:
            bret = utl_str_scan_u16(&bitcoinrpcport, optarg);
            if (!bret || (bitcoinrpcport == 0)) {
                fprintf(stderr, "fail: invaoid RPCPORT.\n");
                return -1;
            }
            break;
#endif
        default:
            break;
        }
    }

#if defined(USE_BITCOIND)
    //load bitcoin.conf file
    if (strlen(bitcoinconf) > 0) {
        bret = conf_btcrpc_load(bitcoinconf, &rpc_conf, chain);
        if (!bret) {
            goto LABEL_EXIT;
        }
    }
    if ((strlen(rpc_conf.rpcuser) == 0) || (strlen(rpc_conf.rpcpasswd) == 0)) {
        //bitcoin.confから読込む
        bret = conf_btcrpc_load_default(&rpc_conf, chain);
        if (!bret) {
            fprintf(stderr, "fail: wrong conf file.\n");
            goto LABEL_EXIT;
        }
        if (strlen(bitcoinrpcuser) > 0) {
            strncpy(rpc_conf.rpcuser, bitcoinrpcuser, SZ_RPC_USER - 1);
            rpc_conf.rpcuser[SZ_RPC_USER - 1] = '\0';
        }
        if (strlen(bitcoinrpcpassword) > 0) {
            strncpy(rpc_conf.rpcpasswd, bitcoinrpcpassword, SZ_RPC_PASSWD - 1);
            rpc_conf.rpcuser[SZ_RPC_PASSWD - 1] = '\0';
        }
        if (bitcoinrpcport != 0) {
            rpc_conf.rpcport = bitcoinrpcport;
        }
        if ( (strlen(rpc_conf.rpcuser) == 0) ||
             (strlen(rpc_conf.rpcpasswd) == 0) ||
             (rpc_conf.rpcport == 0) ) {
            fprintf(stderr, "fail: RPC configuration.\n");
            goto LABEL_EXIT;
        }
    }
    if (strlen(bitcoinrpcurl) > 0) {
        strncpy(rpc_conf.rpcurl, bitcoinrpcurl, SZ_RPC_URL - 1);
        rpc_conf.rpcurl[SZ_RPC_URL - 1] = '\0';
    }
#endif
    bret = btc_init(chain, true);
    if (!bret) {
        fprintf(stderr, "fail: btc_init()\n");
        return -1;
    }

    //O'REILLY Japan: BINARY HACKS #52
    sigset_t ss;
    pthread_t th_sig;
    sig_set_catch_sigs(&ss);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    signal(SIGPIPE , SIG_IGN);   //ignore SIGPIPE
    pthread_create(&th_sig, NULL, &sig_handler_start, NULL);

    //bitcoind起動確認
    uint8_t genesis[BTC_SZ_HASH256];
    bret = btcrpc_init(&rpc_conf, chain);
    if (!bret) {
        fprintf(stderr, "fail: initialize btcrpc\n");
        return -1;
    }
    bret = btcrpc_getgenesisblock(genesis);
    if (!bret) {
        fprintf(stderr, "fail: bitcoin getblockhash\n");
        return -1;
    }
    btc_block_chain_t gentype = ln_genesishash_set(genesis);
    if (gentype != chain) {
        fprintf(stderr, "ERROR: chain not match. check --network option and your chain\n");
        fprintf(stderr, "\tbitcoin-cli getblockchaininfo | jq -e \'.chain\'\n");
        goto LABEL_EXIT;
    }

    ptarmd_start(my_rpcport, &node, gentype);

    btcrpc_term();

    //already detached
    //pthread_join(th_sig, NULL);

    LOGD("$$$ ptarmd: exit\n");
    utl_log_term(); //stop logging

    return 0;

LABEL_EXIT:
    fprintf(stderr, "[usage]\n");
    fprintf(stderr, "\t%s [OPTION]...\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t\t--help : help\n");
    fprintf(stderr, "\t\t--version : version\n");
    fprintf(stderr, "\t\t--network NETWORK : chain(mainnet/testnet/regtest)(default: mainnet)\n");
    fprintf(stderr, "\t\t--port PORT : node port(default: 9735 or previous saved)\n");
    fprintf(stderr, "\t\t--alias NAME : alias name(default: \"node_xxxxxxxxxxxx\" or previous saved)\n");
#if defined(USE_BITCOIND)
    fprintf(stderr, "\t\t--conf BITCOIN_CONF_FILE : using bitcoin.conf(default: ~/.bitcoin/bitcoin.conf)\n");
    fprintf(stderr, "\t\t--bitcoinuser USER : bitcoin RPC user\n");
    fprintf(stderr, "\t\t--bitcoinpassword PASS : bitcoin RPC password\n");
    fprintf(stderr, "\t\t--bitcoinurl URL : bitcoin RPC URL\n");
    fprintf(stderr, "\t\t--bitcoinport PORT : bitcoin RPC port number\n");
    fprintf(stderr, "\t\t--announceip IPADDRv4 : announce IPv4 address(default: none)\n");
#endif
    fprintf(stderr, "\t\t--datadir DIR_PATH : working directory(default: current)\n");
    fprintf(stderr, "\t\t--color RRGGBB : node color(default: 000000)\n");
    fprintf(stderr, "\t\t--rpcport PORT : JSON-RPC port(default: node port+1)\n");
    return -1;
}


/********************************************************************
 * private functions
 ********************************************************************/

static void reset_getopt(void)
{
    //optreset = 1;
    //optind = 1;

    //ref. http://man7.org/linux/man-pages/man3/getopt.3.html#NOTES
    optind = 0;
}


//捕捉するsignal設定
static void sig_set_catch_sigs(sigset_t *pSigSet)
{
    sigemptyset(pSigSet);
    sigaddset(pSigSet, SIGHUP);
    sigaddset(pSigSet, SIGINT);
    sigaddset(pSigSet, SIGQUIT);
    sigaddset(pSigSet, SIGTERM);
    sigaddset(pSigSet, SIGABRT);
    sigaddset(pSigSet, SIGSEGV);
}


//signal捕捉スレッド
static void *sig_handler_start(void *pArg)
{
    (void)pArg;

    LOGD("signal handler\n");
    pthread_detach(pthread_self());

    sigset_t ss;
    siginfo_t info;
    sig_set_catch_sigs(&ss);
    while (1) {
        if (sigwaitinfo(&ss, &info) > 0) {
            fprintf(stderr, "!!! SIGNAL DETECT: %d !!!\n", info.si_signo);
            LOGD("!!! SIGNAL DETECT: %d !!!\n", info.si_signo);
            exit(-1);
        }
    }
    return NULL;
}


static void show_version(void)
{
    fprintf(stderr, "ptarmigan version: %s\n", PTARM_VERSION);
    fprintf(stderr, "DB version: %d\n", LN_DB_VERSION);

    fprintf(stderr, "library version:\n");
    // from version API/macro
    fprintf(stderr, "\tMbedTLS: %s\n", MBEDTLS_VERSION_STRING_FULL);
    fprintf(stderr, "\tlmdb: %s\n", mdb_version(NULL, NULL, NULL));
    fprintf(stderr, "\tjansson: %s\n", JANSSON_VERSION);
    fprintf(stderr, "\tcurl: %s\n", LIBCURL_VERSION);
    fprintf(stderr, "\tlibev: %s\n", event_get_version());
    fprintf(stderr, "\tzlib: %s\n", ZLIB_VERSION);
    fprintf(stderr, "\tboost: %s\n", BOOST_LIB_VERSION);
    // no version API
    fprintf(stderr, "\tinih: r45\n");
    fprintf(stderr, "\tlibbase58: commit 1cb26b5bfff6b52995a2d88a4b7e1041df589d35\n");
    fprintf(stderr, "\tjsonrpc-c(customized): localonly_r2\n");
}
