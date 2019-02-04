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

#include "ptarmd.h"
#include "conf.h"
#include "btcrpc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#if defined(USE_BITCOIND)
#define M_OPTSTRING     "p:n:a:c:d:xNh"
#elif defined(USE_BITCOINJ)
#define M_OPTSTRING     "p:n:a:mtrd:xNh"
#endif


/********************************************************************
 * prototypes
 ********************************************************************/

static void reset_getopt(void);
static void sig_set_catch_sigs(sigset_t *pSigSet);
static void *sig_handler_start(void *pArg);


/********************************************************************
 * entry point
 ********************************************************************/

int main(int argc, char *argv[])
{
    bool bret;
    rpc_conf_t rpc_conf;
    ln_node_addr_t *p_addr;
    char *p_alias;
    int opt;
    uint16_t my_rpcport = 0;

    const struct option OPTIONS[] = {
        { "rpcport", required_argument, NULL, 'P' },
        { 0, 0, 0, 0 }
    };

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
        default:
            break;
        }
    }
    reset_getopt();

    p_addr = ln_node_addr();
    p_alias = ln_node_alias();

#ifdef ENABLE_PLOG_TO_STDOUT
    utl_log_init_stdout();
#else
    utl_log_init();
#endif

    btc_chain_t chain;
#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    chain = BTC_MAINNET;
#elif NETKIND==1
    chain = BTC_TESTNET;
#endif
    bret = btc_init(chain, true);
    if (!bret) {
        fprintf(stderr, "fail: btc_init()\n");
        return -1;
    }

    conf_btcrpc_init(&rpc_conf);
    p_addr->type = LN_ADDR_DESC_TYPE_NONE;
    p_addr->port = 0;

    while ((opt = getopt_long(argc, argv, M_OPTSTRING, OPTIONS, NULL)) != -1) {
        switch (opt) {
        //case 'd':
        //    //`d` option is used to change working directory.
        //    // It is done at the beginning of this process.
        //    break;
        case 'p':
            //port num
            p_addr->port = (uint16_t)atoi(optarg);
            break;
        case 'n':
            //node name(alias)
            strncpy(p_alias, optarg, LN_SZ_ALIAS_STR);
            p_alias[LN_SZ_ALIAS_STR] = '\0';
            break;
        case 'a':
            //ip address
            {
                uint8_t ipbin[LN_ADDR_DESC_ADDR_LEN_IPV4];
                bool addrret = utl_addr_ipv4_str2bin(ipbin, optarg);
                if (addrret) {
                    p_addr->type = LN_ADDR_DESC_TYPE_IPV4;
                    memcpy(p_addr->addr, ipbin, sizeof(ipbin));
                    LOGD("ipv4=");
                    DUMPD(p_addr->addr, sizeof(p_addr->addr));
                } else {
                    LOGE("fail: ipv4(%s)\n", optarg);
                }
            }
            break;
#if defined(USE_BITCOIND)
        case 'c':
            //load btcconf file
            bret = conf_btcrpc_load(optarg, &rpc_conf);
            if (!bret) {
                goto LABEL_EXIT;
            }
            break;
#elif defined(USE_BITCOINJ)
        case 'm':
            //mainnet
            rpc_conf.gen = BTC_BLOCK_CHAIN_BTCMAIN;
            break;
        case 't':
            //testnet
            rpc_conf.gen = BTC_BLOCK_CHAIN_BTCTEST;
            break;
        case 'r':
            //regtest
            rpc_conf.gen = BTC_BLOCK_CHAIN_BTCREGTEST;
            break;
#endif
        case 'P':
            //my rpcport num
            my_rpcport = (uint16_t)atoi(optarg);
            break;
        case 'N':
            //node_announcementを全削除
            bret = ln_db_reset();
            fprintf(stderr, "db_reset: %d\n", bret);
            return 0;
        case 'h':
            //help
            goto LABEL_EXIT;
        default:
            break;
        }
    }

#if defined(USE_BITCOIND)
    if ((strlen(rpc_conf.rpcuser) == 0) || (strlen(rpc_conf.rpcpasswd) == 0)) {
        //bitcoin.confから読込む
        bret = conf_btcrpc_load_default(&rpc_conf);
        if (!bret || (strlen(rpc_conf.rpcuser) == 0) || (strlen(rpc_conf.rpcpasswd) == 0)) {
            goto LABEL_EXIT;
        }
    }
#elif defined(USE_BITCOINJ)
    if (rpc_conf.gen == BTC_BLOCK_CHAIN_UNKNOWN) {
        fprintf(stderr, "ERROR: you need select network.\n");
        goto LABEL_EXIT;
    }
#endif

    //O'REILLY Japan: BINARY HACKS #52
    sigset_t ss;
    pthread_t th_sig;
    sig_set_catch_sigs(&ss);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    signal(SIGPIPE , SIG_IGN);   //ignore SIGPIPE
    pthread_create(&th_sig, NULL, &sig_handler_start, NULL);

    //bitcoind起動確認
    uint8_t genesis[BTC_SZ_HASH256];
    bret = btcrpc_init(&rpc_conf);
    if (!bret) {
        fprintf(stderr, "fail: initialize btcrpc\n");
        return -1;
    }
    bret = btcrpc_getgenesisblock(genesis);
    if (!bret) {
        fprintf(stderr, "fail: bitcoin getblockhash\n");
        return -1;
    }
    ln_genesishash_set(genesis);

#if NETKIND==0
    LOGD("start bitcoin mainnet\n");
#elif NETKIND==1
    LOGD("start bitcoin testnet/regtest\n");
#endif

    ptarmd_start(my_rpcport);

    return 0;

LABEL_EXIT:
    fprintf(stderr, "[usage]\n");
    fprintf(stderr, "\t%s [-p PORT NUM] [-n ALIAS NAME] [-c BITCOIN.CONF] [-a IPv4 ADDRESS] [-i]\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, "\t\t-h : help\n");
    fprintf(stderr, "\t\t-p PORT : node port(default: 9735)\n");
    fprintf(stderr, "\t\t-n NAME : alias name(default: \"node_xxxxxxxxxxxx\")\n");
#if defined(USE_BITCOIND)
    fprintf(stderr, "\t\t-c CONF_FILE : using bitcoin.conf(default: ~/.bitcoin/bitcoin.conf)\n");
    fprintf(stderr, "\t\t-a IPADDRv4 : announce IPv4 address(default: none)\n");
#elif defined(USE_BITCOINJ)
    //fprintf(stderr, "\t\t-m MAINNET\n");
    fprintf(stderr, "\t\t-t TESTNET\n");
    fprintf(stderr, "\t\t-r REGTEST\n");
#endif
    fprintf(stderr, "\t\t-d DIR_PATH : change working directory\n");
    fprintf(stderr, "\t\t--rpcport PORT : JSON-RPC port(default: node port+1)\n");
    fprintf(stderr, "\t\t-N : erase node_announcement DB(TEST)\n");
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
