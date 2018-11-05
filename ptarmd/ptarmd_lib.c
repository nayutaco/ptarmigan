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
/** @file   ptarmd_lib.c
 *  @brief  ptarmd entry point for library
 */
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "btcrpc.h"
#include "conf.h"
#include "ln_db.h"
#include "utl_log.h"
#include "utl_addr.h"


/**************************************************************************
 * macros
 **************************************************************************/


/********************************************************************
 * prototypes
 ********************************************************************/

static void sig_set_catch_sigs(sigset_t *pSigSet);
static void *sig_handler_start(void *pArg);


/********************************************************************
 * entry point
 ********************************************************************/

int ptarm_start(const char *pAlias, const char *pIpAddr, uint16_t Port)
{
    bool bret;
    ln_nodeaddr_t *p_addr = ln_node_addr();
    char *p_alias = ln_node_alias();

    //`d` option is used to change working directory.
    // It is done at the beginning of this process.
    mkdir("node", 0755);
    chdir("node");

    utl_log_init();

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

    p_addr->type = LN_NODEDESC_NONE;
    p_addr->port = Port;

    //node name(alias)
    strncpy(p_alias, pAlias, LN_SZ_ALIAS);
    p_alias[LN_SZ_ALIAS] = '\0';

    //ip address
    uint8_t ipbin[4];
    bool addrret = utl_addr_ipv4_str2bin(ipbin, pIpAddr);
    if (addrret) {
        p_addr->type = LN_NODEDESC_IPV4;
        memcpy(p_addr->addrinfo.addr, ipbin, sizeof(ipbin));
    }

    // if (options & 0x40) {
    //     bret = ln_db_annonod_drop_startup();
    //     fprintf(stderr, "db_annonod_drop: %d\n", bret);
    //     return 0;
    // }

    // if (options & 0x80) {
    //     bret = ln_db_reset();
    //     fprintf(stderr, "db_reset: %d\n", bret);
    //     return 0;
    // }

    //O'REILLY Japan: BINARY HACKS #52
    sigset_t ss;
    pthread_t th_sig;
    sig_set_catch_sigs(&ss);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    signal(SIGPIPE , SIG_IGN);   //ignore SIGPIPE
    pthread_create(&th_sig, NULL, &sig_handler_start, NULL);

    //bitcoind起動確認
    uint8_t genesis[LN_SZ_HASH];
    rpc_conf_t rpc_conf;
    conf_btcrpc_init(&rpc_conf);
    bret = conf_btcrpc_load_default(&rpc_conf);
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

    // https://github.com/lightningnetwork/lightning-rfc/issues/237
    for (int lp = 0; lp < LN_SZ_HASH / 2; lp++) {
        uint8_t tmp = genesis[lp];
        genesis[lp] = genesis[LN_SZ_HASH - lp - 1];
        genesis[LN_SZ_HASH - lp - 1] = tmp;
    }
    ln_genesishash_set(genesis);

#if NETKIND==0
    LOGD("start bitcoin mainnet\n");
#elif NETKIND==1
    LOGD("start bitcoin testnet/regtest\n");
#endif

    ptarmd_start(0);

    return 0;
}


/********************************************************************
 * private functions
 ********************************************************************/

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

    LOGD("[THREAD]signal handler\n");
    pthread_detach(pthread_self());

    sigset_t ss;
    siginfo_t info;
    sig_set_catch_sigs(&ss);
    while (1) {
        if (sigwaitinfo(&ss, &info) > 0) {
            LOGD("!!! SIGNAL DETECT: %d !!!\n", info.si_signo);
            exit(-1);
        }
    }
    return NULL;
}
