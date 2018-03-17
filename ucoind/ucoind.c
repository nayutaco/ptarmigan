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
/** @file   ucoind.c
 *  @brief  ucoin daemon
 *  @note   <pre>
 *                +------------------+
 * main---------->| main thread      |
 *                |                  |
 *                +----+----------+--+
 *               create|          | create
 *                     v          v
 *      +-------------------+   +----------------+
 *      | p2p server thread |   | monitor thread |
 *      |                   |   |                |
 *      +-------------------+   +----------------+
 * </pre>
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/limits.h>
#include <getopt.h>
#include <assert.h>

#include "btcrpc.h"
#include "conf.h"
#include "misc.h"
#include "ln_db.h"

#include "ucoind.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "monitoring.h"
#include "cmd_json.h"


/********************************************************************
 * static variables
 ********************************************************************/

static pthread_mutex_t      mMuxPreimage;
static char                 mExecPath[PATH_MAX];


/********************************************************************
 * entry point
 ********************************************************************/

int main(int argc, char *argv[])
{
    bool bret;
    rpc_conf_t rpc_conf;
    ln_nodeaddr_t *p_addr = ln_node_addr();
    char *p_alias = ln_node_alias();

    memset(&rpc_conf, 0, sizeof(rpc_conf_t));
#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    ucoin_init(UCOIN_MAINNET, true);
    rpc_conf.rpcport = 8332;
#elif NETKIND==1
    ucoin_init(UCOIN_TESTNET, true);
    rpc_conf.rpcport = 18332;
#endif
    strcpy(rpc_conf.rpcurl, "127.0.0.1");

    p_addr->type = LN_NODEDESC_NONE;
    p_addr->port = 9735;

    int opt;
    int options = 0;
    while ((opt = getopt(argc, argv, "p:n:a:c:ih")) != -1) {
        switch (opt) {
        case 'p':
            //port num
            p_addr->port = (uint16_t)atoi(optarg);
            break;
        case 'n':
            //node name(alias)
            strncpy(p_alias, optarg, LN_SZ_ALIAS - 1);
            break;
        case 'a':
            //ip address
            p_addr->type = LN_NODEDESC_IPV4;
            uint8_t *p = p_addr->addrinfo.addr;
            sscanf(optarg, "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8,
                    &p[0], &p[1], &p[2], &p[3]);
            break;
        case 'c':
            //load btcconf file
            bret = load_btcrpc_conf(optarg, &rpc_conf);
            if (!bret) {
                goto LABEL_EXIT;
            }
            break;
        case 'i':
            //show node_id
            options |= 0x01;
            break;
        case 'h':
            //help
            goto LABEL_EXIT;
        default:
            break;
        }
    }

    if ((strlen(rpc_conf.rpcuser) == 0) || (strlen(rpc_conf.rpcpasswd) == 0)) {
        //bitcoin.confから読込む
        bret = load_btcrpc_default_conf(&rpc_conf);
        if (!bret) {
            goto LABEL_EXIT;
        }
    }

    //ucoindがあるパスを取る("routepay"用)
    const char *p_delimit = strrchr(argv[0], '/');
    if (p_delimit != NULL) {
        memcpy(mExecPath, argv[0], p_delimit - argv[0] + 1);
        mExecPath[p_delimit - argv[0] + 1] = '\0';
    } else {
        mExecPath[0] = '\0';
    }

    signal(SIGPIPE , SIG_IGN);   //ignore SIGPIPE
    p2p_cli_init();

    //bitcoind起動確認
    uint8_t genesis[LN_SZ_HASH];
    btcprc_init(&rpc_conf);
    bret = btcprc_getblockhash(genesis, 0);
    if (!bret) {
        DBG_PRINTF("fail: bitcoin getblockhash(check bitcoind)\n");
        return -1;
    }

    // https://github.com/lightningnetwork/lightning-rfc/issues/237
    for (int lp = 0; lp < LN_SZ_HASH / 2; lp++) {
        uint8_t tmp = genesis[lp];
        genesis[lp] = genesis[LN_SZ_HASH - lp - 1];
        genesis[LN_SZ_HASH - lp - 1] = tmp;
    }
    ln_set_genesishash(genesis);

    //node情報読込み
    bret = ln_node_init(0);
    if (!bret) {
        DBG_PRINTF("fail: node init\n");
        return -2;
    }

    if (options == 0x01) {
        //node_id出力
        ucoin_util_dumpbin(stdout, ln_node_getid(), UCOIN_SZ_PUBKEY, true);
        ucoin_term();
        return 0;
    }

    //syslog
    openlog("ucoind", LOG_CONS, LOG_USER);

    //peer config出力
    char fname[256];
    sprintf(fname, FNAME_FMT_NODECONF, p_alias);
    FILE *fp = fopen(fname, "w");
    if (fp) {
        if (p_addr->type == LN_NODEDESC_IPV4) {
            fprintf(fp, "ipaddr=%d.%d.%d.%d\n",
                        p_addr->addrinfo.ipv4.addr[0],
                        p_addr->addrinfo.ipv4.addr[1],
                        p_addr->addrinfo.ipv4.addr[2],
                        p_addr->addrinfo.ipv4.addr[3]);
        } else {
            fprintf(fp, "ipaddr=127.0.0.1\n");
        }
        fprintf(fp, "port=%d\n", p_addr->port);
        fprintf(fp, "node_id=");
        ucoin_util_dumpbin(fp, ln_node_getid(), UCOIN_SZ_PUBKEY, true);
        fclose(fp);
    }

    lnapp_init();

    pthread_mutex_init(&mMuxPreimage, NULL);

    //接続待ち受け用
    pthread_t th_svr;
    pthread_create(&th_svr, NULL, &p2p_svr_start, NULL);

    //チャネル監視用
    pthread_t th_poll;
    pthread_create(&th_poll, NULL, &monitor_thread_start, NULL);

#if NETKIND==0
    SYSLOG_INFO("start bitcoin mainnet");
#elif NETKIND==1
    SYSLOG_INFO("start bitcoin testnet/regtest");
#endif

    //ucoincli受信用
    cmd_json_start(p_addr->port + 1);

    //待ち合わせ
    pthread_join(th_svr, NULL);
    pthread_join(th_poll, NULL);
    DBG_PRINTF("%s exit\n", argv[0]);

    SYSLOG_INFO("end");

    btcprc_term();
    ln_db_term();

    return 0;

LABEL_EXIT:
    fprintf(PRINTOUT, "[usage]\n");
    fprintf(PRINTOUT, "\t%s [-p PORT NUM] [-n ALIAS NAME] [-c BITCOIN.CONF] [-a IPv4 ADDRESS] [-i]\n", argv[0]);
    fprintf(PRINTOUT, "\n");
    fprintf(PRINTOUT, "\t\t-h : help\n");
    fprintf(PRINTOUT, "\t\t-p : node port(default: 9735)\n");
    fprintf(PRINTOUT, "\t\t-n : alias name(default: \"node_xxxxxxxxxxxx\")\n");
    fprintf(PRINTOUT, "\t\t-c : using bitcoin.conf(default: ~/.bitcoin/bitcoin.conf)\n");
    fprintf(PRINTOUT, "\t\t-a : announce IPv4 address(default: none)\n");
    fprintf(PRINTOUT, "\t\t-i : show node_id(not start node)\n");
    return -1;
}


/********************************************************************
 * public functions
 ********************************************************************/

bool ucoind_forward_payment(fwd_proc_add_t *p_add)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", p_add->next_short_channel_id);

    //socketが開いているか検索
    p_appconf = ucoind_search_connected_cnl(p_add->next_short_channel_id);
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_forward_payment(p_appconf, p_add);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


bool ucoind_backward_fulfill(const ln_cb_fulfill_htlc_recv_t *pFulFill)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", pFulFill->prev_short_channel_id);

    //socketが開いているか検索
    p_appconf = ucoind_search_connected_cnl(pFulFill->prev_short_channel_id);
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_backward_fulfill(p_appconf, pFulFill);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


bool ucoind_backward_fail(const ln_cb_fail_htlc_recv_t *pFail)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", pFail->prev_short_channel_id);

    //socketが開いているか検索
    p_appconf = ucoind_search_connected_cnl(pFail->prev_short_channel_id);
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_backward_fail(p_appconf, pFail, false);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


void ucoind_preimage_lock(void)
{
    pthread_mutex_lock(&mMuxPreimage);
}


void ucoind_preimage_unlock(void)
{
    pthread_mutex_unlock(&mMuxPreimage);
}


lnapp_conf_t *ucoind_search_connected_cnl(uint64_t short_channel_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_cli_search_short_channel_id(short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_short_channel_id(short_channel_id);
    }
    return p_appconf;
}


const char *ucoind_get_exec_path(void)
{
    return mExecPath;
}
