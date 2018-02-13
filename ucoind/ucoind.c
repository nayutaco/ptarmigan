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
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/limits.h>
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

static ln_node_t            mNode;
static uint16_t             mNodePort;
static pthread_mutex_t      mMuxPreimage;
static char                 mExecPath[PATH_MAX];


/********************************************************************
 * entry point
 ********************************************************************/

int main(int argc, char *argv[])
{
    bool bret;

#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    ucoin_init(UCOIN_MAINNET, true);
#elif NETKIND==1
    ucoin_init(UCOIN_TESTNET, true);
#endif

    signal(SIGPIPE , SIG_IGN);   //ignore SIGPIPE

    if ((argc == 2) && (strcmp(argv[1], "wif") == 0)) {
        uint8_t priv[UCOIN_SZ_PRIVKEY];
        do {
            ucoin_util_random(priv, UCOIN_SZ_PRIVKEY);
        } while (!ucoin_keys_chkpriv(priv));

        char wif[UCOIN_SZ_WIF_MAX];
        ucoin_keys_priv2wif(wif, priv);
        printf("%s\n", wif);

        uint8_t pub[UCOIN_SZ_PUBKEY];
        ucoin_keys_priv2pub(pub, priv);
        printf(" ");
        for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
            printf("%02x", pub[lp]);
        }
        printf("\n");

        ucoin_term();
        return 0;
    }

    rpc_conf_t rpc_conf;
    node_conf_t node_conf;
    load_node_init(&node_conf, &rpc_conf, ln_node_addr(&mNode));

    if (argc >= 2) {
        bret = load_node_conf(argv[1], &node_conf, &rpc_conf, ln_node_addr(&mNode));
        if (!bret) {
            goto LABEL_EXIT;
        }
    }
    if ((strlen(rpc_conf.rpcuser) == 0) || (strlen(rpc_conf.rpcpasswd) == 0)) {
        //bitcoin.confから読込む
        bret = load_btcrpc_default_conf(&rpc_conf);
        if (!bret) {
            goto LABEL_EXIT;
        }
    }

    if (argc == 3) {
        ucoin_util_keys_t keys;
        ucoin_util_wif2keys(&keys, node_conf.wif);

        if (strcmp(argv[2], "id") == 0) {
            //node_id出力
            ucoin_util_dumpbin(stdout, keys.pub, UCOIN_SZ_PUBKEY, true);
        } else if (strcmp(argv[2], "peer") == 0) {
            //peer config出力
            const ln_nodeaddr_t *p_addr = ln_node_addr(&mNode);
            if (p_addr->type == LN_NODEDESC_IPV4) {
                printf("ipaddr=%d.%d.%d.%d\n",
                            p_addr->addrinfo.ipv4.addr[0],
                            p_addr->addrinfo.ipv4.addr[1],
                            p_addr->addrinfo.ipv4.addr[2],
                            p_addr->addrinfo.ipv4.addr[3]);
            } else {
                printf("ipaddr=127.0.0.1\n");
            }
            printf("port=%d\n", p_addr->port);
            printf("node_id=");
            ucoin_util_dumpbin(stdout, keys.pub, UCOIN_SZ_PUBKEY, true);
        }

        ucoin_term();
        return 0;
    }

    //syslog
    openlog("ucoind", LOG_CONS, LOG_USER);

    //ucoindがあるパスを取る("routepay"用)
    const char *p_delimit = strrchr(argv[0], '/');
    if (p_delimit != NULL) {
        memcpy(mExecPath, argv[0], p_delimit - argv[0] + 1);
        mExecPath[p_delimit - argv[0] + 1] = '\0';
    } else {
        mExecPath[0] = '\0';
    }

    p2p_cli_init();
    btcprc_init(&rpc_conf);

    //bitcoind起動確認
    uint8_t genesis[LN_SZ_HASH];
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
    bret = ln_node_init(&mNode, node_conf.wif, node_conf.name, &node_conf.port, 0);
    if (!bret) {
        DBG_PRINTF("fail: node init\n");
        return -2;
    }
    ln_print_node(&mNode);
    lnapp_init(&mNode);

    pthread_mutex_init(&mMuxPreimage, NULL);

    //接続待ち受け用
    pthread_t th_svr;
    pthread_create(&th_svr, NULL, &p2p_svr_start, &node_conf.port);
    mNodePort = node_conf.port;

    //チャネル監視用
    pthread_t th_poll;
    pthread_create(&th_poll, NULL, &monitor_thread_start, NULL);

#if NETKIND==0
    SYSLOG_INFO("start bitcoin mainnet");
#elif NETKIND==1
    SYSLOG_INFO("start bitcoin testnet");
#endif

    //ucoincli受信用
    cmd_json_start(node_conf.port + 1);

    //待ち合わせ
    pthread_join(th_svr, NULL);
    pthread_join(th_poll, NULL);
    DBG_PRINTF("%s exit\n", argv[0]);

    SYSLOG_INFO("end");

    ln_db_term();

    return 0;

LABEL_EXIT:
    fprintf(PRINTOUT, "[usage]\n");
    fprintf(PRINTOUT, "\t%s wif\tcreate new node_id\n", argv[0]);
    fprintf(PRINTOUT, "\t%s <node.conf>\tstart node\n", argv[0]);
    fprintf(PRINTOUT, "\t%s <node.conf> id\tget node_id\n", argv[0]);
    fprintf(PRINTOUT, "\t%s <node.conf> peer\toutput peer config\n", argv[0]);
    return -1;
}


/********************************************************************
 * public functions
 ********************************************************************/

const uint8_t *ucoind_nodeid(void)
{
    return ln_node_id(&mNode);
}


uint16_t ucoind_nodeport(void)
{
    return mNodePort;
}


const ucoin_util_keys_t *ucoind_nodekeys(void)
{
    return &mNode.keys;
}


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
    if (p_appconf == NULL) {
        DBG_PRINTF("not connected\n");
    }
    return p_appconf;
}


const char *ucoind_get_exec_path(void)
{
    return mExecPath;
}
