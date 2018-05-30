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
#include "ln_db_lmdb.h"

#include "ucoind.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "monitoring.h"
#include "cmd_json.h"

/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct     nodefaillist_t
 *  @brief      接続失敗peer情報リスト
 */
typedef struct nodefaillist_t {
    LIST_ENTRY(nodefaillist_t) list;

    uint8_t     node_id[UCOIN_SZ_PUBKEY];
    char        ipaddr[SZ_IPV4_LEN + 1];
    uint16_t    port;
} nodefaillist_t;
LIST_HEAD(nodefaillisthead_t, nodefaillist_t);


/********************************************************************
 * static variables
 ********************************************************************/

static pthread_mutex_t      mMuxPreimage;
// static char                 mExecPath[PATH_MAX];
static struct nodefaillisthead_t    mNodeFailListHead;


/********************************************************************
 * entry point
 ********************************************************************/

int main(int argc, char *argv[])
{
    bool bret;
    rpc_conf_t rpc_conf;
    ln_nodeaddr_t *p_addr = ln_node_addr();
    char *p_alias = ln_node_alias();

    ucoin_util_log_init();

    memset(&rpc_conf, 0, sizeof(rpc_conf_t));
#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    bret = ucoin_init(UCOIN_MAINNET, true);
    rpc_conf.rpcport = 8332;
#elif NETKIND==1
    bret = ucoin_init(UCOIN_TESTNET, true);
    rpc_conf.rpcport = 18332;
#endif
    strcpy(rpc_conf.rpcurl, "127.0.0.1");
    if (!bret) {
        fprintf(stderr, "fail: ucoin_init()\n");
        return -1;
    }

    p_addr->type = LN_NODEDESC_NONE;
    p_addr->port = 9735;

    int opt;
    int options = 0;
    while ((opt = getopt(argc, argv, "p:n:a:c:d:xh")) != -1) {
        switch (opt) {
        case 'd':
            //db directory
            ln_lmdb_set_path(optarg);
            break;
        case 'p':
            //port num
            p_addr->port = (uint16_t)atoi(optarg);
            break;
        case 'n':
            //node name(alias)
            strncpy(p_alias, optarg, LN_SZ_ALIAS - 1);
            p_alias[LN_SZ_ALIAS] = '\0';
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
        // case 'i':
        //     //show node_id
        //     options |= 0x01;
        //     break;
        case 'x':
            //ノード情報を残してすべて削除
            options |= 0x80;
            break;
        case 'h':
            //help
            goto LABEL_EXIT;
        default:
            break;
        }
    }

    if (options & 0x80) {
        //
        bret = ln_db_reset();
        fprintf(stderr, "db_reset: %d\n", bret);
        return 0;
    }

    if ((strlen(rpc_conf.rpcuser) == 0) || (strlen(rpc_conf.rpcpasswd) == 0)) {
        //bitcoin.confから読込む
        bret = load_btcrpc_default_conf(&rpc_conf);
        if (!bret) {
            goto LABEL_EXIT;
        }
    }

    //ucoindがあるパスを取る("routepay"用)
    // const char *p_delimit = strrchr(argv[0], '/');
    // if (p_delimit != NULL) {
    //     memcpy(mExecPath, argv[0], p_delimit - argv[0] + 1);
    //     mExecPath[p_delimit - argv[0] + 1] = '\0';
    // } else {
    //     mExecPath[0] = '\0';
    // }

    signal(SIGPIPE , SIG_IGN);   //ignore SIGPIPE
    p2p_cli_init();

    //bitcoind起動確認
    uint8_t genesis[LN_SZ_HASH];
    btcrpc_init(&rpc_conf);
    bret = btcrpc_getblockhash(genesis, 0);
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

    // if (options == 0x01) {
    //     //node_id出力
    //     ucoin_util_dumpbin(stdout, ln_node_getid(), UCOIN_SZ_PUBKEY, true);
    //     ucoin_term();
    //     return 0;
    // }

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
    DBG_PRINTF("start bitcoin mainnet\n");
#elif NETKIND==1
    DBG_PRINTF("start bitcoin testnet/regtest\n");
#endif

    uint64_t total_amount = ln_node_total_msat();
    misc_save_event(NULL,
            "ucoind start: total_msat=%" PRIu64 "\n", total_amount);

    //ucoincli受信用
    cmd_json_start(p_addr->port + 1);

    //待ち合わせ
    pthread_join(th_svr, NULL);
    pthread_join(th_poll, NULL);
    DBG_PRINTF("%s exit\n", argv[0]);

    DBG_PRINTF("end\n");

    lnapp_term();
    btcrpc_term();
    ln_db_term();
    ucoin_util_log_term();

    return 0;

LABEL_EXIT:
    fprintf(PRINTOUT, "[usage]\n");
    fprintf(PRINTOUT, "\t%s [-p PORT NUM] [-n ALIAS NAME] [-c BITCOIN.CONF] [-a IPv4 ADDRESS] [-i]\n", argv[0]);
    fprintf(PRINTOUT, "\n");
    fprintf(PRINTOUT, "\t\t-h : help\n");
    fprintf(PRINTOUT, "\t\t-p PORT : node port(default: 9735)\n");
    fprintf(PRINTOUT, "\t\t-n NAME : alias name(default: \"node_xxxxxxxxxxxx\")\n");
    fprintf(PRINTOUT, "\t\t-c CONF_FILE : using bitcoin.conf(default: ~/.bitcoin/bitcoin.conf)\n");
    fprintf(PRINTOUT, "\t\t-a IPADDRv4 : announce IPv4 address(default: none)\n");
    // fprintf(PRINTOUT, "\t\t-i : show node_id(not start node)\n");
    fprintf(PRINTOUT, "\t\t-x : erase current DB(without node_id)\n");
    return -1;
}


/********************************************************************
 * public functions
 ********************************************************************/

bool ucoind_transfer_channel(uint64_t ShortChannelId, trans_cmd_t Cmd, ucoin_buf_t *pBuf)
{
    lnapp_conf_t *p_appconf = NULL;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", ShortChannelId);

    //socketが開いているか検索
    p_appconf = ucoind_search_connected_cnl(ShortChannelId);
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        lnapp_transfer_channel(p_appconf, Cmd, pBuf);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return p_appconf != NULL;
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


// const char *ucoind_get_exec_path(void)
// {
//     return mExecPath;
// }


// ucoind 起動中に接続失敗したnodeを登録していく。
// リストに登録されているnodeに対しては、monitoring.c で自動接続しないようにする。
// 再接続できるようになったか確認する方法を用意していないので、今のところリストから削除する方法はない。
void ucoind_nodefail_add(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc)
{
    DBG_PRINTF("ipaddr(%d)=%s:%" PRIu16 " node_id: ", NodeDesc, pAddr, Port);
    DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);

    if ( misc_all_zero(pNodeId, UCOIN_SZ_PUBKEY) ||
         ucoind_nodefail_get(pNodeId, pAddr, Port, LN_NODEDESC_IPV4) ) {
        //登録の必要なし
        DBG_PRINTF("no save\n");
        return;
    }

    if (NodeDesc == LN_NODEDESC_IPV4) {
        char nodeid_str[UCOIN_SZ_PUBKEY * 2 + 1];
        ucoin_util_bin2str(nodeid_str, pNodeId, UCOIN_SZ_PUBKEY);
        DBG_PRINTF("add nodefail list: %s@%s:%" PRIu16 "\n", nodeid_str, pAddr, Port);

        nodefaillist_t *nf = (nodefaillist_t *)APP_MALLOC(sizeof(nodefaillist_t));
        memcpy(nf->node_id, pNodeId, UCOIN_SZ_PUBKEY);
        strcpy(nf->ipaddr, pAddr);
        nf->port = Port;
        LIST_INSERT_HEAD(&mNodeFailListHead, nf, list);
    }
}


bool ucoind_nodefail_get(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc)
{
    bool detect = false;

    if (NodeDesc == LN_NODEDESC_IPV4) {
        char nodeid_str[UCOIN_SZ_PUBKEY * 2 + 1];
        ucoin_util_bin2str(nodeid_str, pNodeId, UCOIN_SZ_PUBKEY);

        nodefaillist_t *p = LIST_FIRST(&mNodeFailListHead);
        while (p != NULL) {
            if ( (memcmp(p->node_id, pNodeId, UCOIN_SZ_PUBKEY) == 0) &&
                 (strcmp(p->ipaddr, pAddr) == 0) &&
                 (p->port == Port) ) {
                //DBG_PRINTF("get nodefail list: %s@%s:%" PRIu16 "\n", nodeid_str, pAddr, Port);
                detect = true;
                break;
            }
            p = LIST_NEXT(p, list);
        }
    }
    return detect;
}


char *ucoind_error_str(int ErrCode)
{
    static const struct {
        int             err;
        const char      *p_str;
    } kERR[] = {
        { RPCERR_ERROR,                     "error" },
        { RPCERR_NOCONN,                    "not connected" },
        { RPCERR_ALCONN,                    "already connected" },
        { RPCERR_NOCHANN,                   "no channel" },
        { RPCERR_PARSE,                     "parse param" },
        { RPCERR_NOINIT,                    "no init or init not end" },
        { RPCERR_NODEID,                    "invalid node_id" },
        { RPCERR_NOOPEN,                    "channel not open" },
        { RPCERR_ALOPEN,                    "channel already opened" },
        { RPCERR_FULLCLI,                   "client full" },
        { RPCERR_SOCK,                      "socket" },
        { RPCERR_CONNECT,                   "connect" },
        { RPCERR_OPENING,                   "funding now" },
        { RPCERR_FUNDING,                   "fail funding" },
        { RPCERR_INVOICE_FULL,              "invoice full" },
        { RPCERR_INVOICE_ERASE,             "fail: erase invoice" },
        { RPCERR_CLOSE_START,               "fail start closing" },
        { RPCERR_CLOSE_FAIL,                "fail unilateral close" },
        { RPCERR_PAY_STOP,                  "stop payment" },
        { RPCERR_NOROUTE,                   "fail routing" },
        { RPCERR_PAYFAIL,                   "" },
        { RPCERR_PAY_RETRY,                 "retry payment" }
    };

    const char *p_str = "";
    for (size_t lp = 0; lp < ARRAY_SIZE(kERR); lp++) {
        if (kERR[lp].err == ErrCode) {
            p_str = kERR[lp].p_str;
            break;
        }
    }

    return strdup(p_str);
}
