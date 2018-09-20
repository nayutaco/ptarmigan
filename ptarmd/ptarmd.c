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
/** @file   ptarmd.c
 *  @brief  ptarm daemon
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

#include "btcrpc.h"
#include "utl_misc.h"
#include "ln_db.h"
#include "utl_log.h"

#include "ptarmd.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "monitoring.h"
#include "cmd_json.h"


/**************************************************************************
 * macros
 **************************************************************************/


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct     nodefaillist_t
 *  @brief      接続失敗peer情報リスト
 */
typedef struct nodefaillist_t {
    LIST_ENTRY(nodefaillist_t) list;

    uint8_t     node_id[BTC_SZ_PUBKEY];
    char        ipaddr[SZ_IPV4_LEN + 1];
    uint16_t    port;
} nodefaillist_t;
LIST_HEAD(nodefaillisthead_t, nodefaillist_t);


/********************************************************************
 * static variables
 ********************************************************************/

static pthread_mutex_t              mMuxPreimage;
static struct nodefaillisthead_t    mNodeFailListHead;


/********************************************************************
 * prototypes
 ********************************************************************/


/********************************************************************
 * entry point
 ********************************************************************/

int ptarmd_start(uint16_t my_rpcport)
{
    bool bret;
    ln_nodeaddr_t *p_addr = ln_node_addr();

    p2p_cli_init();

    //node情報読込み
    bret = ln_node_init(0);
    if (!bret) {
        fprintf(stderr, "fail: node init\n");
        return -2;
    }

    //peer config出力(内部テストで使用している)
    char fname[256];
    sprintf(fname, FNAME_FMT_NODECONF, ln_node_alias());
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
        btc_util_dumpbin(fp, ln_node_getid(), BTC_SZ_PUBKEY, true);
        fclose(fp);
    }

    pthread_mutex_init(&mMuxPreimage, NULL);

    //接続待ち受け用
    pthread_t th_svr;
    pthread_create(&th_svr, NULL, &p2p_svr_start, NULL);

    //チャネル監視用
    pthread_t th_poll;
    pthread_create(&th_poll, NULL, &monitor_thread_start, NULL);

    uint64_t total_amount = ln_node_total_msat();
    lnapp_save_event(NULL,
            "ptarmd start: total_msat=%" PRIu64 "\n", total_amount);

    //ptarmcli受信用
    cmd_json_start(my_rpcport != 0 ? my_rpcport : p_addr->port + 1);

    //ptarmd_stop()待ち

    //待ち合わせ
    pthread_join(th_svr, NULL);
    pthread_join(th_poll, NULL);

    LOGD("end\n");

    btcrpc_term();
    ln_db_term();
    utl_log_term();

    return 0;
}


/********************************************************************
 * public functions
 ********************************************************************/

void ptarmd_stop(void)
{
    cmd_json_stop();
    p2p_svr_stop_all();
    p2p_cli_stop_all();
    monitor_stop();
}


bool ptarmd_transfer_channel(uint64_t ShortChannelId, trans_cmd_t Cmd, utl_buf_t *pBuf)
{
    lnapp_conf_t *p_appconf = NULL;

    LOGD("  search short_channel_id : %016" PRIx64 "\n", ShortChannelId);

    //socketが開いているか検索
    p_appconf = ptarmd_search_connected_cnl(ShortChannelId);
    if (p_appconf != NULL) {
        LOGD("AppConf found\n");
        lnapp_transfer_channel(p_appconf, Cmd, pBuf);
    } else {
        LOGD("AppConf not found...\n");
    }

    return p_appconf != NULL;
}


void ptarmd_preimage_lock(void)
{
    pthread_mutex_lock(&mMuxPreimage);
}


void ptarmd_preimage_unlock(void)
{
    pthread_mutex_unlock(&mMuxPreimage);
}


lnapp_conf_t *ptarmd_search_connected_cnl(uint64_t short_channel_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_cli_search_short_channel_id(short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_short_channel_id(short_channel_id);
    }
    return p_appconf;
}


// ptarmd 起動中に接続失敗したnodeを登録していく。
// リストに登録されているnodeに対しては、monitoring.c で自動接続しないようにする。
// 再接続できるようになったか確認する方法を用意していないので、今のところリストから削除する方法はない。
void ptarmd_nodefail_add(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc)
{
    LOGD("ipaddr(%d)=%s:%" PRIu16 " node_id: ", NodeDesc, pAddr, Port);
    DUMPD(pNodeId, BTC_SZ_PUBKEY);

    if ( utl_misc_all_zero(pNodeId, BTC_SZ_PUBKEY) ||
         ptarmd_nodefail_get(pNodeId, pAddr, Port, LN_NODEDESC_IPV4) ) {
        //登録の必要なし
        LOGD("no save\n");
        return;
    }

    if (NodeDesc == LN_NODEDESC_IPV4) {
        char nodeid_str[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(nodeid_str, pNodeId, BTC_SZ_PUBKEY);
        LOGD("add nodefail list: %s@%s:%" PRIu16 "\n", nodeid_str, pAddr, Port);

        nodefaillist_t *nf = (nodefaillist_t *)UTL_DBG_MALLOC(sizeof(nodefaillist_t));
        memcpy(nf->node_id, pNodeId, BTC_SZ_PUBKEY);
        strcpy(nf->ipaddr, pAddr);
        nf->port = Port;
        LIST_INSERT_HEAD(&mNodeFailListHead, nf, list);
    }
}


bool ptarmd_nodefail_get(const uint8_t *pNodeId, const char *pAddr, uint16_t Port, ln_nodedesc_t NodeDesc)
{
    bool detect = false;

    if (NodeDesc == LN_NODEDESC_IPV4) {
        char nodeid_str[BTC_SZ_PUBKEY * 2 + 1];
        utl_misc_bin2str(nodeid_str, pNodeId, BTC_SZ_PUBKEY);

        nodefaillist_t *p = LIST_FIRST(&mNodeFailListHead);
        while (p != NULL) {
            if ( (memcmp(p->node_id, pNodeId, BTC_SZ_PUBKEY) == 0) &&
                 (strcmp(p->ipaddr, pAddr) == 0) &&
                 (p->port == Port) ) {
                //LOGD("get nodefail list: %s@%s:%" PRIu16 "\n", nodeid_str, pAddr, Port);
                detect = true;
                break;
            }
            p = LIST_NEXT(p, list);
        }
    }
    return detect;
}


char *ptarmd_error_str(int ErrCode)
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
        { RPCERR_BLOCKCHAIN,                "fail blockchain access" },

        { RPCERR_NODEID,                    "invalid node_id" },
        { RPCERR_NOOPEN,                    "channel not open" },
        { RPCERR_ALOPEN,                    "channel already opened" },
        { RPCERR_FULLCLI,                   "client full" },
        { RPCERR_SOCK,                      "socket" },
        { RPCERR_CONNECT,                   "connect" },
        { RPCERR_PEER_ERROR,                "peer error" },
        { RPCERR_OPENING,                   "funding now" },

        { RPCERR_FUNDING,                   "fail funding" },

        { RPCERR_INVOICE_FULL,              "invoice full" },
        { RPCERR_INVOICE_ERASE,             "erase invoice" },
        { RPCERR_INVOICE_FAIL,              "decode invoice" },
        { RPCERR_INVOICE_OUTDATE,           "outdated invoice" },

        { RPCERR_CLOSE_START,               "fail start closing" },
        { RPCERR_CLOSE_FAIL,                "fail unilateral close" },

        { RPCERR_PAY_STOP,                  "stop payment" },
        { RPCERR_NOROUTE,                   "fail routing" },
        { RPCERR_PAYFAIL,                   "" },
        { RPCERR_PAY_RETRY,                 "retry payment" },
        { RPCERR_TOOMANYHOP,                "fail create invoice(too many hop)" },
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
