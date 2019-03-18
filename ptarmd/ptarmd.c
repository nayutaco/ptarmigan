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
 * main---------->+ main thread      +-----------------+
 *                |  JSON-RPC recv   |                 |
 *                +---+-------+----+-+                 |
 *                    |       |    |                   |
 *                    v       |    v                   v
 *         P2P-server-thread  |  monitor-thread  signal-thread
 *                            v
 *                        +---+------------+
 *         recv-thread <--| channel thread |-+
 *         poll-thread <--|                | |-+
 *         anno-thread <--|                | | |
 *                        +----------------+ | |
 *                           |               | |
 *                           +---------------+ |
 *                             |               |
 *                             +---------------+
 * </pre>
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <libgen.h>
#include <linux/limits.h>

#define LOG_TAG     "ptarmd"
#include "utl_log.h"
#include "utl_time.h"
#include "utl_dbg.h"
#include "utl_str.h"
#include "utl_mem.h"

#include "btc_crypto.h"

#include "ln_setupctl.h"

#include "ptarmd.h"
#include "btcrpc.h"
#include "p2p.h"
#include "lnapp.h"
#include "monitoring.h"
#include "cmd_json.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SCRIPT_DIR            "script"


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct     nodefaillist_t
 *  @brief      connect_fail peer information list
 *  @note
 *      - use for reject node reconnect
 */
typedef struct nodefaillist_t {
    LIST_ENTRY(nodefaillist_t) list;

    uint8_t     node_id[BTC_SZ_PUBKEY];         // peer node_id
    char        ipaddr[SZ_IPV4_LEN + 1];        // IP address
    uint16_t    port;                           // port number
} nodefaillist_t;
LIST_HEAD(nodefaillisthead_t, nodefaillist_t);


/********************************************************************
 * static variables
 ********************************************************************/

static pthread_mutex_t              mMuxPreimage;
static struct nodefaillisthead_t    mNodeFailListHead;
static bool                         mRunning;
static ln_establish_param_t         mEstablishParam;


static const char *kSCRIPT[] = {
    //PTARMD_EVT_STARTED
    "started.sh",
    //PTARMD_EVT_ERROR
    "error.sh",
    //PTARMD_EVT_CONNECTED
    "connected.sh",
    //PTARMD_EVT_DISCONNECTED
    "disconnected.sh",
    //PTARMD_EVT_ESTABLISHED
    "established.sh",
    //PTARMD_EVT_PAYMENT,
    "payment.sh",
    //PTARMD_EVT_FORWARD,
    "forward.sh",
    //PTARMD_EVT_FULFILL,
    "fulfill.sh",
    //PTARMD_EVT_FAIL,
    "fail.sh",
    //PTARMD_EVT_HTLCCHANGED,
    "htlcchanged.sh",
    //PTARMD_EVT_CLOSED
    "closed.sh"
};


/********************************************************************
 * prototypes
 ********************************************************************/

static void load_channel_settings(void);
static bool comp_func_cnl(ln_channel_t *pChannel, void *p_db_param, void *p_param);
static void set_channels(void);


/********************************************************************
 * prototypes
 ********************************************************************/

static char gExecPath[PATH_MAX];


/********************************************************************
 * entry point
 ********************************************************************/

int ptarmd_start(uint16_t RpcPort, const ln_node_t *pNode)
{
    bool bret;

    mkdir(FNAME_LOGDIR, 0755);

    bret = ln_node_init(pNode);
    if (!bret) {
        fprintf(stderr, "fail: node init\n");
        return -2;
    }
    const ln_node_addr_t *p_addr = ln_node_addr();

    p2p_init();

    //peer config出力(内部テストで使用している)
    FILE *fp = fopen(FNAME_FMT_NODECONF, "w");
    if (fp) {
        if (p_addr->type == LN_ADDR_DESC_TYPE_IPV4) {
            fprintf(fp, "ipaddr=%d.%d.%d.%d\n",
                        p_addr->addr[0],
                        p_addr->addr[1],
                        p_addr->addr[2],
                        p_addr->addr[3]);
        } else {
            fprintf(fp, "ipaddr=127.0.0.1\n");
        }
        fprintf(fp, "port=%d\n", p_addr->port);
        fprintf(fp, "node_id=");
        utl_dbg_dump(fp, ln_node_get_id(), BTC_SZ_PUBKEY, true);
        fclose(fp);
    }

    pthread_mutex_init(&mMuxPreimage, NULL);

    load_channel_settings();
    btcrpc_set_creationhash(ln_creationhash_get());
    set_channels();
    lnapp_global_init();

    //接続待ち受け用
    pthread_t th_svr;
    pthread_create(&th_svr, NULL, &p2p_listener_start, NULL);

    //チャネル監視用
    pthread_t th_mon;
    pthread_create(&th_mon, NULL, &monitor_start, NULL);

    uint64_t total_amount = ln_node_total_msat();
    ptarmd_eventlog(NULL, "----------START----------");
    ptarmd_eventlog(NULL,
            "ptarmd start: total_msat=%" PRIu64, total_amount);

    mRunning = true;

    {
        // method: started
        // $1: 0
        // $2: node_id
        char param[256];
        char node_id[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
        sprintf(param, "0x0x0 %s", node_id);
        ptarmd_call_script(PTARMD_EVT_STARTED, param);
    }

    //ptarmcli受信用
    cmd_json_start(RpcPort != 0 ? RpcPort : p_addr->port + 1);

    //ptarmd_stop()待ち

    //待ち合わせ
    pthread_join(th_svr, NULL);
    pthread_join(th_mon, NULL);

    LOGD("end\n");
    total_amount = ln_node_total_msat();
    ptarmd_eventlog(NULL,
            "ptarmd end: total_msat=%" PRIu64 "\n", total_amount);

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
    if (mRunning) {
        mRunning = false;
        LOGD("$$$ stopage order\n");
        cmd_json_stop();
        monitor_stop();
        p2p_stop_all();
        p2p_stop_all();
    } else {
        LOGD("$$$ stopped\n");
    }
}


//https://stackoverflow.com/questions/606041/how-do-i-get-the-path-of-a-process-in-unix-linux
bool ptarmd_execpath_set(void)
{
    ssize_t buff_len;
    if((buff_len = readlink("/proc/self/exe", gExecPath, sizeof(gExecPath) - 1)) != -1) {
        gExecPath[buff_len] = '\0';
        dirname(gExecPath);
    }
    return buff_len != -1;
}


const char *ptarmd_execpath_get(void)
{
    return gExecPath;
}


// bool ptarmd_transfer_channel(uint64_t ShortChannelId, rcvidle_cmd_t Cmd, utl_buf_t *pBuf)
// {
//     lnapp_conf_t *p_appconf = NULL;

//     LOGD("  search short_channel_id : %016" PRIx64 "\n", ShortChannelId);

//     //socketが開いているか検索
//     p_appconf = ptarmd_search_transferable_cnl(ShortChannelId);
//     if (p_appconf != NULL) {
//         LOGD("AppConf found\n");
//         lnapp_transfer_channel(p_appconf, Cmd, pBuf);
//     } else {
//         LOGD("AppConf not found...\n");
//     }

//     return p_appconf != NULL;
// }


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

    p_appconf = p2p_search_short_channel_id(short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_search_short_channel_id(short_channel_id);
    }
    return p_appconf;
}


lnapp_conf_t *ptarmd_search_transferable_cnl(uint64_t short_channel_id)
{
    lnapp_conf_t *p_return = NULL;
    lnapp_conf_t *p_appconf = ptarmd_search_connected_cnl(short_channel_id);
    if (p_appconf == NULL) {
        LOGE("fail: not connected\n");
        goto LABEL_EXIT;
    }
    if (!lnapp_is_active(p_appconf)) {
        LOGE("fail: not working\n");
        goto LABEL_EXIT;
    }
    if (!lnapp_is_inited(p_appconf)) {
        LOGE("fail: not initialized\n");
        goto LABEL_EXIT;
    }
    if (!lnapp_check_ponglist(p_appconf)) {
        LOGE("fail: not pingpong\n");
        goto LABEL_EXIT;
    }
    if (ln_status_get(p_appconf->p_channel) != LN_STATUS_NORMAL) {
        LOGE("fail: bad status\n");
        goto LABEL_EXIT;
    }
    p_return = p_appconf;

LABEL_EXIT:
    return p_return;
}


lnapp_conf_t *ptarmd_search_connected_node_id(const uint8_t *p_node_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_search_node(p_node_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_search_node(p_node_id);
    }
    return p_appconf;
}


lnapp_conf_t *ptarmd_search_transferable_node_id(const uint8_t *p_node_id)
{
    lnapp_conf_t *p_appconf = ptarmd_search_connected_node_id(p_node_id);
    if ((p_appconf != NULL) && (ln_status_get(p_appconf->p_channel) != LN_STATUS_NORMAL)) {
        p_appconf = NULL;
    }
    return p_appconf;
}


// ptarmd 起動中に接続失敗したnodeを登録していく。
// リストに登録されているnodeに対しては、monitoring.c で自動接続しないようにする。
// 再接続できるようになったか確認する方法を用意していないので、今のところリストから削除する方法はない。
void ptarmd_nodefail_add(
            const uint8_t *pNodeId, const char *pAddr, uint16_t Port,
            ln_msg_address_descriptor_type_t NodeDesc)
{
    LOGD("ipaddr(%d)=%s:%" PRIu16 " node_id: ", NodeDesc, pAddr, Port);
    DUMPD(pNodeId, BTC_SZ_PUBKEY);

    if ( utl_mem_is_all_zero(pNodeId, BTC_SZ_PUBKEY) ||
         ptarmd_nodefail_get(pNodeId, pAddr, Port, LN_ADDR_DESC_TYPE_IPV4, false) ) {
        //登録の必要なし
        LOGD("no save\n");
        return;
    }

    if (NodeDesc == LN_ADDR_DESC_TYPE_IPV4) {
        char node_id_str[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(node_id_str, pNodeId, BTC_SZ_PUBKEY);
        LOGD("add nodefail list: %s@%s:%" PRIu16 "\n", node_id_str, pAddr, Port);

        nodefaillist_t *nf = (nodefaillist_t *)UTL_DBG_MALLOC(sizeof(nodefaillist_t));
        memcpy(nf->node_id, pNodeId, BTC_SZ_PUBKEY);
        strcpy(nf->ipaddr, pAddr);
        nf->port = Port;
        LIST_INSERT_HEAD(&mNodeFailListHead, nf, list);
    }
}


bool ptarmd_nodefail_get(
            const uint8_t *pNodeId, const char *pAddr, uint16_t Port,
            ln_msg_address_descriptor_type_t NodeDesc, bool bRemove)
{
    bool detect = false;

    if (NodeDesc == LN_ADDR_DESC_TYPE_IPV4) {
        char node_id_str[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(node_id_str, pNodeId, BTC_SZ_PUBKEY);

        nodefaillist_t *p = LIST_FIRST(&mNodeFailListHead);
        while (p != NULL) {
            if ( (memcmp(p->node_id, pNodeId, BTC_SZ_PUBKEY) == 0) &&
                 (strcmp(p->ipaddr, pAddr) == 0) &&
                 (p->port == Port) ) {
                if (bRemove) {
                    LOGD("get nodefail list: %s@%s:%" PRIu16 "\n", node_id_str, pAddr, Port);
                    LIST_REMOVE(p, list);
                }
                detect = true;
                break;
            }
            p = LIST_NEXT(p, list);
        }
    }
    return detect;
}


const ln_establish_param_t *ptarmd_get_establish_param(void)
{
    return &mEstablishParam;
}


/** イベント発生によるスクリプト実行
 *
 *
 */
void ptarmd_call_script(ptarmd_event_t event, const char *param)
{
    struct stat buf;
    char script[PATH_MAX];
    char path[PATH_MAX];

    errno = 0;
    getcwd(path, sizeof(path));
    if (errno != 0) {
        LOGE("fail: getcwd()\n");
        return;
    }
    snprintf(script, sizeof(script), "%s/" M_SCRIPT_DIR "/%s",
                    path,
                    kSCRIPT[event]);
    LOGD("event=0x%02x(%s)\n", (int)event, script);
    int ret = stat(script, &buf);
    if ((ret == 0) && (buf.st_mode & S_IXUSR)) {
        size_t sclen = strlen(script) + 64 + strlen(param);
        char *cmdline = (char *)UTL_DBG_MALLOC(sclen);    //UTL_DBG_FREE: この中   //+64は余裕を持たせている
        snprintf(cmdline, sclen, "%s %s", script, param);
        LOGD("cmdline: %s\n", cmdline);
        system(cmdline);
        UTL_DBG_FREE(cmdline);      //UTL_DBG_MALLOC: この中
    }
}


void ptarmd_eventlog(const uint8_t *pChannelId, const char *pFormat, ...)
{
    char fname[256];

    if (pChannelId != NULL) {
        char chanid[LN_SZ_CHANNEL_ID * 2 + 1];
        utl_str_bin2str(chanid, pChannelId, LN_SZ_CHANNEL_ID);
        sprintf(fname, FNAME_CHANNEL_LOG, chanid);
    } else {
        sprintf(fname, FNAME_EVENT_LOG);
    }
    FILE *fp = fopen(fname, "a");
    if (fp != NULL) {
        char time[UTL_SZ_TIME_FMT_STR + 1];
        fprintf(fp, "[%s]", utl_time_str_time(time));

        va_list ap;
        va_start(ap, pFormat);
        vfprintf(fp, pFormat, ap);
        va_end(ap);

        fprintf(fp, "\n");
        fclose(fp);
    }
}


const char *ptarmd_error_cstr(int ErrCode)
{
    static const struct {
        int             err;
        const char      *p_str;
    } kERR[] = {
        { RPCERR_ERROR,                     "error" },
        { RPCERR_NOCONN,                    "not connected" },
        { RPCERR_ALCONN,                    "already connected" },
        { RPCERR_NOCHANNEL,                 "no channel" },
        { RPCERR_PARSE,                     "parse param" },
        { RPCERR_NOINIT,                    "no init or init not end" },
        { RPCERR_BLOCKCHAIN,                "fail blockchain access" },
        { RPCERR_BUSY,                      "node busy" },

        { RPCERR_NODEID,                    "invalid node_id" },
        { RPCERR_NOOPEN,                    "channel not open" },
        { RPCERR_ALOPEN,                    "channel already opened" },
        { RPCERR_FULLCLI,                   "client full" },
        { RPCERR_SOCK,                      "socket" },
        { RPCERR_CONNECT,                   "connect" },
        { RPCERR_PEER_ERROR,                "peer error" },
        { RPCERR_OPENING,                   "funding now" },
        { RPCERR_ADDRESS,                   "invalid address" },
        { RPCERR_PORTNUM,                   "invalid port number" },

        { RPCERR_FUNDING,                   "fail funding" },

        { RPCERR_INVOICE_FULL,              "invoice full" },
        { RPCERR_INVOICE_ERASE,             "erase invoice" },
        { RPCERR_INVOICE_FAIL,              "decode invoice" },
        { RPCERR_INVOICE_OUTDATE,           "outdated invoice" },

        { RPCERR_CLOSE_START,               "fail start closing" },
        { RPCERR_CLOSE_FAIL,                "fail unilateral close" },
        { RPCERR_CLOSE_CLEAN,               "remain HTLC" },

        { RPCERR_PAY_STOP,                  "stop payment" },
        { RPCERR_NOROUTE,                   "fail routing" },
        { RPCERR_PAYFAIL,                   "cannot start payment" },
        { RPCERR_PAY_RETRY,                 "retry payment" },
        { RPCERR_TOOMANYHOP,                "too many hop nodes" },
        { RPCERR_NOSTART,                   "payer not found" },
        { RPCERR_NOGOAL,                    "payee not found" },

        { RPCERR_WALLET_ERR,                "wallet error" },
    };

    const char *p_str = "";
    for (size_t lp = 0; lp < ARRAY_SIZE(kERR); lp++) {
        if (kERR[lp].err == ErrCode) {
            p_str = kERR[lp].p_str;
            break;
        }
    }

    return p_str;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** Channel情報設定
 *
 * @param[in,out]       p_conf
 */
static void load_channel_settings(void)
{
    channel_conf_t econf;

    conf_channel_init(&econf);
    (void)conf_channel_load(FNAME_CONF_CHANNEL, &econf);
    mEstablishParam.dust_limit_sat = econf.dust_limit_sat;
    mEstablishParam.max_htlc_value_in_flight_msat = econf.max_htlc_value_in_flight_msat;
    mEstablishParam.channel_reserve_sat = econf.channel_reserve_sat;
    mEstablishParam.htlc_minimum_msat = econf.htlc_minimum_msat;
    mEstablishParam.to_self_delay = econf.to_self_delay;
    mEstablishParam.max_accepted_htlcs = econf.max_accepted_htlcs;
    mEstablishParam.min_depth = econf.min_depth;

    ln_init_localfeatures_set(econf.localfeatures);
}


/** #ln_node_search_channel()処理関数
 *
 * @param[in,out]   pChannel        DBから取得したchannel
 * @param[in,out]   p_db_param      DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         cmp_param_channel_t構造体
 */
static bool comp_func_cnl(ln_channel_t *pChannel, void *p_db_param, void *p_param)
{
    (void)p_db_param; (void)p_param;

    LOGD("short_channel_id=%016" PRIx64 "\n", ln_short_channel_id(pChannel));

    const uint8_t *p_bhash;
    p_bhash = ln_funding_blockhash(pChannel);
    btcrpc_set_channel(ln_remote_node_id(pChannel),
            ln_short_channel_id(pChannel),
            ln_funding_info_txid(&pChannel->funding_info),
            ln_funding_info_txindex(&pChannel->funding_info),
            ln_funding_info_wit_script(&pChannel->funding_info),
            p_bhash,
            ln_funding_last_confirm_get(pChannel));

    return false;
}


static void set_channels(void)
{
    LOGD("\n");
    ln_db_channel_search_readonly(comp_func_cnl, NULL);
}
