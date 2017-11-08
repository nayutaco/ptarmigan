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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "jsonrpc-c.h"

#include "ucoind.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "jsonrpc.h"
#include "conf.h"
#include "misc.h"
#include "ln_db.h"


/**************************************************************************
 * macro
 **************************************************************************/

#define M_WAIT_MON_SEC                  (60)        ///< 監視周期[sec]


/********************************************************************
 * static variables
 ********************************************************************/

static ln_node_t            mNode;
static struct jrpc_server   mJrpc;
static preimage_t           mPreimage[PREIMAGE_NUM];
static pthread_mutex_t      mMuxPreimage;
static volatile bool        mMonitoring;


/********************************************************************
 * prototypes
 ********************************************************************/

static int msg_recv(uint16_t Port);
static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_connect(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_pay(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id);
static lnapp_conf_t *search_connected_lnapp_node(const uint8_t *p_node_id);
static lnapp_conf_t *search_connected_lnapp_cnl(uint64_t short_channel_id);

static void *thread_monitor_start(void *pArg);
static bool monfunc(ln_self_t *self, void *p_param);


/********************************************************************
 * public functions
 ********************************************************************/

int main(int argc, char *argv[])
{
    if (argc < 2) {
        goto LABEL_EXIT;
    }

#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    ucoin_init(UCOIN_MAINNET, true);
#elif NETKIND==1
    ucoin_init(UCOIN_TESTNET, true);
#endif

    if ((argc == 2) && (strcmp(argv[1], "wif") == 0)) {
        uint8_t priv[UCOIN_SZ_PRIVKEY];
        do {
            ucoin_util_random(priv, UCOIN_SZ_PRIVKEY);
        } while (!ucoin_keys_chkpriv(priv));

        char wif[UCOIN_SZ_WIF_MAX];
        ucoin_keys_priv2wif(wif, priv);
        printf("wif=%s\n", wif);

        uint8_t pub[UCOIN_SZ_PUBKEY];
        ucoin_keys_priv2pub(pub, priv);
        fprintf(stderr, "pubkey= ");
        for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
            fprintf(stderr, "%02x", pub[lp]);
        }
        fprintf(stderr, "\n");

        ucoin_term();
        return 0;
    }

    //syslog
    openlog("ucoind", LOG_CONS, LOG_USER);

    rpc_conf_t rpc_conf;
    node_conf_t node_conf;
    bool bret = load_node_conf(argv[1], &node_conf, &rpc_conf, ln_node_addr(&mNode));
    if (!bret) {
        goto LABEL_EXIT;
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

    p2p_cli_init();
    jsonrpc_init(&rpc_conf);

    //bitcoind起動確認
    uint8_t genesis[LN_SZ_HASH];
    bret = jsonrpc_getblockhash(genesis, 0);
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
    ln_node_init(&mNode, node_conf.wif, node_conf.name, 0);
    ln_print_node(&mNode);
    lnapp_init(&mNode);

    for (int lp = 0; lp < PREIMAGE_NUM; lp++) {
        mPreimage[lp].use = false;
    }
    pthread_mutex_init(&mMuxPreimage, NULL);

    //接続待ち受け用
    pthread_t th_svr;
    pthread_create(&th_svr, NULL, &p2p_svr_start, &node_conf.port);

    //チャネル監視用
    pthread_t th_poll;
    mMonitoring = true;
    pthread_create(&th_poll, NULL, &thread_monitor_start, NULL);

#if NETKIND==0
    SYSLOG_INFO("start bitcoin mainnet");
#elif NETKIND==1
    SYSLOG_INFO("start bitcoin testnet");
#endif

    //ucoincli受信用
    msg_recv(node_conf.port + 1);

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


bool forward_payment(fwd_proc_add_t *p_add)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", p_add->next_short_channel_id);

    //socketが開いているか検索
    p_appconf = search_connected_lnapp_cnl(p_add->next_short_channel_id);
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_forward_payment(p_appconf, p_add);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


bool backward_fulfill(const ln_cb_fulfill_htlc_recv_t *pFulFill)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", pFulFill->prev_short_channel_id);

    //socketが開いているか検索
    p_appconf = search_connected_lnapp_cnl(pFulFill->prev_short_channel_id);
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_backward_fulfill(p_appconf, pFulFill);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


bool backward_fail(const ln_cb_fail_htlc_recv_t *pFail)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", pFail->prev_short_channel_id);

    //socketが開いているか検索
    p_appconf = search_connected_lnapp_cnl(pFail->prev_short_channel_id);
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_backward_fail(p_appconf, pFail, false);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


void preimage_lock(void)
{
    pthread_mutex_lock(&mMuxPreimage);
}


void preimage_unlock(void)
{
    pthread_mutex_unlock(&mMuxPreimage);
}


const preimage_t *preimage_get(int index)
{
    return &mPreimage[index];
}


void preimage_clear(int index)
{
    mPreimage[index].use = false;
    memset(mPreimage[index].preimage, 0, LN_SZ_PREIMAGE);
}


/********************************************************************
 * private functions: JSON-RPC server
 ********************************************************************/

static int msg_recv(uint16_t Port)
{
    jrpc_server_init(&mJrpc, Port);
    jrpc_register_procedure(&mJrpc, cmd_fund,        "fund", NULL);
    jrpc_register_procedure(&mJrpc, cmd_connect,     "connect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_close,       "close", NULL);
    jrpc_register_procedure(&mJrpc, cmd_invoice,     "invoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_listinvoice, "listinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_pay,         "pay", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getinfo,     "getinfo", NULL);
    jrpc_register_procedure(&mJrpc, cmd_stop,        "stop", NULL);
    jrpc_register_procedure(&mJrpc, cmd_debug,       "debug", NULL);
    jrpc_server_run(&mJrpc);
    jrpc_server_destroy(&mJrpc);

    return 0;
}


static int json_connect(cJSON *params, int Index, daemon_connect_t *pConn)
{
    cJSON *json;

    //peer_nodeid, peer_addr, peer_port
    json = cJSON_GetArrayItem(params, Index++);
    if (json && (json->type == cJSON_String)) {
        misc_str2bin(pConn->node_id, UCOIN_SZ_PUBKEY, json->valuestring);
        DBG_PRINTF("pConn->node_id=%s\n", json->valuestring);
    } else {
        DBG_PRINTF("fail: node_id\n");
        Index = -1;
        goto LABEL_EXIT;
    }
    if (memcmp(ln_node_id(&mNode), pConn->node_id, UCOIN_SZ_PUBKEY) == 0) {
        //node_idが自分と同じ
        DBG_PRINTF("fail: same own node_id\n");
        Index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, Index++);
    if (json && (json->type == cJSON_String)) {
        strcpy(pConn->ipaddr, json->valuestring);
        DBG_PRINTF("pConn->ipaddr=%s\n", json->valuestring);
    } else {
        DBG_PRINTF("fail: ipaddr\n");
        Index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, Index++);
    if (json && (json->type == cJSON_Number)) {
        pConn->port = json->valueint;
        DBG_PRINTF("pConn->port=%d\n", json->valueint);
    } else {
        DBG_PRINTF("fail: port\n");
        Index = -1;
    }

LABEL_EXIT:
    return Index;
}


static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON *json;
    daemon_connect_t conn;
    funding_conf_t *p_fundconf = (funding_conf_t *)malloc(sizeof(funding_conf_t));  //lnapp.c cb_established()で解放
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //connect parameter
    index = json_connect(params, index, &conn);
    if (index < 0) {
        goto LABEL_EXIT;
    }

    //txid, txindex, signaddr, funding_sat, push_sat

    //txid
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        misc_str2bin_rev(p_fundconf->txid, UCOIN_SZ_TXID, json->valuestring);
        DBG_PRINTF("txid=%s\n", json->valuestring);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //txindex
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        p_fundconf->txindex = json->valueint;
        DBG_PRINTF("txindex=%d\n", json->valueint);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //signaddr
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        strcpy(p_fundconf->signaddr, json->valuestring);
        DBG_PRINTF("signaddr=%s\n", json->valuestring);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //funding_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        p_fundconf->funding_sat = json->valueu64;
        DBG_PRINTF("funding_sat=%" PRIu64 "\n", p_fundconf->funding_sat);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //push_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        p_fundconf->push_sat = json->valueu64;
        DBG_PRINTF("push_sat=%" PRIu64 "\n", p_fundconf->push_sat);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }

    print_funding_conf(p_fundconf);

    SYSLOG_INFO("fund");

    p2p_cli_start(DCMD_CREATE, &conn, p_fundconf, ctx);
    if (ctx->error_code == 0) {
        result = cJSON_CreateString("OK");
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
}


static cJSON *cmd_connect(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    daemon_connect_t conn;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //connect parameter
    index = json_connect(params, 0, &conn);
    if (index < 0) {
        goto LABEL_EXIT;
    }

    SYSLOG_INFO("connect");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(conn.node_id);
    if (p_appconf == NULL) {
        p2p_cli_start(DCMD_CONNECT, &conn, NULL, ctx);
        if (ctx->error_code == 0) {
            result = cJSON_CreateString("OK");
        }
    } else {
        ctx->error_code = RPCERR_ALCONN;
        ctx->error_message = strdup(RPCERR_ALCONN_STR);
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
}


static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    daemon_connect_t conn;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //connect parameter
    index = json_connect(params, index, &conn);
    if (index < 0) {
        goto LABEL_EXIT;
    }

    SYSLOG_INFO("close");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(conn.node_id);
    if (p_appconf != NULL) {
        //接続中
        bool ret = lnapp_close_channel(p_appconf);
        if (ret) {
            result = cJSON_CreateString("OK");
        } else {
            ctx->error_code = RPCERR_CLOSE_HTLC;
            ctx->error_message = strdup(RPCERR_CLOSE_HTLC_STR);
        }
    } else {
        //未接続
        bool haveCnl = ln_node_search_channel_id(NULL, conn.node_id);
        if (haveCnl) {
            //チャネルあり
            //  相手とのチャネルがあるので、接続自体は可能かもしれない。
            //  closeの仕方については、仕様や運用とも関係が深いので、後で変更することになるだろう。
            //  今は、未接続の場合は mutual close以外で閉じることにする。
            DBG_PRINTF("チャネルはあるが接続していない\n");
            bool ret = lnapp_close_channel_force(conn.node_id);
            if (ret) {
                DBG_PRINTF("force closed\n");
            } else {
                DBG_PRINTF("fail: force close\n");
            }
        } else {
            //チャネルなし
            ctx->error_code = RPCERR_NOCHANN;
            ctx->error_message = strdup(RPCERR_NOCHANN_STR);
        }
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
}


static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON *json;
    uint64_t amount;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //amount
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        amount = json->valueu64;
        DBG_PRINTF("amount=%" PRIu64 "\n", amount);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }

    SYSLOG_INFO("invoice");

    result = cJSON_CreateObject();
    pthread_mutex_lock(&mMuxPreimage);

    int lp;
    for (lp = 0; lp < PREIMAGE_NUM; lp++) {
        if (!mPreimage[lp].use) {
            mPreimage[lp].use = true;
            mPreimage[lp].amount = amount;
            ucoin_util_random(mPreimage[lp].preimage, LN_SZ_PREIMAGE);
            break;
        }
    }

    if (lp < PREIMAGE_NUM) {
        uint8_t preimage_hash[LN_SZ_HASH];
        ln_calc_preimage_hash(preimage_hash, mPreimage[lp].preimage);

        char str_hash[LN_SZ_HASH * 2 + 1];
        misc_bin2str(str_hash, preimage_hash, LN_SZ_HASH);
        DBG_PRINTF("preimage[%d]=", lp)
        DUMPBIN(mPreimage[lp].preimage, LN_SZ_PREIMAGE);
        DBG_PRINTF("hash=")
        DUMPBIN(preimage_hash, LN_SZ_HASH);
        cJSON_AddItemToObject(result, "hash", cJSON_CreateString(str_hash));
        cJSON_AddItemToObject(result, "amount", cJSON_CreateNumber64(mPreimage[lp].amount));
    } else {
        SYSLOG_ERR("%s(): no empty place", __func__);
        ctx->error_code = RPCERR_INVOICE_FULL;
        ctx->error_message = strdup(RPCERR_INVOICE_FULL_STR);
    }
    pthread_mutex_unlock(&mMuxPreimage);


LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
}


static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON *result = NULL;
    int index = 0;
    uint8_t preimage_hash[LN_SZ_HASH];
    bool badd = false;
    cJSON *array;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    result = cJSON_CreateArray();

    array = cJSON_CreateArray();
    for (int lp = 0; lp < PREIMAGE_NUM; lp++) {
        if (mPreimage[lp].use) {
            ln_calc_preimage_hash(preimage_hash, mPreimage[lp].preimage);
            cJSON *json = cJSON_CreateArray();

            char str_hash[LN_SZ_HASH * 2 + 1];
            misc_bin2str(str_hash, preimage_hash, LN_SZ_HASH);
            cJSON_AddItemToArray(json, cJSON_CreateString(str_hash));
            cJSON_AddItemToArray(json, cJSON_CreateNumber64(mPreimage[lp].amount));
            cJSON_AddItemToArray(array, json);
            badd = true;
        }
    }
    if (badd) {
        cJSON_AddItemToArray(result, array);
    }


LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
}


static cJSON *cmd_pay(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON *json;
    payment_conf_t payconf;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //blockcount
    int blockcnt = jsonrpc_getblockcount();
    if (blockcnt < 0) {
        index = -1;
        goto LABEL_EXIT;
    }

    //payment_hash, hop_num
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        misc_str2bin(payconf.payment_hash, LN_SZ_HASH, json->valuestring);
        DBG_PRINTF("payment_hash=%s\n", json->valuestring);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        payconf.hop_num = json->valueint;
        DBG_PRINTF("hop_num=%d\n", json->valueint);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //array
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Array)) {
        DBG_PRINTF("trace array\n");
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //[ [...], [...], ..., [...] ]
    for (int lp = 0; lp < payconf.hop_num; lp++) {
        ln_hop_datain_t *p = &payconf.hop_datain[lp];

        DBG_PRINTF("loop=%d\n", lp);
        cJSON *jarray = cJSON_GetArrayItem(json, lp);
        if (jarray && (jarray->type == cJSON_Array)) {
            //[node_id, short_channel_id, amt_to_forward, outgoing_cltv_value]

            //node_id
            cJSON *jprm = cJSON_GetArrayItem(jarray, 0);
            DBG_PRINTF("jprm=%p\n", jprm);
            if (jprm && (jprm->type == cJSON_String)) {
                misc_str2bin(p->pubkey, UCOIN_SZ_PUBKEY, jprm->valuestring);
                DBG_PRINTF("  node_id=");
                DUMPBIN(p->pubkey, UCOIN_SZ_PUBKEY);
            } else {
                DBG_PRINTF("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
            //short_channel_id
            jprm = cJSON_GetArrayItem(jarray, 1);
            if (jprm && (jprm->type == cJSON_String)) {
                p->short_channel_id = strtoull(jprm->valuestring, NULL, 16);
                DBG_PRINTF("  short_channel_id=%016" PRIx64 "\n", p->short_channel_id);
            } else {
                DBG_PRINTF("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
            //amt_to_forward
            jprm = cJSON_GetArrayItem(jarray, 2);
            if (jprm && (jprm->type == cJSON_Number)) {
                p->amt_to_forward = jprm->valueu64;
                DBG_PRINTF("  amt_to_forward=%" PRIu64 "\n", p->amt_to_forward);
            } else {
                DBG_PRINTF("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
            //outgoing_cltv_value
            jprm = cJSON_GetArrayItem(jarray, 3);
            if (jprm && (jprm->type == cJSON_Number)) {
                p->outgoing_cltv_value = jprm->valueint + blockcnt;
                DBG_PRINTF("  outgoing_cltv_value=%d\n", p->outgoing_cltv_value);
            } else {
                DBG_PRINTF("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
        } else {
            DBG_PRINTF("fail: p=%p\n", jarray);
            index = -1;
            goto LABEL_EXIT;
        }
    }

    SYSLOG_INFO("payment");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(payconf.hop_datain[1].pubkey);
    if (p_appconf != NULL) {
        bool ret;
        ret = lnapp_payment(p_appconf, &payconf);
        if (ret) {
            result = cJSON_CreateString("OK");
        } else {
            ctx->error_code = RPCERR_PAY_STOP;
            ctx->error_message = strdup(RPCERR_PAY_STOP_STR);
        }
    } else {
        ctx->error_code = RPCERR_NOCONN;
        ctx->error_message = strdup(RPCERR_NOCONN_STR);
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
}


static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = cJSON_CreateObject();
    cJSON *result_svr = cJSON_CreateArray();
    cJSON *result_cli = cJSON_CreateArray();

    char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
    misc_bin2str(node_id, ln_node_id(&mNode), UCOIN_SZ_PUBKEY);
    cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(node_id));
    p2p_svr_show_self(result_svr);
    cJSON_AddItemToObject(result, "server", result_svr);
    p2p_cli_show_self(result_cli);
    cJSON_AddItemToObject(result, "client", result_cli);

    return result;
}


static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    SYSLOG_INFO("stop");
    p2p_svr_stop_all();
    p2p_cli_stop_all();
    jrpc_server_stop(&mJrpc);

    mMonitoring = false;

    return cJSON_CreateString("OK");
}


static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    const char *ret;
    char str[10];
    cJSON *json;

    json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_Number)) {
        lnapp_set_debug(json->valueint);
        sprintf(str, "%d", json->valueint);
        ret = str;
    } else {
        ret = "NG";
    }

    return cJSON_CreateString(ret);
}


static lnapp_conf_t *search_connected_lnapp_node(const uint8_t *p_node_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_cli_search_node(p_node_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_node(p_node_id);
    }
    return p_appconf;
}


static lnapp_conf_t *search_connected_lnapp_cnl(uint64_t short_channel_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_cli_search_short_channel_id(short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_short_channel_id(short_channel_id);
    }
    return p_appconf;
}


/**************************************************************************
 * private functions: monitoring all channels
 **************************************************************************/

static void *thread_monitor_start(void *pArg)
{
    (void)pArg;

    ln_db_search_channel(monfunc, NULL);

    while (mMonitoring) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < M_WAIT_MON_SEC; lp++) {
            sleep(1);
            if (!mMonitoring) {
                break;
            }
        }

        ln_db_search_channel(monfunc, NULL);
    }
    DBG_PRINTF("stop\n");

    return NULL;
}


static bool monfunc(ln_self_t *self, void *p_param)
{
    (void)p_param;


    uint32_t confm = jsonrpc_get_confirmation(ln_funding_txid(self));
    if (confm > 0) {
        DBG_PRINTF("funding_txid[conf=%u, idx=%d]: ", confm, self->funding_local.txindex);
        DUMPTXID(self->funding_local.txid);

        bool del = false;
        uint64_t sat;
        bool ret = jsonrpc_getxout(&sat, ln_funding_txid(self), ln_funding_txindex(self));
        if (!ret) {
            //gettxoutはunspentを返すので、取得失敗→unilateral close/revoked transaction closeとみなす
            if (ln_is_closing_signed_recvd(self)) {
                //BOLT#5
                //  Otherwise, if the node has received a valid closing_signed message with high enough fee level, it SHOULD use that to perform a mutual close.
                //  https://github.com/lightningnetwork/lightning-rfc/blob/master/05-onchain.md#requirements-1
                DBG_PRINTF("close after closing_signed\n");
                del = true;
            } else {
                //展開されているのが最新のcommit_txか
                ret = jsonrpc_getxout(&sat, self->commit_local.txid, 0);
                if (!ret) {
                    //最新のcommit_tx --> unilateral close
                    SYSLOG_WARN("closed: bad way\n");
                } else {
                    //最新ではないcommit_tx --> revoked transaction close
                    SYSLOG_WARN("closed: ugly way\n");
                }
            }
        }
        if (del) {
            //最後にDBからチャネルを削除
            ret = ln_db_del_channel(self);
            assert(ret);
        }
   }

    return false;
}
