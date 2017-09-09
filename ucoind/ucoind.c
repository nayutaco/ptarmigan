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


/********************************************************************
 * static variables
 ********************************************************************/

static ln_node_t    mNode;
static struct jrpc_server   mJrpc;


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
static lnapp_conf_t *search_connected_lnapp(const uint8_t *p_node_id);


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

        ucoin_term();
        return 0;
    }

    //syslog
    openlog("ucoind", LOG_CONS, LOG_USER);

    rpc_conf_t rpc_conf;
    node_conf_t node_conf;
    bool bret = load_node_conf(argv[1], &node_conf, &rpc_conf);
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

    if ((argc == 3) && (strcmp(argv[2], "id") == 0)) {
        ucoin_util_keys_t keys;
        ucoin_util_wif2keys(&keys, node_conf.wif);
        ucoin_util_dumpbin(stdout, keys.pub, UCOIN_SZ_PUBKEY, true);

        ucoin_term();
        return 0;
    }

    p2p_cli_init();
    jsonrpc_init(&rpc_conf);

    //bitcoind起動確認
    int count = jsonrpc_getblockcount();
    if (count == -1) {
        DBG_PRINTF("fail: bitcoin getblockcount(maybe cannot connect bitcoind)\n");
        return -1;
    }

    //node情報読込み
    ln_node_init(&mNode, node_conf.wif, node_conf.name, 0);
    ln_print_node(&mNode);
    lnapp_init(&mNode);

    //接続待ち受け用
    pthread_t th_svr;
    pthread_create(&th_svr, NULL, &p2p_svr_start, &node_conf.port);

#if NETKIND==0
    SYSLOG_INFO("start bitcoin mainnet");
#elif NETKIND==1
    SYSLOG_INFO("start bitcoin testnet");
#endif

    //ucoincli受信用
    msg_recv(node_conf.port + 1);

    //待ち合わせ
    pthread_join(th_svr, NULL);
    //pthread_join(th_fu, NULL);
    DBG_PRINTF("%s exit\n", argv[0]);

    SYSLOG_INFO("end");

    ln_db_term();

    return 0;

LABEL_EXIT:
    fprintf(PRINTOUT, "[usage]\n\t%s <node.conf>\n\n", argv[0]);
    return -1;
}


bool pay_forward(const ln_cb_add_htlc_recv_t *p_add, uint64_t prev_short_channel_id)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", p_add->p_hop->short_channel_id);

    //socketが開いているか検索
    p_appconf = p2p_cli_search_short_channel_id(p_add->p_hop->short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_short_channel_id(p_add->p_hop->short_channel_id);
    }
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_payment_forward(p_appconf, p_add, prev_short_channel_id);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


bool fulfill_backward(const ln_cb_fulfill_htlc_recv_t *pFulFill)
{
    bool ret = false;
    lnapp_conf_t *p_appconf;

    DBG_PRINTF("  search short_channel_id : %" PRIx64 "\n", pFulFill->prev_short_channel_id);

    //socketが開いているか検索
    p_appconf = p2p_cli_search_short_channel_id(pFulFill->prev_short_channel_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_short_channel_id(pFulFill->prev_short_channel_id);
    }
    if (p_appconf != NULL) {
        DBG_PRINTF("AppConf found\n");
        ret = lnapp_fulfill_backward(p_appconf, pFulFill);
    } else {
        DBG_PRINTF("AppConf not found...\n");
    }

    return ret;
}


/********************************************************************
 * private functions
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
        Index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, Index++);
    if (json && (json->type == cJSON_String)) {
        strcpy(pConn->ipaddr, json->valuestring);
        DBG_PRINTF("pConn->ipaddr=%s\n", json->valuestring);
    } else {
        Index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, Index++);
    if (json && (json->type == cJSON_Number)) {
        pConn->port = json->valueint;
        DBG_PRINTF("pConn->port=%d\n", json->valueint);
    } else {
        Index = -1;
    }

LABEL_EXIT:
    return Index;
}


static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    cJSON *json;
    daemon_connect_t conn;
    funding_conf_t *p_fundconf = (funding_conf_t *)malloc(sizeof(funding_conf_t));
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

    p2p_cli_start(DCMD_CREATE, &conn, p_fundconf, ln_node_id(&mNode), ctx);
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

    lnapp_conf_t *p_appconf = search_connected_lnapp(conn.node_id);
    if (p_appconf == NULL) {
        p2p_cli_start(DCMD_CONNECT, &conn, NULL, ln_node_id(&mNode), ctx);
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

    lnapp_conf_t *p_appconf = search_connected_lnapp(conn.node_id);
    if (p_appconf != NULL) {
        bool ret = lnapp_close_channel(p_appconf);
        if (ret) {
            result = cJSON_CreateString("OK");
        } else {
            ctx->error_code = RPCERR_CLOSE_HTLC;
            ctx->error_message = strdup(RPCERR_CLOSE_HTLC_STR);
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


static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    cJSON *json;
    daemon_connect_t conn;
    uint64_t amount;
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

    lnapp_conf_t *p_appconf = search_connected_lnapp(conn.node_id);
    if (p_appconf != NULL) {
        result = cJSON_CreateObject();
        lnapp_add_preimage(p_appconf, amount, result);
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


static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
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

    lnapp_conf_t *p_appconf = search_connected_lnapp(conn.node_id);
    if (p_appconf != NULL) {
        result = cJSON_CreateArray();
        lnapp_show_payment_hash(p_appconf, result);
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


static cJSON *cmd_pay(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    cJSON *json;
    daemon_connect_t conn;
    payment_conf_t payconf;
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
                p->outgoing_cltv_value = jprm->valueint;
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

    lnapp_conf_t *p_appconf = search_connected_lnapp(payconf.hop_datain[1].pubkey);
    if (p_appconf != NULL) {
        bool ret = lnapp_payment(p_appconf, &payconf);
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
    SYSLOG_INFO("stop");
    p2p_svr_stop_all();
    p2p_cli_stop_all();
    jrpc_server_stop(&mJrpc);

    return cJSON_CreateString("OK");
}


static lnapp_conf_t *search_connected_lnapp(const uint8_t *p_node_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_cli_search_node(p_node_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_node(p_node_id);
    }
    return p_appconf;
}
