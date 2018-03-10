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
/** @file   cmd_json.c
 *  @brief  ucoind JSON-RPC process
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <assert.h>

#include "jsonrpc-c.h"
#include "cmd_json.h"

#include "ln_db.h"
#include "btcrpc.h"

#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "monitoring.h"
#include "ln_db_lmdb.h"
#include "segwit_addr.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_SZ_JSONSTR            (8192)


/********************************************************************
 * static variables
 ********************************************************************/

static struct jrpc_server   mJrpc;

static const char *kOK = "OK";
static const char *kNG = "NG";


/********************************************************************
 * prototypes
 ********************************************************************/

static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_connect(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_disconnect(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_eraseinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_pay(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_disautoconn(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_removechannel(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id);
static lnapp_conf_t *search_connected_lnapp_node(const uint8_t *p_node_id);


/********************************************************************
 * public functions
 ********************************************************************/

void cmd_json_start(uint16_t Port)
{
    jrpc_server_init(&mJrpc, Port);
    jrpc_register_procedure(&mJrpc, cmd_fund,        "fund", NULL);
    jrpc_register_procedure(&mJrpc, cmd_connect,     "connect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disconnect,  "disconnect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_close,       "close", NULL);
    jrpc_register_procedure(&mJrpc, cmd_invoice,     "invoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_eraseinvoice,"eraseinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_listinvoice, "listinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_pay,         "pay", NULL);
    jrpc_register_procedure(&mJrpc, cmd_routepay,    "routepay", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getinfo,     "getinfo", NULL);
    jrpc_register_procedure(&mJrpc, cmd_stop,        "stop", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getlasterror,"getlasterror", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disautoconn, "disautoconn", NULL);
    jrpc_register_procedure(&mJrpc, cmd_removechannel,"removechannel", NULL);
    jrpc_register_procedure(&mJrpc, cmd_debug,       "debug", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getcommittx, "getcommittx", NULL);
    jrpc_server_run(&mJrpc);
    jrpc_server_destroy(&mJrpc);
}


uint16_t cmd_json_get_port(void)
{
    return (uint16_t)mJrpc.port_number;
}


/********************************************************************
 * private functions
 ********************************************************************/

static int json_connect(cJSON *params, int Index, daemon_connect_t *pConn)
{
    cJSON *json;

    //peer_nodeid, peer_addr, peer_port
    json = cJSON_GetArrayItem(params, Index++);
    if (json && (json->type == cJSON_String)) {
        bool ret = misc_str2bin(pConn->node_id, UCOIN_SZ_PUBKEY, json->valuestring);
        if (ret) {
            DBG_PRINTF("pConn->node_id=%s\n", json->valuestring);
        } else {
            DBG_PRINTF("fail: invalid node_id string\n");
            Index = -1;
            goto LABEL_EXIT;
        }
    } else {
        DBG_PRINTF("fail: node_id\n");
        Index = -1;
        goto LABEL_EXIT;
    }
    if (memcmp(ucoind_nodeid(), pConn->node_id, UCOIN_SZ_PUBKEY) == 0) {
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
    funding_conf_t fundconf;
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

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(conn.node_id);
    if (p_appconf == NULL) {
        //未接続
        ctx->error_code = RPCERR_NOCONN;
        ctx->error_message = strdup(RPCERR_NOCONN_STR);
        goto LABEL_EXIT;
    }

    bool haveCnl = ln_node_search_channel(NULL, conn.node_id);
    if (haveCnl) {
        //開設しようとしてチャネルが開いている
        ctx->error_code = RPCERR_ALOPEN;
        ctx->error_message = strdup(RPCERR_ALOPEN_STR);
        goto LABEL_EXIT;
    }

    bool is_funding = ln_is_funding(p_appconf->p_self);
    if (is_funding) {
        //開設しようとしてチャネルが開設中
        ctx->error_code = RPCERR_OPENING;
        ctx->error_message = strdup(RPCERR_OPENING_STR);
        goto LABEL_EXIT;
    }

    bool inited = lnapp_is_inited(p_appconf);
    if (!inited) {
        //BOLTメッセージとして初期化が完了していない(init/channel_reestablish交換できていない)
        ctx->error_code = RPCERR_NOINIT;
        ctx->error_message = strdup(RPCERR_NOINIT_STR);
        goto LABEL_EXIT;
    }

    //txid, txindex, signaddr, funding_sat, push_sat

    //txid
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        misc_str2bin_rev(fundconf.txid, UCOIN_SZ_TXID, json->valuestring);
        DBG_PRINTF("txid=%s\n", json->valuestring);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //txindex
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.txindex = json->valueint;
        DBG_PRINTF("txindex=%d\n", json->valueint);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //signaddr
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        strcpy(fundconf.signaddr, json->valuestring);
        DBG_PRINTF("signaddr=%s\n", json->valuestring);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //funding_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.funding_sat = json->valueu64;
        DBG_PRINTF("funding_sat=%" PRIu64 "\n", fundconf.funding_sat);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //push_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.push_sat = json->valueu64;
        DBG_PRINTF("push_sat=%" PRIu64 "\n", fundconf.push_sat);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //feerate_per_kw
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.feerate_per_kw = (uint32_t)json->valueu64;
        DBG_PRINTF("feerate_per_kw=%" PRIu32 "\n", fundconf.feerate_per_kw);
    } else {
        //スルー
    }

    print_funding_conf(&fundconf);

    SYSLOG_INFO("fund");

    bool ret = lnapp_funding(p_appconf, &fundconf);
    if (ret) {
        result = cJSON_CreateObject();
        cJSON_AddItemToObject(result, "status", cJSON_CreateString("Progressing"));
        cJSON_AddItemToObject(result, "feerate_per_kw", cJSON_CreateNumber64(ln_feerate(p_appconf->p_self)));
    } else {
        ctx->error_code = RPCERR_FUNDING;
        ctx->error_message = strdup(RPCERR_FUNDING_STR);
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
        p2p_cli_start(&conn, ctx);
        if (ctx->error_code == 0) {
            result = cJSON_CreateString(kOK);
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


static cJSON *cmd_disconnect(jrpc_context *ctx, cJSON *params, cJSON *id)
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

    SYSLOG_INFO("disconnect");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(conn.node_id);
    if (p_appconf != NULL) {
        lnapp_stop(p_appconf);
        result = cJSON_CreateString(kOK);
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
    if ((p_appconf != NULL) && (ln_htlc_num(p_appconf->p_self) == 0)) {
        //接続中
        bool ret = lnapp_close_channel(p_appconf);
        if (ret) {
            result = cJSON_CreateString("Progressing");
        } else {
            ctx->error_code = RPCERR_CLOSE_START;
            ctx->error_message = strdup(RPCERR_CLOSE_START_STR);
        }
    } else {
        //未接続
        bool haveCnl = ln_node_search_channel(NULL, conn.node_id);
        if (haveCnl) {
            //チャネルあり
            //  相手とのチャネルがあるので、接続自体は可能かもしれない。
            //  closeの仕方については、仕様や運用とも関係が深いので、後で変更することになるだろう。
            //  今は、未接続の場合は mutual close以外で閉じることにする。
            DBG_PRINTF("チャネルはあるが接続していない\n");
            bool ret = lnapp_close_channel_force(conn.node_id);
            if (ret) {
                result = cJSON_CreateString("unilateral close");
                DBG_PRINTF("force closed\n");
            } else {
                DBG_PRINTF("fail: force close\n");
                ctx->error_code = RPCERR_CLOSE_FAIL;
                ctx->error_message = strdup(RPCERR_CLOSE_FAIL_STR);
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
    uint64_t amount = 0;
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
    ucoind_preimage_lock();

    uint8_t preimage[LN_SZ_PREIMAGE];
    uint8_t preimage_hash[LN_SZ_HASH];
    char str_hash[LN_SZ_HASH * 2 + 1];

    ucoin_util_random(preimage, LN_SZ_PREIMAGE);
    ln_db_preimg_save(preimage, amount, NULL);
    ln_calc_preimage_hash(preimage_hash, preimage);

    misc_bin2str(str_hash, preimage_hash, LN_SZ_HASH);
    DBG_PRINTF("preimage=")
    DUMPBIN(preimage, LN_SZ_PREIMAGE);
    DBG_PRINTF("hash=")
    DUMPBIN(preimage_hash, LN_SZ_HASH);
    cJSON_AddItemToObject(result, "hash", cJSON_CreateString(str_hash));
    cJSON_AddItemToObject(result, "amount", cJSON_CreateNumber64(amount));
    ucoind_preimage_unlock();

    const ucoin_util_keys_t *p_keys = ucoind_nodekeys();
    ln_invoice_t invoice_data;
#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    invoice_data.hrp_type = LN_INVOICE_MAINNET;
#elif NETKIND==1
    invoice_data.hrp_type = LN_INVOICE_TESTNET;
#endif
    invoice_data.amount_msat = amount;
    invoice_data.min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    memcpy(invoice_data.pubkey, p_keys->pub, UCOIN_SZ_PUBKEY);
    memcpy(invoice_data.payment_hash, preimage_hash, LN_SZ_HASH);
    char *p_invoice = NULL;
    bool ret = ln_invoice_encode(&p_invoice, &invoice_data, p_keys->priv);
    if (ret) {
        cJSON_AddItemToObject(result, "bolt11", cJSON_CreateString(p_invoice));
    } else {
        DBG_PRINTF("fail: BOLT11 format\n");
    }
    free(p_invoice);

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
}


static cJSON *cmd_eraseinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON *json;
    cJSON *result = NULL;
    uint8_t preimage_hash[LN_SZ_HASH];
    int index = 0;
    bool ret;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if ((json == NULL) || (json->type != cJSON_String)) {
        index = -1;
        goto LABEL_EXIT;
    }
    if (strlen(json->valuestring) > 0) {
        DBG_PRINTF("erase hash: %s\n", json->valuestring);
        misc_str2bin(preimage_hash, sizeof(preimage_hash), json->valuestring);
        ret = ln_db_preimg_del_hash(preimage_hash);
    } else {
        ret = ln_db_preimg_del(NULL);
    }
    if (ret) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = RPCERR_INVOICE_ERASE;
        ctx->error_message = strdup(RPCERR_INVOICE_ERASE_STR);
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
    (void)id;

    cJSON *result = NULL;
    int index = 0;
    uint8_t preimage[LN_SZ_PREIMAGE];
    uint8_t preimage_hash[LN_SZ_HASH];
    uint64_t amount;
    void *p_cur;
    bool ret;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    result = cJSON_CreateArray();
    ret = ln_db_preimg_cur_open(&p_cur);
    while (ret) {
        ret = ln_db_preimg_cur_get(p_cur, preimage, &amount);
        if (ret) {
            ln_calc_preimage_hash(preimage_hash, preimage);
            cJSON *json = cJSON_CreateArray();

            char str_hash[LN_SZ_HASH * 2 + 1];
            misc_bin2str(str_hash, preimage_hash, LN_SZ_HASH);
            cJSON_AddItemToArray(json, cJSON_CreateString(str_hash));
            cJSON_AddItemToArray(json, cJSON_CreateNumber64(amount));
            cJSON_AddItemToArray(result, json);
        }
    }
    ln_db_preimg_cur_close(p_cur);

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
    int blockcnt = btcprc_getblockcount();
    DBG_PRINTF("blockcnt=%d\n", blockcnt);
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
                DBG_PRINTF("  outgoing_cltv_value=%u\n", p->outgoing_cltv_value);
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

        bool inited = lnapp_is_inited(p_appconf);
        if (inited) {
            bool ret;
            ret = lnapp_payment(p_appconf, &payconf);
            if (ret) {
                result = cJSON_CreateString("Progressing");
            } else {
                ctx->error_code = RPCERR_PAY_STOP;
                ctx->error_message = strdup(RPCERR_PAY_STOP_STR);
            }
        } else {
            //BOLTメッセージとして初期化が完了していない(init/channel_reestablish交換できていない)
            ctx->error_code = RPCERR_NOINIT;
            ctx->error_message = strdup(RPCERR_NOINIT_STR);
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
    if (ctx->error_code != 0) {
        ln_db_annoskip_invoice_del(payconf.payment_hash);
    }
    return result;
}


static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON *json;
    cJSON *result = NULL;
    int index = 0;
    char str_payhash[2 * LN_SZ_HASH + 1];
    char str_payee[2 * UCOIN_SZ_PUBKEY + 1];
    char str_payer[2 * UCOIN_SZ_PUBKEY + 1];
    uint64_t amount_msat = 0;
    uint32_t min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    uint8_t payhash[LN_SZ_HASH];

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //str_payhash, amount_msat, str_payee, str_payer
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        strcpy(str_payhash, json->valuestring);
        DBG_PRINTF("str_payhash=%s\n", str_payhash);
        misc_str2bin(payhash, LN_SZ_HASH, str_payhash);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        amount_msat = json->valueu64;
        DBG_PRINTF("  amount_msat=%" PRIu64 "\n", amount_msat);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        strcpy(str_payee, json->valuestring);
        DBG_PRINTF("str_payee=%s\n", str_payee);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        if (strlen(json->valuestring) > 0) {
            strcpy(str_payer, json->valuestring);
        } else {
            //自分をpayerにする
            misc_bin2str(str_payer, ucoind_nodeid(), UCOIN_SZ_PUBKEY);
        }
        DBG_PRINTF("str_payer=%s\n", str_payer);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        min_final_cltv_expiry = (uint32_t)json->valueu64;
    }
    DBG_PRINTF("  min_final_cltv_expiry=%" PRIu32 "\n", min_final_cltv_expiry);

    SYSLOG_INFO("routepay");

    // execute `routing` command
    char cmd[512];
    sprintf(cmd, "%srouting -s %s -r %s -a %" PRIu64 " -e %d -p %s -j\n",
                ucoind_get_exec_path(),
                str_payer,      // -s
                str_payee,      // -r
                amount_msat,    // -a
                min_final_cltv_expiry,  // -e
                str_payhash);           // -p
    //DBG_PRINTF("cmd=%s\n", cmd);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        DBG_PRINTF("fail: popen(%s)\n", strerror(errno));
        ctx->error_code = RPCERR_ERROR;
        ctx->error_message = strdup(RPCERR_ERROR_STR);
        goto LABEL_EXIT;
    }
    char *p_route = (char *)APP_MALLOC(M_SZ_JSONSTR);
    p_route[0] = '\0';
    char *p_tmp = p_route;
    while (!feof(fp)) {
        fgets(p_tmp, M_SZ_JSONSTR, fp);
        p_tmp += strlen(p_tmp);
    }
    pclose(fp);
    if (strlen(p_route) > 0) {
        //再送のためにinvoice保存
        char *p_invoice = cJSON_PrintUnformatted(params);
        (void)ln_db_annoskip_invoice_save(p_invoice, payhash);
        free(p_invoice);

        DBG_PRINTF("---------------\n");
        DBG_PRINTF2("%s", p_route);
        DBG_PRINTF("---------------\n");
        int retval = misc_sendjson(p_route, "127.0.0.1", cmd_json_get_port());
        if (retval == 0) {
            //payment完了待ち
            result = cJSON_CreateString("Progressing");
        } else {
            DBG_PRINTF("retval=%d\n", retval);
            ctx->error_code = RPCERR_ERROR;
            ctx->error_message = strdup(RPCERR_ERROR_STR);
        }
    } else {
        ln_db_annoskip_invoice_del(payhash);

        ctx->error_code = RPCERR_NOROUTE;
        ctx->error_message = strdup(RPCERR_NOROUTE_STR);
    }
    APP_FREE(p_route);

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
    misc_bin2str(node_id, ucoind_nodeid(), UCOIN_SZ_PUBKEY);
    cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(node_id));
    cJSON_AddItemToObject(result, "node_port", cJSON_CreateNumber(ucoind_nodeport()));
    cJSON_AddItemToObject(result, "jsonrpc_port", cJSON_CreateNumber(cmd_json_get_port()));
    uint8_t *p_hash;
    int cnt = ln_db_annoskip_invoice_get(&p_hash);
    if (cnt > 0) {
        cJSON *result_hash = cJSON_CreateArray();
        uint8_t *p = p_hash;
        for (int lp = 0; lp < cnt; lp++) {
            char hash_str[LN_SZ_HASH * 2 + 1];
            misc_bin2str(hash_str, p, LN_SZ_HASH);
            p += LN_SZ_HASH;
            cJSON_AddItemToArray(result_hash, cJSON_CreateString(hash_str));
        }
        free(p_hash);       //ln_lmdbでmalloc/realloc()している
        cJSON_AddItemToObject(result, "paying_hash", result_hash);
    }
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

    monitor_stop();

    return cJSON_CreateString("OK");
}


static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    daemon_connect_t conn;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //connect parameter
    index = json_connect(params, index, &conn);
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
        goto LABEL_EXIT;
    }

    SYSLOG_INFO("getlasterror");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(conn.node_id);
    if (p_appconf != NULL) {
        //接続中
        DBG_PRINTF("error code: %d\n", p_appconf->err);
        ctx->error_code = p_appconf->err;
        if (p_appconf->p_errstr != NULL) {
            DBG_PRINTF("error msg: %s\n", p_appconf->p_errstr);
            ctx->error_message = p_appconf->p_errstr;
        }
    } else {
        ctx->error_code = RPCERR_NOCONN;
        ctx->error_message = strdup(RPCERR_NOCONN_STR);
    }

LABEL_EXIT:
    return NULL;
}


static cJSON *cmd_disautoconn(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    const char *p_str = NULL;

    cJSON *json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_String)) {
        if (json->valuestring[0] == '1') {
            monitor_disable_autoconn(true);
            p_str = "disable auto connect";
        } else if (json->valuestring[0] == '0') {
            monitor_disable_autoconn(false);
            p_str = "enable auto connect";
        } else {
            //none
        }
    }
    if (p_str != NULL) {
        return cJSON_CreateString(p_str);
    } else {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
        return NULL;
    }
}


static cJSON *cmd_removechannel(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    bool ret = false;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];

    cJSON *json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_String)) {
        misc_str2bin(channel_id, sizeof(channel_id), json->valuestring);
        ret = ln_db_self_del(channel_id);
    }
    if (ret) {
        return cJSON_CreateString(kOK);
    } else {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
        return NULL;
    }
}


static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    const char *ret;
    char str[10];
    cJSON *json;

    json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_Number)) {
        unsigned long dbg = ln_get_debug() ^ json->valueint;
        ln_set_debug(dbg);
        sprintf(str, "%08lx", dbg);
        if (!LN_DBG_FULFILL()) {
            DBG_PRINTF("no fulfill return\n");
        }
        if (!LN_DBG_CLOSING_TX()) {
            DBG_PRINTF("no closing tx\n");
        }
        if (!LN_DBG_MATCH_PREIMAGE()) {
            DBG_PRINTF("force preimage mismatch\n");
        }
        if (!LN_DBG_NODE_AUTO_CONNECT()) {
            DBG_PRINTF("no node Auto connect\n");
        }
        ret = str;
    } else {
        ret = kNG;
    }

    return cJSON_CreateString(ret);
}


static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id)
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

    SYSLOG_INFO("getcommittx");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(conn.node_id);
    if (p_appconf != NULL) {
        //接続中
        result = cJSON_CreateObject();
        bool ret = lnapp_get_committx(p_appconf, result);
        if (!ret) {
            ctx->error_code = RPCERR_ERROR;
            ctx->error_message = strdup(RPCERR_ERROR_STR);
        }
    } else {
        //未接続
        ctx->error_code = RPCERR_NOCHANN;
        ctx->error_message = strdup(RPCERR_NOCHANN_STR);
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = strdup(RPCERR_PARSE_STR);
    }
    return result;
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
