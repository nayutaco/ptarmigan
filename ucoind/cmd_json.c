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
#include "segwit_addr.h"

#include "cmd_json.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"
#include "btcrpc.h"

#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "monitoring.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_SZ_JSONSTR            (8192)
#define M_SZ_PAYERR             (128)

#define M_RETRY_CONN_CHK        (10)        ///< 接続チェック[sec]


/********************************************************************
 * static variables
 ********************************************************************/

static struct jrpc_server   mJrpc;
static char                 mLastPayErr[M_SZ_PAYERR];       //最後に送金エラーが発生した時刻
static int                  mPayTryCount = 0;               //送金トライ回数

static const char *kOK = "OK";


/********************************************************************
 * prototypes
 ********************************************************************/

static cJSON *cmd_connect(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_disconnect(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_eraseinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_pay(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_routepay_first(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_disautoconn(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_removechannel(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_setfeerate(jrpc_context *ctx, cJSON *params, cJSON *id);

static int cmd_connect_proc(const daemon_connect_t *pConn, jrpc_context *ctx);
static int cmd_disconnect_proc(const uint8_t *pNodeId);
static int cmd_stop_proc(void);
static int cmd_fund_proc(const uint8_t *pNodeId, const funding_conf_t *pFund);
static int cmd_invoice_proc(uint8_t *pPayHash, uint64_t AmountMsat);
static int cmd_eraseinvoice_proc(const uint8_t *pPayHash);
static int cmd_routepay_proc1(
                ln_invoice_t **ppInvoiceData,
                ln_routing_result_t *pRouteResult,
                const char *pInvoice, uint64_t AddAmountMsat);
static int cmd_routepay_proc2(
                const ln_invoice_t *pInvoiceData,
                const ln_routing_result_t *pRouteResult,
                const char *pInvoiceStr, uint64_t AddAmountMsat);
static int cmd_close_proc(bool *bMutual, const uint8_t *pNodeId);

static bool json_connect(cJSON *params, int *pIndex, daemon_connect_t *pConn);
static char *create_bolt11(const uint8_t *pPayHash, uint64_t Amount);
static lnapp_conf_t *search_connected_lnapp_node(const uint8_t *p_node_id);


/********************************************************************
 * public functions
 ********************************************************************/

void cmd_json_start(uint16_t Port)
{
    jrpc_server_init(&mJrpc, Port);
    jrpc_register_procedure(&mJrpc, cmd_connect,     "connect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getinfo,     "getinfo", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disconnect,  "disconnect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_stop,        "stop", NULL);
    jrpc_register_procedure(&mJrpc, cmd_fund,        "fund", NULL);
    jrpc_register_procedure(&mJrpc, cmd_invoice,     "invoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_eraseinvoice,"eraseinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_listinvoice, "listinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_pay,         "PAY", NULL);
    jrpc_register_procedure(&mJrpc, cmd_routepay_first, "routepay", NULL);
    jrpc_register_procedure(&mJrpc, cmd_routepay,    "routepay_cont", NULL);
    jrpc_register_procedure(&mJrpc, cmd_close,       "close", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getlasterror,"getlasterror", NULL);
    jrpc_register_procedure(&mJrpc, cmd_debug,       "debug", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getcommittx, "getcommittx", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disautoconn, "disautoconn", NULL);
    jrpc_register_procedure(&mJrpc, cmd_removechannel,"removechannel", NULL);
    jrpc_register_procedure(&mJrpc, cmd_setfeerate,   "setfeerate", NULL);
    jrpc_server_run(&mJrpc);
    jrpc_server_destroy(&mJrpc);
}


uint16_t cmd_json_get_port(void)
{
    return (uint16_t)mJrpc.port_number;
}


void cmd_json_pay_retry(const uint8_t *pPayHash, const char *pInvoice, uint64_t AddAmountMsat)
{
    bool ret;
    char *p_invoice;
    if (pInvoice == NULL) {
        ret = ln_db_invoice_load(&p_invoice, &AddAmountMsat, pPayHash);     //p_invoiceはmalloc()される
    } else {
        p_invoice = (char *)pInvoice;   //constはずし
        ret = true;
    }
    if (ret) {
        DBG_PRINTF("invoice:%s\n", p_invoice);
        char *json = (char *)APP_MALLOC(M_SZ_JSONSTR);      //APP_FREE: この中
        snprintf(json, M_SZ_JSONSTR,
            "{\"method\":\"routepay_cont\",\"params\":[\"%s\",%" PRIu64 "]}", p_invoice, AddAmountMsat);
        int retval = misc_sendjson(json, "127.0.0.1", cmd_json_get_port());
        DBG_PRINTF("retval=%d\n", retval);
        APP_FREE(json);     //APP_MALLOC: この中
    } else {
        DBG_PRINTF("fail: invoice not found\n");
    }
    if (pInvoice == NULL) {
        free(p_invoice);
    }
}


/********************************************************************
 * private functions : JSON-RPC
 ********************************************************************/

/** 接続 : ucoincli -c
 *
 */
static cJSON *cmd_connect(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    daemon_connect_t conn;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    err = cmd_connect_proc(&conn, ctx);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    }
    return result;
}


/** 状態出力 : ucoincli -l
 *
 */
static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = cJSON_CreateObject();
    cJSON *result_peer = cJSON_CreateArray();

    uint64_t amount = ln_node_total_msat();

    //basic info
    char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
    ucoin_util_bin2str(node_id, ln_node_getid(), UCOIN_SZ_PUBKEY);
    cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(node_id));
    cJSON_AddItemToObject(result, "node_port", cJSON_CreateNumber(ln_node_addr()->port));
    cJSON_AddItemToObject(result, "jsonrpc_port", cJSON_CreateNumber(cmd_json_get_port()));
    cJSON_AddNumber64ToObject(result, "total_our_msat", amount);

    //peer info
    p2p_svr_show_self(result_peer);
    p2p_cli_show_self(result_peer);
    cJSON_AddItemToObject(result, "peers", result_peer);

    //payment info
    uint8_t *p_hash;
    int cnt = ln_db_invoice_get(&p_hash);
    if (cnt > 0) {
        cJSON *result_hash = cJSON_CreateArray();
        uint8_t *p = p_hash;
        for (int lp = 0; lp < cnt; lp++) {
            char hash_str[LN_SZ_HASH * 2 + 1];
            ucoin_util_bin2str(hash_str, p, LN_SZ_HASH);
            p += LN_SZ_HASH;
            cJSON_AddItemToArray(result_hash, cJSON_CreateString(hash_str));
        }
        free(p_hash);       //ln_lmdbでmalloc/realloc()している
        cJSON_AddItemToObject(result, "paying_hash", result_hash);
    }
    cJSON_AddItemToObject(result, "last_errpay_date", cJSON_CreateString(mLastPayErr));

    return result;
}


/** 指定channel切断 : ucoincli -q xxxxx
 *
 */
static cJSON *cmd_disconnect(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    daemon_connect_t conn;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    err = cmd_disconnect_proc(conn.node_id);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    }
    return result;
}


/** ノード終了 : ucoincli -q
 *
 */
static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = NULL;

    int err = cmd_stop_proc();
    if (err == 0) {
        result = cJSON_CreateString("OK");
    } else {
        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    }
    jrpc_server_stop(&mJrpc);

    return result;
}


/** channel establish開始 : ucoincli -f
 *
 */
static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    cJSON *json;
    daemon_connect_t conn;
    funding_conf_t fundconf;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    //funding parameter
    //txid
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        misc_str2bin_rev(fundconf.txid, UCOIN_SZ_TXID, json->valuestring);
        DBG_PRINTF("txid=%s\n", json->valuestring);
    } else {
        goto LABEL_EXIT;
    }
    //txindex
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.txindex = json->valueint;
        DBG_PRINTF("txindex=%d\n", json->valueint);
    } else {
        goto LABEL_EXIT;
    }
    //signaddr
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        strcpy(fundconf.signaddr, json->valuestring);
        DBG_PRINTF("signaddr=%s\n", json->valuestring);
    } else {
        goto LABEL_EXIT;
    }
    //funding_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.funding_sat = json->valueu64;
        DBG_PRINTF("funding_sat=%" PRIu64 "\n", fundconf.funding_sat);
    } else {
        goto LABEL_EXIT;
    }
    //push_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.push_sat = json->valueu64;
        DBG_PRINTF("push_sat=%" PRIu64 "\n", fundconf.push_sat);
    } else {
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


    err = cmd_fund_proc(conn.node_id, &fundconf);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateObject();
        cJSON_AddItemToObject(result, "status", cJSON_CreateString("Progressing"));
    } else {
        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    }
    return result;
}


/** invoice作成 : ucoincli -i
 *
 */
static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    cJSON *json;
    uint64_t amount = 0;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        goto LABEL_EXIT;
    }

    //amount
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        amount = json->valueu64;
        DBG_PRINTF("amount=%" PRIu64 "\n", amount);
    } else {
        goto LABEL_EXIT;
    }

    uint8_t preimage_hash[LN_SZ_HASH];
    err = cmd_invoice_proc(preimage_hash, amount);

LABEL_EXIT:
    if (err == 0) {
        char *p_invoice = create_bolt11(preimage_hash, amount);

        if (p_invoice != NULL) {
            char str_hash[LN_SZ_HASH * 2 + 1];

            ucoin_util_bin2str(str_hash, preimage_hash, LN_SZ_HASH);
            result = cJSON_CreateObject();
            cJSON_AddItemToObject(result, "hash", cJSON_CreateString(str_hash));
            cJSON_AddItemToObject(result, "amount", cJSON_CreateNumber64(amount));
            cJSON_AddItemToObject(result, "bolt11", cJSON_CreateString(p_invoice));

            free(p_invoice);
        } else {
            DBG_PRINTF("fail: BOLT11 format\n");
            err = RPCERR_PARSE;
        }
    }
    if (err != 0) {
        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    }
    return result;
}


/** invice削除 : ucoincli -e
 *
 */
static cJSON *cmd_eraseinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    cJSON *json;
    cJSON *result = NULL;
    uint8_t preimage_hash[LN_SZ_HASH];
    int index = 0;

    if (params == NULL) {
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if ((json == NULL) || (json->type != cJSON_String)) {
        goto LABEL_EXIT;
    }
    if (strlen(json->valuestring) > 0) {
        DBG_PRINTF("erase hash: %s\n", json->valuestring);
        misc_str2bin(preimage_hash, sizeof(preimage_hash), json->valuestring);
        err = cmd_eraseinvoice_proc(preimage_hash);
    } else {
        err = cmd_eraseinvoice_proc(NULL);
    }

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    }
    return result;
}


/** invoice一覧出力 : ucoincli -m
 *
 */
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = NULL;
    uint8_t preimage[LN_SZ_PREIMAGE];
    uint8_t preimage_hash[LN_SZ_HASH];
    uint64_t amount;
    void *p_cur;
    bool ret;

    result = cJSON_CreateArray();
    ret = ln_db_preimg_cur_open(&p_cur);
    while (ret) {
        ret = ln_db_preimg_cur_get(p_cur, preimage, &amount);
        if (ret) {
            ln_calc_preimage_hash(preimage_hash, preimage);
            cJSON *json = cJSON_CreateArray();

            char str_hash[LN_SZ_HASH * 2 + 1];
            ucoin_util_bin2str(str_hash, preimage_hash, LN_SZ_HASH);
            cJSON_AddItemToArray(json, cJSON_CreateString(str_hash));
            cJSON_AddItemToArray(json, cJSON_CreateNumber64(amount));
            char *p_invoice = create_bolt11(preimage_hash, amount);
            if (p_invoice != NULL) {
                cJSON_AddItemToArray(json, cJSON_CreateString(p_invoice));
                free(p_invoice);
            }
            cJSON_AddItemToArray(result, json);
        }
    }
    ln_db_preimg_cur_close(p_cur);

    return result;
}


/** 送金開始(テスト用) : "PAY"
 *
 */
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
    int32_t blockcnt = btcrpc_getblockcount();
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

    DBG_PRINTF("payment\n");

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
                ctx->error_message = ucoind_error_str(RPCERR_PAY_STOP);
            }
        } else {
            //BOLTメッセージとして初期化が完了していない(init/channel_reestablish交換できていない)
            ctx->error_code = RPCERR_NOINIT;
            ctx->error_message = ucoind_error_str(RPCERR_NOINIT);
        }
    } else {
        ctx->error_code = RPCERR_NOCONN;
        ctx->error_message = ucoind_error_str(RPCERR_NOCONN);
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
    }
    if (ctx->error_code != 0) {
        ln_db_invoice_del(payconf.payment_hash);
        //一時的なスキップは削除する
        ln_db_annoskip_drop(true);
    }

    return result;
}


/** 送金開始: ucoincli -r / -R
 *
 * 一時ルーティング除外リストをクリアしてから送金する
 */
static cJSON *cmd_routepay_first(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    DBG_PRINTF("routepay_first\n");
    ln_db_annoskip_drop(true);
    mPayTryCount = 0;
    return cmd_routepay(ctx, params, id);
}


/** 送金・再送金: ucoincli -r / -R
 *
 */
static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    DBG_PRINTF("routepay\n");

    int err = RPCERR_PARSE;
    cJSON *result = NULL;
    bool retry = false;
    cJSON *json;
    int index = 0;

    char *p_invoice = NULL;
    uint64_t add_amount_msat = 0;

    ln_invoice_t *p_invoice_data = NULL;
    ln_routing_result_t rt_ret;

    if (params == NULL) {
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        p_invoice = strdup(json->valuestring);
    } else {
        DBG_PRINTF("fail: invalid invoice string\n");
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        add_amount_msat = json->valueu64;
    } else {
        DBG_PRINTF("fail: invalid add amount_msat\n");
        goto LABEL_EXIT;
    }

    err = cmd_routepay_proc1(&p_invoice_data, &rt_ret,
                    p_invoice, add_amount_msat);
    if (err != 0) {
        DBG_PRINTF("fail: pay1\n");
        goto LABEL_EXIT;
    }

    // 送金開始
    //      ここまでで送金ルートは作成済み
    //      これ以降は失敗してもリトライする
    DBG_PRINTF("routepay: pay1\n");
    retry = true;

    //再送のためにinvoice保存
    char *p_invoice_str = cJSON_PrintUnformatted(params);

    err = cmd_routepay_proc2(p_invoice_data, &rt_ret, p_invoice_str, add_amount_msat);
    if (err == RPCERR_PAY_RETRY) {
        //送金リトライ
        cmd_json_pay_retry(p_invoice_data->payment_hash, p_invoice_str, add_amount_msat);
        DBG_PRINTF("retry: %" PRIx64 "\n", rt_ret.hop_datain[0].short_channel_id);
    }
    free(p_invoice_str);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString("start payment");
    } else if (!retry) {
        //送金失敗
        ln_db_invoice_del(p_invoice_data->payment_hash);
        ln_db_annoskip_drop(true);

        //最後に失敗した時間
        char date[50];
        misc_datetime(date, sizeof(date));
        char str_payhash[LN_SZ_HASH * 2 + 1];
        ucoin_util_bin2str(str_payhash, p_invoice_data->payment_hash, LN_SZ_HASH);

        sprintf(mLastPayErr, "[%s]payment fail", date);
        DBG_PRINTF("%s\n", mLastPayErr);
        misc_save_event(NULL, "payment fail: payment_hash=%s try=%d", str_payhash, mPayTryCount);

        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    } else {
        //already processed
    }
    free(p_invoice_data);
    free(p_invoice);

    return result;
}


/** channel close開始 : ucoincli -x
 *
 */
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    daemon_connect_t conn;
    cJSON *result = NULL;
    int index = 0;
    bool b_mutual;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    err = cmd_close_proc(&b_mutual, conn.node_id);

LABEL_EXIT:
    if (err == 0) {
        const char *p_str;
        if (b_mutual) {
            p_str = "Start Mutual Close";
        } else {
            p_str = "Start Unilateral Close";
        }
        result = cJSON_CreateString(p_str);
    } else {
        ctx->error_code = err;
        ctx->error_message = ucoind_error_str(err);
    }

    return result;
}


/** 最後に発生したエラー出力 : ucoincli -w
 *
 */
static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    daemon_connect_t conn;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
        goto LABEL_EXIT;
    }

    DBG_PRINTF("getlasterror\n");

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
        ctx->error_message = ucoind_error_str(RPCERR_NOCONN);
    }

LABEL_EXIT:
    return NULL;
}


/** デバッグフラグのトグル : ucoincli -d
 *
 */
static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    cJSON *result = NULL;
    char str[10];
    cJSON *json;

    if (params == NULL) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_Number)) {
        result = cJSON_CreateObject();

        sprintf(str, "%08lx", ln_get_debug());
        cJSON_AddItemToObject(result, "old", cJSON_CreateString(str));

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
        cJSON_AddItemToObject(result, "new", cJSON_CreateString(str));
    } else {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
    }

LABEL_EXIT:
    return result;
}


/** commitment transaction出力 : ucoincli -g
 *
 * commitment transactionおよび関連するtransactionを16進数文字列出力する。
 */
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    daemon_connect_t conn;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    DBG_PRINTF("getcommittx\n");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(conn.node_id);
    if (p_appconf != NULL) {
        //接続中
        result = cJSON_CreateObject();
        bool ret = lnapp_get_committx(p_appconf, result);
        if (!ret) {
            ctx->error_code = RPCERR_ERROR;
            ctx->error_message = ucoind_error_str(RPCERR_ERROR);
        }
    } else {
        //未接続
        ctx->error_code = RPCERR_NOCHANN;
        ctx->error_message = ucoind_error_str(RPCERR_NOCHANN);
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
    }
    return result;
}


/** チャネル自動接続設定 : ucoincli -s
 *
 * チャネル開設済みのノードに対してはucoindから自動的に接続しようとするが、その動作を制御する。
 */
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
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
        return NULL;
    }
}


/** チャネル情報削除 : ucoincli -X
 *
 * DBから強制的にチャネル情報を削除する。
 */
static cJSON *cmd_removechannel(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    bool ret = false;

    cJSON *json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_String)) {
        uint8_t channel_id[LN_SZ_CHANNEL_ID];
        misc_str2bin(channel_id, sizeof(channel_id), json->valuestring);
        ret = ln_db_self_del(channel_id);
    }
    if (ret) {
        return cJSON_CreateString(kOK);
    } else {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
        return NULL;
    }
}


/** feerate_per_kw手動設定 : ucoincli --setfeerate
 *
 */
static cJSON *cmd_setfeerate(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON *json;
    uint32_t feerate_per_kw = 0;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    //feerate_per_kw
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number) && (json->valueu64 <= UINT32_MAX)) {
        feerate_per_kw = (uint32_t)json->valueu64;
        DBG_PRINTF("feerate_per_kw=%" PRIu32 "\n", feerate_per_kw);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }

    DBG_PRINTF("setfeerate\n");
    monitor_set_feerate_per_kw(feerate_per_kw);
    result = cJSON_CreateString(kOK);

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = ucoind_error_str(RPCERR_PARSE);
    }
    return result;
}


/********************************************************************
 * private functions : procedure
 ********************************************************************/

/** peer接続
 *
 * @param[in]       pConn
 * @param[in,out]   ctx
 * @retval  エラーコード
 */
static int cmd_connect_proc(const daemon_connect_t *pConn, jrpc_context *ctx)
{
    DBG_PRINTF("connect\n");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(pConn->node_id);
    if (p_appconf != NULL) {
        return RPCERR_ALCONN;
    }

    bool ret = p2p_cli_start(pConn, ctx);
    if (!ret) {
        return RPCERR_CONNECT;
    }

    //チェック
    int retry = M_RETRY_CONN_CHK;
    while (retry--) {
        p_appconf = search_connected_lnapp_node(pConn->node_id);
        if ((p_appconf != NULL) && lnapp_is_looping(p_appconf) && lnapp_is_inited(p_appconf)) {
            break;
        }
        sleep(1);
    }
    if (retry < 0) {
        return RPCERR_CONNECT;
    }

    return 0;
}


/** peer切断
 *
 * @param[in]       pNodeId
 * @retval  エラーコード
 */
static int cmd_disconnect_proc(const uint8_t *pNodeId)
{
    DBG_PRINTF("disconnect\n");

    int err;
    lnapp_conf_t *p_appconf = search_connected_lnapp_node(pNodeId);
    if (p_appconf != NULL) {
        lnapp_stop(p_appconf);
        err = 0;
    } else {
        err = RPCERR_NOCONN;
    }

    return err;
}


/** node終了
 *
 * @retval  エラーコード
 */
static int cmd_stop_proc(void)
{
    DBG_PRINTF("stop\n");

    p2p_svr_stop_all();
    p2p_cli_stop_all();
    monitor_stop();

    return 0;
}


/** channel establish開始
 *
 * @param[in]   pNodeId
 * @param[in]   pFund
 * @retval  エラーコード
 */
static int cmd_fund_proc(const uint8_t *pNodeId, const funding_conf_t *pFund)
{
    DBG_PRINTF("fund\n");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(pNodeId);
    if (p_appconf == NULL) {
        //未接続
        return RPCERR_NOCONN;
    }

    bool haveCnl = ln_node_search_channel(NULL, pNodeId);
    if (haveCnl) {
        //開設しようとしてチャネルが開いている
        return RPCERR_ALOPEN;
    }

    bool is_funding = ln_is_funding(p_appconf->p_self);
    if (is_funding) {
        //開設しようとしてチャネルが開設中
        return RPCERR_OPENING;
    }

    bool inited = lnapp_is_inited(p_appconf);
    if (!inited) {
        //BOLTメッセージとして初期化が完了していない(init/channel_reestablish交換できていない)
        return RPCERR_NOINIT;
    }

    bool ret = lnapp_funding(p_appconf, pFund);
    if (!ret) {
        return RPCERR_FUNDING;
    }

    return 0;
}


/** invoice作成
 *
 * @param[out]  pPayHash
 * @param[in]   AmountMsat
 * @retval  エラーコード
 */
static int cmd_invoice_proc(uint8_t *pPayHash, uint64_t AmountMsat)
{
    DBG_PRINTF("invoice\n");

    uint8_t preimage[LN_SZ_PREIMAGE];

    ucoin_util_random(preimage, LN_SZ_PREIMAGE);

    ucoind_preimage_lock();
    ln_db_preimg_save(preimage, AmountMsat, NULL);
    ucoind_preimage_unlock();

    ln_calc_preimage_hash(pPayHash, preimage);
    return 0;
}


/** invoice削除
 *
 * @param[in]   pPayHash
 * @retval  エラーコード
 */
static int cmd_eraseinvoice_proc(const uint8_t *pPayHash)
{
    bool ret;

    if (pPayHash != NULL) {
        ret = ln_db_preimg_del_hash(pPayHash);
    } else {
        ret = ln_db_preimg_del(NULL);
    }
    if (!ret) {
        return RPCERR_INVOICE_ERASE;
    }
    return 0;
}


/** 送金開始1
 * 送金経路作成
 *
 * @param[out]      ppInvoiceData
 * @param[out]      pRouteResult
 * @param[in]       pInvoice
 * @param[in]       AddAmountMsat
 * @retval  エラーコード
 */
static int cmd_routepay_proc1(
                ln_invoice_t **ppInvoiceData,
                ln_routing_result_t *pRouteResult,
                const char *pInvoice, uint64_t AddAmountMsat)
{
    bool bret = ln_invoice_decode(ppInvoiceData, pInvoice);
    if (!bret) {
        return RPCERR_PARSE;
    }

    ln_invoice_t *p_invoice_data = *ppInvoiceData;
    if ( (p_invoice_data->hrp_type != LN_INVOICE_TESTNET) &&
        (p_invoice_data->hrp_type != LN_INVOICE_REGTEST) ) {
        return RPCERR_INVOICE_FAIL;
    }
    p_invoice_data->amount_msat += AddAmountMsat;

    //blockcount
    int32_t blockcnt = btcrpc_getblockcount();
    DBG_PRINTF("blockcnt=%d\n", blockcnt);
    if (blockcnt < 0) {
        return RPCERR_BLOCKCHAIN;
    }

    lnerr_route_t rerr = ln_routing_calculate(pRouteResult,
                    ln_node_getid(),
                    p_invoice_data->pubkey,
                    blockcnt + p_invoice_data->min_final_cltv_expiry,
                    p_invoice_data->amount_msat,
                    p_invoice_data->r_field_num, p_invoice_data->r_field);
    if (rerr != LNROUTE_NONE) {
        DBG_PRINTF("fail: routing\n");
        switch (rerr) {
        case LNROUTE_NOTFOUND:
            return LNERR_ROUTE_NOTFOUND;
        case LNROUTE_TOOMANYHOP:
            return LNERR_ROUTE_TOOMANYHOP;
        default:
            return LNERR_ROUTE_ERROR;
        }
    }

    return 0;
}


/** 送金開始2
 * 送金
 *
 * @param[in]       pInvoiceData
 * @param[in]       pRouteResult
 * @param[in]       pInvoiceStr
 * @param[in]       AddAmountMsat
 * @retval  エラーコード
 */
static int cmd_routepay_proc2(
                const ln_invoice_t *pInvoiceData,
                const ln_routing_result_t *pRouteResult,
                const char *pInvoiceStr, uint64_t AddAmountMsat)
{
    int err = RPCERR_PAY_RETRY;

    //再送のためにinvoice保存
    (void)ln_db_invoice_save(pInvoiceStr, AddAmountMsat, pInvoiceData->payment_hash);

    DBG_PRINTF("-----------------------------------\n");
    for (int lp = 0; lp < pRouteResult->hop_num; lp++) {
        DBG_PRINTF("node_id[%d]: ", lp);
        DUMPBIN(pRouteResult->hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY);
        DBG_PRINTF("  amount_msat: %" PRIu64 "\n", pRouteResult->hop_datain[lp].amt_to_forward);
        DBG_PRINTF("  cltv_expiry: %" PRIu32 "\n", pRouteResult->hop_datain[lp].outgoing_cltv_value);
        DBG_PRINTF("  short_channel_id: %" PRIx64 "\n", pRouteResult->hop_datain[lp].short_channel_id);
    }
    DBG_PRINTF("-----------------------------------\n");

    lnapp_conf_t *p_appconf = search_connected_lnapp_node(pRouteResult->hop_datain[1].pubkey);
    if (p_appconf != NULL) {
        bool inited = lnapp_is_inited(p_appconf);
        if (inited) {
            payment_conf_t payconf;

            memcpy(payconf.payment_hash, pInvoiceData->payment_hash, LN_SZ_HASH);
            payconf.hop_num = pRouteResult->hop_num;
            memcpy(payconf.hop_datain, pRouteResult->hop_datain, sizeof(ln_hop_datain_t) * (1 + LN_HOP_MAX));

            bool ret = lnapp_payment(p_appconf, &payconf);
            if (ret) {
                DBG_PRINTF("start payment\n");
                err = 0;
            } else {
                DBG_PRINTF("fail: lnapp_payment\n");
                ln_db_annoskip_save(pRouteResult->hop_datain[0].short_channel_id, true);
            }
        } else {
            //BOLTメッセージとして初期化が完了していない(init/channel_reestablish交換できていない)
            DBG_PRINTF("fail: not inited\n");
        }
    } else {
        DBG_PRINTF("fail: not connect\n");
    }

    mPayTryCount++;

    if (mPayTryCount == 1) {
        //初回ログ
        uint64_t total_amount = ln_node_total_msat();
        char str_payhash[LN_SZ_HASH * 2 + 1];
        ucoin_util_bin2str(str_payhash, pInvoiceData->payment_hash, LN_SZ_HASH);
        char str_payee[UCOIN_SZ_PUBKEY * 2 + 1];
        ucoin_util_bin2str(str_payee, pInvoiceData->pubkey, UCOIN_SZ_PUBKEY);

        misc_save_event(NULL, "payment: payment_hash=%s payee=%s total_msat=%" PRIu64" amount_msat=%" PRIu64,
                    str_payhash, str_payee, total_amount, pInvoiceData->amount_msat);
    }

    return err;
}


/** channel close開始
 *
 * @param[out]      bMutual         true:Mutual Close開始 / false:Unilateral Close開始
 * @param[in]       pNodeId
 * @retval  エラーコード
 */
static int cmd_close_proc(bool *bMutual, const uint8_t *pNodeId)
{
    DBG_PRINTF("close\n");

    int err;
    lnapp_conf_t *p_appconf = search_connected_lnapp_node(pNodeId);
    if ((p_appconf != NULL) && (ln_htlc_num(p_appconf->p_self) == 0)) {
        //接続中
        bool ret = lnapp_close_channel(p_appconf);
        if (ret) {
            err = 0;
            *bMutual = true;
        } else {
            DBG_PRINTF("fail: mutual  close\n");
            err = RPCERR_CLOSE_START;
        }
    } else {
        //未接続
        bool haveCnl = ln_node_search_channel(NULL, pNodeId);
        if (haveCnl) {
            //チャネルあり
            //  相手とのチャネルがあるので、接続自体は可能かもしれない。
            //  closeの仕方については、仕様や運用とも関係が深いので、後で変更することになるだろう。
            //  今は、未接続の場合は mutual close以外で閉じることにする。
            DBG_PRINTF("チャネルはあるが接続していない\n");
            bool ret = lnapp_close_channel_force(pNodeId);
            if (ret) {
                err = 0;
                *bMutual = false;
            } else {
                DBG_PRINTF("fail: unilateral close\n");
                err = RPCERR_CLOSE_FAIL;
            }
        } else {
            //チャネルなし
            err = RPCERR_NOCHANN;
        }
    }

    return err;
}


/********************************************************************
 * private functions : others
 ********************************************************************/

/** ucoincli -c解析
 *
 */
static bool json_connect(cJSON *params, int *pIndex, daemon_connect_t *pConn)
{
    cJSON *json;

    if (params == NULL) {
        return false;
    }

    //peer_nodeid, peer_addr, peer_port
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_String)) {
        bool ret = misc_str2bin(pConn->node_id, UCOIN_SZ_PUBKEY, json->valuestring);
        if (ret) {
            DBG_PRINTF("pConn->node_id=%s\n", json->valuestring);
        } else {
            DBG_PRINTF("fail: invalid node_id string\n");
            return false;
        }
    } else {
        DBG_PRINTF("fail: node_id\n");
        return false;
    }
    if (memcmp(ln_node_getid(), pConn->node_id, UCOIN_SZ_PUBKEY) == 0) {
        //node_idが自分と同じ
        DBG_PRINTF("fail: same own node_id\n");
        return false;
    }
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_String)) {
        strcpy(pConn->ipaddr, json->valuestring);
        DBG_PRINTF("pConn->ipaddr=%s\n", json->valuestring);
    } else {
        DBG_PRINTF("fail: ipaddr\n");
        return false;
    }
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_Number)) {
        pConn->port = json->valueint;
        DBG_PRINTF("pConn->port=%d\n", json->valueint);
    } else {
        DBG_PRINTF("fail: port\n");
        return false;
    }

    return true;
}


/** BOLT11文字列生成
 *
 */
static char *create_bolt11(const uint8_t *pPayHash, uint64_t Amount)
{
    uint8_t type;
    ucoin_genesis_t gtype = ucoin_util_get_genesis(ln_get_genesishash());
    switch (gtype) {
    case UCOIN_GENESIS_BTCMAIN:
        type = LN_INVOICE_MAINNET;
        break;
    case UCOIN_GENESIS_BTCTEST:
        type = LN_INVOICE_TESTNET;
        break;
    case UCOIN_GENESIS_BTCREGTEST:
        type = LN_INVOICE_REGTEST;
        break;
    default:
        type = UCOIN_GENESIS_UNKNOWN;
        break;
    }
    char *p_invoice = NULL;
    if (type != UCOIN_GENESIS_UNKNOWN) {
        ln_invoice_create(&p_invoice, type, pPayHash, Amount);
    }
    return p_invoice;
}


/** 接続済みlnapp_conf_t取得
 *
 */
static lnapp_conf_t *search_connected_lnapp_node(const uint8_t *p_node_id)
{
    lnapp_conf_t *p_appconf;

    p_appconf = p2p_cli_search_node(p_node_id);
    if (p_appconf == NULL) {
        p_appconf = p2p_svr_search_node(p_node_id);
    }
    return p_appconf;
}
