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
 *  @brief  ptarmd JSON-RPC process
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <assert.h>
#include <errno.h>

#include "jsonrpc-c.h"

#define LOG_TAG     "lnapp"
#include "utl_log.h"
#include "utl_net.h"
#include "utl_time.h"

#include "btc_crypto.h"
#include "ln_invoice.h"
#include "ln_routing.h"
#include "ln_db.h"

#include "ptarmd.h"
#include "btcrpc.h"
#include "p2p.h"
#include "lnapp.h"
#include "lnapp_manager.h"
#include "monitoring.h"
#include "wallet.h"
#include "cmd_json.h"

#ifdef DEVELOPER_MODE
#include "ln_setupctl.h"
#endif


/********************************************************************
 * macros
 ********************************************************************/

#define M_SZ_JSONSTR            (8192)
#define M_SZ_PAYERR             (128)
#define M_RETRY_CONN_CHK        (10)        ///< 接続チェック[sec]

#define M_RPCERR_FREESTRING     (-1)        //no error_str_cjson() or strdup_cjson()

/** @def    M_RFIELD_AMOUNT
 *  @brief  invoice r-field add amount satisfied channel if defined.
 *  @note   if not defined, r-field add not announcement channel
 */
#define M_RFIELD_AMOUNT

#define M_SZ_SCRIPT_PARAM       (512)

#define M_RETRY_COUNT_MAX       (10)


/********************************************************************
 * macros functions
 ********************************************************************/


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    bool b_local;
    const uint8_t *p_node_id;
    cJSON *result;
} getcommittx_t;


typedef struct {
    ln_r_field_t    **pp_field;
    uint64_t        amount_msat;
    uint8_t         *p_fieldnum;
} r_field_param_t;


/********************************************************************
 * static variables
 ********************************************************************/

static struct jrpc_server   mJrpc;
//static char                 mLastPayErr[M_SZ_PAYERR];       //最後に送金エラーが発生した時刻
static bool                 mRunning;

static const char *kOK = "OK";


/********************************************************************
 * prototypes
 ********************************************************************/

static cJSON *cmd_connect(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_connect_nores(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_disconnect(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_exit(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_eraseinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_decodeinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_paytest(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_disautoconn(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_removechannel(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_setfeerate(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_estimatefundingfee(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_paytowallet(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_listpayment(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_listpayment_json(void *p_cur, uint64_t PaymentId, const ln_payment_info_t *pInfo);
static cJSON *cmd_removepayment(jrpc_context *ctx, cJSON *params, cJSON *id);
#ifdef USE_BITCOINJ
static cJSON *cmd_getnewaddress(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getbalance(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_emptywallet(jrpc_context *ctx, cJSON *params, cJSON *id);
#endif
#ifdef DEVELOPER_MODE
static cJSON *cmd_dev_send_error(jrpc_context *ctx, cJSON *params, cJSON *id);
#endif

static int cmd_connect_proc(const peer_conn_t *pConn);
static int cmd_disconnect_proc(const uint8_t *pNodeId);
static int cmd_fund_proc(const uint8_t *pNodeId, const funding_conf_t *pFund, jrpc_context *ctx);
static int cmd_invoice_proc(
    char **ppInvoice,
    uint8_t *pPaymentHash,
    bool bNoRField, uint8_t *pRFieldNum,
    uint64_t AmountMsat,
    uint32_t MinFinalCltvExpiry,
    uint32_t InvoiceExpiry,
    const ln_invoice_desc_t *pDesc);
static int cmd_eraseinvoice_proc(const uint8_t *pPaymentHash);
#if 0
static void cmd_routepay_save_info(
    const ln_invoice_t *pInvoiceData, const char *pInvoiceStr, int32_t BlockCnt);
static void cmd_routepay_save_route(
    const ln_invoice_t *pInvoiceData, const ln_routing_result_t *pRouteResult,
    const char *pResultStr);
#endif
static int cmd_close_mutual_proc(const uint8_t *pNodeId);
static int cmd_close_unilateral_proc(const uint8_t *pNodeId);

static int json_connect(cJSON *params, int *pIndex, peer_conn_t *pConn);
static int json_connect_ipaddr(cJSON *params, int *pIndex, peer_conn_t *pConn);
static int json_connect_name(cJSON *params, int *pIndex, peer_conn_t *pConn);
static char *create_bolt11(
                const uint8_t *pPaymentHash,
                uint64_t Amount,
                const ln_invoice_desc_t *pDesc,
                uint32_t Expiry,
                const ln_r_field_t *pRField,
                uint8_t RFieldNum,
                uint32_t MinFinalCltvExpiry);
static void create_bolt11_r_field(ln_r_field_t **ppRField, uint8_t *pRFieldNum, uint64_t AmountMsat);
static void create_bolt11_r_field_2(lnapp_conf_t *pConf, void *pParam);
static int send_json(const char *pSend, const char *pAddr, uint16_t Port);
static void getcommittx(lnapp_conf_t *pConf, void *pParam);
static bool get_committx(ln_channel_t *pChannel, cJSON *pResult, bool bLocal);
static char *strdup_cjson(const char *pStr);
static char *error_str_cjson(int errCode);
static int payment_error_to_rpc_error(ln_payment_error_t PayErr);


/********************************************************************
 * public functions
 ********************************************************************/

void cmd_json_start(uint16_t Port)
{
    int ret = jrpc_server_init(&mJrpc, Port);
    if (ret != 0) {
        const char *p_err = "ERR: cannot start JSON-RPC event loop\n";
        fprintf(stderr, "%s", p_err);
        LOGE("%s", p_err);
        ptarmd_stop();
        return;
    }

    mRunning = true;
    jrpc_register_procedure(&mJrpc, cmd_connect,     "connect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_connect_nores, "CONNECT", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getinfo,     "getinfo", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disconnect,  "disconnect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_stop,        "stop", NULL);
    jrpc_register_procedure(&mJrpc, cmd_exit,        "EXIT", NULL);
    jrpc_register_procedure(&mJrpc, cmd_fund,        "fund", NULL);
    jrpc_register_procedure(&mJrpc, cmd_invoice,     "invoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_eraseinvoice,"eraseinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_decodeinvoice,  "decodeinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_listinvoice, "listinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_paytest,     "PAY", NULL);
    jrpc_register_procedure(&mJrpc, cmd_routepay,    "routepay", NULL);
    jrpc_register_procedure(&mJrpc, cmd_close,       "close", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getlasterror,"getlasterror", NULL);
    jrpc_register_procedure(&mJrpc, cmd_debug,       "debug", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getcommittx, "getcommittx", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disautoconn, "disautoconn", NULL);
    jrpc_register_procedure(&mJrpc, cmd_removechannel,"removechannel", NULL);
    jrpc_register_procedure(&mJrpc, cmd_setfeerate,   "setfeerate", NULL);
    jrpc_register_procedure(&mJrpc, cmd_estimatefundingfee, "estimatefundingfee", NULL);
    jrpc_register_procedure(&mJrpc, cmd_paytowallet, "walletback", NULL);
    jrpc_register_procedure(&mJrpc, cmd_paytowallet, "paytowallet", NULL);
    jrpc_register_procedure(&mJrpc, cmd_listpayment, "listpayment", NULL);
    jrpc_register_procedure(&mJrpc, cmd_removepayment, "removepayment", NULL);
#ifdef USE_BITCOINJ
    jrpc_register_procedure(&mJrpc, cmd_getnewaddress,  "getnewaddress", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getbalance,  "getbalance", NULL);
    jrpc_register_procedure(&mJrpc, cmd_emptywallet, "emptywallet", NULL);
#endif
#ifdef DEVELOPER_MODE
    jrpc_register_procedure(&mJrpc, cmd_dev_send_error, "DEVsend_error", NULL);
#endif
    LOGD("[start]jrpc_server\n");
    jrpc_server_run(&mJrpc);
    jrpc_server_destroy(&mJrpc);

    LOGD("[exit]jrpc_server\n");
}


void cmd_json_stop(void)
{
    LOGD("stop\n");
    if (mJrpc.port_number != 0) {
        jrpc_server_stop(&mJrpc);
    }
}


int cmd_json_connect(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port)
{
    char nodestr[BTC_SZ_PUBKEY * 2 + 1];
    char json[256];

    utl_str_bin2str(nodestr, pNodeId, BTC_SZ_PUBKEY);
    LOGD("connect:%s@%s:%d\n", nodestr, pIpAddr, Port);

    bool ret = p2p_connect_test(pIpAddr, Port);
    if (!ret) {
        LOGE("fail: connect test\n");
        return -1;
    }

    sprintf(json, "{\"method\":\"CONNECT\",\"params\":[\"%s\",\"%s\",%d]}",
                        nodestr, pIpAddr, Port);

    int retval = send_json(json, "127.0.0.1", mJrpc.port_number);
    LOGD("retval=%d\n", retval);

    return retval;
}


/*
 * jsonrpc-cを終了させたいのだが、別スレッドからjrpc_server_stop()を呼び出しても終わってくれなかった。
 * そのため、jsonrpc-cからjrpc_server_stop()を実行してもらう。
 */
int cmd_json_exit(void)
{
    int retval = send_json("{\"method\":\"EXIT\",\"params\":[]}", "127.0.0.1", mJrpc.port_number);
    LOGD("retval=%d\n", retval);

    return retval;
}


/********************************************************************
 * private functions : JSON-RPC
 ********************************************************************/

/** 接続 : ptarmcli -c
 *
 */
static cJSON *cmd_connect(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err;
    cJSON *json;
    peer_conn_t conn;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    err = json_connect(params, &index, &conn);
    if (err) {
        goto LABEL_EXIT;
    }

    //initial_routing_sync
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        conn.routesync = json->valueint;
    }

    LOGD("$$$: [JSONRPC]connect\n");

    err = cmd_connect_proc(&conn);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}



/** 接続(内部用)
 *
 */
static cJSON *cmd_connect_nores(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err;
    peer_conn_t conn;
    int index = 0;

    //connect parameter
    err = json_connect(params, &index, &conn);
    if (err) {
        goto LABEL_EXIT;
    }

    err = cmd_connect_proc(&conn);

LABEL_EXIT:
    if (err) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    return NULL;
}


/** 状態出力 : ptarmcli -l
 *
 */
static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    bool ret;
    cJSON *json;
    int level = 0;
    cJSON *result = cJSON_CreateObject();
    cJSON *result_peer = cJSON_CreateArray();

    json = cJSON_GetArrayItem(params, 0);
    if ((json != NULL) && (json->type == cJSON_Number)) {
        level = json->valueint;
    }


    LOGD("$$$: [JSONRPC]getinfo\n");

    //basic info
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
    cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(node_id));
    cJSON_AddItemToObject(result, "node_port", cJSON_CreateNumber(ln_node_addr()->port));

    char anno_ip[SZ_CONN_STR + 1];
    ret = ln_node_get_announceip(anno_ip);
    if (ret) {
        cJSON_AddItemToObject(result, "announce_ip", cJSON_CreateString(anno_ip));
    }

    if (level == 1) {
        LOGD("exit\n");
        return result;
    }

    uint64_t total_amount = ln_node_total_msat();
    cJSON_AddNumber64ToObject(result, "total_local_msat", total_amount);

    //blockcount
    int32_t block_count;
    ret = monitor_btc_getblockcount(&block_count);
    if (ret) {
        cJSON_AddItemToObject(result, "block_count", cJSON_CreateNumber(block_count));
    } else {
        LOGE("fail getblockcount()\n");
    }

    //peer info
    p2p_show_channel(result_peer);
    cJSON_AddItemToObject(result, "peers", result_peer);
    LOGD("exit\n");
    return result;
}


/** 指定channel切断 : ptarmcli -q xxxxx
 *
 */
static cJSON *cmd_disconnect(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err;
    peer_conn_t conn;
    cJSON *result = NULL;
    int index = 0;

    LOGD("$$$: [JSONRPC]disconnect\n");

    //connect parameter
    err = json_connect(params, &index, &conn);
    if (err) {
        goto LABEL_EXIT;
    }

    err = cmd_disconnect_proc(conn.node_id);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** ノード終了 : ptarmcli -q
 *
 */
static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    LOGD("$$$: [JSONRPC]stop\n");

    ptarmd_stop();

    LOGD("exit\n");
    return cJSON_CreateString(kOK);
}


/** ノード終了 : ptarmcli --EXIT
 *
 */
static cJSON *cmd_exit(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    LOGD("$$$: [JSONRPC]EXIT\n");

    if (mJrpc.port_number != 0) {
        jrpc_server_stop(&mJrpc);
    }

    LOGD("exit\n");
    return cJSON_CreateString(kOK);
}


/** channel establish開始 : ptarmcli -f
 *
 */
static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err;
    cJSON *json;
    peer_conn_t conn;
    funding_conf_t fundconf;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    err = json_connect(params, &index, &conn);
    if (err) {
        goto LABEL_EXIT;
    }
    err = RPCERR_PARSE;

    //funding parameter
    //txid
    (void)cJSON_GetArrayItem(params, index++);
    //txindex
    (void)cJSON_GetArrayItem(params, index++);
    //funding_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.funding_sat = json->valueu64;
        LOGD("funding_sat=%" PRIu64 "\n", fundconf.funding_sat);
    } else {
        LOGE("funding_sat\n");
        goto LABEL_EXIT;
    }
    //push_msat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.push_msat = json->valueu64;
        LOGD("push_msat=%" PRIu64 "\n", fundconf.push_msat);
    } else {
        LOGE("push_msat\n");
        goto LABEL_EXIT;
    }
    //feerate_per_kw
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.feerate_per_kw = (uint32_t)json->valueu64;
        LOGD("feerate_per_kw=%" PRIu32 "\n", fundconf.feerate_per_kw);
    } else {
        //デフォルト値
        fundconf.feerate_per_kw = 0;
    }
    //private channel
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.priv_channel = json->valueint;
        LOGD("priv_chanel=%" PRIu32 "\n", fundconf.priv_channel);
    } else {
        //デフォルト値
        fundconf.priv_channel = 0;
    }

    LOGD("$$$: [JSONRPC]fund\n");

    err = cmd_fund_proc(conn.node_id, &fundconf, ctx);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateObject();
        cJSON_AddItemToObject(result, "status", cJSON_CreateString("Progressing"));
    } else if (err == M_RPCERR_FREESTRING) {
        //
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** invoice作成 : ptarmcli -i
 *
 */
static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    cJSON *json;
    uint64_t amount_msat = 0;
    cJSON *result = NULL;
    int index = 0;
    uint32_t invoice_expiry = LN_INVOICE_EXPIRY;
    uint32_t min_final_cltv_expiry;
    char description[LN_INVOICE_DESC_MAX + 1] = "";
    char *p_invoice = NULL;
    ln_invoice_desc_t desc;
    uint8_t r_fieldnum = 0;
    bool no_rfield = false;

    if (params == NULL) {
        goto LABEL_EXIT;
    }

    //amount_msat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        amount_msat = json->valueu64;
        LOGD("amount_msat=%" PRIu64 "\n", amount_msat);
    } else {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }
    //min_final_cltv_expiry
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number) && (json->valueint != 0)) {
        min_final_cltv_expiry = json->valueint;
        LOGD("min_final_cltv_expiry=%" PRIu32 "\n", min_final_cltv_expiry);
    } else {
        //デフォルト値
        min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    }
    //description
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        strncpy(description, json->valuestring, sizeof(description));
        description[sizeof(description) - 1] = '\0';
        LOGD("description=%s\n", description);
    }
    //expiry
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        if (json->valueint < LN_INVOICE_EXPIRY_MIN) {
            err = M_RPCERR_FREESTRING;
            ctx->error_code = RPCERR_INVOICE_FAIL;
            ctx->error_message = strdup_cjson("invoice expiry too short");
            goto LABEL_EXIT;
        }
        invoice_expiry = json->valueint;
        LOGD("invoice_expiry=%d\n", invoice_expiry);
    }
    //no-rfield
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        if (json->valueint != 0) {
            LOGD("no-rfield\n");
            no_rfield = true;
        }
    }

    size_t desc_len = strlen(description);
    if (desc_len > LN_INVOICE_DESC_MAX) {
        err = M_RPCERR_FREESTRING;
        ctx->error_code = RPCERR_INVOICE_FAIL;
        ctx->error_message = strdup_cjson("too long description");
        goto LABEL_EXIT;
    }
    desc.type = LN_INVOICE_DESC_TYPE_STRING;
    utl_buf_alloccopy(&desc.data, (const uint8_t *)description, desc_len);

    LOGD("$$$: [JSONRPC]invoice\n");

    uint8_t preimage_hash[BTC_SZ_HASH256];
    err = cmd_invoice_proc(
            &p_invoice, preimage_hash,
            no_rfield, &r_fieldnum,
            amount_msat, min_final_cltv_expiry, invoice_expiry, &desc);
    utl_buf_free(&desc.data);

LABEL_EXIT:
    if (err == 0) {
        if (p_invoice != NULL) {
            char str_hash[BTC_SZ_HASH256 * 2 + 1];

            utl_str_bin2str(str_hash, preimage_hash, BTC_SZ_HASH256);
            result = cJSON_CreateObject();
            cJSON_AddItemToObject(result, "hash", cJSON_CreateString(str_hash));
            cJSON_AddItemToObject(result, "amount_msat", cJSON_CreateNumber64(amount_msat));
            cJSON_AddItemToObject(result, "bolt11", cJSON_CreateString(p_invoice));
#ifdef M_RFIELD_AMOUNT
            if (!no_rfield && (r_fieldnum == 0)) {
                cJSON_AddItemToObject(result, "note", cJSON_CreateString("no payable-amount channel"));
            }
#endif  //M_RFIELD_AMOUNT

            UTL_DBG_FREE(p_invoice);
        } else {
            LOGE("fail: BOLT11 format\n");
            err = RPCERR_PARSE;
        }
    }
    if (err && (err != M_RPCERR_FREESTRING)) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** invice削除 : ptarmcli -e
 *
 */
static cJSON *cmd_eraseinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    cJSON *json;
    cJSON *result = NULL;
    uint8_t preimage_hash[BTC_SZ_HASH256];
    int index = 0;

    if (params == NULL) {
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if ((json == NULL) || (json->type != cJSON_String)) {
        goto LABEL_EXIT;
    }

    LOGD("$$$: [JSONRPC]eraseinvoice\n");

    if (strlen(json->valuestring) > 0) {
        LOGD("erase hash: %s\n", json->valuestring);
        utl_str_str2bin(preimage_hash, sizeof(preimage_hash), json->valuestring);
        err = cmd_eraseinvoice_proc(preimage_hash);
    } else {
        err = cmd_eraseinvoice_proc(NULL);
    }

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** 送金・再送金
 *
 */
static cJSON *cmd_decodeinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    LOGD("$$$ [JSONRPC]decodeinvoice\n");

    int err = 0;
    cJSON *result = NULL;
    cJSON *json;
    int index = 0;
    ln_invoice_t *p_invoice_data = NULL;

    if (params == NULL) {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (!json || (json->type != cJSON_String)) {
        LOGE("fail: invalid invoice string\n");
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    if (!ln_invoice_decode(&p_invoice_data, json->valuestring)) {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    result = cJSON_CreateObject();

    const char *chain;
    switch (p_invoice_data->hrp_type) {
    case LN_INVOICE_MAINNET:
        chain = "bitcoin mainnet";
        break;
    case LN_INVOICE_TESTNET:
        chain = "bitcoin testnet";
        break;
    case LN_INVOICE_REGTEST:
        chain = "bitcoin regtest";
        break;
    default:
        chain = "unknown";
    }
    cJSON_AddItemToObject(result, "chain", cJSON_CreateString(chain));

    //amount_msat
    cJSON_AddItemToObject(result, "amount_msat", cJSON_CreateNumber64(p_invoice_data->amount_msat));
    //timestamp
    char tm_str[UTL_SZ_TIME_FMT_STR + 1];
    time_t tm = (time_t)p_invoice_data->timestamp;
    cJSON_AddItemToObject(result, "timestamp", cJSON_CreateString(utl_time_fmt(tm_str, tm)));
    //expiry
    cJSON_AddItemToObject(result, "expiry", cJSON_CreateNumber(p_invoice_data->expiry));
    //min_final_cltv_expiry
    cJSON_AddItemToObject(result, "min_final_cltv_expiry", cJSON_CreateNumber(p_invoice_data->min_final_cltv_expiry));
    //pubkey
    char pubkey_str[BTC_SZ_PUBKEY * 2 + 1];
    utl_str_bin2str(pubkey_str, p_invoice_data->pubkey, BTC_SZ_PUBKEY);
    cJSON_AddItemToObject(result, "pubkey", cJSON_CreateString(pubkey_str));
    //payment_hash
    char paymenthash_str[BTC_SZ_HASH256 * 2 + 1];
    utl_str_bin2str(paymenthash_str, p_invoice_data->payment_hash, BTC_SZ_HASH256);
    cJSON_AddItemToObject(result, "payment_hash", cJSON_CreateString(paymenthash_str));
    //description
    switch (p_invoice_data->description.type) {
    case LN_INVOICE_DESC_TYPE_STRING:
        cJSON_AddItemToObject(result, "description_string", cJSON_CreateString((const char *)p_invoice_data->description.data.buf));
        break;
    case LN_INVOICE_DESC_TYPE_HASH256:
        {
            char hash_str[BTC_SZ_HASH256 * 2 + 1];
            utl_str_bin2str(hash_str, p_invoice_data->description.data.buf, p_invoice_data->description.data.len);
            cJSON_AddItemToObject(result, "description_hash", cJSON_CreateString(hash_str));
        }
        break;
    default:
        break;
    }
    //r_field
    if (p_invoice_data->r_field_num > 0) {
        cJSON *rfield = cJSON_CreateArray();

        for (int lp = 0; lp < p_invoice_data->r_field_num; lp++) {
            cJSON *field = cJSON_CreateObject();

            utl_str_bin2str(pubkey_str, p_invoice_data->r_field[lp].node_id, BTC_SZ_PUBKEY);
            cJSON_AddItemToObject(field, "node_id", cJSON_CreateString(pubkey_str));

            char sci_str[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
            ln_short_channel_id_string(sci_str, p_invoice_data->r_field[lp].short_channel_id);
            cJSON_AddItemToObject(field, "short_channel_id", cJSON_CreateString(sci_str));

            cJSON_AddItemToObject(field, "fee_base_msat", cJSON_CreateNumber(p_invoice_data->r_field[lp].fee_base_msat));
            cJSON_AddItemToObject(field, "fee_proportional_millionths", cJSON_CreateNumber(p_invoice_data->r_field[lp].fee_base_msat));
            cJSON_AddItemToObject(field, "cltv_expiry_delta", cJSON_CreateNumber(p_invoice_data->r_field[lp].cltv_expiry_delta));
            cJSON_AddItemToArray(rfield, field);
        }
        cJSON_AddItemToObject(result, "r_field", rfield);
    }

LABEL_EXIT:
    if (err) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    ln_invoice_decode_free(p_invoice_data);
    LOGD("exit\n");
    return result;
}

/** invoice一覧出力 : ptarmcli -m
 *
 */
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    cJSON *result = NULL;
    uint8_t preimage_hash[BTC_SZ_HASH256];
    ln_db_preimage_t preimage;
    void *p_cur;
    bool ret;
    const uint8_t *p_selected_hash = NULL;
    uint8_t selected_hash[BTC_SZ_HASH256];

    LOGD("$$$: [JSONRPC]listinvoice\n");

    if (params != NULL) {
        cJSON *json = cJSON_GetArrayItem(params, 0);
        if (json && (json->type == cJSON_String)) {
            utl_str_str2bin(selected_hash, BTC_SZ_HASH256, json->valuestring);
            p_selected_hash = selected_hash;
        }
    }

    result = cJSON_CreateArray();
    ret = ln_db_preimage_cur_open(&p_cur);
    while (ret) {
        bool detect;
        const char *p_bolt11 = NULL;
        ret = ln_db_preimage_cur_get(p_cur, &detect, &preimage, &p_bolt11);
        if (detect) {
            ln_payment_hash_calc(preimage_hash, preimage.preimage);

            if (p_selected_hash != NULL) {
                if (memcmp(selected_hash, preimage_hash, BTC_SZ_HASH256) != 0) {
                    continue;
                }
            }

            cJSON *json = cJSON_CreateObject();

            const char *p_state;
            switch (preimage.state) {
            case LN_DB_PREIMAGE_STATE_UNUSED:
                p_state = "unused";
                break;
            case LN_DB_PREIMAGE_STATE_USED:
                p_state = "used";
                break;
            case LN_DB_PREIMAGE_STATE_EXPIRE:
                p_state = "expire";
                break;
            case LN_DB_PREIMAGE_STATE_UNKNOWN:
            default:
                p_state = "unknown";
                break;
            }
            cJSON_AddItemToObject(json, "state", cJSON_CreateString(p_state));
            char str_hash[BTC_SZ_HASH256 * 2 + 1];
            utl_str_bin2str(str_hash, preimage_hash, BTC_SZ_HASH256);
            cJSON_AddItemToObject(json, "hash", cJSON_CreateString(str_hash));
            cJSON_AddItemToObject(json, "amount_msat", cJSON_CreateNumber64(preimage.amount_msat));
            char time[UTL_SZ_TIME_FMT_STR + 1];
            cJSON_AddItemToObject(json, "creation_time", cJSON_CreateString(utl_time_fmt(time, preimage.creation_time)));
            cJSON_AddItemToObject(json, "expiry", cJSON_CreateNumber(preimage.expiry));
            if ((p_bolt11 != NULL) && (strlen(p_bolt11) > 0)) {
                cJSON_AddItemToObject(json, "bolt11", cJSON_CreateString(p_bolt11));
            }
            // ln_r_field_t *p_r_field = NULL;
            // uint8_t r_fieldnum = 0;
            // create_bolt11_r_field(&p_r_field, &r_fieldnum);
            // char *p_invoice = create_bolt11(preimage_hash, preimage.amount_msat, preimage.expiry, p_r_field, r_fieldnum, LN_MIN_FINAL_CLTV_EXPIRY);
            // if (p_invoice != NULL) {
            //     cJSON_AddItemToObject(json, "invoice", cJSON_CreateString(p_invoice));
            //     UTL_DBG_FREE(p_invoice);
            //     APP_FREE(p_r_field);
            // }
            cJSON_AddItemToArray(result, json);

            if (p_selected_hash != NULL) {
                break;
            }
        }
    }
    ln_db_preimage_cur_close(p_cur, false);
    LOGD("exit\n");
    return result;
}


/** 送金開始(テスト用) : "PAY"
 *
 */
static cJSON *cmd_paytest(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    cJSON               *result = NULL;
    int                 err = 0;
    cJSON               *json;
    int32_t             block_count;
    int                 index = 0;
    ln_payment_route_t  route;
    uint8_t             payment_hash[BTC_SZ_HASH256] = {0};

    if (params == NULL) {
        err = RPCERR_PARSE;
        goto LABEL_ERROR;
    }

    LOGD("$$$: [JSONRPC]PAY\n");

    if (!monitor_btc_getblockcount(&block_count)) {
        err = RPCERR_BLOCKCHAIN;
        goto LABEL_ERROR;
    }
    LOGD("block_count=%d\n", block_count);

    //payment_hash, num_hops
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        utl_str_str2bin(payment_hash, BTC_SZ_HASH256, json->valuestring);
        LOGD("payment_hash=%s\n", json->valuestring);
    } else {
        err = RPCERR_PARSE;
        goto LABEL_ERROR;
    }
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        route.num_hops = json->valueint;
        LOGD("num_hops=%d\n", json->valueint);
    } else {
        err = RPCERR_PARSE;
        goto LABEL_ERROR;
    }
    //array
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Array)) {
        LOGD("trace array\n");
    } else {
        err = RPCERR_PARSE;
        goto LABEL_ERROR;
    }
    //[ [...], [...], ..., [...] ]
    for (int lp = 0; lp < route.num_hops; lp++) {
        ln_hop_datain_t *p = &route.hop_datain[lp];

        LOGD("loop=%d\n", lp);
        cJSON *jarray = cJSON_GetArrayItem(json, lp);
        if (jarray && (jarray->type == cJSON_Array)) {
            //[node_id, short_channel_id, amt_to_forward, outgoing_cltv_value]

            //node_id
            cJSON *jparam = cJSON_GetArrayItem(jarray, 0);
            LOGD("jparam=%p\n", jparam);
            if (jparam && (jparam->type == cJSON_String)) {
                utl_str_str2bin(p->pubkey, BTC_SZ_PUBKEY, jparam->valuestring);
                LOGD("  node_id=");
                DUMPD(p->pubkey, BTC_SZ_PUBKEY);
            } else {
                LOGE("fail: p=%p\n", jparam);
                err = RPCERR_PARSE;
                goto LABEL_ERROR;
            }
            //short_channel_id
            jparam = cJSON_GetArrayItem(jarray, 1);
            if (jparam && (jparam->type == cJSON_String)) {
                p->short_channel_id = strtoull(jparam->valuestring, NULL, 16);
                LOGD("  short_channel_id=%016" PRIx64 "\n", p->short_channel_id);
            } else {
                LOGE("fail: p=%p\n", jparam);
                err = RPCERR_PARSE;
                goto LABEL_ERROR;
            }
            //amt_to_forward
            jparam = cJSON_GetArrayItem(jarray, 2);
            if (jparam && (jparam->type == cJSON_Number)) {
                p->amt_to_forward = jparam->valueu64;
                LOGD("  amt_to_forward=%" PRIu64 "\n", p->amt_to_forward);
            } else {
                LOGE("fail: p=%p\n", jparam);
                err = RPCERR_PARSE;
                goto LABEL_ERROR;
            }
            //outgoing_cltv_value
            jparam = cJSON_GetArrayItem(jarray, 3);
            if (jparam && (jparam->type == cJSON_Number)) {
                p->outgoing_cltv_value = jparam->valueint + block_count;
                LOGD("  outgoing_cltv_value=%u\n", p->outgoing_cltv_value);
            } else {
                LOGE("fail: p=%p\n", jparam);
                err = RPCERR_PARSE;
                goto LABEL_ERROR;
            }
        } else {
            LOGE("fail: p=%p\n", jarray);
            err = RPCERR_PARSE;
            goto LABEL_ERROR;
        }
    }

    LOGD("payment\n");
    ln_payment_error_t pay_err;
    uint64_t payment_id;
    pay_err = ln_payment_start_test(&payment_id, payment_hash, &route, block_count);
    if (pay_err != LN_PAYMENT_OK) {
        LOGE("fail: ???\n");
        err = payment_error_to_rpc_error(err);
        goto LABEL_ERROR;
    }

    // method: payment
    // $1: short_channel_id
    // $2: node_id
    // $3: amt_to_forward
    // $4: outgoing_cltv_value
    // $5: payment_id
    char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
    ln_short_channel_id_string(str_sci, route.hop_datain[0].short_channel_id);
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
    char param[M_SZ_SCRIPT_PARAM];
    snprintf(
        param, sizeof(param), "%s %s %" PRIu64 " %" PRIu32 " %" PRIu64,
        str_sci, node_id, route.hop_datain[0].amt_to_forward,
        route.hop_datain[0].outgoing_cltv_value, payment_id);
    ptarmd_call_script(PTARMD_EVT_PAYMENT, param);

    LOGD("payment start\n");
    result = cJSON_CreateObject();
    cJSON_AddNumber64ToObject(result, "payment_id", payment_id);
    return result;

LABEL_ERROR:
    LOGE("fail: err=%d\n", err);
    ctx->error_code = err;
    ctx->error_message = error_str_cjson(err);
    ln_db_route_skip_drop(true);
    LOGD("exit\n");
    return NULL;
}


/** 送金開始: ptarmcli -r
 *
 * 一時ルーティング除外リストをクリアしてから送金する
 */
static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    LOGD("$$$ [JSONRPC]routepay\n");

    ln_db_route_skip_work(true);

    cJSON       *result = NULL;
    int         err = RPCERR_PARSE;
    cJSON       *json;
    int32_t     block_count;
    int         index = 0;
    char        *p_invoice = NULL;
    uint64_t    add_amount_msat = 0;

    if (params == NULL) {
        goto LABEL_ERROR;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        p_invoice = UTL_DBG_STRDUP(json->valuestring);
    } else {
        LOGE("fail: invalid invoice string\n");
        goto LABEL_ERROR;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        add_amount_msat = json->valueu64;
    } else {
        LOGE("fail: invalid add amount_msat\n");
        goto LABEL_ERROR;
    }

    if (!monitor_btc_getblockcount(&block_count)) {
        err = RPCERR_BLOCKCHAIN;
        goto LABEL_ERROR;
    }
    LOGD("block_count=%d\n", block_count);

    LOGD("payment\n");

    uint64_t            payment_id;
    ln_payment_route_t  route;
    err = payment_error_to_rpc_error(
        ln_payment_start_invoice(
            &payment_id, &route, p_invoice, add_amount_msat, M_RETRY_COUNT_MAX, false, block_count));
    if (err) {
        LOGE("fail: ???\n");
        goto LABEL_ERROR;
    }

    // method: payment
    // $1: short_channel_id
    // $2: node_id
    // $3: amt_to_forward
    // $4: outgoing_cltv_value
    // $5: payment_id
    char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
    ln_short_channel_id_string(str_sci, route.hop_datain[0].short_channel_id);
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_str_bin2str(node_id, ln_node_get_id(), BTC_SZ_PUBKEY);
    char param[M_SZ_SCRIPT_PARAM];
    snprintf(
        param, sizeof(param), "%s %s %" PRIu64 " %" PRIu32 " %" PRIu64,
        str_sci, node_id, route.hop_datain[0].amt_to_forward,
        route.hop_datain[0].outgoing_cltv_value, payment_id);
    ptarmd_call_script(PTARMD_EVT_PAYMENT, param);

    LOGD("payment start\n");
    result = cJSON_CreateObject();
    cJSON_AddNumber64ToObject(result, "payment_id", payment_id);
    UTL_DBG_FREE(p_invoice);
    return result;

LABEL_ERROR:
    ctx->error_code = err;
    ctx->error_message = error_str_cjson(err);
    ln_db_route_skip_work(false);

    UTL_DBG_FREE(p_invoice);
    LOGD("exit\n");
    return result;
}


/** channel mutual close開始 : ptarmcli -x
 *
 */
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err;
    peer_conn_t conn;
    cJSON *result = NULL;
    cJSON *json;
    int index = 0;
    const char *p_str = "";

    LOGD("$$$ [JSONRPC]close\n");

    //connect parameter
    err = json_connect(params, &index, &conn);
    if (err) {
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if ( json && (json->type == cJSON_String) &&
         (strcmp(json->valuestring, "force") == 0) ) {
        LOGD("force close\n");
        p_str = "Start Unilateral Close";
        err = cmd_close_unilateral_proc(conn.node_id);
    } else {
        LOGD("mutual close\n");
        p_str = "Start Mutual Close";
        err = cmd_close_mutual_proc(conn.node_id);
    }

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(p_str);
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** 最後に発生したエラー出力 : ptarmcli -w
 *
 */
static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err;
    peer_conn_t conn;
    int index = 0;

    //connect parameter
    err = json_connect(params, &index, &conn);
    if (err) {
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]getlasterror\n");

    lnapp_conf_t *p_conf = ptarmd_search_connected_node_id(conn.node_id);
    if (p_conf) {
        LOGD("error code: %d\n", p_conf->err);
        ctx->error_code = p_conf->err;
        if (p_conf->p_errstr != NULL) {
            LOGD("error msg: %s\n", p_conf->p_errstr);
            ctx->error_message = strdup_cjson(p_conf->p_errstr);
        }
        lnapp_manager_free_node_ref(p_conf);
        p_conf = NULL;
    } else {
        err = RPCERR_NOCONN;
    }

LABEL_EXIT:
    if (err) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return NULL;
}


/** デバッグフラグのトグル : ptarmcli -d
 *
 */
static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    int err = 0;
    cJSON *result = NULL;
    char str[10];
    cJSON *json;

    if (params == NULL) {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]debug\n");

    json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_Number)) {
        result = cJSON_CreateObject();

        sprintf(str, "%08lx", ln_debug_get());
        cJSON_AddItemToObject(result, "old", cJSON_CreateString(str));

        unsigned long dbg = ln_debug_get() ^ json->valueint;
        ln_debug_set(dbg);
        sprintf(str, "%08lx", dbg);
        cJSON *js_mode = cJSON_CreateArray();
        if (!LN_DBG_FULFILL()) {
            cJSON_AddItemToArray(js_mode, cJSON_CreateString("no fulfill return"));
        }
        if (!LN_DBG_CLOSING_TX()) {
            cJSON_AddItemToArray(js_mode, cJSON_CreateString("no closing tx"));
        }
        if (!LN_DBG_MATCH_PREIMAGE()) {
            cJSON_AddItemToArray(js_mode, cJSON_CreateString("force preimage mismatch"));
        }
        if (!LN_DBG_NODE_AUTO_CONNECT()) {
            cJSON_AddItemToArray(js_mode, cJSON_CreateString("no node Auto connect"));
        }
        if (!LN_DBG_ONION_CREATE_NORMAL_REALM()) {
            cJSON_AddItemToArray(js_mode, cJSON_CreateString("create invalid realm onion"));
        }
        if (!LN_DBG_ONION_CREATE_NORMAL_VERSION()) {
            cJSON_AddItemToArray(js_mode, cJSON_CreateString("create invalid version onion"));
        }
        if (!LN_DBG_FULFILL_BWD()) {
            cJSON_AddItemToArray(js_mode, cJSON_CreateString("fulfill not found"));
        }
        cJSON_AddItemToObject(result, "new", cJSON_CreateString(str));
        cJSON_AddItemToObject(result, "mode", js_mode);
    } else {
        err = RPCERR_PARSE;
    }

LABEL_EXIT:
    if (err) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** commitment transaction出力 : ptarmcli -g
 *
 * commitment transactionおよび関連するtransactionを16進数文字列出力する。
 */
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err;
    peer_conn_t conn;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    err = json_connect(params, &index, &conn);
    if (err) {
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]getcommittx\n");

    result = cJSON_CreateObject();
    getcommittx_t param;
    param.b_local = true;
    param.p_node_id = conn.node_id;
    param.result = result;
    lnapp_manager_each_node(getcommittx, &param);

LABEL_EXIT:
    if (err) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** チャネル自動接続設定 : ptarmcli -s
 *
 * チャネル開設済みのノードに対してはptarmdから自動的に接続しようとするが、その動作を制御する。
 */
static cJSON *cmd_disautoconn(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    const char *p_str = NULL;

    LOGD("$$$ [JSONRPC]disautoconn\n");

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
    LOGD("exit\n");
    if (p_str != NULL) {
        return cJSON_CreateString(p_str);
    } else {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
        return NULL;
    }
}


/** チャネル情報削除 : ptarmcli -X
 *
 * DBから強制的にチャネル情報を削除する。
 */
static cJSON *cmd_removechannel(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    bool ret = false;

    LOGD("$$$ [JSONRPC]removechannel\n");

    cJSON *json = cJSON_GetArrayItem(params, 0);
    if (json && (json->type == cJSON_String)) {
        uint8_t channel_id[LN_SZ_CHANNEL_ID];
        utl_str_str2bin(channel_id, sizeof(channel_id), json->valuestring);
        ret = ln_db_channel_del(channel_id);
    }
    LOGD("exit\n");
    if (ret) {
        return cJSON_CreateString(kOK);
    } else {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
        return NULL;
    }
}


/** feerate_per_kw手動設定 : ptarmcli --setfeerate
 *
 */
static cJSON *cmd_setfeerate(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = 0;
    cJSON *json;
    uint32_t feerate_per_kw = 0;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    //feerate_per_kw
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number) && (json->valueu64 <= UINT32_MAX)) {
        feerate_per_kw = (uint32_t)json->valueu64;
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_per_kw);
    } else {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]setfeerate\n");
    monitor_set_feerate_per_kw(feerate_per_kw);
    result = cJSON_CreateString(kOK);

LABEL_EXIT:
    if (err) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** 予想されるfunding fee : ptarmcli --estimatefundingfee
 *
 */
static cJSON *cmd_estimatefundingfee(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = 0;
    cJSON *json;
    uint32_t feerate_per_kw = 0;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    //feerate_per_kw
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number) && (json->valueu64 <= UINT32_MAX)) {
        feerate_per_kw = (uint32_t)json->valueu64;
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_per_kw);
    } else {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]estimatefundingfee\n");

    if (feerate_per_kw == 0) {
        feerate_per_kw = monitor_btc_feerate_per_kw();
    }
    if (feerate_per_kw == 0) {
        err = RPCERR_BLOCKCHAIN;
        goto LABEL_EXIT;
    }
    uint64_t fee = ln_estimate_fundingtx_fee(feerate_per_kw);
    result = cJSON_CreateNumber64(fee);

LABEL_EXIT:
    if (err) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}


/** DBに残っている1st layerのamountをwalletに返す : ptarmcli -W
 *
 */
static cJSON *cmd_paytowallet(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    bool ret;
    bool tosend = false;
    uint32_t feerate_per_kw = 0;

    LOGD("$$$ [JSONRPC]paytowallet\n");

    if (params != NULL) {
        cJSON *json;
        json = cJSON_GetArrayItem(params, 0);
        if (json && (json->type == cJSON_Number)) {
            tosend = (json->valueint != 0);
        }
        json = cJSON_GetArrayItem(params, 1);
        if (json && (json->type == cJSON_Number)) {
            feerate_per_kw = (uint32_t)json->valueu64;
            LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_per_kw);
        }
    }

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    ret = btcrpc_getnewaddress(addr);
    if (!ret) {
        ctx->error_code = RPCERR_BLOCKCHAIN;
        ctx->error_message = error_str_cjson(RPCERR_BLOCKCHAIN);
        return NULL;
    }
    if (feerate_per_kw == 0) {
        feerate_per_kw = monitor_btc_feerate_per_kw();
    }

    cJSON *result = cJSON_CreateObject();
    ret = wallet_from_ptarm(result, tosend, addr, feerate_per_kw);
    if (!ret) {
        cJSON_Delete(result);
        result = NULL;
        ctx->error_code = RPCERR_WALLET_ERR;
        ctx->error_message = error_str_cjson(RPCERR_WALLET_ERR);
    }
    LOGD("exit\n");
    return result;
}


static cJSON *cmd_listpayment(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    cJSON *result = NULL;
    void *p_cur;
    uint64_t            payment_id;
    uint64_t            selected_id = UINT64_MAX;
    ln_payment_info_t   info;

    LOGD("$$$: [JSONRPC]listpayment\n");

    if (params != NULL) {
        cJSON *json;
        json = cJSON_GetArrayItem(params, 0);
        if (json && (json->type == cJSON_Number)) {
            selected_id = json->valueu64;
        }
    }

    result = cJSON_CreateArray();
    if (selected_id != UINT64_MAX) {
        //single
        if (!ln_db_payment_info_load(&info, selected_id)) {
            return result;
        }
        if (!ln_db_payment_info_cur_open(&p_cur)) {
            return result;
        }
        cJSON *json = cmd_listpayment_json(p_cur, selected_id, &info);
        cJSON_AddItemToArray(result, json);
    } else {
        //all list
        if (!ln_db_payment_info_cur_open(&p_cur)) {
            return result;
        }
        while (ln_db_payment_info_cur_get(p_cur, &payment_id, &info)) {
            cJSON *json = cmd_listpayment_json(p_cur, payment_id, &info);
            cJSON_AddItemToArray(result, json);
        }
    }
    ln_db_payment_info_cur_close(p_cur, false);
    LOGD("exit\n");
    return result;
}


static cJSON *cmd_listpayment_json(void *p_cur, uint64_t PaymentId, const ln_payment_info_t *pInfo)
{
    cJSON *json = cJSON_CreateObject();

    cJSON_AddItemToObject(json, "payment_id", cJSON_CreateNumber64(PaymentId));

    char str_hash[BTC_SZ_HASH256 * 2 + 1];
    utl_str_bin2str(str_hash, pInfo->payment_hash, BTC_SZ_HASH256);
    cJSON_AddItemToObject(json, "payment_hash", cJSON_CreateString(str_hash));

    if (pInfo->state == LN_PAYMENT_STATE_SUCCEEDED) {
        char str_preimage[LN_SZ_PREIMAGE * 2 + 1];
        utl_str_bin2str(str_preimage, pInfo->preimage, LN_SZ_PREIMAGE);
        cJSON_AddItemToObject(json, "preimage", cJSON_CreateString(str_preimage));
    }

    cJSON_AddItemToObject(json, "additional_amount_msat", cJSON_CreateNumber64(pInfo->additional_amount_msat));
    cJSON_AddItemToObject(json, "block_count", cJSON_CreateNumber(pInfo->block_count));
    cJSON_AddItemToObject(json, "retry_count", cJSON_CreateNumber(pInfo->retry_count));
    cJSON_AddItemToObject(json, "max_retry_count", cJSON_CreateNumber(pInfo->max_retry_count));

    if (pInfo->auto_remove) {
        cJSON_AddItemToObject(json, "auto_remove", cJSON_CreateString("true"));
    } else {
        cJSON_AddItemToObject(json, "auto_remove", cJSON_CreateString("false"));
    }

    switch (pInfo->state) {
    case LN_PAYMENT_STATE_PROCESSING:
        cJSON_AddItemToObject(json, "state", cJSON_CreateString("processing"));
        break;
    case LN_PAYMENT_STATE_SUCCEEDED:
        cJSON_AddItemToObject(json, "state", cJSON_CreateString("succeeded"));
        break;
    case LN_PAYMENT_STATE_FAILED:
        cJSON_AddItemToObject(json, "state", cJSON_CreateString("failed"));
        break;
    default:
        LOGE("fail: ???\n");
    }

    utl_buf_t buf_invoice = UTL_BUF_INIT;
    if (ln_db_payment_invoice_load_2(&buf_invoice, PaymentId, p_cur)) {
        char *p_invoice = (char *)UTL_DBG_MALLOC(buf_invoice.len + 1);
        if (p_invoice) {
            memcpy(p_invoice, buf_invoice.buf, buf_invoice.len);
            p_invoice[buf_invoice.len] = '\0';
            cJSON_AddItemToObject(json, "invoice", cJSON_CreateString(p_invoice));
        } else {
            LOGE("fail: ???\n");
        }
        utl_buf_free(&buf_invoice);
    }

    return json;
}


static cJSON *cmd_removepayment(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)id;

    cJSON *result = NULL;
    bool ret = false;
    cJSON *json;
    int index = 0;
    uint64_t payment_id;

    LOGD("$$$ [JSONRPC]removepayment\n");

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        payment_id = json->valueu64;
        LOGD("payment_id=%" PRIu64 "\n", payment_id);
    } else {
        goto LABEL_EXIT;
    }

    ret = ln_db_payment_del_all(payment_id);

LABEL_EXIT:
    if (ret) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = RPCERR_PAY_REMOVE;
        ctx->error_message = error_str_cjson(RPCERR_PAY_REMOVE);
    }
    LOGD("exit\n");
    return result;
}


#ifdef USE_BITCOINJ
/** fund-inアドレス出力 : ptarmcli -F
 *
 */
static cJSON *cmd_getnewaddress(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = NULL;
    bool ret;
    char addr[BTC_SZ_ADDR_STR_MAX + 1];

    LOGD("$$$ [JSONRPC]getnewaddress\n");

    ret = btcrpc_getnewaddress(addr);
    if (ret) {
        result = cJSON_CreateString(addr);
    } else {
        ctx->error_code = RPCERR_BLOCKCHAIN;
        ctx->error_message = error_str_cjson(RPCERR_BLOCKCHAIN);
    }
    LOGD("exit\n");
    return result;
}


/** fund-inアドレス出力 : ptarmcli --getbalance
 *
 */
static cJSON *cmd_getbalance(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = NULL;
    bool ret;
    uint64_t amount = 0;

    LOGD("$$$ [JSONRPC]getbalance\n");

    ret = btcrpc_get_balance(&amount);
    if (ret) {
        result = cJSON_CreateNumber64(amount);
    } else {
        ctx->error_code = RPCERR_BLOCKCHAIN;
        ctx->error_message = error_str_cjson(RPCERR_BLOCKCHAIN);
    }
    LOGD("exit\n");
    return result;
}


/** 送金してwalletを空にする : ptarmcli --emptywallet
 *
 */
static cJSON *cmd_emptywallet(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = 0;
    bool ret = false;
    uint8_t txid[BTC_SZ_TXID];
    cJSON *json;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        LOGD("send to=%" PRIu32 "\n", json->valuestring);
    } else {
        err = RPCERR_PARSE;
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]emptywallet\n");
    ret = btcrpc_empty_wallet(txid, json->valuestring);

LABEL_EXIT:
    if (ret) {
        char str_txid[BTC_SZ_TXID * 2 + 1];
        utl_str_bin2str_rev(str_txid, txid, BTC_SZ_TXID);
        result = cJSON_CreateString(str_txid);
    } else {
        if (err == 0) {
            err = RPCERR_WALLET_ERR;
        }
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    LOGD("exit\n");
    return result;
}
#endif


#ifdef DEVELOPER_MODE
static void cmd_dev_send_error_cb(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;

    ln_error_set(&pConf->channel, 0, "DEBUG: error send");
    ln_error_send(&pConf->channel);
}


static cJSON *cmd_dev_send_error(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    LOGD("$$$ [JSONRPC]dev_send_error\n");

    lnapp_manager_each_node(cmd_dev_send_error_cb, NULL);

    return cJSON_CreateString(kOK);
}
#endif


/********************************************************************
 * private functions : procedure
 ********************************************************************/

/** peer接続
 *
 * @param[in]       pConn
 * @param[in,out]   ctx
 * @retval  エラーコード
 */
static int cmd_connect_proc(const peer_conn_t *pConn)
{
    LOGD("connect\n");

    int err;
    bool ret = p2p_initiator_start(pConn, &err);
    if (!ret) {
        return err;
    }

    //チェック
    if (pConn->routesync > PTARMD_ROUTESYNC_MAX) {
        return JRPC_INVALID_PARAMS;
    }

    int retry = M_RETRY_CONN_CHK;
    while (retry--) {
        lnapp_conf_t *p_conf = ptarmd_search_connected_node_id(pConn->node_id);
        if (p_conf) {
            if (lnapp_is_connected(p_conf)) {
                lnapp_manager_free_node_ref(p_conf);
                p_conf = NULL;
                break;
            }
            lnapp_manager_free_node_ref(p_conf);
            p_conf = NULL;
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
    LOGD("disconnect\n");

    int err;
    lnapp_conf_t *p_conf = ptarmd_search_connected_node_id(pNodeId);
    if (p_conf) {
        lnapp_stop(p_conf);
        err = 0;
        lnapp_manager_free_node_ref(p_conf);
        p_conf = NULL;
    } else {
        err = RPCERR_NOCONN;
    }

    return err;
}


/** channel establish開始
 *
 * @param[in]   pNodeId
 * @param[in]   pFund
 * @retval  エラーコード
 */
static int cmd_fund_proc(const uint8_t *pNodeId, const funding_conf_t *pFund, jrpc_context *ctx)
{
    LOGD("fund\n");

    int ret = 0;

    lnapp_conf_t *p_conf = ptarmd_search_connected_node_id(pNodeId);
    if (!p_conf) {
        //未接続
        return RPCERR_NOCONN;
    }

    if (p_conf->channel.status >= LN_STATUS_ESTABLISH) {
        //開設しようとしてチャネルが開いている
        ret = RPCERR_ALOPEN;
        goto LABEL_EXIT;
    }

    if (ln_funding_info_funding_now(&p_conf->channel.funding_info)) {
        //開設しようとしてチャネルが開設中
        ret = RPCERR_OPENING;
        goto LABEL_EXIT;
    }

    if (!lnapp_is_inited(p_conf)) {
        //BOLTメッセージとして初期化が完了していない(init/channel_reestablish交換できていない)
        ret = RPCERR_NOINIT;
        goto LABEL_EXIT;
    }

    if (!lnapp_check_ponglist(p_conf)) {
        LOGE("fail: node busy\n");
        ret = RPCERR_BUSY;
        goto LABEL_EXIT;
    }

    uint32_t feerate_per_kw = pFund->feerate_per_kw;
    if (feerate_per_kw == 0) {
        feerate_per_kw = monitor_btc_feerate_per_kw();
    }
    if (feerate_per_kw == 0) {
        LOGE("fail: feerate_per_kw==0\n");
        ret = RPCERR_BLOCKCHAIN;
        goto LABEL_EXIT;
    }
    if ( (pFund->funding_sat < LN_FUNDING_SATOSHIS_MIN) ||
         (pFund->funding_sat > LN_FUNDING_SATOSHIS_MAX) ) {
        char str[256];
        if (pFund->funding_sat < LN_FUNDING_SATOSHIS_MIN) {
            snprintf(str, sizeof(str), "funding_satoshis too low(<%d)",
                    LN_FUNDING_SATOSHIS_MIN);
        } else {
            snprintf(str, sizeof(str), "funding_satoshis too high(>%d)",
                    LN_FUNDING_SATOSHIS_MAX);
        }
        LOGE("%s\n", str);
        ctx->error_code = RPCERR_FUNDING;
        ctx->error_message = strdup_cjson(str);
        ret = M_RPCERR_FREESTRING;
        goto LABEL_EXIT;
    }
    if (LN_SATOSHI2MSAT(pFund->funding_sat) < pFund->push_msat) {
        LOGE("push_msat too high\n");
        ctx->error_code = RPCERR_FUNDING;
        ctx->error_message = strdup_cjson("push_msat too high");
        ret = M_RPCERR_FREESTRING;
        goto LABEL_EXIT;
    }

    if (!lnapp_funding(p_conf, pFund)) {
        ret = RPCERR_FUNDING;
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    lnapp_manager_free_node_ref(p_conf);
    return ret;
}


/** invoice作成
 *
 * @param[out]  pPaymentHash
 * @param[in]   AmountMsat
 * @retval  エラーコード
 */
static int cmd_invoice_proc(
    char **ppInvoice,
    uint8_t *pPaymentHash,
    bool bNoRField, uint8_t *pRFieldNum,
    uint64_t AmountMsat,
    uint32_t MinFinalCltvExpiry,
    uint32_t InvoiceExpiry,
    const ln_invoice_desc_t *pDesc)
{
    (void)pDesc;

    LOGD("invoice\n");

    ln_db_preimage_t preimage;
    btc_rng_rand(preimage.preimage, LN_SZ_PREIMAGE);
    preimage.amount_msat = AmountMsat;
    preimage.expiry = InvoiceExpiry;
    preimage.creation_time = (uint64_t)utl_time_time();

    ln_payment_hash_calc(pPaymentHash, preimage.preimage);

    ln_r_field_t *p_r_field = NULL;
    if (!bNoRField) {
        create_bolt11_r_field(&p_r_field, pRFieldNum, AmountMsat);
    } else {
        *pRFieldNum = 0;
    }
    *ppInvoice = create_bolt11(
                        pPaymentHash, AmountMsat,
                        pDesc,
                        InvoiceExpiry,
                        p_r_field, *pRFieldNum,
                        MinFinalCltvExpiry);
    UTL_DBG_FREE(p_r_field);

    ln_db_preimage_save(&preimage, *ppInvoice, NULL);

    return 0;
}


/** invoice削除
 *
 * @param[in]   pPaymentHash
 * @retval  エラーコード
 */
static int cmd_eraseinvoice_proc(const uint8_t *pPaymentHash)
{
    bool ret;

    if (pPaymentHash != NULL) {
        ret = ln_db_preimage_del_hash(pPaymentHash);
    } else {
        ret = ln_db_preimage_del(NULL);
    }
    if (!ret) {
        return RPCERR_INVOICE_ERASE;
    }
    return 0;
}


#if 0
static void cmd_routepay_save_info(
                const ln_invoice_t *pInvoiceData,
                const char *pInvoiceStr,
                int32_t BlockCnt)
{
    //log file
    char str_payment_hash[BTC_SZ_HASH256 * 2 + 1];
    char fname[256];
    FILE *fp;

    utl_str_bin2str(str_payment_hash, pInvoiceData->payment_hash, BTC_SZ_HASH256);
    sprintf(fname, FNAME_INVOICE_LOG, str_payment_hash);

    //file existence check
    struct stat buf;
    int ret = stat(fname, &buf);
    if ((ret == 0) && S_ISREG(buf.st_mode)) {
        //if already exist file, skip writing info.
        return;
    }

    fp = fopen(fname, "w");
    if (fp != NULL) {
        char time[UTL_SZ_TIME_FMT_STR + 1];

        fprintf(fp, "----------- invoice -----------\n");
        fprintf(fp, "invoice: %s\n", pInvoiceStr);
        fprintf(fp, "payment_hash: %s\n", str_payment_hash);
        fprintf(fp, "amount_msat: %" PRIu64 "\n", pInvoiceData->amount_msat);
        fprintf(fp, "current blockcount: %" PRId32 "\n", BlockCnt);
        fprintf(fp, "min_final_cltv_expiry: %" PRId32 "\n", pInvoiceData->min_final_cltv_expiry);
        fprintf(fp, "timestamp: %s\n", utl_time_fmt(time, pInvoiceData->timestamp));
        fclose(fp);
    }
}
#endif


#if 0
static void cmd_routepay_save_route(
                const ln_invoice_t *pInvoiceData,
                const ln_routing_result_t *pRouteResult,
                const char *pResultStr)
{
    //log file
    char str_payment_hash[BTC_SZ_HASH256 * 2 + 1];
    char fname[256];
    FILE *fp;

    utl_str_bin2str(str_payment_hash, pInvoiceData->payment_hash, BTC_SZ_HASH256);
    sprintf(fname, FNAME_INVOICE_LOG, str_payment_hash);
    fp = fopen(fname, "a");
    if (fp != NULL) {
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        char str_pubkey[BTC_SZ_PUBKEY * 2 + 1];

        fprintf(fp, "\n----------- route -----------\n");
        for (int lp = 0; lp < pRouteResult->num_hops; lp++) {
            utl_str_bin2str(str_pubkey, pRouteResult->hop_datain[lp].pubkey, BTC_SZ_PUBKEY);
            fprintf(fp, "[%d] %s\n", lp, str_pubkey);
            LOGD("[%d] %s\n", lp, str_pubkey);
            if (pRouteResult->hop_datain[lp].short_channel_id != 0) {
                ln_short_channel_id_string(str_sci, pRouteResult->hop_datain[lp].short_channel_id);
                fprintf(fp, "  short_channel_id: %s\n", str_sci);
                fprintf(fp, "       amount_msat: %" PRIu64 "\n", pRouteResult->hop_datain[lp].amt_to_forward);
                fprintf(fp, "       cltv_expiry: %" PRIu32 "\n\n", pRouteResult->hop_datain[lp].outgoing_cltv_value);

                LOGD("  short_channel_id: %s\n", str_sci);
                LOGD("       amount_msat: %" PRIu64 "\n", pRouteResult->hop_datain[lp].amt_to_forward);
                LOGD("       cltv_expiry: %" PRIu32 "\n\n", pRouteResult->hop_datain[lp].outgoing_cltv_value);
            }
        }
        fprintf(fp, "----------- end of route -----------\n");
        char time[UTL_SZ_TIME_FMT_STR + 1];
        fprintf(fp, "  result(%s)=%s\n", utl_time_str_time(time), pResultStr);
        fclose(fp);
    }
}
#endif


/** channel mutual close開始
 *
 * @param[in]       pNodeId
 * @retval  エラーコード
 */
static int cmd_close_mutual_proc(const uint8_t *pNodeId)
{
    LOGD("mutual close\n");

    int err = 0;
    lnapp_conf_t *p_conf = ptarmd_search_connected_node_id(pNodeId);
    if (!p_conf) {
        return RPCERR_NOCONN;
    }

    if (!lnapp_check_ponglist(p_conf)) {
        LOGE("fail: node busy\n");
        err = RPCERR_BUSY;
        goto LABEL_EXIT;
    }

    ln_status_t stat = ln_status_get(&p_conf->channel);
    if ((stat < LN_STATUS_ESTABLISH) || (stat > LN_STATUS_NORMAL_OPE)) {
        err = RPCERR_NOCHANNEL;
        goto LABEL_EXIT;
    }

    if (!lnapp_close_channel(p_conf)) {
        LOGE("fail: mutual  close\n");
        err = RPCERR_CLOSE_START;
    }

    err = 0;

LABEL_EXIT:
    lnapp_manager_free_node_ref(p_conf);
    return err;
}


/** channel unilateral close開始
 *
 * @param[in]       pNodeId
 * @retval  エラーコード
 */
static int cmd_close_unilateral_proc(const uint8_t *pNodeId)
{
    LOGD("unilateral close\n");

    int ret = 0;

    lnapp_conf_t *p_conf = lnapp_manager_get_node(pNodeId);
    if (!p_conf) {
        LOGE("fail: unilateral close\n");
        return RPCERR_NOCHANNEL;
    }

    lnapp_stop(p_conf);

    //XXX: block reconnection

    if (!lnapp_close_channel_force(p_conf)) {
        ret = RPCERR_CLOSE_FAIL;
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    lnapp_manager_free_node_ref(p_conf);
    return ret;
}


/********************************************************************
 * private functions : others
 ********************************************************************/

/** ptarmcli -c解析
 *
 */
static int json_connect(cJSON *params, int *pIndex, peer_conn_t *pConn)
{
    cJSON *json;

    if (params == NULL) {
        return RPCERR_PARSE;
    }
    pConn->routesync = PTARMD_ROUTESYNC_DEFAULT;

    //peer_node_id, peer_addr, peer_port
    int err = RPCERR_PARSE;
    json = cJSON_GetArrayItem(params, *pIndex);
    if (json && (json->type == cJSON_String)) {
        if (strlen(json->valuestring) == BTC_SZ_PUBKEY * 2) {
            err = json_connect_ipaddr(params, pIndex, pConn);
        } else {
            err = json_connect_name(params, pIndex, pConn);
        }
    } else {
        LOGE("fail: node_id\n");
        err = RPCERR_PARSE;
    }

    return err;
}


static int json_connect_ipaddr(cJSON *params, int *pIndex, peer_conn_t *pConn)
{
    //peer_node_id, peer_addr, peer_port
    cJSON *json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_String)) {
        bool ret = utl_str_str2bin(pConn->node_id, BTC_SZ_PUBKEY, json->valuestring);
        if (ret) {
            LOGD("pConn->node_id=%s\n", json->valuestring);
        } else {
            LOGE("fail: invalid node_id string\n");
            return RPCERR_PARSE;
        }
    } else {
        LOGE("fail: node_id\n");
        return RPCERR_PARSE;
    }
    if (memcmp(ln_node_get_id(), pConn->node_id, BTC_SZ_PUBKEY) == 0) {
        //node_idが自分と同じ
        LOGE("fail: same own node_id\n");
        return RPCERR_NODEID;
    }
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_String)) {
        strncpy(pConn->ipaddr, json->valuestring, SZ_IPV4_LEN);
        pConn->ipaddr[SZ_IPV4_LEN] = '\0';
        LOGD("pConn->ipaddr=%s\n", json->valuestring);
    } else {
        LOGE("fail: ipaddr\n");
        return RPCERR_ADDRESS;
    }
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_Number)) {
        pConn->port = json->valueint;
        LOGD("pConn->port=%d\n", json->valueint);
    } else {
        LOGE("fail: port\n");
        return RPCERR_PORTNUM;
    }

    return 0;
}


static int json_connect_name(cJSON *params, int *pIndex, peer_conn_t *pConn)
{
    cJSON *json = cJSON_GetArrayItem(params, *pIndex);
    if (json && (json->type != cJSON_String)) {
        LOGE("fail: not string\n");
        return RPCERR_PARSE;
    }

    char node_id_str[BTC_SZ_PUBKEY * 2 + 1] = "";
    char addr_str[LN_SZ_ADDRESS + 1] = "";
    int port = -1;
    int results = sscanf(json->valuestring, "%66s@%" LN_SZ_ADDRESS_STR "[^:]:%d", node_id_str, addr_str, &port);
    if ( (results == 2) && (port == -1)) {
        LOGD("use default port number\n");
        results = 3;
        port = 9735;
    }
    if ( (results != 3) ||
            (strlen(node_id_str) != BTC_SZ_PUBKEY * 2) ||
            (strlen(addr_str) < 3) ||      // shortest name: x.x
            (port <= 0) || (0x10000 <= port) ) {
        LOGE("fail: invalid string(%s)\n", json->valuestring);
        return RPCERR_PARSE;
    }
    bool ret = utl_net_resolve(pConn->ipaddr, addr_str, port);
    if (!ret) {
        LOGE("fail: resolve\n");
        return RPCERR_ADDRESS;
    }
    if (!utl_str_str2bin(pConn->node_id, BTC_SZ_PUBKEY, node_id_str)) {
        LOGE("fail: node_id\n");
        return RPCERR_NODEID;
    }
    if (!btc_keys_check_pub(pConn->node_id)) {
        LOGE("fail: not pubkey\n");
        return RPCERR_NODEID;
    }
    pConn->port = (uint16_t)port;
    (*pIndex) += 3; //node_id, addr, port

    return 0;
}


/** create invoice r-field
 *
 * channel_announcementする前や、channel_announcementしない場合、invoiceのr fieldに経路情報を追加することで、
 * announcementしていない部分の経路を知らせることができる。
 * ただ、その経路は自分へ向いているため、channelの相手が送信するchannel_updateの情報を追加することになる。
 * 現在接続していなくても、送金時には接続している可能性があるため、r fieldに追加する。
 */
static void create_bolt11_r_field(ln_r_field_t **ppRField, uint8_t *pRFieldNum, uint64_t AmountMsat)
{
    r_field_param_t param;

    *ppRField = NULL;
    *pRFieldNum = 0;

    param.pp_field = ppRField;
    param.amount_msat = AmountMsat;
    param.p_fieldnum = pRFieldNum;
    lnapp_manager_each_node(create_bolt11_r_field_2, &param);

    if (*pRFieldNum != 0) {
        LOGD("add r_field: %d\n", *pRFieldNum);
    } else {
        LOGD("no r_field\n");
    }
}


/** #lnapp_manager_each_node()処理関数
 *
 * @param[in,out]   pChannel        channel from DB
 * @param[in,out]   pParam          r_field_param_t構造体
 */
static void create_bolt11_r_field_2(lnapp_conf_t *pConf, void *pParam)
{
    bool ret;
    r_field_param_t *param = (r_field_param_t *)pParam;
    ln_channel_t *p_channel = &pConf->channel;

    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_channel_update_t msg;
    ret = ln_channel_update_get_peer(p_channel, &buf, &msg);
#ifdef M_RFIELD_AMOUNT
    LOGD("remote amount: %" PRIu64 "\n", ln_remote_msat(p_channel));
    if (ret && (ln_remote_payable_msat(p_channel) >= param->amount_msat)) {
        LOGD("invoice: add r-field(%" PRIx64 ")\n", ln_short_channel_id(p_channel));
#else
    if (ret && !ln_is_announced(p_channel)) {
#endif
        size_t sz = (1 + *param->p_fieldnum) * sizeof(ln_r_field_t);
        *param->pp_field = (ln_r_field_t *)UTL_DBG_REALLOC(*param->pp_field, sz);

        ln_r_field_t *pfield = *param->pp_field + *param->p_fieldnum;
        memcpy(pfield->node_id, ln_remote_node_id(p_channel), BTC_SZ_PUBKEY);
        pfield->short_channel_id = ln_short_channel_id(p_channel);
        pfield->fee_base_msat = msg.fee_base_msat;
        pfield->fee_prop_millionths = msg.fee_proportional_millionths;
        pfield->cltv_expiry_delta = msg.cltv_expiry_delta;

        (*param->p_fieldnum)++;
        LOGD("r_field num=%d\n", *param->p_fieldnum);
    }
    utl_buf_free(&buf);
}


/** BOLT11文字列生成
 *
 */
static char *create_bolt11(
                const uint8_t *pPaymentHash,
                uint64_t Amount,
                const ln_invoice_desc_t *pDesc,
                uint32_t Expiry,
                const ln_r_field_t *pRField,
                uint8_t RFieldNum,
                uint32_t MinFinalCltvExpiry)
{
    uint8_t type;
    btc_block_chain_t gtype = btc_block_get_chain(ln_genesishash_get());
    switch (gtype) {
    case BTC_BLOCK_CHAIN_BTCMAIN:
        type = LN_INVOICE_MAINNET;
        break;
    case BTC_BLOCK_CHAIN_BTCTEST:
        type = LN_INVOICE_TESTNET;
        break;
    case BTC_BLOCK_CHAIN_BTCREGTEST:
        type = LN_INVOICE_REGTEST;
        break;
    default:
        type = BTC_BLOCK_CHAIN_UNKNOWN;
        break;
    }
    char *p_invoice = NULL;
    if (type != BTC_BLOCK_CHAIN_UNKNOWN) {
        ln_invoice_create(&p_invoice, type,
                pPaymentHash, Amount, Expiry, pDesc,
                pRField, RFieldNum, MinFinalCltvExpiry);
    }
    return p_invoice;
}


/** JSON-RPC送信
 *
 */
static int send_json(const char *pSend, const char *pAddr, uint16_t Port)
{
    int retval = -1;
    struct sockaddr_in sv_addr;

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        return retval;
    }
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(pAddr);
    sv_addr.sin_port = htons(Port);
    retval = connect(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    if (retval < 0) {
        close(sock);
        return retval;
    }
    retval = write(sock, pSend, strlen(pSend));
    if (retval != (int)strlen(pSend)) {
        LOGD("write ret=%d\n", retval);
    }

    //受信を待つとDBの都合でロックしてしまうため、すぐに閉じる

    close(sock);

    return 0;
}


/** getcommittx処理
 *
 */
static void getcommittx(lnapp_conf_t *pConf, void *pParam)
{
    getcommittx_t *param = (getcommittx_t *)pParam;
    if (memcmp(param->p_node_id, ln_remote_node_id(&pConf->channel), BTC_SZ_PUBKEY) == 0) {
        get_committx(&pConf->channel, param->result, param->b_local);
    }
}

static bool get_committx(ln_channel_t *pChannel, cJSON *pResult, bool bLocal)
{
    LOGD("bLocal=%d\n", bLocal);

    ln_close_force_t close_dat;
    bool ret;
    if (bLocal) {
        ret = ln_close_create_unilateral_tx(pChannel, &close_dat);
    } else {
        ret = ln_close_create_tx(pChannel, &close_dat);
    }
    if (ret) {
        cJSON *result = cJSON_CreateObject();
        utl_buf_t buf = UTL_BUF_INIT;

#if 1
        if (close_dat.p_tx[LN_CLOSE_IDX_COMMIT].vout_cnt > 0) {
            btc_tx_write(&close_dat.p_tx[LN_CLOSE_IDX_COMMIT], &buf);
            char *transaction = (char *)UTL_DBG_MALLOC(buf.len * 2 + 1);        //UTL_DBG_FREE: この中
            utl_str_bin2str(transaction, buf.buf, buf.len);
            utl_buf_free(&buf);

            cJSON_AddItemToObject(result, "committx", cJSON_CreateString(transaction));
            UTL_DBG_FREE(transaction);
        }
#else
        for (int lp = 0; lp < close_dat.num; lp++) {
            if (close_dat.p_tx[lp].vout_cnt > 0) {
                btc_tx_write(&close_dat.p_tx[lp], &buf);
                char *transaction = (char *)UTL_DBG_MALLOC(buf.len * 2 + 1);        //UTL_DBG_FREE: この中
                utl_str_bin2str(transaction, buf.buf, buf.len);
                utl_buf_free(&buf);

                char title[128];
                if (lp == LN_CLOSE_IDX_COMMIT) {
                    strcpy(title, "committx");
                } else if (lp == LN_CLOSE_IDX_TO_LOCAL) {
                    strcpy(title, "to_local");
                } else if (lp == LN_CLOSE_IDX_TO_REMOTE) {
                    strcpy(title, "to_remote");
                } else {
                    snprintf(title, sizeof(title), "htlc%d", lp - LN_CLOSE_IDX_HTLC);
                }
                cJSON_AddItemToObject(result, title, cJSON_CreateString(transaction));
                UTL_DBG_FREE(transaction);
            }
        }

        int num = close_dat.tx_buf.len / sizeof(btc_tx_t);
        btc_tx_t *p_tx = (btc_tx_t *)close_dat.tx_buf.buf;
        for (int lp = 0; lp < num; lp++) {
            btc_tx_write(&p_tx[lp], &buf);
            char *transaction = (char *)UTL_DBG_MALLOC(buf.len * 2 + 1);    //UTL_DBG_FREE: この中
            utl_str_bin2str(transaction, buf.buf, buf.len);
            utl_buf_free(&buf);

            cJSON_AddItemToObject(result, "htlc_out", cJSON_CreateString(transaction));
            UTL_DBG_FREE(transaction);
        }
#endif
        const char *p_title = (bLocal) ? "local" : "remote";
        cJSON_AddItemToObject(pResult, p_title, result);

        ln_close_free_forcetx(&close_dat);
    }

    return ret;
}


/**
 *
 */
static char *strdup_cjson(const char *pStr)
{
    //free by cjson
    //  don't free yourself
    //  don't use UTL_DBG_STRDUP
    return strdup(pStr);
}


/**
 *
 */
static char *error_str_cjson(int errCode)
{
    return strdup_cjson(ptarmd_error_cstr(errCode));
}


int payment_error_to_rpc_error(ln_payment_error_t PayErr)
{
    switch (PayErr) {
    case LN_PAYMENT_OK: return 0;
    case LN_PAYMENT_ERROR: return RPCERR_PAY_STOP;
    case LN_PAYMENT_ERROR_INVOICE: return RPCERR_PAY_STOP;
    case LN_PAYMENT_ERROR_INVOICE_INVALID: return RPCERR_PARSE;
    case LN_PAYMENT_ERROR_INVOICE_INVALID_TYPE: return RPCERR_INVOICE_FAIL;
    case LN_PAYMENT_ERROR_INVOICE_OUTDATE: return RPCERR_INVOICE_OUTDATE;
    case LN_PAYMENT_ERROR_ROUTE: return RPCERR_PAY_STOP;
    case LN_PAYMENT_ERROR_ROUTE_INVALID: return RPCERR_PAY_STOP;
    case LN_PAYMENT_ERROR_ROUTE_NO_START: return RPCERR_NOSTART;
    case LN_PAYMENT_ERROR_ROUTE_NO_GOAL: return RPCERR_NOGOAL;
    case LN_PAYMENT_ERROR_ROUTE_NO_ROUTE: return RPCERR_NOROUTE;
    case LN_PAYMENT_ERROR_ROUTE_TOO_MANY_HOPS: return RPCERR_TOOMANYHOP;
    case LN_PAYMENT_ERROR_RETRY: return RPCERR_PAY_STOP;
    default:
        ;
    }
    return RPCERR_PAY_STOP;
}


