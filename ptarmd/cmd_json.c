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
#include "utl_time.h"

#include "btc_crypto.h"
#include "ln_segwit_addr.h"

#include "ptarmd.h"
#include "btcrpc.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "monitoring.h"
#include "wallet.h"
#include "cmd_json.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_SZ_JSONSTR            (8192)
#define M_SZ_PAYERR             (128)
#define M_RETRY_CONN_CHK        (10)        ///< 接続チェック[sec]

#define M_RPCERR_FREESTRING     (-1)        //no error_str_cjson() or strdup_cjson()


/********************************************************************
 * macros functions
 ********************************************************************/


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    bool b_local;
    const uint8_t *p_nodeid;
    cJSON *result;
} getcommittx_t;


typedef struct {
    ln_fieldr_t     **pp_field;
    uint8_t         *p_fieldnum;
} rfield_prm_t;


/********************************************************************
 * static variables
 ********************************************************************/

static struct jrpc_server   mJrpc;
static char                 mLastPayErr[M_SZ_PAYERR];       //最後に送金エラーが発生した時刻
static int                  mPayTryCount = 0;               //送金トライ回数
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
static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_invoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_eraseinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_paytest(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_routepay_cont(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_debug(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_disautoconn(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_removechannel(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_setfeerate(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_estimatefundingfee(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_walletback(jrpc_context *ctx, cJSON *params, cJSON *id);
#ifdef USE_BITCOINJ
static cJSON *cmd_getnewaddress(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_getbalance(jrpc_context *ctx, cJSON *params, cJSON *id);
static cJSON *cmd_emptywallet(jrpc_context *ctx, cJSON *params, cJSON *id);
#endif

static int cmd_connect_proc(const peer_conn_t *pConn, jrpc_context *ctx);
static int cmd_disconnect_proc(const uint8_t *pNodeId);
static int cmd_stop_proc(void);
static int cmd_fund_proc(const uint8_t *pNodeId, const funding_conf_t *pFund, jrpc_context *ctx);
static int cmd_invoice_proc(uint8_t *pPayHash, uint64_t AmountMsat);
static int cmd_eraseinvoice_proc(const uint8_t *pPayHash);
static int cmd_routepay_proc1(
                ln_invoice_t **ppInvoiceData,
                ln_routing_result_t *pRouteResult,
                const char *pInvoice,
                uint64_t AddAmountMsat,
                int32_t BlockCnt);
static int cmd_routepay_proc2(
                lnapp_conf_t *pAppConf,
                const ln_invoice_t *pInvoiceData,
                const ln_routing_result_t *pRouteResult,
                const char *pInvoiceStr,
                uint64_t AddAmountMsat);
static void cmd_routepay_save_info(
                const ln_invoice_t *pInvoiceData,
                int32_t BlockCnt);
static void cmd_routepay_save_route(
                const ln_invoice_t *pInvoiceData,
                const ln_routing_result_t *pRouteResult,
                const char *pResultStr);
static int cmd_close_mutual_proc(const uint8_t *pNodeId);
static int cmd_close_unilateral_proc(const uint8_t *pNodeId);

static bool json_connect(cJSON *params, int *pIndex, peer_conn_t *pConn);
static char *create_bolt11(
                const uint8_t *pPayHash,
                uint64_t Amount,
                uint32_t Expiry,
                const ln_fieldr_t *pFieldR,
                uint8_t FieldRNum,
                uint32_t MinFinalCltvExpiry);
static void create_bolt11_rfield(ln_fieldr_t **ppFieldR, uint8_t *pFieldRNum);
static bool comp_func_cnl(ln_self_t *self, void *p_db_param, void *p_param);
static int send_json(const char *pSend, const char *pAddr, uint16_t Port);
static bool comp_func_getcommittx(ln_self_t *self, void *p_db_param, void *p_param);
static char *strdup_cjson(const char *pStr);
static char *error_str_cjson(int errCode);


/********************************************************************
 * public functions
 ********************************************************************/

void cmd_json_start(uint16_t Port)
{
    int ret = jrpc_server_init(&mJrpc, Port);
    if (ret != 0) {
        fprintf(stderr, "ERR: cannot start JSON-RPC event loop\n");
        ptarmd_stop();
        return;
    }

    mRunning = true;
    jrpc_register_procedure(&mJrpc, cmd_connect,     "connect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_connect_nores, "CONNECT", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getinfo,     "getinfo", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disconnect,  "disconnect", NULL);
    jrpc_register_procedure(&mJrpc, cmd_stop,        "stop", NULL);
    jrpc_register_procedure(&mJrpc, cmd_fund,        "fund", NULL);
    jrpc_register_procedure(&mJrpc, cmd_invoice,     "invoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_eraseinvoice,"eraseinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_listinvoice, "listinvoice", NULL);
    jrpc_register_procedure(&mJrpc, cmd_paytest,     "PAY", NULL);
    jrpc_register_procedure(&mJrpc, cmd_routepay,    "routepay", NULL);
    jrpc_register_procedure(&mJrpc, cmd_routepay_cont,  "_routepay_cont", NULL);
    jrpc_register_procedure(&mJrpc, cmd_close,       "close", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getlasterror,"getlasterror", NULL);
    jrpc_register_procedure(&mJrpc, cmd_debug,       "debug", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getcommittx, "getcommittx", NULL);
    jrpc_register_procedure(&mJrpc, cmd_disautoconn, "disautoconn", NULL);
    jrpc_register_procedure(&mJrpc, cmd_removechannel,"removechannel", NULL);
    jrpc_register_procedure(&mJrpc, cmd_setfeerate,   "setfeerate", NULL);
    jrpc_register_procedure(&mJrpc, cmd_estimatefundingfee, "estimatefundingfee", NULL);
    jrpc_register_procedure(&mJrpc, cmd_walletback, "walletback", NULL);
#ifdef USE_BITCOINJ
    jrpc_register_procedure(&mJrpc, cmd_getnewaddress,  "getnewaddress", NULL);
    jrpc_register_procedure(&mJrpc, cmd_getbalance,  "getbalance", NULL);
    jrpc_register_procedure(&mJrpc, cmd_emptywallet, "emptywallet", NULL);
#endif
    LOGD("[start]jrpc_server\n");
    jrpc_server_run(&mJrpc);
    jrpc_server_destroy(&mJrpc);

    LOGD("[exit]jrpc_server\n");
}


void cmd_json_stop(void)
{
    if (mRunning) {
        jrpc_server_stop(&mJrpc);
        LOGD("stop jrpc_server\n");
        mRunning = false;
    }
}


int cmd_json_connect(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port)
{
    char nodestr[BTC_SZ_PUBKEY * 2 + 1];
    char json[256];

    utl_str_bin2str(nodestr, pNodeId, BTC_SZ_PUBKEY);
    LOGD("connect:%s@%s:%d\n", nodestr, pIpAddr, Port);

    bool ret = p2p_cli_connect_test(pIpAddr, Port);
    if (!ret) {
        return -1;
    }

    sprintf(json, "{\"method\":\"CONNECT\",\"params\":[\"%s\",\"%s\",%d]}",
                        nodestr, pIpAddr, Port);

    int retval = send_json(json, "127.0.0.1", mJrpc.port_number);
    LOGD("retval=%d\n", retval);

    return retval;
}


int cmd_json_pay(const char *pInvoice, uint64_t AddAmountMsat)
{
    LOGD("invoice:%s\n", pInvoice);
    char *json = (char *)UTL_DBG_MALLOC(M_SZ_JSONSTR);
    snprintf(json, M_SZ_JSONSTR,
        "{\"method\":\"_routepay_cont\",\"params\":[\"%s\",%" PRIu64 "]}", pInvoice, AddAmountMsat);
    int retval = send_json(json, "127.0.0.1", mJrpc.port_number);
    LOGD("retval=%d\n", retval);
    UTL_DBG_FREE(json);

    return retval;
}


int cmd_json_pay_retry(const uint8_t *pPayHash)
{
    bool ret;
    int retval = ENOENT;
    char *p_invoice = NULL;
    uint64_t add_amount_msat;

    LOGD("pay_retry\n");
    ret = ln_db_invoice_load(&p_invoice, &add_amount_msat, pPayHash);   //p_invoiceはUTL_DBG_MALLOC()される
    if (ret) {
        retval = cmd_json_pay(p_invoice, add_amount_msat);
    } else {
        LOGE("fail: invoice not found\n");
    }
    UTL_DBG_FREE(p_invoice);

    return retval;
}


void cmd_json_pay_result(const uint8_t *pPaymentHash, const char *pResultStr)
{
    //log file
    char str_payhash[BTC_SZ_HASH256 * 2 + 1];
    char fname[256];
    FILE *fp;

    utl_str_bin2str(str_payhash, pPaymentHash, BTC_SZ_HASH256);
    sprintf(fname, FNAME_INVOICE_LOG, str_payhash);
    fp = fopen(fname, "a");
    if (fp != NULL) {
        char time[UTL_SZ_TIME_FMT_STR + 1];
        fprintf(fp, "  result(%s)=%s\n", utl_time_str_time(time), pResultStr);
        fclose(fp);
    }
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

    int err = RPCERR_PARSE;
    cJSON *json;
    peer_conn_t conn;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    //initial_routing_sync
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        conn.routesync = json->valueint;
    }

    LOGD("$$$: [JSONRPC]connect\n");

    err = cmd_connect_proc(&conn, ctx);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    return result;
}



/** 接続(内部用)
 *
 */
static cJSON *cmd_connect_nores(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    peer_conn_t conn;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        return NULL;
    }

    (void)cmd_connect_proc(&conn, ctx);
    return NULL;
}


/** 状態出力 : ptarmcli -l
 *
 */
static cJSON *cmd_getinfo(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = cJSON_CreateObject();
    cJSON *result_peer = cJSON_CreateArray();

    uint64_t total_amount = ln_node_total_msat();

    LOGD("$$$: [JSONRPC]getinfo\n");

    //basic info
    char node_id[BTC_SZ_PUBKEY * 2 + 1];
    utl_str_bin2str(node_id, ln_node_getid(), BTC_SZ_PUBKEY);
    cJSON_AddItemToObject(result, "node_id", cJSON_CreateString(node_id));
    cJSON_AddItemToObject(result, "node_port", cJSON_CreateNumber(ln_node_addr()->port));
    cJSON_AddNumber64ToObject(result, "total_our_msat", total_amount);

#ifdef DEVELOPER_MODE
    //blockcount
    int32_t blockcnt;
    bool ret = btcrpc_getblockcount(&blockcnt);
    if (ret) {
        cJSON_AddItemToObject(result, "block_count", cJSON_CreateNumber(blockcnt));
    } else {
        LOGE("fail btcrpc_getblockcount()\n");
    }
#endif

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
            char hash_str[BTC_SZ_HASH256 * 2 + 1];
            utl_str_bin2str(hash_str, p, BTC_SZ_HASH256);
            p += BTC_SZ_HASH256;
            cJSON_AddItemToArray(result_hash, cJSON_CreateString(hash_str));
        }
        UTL_DBG_FREE(p_hash);       //UTL_DBG_MALLOC or UTL_DBG_MALLOC by ln_lmdb
        cJSON_AddItemToObject(result, "paying_hash", result_hash);
    }
    cJSON_AddItemToObject(result, "last_errpay_date", cJSON_CreateString(mLastPayErr));

    return result;
}


/** 指定channel切断 : ptarmcli -q xxxxx
 *
 */
static cJSON *cmd_disconnect(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    peer_conn_t conn;
    cJSON *result = NULL;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    LOGD("$$$: [JSONRPC]disconnect\n");

    err = cmd_disconnect_proc(conn.node_id);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString(kOK);
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    return result;
}


/** ノード終了 : ptarmcli -q
 *
 */
static cJSON *cmd_stop(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = NULL;

    LOGD("$$$: [JSONRPC]stop\n");

    monitor_disable_autoconn(true);
    int err = cmd_stop_proc();
    if (err == 0) {
        result = cJSON_CreateString("OK");
    } else {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
    jrpc_server_stop(&mJrpc);

    return result;
}


/** channel establish開始 : ptarmcli -f
 *
 */
static cJSON *cmd_fund(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    cJSON *json;
    peer_conn_t conn;
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
#ifdef USE_BITCOIND
    if (json && (json->type == cJSON_String)) {
        utl_str_str2bin_rev(fundconf.txid, BTC_SZ_TXID, json->valuestring);
        LOGD("txid=%s\n", json->valuestring);
    } else {
        goto LABEL_EXIT;
    }
#endif
    //txindex
    json = cJSON_GetArrayItem(params, index++);
#ifdef USE_BITCOIND
    if (json && (json->type == cJSON_Number)) {
        fundconf.txindex = json->valueint;
        LOGD("txindex=%d\n", json->valueint);
    } else {
        goto LABEL_EXIT;
    }
#endif
    //funding_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.funding_sat = json->valueu64;
        LOGD("funding_sat=%" PRIu64 "\n", fundconf.funding_sat);
    } else {
        goto LABEL_EXIT;
    }
    //push_sat
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        fundconf.push_sat = json->valueu64;
        LOGD("push_sat=%" PRIu64 "\n", fundconf.push_sat);
    } else {
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
    uint64_t amount = 0;
    cJSON *result = NULL;
    int index = 0;
    uint32_t min_final_cltv_expiry;

    if (params == NULL) {
        goto LABEL_EXIT;
    }

    //amount
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        amount = json->valueu64;
        LOGD("amount=%" PRIu64 "\n", amount);
    } else {
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

    LOGD("$$$: [JSONRPC]invoice\n");

    uint8_t preimage_hash[BTC_SZ_HASH256];
    err = cmd_invoice_proc(preimage_hash, amount);

LABEL_EXIT:
    if (err == 0) {
        ln_fieldr_t *p_rfield = NULL;
        uint8_t rfieldnum = 0;
        create_bolt11_rfield(&p_rfield, &rfieldnum);
        char *p_invoice = create_bolt11(preimage_hash, amount,
                            LN_INVOICE_EXPIRY, p_rfield, rfieldnum,
                            min_final_cltv_expiry);

        if (p_invoice != NULL) {
            char str_hash[BTC_SZ_HASH256 * 2 + 1];

            utl_str_bin2str(str_hash, preimage_hash, BTC_SZ_HASH256);
            result = cJSON_CreateObject();
            cJSON_AddItemToObject(result, "hash", cJSON_CreateString(str_hash));
            cJSON_AddItemToObject(result, "amount", cJSON_CreateNumber64(amount));
            cJSON_AddItemToObject(result, "bolt11", cJSON_CreateString(p_invoice));

            UTL_DBG_FREE(p_invoice);
        } else {
            LOGE("fail: BOLT11 format\n");
            err = RPCERR_PARSE;
        }
        UTL_DBG_FREE(p_rfield);
    }
    if (err != 0) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
    }
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
    return result;
}


/** invoice一覧出力 : ptarmcli -m
 *
 */
static cJSON *cmd_listinvoice(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)ctx; (void)params; (void)id;

    cJSON *result = NULL;
    uint8_t preimage_hash[BTC_SZ_HASH256];
    ln_db_preimg_t preimg;
    void *p_cur;
    bool ret;

    LOGD("$$$: [JSONRPC]listinvoice\n");

    result = cJSON_CreateArray();
    ret = ln_db_preimg_cur_open(&p_cur);
    while (ret) {
        bool detect;
        ret = ln_db_preimg_cur_get(p_cur, &detect, &preimg);
        if (detect) {
            ln_preimage_hash_calc(preimage_hash, preimg.preimage);
            cJSON *json = cJSON_CreateObject();

            char str_hash[BTC_SZ_HASH256 * 2 + 1];
            utl_str_bin2str(str_hash, preimage_hash, BTC_SZ_HASH256);
            cJSON_AddItemToObject(json, "hash", cJSON_CreateString(str_hash));
            cJSON_AddItemToObject(json, "amount_msat", cJSON_CreateNumber64(preimg.amount_msat));
            char time[UTL_SZ_TIME_FMT_STR + 1];
            cJSON_AddItemToObject(json, "creation_time", cJSON_CreateString(utl_time_fmt(time, preimg.creation_time)));
            if (preimg.expiry != UINT32_MAX) {
                cJSON_AddItemToObject(json, "expiry", cJSON_CreateNumber(preimg.expiry));
                // ln_fieldr_t *p_rfield = NULL;
                // uint8_t rfieldnum = 0;
                // create_bolt11_rfield(&p_rfield, &rfieldnum);
                // char *p_invoice = create_bolt11(preimage_hash, preimg.amount_msat, preimg.expiry, p_rfield, rfieldnum, LN_MIN_FINAL_CLTV_EXPIRY);
                // if (p_invoice != NULL) {
                //     cJSON_AddItemToObject(json, "invoice", cJSON_CreateString(p_invoice));
                //     UTL_DBG_FREE(p_invoice);
                //     APP_FREE(p_rfield);
                // }
            } else {
                cJSON_AddItemToObject(json, "expiry", cJSON_CreateString("remove after close"));
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
static cJSON *cmd_paytest(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    bool ret;
    int32_t blockcnt;
    cJSON *json;
    payment_conf_t payconf;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    LOGD("$$$: [JSONRPC]PAY\n");

    //blockcount
    ret = btcrpc_getblockcount(&blockcnt);
    if (!ret) {
        index = -1;
        goto LABEL_EXIT;
    }
    LOGD("blockcnt=%d\n", blockcnt);

    //payment_hash, hop_num
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        utl_str_str2bin(payconf.payment_hash, BTC_SZ_HASH256, json->valuestring);
        LOGD("payment_hash=%s\n", json->valuestring);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        payconf.hop_num = json->valueint;
        LOGD("hop_num=%d\n", json->valueint);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //array
    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Array)) {
        LOGD("trace array\n");
    } else {
        index = -1;
        goto LABEL_EXIT;
    }
    //[ [...], [...], ..., [...] ]
    for (int lp = 0; lp < payconf.hop_num; lp++) {
        ln_hop_datain_t *p = &payconf.hop_datain[lp];

        LOGD("loop=%d\n", lp);
        cJSON *jarray = cJSON_GetArrayItem(json, lp);
        if (jarray && (jarray->type == cJSON_Array)) {
            //[node_id, short_channel_id, amt_to_forward, outgoing_cltv_value]

            //node_id
            cJSON *jprm = cJSON_GetArrayItem(jarray, 0);
            LOGD("jprm=%p\n", jprm);
            if (jprm && (jprm->type == cJSON_String)) {
                utl_str_str2bin(p->pubkey, BTC_SZ_PUBKEY, jprm->valuestring);
                LOGD("  node_id=");
                DUMPD(p->pubkey, BTC_SZ_PUBKEY);
            } else {
                LOGE("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
            //short_channel_id
            jprm = cJSON_GetArrayItem(jarray, 1);
            if (jprm && (jprm->type == cJSON_String)) {
                p->short_channel_id = strtoull(jprm->valuestring, NULL, 16);
                LOGD("  short_channel_id=%016" PRIx64 "\n", p->short_channel_id);
            } else {
                LOGE("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
            //amt_to_forward
            jprm = cJSON_GetArrayItem(jarray, 2);
            if (jprm && (jprm->type == cJSON_Number)) {
                p->amt_to_forward = jprm->valueu64;
                LOGD("  amt_to_forward=%" PRIu64 "\n", p->amt_to_forward);
            } else {
                LOGE("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
            //outgoing_cltv_value
            jprm = cJSON_GetArrayItem(jarray, 3);
            if (jprm && (jprm->type == cJSON_Number)) {
                p->outgoing_cltv_value = jprm->valueint + blockcnt;
                LOGD("  outgoing_cltv_value=%u\n", p->outgoing_cltv_value);
            } else {
                LOGE("fail: p=%p\n", jprm);
                index = -1;
                goto LABEL_EXIT;
            }
        } else {
            LOGE("fail: p=%p\n", jarray);
            index = -1;
            goto LABEL_EXIT;
        }
    }

    LOGD("payment\n");

    lnapp_conf_t *p_appconf = ptarmd_search_transferable_nodeid(payconf.hop_datain[1].pubkey);
    if (p_appconf != NULL) {

        bool inited = lnapp_is_inited(p_appconf);
        if (inited) {
            bool ret;
            const char *p_result = NULL;
            ret = lnapp_payment(p_appconf, &payconf, &p_result);
            if (ret) {
                result = cJSON_CreateString("Progressing");
            } else {
                ctx->error_code = RPCERR_PAY_STOP;
                ctx->error_message = error_str_cjson(RPCERR_PAY_STOP);
            }
        } else {
            //BOLTメッセージとして初期化が完了していない(init/channel_reestablish交換できていない)
            ctx->error_code = RPCERR_NOINIT;
            ctx->error_message = error_str_cjson(RPCERR_NOINIT);
        }
    } else {
        ctx->error_code = RPCERR_NOCONN;
        ctx->error_message = error_str_cjson(RPCERR_NOCONN);
    }

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
    }
    if (ctx->error_code != 0) {
        ln_db_invoice_del(payconf.payment_hash);
        //一時的なスキップは削除する
        ln_db_routeskip_drop(true);
    }

    return result;
}


/** 送金開始: ptarmcli -r
 *
 * 一時ルーティング除外リストをクリアしてから送金する
 */
static cJSON *cmd_routepay(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    LOGD("$$$ [JSONRPC]routepay\n");

    ln_db_routeskip_work(true);
    mPayTryCount = 0;
    return cmd_routepay_cont(ctx, params, id);
}


/** 送金・再送金
 *
 */
static cJSON *cmd_routepay_cont(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    LOGD("$$$ [JSONRPC]routepay_cont\n");

    bool ret;
    int32_t blockcnt;
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
        p_invoice = UTL_DBG_STRDUP(json->valuestring);
    } else {
        LOGE("fail: invalid invoice string\n");
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_Number)) {
        add_amount_msat = json->valueu64;
    } else {
        LOGE("fail: invalid add amount_msat\n");
        goto LABEL_EXIT;
    }

    //blockcount
    ret = btcrpc_getblockcount(&blockcnt);
    if (!ret) {
        err = RPCERR_BLOCKCHAIN;
        goto LABEL_EXIT;
    }
    LOGD("blockcnt=%d\n", blockcnt);

    err = cmd_routepay_proc1(&p_invoice_data, &rt_ret,
                    p_invoice, add_amount_msat, blockcnt);
    if (err != 0) {
        LOGE("fail: pay1\n");
        goto LABEL_EXIT;
    }

    lnapp_conf_t *p_appconf = ptarmd_search_transferable_nodeid(rt_ret.hop_datain[1].pubkey);
    if (p_appconf != NULL) {
        bool ret = lnapp_check_ponglist(p_appconf);
        if (!ret) {
            err = RPCERR_BUSY;
            goto LABEL_EXIT;
        }
    }

    // 送金開始
    //      ここまでで送金ルートは作成済み
    //      これ以降は失敗してもリトライする
    LOGD("routepay: pay1\n");
    err = cmd_routepay_proc2(
                    p_appconf,
                    p_invoice_data, &rt_ret,
                    p_invoice, add_amount_msat);
    retry = (err == RPCERR_PAY_RETRY);

LABEL_EXIT:
    if (err == 0) {
        result = cJSON_CreateString("start payment...");
    } else {
        //paymentはretryを行うが、JSON-RPCのreplyは初回のみ有効
        if (retry) {
            LOGD("retry: skip %016" PRIx64 "\n", rt_ret.hop_datain[0].short_channel_id);
            ln_db_routeskip_save(rt_ret.hop_datain[0].short_channel_id, true);
            cmd_json_pay(p_invoice, add_amount_msat);
            result = cJSON_CreateString("searching payment route...");
        } else {
            //送金失敗
            ctx->error_code = err;
            ctx->error_message = error_str_cjson(err);

            ln_db_invoice_del(p_invoice_data->payment_hash);
            ln_db_routeskip_work(false);
            cmd_json_pay_result(p_invoice_data->payment_hash, "give up");

            //log
            char str_payhash[BTC_SZ_HASH256 * 2 + 1];
            char time[UTL_SZ_TIME_FMT_STR + 1];

            utl_str_bin2str(str_payhash, p_invoice_data->payment_hash, BTC_SZ_HASH256);
            sprintf(mLastPayErr, "[%s]fail payment: %s", utl_time_str_time(time), str_payhash);
            LOGD("%s\n", mLastPayErr);
            ptarmd_eventlog(NULL, "payment fail: payment_hash=%s reason=%s", str_payhash, ctx->error_message);
        }
    }
    UTL_DBG_FREE(p_invoice_data);
    UTL_DBG_FREE(p_invoice);

    return result;
}


/** channel mutual close開始 : ptarmcli -x
 *
 */
static cJSON *cmd_close(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    int err = RPCERR_PARSE;
    peer_conn_t conn;
    cJSON *result = NULL;
    cJSON *json;
    int index = 0;
    const char *p_str = "";

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]close\n");

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

    return result;
}


/** 最後に発生したエラー出力 : ptarmcli -w
 *
 */
static cJSON *cmd_getlasterror(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    peer_conn_t conn;
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]getlasterror\n");

    lnapp_conf_t *p_appconf = ptarmd_search_connected_nodeid(conn.node_id);
    if (p_appconf != NULL) {
        //接続中
        LOGD("error code: %d\n", p_appconf->err);
        ctx->error_code = p_appconf->err;
        if (p_appconf->p_errstr != NULL) {
            LOGD("error msg: %s\n", p_appconf->p_errstr);
            ctx->error_message = strdup_cjson(p_appconf->p_errstr);
        }
    } else {
        ctx->error_code = RPCERR_NOCONN;
        ctx->error_message = error_str_cjson(RPCERR_NOCONN);
    }

LABEL_EXIT:
    return NULL;
}


/** デバッグフラグのトグル : ptarmcli -d
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
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
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
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
    }

LABEL_EXIT:
    return result;
}


/** commitment transaction出力 : ptarmcli -g
 *
 * commitment transactionおよび関連するtransactionを16進数文字列出力する。
 */
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    peer_conn_t conn;
    cJSON *result = cJSON_CreateObject();
    int index = 0;

    //connect parameter
    bool ret = json_connect(params, &index, &conn);
    if (!ret) {
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]getcommittx\n");

    getcommittx_t prm;
    prm.b_local = true;
    prm.p_nodeid = conn.node_id;
    prm.result = result;
    ln_db_self_search_readonly(comp_func_getcommittx, &prm);

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
    }
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
        ret = ln_db_self_del(channel_id);
    }
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
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_per_kw);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]setfeerate\n");
    monitor_set_feerate_per_kw(feerate_per_kw);
    result = cJSON_CreateString(kOK);

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
    }
    return result;
}


/** 予想されるfunding fee : ptarmcli --estimatefundingfee
 *
 */
static cJSON *cmd_estimatefundingfee(jrpc_context *ctx, cJSON *params, cJSON *id)
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
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_per_kw);
    } else {
        index = -1;
        goto LABEL_EXIT;
    }

    LOGD("$$$ [JSONRPC]estimatefundingfee\n");

    if (feerate_per_kw == 0) {
        feerate_per_kw = ptarmd_get_latest_feerate_kw();
    }
    if (feerate_per_kw == 0) {
        ctx->error_code = RPCERR_BLOCKCHAIN;
        ctx->error_message = error_str_cjson(RPCERR_BLOCKCHAIN);
        goto LABEL_EXIT;
    }
    uint64_t fee = ln_estimate_fundingtx_fee(feerate_per_kw);
    result = cJSON_CreateNumber64(fee);

LABEL_EXIT:
    if (index < 0) {
        ctx->error_code = RPCERR_PARSE;
        ctx->error_message = error_str_cjson(RPCERR_PARSE);
    }
    return result;
}


/** DBに残っている1st layerのamountをwalletに返す : ptarmcli -W
 *
 */
static cJSON *cmd_walletback(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)params; (void)id;

    bool ret;
    cJSON *result = NULL;
    bool tosend = false;

    LOGD("$$$ [JSONRPC]walletback\n");

    if (params != NULL) {
        cJSON *json = cJSON_GetArrayItem(params, 0);
        if (json && (json->type == cJSON_Number)) {
            tosend = (json->valueint != 0);
        }
    }

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    ret = btcrpc_getnewaddress(addr);
    if (!ret) {
        ctx->error_code = RPCERR_BLOCKCHAIN;
        ctx->error_message = error_str_cjson(RPCERR_BLOCKCHAIN);
        return NULL;
    }
    uint64_t feerate;
    ret = btcrpc_estimatefee(&feerate, LN_BLK_FEEESTIMATE);
    if (!ret) {
        feerate = 5000;
    }

    char *p_result = NULL;
    uint64_t vout_amount = 0;
    ret = wallet_from_ptarm(&p_result, &vout_amount, tosend, addr, (uint32_t)feerate);
    if (ret) {
        result = cJSON_CreateObject();
        cJSON_AddItemToObject(result, "txid", cJSON_CreateString(p_result));
        cJSON_AddItemToObject(result, "amount", cJSON_CreateNumber64(vout_amount));
        UTL_DBG_FREE(p_result);
    } else {
        ctx->error_code = RPCERR_WALLET_ERR;
        if (p_result != NULL) {
            ctx->error_message = strdup_cjson(p_result);
            UTL_DBG_FREE(p_result);
        } else {
            ctx->error_message = error_str_cjson(RPCERR_WALLET_ERR);
        }
    }

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
    return result;
}


/** 送金してwalletを空にする : ptarmcli --emptywallet
 *
 */
static cJSON *cmd_emptywallet(jrpc_context *ctx, cJSON *params, cJSON *id)
{
    (void)id;

    bool ret = false;
    uint8_t txid[BTC_SZ_TXID];
    cJSON *json;
    cJSON *result = NULL;
    int index = 0;

    if (params == NULL) {
        index = -1;
        goto LABEL_EXIT;
    }

    json = cJSON_GetArrayItem(params, index++);
    if (json && (json->type == cJSON_String)) {
        LOGD("send to=%" PRIu32 "\n", json->valuestring);
    } else {
        index = -1;
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
        if (index < 0) {
            ctx->error_code = RPCERR_PARSE;
            ctx->error_message = error_str_cjson(RPCERR_PARSE);
        } else {
            ctx->error_code = RPCERR_BLOCKCHAIN;
            ctx->error_message = error_str_cjson(RPCERR_BLOCKCHAIN);
        }
    }
    return result;
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
static int cmd_connect_proc(const peer_conn_t *pConn, jrpc_context *ctx)
{
    LOGD("connect\n");

    int err;
    bool ret = p2p_cli_start(pConn, &err);
    if (!ret) {
        ctx->error_code = err;
        ctx->error_message = error_str_cjson(err);
        return RPCERR_CONNECT;
    }

    //チェック
    if (pConn->routesync > PTARMD_ROUTESYNC_MAX) {
        return JRPC_INVALID_PARAMS;
    }

    int retry = M_RETRY_CONN_CHK;
    while (retry--) {
        lnapp_conf_t *p_appconf = ptarmd_search_connected_nodeid(pConn->node_id);
        if ((p_appconf != NULL) && lnapp_is_looping(p_appconf) && lnapp_is_connected(p_appconf)) {
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
    LOGD("disconnect\n");

    int err;
    lnapp_conf_t *p_appconf = ptarmd_search_connected_nodeid(pNodeId);
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
    LOGD("stop\n");

    ptarmd_stop();

    return 0;
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

    lnapp_conf_t *p_appconf = ptarmd_search_connected_nodeid(pNodeId);
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

    bool nopong = lnapp_check_ponglist(p_appconf);
    if (!nopong) {
        return RPCERR_BUSY;
    }

    uint32_t feerate_per_kw = pFund->feerate_per_kw;
    if (feerate_per_kw == 0) {
        feerate_per_kw = ptarmd_get_latest_feerate_kw();
    }
    if (feerate_per_kw == 0) {
        return RPCERR_BLOCKCHAIN;
    }
    uint64_t fee = ln_estimate_initcommittx_fee(feerate_per_kw);
    if (pFund->funding_sat < fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN) {
        char str[256];
        sprintf(str, "funding_sat too low(%" PRIu64 " < %" PRIu64 ") feerate_per_kw=%" PRIu32 "\n",
                pFund->funding_sat, fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN, feerate_per_kw);
        LOGD(str);
        ctx->error_code = RPCERR_FUNDING;
        ctx->error_message = strdup_cjson(str);
        return M_RPCERR_FREESTRING;
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
    LOGD("invoice\n");

    ln_db_preimg_t preimg;

    btc_rng_rand(preimg.preimage, LN_SZ_PREIMAGE);

    ptarmd_preimage_lock();
    preimg.amount_msat = AmountMsat;
    preimg.expiry = LN_INVOICE_EXPIRY;
    preimg.creation_time = 0;
    ln_db_preimg_save(&preimg, NULL);
    ptarmd_preimage_unlock();

    ln_preimage_hash_calc(pPayHash, preimg.preimage);
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
 * @param[in]       BlockCnt
 * @retval  エラーコード
 */
static int cmd_routepay_proc1(
                ln_invoice_t **ppInvoiceData,
                ln_routing_result_t *pRouteResult,
                const char *pInvoice,
                uint64_t AddAmountMsat,
                int32_t BlockCnt)
{
    bool bret = ln_invoice_decode(ppInvoiceData, pInvoice);
    if (!bret) {
        return RPCERR_PARSE;
    }

    //save routing information
    cmd_routepay_save_info(*ppInvoiceData, BlockCnt);

    ln_invoice_t *p_invoice_data = *ppInvoiceData;
    if ( (p_invoice_data->hrp_type != LN_INVOICE_TESTNET) &&
        (p_invoice_data->hrp_type != LN_INVOICE_REGTEST) ) {
        LOGE("fail: mismatch blockchain\n");
        return RPCERR_INVOICE_FAIL;
    }
    time_t now = utl_time_time();
    if (p_invoice_data->timestamp + p_invoice_data->expiry < (uint64_t)now) {
        LOGE("fail: invoice outdated\n");
        return RPCERR_INVOICE_OUTDATE;
    }
    p_invoice_data->amount_msat += AddAmountMsat;

    lnerr_route_t rerr = ln_routing_calculate(pRouteResult,
                    ln_node_getid(),
                    p_invoice_data->pubkey,
                    BlockCnt + p_invoice_data->min_final_cltv_expiry,
                    p_invoice_data->amount_msat,
                    p_invoice_data->r_field_num, p_invoice_data->r_field);
    if (rerr != LNROUTE_OK) {
        LOGE("fail: routing\n");
        switch (rerr) {
        case LNROUTE_NOSTART:
            return RPCERR_NOSTART;
        case LNROUTE_NOGOAL:
            return RPCERR_NOGOAL;
        case LNROUTE_NOTFOUND:
            return RPCERR_NOROUTE;
        case LNROUTE_TOOMANYHOP:
            return RPCERR_TOOMANYHOP;
        default:
            return RPCERR_PAYFAIL;
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
                lnapp_conf_t *pAppConf,
                const ln_invoice_t *pInvoiceData,
                const ln_routing_result_t *pRouteResult,
                const char *pInvoiceStr,
                uint64_t AddAmountMsat)
{
    int err = RPCERR_PAY_RETRY;

    //再送のためにinvoice保存
    (void)ln_db_invoice_save(pInvoiceStr, AddAmountMsat, pInvoiceData->payment_hash);

    //save routing information

    const char *p_result = NULL;
    if (pAppConf != NULL) {
        payment_conf_t payconf;

        memcpy(payconf.payment_hash, pInvoiceData->payment_hash, BTC_SZ_HASH256);
        payconf.hop_num = pRouteResult->hop_num;
        memcpy(payconf.hop_datain, pRouteResult->hop_datain, sizeof(ln_hop_datain_t) * (1 + LN_HOP_MAX));

        bool ret = lnapp_payment(pAppConf, &payconf, &p_result);
        if (ret) {
            LOGD("start payment\n");
            err = 0;
            p_result = "start payment";
        } else {
            LOGE("fail: lnapp_payment(0x%016" PRIx64 ")\n", pRouteResult->hop_datain[0].short_channel_id);
            if (p_result == NULL) {
                p_result = ln_errmsg(pAppConf->p_self);
            }
            if (p_result == NULL) {
                p_result = "fail payment";
            }
        }
    } else {
        LOGE("fail: not connect(%016" PRIx64 "): \n", pRouteResult->hop_datain[0].short_channel_id);
        DUMPD(pRouteResult->hop_datain[1].pubkey, BTC_SZ_PUBKEY);
        p_result = "not connect";
    }
    cmd_routepay_save_route(pInvoiceData, pRouteResult, p_result);

    mPayTryCount++;

    if (mPayTryCount == 1) {
        //初回ログ
        uint64_t total_amount = ln_node_total_msat();
        char str_payhash[BTC_SZ_HASH256 * 2 + 1];
        utl_str_bin2str(str_payhash, pInvoiceData->payment_hash, BTC_SZ_HASH256);
        char str_payee[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(str_payee, pInvoiceData->pubkey, BTC_SZ_PUBKEY);

        ptarmd_eventlog(NULL, "payment start: payment_hash=%s payee=%s total_msat=%" PRIu64" amount_msat=%" PRIu64,
                    str_payhash, str_payee, total_amount, pInvoiceData->amount_msat);
    }

    return err;
}


static void cmd_routepay_save_info(
                const ln_invoice_t *pInvoiceData,
                int32_t BlockCnt)
{
    //log file
    char str_payhash[BTC_SZ_HASH256 * 2 + 1];
    char fname[256];
    FILE *fp;

    utl_str_bin2str(str_payhash, pInvoiceData->payment_hash, BTC_SZ_HASH256);
    sprintf(fname, FNAME_INVOICE_LOG, str_payhash);

    //file existance check
    struct stat buf;
    int ret = stat(fname, &buf);
    if ((ret == 0) && S_ISREG(buf.st_mode)) {
        //if already exist file, skip writting info.
        return;
    }

    fp = fopen(fname, "w");
    if (fp != NULL) {
        char time[UTL_SZ_TIME_FMT_STR + 1];

        fprintf(fp, "----------- invoice -----------\n");
        fprintf(fp, "payment_hash: %s\n", str_payhash);
        fprintf(fp, "amount_msat: %" PRIu64 "\n", pInvoiceData->amount_msat);
        fprintf(fp, "current blockcount: %" PRId32 "\n", BlockCnt);
        fprintf(fp, "min_final_cltv_expiry: %" PRId32 "\n", pInvoiceData->min_final_cltv_expiry);
        fprintf(fp, "timestamp: %s\n", utl_time_fmt(time, pInvoiceData->timestamp));
        fclose(fp);
    }
}


static void cmd_routepay_save_route(
                const ln_invoice_t *pInvoiceData,
                const ln_routing_result_t *pRouteResult,
                const char *pResultStr)
{
    //log file
    char str_payhash[BTC_SZ_HASH256 * 2 + 1];
    char fname[256];
    FILE *fp;

    utl_str_bin2str(str_payhash, pInvoiceData->payment_hash, BTC_SZ_HASH256);
    sprintf(fname, FNAME_INVOICE_LOG, str_payhash);
    fp = fopen(fname, "a");
    if (fp != NULL) {
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        char str_pubkey[BTC_SZ_PUBKEY * 2 + 1];

        fprintf(fp, "\n----------- route -----------\n");
        for (int lp = 0; lp < pRouteResult->hop_num; lp++) {
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


/** channel mutual close開始
 *
 * @param[in]       pNodeId
 * @retval  エラーコード
 */
static int cmd_close_mutual_proc(const uint8_t *pNodeId)
{
    LOGD("mutual close\n");

    int err;
    lnapp_conf_t *p_appconf = ptarmd_search_connected_nodeid(pNodeId);
    if (p_appconf != NULL) {
        //接続中
        bool nopong = lnapp_check_ponglist(p_appconf);
        if (!nopong) {
            err = RPCERR_BUSY;
            goto LABEL_EXIT;
        }

        bool ret = lnapp_close_channel(p_appconf);
        if (ret) {
            err = 0;
        } else {
            LOGE("fail: mutual  close\n");
            err = RPCERR_CLOSE_START;
        }
    } else {
        if (p_appconf == NULL) {
            err = RPCERR_NOCONN;
        } else {
            err = RPCERR_CLOSE_CLEAN;
        }
    }

LABEL_EXIT:
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

    int err;
    bool haveCnl = ln_node_search_channel(NULL, pNodeId);
    if (haveCnl) {
        bool ret = lnapp_close_channel_force(pNodeId);
        if (ret) {
            lnapp_conf_t *p_appconf = ptarmd_search_connected_nodeid(pNodeId);
            if (p_appconf != NULL) {
                lnapp_stop(p_appconf);
            }
            err = 0;
        } else {
            LOGE("fail: unilateral close\n");
            err = RPCERR_CLOSE_FAIL;
        }
    } else {
        //チャネルなし
        err = RPCERR_NOCHANNEL;
    }

    return err;
}


/********************************************************************
 * private functions : others
 ********************************************************************/

/** ptarmcli -c解析
 *
 */
static bool json_connect(cJSON *params, int *pIndex, peer_conn_t *pConn)
{
    cJSON *json;

    if (params == NULL) {
        return false;
    }
    pConn->routesync = PTARMD_ROUTESYNC_DEFAULT;

    //peer_nodeid, peer_addr, peer_port
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_String)) {
        bool ret = utl_str_str2bin(pConn->node_id, BTC_SZ_PUBKEY, json->valuestring);
        if (ret) {
            LOGD("pConn->node_id=%s\n", json->valuestring);
        } else {
            LOGE("fail: invalid node_id string\n");
            return false;
        }
    } else {
        LOGE("fail: node_id\n");
        return false;
    }
    if (memcmp(ln_node_getid(), pConn->node_id, BTC_SZ_PUBKEY) == 0) {
        //node_idが自分と同じ
        LOGE("fail: same own node_id\n");
        return false;
    }
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_String)) {
        strcpy(pConn->ipaddr, json->valuestring);
        LOGD("pConn->ipaddr=%s\n", json->valuestring);
    } else {
        LOGE("fail: ipaddr\n");
        return false;
    }
    json = cJSON_GetArrayItem(params, (*pIndex)++);
    if (json && (json->type == cJSON_Number)) {
        pConn->port = json->valueint;
        LOGD("pConn->port=%d\n", json->valueint);
    } else {
        LOGE("fail: port\n");
        return false;
    }

    return true;
}


/** not public channel情報からr field情報を作成
 *
 * channel_announcementする前や、channel_announcementしない場合、invoiceのr fieldに経路情報を追加することで、
 * announcementしていない部分の経路を知らせることができる。
 * ただ、その経路は自分へ向いているため、channelの相手が送信するchannel_updateの情報を追加することになる。
 * 現在接続していなくても、送金時には接続している可能性があるため、r fieldに追加する。
 */
static void create_bolt11_rfield(ln_fieldr_t **ppFieldR, uint8_t *pFieldRNum)
{
    rfield_prm_t prm;

    *ppFieldR = NULL;
    *pFieldRNum = 0;

    prm.pp_field = ppFieldR;
    prm.p_fieldnum = pFieldRNum;
    ln_db_self_search_readonly(comp_func_cnl, &prm);

    if (*pFieldRNum != 0) {
        LOGD("add r_field: %d\n", *pFieldRNum);
    } else {
        LOGD("no r_field\n");
    }
}


/** #ln_node_search_channel()処理関数
 *
 * @param[in,out]   self            DBから取得したself
 * @param[in,out]   p_db_param      DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         rfield_prm_t構造体
 */
static bool comp_func_cnl(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_db_param;

    bool ret;
    rfield_prm_t *prm = (rfield_prm_t *)p_param;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    ln_msg_channel_update_t msg;
    ret = ln_channel_update_get_peer(self, &buf_bolt, &msg);
    if (ret && !ln_is_announced(self)) {
        size_t sz = (1 + *prm->p_fieldnum) * sizeof(ln_fieldr_t);
        *prm->pp_field = (ln_fieldr_t *)UTL_DBG_REALLOC(*prm->pp_field, sz);

        ln_fieldr_t *pfield = *prm->pp_field + *prm->p_fieldnum;
        memcpy(pfield->node_id, ln_their_node_id(self), BTC_SZ_PUBKEY);
        pfield->short_channel_id = ln_short_channel_id(self);
        pfield->fee_base_msat = msg.fee_base_msat;
        pfield->fee_prop_millionths = msg.fee_proportional_millionths;
        pfield->cltv_expiry_delta = msg.cltv_expiry_delta;

        (*prm->p_fieldnum)++;
        LOGD("r_field num=%d\n", *prm->p_fieldnum);
    }
    utl_buf_free(&buf_bolt);

    return false;
}


/** BOLT11文字列生成
 *
 */
static char *create_bolt11(
                const uint8_t *pPayHash,
                uint64_t Amount,
                uint32_t Expiry,
                const ln_fieldr_t *pFieldR,
                uint8_t FieldRNum,
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
                pPayHash, Amount, Expiry, pFieldR, FieldRNum, MinFinalCltvExpiry);
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
    if (sock < 0) {
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
    write(sock, pSend, strlen(pSend));

    //受信を待つとDBの都合でロックしてしまうため、すぐに閉じる

    close(sock);

    return 0;
}


/** getcommittx処理
 *
 */
static bool comp_func_getcommittx(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_db_param;

    getcommittx_t *prm = (getcommittx_t *)p_param;

    if (memcmp(prm->p_nodeid, ln_their_node_id(self), BTC_SZ_PUBKEY) == 0) {
        lnapp_conf_t appconf;
        appconf.p_self= self;
        lnapp_get_committx(&appconf, prm->result, prm->b_local);
    }

    return false;
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
