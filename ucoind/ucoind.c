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

#define M_WAIT_MON_SEC                  (30)        ///< 監視周期[sec]


/********************************************************************
 * static variables
 ********************************************************************/

static ln_node_t            mNode;
static struct jrpc_server   mJrpc;
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
static cJSON *cmd_getcommittx(jrpc_context *ctx, cJSON *params, cJSON *id);
static lnapp_conf_t *search_connected_lnapp_node(const uint8_t *p_node_id);
static lnapp_conf_t *search_connected_lnapp_cnl(uint64_t short_channel_id);

static void *thread_monitor_start(void *pArg);
static bool monfunc(ln_self_t *self, void *p_db_param, void *p_param);

static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);
static bool close_unilateral_local_received(bool spent);

static bool close_unilateral_remote(ln_self_t *self, void *pDbParam);
static bool close_unilateral_remote_offered(bool spent);
static bool close_unilateral_remote_received(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);

static bool close_others(ln_self_t *self, uint32_t confm, void *pDbParam);
static bool close_revoked_after(ln_self_t *self, uint32_t confm, void *pDbParam);
static bool close_revoked_vout(const ln_self_t *self, const ucoin_tx_t *pTx, int VIndex);

static bool search_spent_tx(ucoin_tx_t *pTx, uint32_t confm, const uint8_t *pTxid, int Index);
static bool search_vout(ucoin_buf_t *pTxBuf, uint32_t confm, const ucoin_buf_t *pVout);


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


/** unilateral closeを自分が行っていた場合の処理(localのcommit_txを展開)
 *
 */
bool close_unilateral_local(ln_self_t *self, void *pDbParam)
{
    bool del;
    bool ret;

    ln_close_force_t close_dat;
    ret = ln_create_close_force_tx(self, &close_dat);
    if (ret) {
        del = true;
        uint8_t txid[UCOIN_SZ_TXID];
        for (int lp = 0; lp < close_dat.num; lp++) {
            if (lp == 0) {
                DBG_PRINTF2("\n$$$ commit_tx\n");
                //for (int lp2 = 0; lp2 < close_dat.p_tx[lp].vout_cnt; lp2++) {
                //    DBG_PRINTF("vout[%d]=%x\n", lp2, close_dat.p_tx[lp].vout[lp2].opt);
                //}
            } else if (lp == 1) {
                DBG_PRINTF2("\n$$$ to_local tx\n");
            } else {
                DBG_PRINTF2("\n$$$ HTLC[%d]\n", lp - 2);
            }
            if (close_dat.p_tx[lp].vin_cnt > 0) {
                //自分のtxを展開済みかチェック
                ucoin_tx_txid(txid, &close_dat.p_tx[lp]);
                DBG_PRINTF("txid[%d]= ", lp);
                DUMPTXID(txid);
                bool broad = jsonrpc_getraw_tx(NULL, txid);
                if (broad) {
                    DBG_PRINTF("already broadcasted[%d]\n", lp);
                    DBG_PRINTF("-->OK\n");
                    continue;
                }

                bool send_req = false;

                //展開済みチェック
                uint64_t sat;
                bool spent = !jsonrpc_getxout(&sat, close_dat.p_tx[lp].vin[0].txid, close_dat.p_tx[lp].vin[0].index);
                DBG_PRINTF("vin spent[%d]=%d\n", lp, spent);

                //ln_create_htlc_tx()後だから、OFFERED/RECEIVEDがわかる
                switch (close_dat.p_tx[lp].vout[0].opt) {
                case LN_HTLCTYPE_OFFERED:
                    send_req = close_unilateral_local_offered(self, &del, spent, &close_dat, lp, pDbParam);
                    break;
                case LN_HTLCTYPE_RECEIVED:
                    send_req = close_unilateral_local_received(spent);
                    break;
                default:
                    DBG_PRINTF("opt=%x\n", close_dat.p_tx[lp].vout[0].opt);
                    send_req = true;
                    break;
                }

                if (send_req) {
                    ucoin_buf_t buf;
                    ucoin_tx_create(&buf, &close_dat.p_tx[lp]);
                    int code = 0;
                    ret = jsonrpc_sendraw_tx(txid, &code, buf.buf, buf.len);
                    DBG_PRINTF("code=%d\n", code);
                    ucoin_buf_free(&buf);
                    if (ret) {
                        DBG_PRINTF("broadcast txid[%d]\n", lp);
                        DBG_PRINTF("-->OK\n");
                    } else {
                        del = false;
                        DBG_PRINTF("fail[%d]: sendrawtransaction\n", lp);
                    }
                }
            } else {
                DBG_PRINTF("skip tx[%d]\n", lp);
                del = false;
            }
        }

        //自分が展開した場合には、HTLC Timeout/Success Txからの出力も行う
        ucoin_tx_t *p_tx = (ucoin_tx_t *)close_dat.tx_buf.buf;
        int num = close_dat.tx_buf.len / sizeof(ucoin_tx_t);
        for (int lp = 0; lp < num; lp++) {
            ucoin_buf_t buf;
            ucoin_tx_create(&buf, &p_tx[lp]);
            int code = 0;
            ret = jsonrpc_sendraw_tx(txid, &code, buf.buf, buf.len);
            DBG_PRINTF("code=%d\n", code);
            ucoin_buf_free(&buf);
            if (ret) {
                DBG_PRINTF("broadcast after tx[%d]\n", lp);
                DBG_PRINTF("-->OK\n");
            } else if (code == -25) {
                DBG_PRINTF("through[%d]: already spent vin\n", lp);
            } else {
                del = false;
                DBG_PRINTF("fail[%d]: sendrawtransaction\n", lp);
            }
        }

        ln_free_close_force_tx(&close_dat);
    } else {
        del = false;
    }

    DBG_PRINTF("del=%d\n", del);

    return del;
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
    jrpc_register_procedure(&mJrpc, cmd_getcommittx, "getcommittx", NULL);
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
    if ((p_appconf != NULL) && (ln_htlc_num(p_appconf->p_self) == 0)) {
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

    uint8_t preimage[LN_SZ_PREIMAGE];
    uint8_t preimage_hash[LN_SZ_HASH];
    char str_hash[LN_SZ_HASH * 2 + 1];

    ucoin_util_random(preimage, LN_SZ_PREIMAGE);
    ln_db_save_preimage(preimage, amount, NULL);
    ln_calc_preimage_hash(preimage_hash, preimage);

    misc_bin2str(str_hash, preimage_hash, LN_SZ_HASH);
    DBG_PRINTF("preimage=")
    DUMPBIN(preimage, LN_SZ_PREIMAGE);
    DBG_PRINTF("hash=")
    DUMPBIN(preimage_hash, LN_SZ_HASH);
    cJSON_AddItemToObject(result, "hash", cJSON_CreateString(str_hash));
    cJSON_AddItemToObject(result, "amount", cJSON_CreateNumber64(amount));
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
    ret = ln_db_cursor_preimage_open(&p_cur);
    while (ret) {
        ret = ln_db_cursor_preimage_get(p_cur, preimage, &amount);
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
    ln_db_cursor_preimage_close(p_cur);

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
        ln_set_debug(json->valueint);
        sprintf(str, "%d", json->valueint);
        ret = str;
    } else {
        ret = "NG";
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

/** チャネル閉鎖監視スレッド
 *
 */
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


/** 監視処理
 *
 */
static bool monfunc(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_param;

    uint32_t confm = jsonrpc_get_confirmation(ln_funding_txid(self));
    if (confm > 0) {
        DBG_PRINTF("funding_txid[conf=%u, idx=%d]: ", confm, ln_funding_txindex(self));
        DUMPTXID(ln_funding_txid(self));

        bool del = false;
        uint64_t sat;
        bool ret = jsonrpc_getxout(&sat, ln_funding_txid(self), ln_funding_txindex(self));
        if (!ret) {
            //funding_tx使用済み

            ln_db_load_revoked(self, p_db_param);
            if (self->revoked_vout.len == 0) {
                //展開されているのが最新のcommit_txか
                ucoin_tx_t tx_commit;
                ucoin_tx_init(&tx_commit);
                if (jsonrpc_getraw_tx(&tx_commit, ln_commit_local(self)->txid)) {
                    //最新のlocal commit_tx --> unilateral close(local)
                    del = close_unilateral_local(self, p_db_param);
                } else if (jsonrpc_getraw_tx(&tx_commit, ln_commit_remote(self)->txid)) {
                    //最新のremote commit_tx --> unilateral close(remote)
                    del = close_unilateral_remote(self, p_db_param);
                } else {
                    //最新ではないcommit_tx --> mutual close or revoked transaction close
                    del = close_others(self, confm, p_db_param);
                }
                ucoin_tx_free(&tx_commit);
            } else {
                // revoked transaction close
                del = close_revoked_after(self, confm, p_db_param);
            }
        }
        if (del) {
            DBG_PRINTF("delete from DB\n");
            ret = ln_db_del_channel(self, p_db_param);
            assert(ret);
        }
    }

    return false;
}


static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    bool send_req = false;

    DBG_PRINTF("offered HTLC output\n");
    if (spent) {
        const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
        if (p_htlc->prev_short_channel_id != 0) {
            //転送元がある場合、preimageを抽出する
            DBG_PRINTF("prev_short_channel_id=%" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);
            ucoin_tx_t tx;
            ucoin_tx_init(&tx);
            uint32_t confm = jsonrpc_get_confirmation(ln_funding_txid(self));
            uint8_t txid[UCOIN_SZ_TXID];
            ucoin_tx_txid(txid, &pCloseDat->p_tx[0]);
            bool ret = search_spent_tx(&tx, confm, txid, pCloseDat->p_htlc_idx[lp]);
            if (ret) {
                //preimageを登録(自分が持っているのと同じ状態にする)
                const ucoin_buf_t *p_buf = ln_preimage_remote(&tx);
                if (p_buf != NULL) {
                    DBG_PRINTF("backward preimage: ");
                    DUMPBIN(p_buf->buf, p_buf->len);
                    ln_db_save_preimage(p_buf->buf, 0, pDbParam);
                } else {
                    assert(0);
                }
            } else {
                DBG_PRINTF("not found txid: ");
                DUMPTXID(txid);
                DBG_PRINTF("index=%d\n", pCloseDat->p_htlc_idx[lp]);
                *pDel = false;
            }
            ucoin_tx_free(&tx);
        }
    } else {
        //タイムアウト用Txを展開(non-BIP68-finalの可能性あり)
        send_req = true;
    }

    return send_req;
}


static bool close_unilateral_local_received(bool spent)
{
    bool send_req;

    DBG_PRINTF("received HTLC output\n");
    if (!spent) {
        //展開(preimageがなければsendrawtransactionに失敗する)
        send_req = true;
    } else {
        //展開済みならOK
        DBG_PRINTF("-->OK\n");
    }

    return send_req;
}


/** unilateral closeを相手が行っていた場合の処理(remoteのcommit_txを展開)
 *
 */
static bool close_unilateral_remote(ln_self_t *self, void *pDbParam)
{
    bool del = true;

    if (ln_htlc_num(self) == 0) {
        DBG_PRINTF("no HTLCS\n");
    } else {
        ln_close_force_t close_dat;
        bool ret = ln_create_closed_tx(self, &close_dat);
        if (ret) {
            del = true;
            uint8_t txid[UCOIN_SZ_TXID];
            for (int lp = 0; lp < close_dat.num; lp++) {
                if (lp == 0) {
                    DBG_PRINTF2("\n$$$ commit_tx\n");
                    continue;
                } else if (lp == 1) {
                    DBG_PRINTF2("\n$$$ to_local tx\n");
                    continue;
                } else {
                    DBG_PRINTF2("\n$$$ HTLC[%d]\n", lp - 2);
                }
                if (close_dat.p_tx[lp].vin_cnt > 0) {
                    //自分のtxを展開済みかチェック
                    ucoin_tx_txid(txid, &close_dat.p_tx[lp]);
                    DBG_PRINTF("txid[%d]= ", lp);
                    DUMPTXID(txid);
                    bool broad = jsonrpc_getraw_tx(NULL, txid);
                    if (broad) {
                        DBG_PRINTF("already broadcasted[%d]\n", lp);
                        DBG_PRINTF("-->OK\n");
                        continue;
                    }

                    bool send_req = false;

                    //展開済みチェック
                    uint64_t sat;
                    bool spent = !jsonrpc_getxout(&sat, close_dat.p_tx[lp].vin[0].txid, close_dat.p_tx[lp].vin[0].index);
                    DBG_PRINTF("vin spent[%d]=%d\n", lp, spent);

                    //ln_create_htlc_tx()後だから、OFFERED/RECEIVEDがわかる
                    switch (close_dat.p_tx[lp].vout[0].opt) {
                    case LN_HTLCTYPE_OFFERED:
                        send_req = close_unilateral_remote_offered(spent);
                        break;
                    case LN_HTLCTYPE_RECEIVED:
                        send_req = close_unilateral_remote_received(self, &del, spent, &close_dat, lp, pDbParam);
                        break;
                    default:
                        DBG_PRINTF("opt=%x\n", close_dat.p_tx[lp].vout[0].opt);
                        break;
                    }

                    if (send_req) {
                        ucoin_buf_t buf;
                        ucoin_tx_create(&buf, &close_dat.p_tx[lp]);
                        ret = jsonrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
                        ucoin_buf_free(&buf);
                        if (ret) {
                            DBG_PRINTF("broadcast txid[%d]: ", lp);
                            DUMPTXID(txid);
                            DBG_PRINTF("-->OK\n");
                        } else {
                            del = false;
                            DBG_PRINTF("fail[%d]: sendrawtransaction\n", lp);
                        }
                    }
                } else {
                    DBG_PRINTF("skip tx[%d]\n", lp);
                    del = false;
                }
            }
            ln_free_close_force_tx(&close_dat);
        } else {
            del = false;
        }
    }

    DBG_PRINTF("del=%d\n", del);

    return del;
}


static bool close_unilateral_remote_offered(bool spent)
{
    bool send_req;

    DBG_PRINTF("offered HTLC output\n");
    if (!spent) {
        //展開(preimageがなければsendrawtransactionに失敗する)
        send_req = true;
    } else {
        //展開済みならOK
        DBG_PRINTF("-->OK\n");
        send_req = false;
    }

    return send_req;
}


static bool close_unilateral_remote_received(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    bool send_req = false;

    DBG_PRINTF("received HTLC output\n");
    if (spent) {
        const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
        if (p_htlc->prev_short_channel_id != 0) {
            //転送元がある場合、preimageを抽出する
            DBG_PRINTF("prev_short_channel_id=%" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);
            ucoin_tx_t tx;
            ucoin_tx_init(&tx);
            uint32_t confm = jsonrpc_get_confirmation(ln_funding_txid(self));
            uint8_t txid[UCOIN_SZ_TXID];
            ucoin_tx_txid(txid, &pCloseDat->p_tx[0]);
            bool ret = search_spent_tx(&tx, confm, txid, pCloseDat->p_htlc_idx[lp]);
            if (ret) {
                //preimageを登録(自分が持っているのと同じ状態にする)
                const ucoin_buf_t *p_buf = ln_preimage_remote(&tx);
                if (p_buf != NULL) {
                    DBG_PRINTF("backward preimage: ");
                    DUMPBIN(p_buf->buf, p_buf->len);
                    ln_db_save_preimage(p_buf->buf, 0, pDbParam);
                } else {
                    assert(0);
                }
            } else {
                DBG_PRINTF("not found txid: ");
                DUMPTXID(txid);
                DBG_PRINTF("index=%d\n", pCloseDat->p_htlc_idx[lp]);
                *pDel = false;
            }
        }
    } else {
        //タイムアウト用Txを展開(non-BIP68-finalの可能性あり)
        send_req = true;
    }

    return send_req;
}


static bool close_others(ln_self_t *self, uint32_t confm, void *pDbParam)
{
    (void)pDbParam;
    bool del = false;

    ucoin_tx_t tx;
    ucoin_tx_init(&tx);
    bool ret = search_spent_tx(&tx, confm, ln_funding_txid(self), ln_funding_txindex(self));
    if (ret) {
        DBG_PRINTF("find!\n");
        ucoin_print_tx(&tx);
        ucoin_buf_t *p_buf_pk = &tx.vout[0].script;
        if ( (tx.vout_cnt <= 2) &&
             (ucoin_buf_cmp(p_buf_pk, &self->shutdown_scriptpk_local) ||
              ucoin_buf_cmp(p_buf_pk, &self->shutdown_scriptpk_remote)) ) {
            //voutのどちらかがshutdown時のscriptPubkeyと一致すればclosing_txと見なす
            DBG_PRINTF("This is closing_tx\n");
            del = true;
        } else {
            //revoked transaction close
            SYSLOG_WARN("closed: ugly way\n");
            ln_close_ugly(self, &tx);

            bool save = true;
            for (int lp = 0; lp < tx.vout_cnt; lp++) {
                if (ucoin_buf_cmp(&tx.vout[lp].script, &self->revoked_vout)) {
                    DBG_PRINTF("[%d]to_local !\n", lp);

                    ret = close_revoked_vout(self, &tx, lp);
                    if (ret) {
                        del = ln_revoked_cnt_dec(self);
                        ln_set_revoked_confm(self, confm);
                    } else {
                        save = false;
                    }
                    break;
                }
            }
            if (save) {
                ln_db_save_revoked(self, true, pDbParam);
            }
        }
    }
    ucoin_tx_free(&tx);

    return del;
}


static bool close_revoked_after(ln_self_t *self, uint32_t confm, void *pDbParam)
{
    bool del = false;

    if (confm != ln_revoked_confm(self)) {
        // DBG_PRINTF("confm=%d, self->revoked_chk=%d\n", confm, ln_revoked_confm(self));
        // DBG_PRINTF("vout: ");
        // DUMPBIN(self->revoked_vout.buf, self->revoked_vout.len);
        // DBG_PRINTF("wit:\n");
        // ucoin_print_script(self->revoked_wit.buf, self->revoked_wit.len);

        ucoin_buf_t txbuf;
        bool ret = search_vout(&txbuf, confm - ln_revoked_confm(self), ln_revoked_vout(self));
        if (ret) {
            bool sendret = true;
            int num = txbuf.len / sizeof(ucoin_tx_t);
            DBG_PRINTF("find! %d\n", num);
            ucoin_tx_t *pTx = (ucoin_tx_t *)txbuf.buf;
            for (int lp = 0; lp < num; lp++) {
                DBG_PRINTF2("-------- %d ----------\n", lp);
                ucoin_print_tx(&pTx[lp]);

                ret = close_revoked_vout(self, &pTx[lp], 0);
                ucoin_tx_free(&pTx[lp]);
                if (ret) {
                    del = ln_revoked_cnt_dec(self);
                    DBG_PRINTF("del=%d, revoked_cnt=%d\n", del, self->revoked_cnt);
                } else {
                    sendret = false;
                    break;
                }
            }
            ucoin_buf_free(&txbuf);

            if (sendret) {
                ln_set_revoked_confm(self, confm);
                ln_db_save_revoked(self, false, pDbParam);
                DBG_PRINTF("del=%d, revoked_cnt=%d\n", del, self->revoked_cnt);
            } else {
                //送信エラーがあった場合には、次回やり直す
                DBG_PRINTF("sendtx error\n");
            }
        } else {
            ln_set_revoked_confm(self, confm);
            ln_db_save_revoked(self, false, pDbParam);
            DBG_PRINTF("no target txid: %d, revoked_cnt=%d\n", confm, self->revoked_cnt);
        }
    } else {
        DBG_PRINTF("same block: %d, revoked_cnt=%d\n", confm, self->revoked_cnt);
    }

    return del;
}


static bool close_revoked_vout(const ln_self_t *self, const ucoin_tx_t *pTx, int VIndex)
{
    uint8_t txid[UCOIN_SZ_TXID];
    ucoin_tx_txid(txid, pTx);

    ucoin_tx_t tx;
    ucoin_tx_init(&tx);
    ln_create_tolocal_spent(self, &tx, pTx->vout[VIndex].value,
                self->commit_local.to_self_delay,
                ln_revoked_wit(self), txid, VIndex, true);
    ucoin_print_tx(&tx);
    ucoin_buf_t buf;
    ucoin_tx_create(&buf, &tx);
    ucoin_tx_free(&tx);
    bool ret = jsonrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
    ucoin_buf_free(&buf);

    return ret;
}


static bool search_spent_tx(ucoin_tx_t *pTx, uint32_t confm, const uint8_t *pTxid, int Index)
{
    bool ret = false;
    int height = jsonrpc_getblockcount();

    //現在からconfmの間に使用したtransactionがある
    if (height > 0) {
        for (uint32_t lp = 0; lp < confm; lp++) {
            ret = jsonrpc_search_txid_block(pTx, height - lp, pTxid, Index);
            if (ret) {
                break;
            }
        }
    }

    return ret;
}


static bool search_vout(ucoin_buf_t *pTxBuf, uint32_t confm, const ucoin_buf_t *pVout)
{
    bool ret = false;
    int height = jsonrpc_getblockcount();

    //現在からconfmの間に使用したtransactionがある
    if (height > 0) {
        for (uint32_t lp = 0; lp < confm; lp++) {
            ret = jsonrpc_search_vout_block(pTxBuf, height - lp, pVout);
            if (ret) {
                DBG_PRINTF("buf.len=%d\n", pTxBuf->len);
                break;
            }
        }
    }

    return ret;
}
