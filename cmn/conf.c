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

#include "conf.h"
#include "misc.h"
#include "ln.h"

//#define M_DEBUG

#define M_CHK_RET(ret)      \
    if (ret < 1) {          \
        goto LABEL_EXIT;    \
    }


bool load_node_conf(const char *pConfFile, node_conf_t *pNodeConf, rpc_conf_t *pRpcConf)
{
    FILE *fp = fopen(pConfFile, "r");
    if (fp == NULL) {
        SYSLOG_ERR("fail open: node conf[%s]", pConfFile);
        return false;
    }

    int results;
    results = fscanf(fp, "port=%" SCNd16 "\n", &pNodeConf->port);
    M_CHK_RET(results);
    results = fscanf(fp, "name=%32s\n", pNodeConf->name);
    M_CHK_RET(results);
    results = fscanf(fp, "wif=%55s\n", pNodeConf->wif);
    M_CHK_RET(results);
    results = fscanf(fp, "rpcuser=%64s\n", pRpcConf->rpcuser);
    M_CHK_RET(results);
    results = fscanf(fp, "rpcpasswd=%64s\n", pRpcConf->rpcpasswd);
    M_CHK_RET(results);
    results = fscanf(fp, "rpcurl=%256s\n", pRpcConf->rpcurl);
    M_CHK_RET(results);

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- node: %s ---\n", pConfFile);
    print_node_conf(pNodeConf, pRpcConf);
#endif

LABEL_EXIT:
    fclose(fp);
    if (results != 1) {
        SYSLOG_ERR("fail node parse[%s]", pConfFile);
    }
    return results == 1;
}


void print_node_conf(const node_conf_t *pNodeConf, const rpc_conf_t *pRpcConf)
{
    fprintf(PRINTOUT, "\n--- node ---\n");
    fprintf(PRINTOUT, "port=%d\n", pNodeConf->port);
    fprintf(PRINTOUT, "name=%s\n", pNodeConf->name);
    fprintf(PRINTOUT, "wif=%s\n", pNodeConf->wif);
    fprintf(PRINTOUT, "rpcuser=%s\n", pRpcConf->rpcuser);
    fprintf(PRINTOUT, "rpcpasswd=%s\n", pRpcConf->rpcpasswd);
    fprintf(PRINTOUT, "rpcurl=%s\n", pRpcConf->rpcurl);
    ucoin_util_keys_t keys;
    ucoin_util_wif2keys(&keys, pNodeConf->wif);
    fprintf(PRINTOUT, "node_id=");
    for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        fprintf(PRINTOUT, "%02x", keys.pub[lp]);
    }
    fprintf(PRINTOUT, "\n\n");
}


bool load_peer_conf(const char *pConfFile, peer_conf_t *pPeerConf)
{
    FILE *fp = fopen(pConfFile, "r");
    if (fp == NULL) {
        SYSLOG_ERR("fail open: peer conf[%s]", pConfFile);
        return false;
    }

    char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
    bool ret = false;
    int results;

    results = fscanf(fp, "ipaddr=%16s\n", pPeerConf->ipaddr);
    M_CHK_RET(results);
    results = fscanf(fp, "port=%" SCNd16 "\n", &pPeerConf->port);
    M_CHK_RET(results);
    results = fscanf(fp, "node_id=%66s\n", node_id);
    M_CHK_RET(results);
    ret = misc_str2bin(pPeerConf->node_id, UCOIN_SZ_PUBKEY, node_id);

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    if (ret) {
        print_peer_conf(pPeerConf);
    }
#endif

LABEL_EXIT:
    fclose(fp);
    if (!ret) {
        SYSLOG_ERR("fail peer parse[%s]", pConfFile);
    }
    return ret;
}


void print_peer_conf(const peer_conf_t *pPeerConf)
{
    fprintf(PRINTOUT, "\n--- peer ---\n");
    fprintf(PRINTOUT, "ipaddr=%s\n", pPeerConf->ipaddr);
    fprintf(PRINTOUT, "port=%d\n", pPeerConf->port);
    fprintf(PRINTOUT, "node_id=");
    for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        fprintf(PRINTOUT, "%02x", pPeerConf->node_id[lp]);
    }
    fprintf(PRINTOUT, "\n\n");
}


bool load_funding_conf(const char *pConfFile, funding_conf_t *pFundConf)
{
    FILE *fp = fopen(pConfFile, "r");
    if (fp == NULL) {
        SYSLOG_ERR("fail open: fund conf[%s]", pConfFile);
        return false;
    }

    char txid[UCOIN_SZ_TXID * 2 + 1];
    bool ret = false;
    int results;
    txid[0] = '\0';

    results = fscanf(fp, "txid=%64s\n", txid);
    M_CHK_RET(results);
    ret = misc_str2bin_rev(pFundConf->txid, UCOIN_SZ_TXID, txid);
    if (ret) {
        ret = false;
        results = fscanf(fp, "txindex=%d\n", &pFundConf->txindex);
        M_CHK_RET(results);
        results = fscanf(fp, "signaddr=%35s\n", pFundConf->signaddr);
        M_CHK_RET(results);
        results = fscanf(fp, "funding_sat=%" SCNu64 "\n", &pFundConf->funding_sat);
        M_CHK_RET(results);
        results = fscanf(fp, "push_sat=%" SCNu64 "\n", &pFundConf->push_sat);
        M_CHK_RET(results);
        ret = true;
    } else {
        perror("misc_str2bin_rev");
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    if (ret) {
        print_funding_conf(pFundConf);
    }
#endif

LABEL_EXIT:
    fclose(fp);
    if (!ret) {
        SYSLOG_ERR("fail fund parse[%s]", pConfFile);
    }
    return ret;
}


void print_funding_conf(const funding_conf_t *pFundConf)
{
    fprintf(PRINTOUT, "\n--- funding ---\n");
    fprintf(PRINTOUT, "txid=");
    misc_print_txid(pFundConf->txid);
    fprintf(PRINTOUT, "txindex=%d\n", pFundConf->txindex);
    fprintf(PRINTOUT, "signaddr=%s\n", pFundConf->signaddr);
    fprintf(PRINTOUT, "funding_sat=%" PRIu64 "\n", pFundConf->funding_sat);
    fprintf(PRINTOUT, "push_sat=%" PRIu64 "\n\n", pFundConf->push_sat);
}


bool load_payment_conf(const char *pConfFile, payment_conf_t *pPayConf)
{
    FILE *fp = fopen(pConfFile, "r");
    if (fp == NULL) {
        SYSLOG_ERR("fail open: pay conf[%s]", pConfFile);
        return false;
    }

    char payment_hash[LN_SZ_HASH * 2 + 1];
    int results;
    bool ret = false;

    payment_hash[0] = '\0';
    results = fscanf(fp, "hash=%64s\n", payment_hash);
    M_CHK_RET(results);
    ret = misc_str2bin(pPayConf->payment_hash, LN_SZ_HASH, payment_hash);
    if (ret) {
        results = fscanf(fp, "hop_num=%" SCNu8 "\n", &pPayConf->hop_num);
        if (results < 1) {
            ret = false;
            goto LABEL_EXIT;
        }
        // hop_numは2以上
        //      hop_datain[0]: 自ノード
        //      hop_datain[1]: 送金先...
        ret &= (2 <= pPayConf->hop_num) && (pPayConf->hop_num <= LN_HOP_MAX);
    }
    if (ret) {
        char node_id[UCOIN_SZ_PUBKEY * 2 + 1];
        //hop_numという名前だが、先頭はONIONに入れない(add_htlcのパラメータ)
        for (int lp = 0; lp < pPayConf->hop_num; lp++) {
            results = fscanf(fp, "%66s,%" SCNx64 ",%" SCNu64 ",%u\n",
                node_id,
                &pPayConf->hop_datain[lp].short_channel_id,
                &pPayConf->hop_datain[lp].amt_to_forward,
                &pPayConf->hop_datain[lp].outgoing_cltv_value);
            if (results != 4) {
                ret = false;
                goto LABEL_EXIT;
            }
            ret = misc_str2bin(pPayConf->hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY, node_id);
            if (!ret) {
                break;
            }
        }
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- payment: %s ---\n", pConfFile);
    if (ret) {
        print_payment_conf(pPayConf);
    }
#endif

LABEL_EXIT:
    fclose(fp);
    if (!ret) {
        SYSLOG_ERR("fail pay parse[%s]", pConfFile);
    }
    return ret;
}


void print_payment_conf(const payment_conf_t *pPayConf)
{
    fprintf(PRINTOUT, "\n--- payment ---\n");
    fprintf(PRINTOUT, "payment_hash=");
    misc_dumpbin(PRINTOUT, pPayConf->payment_hash, LN_SZ_HASH);
    fprintf(PRINTOUT, "hop_num=%d\n", pPayConf->hop_num);
    for (int lp = 0; lp < pPayConf->hop_num; lp++) {
        fprintf(PRINTOUT, " [%d]:\n", lp);
        fprintf(PRINTOUT, "  node_id= ");
        misc_dumpbin(PRINTOUT, pPayConf->hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY);
        fprintf(PRINTOUT, "  short_channel_id= %" PRIx64 "\n", pPayConf->hop_datain[lp].short_channel_id);
        fprintf(PRINTOUT, "  amount_msat= %" PRIu64 "\n", pPayConf->hop_datain[lp].amt_to_forward);
        fprintf(PRINTOUT, "  cltv_expiry: %d\n", pPayConf->hop_datain[lp].outgoing_cltv_value);
    }
}
