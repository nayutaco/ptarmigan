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

#include "inih/ini.h"

#include "conf.h"
#include "misc.h"
#include "ln.h"

//#define M_DEBUG

#define M_CHK_RET(ret)      \
    if (ret < 1) {          \
        goto LABEL_EXIT;    \
    }


/**************************************************************************
 * typedefs
 **************************************************************************/

struct node_confs_t {
    node_conf_t     *p_node_conf;
    rpc_conf_t      *p_rpc_conf;
    ln_nodeaddr_t   *p_addr;
};


/**************************************************************************
 * prototypes
 **************************************************************************/

static int handler_node_conf(void* user, const char* section, const char* name, const char* value);
static int handler_peer_conf(void* user, const char* section, const char* name, const char* value);
static int handler_fund_conf(void* user, const char* section, const char* name, const char* value);
static int handler_btcrpc_conf(void* user, const char* section, const char* name, const char* value);
static int handler_pay_conf(void* user, const char* section, const char* name, const char* value);


/**************************************************************************
 * public functions
 **************************************************************************/

/********************
 * node.conf
 ********************/

bool load_node_conf(const char *pConfFile, node_conf_t *pNodeConf, rpc_conf_t *pRpcConf, ln_nodeaddr_t *pAddr)
{
    struct node_confs_t node_confs = { pNodeConf, pRpcConf, pAddr };
    memset(pNodeConf, 0, sizeof(node_conf_t));
    memset(pRpcConf, 0, sizeof(rpc_conf_t));
    memset(pAddr, 0, sizeof(ln_nodeaddr_t));

    if (ini_parse(pConfFile, handler_node_conf, &node_confs) < 0) {
        SYSLOG_ERR("fail node parse[%s]", pConfFile);
        return false;
    }

    pAddr->port = pNodeConf->port;

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- node: %s ---\n", pConfFile);
    print_node_conf(pNodeConf, pRpcConf);
#endif

    return true;
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
    ucoin_util_dumpbin(PRINTOUT, keys.pub, UCOIN_SZ_PUBKEY, true);
    fprintf(PRINTOUT, "\n\n");
}


/********************
 * peer.conf
 ********************/

bool load_peer_conf(const char *pConfFile, peer_conf_t *pPeerConf)
{
    memset(pPeerConf, 0, sizeof(peer_conf_t));

    if (ini_parse(pConfFile, handler_peer_conf, pPeerConf) < 0) {
        SYSLOG_ERR("fail peer parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    print_peer_conf(pPeerConf);
#endif

    return true;
}


void print_peer_conf(const peer_conf_t *pPeerConf)
{
    fprintf(PRINTOUT, "\n--- peer ---\n");
    fprintf(PRINTOUT, "ipaddr=%s\n", pPeerConf->ipaddr);
    fprintf(PRINTOUT, "port=%d\n", pPeerConf->port);
    fprintf(PRINTOUT, "node_id=");
    ucoin_util_dumpbin(PRINTOUT, pPeerConf->node_id, UCOIN_SZ_PUBKEY, true);
}


/********************
 * fund.conf
 ********************/

bool load_funding_conf(const char *pConfFile, funding_conf_t *pFundConf)
{
    memset(pFundConf, 0, sizeof(funding_conf_t));

    if (ini_parse(pConfFile, handler_fund_conf, pFundConf) < 0) {
        SYSLOG_ERR("fail fund parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    print_funding_conf(pFundConf);
#endif

    return true;
}


void print_funding_conf(const funding_conf_t *pFundConf)
{
    fprintf(PRINTOUT, "\n--- funding ---\n");
    fprintf(PRINTOUT, "txid=");
    ucoin_util_dumptxid(PRINTOUT, pFundConf->txid);
    fprintf(PRINTOUT, "\n");
    fprintf(PRINTOUT, "txindex=%d\n", pFundConf->txindex);
    fprintf(PRINTOUT, "signaddr=%s\n", pFundConf->signaddr);
    fprintf(PRINTOUT, "funding_sat=%" PRIu64 "\n", pFundConf->funding_sat);
    fprintf(PRINTOUT, "push_sat=%" PRIu64 "\n\n", pFundConf->push_sat);
}


/********************
 * bitcoin.conf
 ********************/

bool load_btcrpc_conf(const char *pConfFile, rpc_conf_t *pRpcConf)
{
    memset(pRpcConf, 0, sizeof(rpc_conf_t));

    if (ini_parse(pConfFile, handler_btcrpc_conf, pRpcConf) < 0) {
        SYSLOG_ERR("fail bitcoin.conf parse[%s]", pConfFile);
        return false;
    }

    if ((strlen(pRpcConf->rpcuser) == 0) || (strlen(pRpcConf->rpcpasswd) == 0)) {
        SYSLOG_ERR("fail: no rpcuser or rpcpassword[%s]", pConfFile);
        return false;
    }

    if (strlen(pRpcConf->rpcurl) == 0) {
        strcpy(pRpcConf->rpcurl, "127.0.0.1");
    }
    if (pRpcConf->rpcport == 0) {
#if NETKIND==0
        pRpcConf->rpcport = 8332;
#elif NETKIND==1
        pRpcConf->rpcport = 18332;
#endif
    }
    char tmp[SZ_RPC_URL];
    sprintf(tmp, "http://%s:%d/", pRpcConf->rpcurl, pRpcConf->rpcport);
    strcpy(pRpcConf->rpcurl, tmp);

#ifdef M_DEBUG
    fprintf(PRINTOUT, "rpcuser=%s\n", pRpcConf->rpcuser);
    fprintf(PRINTOUT, "rpcport=%d\n", pRpcConf->rpcport);
    fprintf(PRINTOUT, "rpcurl=%s\n", pRpcConf->rpcurl);
#endif

    return true;
}


bool load_btcrpc_default_conf(rpc_conf_t *pRpcConf)
{
    char path[512];
    sprintf(path, "%s/.bitcoin/bitcoin.conf", getenv("HOME"));
    return load_btcrpc_conf(path, pRpcConf);
}


/********************
 * pay.conf
 ********************/

bool load_payment_conf(const char *pConfFile, payment_conf_t *pPayConf)
{
    memset(pPayConf, 0, sizeof(payment_conf_t));

    if (ini_parse(pConfFile, handler_pay_conf, pPayConf) < 0) {
        SYSLOG_ERR("fail pay parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    print_payment_conf(pPayConf);
#endif

    return true;
}


void print_payment_conf(const payment_conf_t *pPayConf)
{
    fprintf(PRINTOUT, "\n--- payment ---\n");
    fprintf(PRINTOUT, "payment_hash=");
    ucoin_util_dumpbin(PRINTOUT, pPayConf->payment_hash, LN_SZ_HASH, true);
    fprintf(PRINTOUT, "hop_num=%d\n", pPayConf->hop_num);
    for (int lp = 0; lp < pPayConf->hop_num; lp++) {
        fprintf(PRINTOUT, " [%d]:\n", lp);
        fprintf(PRINTOUT, "  node_id= ");
        ucoin_util_dumpbin(PRINTOUT, pPayConf->hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY, true);
        fprintf(PRINTOUT, "  short_channel_id= %" PRIx64 "\n", pPayConf->hop_datain[lp].short_channel_id);
        fprintf(PRINTOUT, "  amount_msat= %" PRIu64 "\n", pPayConf->hop_datain[lp].amt_to_forward);
        fprintf(PRINTOUT, "  cltv_expiry: %d\n", pPayConf->hop_datain[lp].outgoing_cltv_value);
    }
}


/**************************************************************************
 * private functions
 **************************************************************************/

static int handler_node_conf(void* user, const char* section, const char* name, const char* value)
{
    struct node_confs_t* pconfig = (struct node_confs_t *)user;

    if (strcmp(name, "port") == 0) {
        pconfig->p_node_conf->port = (uint16_t)atoi(value);
    } else if (strcmp(name, "name") == 0) {
        strcpy(pconfig->p_node_conf->name, value);
    } else if (strcmp(name, "wif") == 0) {
        strcpy(pconfig->p_node_conf->wif, value);
    } else if (strcmp(name, "rpcuser") == 0) {
        strcpy(pconfig->p_rpc_conf->rpcuser, value);
    } else if (strcmp(name, "rpcpasswd") == 0) {
        strcpy(pconfig->p_rpc_conf->rpcpasswd, value);
    } else if (strcmp(name, "rpcurl") == 0) {
        strcpy(pconfig->p_rpc_conf->rpcurl, value);
    } else if (strcmp(name, "rpcport") == 0) {
        pconfig->p_rpc_conf->rpcport = atoi(value);
    } else if (strcmp(name, "ipv4") == 0) {
        pconfig->p_addr->type = LN_NODEDESC_IPV4;
        uint8_t *p = pconfig->p_addr->addrinfo.addr;
        sscanf(value, "%" SCNu8 ".%" SCNu8 ".%" SCNu8 ".%" SCNu8,
                &p[0], &p[1], &p[2], &p[3]);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


static int handler_peer_conf(void* user, const char* section, const char* name, const char* value)
{
    peer_conf_t* pconfig = (peer_conf_t *)user;

    if (strcmp(name, "ipaddr") == 0) {
        strcpy(pconfig->ipaddr, value);
    } else if (strcmp(name, "port") == 0) {
        pconfig->port = (uint16_t)atoi(value);
    } else if (strcmp(name, "name") == 0) {
        strcpy(pconfig->name, value);
    } else if (strcmp(name, "node_id") == 0) {
        misc_str2bin(pconfig->node_id, UCOIN_SZ_PUBKEY, value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


static int handler_fund_conf(void* user, const char* section, const char* name, const char* value)
{
    funding_conf_t* pconfig = (funding_conf_t *)user;

    if (strcmp(name, "txid") == 0) {
        misc_str2bin_rev(pconfig->txid, UCOIN_SZ_TXID, value);
    } else if (strcmp(name, "txindex") == 0) {
        pconfig->txindex = atoi(value);
    } else if (strcmp(name, "signaddr") == 0) {
        strcpy(pconfig->signaddr, value);
    } else if (strcmp(name, "funding_sat") == 0) {
        pconfig->funding_sat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "push_sat") == 0) {
        pconfig->push_sat = strtoull(value, NULL, 10);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


static int handler_btcrpc_conf(void* user, const char* section, const char* name, const char* value)
{
    rpc_conf_t* pconfig = (rpc_conf_t *)user;

    if (strcmp(name, "rpcuser") == 0) {
        strcpy(pconfig->rpcuser, value);
    } else if (strcmp(name, "rpcpassword") == 0) {
        strcpy(pconfig->rpcpasswd, value);
    } else if (strcmp(name, "rpcconnect") == 0) {
        strcpy(pconfig->rpcurl, value);
    } else if (strcmp(name, "rpcport") == 0) {
        pconfig->rpcport = atoi(value);
    } else {
        //return 0;  /* unknown section/name, error */
    }
    return 1;
}


static bool pay_root(ln_hop_datain_t *pHop, const char *Value)
{
    bool ret;
    char node_id[UCOIN_SZ_PUBKEY * 2 + 1];

    int results = sscanf(Value, "%66s,%" SCNx64 ",%" SCNu64 ",%u\n",
        node_id,
        &pHop->short_channel_id,
        &pHop->amt_to_forward,
        &pHop->outgoing_cltv_value);
    if (results != 4) {
        ret = false;
        goto LABEL_EXIT;
    }
    ret = misc_str2bin(pHop->pubkey, UCOIN_SZ_PUBKEY, node_id);

LABEL_EXIT:
    return ret;
}


static int handler_pay_conf(void* user, const char* section, const char* name, const char* value)
{
    bool ret;
    payment_conf_t* pconfig = (payment_conf_t *)user;

    if (strcmp(name, "hash") == 0) {
        ret = misc_str2bin(pconfig->payment_hash, LN_SZ_HASH, value);
    } else if (strcmp(name, "hop_num") == 0) {
        pconfig->hop_num = atoi(value);
        ret = (2 <= pconfig->hop_num) && (pconfig->hop_num <= LN_HOP_MAX + 1);
    } else if (strncmp(name, "route", 5) == 0) {
        int num = atoi(&name[5]);
        ret = (0 <= num) && (num <= LN_HOP_MAX);
        if (ret) {
            ret = pay_root(&pconfig->hop_datain[num], value);
        }
    } else {
        return 0;  /* unknown section/name, error */
    }
    return (ret) ? 1 : 0;
}
