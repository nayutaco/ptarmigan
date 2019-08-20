/*
 *  Copyright (C) 2017 Ptarmigan Project
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

#include "inih/ini.h"

#define LOG_TAG     "confcli"
#include "utl_log.h"
#include "utl_dbg.h"
#include "utl_str.h"

#include "ln.h"

#include "conf_cli.h"
#include "ptarmd.h"


/**************************************************************************
 * macros
 **************************************************************************/

//#define M_DEBUG


/**************************************************************************
 * prototypes
 **************************************************************************/

#ifdef M_DEBUG
static void print_peer_conf(const peer_conf_t *pPeerConf);
static void print_funding_conf(const funding_conf_t *pFundConf);
static void print_payment_conf(const payment_conf_t *pPayConf);
#endif

static int handler_peer_conf(void* user, const char* section, const char* name, const char* value);
static int handler_fund_conf(void* user, const char* section, const char* name, const char* value);
static int handler_pay_conf(void* user, const char* section, const char* name, const char* value);
static bool chk_nonzero(const uint8_t *pData, int Len);


/**************************************************************************
 * public functions
 **************************************************************************/

/********************
 * peer.conf
 ********************/

void conf_peer_init(peer_conf_t *pPeerConf)
{
    memset(pPeerConf, 0, sizeof(peer_conf_t));
}


bool conf_peer_load(const char *pConfFile, peer_conf_t *pPeerConf)
{
    if (ini_parse(pConfFile, handler_peer_conf, pPeerConf) != 0) {
        //LOGE("fail peer parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(stderr, "\n--- [%s] ---\n", pConfFile);
    print_peer_conf(pPeerConf);
#endif

    return btc_keys_check_pub(pPeerConf->node_id);
}


#ifdef M_DEBUG
static void print_peer_conf(const peer_conf_t *pPeerConf)
{
    fprintf(stderr, "\n--- peer ---\n");
    fprintf(stderr, "ipaddr=%s\n", pPeerConf->ipaddr);
    fprintf(stderr, "port=%d\n", pPeerConf->port);
    fprintf(stderr, "node_id=");
    utl_dbg_dump(stderr, pPeerConf->node_id, BTC_SZ_PUBKEY, true);
}
#endif


/********************
 * fund.conf
 ********************/

void conf_funding_init(funding_conf_t *pFundConf)
{
    memset(pFundConf, 0, sizeof(funding_conf_t));
}


bool conf_funding_load(const char *pConfFile, funding_conf_t *pFundConf)
{
    if (ini_parse(pConfFile, handler_fund_conf, pFundConf) != 0) {
        //LOGE("fail fund parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(stderr, "\n--- [%s] ---\n", pConfFile);
    print_funding_conf(pFundConf);
#endif

    return chk_nonzero(pFundConf->txid, BTC_SZ_TXID);
}


#ifdef M_DEBUG
static void print_funding_conf(const funding_conf_t *pFundConf)
{
    fprintf(stderr, "\n--- funding ---\n");
    fprintf(stderr, "txid=");
    btc_dbg_dump_txid(stderr, pFundConf->txid);
    fprintf(stderr, "\n");
    fprintf(stderr, "txindex=%d\n", pFundConf->txindex);
    fprintf(stderr, "funding_sat=%" PRIu64 "\n", pFundConf->funding_sat);
    fprintf(stderr, "push_msat=%" PRIu64 "\n\n", pFundConf->push_msat);
}
#endif


/********************
 * pay.conf
 ********************/

void conf_payment_init(payment_conf_t *pPayConf)
{
    memset(pPayConf, 0, sizeof(payment_conf_t));
}


bool conf_payment_load(const char *pConfFile, payment_conf_t *pPayConf)
{
    if (ini_parse(pConfFile, handler_pay_conf, pPayConf) != 0) {
        LOGE("fail pay parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(stderr, "\n--- [%s] ---\n", pConfFile);
    print_payment_conf(pPayConf);
#endif

    //payment_hashはconfファイルになくても許可する
    bool ret = (pPayConf->num_hops >= 2);

    return ret;
}


#ifdef M_DEBUG
static void print_payment_conf(const payment_conf_t *pPayConf)
{
    fprintf(stderr, "\n--- payment ---\n");
    fprintf(stderr, "payment_hash=");
    utl_dbg_dump(stderr, pPayConf->payment_hash, BTC_SZ_HASH256, true);
    fprintf(stderr, "num_hops=%d\n", pPayConf->num_hops);
    for (int lp = 0; lp < pPayConf->num_hops; lp++) {
        fprintf(stderr, " [%d]:\n", lp);
        fprintf(stderr, "  node_id= ");
        utl_dbg_dump(stderr, pPayConf->hop_datain[lp].pubkey, BTC_SZ_PUBKEY, true);
        fprintf(stderr, "  short_channel_id= %016" PRIx64 "\n", pPayConf->hop_datain[lp].short_channel_id);
        fprintf(stderr, "  amount_msat= %" PRIu64 "\n", pPayConf->hop_datain[lp].amt_to_forward);
        fprintf(stderr, "  cltv_expiry: %u\n", pPayConf->hop_datain[lp].outgoing_cltv_value);
    }
}
#endif


/**************************************************************************
 * private functions
 **************************************************************************/

static int handler_peer_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    peer_conf_t* pconfig = (peer_conf_t *)user;

    if ((strcmp(name, "ipaddr") == 0) && (strlen(value) <= SZ_IPV4_LEN)) {
        strcpy(pconfig->ipaddr, value);
    } else if (strcmp(name, "port") == 0) {
        pconfig->port = (uint16_t)atoi(value);
    } else if (strcmp(name, "node_id") == 0) {
        utl_str_str2bin(pconfig->node_id, BTC_SZ_PUBKEY, value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


static int handler_fund_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    funding_conf_t* pconfig = (funding_conf_t *)user;

    errno = 0;
    if (strcmp(name, "txid") == 0) {
        utl_str_str2bin_rev(pconfig->txid, BTC_SZ_TXID, value);
    } else if (strcmp(name, "txindex") == 0) {
        pconfig->txindex = atoi(value);
    } else if (strcmp(name, "funding_sat") == 0) {
        pconfig->funding_sat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "push_msat") == 0) {
        pconfig->push_msat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "feerate_per_kw") == 0) {
        pconfig->feerate_per_kw = strtoull(value, NULL, 10);
    } else {
        //skip unknown option
    }
    if (errno) {
        LOGD("errno=%s\n", strerror(errno));
        return 0;
    }
    return 1;
}


static bool pay_root(ln_hop_datain_t *pHop, const char *Value)
{
    bool ret;
    char node_id[BTC_SZ_PUBKEY * 2 + 1];

    int results = sscanf(Value, "%66s,%" SCNx64 ",%" SCNu64 ",%u\n",
        node_id,
        &pHop->short_channel_id,
        &pHop->amt_to_forward,
        &pHop->outgoing_cltv_value);
    if (results != 4) {
        ret = false;
        goto LABEL_EXIT;
    }
    ret = utl_str_str2bin(pHop->pubkey, BTC_SZ_PUBKEY, node_id);

LABEL_EXIT:
    return ret;
}


static int handler_pay_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    bool ret;
    payment_conf_t* pconfig = (payment_conf_t *)user;

    if (strcmp(name, "hash") == 0) {
        ret = utl_str_str2bin(pconfig->payment_hash, BTC_SZ_HASH256, value);
    } else if (strcmp(name, "num_hops") == 0) {
        pconfig->num_hops = atoi(value);
        ret = (2 <= pconfig->num_hops) && (pconfig->num_hops <= LN_HOP_MAX + 1);
    } else if (strncmp(name, "route", 5) == 0) {
        int num = atoi(&name[5]);
        ret = (0 <= num) && (num <= LN_HOP_MAX);
        if (ret) {
            ret = pay_root(&pconfig->hop_datain[num], value);
        }
    } else {
        return 0;  /* unknown section/name, error */
    }
    if (!ret) {
        LOGE("fail: %s\n", name);
    }
    return (ret) ? 1 : 0;
}


static bool chk_nonzero(const uint8_t *pData, int Len)
{
    bool ret = false;
    for (int lp = 0; lp < Len; lp++) {
        if (*pData) {
            ret = true;
            break;
        }
        pData++;
    }
    return ret;
}
