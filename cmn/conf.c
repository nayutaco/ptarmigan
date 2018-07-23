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

/**************************************************************************
 * macros
 **************************************************************************/

//デフォルト値
//  announcement
#define M_CLTV_EXPIRY_DELTA             (36)
#define M_HTLC_MINIMUM_MSAT_ANNO        (0)
#define M_FEE_BASE_MSAT                 (10)
#define M_FEE_PROP_MILLIONTHS           (100)

//  establish
#define M_DUST_LIMIT_SAT                (546)
#define M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT (INT64_MAX)
#define M_CHANNEL_RESERVE_SAT           (700)
#define M_HTLC_MINIMUM_MSAT_EST         (0)
#define M_TO_SELF_DELAY                 (40)
#define M_MAX_ACCEPTED_HTLCS            (LN_HTLC_MAX)
#define M_MIN_DEPTH                     (1)

//  init
#define M_LOCALFEATURES                 (LN_INIT_LF_ROUTE_SYNC | LN_INIT_LF_OPT_DATALOSS_OPT)

//#define M_DEBUG

#define M_CHK_RET(ret)      \
    if (ret < 1) {          \
        goto LABEL_EXIT;    \
    }


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
static int handler_btcrpc_conf(void* user, const char* section, const char* name, const char* value);
static int handler_pay_conf(void* user, const char* section, const char* name, const char* value);
static int handler_anno_conf(void* user, const char* section, const char* name, const char* value);
static int handler_channel_conf(void* user, const char* section, const char* name, const char* value);
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
        //LOGD("fail peer parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(stderr, "\n--- [%s] ---\n", pConfFile);
    print_peer_conf(pPeerConf);
#endif

    return ptarm_keys_chkpub(pPeerConf->node_id);
}


#ifdef M_DEBUG
static void print_peer_conf(const peer_conf_t *pPeerConf)
{
    fprintf(stderr, "\n--- peer ---\n");
    fprintf(stderr, "ipaddr=%s\n", pPeerConf->ipaddr);
    fprintf(stderr, "port=%d\n", pPeerConf->port);
    fprintf(stderr, "node_id=");
    ptarm_util_dumpbin(stderr, pPeerConf->node_id, PTARM_SZ_PUBKEY, true);
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
        //LOGD("fail fund parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(stderr, "\n--- [%s] ---\n", pConfFile);
    print_funding_conf(pFundConf);
#endif

    return chk_nonzero(pFundConf->txid, PTARM_SZ_TXID);
}


#ifdef M_DEBUG
static void print_funding_conf(const funding_conf_t *pFundConf)
{
    fprintf(stderr, "\n--- funding ---\n");
    fprintf(stderr, "txid=");
    ptarm_util_dumptxid(stderr, pFundConf->txid);
    fprintf(stderr, "\n");
    fprintf(stderr, "txindex=%d\n", pFundConf->txindex);
    fprintf(stderr, "funding_sat=%" PRIu64 "\n", pFundConf->funding_sat);
    fprintf(stderr, "push_sat=%" PRIu64 "\n\n", pFundConf->push_sat);
}
#endif


/********************
 * bitcoin.conf
 ********************/

void conf_btcrpc_init(rpc_conf_t *pRpcConf)
{
    memset(pRpcConf, 0, sizeof(rpc_conf_t));
#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    pRpcConf->rpcport = 8332;
#elif NETKIND==1
    pRpcConf->rpcport = 18332;
#endif
    strcpy(pRpcConf->rpcurl, "127.0.0.1");
}


bool conf_btcrpc_load(const char *pConfFile, rpc_conf_t *pRpcConf)
{
    if (ini_parse(pConfFile, handler_btcrpc_conf, pRpcConf) != 0) {
        LOGD("fail bitcoin.conf parse[%s]", pConfFile);
        return false;
    }

    if ((strlen(pRpcConf->rpcuser) == 0) || (strlen(pRpcConf->rpcpasswd) == 0)) {
        LOGD("fail: no rpcuser or rpcpassword[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(stderr, "rpcuser=%s\n", pRpcConf->rpcuser);
    fprintf(stderr, "rpcport=%d\n", pRpcConf->rpcport);
    fprintf(stderr, "rpcurl=%s\n", pRpcConf->rpcurl);
#endif

    return true;
}


bool conf_btcrpc_load_default(rpc_conf_t *pRpcConf)
{
    char path[512];
    sprintf(path, "%s/.bitcoin/bitcoin.conf", getenv("HOME"));
    return conf_btcrpc_load(path, pRpcConf);
}


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
        LOGD("fail pay parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(stderr, "\n--- [%s] ---\n", pConfFile);
    print_payment_conf(pPayConf);
#endif

    //payment_hashはconfファイルになくても許可する
    bool ret = (pPayConf->hop_num >= 2);

    return ret;
}


#ifdef M_DEBUG
static void print_payment_conf(const payment_conf_t *pPayConf)
{
    fprintf(stderr, "\n--- payment ---\n");
    fprintf(stderr, "payment_hash=");
    ptarm_util_dumpbin(stderr, pPayConf->payment_hash, LN_SZ_HASH, true);
    fprintf(stderr, "hop_num=%d\n", pPayConf->hop_num);
    for (int lp = 0; lp < pPayConf->hop_num; lp++) {
        fprintf(stderr, " [%d]:\n", lp);
        fprintf(stderr, "  node_id= ");
        ptarm_util_dumpbin(stderr, pPayConf->hop_datain[lp].pubkey, PTARM_SZ_PUBKEY, true);
        fprintf(stderr, "  short_channel_id= %" PRIx64 "\n", pPayConf->hop_datain[lp].short_channel_id);
        fprintf(stderr, "  amount_msat= %" PRIu64 "\n", pPayConf->hop_datain[lp].amt_to_forward);
        fprintf(stderr, "  cltv_expiry: %u\n", pPayConf->hop_datain[lp].outgoing_cltv_value);
    }
}
#endif


void conf_anno_init(anno_conf_t *pAnnoConf)
{
    memset(pAnnoConf, 0, sizeof(anno_conf_t));

    pAnnoConf->cltv_expiry_delta = M_CLTV_EXPIRY_DELTA;
    pAnnoConf->htlc_minimum_msat = M_HTLC_MINIMUM_MSAT_ANNO;
    pAnnoConf->fee_base_msat = M_FEE_BASE_MSAT;
    pAnnoConf->fee_prop_millionths = M_FEE_PROP_MILLIONTHS;
}


bool conf_anno_load(const char *pConfFile, anno_conf_t *pAnnoConf)
{
    if (ini_parse(pConfFile, handler_anno_conf, pAnnoConf) != 0) {
        //LOGD("fail anno parse[%s]", pConfFile);
        return false;
    }

    return true;
}


void conf_channel_init(channel_conf_t *pChannConf)
{
    memset(pChannConf, 0, sizeof(channel_conf_t));

    pChannConf->dust_limit_sat = M_DUST_LIMIT_SAT;
    pChannConf->max_htlc_value_in_flight_msat = M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT;
    pChannConf->channel_reserve_sat = M_CHANNEL_RESERVE_SAT;
    pChannConf->htlc_minimum_msat = M_HTLC_MINIMUM_MSAT_EST;
    pChannConf->to_self_delay = M_TO_SELF_DELAY;
    pChannConf->max_accepted_htlcs = M_MAX_ACCEPTED_HTLCS;
    pChannConf->min_depth = M_MIN_DEPTH;
    pChannConf->localfeatures = M_LOCALFEATURES;
}


bool conf_channel_load(const char *pConfFile, channel_conf_t *pChannConf)
{
    if (ini_parse(pConfFile, handler_channel_conf, pChannConf) != 0) {
        //LOGD("fail channel parse[%s]", pConfFile);
        return false;
    }

    return true;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static int handler_peer_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    peer_conf_t* pconfig = (peer_conf_t *)user;

    if (strcmp(name, "ipaddr") == 0) {
        strcpy(pconfig->ipaddr, value);
    } else if (strcmp(name, "port") == 0) {
        pconfig->port = (uint16_t)atoi(value);
    } else if (strcmp(name, "node_id") == 0) {
        misc_str2bin(pconfig->node_id, PTARM_SZ_PUBKEY, value);
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
        misc_str2bin_rev(pconfig->txid, PTARM_SZ_TXID, value);
    } else if (strcmp(name, "txindex") == 0) {
        pconfig->txindex = atoi(value);
    } else if (strcmp(name, "funding_sat") == 0) {
        pconfig->funding_sat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "push_sat") == 0) {
        pconfig->push_sat = strtoull(value, NULL, 10);
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


static int handler_btcrpc_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    rpc_conf_t* pconfig = (rpc_conf_t *)user;

    if (strcmp(name, "rpcuser") == 0) {
        strcpy(pconfig->rpcuser, value);
    } else if (strcmp(name, "rpcpassword") == 0) {
        strcpy(pconfig->rpcpasswd, value);
    } else if (strcmp(name, "rpcport") == 0) {
        pconfig->rpcport = atoi(value);
    } else if (strcmp(name, "rpcurl") == 0) {
        //bitcoin.confには無い。ptarmiganテスト用。
        strcpy(pconfig->rpcurl, value);
    } else {
        //return 0;  /* unknown section/name, error */
    }
    return 1;
}


static bool pay_root(ln_hop_datain_t *pHop, const char *Value)
{
    bool ret;
    char node_id[PTARM_SZ_PUBKEY * 2 + 1];

    int results = sscanf(Value, "%66s,%" SCNx64 ",%" SCNu64 ",%u\n",
        node_id,
        &pHop->short_channel_id,
        &pHop->amt_to_forward,
        &pHop->outgoing_cltv_value);
    if (results != 4) {
        ret = false;
        goto LABEL_EXIT;
    }
    ret = misc_str2bin(pHop->pubkey, PTARM_SZ_PUBKEY, node_id);

LABEL_EXIT:
    return ret;
}


static int handler_pay_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

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
    if (!ret) {
        LOGD("fail: %s\n", name);
    }
    return (ret) ? 1 : 0;
}


static int handler_anno_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    bool ret = true;
    anno_conf_t* pconfig = (anno_conf_t *)user;

    errno = 0;
    if (strcmp(name, "cltv_expiry_delta") == 0) {
        pconfig->cltv_expiry_delta = atoi(value);
        ret = (pconfig->cltv_expiry_delta > 0);
    } else if (strcmp(name, "htlc_minimum_msat") == 0) {
        pconfig->htlc_minimum_msat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "fee_base_msat") == 0) {
        pconfig->fee_base_msat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "fee_prop_millionths") == 0) {
        pconfig->fee_prop_millionths = strtoull(value, NULL, 10);
    } else {
        return 0;  /* unknown section/name, error */
    }
    if (!ret) {
        LOGD("fail: %s\n", name);
    }
    if (errno) {
        LOGD("errno=%s\n", strerror(errno));
        return 0;
    }
    return (ret) ? 1 : 0;
}


/** channel.conf解析
 * 設定できない値の場合は、エラーにせずスルーする。
 * そのため、 #conf_channel_init() での初期化を忘れないこと。
 */
static int handler_channel_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    channel_conf_t* pconfig = (channel_conf_t *)user;

    errno = 0;
    if (strcmp(name, "dust_limit_sat") == 0) {
        pconfig->dust_limit_sat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "max_htlc_value_in_flight_msat") == 0) {
        unsigned long long val = strtoull(value, NULL, 10);
        if ((errno == 0) && (val > 0)) {
            pconfig->max_htlc_value_in_flight_msat = (uint64_t)val;
        }
    } else if (strcmp(name, "channel_reserve_sat") == 0) {
        unsigned long long val = strtoull(value, NULL, 10);
        if ((errno == 0) && (val > 0)) {
            pconfig->channel_reserve_sat = val;
        }
    } else if (strcmp(name, "htlc_minimum_msat") == 0) {
        unsigned long long val = strtoull(value, NULL, 10);
        if ((errno == 0)) {
            pconfig->htlc_minimum_msat = val;
        }
    } else if (strcmp(name, "to_self_delay") == 0) {
        int val = atoi(value);
        if (val > 0) {
            pconfig->to_self_delay = (uint16_t)val;
        }
    } else if (strcmp(name, "max_accepted_htlcs") == 0) {
        int val = atoi(value);
        if (val > 0) {
            pconfig->max_accepted_htlcs = (uint16_t)val;
        }
    } else if (strcmp(name, "min_depth") == 0) {
        unsigned long val = strtoul(value, NULL, 10);
        if (val > 0) {
            pconfig->min_depth = val;
        }
    } else if (strcmp(name, "localfeatures") == 0) {
        pconfig->localfeatures = (uint8_t)strtoul(value, NULL, 10);
    } else {
        /* unknown section/name */
    }
    return 1;
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
