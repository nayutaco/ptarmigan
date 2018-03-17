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
 * prototypes
 **************************************************************************/

static int handler_peer_conf(void* user, const char* section, const char* name, const char* value);
static int handler_fund_conf(void* user, const char* section, const char* name, const char* value);
static int handler_btcrpc_conf(void* user, const char* section, const char* name, const char* value);
static int handler_pay_conf(void* user, const char* section, const char* name, const char* value);
static int handler_anno_conf(void* user, const char* section, const char* name, const char* value);
static int handler_establish_conf(void* user, const char* section, const char* name, const char* value);
static bool chk_nonzero(const uint8_t *pData, int Len);


/**************************************************************************
 * public functions
 **************************************************************************/

/********************
 * peer.conf
 ********************/

bool load_peer_conf(const char *pConfFile, peer_conf_t *pPeerConf)
{
    memset(pPeerConf, 0, sizeof(peer_conf_t));

    if (ini_parse(pConfFile, handler_peer_conf, pPeerConf) != 0) {
        //DBG_PRINTF("fail peer parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    print_peer_conf(pPeerConf);
#endif

    return ucoin_keys_chkpub(pPeerConf->node_id);
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

    if (ini_parse(pConfFile, handler_fund_conf, pFundConf) != 0) {
        //DBG_PRINTF("fail fund parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    print_funding_conf(pFundConf);
#endif

    return chk_nonzero(pFundConf->txid, UCOIN_SZ_TXID);
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
    if (ini_parse(pConfFile, handler_btcrpc_conf, pRpcConf) != 0) {
        DBG_PRINTF("fail bitcoin.conf parse[%s]", pConfFile);
        return false;
    }

    if ((strlen(pRpcConf->rpcuser) == 0) || (strlen(pRpcConf->rpcpasswd) == 0)) {
        DBG_PRINTF("fail: no rpcuser or rpcpassword[%s]", pConfFile);
        return false;
    }

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

    if (ini_parse(pConfFile, handler_pay_conf, pPayConf) != 0) {
        DBG_PRINTF("fail pay parse[%s]", pConfFile);
        return false;
    }

#ifdef M_DEBUG
    fprintf(PRINTOUT, "\n--- [%s] ---\n", pConfFile);
    print_payment_conf(pPayConf);
#endif

    //payment_hashはconfファイルになくても許可する
    bool ret = (pPayConf->hop_num >= 2);

    return ret;
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
        fprintf(PRINTOUT, "  cltv_expiry: %u\n", pPayConf->hop_datain[lp].outgoing_cltv_value);
    }
}


bool load_anno_conf(const char *pConfFile, anno_conf_t *pAnnoConf)
{
    memset(pAnnoConf, 0, sizeof(anno_conf_t));

    if (ini_parse(pConfFile, handler_anno_conf, pAnnoConf) != 0) {
        //DBG_PRINTF("fail anno parse[%s]", pConfFile);
        return false;
    }

    return true;
}


bool load_establish_conf(const char *pConfFile, establish_conf_t *pEstConf)
{
    memset(pEstConf, 0, sizeof(establish_conf_t));

    if (ini_parse(pConfFile, handler_establish_conf, pEstConf) != 0) {
        //DBG_PRINTF("fail establish parse[%s]", pConfFile);
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
    (void)section;

    funding_conf_t* pconfig = (funding_conf_t *)user;

    errno = 0;
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
    } else if (strcmp(name, "feerate_per_kw") == 0) {
        pconfig->feerate_per_kw = strtoull(value, NULL, 10);
    } else {
        return 0;  /* unknown section/name, error */
    }
    if (errno) {
        DBG_PRINTF("errno=%s\n", strerror(errno));
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
        DBG_PRINTF("fail: %s\n", name);
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
        DBG_PRINTF("fail: %s\n", name);
    }
    if (errno) {
        DBG_PRINTF("errno=%s\n", strerror(errno));
        return 0;
    }
    return (ret) ? 1 : 0;
}


static int handler_establish_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    bool ret = true;
    establish_conf_t* pconfig = (establish_conf_t *)user;

    errno = 0;
    if (strcmp(name, "dust_limit_sat") == 0) {
        pconfig->dust_limit_sat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "max_htlc_value_in_flight_msat") == 0) {
        pconfig->max_htlc_value_in_flight_msat = strtoull(value, NULL, 10);
        ret = (pconfig->max_htlc_value_in_flight_msat > 0);
    } else if (strcmp(name, "channel_reserve_sat") == 0) {
        pconfig->channel_reserve_sat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "htlc_minimum_msat") == 0) {
        pconfig->htlc_minimum_msat = strtoull(value, NULL, 10);
    } else if (strcmp(name, "to_self_delay") == 0) {
        pconfig->to_self_delay = atoi(value);
        ret = (pconfig->to_self_delay > 0);
    } else if (strcmp(name, "max_accepted_htlcs") == 0) {
        pconfig->max_accepted_htlcs = atoi(value);
        ret = (pconfig->max_accepted_htlcs > 0);
    } else if (strcmp(name, "min_depth") == 0) {
        pconfig->min_depth = strtoul(value, NULL, 10);
        ret = (pconfig->min_depth > 0);
    } else {
        return 0;  /* unknown section/name, error */
    }
    if (!ret) {
        DBG_PRINTF("fail: %s\n", name);
    }
    if (errno) {
        DBG_PRINTF("errno=%s\n", strerror(errno));
        return 0;
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