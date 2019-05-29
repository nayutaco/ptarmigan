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

#include "inih/ini.h"

#define LOG_TAG     "conf"
#include "utl_log.h"

#include "conf.h"


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
#define M_MAX_HTLC_VALUE_IN_FLIGHT_MSAT (UINT32_MAX)
#define M_CHANNEL_RESERVE_SAT           (700)
#define M_HTLC_MINIMUM_MSAT_EST         (0)
#define M_TO_SELF_DELAY                 (40)
#define M_MAX_ACCEPTED_HTLCS            (LN_HTLC_RECEIVED_MAX)
#define M_MIN_DEPTH                     (1)

//  init
#define M_LOCALFEATURES                 (LN_INIT_LF_OPT_DATALOSS)

//#define M_DEBUG


/**************************************************************************
 * prototypes
 **************************************************************************/

#ifdef USE_BITCOIND
static int handler_btcrpc_conf(void* user, const char* section, const char* name, const char* value);
#endif  //USE_BITCOIND
static int handler_anno_conf(void* user, const char* section, const char* name, const char* value);
static int handler_channel_conf(void* user, const char* section, const char* name, const char* value);
static int handler_connect_conf(void* user, const char* section, const char* name, const char* value);


/**************************************************************************
 * public functions
 **************************************************************************/

/********************
 * bitcoin.conf
 ********************/

void conf_btcrpc_init(rpc_conf_t *pRpcConf)
{
    memset(pRpcConf, 0, sizeof(rpc_conf_t));
}


#if defined(USE_BITCOIND)
bool conf_btcrpc_load(const char *pConfFile, rpc_conf_t *pRpcConf, btc_block_chain_t Chain)
{
    LOGD("load bitcoin.conf: %s\n", pConfFile);
    if (ini_parse(pConfFile, handler_btcrpc_conf, pRpcConf) != 0) {
        LOGE("fail bitcoin.conf parse[%s]\n", pConfFile);
        fprintf(stderr, "fail bitcoin.conf parse[%s]\n", pConfFile);
        return false;
    }
    if (pRpcConf->rpcport == 0) {
        switch (Chain) {
        case BTC_BLOCK_CHAIN_BTCMAIN:
            pRpcConf->rpcport = 8332;
            break;
        case BTC_BLOCK_CHAIN_BTCTEST:
            pRpcConf->rpcport = 18332;
            break;
        case BTC_BLOCK_CHAIN_BTCREGTEST:
            pRpcConf->rpcport = 18443;
            break;
        default:
            LOGE("unknown chain\n");
            break;
        }
    }
    if (strlen(pRpcConf->rpcurl) == 0) {
        strcpy(pRpcConf->rpcurl, "127.0.0.1");
    }

#ifdef M_DEBUG
    fprintf(stderr, "rpcuser=%s\n", pRpcConf->rpcuser);
    fprintf(stderr, "rpcpassword=%s\n", pRpcConf->rpcpasswd);
    fprintf(stderr, "rpcport=%d\n", pRpcConf->rpcport);
    fprintf(stderr, "rpcurl=%s\n", pRpcConf->rpcurl);
#endif

    return true;
}


bool conf_btcrpc_load_default(rpc_conf_t *pRpcConf, btc_block_chain_t Chain)
{
    char path[512];
    sprintf(path, "%s/.bitcoin/bitcoin.conf", getenv("HOME"));
    return conf_btcrpc_load(path, pRpcConf, Chain);
}
#endif  //USE_BITCOIND


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
        //LOGE("fail anno parse[%s]", pConfFile);
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
        //LOGE("fail channel parse[%s]", pConfFile);
        return false;
    }

    return true;
}


void conf_connect_init(connect_conf_t *pConnConf)
{
    memset(pConnConf, 0, sizeof(connect_conf_t));
}


bool conf_connect_load(const char *pConfFile, connect_conf_t *pConnConf)
{
    if (ini_parse(pConfFile, handler_connect_conf, pConnConf) != 0) {
        return false;
    }

    return true;
}


/**************************************************************************
 * private functions
 **************************************************************************/

#ifdef USE_BITCOIND
static int handler_btcrpc_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    rpc_conf_t* pconfig = (rpc_conf_t *)user;

    if ((strcmp(name, "rpcuser") == 0) && (strlen(value) < SZ_RPC_USER)) {
        strcpy(pconfig->rpcuser, value);
    } else if ((strcmp(name, "rpcpassword") == 0) && (strlen(value) < SZ_RPC_PASSWD)) {
        strcpy(pconfig->rpcpasswd, value);
    } else if (strcmp(name, "rpcport") == 0) {
        pconfig->rpcport = atoi(value);
    } else if ((strcmp(name, "rpcurl") == 0) && (strlen(value) < SZ_RPC_URL)) {
        //bitcoin.confには無い。ptarmiganテスト用。
        strcpy(pconfig->rpcurl, value);
    } else {
        //return 0;  /* unknown section/name, error */
    }
    return 1;
}
#endif


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
        LOGE("fail: %s\n", name);
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


static int handler_connect_conf(void* user, const char* section, const char* name, const char* value)
{
    (void)section;

    connect_conf_t* pconfig = (connect_conf_t *)user;

    if (strncmp(name, "node", 4) == 0) {
        int num = 0;
        num = (int)strtol(name + 4, NULL, 10);
        if ((0 <= num) && (num < PTARMD_CONNLIST_MAX)) {
            strncpy(pconfig->conn_str[num], value, SZ_NODECONN_STR);
            pconfig->conn_str[num][SZ_NODECONN_STR] = '\0';
        } else {
            //through
        }
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}
