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
/** @file   ln_node.c
 *  @brief  ノード情報
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "utl_addr.h"
#include "utl_dbg.h"
#include "utl_net.h"
#include "utl_str.h"
#include "utl_time.h"

#include "btc_crypto.h"
#include "btc_sig.h"

#include "ln_db.h"
#include "ln_msg_anno.h"
#include "ln_node.h"
#include "ln_local.h"
#include "ln_db_lmdb.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    const uint8_t *p_node_id;
    ln_channel_t *p_channel;
} comp_param_cnl_t;


/** @struct comp_param_srcnodeid_t
 *  @brief  #ln_node_search_node_id()用
 */
typedef struct {
    uint8_t *p_node_id;
    uint64_t short_channel_id;
} comp_param_srcnodeid_t;


/**************************************************************************
 * private variables
 **************************************************************************/

static ln_node_t    mNode;


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool comp_func_cnl(ln_channel_t *pChannel, void *p_db_param, void *p_param);
static bool comp_func_total_msat(ln_channel_t *pChannel, void *p_db_param, void *p_param);
static bool comp_func_srch_nodeid(ln_channel_t *pChannel, void *p_db_param, void *p_param);
//static bool comp_node_addr(const ln_node_addr_t *pAddr1, const ln_node_addr_t *pAddr2);
static void print_node(void);


/**************************************************************************
 * public functions
 **************************************************************************/

const uint8_t *ln_node_getid(void)
{
    return mNode.keys.pub;
}


const ln_node_addr_t *ln_node_addr(void)
{
    return &mNode.addr;
}


void ln_node_addr_set(const ln_node_addr_t *pAddr)
{
    memcpy(&mNode.addr, pAddr, sizeof(ln_node_addr_t));
}


const char *ln_node_alias(void)
{
    return mNode.alias;
}


void ln_node_alias_set(const char *pAlias)
{
    strncpy(mNode.alias, pAlias, LN_SZ_ALIAS_STR);
    mNode.alias[LN_SZ_ALIAS_STR] = '\0';
    LOGD("alias: %s\n", mNode.alias);
}


bool ln_node_init(uint8_t Features)
{
    bool ret = false;
    char wif[BTC_SZ_WIF_STR_MAX + 1];
    btc_chain_t chain;
    utl_buf_t buf_node_old = UTL_BUF_INIT;
    utl_buf_t buf_node_new = UTL_BUF_INIT;
    utl_buf_t buf_addrs = UTL_BUF_INIT;
    ln_msg_node_announcement_t msg;
    ln_msg_node_announcement_addresses_t addrs;

    mNode.features = Features;

    if (!ln_db_init(wif, mNode.alias, &mNode.addr.port, true)) {
        LOGE("fail: db init\n");
        goto LABEL_EXIT;
    }

    if (!btc_keys_wif2keys(&mNode.keys, &chain, wif)) goto LABEL_EXIT;

    //create new
    {
        uint8_t dummy_signature[LN_SZ_SIGNATURE];
        uint8_t alias[LN_SZ_ALIAS_STR] = {0};
        uint8_t rgb_color[LN_SZ_RGB_COLOR] = {0};
        memset(dummy_signature, 0xcc, sizeof(dummy_signature));
        strncpy((char *)alias, mNode.alias, LN_SZ_ALIAS_STR);

        if ((mNode.addr.type == LN_ADDR_DESC_TYPE_IPV4) && utl_net_ipv4_addr_is_routable(mNode.addr.addr)) {
            addrs.addresses[0].type = mNode.addr.type;
            addrs.addresses[0].p_addr = mNode.addr.addr;
            addrs.addresses[0].port = mNode.addr.port;
            addrs.num = 1;
        } else {
            LOGD("no IP address or not routable address\n");
            addrs.num = 0;
        }
        if (!ln_msg_node_announcement_addresses_write(&buf_addrs, &addrs)) goto LABEL_EXIT;

        msg.p_signature = dummy_signature;
        msg.flen = 0;
        msg.p_features = NULL;
        msg.timestamp = (uint32_t)utl_time_time();
        msg.p_node_id = mNode.keys.pub;
        msg.p_rgb_color = rgb_color;
        msg.p_alias = alias;
        msg.addrlen = buf_addrs.len;
        msg.p_addresses = buf_addrs.buf;
        if (!ln_msg_node_announcement_write(&buf_node_new, &msg) )goto LABEL_EXIT;
        if (!ln_msg_node_announcement_sign(buf_node_new.buf, buf_node_new.len)) goto LABEL_EXIT;
    }

    //compare current
    if (ln_db_annonod_load(&buf_node_old, NULL, mNode.keys.pub)) {
        if (!utl_buf_equal(&buf_node_old, &buf_node_new)) {
            LOGD("$$$ change node_announcement\n");
            (void)ln_db_annonod_save(&buf_node_new, &msg, NULL); //XXX:
        }
    } else {
        LOGD("new\n");
        if (!ln_db_annonod_save(&buf_node_new, &msg, NULL)) goto LABEL_EXIT;
    }

    LOGD("my node_id: ");
    DUMPD(mNode.keys.pub, BTC_SZ_PUBKEY);
    print_node();

    ret = true;

LABEL_EXIT:
    utl_buf_free(&buf_node_old);
    utl_buf_free(&buf_node_new);
    utl_buf_free(&buf_addrs);
    return ret;
}


void ln_node_term(void)
{
    memset(&mNode, 0, sizeof(ln_node_t));
}


bool ln_node_search_channel(ln_channel_t *pChannel, const uint8_t *pNodeId)
{
    LOGD("search id:");
    DUMPD(pNodeId, BTC_SZ_PUBKEY);

    comp_param_cnl_t prm;

    prm.p_node_id = pNodeId;
    prm.p_channel = pChannel;
    bool detect = ln_db_channel_search_readonly(comp_func_cnl, &prm);

    LOGD("  --> detect=%d\n", detect);

    return detect;
}


bool ln_node_search_nodeanno(ln_msg_node_announcement_t *pNodeAnno, utl_buf_t *pNodeAnnoBuf, const uint8_t *pNodeId)
{
    if (!ln_db_annonod_load(pNodeAnnoBuf, NULL, pNodeId)) return false;
    if (!ln_msg_node_announcement_read(pNodeAnno, pNodeAnnoBuf->buf, pNodeAnnoBuf->len)) {
        LOGE("fail: read node_announcement\n");
        utl_buf_free(pNodeAnnoBuf);
        return false;
    }
    return true;
}


uint64_t ln_node_total_msat(void)
{
    uint64_t amount = 0;
    ln_db_channel_search_readonly(comp_func_total_msat, &amount);
    return amount;
}


bool ln_node_addr_dec(ln_node_conn_t *pNodeConn, const char *pConnStr)
{
    // <pubkey>@<ipaddr>:<port>
    // (33 * 2)@x.x.x.x:x
    char node_id_str[BTC_SZ_PUBKEY * 2 + 1] = "";
    int port = -1;
    int results = sscanf(pConnStr, "%66s@%15[^:]:%d", node_id_str, pNodeConn->addr, &port);
    if ( (results != 3) ||
         (strlen(node_id_str) != BTC_SZ_PUBKEY * 2) ||
         (strlen(pNodeConn->addr) < 7) ||
         (port <= 0) || (0x10000 <= port) ) {
        LOGE("fail: invalid string(%s)\n", pConnStr);
        return false;
    }
    uint8_t baddr[4];
    if (!utl_addr_ipv4_str2bin(baddr, pNodeConn->addr)) {
        LOGE("fail\n");
        return false;
    }
    // if (!utl_net_ipv4_addr_is_routable(baddr)) {
    //     LOGE("fail\n");
    //     return false;
    // }
    if (!utl_str_str2bin(pNodeConn->node_id, BTC_SZ_PUBKEY, node_id_str)) {
        LOGE("fail\n");
        return false;
    }
    if (!btc_keys_check_pub(pNodeConn->node_id)) {
        LOGE("fail\n");
        return false;
    }
    pNodeConn->port = (uint16_t)port;
    return true;
}


/********************************************************************
 * HIDDEN
 ********************************************************************/

void HIDDEN ln_node_create_key(char *pWif, uint8_t *pPubKey)
{
    btc_keys_t keys;
    btc_keys_create(&keys);
    memcpy(pPubKey, keys.pub, BTC_SZ_PUBKEY);
    btc_keys_priv2wif(pWif, keys.priv);
}


bool HIDDEN ln_node_generate_shared_secret(uint8_t *pResult, const uint8_t *pPubKey)
{
    return btc_ecc_shared_secret_sha256(pResult, pPubKey, mNode.keys.priv);
}


bool HIDDEN ln_node_sign_nodekey(uint8_t *pRS, const uint8_t *pHash)
{
    return btc_sig_sign_rs(pRS, pHash, mNode.keys.priv);
}


bool HIDDEN ln_node_search_node_id(uint8_t *pNodeId, uint64_t ShortChannelId)
{
    comp_param_srcnodeid_t param;
    param.p_node_id = pNodeId;
    param.short_channel_id = ShortChannelId;
    bool ret = ln_db_channel_search_readonly(comp_func_srch_nodeid, &param);
    LOGD("ret=%d\n", ret);
    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** #ln_node_search_channel()処理関数
 *
 * @param[in,out]   pChannel        channel from DB
 * @param[in,out]   p_db_param      DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         comp_param_cnl_t構造体
 */
static bool comp_func_cnl(ln_channel_t *pChannel, void *p_db_param, void *p_param)
{
    (void)p_db_param;
    comp_param_cnl_t *p = (comp_param_cnl_t *)p_param;

    bool ret = (memcmp(pChannel->peer_node_id, p->p_node_id, BTC_SZ_PUBKEY) == 0);
    if (ret) {
        if (p->p_channel) {
            //DBから復元(pChannelからshallow copyするので、pChannelは解放しない)
            LOGD("recover pChannel from DB...\n");
            ln_db_copy_channel(p->p_channel, pChannel);

            if (p->p_channel->short_channel_id != 0) {
                utl_buf_t buf = UTL_BUF_INIT;

                bool bret2 = ln_db_annocnl_load(&p->p_channel->cnl_anno, p->p_channel->short_channel_id);
                if (bret2) {
                    utl_buf_alloccopy(&p->p_channel->cnl_anno, buf.buf, buf.len);
                }
                utl_buf_free(&buf);
            }
            ln_print_keys(p->p_channel);
        } else {
            //true時は呼び元では解放しないので、ここで解放する
            ln_term(pChannel);
        }
    }
    return ret;
}


/** #ln_node_total_msat()処理関数
 *
 * our_msatの総額を求める。
 *
 * @param[in,out]   pChannel        channel from DB
 * @param[in,out]   p_db_param      DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         uint64_t
 */
static bool comp_func_total_msat(ln_channel_t *pChannel, void *p_db_param, void *p_param)
{
    (void)p_db_param;
    uint64_t *p_amount = (uint64_t *)p_param;

    //LOGD("our_msat:%" PRIu64 "\n", ln_our_msat(pChannel));
    *p_amount += ln_our_msat(pChannel);
    return false;
}


/** #ln_node_search_node_id()処理関数
 *
 * short_channel_idが一致した場合のnode_id(相手側)を返す。
 *
 * @param[in,out]   pChannel        channel from DB
 * @param[in,out]   p_db_param      DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         comp_param_srcnodeid_t
 */
static bool comp_func_srch_nodeid(ln_channel_t *pChannel, void *p_db_param, void *p_param)
{
    (void)p_db_param;

    comp_param_srcnodeid_t *p_srch = (comp_param_srcnodeid_t *)p_param;
    bool ret = (ln_short_channel_id(pChannel) == p_srch->short_channel_id);
    if (ret) {
        memcpy(p_srch->p_node_id, ln_their_node_id(pChannel), BTC_SZ_PUBKEY);
        ln_term(pChannel);
    }
    return ret;
}


#if 0
/** ln_node_addr_t比較
 *
 * @param[in]   pAddr1      比較対象1
 * @param[in]   pAddr2      比較対象2
 * @retval  true    一致
 */
static bool comp_node_addr(const ln_node_addr_t *pAddr1, const ln_node_addr_t *pAddr2)
{
    const size_t SZ[] = {
        0,          //LN_ADDR_DESC_TYPE_NONE
        4,          //LN_ADDR_DESC_TYPE_IPV4
        16,         //LN_ADDR_DESC_TYPE_IPV6
        10,         //LN_ADDR_DESC_TYPE_TORV2
        35          //LN_ADDR_DESC_TYPE_TORV3
    };

    if (pAddr1->type != pAddr2->type) {
        LOGE("not match: type %d != %d\n", pAddr1->type, pAddr2->type);
        return false;
    }
    if (pAddr1->type <= LN_ADDR_DESC_TYPE_TORV3) {
        if (memcmp(pAddr1->addrinfo.addr, pAddr2->addrinfo.addr, SZ[pAddr1->type]) != 0) {
            LOGE("not match: addr\n");
            return false;
        }
    } else {
        LOGE("invalid: type\n");
        return false;
    }
    return true;
}
#endif


static void print_node(void)
{
    printf("=NODE=============================================\n");
    // printf("node_key: ");
    // utl_dbg_dump(stdout, mNode.keys.priv, BTC_SZ_PRIVKEY, true);
    printf("node_id: ");
    utl_dbg_dump(stdout, mNode.keys.pub, BTC_SZ_PUBKEY, true);
    printf("features= %02x\n", mNode.features);
    printf("alias= %s\n", mNode.alias);
    printf("addr.type=%d\n", mNode.addr.type);
    if (mNode.addr.type == LN_ADDR_DESC_TYPE_IPV4) {
        printf("ipv4=%d.%d.%d.%d:%d\n",
                mNode.addr.addr[0],
                mNode.addr.addr[1],
                mNode.addr.addr[2],
                mNode.addr.addr[3],
                mNode.addr.port);
    } else {
        printf("port=%d\n", mNode.addr.port);
    }
    printf("=============================================\n");
}


#ifdef UNITTEST
void ln_node_setkey(const uint8_t *pPrivKey)
{
    memcpy(mNode.keys.priv, pPrivKey, BTC_SZ_PRIVKEY);
    btc_keys_priv2pub(mNode.keys.pub, mNode.keys.priv);
}
#endif  //UNITTEST
