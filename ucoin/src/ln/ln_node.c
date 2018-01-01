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
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "ln_db.h"
#include "ln/ln_misc.h"
#include "ln/ln_msg_anno.h"
#include "ln/ln_node.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    const uint8_t *p_node_id;
    ln_self_t *p_self;
} comp_param_cnl_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool comp_func_cnl(ln_self_t *self, void *p_db_param, void *p_param);
static void copy_channel(ln_self_t *pOutSelf, const ln_self_t *pInSelf);


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_node_init(ln_node_t *node, const char *pWif, const char *pNodeName, uint8_t Features)
{
    ucoin_buf_t buf_node;
    ucoin_buf_init(&buf_node);

    bool ret = ucoin_util_wif2keys(&node->keys, pWif);
    assert(ret);
    if (!ret) {
        goto LABEL_EXIT;
    }
    strcpy(node->alias, pNodeName);
    node->features = Features;

    ln_db_init(ln_node_id(node));

    ret = ln_db_load_anno_node(&buf_node, NULL, NULL, ln_node_id(node));
    if (!ret) {
        //自buf_nodeuncement無し
        ln_node_announce_t anno;

        anno.timestamp = (uint32_t)time(NULL);
        anno.p_my_node = &node->keys;
        anno.p_alias = node->alias;
        anno.rgbcolor[0] = 0;
        anno.rgbcolor[1] = 0;
        anno.rgbcolor[2] = 0;
        memcpy(&anno.addr, &node->addr, sizeof(ln_nodeaddr_t));
        ret = ln_msg_node_announce_create(&buf_node, &anno);
        if (!ret) {
            goto LABEL_EXIT;
        }
        ret = ln_db_save_anno_node(&buf_node, ln_node_id(node), ln_node_id(node));
    }

LABEL_EXIT:
    ucoin_buf_free(&buf_node);
    assert(ret);
    return ret;
}


void ln_node_term(ln_node_t *node)
{
    memset(node, 0, sizeof(ln_node_t));
}


bool ln_node_search_channel(ln_self_t *pSelf, const uint8_t *pNodeId)
{
    comp_param_cnl_t prm;

    prm.p_node_id = pNodeId;
    prm.p_self = pSelf;
    bool detect = ln_db_search_channel(comp_func_cnl, &prm);

    DBG_PRINTF("search id:");
    DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);
    DBG_PRINTF("  --> detect=%d\n", detect);

    return detect;
}


/********************************************************************
 * HIDDEN
 ********************************************************************/

bool HIDDEN ln_node_recv_node_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("\n");

    bool ret;
    ln_node_announce_t ann;
    uint8_t node_pub[UCOIN_SZ_PUBKEY];
    char node_alias[LN_SZ_ALIAS + 1];
    ucoin_buf_t buf_old;

    //通知されたノード情報を、追加 or 更新する
    ann.p_node_id = node_pub;
    ann.p_alias = node_alias;
    ret = ln_msg_node_announce_read(&ann, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    DBG_PRINTF("node_id:");
    DUMPBIN(node_pub, sizeof(node_pub));
    ucoin_buf_init(&buf_old);
    ret = ln_db_load_anno_node(&buf_old, NULL, NULL, node_pub);
    bool update = false;
    if (ret) {
        //保存データあり
        ln_node_announce_t ann_old;
        uint8_t node_pub_old[UCOIN_SZ_PUBKEY];
        char node_alias_old[LN_SZ_ALIAS + 1];

        ann_old.p_node_id = node_pub_old;
        ann_old.p_alias = node_alias_old;
        ret = ln_msg_node_announce_read(&ann_old, buf_old.buf, buf_old.len);
        if (ret) {
            if (ann.timestamp > ann_old.timestamp) {
                DBG_PRINTF("更新\n");
                update = true;
            } else if (ann.timestamp == ann_old.timestamp) {
                DBG_PRINTF("更新不要\n");
            } else {
                DBG_PRINTF("古いデータ\n");
            }
        } else {
            DBG_PRINTF("fail: read message\n");
        }
    } else {
        update = true;
    }
    if (update) {
        //新規 or 更新
        DBG_PRINTF("保存\n");
        ucoin_buf_t buf_ann;
        buf_ann.buf = (CONST_CAST uint8_t *)pData;
        buf_ann.len = Len;
        ret = ln_db_save_anno_node(&buf_ann, ln_their_node_id(self), node_pub);

        if (ret) {
            (*self->p_callback)(self, LN_CB_NODE_ANNO_RECV, &ann);
        }
    }
    ucoin_buf_free(&buf_old);

    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static bool comp_func_cnl(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_db_param;
    comp_param_cnl_t *p = (comp_param_cnl_t *)p_param;

    bool ret = (memcmp(self->peer_node.node_id, p->p_node_id, UCOIN_SZ_PUBKEY) == 0);
    if (ret) {
        if (p->p_self) {
            copy_channel(p->p_self, self);
            ln_misc_update_scriptkeys(&p->p_self->funding_local, &p->p_self->funding_remote);
        } else {
            //true時は予備元では解放しないので、ここで解放する
            ln_term(self);
        }
    }
    return ret;
}


static void copy_channel(ln_self_t *pOutSelf, const ln_self_t *pInSelf)
{
    pOutSelf->lfeature_remote = pInSelf->lfeature_remote;     //3
    pOutSelf->storage_index = pInSelf->storage_index;     //5
    memcpy(pOutSelf->storage_seed, pInSelf->storage_seed, UCOIN_SZ_PRIVKEY);      //6

    pOutSelf->funding_local = pInSelf->funding_local;     //7
    pOutSelf->funding_remote = pInSelf->funding_remote;       //8

    pOutSelf->obscured = pInSelf->obscured;       //9
    pOutSelf->key_fund_sort = pInSelf->key_fund_sort;     //10
    pOutSelf->htlc_num = pInSelf->htlc_num;       //11
    pOutSelf->commit_num = pInSelf->commit_num;       //12
    pOutSelf->htlc_id_num = pInSelf->htlc_id_num;     //13
    pOutSelf->our_msat = pInSelf->our_msat;       //14
    pOutSelf->their_msat = pInSelf->their_msat;       //15
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        pOutSelf->cnl_add_htlc[idx] = pInSelf->cnl_add_htlc[idx];       //16
        pOutSelf->cnl_add_htlc[idx].p_channel_id = NULL;     //送受信前に決定する
        pOutSelf->cnl_add_htlc[idx].p_onion_route = NULL;
        //shared secretは別DB
        ucoin_buf_init(&pOutSelf->cnl_add_htlc[idx].shared_secret);
    }
    memcpy(pOutSelf->channel_id, pInSelf->channel_id, LN_SZ_CHANNEL_ID);      //17
    pOutSelf->short_channel_id = pInSelf->short_channel_id;       //18
    pOutSelf->commit_local = pInSelf->commit_local;       //19
    pOutSelf->commit_remote = pInSelf->commit_remote;     //20
    pOutSelf->funding_sat = pInSelf->funding_sat;     //21
    pOutSelf->feerate_per_kw = pInSelf->feerate_per_kw;       //22
    pOutSelf->peer_storage = pInSelf->peer_storage;     //23
    pOutSelf->peer_storage_index = pInSelf->peer_storage_index;     //24
    pOutSelf->remote_commit_num = pInSelf->remote_commit_num;  //25
    pOutSelf->revoke_num = pInSelf->revoke_num;  //26
    pOutSelf->remote_revoke_num = pInSelf->remote_revoke_num;  //27
    pOutSelf->fund_flag = pInSelf->fund_flag;  //28
    memcpy(&pOutSelf->peer_node, &pInSelf->peer_node, sizeof(ln_node_info_t));   //29
    pOutSelf->min_depth = pInSelf->min_depth;  //30

    //スクリプト部分(shallow copy)

    //cnl_anno
    ucoin_buf_free(&pOutSelf->cnl_anno);
    memcpy(&pOutSelf->cnl_anno, &pInSelf->cnl_anno, sizeof(ucoin_buf_t));

    //redeem_fund
    ucoin_buf_free(&pOutSelf->redeem_fund);
    memcpy(&pOutSelf->redeem_fund, &pInSelf->redeem_fund, sizeof(ucoin_buf_t));

    //shutdown_scriptpk_local
    ucoin_buf_free(&pOutSelf->shutdown_scriptpk_local);
    memcpy(&pOutSelf->shutdown_scriptpk_local, &pInSelf->shutdown_scriptpk_local, sizeof(ucoin_buf_t));

    //shutdown_scriptpk_remote
    ucoin_buf_free(&pOutSelf->shutdown_scriptpk_remote);
    memcpy(&pOutSelf->shutdown_scriptpk_remote, &pInSelf->shutdown_scriptpk_remote, sizeof(ucoin_buf_t));

    //tx_funding
    ucoin_tx_free(&pOutSelf->tx_funding);
    memcpy(&pOutSelf->tx_funding, &pInSelf->tx_funding, sizeof(ucoin_tx_t));
}
