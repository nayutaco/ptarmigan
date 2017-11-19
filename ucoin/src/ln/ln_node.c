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


bool ln_node_search_channel_id(ln_self_t *pSelf, const uint8_t *pNodeId)
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
            ln_db_copy_channel(p->p_self, self);
        } else {
            //true時は予備元では解放しないので、ここで解放する
            ln_term(self);
        }
    }
    return ret;
}
