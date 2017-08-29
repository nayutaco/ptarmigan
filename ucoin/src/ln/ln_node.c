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
 * prototypes
 **************************************************************************/

static bool get_nodeid(uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir);


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

    ln_db_init();

    ret = ln_db_load_anno_node(&buf_node, NULL, NULL, ln_node_id(node));
    if (!ret) {
        //自buf_nodeuncement無し
        ln_node_announce_t anno;

        anno.timestamp = (uint32_t)time(NULL);
        anno.p_my_node = &node->keys;
        anno.p_alias = node->alias;
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


uint64_t ln_node_search_short_cnl_id(const uint8_t *pNodeId1, const uint8_t *pNodeId2)
{
    const uint8_t *p_node_id1;
    const uint8_t *p_node_id2;

    int lp;
    for (lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        if (pNodeId1[lp] != pNodeId2[lp]) {
            break;
        }
    }
    if (pNodeId1[lp] < pNodeId2[lp]) {
        p_node_id1 = pNodeId1;
        p_node_id2 = pNodeId2;
    } else {
        p_node_id1 = pNodeId2;
        p_node_id2 = pNodeId1;
    }
    uint64_t short_channel_id = ln_db_search_channel_short_channel_id(p_node_id1, p_node_id2);

    DBG_PRINTF("search id1:");
    DUMPBIN(p_node_id1, UCOIN_SZ_PUBKEY);
    DBG_PRINTF("       id2:");
    DUMPBIN(p_node_id2, UCOIN_SZ_PUBKEY);
    DBG_PRINTF("  --> %016" PRIx64 "\n", short_channel_id);

    return short_channel_id;
}


#ifdef UCOIN_USE_PRINTFUNC
void ln_print_node(const ln_node_t *node)
{
    printf("=NODE=============================================\n");
    printf("   keyv: ");
    ucoin_util_dumpbin(PRINTOUT, node->keys.priv, UCOIN_SZ_PRIVKEY);
    printf("   keyp: ");
    ucoin_util_dumpbin(PRINTOUT, node->keys.pub, UCOIN_SZ_PUBKEY);
    printf("features= %02x\n", node->features);
    printf("alias= %s\n", node->alias);
    printf("=============================================\n\n\n");
}
#endif


/********************************************************************
 * HIDDEN
 ********************************************************************/

bool HIDDEN ln_node_recv_channel_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("\n");

    ln_cnl_announce_read_t ann;

    bool ret = ln_msg_cnl_announce_read(&ann, pData, Len);
    if (ret) {
        ln_cb_channel_anno_recv_t param;

        param.short_channel_id = ann.short_channel_id;
        (*self->p_callback)(self, LN_CB_CHANNEL_ANNO_RECV, &param);
    } else {
        DBG_PRINTF("err\n");
    }

    ucoin_buf_t buf;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;

    //DB読込み
    ucoin_buf_t buf_bolt;
    ret = ln_db_load_anno_channel(&buf_bolt, ann.short_channel_id);
    if (ret) {
        // BOLT#7
        //  https://github.com/nayuta-ueno/lightning-rfc/blob/master/07-routing-gossip.md#requirements-1
        //
        // If it has previously received a valid channel_announcement
        // for the same transaction in the same block, but different node_id_1 or node_id_2,
        // it SHOULD blacklist the previous message's node_id_1 and node_id_2 as well as
        // this node_id_1 and node_id_2 and forget channels connected to them,
        // otherwise it SHOULD store this channel_announcement.
        if (ucoin_buf_cmp(&buf_bolt, &buf)) {
            DBG_PRINTF("同じものが送られてきたので、スルー\n");
        } else {
            DBG_PRINTF("不一致のためblacklist入りする予定\n");
            assert(0);
        }
    }

    //DB保存
    ret = ln_db_save_anno_channel(&buf, ann.short_channel_id, ln_their_node_id(self));
    assert(ret);

    return ret;
}


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
    }
    ucoin_buf_free(&buf_old);

    return ret;
}


bool HIDDEN ln_node_recv_channel_update(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("\n");

    ln_cnl_update_t upd;

    //verify
    upd.p_key = self->peer_node.node_id;
    bool ret = ln_msg_cnl_update_read(&upd, pData, Len);
    DBG_PRINTF("ret=%d\n", ret);

    if (ret) {
        //short_channel_id と dir から node_id を取得する
        uint8_t node_id[UCOIN_SZ_PUBKEY];

        ret = get_nodeid(node_id, upd.short_channel_id, upd.flags & 0x0001);
        if (ret && ucoin_keys_chkpub(node_id)) {
            ret = ln_msg_cnl_update_verify(node_id, pData, Len);
        } else {
            DBG_PRINTF("err\n");
        }
    }

    if (ret) {
        //DB保存
        ucoin_buf_t buf;
        buf.buf = (CONST_CAST uint8_t *)pData;
        buf.len = Len;
        ret = ln_db_save_anno_channel_upd(&buf, upd.short_channel_id, upd.flags & 0x0001);
        assert(ret);
    } else {
        DBG_PRINTF("err\n");
    }

    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

//node_id取得
static bool get_nodeid(uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir)
{
    bool ret;

    pNodeId[0] = 0x00;

    ucoin_buf_t buf_cnl_anno;
    ucoin_buf_init(&buf_cnl_anno);
    ret = ln_db_load_anno_channel(&buf_cnl_anno, short_channel_id);
    if (ret) {
        ln_cnl_announce_read_t ann;

        ret = ln_msg_cnl_announce_read(&ann, buf_cnl_anno.buf, buf_cnl_anno.len);
        DBG_PRINTF("ret=%d\n", ret);
        if (ret) {
            const uint8_t *p_node_id;
            if (Dir == 0) {
                p_node_id = ann.node_id1;
            } else {
                p_node_id = ann.node_id2;
            }
            memcpy(pNodeId, p_node_id, UCOIN_SZ_PUBKEY);
        } else {
            DBG_PRINTF("ret=%d\n", ret);
        }
    } else {
        DBG_PRINTF("ret=%d\n", ret);
    }
    ucoin_buf_free(&buf_cnl_anno);

    return ret;
}
