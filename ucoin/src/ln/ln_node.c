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
#include <assert.h>

#include "ln/ln_misc.h"
#include "ln/ln_msg_anno.h"
#include "ln/ln_node.h"


/**************************************************************************
 * macros
 **************************************************************************/

//TODO:暫定
//#define M_DFL_EXPIRY                            (90)


/**************************************************************************
 * prototypes
 **************************************************************************/

static int add_cnl(ln_node_t *node, uint64_t short_channel_id, int8_t node1, int8_t node2);


/**************************************************************************
 * public functions
 **************************************************************************/

void ln_node_init(ln_node_t *node, const char *pWif, const char *pNodeName, uint8_t Features)
{
    bool ret = ucoin_util_wif2keys(&node->keys, pWif);
    assert(ret);
    if (!ret) {
        return;
    }
    strcpy(node->alias, pNodeName);
    node->features = Features;

    node->node_num = 0;
    for (int lp = 0; lp < LN_NODE_MAX; lp++) {
        memset(node->node_info[lp].node_id, 0, UCOIN_SZ_PUBKEY);
        node->node_info[lp].alias[0] = '\0';
        node->node_info[lp].timestamp = 0;
        node->node_info[lp].sort = UCOIN_KEYS_SORT_OTHER;
    }

    node->channel_num = 0;
    for (int lp = 0; lp < LN_CHANNEL_MAX; lp++) {
        node->channel_info[lp].node1 = NODE_MYSELF;
        node->channel_info[lp].node2 = NODE_MYSELF;
        node->channel_info[lp].short_channel_id = 0;
    }
}


void ln_node_term(ln_node_t *node)
{
    node->node_num = 0;
    node->channel_num = 0;
}


uint64_t ln_node_search_short_cnl_id(ln_node_t *node, const uint8_t *p_node_id)
{
    uint64_t short_channel_id = 0;

    uint8_t idx = ln_node_search_nodeid(node, p_node_id);
    if (idx != LN_NODE_MAX) {
        short_channel_id = ln_node_search_idx(node, idx);
    }

    return short_channel_id;
}


#ifdef UCOIN_USE_PRINTFUNC
void ln_print_node(const ln_node_t *node)
{
    printf("=NODE=======================================================================\n");
    printf("   keyv: ");
    ucoin_util_dumpbin(PRINTOUT, node->keys.priv, UCOIN_SZ_PRIVKEY);
    printf("   keyp: ");
    ucoin_util_dumpbin(PRINTOUT, node->keys.pub, UCOIN_SZ_PUBKEY);
    printf("features= %02x\n", node->features);
    printf("alias= %s\n", node->alias);
    printf("node_num= %d\n", node->node_num);
    for (int lp = 0; lp < LN_NODE_MAX; lp++) {
        printf("node[%d]:\n", lp);
        printf("   node_id: ");
        ucoin_util_dumpbin(PRINTOUT, node->node_info[lp].node_id, UCOIN_SZ_PUBKEY);
        printf("   alias= %s\n", node->node_info[lp].alias);
        printf("   sort= %s\n\n", (node->node_info[lp].sort == UCOIN_KEYS_SORT_ASC) ? "asc" : "other");
    }
    printf("channel_num= %d\n", node->channel_num);
    for (int lp = 0; lp < LN_CHANNEL_MAX; lp++) {
        printf("  node1=%d\n", node->channel_info[lp].node1);
        printf("  node2=%d\n", node->channel_info[lp].node2);
        printf("  short_channel_id= %" PRIx64 "\n\n", node->channel_info[lp].short_channel_id);
    }
    printf("========================================================================\n\n\n");
}
#endif


/********************************************************************
 * HIDDEN
 ********************************************************************/

bool HIDDEN ln_node_recv_channel_announcement(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("\n");
    return true;
}


bool HIDDEN ln_node_recv_node_announcement(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    ln_node_announce_t ann;
    uint8_t node_pub[UCOIN_SZ_PUBKEY];
    char node_alias[LN_SZ_ALIAS + 1];

    //通知されたノード情報を、追加 or 更新する
    ann.p_node_id = node_pub;
    ann.p_alias = node_alias;
    ret = ln_msg_node_announce_read(&ann, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }
    int idx = ln_node_update_node_anno(self->p_node, &ann);
    if ((idx != NODE_NOT_FOUND) && (idx != NODE_NO_UPDATE)) {
        self->node_idx = idx;

        //node_announcement受信通知
        ln_cb_node_anno_recv_t param;
        param.p_node_id = self->p_node->node_info[idx].node_id;
        param.short_channel_id = ln_node_search_idx(self->p_node, idx);
        (*self->p_callback)(self, LN_CB_NODE_ANNO_RECV, &param);
    }

    return idx != NODE_NOT_FOUND;       //上限で保持できない場合はfalseにしておくが、意味は無い
}


bool HIDDEN ln_node_recv_channel_update(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("\n");
    DBG_PRINTF2("short_channel_id= %" PRIx64 "\n", self->short_channel_id);
    return true;
}


bool HIDDEN ln_node_recv_announcement_signatures(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    ln_announce_signs_t anno_signs;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;
    ln_node_t *node = self->p_node;

    DBG_PRINTF("node=%p\n", node);

    //announcement_signaturesを受信したときの状態として、以下が考えられる。
    //      - 相手から初めて受け取り、まだ自分からは送信していない
    //      - 自分から送信していて、相手から初めて受け取った
    //      - 持っているけど、また受け取った
    //
    //  また、announcement_signatures はチャネル間メッセージだが、
    //  channel_announcment はノードとして管理する情報になる。
    //  ここら辺が紛らわしくなってくる理由だろう。

    //short_channel_idで検索
    uint64_t short_channel_id = ln_msg_announce_signs_read_short_cnl_id(pData, Len, self->channel_id);
    if (short_channel_id == 0) {
        DBG_PRINTF("fail: invalid packet\n");
        return false;
    }
    if (short_channel_id != self->short_channel_id) {
        DBG_PRINTF("fail: short_channel_id mismatch\n");
        return false;
    }
    bool b_add;
    int idx = ln_node_search_add_cnl(node, &b_add, short_channel_id, self->node_idx, NODE_MYSELF);
    if (idx == CHANNEL_NOT_FOUND) {
        DBG_PRINTF("fail: channel search\n");
        return false;
    }

    ucoin_buf_free(&self->cnl_anno);

    ln_cnl_announce_t anno;
    anno.short_channel_id = short_channel_id;
    anno.p_my_node = &node->keys;
    anno.p_my_funding = &self->funding_local.keys[MSG_FUNDIDX_FUNDING];
    anno.p_peer_node_pub = node->node_info[self->node_idx].node_id;
    anno.p_peer_funding_pub = self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING];
    anno.sort = node->node_info[self->node_idx].sort;
    ret = ln_msg_cnl_announce_create(&self->cnl_anno,
            (uint8_t **)&p_sig_node, (uint8_t **)&p_sig_btc, &anno);
    if (!ret) {
        DBG_PRINTF("fail: ln_msg_cnl_announce_create\n");
        return false;
    }

    //TODO: メッセージ構成に深入りしすぎてよくないが、暫定でこうする
    if (node->node_info[self->node_idx].sort == UCOIN_KEYS_SORT_ASC) {
        p_sig_node = self->cnl_anno.buf + sizeof(uint16_t) + LN_SZ_SIGNATURE;
    } else {
        p_sig_node = self->cnl_anno.buf + sizeof(uint16_t);
    }
    p_sig_btc = p_sig_node + LN_SZ_SIGNATURE * 2;

    anno_signs.p_channel_id = channel_id;
    anno_signs.p_node_signature = p_sig_node;
    anno_signs.p_btc_signature = p_sig_btc;
    ret = ln_msg_announce_signs_read(&anno_signs, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
        return false;
    }

    //announcement_signatures受信通知
    (*self->p_callback)(self, LN_CB_ANNO_SIGNS_RECV, NULL);

#warning デバッグ表示
    DBG_PRINTF("+++ ln_msg_cnl_announce_print[%" PRIx64 "] +++\n", self->short_channel_id);
    ln_msg_cnl_announce_print(self->cnl_anno.buf, self->cnl_anno.len);
    ln_cnl_announce_t ca;
    ret = ln_msg_cnl_announce_read(&ca, self->cnl_anno.buf, self->cnl_anno.len);
    DBG_PRINTF("+++ ln_msg_cnl_announce_read() : %d\n", ret);
    if (ret) {
        DBG_PRINTF2("short_channel_id = %" PRIx64 "\n", ca.short_channel_id);
    }

    return true;
}


int HIDDEN ln_node_update_node_anno(ln_node_t *node, const ln_node_announce_t *pAnno)
{
    bool update = false;
    int idx;

    for (idx = 0; idx < node->node_num; idx++) {
        if (memcmp(node->node_info[idx].node_id, pAnno->p_node_id, UCOIN_SZ_PUBKEY) == 0) {
            if (node->node_info[idx].timestamp < pAnno->timestamp) {
                //更新可能
                update = true;
            } else {
                //更新不要
                idx = NODE_NO_UPDATE;
            }
            break;
        }
    }
    if (!update && (idx == NODE_NO_UPDATE)) {
        DBG_PRINTF("update unnecessary\n");
        return NODE_NO_UPDATE;
    }

    if (!update) {
        if (node->node_num >= LN_NODE_MAX - 1) {
            //ノード数が上限で記憶できない
            DBG_PRINTF("fail: node maximum\n");
            return NODE_NOT_FOUND;
        }
        idx = node->node_num;
        node->node_num++;
    }

    memcpy(node->node_info[idx].node_id, pAnno->p_node_id, UCOIN_SZ_PUBKEY);
    strcpy(node->node_info[idx].alias, pAnno->p_alias);
    node->node_info[idx].timestamp = pAnno->timestamp;
    int cmp = memcmp(node->keys.pub, node->node_info[idx].node_id, UCOIN_SZ_PUBKEY);
    if (cmp < 0) {
        //自ノードが先
        node->node_info[idx].sort = UCOIN_KEYS_SORT_ASC;
    } else {
        node->node_info[idx].sort = UCOIN_KEYS_SORT_OTHER;
    }

    return idx;
}


int HIDDEN ln_node_search_add_cnl(ln_node_t *node, bool *pAdd, uint64_t short_channel_id, int8_t node1, int8_t node2)
{
    int idx;
    for (idx = 0; idx < node->channel_num; idx++) {
        if (node->channel_info[idx].short_channel_id == short_channel_id) {
            break;
        }
    }
    if (idx == node->channel_num) {
        //追加
        if (idx >= LN_CHANNEL_MAX - 1) {
            //ノード数が上限で記憶できない
            DBG_PRINTF("fail: channel maximum\n");
            return CHANNEL_NOT_FOUND;
        }
        if (node1 > node2) {
            //検索しやすいように昇順にしておく
            int8_t tmp = node1;
            node1 = node2;
            node2 = tmp;
        }
        idx = add_cnl(node, short_channel_id, node1, node2);
        *pAdd = true;
    } else {
        *pAdd = false;
    }

    return idx;
}


uint8_t HIDDEN ln_node_search_nodeid(ln_node_t *node, const uint8_t *pNodeId)
{
    DBG_PRINTF("search id:");
    DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);

    uint8_t lp;
    for (lp = 0; lp < LN_NODE_MAX; lp++) {
        if (memcmp(node->node_info[lp].node_id, pNodeId, UCOIN_SZ_PUBKEY) == 0) {
            DBG_PRINTF("node found\n");
            break;
        }
    }

    return lp;
}


uint64_t HIDDEN ln_node_search_idx(ln_node_t *node, int8_t node_idx)
{
    const ln_channel_info_t *cinfo = node->channel_info;

    for (int lp = 0; lp < LN_CHANNEL_MAX; lp++) {
        if ((cinfo[lp].node1 == NODE_MYSELF) && (cinfo[lp].node2 == node_idx)) {
            DBG_PRINTF("short_channel_id found: %" PRIx64 "\n", cinfo[lp].short_channel_id);
            return cinfo[lp].short_channel_id;
        }
    }

    return 0;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static int add_cnl(ln_node_t *node, uint64_t short_channel_id, int8_t node1, int8_t node2)
{
    int idx = node->channel_num;
    node->channel_info[idx].node1 = node1;
    node->channel_info[idx].node2 = node2;
    node->channel_info[idx].short_channel_id = short_channel_id;
    node->channel_num++;

    return idx;
}
