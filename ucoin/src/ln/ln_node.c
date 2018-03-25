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
 * private variables
 **************************************************************************/

static ln_node_t    mNode;


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool comp_func_cnl(ln_self_t *self, void *p_db_param, void *p_param);
static bool comp_node_addr(const ln_nodeaddr_t *pAddr1, const ln_nodeaddr_t *pAddr2);
static void print_node(void);


/**************************************************************************
 * public functions
 **************************************************************************/

const uint8_t *ln_node_getid(void)
{
    return mNode.keys.pub;
}

ln_nodeaddr_t *ln_node_addr(void)
{
    return &mNode.addr;
}


char *ln_node_alias(void)
{
    return mNode.alias;
}


bool ln_node_init(uint8_t Features)
{
    bool ret;
    char wif[UCOIN_SZ_WIF_MAX];
    ucoin_chain_t chain;
    ucoin_buf_t buf_node;
    ucoin_buf_init(&buf_node);

    mNode.features = Features;

    ret = ln_db_init(wif, mNode.alias, &mNode.addr.port);
    if (ret) {
        //新規設定 or DBから読み込み
        ret = ucoin_util_wif2keys(&mNode.keys, &chain, wif);
        if (!ret) {
            goto LABEL_EXIT;
        }
    } else {
        DBG_PRINTF("fail: db init\n");
        goto LABEL_EXIT;
    }

    ln_node_announce_t anno;

    ret = ln_db_annonod_load(&buf_node, NULL, mNode.keys.pub);
    if (ret) {
        //ノード設定が変更されていないかチェック
        //  少なくともnode_idは変更されていない
        uint8_t node_id[UCOIN_SZ_PUBKEY];
        char node_alias[LN_SZ_ALIAS + 1];

        anno.p_node_id = node_id;
        anno.p_alias = node_alias;
        ret = ln_msg_node_announce_read(&anno, buf_node.buf, buf_node.len);
        if (ret) {
            if ( (memcmp(anno.p_node_id, mNode.keys.pub, UCOIN_SZ_PUBKEY) != 0) ||
                 (strcmp(anno.p_alias, mNode.alias) != 0) ||
                 (anno.rgbcolor[0] != 0) || (anno.rgbcolor[1] != 0) || (anno.rgbcolor[2] != 0) ||
                 (!comp_node_addr(&anno.addr, &mNode.addr) && (mNode.addr.type != LN_NODEDESC_NONE)) ) {
                //保持している情報と不一致(IPアドレスは引数で指定された場合のみチェック)
                DBG_PRINTF("fail: node info not match\n");
                ret = false;
                goto LABEL_EXIT;
            } else {
                DBG_PRINTF("same node.conf\n");
                uint16_t bak = mNode.addr.port; //node_announcementにはポート番号が載らないことがあり得る
                memcpy(&mNode.addr, &anno.addr, sizeof(anno.addr));
                mNode.addr.port = bak;
            }
        }
    } else {
        //自node_announcement無し
        DBG_PRINTF("new\n");

        anno.timestamp = (uint32_t)time(NULL);
        anno.p_node_id = mNode.keys.pub;
        anno.p_alias = mNode.alias;
        anno.rgbcolor[0] = 0;
        anno.rgbcolor[1] = 0;
        anno.rgbcolor[2] = 0;
        memcpy(&anno.addr, &mNode.addr, sizeof(ln_nodeaddr_t));
        ret = ln_msg_node_announce_create(&buf_node, &anno);
        if (!ret) {
            goto LABEL_EXIT;
        }
        ret = ln_db_annonod_save(&buf_node, &anno, NULL);
    }

    if (ret) {
        print_node();
    }

LABEL_EXIT:
    ucoin_buf_free(&buf_node);
    return ret;
}


void ln_node_term(void)
{
    memset(&mNode, 0, sizeof(ln_node_t));
}


bool ln_node_search_channel(ln_self_t *self, const uint8_t *pNodeId)
{
    comp_param_cnl_t prm;

    prm.p_node_id = pNodeId;
    prm.p_self = self;
    bool detect = ln_db_self_search(comp_func_cnl, &prm);

    DBG_PRINTF("search id:");
    DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);
    DBG_PRINTF("  --> detect=%d\n", detect);

    return detect;
}


bool ln_node_search_nodeanno(ln_node_announce_t *pNodeAnno, const uint8_t *pNodeId)
{
    ucoin_buf_t buf_anno;

    ucoin_buf_init(&buf_anno);
    bool ret = ln_db_annonod_load(&buf_anno, NULL, pNodeId);
    if (ret) {
        pNodeAnno->p_node_id = NULL;
        pNodeAnno->p_alias = NULL;
        ret = ln_msg_node_announce_read(pNodeAnno, buf_anno.buf, buf_anno.len);
        if (!ret) {
            DBG_PRINTF("fail: read node_announcement\n");
        }
    }
    ucoin_buf_free(&buf_anno);

    return ret;
}


/********************************************************************
 * HIDDEN
 ********************************************************************/

/** node_announcement受信処理
 *
 */
bool HIDDEN ln_node_recv_node_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //DBG_PRINTF("\n");

    bool ret;
    ln_node_announce_t anno;
    uint8_t node_id[UCOIN_SZ_PUBKEY];
    char node_alias[LN_SZ_ALIAS + 1];

    anno.p_node_id = node_id;
    anno.p_alias = node_alias;
    ret = ln_msg_node_announce_read(&anno, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //DBG_PRINTF("node_id:");
    //DUMPBIN(node_id, sizeof(node_id));

    ucoin_buf_t buf_ann;
    buf_ann.buf = (CONST_CAST uint8_t *)pData;
    buf_ann.len = Len;
    ret = ln_db_annonod_save(&buf_ann, &anno, ln_their_node_id(self));
    if (ret) {
        (*self->p_callback)(self, LN_CB_NODE_ANNO_RECV, &anno);
    }

    return true;
}


void HIDDEN ln_node_generate_shared_secret(uint8_t *pResult, const uint8_t *pPubKey)
{
    DBG_PRINTF("\n");

    uint8_t pub[UCOIN_SZ_PUBKEY];
    ucoin_util_mul_pubkey(pub, pPubKey, mNode.keys.priv, UCOIN_SZ_PRIVKEY);
    ucoin_util_sha256(pResult, pub, sizeof(pub));
}


bool HIDDEN ln_node_sign_nodekey(uint8_t *pRS, const uint8_t *pHash)
{
    return ucoin_tx_sign_rs(pRS, pHash, mNode.keys.priv);
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** #ln_node_search_channel()処理関数
 *
 * @param[in,out]   self            DBから取得したself
 * @param[in,out]   p_db_param      DB情報(ln_dbで使用する)
 * @param[in,out]   p_param         comp_param_cnl_t構造体
 */
static bool comp_func_cnl(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_db_param;
    comp_param_cnl_t *p = (comp_param_cnl_t *)p_param;

    bool ret = (memcmp(self->peer_node_id, p->p_node_id, UCOIN_SZ_PUBKEY) == 0);
    if (ret) {
        if (p->p_self) {
            //DBから復元
            ln_db_copy_channel(p->p_self, self);

            if (p->p_self->short_channel_id != 0) {
                ucoin_buf_t buf;

                ucoin_buf_init(&buf);
                bool bret2 = ln_db_annocnl_load(&p->p_self->cnl_anno, p->p_self->short_channel_id);
                if (bret2) {
                    ucoin_buf_alloccopy(&p->p_self->cnl_anno, buf.buf, buf.len);
                }
                ucoin_buf_free(&buf);
            }
        } else {
            //true時は呼び元では解放しないので、ここで解放する
            ln_term(self);
        }
    }
    return ret;
}


/** ln_nodeaddr_t比較
 *
 * @param[in]   pAddr1      比較対象1
 * @param[in]   pAddr2      比較対象2
 * @retval  true    一致
 */
static bool comp_node_addr(const ln_nodeaddr_t *pAddr1, const ln_nodeaddr_t *pAddr2)
{
    const size_t SZ[] = {
        0,          //LN_NODEDESC_NONE
        4,          //LN_NODEDESC_IPV4
        16,         //LN_NODEDESC_IPV6
        10,         //LN_NODEDESC_ONIONV2
        35          //LN_NODEDESC_ONIONV3
    };

    if (pAddr1->type != pAddr2->type) {
        DBG_PRINTF("not match: type\n");
        return false;
    }
    if ((pAddr1->type != LN_NODEDESC_NONE) && (pAddr1->port != pAddr2->port)) {
        DBG_PRINTF("not match: port, %d, %d\n", pAddr1->port, pAddr2->port);
        return false;
    }
    if (pAddr1->type <= LN_NODEDESC_ONIONV3) {
        if (memcmp(pAddr1->addrinfo.addr, pAddr2->addrinfo.addr, SZ[pAddr1->type]) != 0) {
            DBG_PRINTF("not match: addr\n");
            return false;
        }
    } else {
        DBG_PRINTF("invalid: type\n");
        return false;
    }
    return true;
}


static void print_node(void)
{
    printf("=NODE=============================================\n");
    // printf("node_key: ");
    // ucoin_util_dumpbin(PRINTOUT, mNode.keys.priv, UCOIN_SZ_PRIVKEY, true);
    printf("node_id: ");
    ucoin_util_dumpbin(PRINTOUT, mNode.keys.pub, UCOIN_SZ_PUBKEY, true);
    printf("features= %02x\n", mNode.features);
    printf("alias= %s\n", mNode.alias);
    printf("addr.type=%d\n", mNode.addr.type);
    if (mNode.addr.type == LN_NODEDESC_IPV4) {
        printf("ipv4=%d.%d.%d.%d:%d\n",
                mNode.addr.addrinfo.ipv4.addr[0],
                mNode.addr.addrinfo.ipv4.addr[1],
                mNode.addr.addrinfo.ipv4.addr[2],
                mNode.addr.addrinfo.ipv4.addr[3],
                mNode.addr.port);
    } else {
        printf("port=%d\n", mNode.addr.port);
    }
    printf("=============================================\n\n\n");
}


#ifdef UNITTEST
static void ln_node_setkey(const uint8_t *pPrivKey)
{
    memcpy(mNode.keys.priv, pPrivKey, UCOIN_SZ_PRIVKEY);
    ucoin_keys_priv2pub(mNode.keys.pub, mNode.keys.priv);
}
#endif  //UNITTEST
