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
/** @file   ln_node.h
 *  @brief  [LN]node関連
 */
#ifndef LN_NODE_H__
#define LN_NODE_H__

#include "ln_msg_anno.h"


/********************************************************************
 * macros
 ********************************************************************/

/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct     ln_node_addr_t
 *  @brief      node_announcementのアドレス情報
 */
typedef struct {
    ln_msg_address_descriptor_type_t   type;
    uint8_t     addr[LN_ADDR_DESC_ADDR_LEN_MAX];
    uint16_t    port;
} ln_node_addr_t;


/** @struct ln_node_t
 *  @brief  ノード情報
 */
typedef struct {
    btc_keys_t          keys;                           ///< node鍵
    uint8_t             features;                       ///< localfeatures
    char                alias[LN_SZ_ALIAS_STR + 1];     ///< ノード名(\0 terminate)
    ln_node_addr_t       addr;                           ///< ノードアドレス
} ln_node_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** nodekey生成
 *
 * @param[out]      pWif            秘密鍵(WIF形式)
 * @param[out]      pPubKey         公開鍵
 */
void HIDDEN ln_node_create_key(char *pWif, uint8_t *pPubKey);


/** 共有鍵生成
 *
 */
bool HIDDEN ln_node_generate_shared_secret(uint8_t *pResult, const uint8_t *pPubKey);


/** node privkeyによる署名
 * 
 */
bool HIDDEN ln_node_sign_nodekey(uint8_t *pRS, const uint8_t *pHash);


/** short_channel_idから相手のnode_idを検索(channel DB)
 * 
 * @param[out] pNodeId          検索結果(戻り値がtrue時)
 * @param[in] ShortChannelId    検索するshort_channel_id
 * @retval  true    検索成功 
 */
bool HIDDEN ln_node_search_node_id(uint8_t *pNodeId, uint64_t ShortChannelId);

#endif /* LN_NODE_H__ */
