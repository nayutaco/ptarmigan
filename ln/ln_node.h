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

#define LN_NODE_ADDR_INIT               { LN_ADDR_DESC_TYPE_NONE, "", 0}
#define LN_NODE_INIT                    { {{0},{0}}, "", {0}, LN_NODE_ADDR_INIT }

#define LN_SZ_ADDRESS                   (250)
#define LN_SZ_ADDRESS_STR               "250"


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
    char                alias[LN_SZ_ALIAS_STR + 1];     ///< ノード名(\0 terminate)
    uint8_t             color[LN_SZ_RGB_COLOR];         ///< RGB
    ln_node_addr_t      addr;                           ///< ノードアドレス
} ln_node_t;


/** @struct ln_node_conn_t
 *  @brief  node connection info
 */
typedef struct {
    uint8_t             node_id[BTC_SZ_PUBKEY];
    char                addr[LN_ADDR_DESC_ADDR_LEN_MAX];
    uint16_t            port;
} ln_node_conn_t;


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


/** decode node connection string
 * 
 * @param[out]  pNodeConn       decoded info
 * @param[in]   pConnStr        connection string(<NODE_ID>@<IPADDR>:<PORT>)
 * @retval  true    success
 */
bool ln_node_addr_dec(ln_node_conn_t *pNodeConn, const char *pConnStr);


/** get announcement IP address string
 * 
 * @param[out]  pIpStr      `ptarmd --announceip`
 * @retval  true    success
 */
bool ln_node_get_announceip(char *pIpStr);

#endif /* LN_NODE_H__ */
