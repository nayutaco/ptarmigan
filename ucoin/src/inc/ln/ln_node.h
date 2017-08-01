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
 *  @author ueno@nayuta.co
 */
#ifndef LN_NODE_H__
#define LN_NODE_H__

#include "ln_local.h"


/********************************************************************
 * prototypes
 ********************************************************************/

bool HIDDEN ln_node_recv_channel_announcement(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_node_recv_node_announcement(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_node_recv_channel_update(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_node_recv_announcement_signatures(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pData, uint16_t Len);


/** node_announcment情報追加
 *
 * @param[in,out]   node
 * @param[in]       pAnno
 * @retval  NODE_NOT_FOUND以外  追加成功
 * @retval  NODE_NOT_FOUND      追加失敗
 */
int HIDDEN ln_node_update_node_anno(ln_node_t *node, const ln_node_announce_t *pAnno);


/** channel_announcement検索
 *
 * @param[in,out]   node
 * @param[out]      pAdd                    true:追加  false:既存
 * @param[in]       short_channel_id        検索するshort_channel_id
 * @param[in]       node1                   node1のnode_idx
 * @param[in]       node2                   node2のnode_idx
 * @retval  CHANNEL_NOT_FOUND以外   検索 or 追加成功
 * @retval  CHANNEL_NOT_FOUND       失敗
 * @note
 *      - announcement_signaturesのデータに対して用いるため、片方は必ず自ノードになる
 */
int HIDDEN ln_node_search_cnl_anno(ln_node_t *node, bool *pAdd, uint64_t short_channel_id, int8_t node1, int8_t node2);


/** node_idからnode_idx検索
 *
 * node_idから、保持しているノード情報へのインデックスを返す。
 *
 * @param[in,out]   node            ノード情報
 * @param[in]       pNodeId         node_id(node_idxではない)
 * @retval      LN_NODE_MAX以外     検索したshort_channel_id
 * @retval      LN_NODE_MAX         検索失敗
 */
uint8_t HIDDEN ln_node_search_nodeid(ln_node_t *node, const uint8_t *pNodeId);


/** node_idxから接続しているshort_channel_id検索
 *
 * 自ノードと接続しているnode_idxを検索し、short_channel_idを返す。
 *
 * @param[in,out]   node            ノード情報
 * @param[in]       node_idx        ln_node_t.node_info[node_idx]
 * @retval      0以外   検索したshort_channel_id
 * @retval      0       検索失敗
 */
uint64_t HIDDEN ln_node_search_idx(ln_node_t *node, int8_t node_idx);

#endif /* LN_NODE_H__ */
