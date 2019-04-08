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
/** @file   p2p.h
 *  @brief  p2p
 */
#ifndef P2P_H__
#define P2P_H__

#include <stdint.h>

#include "jsonrpc-c.h"

#include "lnapp.h"

#ifdef __cplusplus
extern "C" {
#endif


/********************************************************************
 * prototypes
 ********************************************************************/

/** [p2p]初期化
 *
 */
void p2p_init(void);


/** [p2p]接続テスト
 * 
 */
bool p2p_connect_test(const char *pIpAddr, uint16_t Port);


/** [p2p]開始
 *
 */
bool p2p_initiator_start(const peer_conn_t *pConn, int *pErrCode);


/** [p2p] 接続情報を保存
 *
 */
bool p2p_store_peer_conn(const peer_conn_t* pPeerConn);


/** [p2p] 接続情報を復元
 *
 */
bool p2p_load_peer_conn(peer_conn_t* pPeerConn, const uint8_t *pNodeId);


/** [p2p]開始
 *
 */
void *p2p_listener_start(void *pArg);


/** [p2p]全停止
 *
 */
void p2p_stop(void);


/** [p2p]node_idによる検索
 *
 */
lnapp_conf_t *p2p_search_node(const uint8_t *pNodeId);


/** [p2p]short_channel_idによる検索
 *
 */
lnapp_conf_t *p2p_search_short_channel_id(uint64_t short_channel_id);


/** [p2p]動作中lnapp全出力
 *
 */
void p2p_show_channel(cJSON *pResult);


#ifdef __cplusplus
}
#endif

#endif /* P2P_H__ */
