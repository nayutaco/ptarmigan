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
/** @file   p2p_cli.h
 *  @brief  ucoind client動作 header
 */
#ifndef P2P_CLI_H__
#define P2P_CLI_H__

#include <stdint.h>

#include "jsonrpc-c.h"

#include "lnapp.h"


/********************************************************************
 * prototypes
 ********************************************************************/

/** [p2p_cli]初期化
 *
 */
void p2p_cli_init(void);


/** [p2p_cli]開始
 *
 */
void p2p_cli_start(daemoncmd_t Cmd, const daemon_connect_t *pConn, void *pParam, jrpc_context *ctx);


/** [p2p_cli]全停止
 *
 */
void p2p_cli_stop_all(void);


/** [p2p_cli]node_idによる検索
 *
 */
lnapp_conf_t *p2p_cli_search_node(const uint8_t *pNodeId);


/** [p2p_cli]short_channel_idによる検索
 *
 */
lnapp_conf_t *p2p_cli_search_short_channel_id(uint64_t short_channel_id);


/** [p2p_cli]動作中lnapp全出力
 *
 */
void p2p_cli_show_self(cJSON *pResult);


/** [p2p_cli]ループ状態取得
 *
 */
bool p2p_cli_is_looping(void);

#endif /* P2P_CLI_H__ */
