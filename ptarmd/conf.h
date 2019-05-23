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
#ifndef CONF_H__
#define CONF_H__

#include <stdbool.h>
#include "ptarmd.h"

#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


void conf_btcrpc_init(rpc_conf_t *pRpcConf);
#if defined(USE_BITCOIND)
bool conf_btcrpc_load(const char *pConfFile, rpc_conf_t *pRpcConf, btc_block_chain_t Chain);
bool conf_btcrpc_load_default(rpc_conf_t *pRpcConf, btc_block_chain_t Chain);
#endif  //USE_BITCOIND

void conf_anno_init(anno_conf_t *pAnnoConf);
bool conf_anno_load(const char *pConfFile, anno_conf_t *pAnnoConf);

void conf_channel_init(channel_conf_t *pEstConf);
bool conf_channel_load(const char *pConfFile, channel_conf_t *pEstConf);

void conf_connect_init(connect_conf_t *pConnConf);
bool conf_connect_load(const char *pConfFile, connect_conf_t *pConnConf);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* CONF_H__ */
