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
#include "ucoind.h"

#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


bool load_peer_conf(const char *pConfFile, peer_conf_t *pPeerConf);
void print_peer_conf(const peer_conf_t *pPeerConf);

bool load_funding_conf(const char *pConfFile, funding_conf_t *pFundConf);
void print_funding_conf(const funding_conf_t *pFundConf);

bool load_btcrpc_conf(const char *pConfFile, rpc_conf_t *pRpcConf);
bool load_btcrpc_default_conf(rpc_conf_t *pRpcConf);

bool load_payment_conf(const char *pConfFile, payment_conf_t *pPayConf);
void print_payment_conf(const payment_conf_t *pPayConf);

bool load_anno_conf(const char *pConfFile, anno_conf_t *pAnnoConf);

bool load_establish_conf(const char *pConfFile, establish_conf_t *pEstConf);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* CONF_H__ */
