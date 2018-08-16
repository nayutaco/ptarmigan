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


void conf_peer_init(peer_conf_t *pPeerConf);
bool conf_peer_load(const char *pConfFile, peer_conf_t *pPeerConf);

void conf_funding_init(funding_conf_t *pFundConf);
bool conf_funding_load(const char *pConfFile, funding_conf_t *pFundConf);

void conf_payment_init(payment_conf_t *pPayConf);
bool conf_payment_load(const char *pConfFile, payment_conf_t *pPayConf);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* CONF_H__ */
