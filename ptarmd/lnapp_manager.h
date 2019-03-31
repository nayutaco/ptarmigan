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
/** @file   lnapp_manager.h
 *  @brief  lnapp_manager header
 */
#ifndef LNAPP_MANAGER_H__
#define LNAPP_MANAGER_H__

#include "lnapp.h"


#ifdef __cplusplus
extern "C" {
#endif


/********************************************************************
 * prototypes
 ********************************************************************/

void lnapp_manager_init(void);
void lnapp_manager_term(void);
lnapp_conf_t *lnapp_manager_get_node(const uint8_t *pNodeId);
void lnapp_manager_each_node(void (*pCallback)(lnapp_conf_t *pConf, void *pParam), void *pParam);
lnapp_conf_t *lnapp_manager_get_new_node(const uint8_t *pNodeId);
void lnapp_manager_free_node_ref(lnapp_conf_t *pConf);
void lnapp_manager_prune_node();


#ifdef __cplusplus
}
#endif

#endif /* LNAPP_MANAGER_H__ */
