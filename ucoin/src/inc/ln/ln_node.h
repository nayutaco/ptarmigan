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

/** node_announcement受信
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pData           受信データ
 * @param[in]           Len             pData長
 * @retval      true    解析成功
 */
bool HIDDEN ln_node_recv_node_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len);


void HIDDEN ln_node_generate_shared_secret(uint8_t *pResult, const uint8_t *pPubKey);

/** node privkeyによる署名
 */
bool HIDDEN ln_node_sign_nodekey(uint8_t *pRS, const uint8_t *pHash);

#endif /* LN_NODE_H__ */
