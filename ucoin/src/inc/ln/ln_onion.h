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
/** @file   ln_onion.h
 *  @brief  ONION関連
 *  @author ueno@nayuta.co
 */
#ifndef LN_ONION_H__
#define LN_ONION_H__


#include "ln_local.h"


/**************************************************************************
 * ONION
 **************************************************************************/

/** ONIONパラメータ復元
 *
 * @param[out]      pNextPacket         次に送るONIONパケット[LN_SZ_ONION_ROUTE]
 * @param[out]      pNextData           復元情報
 * @param[out]      pSharedSecret       共有秘密鍵
 * @param[in]       pPacket             解析するONIONパケット
 * @param[in]       pOnionPrivKey       自ノード秘密鍵?
 * @param[in]       pAssocData          Associated Data
 * @param[in]       AssocLen            pAssocData長
 * @retval      true    成功
 * @note
 *      - pNextData->b_exitがtrueの場合、pNextPacketは無効
 *      - pNextPacketとpPacketに同じアドレスを指定できる
 */
bool HIDDEN ln_onion_read_packet(uint8_t *pNextPacket, ln_hop_dataout_t *pNextData,
            ucoin_buf_t *pSharedSecret,
            const uint8_t *pPacket,
            const uint8_t *pAssocData, int AssocLen);

#endif /* LN_ONION_H__ */
