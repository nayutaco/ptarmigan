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
/** @file   ln_establish.h
 *  @brief  ln_establish
 */
#ifndef LN_ESTABLISH_H__
#define LN_ESTABLISH_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln.h"
#include "ln_msg_establish.h"

//XXX: unit test

/********************************************************************
 * macros
 ********************************************************************/
/********************************************************************
 * prototypes
 ********************************************************************/

/** send open_channel
 *
 * @param[in,out]       self            channel info
 * @param[in]           pFundin         fund-in情報
 * @param[in]           FundingSat      fundingするamount[satoshi]
 * @param[in]           PushSat         push_msatするamount[satoshi]
 * @param[in]           FeeRate         feerate_per_kw
 * retval       true    成功
 */
bool /*HIDDEN*/ ln_open_channel_send(
    ln_self_t *self, const ln_fundin_t *pFundin, uint64_t FundingSat, uint64_t PushSat, uint32_t FeeRate);
bool HIDDEN ln_open_channel_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_accept_channel_send(ln_self_t *self);
bool HIDDEN ln_accept_channel_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_funding_created_send(ln_self_t *self);
bool HIDDEN ln_funding_created_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_funding_signed_send(ln_self_t *self);
bool HIDDEN ln_funding_signed_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool /*HIDDEN*/ ln_funding_locked_send(ln_self_t *self);
bool HIDDEN ln_funding_locked_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool /*HIDDEN*/ ln_channel_reestablish_send(ln_self_t *self);
bool HIDDEN ln_channel_reestablish_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);


#endif /* LN_ESTABLISH_H__ */
