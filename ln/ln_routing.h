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
/** @file   ln_routing.h
 *  @brief  ln_routing
 */
#ifndef LN_ROUTING_H__
#define LN_ROUTING_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln_err.h"
#include "ln_onion.h"
#include "ln_invoice.h"
#include "ln_msg_anno.h"


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     ln_routing_result_t
 *  @brief      #ln_routing_calculate()戻り値
 */
typedef struct {
    uint8_t             num_hops;
    ln_hop_datain_t     hop_datain[1 + LN_HOP_MAX];     //先頭は送信者
} ln_routing_result_t;


/********************************************************************
 * prototypes
 ********************************************************************/

bool ln_routing_init(const uint8_t *pPayerId);


/**
 * 
 * @note
 *      - channel_update情報の方向はpNode1==>pNode2となるように呼び出すこと
 */
bool ln_routing_add_channel(
        const ln_msg_channel_update_t *pChannelUpdate,
        const uint8_t *pNode1, const uint8_t *pNode2);


void ln_routing_add_rfield(uint8_t AddNum, const ln_r_field_t *pAddRoute, const uint8_t *pPayeeId);


/** 支払いルート作成
 *
 * @param[out]  pResult
 * @param[in]   pPayerId
 * @param[in]   pPayeeId
 * @param[in]   CltvExpiry
 * @param[in]   AmountMsat
 * @param[in]   AddNum          追加route数(invoiceのr fieldを想定)
 * @param[in]   pAddRoute       追加route(invoiceのr fieldを想定)
 * @return  LNERR_ROUTE_xxx
 */
lnerr_route_t ln_routing_calculate(
        ln_routing_result_t *pResult,
        const uint8_t *pPayerId,
        const uint8_t *pPayeeId,
        uint32_t CltvExpiry,
        uint64_t AmountMsat);


/** routing skip DB削除
 *
 * routingから除外するchannelリストを削除する。
 */
void ln_routing_clear_skipdb(void);


void ln_routing_create_dot(const char *pFilename);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* LN_ROUTING_H__ */
