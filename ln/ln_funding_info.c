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
/** @file   ln_funding_info.c
 *  @brief  ln_funding
 */
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

#include "ln_funding_info.h"


/**************************************************************************
 * public functions
 **************************************************************************/

void ln_funding_info_set_txid(ln_funding_info_t *pFundingInfo, const uint8_t *pTxid)
{
    memcpy(pFundingInfo->txid, pTxid, BTC_SZ_TXID);
}


const uint8_t *ln_funding_info_txid(const ln_funding_info_t *pFundingInfo)
{
    return pFundingInfo->txid;
}


uint32_t ln_funding_info_txindex(const ln_funding_info_t *pFundingInfo)
{
    return pFundingInfo->txindex;
}


const utl_buf_t *ln_funding_info_wit_script(const ln_funding_info_t *pFundingInfo)
{
    return &pFundingInfo->wit_script;
}


uint32_t ln_funding_info_minimum_depth(const ln_funding_info_t *pFundingInfo)
{
    return pFundingInfo->minimum_depth;
}


bool ln_funding_info_is_funder(const ln_funding_info_t *pFundingInfo, bool bLocal)
{
    if (pFundingInfo->role == LN_FUNDING_ROLE_FUNDER) {
        return bLocal;
    } else {
        return !bLocal;
    }
}


bool ln_funding_info_funding_now(const ln_funding_info_t *pFundingInfo)
{
    return (pFundingInfo->state & LN_FUNDING_STATE_STATE_FUNDING);
}


const btc_tx_t *ln_funding_info_tx(const ln_funding_info_t *pFundingInfo)
{
    return &pFundingInfo->tx_data;
}

