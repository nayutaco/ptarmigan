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
/** @file   ln_update_info.h
 *  @brief  ln_update_info
 */
#ifndef LN_UPDATE_INFO_H__
#define LN_UPDATE_INFO_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln_update.h"

//
/********************************************************************
 * macros
 ********************************************************************/

#define LN_HTLC_OFFERED_MAX             (6)
#define LN_HTLC_RECEIVED_MAX            (6)
#define LN_HTLC_MAX                     (LN_HTLC_OFFERED_MAX + LN_HTLC_RECEIVED_MAX)

//The number of possible states+1 is necessary.
//  (Because the extra is to add new updates first)
//  Since `update_fee` is performed only from a funder,
//  it is sufficient to consider only one side.
//  There are states that can not be taken at the same time,
//  so it should be a little less.
#define LN_FEE_UPDATE_MAX               (8)


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    ln_update_t                 updates[LN_UPDATE_MAX];         ///< updates
    ln_htlc_t                   htlcs[LN_HTLC_MAX];             ///< htlcs
    uint64_t                    next_htlc_id;                   ///< update_add_htlcで使うidの管理 //XXX: Append immediately before sending
    ln_fee_update_t             fee_updates[LN_FEE_UPDATE_MAX]; ///< fee update
    uint32_t                    feerate_per_kw_irrevocably_committed;   ///< feerate_per_kw
    uint64_t                    next_fee_update_id;             ///< fee update id
} ln_update_info_t;


/********************************************************************
 * prototypes
 ********************************************************************/

void ln_update_info_init(ln_update_info_t *pInfo);
void ln_update_info_free(ln_update_info_t *pInfo);

bool ln_update_info_set_add_htlc_send(ln_update_info_t *pInfo, uint16_t *pUpdateIdx);
bool ln_update_info_set_add_htlc_recv(ln_update_info_t *pInfo, uint16_t *pUpdateIdx);
bool ln_update_info_clear_htlc(ln_update_info_t *pInfo, uint16_t UpdateIdx);

bool ln_update_info_set_del_htlc_pre_send(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId, uint8_t Type);
bool ln_update_info_set_del_htlc_recv(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId, uint8_t Type);

bool ln_update_info_set_fee_pre_send(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint32_t FeeratePerKw);
bool ln_update_info_set_fee_recv(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint32_t FeeratePerKw);
bool ln_update_info_clear_fee(ln_update_info_t *pInfo, uint16_t UpdateIdx);

bool ln_update_info_set_initial_fee_send(ln_update_info_t *pInfo, uint32_t FeeratePerKw);
bool ln_update_info_set_initial_fee_recv(ln_update_info_t *pInfo, uint32_t FeeratePerKw);
void ln_update_info_prune_fee_updates(ln_update_info_t *pInfo);
uint32_t ln_update_info_get_feerate_per_kw_pre_committed(const ln_update_info_t *pInfo, bool bLocal);
uint32_t ln_update_info_get_feerate_per_kw_committed(const ln_update_info_t *pInfo, bool bLocal);
uint16_t ln_update_info_get_num_fee_updates(ln_update_info_t *pInfo);
bool ln_update_info_fee_update_needs(ln_update_info_t *pInfo, uint32_t FeeratePerKw);

bool ln_update_info_get_update(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint8_t Type, uint16_t TypeSpecificIdx);
bool ln_update_info_get_update_add_htlc_send_enabled(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId);
bool ln_update_info_get_update_add_htlc_forwarded_send_enabled(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t PrevShortChannelId, uint64_t PrevHtlcId);
bool ln_update_info_get_update_add_htlc_recv_enabled(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId);
bool ln_update_info_get_update_add_htlc_forwarded_send(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t PrevShortChannelId, uint64_t PrevHtlcId);
bool ln_update_info_get_corresponding_update(
    const ln_update_info_t *pInfo, uint16_t *pCorrespondingUpdateIdx, uint16_t UpdateIdx);

bool ln_update_info_irrevocably_committed_htlcs_exists(ln_update_info_t *pInfo);

bool ln_update_info_commitment_signed_send_needs(ln_update_info_t *pInfo);

void ln_update_info_clear_irrevocably_committed_updates(ln_update_info_t *pInfo);

void ln_update_info_reset_new_update(ln_update_info_t *pInfo);

//cs and ra only
void ln_update_info_set_state_flag_all(ln_update_info_t *pInfo, uint8_t flag);

uint64_t ln_update_info_get_htlc_value_in_flight_msat(ln_update_info_t *pInfo, bool bLocal);

uint16_t ln_update_info_get_num_received_htlcs(ln_update_info_t *pInfo, bool bLocal);

//for reconnecting
void ln_update_info_clear_pending_updates(ln_update_info_t *pInfo, bool *pUpdated);

bool ln_update_info_is_channel_clean(ln_update_info_t *pInfo);


#endif /* LN_UPDATE_INFO_H__ */
