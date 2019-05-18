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
/** @file   ln_update_info.c
 *  @brief  ln_update_info
 */
#include <inttypes.h>

#include "ln_db_lmdb.h"
#include "ln_update_info.h"
#include "ln_local.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static uint32_t get_last_feerate_per_kw(ln_update_info_t *pInfo);


/**************************************************************************
 * public functions
 **************************************************************************/

void ln_update_info_init(ln_update_info_t *pInfo) {
    memset(pInfo, 0x00, sizeof(ln_update_info_t));
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->htlcs); idx++) {
        utl_buf_init(&pInfo->htlcs[idx].buf_preimage);
        utl_buf_init(&pInfo->htlcs[idx].buf_onion_reason);
        utl_buf_init(&pInfo->htlcs[idx].buf_shared_secret);
    }
}


void ln_update_info_free(ln_update_info_t *pInfo) {
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->htlcs); idx++) {
        utl_buf_free(&pInfo->htlcs[idx].buf_preimage);
        utl_buf_free(&pInfo->htlcs[idx].buf_onion_reason);
        utl_buf_free(&pInfo->htlcs[idx].buf_shared_secret);
    }
    memset(pInfo, 0x00, sizeof(ln_update_info_t));
}


bool ln_update_info_set_add_htlc_send(ln_update_info_t *pInfo, uint16_t *pUpdateIdx)
{
    uint16_t htlc_idx;
    ln_htlc_t *p_htlc = ln_htlc_get_empty(pInfo->htlcs, &htlc_idx);
    if (!p_htlc) return false;
    uint16_t update_idx;
    ln_update_t *p_update = ln_update_get_empty(pInfo->updates, &update_idx);
    if (!p_update) return false;
    p_update->type_specific_idx = htlc_idx;
    p_update->enabled = true;
    p_htlc->enabled = true;
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    *pUpdateIdx = update_idx;
    return true;
}


bool ln_update_info_set_add_htlc_recv(ln_update_info_t *pInfo, uint16_t *pUpdateIdx)
{
    uint16_t htlc_idx;
    ln_htlc_t *p_htlc = ln_htlc_get_empty(pInfo->htlcs, &htlc_idx);
    if (!p_htlc) return false;
    uint16_t update_idx;
    ln_update_t *p_update = ln_update_get_empty(pInfo->updates, &update_idx);
    if (!p_update) return false;
    p_update->type_specific_idx = htlc_idx;
    p_update->enabled = true;
    p_htlc->enabled = true;
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);
    *pUpdateIdx = update_idx;
    return true;
}


bool ln_update_info_clear_htlc(ln_update_info_t *pInfo, uint16_t UpdateIdx)
{
    if (UpdateIdx >= ARRAY_SIZE(pInfo->updates)) {
        assert(0);
        return false;
    }

    ln_update_t *p_update = &pInfo->updates[UpdateIdx];
    if (!(p_update->type & LN_UPDATE_TYPE_MASK_HTLC)) {
        ln_update_clear(p_update);
        return true;
    }

    if (p_update->type_specific_idx >= ARRAY_SIZE(pInfo->htlcs)) {
        assert(0);
        return false;
    }

    //clear htlc
    ln_htlc_t *p_htlc = &pInfo->htlcs[p_update->type_specific_idx];
    if (p_htlc->buf_preimage.len) {
        /*ignore*/ ln_db_preimage_used(p_htlc->buf_preimage.buf); //XXX: delete outside the function
    }
    utl_buf_free(&p_htlc->buf_preimage);
    utl_buf_free(&p_htlc->buf_onion_reason);
    utl_buf_free(&p_htlc->buf_shared_secret);
    memset(p_htlc, 0x00, sizeof(ln_htlc_t));

    //clear corresponding update (add -> del, del -> add)
    uint16_t corresponding_update_idx;
    if (ln_update_info_get_corresponding_update(pInfo, &corresponding_update_idx, UpdateIdx)) {
        ln_update_clear(&pInfo->updates[corresponding_update_idx]);
    }

    //clear update
    ln_update_clear(p_update);
    return true;
}


bool ln_update_info_get_corresponding_update(
    const ln_update_info_t *pInfo, uint16_t *pCorrespondingUpdateIdx, uint16_t UpdateIdx)
{
    const ln_update_t *p_update = &pInfo->updates[UpdateIdx];
    if (!LN_UPDATE_USED(p_update)) return false;
    if (!(p_update->type & LN_UPDATE_TYPE_MASK_HTLC)) {
        return false;
    }
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        if (idx == UpdateIdx) continue; //skip myself
        const ln_update_t *p_update_2 = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update_2)) continue;
        if (!(p_update_2->type & LN_UPDATE_TYPE_MASK_HTLC)) continue;
        if (p_update_2->type_specific_idx != p_update->type_specific_idx) continue;
        *pCorrespondingUpdateIdx = idx;
        return true;
    }
    return false;
}


bool ln_update_info_set_del_htlc_pre_send(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId, uint8_t Type)
{
    assert(Type & LN_UPDATE_TYPE_MASK_DEL_HTLC);

    uint16_t update_idx_add_htlc;
    if (!ln_update_info_get_update_add_htlc_recv_enabled(pInfo, &update_idx_add_htlc, HtlcId)) {
        //we don't have the corresponding update_add_htlc
        LOGE("fail: ???\n");
        return false;
    }

    if (!LN_UPDATE_IRREVOCABLY_COMMITTED(&pInfo->updates[update_idx_add_htlc])) {
        LOGE("fail: ???\n");
        return false;
    }

    uint16_t update_idx_del_htlc;
    if (ln_update_info_get_update(
        pInfo, &update_idx_del_htlc, LN_UPDATE_TYPE_MASK_DEL_HTLC, pInfo->updates[update_idx_add_htlc].type_specific_idx)) {
        //I have already received it
        //XXX: LOGE("fail: ???\n");
        return false;
    }

    ln_update_t *p_update = ln_update_get_empty(pInfo->updates, &update_idx_del_htlc);
    if (!p_update) {
        LOGE("fail: ???\n");
        return false;
    }

    p_update->enabled = true;
    p_update->type = Type;
    //p_update->flags.up_send = 1; //NOT set the flag, pre send
    p_update->type_specific_idx = pInfo->updates[update_idx_add_htlc].type_specific_idx;
    *pUpdateIdx = update_idx_del_htlc;
    return true;
}


bool ln_update_info_set_del_htlc_recv(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId, uint8_t Type)
{
    assert(Type & LN_UPDATE_TYPE_MASK_DEL_HTLC);

    uint16_t update_idx_add_htlc;
    if (!ln_update_info_get_update_add_htlc_send_enabled(pInfo, &update_idx_add_htlc, HtlcId)) {
        //we don't have the corresponding update_add_htlc
        LOGE("fail: ???\n");
        return false;
    }

    if (!LN_UPDATE_IRREVOCABLY_COMMITTED(&pInfo->updates[update_idx_add_htlc])) {
        LOGE("fail: ???\n");
        return false;
    }

    uint16_t update_idx_del_htlc;
    if (ln_update_info_get_update(
        pInfo, &update_idx_del_htlc, LN_UPDATE_TYPE_MASK_DEL_HTLC, pInfo->updates[update_idx_add_htlc].type_specific_idx)) {
        //I have already received it
        LOGE("fail: ???\n");
        return false;
    }

    ln_update_t *p_update = ln_update_get_empty(pInfo->updates, &update_idx_del_htlc);
    if (!p_update) {
        LOGE("fail: ???\n");
        return false;
    }

    p_update->enabled = true;
    p_update->type = Type;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);
    p_update->type_specific_idx = pInfo->updates[update_idx_add_htlc].type_specific_idx;
    *pUpdateIdx = update_idx_del_htlc;
    return true;
}


bool ln_update_info_set_fee_pre_send(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint32_t FeeratePerKw)
{
    if (!ln_update_info_fee_update_needs(pInfo, FeeratePerKw)) return false;

    uint16_t fee_update_idx;
    ln_fee_update_t *p_fee_update = ln_fee_update_get_empty(pInfo->fee_updates, &fee_update_idx);
    if (!p_fee_update) return false;

    uint16_t update_idx;
    ln_update_t *p_update = ln_update_get_empty(pInfo->updates, &update_idx);
    if (!p_update) return false;

    p_update->type_specific_idx = fee_update_idx;
    p_update->enabled = true;
    p_fee_update->enabled = true;
    p_fee_update->id = pInfo->next_fee_update_id++;
    p_fee_update->feerate_per_kw = FeeratePerKw;
    p_update->type = LN_UPDATE_TYPE_FEE;

    //*Older* updates with the same state are removed.
    //  Therefore, what we added *now* should *NOT* be removed.
    //  There should be enough slots so that `ln_fee_update_get_empty` will not fail
    //  if we remove the older updates here.
    ln_update_info_prune_fee_updates(pInfo);

    *pUpdateIdx = update_idx;
    return true;
}


bool ln_update_info_set_fee_recv(ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint32_t FeeratePerKw)
{
    if (!ln_update_info_fee_update_needs(pInfo, FeeratePerKw)) return false;

    uint16_t fee_update_idx;
    ln_fee_update_t *p_fee_update = ln_fee_update_get_empty(pInfo->fee_updates, &fee_update_idx);
    if (!p_fee_update) return false;

    uint16_t update_idx;
    ln_update_t *p_update = ln_update_get_empty(pInfo->updates, &update_idx);
    if (!p_update) return false;

    p_update->type_specific_idx = fee_update_idx;
    p_update->enabled = true;
    p_fee_update->enabled = true;
    p_fee_update->id = pInfo->next_fee_update_id++;
    p_fee_update->feerate_per_kw = FeeratePerKw;
    p_update->type = LN_UPDATE_TYPE_FEE;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);

    //*Older* updates with the same state are removed.
    //  Therefore, what we added *now* should *NOT* be removed.
    //  There should be enough slots so that `ln_fee_update_get_empty` will not fail
    //  if we remove the older updates here.
    ln_update_info_prune_fee_updates(pInfo);

    *pUpdateIdx = update_idx;
    return true;
}


bool ln_update_info_clear_fee(ln_update_info_t *pInfo, uint16_t UpdateIdx)
{
    if (UpdateIdx >= ARRAY_SIZE(pInfo->updates)) {
        assert(0);
        return false;
    }

    ln_update_t *p_update = &pInfo->updates[UpdateIdx];
    if (!(p_update->type & LN_UPDATE_TYPE_FEE)) {
        ln_update_clear(p_update);
        return true;
    }

    if (p_update->type_specific_idx >= ARRAY_SIZE(pInfo->fee_updates)) {
        assert(0);
        return false;
    }

    //clear fee_update
    ln_fee_update_t *p_fee_update = &pInfo->fee_updates[p_update->type_specific_idx];
    memset(p_fee_update, 0x00, sizeof(ln_fee_update_t));

    //clear update
    ln_update_clear(p_update);
    return true;
}


bool ln_update_info_set_initial_fee_send(ln_update_info_t *pInfo, uint32_t FeeratePerKw)
{
    pInfo->feerate_per_kw_irrevocably_committed = FeeratePerKw;
    return true;
}


bool ln_update_info_set_initial_fee_recv(ln_update_info_t *pInfo, uint32_t FeeratePerKw)
{
    pInfo->feerate_per_kw_irrevocably_committed = FeeratePerKw;
    return true;
}


void ln_update_info_prune_fee_updates(ln_update_info_t *pInfo)
{
    //Remove the older `fee_update`s with the same state

    struct info {
        uint16_t update_idx;
        uint8_t update_state;
        uint64_t fee_update_id;
        bool need_to_be_pruned;
    } infos[ARRAY_SIZE(pInfo->fee_updates)];
    uint32_t num_infos = 0;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (p_update->type != LN_UPDATE_TYPE_FEE) continue;
        assert(num_infos < ARRAY_SIZE(pInfo->fee_updates));
        infos[num_infos].update_idx = idx;
        infos[num_infos].update_state = p_update->state;
        ln_fee_update_t *p_fee_update = &pInfo->fee_updates[p_update->type_specific_idx];
        infos[num_infos].fee_update_id = p_fee_update->id;
        infos[num_infos].need_to_be_pruned = false;
        num_infos++;
    }

    for (uint16_t i = 0; i < num_infos; i++) {
        for (uint16_t j = i + 1; j < num_infos; j++) {
            if (infos[i].update_state != infos[j].update_state) continue;
            infos[infos[i].fee_update_id < infos[j].fee_update_id ? i : j].need_to_be_pruned = true;
        }
    }

    for (uint16_t i = 0; i < num_infos; i++) {
        if (!infos[i].need_to_be_pruned) continue;
        bool ret = ln_update_info_clear_fee(pInfo, infos[i].update_idx);
        assert(ret);
        (void)ret;
    }
}


uint32_t ln_update_info_get_feerate_per_kw_pre_committed(const ln_update_info_t *pInfo, bool bLocal)
{
    uint64_t id = 0;
    uint32_t feerate_per_kw = 0;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        const ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_ENABLED(p_update, LN_UPDATE_TYPE_FEE, bLocal)) continue;
        const ln_fee_update_t *p_fee_update = &pInfo->fee_updates[p_update->type_specific_idx];
        if (p_fee_update->id < id) continue;
        id = p_fee_update->id;
        feerate_per_kw = p_fee_update->feerate_per_kw;
    }
    if (!feerate_per_kw) {
        feerate_per_kw = pInfo->feerate_per_kw_irrevocably_committed;
    }
    return feerate_per_kw;
}


uint32_t ln_update_info_get_feerate_per_kw_committed(const ln_update_info_t *pInfo, bool bLocal)
{
    uint64_t id = 0;
    uint32_t feerate_per_kw = 0;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        const ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_ENABLED(p_update, LN_UPDATE_TYPE_FEE, bLocal)) continue;
        if (LN_UPDATE_UNCOMMITTED(p_update, bLocal)) continue;
        const ln_fee_update_t *p_fee_update = &pInfo->fee_updates[p_update->type_specific_idx];
        if (p_fee_update->id < id) continue;
        id = p_fee_update->id;
        feerate_per_kw = p_fee_update->feerate_per_kw;
    }
    if (!feerate_per_kw) {
        feerate_per_kw = pInfo->feerate_per_kw_irrevocably_committed;
    }
    return feerate_per_kw;
}


uint16_t ln_update_info_get_num_fee_updates(ln_update_info_t *pInfo)
{
    uint16_t num_fee_updates = 0;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->fee_updates); idx++) {
        ln_fee_update_t *p_fee_update = &pInfo->fee_updates[idx];
        if (!p_fee_update->enabled) continue;
        num_fee_updates++;
    }
    return num_fee_updates;
}


bool ln_update_info_fee_update_needs(ln_update_info_t *pInfo, uint32_t FeeratePerKw)
{
    if (!FeeratePerKw) return false;
    if (FeeratePerKw == get_last_feerate_per_kw(pInfo)) return false;
    return true;
}


bool ln_update_info_get_update(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint8_t Type, uint16_t TypeSpecificIdx)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        const ln_update_t *p_update = &pInfo->updates[idx];
        if (!p_update->enabled) continue;
        if (!(p_update->type & Type)) continue;
        if (p_update->type_specific_idx != TypeSpecificIdx) continue;
        *pUpdateIdx = idx;
        return true;
    }
    return false;
}


bool ln_update_info_get_update_add_htlc_send_enabled(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        const ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true)) continue;
        if (pInfo->htlcs[p_update->type_specific_idx].id != HtlcId) continue;
        *pUpdateIdx = idx;
        return true;
    }
    return false;
}


bool ln_update_info_get_update_add_htlc_recv_enabled(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t HtlcId)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        const ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true)) continue;
        if (pInfo->htlcs[p_update->type_specific_idx].id != HtlcId) continue;
        *pUpdateIdx = idx;
        return true;
    }
    return false;
}


bool ln_update_info_get_update_add_htlc_forwarded_send(
    const ln_update_info_t *pInfo, uint16_t *pUpdateIdx, uint64_t PrevShortChannelId, uint64_t PrevHtlcId)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        const ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (p_update->type != LN_UPDATE_TYPE_ADD_HTLC) continue;
        if (!LN_UPDATE_OFFERED(p_update)) continue;
        if (pInfo->htlcs[p_update->type_specific_idx].neighbor_short_channel_id != PrevShortChannelId) continue;
        if (pInfo->htlcs[p_update->type_specific_idx].neighbor_id != PrevHtlcId) continue;
        *pUpdateIdx = idx;
        return true;
    }
    return false;
}


bool ln_update_info_irrevocably_committed_htlcs_exists(ln_update_info_t *pInfo)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_IRREVOCABLY_COMMITTED(p_update)) continue;
        if (!(p_update->type & LN_UPDATE_TYPE_MASK_DEL_HTLC)) continue;
        return true;
    }
    return false;
}


bool ln_update_info_commitment_signed_send_needs(ln_update_info_t *pInfo)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_REMOTE_COMSIGING(p_update)) continue;
        return false;
    }

    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_WAIT_SEND_CS(p_update)) continue;
        return true;
    }
    return false;
}


void ln_update_info_clear_irrevocably_committed_updates(ln_update_info_t *pInfo)
{
    ln_update_info_prune_fee_updates(pInfo);

    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (!LN_UPDATE_IRREVOCABLY_COMMITTED(p_update)) continue;
        if (p_update->type & LN_UPDATE_TYPE_MASK_DEL_HTLC) {
            /*ignore*/ ln_update_info_clear_htlc(pInfo, idx);
        } else if (p_update->type == LN_UPDATE_TYPE_FEE) {
            pInfo->feerate_per_kw_irrevocably_committed =
                pInfo->fee_updates[p_update->type_specific_idx].feerate_per_kw;
            /*ignore*/ ln_update_info_clear_fee(pInfo, idx);
        }
    }
}


void ln_update_info_set_state_flag_all(ln_update_info_t *pInfo, uint8_t flag)
{
    switch (flag) {
    case LN_UPDATE_STATE_FLAG_CS_SEND:
        for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
            ln_update_t *p_update = &pInfo->updates[idx];
            if (!LN_UPDATE_USED(p_update)) continue;
            switch (p_update->state) {
            case LN_UPDATE_STATE_OFFERED_UP_SEND:
            case LN_UPDATE_STATE_RECEIVED_RA_SEND:
                LN_UPDATE_FLAG_SET(p_update, flag);
                break;
            default:
                ;
            }
        }
        break;
    case LN_UPDATE_STATE_FLAG_CS_RECV:
        for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
            ln_update_t *p_update = &pInfo->updates[idx];
            if (!LN_UPDATE_USED(p_update)) continue;
            switch (p_update->state) {
            case LN_UPDATE_STATE_OFFERED_RA_RECV:
            case LN_UPDATE_STATE_RECEIVED_UP_RECV:
                LN_UPDATE_FLAG_SET(p_update, flag);
                break;
            default:
                ;
            }
        }
        break;
    case LN_UPDATE_STATE_FLAG_RA_SEND:
        for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
            ln_update_t *p_update = &pInfo->updates[idx];
            if (!LN_UPDATE_USED(p_update)) continue;
            switch (p_update->state) {
            case LN_UPDATE_STATE_OFFERED_CS_RECV:
            case LN_UPDATE_STATE_RECEIVED_CS_RECV:
                LN_UPDATE_FLAG_SET(p_update, flag);
                break;
            default:
                ;
            }
        }
        break;
    case LN_UPDATE_STATE_FLAG_RA_RECV:
        for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
            ln_update_t *p_update = &pInfo->updates[idx];
            if (!LN_UPDATE_USED(p_update)) continue;
            switch (p_update->state) {
            case LN_UPDATE_STATE_OFFERED_CS_SEND:
            case LN_UPDATE_STATE_RECEIVED_CS_SEND:
                LN_UPDATE_FLAG_SET(p_update, flag);
                break;
            default:
                ;
            }
        }
        break;
    default:
        assert(0);
    }
}


void ln_update_info_reset_new_update(ln_update_info_t *pInfo) {
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        p_update->new_update = false;
    }
}


uint64_t ln_update_info_get_htlc_value_in_flight_msat(ln_update_info_t *pInfo, bool bLocal)
{
    uint64_t value = 0;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) {
            value += pInfo->htlcs[p_update->type_specific_idx].amount_msat;
        }
        if (LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, bLocal)) {
            value -= pInfo->htlcs[p_update->type_specific_idx].amount_msat;
        }
    }
    return value;
}


uint16_t ln_update_info_get_num_received_htlcs(ln_update_info_t *pInfo, bool bLocal)
{
    uint16_t num = 0;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, bLocal)) {
            num++;
        }
        if (LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, bLocal)) {
            num--;
        }
    }
    return num;
}


void ln_update_info_clear_pending_updates(ln_update_info_t *pInfo, bool *pUpdated)
{
    *pUpdated = false;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        ln_update_t *p_update = &pInfo->updates[idx];
        if (!LN_UPDATE_USED(p_update)) continue;
        if (p_update->state != LN_UPDATE_STATE_OFFERED_WAIT_SEND &&
            p_update->state != LN_UPDATE_STATE_OFFERED_UP_SEND &&
            p_update->state != LN_UPDATE_STATE_RECEIVED_UP_RECV) continue; //check not committed
        *pUpdated = true;
        switch (p_update->type) {
        case LN_UPDATE_TYPE_ADD_HTLC:
            LOGD("clear update add htlc update_idx=%u\n", idx);
            if (!ln_update_info_clear_htlc(pInfo, idx)) {
                LOGE("fail: ???\n");
            }
            break;
        case LN_UPDATE_TYPE_FULFILL_HTLC:
        case LN_UPDATE_TYPE_FAIL_HTLC:
        case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
            LOGD("clear update del htlc update_idx=%u\n", idx);
            ln_update_clear(p_update);
            break;
        case LN_UPDATE_TYPE_FEE:
            LOGD("clear update fee update_idx=%u\n", idx);
            if (!ln_update_info_clear_fee(pInfo, idx)) {
                LOGE("fail: ???\n");
            }
            break;
        default:
            LOGE("fail: ???\n");
        }
    }
}


bool ln_update_info_is_channel_clean(ln_update_info_t *pInfo)
{
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->updates); idx++) {
        if (pInfo->updates[idx].enabled) return false;
    }
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->htlcs); idx++) {
        if (pInfo->htlcs[idx].enabled) return false;
    }
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->fee_updates); idx++) {
        if (pInfo->fee_updates[idx].enabled) return false;
    }
    return true;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static uint32_t get_last_feerate_per_kw(ln_update_info_t *pInfo)
{
    uint64_t id = 0;
    uint32_t feerate_per_kw = 0;
    for (uint16_t idx = 0; idx < ARRAY_SIZE(pInfo->fee_updates); idx++) {
        ln_fee_update_t *p_fee_update = &pInfo->fee_updates[idx];
        if (!p_fee_update->enabled) continue;
        if (p_fee_update->id < id) continue;
        id = p_fee_update->id;
        feerate_per_kw = p_fee_update->feerate_per_kw;
    }
    if (!feerate_per_kw) {
        feerate_per_kw = pInfo->feerate_per_kw_irrevocably_committed;
    }
    return feerate_per_kw;
}
