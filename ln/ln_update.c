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
/** @file   ln_htlc.c
 *  @brief  ln_htlc
 */
#include "utl_int.h"

#include "ln_local.h"
#include "ln_update.h"


/**************************************************************************
 * public functions
 **************************************************************************/

uint32_t ln_update_flags2u32(ln_update_flags_t Flags)
{
    if (sizeof(ln_update_flags_t) == 2) {
        return utl_int_pack_u16be((const uint8_t *)&Flags);
    } else if (sizeof(ln_update_flags_t) == 4) {
        return utl_int_pack_u32be((const uint8_t *)&Flags);
    } else {
        return 0;
    }
}


ln_update_t *ln_update_get_empty( ln_update_t *pUpdates, uint16_t *pUpdateIdx)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pUpdates[idx];
        if (LN_UPDATE_ENABLED(p_update)) continue;
        if (pUpdateIdx) {
            *pUpdateIdx = idx;
        }
        return p_update;
    }
    return NULL;
}


ln_htlc_t *ln_htlc_get_empty(ln_htlc_t *pHtlcs, uint16_t *pHtlcIdx)
{
    for (uint16_t idx = 0; idx < LN_HTLC_RECEIVED_MAX; idx++) {
        ln_htlc_t *p_htlc = &pHtlcs[idx];
        if (p_htlc->enabled) continue;
        if (pHtlcIdx) {
            *pHtlcIdx = idx;
        }
        return p_htlc;
    }
    return NULL;
}


bool ln_update_get_corresponding_update(
    const ln_update_t *pUpdates, uint16_t *pCorrespondingUpdateIdx, uint16_t UpdateIdx)
{
    const ln_update_t *p_update = &pUpdates[UpdateIdx];
    if (LN_UPDATE_EMPTY(p_update)) return false;
    switch (p_update->type) {
    case LN_UPDATE_TYPE_ADD_HTLC:
    case LN_UPDATE_TYPE_FULFILL_HTLC:
    case LN_UPDATE_TYPE_FAIL_HTLC:
    case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
        break;
    default:
        return false;
    }
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        if (idx == UpdateIdx) continue; //skip myself
        const ln_update_t *p_update_2 = &pUpdates[idx];
        if (LN_UPDATE_EMPTY(p_update_2)) continue;
        switch (p_update_2->type) {
        case LN_UPDATE_TYPE_ADD_HTLC:
        case LN_UPDATE_TYPE_FULFILL_HTLC:
        case LN_UPDATE_TYPE_FAIL_HTLC:
        case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
            break;
        default:
            continue;
        }
        if (p_update_2->htlc_idx != p_update->htlc_idx) continue;
        *pCorrespondingUpdateIdx = idx;
        return true;
    }
    return false;
}


ln_update_t *ln_update_set_del_htlc_send(ln_update_t *pUpdates, uint16_t HtlcIdx, uint8_t Type)
{
    switch (Type) {
    case LN_UPDATE_TYPE_FULFILL_HTLC:
    case LN_UPDATE_TYPE_FAIL_HTLC:
    case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
        break;
    default:
        assert(0);
        return NULL;
    }

    if (ln_update_get_update_del_htlc_const(pUpdates, HtlcIdx)) {
        //I have already received it
        return NULL;
    }

    ln_update_t *p_update = ln_update_get_empty(pUpdates, NULL);
    assert(p_update);

    p_update->enabled = true;
    p_update->type = Type;
    //p_update->flags.up_send = 1; //XXX:
    p_update->htlc_idx = HtlcIdx;
    return p_update;
}


ln_update_t *ln_update_set_del_htlc_recv(ln_update_t *pUpdates, uint16_t HtlcIdx, uint8_t Type)
{
    switch (Type) {
    case LN_UPDATE_TYPE_FULFILL_HTLC:
    case LN_UPDATE_TYPE_FAIL_HTLC:
    case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
        break;
    default:
        assert(0);
        return NULL;
    }

    if (ln_update_get_update_del_htlc_const(pUpdates, HtlcIdx)) {
        //I have already received it
        return NULL;
    }

    ln_update_t *p_update = ln_update_get_empty(pUpdates, NULL);
    assert(p_update);

    p_update->enabled = true;
    p_update->type = Type;
    p_update->flags.up_recv = 1; //XXX:
    p_update->htlc_idx = HtlcIdx;
    return p_update;
}


ln_update_t *ln_update_get_update_enabled_but_none(ln_update_t *pUpdates, uint16_t HtlcIdx)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pUpdates[idx];
        if (!p_update->enabled) continue;
        if (p_update->type != LN_UPDATE_TYPE_NONE) continue;
        if (p_update->htlc_idx != HtlcIdx) continue;
        return p_update;
    }
    return NULL; 
}


ln_update_t *ln_update_get_update_add_htlc(ln_update_t *pUpdates, uint16_t HtlcIdx)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pUpdates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (p_update->type != LN_UPDATE_TYPE_ADD_HTLC) continue;
        if (p_update->htlc_idx != HtlcIdx) continue;
        return p_update;
    }
    return NULL; 
}

ln_update_t *ln_update_get_update_del_htlc(ln_update_t *pUpdates, uint16_t HtlcIdx)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pUpdates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        switch (p_update->type) {
        case LN_UPDATE_TYPE_FULFILL_HTLC:
        case LN_UPDATE_TYPE_FAIL_HTLC:
        case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
            break;
        default:
            continue;
        }
        if (p_update->htlc_idx != HtlcIdx) continue;
        return p_update;
    }
    return NULL; 
}


const ln_update_t *ln_update_get_update_del_htlc_const(const ln_update_t *pUpdates, uint16_t HtlcIdx)
{
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        const ln_update_t *p_update = &pUpdates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        switch (p_update->type) {
        case LN_UPDATE_TYPE_FULFILL_HTLC:
        case LN_UPDATE_TYPE_FAIL_HTLC:
        case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
            break;
        default:
            continue;
        }
        if (p_update->htlc_idx != HtlcIdx) continue;
        return p_update;
    }
    return NULL; 
}


#ifdef LN_DBG_PRINT
void ln_update_print(const ln_update_t *pUpdate)
{
    const ln_update_flags_t *p_flags = &pUpdate->flags;
    LOGD("    type=%s\n", ln_update_type_str(pUpdate->type));
    LOGD("    up_send=%d\n", p_flags->up_send);
    LOGD("    up_recv=%d\n", p_flags->up_recv);
    LOGD("    cs_send=%d\n", p_flags->cs_send);
    LOGD("    cs_recv=%d\n", p_flags->cs_recv);
    LOGD("    ra_send=%d\n", p_flags->ra_send);
    LOGD("    ra_recv=%d\n", p_flags->ra_recv);
    LOGD("    fin_type=%s\n", ln_update_type_str(pUpdate->fin_type));
}

void ln_update_updates_print(const ln_update_t *pUpdates)
{
    LOGD("------------------------------------------\n");
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        const ln_update_t *p_update = &pUpdates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        //LOGD("UPDATE[%d]: neighbor_short_channel_id=%016" PRIx64 "(%d)\n",
        //    idx, p_update->neighbor_short_channel_id, p_update->neighbor_idx);
        ln_update_print(p_update);
    }
    LOGD("------------------------------------------\n");
}
#endif
