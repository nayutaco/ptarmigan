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
/** @file   ln_msg_establish.c
 *  @brief  [LN]Establish関連
 *  @sa     https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#channel-establishment
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

#include "utl_int.h"

#include "ln_msg_establish.h"
#include "ln_misc.h"
#include "ln_local.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_CREATE
#define DBG_PRINT_READ


/********************************************************************
 * const variables
 ********************************************************************/


/**************************************************************************
 * prototypes
 **************************************************************************/

static void open_channel_print(const ln_open_channel_t *pMsg);
static void accept_channel_print(const ln_accept_channel_t *pMsg);
static void funding_created_print(const ln_funding_created_t *pMsg);
static void funding_signed_print(const ln_funding_signed_t *pMsg);
static void funding_locked_print(const ln_funding_locked_t *pMsg);
static void channel_reestablish_print(const ln_channel_reestablish_t *pMsg);


/********************************************************************
 * open_channel
 ********************************************************************/

bool HIDDEN ln_msg_open_channel_write(utl_buf_t *pBuf, const ln_open_channel_t *pMsg)
{
    //    type: 32 (open_channel)
    //    data:
    //        [32:chain_hash]
    //        [32:temporary_channel_id]
    //        [8:funding_satoshis]
    //        [8:push_msat]
    //        [8:dust_limit_satoshis]
    //        [8:max_htlc_value_in_flight_msat]
    //        [8:channel_reserve_satoshis]
    //        [8:htlc_minimum_msat]
    //        [4:feerate_per_kw]
    //        [2:to_self_delay]
    //        [2:max_accepted_htlcs]
    //        [33:funding_pubkey]
    //        [33:revocation_basepoint]
    //        [33:payment_basepoint]
    //        [33:delayed_payment_basepoint]
    //        [33:htlc_basepoint]
    //        [33:first_per_commitment_point]
    //        [1:channel_flags]

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    open_channel_print(pMsg);
#endif  //DBG_PRINT_CREATE

    if ( (pMsg->funding_sat >= (uint64_t)16777216) ||
         (LN_SATOSHI2MSAT(pMsg->funding_sat) < pMsg->push_msat) ||
         (pMsg->max_accepted_htlcs > 483) ) {
        LOGD("fail: invalid parameter(%" PRIu64 ", %" PRIu64 ")\n", LN_SATOSHI2MSAT(pMsg->funding_sat), pMsg->push_msat);
        return false;
    }

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 319);

    //type: 0x20 (open_channel)
    ln_misc_push16be(&proto, MSGTYPE_OPEN_CHANNEL);

    //        [32:chain_hash]
    utl_push_data(&proto, gGenesisChainHash, sizeof(gGenesisChainHash));

    //        [32:temporary_channel_id]
    utl_push_data(&proto, pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:funding_satoshis]
    ln_misc_push64be(&proto, pMsg->funding_sat);

    //        [8:push_msat]
    ln_misc_push64be(&proto, pMsg->push_msat);

    //        [8:push_msat]
    ln_misc_push64be(&proto, pMsg->dust_limit_sat);

    //        [8:max_htlc_value_in_flight_msat]
    ln_misc_push64be(&proto, pMsg->max_htlc_value_in_flight_msat);

    //        [8:channel_reserve_satoshis]
    ln_misc_push64be(&proto, pMsg->channel_reserve_sat);

    //        [8:htlc_minimum_msat]
    ln_misc_push64be(&proto, pMsg->htlc_minimum_msat);

    //        [4:feerate_per_kw]
    ln_misc_push32be(&proto, pMsg->feerate_per_kw);

    //        [2:to_self_delay]
    ln_misc_push16be(&proto, pMsg->to_self_delay);

    //        [2:max_accepted_htlcs]
    ln_misc_push16be(&proto, pMsg->max_accepted_htlcs);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //        [33:funding_pubkey]
        //        [33:revocation_basepoint]
        //        [33:payment_basepoint]
        //        [33:delayed_payment_basepoint]
        //        [33:htlc_basepoint]
        //        [33:first_per_commitment_point]
        if (!btc_keys_check_pub(pMsg->p_pubkeys[lp])) {
            LOGD("fail: check pubkey\n");
            return false;
        }
        utl_push_data(&proto, pMsg->p_pubkeys[lp], BTC_SZ_PUBKEY);
    }

    //        [1:channel_flags]
    ln_misc_push8(&proto, pMsg->channel_flags);

    assert(sizeof(uint16_t) + 319 == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_open_channel_read(ln_open_channel_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 319) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_OPEN_CHANNEL) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:chain_hash]
    int cmp = memcmp(gGenesisChainHash, pData + pos, sizeof(gGenesisChainHash));
    if (cmp != 0) {
        LOGD("fail: chain-hash mismatch\n");
        return false;
    }
    pos += sizeof(gGenesisChainHash);

    //        [32:temporary_channel_id]
    memcpy(pMsg->p_temp_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:funding_satoshis]
    pMsg->funding_sat = utl_int_pack_u64be(pData + pos);
    if (pMsg->funding_sat >= (uint64_t)16777216) {
        LOGD("fail: large funding-satoshis (%" PRIu64 ")\n", LN_SATOSHI2MSAT(pMsg->funding_sat));
        return false;
    }
    pos += sizeof(uint64_t);

    //        [8:push_msat]
    pMsg->push_msat = utl_int_pack_u64be(pData + pos);
    if (LN_SATOSHI2MSAT(pMsg->funding_sat) < pMsg->push_msat) {
        LOGD("fail: invalid funding-satoshis (%" PRIu64 " < %" PRIu64 ")\n", LN_SATOSHI2MSAT(pMsg->funding_sat), pMsg->push_msat);
        return false;
    }
    pos += sizeof(uint64_t);

    //        [8:dust_limit_satoshis]
    pMsg->dust_limit_sat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:max_htlc_value_in_flight_msat]
    pMsg->max_htlc_value_in_flight_msat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:channel_reserve_satoshis]
    pMsg->channel_reserve_sat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:htlc_minimum_msat]
    pMsg->htlc_minimum_msat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [4:feerate_per_kw]
    pMsg->feerate_per_kw = utl_int_pack_u32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [2:to_self_delay]
    pMsg->to_self_delay = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [2:max_accepted_htlcs]
    pMsg->max_accepted_htlcs = utl_int_pack_u16be(pData + pos);
    if (pMsg->max_accepted_htlcs > 483) {
        LOGD("fail: invalid max-accepted-htlcs\n");
        return false;
    }
    pos += sizeof(uint16_t);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //        [33:funding_pubkey]
        //        [33:revocation_basepoint]
        //        [33:payment_basepoint]
        //        [33:delayed_payment_basepoint]
        //        [33:htlc_basepoint]
        //        [33:first_per_commitment_point]
        if (!btc_keys_check_pub(pData + pos)) {
            LOGD("fail: check pubkey: %d\n", lp);
            DUMPD(pData + pos, BTC_SZ_PUBKEY);
            return false;
        }
        memcpy(pMsg->p_pubkeys[lp], pData + pos, BTC_SZ_PUBKEY);
        pos += BTC_SZ_PUBKEY;
    }

    //        [1:channel_flags]
    pMsg->channel_flags = *(pData + pos);
    if ((pMsg->channel_flags & ~CHANNEL_FLAGS_MASK) != 0) {
        LOGD("fail: unknown channel_flags: %02x\n", pMsg->channel_flags);
        return false;
    }
    pos++;

    //        [2:shutdown_len] (option_upfront_shutdown_script)
    uint16_t shutdown_len = 0;
    if (Len - pos >= (int)sizeof(uint16_t)) {
        shutdown_len = utl_int_pack_u16be(pData + pos);
        pos += sizeof(uint16_t);
        LOGD("shutdown_len= %" PRIu16 "\n", shutdown_len);
    }
    //        [shutdown_len: shutdown_scriptpubkey] (option_upfront_shutdown_script)
    if (Len - pos >= shutdown_len) {
        LOGD("shutdown_scriptpubkey= ");
        DUMPD(pData, shutdown_len);
        pos += shutdown_len;
    }

    assert(Len >= pos);

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    open_channel_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void open_channel_print(const ln_open_channel_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[open_channel]-------------------------------\n");
    LOGD("temporary_channel_id: ");
    DUMPD(pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("funding_sat= %" PRIu64 "\n", pMsg->funding_sat);
    LOGD("push_msat= %" PRIu64 "\n", pMsg->push_msat);
    LOGD("dust_limit_sat= %" PRIu64 "\n", pMsg->dust_limit_sat);
    LOGD("max_htlc_value_in_flight_msat= %" PRIu64 "\n", pMsg->max_htlc_value_in_flight_msat);
    LOGD("channel_reserve_sat= %" PRIu64 "\n", pMsg->channel_reserve_sat);
    LOGD("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    LOGD("feerate_per_kw= %" PRIu32 "\n", pMsg->feerate_per_kw);
    LOGD("to_self_delay= %u\n", pMsg->to_self_delay);
    LOGD("max_accepted_htlcs= %u\n", pMsg->max_accepted_htlcs);
    LOGD("p_funding_pubkey        : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_FUNDING], BTC_SZ_PUBKEY);
    LOGD("p_revocation_basept     : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_REVOCATION], BTC_SZ_PUBKEY);
    LOGD("p_payment_basept        : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_PAYMENT], BTC_SZ_PUBKEY);
    LOGD("p_delayed_payment_basept: ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_DELAYED], BTC_SZ_PUBKEY);
    LOGD("p_htlc_basept           : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_HTLC], BTC_SZ_PUBKEY);
    LOGD("p_first_per_commitpt    : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    LOGD("channel_flags           : %02x\n", pMsg->channel_flags);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * accept_channel
 ********************************************************************/

bool HIDDEN ln_msg_accept_channel_write(utl_buf_t *pBuf, const ln_accept_channel_t *pMsg)
{
    //    type: 33 (accept_channel)
    //    data:
    //        [32:temporary_channel_id]
    //        [8:dust_limit_satoshis]
    //        [8:max_htlc_value_in_flight_msat]
    //        [8:channel_reserve_satoshis]
    //        [8:htlc_minimum_msat]
    //        [4:minimum_depth]
    //        [2:to_self_delay]
    //        [2:max_accepted_htlcs]
    //        [33:funding_pubkey]
    //        [33:revocation_basepoint]
    //        [33:payment_basepoint]
    //        [33:delayed_payment_basepoint]
    //        [33:htlc_basepoint]
    //        [33:first_per_commitment_point]

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    accept_channel_print(pMsg);
#endif  //DBG_PRINT_CREATE

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 270);

    //type: 0x21 (accept_channel)
    ln_misc_push16be(&proto, MSGTYPE_ACCEPT_CHANNEL);

    //        [32:temporary_channel_id]
    utl_push_data(&proto, pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:dust_limit_satoshis]
    ln_misc_push64be(&proto, pMsg->dust_limit_sat);

    //        [8:max_htlc_value_in_flight_msat]
    ln_misc_push64be(&proto, pMsg->max_htlc_value_in_flight_msat);

    //        [8:channel_reserve_satoshis]
    ln_misc_push64be(&proto, pMsg->channel_reserve_sat);

    //        [8:htlc_minimum_msat]
    ln_misc_push64be(&proto, pMsg->htlc_minimum_msat);

    //        [4:minimum_depth]
    ln_misc_push32be(&proto, pMsg->min_depth);

    //        [2:to_self_delay]
    ln_misc_push16be(&proto, pMsg->to_self_delay);

    //        [2:max_accepted_htlcs]
    ln_misc_push16be(&proto, pMsg->max_accepted_htlcs);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //        [33:funding_pubkey]
        //        [33:revocation_basepoint]
        //        [33:payment_basepoint]
        //        [33:delayed_payment_basepoint]
        //        [33:htlc_basepoint]
        //        [33:first_per_commitment_point]
        if (!btc_keys_check_pub(pMsg->p_pubkeys[lp])) {
            LOGD("fail: check pubkey\n");
            return false;
        }
        utl_push_data(&proto, pMsg->p_pubkeys[lp], BTC_SZ_PUBKEY);
    }

    assert(sizeof(uint16_t) + 270 == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_accept_channel_read(ln_accept_channel_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 270) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_ACCEPT_CHANNEL) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:temporary_channel_id]
    memcpy(pMsg->p_temp_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:dust_limit_satoshis]
    pMsg->dust_limit_sat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:max_htlc_value_in_flight_msat]
    pMsg->max_htlc_value_in_flight_msat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:channel_reserve_satoshis]
    pMsg->channel_reserve_sat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:htlc_minimum_msat]
    pMsg->htlc_minimum_msat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [4:minimum_depth]
    pMsg->min_depth = utl_int_pack_u32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [2:to_self_delay]
    pMsg->to_self_delay = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [2:max_accepted_htlcs]
    pMsg->max_accepted_htlcs = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //        [33:funding_pubkey]
        //        [33:revocation_basepoint]
        //        [33:payment_basepoint]
        //        [33:delayed_payment_basepoint]
        //        [33:htlc_basepoint]
        //        [33:first_per_commitment_point]
        if (!btc_keys_check_pub(pData + pos)) {
            LOGD("fail: check pubkey\n");
            return false;
        }
        memcpy(pMsg->p_pubkeys[lp], pData + pos, BTC_SZ_PUBKEY);
        pos += BTC_SZ_PUBKEY;
    }

    //        [2:shutdown_len] (option_upfront_shutdown_script)
    uint16_t shutdown_len = 0;
    if (Len - pos >= (int)sizeof(uint16_t)) {
        shutdown_len = utl_int_pack_u16be(pData + pos);
        pos += sizeof(uint16_t);
        LOGD("shutdown_len= %" PRIu16 "\n", shutdown_len);
    }
    //        [shutdown_len: shutdown_scriptpubkey] (option_upfront_shutdown_script)
    if (Len - pos >= shutdown_len) {
        LOGD("shutdown_scriptpubkey= ");
        DUMPD(pData, shutdown_len);
        pos += shutdown_len;
    }

    assert(Len >= pos);

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    accept_channel_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void accept_channel_print(const ln_accept_channel_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[accept_channel]-------------------------------\n");
    LOGD("temporary_channel_id: ");
    DUMPD(pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("dust_limit_sat= %" PRIu64 "\n", pMsg->dust_limit_sat);
    LOGD("max_htlc_value_in_flight_msat= %" PRIu64 "\n", pMsg->max_htlc_value_in_flight_msat);
    LOGD("channel_reserve_sat= %" PRIu64 "\n", pMsg->channel_reserve_sat);
    LOGD("min_depth= %" PRIu32 "\n", pMsg->min_depth);
    LOGD("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    LOGD("to_self_delay= %u\n", pMsg->to_self_delay);
    LOGD("max_accepted_htlcs= %u\n", pMsg->max_accepted_htlcs);
    LOGD("p_funding_pubkey        : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_FUNDING], BTC_SZ_PUBKEY);
    LOGD("p_revocation_basept     : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_REVOCATION], BTC_SZ_PUBKEY);
    LOGD("p_payment_basept        : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_PAYMENT], BTC_SZ_PUBKEY);
    LOGD("p_delayed_payment_basept: ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_DELAYED], BTC_SZ_PUBKEY);
    LOGD("p_htlc_basept           : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_HTLC], BTC_SZ_PUBKEY);
    LOGD("p_first_per_commitpt    : ");
    DUMPD(pMsg->p_pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * funding_created
 ********************************************************************/

bool HIDDEN ln_msg_funding_created_write(utl_buf_t *pBuf, const ln_funding_created_t *pMsg)
{
    //    type: 34 (funding_created)
    //    data:
    //        [32:temporary_channel_id]
    //        [32:funding_txid]
    //        [2:funding_output_index]
    //        [64:signature]

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_created_print(pMsg);
#endif  //DBG_PRINT_CREATE

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 130);

    //    type: 0x22 (funding_created)
    ln_misc_push16be(&proto, MSGTYPE_FUNDING_CREATED);

    //        [32:temporary_channel_id]
    utl_push_data(&proto, pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);

    //        [32:funding_txid]
    // BE変換
#if 0
    uint8_t txid[BTC_SZ_TXID];
    for (int lp = 0; lp < BTC_SZ_TXID; lp++) {
        txid[lp] = pMsg->p_funding_txid[BTC_SZ_TXID - lp - 1];
    }
    utl_push_data(&proto, txid, BTC_SZ_TXID);
#else
    //そのまま
    utl_push_data(&proto, pMsg->p_funding_txid, BTC_SZ_TXID);
#endif

    //        [2:funding_output_index]
    ln_misc_push16be(&proto, pMsg->funding_output_idx);

    //        [64:signature]
    utl_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 130 == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_funding_created_read(ln_funding_created_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 130) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_FUNDING_CREATED) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:temporary_channel_id]
    memcpy(pMsg->p_temp_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [32:funding_txid]
#if 0
    // LE変換
    for (int lp = 0; lp < BTC_SZ_TXID; lp++) {
        pMsg->p_funding_txid[lp] = *(pData + pos + BTC_SZ_TXID - lp - 1);
    }
#else
    //そのまま
    memcpy(pMsg->p_funding_txid, pData + pos, BTC_SZ_TXID);
#endif
    pos += BTC_SZ_TXID;

    //        [2:funding_output_index]
    pMsg->funding_output_idx = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [64:signature]
    memcpy(pMsg->p_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    assert(Len >= pos);

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_created_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void funding_created_print(const ln_funding_created_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[funding_created]-------------------------------\n");
    LOGD("temporary_channel_id: ");
    DUMPD(pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("p_funding_txid: ");
    TXIDD(pMsg->p_funding_txid);
    LOGD("funding_output_idx= %lu\n", (unsigned long)pMsg->funding_output_idx);
    LOGD("signature: ");
    DUMPD(pMsg->p_signature, LN_SZ_SIGNATURE);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * funding_signed
 ********************************************************************/

bool HIDDEN ln_msg_funding_signed_write(utl_buf_t *pBuf, const ln_funding_signed_t *pMsg)
{
    //    type: 35 (funding_signed)
    //    data:
    //        [32:channel_id]
    //        [64:signature]

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_signed_print(pMsg);
#endif  //DBG_PRINT_CREATE

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 96);

    //    type: 0x23 (funding_signed)
    ln_misc_push16be(&proto, MSGTYPE_FUNDING_SIGNED);

    //        [32:channel_id]
    utl_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [64:signature]
    utl_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 96 == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_funding_signed_read(ln_funding_signed_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 96) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_FUNDING_SIGNED) {
        LOGD("fail: invalid parameter\n");
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel_id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [64:signature]
    memcpy(pMsg->p_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    assert(Len >= pos);

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_signed_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void funding_signed_print(const ln_funding_signed_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[funding_signed]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("signature: ");
    DUMPD(pMsg->p_signature, LN_SZ_SIGNATURE);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * funding_locked
 ********************************************************************/

bool HIDDEN ln_msg_funding_locked_write(utl_buf_t *pBuf, const ln_funding_locked_t *pMsg)
{
    //    type: 36 (funding_locked)
    //    data:
    //        [32:channel_id]
    //        [33:next_per_commitment_point]

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_locked_print(pMsg);
#endif  //DBG_PRINT_CREATE

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 65);

    //    type: 0x24 (funding_locked)
    ln_misc_push16be(&proto, MSGTYPE_FUNDING_LOCKED);

    //        [32:channel_id]
    utl_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [33:next_per_commitment_point]
    utl_push_data(&proto, pMsg->p_per_commitpt, BTC_SZ_PUBKEY);

    assert(sizeof(uint16_t) + 65 == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_funding_locked_read(ln_funding_locked_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 65) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_FUNDING_LOCKED) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel_id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [33:next_per_commitment_point]
    memcpy(pMsg->p_per_commitpt, pData + pos, BTC_SZ_PUBKEY);
    pos += BTC_SZ_PUBKEY;

    assert(Len >= pos);

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_locked_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void funding_locked_print(const ln_funding_locked_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[funding_locked]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("p_per_commitpt: ");
    DUMPD(pMsg->p_per_commitpt, BTC_SZ_PUBKEY);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * channel_reestablish
 ********************************************************************/

bool HIDDEN ln_msg_channel_reestablish_write(utl_buf_t *pBuf, const ln_channel_reestablish_t *pMsg)
{
    //    type: 136 (channel_reestablish)
    //    data:
    //        [32:channel_id]
    //        [8:next_local_commitment_number]
    //        [8:next_remote_revocation_number]
    //        [32:your_last_per_commitment_secret] (option_data_loss_protect)
    //        [33:my_current_per_commitment_point] (option_data_loss_protect)

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_reestablish_print(pMsg);
#endif  //DBG_PRINT_CREATE
    uint32_t len = sizeof(uint16_t) + 48;
    if (pMsg->option_data_loss_protect) {
        len += 65;
    }

    utl_push_init(&proto, pBuf, len);

    //    type: 136 (channel_reestablish)
    ln_misc_push16be(&proto, MSGTYPE_CHANNEL_REESTABLISH);

    //        [32:channel_id]
    utl_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:next_local_commitment_number]
    ln_misc_push64be(&proto, pMsg->next_local_commitment_number);

    //        [8:next_remote_revocation_number]
    ln_misc_push64be(&proto, pMsg->next_remote_revocation_number);

    if (pMsg->option_data_loss_protect) {
        //        [32:your_last_per_commitment_secret]
        utl_push_data(&proto, pMsg->p_your_last_per_commitment_secret, BTC_SZ_PRIVKEY);
        //        [33:my_current_per_commitment_point]
        utl_push_data(&proto, pMsg->p_my_current_per_commitment_point, BTC_SZ_PUBKEY);
    }

    assert(len == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_channel_reestablish_read(ln_channel_reestablish_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 48) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }
    pMsg->option_data_loss_protect = (Len >= sizeof(uint16_t) + 113);

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_CHANNEL_REESTABLISH) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel_id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:next_local_commitment_number]
    pMsg->next_local_commitment_number = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:next_remote_revocation_number]
    pMsg->next_remote_revocation_number = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    if (pMsg->option_data_loss_protect) {
        //[32:your_last_per_commitment_secret] (option_data_loss_protect)
        if (Len >= pos + BTC_SZ_PRIVKEY) {
            memcpy(pMsg->p_your_last_per_commitment_secret, pData + pos, BTC_SZ_PRIVKEY);
            pos += BTC_SZ_PRIVKEY;
        }

        //[33:my_current_per_commitment_point] (option_data_loss_protect)
        if (Len >= pos + BTC_SZ_PUBKEY) {
            memcpy(pMsg->p_my_current_per_commitment_point, pData + pos, BTC_SZ_PUBKEY);
            pos += BTC_SZ_PUBKEY;
        }
    }

    assert(Len >= pos);

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_reestablish_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void channel_reestablish_print(const ln_channel_reestablish_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[channel_reestablish]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("next_local_commitment_number: %" PRIu64 "\n", pMsg->next_local_commitment_number);
    LOGD("next_remote_revocation_number: %" PRIu64 "\n", pMsg->next_remote_revocation_number);
    if (pMsg->option_data_loss_protect) {
        LOGD("your_last_per_commitment_secret: ");
        DUMPD(pMsg->p_your_last_per_commitment_secret, BTC_SZ_PRIVKEY);
        LOGD("my_current_per_commitment_point: ");
        DUMPD(pMsg->p_my_current_per_commitment_point, BTC_SZ_PUBKEY);
    }
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
