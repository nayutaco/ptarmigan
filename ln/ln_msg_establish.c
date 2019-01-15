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

#include "btc_buf.h"

#include "ln_msg_establish.h"
#include "ln_misc.h"
#include "ln_local.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_WRITE
#define DBG_PRINT_READ


/********************************************************************
 * const variables
 ********************************************************************/


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool open_channel_check(const ln_msg_open_channel_t *pMsg);
static void open_channel_print(const ln_msg_open_channel_t *pMsg);
static bool accept_channel_check(const ln_msg_accept_channel_t *pMsg);
static void accept_channel_print(const ln_msg_accept_channel_t *pMsg);
static void funding_created_print(const ln_msg_funding_created_t *pMsg);
static void funding_signed_print(const ln_msg_funding_signed_t *pMsg);
static void funding_locked_print(const ln_msg_funding_locked_t *pMsg);
static void channel_reestablish_print(const ln_msg_channel_reestablish_t *pMsg, bool bOptionDataLossProtect);


/********************************************************************
 * open_channel
 ********************************************************************/

bool HIDDEN ln_msg_open_channel_write(utl_buf_t *pBuf, const ln_msg_open_channel_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    open_channel_print(pMsg);
#endif  //DBG_PRINT_WRITE

    if (!open_channel_check(pMsg)) goto LABEL_ERROR;

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_OPEN_CHANNEL)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_chain_hash, BTC_SZ_HASH256)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_temporary_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->funding_satoshis)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->push_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->dust_limit_satoshis)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->max_htlc_value_in_flight_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->channel_reserve_satoshis)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->htlc_minimum_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->feerate_per_kw)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->to_self_delay)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->max_accepted_htlcs)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_funding_pubkey, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_revocation_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_delayed_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_htlc_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_first_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_flags, LN_SZ_CHANNEL_FLAGS)) goto LABEL_ERROR;
    if (pMsg->shutdown_len) {
        if (!btc_buf_w_write_u16be(&buf_w, pMsg->shutdown_len)) goto LABEL_ERROR;
        if (!btc_buf_w_write_data(&buf_w, pMsg->p_shutdown_scriptpubkey, pMsg->shutdown_len)) goto LABEL_ERROR;
    }
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_open_channel_read(ln_msg_open_channel_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_OPEN_CHANNEL) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_chain_hash, (int32_t)BTC_SZ_HASH256)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_temporary_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->funding_satoshis)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->push_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->dust_limit_satoshis)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->max_htlc_value_in_flight_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->channel_reserve_satoshis)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->htlc_minimum_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->feerate_per_kw)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->to_self_delay)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->max_accepted_htlcs)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_funding_pubkey, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_revocation_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_delayed_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_htlc_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_first_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_flags, LN_SZ_CHANNEL_FLAGS)) goto LABEL_ERROR_SYNTAX;
    //XXX: check `option_upfront_shutdown_script`
    pMsg->shutdown_len = 0; //XXX:
    // if (!btc_buf_r_read_u16be(&buf_r, &pMsg->shutdown_len)) goto LABEL_ERROR_SYNTAX;
    // if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_shutdown_scriptpubkey, pMsg->shutdown_len)) goto LABEL_ERROR_SYNTAX;
    if (!open_channel_check(pMsg)) goto LABEL_ERROR;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    open_channel_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;

LABEL_ERROR:
    return false;
}


//XXX:
static bool open_channel_check(const ln_msg_open_channel_t *pMsg)
{
    if (memcmp(gGenesisChainHash, pMsg->p_chain_hash, sizeof(gGenesisChainHash))) {
        LOGD("fail: chain_hash mismatch\n");
        return false;
    }
    if (pMsg->funding_satoshis > (uint64_t)LN_FUNDING_SATOSHIS_MAX) {
        LOGD("fail: large funding_satoshis (%" PRIu64 ")\n", LN_SATOSHI2MSAT(pMsg->funding_satoshis));
        return false;
    }
    if (LN_SATOSHI2MSAT(pMsg->funding_satoshis) < pMsg->push_msat) {
        LOGD("fail: invalid funding_satoshis (%" PRIu64 " < %" PRIu64 ")\n", LN_SATOSHI2MSAT(pMsg->funding_satoshis), pMsg->push_msat);
        return false;
    }
    if (pMsg->max_accepted_htlcs > LN_MAX_ACCEPTED_HTLCS_MAX) {
        LOGD("fail: invalid max_accepted_htlcs\n");
        return false;
    }
    if (!btc_keys_check_pub(pMsg->p_funding_pubkey)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_revocation_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_payment_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_delayed_payment_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_htlc_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_first_per_commitment_point)) goto LABEL_ERROR_INVALID_PUBKEY;
    //XXX: ignore undefined bits
    //if ((pMsg->p_channel_flags[0] & ~CHANNEL_FLAGS_MASK) != 0) {
    //    LOGD("fail: unknown channel_flags: %02x\n", pMsg->p_cahannel_flags[0]);
    //    return false;
    //}
    return true;

LABEL_ERROR_INVALID_PUBKEY:
    LOGD("fail: invalid pubkey\n");
    return false;
}


static void open_channel_print(const ln_msg_open_channel_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[open_channel]-------------------------------\n");
    LOGD("chain_hash: ");
    DUMPD(pMsg->p_chain_hash, BTC_SZ_HASH256);
    LOGD("temporary_channel_id: ");
    DUMPD(pMsg->p_temporary_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("funding_satoshis= %" PRIu64 "\n", pMsg->funding_satoshis);
    LOGD("push_msat= %" PRIu64 "\n", pMsg->push_msat);
    LOGD("dust_limit_satoshis= %" PRIu64 "\n", pMsg->dust_limit_satoshis);
    LOGD("max_htlc_value_in_flight_msat= %" PRIu64 "\n", pMsg->max_htlc_value_in_flight_msat);
    LOGD("channel_reserve_satoshis= %" PRIu64 "\n", pMsg->channel_reserve_satoshis);
    LOGD("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    LOGD("feerate_per_kw= %u\n", pMsg->feerate_per_kw);
    LOGD("to_self_delay= %u\n", pMsg->to_self_delay);
    LOGD("max_accepted_htlcs= %" PRIu16 "\n", pMsg->max_accepted_htlcs);
    LOGD("funding_pubkey: ");
    DUMPD(pMsg->p_funding_pubkey, BTC_SZ_PUBKEY);
    LOGD("revocation_basepoint: ");
    DUMPD(pMsg->p_revocation_basepoint, BTC_SZ_PUBKEY);
    LOGD("payment_basepoint: ");
    DUMPD(pMsg->p_payment_basepoint, BTC_SZ_PUBKEY);
    LOGD("delayed_payment_basepoint: ");
    DUMPD(pMsg->p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    LOGD("htlc_basepoint: ");
    DUMPD(pMsg->p_htlc_basepoint, BTC_SZ_PUBKEY);
    LOGD("first_per_commitment_point: ");
    DUMPD(pMsg->p_first_per_commitment_point, BTC_SZ_PUBKEY);
    LOGD("channel_flags: ");
    DUMPD(pMsg->p_channel_flags, LN_SZ_CHANNEL_FLAGS);
    LOGD("shutdown_scriptpubkey: ");
    DUMPD(pMsg->p_shutdown_scriptpubkey, pMsg->shutdown_len);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * accept_channel
 ********************************************************************/

bool HIDDEN ln_msg_accept_channel_write(utl_buf_t *pBuf, const ln_msg_accept_channel_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    accept_channel_print(pMsg);
#endif  //DBG_PRINT_WRITE

    if (!accept_channel_check(pMsg)) goto LABEL_ERROR;

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_ACCEPT_CHANNEL)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_temporary_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->dust_limit_satoshis)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->max_htlc_value_in_flight_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->channel_reserve_satoshis)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->htlc_minimum_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->minimum_depth)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->to_self_delay)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->max_accepted_htlcs)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_funding_pubkey, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_revocation_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_delayed_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_htlc_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_first_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (pMsg->shutdown_len) {
        if (!btc_buf_w_write_u16be(&buf_w, pMsg->shutdown_len)) goto LABEL_ERROR;
        if (!btc_buf_w_write_data(&buf_w, pMsg->p_shutdown_scriptpubkey, pMsg->shutdown_len)) goto LABEL_ERROR;
    }
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_accept_channel_read(ln_msg_accept_channel_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_ACCEPT_CHANNEL) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_temporary_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->dust_limit_satoshis)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->max_htlc_value_in_flight_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->channel_reserve_satoshis)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->htlc_minimum_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->minimum_depth)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->to_self_delay)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->max_accepted_htlcs)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_funding_pubkey, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_revocation_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_delayed_payment_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_htlc_basepoint, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_first_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    //XXX: check `option_upfront_shutdown_script`
    pMsg->shutdown_len = 0; //XXX:
    // if (!btc_buf_r_read_u16be(&buf_r, &pMsg->shutdown_len)) goto LABEL_ERROR_SYNTAX;
    // if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_shutdown_scriptpubkey, pMsg->shutdown_len)) goto LABEL_ERROR_SYNTAX;
    if (!accept_channel_check(pMsg)) goto LABEL_ERROR;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    accept_channel_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;

LABEL_ERROR:
    return false;
}


//XXX:
static bool accept_channel_check(const ln_msg_accept_channel_t *pMsg)
{
    if (pMsg->max_accepted_htlcs > LN_MAX_ACCEPTED_HTLCS_MAX) {
        LOGD("fail: invalid max_accepted_htlcs\n");
        return false;
    }
    if (!btc_keys_check_pub(pMsg->p_funding_pubkey)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_revocation_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_payment_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_delayed_payment_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_htlc_basepoint)) goto LABEL_ERROR_INVALID_PUBKEY;
    if (!btc_keys_check_pub(pMsg->p_first_per_commitment_point)) goto LABEL_ERROR_INVALID_PUBKEY;
    return true;

LABEL_ERROR_INVALID_PUBKEY:
    LOGD("fail: invalid pubkey\n");
    return false;
}


static void accept_channel_print(const ln_msg_accept_channel_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[accept_channel]-------------------------------\n");
    LOGD("temporary_channel_id: ");
    DUMPD(pMsg->p_temporary_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("dust_limit_satoshis= %" PRIu64 "\n", pMsg->dust_limit_satoshis);
    LOGD("max_htlc_value_in_flight_msat= %" PRIu64 "\n", pMsg->max_htlc_value_in_flight_msat);
    LOGD("channel_reserve_satoshis= %" PRIu64 "\n", pMsg->channel_reserve_satoshis);
    LOGD("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    LOGD("minimum_depth= %u\n", pMsg->minimum_depth);
    LOGD("to_self_delay= %u\n", pMsg->to_self_delay);
    LOGD("max_accepted_htlcs= %u\n", pMsg->max_accepted_htlcs);
    LOGD("funding_pubkey: ");
    DUMPD(pMsg->p_funding_pubkey, BTC_SZ_PUBKEY);
    LOGD("revocation_basepoint: ");
    DUMPD(pMsg->p_revocation_basepoint, BTC_SZ_PUBKEY);
    LOGD("payment_basepoint: ");
    DUMPD(pMsg->p_payment_basepoint, BTC_SZ_PUBKEY);
    LOGD("delayed_payment_basepoint: ");
    DUMPD(pMsg->p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    LOGD("htlc_basepoint: ");
    DUMPD(pMsg->p_htlc_basepoint, BTC_SZ_PUBKEY);
    LOGD("first_per_commitment_point: ");
    DUMPD(pMsg->p_first_per_commitment_point, BTC_SZ_PUBKEY);
    LOGD("shutdown_scriptpubkey: ");
    DUMPD(pMsg->p_shutdown_scriptpubkey, pMsg->shutdown_len);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * funding_created
 ********************************************************************/

bool HIDDEN ln_msg_funding_created_write(utl_buf_t *pBuf, const ln_msg_funding_created_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_created_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_FUNDING_CREATED)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_temporary_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_funding_txid, BTC_SZ_TXID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->funding_output_index)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_funding_created_read(ln_msg_funding_created_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_FUNDING_CREATED) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_temporary_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_funding_txid, BTC_SZ_TXID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->funding_output_index)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_created_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


static void funding_created_print(const ln_msg_funding_created_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[funding_created]-------------------------------\n");
    LOGD("temporary_channel_id: ");
    DUMPD(pMsg->p_temporary_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("funding_txid: ");
    TXIDD(pMsg->p_funding_txid);
    LOGD("funding_output_idx= %u\n", pMsg->funding_output_index);
    LOGD("signature: ");
    DUMPD(pMsg->p_signature, LN_SZ_SIGNATURE);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * funding_signed
 ********************************************************************/

bool HIDDEN ln_msg_funding_signed_write(utl_buf_t *pBuf, const ln_msg_funding_signed_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_signed_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_FUNDING_SIGNED)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_funding_signed_read(ln_msg_funding_signed_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_FUNDING_SIGNED) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_signed_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


static void funding_signed_print(const ln_msg_funding_signed_t *pMsg)
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

bool HIDDEN ln_msg_funding_locked_write(utl_buf_t *pBuf, const ln_msg_funding_locked_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_locked_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_FUNDING_LOCKED)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_next_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_funding_locked_read(ln_msg_funding_locked_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_FUNDING_LOCKED) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_next_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    funding_locked_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


static void funding_locked_print(const ln_msg_funding_locked_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[funding_locked]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("next_per_commitment_point: ");
    DUMPD(pMsg->p_next_per_commitment_point, BTC_SZ_PUBKEY);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * channel_reestablish
 ********************************************************************/

bool HIDDEN ln_msg_channel_reestablish_write(utl_buf_t *pBuf, const ln_msg_channel_reestablish_t *pMsg, bool bOptionDataLossProtect)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_reestablish_print(pMsg, bOptionDataLossProtect);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_CHANNEL_REESTABLISH)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->next_local_commitment_number)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->next_remote_revocation_number)) goto LABEL_ERROR;
    if (bOptionDataLossProtect && pMsg->p_your_last_per_commitment_secret && pMsg->p_my_current_per_commitment_point) {
        if (!btc_buf_w_write_data(&buf_w, pMsg->p_your_last_per_commitment_secret, BTC_SZ_PRIVKEY)) goto LABEL_ERROR;
        if (!btc_buf_w_write_data(&buf_w, pMsg->p_my_current_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    }
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_channel_reestablish_read(ln_msg_channel_reestablish_t *pMsg, const uint8_t *pData, uint16_t Len, bool bOptionDataLossProtect)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_CHANNEL_REESTABLISH) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->next_local_commitment_number)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->next_remote_revocation_number)) goto LABEL_ERROR_SYNTAX;
    if (bOptionDataLossProtect && btc_buf_r_remains(&buf_r) >= BTC_SZ_PRIVKEY + BTC_SZ_PUBKEY) {
        if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_your_last_per_commitment_secret, (int32_t)BTC_SZ_PRIVKEY)) goto LABEL_ERROR_SYNTAX;
        if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_my_current_per_commitment_point, (int32_t)BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;

    } else {
        pMsg->p_your_last_per_commitment_secret = NULL;
        pMsg->p_my_current_per_commitment_point = NULL;
    }


#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_reestablish_print(pMsg, bOptionDataLossProtect);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


static void channel_reestablish_print(const ln_msg_channel_reestablish_t *pMsg, bool bOptionDataLossProtect)
{
#ifdef PTARM_DEBUG
    LOGD("-[channel_reestablish]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("next_local_commitment_number: %" PRIu64 "\n", pMsg->next_local_commitment_number);
    LOGD("next_remote_revocation_number: %" PRIu64 "\n", pMsg->next_remote_revocation_number);
    if (bOptionDataLossProtect && pMsg->p_your_last_per_commitment_secret && pMsg->p_my_current_per_commitment_point) {
        LOGD("your_last_per_commitment_secret: ");
        DUMPD(pMsg->p_your_last_per_commitment_secret, BTC_SZ_PRIVKEY);
        LOGD("my_current_per_commitment_point: ");
        DUMPD(pMsg->p_my_current_per_commitment_point, BTC_SZ_PUBKEY);
    }
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
