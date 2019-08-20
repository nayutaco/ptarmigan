/*
 *  Copyright (C) 2017 Ptarmigan Project
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
/** @file   ln_msg_normalope.c
 *  @brief  [LN]Normal Operation関連
 *  @sa     https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#normal-operation
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "utl_dbg.h"
#include "utl_int.h"

#include "btc_crypto.h"
#include "btc_buf.h"

#include "ln_msg_normalope.h"
#include "ln_local.h"
#include "ln_msg.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_WRITE
#define DBG_PRINT_READ


/**************************************************************************
 * prototypes
 **************************************************************************/

static void update_add_htlc_print(const ln_msg_update_add_htlc_t *pMsg);
static void update_fulfill_htlc_print(const ln_msg_update_fulfill_htlc_t *pMsg);
static void update_fail_htlc_print(const ln_msg_update_fail_htlc_t *pMsg);
static void update_fail_malformed_htlc_print(const ln_msg_update_fail_malformed_htlc_t *pMsg);
static void commitment_signed_print(const ln_msg_commitment_signed_t *pMsg);
static void revoke_and_ack_print(const ln_msg_revoke_and_ack_t *pMsg);
static void update_fee_print(const ln_msg_update_fee_t *pMsg);


/********************************************************************
 * update_add_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_add_htlc_write(utl_buf_t *pBuf, const ln_msg_update_add_htlc_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_add_htlc_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_UPDATE_ADD_HTLC)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->id)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->amount_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_payment_hash, BTC_SZ_HASH256)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->cltv_expiry)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_onion_routing_packet, LN_SZ_ONION_ROUTE)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_update_add_htlc_read(ln_msg_update_add_htlc_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_UPDATE_ADD_HTLC) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->id)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->amount_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_payment_hash, BTC_SZ_HASH256)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->cltv_expiry)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_onion_routing_packet, LN_SZ_ONION_ROUTE)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_add_htlc_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void update_add_htlc_print(const ln_msg_update_add_htlc_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[update_add_htlc]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("id: %" PRIu64 "\n", pMsg->id);
    LOGD("amount_msat: %" PRIu64 "\n", pMsg->amount_msat);
    LOGD("payment_hash: ");
    DUMPD(pMsg->p_payment_hash, BTC_SZ_HASH256);
    LOGD("cltv_expiry: %u\n", pMsg->cltv_expiry);
    LOGD("onion_routing_packet(top 34bytes only): ");
    DUMPD(pMsg->p_onion_routing_packet, 34);
    LOGD("--------------------------------\n");
#else
    (void)pMsg;
#endif  //PTARM_DEBUG
}


/********************************************************************
 * update_fulfill_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_fulfill_htlc_write(utl_buf_t *pBuf, const ln_msg_update_fulfill_htlc_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fulfill_htlc_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_UPDATE_FULFILL_HTLC)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->id)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_payment_preimage, BTC_SZ_PRIVKEY)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_update_fulfill_htlc_read(ln_msg_update_fulfill_htlc_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_UPDATE_FULFILL_HTLC) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->id)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_payment_preimage, BTC_SZ_PRIVKEY)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fulfill_htlc_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void update_fulfill_htlc_print(const ln_msg_update_fulfill_htlc_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[update_fulfill_htlc]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("id: %" PRIu64 "\n", pMsg->id);
    //LOGD("p_payment_preimage: ");
    //DUMPD(pMsg->p_payment_preimage, BTC_SZ_PRIVKEY);
    LOGD("p_payment_preimage: ???\n");
    LOGD("--------------------------------\n");
#else
    (void)pMsg;
#endif  //PTARM_DEBUG
}


/********************************************************************
 * update_fail_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_fail_htlc_write(utl_buf_t *pBuf, const ln_msg_update_fail_htlc_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fail_htlc_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_UPDATE_FAIL_HTLC)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->id)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->len)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_reason, pMsg->len)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_update_fail_htlc_read(ln_msg_update_fail_htlc_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_UPDATE_FAIL_HTLC) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->id)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->len)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_reason, pMsg->len)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fail_htlc_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void update_fail_htlc_print(const ln_msg_update_fail_htlc_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[update_fail_htlc]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("id: %" PRIu64 "\n", pMsg->id);
    LOGD("reason: ");
    DUMPD(pMsg->p_reason, pMsg->len);
    LOGD("--------------------------------\n");
#else
    (void)pMsg;
#endif  //PTARM_DEBUG
}


/********************************************************************
 * update_fail_malformed_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_fail_malformed_htlc_write(utl_buf_t *pBuf, const ln_msg_update_fail_malformed_htlc_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fail_malformed_htlc_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->id)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_sha256_of_onion, BTC_SZ_HASH256)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->failure_code)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_update_fail_malformed_htlc_read(ln_msg_update_fail_malformed_htlc_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->id)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_sha256_of_onion, BTC_SZ_HASH256)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->failure_code)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fail_malformed_htlc_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void update_fail_malformed_htlc_print(const ln_msg_update_fail_malformed_htlc_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[update_fail_malformed_htlc]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("id: %" PRIu64 "\n", pMsg->id);
    LOGD("sha256_of_onion: ");
    DUMPD(pMsg->p_sha256_of_onion, BTC_SZ_HASH256);
    LOGD("failure_code: %04x\n", pMsg->failure_code);
    LOGD("--------------------------------\n");
#else
    (void)pMsg;
#endif  //PTARM_DEBUG
}


/********************************************************************
 * commitment_signed
 ********************************************************************/

bool HIDDEN ln_msg_commitment_signed_write(utl_buf_t *pBuf, const ln_msg_commitment_signed_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    commitment_signed_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_COMMITMENT_SIGNED)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->num_htlcs)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_htlc_signature, pMsg->num_htlcs * LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_commitment_signed_read(ln_msg_commitment_signed_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_COMMITMENT_SIGNED) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->num_htlcs)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_htlc_signature, pMsg->num_htlcs * LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    commitment_signed_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void commitment_signed_print(const ln_msg_commitment_signed_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[commitment_signed]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("signature: ");
    DUMPD(pMsg->p_signature, LN_SZ_SIGNATURE);
    LOGD("num_htlc: %lu\n", pMsg->num_htlcs);
    for (int lp = 0; lp < pMsg->num_htlcs; lp++) {
        LOGD("htlc_signature[%d]: ", lp);
        DUMPD(pMsg->p_htlc_signature + lp * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
    }
    LOGD("--------------------------------\n");
#else
    (void)pMsg;
#endif  //PTARM_DEBUG
}


/********************************************************************
 * revoke_and_ack
 ********************************************************************/

bool HIDDEN ln_msg_revoke_and_ack_write(utl_buf_t *pBuf, const ln_msg_revoke_and_ack_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    revoke_and_ack_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_REVOKE_AND_ACK)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_per_commitment_secret, BTC_SZ_PRIVKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_next_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_revoke_and_ack_read(ln_msg_revoke_and_ack_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_REVOKE_AND_ACK) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_per_commitment_secret, BTC_SZ_PRIVKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_next_per_commitment_point, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    revoke_and_ack_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void revoke_and_ack_print(const ln_msg_revoke_and_ack_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[revoke_and_ack]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    //LOGD("per_commitment_secret: ");
    //DUMPD(pMsg->p_per_commitment_secret, BTC_SZ_PRIVKEY);
    LOGD("per_commitment_secret: ???\n");
    LOGD("next_per_commitment_point: ");
    DUMPD(pMsg->p_next_per_commitment_point, BTC_SZ_PUBKEY);
    LOGD("--------------------------------\n");
#else
    (void)pMsg;
#endif  //PTARM_DEBUG
}


/********************************************************************
 * update_fee
 ********************************************************************/

bool HIDDEN ln_msg_update_fee_write(utl_buf_t *pBuf, const ln_msg_update_fee_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fee_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_UPDATE_FEE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->feerate_per_kw)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_UPDATE_FEE) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->feerate_per_kw)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    update_fee_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void update_fee_print(const ln_msg_update_fee_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[update_fee]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("feerate_per_kw: %u\n", pMsg->feerate_per_kw);
    LOGD("--------------------------------\n");
#else
    (void)pMsg;
#endif  //PTARM_DEBUG
}
