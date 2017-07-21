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
/** @file   ln_msg_normalope.c
 *  @brief  [LN]Normal Operation関連
 *  @author ueno@nayuta.co
 *  @sa     https://github.com/nayuta-ueno/lightning-rfc/blob/master/02-peer-protocol.md#normal-operation
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "ln_msg_normalope.h"
#include "ln_misc.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_CREATE
#define DBG_PRINT_READ


/**************************************************************************
 * prototypes
 **************************************************************************/

static void update_add_htlc_print(const ln_update_add_htlc_t *pMsg);
static void update_fulfill_htlc_print(const ln_update_fulfill_htlc_t *pMsg);
static void update_fail_htlc_print(const ln_update_fail_htlc_t *pMsg);
static void update_fail_malformed_htlc_print(const ln_update_fail_malformed_htlc_t *pMsg);
static void commit_signed_print(const ln_commit_signed_t *pMsg);
static void revoke_and_ack_print(const ln_revoke_and_ack_t *pMsg);
static void update_fee_print(const ln_update_fee_t *pMsg);


/********************************************************************
 * update_add_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_add_htlc_create(ucoin_buf_t *pBuf, const ln_update_add_htlc_t *pMsg)
{
    //    type: 128 (update_add_htlc)
    //    data:
    //        [32:channel-id]
    //        [8:id]
    //        [8:amount-msat]
    //        [4:cltv-expiry]
    //        [32:payment-hash]
    //        [1366:onion-routing-packet]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_add_htlc_print(pMsg);
#endif  //DBG_PRINT_CREATE

    if (pMsg->cltv_expiry >= (uint32_t)500000000) {
        DBG_PRINTF("fail: expiry >= 500000000\n");
        return false;
    }

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 1450);

    //    type: 128 (update_add_htlc)
    ln_misc_push16be(&proto, MSGTYPE_UPDATE_ADD_HTLC);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:id]
    ln_misc_push64be(&proto, pMsg->id);

    //        [8:amount-msat]
    ln_misc_push64be(&proto, pMsg->amount_msat);

    //        [32:payment-hash]
    ucoin_push_data(&proto, pMsg->payment_sha256, LN_SZ_HASH);

    //        [4:cltv-expiry]
    ln_misc_push32be(&proto, pMsg->cltv_expiry);

    //        [1366:onion-routing-packet]
    ucoin_push_data(&proto, pMsg->p_onion_route, LN_SZ_ONION_ROUTE);

    assert(sizeof(uint16_t) + 1450 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_update_add_htlc_read(ln_update_add_htlc_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 1450) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_UPDATE_ADD_HTLC) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    pMsg->flag = LN_HTLC_FLAG_RECV;

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:id]
    pMsg->id = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [8:amount-msat]
    pMsg->amount_msat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [32:payment-hash]
    memcpy(pMsg->payment_sha256, pData + pos, LN_SZ_HASH);
    pos += LN_SZ_HASH;

    //        [4:cltv-expiry]
    pMsg->cltv_expiry = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [1366:onion-routing-packet]
    memcpy(pMsg->p_onion_route, pData + pos, LN_SZ_ONION_ROUTE);
    pos += LN_SZ_ONION_ROUTE;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_add_htlc_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void update_add_htlc_print(const ln_update_add_htlc_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[update_add_htlc]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("id: %" PRIx64 "\n", pMsg->id);
    DBG_PRINTF2("amount_msat: %" PRIu64 "\n", pMsg->amount_msat);
    DBG_PRINTF2("cltv_expiry: %u\n", pMsg->cltv_expiry);
    DBG_PRINTF2("payment_sha256: ");
    DUMPBIN(pMsg->payment_sha256, LN_SZ_HASH);
//    DBG_PRINTF2("p_onion_route: ");
//    DUMPBIN(pMsg->p_onion_route, LN_SZ_ONION_ROUTE);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * update_fulfill_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_fulfill_htlc_create(ucoin_buf_t *pBuf, const ln_update_fulfill_htlc_t *pMsg)
{
//    type: 130 (update_fulfill_htlc)
//    data:
//        [32:channel-id]
//        [8:id]
//        [32:payment-preimage]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fulfill_htlc_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 72);

//    type: 130 (update_fulfill_htlc)
    ln_misc_push16be(&proto, MSGTYPE_UPDATE_FULFILL_HTLC);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:id]
    ln_misc_push64be(&proto, pMsg->id);

    //        [32:payment-preimage]
    ucoin_push_data(&proto, pMsg->p_payment_preimage, UCOIN_SZ_PRIVKEY);

    assert(sizeof(uint16_t) + 72 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_update_fulfill_htlc_read(ln_update_fulfill_htlc_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 72) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_UPDATE_FULFILL_HTLC) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:id]
    pMsg->id = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

//        [32:payment-preimage]
    memcpy(pMsg->p_payment_preimage, pData + pos, UCOIN_SZ_PRIVKEY);
    pos += UCOIN_SZ_PRIVKEY;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fulfill_htlc_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void update_fulfill_htlc_print(const ln_update_fulfill_htlc_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[update_fulfill_htlc]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("id: %" PRIx64 "\n", pMsg->id);
    DBG_PRINTF2("p_payment_preimage: ");
    DUMPBIN(pMsg->p_payment_preimage, UCOIN_SZ_PRIVKEY);
    uint8_t sha[UCOIN_SZ_SHA256];
    ucoin_util_sha256(sha, pMsg->p_payment_preimage, UCOIN_SZ_PRIVKEY);
    DBG_PRINTF2("              hash: ");
    DUMPBIN(sha, sizeof(sha));
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * update_fail_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_fail_htlc_create(ucoin_buf_t *pBuf, const ln_update_fail_htlc_t *pMsg)
{
    //    type: 131 (update_fail_htlc)
    //    data:
    //        [32:channel-id]
    //        [8:id]
    //        [2:len]
    //        [len:reason]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fail_htlc_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 42 + pMsg->p_reason->len);

    //    type: 131 (update_fail_htlc)
    ln_misc_push16be(&proto, MSGTYPE_UPDATE_FAIL_HTLC);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:id]
    ln_misc_push64be(&proto, pMsg->id);

    //        [2:len]
    ln_misc_push16be(&proto, pMsg->p_reason->len);

    //        [len:reason]
    ucoin_push_data(&proto, pMsg->p_reason->buf, pMsg->p_reason->len);

    assert(sizeof(uint16_t) + 42 + pMsg->p_reason->len == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_update_fail_htlc_read(ln_update_fail_htlc_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 42) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_UPDATE_FAIL_HTLC) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:id]
    pMsg->id = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);
    if (Len - pos < len) {
        DBG_PRINTF("fail: invalid reason length: %d\n", Len);
        *pLen = 0;      //error
        return false;
    }

    //        [len:reason]
    ucoin_buf_alloccopy(pMsg->p_reason, pData + pos, len);
    pos += len;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fail_htlc_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void update_fail_htlc_print(const ln_update_fail_htlc_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[update_fail_htlc]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("id: %" PRIx64 "\n", pMsg->id);
    DBG_PRINTF2("len= %lu\n", (unsigned long)pMsg->p_reason->len);
    DBG_PRINTF2("p_reason: ");
    DUMPBIN(pMsg->p_reason->buf, pMsg->p_reason->len);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * commit_signed
 ********************************************************************/

bool HIDDEN ln_msg_commit_signed_create(ucoin_buf_t *pBuf, const ln_commit_signed_t *pMsg)
{
    //    type: 132 (commitment_signed)
    //    data:
    //        [32:channel-id]
    //        [64:signature]
    //        [2:num-htlcs]
    //        [num-htlcs*64:htlc-signature]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    commit_signed_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 98 + pMsg->num_htlcs * LN_SZ_SIGNATURE);

    //    type: 132 (commitment_signed)
    ln_misc_push16be(&proto, MSGTYPE_COMMITMENT_SIGNED);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [64:signature]
    ucoin_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);

    //        [2:num-htlcs]
    ln_misc_push16be(&proto, pMsg->num_htlcs);

    //        [num-htlcs*64:htlc-signature]
    ucoin_push_data(&proto, pMsg->p_htlc_signature, pMsg->num_htlcs * LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 98 + pMsg->num_htlcs * LN_SZ_SIGNATURE == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_commit_signed_read(ln_commit_signed_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 98) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_COMMITMENT_SIGNED) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [64:signature]
    memcpy(pMsg->p_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    //        [2:num-htlcs]
    pMsg->num_htlcs = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);


    //        [num-htlcs*64:htlc-signature]
    pMsg->p_htlc_signature = (uint8_t *)M_MALLOC(pMsg->num_htlcs * LN_SZ_SIGNATURE);
    memcpy(pMsg->p_htlc_signature, pData + pos, pMsg->num_htlcs * LN_SZ_SIGNATURE);
    pos += pMsg->num_htlcs * LN_SZ_SIGNATURE;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    commit_signed_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void commit_signed_print(const ln_commit_signed_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[commit_signed]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("signature: ");
    DUMPBIN(pMsg->p_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("num_htlcs= %lu\n", (unsigned long)pMsg->num_htlcs);
    for (int lp = 0; lp < pMsg->num_htlcs; lp++) {
        DBG_PRINTF2("htlc-signature[%d]: ", lp);
        DUMPBIN(pMsg->p_htlc_signature + lp * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
    }
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * revoke_and_ack
 ********************************************************************/

bool HIDDEN ln_msg_revoke_and_ack_create(ucoin_buf_t *pBuf, const ln_revoke_and_ack_t *pMsg)
{
    //    type: 133 (revoke_and_ack)
    //    data:
    //        [32:channel-id]
    //        [32:per-commitment-secret]
    //        [33:next-per-commitment-point]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    revoke_and_ack_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 97);

    //    type: 133 (revoke_and_ack)
    ln_misc_push16be(&proto, MSGTYPE_REVOKE_AND_ACK);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [32:per-commitment-secret]
    ucoin_push_data(&proto, pMsg->p_per_commit_secret, UCOIN_SZ_PRIVKEY);

    //        [33:next-per-commitment-point]
    ucoin_push_data(&proto, pMsg->p_per_commitpt, UCOIN_SZ_PUBKEY);

    assert(sizeof(uint16_t) + 97 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_revoke_and_ack_read(ln_revoke_and_ack_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 97) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_REVOKE_AND_ACK) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [32:per-commitment-secret]
    memcpy(pMsg->p_per_commit_secret, pData + pos, UCOIN_SZ_PRIVKEY);
    pos += UCOIN_SZ_PRIVKEY;

    //        [33:next-per-commitment-point]
    memcpy(pMsg->p_per_commitpt, pData + pos, UCOIN_SZ_PUBKEY);
    pos += UCOIN_SZ_PUBKEY;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    revoke_and_ack_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void revoke_and_ack_print(const ln_revoke_and_ack_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[revoke_and_ack]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("per-commitment-secret: ");
    DUMPBIN(pMsg->p_per_commit_secret, UCOIN_SZ_PRIVKEY);
    DBG_PRINTF2("next-per-commitment-point: ");
    DUMPBIN(pMsg->p_per_commitpt, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * update_fee
 ********************************************************************/

bool HIDDEN ln_msg_update_fee_create(ucoin_buf_t *pBuf, const ln_update_fee_t *pMsg)
{
    //    type: 134 (update_fee)
    //    data:
    //        [32:channel-id]
    //        [4:feerate-per-kw]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fee_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 36);

    //    type: 134 (update_fee)
    ln_misc_push16be(&proto, MSGTYPE_UPDATE_FEE);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [4:feerate-per-kw]
    ln_misc_push32be(&proto, pMsg->feerate_per_kw);

    assert(sizeof(uint16_t) + 36 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 36) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_UPDATE_FEE) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [4:feerate-per-kw]
    pMsg->feerate_per_kw = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fee_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void update_fee_print(const ln_update_fee_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[update_fee]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("feerate_per_kw= %lu\n", (unsigned long)pMsg->feerate_per_kw);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * update_fail_malformed_htlc
 ********************************************************************/

bool HIDDEN ln_msg_update_fail_malformed_htlc_create(ucoin_buf_t *pBuf, const ln_update_fail_malformed_htlc_t *pMsg)
{
    //    type: 135 (update_fail_malformed_htlc)
    //    data:
    //        [32:channel-id]
    //        [8:id]
    //        [32:sha256-of-onion]
    //        [2:failure-code]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fail_malformed_htlc_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 74);

    //    type: 135 (update_fail_malformed_htlc)
    ln_misc_push16be(&proto, MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:id]
    ln_misc_push64be(&proto, pMsg->id);

    //        [32:sha256-of-onion]
    ucoin_push_data(&proto, pMsg->p_sha256_onion, LN_SZ_HASH);

    //        [2:failure-code]
    ln_misc_push16be(&proto, pMsg->failure_code);

    assert(sizeof(uint16_t) + 74 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_update_fail_malformed_htlc_read(ln_update_fail_malformed_htlc_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 74) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:id]
    pMsg->id = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [32:sha256-of-onion]
    memcpy(pMsg->p_sha256_onion, pData + pos, LN_SZ_HASH);
    pos += LN_SZ_HASH;

    //        [2:failure-code]
    pMsg->failure_code = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    update_fail_malformed_htlc_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void update_fail_malformed_htlc_print(const ln_update_fail_malformed_htlc_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[update_fail_malformed_htlc]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("id: %" PRIx64 "\n", pMsg->id);
    DBG_PRINTF2("p_sha256_onion: ");
    DUMPBIN(pMsg->p_sha256_onion, LN_SZ_HASH);
    DBG_PRINTF2("failure_code: %04x\n", pMsg->failure_code);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}
