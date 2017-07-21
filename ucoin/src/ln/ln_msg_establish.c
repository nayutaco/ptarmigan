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
 *  @author ueno@nayuta.co
 *  @sa     https://github.com/nayuta-ueno/lightning-rfc/blob/master/02-peer-protocol.md#channel-establishment
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

#include "ln_msg_establish.h"
#include "ln_misc.h"


/********************************************************************
 * macros
 ********************************************************************/

//#define DBG_PRINT_CREATE
#define DBG_PRINT_READ


/********************************************************************
 * const variables
 ********************************************************************/

///< 32: chain-hash
static const uint8_t M_CHAIN_HASH_MAINNET[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xd6, 0x68,
    0x9c, 0x08, 0x5a, 0xe1, 0x65, 0x83, 0x1e, 0x93,
    0x4f, 0xf7, 0x63, 0xae, 0x46, 0xa2, 0xa6, 0xc1,
    0x72, 0xb3, 0xf1, 0xb6, 0x0a, 0x8c, 0xe2, 0x6f,
};

//static const uint8_t M_CHAIN_HASH_TESTNET[] = {
//    0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01,
//    0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97, 0x79, 0xba,
//    0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08,
//    0x71, 0x95, 0x26, 0xf8, 0xd7, 0x7f, 0x49, 0x43,
//};


/**************************************************************************
 * prototypes
 **************************************************************************/

static void open_channel_print(const ln_open_channel_t *pMsg);
static void accept_channel_print(const ln_accept_channel_t *pMsg);
static void funding_created_print(const ln_funding_created_t *pMsg);
static void funding_signed_print(const ln_funding_signed_t *pMsg);
static void funding_locked_print(const ln_funding_locked_t *pMsg);


/********************************************************************
 * open_channel
 ********************************************************************/

bool HIDDEN ln_msg_open_channel_create(ucoin_buf_t *pBuf, const ln_open_channel_t *pMsg)
{
    //    type: 32 (open_channel)
    //    data:
    //        [32:chain-hash]
    //        [32:temporary-channel-id]
    //        [8:funding-satoshis]
    //        [8:push-msat]
    //        [8:dust-limit-satoshis]
    //        [8:max-htlc-value-in-flight-msat]
    //        [8:channel-reserve-satoshis]
    //        [8:htlc-minimum-msat]
    //        [4:feerate-per-kw]
    //        [2:to-self-delay]
    //        [2:max-accepted-htlcs]
    //        [33:funding-pubkey]
    //        [33:revocation-basepoint]
    //        [33:payment-basepoint]
    //        [33:delayed-payment-basepoint]
    //        [33:first-per-commitment-point]
    //        [1:channel_flags]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    open_channel_print(pMsg);
#endif  //DBG_PRINT_CREATE

    if ( (LN_SATOSHI2MSAT(pMsg->funding_sat) < pMsg->push_msat) ||
         (pMsg->max_accepted_htlcs > 483) ) {
        DBG_PRINTF("fail: invalid parameter(%" PRIu64 ", %" PRIu64 ")\n", LN_SATOSHI2MSAT(pMsg->funding_sat), pMsg->push_msat);
        return false;
    }

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 286);

    //type: 0x20 (open_channel)
    ln_misc_push16be(&proto, MSGTYPE_OPEN_CHANNEL);

    //    [32:chain-hash]
    ucoin_push_data(&proto, M_CHAIN_HASH_MAINNET, sizeof(M_CHAIN_HASH_MAINNET));

    //    [32:temporary-channel-id]
    ucoin_push_data(&proto, pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);

    //    [8:funding-satoshis]
    ln_misc_push64be(&proto, pMsg->funding_sat);

    //    [8:push-msat]
    ln_misc_push64be(&proto, pMsg->push_msat);

    //    [8:dust-limit-satoshis]
    ln_misc_push64be(&proto, pMsg->dust_limit_sat);

    //    [8:max-htlc-value-in-flight-msat]
    ln_misc_push64be(&proto, pMsg->max_htlc_value_in_flight_msat);

    //    [8:channel-reserve-satoshis]
    ln_misc_push64be(&proto, pMsg->channel_reserve_sat);

    //        [8:htlc-minimum-msat]
    ln_misc_push64be(&proto, pMsg->htlc_minimum_msat);

    //    [4:feerate-per-kw]
    ln_misc_push32be(&proto, pMsg->feerate_per_kw);

    //    [2:to-self-delay]
    ln_misc_push16be(&proto, pMsg->to_self_delay);

    //    [2:max-accepted-htlcs]
    ln_misc_push16be(&proto, pMsg->max_accepted_htlcs);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //    [33:funding-pubkey]
        //    [33:revocation-basepoint]
        //    [33:payment-basepoint]
        //    [33:delayed-payment-basepoint]
        //    [33:first-per-commitment-point]
        if (!ucoin_keys_chkpub(pMsg->p_pubkeys[lp])) {
            DBG_PRINTF("fail: check pubkey\n");
            return false;
        }
        ucoin_push_data(&proto, pMsg->p_pubkeys[lp], UCOIN_SZ_PUBKEY);
    }
    //        [1:channel_flags]
    ln_misc_push8(&proto, CHANNEL_FLAGS);

    assert(sizeof(uint16_t) + 286 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_open_channel_read(ln_open_channel_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 286) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_OPEN_CHANNEL) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //    [32:chain-hash]
    int cmp = memcmp(M_CHAIN_HASH_MAINNET, pData + pos, sizeof(M_CHAIN_HASH_MAINNET));
    if (cmp != 0) {
        DBG_PRINTF("fail: chain-hash mismatch\n");
        *pLen = 0;      //error
        return false;
    }
    pos += sizeof(M_CHAIN_HASH_MAINNET);

    //    [32:temporary-channel-id]
    memcpy(pMsg->p_temp_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //    [8:funding-satoshis]
    pMsg->funding_sat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [8:push-msat]
    pMsg->push_msat = ln_misc_get64be(pData + pos);
    if (LN_SATOSHI2MSAT(pMsg->funding_sat) < pMsg->push_msat) {
        DBG_PRINTF("fail: invalid funding-satoshis (%" PRIu64 " < %" PRIu64 ")\n", LN_SATOSHI2MSAT(pMsg->funding_sat), pMsg->push_msat);
        *pLen = 0;      //error
        return false;
    }
    pos += sizeof(uint64_t);

    //    [8:dust-limit-satoshis]
    pMsg->dust_limit_sat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [8:max-htlc-value-in-flight-msat]
    pMsg->max_htlc_value_in_flight_msat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [8:channel-reserve-satoshis]
    pMsg->channel_reserve_sat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [8:htlc-minimum-msat]
    pMsg->htlc_minimum_msat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [4:feerate-per-kw]
    pMsg->feerate_per_kw = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //    [2:to-self-delay]
    pMsg->to_self_delay = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //    [2:max-accepted-htlcs]
    pMsg->max_accepted_htlcs = ln_misc_get16be(pData + pos);
    if (pMsg->max_accepted_htlcs > 483) {
        DBG_PRINTF("fail: invalid max-accepted-htlcs\n");
        *pLen = 0;      //error
        return false;
    }
    pos += sizeof(uint16_t);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //    [33:funding-pubkey]
        //    [33:revocation-basepoint]
        //    [33:payment-basepoint]
        //    [33:delayed-payment-basepoint]
        //    [33:first-per-commitment-point]
        if (!ucoin_keys_chkpub(pData + pos)) {
            DBG_PRINTF("fail: check pubkey: %d\n", lp);
            DUMPBIN(pData + pos, UCOIN_SZ_PUBKEY);
            *pLen = 0;      //error
            return false;
        }
        memcpy(pMsg->p_pubkeys[lp], pData + pos, UCOIN_SZ_PUBKEY);
        pos += UCOIN_SZ_PUBKEY;
    }

    //        [1:channel_flags]
    uint8_t channel_flags = *(pData + pos);
    if (((channel_flags & CHANNEL_FLAGS_MASK) != 0) || (channel_flags != CHANNEL_FLAGS)) {
        DBG_PRINTF("fail: channel_flags.announce_channel mismatch\n");
        *pLen = 0;      //error
        return false;
    }
    pos++;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    open_channel_print(pMsg);
    DBG_PRINTF2("channel_flags : %d\n", channel_flags);
#endif  //DBG_PRINT_READ

    return true;
}


static void open_channel_print(const ln_open_channel_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[open_channel]-------------------------------\n\n");
    DBG_PRINTF2("temporary-channel-id: ");
    DUMPBIN(pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("funding_sat= %" PRIu64 "\n", pMsg->funding_sat);
    DBG_PRINTF2("push_msat= %" PRIu64 "\n", pMsg->push_msat);
    DBG_PRINTF2("dust_limit_sat= %" PRIu64 "\n", pMsg->dust_limit_sat);
    DBG_PRINTF2("max_htlc_value_in_flight_msat= %" PRIu64 "\n", pMsg->max_htlc_value_in_flight_msat);
    DBG_PRINTF2("channel_reserve_sat= %" PRIu64 "\n", pMsg->channel_reserve_sat);
    DBG_PRINTF2("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    DBG_PRINTF2("feerate_per_kw= %" PRIu32 "\n", pMsg->feerate_per_kw);
    DBG_PRINTF2("to_self_delay= %u\n", pMsg->to_self_delay);
    DBG_PRINTF2("max_accepted_htlcs= %u\n", pMsg->max_accepted_htlcs);
    DBG_PRINTF2("p_funding_pubkey        : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_FUNDING], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_revocation_basept     : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_REVOCATION], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_payment_basept        : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_PAYMENT], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_delayed_payment_basept: ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_DELAYED_PAYMENT], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_first_per_commitpt    : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * accept_channel
 ********************************************************************/

bool HIDDEN ln_msg_accept_channel_create(ucoin_buf_t *pBuf, const ln_accept_channel_t *pMsg)
{
    //    type: 33 (accept_channel)
    //    data:
    //        [32:temporary-channel-id]
    //        [8:dust-limit-satoshis]
    //        [8:max-htlc-value-in-flight-msat]
    //        [8:channel-reserve-satoshis]
    //        [8:htlc-minimum-msat]
    //        [4:minimum-depth]
    //        [2:to-self-delay]
    //        [2:max-accepted-htlcs]
    //        [33:funding-pubkey]
    //        [33:revocation-basepoint]
    //        [33:payment-basepoint]
    //        [33:delayed-payment-basepoint]
    //        [33:first-per-commitment-point]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    accept_channel_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 237);

    //type: 0x21 (accept_channel)
    ln_misc_push16be(&proto, MSGTYPE_ACCEPT_CHANNEL);

    //    [32:temporary-channel-id]
    ucoin_push_data(&proto, pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);

    //    [8:dust-limit-satoshis]
    ln_misc_push64be(&proto, pMsg->dust_limit_sat);

    //    [8:max-htlc-value-in-flight-msat]
    ln_misc_push64be(&proto, pMsg->max_htlc_value_in_flight_msat);

    //    [8:channel-reserve-satoshis]
    ln_misc_push64be(&proto, pMsg->channel_reserve_sat);

    //    [8:htlc-minimum-msat]
    ln_misc_push64be(&proto, pMsg->htlc_minimum_msat);

    //    [4:minimum-depth]
    ln_misc_push32be(&proto, pMsg->min_depth);

    //    [2:to-self-delay]
    ln_misc_push16be(&proto, pMsg->to_self_delay);

    //    [2:max-accepted-htlcs]
    ln_misc_push16be(&proto, pMsg->max_accepted_htlcs);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //    [33:funding-pubkey]
        //    [33:revocation-basepoint]
        //    [33:payment-basepoint]
        //    [33:delayed-payment-basepoint]
        //    [33:first-per-commitment-point]
        if (!ucoin_keys_chkpub(pMsg->p_pubkeys[lp])) {
            DBG_PRINTF("fail: check pubkey\n");
            return false;
        }
        ucoin_push_data(&proto, pMsg->p_pubkeys[lp], UCOIN_SZ_PUBKEY);
    }

    assert(sizeof(uint16_t) + 237 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_accept_channel_read(ln_accept_channel_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 237) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_ACCEPT_CHANNEL) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //    [32:temporary-channel-id]
    memcpy(pMsg->p_temp_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //    [8:dust-limit-satoshis]
    pMsg->dust_limit_sat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [8:max-htlc-value-in-flight-msat]
    pMsg->max_htlc_value_in_flight_msat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [8:channel-reserve-satoshis]
    pMsg->channel_reserve_sat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [8:htlc-minimum-msat]
    pMsg->htlc_minimum_msat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //    [4:minimum-depth]
    pMsg->min_depth = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //    [2:to-self-delay]
    pMsg->to_self_delay = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //    [2:max-accepted-htlcs]
    pMsg->max_accepted_htlcs = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        //    [33:funding-pubkey]
        //    [33:revocation-basepoint]
        //    [33:payment-basepoint]
        //    [33:delayed-payment-basepoint]
        //    [33:first-per-commitment-point]
        if (!ucoin_keys_chkpub(pData + pos)) {
            DBG_PRINTF("fail: check pubkey\n");
            *pLen = 0;      //error
            return false;
        }
        memcpy(pMsg->p_pubkeys[lp], pData + pos, UCOIN_SZ_PUBKEY);
        pos += UCOIN_SZ_PUBKEY;
    }

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    accept_channel_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void accept_channel_print(const ln_accept_channel_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[accept_channel]-------------------------------\n\n");
    DBG_PRINTF2("temporary-channel-id: ");
    DUMPBIN(pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("dust_limit_sat= %" PRIu64 "\n", pMsg->dust_limit_sat);
    DBG_PRINTF2("max_htlc_value_in_flight_msat= %" PRIu64 "\n", pMsg->max_htlc_value_in_flight_msat);
    DBG_PRINTF2("channel_reserve_sat= %" PRIu64 "\n", pMsg->channel_reserve_sat);
    DBG_PRINTF2("min_depth= %" PRIu32 "\n", pMsg->min_depth);
    DBG_PRINTF2("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    DBG_PRINTF2("to_self_delay= %u\n", pMsg->to_self_delay);
    DBG_PRINTF2("max_accepted_htlcs= %u\n", pMsg->max_accepted_htlcs);
    DBG_PRINTF2("p_funding_pubkey        : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_FUNDING], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_revocation_basept     : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_REVOCATION], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_payment_basept        : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_PAYMENT], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_delayed_payment_basept: ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_DELAYED_PAYMENT], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_first_per_commitpt    : ");
    DUMPBIN(pMsg->p_pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * funding_created
 ********************************************************************/

bool HIDDEN ln_msg_funding_created_create(ucoin_buf_t *pBuf, const ln_funding_created_t *pMsg)
{
    //    type: 34 (funding_created)
    //    data:
    //        [32:temporary-channel-id]
    //        [32:funding-txid]
    //        [2:funding-output-index]
    //        [64:signature]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    funding_created_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 130);

    //    type: 0x22 (funding_created)
    ln_misc_push16be(&proto, MSGTYPE_FUNDING_CREATED);

    //        [32:temporary-channel-id]
    ucoin_push_data(&proto, pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);

    //        [32:funding-txid]
    // BE変換
    uint8_t txid[UCOIN_SZ_TXID];
    for (int lp = 0; lp < UCOIN_SZ_TXID; lp++) {
        txid[lp] = pMsg->p_funding_txid[UCOIN_SZ_TXID - lp - 1];
    }
    ucoin_push_data(&proto, txid, UCOIN_SZ_TXID);

    //        [2:funding-output-index]
    ln_misc_push16be(&proto, pMsg->funding_output_idx);

    //        [64:signature]
    ucoin_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 130 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_funding_created_read(ln_funding_created_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 130) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_FUNDING_CREATED) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:temporary-channel-id]
    memcpy(pMsg->p_temp_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [32:funding-txid]
    // LE変換
    for (int lp = 0; lp < UCOIN_SZ_TXID; lp++) {
        pMsg->p_funding_txid[lp] = *(pData + pos + UCOIN_SZ_TXID - lp - 1);
    }
    pos += UCOIN_SZ_TXID;

    //        [2:funding-output-index]
    pMsg->funding_output_idx = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [64:signature]
    memcpy(pMsg->p_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    funding_created_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void funding_created_print(const ln_funding_created_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[funding_created]-------------------------------\n\n");
    DBG_PRINTF2("temporary-channel-id: ");
    DUMPBIN(pMsg->p_temp_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("p_funding_txid: ");
    DUMPBIN(pMsg->p_funding_txid, UCOIN_SZ_TXID);
    DBG_PRINTF2("funding_output_idx= %lu\n", (unsigned long)pMsg->funding_output_idx);
    DBG_PRINTF2("signature: ");
    DUMPBIN(pMsg->p_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * funding_signed
 ********************************************************************/

bool HIDDEN ln_msg_funding_signed_create(ucoin_buf_t *pBuf, const ln_funding_signed_t *pMsg)
{
    //    type: 35 (funding_signed)
    //    data:
    //        [32:channel-id]
    //        [64:signature]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    funding_signed_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 96);

    //    type: 0x23 (funding_signed)
    ln_misc_push16be(&proto, MSGTYPE_FUNDING_SIGNED);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [64:signature]
    ucoin_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 96 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_funding_signed_read(ln_funding_signed_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 96) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_FUNDING_SIGNED) {
        DBG_PRINTF("fail: invalid parameter\n");
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

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    funding_signed_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void funding_signed_print(const ln_funding_signed_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[funding_signed]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("signature: ");
    DUMPBIN(pMsg->p_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * funding_locked
 ********************************************************************/

bool HIDDEN ln_msg_funding_locked_create(ucoin_buf_t *pBuf, const ln_funding_locked_t *pMsg)
{
    //    type: 36 (funding_locked)
    //    data:
    //        [32:channel-id]
    //        [33:next-per-commitment-point]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    funding_locked_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 65);

    //    type: 0x24 (funding_locked)
    ln_misc_push16be(&proto, MSGTYPE_FUNDING_LOCKED);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [33:next-per-commitment-point]
    ucoin_push_data(&proto, pMsg->p_per_commitpt, UCOIN_SZ_PUBKEY);

    assert(sizeof(uint16_t) + 65 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_funding_locked_read(ln_funding_locked_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 65) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_FUNDING_LOCKED) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [33:next-per-commitment-point]
    memcpy(pMsg->p_per_commitpt, pData + pos, UCOIN_SZ_PUBKEY);
    pos += UCOIN_SZ_PUBKEY;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    funding_locked_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void funding_locked_print(const ln_funding_locked_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[funding_locked]-------------------------------\n\n");
    DBG_PRINTF2("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("p_per_commitpt: ");
    DUMPBIN(pMsg->p_per_commitpt, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}
