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
/** @file   ln_msg_x_normalope.c
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

#include "ln_msg_x_normalope.h"
#include "ln_local.h"
#include "ln_msg_x.h"


/********************************************************************
 * macros
 ********************************************************************/

//#define DBG_PRINT_WRITE
//#define DBG_PRINT_READ


/**************************************************************************
 * prototypes
 **************************************************************************/

#if defined(DBG_PRINT_READ) || defined(DBG_PRINT_WRITE)
static void x_update_add_htlc_print(const ln_msg_x_update_add_htlc_t *pMsg);
static void x_update_fulfill_htlc_print(const ln_msg_x_update_fulfill_htlc_t *pMsg);
static void x_update_fail_htlc_print(const ln_msg_x_update_fail_htlc_t *pMsg);
#endif  //DBG_PRINT_READ || DBG_PRINT_WRITE


/********************************************************************
 * update_add_htlc
 ********************************************************************/

bool HIDDEN ln_msg_x_update_add_htlc_write(utl_buf_t *pBuf, const ln_msg_x_update_add_htlc_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_update_add_htlc_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_X_UPDATE_ADD_HTLC)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->amount_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_payment_hash, BTC_SZ_HASH256)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->cltv_expiry)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->amt_to_forward)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->outgoing_cltv_value)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_onion_routing_packet, LN_SZ_ONION_ROUTE)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_x_update_add_htlc_read(ln_msg_x_update_add_htlc_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_X_UPDATE_ADD_HTLC) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->amount_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_payment_hash, BTC_SZ_HASH256)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->cltv_expiry)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->amt_to_forward)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->outgoing_cltv_value)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_onion_routing_packet, LN_SZ_ONION_ROUTE)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_update_add_htlc_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


#if defined(DBG_PRINT_READ) || defined(DBG_PRINT_WRITE)
static void x_update_add_htlc_print(const ln_msg_x_update_add_htlc_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[x_update_add_htlc]-------------------------------\n");
    LOGD("amount_msat: %" PRIu64 "\n", pMsg->amount_msat);
    LOGD("payment_hash: ");
    DUMPD(pMsg->p_payment_hash, BTC_SZ_HASH256);
    LOGD("cltv_expiry: %u\n", pMsg->cltv_expiry);
    LOGD("amt_to_forward: %" PRIu64 "\n", pMsg->amt_to_forward);
    LOGD("outgoing_cltv_value: %u\n", pMsg->outgoing_cltv_value);
    LOGD("onion_routing_packet(top 34bytes only): ");
    DUMPD(pMsg->p_onion_routing_packet, 34);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif  //DBG_PRINT_READ || DBG_PRINT_WRITE


/********************************************************************
 * update_fulfill_htlc
 ********************************************************************/

bool HIDDEN ln_msg_x_update_fulfill_htlc_write(utl_buf_t *pBuf, const ln_msg_x_update_fulfill_htlc_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_update_fulfill_htlc_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_X_UPDATE_FULFILL_HTLC)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_payment_preimage, BTC_SZ_PRIVKEY)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_x_update_fulfill_htlc_read(ln_msg_x_update_fulfill_htlc_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_X_UPDATE_FULFILL_HTLC) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_payment_preimage, BTC_SZ_PRIVKEY)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_update_fulfill_htlc_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


#if defined(DBG_PRINT_READ) || defined(DBG_PRINT_WRITE)
static void x_update_fulfill_htlc_print(const ln_msg_x_update_fulfill_htlc_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[x_update_fulfill_htlc]-------------------------------\n");
    LOGD("p_payment_preimage: ");
    DUMPD(pMsg->p_payment_preimage, BTC_SZ_PRIVKEY);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif  //DBG_PRINT_READ || DBG_PRINT_WRITE


/********************************************************************
 * update_fail_htlc
 ********************************************************************/

bool HIDDEN ln_msg_x_update_fail_htlc_write(utl_buf_t *pBuf, const ln_msg_x_update_fail_htlc_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_update_fail_htlc_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_X_UPDATE_FAIL_HTLC)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->len)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_reason, pMsg->len)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_x_update_fail_htlc_read(ln_msg_x_update_fail_htlc_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_X_UPDATE_FAIL_HTLC) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->len)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_reason, pMsg->len)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_update_fail_htlc_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


#if defined(DBG_PRINT_READ) || defined(DBG_PRINT_WRITE)
static void x_update_fail_htlc_print(const ln_msg_x_update_fail_htlc_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[x_update_fail_htlc]-------------------------------\n");
    LOGD("reason: ");
    DUMPD(pMsg->p_reason, pMsg->len);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif  //DBG_PRINT_READ || DBG_PRINT_WRITE


