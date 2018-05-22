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
/** @file   ln_msg_close.c
 *  @brief  [LN]Close関連
 *  @author ueno@nayuta.co
 *  @sa     https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#channel-close
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ln_msg_close.h"
#include "ln_misc.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_CREATE
#define DBG_PRINT_READ


/**************************************************************************
 * prototypes
 **************************************************************************/

static void shutdown_print(const ln_shutdown_t *pMsg);
static void closing_signed_print(const ln_closing_signed_t *pMsg);


/********************************************************************
 * shutdown
 ********************************************************************/

bool HIDDEN ln_msg_shutdown_create(ucoin_buf_t *pBuf, const ln_shutdown_t *pMsg)
{
    //    type: 38 (shutdown)
    //    data:
    //        [32:channel-id]
    //        [2:len]
    //        [len:scriptpubkey]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("@@@@@ %s @@@@@\n", __func__);
    shutdown_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 34 + pMsg->p_scriptpk->len);

    //    type: 38 (shutdown)
    ln_misc_push16be(&proto, MSGTYPE_SHUTDOWN);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [2:len]
    ln_misc_push16be(&proto, pMsg->p_scriptpk->len);

    //        [len:scriptpubkey]
    ucoin_push_data(&proto, pMsg->p_scriptpk->buf, pMsg->p_scriptpk->len);

    assert(sizeof(uint16_t) + 34 + pMsg->p_scriptpk->len == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_shutdown_read(ln_shutdown_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 34) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_SHUTDOWN) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);
    if (Len - pos < len) {
        DBG_PRINTF("fail: invalid scriptpubkey length: %d\n", Len);
        return false;
    }

    //        [len:scriptpubkey]
    ucoin_buf_alloccopy(pMsg->p_scriptpk, pData + pos, len);
    pos += len;

    assert(Len == pos);

#ifdef DBG_PRINT_READ
    DBG_PRINTF("@@@@@ %s @@@@@\n", __func__);
    shutdown_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void shutdown_print(const ln_shutdown_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF("-[shutdown]-------------------------------\n");
    DBG_PRINTF("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF("p_scriptpk: ");
    DUMPBIN(pMsg->p_scriptpk->buf, pMsg->p_scriptpk->len);
    DBG_PRINTF("--------------------------------\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * closing_signed
 ********************************************************************/

bool HIDDEN ln_msg_closing_signed_create(ucoin_buf_t *pBuf, const ln_closing_signed_t *pMsg)
{
    //    type: 39 (closing_signed)
    //    data:
    //        [32:channel-id]
    //        [8:fee-satoshis]
    //        [64:signature]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("@@@@@ %s @@@@@\n", __func__);
    closing_signed_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 104);

    //    type: 39 (closing_signed)
    ln_misc_push16be(&proto, MSGTYPE_CLOSING_SIGNED);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:fee-satoshis]
    ln_misc_push64be(&proto, pMsg->fee_sat);

    //        [64:signature]
    ucoin_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 104 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_closing_signed_read(ln_closing_signed_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 104) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CLOSING_SIGNED) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:fee-satoshis]
    pMsg->fee_sat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [64:signature]
    memcpy(pMsg->p_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    assert(Len == pos);

#ifdef DBG_PRINT_READ
    DBG_PRINTF("@@@@@ %s @@@@@\n", __func__);
    closing_signed_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void closing_signed_print(const ln_closing_signed_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF("-[closing_signed]-------------------------------\n");
    DBG_PRINTF("channel-id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF("fee_sat= %llu\n", (unsigned long long)pMsg->fee_sat);
    DBG_PRINTF("signature: ");
    DUMPBIN(pMsg->p_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF("--------------------------------\n");
#endif  //UCOIN_DEBUG
}
