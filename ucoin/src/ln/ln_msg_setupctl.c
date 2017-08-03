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
/** @file   ln_msg_setupctl.c
 *  @brief  [LN]Setup/Control関連
 *  @author ueno@nayuta.co
 *  @sa     https://github.com/nayuta-ueno/lightning-rfc/blob/master/01-messaging.md
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "ln_msg_setupctl.h"
#include "ln_misc.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_CREATE
#define DBG_PRINT_READ


/**************************************************************************
 * prototypes
 **************************************************************************/

static void init_print(const ln_init_t *pMsg);


/********************************************************************
 * init
 ********************************************************************/

bool HIDDEN ln_msg_init_create(ucoin_buf_t *pBuf, const ln_init_t *pMsg)
{
    //    type: 16 (init)
    //    data:
    //        [2:gflen]
    //        [gflen:globalfeatures]
    //        [2:lflen]
    //        [lflen:localfeatures]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    init_print(pMsg);
#endif  //DBG_PRINT_CREATE

    //gflen=0, lflen=0
    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 4 + pMsg->gflen + pMsg->lflen);

    //    type: 16 (init)
    ln_misc_push16be(&proto, MSGTYPE_INIT);

    //        [2:gflen]
    ln_misc_push16be(&proto, pMsg->gflen);

    //        [gflen:globalfeatures]
    if (pMsg->gflen > 0) {
        ucoin_push_data(&proto, pMsg->globalfeatures, pMsg->gflen);
    }

    //        [2:lflen]
    ln_misc_push16be(&proto, pMsg->lflen);

    //        [lflen:localfeatures]
    if (pMsg->lflen > 0) {
        ucoin_push_data(&proto, pMsg->localfeatures, pMsg->lflen);
    }

    assert(sizeof(uint16_t) + 4 + pMsg->gflen + pMsg->lflen == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_init_read(ln_init_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //gflen=0, lflen=0
    if (Len < sizeof(uint16_t) + 4) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_INIT) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [2:gflen]
    uint16_t gflen = ln_misc_get16be(pData + pos);
    if (Len < sizeof(uint16_t) + 4 + gflen) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }
    pos += sizeof(uint16_t);

    //        [gflen:globalfeatures]
    if (gflen <= LN_SZ_GFLEN_MAX) {
        pMsg->gflen = gflen;
        memcpy(pMsg->globalfeatures, pData + pos, gflen);
    } else {
        pMsg->gflen = 0xff;
    }
    pos += gflen;

    //        [2:lflen]
    uint16_t lflen = ln_misc_get16be(pData + pos);
    if (Len < sizeof(uint16_t) + 4 + gflen + lflen) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }
    pos += sizeof(uint16_t);

    //        [lflen:localfeatures]
    if (lflen <= LN_SZ_LFLEN_MAX) {
        pMsg->lflen = lflen;
        memcpy(pMsg->localfeatures, pData + pos, lflen);
    } else {
        pMsg->lflen = 0xff;
    }
    pos += lflen;

    assert(Len == pos);

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    init_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void init_print(const ln_init_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[init]-------------------------------\n\n");
    DBG_PRINTF2("globalfeatures(%d)= ", pMsg->gflen);
    if (pMsg->gflen <= LN_SZ_GFLEN_MAX) {
        DUMPBIN(pMsg->globalfeatures, pMsg->gflen);
    } else {
        DBG_PRINTF2("--\n");
    }
    DBG_PRINTF2("localfeatures(%d)= ", pMsg->lflen);
    if (pMsg->lflen <= LN_SZ_GFLEN_MAX) {
        DUMPBIN(pMsg->localfeatures, pMsg->lflen);
    } else {
        DBG_PRINTF2("--\n");
    }
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * error
 ********************************************************************/

bool HIDDEN ln_msg_error_read(void *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 4) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_ERROR) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    DBG_PRINTF("channel_id:");
    DUMPBIN(pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [len:data]
    DBG_PRINTF("data(%d): ", len);
    //DUMPBIN(pData + pos, len);
    DBG_PRINTF("%s\n", pData + pos);
    pos += len;

    return true;
}


/********************************************************************
 * ping
 ********************************************************************/

bool HIDDEN ln_msg_ping_create(ucoin_buf_t *pBuf, const ln_ping_t *pMsg)
{
    //        type: 18 (ping)
    //        data:
    //            [2:num_pong_bytes]
    //            [2:byteslen]
    //            [byteslen:ignored]

    ucoin_push_t    proto;

DBG_PRINTF("pMsg->num_pong_bytes=%d\n", pMsg->num_pong_bytes);

    if (pMsg->num_pong_bytes >= 65532) {
        DBG_PRINTF("fail: num_pong_bytes: %d\n", pMsg->num_pong_bytes);
        return false;
    }

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 4 + pMsg->byteslen);

    //        type: 18 (ping)
    ln_misc_push16be(&proto, MSGTYPE_PING);

    //            [2:num_pong_bytes]
    ln_misc_push16be(&proto, pMsg->num_pong_bytes);

    //            [2:byteslen]
    ln_misc_push16be(&proto, pMsg->byteslen);

    //            [byteslen:ignored]
    memset(pBuf->buf + proto.pos, 0, pMsg->byteslen);
    proto.pos += pMsg->byteslen;

    assert(sizeof(uint16_t) + 4 + pMsg->byteslen == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_ping_read(ln_ping_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 4) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_PING) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }

    pMsg->num_pong_bytes = ln_misc_get16be(pData + sizeof(uint16_t));
    if (pMsg->num_pong_bytes > 65531) {
        DBG_PRINTF("fail: num_pong_bytes too large %04x\n", pMsg->num_pong_bytes);
        return false;
    }

    pMsg->byteslen = ln_misc_get16be(pData + sizeof(uint16_t) + 2);
    if (Len < sizeof(uint16_t) + 4 + pMsg->byteslen) {
        DBG_PRINTF("fail: invalid length2: %d, bytelen=%d\n", Len, pMsg->byteslen);
        return false;
    }

    for (int lp = 0; lp < pMsg->byteslen; lp++) {
        if (*(pData + sizeof(uint16_t) + 4 + lp) != 0x00) {
            DBG_PRINTF("fail: contain not ZERO\n");
            return false;
        }
    }

    assert(Len == sizeof(uint16_t) + 4 + pMsg->byteslen);

    return true;
}


/********************************************************************
 * pong
 ********************************************************************/

bool HIDDEN ln_msg_pong_create(ucoin_buf_t *pBuf, const ln_pong_t *pMsg)
{
    //        type: 19 (pong)
    //        data:
    //            [2:byteslen]
    //            [byteslen:ignored]

    ucoin_push_t    proto;

    if (pMsg->byteslen >= 65532) {
        DBG_PRINTF("fail: byteslen: %d\n", pMsg->byteslen);
        return false;
    }

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 2 + pMsg->byteslen);

    //        type: 19 (pong)
    ln_misc_push16be(&proto, MSGTYPE_PONG);

    //            [2:byteslen]
    ln_misc_push16be(&proto, pMsg->byteslen);

    //            [byteslen:ignored]
    memset(pBuf->buf + proto.pos, 0, pMsg->byteslen);
    proto.pos += pMsg->byteslen;

    assert(sizeof(uint16_t) + 2 + pMsg->byteslen == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_pong_read(ln_pong_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 2) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_PONG) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }

    pMsg->byteslen = ln_misc_get16be(pData + sizeof(uint16_t));
    if (pMsg->byteslen > 65531) {
        DBG_PRINTF("fail: byteslen too large %04x\n", pMsg->byteslen);
        return false;
    }
    if (Len < sizeof(uint16_t) + 2 + pMsg->byteslen) {
        DBG_PRINTF("fail: invalid length2: %d, %d\n", Len, pMsg->byteslen);
        return false;
    }

    for (int lp = 0; lp < pMsg->byteslen; lp++) {
        if (*(pData + sizeof(uint16_t) + 2 + lp) != 0x00) {
            DBG_PRINTF("fail: contain not ZERO\n");
            return false;
        }
    }

    assert(Len == sizeof(uint16_t) + 2 + pMsg->byteslen);

    return true;
}
