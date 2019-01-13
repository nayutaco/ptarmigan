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
 *  @sa     https://github.com/lightningnetwork/lightning-rfc/blob/master/01-messaging.md
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <assert.h>

#include "utl_dbg.h"
#include "utl_int.h"

#include "ln_msg_setupctl.h"
#include "ln_misc.h"
#include "ln_local.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_WRITE
#define DBG_PRINT_READ

// #define M_PING_NONZERO_CHK
// #define M_PONG_NONZERO_CHK


/**************************************************************************
 * prototypes
 **************************************************************************/

static void init_print(const ln_init_t *pMsg);
static void error_print(const ln_error_t *pMsg);
// static void ping_print(const ln_ping_t *pMsg);
// static void pong_print(const ln_pong_t *pMsg);


/********************************************************************
 * init
 ********************************************************************/

bool HIDDEN ln_msg_init_write(utl_buf_t *pBuf, const ln_init_t *pMsg)
{
    //    type: 16 (init)
    //    data:
    //        [2:gflen]
    //        [gflen:globalfeatures]
    //        [2:lflen]
    //        [lflen:localfeatures]

    utl_push_t    proto;

#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    init_print(pMsg);
#endif  //DBG_PRINT_WRITE

    //gflen=0, lflen=0
    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 4 + pMsg->globalfeatures.len + pMsg->localfeatures.len);

    //    type: 16 (init)
    ln_misc_push16be(&proto, MSGTYPE_INIT);

    //        [2:gflen]
    ln_misc_push16be(&proto, pMsg->globalfeatures.len);

    //        [gflen:globalfeatures]
    if (pMsg->globalfeatures.len > 0) {
        utl_push_data(&proto, pMsg->globalfeatures.buf, pMsg->globalfeatures.len);
    }

    //        [2:lflen]
    ln_misc_push16be(&proto, pMsg->localfeatures.len);

    //        [lflen:localfeatures]
    if (pMsg->localfeatures.len > 0) {
        utl_push_data(&proto, pMsg->localfeatures.buf, pMsg->localfeatures.len);
    }

    assert(sizeof(uint16_t) + 4 + pMsg->globalfeatures.len + pMsg->localfeatures.len == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_init_read(ln_init_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //gflen=0, lflen=0
    if (Len < sizeof(uint16_t) + 4) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_INIT) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [2:gflen]
    uint16_t gflen = utl_int_pack_u16be(pData + pos);
    if (Len < sizeof(uint16_t) + 4 + gflen) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }
    pos += sizeof(uint16_t);

    //        [gflen:globalfeatures]
    utl_buf_alloccopy(&pMsg->globalfeatures, pData + pos, gflen);
    pos += gflen;

    //        [2:lflen]
    uint16_t lflen = utl_int_pack_u16be(pData + pos);
    if (Len < sizeof(uint16_t) + 4 + gflen + lflen) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }
    pos += sizeof(uint16_t);

    //        [lflen:localfeatures]
    utl_buf_alloccopy(&pMsg->localfeatures, pData + pos, lflen);
    pos += lflen;

    assert(Len >= pos);

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    init_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void init_print(const ln_init_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[init]-------------------------------\n");
    LOGD("globalfeatures(%d)= ", pMsg->globalfeatures.len);
    DUMPD(pMsg->globalfeatures.buf, pMsg->globalfeatures.len);
    LOGD("localfeatures(%d)= ", pMsg->localfeatures.len);
    DUMPD(pMsg->localfeatures.buf, pMsg->localfeatures.len);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * error
 ********************************************************************/

bool HIDDEN ln_msg_error_write(utl_buf_t *pBuf, const ln_error_t *pMsg)
{
    //    type: 17 (error)
    //    data:
    //        [32:channel_id]
    //        [2:len]
    //        [len:data]

    utl_push_t    proto;

    error_print(pMsg);

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + LN_SZ_CHANNEL_ID + sizeof(uint16_t) + pMsg->len);

    //    type: 17 (error)
    ln_misc_push16be(&proto, MSGTYPE_ERROR);

    //        [32:channel_id]
    utl_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [2:len]
    ln_misc_push16be(&proto, pMsg->len);

    //        [len:data]
    if (pMsg->len > 0) {
        utl_push_data(&proto, pMsg->p_data, pMsg->len);
    }

    assert(sizeof(uint16_t) + LN_SZ_CHANNEL_ID + sizeof(uint16_t) + pMsg->len == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_error_read(ln_error_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 4) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_ERROR) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [2:len]
    uint16_t len = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [len:data]
    pMsg->len = len;
    pMsg->p_data = (char *)UTL_DBG_MALLOC(len + 1);
    memcpy(pMsg->p_data, pData + pos, len);
    pMsg->p_data[len] = '\0';

    //pos += len;

    error_print(pMsg);

    return true;
}


static void error_print(const ln_error_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[error]-------------------------------\n");
    LOGD("channel-id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("data: ");
    DUMPD((const uint8_t *)pMsg->p_data, pMsg->len);
    LOGD("      ");
    for (uint16_t lp = 0; lp < pMsg->len; lp++) {
        char c = (char)pMsg->p_data[lp];
        if (isprint(c)) {
            LOGD2("%c", c);
        } else {
            LOGD2("?");
        }
    }
    LOGD2("\n");
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * ping
 ********************************************************************/

bool HIDDEN ln_msg_ping_write(utl_buf_t *pBuf, const ln_ping_t *pMsg)
{
    //        type: 18 (ping)
    //        data:
    //            [2:num_pong_bytes]
    //            [2:byteslen]
    //            [byteslen:ignored]

    utl_push_t    proto;

    if (pMsg->num_pong_bytes >= 65532) {
        LOGD("fail: num_pong_bytes: %d\n", pMsg->num_pong_bytes);
        return false;
    }

#ifdef DBG_PRINT_WRITE
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //ping_print(pMsg);
#endif  //DBG_PRINT_WRITE

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 4 + pMsg->byteslen);

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

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_ping_read(ln_ping_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 4) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_PING) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    pMsg->num_pong_bytes = utl_int_pack_u16be(pData + sizeof(uint16_t));
    if (pMsg->num_pong_bytes > 65531) {
        LOGD("fail: num_pong_bytes too large %04x\n", pMsg->num_pong_bytes);
        return false;
    }

    pMsg->byteslen = utl_int_pack_u16be(pData + sizeof(uint16_t) + 2);
    if (Len < sizeof(uint16_t) + 4 + pMsg->byteslen) {
        LOGD("fail: invalid length2: %d, bytelen=%d\n", Len, pMsg->byteslen);
        return false;
    }

#ifdef DBG_PRINT_READ
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //ping_print(pMsg);
#endif  //DBG_PRINT_READ

#ifdef M_PING_NONZERO_CHK
    for (int lp = 0; lp < pMsg->byteslen; lp++) {
        if (*(pData + sizeof(uint16_t) + 4 + lp) != 0x00) {
            LOGD("fail: contain not ZERO\n");
            return false;
        }
    }
#endif  //M_PING_NONZERO_CHK

    assert(Len >= sizeof(uint16_t) + 4 + pMsg->byteslen);

    return true;
}


#if 0
static void ping_print(const ln_ping_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD2("-[ping]-------------------------------\n");
    LOGD2("num_pong_bytes: %" PRIu16 "\n", pMsg->num_pong_bytes);
    LOGD2("byteslen: %" PRIu16 "\n", pMsg->byteslen);
    LOGD2("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif


/********************************************************************
 * pong
 ********************************************************************/

bool HIDDEN ln_msg_pong_write(utl_buf_t *pBuf, const ln_pong_t *pMsg)
{
    //        type: 19 (pong)
    //        data:
    //            [2:byteslen]
    //            [byteslen:ignored]

    utl_push_t    proto;

    if (pMsg->byteslen >= 65532) {
        LOGD("fail: byteslen: %d\n", pMsg->byteslen);
        return false;
    }

#ifdef DBG_PRINT_WRITE
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //pong_print(pMsg);
#endif  //DBG_PRINT_WRITE

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 2 + pMsg->byteslen);

    //        type: 19 (pong)
    ln_misc_push16be(&proto, MSGTYPE_PONG);

    //            [2:byteslen]
    ln_misc_push16be(&proto, pMsg->byteslen);

    //            [byteslen:ignored]
    memset(pBuf->buf + proto.pos, 0, pMsg->byteslen);
    proto.pos += pMsg->byteslen;

    assert(sizeof(uint16_t) + 2 + pMsg->byteslen == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_pong_read(ln_pong_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 2) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_PONG) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    pMsg->byteslen = utl_int_pack_u16be(pData + sizeof(uint16_t));
    if (pMsg->byteslen > 65531) {
        LOGD("fail: byteslen too large %04x\n", pMsg->byteslen);
        return false;
    }
    if (Len < sizeof(uint16_t) + 2 + pMsg->byteslen) {
        LOGD("fail: invalid length2: %d, %d\n", Len, pMsg->byteslen);
        return false;
    }

#ifdef DBG_PRINT_READ
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //pong_print(pMsg);
#endif  //DBG_PRINT_READ

#ifdef M_PONG_NONZERO_CHK
    for (int lp = 0; lp < pMsg->byteslen; lp++) {
        if (*(pData + sizeof(uint16_t) + 2 + lp) != 0x00) {
            LOGD("fail: contain not ZERO\n");
            return false;
        }
    }
#endif  //M_PONG_NONZERO_CHK

    assert(Len >= sizeof(uint16_t) + 2 + pMsg->byteslen);

    return true;
}


#if 0
static void pong_print(const ln_pong_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD2("-[pong]-------------------------------\n");
    LOGD2("byteslen: %" PRIu16 "\n", pMsg->byteslen);
    LOGD2("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif
