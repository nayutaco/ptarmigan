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

#include "btc_buf.h"

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

static void init_print(const ln_msg_init_t *pMsg);
static void error_print(const ln_msg_error_t *pMsg);
// static void ping_print(const ln_msg_ping_t *pMsg);
// static void pong_print(const ln_msg_pong_t *pMsg);


/********************************************************************
 * init
 ********************************************************************/

bool HIDDEN ln_msg_init_write(utl_buf_t *pBuf, const ln_msg_init_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    init_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_INIT)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->gflen)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_globalfeatures, pMsg->gflen)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->lflen)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_localfeatures, pMsg->lflen)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->gflen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_globalfeatures, (int32_t)pMsg->gflen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->lflen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_localfeatures, (int32_t)pMsg->lflen)) goto LABEL_ERROR_SYNTAX;

    //XXX:
    if (type != MSGTYPE_INIT) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    init_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


static void init_print(const ln_msg_init_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[init]-------------------------------\n");
    LOGD("globalfeatures(%u)= ", pMsg->gflen);
    DUMPD(pMsg->p_globalfeatures, pMsg->gflen);
    LOGD("localfeatures(%u)= ", pMsg->lflen);
    DUMPD(pMsg->p_localfeatures, pMsg->lflen);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * error
 ********************************************************************/

bool HIDDEN ln_msg_error_write(utl_buf_t *pBuf, const ln_msg_error_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    error_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_ERROR)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->len)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_data, pMsg->len)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_error_read(ln_msg_error_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->len)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_data, (int32_t)pMsg->len)) goto LABEL_ERROR_SYNTAX;

    //XXX:
    if (type != MSGTYPE_ERROR) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

// #ifdef DBG_PRINT_READ
//     LOGD("@@@@@ %s @@@@@\n", __func__);
    error_print(pMsg);
// #endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


static void error_print(const ln_msg_error_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[error]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("data: ");
    DUMPD(pMsg->p_data, pMsg->len);
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

bool HIDDEN ln_msg_ping_write(utl_buf_t *pBuf, const ln_msg_ping_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //ping_print(pMsg);
#endif  //DBG_PRINT_WRITE

    //XXX:
    if (pMsg->num_pong_bytes > LN_NUM_PONG_BYTES_MAX) {
        LOGD("fail: num_pong_bytes: %d\n", pMsg->num_pong_bytes);
        return false;
    }

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_PING)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->num_pong_bytes)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->byteslen)) goto LABEL_ERROR;
    if (pMsg->p_ignored) {
        if (!btc_buf_w_write_data(&buf_w, pMsg->p_ignored, pMsg->byteslen)) goto LABEL_ERROR;
    } else {
        if (!btc_buf_w_write_zeros(&buf_w, pMsg->byteslen)) goto LABEL_ERROR;
    }
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_ping_read(ln_msg_ping_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->num_pong_bytes)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->byteslen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_ignored, (int32_t)pMsg->byteslen)) goto LABEL_ERROR_SYNTAX;

    //XXX:
    if (type != MSGTYPE_PING) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (pMsg->num_pong_bytes > LN_NUM_PONG_BYTES_MAX) {
        LOGD("fail: num_pong_bytes %04x\n", pMsg->num_pong_bytes);
        return false;
    }
#ifdef M_PING_NONZERO_CHK
    for (int lp = 0; lp < pMsg->byteslen; lp++) {
        if (*(pMsg->p_ignored + lp)) {
            LOGD("fail: contain not zero\n");
            return false;
        }
    }
#endif  //M_PING_NONZERO_CHK

#ifdef DBG_PRINT_READ
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //ping_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


#if 0
static void ping_print(const ln_msg_ping_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[ping]-------------------------------\n");
    LOGD("num_pong_bytes: %u\n", pMsg->num_pong_bytes);
    LOGD("byteslen: %u\n", pMsg->byteslen);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif


/********************************************************************
 * pong
 ********************************************************************/

bool HIDDEN ln_msg_pong_write(utl_buf_t *pBuf, const ln_msg_pong_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //pong_print(pMsg);
#endif  //DBG_PRINT_WRITE

    //XXX:
    if (pMsg->byteslen > LN_NUM_PONG_BYTES_MAX) {
        LOGD("fail: byteslen: %d\n", pMsg->byteslen);
        return false;
    }

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_PONG)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->byteslen)) goto LABEL_ERROR;
    if (pMsg->p_ignored) {
        if (!btc_buf_w_write_data(&buf_w, pMsg->p_ignored, pMsg->byteslen)) goto LABEL_ERROR;
    } else {
        if (!btc_buf_w_write_zeros(&buf_w, pMsg->byteslen)) goto LABEL_ERROR;
    }
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_pong_read(ln_msg_pong_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->byteslen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_ignored, (int32_t)pMsg->byteslen)) goto LABEL_ERROR_SYNTAX;

    //XXX:
    if (type != MSGTYPE_PONG) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    if (pMsg->byteslen > LN_NUM_PONG_BYTES_MAX) {
        LOGD("fail: byteslen %04x\n", pMsg->byteslen);
        return false;
    }
#ifdef M_PONG_NONZERO_CHK
    for (int lp = 0; lp < pMsg->byteslen; lp++) {
        if (*(pMsg->p_ignored + lp)) {
            LOGD("fail: contain not zero\n");
            return false;
        }
    }
#endif  //M_PONG_NONZERO_CHK

#ifdef DBG_PRINT_READ
    //LOGD("@@@@@ %s @@@@@\n", __func__);
    //pong_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGD("fail: invalid syntax\n");
    return false;
}


#if 0
static void pong_print(const ln_msg_pong_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[pong]-------------------------------\n");
    LOGD("byteslen: %u\n", pMsg->byteslen);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif
