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
/** @file   ln_misc.c
 *  @brief  [LN]雑多
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/md.h"

#include "btc_crypto.h"

#include "ln_misc.h"
#include "ln_derkey.h"
#include "ln_local.h"


/********************************************************************
 * public functions
 ********************************************************************/

const char *ln_msg_name(uint16_t Type)
{
    const struct {
        uint16_t        type;
        const char      *name;
    } MESSAGE[] = {
        { 0x0010, "init" },
        { 0x0011, "error" },
        { 0x0012, "ping" },
        { 0x0013, "pong" },
        { 0x0020, "open_channel" },
        { 0x0021, "accept_channel" },
        { 0x0022, "funding_created" },
        { 0x0023, "funding_signed" },
        { 0x0024, "funding_locked" },
        { 0x0026, "shutdown" },
        { 0x0027, "closing_signed" },
        { 0x0080, "update_add_htlc" },
        { 0x0082, "update_fulfill_htlc" },
        { 0x0083, "update_fail_htlc" },
        { 0x0084, "commitment_signed" },
        { 0x0085, "revoke_and_ack" },
        { 0x0086, "update_fee" },
        { 0x0087, "update_fail_malformed_htlc" },
        { 0x0088, "channel_reestablish" },
        { 0x0100, "channel_announcement" },
        { 0x0101, "node_announcement" },
        { 0x0102, "channel_update" },
        { 0x0103, "announcement_signatures" },
    };
    for (size_t lp = 0; lp < ARRAY_SIZE(MESSAGE); lp++) {
        if (Type == MESSAGE[lp].type) {
            return MESSAGE[lp].name;
        }
    }
    return "UNKNOWN MESSAGE";
}


/********************************************************************
 * functions
 ********************************************************************/

bool HIDDEN ln_misc_sigtrim(uint8_t *pSig, const uint8_t *pBuf)
{
    //署名
    //  [30][4+r_len+s_len][02][r len][...][02][s_len][...][01]
    //
    //  基本的に、r=32byte, s=32byte
    //  しかし、DER形式のため以下の操作が発生する
    //      - 最上位bitが立っていると負の数と見なされてNGのため、0x00を付与する
    //      - 最上位バイトの0x00は負の数を回避する以外にはNGのため、取り除く
    //
    //  よって、例えばr=000...00, s=000...00だった場合、以下となる
    //      300602010002010001

    uint8_t sz = pBuf[1] - 4;
    uint8_t sz_r = pBuf[3];
    uint8_t sz_s = pBuf[4 + sz_r + 1];
    const uint8_t *p = pBuf + 4;

    if (sz != sz_r + sz_s) {
        return false;
    }

    //r
    //0除去
    for (int lp = 0; lp < sz_r - 1; lp++) {
        if (*p != 0) {
            break;
        }
        sz_r--;
        p++;
    }
    if (sz_r > 32) {
        return false;
    }
    if (sz_r < 32) {
        memset(pSig, 0, 32 - sz_r);
        pSig += 32 - sz_r;
    }
    memcpy(pSig, p, sz_r);
    pSig += sz_r;
    p += sz_r + 2;

    //s
    //0除去
    for (int lp = 0; lp < sz_s - 1; lp++) {
        if (*p != 0) {
            break;
        }
        sz_s--;
        p++;
    }
    if (sz_s > 32) {
        return false;
    }
    if (sz_s < 32) {
        memset(pSig, 0, 32 - sz_s);
        pSig += 32 - sz_s;
    }
    memcpy(pSig, p, sz_s);

    return true;
}


void HIDDEN ln_misc_sigexpand(utl_buf_t *pSig, const uint8_t *pBuf)
{
    utl_push_t    push;
    uint8_t r_len = 32;
    uint8_t s_len = 32;
    const uint8_t *r_p;
    const uint8_t *s_p;

    r_p = pBuf;
    for (int lp = 0; lp < 31; lp++) {
        if (*r_p != 0) {
            break;
        }
        r_p++;
        r_len--;
    }
    if (*r_p & 0x80) {
        r_len++;
    }

    s_p = pBuf + 32;
    for (int lp = 0; lp < 31; lp++) {
        if (*s_p != 0) {
            break;
        }
        s_p++;
        s_len--;
    }
    if (*s_p & 0x80) {
        s_len++;
    }

    //署名
    //  [30][4+r_len+s_len][02][r len][...][02][s_len][...][01]
    utl_push_init(&push, pSig, 7 + r_len + s_len);

    uint8_t buf[6];
    buf[0] = 0x30;
    buf[1] = (uint8_t)(4 + r_len + s_len);
    buf[2] = 0x02;
    buf[3] = r_len;
    buf[4] = 0x00;
    buf[5] = 0x01;
    utl_push_data(&push, buf, 4);
    if (*r_p & 0x80) {
        buf[0] = 0x00;
        utl_push_data(&push, buf, 1);
        r_len--;
    }
    utl_push_data(&push, r_p, r_len);

    buf[0] = 0x02;
    buf[1] = s_len;
    utl_push_data(&push, buf, 2);
    if (*s_p & 0x80) {
        buf[0] = 0x00;
        utl_push_data(&push, buf, 1);
        s_len--;
    }
    utl_push_data(&push, s_p, s_len);
    buf[0] = 0x01;
    utl_push_data(&push, buf, 1);        //SIGHASH_ALL
}
