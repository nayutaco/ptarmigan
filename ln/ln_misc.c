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

void HIDDEN ln_misc_sig_expand(utl_buf_t *pSig, const uint8_t *pBuf)
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
