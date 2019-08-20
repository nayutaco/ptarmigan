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
/** @file   btc_script_buf.c
 *  @brief  btc_script_buf
 */
#include "utl_dbg.h"

#include "btc.h"
#include "btc_script.h"
#include "btc_script_buf.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_script_buf_w_write_item(btc_buf_w_t *pBufW, const void *pData, uint32_t Len)
{

    //https://github.com/bitcoin/bitcoin
    // see CheckMinimalPush

    uint8_t *p_data = (uint8_t *)pData;
    uint8_t buf[5];

    if (Len == 0 || (Len == 1 && p_data[0] == 0x00)) {
        buf[0] = OP_0;
        if (!btc_script_buf_w_write_data(pBufW, buf, 1)) return false;
    } else if (Len == 1 && p_data[0] <= 0x10) {
        buf[0] = OP_X + p_data[0];
        if (!btc_script_buf_w_write_data(pBufW, buf, 1)) return false;
    } else if (Len == 1 && p_data[0] == 0x81) {
        buf[0] = OP_1NEGATE;
        if (!btc_script_buf_w_write_data(pBufW, buf, 1)) return false;
    } else if (Len <= 0x4b) {
        buf[0] = Len;
        if (!btc_script_buf_w_write_data(pBufW, buf, 1)) return false;
        if (!btc_script_buf_w_write_data(pBufW, p_data, Len)) return false;
    } else if (Len <= 0xff) {
        buf[0] = OP_PUSHDATA1;
        buf[1] = Len;
        if (!btc_script_buf_w_write_data(pBufW, buf, 2)) return false;
        if (!btc_script_buf_w_write_data(pBufW, p_data, Len)) return false;
    } else if (Len <= 0xffff) {
        buf[0] = OP_PUSHDATA2;
        buf[1] = (uint8_t)(Len >> 8);
        buf[2] = (uint8_t)Len;
        if (!btc_script_buf_w_write_data(pBufW, buf, 3)) return false;
        if (!btc_script_buf_w_write_data(pBufW, p_data, Len)) return false;
    } else {
        return false;
    }
    return true;
}


bool btc_script_buf_w_write_item_positive_integer(btc_buf_w_t *pBufW, uint64_t Value)
{
    int len;
    uint8_t buf[7];

    if (Value == 0x00) {
        buf[0] = 0x00;
        len = 1;
    } else if (Value <= 16) {
        //use OP_1 ... OP_16
        buf[0] = 0x50 + Value;
        len = 1;
    } else if (Value <= __UINT64_C(0x7fffffffff)) {
        for (len = 1; len <= 6; len++) {
            if (Value < ((uint64_t)0x80 << 8 * (len - 1))) {
                buf[0] = len;
                for (int lp = 0; lp < len; lp++) {
                    buf[1 + lp] = (uint8_t)(Value >> 8 * lp);
                }
                len++;
                break;
            }
        }
    } else {
        return false;
    }
    return btc_script_buf_w_write_data(pBufW, buf, len);
}
