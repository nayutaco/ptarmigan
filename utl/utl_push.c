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
/** @file   utl_push.c
 *  @brief  bitcoinスクリプト作成
 */
#include "utl_local.h"

#include "utl_push.h"
#include "utl_dbg.h"
#include "utl_int.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_push_init(utl_push_t *pPush, utl_buf_t *pBuf, uint32_t Size)
{
    pPush->pos = 0;
    pPush->data = pBuf;
    if (Size) {
        if (!utl_buf_alloc(pPush->data, Size)) return false;
    } else {
        utl_buf_init(pPush->data);
    }
    return true;
}


bool utl_push_data(utl_push_t *pPush, const void *pData, uint32_t Len)
{
    int rest = pPush->data->len - pPush->pos - Len;
    if (rest < 0) {
        //足りない分を拡張
        pPush->data->buf = (uint8_t *)UTL_DBG_REALLOC(pPush->data->buf, pPush->data->len - rest);
        if (!pPush->data->buf) return false;
        pPush->data->len = pPush->data->len - rest;
    }
    memcpy(&pPush->data->buf[pPush->pos], pData, Len);
    pPush->pos += Len;
    return true;
}


bool utl_push_value(utl_push_t *pPush, uint64_t Value)
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
    } else if (Value <= UINT64_C(0x7fffffffff)) {
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
    return utl_push_data(pPush, buf, len);
}


bool utl_push_trim(utl_push_t *pPush)
{
    if (pPush->data->len != pPush->pos) {
        if (pPush->pos == 0) {
            utl_buf_free(pPush->data);
        } else {
            pPush->data->len = pPush->pos;
            pPush->data->buf = (uint8_t *)UTL_DBG_REALLOC(pPush->data->buf, pPush->pos);
            if (!pPush->data->buf) return false;
        }
    }
    return true;
}


bool utl_push_byte(utl_push_t *pPush, uint8_t Value)
{
    return utl_push_data(pPush, &Value, sizeof(Value));
}


bool utl_push_u16be(utl_push_t *pPush, uint16_t Value)
{
    uint8_t data[sizeof(Value)];
    utl_int_unpack_u16be(data, Value);
    return utl_push_data(pPush, data, sizeof(data));
}


bool utl_push_u32be(utl_push_t *pPush, uint32_t Value)
{
    uint8_t data[sizeof(Value)];
    utl_int_unpack_u32be(data, Value);
    return utl_push_data(pPush, data, sizeof(data));
}


bool utl_push_u64be(utl_push_t *pPush, uint64_t Value)
{
    uint8_t data[sizeof(Value)];
    utl_int_unpack_u64be(data, Value);
    return utl_push_data(pPush, data, sizeof(data));
}

