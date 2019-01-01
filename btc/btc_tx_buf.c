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
/** @file   btc_tx_buf.c
 *  @brief  btc_tx_buf
 */
#ifdef PTARM_USE_PRINTFUNC
#endif  //PTARM_USE_PRINTFUNC

#include <string.h>
#include <assert.h>

#include "utl_int.h"

#include "btc_tx_buf.h"


/**************************************************************************
 * public functions
 **************************************************************************/

void btc_tx_buf_r_init(btc_buf_r_t *pBuf, const uint8_t *pData, uint32_t Len)
{
    pBuf->data = pData;
    pBuf->len = Len;
    pBuf->pos = 0;
}


const uint8_t *btc_tx_buf_r_get_pos(btc_buf_r_t *pBuf)
{
    return pBuf->data + pBuf->pos;
}


bool btc_tx_buf_r_read(btc_buf_r_t *pBuf, uint8_t *pData, uint32_t Len)
{
    if (pBuf->pos + Len > pBuf->len) return false;
    memcpy(pData, pBuf->data + pBuf->pos, Len);
    pBuf->pos += Len;
    return true;
}


bool btc_tx_buf_r_read_byte(btc_buf_r_t *pBuf, uint8_t *pByte)
{
    if (pBuf->pos + 1 > pBuf->len) return false;
    *pByte = *(pBuf->data + pBuf->pos);
    pBuf->pos++;
    return true;
}


bool btc_tx_buf_r_read_u32le(btc_buf_r_t *pBuf, uint32_t *U32)
{
    if (pBuf->pos + 4 > pBuf->len) return false;
    *U32 = utl_int_pack_u32le(pBuf->data + pBuf->pos);
    pBuf->pos += 4;
    return true;
}


bool btc_tx_buf_r_read_u64le(btc_buf_r_t *pBuf, uint64_t *U64)
{
    if (pBuf->pos + 8 > pBuf->len) return false;
    *U64 = utl_int_pack_u64le(pBuf->data + pBuf->pos);
    pBuf->pos += 8;
    return true;
}


bool btc_tx_buf_r_seek(btc_buf_r_t *pBuf, int32_t offset)
{
    if (offset > 0) {
        if (pBuf->pos + offset > pBuf->len) return false;
    } else {
        if (pBuf->pos < (uint32_t)-offset) return false;
    }
    pBuf->pos += offset;
    return true;
}


uint32_t btc_tx_buf_r_remains(btc_buf_r_t *pBuf)
{
    return pBuf->len - pBuf->pos;
}


bool btc_tx_buf_r_read_varint(btc_buf_r_t *pBuf, uint64_t *pValue)
{
    if (pBuf->pos + 1 > pBuf->len) return false;
    const uint8_t *data_pos = pBuf->data + pBuf->pos;
    if (*(data_pos) < 0xfd) {
        *pValue = *data_pos;
        pBuf->pos += 1;
    } else if (*(data_pos) == 0xfd) {
        if (pBuf->pos + 3 > pBuf->len) return false;
        *pValue = utl_int_pack_u16le(data_pos + 1);
        pBuf->pos += 3;
    } else if (*(data_pos) == 0xfe) {
        if (pBuf->pos + 5 > pBuf->len) return false;
        *pValue = utl_int_pack_u32le(data_pos + 1);
        pBuf->pos += 5;
    } else if (*(data_pos) == 0xff) {
        if (pBuf->pos + 9 > pBuf->len) return false;
        *pValue = utl_int_pack_u64le(data_pos + 1);
        pBuf->pos += 9;
    } else {
        assert(false);
        return false;
    }
    return true;
}
