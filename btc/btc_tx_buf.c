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

void btc_tx_buf_r_init(btc_buf_r_t *pBufR, const uint8_t *pData, uint32_t Len)
{
    pBufR->data = pData;
    pBufR->len = Len;
    pBufR->pos = 0;
}


const uint8_t *btc_tx_buf_r_get_pos(btc_buf_r_t *pBufR)
{
    return pBufR->data + pBufR->pos;
}


bool btc_tx_buf_r_read(btc_buf_r_t *pBufR, uint8_t *pData, uint32_t Len)
{
    if (pBufR->pos + Len > pBufR->len) return false;
    memcpy(pData, pBufR->data + pBufR->pos, Len);
    pBufR->pos += Len;
    return true;
}


bool btc_tx_buf_r_read_byte(btc_buf_r_t *pBufR, uint8_t *pByte)
{
    if (pBufR->pos + 1 > pBufR->len) return false;
    *pByte = *(pBufR->data + pBufR->pos);
    pBufR->pos++;
    return true;
}


bool btc_tx_buf_r_read_u32le(btc_buf_r_t *pBufR, uint32_t *U32)
{
    if (pBufR->pos + 4 > pBufR->len) return false;
    *U32 = utl_int_pack_u32le(pBufR->data + pBufR->pos);
    pBufR->pos += 4;
    return true;
}


bool btc_tx_buf_r_read_u64le(btc_buf_r_t *pBufR, uint64_t *U64)
{
    if (pBufR->pos + 8 > pBufR->len) return false;
    *U64 = utl_int_pack_u64le(pBufR->data + pBufR->pos);
    pBufR->pos += 8;
    return true;
}


bool btc_tx_buf_r_seek(btc_buf_r_t *pBufR, int32_t offset)
{
    if (offset > 0) {
        if (pBufR->pos + offset > pBufR->len) return false;
    } else {
        if (pBufR->pos < (uint32_t)-offset) return false;
    }
    pBufR->pos += offset;
    return true;
}


uint32_t btc_tx_buf_r_remains(btc_buf_r_t *pBufR)
{
    return pBufR->len - pBufR->pos;
}


bool btc_tx_buf_r_read_varint(btc_buf_r_t *pBufR, uint64_t *pValue)
{
    if (pBufR->pos + 1 > pBufR->len) return false;
    const uint8_t *data_pos = pBufR->data + pBufR->pos;
    if (*(data_pos) < 0xfd) {
        *pValue = *data_pos;
        pBufR->pos += 1;
    } else if (*(data_pos) == 0xfd) {
        if (pBufR->pos + 3 > pBufR->len) return false;
        *pValue = utl_int_pack_u16le(data_pos + 1);
        pBufR->pos += 3;
    } else if (*(data_pos) == 0xfe) {
        if (pBufR->pos + 5 > pBufR->len) return false;
        *pValue = utl_int_pack_u32le(data_pos + 1);
        pBufR->pos += 5;
    } else if (*(data_pos) == 0xff) {
        if (pBufR->pos + 9 > pBufR->len) return false;
        *pValue = utl_int_pack_u64le(data_pos + 1);
        pBufR->pos += 9;
    } else {
        assert(false);
        return false;
    }
    return true;
}
