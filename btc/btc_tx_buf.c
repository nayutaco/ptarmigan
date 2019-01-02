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
#include "utl_dbg.h"

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


bool btc_tx_buf_w_init(btc_buf_w_t *pBufW, utl_buf_t *pBuf, uint32_t Size)
{
    pBufW->pos = 0;
    pBufW->buf = pBuf;
    if (Size) {
        if (!utl_buf_alloc(pBufW->buf, Size)) return false;
    } else {
        utl_buf_init(pBufW->buf);
    }
    return true;
}


uint8_t *btc_tx_buf_w_get_data(btc_buf_w_t *pBufW)
{
    return pBufW->buf->buf;
}


uint32_t btc_tx_buf_w_get_len(btc_buf_w_t *pBufW)
{
    return pBufW->pos;
}


bool btc_tx_buf_w_write_data(btc_buf_w_t *pBufW, const void *pData, uint32_t Len)
{
    int remains = pBufW->buf->len - pBufW->pos - Len;
    if (remains < 0) {
        pBufW->buf->buf = (uint8_t *)UTL_DBG_REALLOC(pBufW->buf->buf, pBufW->buf->len - remains);
        if (!pBufW->buf->buf) return false;
        pBufW->buf->len = pBufW->buf->len - remains;
    }
    memcpy(&pBufW->buf->buf[pBufW->pos], pData, Len);
    pBufW->pos += Len;
    return true;
}


bool btc_tx_buf_w_write_varint_len(btc_buf_w_t *pBufW, uint64_t Size)
{
    uint8_t buf[9];
    uint32_t len;

    if (Size < 0xfd) {
        len = 1;
        buf[0] = (uint8_t)Size;
    } else if (Size <= UINT16_MAX) {
        len = 3;
        buf[0] = 0xfd;
        utl_int_unpack_u16le(buf + 1, (uint16_t)Size);
    } else if (Size <= UINT32_MAX) {
        len = 5;
        buf[0] = 0xfe;
        utl_int_unpack_u32le(buf + 1, (uint32_t)Size);
    } else {
        len = 9;
        buf[0] = 0xff;
        utl_int_unpack_u64le(buf + 1, Size);
    }
    return btc_tx_buf_w_write_data(pBufW, buf, len);
}


bool btc_tx_buf_w_trim(btc_buf_w_t *pBufW)
{
    if (pBufW->buf->len != pBufW->pos) {
        if (pBufW->pos == 0) {
            utl_buf_free(pBufW->buf);
        } else {
            pBufW->buf->len = pBufW->pos;
            pBufW->buf->buf = (uint8_t *)UTL_DBG_REALLOC(pBufW->buf->buf, pBufW->pos);
            if (!pBufW->buf->buf) return false;
        }
    }
    return true;
}


void btc_tx_buf_w_truncate(btc_buf_w_t *pBufW)
{
    pBufW->pos = 0;
}
