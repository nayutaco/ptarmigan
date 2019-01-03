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
/** @file   btc_buf.c
 *  @brief  btc_buf
 */
#ifdef PTARM_USE_PRINTFUNC
#endif  //PTARM_USE_PRINTFUNC

#include <string.h>
#include <assert.h>

#include "utl_int.h"
#include "utl_dbg.h"

#include "btc_util.h"
#include "btc_buf.h"


/**************************************************************************
 * public functions
 **************************************************************************/

void btc_buf_r_init(btc_buf_r_t *pBufR, const uint8_t *pData, uint32_t Len)
{
    pBufR->_data = pData;
    pBufR->_data_len = Len;
    pBufR->_pos = 0;
}


const uint8_t *btc_buf_r_get_pos(btc_buf_r_t *pBufR)
{
    return pBufR->_data + pBufR->_pos;
}


bool btc_buf_r_read(btc_buf_r_t *pBufR, uint8_t *pData, uint32_t Len)
{
    if (pBufR->_pos + Len > pBufR->_data_len) return false;
    memcpy(pData, pBufR->_data + pBufR->_pos, Len);
    pBufR->_pos += Len;
    return true;
}


bool btc_buf_r_read_byte(btc_buf_r_t *pBufR, uint8_t *pByte)
{
    if (pBufR->_pos + 1 > pBufR->_data_len) return false;
    *pByte = *(pBufR->_data + pBufR->_pos);
    pBufR->_pos++;
    return true;
}


bool btc_buf_r_read_u32le(btc_buf_r_t *pBufR, uint32_t *U32)
{
    if (pBufR->_pos + 4 > pBufR->_data_len) return false;
    *U32 = utl_int_pack_u32le(pBufR->_data + pBufR->_pos);
    pBufR->_pos += 4;
    return true;
}


bool btc_buf_r_read_u64le(btc_buf_r_t *pBufR, uint64_t *U64)
{
    if (pBufR->_pos + 8 > pBufR->_data_len) return false;
    *U64 = utl_int_pack_u64le(pBufR->_data + pBufR->_pos);
    pBufR->_pos += 8;
    return true;
}


bool btc_buf_r_seek(btc_buf_r_t *pBufR, int32_t offset)
{
    if (offset > 0) {
        if (pBufR->_pos + offset > pBufR->_data_len) return false;
    } else {
        if (pBufR->_pos < (uint32_t)-offset) return false;
    }
    pBufR->_pos += offset;
    return true;
}


uint32_t btc_buf_r_remains(btc_buf_r_t *pBufR)
{
    return pBufR->_data_len - pBufR->_pos;
}


bool btc_buf_w_init(btc_buf_w_t *pBufW, uint32_t Size)
{
    pBufW->_pos = 0;
    if (Size) {
        pBufW->_buf = (uint8_t *)UTL_DBG_MALLOC(Size);
        if (!pBufW->_buf) return false;
        pBufW->_buf_len = Size;
    } else {
        pBufW->_buf = NULL;
        pBufW->_buf_len = 0;
    }
    return true;
}


void btc_buf_w_free(btc_buf_w_t *pBufW)
{
    pBufW->_pos = 0;
    if (pBufW->_buf) {
#ifdef PTARM_DEBUG
        memset(pBufW->_buf, 0x00, pBufW->_buf_len);
#endif  //PTARM_DEBUG
        UTL_DBG_FREE(pBufW->_buf);
        pBufW->_buf_len = 0;
    } else {
        //LOGD("no UTL_DBG_FREE memory\n");
    }
}


uint8_t *btc_buf_w_get_data(btc_buf_w_t *pBufW)
{
    return pBufW->_buf;
}


uint32_t btc_buf_w_get_len(btc_buf_w_t *pBufW)
{
    return pBufW->_pos;
}


bool btc_buf_w_write_data(btc_buf_w_t *pBufW, const void *pData, uint32_t Len)
{
    int remains = pBufW->_buf_len - pBufW->_pos - Len;
    if (remains < 0) {
        pBufW->_buf = (uint8_t *)UTL_DBG_REALLOC(pBufW->_buf, pBufW->_buf_len - remains);
        if (!pBufW->_buf) return false;
        pBufW->_buf_len = pBufW->_buf_len - remains;
    }
    memcpy(&pBufW->_buf[pBufW->_pos], pData, Len);
    pBufW->_pos += Len;
    return true;
}


bool btc_buf_w_write_u16le(btc_buf_w_t *pBufW, uint16_t U16)
{
    uint8_t buf[2];
    utl_int_unpack_u16le(buf, U16);
    return btc_buf_w_write_data(pBufW, buf, 2);
}


bool btc_buf_w_write_u32le(btc_buf_w_t *pBufW, uint32_t U32)
{
    uint8_t buf[4];
    utl_int_unpack_u32le(buf, U32);
    return btc_buf_w_write_data(pBufW, buf, 4);
}


bool btc_buf_w_write_u64le(btc_buf_w_t *pBufW, uint64_t U64)
{
    uint8_t buf[8];
    utl_int_unpack_u64le(buf, U64);
    return btc_buf_w_write_data(pBufW, buf, 8);
}


bool btc_buf_w_write_hash256(btc_buf_w_t *pBufW, const void *pData, uint32_t Len)
{
    uint8_t buf[BTC_SZ_HASH256];

    btc_util_hash256(buf, (uint8_t *)pData, Len);
    return btc_buf_w_write_data(pBufW, buf, BTC_SZ_HASH256);
}


void btc_buf_w_truncate(btc_buf_w_t *pBufW)
{
    pBufW->_pos = 0;
}
