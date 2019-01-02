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
    pBufR->_data = pData;
    pBufR->_data_len = Len;
    pBufR->_pos = 0;
}


const uint8_t *btc_tx_buf_r_get_pos(btc_buf_r_t *pBufR)
{
    return pBufR->_data + pBufR->_pos;
}


bool btc_tx_buf_r_read(btc_buf_r_t *pBufR, uint8_t *pData, uint32_t Len)
{
    if (pBufR->_pos + Len > pBufR->_data_len) return false;
    memcpy(pData, pBufR->_data + pBufR->_pos, Len);
    pBufR->_pos += Len;
    return true;
}


bool btc_tx_buf_r_read_byte(btc_buf_r_t *pBufR, uint8_t *pByte)
{
    if (pBufR->_pos + 1 > pBufR->_data_len) return false;
    *pByte = *(pBufR->_data + pBufR->_pos);
    pBufR->_pos++;
    return true;
}


bool btc_tx_buf_r_read_u32le(btc_buf_r_t *pBufR, uint32_t *U32)
{
    if (pBufR->_pos + 4 > pBufR->_data_len) return false;
    *U32 = utl_int_pack_u32le(pBufR->_data + pBufR->_pos);
    pBufR->_pos += 4;
    return true;
}


bool btc_tx_buf_r_read_u64le(btc_buf_r_t *pBufR, uint64_t *U64)
{
    if (pBufR->_pos + 8 > pBufR->_data_len) return false;
    *U64 = utl_int_pack_u64le(pBufR->_data + pBufR->_pos);
    pBufR->_pos += 8;
    return true;
}


bool btc_tx_buf_r_seek(btc_buf_r_t *pBufR, int32_t offset)
{
    if (offset > 0) {
        if (pBufR->_pos + offset > pBufR->_data_len) return false;
    } else {
        if (pBufR->_pos < (uint32_t)-offset) return false;
    }
    pBufR->_pos += offset;
    return true;
}


uint32_t btc_tx_buf_r_remains(btc_buf_r_t *pBufR)
{
    return pBufR->_data_len - pBufR->_pos;
}


bool btc_tx_buf_r_read_varint(btc_buf_r_t *pBufR, uint64_t *pValue)
{
    if (pBufR->_pos + 1 > pBufR->_data_len) return false;
    const uint8_t *data_pos = pBufR->_data + pBufR->_pos;
    if (*(data_pos) < 0xfd) {
        *pValue = *data_pos;
        pBufR->_pos += 1;
    } else if (*(data_pos) == 0xfd) {
        if (pBufR->_pos + 3 > pBufR->_data_len) return false;
        *pValue = utl_int_pack_u16le(data_pos + 1);
        pBufR->_pos += 3;
    } else if (*(data_pos) == 0xfe) {
        if (pBufR->_pos + 5 > pBufR->_data_len) return false;
        *pValue = utl_int_pack_u32le(data_pos + 1);
        pBufR->_pos += 5;
    } else if (*(data_pos) == 0xff) {
        if (pBufR->_pos + 9 > pBufR->_data_len) return false;
        *pValue = utl_int_pack_u64le(data_pos + 1);
        pBufR->_pos += 9;
    } else {
        assert(false);
        return false;
    }
    return true;
}


bool btc_tx_buf_w_init(btc_buf_w_t *pBufW, uint32_t Size)
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


void btc_tx_buf_w_free(btc_buf_w_t *pBufW)
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


uint8_t *btc_tx_buf_w_get_data(btc_buf_w_t *pBufW)
{
    return pBufW->_buf;
}


uint32_t btc_tx_buf_w_get_len(btc_buf_w_t *pBufW)
{
    return pBufW->_pos;
}


bool btc_tx_buf_w_write_data(btc_buf_w_t *pBufW, const void *pData, uint32_t Len)
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


void btc_tx_buf_w_truncate(btc_buf_w_t *pBufW)
{
    pBufW->_pos = 0;
}
