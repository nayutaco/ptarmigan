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

