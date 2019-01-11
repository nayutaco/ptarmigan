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
#include <assert.h>

#include "utl_int.h"


/**************************************************************************
 * private variables
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

uint16_t utl_int_pack_u16le(const uint8_t *pData)
{
    return (uint16_t)(
        *pData |
        (uint16_t)*(pData + 1) << 8
    );
}


uint32_t utl_int_pack_u32le(const uint8_t *pData)
{
    return (uint32_t)(
        *pData |
        (uint32_t)*(pData + 1) << 8 |
        (uint32_t)*(pData + 2) << 16 |
        (uint32_t)*(pData + 3) << 24
    );
}


uint64_t utl_int_pack_u64le(const uint8_t *pData)
{
    return (uint64_t)(
        *pData |
        (uint64_t)*(pData + 1) << 8 |
        (uint64_t)*(pData + 2) << 16 |
        (uint64_t)*(pData + 3) << 24 |
        (uint64_t)*(pData + 4) << 32 |
        (uint64_t)*(pData + 5) << 40 |
        (uint64_t)*(pData + 6) << 48 |
        (uint64_t)*(pData + 7) << 56
    );
}


uint64_t utl_int_pack_u64be(const uint8_t *pData)
{
    return (uint64_t)(
        (uint64_t)*pData << 56 |
        (uint64_t)*(pData + 1) << 48 |
        (uint64_t)*(pData + 2) << 40 |
        (uint64_t)*(pData + 3) << 32 |
        (uint64_t)*(pData + 4) << 24 |
        (uint64_t)*(pData + 5) << 16 |
        (uint64_t)*(pData + 6) << 8 |
        *(pData + 7)
    );
}


uint32_t utl_int_pack_u32be(const uint8_t *pData)
{
    return (uint32_t)(
        (uint32_t)*pData << 24 |
        (uint32_t)*(pData + 1) << 16 |
        (uint32_t)*(pData + 2) << 8 |
        *(pData + 3)
    );
}


uint16_t utl_int_pack_u16be(const uint8_t *pData)
{
    return (uint16_t)(
        (uint16_t)*pData << 8 |
        *(pData + 1)
    );
}


void utl_int_unpack_u16be(uint8_t *pData, uint16_t U16)
{
    pData[0] = (uint8_t)(U16 >> 8);
    pData[1] = (uint8_t)U16;
}


void utl_int_unpack_u32be(uint8_t *pData, uint32_t U32)
{
    pData[0] = (uint8_t)(U32 >> 24);
    pData[1] = (uint8_t)(U32 >> 16);
    pData[2] = (uint8_t)(U32 >> 8);
    pData[3] = (uint8_t)U32;
}


void utl_int_unpack_u64be(uint8_t *pData, uint64_t U64)
{
    pData[0] = (uint8_t)(U64 >> 56);
    pData[1] = (uint8_t)(U64 >> 48);
    pData[2] = (uint8_t)(U64 >> 40);
    pData[3] = (uint8_t)(U64 >> 32);
    pData[4] = (uint8_t)(U64 >> 24);
    pData[5] = (uint8_t)(U64 >> 16);
    pData[6] = (uint8_t)(U64 >> 8);
    pData[7] = (uint8_t)U64;
}


void utl_int_unpack_u16le(uint8_t *pData, uint16_t U16)
{
    pData[0] = (uint8_t)U16;
    pData[1] = (uint8_t)(U16 >> 8);
}


void utl_int_unpack_u32le(uint8_t *pData, uint32_t U32)
{
    pData[0] = (uint8_t)U32;
    pData[1] = (uint8_t)(U32 >> 8);
    pData[2] = (uint8_t)(U32 >> 16);
    pData[3] = (uint8_t)(U32 >> 24);
}


void utl_int_unpack_u64le(uint8_t *pData, uint64_t U64)
{
    pData[0] = (uint8_t)U64;
    pData[1] = (uint8_t)(U64 >> 8);
    pData[2] = (uint8_t)(U64 >> 16);
    pData[3] = (uint8_t)(U64 >> 24);
    pData[4] = (uint8_t)(U64 >> 32);
    pData[5] = (uint8_t)(U64 >> 40);
    pData[6] = (uint8_t)(U64 >> 48);
    pData[7] = (uint8_t)(U64 >> 56);
}


uint8_t utl_int_digit(uint64_t V, uint8_t base)
{
    assert(base);

    uint8_t digit = 0;
    while (V) {
        V /= base;
        digit++;
    }
    return digit;
}
