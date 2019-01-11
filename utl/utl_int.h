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
/**
 * @file    utl_int.h
 * @brief   utl_int
 */
#ifndef UTL_INT_H__
#define UTL_INT_H__

#include <stdint.h>
#include <inttypes.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define M_UINT16_MAX_DIGIT  (5)
#define M_UINT32_MAX_DIGIT  (10)
#define M_UINT64_MAX_DIGIT  (20)


/**************************************************************************
 * prototypes
 **************************************************************************/

uint16_t utl_int_pack_u16le(const uint8_t *pData);
uint32_t utl_int_pack_u32le(const uint8_t *pData);
uint64_t utl_int_pack_u64le(const uint8_t *pData);
uint16_t utl_int_pack_u16be(const uint8_t *pData);
uint32_t utl_int_pack_u32be(const uint8_t *pData);
uint64_t utl_int_pack_u64be(const uint8_t *pData);
void utl_int_unpack_u16be(uint8_t *pData, uint16_t U16);
void utl_int_unpack_u32be(uint8_t *pData, uint32_t U32);
void utl_int_unpack_u64be(uint8_t *pData, uint64_t U64);
void utl_int_unpack_u16le(uint8_t *pData, uint16_t U16);
void utl_int_unpack_u32le(uint8_t *pData, uint32_t U32);
void utl_int_unpack_u64le(uint8_t *pData, uint64_t U64);

//return digit number
// note: if V=0 return 0 not 1
uint8_t utl_int_digit(uint64_t V, uint8_t base);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_INT_H__ */
