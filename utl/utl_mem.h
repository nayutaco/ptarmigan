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
/**
 * @file    utl_mem.h
 * @brief   utl_mem
 */
#ifndef UTL_MEM_H__
#define UTL_MEM_H__

#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

//XXX: comment & test
void utl_mem_reverse_byte(uint8_t *pDst, const uint8_t *pSrc, size_t Len);
void utl_mem_swap(void *pA, void *pB, void *pTemp, size_t Len);


/** 全データが0x00かのチェック
 *
 * @param[in]       pData               チェック対象
 * @param[in]       Len                 pData長
 * @retval  true    全データが0x00
 */
bool utl_mem_is_all_zero(const void *pData, size_t Len);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_MEM_H__ */
