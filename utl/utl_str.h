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
 * @file    utl_str.h
 * @brief   utl_str
 */
#ifndef UTL_STR_H__
#define UTL_STR_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


/**************************************************************************
 * types
 **************************************************************************/

/** @struct utl_str_t
 *  @brief  string buffer
 *
 */
typedef struct {
    char            *buf;       ///< buffer
} utl_str_t;

/**************************************************************************
 * prototypes
 **************************************************************************/

/** convert string to uint16_t
 *
 * @param[out]  n       uint16_t number
 * @param[in]   s       string
 * @retval      true    success
 */
bool utl_str_scan_u16(uint16_t *n, const char *s);

/** convert string to uint32_t
 *
 * @param[out]  n       uint32_t number
 * @param[in]   s       string
 * @retval      true    success
 */
bool utl_str_scan_u32(uint32_t *n, const char *s);

/** init #utl_str_t
 *
 * @param[in,out]   x   object
 */
void utl_str_init(utl_str_t *x);

/** append string
 *
 * @param[out]  x   object
 */
bool utl_str_append(utl_str_t *x, const char *s);

/** get string
 *
 * @param[in]   x   object
 */
const char *utl_str_get(utl_str_t *x);

/** free #utl_str_t
 *
 * @param[in]   x   object
 */
void utl_str_free(utl_str_t *x);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_STR_H__ */
