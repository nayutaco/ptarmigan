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
/** @file   btc_script_buf.h
 *  @brief  btc_script_buf
 *
 * @note
 *      - btc_script_buf
 *
 */
#ifndef BTC_SCRIPT_BUF_H__
#define BTC_SCRIPT_BUF_H__

#include <stdint.h>
#include <stdbool.h>

#include <utl_buf.h>

#include <btc_buf.h>


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * types
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

//https://en.bitcoin.it/wiki/Script
// see `Constants`
//XXX: comment
bool btc_script_buf_w_init(btc_buf_w_t *pBufW, uint32_t Size);
void btc_script_buf_w_free(btc_buf_w_t *pBufW);
uint8_t *btc_script_buf_w_get_data(btc_buf_w_t *pBufW);
uint32_t btc_script_buf_w_get_len(btc_buf_w_t *pBufW);
bool btc_script_buf_w_write_data(btc_buf_w_t *pBufW, const void *pData, uint32_t Len);
bool btc_script_buf_w_write_item(btc_buf_w_t *pBufW, const void *pData, uint32_t Len);
void btc_script_buf_w_truncate(btc_buf_w_t *pBufW);


/** write an item of a positive integer to the stack
 *
 * As a result `Value` will be 2-6 bytes on the stack.<br>
 * Integers on the stack are interpreted as a signed.<br>
 * However, only positive integers (0-549755813887) can be witten by this function.
 *
 * @param[out]  pBufW       buffer
 * @param[in]   Value       value (0-549755813887)
 * @retval      true    success
 */
bool btc_script_buf_w_write_item_positive_integer(btc_buf_w_t *pBufW, uint64_t Value);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_SCRIPT_BUF_H__ */
