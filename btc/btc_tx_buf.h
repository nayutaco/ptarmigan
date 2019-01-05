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
/** @file   btc_tx_buf.h
 *  @brief  btc_tx_buf
 */
#ifndef BTC_TX_BUF_H__
#define BTC_TX_BUF_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>

#include <btc_buf.h>


/**************************************************************************
 * typedefs
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

//XXX: test & comment
#define btc_tx_buf_r_init           btc_buf_r_init
#define btc_tx_buf_r_get_pos        btc_buf_r_get_pos
#define btc_tx_buf_r_read           btc_buf_r_read
#define btc_tx_buf_r_read_byte      btc_buf_r_read_byte
#define btc_tx_buf_r_read_u32le     btc_buf_r_read_u32le
#define btc_tx_buf_r_read_u64le     btc_buf_r_read_u64le
#define btc_tx_buf_r_seek           btc_buf_r_seek
#define btc_tx_buf_r_remains        btc_buf_r_remains
bool btc_tx_buf_r_read_varint(btc_buf_r_t *pBufR, uint64_t *pValue);


//XXX: comment
#define btc_tx_buf_w_init           btc_buf_w_init
#define btc_tx_buf_w_free           btc_buf_w_free
#define btc_tx_buf_w_get_data       btc_buf_w_get_data
#define btc_tx_buf_w_get_len        btc_buf_w_get_len
#define btc_tx_buf_w_write_data     btc_buf_w_write_data
#define btc_tx_buf_w_write_byte     btc_buf_w_write_byte
#define btc_tx_buf_w_write_u32le    btc_buf_w_write_u32le
#define btc_tx_buf_w_write_u64le    btc_buf_w_write_u64le
bool btc_tx_buf_w_write_varint_len(btc_buf_w_t *pBufW, uint64_t Size);
bool btc_tx_buf_w_write_varint_len_data(btc_buf_w_t *pBufW, const void *pData, uint32_t Len);
#define btc_tx_buf_w_truncate       btc_buf_w_truncate


#endif /* BTC_TX_BUF_H__ */
