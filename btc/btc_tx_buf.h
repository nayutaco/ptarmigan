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

//XXX: comment
void btc_tx_buf_r_init(btc_buf_r_t *pBufR, const uint8_t *pData, uint32_t Len);
const uint8_t *btc_tx_buf_r_get_pos(btc_buf_r_t *pBufR);
bool btc_tx_buf_r_read(btc_buf_r_t *pBufR, uint8_t *pData, uint32_t Len);
bool btc_tx_buf_r_read_byte(btc_buf_r_t *pBufR, uint8_t *pByte);
bool btc_tx_buf_r_read_u32le(btc_buf_r_t *pBufR, uint32_t *U32);
bool btc_tx_buf_r_read_u64le(btc_buf_r_t *pBufR, uint64_t *U64);
bool btc_tx_buf_r_seek(btc_buf_r_t *pBufR, int32_t offset);
uint32_t btc_tx_buf_r_remains(btc_buf_r_t *pBufR);
bool btc_tx_buf_r_read_varint(btc_buf_r_t *pBufR, uint64_t *pValue);


#endif /* BTC_TX_BUF_H__ */
