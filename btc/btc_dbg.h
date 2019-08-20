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
/** @file   btc_dbg.h
 *  @brief  btc_dbg
 */
#ifndef BTC_DBG_H__
#define BTC_DBG_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * typedefs
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
void btc_dbg_dump_txid(FILE *fp, const uint8_t *pTxid);
#else
#define btc_dbg_dump_txid(...)
#endif  //PTARM_USE_PRINTFUNC


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_DBG_H__ */
