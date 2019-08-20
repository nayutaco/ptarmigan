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
/** @file   btc_test_util.h
 *  @brief  btc_test_util
 */
#ifndef BTC_TEST_UTIL_H__
#define BTC_TEST_UTIL_H__

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"

#include "btc_keys.h"


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

/** P2PKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       pKeys
 * @return      true:成功
 */
bool btc_test_util_sign_p2pkh(btc_tx_t *pTx, uint32_t Index, const btc_keys_t *pKeys);


/** P2PKH署名チェック
 *
 * @param[in,out]   pTx         一時的に更新する
 * @param[in]       Index
 * @param[in]       pAddrVout   チェック用
 * @return      true:成功
 */
bool btc_test_util_verify_p2pkh(btc_tx_t *pTx, uint32_t Index, const char *pAddrVout);


/** P2WPKH署名
 *
 * @param[out]      pTx
 * @param[in]       Index
 * @param[in]       Value
 * @param[in]       pKeys
 * @return      true:成功
 * @note
 *      - #btc_init()の設定で署名する
 */
bool btc_test_util_sign_p2wpkh(btc_tx_t *pTx, uint32_t Index, uint64_t Value, const btc_keys_t *pKeys);


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* BTC_TEST_UTIL_H__ */
