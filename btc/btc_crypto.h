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
/** @file   btc_crypto.h
 *  @brief  btc_crypto
 */
#ifndef BTC_CRYPTO_H__
#define BTC_CRYPTO_H__

#include <sys/types.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>


/**************************************************************************
 * typedefs
 **************************************************************************/

/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * macro functions
 **************************************************************************/

/**************************************************************************
 * package variables
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

/** 圧縮された公開鍵をkeypairに展開する
 *
 * @param[in]       pPubKey     圧縮された公開鍵
 * @return      0   成功
 * @note
 *      - https://bitcointalk.org/index.php?topic=644919.0
 *      - https://gist.github.com/flying-fury/6bc42c8bb60e5ea26631
 */
int HIDDEN btcl_util_set_keypair(void *pKeyPair, const uint8_t *pPubKey);



#endif /* BTC_CRYPTO_H__ */
