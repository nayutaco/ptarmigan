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
/** @file   btc_dbg.c
 *  @brief  btc_dbg
 */
#include <sys/stat.h>
#include <sys/types.h>

#include "btc_tx.h"
#include "btc_dbg.h"


/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * private variables
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

/**************************************************************************
 *const variables
 **************************************************************************/

/**************************************************************************
 * public functions
 **************************************************************************/

#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
/** uint8[]の内容をFILE*出力
 *
 * @param[in]       fp          出力先
 * @param[in]       pTxid
 */
void btc_dbg_dump_txid(FILE *fp, const uint8_t *pTxid)
{
    for (uint16_t lp = 0; lp < BTC_SZ_TXID; lp++) {
        fprintf(fp, "%02x", pTxid[BTC_SZ_TXID - lp - 1]);
    }
}
#endif  //PTARM_USE_PRINTFUNC || PTARM_DEBUG


/**************************************************************************
 * private functions
 **************************************************************************/


