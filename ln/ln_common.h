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
/** @file   ln_common.h
 *  @brief  ln_common
 */
#ifndef LN_COMMON_H__
#define LN_COMMON_H__

#include <stdint.h>
#include <stdbool.h>


/**************************************************************************
 * macros
 **************************************************************************/

#define LN_SZ_SIGNATURE                 BTC_SZ_SIGN_RS    ///< (size) signature

#define LN_DBG_PRINT
#ifdef LN_DBG_PRINT
#define LN_DBG_COMMIT_NUM_PRINT(pChannel) { LOGD("----- debug commit_num -----\n"); ln_dbg_commitnum(pChannel); }
#define LN_DBG_UPDATE_PRINT(pUpdate) ln_update_print(pUpdate)
#define LN_DBG_UPDATES_PRINT(pUpdates) ln_update_updates_print(pUpdates)
#else
#define LN_DBG_COMMIT_NUM_PRINT(pChannel) //none
#define LN_DBG_UPDATE_PRINT(pUpdate) //none
#define LN_DBG_UPDATES_PRINT(pUpdates) //none
#endif


#endif /* LN_COMMON_H__ */
