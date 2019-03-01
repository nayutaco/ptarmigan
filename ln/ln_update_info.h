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
/** @file   ln_update_info.h
 *  @brief  ln_update_info
 */
#ifndef LN_UPDATE_INFO_H__
#define LN_UPDATE_INFO_H__

#include <stdint.h>
#include <stdbool.h>


/********************************************************************
 * macros
 ********************************************************************/

#define LN_HTLC_OFFERED_MAX_XXX         (6)         ///<
#define LN_HTLC_RECEIVED_MAX            (6)         ///<
#define LN_HTLC_MAX_XXX                 (LN_HTLC_OFFERED_MAX_XXX + LN_HTLC_RECEIVED_MAX)


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    ln_update_t                 updates[LN_UPDATE_MAX];         ///< updates
    ln_htlc_t                   htlcs[LN_HTLC_RECEIVED_MAX];    ///< htlcs
    uint64_t                    next_htlc_id;                   ///< update_add_htlcで使うidの管理 //XXX: Append immediately before sending
} ln_update_info_t;


#endif /* LN_UPDATE_INFO_H__ */
