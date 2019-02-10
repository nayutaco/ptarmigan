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
/** @file   ln_htlc.c
 *  @brief  ln_htlc
 */
#include "ln_htlc.h"


/**************************************************************************
 * public functions
 **************************************************************************/

#if 0
uint32_t ln_htlc_flags2u32(ln_htlc_flags_t Flags)
{
    if (sizeof(ln_htlc_flags_t) == 2) {
        return utl_int_pack_u16be((const uint8_t *)Flags);
    } else if (sizeof(ln_htlc_flags_t) == 4) {
        return utl_int_pack_u32be((const uint8_t *)Flags);
    } else {
        return 0;
    }
}
#endif
