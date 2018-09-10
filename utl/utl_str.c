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

#include <string.h>

#include "utl_str.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_str_scan_u32(uint32_t *n, const char* s)
{
    const char* UINT32_MAX_STR = "4294967295";

    if (!s[0]) return false;
    if (s[0] == '0' && strlen(s) > 1) return false; //leading zeros are not allowed

    //check overflow
    if (strlen(s) > strlen(UINT32_MAX_STR)) return false;
    if (strlen(s) == strlen(UINT32_MAX_STR)) {
        for (int i = 0; i < (int)strlen(s); i++) {
            if (s[i] > UINT32_MAX_STR[i]) return false;
            if (s[i] == UINT32_MAX_STR[i]) continue;
            break;
        }
    }
  
    *n = 0;
    for (int i = 0; s[i]; i++) {
        *n *= 10;
        if (s[i] < '0' || s[i] > '9') return false;
        *n += s[i] - '0';
    }

    return true;
}
