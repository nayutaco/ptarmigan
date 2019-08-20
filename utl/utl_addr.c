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

#include <stdio.h>
#include <string.h>

#include "utl_addr.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_addr_ipv4_str2bin(uint8_t b[4], const char *s)
{
    int bi = 0;
    int decc = 0;
    for (int si = 0; si < (int)strlen(s) + 1; si++) {
        if (s[si] >= '0' && s[si] <= '9') { //decimal
            //over
            if (decc == 3) return false;

            //leading a zero
            if (decc == 1 && s[si - 1] == '0') return false;

            decc++;
        } else if (s[si] == '.' || s[si] == '\0') { //separater
            //over
            if (bi == 4) return false;

            //leading non-decimal
            if (decc == 0) return false;    
            
            //decc is 1 or 2 or 3  
            uint32_t b32 = s[si - decc--] - '0';
            if (decc) {
                b32 *= 10;
                b32 += s[si - decc--] - '0';
            }
            if (decc) {
                b32 *= 10;
                b32 += s[si - decc--] - '0';
            }
            
            if (b32 >= 256) return false;
            b[bi++] = (uint8_t)b32;
        } else {
            return false;
        }
    }
    if (bi != 4) return false;
    return true;
}
