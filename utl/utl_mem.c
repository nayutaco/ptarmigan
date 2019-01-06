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

#include "utl_mem.h"


/**************************************************************************
 * private variables
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

void utl_mem_reverse_byte(uint8_t *pDst, const uint8_t *pSrc, size_t Len)
{
    for (size_t i = 0; i < Len / 2; i++) {
        pDst[i] = pSrc[Len - 1 - i];
    }
}

void utl_mem_swap(void *pA, void *pB, void *pTemp, size_t Len)
{
    memcpy(pTemp, pA, Len);
    memcpy(pA, pB, Len);
    memcpy(pB, pTemp, Len);
}


bool utl_mem_is_all_zero(const void *pData, size_t Len)
{
    bool ret = true;
    const uint8_t *p = (const uint8_t *)pData;
    for (size_t lp = 0; lp < Len; lp++) {
        if (p[lp] != 0x00) {
            ret = false;
            break;
        }
    }
    return ret;
}


