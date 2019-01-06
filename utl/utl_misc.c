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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "utl_local.h"
#include "utl_misc.h"


/**************************************************************************
 * private variables
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

void utl_misc_msleep(unsigned long slp)
{
    struct timespec req = { 0, (long)(slp * 1000000UL) };
    nanosleep(&req, NULL);
}


bool utl_misc_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr)
{
    if (strlen(pStr) != BinLen * 2) {
        LOGD("fail: invalid buffer size: %zu != %" PRIu32 " * 2\n", strlen(pStr), BinLen);
        return false;
    }

    bool ret = true;

    char str[3];
    str[2] = '\0';
    uint32_t lp;
    for (lp = 0; lp < BinLen; lp++) {
        str[0] = *(pStr + 2 * lp);
        str[1] = *(pStr + 2 * lp + 1);
        if (!isxdigit(str[0]) || !isxdigit(str[1])) {
            LOGD("fail: str=%s\n", str);
            ret = false;
            break;
        }
        pBin[lp] = (uint8_t)strtoul(str, NULL, 16);
    }

    return ret;
}


bool utl_misc_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr)
{
    bool ret = utl_misc_str2bin(pBin, BinLen, pStr);
    if (ret) {
        for (uint32_t lp = 0; lp < BinLen / 2; lp++) {
            uint8_t tmp = pBin[lp];
            pBin[lp] = pBin[BinLen - lp - 1];
            pBin[BinLen - lp - 1] = tmp;
        }
    }

    return ret;
}


bool utl_misc_is_all_zero(const void *pData, size_t Len)
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


void utl_misc_bin2str(char *pStr, const uint8_t *pBin, uint32_t BinLen)
{
    *pStr = '\0';
    for (uint32_t lp = 0; lp < BinLen; lp++) {
        char str[3];
        sprintf(str, "%02x", pBin[lp]);
        strcat(pStr, str);
    }
}


void utl_misc_bin2str_rev(char *pStr, const uint8_t *pBin, uint32_t BinLen)
{
    *pStr = '\0';
    for (uint32_t lp = 0; lp < BinLen; lp++) {
        char str[3];
        sprintf(str, "%02x", pBin[BinLen - lp - 1]);
        strcat(pStr, str);
    }
}

