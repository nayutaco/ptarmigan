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

#include <assert.h>
#include <string.h>
#include <ctype.h>

#include "utl_local.h"
#include "utl_dbg.h"
#include "utl_int.h"
#include "utl_str.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_str_scan_u16(uint16_t *n, const char* s)
{
    const char* UINT16_MAX_STR = "65535";

    assert(s != NULL && n != NULL);

    if (!s[0]) return false;
    if (s[0] == '0' && s[1] != '\0') return false; //leading zeros are not allowed

    //check overflow
    if (strlen(s) > sizeof(UINT16_MAX_STR) - 1) return false;
    if (strlen(s) == sizeof(UINT16_MAX_STR) - 1) {
        for (int i = 0; i < (int)strlen(s); i++) {
            if (s[i] > UINT16_MAX_STR[i]) return false;
            if (s[i] == UINT16_MAX_STR[i]) continue;
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

bool utl_str_scan_u32(uint32_t *n, const char* s)
{
    const char* UINT32_MAX_STR = "4294967295";

    assert(s != NULL && n != NULL);

    if (!s[0]) return false;
    if (s[0] == '0' && s[1] != '\0') return false; //leading zeros are not allowed

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

void utl_str_init(utl_str_t *x)
{
    memset(x, 0x00, sizeof(utl_str_t));
}

bool utl_str_append(utl_str_t *x, const char *s)
{
    if (!s) return false;
    if (x->buf) {
        //after calling UTL_DBG_REALLOC x->buf may be broken, therefore, preserve its length
        uint32_t n_org = strlen(x->buf);

        uint32_t n = strlen(x->buf) + strlen(s) + 1;
        char* tmp = (char*)UTL_DBG_REALLOC(x->buf, n);
        if (!tmp) return false;
        strncpy(tmp + n_org, s, strlen(s) + 1);
        x->buf = tmp;
    } else {
        x->buf = UTL_DBG_STRDUP(s);
        if (!x->buf) return false;
    }
    return true;
}

const char *utl_str_get(utl_str_t *x)
{
    return x->buf ? x->buf : "";
}

void utl_str_free(utl_str_t *x)
{
    if (x->buf) {
        UTL_DBG_FREE(x->buf);
    }
    memset(x, 0x00, sizeof(utl_str_t));
}


bool utl_str_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr)
{
    if (strlen(pStr) != BinLen * 2) {
        LOGE("fail: invalid buffer size: %zu != %" PRIu32 " * 2\n", strlen(pStr), BinLen);
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
            LOGE("fail: str=%s\n", str);
            ret = false;
            break;
        }
        pBin[lp] = (uint8_t)strtoul(str, NULL, 16);
    }

    return ret;
}


bool utl_str_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr)
{
    bool ret = utl_str_str2bin(pBin, BinLen, pStr);
    if (ret) {
        for (uint32_t lp = 0; lp < BinLen / 2; lp++) {
            uint8_t tmp = pBin[lp];
            pBin[lp] = pBin[BinLen - lp - 1];
            pBin[BinLen - lp - 1] = tmp;
        }
    }

    return ret;
}


void utl_str_bin2str(char *pStr, const uint8_t *pBin, uint32_t BinLen)
{
    assert(pStr != NULL && pBin != NULL);

    *pStr = '\0';
    for (uint32_t lp = 0; lp < BinLen; lp++) {
        char str[3];
        sprintf(str, "%02x", pBin[lp]);
        strcat(pStr, str);
    }
}


void utl_str_bin2str_rev(char *pStr, const uint8_t *pBin, uint32_t BinLen)
{
    assert(pStr != NULL && pBin != NULL);

    *pStr = '\0';
    for (uint32_t lp = 0; lp < BinLen; lp++) {
        char str[3];
        sprintf(str, "%02x", pBin[BinLen - lp - 1]);
        strcat(pStr, str);
    }
}


bool utl_str_itoa(char *pStr, uint32_t Size, uint64_t Value)
{
    uint8_t digit = (Value) ? utl_int_digit(Value, 10) : 1;

    assert(pStr != NULL);

    if (Size <= digit) return false;
    pStr[digit] = '\0';

    while (digit--) {
        pStr[digit] = (uint8_t)('0' + Value % 10);
        Value /= 10;
    }
    return true;
}


bool utl_str_copy_and_fill_zeros(char *pDst, const char *pSrc, uint32_t Size)
{
    assert(pDst != NULL && pSrc != NULL);

    if (Size < strlen(pSrc)) return false;
    strncpy(pDst, pSrc, Size); //`strncpy` fills zeros
    return true;
}


bool utl_str_copy_and_append_zero(char *pBuf, uint32_t BufSize, const uint8_t *pData, uint32_t DataSize)
{
    assert(pBuf != NULL && pData != NULL);

    if (BufSize <= DataSize) return false;
    strncpy(pBuf, (const char *)pData, DataSize); //`strncpy` fills zeros
    pBuf[DataSize] = 0;
    return true;
}
