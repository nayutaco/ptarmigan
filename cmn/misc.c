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

#include "misc.h"
#include "ucoind.h"


void misc_bin2str(char *pStr, const uint8_t *pBin, uint16_t BinLen)
{
    *pStr = '\0';
    for (int lp = 0; lp < BinLen; lp++) {
        char str[3];
        sprintf(str, "%02x", pBin[lp]);
        strcat(pStr, str);
    }
}


void misc_bin2str_rev(char *pStr, const uint8_t *pBin, uint16_t BinLen)
{
    *pStr = '\0';
    for (int lp = 0; lp < BinLen; lp++) {
        char str[3];
        sprintf(str, "%02x", pBin[BinLen - lp - 1]);
        strcat(pStr, str);
    }
}


bool misc_str2bin(uint8_t *pBin, uint16_t BinLen, const char *pStr)
{
    if (strlen(pStr) != BinLen * 2) {
        DBG_PRINTF("fail: invalid buffer size\n");
        return false;
    }

    bool ret = true;

    char str[3];
    str[2] = '\0';
    int lp;
    for (lp = 0; lp < BinLen; lp++) {
        str[0] = *(pStr + 2 * lp);
        str[1] = *(pStr + 2 * lp + 1);
        if (!str[0]) {
            //偶数文字で\0ならばOK
            break;
        }
        if (!str[1]) {
            //奇数文字で\0ならばNG
            DBG_PRINTF("fail: odd length\n");
            ret = false;
            break;
        }
        char *endp = NULL;
        uint8_t bin = (uint8_t)strtoul(str, &endp, 16);
        if ((endp != NULL) && (*endp != 0x00)) {
            //変換失敗
            DBG_PRINTF("fail: *endp = %p(%02x)\n", endp, *endp);
            ret = false;
            break;
        }
        pBin[lp] = bin;
    }

    return ret;
}


bool misc_str2bin_rev(uint8_t *pBin, uint16_t BinLen, const char *pStr)
{
    bool ret = misc_str2bin(pBin, BinLen, pStr);
    if (ret) {
        for (int lp = 0; lp < BinLen / 2; lp++) {
            uint8_t tmp = pBin[lp];
            pBin[lp] = pBin[BinLen - lp - 1];
            pBin[BinLen - lp - 1] = tmp;
        }
    }

    return ret;
}
