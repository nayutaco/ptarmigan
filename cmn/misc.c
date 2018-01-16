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
#include <sys/socket.h>
#include <arpa/inet.h>

#include "misc.h"
#include "ucoind.h"


/**************************************************************************
 * private variables
 **************************************************************************/

#ifdef APP_DEBUG_MEM
static int mcount = 0;
#endif  //APP_DEBUG_MEM


/**************************************************************************
 *const variables
 **************************************************************************/

// https://github.com/lightningnetwork/lightning-rfc/issues/237
// https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
static const uint8_t M_BTC_GENESIS_MAIN[] = {
    // bitcoin mainnet
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_TEST[] = {
    // bitcoin testnet
    0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
    0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
    0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
    0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_REGTEST[] = {
    // bitcoin regtest
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
    0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
    0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
};


/**************************************************************************
 * public functions
 **************************************************************************/

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


misc_genesis_t misc_get_genesis(const uint8_t *pGenesisHash)
{
    misc_genesis_t ret;
    
    if (memcmp(pGenesisHash, M_BTC_GENESIS_MAIN, LN_SZ_HASH) == 0) {
        ret = MISC_GENESIS_BTCMAIN;
    } else if (memcmp(pGenesisHash, M_BTC_GENESIS_TEST, LN_SZ_HASH) == 0) {
        ret = MISC_GENESIS_BTCTEST;
    } else if (memcmp(pGenesisHash, M_BTC_GENESIS_REGTEST, LN_SZ_HASH) == 0) {
        ret = MISC_GENESIS_BTCREGTEST;
    } else {
        DBG_PRINTF2("unknown genesis hash\n");
        ret = MISC_GENESIS_UNKNOWN;
    }
    return ret;
}


/** JSON-RPC送信
 *
 */
int misc_sendjson(const char *pSend, const char *pAddr, uint16_t Port)
{
    int retval = -1;
    struct sockaddr_in sv_addr;

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return retval;
    }
    memset(&sv_addr, 0, sizeof(sv_addr));
    sv_addr.sin_family = AF_INET;
    sv_addr.sin_addr.s_addr = inet_addr(pAddr);
    sv_addr.sin_port = htons(Port);
    retval = connect(sock, (struct sockaddr *)&sv_addr, sizeof(sv_addr));
    if (retval < 0) {
        close(sock);
        return retval;
    }
    write(sock, pSend, strlen(pSend));

    //受信を待つとDBの都合でロックしてしまうため、すぐに閉じる

    close(sock);

    return 0;
}


/**************************************************************************
 * debug functions
 **************************************************************************/

#ifdef APP_DEBUG_MEM

void *misc_dbg_malloc(size_t size)
{
    void *p = malloc(size);
    if (p) {
        mcount++;
    }
    return p;
}


//void *misc_dbg_realloc(void *ptr, size_t size)
//{
//    void *p = realloc(ptr, size);
//    if ((ptr == NULL) && p) {
//        mcount++;
//    }
//    return p;
//}


//void *misc_dbg_calloc(size_t blk, size_t size)
//{
//    void *p = calloc(blk, size);
//    if (p) {
//        mcount++;
//    }
//    return p;
//}


void misc_dbg_free(void *ptr)
{
    //NULL代入してfree()だけするパターンもあるため、NULLチェックする
    if (ptr) {
        mcount--;
    }
    free(ptr);
}


int misc_dbg_malloc_cnt(void)
{
    return mcount;
}

#endif
