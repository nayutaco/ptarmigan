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
/** @file   utl_dbg.c
 *  @brief  utl処理: 汎用処理
 */
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "utl_local.h"
#include "utl_dbg.h"
#include "utl_log.h"


/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * private variables
 **************************************************************************/

#ifdef PTARM_DEBUG_MEM
static int mcount = 0;
#endif  //PTARM_DEBUG_MEM


/**************************************************************************
 * public functions
 **************************************************************************/

#ifdef PTARM_DEBUG_MEM
int utl_dbg_malloc_cnt(void)
{
    return mcount;
}

void utl_dbg_malloc_cnt_reset(void)
{
    mcount = 0;
}
#endif  //PTARM_DEBUG_MEM


/**************************************************************************
 * package functions
 **************************************************************************/

#ifdef PTARM_DEBUG_MEM

#if 1
void HIDDEN *utl_dbg_malloc(size_t Size)
{
    void *p = malloc(Size);
    if (p) {
        mcount++;
    }
    LOGD("UTL_DBG_MALLOC:%d\n", utl_dbg_malloc_cnt());
    return p;
}


void HIDDEN *utl_dbg_realloc(void *pBuf, size_t Size)
{
    void *p = realloc(pBuf, Size);
    if ((pBuf == NULL) && p) {
        mcount++;
    }
    LOGD("UTL_DBG_REALLOC:%d\n", utl_dbg_malloc_cnt());
    return p;
}


void HIDDEN *utl_dbg_calloc(size_t Block, size_t Size)
{
    void *p = calloc(Block, Size);
    if (p) {
        mcount++;
    }
    LOGD("UTL_DBG_CALLOC:%d\n", utl_dbg_malloc_cnt());
    return p;
}

char HIDDEN *utl_dbg_strdup(const char *pStr)
{
    char *p = strdup(pStr);
    if (p) {
        mcount++;
    }
    LOGD("UTL_DBG_STRDUP:%d\n", utl_dbg_malloc_cnt());
    return p;
}

void HIDDEN utl_dbg_free(void *pBuf)
{
    //NULL代入してfree()だけするパターンもあるため、NULLチェックする
    if (pBuf) {
        mcount--;
    }
    free(pBuf);
    LOGD("UTL_DBG_FREE:%d\n", utl_dbg_malloc_cnt());
}


#else

static struct {
    int allocs;
    void *p;
} mem[100];

void HIDDEN *utl_dbg_malloc(size_t Size)
{
    void *p = malloc(Size);
    if (p) {
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == 0) {
                mem[lp].allocs++;
                mem[lp].p = p;
                break;
            }
        }
        mcount++;
    } else {
        printf("0 malloc\n");
    }
    printf("%s(%u)[%d] = %p\n", __func__, (unsigned int)Size, mcount, p);
    return p;
}


void HIDDEN *utl_dbg_realloc(void *pBuf, size_t Size)
{
    void *p = realloc(pBuf, Size);
    if (pBuf && (pBuf != p)) {
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == pBuf) {
                printf("   realloc update\n");
                mem[lp].p = p;
                break;
            }
        }
    } else if ((pBuf == NULL) && p) {
        mcount++;
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == 0) {
                mem[lp].allocs++;
                mem[lp].p = p;
                break;
            }
        }
    } else {
        printf("   realloc same\n");
    }
    printf("%s(%p, %u)[%d] = %p\n", __func__, pBuf, (unsigned int)Size, mcount, p);
    return p;
}

void HIDDEN *utl_dbg_calloc(size_t Block, size_t Size)
{
    void *p = calloc(Block, Size);
    if (p) {
        mcount++;
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == 0) {
                mem[lp].allocs++;
                mem[lp].p = p;
                break;
            }
        }
    }
    printf("%s(%u, %u)[%d] = %p\n", __func__, (unsigned int)Block, (unsigned int)Size, mcount, p);
    return p;
}

char HIDDEN *utl_dbg_strdup(const char *pStr)
{
    char *p = strdup(pStr);
    if (p) {
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == 0) {
                mem[lp].allocs++;
                mem[lp].p = (void*)p;
                break;
            }
        }
        mcount++;
    } else {
        printf("0 strdup\n");
    }
    printf("%s(%u)[%d] = %p\n", __func__, (unsigned int)(strlen(pStr) + 1), mcount, p);
    return p;
}

void HIDDEN utl_dbg_free(void *pBuf)
{
    //NULL代入してfree()だけするパターンもあるため、NULLチェックする
    if (pBuf) {
        mcount--;
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == pBuf) {
                mem[lp].allocs--;
                if (mem[lp].allocs == 0) {
                    mem[lp].p = NULL;
                }
                printf("%s(%p) allocs:%d\n", __func__, pBuf, mem[lp].allocs);
                break;
            }
        }
    }
    printf("%s(%p)[%d]\n", __func__, pBuf, mcount);
    free(pBuf);
}

void utl_dbg_show_mem(void)
{
    for (int lp = 0; lp < 100; lp++) {
        if (mem[lp].p) {
            printf("[%2d]allocs=%d, p=%p\n", lp, mem[lp].allocs, mem[lp].p);
        }

    }
}
#endif

#endif  //PTARM_DEBUG_MEM

