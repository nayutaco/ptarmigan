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
/** @file   ptarm_dbg.c
 *  @brief  util処理: 汎用処理
 *  @author ueno@nayuta.co
 */
#include <sys/stat.h>
#include <sys/types.h>

#include "util_local.h"
#include "ptarm_dbg.h"


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
int ptarm_dbg_malloc_cnt(void)
{
    return mcount;
}

void ptarm_dbg_malloc_cnt_reset(void)
{
    mcount = 0;
}
#endif  //PTARM_DEBUG_MEM


/**************************************************************************
 * package functions
 **************************************************************************/

#ifdef PTARM_DEBUG_MEM

#if 1
void HIDDEN *ptarm_dbg_malloc(size_t size)
{
    void *p = malloc(size);
    if (p) {
        mcount++;
    }
    return p;
}


void HIDDEN *ptarm_dbg_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if ((ptr == NULL) && p) {
        mcount++;
    }
    return p;
}


void HIDDEN *ptarm_dbg_calloc(size_t blk, size_t size)
{
    void *p = calloc(blk, size);
    if (p) {
        mcount++;
    }
    return p;
}


void HIDDEN ptarm_dbg_free(void *ptr)
{
    //NULL代入してfree()だけするパターンもあるため、NULLチェックする
    if (ptr) {
        mcount--;
    }
    free(ptr);
}


#else

static struct {
    int allocs;
    void *p;
} mem[100];

void HIDDEN *ptarm_dbg_malloc(size_t size)
{
    void *p = malloc(size);
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
    printf("%s(%u)[%d] = %p\n", __func__, size, mcount, p);
    return p;
}


void HIDDEN *ptarm_dbg_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (ptr && (ptr != p)) {
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == ptr) {
                printf("   realloc update\n");
                mem[lp].p = p;
                break;
            }
        }
    } else if ((ptr == NULL) && p) {
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
    printf("%s(%p, %u)[%d] = %p\n", __func__, ptr, size, mcount, p);
    return p;
}


void HIDDEN *ptarm_dbg_calloc(size_t blk, size_t size)
{
    void *p = calloc(blk, size);
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
    printf("%s(%u, %u)[%d] = %p\n", __func__, blk, size, mcount, p);
    return p;
}


void HIDDEN ptarm_dbg_free(void *ptr)
{
    //NULL代入してfree()だけするパターンもあるため、NULLチェックする
    if (ptr) {
        mcount--;
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == ptr) {
                mem[lp].allocs--;
                if (mem[lp].allocs == 0) {
                    mem[lp].p = NULL;
                }
                printf("%s(%p) allocs:%d\n", __func__, ptr, mem[lp].allocs);
                break;
            }
        }
    }
    printf("%s(%p)[%d]\n", __func__, ptr, mcount);
    free(ptr);
}

void ptarm_dbg_show_mem(void)
{
    for (int lp = 0; lp < 100; lp++) {
        if (mem[lp].p) {
            printf("[%2d]allocs=%d, p=%p\n", lp, mem[lp].allocs, mem[lp].p);
        }

    }
}
#endif

#endif  //PTARM_DEBUG_MEM

