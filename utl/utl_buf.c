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
/** @file   utl_buf.c
 *  @brief  可変サイズバッファ
 *  @author ueno@nayuta.co
 */
#include "utl_local.h"

#include "utl_buf.h"
#include "utl_dbg.h"


/**************************************************************************
 * public functions
 **************************************************************************/

void utl_buf_init(utl_buf_t *pBuf)
{
    pBuf->len = 0;
    pBuf->buf = NULL;
}


void utl_buf_free(utl_buf_t *pBuf)
{
    if (pBuf->buf) {
#ifdef PTARM_DEBUG
        memset(pBuf->buf, 0, pBuf->len);
#endif  //PTARM_DEBUG
        UTL_DBG_FREE(pBuf->buf);
        pBuf->len = 0;
    } else {
        //LOGD("no UTL_DBG_FREE memory\n");
    }
}


void utl_buf_alloc(utl_buf_t *pBuf, uint32_t Size)
{
    pBuf->len = Size;
    pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(Size);
}


void utl_buf_realloc(utl_buf_t *pBuf, uint32_t Size)
{
    pBuf->len = Size;
    pBuf->buf = (uint8_t *)UTL_DBG_REALLOC(pBuf->buf, Size);
}


void utl_buf_alloccopy(utl_buf_t *pBuf, const uint8_t *pData, uint32_t Len)
{
    if (Len > 0) {
        utl_buf_alloc(pBuf, Len);
        memcpy(pBuf->buf, pData, Len);
    } else {
        utl_buf_init(pBuf);
    }
}


bool utl_buf_cmp(const utl_buf_t *pBuf1, const utl_buf_t *pBuf2)
{
    return (pBuf1->len == pBuf2->len) && (memcmp(pBuf1->buf, pBuf2->buf, pBuf1->len) == 0);
}
