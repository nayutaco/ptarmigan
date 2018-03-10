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
/** @file   ucoin_buf.c
 *  @brief  可変サイズバッファ
 *  @author ueno@nayuta.co
 */
#include "ucoin_local.h"


/**************************************************************************
 * public functions
 **************************************************************************/

void ucoin_buf_init(ucoin_buf_t *pBuf)
{
    pBuf->len = 0;
    pBuf->buf = NULL;
}


void ucoin_buf_free(ucoin_buf_t *pBuf)
{
    if (pBuf->buf) {
#ifdef UCOIN_DEBUG
        memset(pBuf->buf, 0, pBuf->len);
#endif  //UCOIN_DEBUG
        M_FREE(pBuf->buf);
        pBuf->buf = NULL;
        pBuf->len = 0;
    } else {
        //DBG_PRINTF("no M_FREE memory\n");
    }
}


void ucoin_buf_alloc(ucoin_buf_t *pBuf, uint32_t Size)
{
    pBuf->len = Size;
    pBuf->buf = (uint8_t *)M_MALLOC(Size);
}


void ucoin_buf_alloccopy(ucoin_buf_t *pBuf, const uint8_t *pData, uint32_t Len)
{
    if (Len > 0) {
        ucoin_buf_alloc(pBuf, Len);
        memcpy(pBuf->buf, pData, Len);
    } else {
        ucoin_buf_init(pBuf);
    }
}


bool ucoin_buf_cmp(const ucoin_buf_t *pBuf1, const ucoin_buf_t *pBuf2)
{
    return (pBuf1->len == pBuf2->len) && (memcmp(pBuf1->buf, pBuf2->buf, pBuf1->len) == 0);
}
