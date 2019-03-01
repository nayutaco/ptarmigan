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

#include "utl_local.h"
#include "utl_dbg.h"
#include "utl_queue.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_queue_create(utl_queue_t *pQueue, size_t Size, uint32_t N)
{
    memset(pQueue, 0x00, sizeof(utl_queue_t));
    pQueue->p_buf = (uint8_t *)UTL_DBG_MALLOC(Size * N);
    if (!pQueue->p_buf) return false;
    pQueue->size = Size;
    pQueue->n = N;
    return true;
}


void utl_queue_free(utl_queue_t *pQueue)
{
    if (pQueue->p_buf) {
        UTL_DBG_FREE(pQueue->p_buf);
    } 
    memset(pQueue, 0x00, sizeof(utl_queue_t));
}


bool utl_queue_push(utl_queue_t *pQueue, const void *pItem)
{
    if (pQueue->num_items == pQueue->n) return false;
    int tail = (pQueue->head + pQueue->num_items) % pQueue->n;
    memcpy(pQueue->p_buf + tail * pQueue->size, pItem, pQueue->size);
    pQueue->num_items++;
    return true;
}


bool utl_queue_pop(utl_queue_t *pQueue, void *pItem)
{
    if (!pQueue->num_items) return false;
    memcpy(pItem, pQueue->p_buf + pQueue->head * pQueue->size, pQueue->size);
    pQueue->head = (pQueue->head + 1) % pQueue->n;
    pQueue->num_items--;
    return true;
}
