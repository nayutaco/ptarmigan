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
/**
 * @file    utl_queue.h
 * @brief   utl_queue
 */
#ifndef UTL_QUEUE_H__
#define UTL_QUEUE_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


/**************************************************************************
 * types
 **************************************************************************/

/** @struct utl_queue_t
 *  @brief  queue
 *
 */
typedef struct {
    uint8_t* p_buf;
    size_t size;
    uint32_t n;
    uint32_t head;
    uint32_t num_items;
} utl_queue_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

bool utl_queue_create(utl_queue_t *pQueue, size_t Size, uint32_t N);
void utl_queue_free(utl_queue_t *pQueue);
bool utl_queue_push(utl_queue_t *pQueue, const void *pItem);
bool utl_queue_pop(utl_queue_t *pQueue, void *pItem);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_QUEUE_H__ */
