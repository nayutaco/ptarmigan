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
/** @file   ptarm_dbg.h
 *  @brief  ptarm_dbg
 *  @author ueno@nayuta.co
 *
 * @note
 *      - ptarm_dbg
 */
#ifndef PTARM_DBG_H__
#define PTARM_DBG_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/**************************************************************************
 * prototypes
 **************************************************************************/

#ifdef PTARM_DEBUG_MEM
void* ptarm_dbg_malloc(size_t);
void* ptarm_dbg_realloc(void*, size_t);
void* ptarm_dbg_calloc(size_t, size_t);
void  ptarm_dbg_free(void*);

/** (デバッグ用)malloc残数取得
 * ptarmライブラリ内でmalloc()した回数からfree()した回数を返す。<br/>
 * PTARM_DEBUG_MEM 定義時のみ有効で、未定義の場合は常に-1を返す。
 *
 * @return  malloc残数
 */
int ptarm_dbg_malloc_cnt(void);

void ptarm_dbg_malloc_cnt_reset(void);
#endif  //PTARM_DEBUG_MEM


#ifdef __cplusplus
}
#endif //__cplusplus

#endif /* PTARM_DBG_H__ */
