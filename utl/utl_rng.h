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
 * @file    utl_rng.h
 * @brief   utl_rng
 */
#ifndef UTL_RNG_H__
#define UTL_RNG_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/


/**************************************************************************
 * prototypes
 **************************************************************************/

/** init random generator
 *
 * @return          true        success
 */
bool utl_rng_init(void);


/** generate random data
 *
 * @param[out]      pData       random data
 * @param[in]       Len         data length
 * @return          true        success
 */
bool utl_rng_rand(uint8_t *pData, uint16_t Len);


/** free random generator
 *
 */
void utl_rng_free(void);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_RND_H__ */
