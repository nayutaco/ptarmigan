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
 * @file    utl_time.h
 * @brief   utl_time
 */
#ifndef UTL_TIME_H__
#define UTL_TIME_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <time.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

#define UTL_SZ_TIME_FMT_STR         (20)            ///< e.g. "2014-10-10T04:50:40Z"


/**************************************************************************
 * prototypes
 **************************************************************************/

/** get current time
 *
 * @return          current time (unix time)
 */
time_t utl_time_time(void);


/** get current time
 *
 * @param[out]      pStr        current time (string formated)
 * @return          pStr addr
 */
const char *utl_time_str_time(char pStr[UTL_SZ_TIME_FMT_STR + 1]);


/** format unix time
 *
 * @param[out]      pStr        string formated time
 * @param[in]       Time        unix time
 * @return          pStr addr
 */
const char *utl_time_fmt(char pStr[UTL_SZ_TIME_FMT_STR + 1], time_t Time);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_TIME_H__ */
