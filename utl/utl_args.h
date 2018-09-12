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
 * @file    utl_args.h
 * @brief   utl_args.h
 */
#ifndef UTL_ARGS_H__
#define UTL_ARGS_H__

#include <stdint.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * types
 **************************************************************************/

/** @struct utl_arginfo_t
 *  @brief  utl_arginfo_t
 *
 */
typedef struct {
    const char      *name;          ///< name(required, but set NULL in the watchdog entry)
    const char      *arg;           ///< arg(optional, if set, display name=<arg>)
    const char      *param_default; ///< param_default(optional)
    const char      *help;          ///< help(optional)
    char            *param;         ///< param
    bool            is_set;         ///< is_set
} utl_arginfo_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

bool utl_args_parse(utl_arginfo_t *arginfo, int argc, const char* const argv[]);

void utl_args_free(utl_arginfo_t *arginfo);

bool utl_args_is_set(utl_arginfo_t *arginfo, const char *name);

const char *utl_args_get_string(utl_arginfo_t *arginfo, const char *name);

bool utl_args_get_u16(utl_arginfo_t *arginfo, uint16_t *n, const char *name);

bool utl_args_get_u32(utl_arginfo_t *arginfo, uint32_t *n, const char *name);

bool utl_args_get_help_messages(utl_arginfo_t *arginfo, utl_str_t *messages);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_ARGS_H__ */
