/*
 *  Copyright (C) 2017 Ptarmigan Project
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
 * @file    utl_jsonrpc.h
 * @brief   utl_jsonrpc
 */
#ifndef UTL_JSONRPC_H__
#define UTL_JSONRPC_H__

#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus


/**************************************************************************
 * macros
 **************************************************************************/

/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct utl_jsonrpc_param_t
 *  @brief  params
 *
 */
typedef struct {
    const char *method;     ///< method
    int index;              ///< index of params
} utl_jsonrpc_param_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** create json-rpc request
 *
 * @param[in/out]   body                json-rpc request body
 * @param[in]       method              method
 * @param[in]       paramv              param values
 * @param[in]       paramc              param count
 * @param[in]       non_string_params   params of non-string(bool/number/etc.)
 * @retval          true                success
 */
bool utl_jsonrpc_create_request(utl_str_t *body, const char *method, const char *paramv[], int paramc, const utl_jsonrpc_param_t *non_string_params);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_JSONRPC_H__ */
