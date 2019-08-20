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

#include <string.h>

#include "utl_str.h"
#include "utl_jsonrpc.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool param_is_set(const utl_jsonrpc_param_t params[], const char *method, int index);


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_jsonrpc_create_request(utl_str_t *body, const char *method, const char *paramv[], int paramc, const utl_jsonrpc_param_t non_string_params[])
{
    bool ret = false;
    utl_str_init(body);

    if (!utl_str_append(body, "{\"method\":\"")) goto LABEL_EXIT;
    if (!utl_str_append(body, method)) goto LABEL_EXIT;
    if (!utl_str_append(body, "\",\"params\":[")) goto LABEL_EXIT;
    for (int i = 0; i < paramc; i++) {
        if (i && !utl_str_append(body, ",")) goto LABEL_EXIT;
        if (param_is_set(non_string_params, method, i)) {
            if (!utl_str_append(body, paramv[i])) goto LABEL_EXIT;
        } else {
            if (!utl_str_append(body, "\"")) goto LABEL_EXIT;
            if (!utl_str_append(body, paramv[i])) goto LABEL_EXIT;
            if (!utl_str_append(body, "\"")) goto LABEL_EXIT;
        }
    }
    if (!utl_str_append(body, "]}")) goto LABEL_EXIT;
    ret = true;

LABEL_EXIT:
    if (!ret) {
        utl_str_free(body);
    }
    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static bool param_is_set(const utl_jsonrpc_param_t params[], const char *method, int index) {
    for (int i = 0; params[i].method; i++) {
        if (strcmp(params[i].method, method)) continue;
        if (params[i].index == index) return true;
    }
    return false;
}
