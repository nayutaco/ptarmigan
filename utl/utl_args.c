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

#include <string.h>

#include "utl_dbg.h"
#include "utl_str.h"
#include "utl_args.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static utl_arginfo_t *findn_arginfo(utl_arginfo_t *arginfo, const char *name, int len);
static utl_arginfo_t *find_arginfo(utl_arginfo_t *arginfo, const char *name);


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_args_parse(utl_arginfo_t *arginfo, int argc, const char* const argv[])
{
    //case1
    // argv[0]: program -- skip
    // argv[1]: -option0
    // argv[2]: -option1

    //case2
    // argv[0]: program -- skip
    // argv[1]: command -- skip
    // argv[2]: -option0
    // argv[3]: -option1
    // argv[5]: command_param0 -- skip
    // argv[6]: command_param1 -- skip

    bool ret = false;
    int offset = 1;

    if (argc < 1) return false;
    if (argc >= 2) {
        if (argv[1][0] != '-') {
            //skip command
            offset++;
        }
    }
    
    for (int i = 0; arginfo[i].name; i++) {
        if (!arginfo[i].arg) {
            if (arginfo[i].param_default) return false;
        }
        if (arginfo[i].param) return false;
        if (arginfo[i].is_set) return false;
    }

    for (int i = offset; i < argc; i++) {
        const char *v = argv[i];

        //skip command_params
        if (v[0] != '-') break;

        const char *p = strchr(v, '=');
        int v_len = strlen(v);
        if (p) {
            v_len = p - v;
        }

        utl_arginfo_t *info = findn_arginfo(arginfo, v, v_len);
        if (!info) goto LABEL_EXIT;
        if (info->is_set) goto LABEL_EXIT;
        if (info->arg && p) {
            info->param = UTL_DBG_STRDUP(p + 1);
        } else if (!info->arg && !p) {
        } else {
            goto LABEL_EXIT;
        }
        info->is_set = true;
    }

    for (int i = 0; arginfo[i].name; i++) {
        utl_arginfo_t *info = &arginfo[i];
        if (!info->is_set && info->param_default) {
            info->param = UTL_DBG_STRDUP(info->param_default);
            info->is_set = true;
        }
    }

    ret = true;

LABEL_EXIT:
    if (!ret) {
        utl_args_free(arginfo);
    }
    return ret;
}

bool utl_args_is_set(utl_arginfo_t *arginfo, const char *name)
{
    utl_arginfo_t *info = find_arginfo(arginfo, name);
    if (!info) return false;
    return info->is_set;
}

const char *utl_args_get_string(utl_arginfo_t *arginfo, const char *name)
{
    utl_arginfo_t *info = find_arginfo(arginfo, name);
    if (!info) return NULL;
    if (!info->is_set) return NULL;
    return info->param;
}

bool utl_args_get_u16(utl_arginfo_t *arginfo, uint16_t *n, const char *name)
{
    utl_arginfo_t *info = find_arginfo(arginfo, name);
    if (!info) return false;
    if (!info->is_set) return false;
    if (!info->param) return false;
    if (!utl_str_scan_u16(n, info->param)) return false;
    return true;
}

bool utl_args_get_u32(utl_arginfo_t *arginfo, uint32_t *n, const char *name)
{
    utl_arginfo_t *info = find_arginfo(arginfo, name);
    if (!info) return false;
    if (!info->is_set) return false;
    if (!info->param) return false;
    if (!utl_str_scan_u32(n, info->param)) return false;
    return true;
}

void utl_args_free(utl_arginfo_t *arginfo)
{
    for (int i = 0; arginfo[i].name; i++) {
        arginfo[i].is_set = false;
        if (!arginfo[i].param) continue;
        UTL_DBG_FREE(arginfo[i].param);
        arginfo[i].param = 0;
    }
}

bool utl_args_get_help_messages(utl_arginfo_t *arginfo, utl_str_t *messages)
{
    for (int i = 0; arginfo[i].name; i++) {
        utl_arginfo_t *info = &arginfo[i];
        if (!utl_str_append(messages, "  ")) return false;
        if (!utl_str_append(messages, info->name)) return false;
        if (info->arg) {
            if (!utl_str_append(messages, "=<")) return false;
            if (!utl_str_append(messages, info->arg)) return false;
            if (!utl_str_append(messages, ">")) return false;
        }
        if (!utl_str_append(messages, "\n")) return false;
        if (info->help) {
            if (!utl_str_append(messages, "       ")) return false;
            if (!utl_str_append(messages, info->help)) return false;
            if (info->arg && info->param_default) {
                if (!utl_str_append(messages, " ")) return false;
                if (!utl_str_append(messages, "(default: ")) return false;
                if (!utl_str_append(messages, info->param_default)) return false;
                if (!utl_str_append(messages, ")")) return false;
            }
            if (!utl_str_append(messages, "\n")) return false;
        } else if (info->arg && info->param_default) {
            if (!utl_str_append(messages, "       ")) return false;
            if (!utl_str_append(messages, "(default: ")) return false;
            if (!utl_str_append(messages, info->param_default)) return false;
            if (!utl_str_append(messages, ")")) return false;
            if (!utl_str_append(messages, "\n")) return false;
        }
        if (!utl_str_append(messages, "\n")) return false;
    }
    return true;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static utl_arginfo_t *findn_arginfo(utl_arginfo_t *arginfo, const char *name, int len)
{
    for (int i = 0; arginfo[i].name; i++) {
        if (!strncmp(name, arginfo[i].name, len)) return &arginfo[i];
    }
    return NULL;
}

static utl_arginfo_t *find_arginfo(utl_arginfo_t *arginfo, const char *name)
{
    return findn_arginfo(arginfo, name, strlen(name));
}

