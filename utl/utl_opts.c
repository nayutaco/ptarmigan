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

#include "utl_dbg.h"
#include "utl_str.h"
#include "utl_opts.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static utl_opt_t *findn_opts(utl_opt_t *opts, const char *name, int len);
static utl_opt_t *find_opts(utl_opt_t *opts, const char *name);


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_opts_parse(utl_opt_t *opts, int argc, const char* const argv[])
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
    
    for (int i = 0; opts[i].name; i++) {
        if (!opts[i].arg) {
            if (opts[i].param_default) return false;
        }
        if (opts[i].param) return false;
        if (opts[i].is_set) return false;
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

        utl_opt_t *info = findn_opts(opts, v, v_len);
        if (!info) goto LABEL_EXIT;
        if (info->is_set) goto LABEL_EXIT;
        if (info->arg && p) {
            info->param = UTL_DBG_STRDUP(p + 1);
            if (!info->param) goto LABEL_EXIT;
        } else if (!info->arg && !p) {
        } else {
            goto LABEL_EXIT;
        }
        info->is_set = true;
    }

    for (int i = 0; opts[i].name; i++) {
        utl_opt_t *info = &opts[i];
        if (!info->is_set && info->param_default) {
            info->param = UTL_DBG_STRDUP(info->param_default);
            if (!info->param) goto LABEL_EXIT;
            info->is_set = true;
        }
    }

    ret = true;

LABEL_EXIT:
    if (!ret) {
        utl_opts_free(opts);
    }
    return ret;
}

bool utl_opts_is_set(utl_opt_t *opts, const char *name)
{
    utl_opt_t *info = find_opts(opts, name);
    if (!info) return false;
    return info->is_set;
}

const char *utl_opts_get_string(utl_opt_t *opts, const char *name)
{
    utl_opt_t *info = find_opts(opts, name);
    if (!info) return NULL;
    if (!info->is_set) return NULL;
    return info->param;
}

bool utl_opts_get_u16(utl_opt_t *opts, uint16_t *n, const char *name)
{
    utl_opt_t *info = find_opts(opts, name);
    if (!info) return false;
    if (!info->is_set) return false;
    if (!info->param) return false;
    if (!utl_str_scan_u16(n, info->param)) return false;
    return true;
}

bool utl_opts_get_u32(utl_opt_t *opts, uint32_t *n, const char *name)
{
    utl_opt_t *info = find_opts(opts, name);
    if (!info) return false;
    if (!info->is_set) return false;
    if (!info->param) return false;
    if (!utl_str_scan_u32(n, info->param)) return false;
    return true;
}

void utl_opts_free(utl_opt_t *opts)
{
    for (int i = 0; opts[i].name; i++) {
        opts[i].is_set = false;
        if (!opts[i].param) continue;
        UTL_DBG_FREE(opts[i].param);
        opts[i].param = 0;
    }
}

bool utl_opts_get_help_messages(utl_opt_t *opts, utl_str_t *messages)
{
    for (int i = 0; opts[i].name; i++) {
        utl_opt_t *info = &opts[i];
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

static utl_opt_t *findn_opts(utl_opt_t *opts, const char *name, int len)
{
    for (int i = 0; opts[i].name; i++) {
        if (!strncmp(name, opts[i].name, len)) return &opts[i];
    }
    return NULL;
}

static utl_opt_t *find_opts(utl_opt_t *opts, const char *name)
{
    return findn_opts(opts, name, strlen(name));
}

