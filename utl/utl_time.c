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
//#define M_TIME_USEC

#include <time.h>
#include <stdio.h>
#ifdef M_TIME_USEC
#include <sys/time.h>
#endif

#include "utl_time.h"


/**************************************************************************
 * private variables
 **************************************************************************/


/**************************************************************************
 * public functions
 **************************************************************************/

time_t utl_time_time(void)
{
    return time(NULL);
}


const char *utl_time_str_time(char pStr[UTL_SZ_TIME_FMT_STR + 1])
{
    utl_time_fmt(pStr, utl_time_time());
    return pStr;
}


const char *utl_time_fmt(char pStr[UTL_SZ_TIME_FMT_STR + 1], time_t Time)
{
#ifdef M_TIME_USEC
    struct timeval ttt;
    gettimeofday(&ttt, NULL);
#endif

    struct tm tmval;
    gmtime_r(&Time, &tmval);
#ifdef M_TIME_USEC
    sprintf(pStr, "%02d:%02d:%02d.%06ld",
        tmval.tm_hour,
        tmval.tm_min,
        tmval.tm_sec,
        ttt.tv_usec);
#else
    sprintf(pStr, "%04d-%02d-%02dT%02d:%02d:%02dZ",
        tmval.tm_year + 1900,
        tmval.tm_mon + 1,
        tmval.tm_mday,
        tmval.tm_hour,
        tmval.tm_min,
        tmval.tm_sec);
#endif
    return pStr;
}


