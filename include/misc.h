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
#ifndef MISC_H__
#define MISC_H__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

#include <syslog.h>


/**************************************************************************
 * macros
 **************************************************************************/

#define SYSLOG_ERR(format, ...)  { syslog(LOG_ERR, format, ##__VA_ARGS__); }
#define SYSLOG_WARN(format, ...) { syslog(LOG_WARNING, format, ##__VA_ARGS__); }
#define SYSLOG_INFO(format, ...) { syslog(LOG_INFO, format, ##__VA_ARGS__); }


/**************************************************************************
 * prototypes
 **************************************************************************/

static inline void misc_msleep(unsigned long slp) {
    struct timespec req = { 0, slp * 1000000UL };
    nanosleep(&req, NULL);
}

void misc_bin2str(char *pStr, const uint8_t *pBin, uint16_t BinLen);
void misc_bin2str_rev(char *pStr, const uint8_t *pBin, uint16_t BinLen);
bool misc_str2bin(uint8_t *pBin, uint16_t BinLen, const char *pStr);
bool misc_str2bin_rev(uint8_t *pBin, uint16_t BinLen, const char *pStr);
void misc_dumpbin(FILE *fp, const uint8_t *pData, uint16_t Len);
void misc_print_txid(const uint8_t *pTxid);

#endif /* MISC_H__ */
