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
/** @file   btc_segwit_addr.c
 *  @brief  btc_segwit_addr
 */
#include "string.h"

#include "segwit_addr.h"
#include "btc_segwit_addr.h"

bool btc_bech32_encode(char *output, size_t output_len, const char *hrp, const uint8_t *data, size_t data_len, bool ln)
{
    if (!strlen(hrp)) return false;
    if (output_len < strlen(hrp) + data_len + 8) return false;
    return bech32_encode(output, hrp, data, data_len, ln);
}


bool btc_bech32_decode(char* hrp, size_t hrp_len, uint8_t *data, size_t *data_len, const char *input, bool ln)
{
    //rough test
    // if (strlen(input) < 6) return false;
    // if (hrp_len < strlen(input) - 6) return false;
    // if (strlen(input) < 8) return false;
    // if (*data_len < strlen(input) - 8) return false;

    //more rigorous test
    size_t data_len_tmp = 0;
    size_t input_len = strlen(input);
    while (data_len_tmp < input_len && input[(input_len - 1) - data_len_tmp] != '1') {
        ++data_len_tmp;
    }
    size_t hrp_len_tmp = input_len - (1 + data_len_tmp);
    if (1 + data_len_tmp >= input_len || data_len_tmp < 6) {
        return false;
    }
    data_len_tmp -= 6;

    if (hrp_len < hrp_len_tmp + 1) return false;
    if (*data_len < data_len_tmp) return false;

    return bech32_decode(hrp, data, data_len, input, ln);
}


bool btc_segwit_addr_encode(char* output, size_t output_len, uint8_t hrp_type, int ver, const uint8_t* prog, size_t prog_len)
{
    if (output_len < 73 + hrp_len(hrp_type)) return false;
    //if (ver != 0) return false;
    return segwit_addr_encode(output, hrp_type, ver, prog, prog_len);
}


bool btc_segwit_addr_decode(int* ver, uint8_t* prog, size_t* prog_len, uint8_t hrp_type, const char* addr)
{
    if (*prog_len < 40) return false;
    return segwit_addr_decode(ver, prog, prog_len, hrp_type, addr);
}

