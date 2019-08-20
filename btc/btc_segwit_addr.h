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
/** @file   btc_segwit_addr.h
 *  @brief  btc_segwit_addr
 */
#ifndef _BTC_SEGWIT_ADDR_H_
#define _BTC_SEGWIT_ADDR_H_ 1

#include "stdbool.h"
#include "stddef.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define BTC_SEGWIT_ADDR_MAINNET     ((uint8_t)0)
#define BTC_SEGWIT_ADDR_TESTNET     ((uint8_t)1)
#define BTC_SEGWIT_ADDR_REGTEST     ((uint8_t)2)
#define BTC_SEGWIT_ADDR_MAINNET2    ((uint8_t)3)
#define BTC_SEGWIT_ADDR_TESTNET2    ((uint8_t)4)
#define BTC_SEGWIT_ADDR_REGTEST2    ((uint8_t)5)

size_t btc_bech32_encode_buf_len(const char *hrp, size_t data_len);

/** Encode a Bech32 string
 *
 *  Out: output:    Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                  will be updated to contain the null-terminated Bech32 string.
 *  In: output_len: Length of the output array.
 *      hrp :       Pointer to the non-null-terminated human readable part(length=2).
 *      data :      Pointer to an array of 5-bit values.
 *      data_len:   Length of the data array.
 *      ln:         Invoice for Lightning Network.
 *  Returns true if successful.
 */
bool btc_bech32_encode(
    char *output,
    size_t output_len,
    const char *hrp,
    const uint8_t *data,
    size_t data_len,
    bool ln
);

/** Decode a Bech32 string
 *
 *  Out: hrp:         Pointer to a buffer of size strlen(input) - 6. Will be
 *                    updated to contain the null-terminated human readable part.
 *  In: hrp_len:      Length of the hrp array.
 *  Out: data:        Pointer to a buffer of size strlen(input) - 8 that will
 *                    hold the encoded 5-bit data values.
 *  In/Out: data_len: Pointer to a size_t that will be updated to be the number
 *                    of entries in data.
 *  In: input:        Pointer to a null-terminated Bech32 string.
 *      ln:           Invoice for Lightning Network.
 *  Returns true if succesful.
 */
bool btc_bech32_decode(
    char* hrp,
    size_t hrp_len,
    uint8_t *data,
    size_t *data_len,
    const char *input,
    bool ln
);

/** Encode a SegWit address
 *
 *  Out: output:    Pointer to a buffer of size 73 + strlen(hrp) that will be
 *                  updated to contain the null-terminated address.
 *  In: output_len: Length of the output array.
 *      hrp_type:   SEGWIT_ADDR_MAINNET or SEGWIT_ADDR_TESTNET
 *      ver:        Version of the witness program (between 0 and 16 inclusive).
 *      prog:       Data bytes for the witness program (between 2 and 40 bytes).
 *      prog_len:   Number of data bytes in prog.
 *  Returns true if successful.
 */
bool btc_segwit_addr_encode(
    char* output,
    size_t output_len,
    uint8_t hrp_type,
    int ver,
    const uint8_t* prog,
    size_t prog_len
);

/** Decode a SegWit address
 *
 *  Out: ver:         Pointer to an int that will be updated to contain the witness
 *                    program version (between 0 and 16 inclusive).
 *       prog:        Pointer to a buffer of size 40 that will be updated to
 *                    contain the witness program bytes.
 *  In/Out: prog_len: Pointer to a size_t that will be updated to contain the length
 *                    of bytes in prog.
 *  Out: hrp_type:    SEGWIT_ADDR_MAINNET or SEGWIT_ADDR_TESTNET
 *       addr:        Pointer to the null-terminated address.
 *  Returns true if successful.
 */
bool btc_segwit_addr_decode(
    int* ver,
    uint8_t* prog,
    size_t* prog_len,
    uint8_t hrp_type,
    const char* addr
);

size_t btc_convert_bits_buf_len(int outbits, size_t inlen, int inbits);

bool btc_convert_bits(
    uint8_t* out,
    size_t* outlen, //XXX: [in/out] offset of out
    int outbits,
    const uint8_t* in,
    size_t inlen,
    int inbits,
    bool pad
);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
