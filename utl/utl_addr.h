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
 * @file    utl_addr.h
 * @brief   utl_addr
 */
#ifndef UTL_ADDR_H__
#define UTL_ADDR_H__

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

/**************************************************************************
 * prototypes
 **************************************************************************/

/** convert ipv4 address string to byte array
 *
 * @param[out]  b       ipv4 address byte array(network byte order)
 * @param[in]   s       ipv4 address string
 * @retval      true    routable
 */
bool utl_addr_ipv4_str2bin(uint8_t b[4], const char *s);


#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_ADDR_H__ */
