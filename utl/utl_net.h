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
 * @file    utl_net.h
 * @brief   utl_net
 */
#ifndef UTL_NET_H__
#define UTL_NET_H__

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

/** check ipv4 addr is routable or not
 *
 * @param[in]    addr    network byte order ipv4 address
 * @retval      true    routable
 */
bool utl_net_ipv4_addr_is_routable(const uint8_t* addr);


/** name resolution
 * 
 * @param[out]  pIpStr      first resolved result
 * @param[in]   pName       name
 * @param[in]   Port        port number
 */
bool utl_net_resolve(char *pIpStr, const char *pName, int Port);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* UTL_NET_H__ */
