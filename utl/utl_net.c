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
#include "utl_common.h"
#include "utl_local.h"
#include "utl_net.h"


/**************************************************************************
 * macro functions
 **************************************************************************/

#define M_IPV4_ADDR_PACK(b0, b1, b2, b3) ( \
    (const uint8_t)b0 <<  24 | \
    (const uint8_t)b1 << 16 | \
    (const uint8_t)b2 << 8 | \
    (const uint8_t)b3 \
)

#define M_IPV4_ADDR_MASK_EXPAND(mask_bit_num)  ((uint32_t)(0xffffffff << (32 - mask_bit_num)))


/**************************************************************************
 * prototypes
 **************************************************************************/

static inline bool ipv4_addr_is_subset(const uint8_t addr[4], uint8_t mask_bit_num, const uint8_t target_addr[4]);


/**************************************************************************
 * public functions
 **************************************************************************/

bool utl_net_ipv4_addr_is_routable(const uint8_t* addr)
{
    struct addrblock {
        uint8_t addr[4];
        uint8_t mask_bit_num;
    } reserved[] = {
        {{0, 0, 0, 0}, 8},
        {{10, 0, 0, 0}, 8},
        {{100, 64, 0, 0}, 10},
        {{127, 0, 0, 0}, 8},
        {{169, 254, 0, 0}, 16},
        {{172, 16, 0, 0}, 12},
        {{192, 0, 0, 0}, 24},
        {{192, 0, 2, 0}, 24},
        {{192, 88, 99, 0}, 24},
        {{192, 168, 0, 0}, 16},
        {{198, 18, 0, 0}, 15},
        {{198, 51, 100, 0}, 24},
        {{203, 0, 113, 0}, 24},
        {{224, 0, 0, 0}, 4},
        {{240, 0, 0, 0}, 4},
        {{255, 255, 255, 255}, 32},
    };

    for (int i = 0; i < (int)ARRAY_SIZE(reserved); ++i) {
        if (ipv4_addr_is_subset(reserved[i].addr, reserved[i].mask_bit_num, addr)) return false;
    }
    return true;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static inline bool ipv4_addr_is_subset(const uint8_t addr[4], uint8_t mask_bit_num, const uint8_t target_addr[4])
{
    uint32_t addr_packed = M_IPV4_ADDR_PACK(addr[0], addr[1], addr[2], addr[3]);
    uint32_t mask = M_IPV4_ADDR_MASK_EXPAND(mask_bit_num);
    uint32_t target_addr_packed = M_IPV4_ADDR_PACK(target_addr[0], target_addr[1], target_addr[2], target_addr[3]);

    return !((addr_packed ^ target_addr_packed) & mask);
}


/**************************************************************************
 * debug functions
 **************************************************************************/

