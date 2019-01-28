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
/** @file   ln_msg.c
 *  @brief  msg
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utl_common.h"

#include "ln_msg.h"


/********************************************************************
 * public functions
 ********************************************************************/

const char *ln_msg_name(uint16_t Type)
{
    const struct {
        uint16_t        type;
        const char      *name;
    } MESSAGE[] = {
        { 0x0010, "init" },
        { 0x0011, "error" },
        { 0x0012, "ping" },
        { 0x0013, "pong" },
        { 0x0020, "open_channel" },
        { 0x0021, "accept_channel" },
        { 0x0022, "funding_created" },
        { 0x0023, "funding_signed" },
        { 0x0024, "funding_locked" },
        { 0x0026, "shutdown" },
        { 0x0027, "closing_signed" },
        { 0x0080, "update_add_htlc" },
        { 0x0082, "update_fulfill_htlc" },
        { 0x0083, "update_fail_htlc" },
        { 0x0084, "commitment_signed" },
        { 0x0085, "revoke_and_ack" },
        { 0x0086, "update_fee" },
        { 0x0087, "update_fail_malformed_htlc" },
        { 0x0088, "channel_reestablish" },
        { 0x0100, "channel_announcement" },
        { 0x0101, "node_announcement" },
        { 0x0102, "channel_update" },
        { 0x0103, "announcement_signatures" },
        { 0x0105, "query_short_channel_ids" },
        { 0x0106, "reply_short_channel_ids_end" },
        { 0x0107, "query_channel_range" },
        { 0x0108, "reply_channel_range" },
        { 0x0109, "gossip_timestamp_filter" },
    };
    for (size_t lp = 0; lp < ARRAY_SIZE(MESSAGE); lp++) {
        if (Type == MESSAGE[lp].type) {
            return MESSAGE[lp].name;
        }
    }
    return "UNKNOWN MESSAGE";
}


