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
/** @file   ln_anno.h
 *  @brief  ln_anno
 */
#ifndef LN_ANNO_H__
#define LN_ANNO_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln.h"
#include "ln_msg_anno.h"

//XXX: unit test

/********************************************************************
 * prototypes
 ********************************************************************/

bool /*HIDDEN*/ ln_announcement_signatures_send(ln_channel_t *pChannel);
bool HIDDEN ln_announcement_signatures_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
//XXX: no ch-anno send
bool HIDDEN ln_channel_announcement_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_node_announcement_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool /*HIDDEN*/ ln_channel_update_send(ln_channel_t *pChannel);
bool HIDDEN ln_channel_update_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool ln_channel_update_disable(ln_channel_t *pChannel);

bool ln_query_short_channel_ids_send(ln_channel_t *pChannel, const uint8_t *pEncodedIds, uint16_t Len);
bool HIDDEN ln_query_short_channel_ids_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool ln_reply_short_channel_ids_end_send(ln_channel_t *pChannel, const ln_msg_query_short_channel_ids_t *pMsg);
bool HIDDEN ln_reply_short_channel_ids_end_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool ln_query_channel_range_send(ln_channel_t *pChannel, uint32_t FirstBlock, uint32_t Num);
bool HIDDEN ln_query_channel_range_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool ln_reply_channel_range_send(ln_channel_t *pChannel, const ln_msg_query_channel_range_t *pMsg);
bool HIDDEN ln_reply_channel_range_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool ln_gossip_timestamp_filter_send(ln_channel_t *pChannel);
bool HIDDEN ln_gossip_timestamp_filter_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);

#endif /* LN_ANNO_H__ */
