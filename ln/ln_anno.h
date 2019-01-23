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

bool /*HIDDEN*/ ln_announcement_signatures_send(ln_self_t *self);
bool HIDDEN ln_announcement_signatures_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
//XXX: no ch-anno send
bool HIDDEN ln_channel_announcement_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_node_announcement_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool /*HIDDEN*/ ln_channel_update_send(ln_self_t *self);
bool HIDDEN ln_channel_update_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len);
bool ln_channel_update_disable(ln_self_t *self);


#endif /* LN_ANNO_H__ */
