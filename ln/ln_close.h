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
/** @file   ln_close.h
 *  @brief  ln_close
 */
#ifndef LN_CLOSE_H__
#define LN_CLOSE_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln.h"
#include "ln_msg_close.h"

//XXX: unit test

/********************************************************************
 * prototypes
 ********************************************************************/

bool /*HIDDEN*/ ln_is_shutdowning(ln_channel_t *pChannel);
bool /*HIDDEN*/ ln_shutdown_set_send(ln_channel_t *pChannel);
void /*HIDDEN*/ ln_shutdown_reset(ln_channel_t *pChannel);
bool HIDDEN ln_shutdown_send_needs(ln_channel_t *pChannel);
bool HIDDEN ln_closing_signed_send_needs(ln_channel_t *pChannel);

bool HIDDEN ln_shutdown_send(ln_channel_t *pChannel);
bool HIDDEN ln_shutdown_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_closing_signed_send(ln_channel_t *pChannel, ln_msg_closing_signed_t *pClosingSignedMsg);
bool HIDDEN ln_closing_signed_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);


#endif /* LN_CLOSE_H__ */
