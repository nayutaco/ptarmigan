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
/** @file   lnapp_cb.h
 *  @brief  lnapp_cb header
 */
#ifndef LNAPP_CB_H__
#define LNAPP_CB_H__

#include <pthread.h>
#include <sys/queue.h>

#include "ptarmd.h"
#include "conf.h"


#ifdef __cplusplus
extern "C" {
#endif

/********************************************************************
 * prototypes
 ********************************************************************/

void lnapp_notify_cb(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam);


#ifdef __cplusplus
}
#endif

#endif /* LNAPP_CB_H__ */
