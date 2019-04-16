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
/** @file   lnapp_util.h
 *  @brief  lnapp_util
 */
#ifndef LNAPP_UTIL_H__
#define LNAPP_UTIL_H__

#include <stdint.h>

#include "lnapp.h"


#ifdef __cplusplus
extern "C" {
#endif

/********************************************************************
 * macros
 ********************************************************************/

#define LNAPP_WAIT_ANNO_HYSTER_SEC  (1)         //announce DBが更新されて展開するまでの最低空き時間[sec]


/********************************************************************
 * prototypes
 ********************************************************************/

void lnapp_stop_threads(lnapp_conf_t *p_conf);
bool lnapp_send_peer_raw(lnapp_conf_t *p_conf, const utl_buf_t *pBuf);
bool lnapp_send_peer_noise(lnapp_conf_t *p_conf, const utl_buf_t *pBuf);
void lnapp_set_last_error(lnapp_conf_t *p_conf, int Err, const char *pErrStr);


#ifdef __cplusplus
}
#endif

#endif /* LNAPP_UTIL_H__ */
