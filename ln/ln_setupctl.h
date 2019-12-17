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
/** @file   ln_setupctl.h
 *  @brief  ln_setupctl
 */
#ifndef LN_SETUPCTL_H__
#define LN_SETUPCTL_H__

#include <stdbool.h>

#include "ln.h"
#include "ln_msg_setupctl.h"

//XXX: unit test

/********************************************************************
 * macros
 ********************************************************************/

// ln_channel_t.init_flag //XXX:
#define M_INIT_FLAG_SEND                    (0x0001)
#define M_INIT_FLAG_RECV                    (0x0002)
#define M_INIT_FLAG_EXCG                    (M_INIT_FLAG_SEND | M_INIT_FLAG_RECV)
#define M_INIT_FLAG_EXCHNAGED(flag)         (((flag) & M_INIT_FLAG_EXCG) == M_INIT_FLAG_EXCG)
#define M_INIT_FLAG_REEST_SEND              (0x0004)
#define M_INIT_FLAG_REEST_RECV              (0x0008)
#define M_INIT_FLAG_REEST_EXCG              (M_INIT_FLAG_REEST_SEND | M_INIT_FLAG_REEST_RECV)
#define M_INIT_FLAG_REEST_EXCHNAGED(flag)   (((flag) & M_INIT_FLAG_REEST_EXCG) == M_INIT_FLAG_REEST_EXCG)
#define M_INIT_ANNOSIG_SENT                 (0x0010)          ///< announcement_signatures送信/再送済み
#define M_INIT_GOSSIP_QUERY                 (0x0020)          ///< gossip_queries
#define M_INIT_FLAG_FLOCK_SEND              (0x0040)
#define M_INIT_FLAG_FLOCK_RECV              (0x0080)
#define M_INIT_FLAG_FLOCK_EXCG              (M_INIT_FLAG_FLOCK_SEND | M_INIT_FLAG_FLOCK_RECV)
#define M_INIT_FLAG_FLOCK_EXCHNAGED(flag)   (((flag) & M_INIT_FLAG_FLOCK_EXCG) == M_INIT_FLAG_FLOCK_EXCG)
#define M_INIT_FLAG_STATIC_REMOTEKEY        (0x0100)

#define M_SET_ERR(pChannel, err, fmt,...) { \
        ln_error_set(pChannel, err, fmt, ##__VA_ARGS__); \
        LOGE("[%s:%d]fail: %s\n", __func__, (int)__LINE__, pChannel->err_msg); \
    }
#define M_SEND_ERR(pChannel, err, fmt, ...) { \
        ln_error_set(pChannel, err, fmt, ##__VA_ARGS__); \
        ln_error_send(pChannel); \
        LOGE("[%s:%d]fail: %s\n", __func__, (int)__LINE__, pChannel->err_msg); \
    }


/********************************************************************
 * prototypes
 ********************************************************************/

/** init.localfeatures設定
 * 未設定の場合はデフォルト値が使用される。
 *
 */
void ln_init_localfeatures_set(uint16_t lf);

void /*HIDDEN*/ ln_error_set(ln_channel_t *pChannel, int Err, const char *pFormat, ...);

bool /*HIDDEN*/ ln_init_send(ln_channel_t *pChannel, bool bInitRouteSync, bool bHaveCnl);
bool HIDDEN ln_init_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool /*HIDDEN*/ ln_error_send(ln_channel_t *pChannel);
bool HIDDEN ln_error_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool /*HIDDEN*/ ln_ping_send(ln_channel_t *pChannel, uint16_t PingLen, uint16_t PongLen);
bool HIDDEN ln_ping_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);
bool HIDDEN ln_pong_send(ln_channel_t *pChannel, ln_msg_ping_t *pPingMsg);
bool HIDDEN ln_pong_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len);


#endif /* LN_SETUPCTL_H__ */
