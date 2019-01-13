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
/** @file   ln_msg_setupctl.h
 *  @brief  [LN]Setup/Control関連
 */
#ifndef LN_MSG_SETUPCTL_H__
#define LN_MSG_SETUPCTL_H__

#include <stdbool.h>

#include "ln.h"


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct     ln_msg_init_t
 *  @brief      init
 */
typedef struct {
    //type: 16 (init)
    //data:
    //  [2:gflen]
    //  [gflen:globalfeatures]
    //  [2:lflen]
    //  [lflen:localfeatures]

    uint16_t        gflen;
    const uint8_t   *p_globalfeatures;
    uint16_t        lflen;
    const uint8_t   *p_localfeatures;
} ln_msg_init_t;


/** @struct     ln_msg_error_t
 *  @brief      error
 */
typedef struct {
    //type: 17 (error)
    //data:
    //  [32:channel_id]
    //  [2:len]
    //  [len:data]

    const uint8_t   *p_channel_id;
    uint16_t        len;
    const uint8_t   *p_data;
} ln_msg_error_t;


/** @struct     ln_msg_ping_t
 *  @brief      ping
 */
typedef struct {
    //type: 18 (ping)
    //data:
    //  [2:num_pong_bytes]
    //  [2:byteslen]
    //  [byteslen:ignored]

    uint16_t        num_pong_bytes;
    uint16_t        byteslen;
    const uint8_t   *p_ignored;
} ln_msg_ping_t;


/** @struct     ln_msg_pong_t
 *  @brief      pong
 */
typedef struct {
    //type: 19 (pong)
    //data:
    //  [2:byteslen]
    //  [byteslen:ignored]

    uint16_t        byteslen;
    const uint8_t   *p_ignored;
} ln_msg_pong_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** init生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_init_write(utl_buf_t *pBuf, const ln_msg_init_t *pMsg);


/** init読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len);


/** error生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_error_write(utl_buf_t *pBuf, const ln_msg_error_t *pMsg);


/** error読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_error_read(ln_msg_error_t *pMsg, const uint8_t *pData, uint16_t Len);


/** ping生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_ping_write(utl_buf_t *pBuf, const ln_msg_ping_t *pMsg);


/** ping読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_ping_read(ln_msg_ping_t *pMsg, const uint8_t *pData, uint16_t Len);


/** pong生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_pong_write(utl_buf_t *pBuf, const ln_msg_pong_t *pMsg);


/** pong読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_pong_read(ln_msg_pong_t *pMsg, const uint8_t *pData, uint16_t Len);


#endif /* LN_MSG_SETUPCTL_H__ */
