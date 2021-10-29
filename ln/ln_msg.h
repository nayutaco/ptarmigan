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
/** @file   ln_msg.h
 *  @brief  msg
 */
#ifndef LN_MSG_H__
#define LN_MSG_H__

#include <stdint.h>
#include <stdbool.h>


/**************************************************************************
 * macros
 **************************************************************************/

/*
 * message type
 */
#define MSGTYPE_INIT                        ((uint16_t)0x0010)
#define MSGTYPE_ERROR                       ((uint16_t)0x0011)
#define MSGTYPE_PING                        ((uint16_t)0x0012)
#define MSGTYPE_PONG                        ((uint16_t)0x0013)

#define MSGTYPE_OPEN_CHANNEL                ((uint16_t)0x0020)
#define MSGTYPE_ACCEPT_CHANNEL              ((uint16_t)0x0021)
#define MSGTYPE_FUNDING_CREATED             ((uint16_t)0x0022)
#define MSGTYPE_FUNDING_SIGNED              ((uint16_t)0x0023)
#define MSGTYPE_FUNDING_LOCKED              ((uint16_t)0x0024)
#define MSGTYPE_SHUTDOWN                    ((uint16_t)0x0026)
#define MSGTYPE_CLOSING_SIGNED              ((uint16_t)0x0027)

#define MSGTYPE_UPDATE_ADD_HTLC             ((uint16_t)0x0080)
#define MSGTYPE_UPDATE_FULFILL_HTLC         ((uint16_t)0x0082)
#define MSGTYPE_UPDATE_FAIL_HTLC            ((uint16_t)0x0083)
#define MSGTYPE_COMMITMENT_SIGNED           ((uint16_t)0x0084)
#define MSGTYPE_REVOKE_AND_ACK              ((uint16_t)0x0085)
#define MSGTYPE_UPDATE_FEE                  ((uint16_t)0x0086)
#define MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC  ((uint16_t)0x0087)
#define MSGTYPE_CHANNEL_REESTABLISH         ((uint16_t)0x0088)

#define MSGTYPE_CHANNEL_ANNOUNCEMENT        ((uint16_t)0x0100)
#define MSGTYPE_NODE_ANNOUNCEMENT           ((uint16_t)0x0101)
#define MSGTYPE_CHANNEL_UPDATE              ((uint16_t)0x0102)
#define MSGTYPE_ANNOUNCEMENT_SIGNATURES     ((uint16_t)0x0103)
#define MSGTYPE_QUERY_SHORT_CHANNEL_IDS     ((uint16_t)0x0105)
#define MSGTYPE_REPLY_SHORT_CHANNEL_IDS_END ((uint16_t)0x0106)
#define MSGTYPE_QUERY_CHANNEL_RANGE         ((uint16_t)0x0107)
#define MSGTYPE_REPLY_CHANNEL_RANGE         ((uint16_t)0x0108)
#define MSGTYPE_GOSSIP_TIMESTAMP_FILTER     ((uint16_t)0x0109)


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef enum ln_msg_groupt_t {
    MSGGROUP_UNKNOWN,       ///< unknown group
    MSGGROUP_SETUP_CTRL,    ///< Setup & Control (types 0-31)
    MSGGROUP_CHANNEL,       ///< Channel (types 32-127)
    MSGGROUP_COMMIT,        ///< Commitment (types 128-255)
    MSGGROUP_ROUTING,       ///< Routing (types 256-511)
} ln_msg_groupt_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

/** get message name
 *
 * @param[in]   type        BOLT message type
 * @return      message name
 */
const char *ln_msg_name(uint16_t Type);


uint16_t ln_msg_type(ln_msg_groupt_t *pGrp, const uint8_t *pData, uint16_t Len);


#endif /* LN_MSG_H__ */
