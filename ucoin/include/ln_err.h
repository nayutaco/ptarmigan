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
/** @file   ln_err.h
 *  @brief  Lightning Library Error Code
 *  @author ueno@nayuta.co
 */
#ifndef LN_ERR_H__
#define LN_ERR_H__
#if 0
#define LNERR_GRP_GENERAL       (1000)
#define LNERR_GRP_ESTABLISH     (1100)
#define LNERR_GRP_CLOSE         (1200)
#define LNERR_GRP_MSG           ()

#define LNERR_INV_NODEID            (LNERR_GRP_GENERAL +  1)
#define LNERR_INV_PRIVKEY           (LNERR_GRP_GENERAL +  2)
#define LNERR_INV_PREF              (LNERR_GRP_GENERAL +  3)
#define LNERR_INV_ADDR              (LNERR_GRP_GENERAL +  4)
#define LNERR_INV_STATE             (LNERR_GRP_GENERAL +  5)
#define LNERR_NO_PEER               (LNERR_GRP_GENERAL +  6)
#define LNERR_NO_CHANNEL            (LNERR_GRP_GENERAL +  7)
#define LNERR_INV_CHANNEL           (LNERR_GRP_GENERAL +  8)
#define LNERR_INV_SHORT_CHANNEL     (LNERR_GRP_GENERAL +  9)
#define LNERR_INV_VALUE             (LNERR_GRP_GENERAL + 10)
#define LNERR_INV_FEATURE           (LNERR_GRP_GENERAL + 11)
#define LNERR_INV_SIDE              (LNERR_GRP_GENERAL + 12)

#define LNERR_HTLC_FULL             (LNERR_GRP_ESTABLISH +  1)
#define LNERR_INV_PREIMAGE          (LNERR_GRP_ESTABLISH +  2)
#define LNERR_INV_ID                (LNERR_GRP_ESTABLISH +  3)
#define LNERR_CREATE_2OF2           (LNERR_GRP_ESTABLISH +  4)
#define LNERR_ADDHTLC_APP           (LNERR_GRP_ESTABLISH +  5)

#define LNERR_NOT_CLEAN             (LNERR_GRP_CLOSE +  1)

#define LNERR_PINGPONG
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_


#define LNERR_MSG_INIT
#define LNERR_MSG_ERROR
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#define LNERR_
#else
enum {
    LNERR_INV_NODEID,
    LNERR_INV_PRIVKEY,
    LNERR_INV_PREF,
    LNERR_INV_ADDR,
    LNERR_INV_STATE,
    LNERR_NO_PEER,
    LNERR_NO_CHANNEL,
    LNERR_INV_CHANNEL,
    LNERR_INV_SHORT_CHANNEL,
    LNERR_INV_VALUE,
    LNERR_INV_FEATURE,
    LNERR_INV_SIDE,
    LNERR_NOT_CLEAN,
    LNERR_HTLC_FULL,
    LNERR_HTLC_NUM,
    LNERR_INV_PREIMAGE,
    LNERR_INV_ID,
    LNERR_PINGPONG,
    LNERR_CREATE_2OF2,
    LNERR_MSG_INIT,
    LNERR_MSG_ERROR,
    LNERR_ADDHTLC_APP,
};
#endif
#endif /* LN_ERR_H__ */
