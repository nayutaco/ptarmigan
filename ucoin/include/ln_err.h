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


/**************************************************************************
 * library error
 **************************************************************************/

enum {
    LNERR_ERROR,
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
    LNERR_CREATE_MSG,
    LNERR_CREATE_TX,
    LNERR_MSG_READ,
    LNERR_MSG_INIT,
    LNERR_MSG_ERROR,
    LNERR_ADDHTLC_APP,
    LNERR_ALREADY_FUNDING,
    LNERR_ONION,
};


/**************************************************************************
 * onion
 **************************************************************************/

#define LNERR_ONION_BADONION        ((uint16_t)0x8000)
#define LNERR_ONION_PERM            ((uint16_t)0x4000)
#define LNERR_ONION_NODE            ((uint16_t)0x2000)
#define LNERR_ONION_UPDATE          ((uint16_t)0x1000)

typedef enum {
    LNONION_INV_REALM               = ((uint16_t)(LNERR_ONION_PERM | 1)),
    LNONION_TMP_NODE_FAIL           = ((uint16_t)(LNERR_ONION_NODE | 2)),
    LNONION_PERM_NODE_FAIL          = ((uint16_t)(LNERR_ONION_PERM | LNERR_ONION_NODE | 2)),
    LNONION_REQ_NODE_FTR_MISSING    = ((uint16_t)(LNERR_ONION_PERM | LNERR_ONION_NODE | 3)),
    LNONION_INV_ONION_VERSION       = ((uint16_t)(LNERR_ONION_BADONION | LNERR_ONION_PERM | 4)),
    LNONION_INV_ONION_HMAC          = ((uint16_t)(LNERR_ONION_BADONION | LNERR_ONION_PERM | 5)),
    LNONION_INV_ONION_KEY           = ((uint16_t)(LNERR_ONION_BADONION | LNERR_ONION_PERM | 6)),
    LNONION_TMP_CHAN_FAIL           = ((uint16_t)(LNERR_ONION_UPDATE | 7)),
    LNONION_PERM_CHAN_FAIL          = ((uint16_t)(LNERR_ONION_PERM | 8)),
    LNONION_REQ_CHAN_FTR_MISSING    = ((uint16_t)(LNERR_ONION_PERM | 9)),
    LNONION_UNKNOWN_NEXT_PEER       = ((uint16_t)(LNERR_ONION_PERM | 10)),
    LNONION_AMT_BELOW_MIN           = ((uint16_t)(LNERR_ONION_UPDATE | 11)),
    LNONION_FEE_INSUFFICIENT        = ((uint16_t)(LNERR_ONION_UPDATE | 12)),
    LNONION_INCORR_CLTV_EXPIRY      = ((uint16_t)(LNERR_ONION_UPDATE | 13)),
    LNONION_EXPIRY_TOO_SOON         = ((uint16_t)(LNERR_ONION_UPDATE | 14)),
    LNONION_UNKNOWN_PAY_HASH        = ((uint16_t)(LNERR_ONION_PERM | 15)),
    LNONION_INCORR_PAY_AMT          = ((uint16_t)(LNERR_ONION_PERM | 16)),
    LNONION_FINAL_EXPIRY_TOO_SOON   = ((uint16_t)(17)),
    LNONION_FINAL_INCORR_CLTV_EXP   = ((uint16_t)(18)),
    LNONION_FINAL_INCORR_HTLC_AMT   = ((uint16_t)(19)),
    LNONION_CHAN_DISABLE            = ((uint16_t)(LNERR_ONION_UPDATE | 20)),
    LNONION_EXPIRY_TOO_FAR          = ((uint16_t)(21)),
} lnerr_onion_t;

#endif /* LN_ERR_H__ */
