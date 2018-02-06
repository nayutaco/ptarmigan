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
    LNERR_ALREADY_FUNDING,
};

#endif /* LN_ERR_H__ */
