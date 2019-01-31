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
/** @file   ln_comtx_util.h
 *  @brief  ln_comtx_ex
 */
#ifndef LN_COMTX_EX_H__
#define LN_COMTX_EX_H__

#include <stdint.h>
#include <stdbool.h>

#include "utl_common.h"

//XXX: unit test


/********************************************************************
 * macros
 ********************************************************************/

/** @def    LN_SEQUENCE(obs)
 *  @brief  obscured commitment numberから<sequence>算出
 */
#define LN_SEQUENCE(obs)        ((uint32_t)(0x80000000 | (((obs) >> 24) & 0xffffff))) //[0x80][upper 3bytes]


/** @def    LN_LOCKTIME(obs)
 *  @brief  obscured commitment numberから<locktime>算出
 */
#define LN_LOCKTIME(obs)        ((uint32_t)(0x20000000 | ((obs) & 0xffffff)))         //[0x20][lower 3bytes]


/********************************************************************
 * prototypes
 ********************************************************************/

/** Obscured Commitment Number計算
 *
 * @param[in]       pOpenPayBasePt     payment_basepoint from open_channel
 * @param[in]       pAcceptPayBasePt   payment_basepoint from accept_channel
 * @return      Obscured Commitment Number Base
 */
uint64_t HIDDEN ln_comtx_calc_obscured_commit_num_base(const uint8_t *pOpenPayBasePt, const uint8_t *pAcceptPayBasePt);


uint64_t HIDDEN ln_comtx_calc_obscured_commit_num(uint64_t ObscuredCommitNumBase, uint64_t CommitNum);


#endif /* LN_COMTX_EX_H__ */
