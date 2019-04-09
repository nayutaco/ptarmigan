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
/** @file   ln_msg_x_payment.h
 *  @brief  payment
 */
#ifndef LN_MSG_X_PAYMENT_H__
#define LN_MSG_X_PAYMENT_H__

#include <stdbool.h>

#include "utl_buf.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     ln_msg_x_payment_invoice_t
 *  @brief      payment_invoice
 */
typedef struct {
    //type: 32 (x_payment_invoice)
    //data:
    //  [2:len]
    //  [len:invoice]
    //  [8:amount_msat] (option)

    uint16_t        len;
    const uint8_t   *p_invoice;
    uint64_t        amount_msat;
} ln_msg_x_payment_invoice_t;


/********************************************************************
 * prototypes
 ********************************************************************/

/** payment_invoice生成
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_payment_invoice_write(utl_buf_t *pBuf, const ln_msg_x_payment_invoice_t *pMsg);


/** payment_invoice読込み
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_x_payment_invoice_read(ln_msg_x_payment_invoice_t *pMsg, const uint8_t *pData, uint16_t Len);


#endif /* LN_MSG_X_PAYMENT_H__ */
