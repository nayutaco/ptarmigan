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
/** @file   ln_payment.h
 *  @brief  ln_payment
 */
#ifndef LN_PAYMENT_H__
#define LN_PAYMENT_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln.h"

//XXX: unit test


/********************************************************************
 * typedef
 ********************************************************************/

#define LN_PAYMENT_ID_INVALID   UINT64_C(0xffffffffffffffff)


/********************************************************************
 * typedef
 ********************************************************************/

typedef enum {
    LN_PAYMENT_OK = 0,
    LN_PAYMENT_ERROR = 1,
    LN_PAYMENT_ERROR_INVOICE,
    LN_PAYMENT_ERROR_INVOICE_INVALID,
    LN_PAYMENT_ERROR_INVOICE_INVALID_TYPE,
    LN_PAYMENT_ERROR_INVOICE_OUTDATE,
    LN_PAYMENT_ERROR_ROUTE,
    LN_PAYMENT_ERROR_ROUTE_INVALID,
    LN_PAYMENT_ERROR_ROUTE_NO_START,
    LN_PAYMENT_ERROR_ROUTE_NO_GOAL,
    LN_PAYMENT_ERROR_ROUTE_NO_ROUTE,
    LN_PAYMENT_ERROR_ROUTE_TOO_MANY_HOPS,
    LN_PAYMENT_ERROR_RETRY,
} ln_payment_error_t;


typedef enum {
    LN_PAYMENT_NONE = 0,
    LN_PAYMENT_PROCESSING = 1,
    LN_PAYMENT_SUCCEEDED = 2,
    LN_PAYMENT_FAILED = 3,
} ln_payment_state_t;

typedef struct {
    uint8_t             payment_hash[BTC_SZ_HASH256];
    uint64_t            additional_amount_msat;
    uint8_t             retry_count;
    uint8_t             retry_count_max;
    bool                auto_remove;
    ln_payment_state_t  state;
} ln_payment_info_t;


typedef struct {
    uint8_t             hop_num;
    ln_hop_datain_t     hop_datain[1 + LN_HOP_MAX];     //[0] is a payer's data
} ln_payment_route_t;


/********************************************************************
 * prototypes
 ********************************************************************/

ln_payment_error_t ln_payment_start_invoice(
    uint64_t *pPaymentId, ln_payment_route_t *pRoute,
    const char *pInvoice, uint64_t AdditionalAmountMsat,
    uint8_t RetryCount, bool AutoRemove,
    uint32_t BlockCount);
ln_payment_error_t ln_payment_start_debug(
    uint64_t *pPaymentId, const uint8_t *pPaymentHash, const ln_payment_route_t *pRoute);
ln_payment_error_t ln_payment_retry(uint64_t PaymentId, uint32_t BlockCount);
bool ln_payment_end(uint64_t PaymentId, ln_payment_state_t state);

bool ln_payment_route_save(uint64_t PaymentId, const ln_payment_route_t *pRoute);
bool ln_payment_route_load(ln_payment_route_t *pRoute, uint64_t PaymentId);
bool ln_payment_route_del(uint64_t PaymentId);


#endif /* LN_PAYMENT_H__ */
