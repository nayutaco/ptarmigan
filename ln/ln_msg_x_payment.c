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
/** @file   ln_msg_x_payment.c
 *  @brief  msg_x_payment
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "utl_dbg.h"
#include "utl_int.h"

#include "btc_crypto.h"
#include "btc_buf.h"

#include "ln_msg_x_payment.h"
#include "ln_local.h"
#include "ln_msg_x.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_WRITE
#define DBG_PRINT_READ


/**************************************************************************
 * prototypes
 **************************************************************************/

#if defined(DBG_PRINT_READ) || defined(DBG_PRINT_WRITE)
static void x_payment_invoice_print(const ln_msg_x_payment_invoice_t *pMsg);
#endif  //DBG_PRINT_READ || DBG_PRINT_WRITE


/********************************************************************
 * payment_invoice
 ********************************************************************/

bool HIDDEN ln_msg_x_payment_invoice_write(utl_buf_t *pBuf, const ln_msg_x_payment_invoice_t *pMsg)
{
#ifdef DBG_PRINT_WRITE
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_payment_invoice_print(pMsg);
#endif  //DBG_PRINT_WRITE

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_X_PAYMENT_INVOICE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->len)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_invoice, pMsg->len)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->amount_msat)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_x_payment_invoice_read(ln_msg_x_payment_invoice_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_X_PAYMENT_INVOICE) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->len)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_invoice, BTC_SZ_HASH256)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->amount_msat)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ
    LOGD("@@@@@ %s @@@@@\n", __func__);
    x_payment_invoice_print(pMsg);
#endif  //DBG_PRINT_READ
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


#if defined(DBG_PRINT_READ) || defined(DBG_PRINT_WRITE)
static void x_payment_invoice_print(const ln_msg_x_payment_invoice_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[x_payment_invoice]-------------------------------\n");
    LOGD("invoice: ");
    DUMPD(pMsg->p_invoice, pMsg->len);
    LOGD("amount_msat: %" PRIu64 "\n", pMsg->amount_msat);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif  //DBG_PRINT_READ || DBG_PRINT_WRITE
