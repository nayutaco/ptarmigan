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
/** @file   ln_payment.c
 *  @brief  ln_payment
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "utl_str.h"
#include "utl_buf.h"
#include "utl_dbg.h"
#include "utl_time.h"
#include "utl_int.h"

#include "btc_crypto.h"
#include "btc_script.h"
#include "btc_sw.h"

#include "ln_db.h"
#include "ln_signer.h"
#include "ln_commit_tx.h"
#include "ln_derkey.h"
#include "ln_script.h"
#include "ln.h"
#include "ln_local.h"
#include "ln_setupctl.h"
#include "ln_anno.h"
#include "ln_invoice.h"
#include "ln_routing.h"
#include "ln_normalope.h"
#include "ln_payment.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static ln_payment_error_t route_invoice(
    ln_payment_route_t *pRoute, uint8_t *pPaymentHash,
    const char *pInvoice, uint32_t InvoiceLen,
    uint64_t AdditionalAmountMsat, uint32_t BlockCount);
static ln_payment_error_t payment_start(
    uint64_t *pPaymentId, const ln_payment_route_t *pRoute, const uint8_t *pPaymentHash,
    uint64_t AdditionalAmountMsat, uint8_t RetryCount, bool AutoRemove, uint32_t BlockCount,
    const char *pInvoice);
static ln_payment_error_t check_route(const ln_payment_route_t *pRoute);
static void payment_info_init(
    ln_payment_info_t *pInfo, const uint8_t *pPaymentHash, uint64_t AdditionalAmountMsat,
    uint8_t RetryCount, bool AutoRemove, uint32_t BlockCount, ln_payment_state_t state);
static ln_payment_error_t payment(uint64_t PaymentId, const uint8_t *pPaymentHash, const ln_payment_route_t *pRoute);


/********************************************************************
 * public functions
 ********************************************************************/

ln_payment_error_t ln_payment_start_invoice(
    uint64_t *pPaymentId, ln_payment_route_t *pRoute, const char *pInvoice,
    uint64_t AdditionalAmountMsat, uint8_t RetryCount, bool AutoRemove, uint32_t BlockCount)
{
    *pPaymentId = LN_PAYMENT_ID_INVALID;

    ln_payment_error_t  retval = LN_PAYMENT_ERROR;
    uint8_t             payment_hash[BTC_SZ_HASH256];

    retval = route_invoice(
        pRoute, payment_hash, pInvoice, strlen(pInvoice), AdditionalAmountMsat, BlockCount);
    if (retval != LN_PAYMENT_OK) {
        LOGE("fail: ???\n");
        return retval;
    }

    return payment_start(
        pPaymentId, pRoute, payment_hash, AdditionalAmountMsat,
        RetryCount, AutoRemove, BlockCount, pInvoice);
}


ln_payment_error_t ln_payment_start_test(
    uint64_t *pPaymentId, const uint8_t *pPaymentHash, const ln_payment_route_t *pRoute,
    uint32_t BlockCount)
{
    *pPaymentId = LN_PAYMENT_ID_INVALID;

    return payment_start(
        pPaymentId, pRoute, pPaymentHash, 0, 0, true, BlockCount, NULL);
}


ln_payment_error_t ln_payment_retry(uint64_t PaymentId, uint32_t BlockCount)
{
    ln_payment_error_t  retval = LN_PAYMENT_ERROR;
    utl_buf_t           buf_invoice = UTL_BUF_INIT;
    ln_payment_route_t  route;
    uint8_t             payment_hash[BTC_SZ_HASH256];
    ln_payment_info_t   info;

    //local payment data
    LOGD("payment_id: %" PRIu64 "\n", PaymentId);
    if (!ln_db_payment_info_load(&info, PaymentId)) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }
    if (info.retry_count >= info.max_retry_count) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }
    if (!ln_db_payment_invoice_load(&buf_invoice, PaymentId)) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }
    info.retry_count++;

    //routing with invoice
    retval = route_invoice(
        &route, payment_hash, (const char *)buf_invoice.buf, buf_invoice.len,
        info.additional_amount_msat, BlockCount);
    if (retval != LN_PAYMENT_OK) {
        LOGE("fail: ???\n");
        goto LABEL_ERROR;
    }

    //update payment data
    if (!ln_db_payment_info_save(PaymentId, &info)) {
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }
    if (!ln_payment_route_save(PaymentId, &route)) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }

    //payment
    retval = payment(PaymentId, payment_hash, &route);
    if (retval != LN_PAYMENT_OK) {
        LOGE("fail: ???\n");
        goto LABEL_ERROR;
    }

    utl_buf_free(&buf_invoice);
    return LN_PAYMENT_OK;

LABEL_ERROR:
    if (retval == LN_PAYMENT_ERROR_RETRY) {
        retval = ln_payment_retry(PaymentId, BlockCount);
    }

    utl_buf_free(&buf_invoice);
    return retval;
}


bool ln_payment_end(uint64_t PaymentId, ln_payment_state_t State, const uint8_t *pPreimage)
{
    ln_payment_info_t info;
    if (!ln_db_payment_info_load(&info, PaymentId)) {
        LOGE("fail: ???\n");
        return false;
    }
    if (info.auto_remove) {
        /*ignore*/ln_db_payment_del_all(PaymentId);
    } else {
        /*ignore*/ln_db_payment_shared_secrets_del(PaymentId);
        /*ignore*/ln_db_payment_route_del(PaymentId);
        info.state = State;
        if (State == LN_PAYMENT_STATE_SUCCEEDED) {
            if (pPreimage) {
                memcpy(info.preimage, pPreimage, LN_SZ_PREIMAGE);
            } else {
                LOGE("fail: ???\n");
            }
        }
        if (!ln_db_payment_info_save(PaymentId, &info)) {
            LOGE("fail: ???\n");
            return false;
        }
    }
    return true;
}


bool ln_payment_route_save(uint64_t PaymentId, const ln_payment_route_t *pRoute)
{
    return ln_db_payment_route_save(PaymentId, (const uint8_t *)pRoute->hop_datain, pRoute->num_hops * sizeof(ln_hop_datain_t));
}


bool ln_payment_route_load(ln_payment_route_t *pRoute, uint64_t PaymentId)
{
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_db_payment_route_load(&buf, PaymentId)) {
        LOGE("fail: ???\n");
        return false;
    }
    if (buf.len % sizeof(ln_hop_datain_t)) {
        LOGE("fail: ???\n");
        utl_buf_free(&buf);
        return false;
    }
    pRoute->num_hops = buf.len / sizeof(ln_hop_datain_t);
    memcpy(pRoute->hop_datain, buf.buf, buf.len);
    utl_buf_free(&buf);
    return true;
}


bool ln_payment_route_del(uint64_t PaymentId)
{
    return ln_db_payment_route_del(PaymentId);
}


/********************************************************************
 * private functions
 ********************************************************************/

static void payment_info_init(
    ln_payment_info_t *pInfo, const uint8_t *pPaymentHash, uint64_t AdditionalAmountMsat,
    uint8_t RetryCount, bool AutoRemove, uint32_t BlockCount, ln_payment_state_t state)
{
    memset(pInfo, 0x00, sizeof(ln_payment_info_t));
    memcpy(pInfo->payment_hash, pPaymentHash, BTC_SZ_HASH256);
    pInfo->additional_amount_msat = AdditionalAmountMsat;
    pInfo->retry_count = 0;
    pInfo->max_retry_count = RetryCount;
    pInfo->auto_remove = AutoRemove;
    pInfo->block_count = BlockCount;
    pInfo->state = state;
}


static ln_payment_error_t route_invoice(
    ln_payment_route_t *pRoute, uint8_t *pPaymentHash,
    const char *pInvoice, uint32_t InvoiceLen,
    uint64_t AdditionalAmountMsat, uint32_t BlockCount)
{
    ln_payment_error_t retval = LN_PAYMENT_ERROR;

    ln_invoice_t *p_invoice_data = NULL;
    if (!ln_invoice_decode_2(&p_invoice_data, pInvoice, InvoiceLen)) {
        retval =  LN_PAYMENT_ERROR_INVOICE_INVALID;
        goto LABEL_ERROR;
    }

    switch (p_invoice_data->hrp_type) {
    case LN_INVOICE_MAINNET:
    case LN_INVOICE_TESTNET:
    case LN_INVOICE_REGTEST:
        break;
    default:
        LOGE("fail: mismatch blockchain\n");
        retval = LN_PAYMENT_ERROR_INVOICE_INVALID_TYPE;
        goto LABEL_ERROR;
    }

    if (p_invoice_data->timestamp + p_invoice_data->expiry < (uint64_t)utl_time_time()) {
        LOGE("fail: invoice outdated\n");
        retval = LN_PAYMENT_ERROR_INVOICE_OUTDATE;
        goto LABEL_ERROR;
    }

    ln_routing_add_rfield(
        p_invoice_data->r_field_num,
        p_invoice_data->r_field,
        p_invoice_data->pubkey);

    p_invoice_data->amount_msat += AdditionalAmountMsat;

    ln_routing_result_t route_result;
    lnerr_route_t err = ln_routing_calculate(
        &route_result, ln_node_get_id(), p_invoice_data->pubkey,
        BlockCount + p_invoice_data->min_final_cltv_expiry,
        p_invoice_data->amount_msat);
    if (err != LNROUTE_OK) {
        LOGE("fail: routing\n");
        switch (err) {
        case LNROUTE_NOSTART:
            retval = LN_PAYMENT_ERROR_ROUTE_NO_START;
            goto LABEL_ERROR;
        case LNROUTE_NOGOAL:
            retval = LN_PAYMENT_ERROR_ROUTE_NO_GOAL;
            goto LABEL_ERROR;
        case LNROUTE_NOTFOUND:
            retval = LN_PAYMENT_ERROR_ROUTE_NO_ROUTE;
            goto LABEL_ERROR;
        case LNROUTE_TOOMANYHOP:
            retval = LN_PAYMENT_ERROR_ROUTE_TOO_MANY_HOPS;
            goto LABEL_ERROR;
        default:
            retval = LN_PAYMENT_ERROR_ROUTE;
            goto LABEL_ERROR;
        }
    }

    memcpy(pPaymentHash, p_invoice_data->payment_hash, BTC_SZ_HASH256);
    pRoute->num_hops = route_result.num_hops;
    memcpy(pRoute->hop_datain, route_result.hop_datain, sizeof(pRoute->hop_datain));

    ln_invoice_decode_free(p_invoice_data);
    return LN_PAYMENT_OK;

LABEL_ERROR:
    ln_invoice_decode_free(p_invoice_data);
    return retval;
}


static ln_payment_error_t payment_start(
    uint64_t *pPaymentId, const ln_payment_route_t *pRoute, const uint8_t *pPaymentHash,
    uint64_t AdditionalAmountMsat, uint8_t RetryCount, bool AutoRemove, uint32_t BlockCount,
    const char *pInvoice)
{
    ln_payment_error_t  retval = LN_PAYMENT_ERROR;
    ln_payment_info_t   info;

    //save payment data
    if (!ln_db_payment_get_new_payment_id(pPaymentId)) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }
    LOGD("payment_id: %" PRIu64 "\n", *pPaymentId);
    payment_info_init(
        &info, pPaymentHash, AdditionalAmountMsat, RetryCount, AutoRemove,
        BlockCount, LN_PAYMENT_STATE_PROCESSING);
    if (!ln_db_payment_info_save(*pPaymentId, &info)) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }
    if (!ln_payment_route_save(*pPaymentId, pRoute)) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }
    if (pInvoice) {
        if (!ln_db_payment_invoice_save(
            *pPaymentId, (const uint8_t *)pInvoice, strlen(pInvoice))) {
            LOGE("fail: ???\n");
            retval = LN_PAYMENT_ERROR;
            goto LABEL_ERROR;
        }
    }

    //payment
    retval = payment(*pPaymentId, pPaymentHash, pRoute);
    if (retval != LN_PAYMENT_OK) {
        LOGE("fail: ???\n");
        goto LABEL_ERROR;
    }

    return LN_PAYMENT_OK;

LABEL_ERROR:
    if (retval == LN_PAYMENT_ERROR_RETRY && !RetryCount) {
        retval = LN_PAYMENT_ERROR;
    }
    if (retval == LN_PAYMENT_ERROR_RETRY) {
        retval = ln_payment_retry(*pPaymentId, BlockCount);
    } else {
        ln_db_payment_del_all(*pPaymentId);
    }
    return retval;
}


static ln_payment_error_t payment(
    uint64_t PaymentId, const uint8_t *pPaymentHash, const ln_payment_route_t *pRoute)
{
    uint8_t             session_key[BTC_SZ_PRIVKEY];
    uint8_t             onion[LN_SZ_ONION_ROUTE];
    utl_buf_t           secrets = UTL_BUF_INIT;
    ln_payment_error_t  retval = LN_PAYMENT_ERROR;

    retval = check_route(pRoute);
    if (retval != LN_PAYMENT_OK) {
        goto LABEL_ERROR;
    }

    btc_rng_rand(session_key, sizeof(session_key));
    if (!ln_onion_create_packet(
        onion, &secrets, &pRoute->hop_datain[1], pRoute->num_hops - 1,
        session_key, pPaymentHash, BTC_SZ_HASH256)) {
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }

    if (!ln_db_payment_shared_secrets_save(PaymentId, secrets.buf, secrets.len)) {
        LOGE("fail: ???\n");
        retval = LN_PAYMENT_ERROR;
        goto LABEL_ERROR;
    }

    if (!ln_set_add_htlc_send_origin(
        pRoute->hop_datain[0].short_channel_id, 0, PaymentId,
        pRoute->hop_datain[0].amt_to_forward, pPaymentHash,
        pRoute->hop_datain[0].outgoing_cltv_value, onion)) {
        ln_db_route_skip_save(pRoute->hop_datain[0].short_channel_id, false);
        retval = LN_PAYMENT_ERROR_RETRY;
        goto LABEL_ERROR;
    }

    utl_buf_free(&secrets);
    return LN_PAYMENT_OK;

LABEL_ERROR:
    utl_buf_free(&secrets);
    return retval;
}


static ln_payment_error_t check_route(const ln_payment_route_t *pRoute)
{
    for (int lp = 0; lp < pRoute->num_hops - 2; lp++) {
        if (pRoute->hop_datain[lp].amt_to_forward < pRoute->hop_datain[lp + 1].amt_to_forward) {
            LOGE("[%d]amt_to_forward larger than previous (%" PRIu64 " < %" PRIu64 ")\n",
                lp, pRoute->hop_datain[lp].amt_to_forward, pRoute->hop_datain[lp + 1].amt_to_forward);
            return LN_PAYMENT_ERROR_ROUTE_INVALID;
        }
        if (pRoute->hop_datain[lp].outgoing_cltv_value <= pRoute->hop_datain[lp + 1].outgoing_cltv_value) {
            LOGE("[%d]outgoing_cltv_value larger than previous (%" PRIu32 " < %" PRIu32 ")\n",
                lp, pRoute->hop_datain[lp].outgoing_cltv_value, pRoute->hop_datain[lp + 1].outgoing_cltv_value);
            return LN_PAYMENT_ERROR_ROUTE_INVALID;
        }
    }
    return LN_PAYMENT_OK;
}
