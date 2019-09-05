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
/** @file   ln_tlv.c
 *  @brief  TLV
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utl_common.h"
#include "utl_dbg.h"
#include "utl_int.h"
#define LOG_TAG "ln_tlv"
#include "utl_log.h"

#include "btc_tx_buf.h"
#include "ln_tlv.h"


/********************************************************************
 * prototypes
 ********************************************************************/

static bool read_tlv(ln_tlv_t *pTlv, btc_buf_r_t *pBuf);


/********************************************************************
 * public functions
 ********************************************************************/

bool ln_tlv_read(ln_tlv_record_t **ppTlvRec, const uint8_t *pData, uint32_t Len)
{
    bool ret;
    uint16_t num = 0;
    btc_buf_r_t buf_r;
    ln_tlv_t tlv;

    *ppTlvRec = NULL;

    btc_buf_r_init(&buf_r, pData, Len);

    while (btc_tx_buf_r_remains(&buf_r) > 0) {
        ret = read_tlv(&tlv, &buf_r);
        if (ret) {
            num++;
            *ppTlvRec = (ln_tlv_record_t *)UTL_DBG_REALLOC(*ppTlvRec,
                            sizeof(ln_tlv_record_t) + sizeof(ln_tlv_t) * num);
            memcpy(&(*ppTlvRec)->tlvs[num - 1], &tlv, sizeof(tlv));
            (*ppTlvRec)->num = num;
        } else {
            LOGE("fail: tlv %d\n", num);
            for (uint16_t lp = 0; lp < num; lp++) {
                utl_buf_free(&((*ppTlvRec)->tlvs[lp].value));
            }
            UTL_DBG_FREE(*ppTlvRec);
            *ppTlvRec = NULL;
            break;
        }
    }

    return ret;
}


bool ln_tlv_write(utl_buf_t *pBuf, const ln_tlv_record_t *pTlvRec)
{
    (void)pBuf; (void)pTlvRec;
    return false;
}


void ln_tlv_free(ln_tlv_record_t *pTlvRec)
{
    for (uint16_t lp = 0; lp < pTlvRec->num; lp++) {
        utl_buf_free(&((pTlvRec)->tlvs[lp].value));
    }
    UTL_DBG_FREE(pTlvRec);
}


/********************************************************************
 * private functions
 ********************************************************************/

static bool read_tlv(ln_tlv_t *pTlv, btc_buf_r_t *pBuf)
{
    bool ret;
    uint64_t length;

    //type
    ret = btc_tx_buf_r_read_varint_be(pBuf, &pTlv->type);
    if (!ret) {
        LOGE("fail: type\n");
        return false;
    }
LOGD("type=%d\n", pTlv->type);
    //length
    ret = btc_tx_buf_r_read_varint_be(pBuf, &length);
    if (!ret) {
        LOGE("fail: length\n");
        return false;
    }
LOGD("length=%d\n", length);
    //value
    utl_buf_alloccopy(&pTlv->value,
            btc_buf_r_get_pos(pBuf), length);
    ret = btc_tx_buf_r_seek(pBuf, length);

    return ret;
}
