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
/** @file   ln_setupctl.c
 *  @brief  ln_setupctl
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
#include "ln.h"
#include "ln_msg_setupctl.h"
#include "ln_local.h"
#include "ln_setupctl.h"


/**************************************************************************
 * static variables
 **************************************************************************/

/// init.localfeatures defalt value
static uint8_t mInitLocalFeatures[1];


/**************************************************************************
 * prototypes
 **************************************************************************/

/**************************************************************************
 * public functions
 **************************************************************************/

void ln_init_localfeatures_set(uint8_t lf)
{
    LOGD("localfeatures=0x%02x\n", lf);
    mInitLocalFeatures[0] = lf;
}


void HIDDEN ln_error_set(ln_channel_t *pChannel, int Err, const char *pFormat, ...)
{
    va_list ap;

    pChannel->err = Err;

    va_start(ap, pFormat);
    vsnprintf(pChannel->err_msg, LN_SZ_ERRMSG, pFormat, ap);
    va_end(ap);
}


bool /*HIDDEN*/ ln_init_send(ln_channel_t *pChannel, bool bInitRouteSync, bool bHaveCnl)
{
    (void)bHaveCnl;

    if (pChannel->init_flag & M_INIT_FLAG_SEND) {
        M_SEND_ERR(pChannel, LNERR_INV_STATE, "init already sent");
        return false;
    }

    ln_msg_init_t msg;
    msg.gflen = 0;
    msg.p_globalfeatures = NULL;
    pChannel->lfeature_local = mInitLocalFeatures[0] | (bInitRouteSync ? LN_INIT_LF_ROUTE_SYNC : 0);
#ifdef USE_GQUERY
    pChannel->lfeature_local |= LN_INIT_LF_OPT_GSP_QUERY;
#endif  //USE_GQUERY
    msg.lflen = sizeof(pChannel->lfeature_local);
    msg.p_localfeatures = &pChannel->lfeature_local;
    LOGD("localfeatures: ");
    DUMPD(msg.p_localfeatures, msg.lflen);
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_init_write(&buf, &msg)) {
        return false;
    }
    pChannel->init_flag |= M_INIT_FLAG_SEND;

    M_DB_CHANNEL_SAVE(pChannel);

    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_init_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    bool ret = false;

    if (pChannel->init_flag & M_INIT_FLAG_RECV) {
        //TODO: multiple init error
        M_SEND_ERR(pChannel, LNERR_MSG_INIT, "multiple init receive");
        return false;
    }

    ln_msg_init_t msg;
    if (!ln_msg_init_read(&msg, pData, Len)) {
        LOGE("fail: read\n");
        goto LABEL_EXIT;
    }

    //globalfeatures not assigned
    for (uint32_t lp = 0; lp < msg.gflen; lp++) {
        if (msg.p_globalfeatures[lp] & 0x55) { //even bits
            LOGE("fail: unknown bit(globalfeatures)\n");
            goto LABEL_EXIT;
        }
    }

    pChannel->lfeature_remote = 0x00;
    if (msg.lflen) {
        //2018/06/27(comit: f6312d9a702ede0f85e094d75fd95c5e3b245bcf)
        //      https://github.com/lightningnetwork/lightning-rfc/blob/f6312d9a702ede0f85e094d75fd95c5e3b245bcf/09-features.md#assigned-localfeatures-flags
        //  bit0 : option_data_loss_protect
        //  bit2 : (none)
        //  bit4 : option_upfront_shutdown_script
        //  bit6 : gossip_queries
        if (msg.p_localfeatures[0] & (LN_INIT_LF_OPT_UPF_SHDN_REQ | LN_INIT_LF_OPT_GSP_QUERY_REQ)) { //even bits
            LOGE("fail: unknown bit(localfeatures)\n");
            goto LABEL_EXIT;
        }

        for (uint32_t lp = 1; lp < msg.lflen; lp++) {
            if (msg.p_localfeatures[lp] & 0x55) { //even bits
                LOGE("fail: unknown bit(localfeatures)\n");
                goto LABEL_EXIT;
            }
        }
        pChannel->lfeature_remote = msg.p_localfeatures[0];
    }

    //gossip_queries
    if ( (pChannel->lfeature_local & LN_INIT_LF_OPT_GSP_QUERIES) &&
         (pChannel->lfeature_remote & LN_INIT_LF_OPT_GSP_QUERIES) ) {
        //gossip_queries negotiate
        pChannel->init_flag |= M_INIT_GOSSIP_QUERY;
    }

    pChannel->init_flag |= M_INIT_FLAG_RECV;

    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_INIT_RECV, NULL);

    ret = true;

LABEL_EXIT:
    if (!ret) {
        M_SET_ERR(pChannel, LNERR_INV_FEATURE, "init error");
    }
    return ret;
}


bool HIDDEN ln_error_send(ln_channel_t *pChannel, int Err, const char *pFormat, ...)
{
    ln_error_set(pChannel, Err, pFormat);
    ln_msg_error_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.p_data = (const uint8_t *)pChannel->err_msg;
    msg.len = strlen(pChannel->err_msg);
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_error_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_error_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    if (ln_funding_info_funding_now(&pChannel->funding_info)) {
        LOGD("stop funding\n");
        ln_establish_free(pChannel);
    }

    ln_msg_error_t msg;
    ln_msg_error_read(&msg, pData, Len);
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_ERROR, &msg);
    return true;
}


bool /*HIDDEN*/ ln_ping_send(ln_channel_t *pChannel, uint16_t PingLen, uint16_t PongLen)
{
    (void)pChannel;

    ln_msg_ping_t msg;
    msg.byteslen = PingLen;
    msg.num_pong_bytes = PongLen;
    msg.p_ignored = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_ping_write(&buf, &msg)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_ping_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    ln_msg_ping_t msg;
    if (!ln_msg_ping_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }

    if (!ln_pong_send(pChannel, &msg)) return false;

    //LOGD("END\n");
    return true;
}


bool HIDDEN ln_pong_send(ln_channel_t *pChannel, ln_msg_ping_t *pPingMsg)
{
    ln_msg_pong_t msg;
    msg.byteslen = pPingMsg->num_pong_bytes;
    msg.p_ignored = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_pong_write(&buf, &msg)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_pong_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    ln_msg_pong_t msg;
    if (!ln_msg_pong_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    ln_cb_param_notify_pong_recv_t param;
    param.ret = false;
    param.byteslen = msg.byteslen;
    param.p_ignored = msg.p_ignored;
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_PONG_RECV, &param);

    //LOGD("END\n");
    return param.ret;
}


/********************************************************************
 * private functions
 ********************************************************************/
