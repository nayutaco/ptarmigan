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


void HIDDEN ln_error_set(ln_self_t *self, int Err, const char *pFormat, ...)
{
    va_list ap;

    self->err = Err;

    va_start(ap, pFormat);
    vsnprintf(self->err_msg, LN_SZ_ERRMSG, pFormat, ap);
    va_end(ap);
}


bool /*HIDDEN*/ ln_init_send(ln_self_t *self, bool bInitRouteSync, bool bHaveCnl)
{
    (void)bHaveCnl;

    if (self->init_flag & M_INIT_FLAG_SEND) {
        M_SEND_ERR(self, LNERR_INV_STATE, "init already sent");
        return false;
    }

    ln_msg_init_t msg;
    msg.gflen = 0;
    msg.p_globalfeatures = NULL;
    self->lfeature_local = mInitLocalFeatures[0] | (bInitRouteSync ? LN_INIT_LF_ROUTE_SYNC : 0);
    msg.lflen = sizeof(self->lfeature_local);
    msg.p_localfeatures = &self->lfeature_local;
    LOGD("localfeatures: ");
    DUMPD(msg.p_localfeatures, msg.lflen);
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_init_write(&buf, &msg)) {
        return false;
    }
    self->init_flag |= M_INIT_FLAG_SEND;

    M_DB_SELF_SAVE(self);

    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_init_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret = false;
    bool initial_routing_sync = false;

    if (self->init_flag & M_INIT_FLAG_RECV) {
        //TODO: multiple init error
        M_SEND_ERR(self, LNERR_MSG_INIT, "multiple init receive");
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

    self->lfeature_remote = 0x00;
    if (msg.lflen) {
        //check
        for (uint32_t lp = 0; lp < msg.lflen; lp++) {
            if (lp == 0) {
                //2018/06/27(comit: f6312d9a702ede0f85e094d75fd95c5e3b245bcf)
                //      https://github.com/lightningnetwork/lightning-rfc/blob/f6312d9a702ede0f85e094d75fd95c5e3b245bcf/09-features.md#assigned-localfeatures-flags
                //  bit0/1 : option_data_loss_protect
                //  bit3   : initial_routing_sync
                //  bit4/5 : option_upfront_shutdown_script
                //  bit6/7 : gossip_queries
                uint8_t flag = (msg.p_localfeatures[lp] & (~LN_INIT_LF_OPT_DATALOSS_REQ));
                if (flag & 0x55) { //even bits
                    LOGE("fail: unknown bit(localfeatures)\n");
                    goto LABEL_EXIT;
                }
                initial_routing_sync = (msg.p_localfeatures[lp] & LN_INIT_LF_ROUTE_SYNC);
            } else if (msg.p_localfeatures[lp] & 0x55) { //even bits
                LOGE("fail: unknown bit(localfeatures)\n");
                goto LABEL_EXIT;
            }
        }
        self->lfeature_remote = msg.p_localfeatures[0];
    }

    self->init_flag |= M_INIT_FLAG_RECV;

    ln_callback(self, LN_CB_INIT_RECV, &initial_routing_sync);

    ret = true;

LABEL_EXIT:
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_FEATURE, "init error");
    }
    return ret;
}


bool HIDDEN ln_error_send(ln_self_t *self, int Err, const char *pFormat, ...)
{
    ln_error_set(self, Err, pFormat);
    ln_msg_error_t msg;
    msg.p_channel_id = self->channel_id;
    msg.p_data = (const uint8_t *)self->err_msg;
    msg.len = strlen(self->err_msg);
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_error_write(&buf, &msg);
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_error_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    if (ln_is_funding(self)) {
        LOGD("stop funding\n");
        ln_establish_free(self);
    }

    ln_msg_error_t msg;
    ln_msg_error_read(&msg, pData, Len);
    ln_callback(self, LN_CB_ERROR, &msg);
    return true;
}


bool /*HIDDEN*/ ln_ping_send(ln_self_t *self, uint16_t PingLen, uint16_t PongLen)
{
    (void)self;

    ln_msg_ping_t msg;
    msg.byteslen = PingLen;
    msg.num_pong_bytes = PongLen;
    msg.p_ignored = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_ping_write(&buf, &msg)) return false;
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_ping_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    ln_msg_ping_t msg;
    if (!ln_msg_ping_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    if (!ln_pong_send(self, &msg)) return false;

    //LOGD("END\n");
    return true;
}


bool HIDDEN ln_pong_send(ln_self_t *self, ln_msg_ping_t *pPingMsg)
{
    bool ret = false;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_pong_t msg;

    msg.byteslen = pPingMsg->num_pong_bytes;
    msg.p_ignored = NULL;
    if (!ln_msg_pong_write(&buf, &msg)) goto LABEL_EXIT;
    ln_callback(self, LN_CB_SEND_REQ, &buf);

    ret = true;

LABEL_EXIT:
    utl_buf_free(&buf);
    return ret;
}


bool HIDDEN ln_pong_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    ln_msg_pong_t msg;
    if (!ln_msg_pong_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    ln_cb_pong_recv_t pongrecv;
    pongrecv.result = false;
    pongrecv.byteslen = msg.byteslen;
    pongrecv.p_ignored = msg.p_ignored;
    ln_callback(self, LN_CB_PONG_RECV, &pongrecv);

    //LOGD("END\n");
    return pongrecv.result;
}


/********************************************************************
 * private functions
 ********************************************************************/
