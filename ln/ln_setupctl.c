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
//#include "ln_misc.h"
#include "ln_msg_setupctl.h"
/*#include "ln_node.h"
#include "ln_enc_auth.h"
#include "ln_onion.h"
#include "ln_script.h"
#include "ln_comtx.h"
#include "ln_derkey.h"
#include "ln_signer.h"
*/
#include "ln_local.h"
#include "ln_setupctl.h"


/**************************************************************************
 * static variables
 **************************************************************************/

/// init.localfeaturesデフォルト値
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


bool ln_init_create(ln_self_t *self, utl_buf_t *pInit, bool bInitRouteSync, bool bHaveCnl)
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
    bool ret = ln_msg_init_write(pInit, &msg);
    if (ret) {
        self->init_flag |= M_INIT_FLAG_SEND;
    }

    M_DB_SELF_SAVE(self);

    return ret;
}


bool HIDDEN ln_init_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    bool initial_routing_sync = false;

    if (self->init_flag & M_INIT_FLAG_RECV) {
        //TODO: 2回init受信した場合はエラーにする
        M_SEND_ERR(self, LNERR_MSG_INIT, "multiple init receive");
        return false;
    }

    ln_msg_init_t msg;
    ret = ln_msg_init_read(&msg, pData, Len);
    if (!ret) {
        LOGE("fail: read\n");
        goto LABEL_EXIT;
    }

    //2018/06/27(comit: f6312d9a702ede0f85e094d75fd95c5e3b245bcf)
    //      https://github.com/lightningnetwork/lightning-rfc/blob/f6312d9a702ede0f85e094d75fd95c5e3b245bcf/09-features.md#assigned-globalfeatures-flags
    //  globalfeatures not assigned
    for (uint32_t lp = 0; lp < msg.gflen; lp++) {
        if (msg.p_globalfeatures[lp] & 0x55) {
            //even bit: 未対応のため、エラーにする
            LOGE("fail: unknown bit(globalfeatures)\n");
            ret = false;
            goto LABEL_EXIT;
        } else {
            //odd bit: 未知でもスルー
        }
    }

    if (msg.lflen == 0) {
        self->lfeature_remote = 0x00;
    } else {
        //2018/06/27(comit: f6312d9a702ede0f85e094d75fd95c5e3b245bcf)
        //      https://github.com/lightningnetwork/lightning-rfc/blob/f6312d9a702ede0f85e094d75fd95c5e3b245bcf/09-features.md#assigned-localfeatures-flags
        //  bit0/1 : option_data_loss_protect
        //  bit3   : initial_routing_sync
        //  bit4/5 : option_upfront_shutdown_script
        //  bit6/7 : gossip_queries
        uint8_t flag = (msg.p_localfeatures[0] & (~LN_INIT_LF_OPT_DATALOSS_REQ));
        if (flag & 0x55) {
            //even bit: 未対応のため、エラーにする
            LOGE("fail: unknown bit(localfeatures)\n");
            ret = false;
            goto LABEL_EXIT;
        } else {
            //odd bit: 未知でもスルー
        }

        initial_routing_sync = (msg.p_localfeatures[0] & LN_INIT_LF_ROUTE_SYNC);

        if (msg.lflen > 1) {
            for (uint32_t lp = 1; lp < msg.lflen; lp++) {
                if (msg.p_localfeatures[lp] & 0x55) {
                    //even bit: 未対応のため、エラーにする
                    LOGE("fail: unknown bit(localfeatures)\n");
                    ret = false;
                    goto LABEL_EXIT;
                } else {
                    //odd bit: 未知でもスルー
                }
            }
        }
        self->lfeature_remote = msg.p_localfeatures[0];
    }

    self->init_flag |= M_INIT_FLAG_RECV;

    //init受信通知
    ln_callback(self, LN_CB_INIT_RECV, &initial_routing_sync);

LABEL_EXIT:
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_FEATURE, "init error");
    }

    return ret;
}


bool HIDDEN ln_error_send(ln_self_t *self, const ln_msg_error_t *pErrorMsg)
{
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_error_write(&buf, pErrorMsg);
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return false;
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


bool ln_ping_create(ln_self_t *self, utl_buf_t *pPing, uint16_t PingLen, uint16_t PongLen)
{
    (void)self;

    ln_msg_ping_t msg;

    msg.byteslen = PingLen;
    msg.num_pong_bytes = PongLen;
    msg.p_ignored = NULL;
    bool ret = ln_msg_ping_write(pPing, &msg);
    return ret;
}


bool HIDDEN ln_ping_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    bool ret;

    ln_msg_ping_t msg;
    ret = ln_msg_ping_read(&msg, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    ret = ln_pong_send(self, &msg);

    //LOGD("END\n");
    return ret;
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
