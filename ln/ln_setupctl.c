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

/// init.localfeatures default value
static uint16_t mInitLocalFeatures;


/**************************************************************************
 * prototypes
 **************************************************************************/

/**************************************************************************
 * public functions
 **************************************************************************/

void ln_init_localfeatures_set(uint16_t lf)
{
    LOGD("localfeatures=0x%04x\n", lf);
    mInitLocalFeatures = lf;
}


void /*HIDDEN*/ ln_error_set(ln_channel_t *pChannel, int Err, const char *pFormat, ...)
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
    pChannel->lfeature_local = mInitLocalFeatures | (bInitRouteSync ? LN_INIT_LF_ROUTE_SYNC : 0);
    msg.lflen = sizeof(pChannel->lfeature_local);
    uint8_t lfeature[sizeof(uint16_t)];
    utl_int_unpack_u16be(lfeature, pChannel->lfeature_local);

    //shorten
    const uint8_t *p_lfeature = lfeature;
    for (size_t lp = 0; lp < sizeof(lfeature); lp++) {
        if (*p_lfeature == 0) {
            p_lfeature++;
            msg.lflen--;
        }
    }
    msg.p_localfeatures = p_lfeature;

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
    uint16_t feature = 0;

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
    if ( (msg.gflen > 2) ||
         ((msg.gflen == 2) && ((msg.p_globalfeatures[0] & 0xc0) != 0)) ) {
        // BOLT1:
        //  - SHOULD NOT set features greater than 13 in globalfeatures.
        LOGE("fail: globalfeature greater than 13.\n");
        goto LABEL_EXIT;
    }
    for (uint32_t lp = 0; lp < msg.gflen; lp++) {
        if (msg.p_globalfeatures[lp] & 0x55) { //even bits
            LOGE("fail: unknown bit(globalfeatures)\n");
            goto LABEL_EXIT;
        }
    }

    //2019/11/27(commit: 8e69306e0a93375a1bbb1a0099f7ce3025ae4c0f)
    //      https://github.com/lightningnetwork/lightning-rfc/commit/8e69306e0a93375a1bbb1a0099f7ce3025ae4c0f
    //  bit 1/ 0 : option_data_loss_protect
    //  bit 3/ - : initial_routing_sync
    //  bit 5/ 4 : option_upfront_shutdown_script
    //  bit 7/ 6 : gossip_queries
    //  bit 9/ 8 : var_onion_optin
    //  bit11/10 : gossip_queries_ex
    //  bit13/12 : option_static_remotekey
    if (msg.lflen > 0) {
        feature = msg.p_localfeatures[msg.lflen - 1];
    }
    if (msg.lflen > 1) {
        feature |= msg.p_localfeatures[msg.lflen - 2] << 8;
    }
    if (msg.lflen > 2) {
        for (int lp = 0; lp < msg.lflen - 2; lp++) {
            if (msg.p_localfeatures[msg.lflen - lp] && 0x55) {
                LOGE("fail: Ptarmigan not support\n");
                goto LABEL_EXIT;
            }
        }
    }

    //require feature
    if (feature & LN_INIT_LF_ROUTE_SYNC_REQ) {
        LOGE("fail: invalid feature bit 2\n");
        goto LABEL_EXIT;
    }
    if (feature & LN_INIT_LF_OPT_UPF_SHDN_REQ) {
        LOGE("fail: Ptarmigan not support: option_upfront_shutdown_script\n");
        goto LABEL_EXIT;
    }
    if (feature & LN_INIT_LF_OPT_GSP_QUERY_REQ) {
#ifdef USE_GOSSIP_QUERY
        LOGD("support: gossip_queries\n");
#else
        LOGE("fail: Ptarmigan not support: gossip_queries\n");
        goto LABEL_EXIT;
#endif
    }
    if (feature & LN_INIT_LF_OPT_VAR_ONION_REQ) {
        LOGE("fail: Ptarmigan not support: var_onion_optin\n");
        goto LABEL_EXIT;
    }
    if (feature & LN_INIT_LF_OPT_GQUERY_EX_REQ) {
        LOGE("fail: Ptarmigan not support: gossip_queries_ex\n");
        goto LABEL_EXIT;
    }
    if (feature & LN_INIT_LF_OPT_STATIC_RKEY_REQ) {
        LOGE("fail: Ptarmigan not support: option_static_remotekey\n");
        goto LABEL_EXIT;
    }
    if (feature & LN_INIT_LF_OPT_15_14_REQ) {
        LOGE("fail: invalid feature bit 15/14\n");
        goto LABEL_EXIT;
    }
    pChannel->lfeature_remote = feature;

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


bool /*HIDDEN*/ ln_error_send(ln_channel_t *pChannel)
{
    ln_msg_error_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.p_data = (const uint8_t *)pChannel->err_msg;
    msg.len = strlen(pChannel->err_msg);
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_error_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    ln_callback(pChannel, LN_CB_TYPE_SEND_ERROR, &msg);
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
