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
/** @file   ln_anno.c
 *  @brief  ln_anno
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
#include "ln.h"
#include "ln_msg_anno.h"
#include "ln_local.h"
#include "ln_setupctl.h"
#include "ln_anno.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_ANNO_FLAG_SEND                    (0x01)          ///< announcement_signatures送信済み
#define M_ANNO_FLAG_RECV                    (0x02)          ///< announcement_signatures受信済み
//#define LN_ANNO_FLAG_END

#define M_UPDCNL_TIMERANGE                  (uint32_t)(60 * 60)     //1hour


/**************************************************************************
 * prototypes
 **************************************************************************/

static void proc_announcement_signatures(ln_self_t *self);
static bool create_local_channel_announcement(ln_self_t *self);
static bool get_node_id_from_channel_announcement(ln_self_t *self, uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir);
static bool create_channel_update(ln_self_t *self, ln_msg_channel_update_t *pUpd, utl_buf_t *pCnlUpd, uint32_t TimeStamp, uint8_t Flag);


/**************************************************************************
 * public functions
 **************************************************************************/

bool /*HIDDEN*/ ln_announcement_signatures_send(ln_self_t *self)
{
    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;
    if (!self->cnl_anno.buf) {
        if (!create_local_channel_announcement(self)) return false;
    }
    ln_msg_channel_announcement_get_sigs(self->cnl_anno.buf, &p_sig_node, &p_sig_btc, true, ln_node_id_sort(self, NULL));

    ln_msg_announcement_signatures_t msg;
    msg.p_channel_id = self->channel_id;
    msg.short_channel_id = self->short_channel_id;
    msg.p_node_signature = p_sig_node;
    msg.p_bitcoin_signature = p_sig_btc;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_announcement_signatures_write(&buf, &msg)) {
        LOGE("fail: create shutdown\n");
        return false;
    }

    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    self->anno_flag |= M_ANNO_FLAG_SEND;
    proc_announcement_signatures(self);
    M_DB_SELF_SAVE(self);
    self->init_flag |= M_INIT_ANNOSIG_SENT;
    return true;
}


bool HIDDEN ln_announcement_signatures_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    if (!self->fund_flag) { //XXX: after `funding_locked`
        LOGE("fail: not open peer\n");
        return false;
    }

    if (!self->cnl_anno.buf) {
        create_local_channel_announcement(self);
    }

    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;
    btc_script_pubkey_order_t sort = ln_node_id_sort(self, NULL);
    ln_msg_channel_announcement_get_sigs(self->cnl_anno.buf, &p_sig_node, &p_sig_btc, false, sort);

    ln_msg_announcement_signatures_t msg;
    if (!ln_msg_announcement_signatures_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    if (!msg.short_channel_id) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(p_sig_node, msg.p_node_signature, LN_SZ_SIGNATURE);
    memcpy(p_sig_btc, msg.p_bitcoin_signature, LN_SZ_SIGNATURE);

    if (!ln_check_channel_id(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    if (self->short_channel_id) {
        if (msg.short_channel_id != self->short_channel_id) {
            LOGE("fail: short_channel_id mismatch: %016" PRIx64 " != %016" PRIx64 "\n", self->short_channel_id, msg.short_channel_id);
            M_SET_ERR(self, LNERR_MSG_READ, "read message"); //XXX:
            return false;
        }
    }

    if (!(self->anno_flag & LN_ANNO_FLAG_END)) {
        self->short_channel_id = msg.short_channel_id;
        if (!ln_msg_channel_announcement_update_short_channel_id(self->cnl_anno.buf, self->short_channel_id)) {
            LOGE("fail: update short_channel_id\n");
            return false;
        }
        if (!ln_msg_channel_announcement_sign(
            self->cnl_anno.buf, self->cnl_anno.len,
            self->privkeys_local.secrets[LN_BASEPOINT_IDX_FUNDING],
            sort)) {
            LOGE("fail: sign\n");
            return false;
        }
        self->anno_flag |= M_ANNO_FLAG_RECV;
        proc_announcement_signatures(self);
        M_DB_SELF_SAVE(self);
    } else if ((self->init_flag & M_INIT_ANNOSIG_SENT) == 0) {
        //BOLT07
        //  MUST respond to the first announcement_signatures message with its own announcement_signatures message.
        //  LN_ANNO_FLAG_ENDであっても再接続後の初回のみは送信する
        LOGD("respond announcement_signatures\n");
        /*ignore*/ ln_announcement_signatures_send(self);
        self->init_flag |= M_INIT_ANNOSIG_SENT;
    }

    return true;
}


//called by `ln_channel_announcement_recv` only
static bool channel_announcement_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    ln_msg_channel_announcement_t msg;
    if (!ln_msg_channel_announcement_read(&msg, pData, Len)) {
        LOGE("fail: do nothing\n");
        return false;
    }
    if (!msg.short_channel_id) {
        LOGE("fail: do nothing\n");
        return false;
    }
    if (memcmp(ln_genesishash_get(), msg.p_chain_hash, BTC_SZ_HASH256)) {
        LOGE("fail: chain_hash mismatch\n");
        return false;
    }

    //XXX: check sign
    //ln_msg_channel_announcement_verify

    utl_buf_t buf = UTL_BUF_INIT;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;
    if (!ln_db_annocnl_save(&buf, msg.short_channel_id, ln_their_node_id(self), msg.p_node_id_1, msg.p_node_id_2)) {
        LOGE("fail: save\n");
        return false;
    }
    LOGD("save channel_announcement: %016" PRIx64 "\n", msg.short_channel_id);

    ln_cb_update_annodb_t db;
    db.anno = LN_CB_UPDATE_ANNODB_CNL_ANNO;
    ln_callback(self, LN_CB_UPDATE_ANNODB, &db);
    return true;
}


bool HIDDEN ln_channel_announcement_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //always return ture
    //don't close the channel

    /*ignore*/channel_announcement_recv(self, pData, Len);
    return true;
}


//called by `ln_node_announcement_recv` only
static bool node_announcement_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    ln_msg_node_announcement_t msg;
    if (!ln_msg_node_announcement_read(&msg, pData, Len)) {
        LOGE("fail: read message\n");
        return false;
    }
    if (!ln_msg_node_announcement_verify(&msg, pData, Len)) {
        LOGE("fail: verify\n");
        return false;
    }

    LOGV("node_id:");
    DUMPV(msg.p_node_id, BTC_SZ_PUBKEY);

    utl_buf_t buf = UTL_BUF_INIT;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;
    if (!ln_db_annonod_save(&buf, &msg, ln_their_node_id(self))) {
        LOGE("fail: save\n");
        return false;
    }
    LOGD("save node_announcement: ");
    DUMPD(msg.p_node_id, BTC_SZ_PUBKEY);

    ln_cb_update_annodb_t db;
    db.anno = LN_CB_UPDATE_ANNODB_NODE_ANNO;
    ln_callback(self, LN_CB_UPDATE_ANNODB, &db);
    return true;
}


bool HIDDEN ln_node_announcement_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //always return ture
    //don't close the channel

    /*ignore*/node_announcement_recv(self, pData, Len);
    return true;
}


bool /*HIDDEN*/ ln_channel_update_send(ln_self_t *self)
{
    ln_msg_channel_update_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!create_channel_update(self, &msg, &buf, (uint32_t)utl_time_time(), 0)) {
        LOGE("fail: create channel_update\n");
        return false;
    }

    if (!ln_db_annocnlupd_save(&buf, &msg, NULL)) {
        LOGE("fail: save channel_update\n");
        return false;
    }

    if (self->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) {
        //we have exchanged our announcement signatures
        //save for broadcasting
        ln_cb_update_annodb_t db;
        db.anno = LN_CB_UPDATE_ANNODB_CNL_UPD;
        ln_callback(self, LN_CB_UPDATE_ANNODB, &db);
    }

    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


//called by `ln_channel_update_recv` only
static bool channel_update_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    (void)self;

    ln_msg_channel_update_t msg;
    uint64_t now = (uint64_t)utl_time_time();

    if (!ln_msg_channel_update_read(&msg, pData, Len)) {
        LOGE("fail: decode\n");
        return false;
    }

    //timestamp check
    if (ln_db_annocnlupd_is_prune(now, msg.timestamp)) {
        char time[UTL_SZ_TIME_FMT_STR + 1];
        LOGD("older channel: not save(%016" PRIx64 "): %s\n", msg.short_channel_id, utl_time_fmt(time, msg.timestamp));
        return false;
    }

    if (memcmp(ln_genesishash_get(), msg.p_chain_hash, BTC_SZ_HASH256)) {
        LOGE("fail: chain_hash mismatch\n");
        return false;
    }

    LOGV("recv channel_upd%d: %016" PRIx64 "\n", (int)(1 + (msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION)), msg.short_channel_id);

    uint8_t node_id[BTC_SZ_PUBKEY];
    if (get_node_id_from_channel_announcement(self, node_id, msg.short_channel_id, msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION)) {
        //found
        if (!btc_keys_check_pub(node_id)) {
            LOGE("fail: invalid pubkey\n");
            return false;
        }
        if (!ln_msg_channel_update_verify(node_id, pData, Len)) {
            LOGE("fail: verify\n");
            return false;
        }
    } else {
        //not found
        //  BOLT#11
        //      r fieldでchannel_update相当のデータを送信したい場合に備えて保持する
        //      https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001220.html
        LOGD("through: not found channel_announcement in DB, but save\n");
    }

    //BOLT07
    //  if the timestamp is unreasonably far in the future:
    //    MAY discard the channel_update.
    if (msg.timestamp > now + M_UPDCNL_TIMERANGE) {
        LOGD("through: timestamp is unreasonably far\n");
        return false;
    }

    utl_buf_t buf = UTL_BUF_INIT;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;
    if (!ln_db_annocnlupd_save(&buf, &msg, ln_their_node_id(self))) {
        LOGE("fail: save\n");
        return false;
    }
    LOGD("save channel_update: %016" PRIx64 ":%d\n", msg.short_channel_id, msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION);

    ln_cb_update_annodb_t db;
    db.anno = LN_CB_UPDATE_ANNODB_CNL_UPD;
    ln_callback(self, LN_CB_UPDATE_ANNODB, &db);
    return true;
}


bool HIDDEN ln_channel_update_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //always return ture
    //don't close the channel

    /*ignore*/channel_update_recv(self, pData, Len);
    return true;
}


bool ln_channel_update_disable(ln_self_t *self)
{
    ln_msg_channel_update_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!create_channel_update(self, &msg, &buf, (uint32_t)utl_time_time(), LN_CNLUPD_CHFLAGS_DISABLE)) return false;
    ln_db_annocnlupd_save(&buf, &msg, ln_their_node_id(self));
    utl_buf_free(&buf);
    return true;
}


/********************************************************************
 * private functions
 ********************************************************************/

static void proc_announcement_signatures(ln_self_t *self)
{
    if ( (self->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) && self->short_channel_id ) {
        //announcement_signatures have been exchanged
        LOGD("announcement_signatures sent and recv: %016" PRIx64 "\n", self->short_channel_id);

        //channel_announcement
        if (ln_db_annocnl_save(
            &self->cnl_anno, self->short_channel_id, NULL, ln_their_node_id(self), ln_node_getid())) {
            utl_buf_free(&self->cnl_anno);
        } else {
            LOGE("fail\n");
        }

        //channel_update
        ln_msg_channel_update_t msg;
        utl_buf_t buf = UTL_BUF_INIT;
        if (create_channel_update(self, &msg, &buf, (uint32_t)utl_time_time(), 0)) {
            ln_db_annocnlupd_save(&buf, &msg, NULL);
        } else {
            LOGE("fail\n");
        }
        utl_buf_free(&buf);

        self->anno_flag |= LN_ANNO_FLAG_END;
    } else {
        LOGD("yet: anno_flag=%02x, short_channel_id=%016" PRIx64 "\n", self->anno_flag, self->short_channel_id);
    }
}


static bool create_local_channel_announcement(ln_self_t *self)
{
    LOGD("short_channel_id=%016" PRIx64 "\n", self->short_channel_id);
    utl_buf_free(&self->cnl_anno);

    uint8_t dummy_signature[LN_SZ_SIGNATURE] = {0};
    memset(dummy_signature, 0xcc, sizeof(dummy_signature));
    ln_msg_channel_announcement_t msg;
    msg.p_node_signature_1 = dummy_signature;
    msg.p_node_signature_2 = dummy_signature;
    msg.p_bitcoin_signature_1 = dummy_signature;
    msg.p_bitcoin_signature_2 = dummy_signature;
    msg.len = 0;
    msg.p_features = NULL;
    msg.p_chain_hash = ln_genesishash_get();
    msg.short_channel_id = self->short_channel_id;
    btc_script_pubkey_order_t sort = ln_node_id_sort(self, NULL);
    if (sort == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
        msg.p_node_id_1 = ln_node_getid();
        msg.p_node_id_2 = self->peer_node_id;
        msg.p_bitcoin_key_1 = self->pubkeys_local.basepoints[LN_BASEPOINT_IDX_FUNDING];
        msg.p_bitcoin_key_2 = self->pubkeys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING];
    } else {
        msg.p_node_id_1 = self->peer_node_id;
        msg.p_node_id_2 = ln_node_getid();
        msg.p_bitcoin_key_1 = self->pubkeys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING];
        msg.p_bitcoin_key_2 = self->pubkeys_local.basepoints[LN_BASEPOINT_IDX_FUNDING];
    }
    if (!ln_msg_channel_announcement_write(&self->cnl_anno, &msg)) return false;
    return ln_msg_channel_announcement_sign(
        self->cnl_anno.buf, self->cnl_anno.len,
        self->privkeys_local.secrets[LN_BASEPOINT_IDX_FUNDING],
        sort);
}


static bool get_node_id_from_channel_announcement(ln_self_t *self, uint8_t *pNodeId, uint64_t ShortChannelId, uint8_t Dir)
{
    bool ret = false;

    pNodeId[0] = 0x00;

    utl_buf_t buf = UTL_BUF_INIT;
    if (ln_db_annocnl_load(&buf, ShortChannelId)) {
        ln_msg_channel_announcement_t msg;
        if (!ln_msg_channel_announcement_read(&msg, buf.buf, buf.len)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        memcpy(pNodeId, Dir ? msg.p_node_id_2 : msg.p_node_id_1, BTC_SZ_PUBKEY);
    } else {
        if (ShortChannelId != self->short_channel_id) goto LABEL_EXIT;
        btc_script_pubkey_order_t order = ln_node_id_sort(self, NULL);
        if ( ((order == BTC_SCRYPT_PUBKEY_ORDER_ASC) && (Dir == 0)) ||
             ((order == BTC_SCRYPT_PUBKEY_ORDER_OTHER) && (Dir == 1)) ) {
            LOGD("this channel: my node\n");
            memcpy(pNodeId, ln_node_getid(), BTC_SZ_PUBKEY);
        } else {
            LOGD("this channel: peer node\n");
            memcpy(pNodeId, self->peer_node_id, BTC_SZ_PUBKEY);
        }
    }

    ret = true;

LABEL_EXIT:
    utl_buf_free(&buf);
    return ret;
}


/** channel_update作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pUpd            生成したchannel_update構造体
 * @param[out]          pCnlUpd         生成したchannel_updateメッセージ
 * @param[in]           TimeStamp       作成時刻とするEPOCH time
 * @param[in]           Flag            flagsにORする値
 * @retval      ture    成功
 */
static bool create_channel_update(
    ln_self_t *self, ln_msg_channel_update_t *pUpd, utl_buf_t *pCnlUpd, uint32_t TimeStamp, uint8_t Flag)
{
    uint8_t dummy_signature[LN_SZ_SIGNATURE] = {0};
    memset(dummy_signature, 0xcc, sizeof(dummy_signature));
    pUpd->p_signature = dummy_signature;
    pUpd->p_chain_hash = ln_genesishash_get();
    pUpd->short_channel_id = self->short_channel_id;
    pUpd->timestamp = TimeStamp;
    pUpd->message_flags = 0;
    pUpd->channel_flags = Flag | ln_sort_to_dir(ln_node_id_sort(self, NULL));
    pUpd->cltv_expiry_delta = self->anno_prm.cltv_expiry_delta;
    pUpd->htlc_minimum_msat = self->anno_prm.htlc_minimum_msat;
    pUpd->fee_base_msat = self->anno_prm.fee_base_msat;
    pUpd->fee_proportional_millionths = self->anno_prm.fee_prop_millionths;
    pUpd->htlc_maximum_msat = 0;
    if (!ln_msg_channel_update_write(pCnlUpd, pUpd)) return false;
    return ln_msg_channel_update_sign(pCnlUpd->buf, pCnlUpd->len);
}
