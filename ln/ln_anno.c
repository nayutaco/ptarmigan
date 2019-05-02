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

#define M_UPDCNL_TIMERANGE                  ((uint32_t)(60 * 60))   //1hour

#define M_SEND_ENCODED_IDS                  (50)


/**************************************************************************
 * prototypes
 **************************************************************************/

static void proc_announcement_signatures(ln_channel_t *pChannel);
static bool create_local_channel_announcement(ln_channel_t *pChannel);
static bool get_node_id_from_channel_announcement(ln_channel_t *pChannel, uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir);
static bool create_channel_update(ln_channel_t *pChannel, ln_msg_channel_update_t *pUpd, utl_buf_t *pCnlUpd, uint32_t TimeStamp, uint8_t Flag);


/**************************************************************************
 * public functions
 **************************************************************************/

bool /*HIDDEN*/ ln_announcement_signatures_send(ln_channel_t *pChannel)
{
    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;
    if (!pChannel->cnl_anno.buf) {
        if (!create_local_channel_announcement(pChannel)) return false;
    }
    ln_msg_channel_announcement_get_sigs(pChannel->cnl_anno.buf, &p_sig_node, &p_sig_btc, true, ln_node_id_order(pChannel, NULL));

    ln_msg_announcement_signatures_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.short_channel_id = pChannel->short_channel_id;
    msg.p_node_signature = p_sig_node;
    msg.p_bitcoin_signature = p_sig_btc;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_announcement_signatures_write(&buf, &msg)) {
        LOGE("fail: create shutdown\n");
        return false;
    }

    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    pChannel->anno_flag |= M_ANNO_FLAG_SEND;
    proc_announcement_signatures(pChannel);
    M_DB_CHANNEL_SAVE(pChannel);
    pChannel->init_flag |= M_INIT_ANNOSIG_SENT;
    return true;
}


bool HIDDEN ln_announcement_signatures_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    if (!pChannel->funding_info.state) { //XXX: not after `funding_locked`
        LOGE("fail: not open peer\n");
        return false;
    }

    if (!pChannel->cnl_anno.buf) {
        create_local_channel_announcement(pChannel);
    }

    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;
    btc_script_pubkey_order_t order = ln_node_id_order(pChannel, NULL);
    ln_msg_channel_announcement_get_sigs(pChannel->cnl_anno.buf, &p_sig_node, &p_sig_btc, false, order);

    ln_msg_announcement_signatures_t msg;
    if (!ln_msg_announcement_signatures_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    if (!msg.short_channel_id) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(p_sig_node, msg.p_node_signature, LN_SZ_SIGNATURE);
    memcpy(p_sig_btc, msg.p_bitcoin_signature, LN_SZ_SIGNATURE);

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    if (pChannel->short_channel_id) {
        if (msg.short_channel_id != pChannel->short_channel_id) {
            LOGE("fail: short_channel_id mismatch: %016" PRIx64 " != %016" PRIx64 "\n", pChannel->short_channel_id, msg.short_channel_id);
            M_SET_ERR(pChannel, LNERR_MSG_READ, "read message"); //XXX:
            return false;
        }
    }

    if (!(pChannel->anno_flag & LN_ANNO_FLAG_END)) {
        pChannel->short_channel_id = msg.short_channel_id;
        if (!ln_msg_channel_announcement_update_short_channel_id(pChannel->cnl_anno.buf, pChannel->short_channel_id)) {
            LOGE("fail: update short_channel_id\n");
            return false;
        }
        if (!ln_msg_channel_announcement_sign(
            pChannel->cnl_anno.buf, pChannel->cnl_anno.len,
            pChannel->keys_local.secrets[LN_BASEPOINT_IDX_FUNDING],
            order)) {
            LOGE("fail: sign\n");
            return false;
        }
        pChannel->anno_flag |= M_ANNO_FLAG_RECV;
        proc_announcement_signatures(pChannel);
        M_DB_CHANNEL_SAVE(pChannel);
    } else if ((pChannel->init_flag & M_INIT_ANNOSIG_SENT) == 0) {
        //BOLT07
        //  MUST respond to the first announcement_signatures message with its own announcement_signatures message.
        //  LN_ANNO_FLAG_ENDであっても再接続後の初回のみは送信する
        LOGD("respond announcement_signatures\n");
        /*ignore*/ ln_announcement_signatures_send(pChannel);
        pChannel->init_flag |= M_INIT_ANNOSIG_SENT;
    }

    return true;
}


//called by `ln_channel_announcement_recv` only
static bool channel_announcement_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
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
        LOGD("through: chain_hash mismatch\n");
        return true;
    }

    //XXX: check sign
    //ln_msg_channel_announcement_verify

    utl_buf_t buf = UTL_BUF_INIT;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;
    if (!ln_db_cnlanno_save(&buf, msg.short_channel_id, ln_remote_node_id(pChannel), msg.p_node_id_1, msg.p_node_id_2)) {
        LOGE("fail: save\n");
        return false;
    }
    //LOGD("save channel_announcement: %016" PRIx64 "\n", msg.short_channel_id);

    ln_cb_param_notify_annodb_update_t db;
    db.type = LN_CB_ANNO_TYPE_CNL_ANNO;
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_ANNODB_UPDATE, &db);
    return true;
}


bool HIDDEN ln_channel_announcement_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    //always return ture
    //don't close the channel

    /*ignore*/channel_announcement_recv(pChannel, pData, Len);
    return true;
}


//called by `ln_node_announcement_recv` only
static bool node_announcement_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    ln_msg_node_announcement_t msg;
    if (!ln_msg_node_announcement_read(&msg, pData, Len)) {
        LOGE("fail: read message\n");
        return false;
    }
#if 0
    if (!ln_msg_node_announcement_verify(&msg, pData, Len)) {
        LOGE("fail: verify\n");
        return false;
    }
#endif

    //LOGV("node_id:");
    //DUMPV(msg.p_node_id, BTC_SZ_PUBKEY);

    utl_buf_t buf = UTL_BUF_INIT;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;
    if (!ln_db_nodeanno_save(&buf, &msg, ln_remote_node_id(pChannel))) {
        LOGE("fail: save\n");
        return false;
    }
    //LOGD("save node_announcement: ");
    //DUMPD(msg.p_node_id, BTC_SZ_PUBKEY);

    ln_cb_param_notify_annodb_update_t db;
    db.type = LN_CB_ANNO_TYPE_NODE_ANNO;
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_ANNODB_UPDATE, &db);
    return true;
}


bool HIDDEN ln_node_announcement_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    //always return ture
    //don't close the channel

    /*ignore*/node_announcement_recv(pChannel, pData, Len);
    return true;
}


bool /*HIDDEN*/ ln_channel_update_send(ln_channel_t *pChannel)
{
    ln_msg_channel_update_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!create_channel_update(pChannel, &msg, &buf, (uint32_t)utl_time_time(), 0)) {
        LOGE("fail: create channel_update\n");
        return false;
    }

    if (!ln_db_cnlupd_save(&buf, &msg, NULL)) {
        LOGE("fail: save channel_update\n");
        return false;
    }

    if (pChannel->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) {
        //we have exchanged local announcement signatures
        //save for broadcasting
        ln_cb_param_notify_annodb_update_t db;
        db.type = LN_CB_ANNO_TYPE_CNL_UPD;
        ln_callback(pChannel, LN_CB_TYPE_NOTIFY_ANNODB_UPDATE, &db);
    }

    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


//called by `ln_channel_update_recv` only
static bool channel_update_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    (void)pChannel;

    ln_msg_channel_update_t msg;
    uint64_t now = (uint64_t)utl_time_time();

    if (!ln_msg_channel_update_read(&msg, pData, Len)) {
        LOGE("fail: decode\n");
        return false;
    }

    if (memcmp(ln_genesishash_get(), msg.p_chain_hash, BTC_SZ_HASH256)) {
        LOGD("through: chain_hash mismatch\n");
        return true;
    }
    int dir = msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION;

    //timestamp check
    if (ln_db_cnlupd_need_to_prune(now, msg.timestamp)) {
        char time[UTL_SZ_TIME_FMT_STR + 1];
        LOGD("older channel_update: not save(%016" PRIx64 ":%d): %s\n", msg.short_channel_id, dir, utl_time_fmt(time, msg.timestamp));
        return true;
    }

    //LOGV("recv channel_update: %016" PRIx64 ":%d\n", msg.short_channel_id, dir);

    uint8_t node_id[BTC_SZ_PUBKEY];
    if (get_node_id_from_channel_announcement(pChannel, node_id, msg.short_channel_id, dir)) {
        //found
        if (!btc_keys_check_pub(node_id)) {
            LOGE("fail: invalid pubkey\n");
            return false;
        }
#if 0
        if (!ln_msg_channel_update_verify(node_id, pData, Len)) {
            LOGE("fail: verify\n");
            return false;
        }
#endif
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
    if (!ln_db_cnlupd_save(&buf, &msg, ln_remote_node_id(pChannel))) {
        LOGE("fail: save\n");
        return false;
    }
    //LOGD("save channel_update: %016" PRIx64 ":%d\n", msg.short_channel_id, dir);

    ln_cb_param_notify_annodb_update_t db;
    db.type = LN_CB_ANNO_TYPE_CNL_UPD;
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_ANNODB_UPDATE, &db);
    return true;
}


bool HIDDEN ln_channel_update_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    //always return true
    //don't close the channel

    /*ignore*/channel_update_recv(pChannel, pData, Len);
    return true;
}


bool ln_channel_update_disable(ln_channel_t *pChannel)
{
    ln_msg_channel_update_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!create_channel_update(pChannel, &msg, &buf, (uint32_t)utl_time_time(), LN_CNLUPD_CHFLAGS_DISABLE)) return false;
    (void)ln_db_cnlupd_save(&buf, &msg, ln_remote_node_id(pChannel));
    utl_buf_free(&buf);
    return true;
}


bool ln_query_short_channel_ids_send(ln_channel_t *pChannel, const uint8_t *pEncodedIds, uint16_t Len)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGE("fail: not gossip_queries\n");
        return false;
    }
    if (pChannel->gossip_query.request.wait_query_short_channel_ids_end) {
        LOGE("fail: already query_short_channel_ids\n");
        return false;
    }

    //ToDo: GQUERY TEST(相手が持つすべてを要求している)
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_query_short_channel_ids_t msg;
    msg.p_chain_hash = ln_genesishash_get();
    msg.len = Len;
    msg.p_encoded_short_ids = pEncodedIds;
    if (!ln_msg_query_short_channel_ids_write(&buf, &msg)) return false;
    pChannel->gossip_query.request.wait_query_short_channel_ids_end = true;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
#else
    (void)pChannel; (void)pEncodedIds; (void)Len;
    return false;
#endif
}


bool HIDDEN ln_query_short_channel_ids_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGD("through: not gossip_queries\n");
        return true;
    }

    ln_msg_query_short_channel_ids_t msg;
    if (!ln_msg_query_short_channel_ids_read(&msg, pData, Len)) {
        LOGE("fail: read query_short_channel_ids\n");
        return false;
    }
    uint64_t *p_short_channel_ids;
    size_t ids;
    if (!ln_msg_gossip_ids_decode(&p_short_channel_ids, &ids, msg.p_encoded_short_ids, msg.len)) {
        return false;
    }
    if (!ln_db_annoinfos_del_node_id(ln_remote_node_id(pChannel), p_short_channel_ids, ids)) {
        return false;
    }
    UTL_DBG_FREE(p_short_channel_ids);

    return true;
#else
    (void)pChannel; (void)pData; (void)Len;
    return false;
#endif
}


bool ln_reply_short_channel_ids_end_send(ln_channel_t *pChannel, const ln_msg_query_short_channel_ids_t *pMsg)
{
#ifdef USE_GOSSIP_QUERY
    (void)pMsg;

    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGE("fail: not gossip_queries\n");
        return false;
    }

    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_query_short_channel_ids_t msg;
    msg.p_chain_hash = ln_genesishash_get();
    msg.len = 0;
    msg.p_encoded_short_ids = NULL;
    if (!ln_msg_query_short_channel_ids_write(&buf, &msg)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
#else
    (void)pChannel; (void)pMsg;
    return false;
#endif
}


bool HIDDEN ln_reply_short_channel_ids_end_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGE("fail: not gossip_queries\n");
        return false;
    }
    if (!pChannel->gossip_query.request.wait_query_short_channel_ids_end) {
        LOGE("fail: query_short_channel_ids not sent\n");
        return false;
    }
    ln_msg_reply_short_channel_ids_end_t msg;
    if (!ln_msg_reply_short_channel_ids_end_read(&msg, pData, Len)) {
        return false;
    }
    pChannel->gossip_query.request.wait_query_short_channel_ids_end = false;
    return true;
#else
    (void)pChannel; (void)pData; (void)Len;
    return false;
#endif
}


bool ln_query_channel_range_send(ln_channel_t *pChannel, uint32_t FirstBlock, uint32_t Num)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGE("fail: not gossip_queries\n");
        return false;
    }
    if (pChannel->gossip_query.request.rest_blocks != 0) {
        LOGE("fail: not all reply_channel_range received\n");
        return false;
    }

    ln_msg_query_channel_range_t msg;
    msg.p_chain_hash = ln_genesishash_get();
    msg.first_blocknum = FirstBlock;
    uint64_t last_block = (uint64_t)FirstBlock + (uint64_t)Num - 1;
    if (last_block > UINT32_MAX) {
        Num = UINT32_MAX - FirstBlock + 1;
        LOGD("auto ranging: number_of_blocks=%" PRIu32 "\n", Num);
    }
    msg.number_of_blocks = Num;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_query_channel_range_write(&buf, &msg)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    pChannel->gossip_query.request.first_blocknum = FirstBlock;
    pChannel->gossip_query.request.rest_blocks = Num;
    return true;
#else
    (void)pChannel; (void)FirstBlock; (void)Num;
    return false;
#endif
}


bool HIDDEN ln_query_channel_range_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGD("through: not gossip_queries\n");
        return true;
    }

    ln_msg_query_channel_range_t msg;
    if (!ln_msg_query_channel_range_read(&msg, pData, Len)) {
        return false;
    }
    if (!ln_reply_channel_range_send(pChannel, &msg)) {
        return false;
    }
    return true;
#else
    (void)pChannel; (void)pData; (void)Len;
    return false;
#endif
}


bool ln_reply_channel_range_send(ln_channel_t *pChannel, const ln_msg_query_channel_range_t *pMsg)
{
#ifdef USE_GOSSIP_QUERY
    bool ret;

    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGE("fail: not gossip_queries\n");
        return false;
    }

    ln_msg_reply_channel_range_t msg;
    msg.p_chain_hash = pMsg->p_chain_hash;

    //get short_channel_ids from DB
    //  heightからshort_channel_idを取得する
    //  "ascending order"という仕様があるので、昇順

    //get all short_channel_id
    uint64_t short_channel_id = 0;
    void *p_cur_cnl = NULL;         //channel
    if (!ln_db_anno_transaction()) {
        LOGE("fail\n");
        return false;
    }
    if (!ln_db_anno_cur_open(&p_cur_cnl, LN_DB_CUR_CNLANNO)) {
        LOGE("fail\n");
        ln_db_anno_commit(false);
        return false;
    }
    utl_buf_t short_ids;
    utl_push_t push;
    utl_push_init(&push, &short_ids, 0);
    char type;
    while (ln_db_cnlanno_cur_get(p_cur_cnl, &short_channel_id, &type, NULL, NULL)) {
        //LOGD("short_channel_id=%016" PRIx64 ", type=%c\n", short_channel_id, type);
        if (type == LN_DB_CNLANNO_ANNO) {
            //channel_announcementがあるものだけ送信する
            utl_push_data(&push, &short_channel_id, LN_SZ_SHORT_CHANNEL_ID);
        }
    }
    ln_db_anno_cur_close(p_cur_cnl);
    ln_db_anno_commit(false);

    //encode
    utl_buf_t encoded_ids = UTL_BUF_INIT;
    ret = ln_msg_gossip_ids_encode(&encoded_ids, (const uint64_t *)short_ids.buf, short_ids.len / LN_SZ_SHORT_CHANNEL_ID);
    utl_buf_free(&short_ids);
    if (!ret) {
        utl_buf_free(&encoded_ids);
        return false;
    }

    //send
    msg.first_blocknum = pMsg->first_blocknum;
    msg.number_of_blocks = pMsg->number_of_blocks;
    msg.complete = 1;
    msg.len = (uint16_t)encoded_ids.len;
    msg.p_encoded_short_ids = encoded_ids.buf;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_reply_channel_range_write(&buf, &msg)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    utl_buf_free(&encoded_ids);
    return true;
#else
    (void)pChannel; (void)pMsg;
    return false;
#endif
}


bool HIDDEN ln_reply_channel_range_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGE("fail: not gossip_queries\n");
        return false;
    }

    ln_msg_reply_channel_range_t msg;
    bool ret = ln_msg_reply_channel_range_read(&msg, pData, Len);
    if (ret) {
        if (msg.first_blocknum != pChannel->gossip_query.request.first_blocknum) {
            LOGE("fail: not first_blocknum(require=%" PRIu32 ", get=%" PRIu32 ")\n",
                pChannel->gossip_query.request.first_blocknum,
                msg.first_blocknum);
            return true;
        }
        if (msg.number_of_blocks > pChannel->gossip_query.request.rest_blocks) {
            LOGE("fail: too large blocks(rest=%" PRIu32 ", get=%" PRIu32 ")\n",
                pChannel->gossip_query.request.rest_blocks,
                msg.number_of_blocks);
            return true;
        }
        pChannel->gossip_query.request.first_blocknum += msg.number_of_blocks;
        pChannel->gossip_query.request.rest_blocks -= msg.number_of_blocks;
        if (msg.len > 1) {
            //分解してlistに追加
            uint64_t *p_short_ids = NULL;
            size_t ids = 0;
            ret = ln_msg_gossip_ids_decode(&p_short_ids, &ids, msg.p_encoded_short_ids, msg.len);
            if (ret) {
                LOGD("IDS=%" PRIu64 "\n", ids);
#if 0
                //debug
                char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
                for (size_t lp = 0; lp < ids; lp++) {
                    ln_short_channel_id_string(str_sci, p_short_ids[lp]);
                    LOGD("[%ld]%s\n", lp, str_sci);
                }
#endif

                //find last pointer
                struct ln_anno_encoded_ids_t *p_list = LIST_FIRST(&pChannel->gossip_query.request.send_encoded_ids);
                while (p_list != NULL) {
                    struct ln_anno_encoded_ids_t *p_next = LIST_NEXT(p_list, list);
                    if (p_next == NULL) {
                        break;
                    }
                    p_list = p_next;
                }
                //add last
                uint64_t cnt = 0;
                while (ids > 0) {
                    struct ln_anno_encoded_ids_t *p_encoded = (struct ln_anno_encoded_ids_t *)UTL_DBG_MALLOC(sizeof(struct ln_anno_encoded_ids_t));
                    utl_buf_alloc(&p_encoded->encoded_short_ids, 1 + sizeof(uint64_t) * M_SEND_ENCODED_IDS);
                    uint8_t *p = p_encoded->encoded_short_ids.buf;
                    *p = LN_GOSSIPQUERY_ENCODE_NONE;
                    for (int lp = 0; lp < M_SEND_ENCODED_IDS; lp++) {
                        utl_int_unpack_u64be(p + 1 + sizeof(uint64_t) * lp, p_short_ids[cnt]);
                        cnt++;
                        ids--;
                        if (ids == 0) {
                            p_encoded->encoded_short_ids.len = 1 + sizeof(uint64_t) * (lp + 1);
                            p = (uint8_t *)UTL_DBG_REALLOC(p, p_encoded->encoded_short_ids.len);
                            break;
                        }
                    }
                    if (p_list != NULL) {
                        LIST_INSERT_AFTER(p_list, p_encoded, list);
                    } else {
                        LIST_INSERT_HEAD(&pChannel->gossip_query.request.send_encoded_ids, p_encoded, list);
                    }
                    p_list = p_encoded;
                }
                UTL_DBG_FREE(p_short_ids);

#if 0
                LOGD("------------------------------------\n");
                cnt = 0;
                struct ln_anno_encoded_ids_t *p_var;
                LIST_FOREACH(p_var, &pChannel->gossip_query.request.send_encoded_ids, list) {
                    LOGD("encode: %02x\n", p_var->encoded_short_ids.buf[0]);
                    const uint8_t *p = p_var->encoded_short_ids.buf + 1;
                    int num = (p_var->encoded_short_ids.len - 1) / sizeof(uint64_t);
                    for (int lp = 0; lp < num; lp++) {
                        uint64_t sci = utl_int_pack_u64be(p + sizeof(uint64_t) * lp);
                        ln_short_channel_id_string(str_sci, sci);
                        LOGD("  [%2d]%s\n", cnt, str_sci);
                        cnt++;
                    }
                }
                LOGD("------------------------------------\n");
#endif
            }
        }
        if (pChannel->gossip_query.request.rest_blocks == 0) {
            LOGD("all reply_channel_range received.\n");
        }
    }
    return true;
#else
    (void)pChannel; (void)pData; (void)Len;
    return false;
#endif
}


bool ln_gossip_timestamp_filter_send(ln_channel_t *pChannel)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGE("fail: not gossip_queries\n");
        return false;
    }

    ln_msg_gossip_timestamp_filter_t msg;
    msg.p_chain_hash = ln_genesishash_get();
    msg.first_timestamp = (uint32_t)utl_time_time();
    msg.timestamp_range = UINT32_MAX;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_gossip_timestamp_filter_write(&buf, &msg)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
#else
    (void)pChannel;
    return false;
#endif
}


bool HIDDEN ln_gossip_timestamp_filter_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
#ifdef USE_GOSSIP_QUERY
    if ((pChannel->init_flag & M_INIT_GOSSIP_QUERY) == 0) {
        LOGD("through: not gossip_queries\n");
        return true;
    }

    ln_msg_gossip_timestamp_filter_t msg;
    ln_msg_gossip_timestamp_filter_read(&msg, pData, Len);
    return true;
#else
    (void)pChannel; (void)pData; (void)Len;
    return false;
#endif
}


/********************************************************************
 * private functions
 ********************************************************************/

static void proc_announcement_signatures(ln_channel_t *pChannel)
{
    if (pChannel->anno_flag != (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) {
        LOGD("yet: anno_flag=%02x\n", pChannel->anno_flag);
        return;
    }
    if (pChannel->short_channel_id == 0) {
        LOGD("yet: no short_channel_id\n");
        return;
    }
    //announcement_signatures have been exchanged
    LOGD("announcement_signatures sent and recv: %016" PRIx64 "\n", pChannel->short_channel_id);

    //channel_announcement
    {
        //verify
        ln_msg_channel_announcement_t msg;
        if (!ln_msg_channel_announcement_read(&msg, pChannel->cnl_anno.buf, pChannel->cnl_anno.len)) {
            LOGE("fail: read\n");
            return;
        }
        if (!ln_msg_channel_announcement_verify(&msg, pChannel->cnl_anno.buf, pChannel->cnl_anno.len)) {
            LOGE("fail: verify\n");
            return;
        }
        if (ln_db_cnlanno_save(
            &pChannel->cnl_anno, pChannel->short_channel_id, NULL, ln_remote_node_id(pChannel), ln_node_get_id())) {
            utl_buf_free(&pChannel->cnl_anno);
        } else {
            LOGE("fail\n");
        }
    }

    //channel_update
    {
        ln_msg_channel_update_t msg;
        utl_buf_t buf = UTL_BUF_INIT;
        if (create_channel_update(pChannel, &msg, &buf, (uint32_t)utl_time_time(), 0)) {
            ln_db_cnlupd_save(&buf, &msg, NULL);
        } else {
            LOGE("fail\n");
        }
        utl_buf_free(&buf);
    }

    pChannel->anno_flag |= LN_ANNO_FLAG_END;
}


static bool create_local_channel_announcement(ln_channel_t *pChannel)
{
    LOGD("short_channel_id=%016" PRIx64 "\n", pChannel->short_channel_id);
    utl_buf_free(&pChannel->cnl_anno);

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
    msg.short_channel_id = pChannel->short_channel_id;
    btc_script_pubkey_order_t order = ln_node_id_order(pChannel, NULL);
    if (order == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
        msg.p_node_id_1 = ln_node_get_id();
        msg.p_node_id_2 = pChannel->peer_node_id;
        msg.p_bitcoin_key_1 = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING];
        msg.p_bitcoin_key_2 = pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING];
    } else {
        msg.p_node_id_1 = pChannel->peer_node_id;
        msg.p_node_id_2 = ln_node_get_id();
        msg.p_bitcoin_key_1 = pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING];
        msg.p_bitcoin_key_2 = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING];
    }
    if (!ln_msg_channel_announcement_write(&pChannel->cnl_anno, &msg)) return false;
    return ln_msg_channel_announcement_sign(
        pChannel->cnl_anno.buf, pChannel->cnl_anno.len,
        pChannel->keys_local.secrets[LN_BASEPOINT_IDX_FUNDING],
        order);
}


static bool get_node_id_from_channel_announcement(ln_channel_t *pChannel, uint8_t *pNodeId, uint64_t ShortChannelId, uint8_t Dir)
{
    bool ret = false;

    pNodeId[0] = 0x00;

    utl_buf_t buf = UTL_BUF_INIT;
    if (ln_db_cnlanno_load(&buf, ShortChannelId)) {
        ln_msg_channel_announcement_t msg;
        if (!ln_msg_channel_announcement_read(&msg, buf.buf, buf.len)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        memcpy(pNodeId, Dir ? msg.p_node_id_2 : msg.p_node_id_1, BTC_SZ_PUBKEY);
    } else {
        if (ShortChannelId != pChannel->short_channel_id) goto LABEL_EXIT;
        btc_script_pubkey_order_t order = ln_node_id_order(pChannel, NULL);
        if ( ((order == BTC_SCRYPT_PUBKEY_ORDER_ASC) && (Dir == 0)) ||
             ((order == BTC_SCRYPT_PUBKEY_ORDER_OTHER) && (Dir == 1)) ) {
            LOGD("this channel: my node\n");
            memcpy(pNodeId, ln_node_get_id(), BTC_SZ_PUBKEY);
        } else {
            LOGD("this channel: peer node\n");
            memcpy(pNodeId, pChannel->peer_node_id, BTC_SZ_PUBKEY);
        }
    }

    ret = true;

LABEL_EXIT:
    utl_buf_free(&buf);
    return ret;
}


/** channel_update作成
 *
 * @param[in,out]       pChannel        channel情報
 * @param[out]          pUpd            生成したchannel_update構造体
 * @param[out]          pCnlUpd         生成したchannel_updateメッセージ
 * @param[in]           TimeStamp       作成時刻とするEPOCH time
 * @param[in]           Flag            flagsにORする値
 * @retval      ture    成功
 */
static bool create_channel_update(
    ln_channel_t *pChannel, ln_msg_channel_update_t *pUpd, utl_buf_t *pCnlUpd, uint32_t TimeStamp, uint8_t Flag)
{
    uint8_t dummy_signature[LN_SZ_SIGNATURE] = {0};
    memset(dummy_signature, 0xcc, sizeof(dummy_signature));
    pUpd->p_signature = dummy_signature;
    pUpd->p_chain_hash = ln_genesishash_get();
    pUpd->short_channel_id = pChannel->short_channel_id;
    pUpd->timestamp = TimeStamp;
    pUpd->message_flags = 0;
    pUpd->channel_flags = Flag | ln_order_to_dir(ln_node_id_order(pChannel, NULL));
    pUpd->cltv_expiry_delta = pChannel->anno_param.cltv_expiry_delta;
    pUpd->htlc_minimum_msat = pChannel->anno_param.htlc_minimum_msat;
    pUpd->fee_base_msat = pChannel->anno_param.fee_base_msat;
    pUpd->fee_proportional_millionths = pChannel->anno_param.fee_prop_millionths;
    pUpd->htlc_maximum_msat = 0;
    if (!ln_msg_channel_update_write(pCnlUpd, pUpd)) return false;
    return ln_msg_channel_update_sign(pCnlUpd->buf, pCnlUpd->len);
}
