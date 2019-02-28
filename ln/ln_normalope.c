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
/** @file   ln_normalope.c
 *  @brief  ln_normalope
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
#include "ln_comtx.h"
#include "ln_derkey.h"
#include "ln_script.h"
#include "ln_onion.h"
#include "ln_node.h"
#include "ln.h"
#include "ln_msg.h"
#include "ln_setupctl.h"
#include "ln_msg_normalope.h"
#include "ln_local.h"
#include "ln_normalope.h"
#include "ln_funding_info.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_HYSTE_CLTV_EXPIRY_MIN             (7)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_SOON            (1)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_FAR             (144 * 15)      ///< BOLT4 check:cltv_expiryのhysteresis(15日)

#define M_UPDATEFEE_CHK_MIN_OK(val,rate)    (val >= (uint32_t)(rate * 0.2))
#define M_UPDATEFEE_CHK_MAX_OK(val,rate)    (val <= (uint32_t)(rate * 20))


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool check_recv_add_htlc_bolt2(ln_channel_t *pChannel, const ln_htlc_t *pHtlc);
static bool check_recv_add_htlc_bolt4(ln_channel_t *pChannel, uint16_t update_idx);
static bool check_recv_add_htlc_bolt4_common(ln_channel_t *pChannel, utl_push_t *pPushReason);
static bool check_recv_add_htlc_bolt4_final(
    ln_channel_t *pChannel, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason,
    ln_htlc_t *pHtlc, uint8_t *pPreimage, int32_t Height);
static bool check_recv_add_htlc_bolt4_forward(
    ln_channel_t *pChannel, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason,
    ln_htlc_t *pHtlc,int32_t Height);
static bool store_peer_percommit_secret(ln_channel_t *pChannel, const uint8_t *p_prev_secret);
static void clear_htlc(ln_channel_t *pChannel, uint16_t UpdateIdx);
static bool update_add_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx);
static bool update_fulfill_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx);
static bool update_fail_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx);
static bool update_fail_malformed_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx);
static bool commitment_signed_send(ln_channel_t *pChannel);
static bool revoke_and_ack_send(ln_channel_t *pChannel);
static bool check_create_add_htlc(ln_channel_t *pChannel, utl_buf_t *pReason, uint64_t amount_msat, uint32_t cltv_value);
static bool set_add_htlc(
    ln_channel_t *pChannel, uint64_t *pHtlcId, utl_buf_t *pReason, uint16_t *pHtlcIdx,
    const uint8_t *pPacket, uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash,
    uint64_t PrevShortChannelId, uint16_t PrevHtlcIdx, const utl_buf_t *pSharedSecrets);
static bool check_create_remote_commit_tx(ln_channel_t *pChannel, uint16_t UpdateIdx);
static uint64_t htlc_value_in_flight_msat(ln_channel_t *pChannel, bool bLocal);
static uint64_t htlc_value_in_flight_msat_local(ln_channel_t *pChannel);
static uint64_t htlc_value_in_flight_msat_remote(ln_channel_t *pChannel);


/**************************************************************************
 * public functions
 **************************************************************************/

bool HIDDEN ln_update_add_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_update_t *p_update = NULL;
    ln_htlc_t *p_htlc = NULL;
    uint16_t update_idx;
    uint16_t htlc_idx;

    p_update = ln_update_get_empty(pChannel->updates, &update_idx);
    if (!p_update) {
        M_SET_ERR(pChannel, LNERR_HTLC_FULL, "no free updates");
        return false;
    }
    p_htlc = ln_htlc_get_empty(pChannel->htlcs, &htlc_idx);
    if (!p_htlc) {
        M_SET_ERR(pChannel, LNERR_HTLC_FULL, "no free htlcs");
        return false;
    }
    p_update->htlc_idx = htlc_idx;
    p_update->enabled = true;
    p_htlc->enabled = true;
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    p_update->flags.up_recv = 1;

    ln_msg_update_add_htlc_t msg;
    if (!ln_msg_update_add_htlc_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        clear_htlc(pChannel, update_idx);
        return false;
    }
    p_htlc->id = msg.id;
    p_htlc->amount_msat = msg.amount_msat;
    memcpy(p_htlc->payment_hash, msg.p_payment_hash, BTC_SZ_HASH256);
    p_htlc->cltv_expiry = msg.cltv_expiry;
    if (!utl_buf_alloccopy(&p_htlc->buf_onion_reason, msg.p_onion_routing_packet, LN_SZ_ONION_ROUTE)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "memory allocation error");
        clear_htlc(pChannel, update_idx);
        return false;
    }

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        clear_htlc(pChannel, update_idx);
        return false;
    }

    // BOLT2 check
    //  NG時は、基本的にチャネルを失敗させる。
    //  「相手のamountより HTLCのamountの方が大きい」というような、あってはいけないチェックを行う。
    //  送金額が足りないのは、転送する先のチャネルにamountが足りていない場合になるため、
    //  それはupdate_add_htlcをrevoke_and_ackまで終わらせた後、update_fail_htlcを返すことになる。
    //
    if (!check_recv_add_htlc_bolt2(pChannel, p_htlc)) {
        LOGE("fail: BOLT2 check\n");
        clear_htlc(pChannel, update_idx);
        return false;
    }

    //XXX: should not ignore
    /*ignore*/ check_recv_add_htlc_bolt4(pChannel, update_idx);

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_update_fulfill_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_update_fulfill_htlc_t msg;
    if (!ln_msg_update_fulfill_htlc_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    const ln_update_t *p_update_add_htlc;
    ln_htlc_t *p_htlc = NULL;
    uint16_t update_idx_add_htlc;
    for (update_idx_add_htlc = 0; update_idx_add_htlc < LN_UPDATE_MAX; update_idx_add_htlc++) {
        p_update_add_htlc = &pChannel->updates[update_idx_add_htlc];
        if (!LN_UPDATE_ENABLED(p_update_add_htlc)) continue;
        if (!LN_UPDATE_LOCAL_ADD_HTLC_SEND_ENABLED(p_update_add_htlc)) continue;
        if (!LN_UPDATE_IRREVOCABLY_COMMITTED(p_update_add_htlc)) continue;
        p_htlc = &pChannel->htlcs[p_update_add_htlc->htlc_idx];
        if (p_htlc->id != msg.id) continue;
        break;
    }
    if (update_idx_add_htlc == LN_UPDATE_MAX) {
        M_SET_ERR(pChannel, LNERR_INV_ID, "fulfill htlc");
        return false;
    }

    uint8_t hash[BTC_SZ_HASH256];
    btc_md_sha256(hash, msg.p_payment_preimage, BTC_SZ_PRIVKEY);
    LOGD("hash: ");
    DUMPD(hash, sizeof(hash));
    if (memcmp(hash, p_htlc->payment_hash, BTC_SZ_HASH256)) {
        LOGE("fail: match id, but fail payment_hash\n");
        M_SET_ERR(pChannel, LNERR_INV_ID, "fulfill htlc");
        return false;
    }

    if (!ln_update_set_del_htlc_recv(
        pChannel->updates, p_update_add_htlc->htlc_idx, LN_UPDATE_TYPE_FULFILL_HTLC)) {
        M_SET_ERR(pChannel, LNERR_INV_ID, "fulfill htlc");
        return false;
    }

    ln_cb_param_notify_fulfill_htlc_recv_t cb_param;
    cb_param.ret = false;
    cb_param.prev_short_channel_id = p_htlc->neighbor_short_channel_id;
    cb_param.prev_htlc_idx = p_htlc->neighbor_idx;
    cb_param.p_preimage = msg.p_payment_preimage;
    cb_param.next_id = p_htlc->id;
    cb_param.amount_msat = p_htlc->amount_msat;
    //XXX: In the current implementation it will be called more than once in a retry at reconnection
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV, &cb_param);
    if (!cb_param.ret) {
        LOGE("fail: backwind\n");
        /*ignore*/
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_update_fail_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_update_fail_htlc_t msg;
    if (!ln_msg_update_fail_htlc_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    const ln_update_t *p_update_add_htlc;
    ln_htlc_t *p_htlc = NULL;
    uint16_t update_idx_add_htlc;
    for (update_idx_add_htlc = 0; update_idx_add_htlc < LN_UPDATE_MAX; update_idx_add_htlc++) {
        p_update_add_htlc = &pChannel->updates[update_idx_add_htlc];
        if (!LN_UPDATE_ENABLED(p_update_add_htlc)) continue;
        if (!LN_UPDATE_LOCAL_ADD_HTLC_SEND_ENABLED(p_update_add_htlc)) continue;
        if (!LN_UPDATE_IRREVOCABLY_COMMITTED(p_update_add_htlc)) continue;
        p_htlc = &pChannel->htlcs[p_update_add_htlc->htlc_idx];
        if (p_htlc->id != msg.id) continue;
        break;
    }
    if (update_idx_add_htlc == LN_UPDATE_MAX) {
        M_SET_ERR(pChannel, LNERR_INV_ID, "fail htlc");
        return false;
    }

    if (!ln_update_set_del_htlc_recv(
        pChannel->updates, p_update_add_htlc->htlc_idx, LN_UPDATE_TYPE_FAIL_HTLC)) {
        M_SET_ERR(pChannel, LNERR_INV_ID, "fail htlc");
        return false;
    }

    utl_buf_free(&p_htlc->buf_onion_reason);
    utl_buf_alloccopy(&p_htlc->buf_onion_reason, msg.p_reason, msg.len);
#if 0
    ln_cb_param_notify_fail_htlc_recv_t cb_param;
    cb_param.ret = false;
    cb_param.prev_short_channel_id = p_htlc->neighbor_short_channel_id;
    utl_buf_t reason;
    utl_buf_init_2(&reason, (CONST_CAST uint8_t *)msg.p_reason, msg.len);
    cb_param.p_reason = &reason;
    cb_param.p_shared_secret = &p_htlc->buf_shared_secret;
    cb_param.prev_htlc_idx = p_htlc->neighbor_idx;
    cb_param.next_id = p_htlc->id;
    cb_param.p_payment_hash = p_htlc->payment_hash;
    cb_param.fail_malformed_failure_code = 0;
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_FAIL_HTLC_RECV, &cb_param);
    if (!cb_param.ret) {
        LOGE("fail: backwind\n");
        /*ignore*/
    }
#endif
    return true;
}


bool HIDDEN ln_update_fail_malformed_htlc_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_update_fail_malformed_htlc_t msg;
    if (!ln_msg_update_fail_malformed_htlc_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    if ((msg.failure_code & LNERR_ONION_BADONION) == 0) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "no BADONION bit");
        return false;
    }

    const ln_update_t *p_update_add_htlc;
    ln_htlc_t *p_htlc = NULL;
    uint16_t update_idx_add_htlc;
    for (update_idx_add_htlc = 0; update_idx_add_htlc < LN_UPDATE_MAX; update_idx_add_htlc++) {
        p_update_add_htlc = &pChannel->updates[update_idx_add_htlc];
        if (!LN_UPDATE_ENABLED(p_update_add_htlc)) continue;
        if (!LN_UPDATE_LOCAL_ADD_HTLC_SEND_ENABLED(p_update_add_htlc)) continue;
        if (!LN_UPDATE_IRREVOCABLY_COMMITTED(p_update_add_htlc)) continue;
        p_htlc = &pChannel->htlcs[p_update_add_htlc->htlc_idx];
        if (p_htlc->id != msg.id) continue;
        break;
    }
    if (update_idx_add_htlc == LN_UPDATE_MAX) {
        M_SET_ERR(pChannel, LNERR_INV_ID, "fail malformed htlc");
        return false;
    }

    if (!ln_update_set_del_htlc_recv(
        pChannel->updates, p_update_add_htlc->htlc_idx, LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC)) {
        M_SET_ERR(pChannel, LNERR_INV_ID, "fail malformed htlc");
        return false;
    }

    //XXX: ???
    //受信したmal_htlcは、Offered HTLCについてチェックする。
    //仕様としては、sha256_of_onionを確認し、再送か別エラーにするなので、
    //  ここでは受信したfailure_codeでエラーを作る。
    //
    // BOLT#02
    //  if the sha256_of_onion in update_fail_malformed_htlc doesn't match the onion it sent:
    //      MAY retry or choose an alternate error response.
    utl_buf_t reason = UTL_BUF_INIT;
    utl_push_t push_reason;
    utl_push_init(&push_reason, &reason, 2 + BTC_SZ_HASH256);
    utl_push_u16be(&push_reason, msg.failure_code);
    utl_push_data(&push_reason, msg.p_sha256_of_onion, BTC_SZ_HASH256);
    utl_buf_free(&p_htlc->buf_onion_reason);
    utl_buf_alloccopy(&p_htlc->buf_onion_reason, reason.buf, reason.len);
    utl_buf_free(&reason);
    LOGD("END\n");
    return true;
}


bool HIDDEN ln_commitment_signed_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_commitment_signed_t msg;
    if (!ln_msg_commitment_signed_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(pChannel->commit_info_local.remote_sig, msg.p_signature, LN_SZ_SIGNATURE);

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //署名チェック＋保存: To-Local
    pChannel->commit_info_local.commit_num++;
    if (!ln_comtx_create_local( //HTLC署名のみ(closeなし)
        pChannel, &pChannel->commit_info_local, NULL,
        (const uint8_t (*)[LN_SZ_SIGNATURE])msg.p_htlc_signature, msg.num_htlcs)) {
        LOGE("fail: create_to_local\n");
        return false;
    }

    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pChannel->updates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (!LN_UPDATE_LOCAL_SOME_UPDATE_ENABLED(p_update)) continue;
        LOGD(" [%d]cs_recv=1\n", idx);
        p_update->flags.cs_recv = 1;
    }

    if (!revoke_and_ack_send(pChannel)) {
        return false;
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_revoke_and_ack_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    uint32_t num_fwds = 0;

    //for callbacks
    ln_cb_param_start_fwd_add_htlc_t fwds[LN_UPDATE_MAX]; //XXX: dynamically allocate
    uint32_t num_bwds = 0;
    ln_cb_param_start_bwd_del_htlc_t bwds[LN_UPDATE_MAX]; //XXX: dynamically allocate
    uint8_t bwd_payment_hashs[LN_UPDATE_MAX][BTC_SZ_HASH256]; //XXX: dynamically allocate
    bool revack_exchanged = false;

    ln_msg_revoke_and_ack_t msg;
    if (!ln_msg_revoke_and_ack_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        goto LABEL_ERROR;
    }

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_ERROR;
    }

    //prev_secretチェック
    //  受信したper_commitment_secretが、前回受信したper_commitment_pointと等しいこと
    //XXX: not check?
    uint8_t prev_commitpt[BTC_SZ_PUBKEY];
    if (!btc_keys_priv2pub(prev_commitpt, msg.p_per_commitment_secret)) {
        LOGE("fail: prev_secret convert\n");
        goto LABEL_ERROR;
    }

    LOGD("$$$ revoke_num: %" PRIu64 "\n", pChannel->commit_info_local.revoke_num);
    LOGD("$$$ prev per_commit_pt: ");
    DUMPD(prev_commitpt, BTC_SZ_PUBKEY);

    // uint8_t old_secret[BTC_SZ_PRIVKEY];
    // for (uint64_t index = 0; index <= pChannel->commit_info_local.revoke_num + 1; index++) {
    //     ret = ln_derkey_remote_storage_get_secret(&pChannel->privkeys_remote, old_secret, LN_SECRET_INDEX_INIT - index);
    //     if (ret) {
    //         uint8_t pubkey[BTC_SZ_PUBKEY];
    //         btc_keys_priv2pub(pubkey, old_secret);
    //         //M_DB_CHANNEL_SAVE(pChannel);
    //         LOGD("$$$ old_secret(%016" PRIx64 "): ", LN_SECRET_INDEX_INIT - index);
    //         DUMPD(old_secret, sizeof(old_secret));
    //         LOGD("$$$ pubkey: ");
    //         DUMPD(pubkey, sizeof(pubkey));
    //     } else {
    //         LOGD("$$$ fail: get last secret\n");
    //         //goto LABEL_ERROR;
    //     }
    // }

    // if (memcmp(prev_commitpt, pChannel->pubkeys_remote.prev_per_commitment_point, BTC_SZ_PUBKEY) != 0) {
    //     LOGE("fail: prev_secret mismatch\n");

    //     //check re-send
    //     if (memcmp(new_commitpt, pChannel->pubkeys_remote.per_commitment_point, BTC_SZ_PUBKEY) == 0) {
    //         //current per_commitment_point
    //         LOGD("skip: same as previous next_per_commitment_point\n");
    //         ret = true;
    //     } else {
    //         LOGD("recv secret: ");
    //         DUMPD(prev_commitpt, BTC_SZ_PUBKEY);
    //         LOGD("my secret: ");
    //         DUMPD(pChannel->pubkeys_remote.prev_per_commitment_point, BTC_SZ_PUBKEY);
    //         ret = false;
    //     }
    //     goto LABEL_ERROR;
    // }

    //save prev_secret
    if (!store_peer_percommit_secret(pChannel, msg.p_per_commitment_secret)) {
        LOGE("fail: store prev secret\n");
        goto LABEL_ERROR;
    }

    //update per_commitment_point
    memcpy(pChannel->keys_remote.prev_per_commitment_point, pChannel->keys_remote.per_commitment_point, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.per_commitment_point, msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);
    ln_update_script_pubkeys(pChannel);
    //ln_print_keys(&pChannel->funding_info_local, &pChannel->funding_info_remote);

    pChannel->commit_info_remote.revoke_num = pChannel->commit_info_remote.commit_num - 1;

    for (uint16_t update_idx = 0; update_idx < LN_UPDATE_MAX; update_idx++) {
        ln_update_t *p_update = &pChannel->updates[update_idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (!LN_UPDATE_REMOTE_COMSIGING(p_update)) continue;
        revack_exchanged = true;

        if (LN_UPDATE_LOCAL_ADD_HTLC_RECV_ENABLED(p_update)) {
            ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];
            if (p_htlc->neighbor_short_channel_id) {
                LOGD("forward: %d\n", p_htlc->neighbor_idx);
                fwds[num_fwds].next_short_channel_id = p_htlc->neighbor_short_channel_id;
                fwds[num_fwds].next_htlc_idx = p_htlc->neighbor_idx;
                //p_update->neighbor_short_channel_id = 0;
                num_fwds++;
            }

            LOGD(" [%d]ra_recv=1\n", update_idx);
            p_update->flags.ra_recv = 1;

            if (LN_DBG_FULFILL()) {
                //XXX: Send immediately?
                switch (p_update->fin_type) {
                case LN_UPDATE_TYPE_FULFILL_HTLC:
                    LOGD("fin update type: %d\n", p_update->fin_type);
                    /*ignore*/ ln_fulfill_htlc_set(
                        pChannel, p_update->htlc_idx, NULL); //XXX:
                        //XXX: Should callback to the final node and register issuance of preimage
                    break;
                case LN_UPDATE_TYPE_FAIL_HTLC:
                case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
                    /*ignore*/ ln_fail_htlc_set(
                        pChannel, p_update->htlc_idx, p_update->fin_type, NULL);
                        //XXX: Should callback to the (final) node
                default:
                    ;
                }
            }
        } else if (LN_UPDATE_LOCAL_DEL_HTLC_RECV_ENABLED(p_update)) {
            ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];
            if (p_update->type != LN_UPDATE_TYPE_FULFILL_HTLC) {
                bwds[num_bwds].ret = false;
                bwds[num_bwds].update_type = p_update->type;
                bwds[num_bwds].prev_short_channel_id = p_htlc->neighbor_short_channel_id;
                bwds[num_bwds].p_reason = &p_htlc->buf_onion_reason;
                bwds[num_bwds].p_shared_secret = &p_htlc->buf_shared_secret;
                bwds[num_bwds].prev_htlc_idx = p_htlc->neighbor_idx;
                bwds[num_bwds].next_htlc_id = p_htlc->id;
                bwds[num_bwds].p_payment_hash = p_htlc->payment_hash;
                if (p_update->type == LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC) {
                    if (p_htlc->buf_onion_reason.len < 2) {
                        LOGE("fail: ???\n");
                        goto LABEL_ERROR;
                    }
                    bwds[num_bwds].fail_malformed_failure_code = utl_int_pack_u16be(p_htlc->buf_onion_reason.buf);
                } else {
                    bwds[num_bwds].fail_malformed_failure_code = 0;
                }
                memcpy(bwd_payment_hashs[num_bwds], p_htlc->payment_hash, BTC_SZ_HASH256);
                num_bwds++;
            }

            LOGD(" [%d]ra_recv=1\n", update_idx);
            p_update->flags.ra_recv = 1;

            LOGD("clear_htlc: %016" PRIx64 " UPDATE[%u], HTLC[%u]\n",
                pChannel->short_channel_id, update_idx, p_update->htlc_idx);
        } else {
            LOGD(" [%d]ra_recv=1\n", update_idx);
            p_update->flags.ra_recv = 1;
        }
    }

    //Be sure to save before fowrarding and backwarding
    //  Otherwise there is a possibility of fowrarding and backwarding of the same updates multiple times
    LN_DBG_COMMIT_NUM_PRINT(pChannel);
    M_DB_CHANNEL_SAVE(pChannel);

    for (uint32_t lp = 0; lp < num_fwds; lp++) {
        ln_callback(pChannel, LN_CB_TYPE_START_FWD_ADD_HTLC, &fwds[lp]);
    }
    for (uint32_t lp = 0; lp < num_bwds; lp++) {
        if (bwds[lp].prev_short_channel_id) {
            LOGD("backward fail_htlc!\n");
            ln_callback(pChannel, LN_CB_TYPE_START_BWD_DEL_HTLC, &bwds[lp]);
        } else {
            //XXX: one callback
            LOGD("fail_htlc!\n");
            ln_callback(pChannel, LN_CB_TYPE_START_BWD_DEL_HTLC, &bwds[lp]);
            LOGD("retry the payment! in the origin node\n");
            ln_callback(pChannel, LN_CB_TYPE_RETRY_PAYMENT, bwd_payment_hashs[lp]);
        }
    }
    if (revack_exchanged) {
        ln_callback(pChannel, LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE, NULL);
    }

    for (uint16_t update_idx = 0; update_idx < LN_UPDATE_MAX; update_idx++) {
        ln_update_t *p_update = &pChannel->updates[update_idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (!LN_UPDATE_LOCAL_DEL_HTLC_RECV_ENABLED(p_update)) continue;
        if (!LN_UPDATE_IRREVOCABLY_COMMITTED(p_update)) continue;
        clear_htlc(pChannel, update_idx);
    }

    LOGD("END\n");
    return true;

LABEL_ERROR:
    LOGD("END\n");
    return false;
}


bool HIDDEN ln_update_fee_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_update_fee_t msg;
    uint32_t rate;
    uint32_t old_fee;

    if (!ln_msg_update_fee_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }

    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //BOLT02
    //  A receiving node:
    //    if the sender is not responsible for paying the Bitcoin fee:
    //      MUST fail the channel.
    if (ln_funding_info_is_funder(&pChannel->funding_info, true)) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "not fundee");
        return false;
    }

    if (msg.feerate_per_kw < LN_FEERATE_PER_KW_MIN) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "too low feerate_per_kw");
        return false;
    }

    ln_callback(pChannel, LN_CB_TYPE_GET_LATEST_FEERATE, &rate);
    if (!M_UPDATEFEE_CHK_MIN_OK(msg.feerate_per_kw, rate)) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "too low feerate_per_kw from current");
        return false;
    }
    if (!M_UPDATEFEE_CHK_MAX_OK(msg.feerate_per_kw, rate)) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "too large feerate_per_kw from current");
        return false;
    }

    //feerate_per_kw更新
    old_fee = pChannel->feerate_per_kw;
    LOGD("change fee: %" PRIu32 " --> %" PRIu32 "\n", pChannel->feerate_per_kw, msg.feerate_per_kw);
    pChannel->feerate_per_kw = msg.feerate_per_kw;
    //M_DB_CHANNEL_SAVE(pChannel);  //確定するまでDB保存しない

    //fee更新通知
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV, &old_fee);

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_update_fee_send(ln_channel_t *pChannel, uint32_t FeeratePerKw)
{
    LOGD("BEGIN: %" PRIu32 " --> %" PRIu32 "\n", pChannel->feerate_per_kw, FeeratePerKw);

    if (!M_INIT_CH_EXCHANGED(pChannel->init_flag)) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "no init/channel_reestablish finished");
        return false;
    }

    //BOLT02
    //  The node not responsible for paying the Bitcoin fee:
    //    MUST NOT send update_fee.
    if (!ln_funding_info_is_funder(&pChannel->funding_info, true)) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "not funder");
        return false;
    }

    if (pChannel->feerate_per_kw == FeeratePerKw) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "same feerate_per_kw");
        return false;
    }
    if (FeeratePerKw < LN_FEERATE_PER_KW_MIN) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "feerate_per_kw too low");
        return false;
    }

    ln_msg_update_fee_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.feerate_per_kw = FeeratePerKw;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_update_fee_write(&buf, &msg)) {
        LOGE("fail\n");
        return false;
    }
    pChannel->feerate_per_kw = FeeratePerKw;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    LOGD("END\n");
    return true;
}


bool ln_set_add_htlc_send(
    ln_channel_t *pChannel, uint64_t *pHtlcId, utl_buf_t *pReason, const uint8_t *pPacket,
    uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash, uint64_t PrevShortChannelId,
    uint16_t PrevHtlcIdx, const utl_buf_t *pSharedSecrets)
{
    LOGD("BEGIN\n");

    //BOLT2
    //  MUST NOT send an update_add_htlc after a shutdown.
    if (pChannel->shutdown_flag) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "shutdown: not allow add_htlc");
        return false;
    }

    uint16_t htlc_idx;
    if (!set_add_htlc(
        pChannel, pHtlcId, pReason, &htlc_idx, pPacket, AmountMsat,
        CltvValue, pPaymentHash, PrevShortChannelId, PrevHtlcIdx, pSharedSecrets)) return false;

    ln_update_t *p_update = ln_update_get_update_enabled_but_none(pChannel->updates, htlc_idx);
    assert(p_update);
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    LN_DBG_UPDATE_PRINT(p_update);
    return true;
}


bool ln_set_add_htlc_send_fwd(
    ln_channel_t *pChannel, uint64_t *pHtlcId, utl_buf_t *pReason, uint16_t *pNextHtlcIdx,
    const uint8_t *pPacket, uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash,
    uint64_t PrevShortChannelId, uint16_t PrevHtlcIdx, const utl_buf_t *pSharedSecrets)
{
    LOGD("BEGIN\n");

    //BOLT2
    //  MUST NOT send an update_add_htlc after a shutdown.
    if (pChannel->shutdown_flag) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "shutdown: not allow add_htlc");
        return false;
    }

    uint16_t htlc_idx;
    if (!set_add_htlc(
        pChannel, pHtlcId, pReason, &htlc_idx, pPacket, AmountMsat, CltvValue,
        pPaymentHash, PrevShortChannelId, PrevHtlcIdx, pSharedSecrets)) return false;

    //typeは #ln_recv_idle_proc()のHTLC final経由で #ln_add_htlc_start_fwd()を呼び出して設定
    ln_update_t *p_update = ln_update_get_update_enabled_but_none(pChannel->updates, htlc_idx);
    *pNextHtlcIdx = htlc_idx;
    assert(p_update);
    LN_DBG_UPDATE_PRINT(p_update);
    return true;
}


void ln_add_htlc_start_fwd(ln_channel_t *pChannel, uint16_t NextHtlcIdx)
{
    LOGD("BEGIN\n");
    ln_update_t *p_update = ln_update_get_update_enabled_but_none(pChannel->updates, NextHtlcIdx);
    assert(p_update);
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    LN_DBG_UPDATE_PRINT(p_update);
}


bool ln_fulfill_htlc_set(ln_channel_t *pChannel, uint16_t HtlcIdx, const uint8_t *pPreimage)
{
    LOGD("BEGIN\n");

    ln_update_t *p_update_add_htlc = ln_update_get_update_add_htlc(pChannel->updates, HtlcIdx);
    assert(p_update_add_htlc);
    if (!LN_UPDATE_LOCAL_ADD_HTLC_RECV_ENABLED(p_update_add_htlc)) return false;
    if (!LN_UPDATE_IRREVOCABLY_COMMITTED(p_update_add_htlc)) return false;

    ln_update_t *p_update_del_htlc = ln_update_set_del_htlc_send(
        pChannel->updates, HtlcIdx, LN_UPDATE_TYPE_FULFILL_HTLC);
    assert(p_update_del_htlc);
    
    if (pPreimage) {
        ln_htlc_t *p_htlc = &pChannel->htlcs[HtlcIdx];
        if (!utl_buf_alloccopy(&p_htlc->buf_payment_preimage, pPreimage, LN_SZ_PREIMAGE)) return false;
        //M_DB_CHANNEL_SAVE(pChannel); //XXX: Since the forwarding data of update is stored separately, this is not necessary
    }

    LN_DBG_UPDATE_PRINT(p_update_del_htlc);
    return true;
}


bool ln_fail_htlc_set(ln_channel_t *pChannel, uint16_t HtlcIdx, uint8_t UpdateType, const utl_buf_t *pReason)
{
    LOGD("BEGIN\n");

    ln_update_t *p_update_add_htlc = ln_update_get_update_add_htlc(pChannel->updates, HtlcIdx);
    if (!LN_UPDATE_LOCAL_ADD_HTLC_RECV_ENABLED(p_update_add_htlc)) return false;

    if (LN_UPDATE_IRREVOCABLY_COMMITTED(p_update_add_htlc)) {
        ln_update_t *p_update_del_htlc = ln_update_set_del_htlc_send(
            pChannel->updates, HtlcIdx, UpdateType);
        assert(p_update_del_htlc);
        LN_DBG_UPDATE_PRINT(p_update_del_htlc);
    } else {
        p_update_add_htlc->fin_type = UpdateType;
    }
    
    if (pReason) {
        ln_htlc_t *p_htlc = &pChannel->htlcs[HtlcIdx];
        utl_buf_free(&p_htlc->buf_onion_reason);
        ln_onion_failure_forward(&p_htlc->buf_onion_reason, &p_htlc->buf_shared_secret, pReason);
    }
    return true;
}


void ln_recv_idle_proc(ln_channel_t *pChannel, uint32_t FeeratePerKw)
{
    //XXX: should return the return code
    //LOGD("$$$ update_fee: %" PRIu32 " ==> %" PRIu32 "\n", pChannel->feerate_per_kw, FeeratePerKw);

    uint16_t num_updates = 0;
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pChannel->updates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        num_updates++;
        if (LN_UPDATE_COMSIGING(p_update)) {
            //XXX: We should be able to send an update message at this timing
            return;
        }
    }

    if (num_updates) {
        for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
            ln_update_t *p_update = &pChannel->updates[idx];
            if (!LN_UPDATE_ENABLED(p_update)) continue;
            if (LN_UPDATE_WILL_SEND(p_update)) {
                if (p_update->type == LN_UPDATE_TYPE_ADD_HTLC) {
                    /*ignore*/ update_add_htlc_send(pChannel, idx);
                } else {
                    if (!LN_DBG_FULFILL() || !LN_DBG_FULFILL_BWD()) {
                        LOGD("DBG: no fulfill mode\n");
                        continue;
                    }
                    switch (p_update->type) {
                    case LN_UPDATE_TYPE_FULFILL_HTLC:
                        /*ignore*/ update_fulfill_htlc_send(pChannel, idx);
                        break;
                    case LN_UPDATE_TYPE_FAIL_HTLC:
                        /*ignore*/ update_fail_htlc_send(pChannel, idx);
                        break;
                    case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
                        /*ignore*/ update_fail_malformed_htlc_send(pChannel, idx);
                        break;
                    default:
                        assert(0);
                    }
                }
            }
        }
    }

    bool b_comsig_needed = false;
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pChannel->updates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (!LN_UPDATE_WILL_COMSIG_SEND(p_update)) continue;
        b_comsig_needed = true;
        break;
    }

    if (!b_comsig_needed && ((FeeratePerKw != 0) && (pChannel->feerate_per_kw != FeeratePerKw))) {
        if (ln_update_fee_send(pChannel, FeeratePerKw)) {
            b_comsig_needed = true;
        }
    }

    if (b_comsig_needed) {
        /*ignore*/ commitment_signed_send(pChannel);
    }
}


void ln_channel_reestablish_after(ln_channel_t *pChannel)
{
    LN_DBG_COMMIT_NUM_PRINT(pChannel);
    LN_DBG_UPDATES_PRINT(pChannel->updates);

    LOGD("pChannel->reest_revoke_num=%" PRIu64 "\n", pChannel->reest_revoke_num);
    LOGD("pChannel->reest_commit_num=%" PRIu64 "\n", pChannel->reest_commit_num);

    //
    //BOLT#02
    //  commit_txは、作成する関数内でcommit_num+1している(インクリメントはしない)。
    //  そのため、(commit_num+1)がcommit_tx作成時のcommitment numberである。

    //  next_local_commitment_number
    if (pChannel->commit_info_remote.commit_num == pChannel->reest_commit_num) {
        //  if next_local_commitment_number is equal to the commitment number of the last commitment_signed message the receiving node has sent:
        //      * MUST reuse the same commitment number for its next commitment_signed.
        //remote.per_commitment_pointを1つ戻して、キャンセルされたupdateメッセージを再送する
        //XXX: If the corresponding `revoke_andk_ack` is received, channel should be failed
        LOGD("$$$ resend: previous update message\n");
        for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
            ln_update_t *p_update = &pChannel->updates[idx];
            if (!LN_UPDATE_ENABLED(p_update)) continue;
            if (!LN_UPDATE_REMOTE_COMSIGING(p_update)) continue;
            LN_UPDATE_ENABLE_RESEND_UPDATE(p_update);
            //The update message will be sent in the idle proc.
        }
        pChannel->commit_info_remote.commit_num--;
    }

    //BOLT#02
    //  next_remote_revocation_number
    if (pChannel->commit_info_local.revoke_num == pChannel->reest_revoke_num) {
        // if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack the receiving node sent, AND the receiving node hasn't already received a closing_signed:
        //      * MUST re-send the revoke_and_ack.
        LOGD("$$$ next_remote_revocation_number == local commit_num: resend\n");

        uint8_t prev_secret[BTC_SZ_PRIVKEY];
        ln_derkey_local_storage_create_prev_per_commitment_secret(&pChannel->keys_local, prev_secret, NULL);

        utl_buf_t buf = UTL_BUF_INIT;
        ln_msg_revoke_and_ack_t revack;
        revack.p_channel_id = pChannel->channel_id;
        revack.p_per_commitment_secret = prev_secret;
        revack.p_next_per_commitment_point = pChannel->keys_local.per_commitment_point;
        LOGD("  send revoke_and_ack.next_per_commitment_point=%" PRIu64 "\n", pChannel->keys_local.per_commitment_point);
        bool ret = ln_msg_revoke_and_ack_write(&buf, &revack);
        if (ret) {
            ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
            LOGD("OK: re-send revoke_and_ack\n");
        } else {
            LOGE("fail: re-send revoke_and_ack\n");
        }
        utl_buf_free(&buf);
    }
}


/********************************************************************
 * private functions
 ********************************************************************/

/** [BOLT#2]ln_update_add_htlc_recv()のチェック項目
 *
 */
static bool check_recv_add_htlc_bolt2(ln_channel_t *pChannel, const ln_htlc_t *pHtlc)
{
    const ln_htlc_t *p_htlc = pHtlc;

    //shutdown
    if (pChannel->shutdown_flag & LN_SHDN_FLAG_RECV) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "already shutdown received");
        return false;
    }

    //amount_msatが0の場合、チャネルを失敗させる。
    //amount_msatが自分のhtlc_minimum_msat未満の場合、チャネルを失敗させる。
    //  receiving an amount_msat equal to 0, OR less than its own htlc_minimum_msat
    if (p_htlc->amount_msat < pChannel->commit_info_local.htlc_minimum_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "amount_msat < local htlc_minimum_msat");
        return false;
    }

    //送信側が現在のfeerate_per_kwで支払えないようなamount_msatの場合、チャネルを失敗させる。
    //  receiving an amount_msat that the sending node cannot afford at the current feerate_per_kw
    if (pChannel->commit_info_local.remote_msat < p_htlc->amount_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "commit_info_local.remote_msat too small(%" PRIu64 " < %" PRIu64 ")", pChannel->commit_info_local.remote_msat, p_htlc->amount_msat);
        return false;
    }

    //追加した結果が自分のmax_accepted_htlcsより多くなるなら、チャネルを失敗させる。
    //  if a sending node adds more than its max_accepted_htlcs HTLCs to its local commitment transaction
    //XXX: bug
    //  don't compare with the number of HTLC outputs but HTLCs (including trimmed ones)
    if (pChannel->commit_info_local.max_accepted_htlcs < pChannel->commit_info_local.num_htlc_outputs) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "over max_accepted_htlcs : %d", pChannel->commit_info_local.num_htlc_outputs);
        return false;
    }

    //加算した結果が自分のmax_htlc_value_in_flight_msatを超えるなら、チャネルを失敗させる。
    //      adds more than its max_htlc_value_in_flight_msat worth of offered HTLCs to its local commitment transaction
    if (htlc_value_in_flight_msat_local(pChannel) > pChannel->commit_info_local.max_htlc_value_in_flight_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "exceed local max_htlc_value_in_flight_msat");
        return false;
    }

    //cltv_expiryが500000000以上の場合、チャネルを失敗させる。
    //  if sending node sets cltv_expiry to greater or equal to 500000000
    if (p_htlc->cltv_expiry >= BTC_TX_LOCKTIME_LIMIT) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "cltv_expiry >= 500000000");
        return false;
    }

    //for channels with chain_hash identifying the Bitcoin blockchain, if the four most significant bytes of amount_msat are not 0
    if (p_htlc->amount_msat & (uint64_t)0xffffffff00000000) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "Bitcoin amount_msat must 4 MSByte not 0");
        return false;
    }

    //同じpayment_hashが複数のHTLCにあってもよい。
    //  MUST allow multiple HTLCs with the same payment_hash

    //TODO: 再接続後に、送信側に受入(acknowledge)されていない前と同じidを送ってきても、無視する。
    //  if the sender did not previously acknowledge the commitment of that HTLC
    //      MUST ignore a repeated id value after a reconnection.

    //TODO: 他のidを破壊するようであれば、チャネルを失敗させる。
    //  if other id violations occur

    return true;
}


static bool check_recv_add_htlc_bolt4(ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    ln_update_t *p_update = &pChannel->updates[UpdateIdx];
    ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];

    typedef enum {
        RESULT_OK,
        RESULT_FAIL,
        RESULT_FAIL_MALFORMED,
    } result_t;

    //BOLT4 check
    //  [2018/09/07] N/A
    //      A2. 該当する状況なし
    //      A3. 該当する状況なし
    //      A4. node_announcement.featuresは未定義
    //      B6. channel_announcement.featuresは未定義

    ln_hop_dataout_t hop_dataout;   // update_add_htlc受信後のONION解析結果
    uint8_t preimage[LN_SZ_PREIMAGE];
    utl_push_t push_htlc;
    utl_buf_t buf_reason = UTL_BUF_INIT;
    int32_t height = 0;
    result_t result = RESULT_OK;
    ln_cb_param_nofity_add_htlc_recv_t cb_param;

    utl_push_init(&push_htlc, &buf_reason, 0);

    if (!ln_onion_read_packet(
        p_htlc->buf_onion_reason.buf, &hop_dataout, &p_htlc->buf_shared_secret, &push_htlc,
        p_htlc->buf_onion_reason.buf, p_htlc->payment_hash, BTC_SZ_HASH256)) {
        //A1. if the realm byte is unknown:
        //      invalid_realm
        //B1. if the onion version byte is unknown:
        //      invalid_onion_version
        //B2. if the onion HMAC is incorrect:
        //      invalid_onion_hmac
        //B3. if the ephemeral key in the onion is unparsable:
        //      invalid_onion_key

        M_SET_ERR(pChannel, LNERR_ONION, "onion-read");
        uint16_t failure_code = utl_int_pack_u16be(buf_reason.buf);
        if (failure_code & LNERR_ONION_BADONION) {
            result = RESULT_FAIL_MALFORMED;
        } else {
            result = RESULT_FAIL;
        }
        utl_buf_free(&p_htlc->buf_onion_reason);
        goto LABEL_EXIT;
    }

    ln_callback(pChannel, LN_CB_TYPE_GET_BLOCK_COUNT, &height);
    if (height <= 0) {
        M_SET_ERR(pChannel, LNERR_BITCOIND, "getblockcount");
        LOGE("fail\n");
        result = RESULT_FAIL;
        goto LABEL_EXIT;
    }

    if (hop_dataout.b_exit) {
        if (!check_recv_add_htlc_bolt4_final(pChannel, &hop_dataout, &push_htlc, p_htlc, preimage, height)) {
            LOGE("fail\n");
            result = RESULT_FAIL;
            goto LABEL_EXIT;
        }
        utl_buf_alloccopy(&p_htlc->buf_payment_preimage, preimage, LN_SZ_PREIMAGE);
        utl_buf_free(&p_htlc->buf_onion_reason);
    } else {
        if (!check_recv_add_htlc_bolt4_forward(pChannel, &hop_dataout, &push_htlc, p_htlc, height)) {
            LOGE("fail\n");
            result = RESULT_FAIL;
            goto LABEL_EXIT;
        }
    }

    if (!check_recv_add_htlc_bolt4_common(pChannel, &push_htlc)) {
        LOGE("fail\n");
        result = RESULT_FAIL;
        goto LABEL_EXIT;
    }

    //update_add_htlc受信通知
    //  hop nodeの場合、転送先ln_channel_tのupdates[],htlcs[]に設定まで行う
    cb_param.ret = true;
    cb_param.id = p_htlc->id;
    cb_param.p_payment = p_htlc->payment_hash;
    cb_param.p_hop = &hop_dataout;
    cb_param.amount_msat = p_htlc->amount_msat;
    cb_param.cltv_expiry = p_htlc->cltv_expiry;
    cb_param.htlc_idx = p_update->htlc_idx;
        //転送先にとっては、prev_update_idx
        //戻り値は転送先の  next_update_idx
    cb_param.p_onion_reason = &p_htlc->buf_onion_reason;
    cb_param.p_shared_secret = &p_htlc->buf_shared_secret;
    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV, &cb_param);

    if (!cb_param.ret) {
        utl_buf_t buf = UTL_BUF_INIT;
        if (ln_channel_update_get_peer(pChannel, &buf, NULL)) {
            LOGE("fail: --> temporary channel failure\n");
            utl_push_u16be(&push_htlc, LNONION_TMP_CHAN_FAIL);
            utl_push_u16be(&push_htlc, (uint16_t)buf.len);
            utl_push_data(&push_htlc, buf.buf, buf.len);
            utl_buf_free(&buf);
        } else {
            LOGE("fail: --> unknown next peer\n");
            utl_push_u16be(&push_htlc, LNONION_UNKNOWN_NEXT_PEER);
        }
        result = RESULT_FAIL;
        goto LABEL_EXIT;
    }

    if (hop_dataout.b_exit) {
        LOGD("final node: will backwind fulfill_htlc\n");
        LOGD("[FIN_DELHTLC](%016" PRIx64 ")%d --> %d\n",
            pChannel->short_channel_id, p_update->fin_type, LN_UPDATE_TYPE_FULFILL_HTLC);
        p_update->fin_type = LN_UPDATE_TYPE_FULFILL_HTLC;
    } else {
        LOGD("hop node: will forward another channel\n");
        p_htlc->neighbor_short_channel_id = hop_dataout.short_channel_id;
        p_htlc->neighbor_idx = cb_param.htlc_idx;
    }

LABEL_EXIT:
    LOGD("HTLC add : id=%" PRIu64 ", amount_msat=%" PRIu64 "\n", p_htlc->id, p_htlc->amount_msat);
    LOGD("  result=%d\n", result);
    LOGD("  id=%" PRIu64 "\n", p_htlc->id);
    LOGD("  %s\n", (hop_dataout.b_exit) ? "intended recipient" : "forwarding HTLCs");
    LOGD("  FWD: short_channel_id: %016" PRIx64 "\n", hop_dataout.short_channel_id);
    LOGD("  FWD: amt_to_forward: %" PRIu64 "\n", hop_dataout.amt_to_forward);
    LOGD("  FWD: outgoing_cltv_value: %d\n", hop_dataout.outgoing_cltv_value);
    LOGD("  -------\n");
    LOGD("  amount_msat: %" PRIu64 "\n", p_htlc->amount_msat);
    LOGD("  cltv_expiry: %d\n", p_htlc->cltv_expiry);
    LOGD("  my fee : %" PRIu64 "\n", (uint64_t)(p_htlc->amount_msat - hop_dataout.amt_to_forward));
    LOGD("  cltv_expiry - outgoing_cltv_value(%" PRIu32") = %d\n",
        hop_dataout.outgoing_cltv_value, p_htlc->cltv_expiry - hop_dataout.outgoing_cltv_value);

    switch (result) {
    case RESULT_FAIL:
        LOGE("fail: will backwind fail_htlc\n");
        LOGD("[FIN_DELHTLC](%016" PRIx64 ")%d --> %d\n",
            pChannel->short_channel_id, p_update->fin_type, LN_UPDATE_TYPE_FAIL_HTLC);
        p_update->fin_type = LN_UPDATE_TYPE_FAIL_HTLC;
        utl_buf_free(&p_htlc->buf_onion_reason);
        ln_onion_failure_create(&p_htlc->buf_onion_reason, &p_htlc->buf_shared_secret, &buf_reason);
            //折り返しだけAPIが異なる
        break;
    case RESULT_FAIL_MALFORMED:
        LOGE("fail: will backwind fail_malformed_htlc\n");
        LOGD("[FIN_DELHTLC](%016" PRIx64 ")%d --> %d\n",
            pChannel->short_channel_id, p_update->fin_type, LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC);
        p_update->fin_type = LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC;
        utl_buf_free(&p_htlc->buf_onion_reason);
        utl_buf_alloccopy(&p_htlc->buf_onion_reason, buf_reason.buf, buf_reason.len);
        break;
    default:
        ;
    }
    utl_buf_free(&buf_reason);
    return true;
}


static bool check_recv_add_htlc_bolt4_common(ln_channel_t *pChannel, utl_push_t *pPushReason)
{
    (void)pPushReason;

    //shutdown
    if (pChannel->shutdown_flag & LN_SHDN_FLAG_SEND) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "already shutdown sent");
        utl_push_u16be(pPushReason, LNONION_PERM_CHAN_FAIL);
        return false;
    }

    //A3. if an otherwise unspecified permanent error occurs for the entire node:
    //      permanent_node_failure
    //
    //      N/A

    //A4. if a node has requirements advertised in its node_announcement features, which were NOT included in the onion:
    //      required_node_feature_missing
    //
    //      N/A

    return true;
}


/** [BOLT#4]ln_update_add_htlc_recv()のチェック(final node)
 *
 *      pDataOut                 : onionパラメータ
 *
 * +------+                          +------+                          +------+
 * |node_A|------------------------->|node_B|------------------------->|node_C|
 * +------+  update_add_htlc         +------+  update_add_htlc         +------+
 *             amount_msat_AB                    amount_msat_BC
 *             onion_routing_packet_AB           onion_routing_packet_BC
 *               amt_to_forward_BC
 *
 * @param[in,out]       pChannel
 * @param[out]          pDataOut        onion packetデコード結果
 * @param[out]          pPushReason     error reason
 * @param[in,out]       pHtlc           activeなpChannel->htlcs[Index]
 * @param[out]          pPreimage       pAddHtlc->payment_hashに該当するpreimage
 * @param[in]           Height          current block height
 * @retval  true    成功
 */
static bool check_recv_add_htlc_bolt4_final(
    ln_channel_t *pChannel, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason,
    ln_htlc_t *pHtlc, uint8_t *pPreimage, int32_t Height)
{
    ln_htlc_t *p_htlc = pHtlc;

    //search preimage
    ln_db_preimage_t preimage;
    uint8_t preimage_hash[BTC_SZ_HASH256];

    preimage.amount_msat = (uint64_t)-1;
    preimage.expiry = 0;
    void *p_cur;
    if (!ln_db_preimage_cur_open(&p_cur)) { //XXX: internal error?
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "preimage mismatch");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_PAY_HASH);
        return false;
    }
    bool detect = false;
    for (;;) {
        detect = false;
        if (!ln_db_preimage_cur_get(p_cur, &detect, &preimage)) break;     //from invoice
        if (!detect) continue;
        memcpy(pPreimage, preimage.preimage, LN_SZ_PREIMAGE);
        ln_payment_hash_calc(preimage_hash, pPreimage);
        if (memcmp(preimage_hash, p_htlc->payment_hash, BTC_SZ_HASH256)) continue;
        break;
    }
    ln_db_preimage_cur_close(p_cur);
    if (!detect) {
        //C1. if the payment hash has already been paid:
        //      ★(採用)MAY treat the payment hash as unknown.★
        //      MAY succeed in accepting the HTLC.
        //C3. if the payment hash is unknown:
        //      unknown_payment_hash
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "preimage mismatch");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_PAY_HASH);
        return false;
    }
    LOGD("match preimage: ");
    DUMPD(pPreimage, LN_SZ_PREIMAGE);

    //C2. if the amount paid is less than the amount expected:
    //      incorrect_payment_amount
    if (p_htlc->amount_msat < preimage.amount_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "incorrect_payment_amount(final) : %" PRIu64 " < %" PRIu64, pDataOut->amt_to_forward, preimage.amount_msat);
        utl_push_u16be(pPushReason, LNONION_INCORR_PAY_AMT);
        return false;
    }

    //C4. if the amount paid is more than twice the amount expected:
    //      incorrect_payment_amount
    if (preimage.amount_msat * 2 < p_htlc->amount_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "large amount_msat : %" PRIu64 " < %" PRIu64,
            preimage.amount_msat * 2, pDataOut->amt_to_forward);
        utl_push_u16be(pPushReason, LNONION_INCORR_PAY_AMT);
        return false;
    }

    //C5. if the cltv_expiry value is unreasonably near the present:
    //      final_expiry_too_soon
    //          今のところ、min_final_cltv_expiryは固定値(#LN_MIN_FINAL_CLTV_EXPIRY)しかない。
    LOGD("outgoing_cltv_value=%" PRIu32 ", min_final_cltv_expiry=%" PRIu16 ", height=%" PRId32 "\n",
        pDataOut->outgoing_cltv_value, LN_MIN_FINAL_CLTV_EXPIRY, Height);
    if ( (pDataOut->outgoing_cltv_value + M_HYSTE_CLTV_EXPIRY_SOON < (uint32_t)Height + LN_MIN_FINAL_CLTV_EXPIRY) ||
         (pDataOut->outgoing_cltv_value < (uint32_t)Height + M_HYSTE_CLTV_EXPIRY_MIN) ) {
        LOGD("%" PRIu32 " < %" PRId32 "\n",
            pDataOut->outgoing_cltv_value + M_HYSTE_CLTV_EXPIRY_SOON, Height + M_HYSTE_CLTV_EXPIRY_MIN);
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "cltv_expiry too soon(final)");
        utl_push_u16be(pPushReason, LNONION_FINAL_EXPIRY_TOO_SOON);
        return false;
    }

    //C6. if the outgoing_cltv_value does NOT correspond with the cltv_expiry from the final node's HTLC:
    //      final_incorrect_cltv_expiry
    if (pDataOut->outgoing_cltv_value != p_htlc->cltv_expiry) {
        LOGD("%" PRIu32 " --- %" PRIu32 "\n", pDataOut->outgoing_cltv_value, ln_cltv_expily_delta(pChannel));
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "incorrect cltv expiry(final)");
        utl_push_u16be(pPushReason, LNONION_FINAL_INCORR_CLTV_EXP);
        //[4:cltv_expiry]
        utl_push_u32be(pPushReason, pDataOut->outgoing_cltv_value);
        return false;
    }

    //C7. if the amt_to_forward is greater than the incoming_htlc_amt from the final node's HTLC:
    //      final_incorrect_htlc_amount
    if (pDataOut->amt_to_forward > p_htlc->amount_msat) {
        LOGD("%" PRIu64 " --- %" PRIu64 "\n", pDataOut->amt_to_forward, p_htlc->amount_msat);
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "incorrect_payment_amount(final)");
        utl_push_u16be(pPushReason, LNONION_FINAL_INCORR_HTLC_AMT);
        //[4:incoming_htlc_amt]
        utl_push_u32be(pPushReason, p_htlc->amount_msat);
        return false;
    }
    return true;
}


/** [BOLT#4]ln_update_add_htlc_recv()のチェック(forward node)
 *
 * @param[in,out]       pChannel
 * @param[out]          pDataOut        onion packetデコード結果
 * @param[out]          pPushReason     error reason
 * @param[in,out]       pHtlc           activeなpChannel->htlcs[Index]
 * @param[in]           Height          current block height
 * @retval  true    成功
 */
static bool check_recv_add_htlc_bolt4_forward(
    ln_channel_t *pChannel, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason,
    ln_htlc_t *pHtlc, int32_t Height)
{
    ln_htlc_t *p_htlc = pHtlc;

    //処理前呼び出し
    //  転送先取得(final nodeの場合は、p_next_channelにNULLが返る)
    ln_cb_param_notify_add_htlc_recv_prev_t recv_prev;
    recv_prev.p_next_channel = NULL;
    if (pDataOut->short_channel_id) {
        recv_prev.next_short_channel_id = pDataOut->short_channel_id;
        ln_callback(pChannel, LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV_PREV, &recv_prev);
    }

    //B6. if the outgoing channel has requirements advertised in its channel_announcement's features, which were NOT included in the onion:
    //      required_channel_feature_missing
    //
    //      2018/09/07: channel_announcement.features not defined

    //B7. if the receiving peer specified by the onion is NOT known:
    //      unknown_next_peer
    if ( (pDataOut->short_channel_id == 0) ||
        (recv_prev.p_next_channel == NULL) ||
        (ln_status_get(recv_prev.p_next_channel) != LN_STATUS_NORMAL) ) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "no next channel");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        return false;
    }

    //load channel_update
    ln_msg_channel_update_t cnlupd;
    utl_buf_t cnlupd_buf = UTL_BUF_INIT;
    uint8_t peer_id[BTC_SZ_PUBKEY];
    if (!ln_node_search_node_id(peer_id, pDataOut->short_channel_id)) {
        LOGE("fail: ln_node_search_node_id\n");
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "no channel_update");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        return false;
    }
    uint8_t dir = ln_order_to_dir(ln_node_id_order(pChannel, peer_id));
    if (!ln_db_annocnlupd_load(&cnlupd_buf, NULL, pDataOut->short_channel_id, dir, NULL)) {
        LOGE("fail: ln_db_annocnlupd_load: %016" PRIx64 ", dir=%d\n",
            pDataOut->short_channel_id, dir);
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "no channel_update");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        return false;
    }
    if (!ln_msg_channel_update_read(&cnlupd, cnlupd_buf.buf, cnlupd_buf.len)) {
        LOGE("fail: ln_msg_channel_update_read\n");
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "no channel_update");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        return false;
    }
    LOGD("short_channel_id=%016" PRIx64 "\n", pDataOut->short_channel_id);

    //B8. if the HTLC amount is less than the currently specified minimum amount:
    //      amount_below_minimum
    //      (report the amount of the incoming HTLC and the current channel setting for the outgoing channel.)
    if (pDataOut->amt_to_forward < recv_prev.p_next_channel->commit_info_remote.htlc_minimum_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "lower than htlc_minimum_msat : %" PRIu64 " < %" PRIu64,
            pDataOut->amt_to_forward, recv_prev.p_next_channel->commit_info_remote.htlc_minimum_msat);
        utl_push_u16be(pPushReason, LNONION_AMT_BELOW_MIN);
        //[8:htlc_msat]
        //[2:len]
        utl_push_u16be(pPushReason, cnlupd_buf.len);
        //[len:channel_update]
        utl_push_data(pPushReason, cnlupd_buf.buf, cnlupd_buf.len);
        return false;
    }

    //B9. if the HTLC does NOT pay a sufficient fee:
    //      fee_insufficient
    //      (report the amount of the incoming HTLC and the current channel setting for the outgoing channel.)
    uint64_t fwd_fee = ln_forward_fee(pChannel, pDataOut->amt_to_forward);
    if (p_htlc->amount_msat < pDataOut->amt_to_forward + fwd_fee) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "fee not enough : %" PRIu32 " < %" PRIu32,
            fwd_fee, p_htlc->amount_msat - pDataOut->amt_to_forward);
        utl_push_u16be(pPushReason, LNONION_FEE_INSUFFICIENT);
        //[8:htlc_msat]
        //[2:len]
        utl_push_u16be(pPushReason, cnlupd_buf.len);
        //[len:channel_update]
        utl_push_data(pPushReason, cnlupd_buf.buf, cnlupd_buf.len);
        return false;
    }

    //B10. if the outgoing_cltv_value does NOT match the update_add_htlc's cltv_expiry minus the cltv_expiry_delta for the outgoing channel:
    //      incorrect_cltv_expiry
    //      (report the cltv_expiry and the current channel setting for the outgoing channel.)
    if ( (p_htlc->cltv_expiry <= pDataOut->outgoing_cltv_value) ||
        (p_htlc->cltv_expiry + ln_cltv_expily_delta(recv_prev.p_next_channel) < pDataOut->outgoing_cltv_value) ) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "cltv not enough : %" PRIu32,
            ln_cltv_expily_delta(recv_prev.p_next_channel));
        utl_push_u16be(pPushReason, LNONION_INCORR_CLTV_EXPIRY);
        //[4:cltv_expiry]
        //[2:len]
        utl_push_u16be(pPushReason, cnlupd_buf.len);
        //[len:channel_update]
        utl_push_data(pPushReason, cnlupd_buf.buf, cnlupd_buf.len);
        return false;
    }

    //B11. if the cltv_expiry is unreasonably near the present:
    //      expiry_too_soon
    //      (report the current channel setting for the outgoing channel.)
    LOGD("cltv_value=%" PRIu32 ", expiry_delta=%" PRIu16 ", height=%" PRId32 "\n",
        p_htlc->cltv_expiry, cnlupd.cltv_expiry_delta, Height);
    if ( (p_htlc->cltv_expiry + M_HYSTE_CLTV_EXPIRY_SOON < (uint32_t)Height + cnlupd.cltv_expiry_delta) ||
        (p_htlc->cltv_expiry < (uint32_t)Height + M_HYSTE_CLTV_EXPIRY_MIN) ) {
        LOGD("%" PRIu32 " < %" PRId32 "\n",
            p_htlc->cltv_expiry + M_HYSTE_CLTV_EXPIRY_SOON, Height + cnlupd.cltv_expiry_delta);
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "expiry too soon : %" PRIu32,
            ln_cltv_expily_delta(recv_prev.p_next_channel));
        utl_push_u16be(pPushReason, LNONION_EXPIRY_TOO_SOON);
        //[2:len]
        utl_push_u16be(pPushReason, cnlupd_buf.len);
        //[len:channel_update]
        utl_push_data(pPushReason, cnlupd_buf.buf, cnlupd_buf.len);
        return false;
    }

    //B12. if the cltv_expiry is unreasonably far in the future:
    //      expiry_too_far
    if (p_htlc->cltv_expiry > (uint32_t)Height + cnlupd.cltv_expiry_delta + M_HYSTE_CLTV_EXPIRY_FAR) {
        LOGD("%" PRIu32 " > %" PRId32 "\n",
            p_htlc->cltv_expiry, Height + cnlupd.cltv_expiry_delta + M_HYSTE_CLTV_EXPIRY_FAR);
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "expiry too far : %" PRIu32,
            ln_cltv_expily_delta(recv_prev.p_next_channel));
        utl_push_u16be(pPushReason, LNONION_EXPIRY_TOO_FAR);
        return false;
    }
    return true;
}


/** peerから受信したper_commitment_secret保存
 *
 * @param[in,out]   pChannel        チャネル情報
 * @param[in]       p_prev_secret   受信したper_commitment_secret
 * @retval  true    成功
 * @note
 *      - indexを進める
 */
static bool store_peer_percommit_secret(ln_channel_t *pChannel, const uint8_t *p_prev_secret)
{
    //LOGD("I=%016" PRIx64 "\n", ln_derkey_remote_storage_get_current_index()&pChannel->keys_remote);
    //DUMPD(p_prev_secret, BTC_SZ_PRIVKEY);
    uint8_t pub[BTC_SZ_PUBKEY];
    btc_keys_priv2pub(pub, p_prev_secret);
    //DUMPD(pub, BTC_SZ_PUBKEY);
    bool ret = ln_derkey_remote_storage_insert_per_commitment_secret(&pChannel->keys_remote, p_prev_secret);
    if (!ret) return false;

    //M_DB_CHANNEL_SAVE(pChannel);  //保存は呼び出し元で行う
    LOGD("I=%016" PRIx64 "\n", ln_derkey_remote_storage_get_current_index(&pChannel->keys_remote));

    //for (uint64_t idx = LN_SECRET_INDEX_INIT; idx > ln_derkey_remote_storage_get_current_index(&pChannel->keys_remote); idx--) {
    //    LOGD("I=%016" PRIx64 "\n", idx);
    //    LOGD2("  ");
    //    uint8_t sec[BTC_SZ_PRIVKEY];
    //    ret = ln_derkey_remote_storage_get_secret(&pChannel->keys_remote, sec, idx);
    //    assert(ret);
    //    LOGD2("  pri:");
    //    DUMPD(sec, BTC_SZ_PRIVKEY);
    //    LOGD2("  pub:");
    //    btc_keys_priv2pub(pub, sec);
    //    DUMPD(pub, BTC_SZ_PUBKEY);
    //}
    return true;
}

static void clear_htlc(ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    ln_update_t *p_update = &pChannel->updates[UpdateIdx];
    if (!LN_UPDATE_ENABLED(p_update)) {
        memset(p_update, 0x00, sizeof(ln_update_t));
        return;
    }

    ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];
    ln_db_preimage_del(p_htlc->buf_payment_preimage.buf);
    utl_buf_free(&p_htlc->buf_payment_preimage);
    utl_buf_free(&p_htlc->buf_onion_reason);
    utl_buf_free(&p_htlc->buf_shared_secret);
    memset(p_htlc, 0x00, sizeof(ln_htlc_t));

    uint16_t corresponding_update_idx;
    if (ln_update_get_corresponding_update(pChannel->updates, &corresponding_update_idx, UpdateIdx)) {
        memset(&pChannel->updates[corresponding_update_idx], 0x00, sizeof(ln_update_t));
    }

    memset(p_update, 0x00, sizeof(ln_update_t));
}


static bool commitment_signed_send(ln_channel_t *pChannel)
{
    LOGD("BEGIN\n");

    bool ret = false;
    uint8_t (*p_htlc_sigs)[LN_SZ_SIGNATURE] = NULL;
    utl_buf_t buf = UTL_BUF_INIT;

    if (!M_INIT_FLAG_EXCHNAGED(pChannel->init_flag)) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "no init finished");
        goto LABEL_EXIT;
    }

    //create sigs for remote commitment transaction
    pChannel->commit_info_remote.commit_num++;
    if (!ln_comtx_create_remote(
        pChannel, &pChannel->commit_info_remote, NULL, &p_htlc_sigs)) {
        M_SET_ERR(pChannel, LNERR_MSG_ERROR, "create remote commitment transaction");
        goto LABEL_EXIT;
    }

    ln_msg_commitment_signed_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.p_signature = pChannel->commit_info_remote.remote_sig;
    msg.num_htlcs = pChannel->commit_info_remote.num_htlc_outputs;
    msg.p_htlc_signature = (uint8_t *)p_htlc_sigs;
    if (!ln_msg_commitment_signed_write(&buf, &msg)) {
        M_SET_ERR(pChannel, LNERR_MSG_ERROR, "create commitment_signed");
        LOGE("fail: create commit_tx(0x%" PRIx64 ")\n", ln_short_channel_id(pChannel));
        ln_callback(pChannel, LN_CB_TYPE_STOP_CHANNEL, NULL);
        utl_buf_free(&buf);
        goto LABEL_EXIT;
    }

    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pChannel->updates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (!LN_UPDATE_REMOTE_SOME_UPDATE_ENABLED(p_update)) continue;
        LOGD(" [%d]cs_send=1\n", idx);
        p_update->flags.cs_send = 1;
    }

    //We have to save the channel before sending the message
    //  Otherwise, if aborted after sending it, the channel forgets sending it
    LN_DBG_COMMIT_NUM_PRINT(pChannel);
    M_DB_CHANNEL_SAVE(pChannel);

    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);

    ret = true;

LABEL_EXIT:
    utl_buf_free(&buf);
    UTL_DBG_FREE(p_htlc_sigs);
    LOGD("END\n");
    return ret;
}


static bool revoke_and_ack_send(ln_channel_t *pChannel)
{
    LOGD("BEGIN\n");

    uint8_t prev_secret[BTC_SZ_PRIVKEY];
    ln_derkey_local_storage_create_prev_per_commitment_secret(&pChannel->keys_local, prev_secret, NULL);
    ln_derkey_local_storage_update_per_commitment_point(&pChannel->keys_local);
    ln_update_script_pubkeys(pChannel);
    pChannel->commit_info_local.revoke_num++;

    //XXX: ???
    // //revokeするsecret
    // for (uint64_t index = 0; index <= pChannel->commit_info_local.revoke_num + 1; index++) {
    //     uint8_t old_secret[BTC_SZ_PRIVKEY];
    //     ln_derkey_remote_storage_create_secret(&pChannel->privkeys, old_secret, LN_SECRET_INDEX_INIT - index);
    //     LOGD("$$$ old_secret(%016" PRIx64 "): ", LN_SECRET_INDEX_INIT - index);
    //     DUMPD(old_secret, sizeof(old_secret));
    // }

    bool b_htlc_completed = false;
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pChannel->updates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (LN_UPDATE_LOCAL_SOME_UPDATE_ENABLED(p_update)) {
            LOGD(" [%d]ra_send=1\n", idx);
            p_update->flags.ra_send = 1;
        }
        if (LN_UPDATE_REMOTE_DEL_HTLC_RECV_ENABLED(p_update) &&
            LN_UPDATE_IRREVOCABLY_COMMITTED(p_update)) {
            LOGD("clear_htlc: %016" PRIx64 " UPDATE[%u], HTLC[%u]\n",
                pChannel->short_channel_id, idx, p_update->htlc_idx);
            clear_htlc(pChannel, idx);
            b_htlc_completed = true;
        }
    }

    //We have to save the channel before sending the message
    //  Otherwise, if aborted after sending it, the channel forgets sending it
    LN_DBG_COMMIT_NUM_PRINT(pChannel);
    M_DB_SECRET_SAVE(pChannel);
    M_DB_CHANNEL_SAVE(pChannel);

    ln_msg_revoke_and_ack_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.p_per_commitment_secret = prev_secret;
    msg.p_next_per_commitment_point = pChannel->keys_local.per_commitment_point;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_revoke_and_ack_write(&buf, &msg)) {
        LOGE("fail: ???\n");
        return false;
    }
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    if (b_htlc_completed) {
        ln_callback(pChannel, LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE, NULL);
    }
    LOGD("END\n");
    return true;
}


/** update_add_htlc作成前チェック
 *
 * @param[in,out]       pChannel    #M_SET_ERR()で書込む
 * @param[out]          pReason     (非NULL時かつ戻り値がfalse)onion reason
 * @param[in]           amount_msat
 * @param[in]           cltv_value
 * @retval      true    チェックOK
 */
static bool check_create_add_htlc(
    ln_channel_t *pChannel, utl_buf_t *pReason, uint64_t amount_msat, uint32_t cltv_value)
{
    uint64_t close_fee_msat = LN_SATOSHI2MSAT(ln_closing_signed_initfee(pChannel));
    if (pReason) {
        utl_buf_free(pReason);
    }

    //cltv_expiryは、500000000未満にしなくてはならない
    if (cltv_value >= BTC_TX_LOCKTIME_LIMIT) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "cltv_value >= 500000000");
        goto LABEL_ERROR;
    }

    //相手が指定したchannel_reserve_satは残しておく必要あり
    if (pChannel->commit_info_remote.remote_msat < amount_msat + LN_SATOSHI2MSAT(pChannel->commit_info_remote.channel_reserve_sat)) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE,
            "commit_info_remote.remote_msat(%" PRIu64 ") - amount_msat(%" PRIu64 ") < channel_reserve msat(%" PRIu64 ")",
            pChannel->commit_info_remote.remote_msat, amount_msat, LN_SATOSHI2MSAT(pChannel->commit_info_remote.channel_reserve_sat));
        goto LABEL_ERROR;
    }

    //現在のfeerate_per_kwで支払えないようなamount_msatを指定してはいけない
    if (pChannel->commit_info_remote.remote_msat < amount_msat + close_fee_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE,
            "commit_info_remote.remote_msat(%" PRIu64 ") - amount_msat(%" PRIu64 ") < closing_fee_msat(%" PRIu64 ")",
            pChannel->commit_info_remote.remote_msat, amount_msat, close_fee_msat);
        goto LABEL_ERROR;
    }

    //追加した結果が相手のmax_accepted_htlcsより多くなるなら、追加してはならない。
    //XXX: bug
    //  don't compare with the number of HTLC outputs but HTLCs (including trimmed ones)
    if (pChannel->commit_info_remote.max_accepted_htlcs <= pChannel->commit_info_remote.num_htlc_outputs) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "over max_accepted_htlcs : %d <= %d",
            pChannel->commit_info_remote.max_accepted_htlcs, pChannel->commit_info_remote.num_htlc_outputs);
        goto LABEL_ERROR;
    }

    //amount_msatは、0より大きくなくてはならない。
    //amount_msatは、相手のhtlc_minimum_msat未満にしてはならない。
    if ((amount_msat == 0) || (amount_msat < pChannel->commit_info_remote.htlc_minimum_msat)) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "amount_msat(%" PRIu64 ") < remote htlc_minimum_msat(%" PRIu64 ")",
            amount_msat, pChannel->commit_info_remote.htlc_minimum_msat);
        goto LABEL_ERROR;
    }

    //加算した結果が相手のmax_htlc_value_in_flight_msatを超えるなら、追加してはならない。
    if (htlc_value_in_flight_msat_remote(pChannel) > pChannel->commit_info_remote.max_htlc_value_in_flight_msat) {
        M_SET_ERR(pChannel, LNERR_INV_VALUE,
            "exceed remote max_htlc_value_in_flight_msat(%" PRIu64 ")",
            pChannel->commit_info_remote.max_htlc_value_in_flight_msat);
        goto LABEL_ERROR;
    }

    if (pReason && !pReason->len) {
        //forwarding only
        //  If channel_update has been received, it is checked whether it is disabled
        utl_buf_t buf = UTL_BUF_INIT;
        if (ln_channel_update_get_peer(pChannel, &buf, NULL)) {
            ln_msg_channel_update_t msg;
            if (!ln_msg_channel_update_read(&msg, buf.buf, buf.len) ||
                msg.channel_flags & LN_CNLUPD_CHFLAGS_DISABLE) {
                //B13. if the channel is disabled:
                //      channel_disabled
                //      (report the current channel setting for the outgoing channel.)
                LOGE("fail: channel_disabled\n");
                utl_push_t push;
                utl_push_init(
                    &push, pReason, sizeof(uint16_t) + sizeof(uint16_t) + buf.len);
                utl_push_u16be(&push, LNONION_CHAN_DISABLE);
                utl_push_u16be(&push, (uint16_t)buf.len);
                utl_push_data(&push, buf.buf, buf.len);
                goto LABEL_ERROR;
            }
        }
    }
    return true;

LABEL_ERROR:
    if (pReason && !pReason->len) {
        //failure && forwarding only
        utl_buf_t buf = UTL_BUF_INIT;
        if (ln_channel_update_get_peer(pChannel, &buf, NULL)) {
            //B4. if during forwarding to its receiving peer, an otherwise unspecified, transient error occurs in the outgoing channel (e.g. channel capacity reached, too many in-flight HTLCs, etc.):
            //      temporary_channel_failure
            LOGE("fail: temporary_channel_failure\n");
            utl_push_t push;
            utl_push_init(
                &push, pReason, sizeof(uint16_t) + sizeof(uint16_t) + buf.len);
            utl_push_u16be(&push, LNONION_TMP_CHAN_FAIL);
            utl_push_u16be(&push, (uint16_t)buf.len);
            utl_push_data(&push, buf.buf, buf.len);
        } else {
            //B5. if an otherwise unspecified, permanent error occurs during forwarding to its receiving peer (e.g. channel recently closed):
            //      permanent_channel_failure
            LOGE("fail: permanent_channel_failure\n");
            utl_push_t push;
            utl_push_init(&push, pReason, sizeof(uint16_t));
            utl_push_u16be(&push, LNONION_PERM_CHAN_FAIL);
        }
    }
    return false;
}


static bool set_add_htlc(
    ln_channel_t *pChannel, uint64_t *pHtlcId, utl_buf_t *pReason, uint16_t *pHtlcIdx,
    const uint8_t *pPacket, uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash,
    uint64_t PrevShortChannelId, uint16_t PrevHtlcIdx, const utl_buf_t *pSharedSecrets)
{
    LOGD("BEGIN\n");
    LOGD("  AmountMsat=%" PRIu64 "\n", AmountMsat);
    LOGD("  CltvValue=%d\n", CltvValue);
    LOGD("  paymentHash=");
    DUMPD(pPaymentHash, BTC_SZ_HASH256);
    LOGD("  PrevShortChannelId=%016" PRIx64 "\n", PrevShortChannelId);

    ln_update_t *p_update = NULL;
    ln_htlc_t *p_htlc = NULL;
    uint16_t update_idx;
    uint16_t htlc_idx;

    if (!check_create_add_htlc(pChannel, pReason, AmountMsat, CltvValue)) {
        LOGE("fail: create update_add_htlc\n");
        return false;
    }
    if (!ln_update_get_empty(pChannel->updates, &update_idx)) {
        M_SET_ERR(pChannel, LNERR_HTLC_FULL, "no free updates");
        return false;
    }
    if (!ln_htlc_get_empty(pChannel->htlcs, &htlc_idx)) {
        M_SET_ERR(pChannel, LNERR_HTLC_FULL, "no free htlcs");
        return false;
    }
    p_update = &pChannel->updates[update_idx];
    p_htlc = &pChannel->htlcs[htlc_idx];
    p_update->htlc_idx = htlc_idx;
    p_update->enabled = true;
    p_htlc->enabled = true;
    LOGD("OK\n");

    p_htlc->id = pChannel->next_htlc_id++;
        //XXX: Add on sending (Then a natural value is added at the time of resend at reestablish)
    p_htlc->amount_msat = AmountMsat;
    p_htlc->cltv_expiry = CltvValue;
    memcpy(p_htlc->payment_hash, pPaymentHash, BTC_SZ_HASH256);
    utl_buf_alloccopy(&p_htlc->buf_onion_reason, pPacket, LN_SZ_ONION_ROUTE);
    p_htlc->neighbor_short_channel_id = PrevShortChannelId;
    p_htlc->neighbor_idx = PrevHtlcIdx;
    utl_buf_free(&p_htlc->buf_shared_secret);
    if (pSharedSecrets) {
        if (!utl_buf_alloccopy(
            &p_htlc->buf_shared_secret, pSharedSecrets->buf, pSharedSecrets->len)) {
            LOGD("clear_htlc: %016" PRIx64 " UPDATE[%u], HTLC[%u]\n",
                pChannel->short_channel_id, update_idx, htlc_idx);
            clear_htlc(pChannel, update_idx);
            return false;
        }
    }

    if (!check_create_remote_commit_tx(pChannel, update_idx)) {
        M_SET_ERR(pChannel, LNERR_MSG_ERROR, "create remote commit_tx(check)");
        LOGD("clear_htlc: %016" PRIx64 " UPDATE[%u], HTLC[%u]\n",
            pChannel->short_channel_id, update_idx, htlc_idx);
        clear_htlc(pChannel, update_idx);
        return false;
    }

    *pHtlcIdx = htlc_idx;
    *pHtlcId = p_htlc->id;
    LOGD("HTLC add : neighbor_short_channel_id=%" PRIu64 "\n", p_htlc->neighbor_short_channel_id);
    LOGD("           pChannel->updates[%u].flags = 0x%04x\n", update_idx, p_update->flags);
    return true;
}


/** send update_add_htlc
 *
 * @param[in,out]       pChannel        channel情報
 * @param[in]           UpdateIdx             生成するHTLCの内部管理index値
 */
static bool update_add_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    LOGD("pChannel->updates[%u].flags = 0x%04x\n", UpdateIdx, pChannel->updates[UpdateIdx].flags);
    ln_update_t *p_update = &pChannel->updates[UpdateIdx];
    ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];

    ln_msg_update_add_htlc_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.id = p_htlc->id;
    msg.amount_msat = p_htlc->amount_msat;
    msg.p_payment_hash = p_htlc->payment_hash;
    msg.cltv_expiry = p_htlc->cltv_expiry;
    msg.p_onion_routing_packet = p_htlc->buf_onion_reason.buf;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_update_add_htlc_write(&buf, &msg)) {
        M_SEND_ERR(pChannel, LNERR_ERROR, "internal error: add_htlc");
        return false;
    }
    p_update->flags.up_send = 1;
    LOGD("send: %s\n", ln_msg_name(utl_int_pack_u16be(buf.buf)));
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


/** send update_fulfill_htlc
 *
 * @param[in,out]       pChannel        channel情報
 * @param[in]           UpdateIdx       index of the updates
 */
static bool update_fulfill_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    LOGD("pChannel->updates[%u].flags = 0x%04x\n", UpdateIdx, pChannel->updates[UpdateIdx].flags);
    ln_update_t *p_update = &pChannel->updates[UpdateIdx];
    ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];

    ln_msg_update_fulfill_htlc_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.id = p_htlc->id;
    msg.p_payment_preimage = p_htlc->buf_payment_preimage.buf;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_update_fulfill_htlc_write(&buf, &msg)) {
        M_SEND_ERR(pChannel, LNERR_ERROR, "internal error: fulfill_htlc");
        return false;
    }
    p_update->flags.up_send = 1;
    LOGD("send: %s\n", ln_msg_name(utl_int_pack_u16be(buf.buf)));
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


/** send update_fail_htlc
 *
 * @param[in,out]       pChannel        channel情報
 * @param[in]           UpdateIdx       index of the updates
 */
static bool update_fail_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    LOGD("pChannel->updates[%u].flags = 0x%04x\n", UpdateIdx, pChannel->updates[UpdateIdx].flags);
    ln_update_t *p_update = &pChannel->updates[UpdateIdx];
    ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];

    ln_msg_update_fail_htlc_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.id = p_htlc->id;
    msg.len = p_htlc->buf_onion_reason.len;
    msg.p_reason = p_htlc->buf_onion_reason.buf;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_update_fail_htlc_write(&buf, &msg)) {
        M_SEND_ERR(pChannel, LNERR_ERROR, "internal error: fail_htlc");
        return false;
    }
    p_update->flags.up_send = 1;
    LOGD("send: %s\n", ln_msg_name(utl_int_pack_u16be(buf.buf)));
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    return true;
}


/** send update_fail_malformed_htlc
 *
 * @param[in,out]       pChannel        channel情報
 * @param[in]           UpdateIdx       index of the updates
 */
static bool update_fail_malformed_htlc_send(ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    LOGD("pChannel->updates[%u].flags = 0x%04x\n", UpdateIdx, pChannel->updates[UpdateIdx].flags);
    ln_update_t *p_update = &pChannel->updates[UpdateIdx];
    ln_htlc_t *p_htlc = &pChannel->htlcs[p_update->htlc_idx];

    ln_msg_update_fail_malformed_htlc_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.id = p_htlc->id;
    msg.p_sha256_of_onion = p_htlc->buf_onion_reason.buf + sizeof(uint16_t);
    msg.failure_code = utl_int_pack_u16be(p_htlc->buf_onion_reason.buf);
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_update_fail_malformed_htlc_write(&buf, &msg)) {
        M_SEND_ERR(pChannel, LNERR_ERROR, "internal error: malformed_htlc");
        return false;
    }
    p_update->flags.up_send = 1;
    LOGD("send: %s\n", ln_msg_name(utl_int_pack_u16be(buf.buf)));
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    return true;
}


static bool check_create_remote_commit_tx(ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    bool ret = false;

    ln_update_t *p_update = &pChannel->updates[UpdateIdx];
    ln_commit_info_t new_commit_info = pChannel->commit_info_remote;
    new_commit_info.commit_num++;

    ln_update_t bak = *p_update;
    LN_UPDATE_REMOTE_ENABLE_ADD_HTLC_RECV(p_update);
    uint8_t (*p_htlc_sigs)[LN_SZ_SIGNATURE] = NULL;
    if (!ln_comtx_create_remote(pChannel, &new_commit_info, NULL, &p_htlc_sigs)) {
        M_SET_ERR(pChannel, LNERR_MSG_ERROR, "create remote commit_tx(check)");
        goto LABEL_EXIT;
    }

    ret = true;

LABEL_EXIT:
    *p_update = bak;
    UTL_DBG_FREE(p_htlc_sigs);
    return ret;
}


static uint64_t htlc_value_in_flight_msat(ln_channel_t *pChannel, bool bLocal)
{
    uint64_t value = 0;
    for (uint16_t idx; idx < LN_UPDATE_MAX; idx++) {
        ln_update_t *p_update = &pChannel->updates[idx];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (LN_UPDATE_ADD_HTLC_RECV_ENABLED(p_update, bLocal)) {
            value += pChannel->htlcs[p_update->htlc_idx].amount_msat;
        }
        if (LN_UPDATE_DEL_HTLC_SEND_ENABLED(p_update, bLocal)) {
            value -= pChannel->htlcs[p_update->htlc_idx].amount_msat;
        }
    }
    return value;
}


static uint64_t htlc_value_in_flight_msat_local(ln_channel_t *pChannel)
{
    return htlc_value_in_flight_msat(pChannel, true);
}


static uint64_t htlc_value_in_flight_msat_remote(ln_channel_t *pChannel)
{
    return htlc_value_in_flight_msat(pChannel, false);
}

