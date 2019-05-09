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
/** @file   ln_establish.c
 *  @brief  ln_establish
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
#include "ln_commit_tx_util.h"
#include "ln_derkey.h"
#include "ln_script.h"
#include "ln.h"
#include "ln_msg_establish.h"
#include "ln_local.h"
#include "ln_setupctl.h"
#include "ln_close.h"
#include "ln_establish.h"


/**************************************************************************
 * macros
 **************************************************************************/

//feerate: receive open_channel
// #define M_FEERATE_CHK_MIN_OK(local,remote)   ( 0.5 * (local) < 1.0 * (remote))  ///< feerate_per_kwのmin判定
// #define M_FEERATE_CHK_MAX_OK(local,remote)   (10.0 * (local) > 1.0 * (remote))  ///< feerate_per_kwのmax判定
#define M_FEERATE_CHK_MIN_OK(local,remote)      (true)  ///< feerate_per_kwのmin判定(ALL OK)
#define M_FEERATE_CHK_MAX_OK(local,remote)      (true)  ///< feerate_per_kwのmax判定(ALL OK)

#define M_FUNDING_INDEX                         (0)     ///< funding_txのvout


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool check_peer_node(ln_channel_t *pChannel);

static void start_funding_wait(ln_channel_t *pChannel, bool bSendTx);
static bool create_funding_tx(ln_channel_t *pChannel, bool bSign);


/**************************************************************************
 * public functions
 **************************************************************************/

bool /*HIDDEN*/ ln_open_channel_send(
    ln_channel_t *pChannel, uint64_t FundingSat, uint64_t PushMSat, uint32_t FeeRate,
    uint8_t PrivChannel)
{
    if (!M_INIT_FLAG_EXCHNAGED(pChannel->init_flag)) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "no init finished.");
        return false;
    }
    if (!check_peer_node(pChannel)) {
        M_SET_ERR(pChannel, LNERR_NO_PEER, "no peer node_id");
        return false;
    }
    if (ln_funding_info_funding_now(&pChannel->funding_info)) {
        M_SET_ERR(pChannel, LNERR_ALREADY_FUNDING, "already funding");
        return false;
    }
    if (FeeRate < LN_FEERATE_PER_KW_MIN) {
        //feerate_per_kw too low
        M_SET_ERR(pChannel, LNERR_INV_VALUE, "feerate_per_kw too low");
        return false;
    }

    //temporary_channel_id
    btc_rng_rand(pChannel->channel_id, LN_SZ_CHANNEL_ID);

    //open_channel
    ln_msg_open_channel_t msg;
    msg.p_chain_hash = ln_genesishash_get();
    msg.p_temporary_channel_id = pChannel->channel_id;
    msg.funding_satoshis = FundingSat;
    msg.push_msat = PushMSat;
    msg.dust_limit_satoshis = pChannel->establish.param.dust_limit_sat;
    if (pChannel->establish.param.max_htlc_value_in_flight_msat > LN_SATOSHI2MSAT(msg.funding_satoshis)) {
        msg.max_htlc_value_in_flight_msat = LN_SATOSHI2MSAT(msg.funding_satoshis);
    } else {
        msg.max_htlc_value_in_flight_msat = pChannel->establish.param.max_htlc_value_in_flight_msat;
    }
    msg.channel_reserve_satoshis = pChannel->establish.param.channel_reserve_sat;
    msg.htlc_minimum_msat = pChannel->establish.param.htlc_minimum_msat;
    msg.feerate_per_kw = FeeRate;
    msg.to_self_delay = pChannel->establish.param.to_self_delay;
    msg.max_accepted_htlcs = pChannel->establish.param.max_accepted_htlcs;
    msg.p_funding_pubkey = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING];
    msg.p_revocation_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_REVOCATION];
    msg.p_payment_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_PAYMENT];
    msg.p_delayed_payment_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_DELAYED];
    msg.p_htlc_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_HTLC];
    msg.p_first_per_commitment_point = pChannel->keys_local.per_commitment_point;
    if (PrivChannel != 0) {
        LOGD("private channel\n");
        msg.channel_flags = 0;
    } else {
        msg.channel_flags = CHANNEL_FLAGS_ANNOCNL;
    }
    msg.shutdown_len = 0;
    msg.p_shutdown_scriptpubkey = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_open_channel_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    pChannel->commit_info_local.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_info_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_info_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_info_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_info_local.max_accepted_htlcs = msg.max_accepted_htlcs;
    pChannel->commit_info_local.local_msat =
        pChannel->commit_info_remote.remote_msat =
        LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    pChannel->commit_info_local.remote_msat =
        pChannel->commit_info_remote.local_msat =
        msg.push_msat;
    pChannel->funding_info.funding_satoshis = msg.funding_satoshis;
    if (!ln_update_info_set_initial_fee_send(&pChannel->update_info, msg.feerate_per_kw)) return false;
    pChannel->commit_info_remote.to_self_delay = msg.to_self_delay;

    pChannel->funding_info.state =
        (ln_funding_state_t)(
            ((msg.channel_flags & CHANNEL_FLAGS_MASK) ? LN_FUNDING_STATE_STATE_NO_ANNO_CH : 0) |
            LN_FUNDING_STATE_STATE_FUNDING);
    pChannel->funding_info.role = LN_FUNDING_ROLE_FUNDER;
    return true;
}


bool HIDDEN ln_open_channel_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (ln_funding_info_is_funder(&pChannel->funding_info, true)) {
        M_SET_ERR(pChannel, LNERR_INV_SIDE, "not fundee");
        return false;
    }
    if (ln_funding_info_funding_now(&pChannel->funding_info)) {
        M_SET_ERR(pChannel, LNERR_ALREADY_FUNDING, "already funding");
        return false;
    }
    if (pChannel->short_channel_id != 0) {
        M_SET_ERR(pChannel, LNERR_ALREADY_FUNDING, "already established");
        return false;
    }

    ln_msg_open_channel_t msg;
    if (!ln_msg_open_channel_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(pChannel->channel_id, msg.p_temporary_channel_id, LN_SZ_CHANNEL_ID);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING], msg.p_funding_pubkey, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_REVOCATION], msg.p_revocation_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_PAYMENT], msg.p_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_DELAYED], msg.p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_HTLC], msg.p_htlc_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.per_commitment_point, msg.p_first_per_commitment_point, BTC_SZ_PUBKEY);

    if (memcmp(ln_genesishash_get(), msg.p_chain_hash, BTC_SZ_HASH256)) {
        LOGE("fail: chain_hash mismatch\n");
        return false;
    }

    //check feerate_per_kw
    uint32_t feerate_per_kw;
    ln_callback(pChannel, LN_CB_TYPE_GET_LATEST_FEERATE, &feerate_per_kw);
    if ( (msg.feerate_per_kw < LN_FEERATE_PER_KW_MIN) ||
         !M_FEERATE_CHK_MIN_OK(feerate_per_kw, msg.feerate_per_kw) ) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "%s", "fail: feerate_per_kw is too low");
        return false;
    }
    if (!M_FEERATE_CHK_MAX_OK(feerate_per_kw, msg.feerate_per_kw)) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "%s", "fail: feerate_per_kw is too large");
        return false;
    }

    if (msg.funding_satoshis < LN_FUNDING_SATOSHIS_MIN) {
        char str[256];
        snprintf(str, sizeof(str), "funding_satoshis too low(%" PRIu64 " < %d)",
            msg.funding_satoshis, LN_FUNDING_SATOSHIS_MIN);
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "%s", str);
        return false;
    }

    //BOLT02
    //  The sender:
    //      - MUST set channel_reserve_satoshis greater than or equal to dust_limit_satoshis from the open_channel message.
    //      - MUST set dust_limit_satoshis less than or equal to channel_reserve_satoshis from the open_channel message.
    if (pChannel->establish.param.channel_reserve_sat < msg.dust_limit_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "local channel_reserve_satoshis is lower than remote dust_limit_satoshis");
        return false;
    }
    if (pChannel->establish.param.dust_limit_sat > msg.channel_reserve_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "local dust_limit_satoshis is greater than remote channel_reserve_satoshis");
        return false;
    }

    //params for commit_info_remote
    pChannel->commit_info_remote.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_info_remote.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_info_remote.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_info_remote.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_info_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    pChannel->commit_info_local.to_self_delay = msg.to_self_delay; //XXX:

    //copy first_per_commitment_point for the first revoke_and_ack
    memcpy(pChannel->keys_remote.prev_per_commitment_point, pChannel->keys_remote.per_commitment_point, BTC_SZ_PUBKEY);

    //params for funding
    pChannel->funding_info.funding_satoshis = msg.funding_satoshis;
    if (!ln_update_info_set_initial_fee_recv(&pChannel->update_info, msg.feerate_per_kw)) return false;
    pChannel->commit_info_remote.remote_msat =
        pChannel->commit_info_local.local_msat =
        msg.push_msat;
    pChannel->commit_info_remote.local_msat =
        pChannel->commit_info_local.remote_msat =
        LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    pChannel->funding_info.state = (ln_funding_state_t)(
        ((msg.channel_flags & 1) ? LN_FUNDING_STATE_STATE_NO_ANNO_CH : 0) |
        LN_FUNDING_STATE_STATE_FUNDING);

    //generate keys
    ln_derkey_update_script_pubkeys(&pChannel->keys_local, &pChannel->keys_remote);
    ln_print_keys(pChannel);

    if (!ln_accept_channel_send(pChannel)) {
        LOGE("fail: send accept_channel\n");
        return false;
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_accept_channel_send(ln_channel_t *pChannel)
{
    ln_msg_accept_channel_t msg;
    msg.p_temporary_channel_id = pChannel->channel_id;
    msg.dust_limit_satoshis = pChannel->establish.param.dust_limit_sat;
    msg.max_htlc_value_in_flight_msat = pChannel->establish.param.max_htlc_value_in_flight_msat;
    msg.channel_reserve_satoshis = pChannel->establish.param.channel_reserve_sat;
    msg.htlc_minimum_msat = pChannel->establish.param.htlc_minimum_msat;
    msg.minimum_depth = pChannel->establish.param.min_depth;
    msg.to_self_delay = pChannel->establish.param.to_self_delay;
    msg.max_accepted_htlcs = pChannel->establish.param.max_accepted_htlcs;
    msg.p_funding_pubkey = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING];
    msg.p_revocation_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_REVOCATION];
    msg.p_payment_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_PAYMENT];
    msg.p_delayed_payment_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_DELAYED];
    msg.p_htlc_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_HTLC];
    msg.p_first_per_commitment_point = pChannel->keys_local.per_commitment_point;
    msg.shutdown_len = 0;
    msg.p_shutdown_scriptpubkey = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_accept_channel_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    pChannel->funding_info.minimum_depth = msg.minimum_depth;
    pChannel->commit_info_local.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_info_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_info_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_info_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_info_local.max_accepted_htlcs = msg.max_accepted_htlcs;

    pChannel->commit_info_remote.to_self_delay = msg.to_self_delay; //XXX:

    //obscured commitment tx number
    pChannel->commit_info_local.obscured_commit_num_mask =
        pChannel->commit_info_remote.obscured_commit_num_mask =
        ln_commit_tx_calc_obscured_commit_num_mask(
            pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_PAYMENT],
            pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_PAYMENT]);
    LOGD("obscured_commit_num_mask=0x%016" PRIx64 "\n", pChannel->commit_info_local.obscured_commit_num_mask);

    //vout 2-of-2
    if (!btc_script_2of2_create_redeem_sorted(&pChannel->funding_info.wit_script, &pChannel->funding_info.key_order,
        pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING], pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING])) {
        M_SET_ERR(pChannel, LNERR_CREATE_2OF2, "create 2-of-2");
        return false;
    }
    return true;
}


bool HIDDEN ln_accept_channel_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!ln_funding_info_is_funder(&pChannel->funding_info, true)) {
        M_SET_ERR(pChannel, LNERR_INV_SIDE, "not funder");
        return false;
    }

    ln_msg_accept_channel_t msg;
    if (!ln_msg_accept_channel_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING], msg.p_funding_pubkey, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_REVOCATION], msg.p_revocation_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_PAYMENT], msg.p_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_DELAYED], msg.p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_HTLC], msg.p_htlc_basepoint, BTC_SZ_PUBKEY);
    memcpy(pChannel->keys_remote.per_commitment_point, msg.p_first_per_commitment_point, BTC_SZ_PUBKEY);

    //temporary_channel_id
    if (!ln_check_channel_id(msg.p_temporary_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //BOLT02
    // The receiver:
    //  - if channel_reserve_satoshis is less than dust_limit_satoshis within the open_channel message:
    //   - MUST reject the channel.
    //  - if channel_reserve_satoshis from the open_channel message is less than dust_limit_satoshis:
    //   - MUST reject the channel. Other fields have the same requirements as their counterparts in open_channel.
    if (pChannel->commit_info_local.dust_limit_sat > msg.channel_reserve_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "local dust_limit_satoshis is greater than remote channel_reserve_satoshis");
        return false;
    }
    if (pChannel->commit_info_local.channel_reserve_sat < msg.dust_limit_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "local channel_reserve_satoshis is lower than remote dust_limit_satoshis");
        return false;
    }

    pChannel->funding_info.minimum_depth = msg.minimum_depth;
    pChannel->commit_info_remote.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_info_remote.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_info_remote.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_info_remote.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_info_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    pChannel->commit_info_local.to_self_delay = msg.to_self_delay; //XXX:

    //first_per_commitment_pointは初回revoke_and_ackのper_commitment_secretに対応する
    memcpy(pChannel->keys_remote.prev_per_commitment_point, pChannel->keys_remote.per_commitment_point, BTC_SZ_PUBKEY);

    //generate keys
    ln_derkey_update_script_pubkeys(&pChannel->keys_local, &pChannel->keys_remote);
    ln_print_keys(pChannel);

    //create funding_tx
    if (!create_funding_tx(pChannel, true)) {
        M_SET_ERR(pChannel, LNERR_CREATE_TX, "create funding_tx");
        return false;
    }

    //obscured commitment tx number
    pChannel->commit_info_remote.obscured_commit_num_mask =
        pChannel->commit_info_local.obscured_commit_num_mask =
        ln_commit_tx_calc_obscured_commit_num_mask(pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_PAYMENT],
        pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_PAYMENT]);
    LOGD("obscured_commit_num_mask=0x%016" PRIx64 "\n", pChannel->commit_info_remote.obscured_commit_num_mask);

    //initial commit tx(Remoteが持つTo-Local)
    if (!ln_commit_tx_create_remote(
        &pChannel->commit_info_remote, &pChannel->update_info,
        &pChannel->keys_local, &pChannel->keys_remote, NULL)) {
        LOGE("fail: ???\n");
        return false;
    }

    if (!ln_funding_created_send(pChannel)) {
        //XXX:
        return false;
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_funding_created_send(ln_channel_t *pChannel)
{
    ln_msg_funding_created_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    msg.p_temporary_channel_id = pChannel->channel_id;
    msg.p_funding_txid = ln_funding_info_txid(&pChannel->funding_info);
    msg.funding_output_index = ln_funding_info_txindex(&pChannel->funding_info);
    msg.p_signature = pChannel->commit_info_remote.remote_sig;
    ln_msg_funding_created_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_funding_created_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (ln_funding_info_is_funder(&pChannel->funding_info, true)) {
        M_SET_ERR(pChannel, LNERR_INV_SIDE, "not fundee");
        return false;
    }

    ln_msg_funding_created_t msg;
    if (!ln_msg_funding_created_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    ln_funding_info_set_txid(&pChannel->funding_info, msg.p_funding_txid);
    memcpy(pChannel->commit_info_local.remote_sig, msg.p_signature, LN_SZ_SIGNATURE);

    //temporary_channel_id
    if (!ln_check_channel_id(msg.p_temporary_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    pChannel->funding_info.txindex = msg.funding_output_index;

    //署名チェック用
    btc_tx_free(&pChannel->funding_info.tx_data);
    for (uint32_t lp = 0; lp < ln_funding_info_txindex(&pChannel->funding_info); lp++) {
        //処理の都合上、voutの位置を調整している
        btc_tx_add_vout(&pChannel->funding_info.tx_data, 0);
    }
    btc_sw_add_vout_p2wsh_wit(
        &pChannel->funding_info.tx_data, pChannel->funding_info.funding_satoshis, &pChannel->funding_info.wit_script);
    //TODO: 実装上、vinが0、voutが1だった場合にsegwitと誤認してしまう
    btc_tx_add_vin(&pChannel->funding_info.tx_data, ln_funding_info_txid(&pChannel->funding_info), 0);

    //verify sign
    //  initial commit tx(自分が持つTo-Local)
    if (!ln_commit_tx_create_local(
        &pChannel->commit_info_local, &pChannel->update_info,
        &pChannel->keys_local, NULL, 0)) {
        LOGE("fail: create_to_local\n");
        return false;
    }

    //initial commit tx(Remoteが持つTo-Local)
    if (!ln_commit_tx_create_remote(
        &pChannel->commit_info_remote, &pChannel->update_info,
        &pChannel->keys_local, &pChannel->keys_remote, NULL)) {
        LOGE("fail: ???\n");
        return false;
    }

    //temporary_channel_id -> channel_id
    ln_channel_id_calc(pChannel->channel_id, ln_funding_info_txid(&pChannel->funding_info), ln_funding_info_txindex(&pChannel->funding_info));

    if (!ln_funding_signed_send(pChannel)) {
        //XXX:
        return false;
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_funding_signed_send(ln_channel_t *pChannel)
{
    ln_msg_funding_signed_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.p_signature = pChannel->commit_info_remote.remote_sig;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_funding_signed_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    //wait funding_tx
    start_funding_wait(pChannel, false);
    return true;
}


bool HIDDEN ln_funding_signed_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!ln_funding_info_is_funder(&pChannel->funding_info, true)) {
        M_SET_ERR(pChannel, LNERR_INV_SIDE, "not funder");
        return false;
    }

    ln_msg_funding_signed_t msg;
    if (!ln_msg_funding_signed_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(pChannel->commit_info_local.remote_sig, msg.p_signature, LN_SZ_SIGNATURE);

    //channel_id
    ln_channel_id_calc(
        pChannel->channel_id, ln_funding_info_txid(&pChannel->funding_info), ln_funding_info_txindex(&pChannel->funding_info));
    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //initial commit tx(自分が持つTo-Local)
    //  HTLCは存在しない
    if (!ln_commit_tx_create_local(
        &pChannel->commit_info_local, &pChannel->update_info,
        &pChannel->keys_local, NULL, 0)) {
        LOGE("fail: create_to_local\n");
        return false;
    }

    //funding_tx安定待ち
    start_funding_wait(pChannel, true);

    LOGD("END\n");
    return true;
}


bool /*HIDDEN*/ ln_funding_locked_send(ln_channel_t *pChannel)
{
    LOGD("\n");

    ln_msg_funding_locked_t msg;
    msg.p_channel_id = pChannel->channel_id;
    msg.p_next_per_commitment_point = pChannel->keys_local.per_commitment_point;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_funding_locked_write(&buf, &msg)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    //channel_reestablishと同じ扱いにする
    pChannel->init_flag |= M_INIT_FLAG_REEST_SEND;

    LN_DBG_COMMIT_NUM_PRINT(pChannel);
    return true;
}


/*
 * funding_lockedはお互い送信し合うことになる。
 *      open_channel送信側: funding_signed受信→funding_tx安定待ち→funding_locked送信→funding_locked受信→完了
 *      open_channel受信側: funding_locked受信→funding_tx安定待ち→完了
 *
 * funding_tx安定待ちで一度シーケンスが止まる。
 */
bool HIDDEN ln_funding_locked_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_funding_locked_t msg;
    if (!ln_msg_funding_locked_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel_id
    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    LOGV("prev: ");
    DUMPV(pChannel->keys_remote.per_commitment_point, BTC_SZ_PUBKEY);
    LOGV("next: ");
    DUMPV(msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);

    //pubkeys.prev_per_commitment_pointはrevoke_and_ackでのみ更新する
    memcpy(pChannel->keys_remote.per_commitment_point, msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);

    //funding中終了
    ln_establish_free(pChannel);

    ln_derkey_update_script_pubkeys(&pChannel->keys_local, &pChannel->keys_remote);
    ln_print_keys(pChannel);
    M_DB_CHANNEL_SAVE(pChannel);

    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV, NULL);

    //channel_reestablishと同じ扱いにする
    pChannel->init_flag |= M_INIT_FLAG_REEST_RECV;

    LN_DBG_COMMIT_NUM_PRINT(pChannel);

    LOGD("END\n");
    return true;
}


bool /*HIDDEN*/ ln_channel_reestablish_send(ln_channel_t *pChannel)
{
    ln_msg_channel_reestablish_t msg;
    uint8_t your_last_per_commitment_secret[BTC_SZ_PRIVKEY] = {0};
    uint8_t my_current_per_commitment_point[BTC_SZ_PUBKEY] = {0};
    msg.p_channel_id = pChannel->channel_id;
    msg.p_your_last_per_commitment_secret = your_last_per_commitment_secret;
    msg.p_my_current_per_commitment_point = my_current_per_commitment_point;

    LN_DBG_COMMIT_NUM_PRINT(pChannel);

    //MUST set next_local_commitment_number to the commitment number
    //  of the next commitment_signed it expects to receive.
    msg.next_local_commitment_number = pChannel->commit_info_local.commit_num + 1;
    //MUST set next_remote_revocation_number to the commitment number
    //  of the next revoke_and_ack message it expects to receive.
    msg.next_remote_revocation_number = pChannel->commit_info_remote.revoke_num + 1;

    //option_data_loss_protect
    bool option_data_loss_protect = false;
    if (pChannel->lfeature_local & LN_INIT_LF_OPT_DATALOSS) {
        option_data_loss_protect = true;

        if (pChannel->commit_info_remote.commit_num) {
            if (!ln_derkey_remote_storage_get_secret(
                &pChannel->keys_remote, your_last_per_commitment_secret,
                (uint64_t)(LN_SECRET_INDEX_INIT - pChannel->commit_info_remote.revoke_num))) {
                LOGD("no last secret\n");
                memset(your_last_per_commitment_secret, 0, BTC_SZ_PRIVKEY);
            }
        }

        uint8_t secret_buf[BTC_SZ_PRIVKEY];
        ln_derkey_local_storage_create_prev_per_commitment_secret(&pChannel->keys_local, secret_buf, my_current_per_commitment_point);
    }

    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_channel_reestablish_write(&buf, &msg, option_data_loss_protect)) return false;
    ln_callback(pChannel, LN_CB_TYPE_SEND_MESSAGE, &buf);
    utl_buf_free(&buf);

    pChannel->init_flag |= M_INIT_FLAG_REEST_SEND;
    if (M_INIT_FLAG_REEST_EXCHNAGED(pChannel->init_flag)) {
        ln_channel_reestablish_after(pChannel);
    }
    return true;
}


bool HIDDEN ln_channel_reestablish_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_channel_reestablish_t msg;
    bool option_data_loss_protect = (pChannel->lfeature_local & LN_INIT_LF_OPT_DATALOSS);
    if (!ln_msg_channel_reestablish_read(&msg, pData, Len, option_data_loss_protect)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    option_data_loss_protect =
        option_data_loss_protect &&
        msg.p_your_last_per_commitment_secret &&
        msg.p_my_current_per_commitment_point;

    //channel_id
    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    LN_DBG_COMMIT_NUM_PRINT(pChannel);
    pChannel->reest_next_local_commit_num = msg.next_local_commitment_number;
    pChannel->reest_next_remote_revoke_num = msg.next_remote_revocation_number;

    //BOLT#02
    //  commit_txは、作成する関数内でcommit_num+1している(インクリメントはしない)。
    //  そのため、(commit_num+1)がcommit_tx作成時のcommitment numberである。

    //  next_local_commitment_number
    bool chk_commit_num = true;
    if (pChannel->commit_info_remote.commit_num + 1 == msg.next_local_commitment_number) {
        LOGD("next_local_commitment_number: OK\n");
    } else if (pChannel->commit_info_remote.commit_num == msg.next_local_commitment_number) {
        //  if next_local_commitment_number is equal to the commitment number of the last commitment_signed message the receiving node has sent:
        //      * MUST reuse the same commitment number for its next commitment_signed.
        LOGD("next_local_commitment_number == remote commit_num: reuse\n");
    } else {
        // if next_local_commitment_number is not 1 greater than the commitment number of the last commitment_signed message the receiving node has sent:
        //      * SHOULD fail the channel.
        LOGE("fail: next commitment number[%" PRIu64 "(expect) != %" PRIu64 "(recv)]\n", pChannel->commit_info_remote.commit_num + 1, msg.next_local_commitment_number);
        chk_commit_num = false;
    }

    //BOLT#02
    //  next_remote_revocation_number
    bool chk_revoke_num = true;
    if (pChannel->commit_info_local.revoke_num + 1 == msg.next_remote_revocation_number) {
        LOGD("next_remote_revocation_number: OK\n");
    } else if (pChannel->commit_info_local.revoke_num == msg.next_remote_revocation_number) {
        // if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack the receiving node sent, AND the receiving node hasn't already received a closing_signed:
        //      * MUST re-send the revoke_and_ack.
        LOGD("next_remote_revocation_number == local commit_num: resend\n");
    } else {
        LOGE("fail: next revocation number[%" PRIu64 "(expect) != %" PRIu64 "(recv)]\n", pChannel->commit_info_local.revoke_num + 1, msg.next_remote_revocation_number);
        chk_revoke_num = false;
    }

    //BOLT#2
    //  if it supports option_data_loss_protect, AND the option_data_loss_protect fields are present:
    if ( !(chk_commit_num && chk_revoke_num) && option_data_loss_protect ) {
        //if next_remote_revocation_number is greater than expected above,
        if (msg.next_remote_revocation_number > pChannel->commit_info_local.commit_num) { //XXX: ?
            //  AND your_last_per_commitment_secret is correct for that next_remote_revocation_number minus 1:
            uint8_t secret[BTC_SZ_PRIVKEY];
            ln_derkey_local_storage_create_per_commitment_secret(&pChannel->keys_local, secret, LN_SECRET_INDEX_INIT - (msg.next_remote_revocation_number - 1));
            //LOGD("secret: ");
            //DUMPD(secret, BTC_SZ_PRIVKEY);
            if (memcmp(secret, msg.p_your_last_per_commitment_secret, BTC_SZ_PRIVKEY) == 0) {
                //MUST NOT broadcast its commitment transaction.
                //SHOULD fail the channel.
                //SHOULD store my_current_per_commitment_point to retrieve funds should the sending node broadcast its commitment transaction on-chain.
                LOGE("MUST NOT broadcast its commitment transaction\n");
            } else {
                //SHOULD fail the channel.
                LOGE("SHOULD fail the channel\n");
                goto LABEL_ERROR;
            }
        } else {
            //SHOULD fail the channel.
            LOGE("SHOULD fail the channel\n");
            goto LABEL_ERROR;
        }
    }

    ln_callback(pChannel, LN_CB_TYPE_NOTIFY_REESTABLISH_RECV, NULL);

    pChannel->init_flag |= M_INIT_FLAG_REEST_RECV;
    if (M_INIT_FLAG_REEST_EXCHNAGED(pChannel->init_flag)) {
        ln_channel_reestablish_after(pChannel);
    }
    return true;

LABEL_ERROR:
    return false;
}


void ln_channel_reestablish_before(ln_channel_t *pChannel)
{
    bool updated = false;
    ln_update_info_clear_pending_updates(&pChannel->update_info, &updated);
    ln_shutdown_reset(pChannel);
}


void ln_channel_reestablish_after(ln_channel_t *pChannel)
{
    LN_DBG_COMMIT_NUM_PRINT(pChannel);
    LN_DBG_UPDATES_PRINT(pChannel->update_info.updates);

    LOGD("pChannel->reest_next_remote_revoke_num=%" PRIu64 "\n", pChannel->reest_next_remote_revoke_num);
    LOGD("pChannel->reest_next_local_commit_num=%" PRIu64 "\n", pChannel->reest_next_local_commit_num);

    //
    //BOLT#02

    //  next_local_commitment_number
    if (pChannel->commit_info_remote.commit_num == pChannel->reest_next_local_commit_num) {
        //  if next_local_commitment_number is equal to the commitment number of the last commitment_signed message the receiving node has sent:
        //      * MUST reuse the same commitment number for its next commitment_signed.
        //remote.per_commitment_pointを1つ戻して、キャンセルされたupdateメッセージを再送する
        //XXX: If the corresponding `revoke_andk_ack` is received, channel should be failed
        LOGD("$$$ resend: previous update message\n");
        ln_commit_tx_rewind_one_commit_remote(&pChannel->commit_info_remote, &pChannel->update_info);
    }

    //  next_remote_revocation_number
    if (pChannel->commit_info_local.revoke_num == pChannel->reest_next_remote_revoke_num) {
        // if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack the receiving node sent, AND the receiving node hasn't already received a closing_signed:
        //      * MUST re-send the revoke_and_ack.
        LOGD("$$$ next_remote_revocation_number == local commit_num: resend\n");

        //  for resending `revoke_and_ack`
        //    as we updated index at the first `revoke_and_ack`
        uint8_t prev_secret[BTC_SZ_PRIVKEY];
        ln_derkey_local_storage_create_second_prev_per_commitment_secret(&pChannel->keys_local, prev_secret, NULL);

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

static bool check_peer_node(ln_channel_t *pChannel)
{
    if (pChannel->peer_node_id[0] == 0x00) return false; //invalid value
    return true;
}


/** create funding_tx
 *
 * @param[in,out]       pChannel
 */
static bool create_funding_tx(ln_channel_t *pChannel, bool bSign)
{
    btc_tx_free(&pChannel->funding_info.tx_data);

    //vout 2-of-2
    btc_script_2of2_create_redeem_sorted(
        &pChannel->funding_info.wit_script, &pChannel->funding_info.key_order,
        pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING],
        pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING]);
    //sign
    if (!bSign) return true; //not sign

    utl_buf_t two_of_two = UTL_BUF_INIT;
    btc_script_p2wsh_create_scriptpk(&two_of_two, &pChannel->funding_info.wit_script);

    ln_cb_param_sign_funding_tx_t param;
    param.p_tx =  &pChannel->funding_info.tx_data;
    param.p_buf_scriptpk = &two_of_two;
    param.amount = pChannel->funding_info.funding_satoshis;
    ln_callback(pChannel, LN_CB_TYPE_SIGN_FUNDING_TX, &param);
    if (!param.ret) {
        LOGE("fail: signature\n");
        btc_tx_free(&pChannel->funding_info.tx_data);
        utl_buf_free(&two_of_two);
        return false;
    }

    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(&pChannel->funding_info.tx_data, txid);
    ln_funding_info_set_txid(&pChannel->funding_info, txid);
    LOGD("***** funding_tx *****\n");
    M_DBG_PRINT_TX(&pChannel->funding_info.tx_data);

    //search funding vout
    uint32_t lp;
    for (lp = 0; lp < pChannel->funding_info.tx_data.vout_cnt; lp++) {
        if (utl_buf_equal(&pChannel->funding_info.tx_data.vout[lp].script, &two_of_two)) break;
    }
    utl_buf_free(&two_of_two);
    if (lp == pChannel->funding_info.tx_data.vout_cnt) {
        //not found
        LOGE("fail: vout not found\n");
        btc_tx_free(&pChannel->funding_info.tx_data);
        return false;
    }
    pChannel->funding_info.txindex = lp;

    LOGD("funding_txindex=%d\n", ln_funding_info_txindex(&pChannel->funding_info));
    return true;
}


/** funding_tx minimum_depth待ち開始
 *
 * @param[in]   pChannel
 * @param[in]   bSendTx     true:funding_txをbroadcastする
 *
 * @note
 *      - funding_signed送信後あるいはfunding_tx展開後のみ呼び出す
 */
static void start_funding_wait(ln_channel_t *pChannel, bool bSendTx)
{
    ln_cb_param_wait_funding_tx_t funding;

    //commitment numberは0から始まる
    //  BOLT#0
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/00-introduction.md#glossary-and-terminology-guide
    //が、opening時を1回とカウントするので、Normal Operationでは1から始まる
    //  BOLT#2
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#rationale-10
    pChannel->commit_info_local.commit_num = 0;
    pChannel->commit_info_local.revoke_num = (uint64_t)-1;
    pChannel->commit_info_remote.commit_num = 0;
    pChannel->commit_info_remote.revoke_num = (uint64_t)-1;
    // pChannel->update_info.next_htlc_id = 0;
    // pChannel->short_channel_id = 0;

    //storage_next_indexデクリメントおよびper_commit_secret更新
    ln_derkey_local_storage_update_per_commitment_point(&pChannel->keys_local);
    ln_derkey_update_script_pubkeys(&pChannel->keys_local, &pChannel->keys_remote);

    //save the channel
    //  we should save the channel before broadcasting the funding tx
    //  don't forget it even if the process aborts
    pChannel->status = LN_STATUS_ESTABLISH;
    M_DB_SECRET_SAVE(pChannel);
    M_DB_CHANNEL_SAVE(pChannel);

    funding.b_send = bSendTx;
    if (bSendTx) {
        funding.p_tx_funding = &pChannel->funding_info.tx_data;
    }
    funding.ret = false;
    ln_callback(pChannel, LN_CB_TYPE_WAIT_FUNDING_TX, &funding);

    LN_DBG_COMMIT_NUM_PRINT(pChannel);
}
