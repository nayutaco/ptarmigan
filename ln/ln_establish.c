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
#include "ln_comtx.h"
#include "ln_comtx_util.h"
#include "ln_derkey.h"
#include "ln_script.h"
#include "ln.h"
#include "ln_msg_establish.h"
#include "ln_local.h"
#include "ln_setupctl.h"
#include "ln_establish.h"


/**************************************************************************
 * macros
 **************************************************************************/

//feerate: receive open_channel
// #define M_FEERATE_CHK_MIN_OK(our,their)     ( 0.5 * (our) < 1.0 * (their))  ///< feerate_per_kwのmin判定
// #define M_FEERATE_CHK_MAX_OK(our,their)     (10.0 * (our) > 1.0 * (their))  ///< feerate_per_kwのmax判定
#define M_FEERATE_CHK_MIN_OK(our,their)     (true)  ///< feerate_per_kwのmin判定(ALL OK)
#define M_FEERATE_CHK_MAX_OK(our,their)     (true)  ///< feerate_per_kwのmax判定(ALL OK)

#define M_FUNDING_INDEX                     (0)             ///< funding_txのvout


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
    ln_channel_t *pChannel, const ln_fundin_t *pFundin, uint64_t FundingSat, uint64_t PushSat, uint32_t FeeRate)
{
    if (!M_INIT_FLAG_EXCHNAGED(pChannel->init_flag)) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "no init finished.");
        return false;
    }
    if (!check_peer_node(pChannel)) {
        M_SET_ERR(pChannel, LNERR_NO_PEER, "no peer node_id");
        return false;
    }
    if (ln_is_funding(pChannel)) {
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

#if defined(USE_BITCOIND)
    pChannel->establish.p_fundin = (ln_fundin_t *)UTL_DBG_MALLOC(sizeof(ln_fundin_t));
    memcpy(pChannel->establish.p_fundin, pFundin, sizeof(ln_fundin_t));
#else
    (void)pFundin;
#endif

    //open_channel
    ln_msg_open_channel_t msg;
    msg.p_chain_hash = ln_genesishash_get();
    msg.p_temporary_channel_id = pChannel->channel_id;
    msg.funding_satoshis = FundingSat;
    msg.push_msat = LN_SATOSHI2MSAT(PushSat);
    msg.dust_limit_satoshis = pChannel->establish.estprm.dust_limit_sat;
    if (pChannel->establish.estprm.max_htlc_value_in_flight_msat > LN_SATOSHI2MSAT(msg.funding_satoshis)) {
        msg.max_htlc_value_in_flight_msat = LN_SATOSHI2MSAT(msg.funding_satoshis);
    } else {
        msg.max_htlc_value_in_flight_msat = pChannel->establish.estprm.max_htlc_value_in_flight_msat;
    }
    msg.channel_reserve_satoshis = pChannel->establish.estprm.channel_reserve_sat;
    msg.htlc_minimum_msat = pChannel->establish.estprm.htlc_minimum_msat;
    msg.feerate_per_kw = FeeRate;
    msg.to_self_delay = pChannel->establish.estprm.to_self_delay;
    msg.max_accepted_htlcs = pChannel->establish.estprm.max_accepted_htlcs;
    msg.p_funding_pubkey = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING];
    msg.p_revocation_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_REVOCATION];
    msg.p_payment_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_PAYMENT];
    msg.p_delayed_payment_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_DELAYED];
    msg.p_htlc_basepoint = pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_HTLC];
    msg.p_first_per_commitment_point = pChannel->keys_local.per_commitment_point;
    msg.channel_flags = CHANNEL_FLAGS_VALUE;
    msg.shutdown_len = 0;
    msg.p_shutdown_scriptpubkey = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_open_channel_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    pChannel->commit_tx_local.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_tx_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_tx_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_tx_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_tx_local.max_accepted_htlcs = msg.max_accepted_htlcs;
    pChannel->our_msat = LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    pChannel->their_msat = msg.push_msat;
    pChannel->funding_tx.funding_satoshis = msg.funding_satoshis;
    pChannel->feerate_per_kw = msg.feerate_per_kw;

    pChannel->commit_tx_remote.to_self_delay = msg.to_self_delay; //XXX:

    pChannel->fund_flag = (ln_fundflag_t)(LN_FUNDFLAG_FUNDER | ((msg.channel_flags & 1) ? LN_FUNDFLAG_NO_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);
    return true;
}


bool HIDDEN ln_open_channel_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (ln_is_funder(pChannel)) {
        M_SET_ERR(pChannel, LNERR_INV_SIDE, "not fundee");
        return false;
    }
    if (ln_is_funding(pChannel)) {
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
    ln_callback(pChannel, LN_CB_GET_LATEST_FEERATE, &pChannel->feerate_per_kw);
    if ( (msg.feerate_per_kw < LN_FEERATE_PER_KW_MIN) ||
         !M_FEERATE_CHK_MIN_OK(pChannel->feerate_per_kw, msg.feerate_per_kw) ) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "%s", "fail: feerate_per_kw is too low");
        return false;
    }
    if (!M_FEERATE_CHK_MAX_OK(pChannel->feerate_per_kw, msg.feerate_per_kw)) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "%s", "fail: feerate_per_kw is too large");
        return false;
    }

    uint64_t fee = ln_estimate_initcommittx_fee(msg.feerate_per_kw);
    if (msg.funding_satoshis < fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN) {
        char str[256];
        sprintf(str, "funding_satoshis too low(%" PRIu64 " < %" PRIu64 ")",
            msg.funding_satoshis, fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN);
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "%s", str);
        return false;
    }

    //BOLT02
    //  The sender:
    //      - MUST set channel_reserve_satoshis greater than or equal to dust_limit_satoshis from the open_channel message.
    //      - MUST set dust_limit_satoshis less than or equal to channel_reserve_satoshis from the open_channel message.
    if (pChannel->establish.estprm.channel_reserve_sat < msg.dust_limit_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "our channel_reserve_satoshis is lower than their dust_limit_satoshis");
        return false;
    }
    if (pChannel->establish.estprm.dust_limit_sat > msg.channel_reserve_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "our dust_limit_satoshis is greater than their channel_reserve_satoshis");
        return false;
    }

    //params for commit_tx_remote
    pChannel->commit_tx_remote.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_tx_remote.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_tx_remote.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_tx_remote.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_tx_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    pChannel->commit_tx_local.to_self_delay = msg.to_self_delay; //XXX:

    //copy first_per_commitment_point for the first revoke_and_ack
    memcpy(pChannel->keys_remote.prev_per_commitment_point, pChannel->keys_remote.per_commitment_point, BTC_SZ_PUBKEY);

    //params for funding
    pChannel->funding_tx.funding_satoshis = msg.funding_satoshis;
    pChannel->feerate_per_kw = msg.feerate_per_kw;
    pChannel->our_msat = msg.push_msat;
    pChannel->their_msat = LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    pChannel->fund_flag = (ln_fundflag_t)(((msg.channel_flags & 1) ? LN_FUNDFLAG_NO_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);

    //generate keys
    ln_update_script_pubkeys(pChannel);
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
    msg.dust_limit_satoshis = pChannel->establish.estprm.dust_limit_sat;
    msg.max_htlc_value_in_flight_msat = pChannel->establish.estprm.max_htlc_value_in_flight_msat;
    msg.channel_reserve_satoshis = pChannel->establish.estprm.channel_reserve_sat;
    msg.htlc_minimum_msat = pChannel->establish.estprm.htlc_minimum_msat;
    msg.minimum_depth = pChannel->establish.estprm.min_depth;
    msg.to_self_delay = pChannel->establish.estprm.to_self_delay;
    msg.max_accepted_htlcs = pChannel->establish.estprm.max_accepted_htlcs;
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
    ln_callback(pChannel, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    pChannel->min_depth = msg.minimum_depth;
    pChannel->commit_tx_local.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_tx_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_tx_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_tx_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_tx_local.max_accepted_htlcs = msg.max_accepted_htlcs;

    pChannel->commit_tx_remote.to_self_delay = msg.to_self_delay; //XXX:

    //obscured commitment tx number
    pChannel->obscured_commit_num_mask = ln_comtx_calc_obscured_commit_num_mask(
        pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_PAYMENT], pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_PAYMENT]);
    LOGD("obscured_commit_num_mask=0x%016" PRIx64 "\n", pChannel->obscured_commit_num_mask);

    //vout 2-of-2
    if (!btc_script_2of2_create_redeem_sorted(&pChannel->funding_tx.wit_script, &pChannel->funding_tx.key_order,
        pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING], pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING])) {
        M_SET_ERR(pChannel, LNERR_CREATE_2OF2, "create 2-of-2");
        return false;
    }
    return true;
}


bool HIDDEN ln_accept_channel_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!ln_is_funder(pChannel)) {
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
    if (pChannel->commit_tx_local.dust_limit_sat > msg.channel_reserve_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "our dust_limit_satoshis is greater than their channel_reserve_satoshis");
        return false;
    }
    if (pChannel->commit_tx_local.channel_reserve_sat < msg.dust_limit_satoshis) {
        M_SEND_ERR(pChannel, LNERR_INV_VALUE, "our channel_reserve_satoshis is lower than their dust_limit_satoshis");
        return false;
    }

    pChannel->min_depth = msg.minimum_depth;
    pChannel->commit_tx_remote.dust_limit_sat = msg.dust_limit_satoshis;
    pChannel->commit_tx_remote.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    pChannel->commit_tx_remote.channel_reserve_sat = msg.channel_reserve_satoshis;
    pChannel->commit_tx_remote.htlc_minimum_msat = msg.htlc_minimum_msat;
    pChannel->commit_tx_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    pChannel->commit_tx_local.to_self_delay = msg.to_self_delay; //XXX:

    //first_per_commitment_pointは初回revoke_and_ackのper_commitment_secretに対応する
    memcpy(pChannel->keys_remote.prev_per_commitment_point, pChannel->keys_remote.per_commitment_point, BTC_SZ_PUBKEY);

    //generate keys
    ln_update_script_pubkeys(pChannel);
    ln_print_keys(pChannel);

    //create funding_tx
    if (!create_funding_tx(pChannel, true)) {
        M_SET_ERR(pChannel, LNERR_CREATE_TX, "create funding_tx");
        return false;
    }

    //obscured commitment tx number
    pChannel->obscured_commit_num_mask = ln_comtx_calc_obscured_commit_num_mask(
        pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_PAYMENT], pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_PAYMENT]);
    LOGD("obscured_commit_num_mask=0x%016" PRIx64 "\n", pChannel->obscured_commit_num_mask);

    //initial commit tx(Remoteが持つTo-Local)
    //  署名計算のみのため、計算後は破棄する
    //  HTLCは存在しないため、計算省略
    if (!ln_comtx_create_remote(pChannel, &pChannel->commit_tx_remote,
        NULL, NULL, //close無し、署名作成無し
        0)) {
        //XXX:
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
    msg.p_funding_txid = ln_funding_txid(pChannel);
    msg.funding_output_index = ln_funding_txindex(pChannel);
    msg.p_signature = pChannel->commit_tx_remote.remote_sig;
    ln_msg_funding_created_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_funding_created_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (ln_is_funder(pChannel)) {
        M_SET_ERR(pChannel, LNERR_INV_SIDE, "not fundee");
        return false;
    }

    ln_msg_funding_created_t msg;
    if (!ln_msg_funding_created_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    ln_funding_set_txid(pChannel, msg.p_funding_txid);
    memcpy(pChannel->commit_tx_local.remote_sig, msg.p_signature, LN_SZ_SIGNATURE);

    //temporary_channel_id
    if (!ln_check_channel_id(msg.p_temporary_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    ln_funding_set_txindex(pChannel, msg.funding_output_index);

    //署名チェック用
    btc_tx_free(&pChannel->tx_funding);
    for (uint32_t lp = 0; lp < ln_funding_txindex(pChannel); lp++) {
        //処理の都合上、voutの位置を調整している
        btc_tx_add_vout(&pChannel->tx_funding, 0);
    }
    btc_sw_add_vout_p2wsh_wit(&pChannel->tx_funding, pChannel->funding_tx.funding_satoshis, &pChannel->funding_tx.wit_script);
    //TODO: 実装上、vinが0、voutが1だった場合にsegwitと誤認してしまう
    btc_tx_add_vin(&pChannel->tx_funding, ln_funding_txid(pChannel), 0);

    //署名チェック
    //  initial commit tx(自分が持つTo-Local)
    //    to_self_delayは自分の値(open_channel)を使う
    //    HTLCは存在しない
    if (!ln_comtx_create_local( //closeもHTLC署名も無し
        pChannel,
        NULL,
        NULL,
        0,
        0,
        pChannel->commit_tx_local.to_self_delay,
        pChannel->commit_tx_local.dust_limit_sat)) {
        LOGE("fail: create_to_local\n");
        return false;
    }

    // initial commit tx(Remoteが持つTo-Local)
    //      署名計算のみのため、計算後は破棄する
    //      HTLCは存在しないため、計算省略
    if (!ln_comtx_create_remote(pChannel, &pChannel->commit_tx_remote,
        NULL, NULL,     //close無し、署名作成無し
        0)) {
        LOGE("fail: create_to_remote\n");
        return false;
    }

    //temporary_channel_id -> channel_id
    ln_channel_id_calc(pChannel->channel_id, ln_funding_txid(pChannel), ln_funding_txindex(pChannel));

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
    msg.p_signature = pChannel->commit_tx_remote.remote_sig;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_funding_signed_write(&buf, &msg);
    ln_callback(pChannel, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    //wait funding_tx
    start_funding_wait(pChannel, false);
    return true;
}


bool HIDDEN ln_funding_signed_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!ln_is_funder(pChannel)) {
        M_SET_ERR(pChannel, LNERR_INV_SIDE, "not funder");
        return false;
    }

    ln_msg_funding_signed_t msg;
    if (!ln_msg_funding_signed_read(&msg, pData, Len)) {
        M_SET_ERR(pChannel, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(pChannel->commit_tx_local.remote_sig, msg.p_signature, LN_SZ_SIGNATURE);

    //channel_id
    ln_channel_id_calc(pChannel->channel_id, ln_funding_txid(pChannel), ln_funding_txindex(pChannel));
    if (!ln_check_channel_id(msg.p_channel_id, pChannel->channel_id)) {
        M_SET_ERR(pChannel, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //initial commit tx(自分が持つTo-Local)
    //  to_self_delayは相手の値(accept_channel)を使う
    //  HTLCは存在しない
    if (!ln_comtx_create_local(pChannel, //closeもHTLC署名も無し
        NULL,
        NULL,
        0,
        0,
        pChannel->commit_tx_local.to_self_delay,
        pChannel->commit_tx_local.dust_limit_sat)) {
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
    ln_callback(pChannel, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    //channel_reestablishと同じ扱いにする
    pChannel->init_flag |= M_INIT_FLAG_REEST_SEND;

    M_DBG_COMMITNUM(pChannel);
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

    ln_update_script_pubkeys(pChannel);
    ln_print_keys(pChannel);
    M_DB_CHANNEL_SAVE(pChannel);

    ln_callback(pChannel, LN_CB_FUNDINGLOCKED_RECV, NULL);

    //channel_reestablishと同じ扱いにする
    pChannel->init_flag |= M_INIT_FLAG_REEST_RECV;

    M_DBG_COMMITNUM(pChannel);

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

    M_DBG_COMMITNUM(pChannel);

    //MUST set next_local_commitment_number to the commitment number
    //  of the next commitment_signed it expects to receive.
    msg.next_local_commitment_number = pChannel->commit_tx_local.commit_num + 1;
    //MUST set next_remote_revocation_number to the commitment number
    //  of the next revoke_and_ack message it expects to receive.
    msg.next_remote_revocation_number = pChannel->commit_tx_remote.revoke_num + 1;

    //option_data_loss_protect
    bool option_data_loss_protect = false;
    if (pChannel->lfeature_local & LN_INIT_LF_OPT_DATALOSS) {
        option_data_loss_protect = true;

        if (pChannel->commit_tx_remote.commit_num) {
            if (!ln_derkey_remote_storage_get_secret(
                &pChannel->keys_remote, your_last_per_commitment_secret,
                (uint64_t)(LN_SECRET_INDEX_INIT - (pChannel->commit_tx_remote.commit_num - 1)))) {
                LOGD("no last secret\n");
                memset(your_last_per_commitment_secret, 0, BTC_SZ_PRIVKEY);
            }
        }

        uint8_t secret_buf[BTC_SZ_PRIVKEY];
        ln_derkey_local_storage_create_prev_per_commitment_secret(&pChannel->keys_local, secret_buf, my_current_per_commitment_point);
    }

    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_channel_reestablish_write(&buf, &msg, option_data_loss_protect)) return false;
    ln_callback(pChannel, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    pChannel->init_flag |= M_INIT_FLAG_REEST_SEND;
    return true;
}


bool HIDDEN ln_channel_reestablish_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    bool ret = false;

    LOGD("BEGIN\n");

    ln_msg_channel_reestablish_t msg;
    bool option_data_loss_protect = (pChannel->lfeature_local & LN_INIT_LF_OPT_DATALOSS);
    ret = ln_msg_channel_reestablish_read(&msg, pData, Len, option_data_loss_protect);
    if (!ret) {
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

    M_DBG_COMMITNUM(pChannel);
    pChannel->reest_commit_num = msg.next_local_commitment_number;
    pChannel->reest_revoke_num = msg.next_remote_revocation_number;

    //BOLT#02
    //  commit_txは、作成する関数内でcommit_num+1している(インクリメントはしない)。
    //  そのため、(commit_num+1)がcommit_tx作成時のcommitment numberである。

    //  next_local_commitment_number
    bool chk_commit_num = true;
    if (pChannel->commit_tx_remote.commit_num + 1 == msg.next_local_commitment_number) {
        LOGD("next_local_commitment_number: OK\n");
    } else if (pChannel->commit_tx_remote.commit_num == msg.next_local_commitment_number) {
        //  if next_local_commitment_number is equal to the commitment number of the last commitment_signed message the receiving node has sent:
        //      * MUST reuse the same commitment number for its next commitment_signed.
        LOGD("next_local_commitment_number == remote commit_num: reuse\n");
    } else {
        // if next_local_commitment_number is not 1 greater than the commitment number of the last commitment_signed message the receiving node has sent:
        //      * SHOULD fail the channel.
        LOGE("fail: next commitment number[%" PRIu64 "(expect) != %" PRIu64 "(recv)]\n", pChannel->commit_tx_remote.commit_num + 1, msg.next_local_commitment_number);
        chk_commit_num = false;
    }

    //BOLT#02
    //  next_remote_revocation_number
    bool chk_revoke_num = true;
    if (pChannel->commit_tx_local.revoke_num + 1 == msg.next_remote_revocation_number) {
        LOGD("next_remote_revocation_number: OK\n");
    } else if (pChannel->commit_tx_local.revoke_num == msg.next_remote_revocation_number) {
        // if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack the receiving node sent, AND the receiving node hasn't already received a closing_signed:
        //      * MUST re-send the revoke_and_ack.
        LOGD("next_remote_revocation_number == local commit_num: resend\n");
    } else {
        LOGE("fail: next revocation number[%" PRIu64 "(expect) != %" PRIu64 "(recv)]\n", pChannel->commit_tx_local.revoke_num + 1, msg.next_remote_revocation_number);
        chk_revoke_num = false;
    }

    //BOLT#2
    //  if it supports option_data_loss_protect, AND the option_data_loss_protect fields are present:
    if ( !(chk_commit_num && chk_revoke_num) && option_data_loss_protect ) {
        //if next_remote_revocation_number is greater than expected above,
        if (msg.next_remote_revocation_number > pChannel->commit_tx_local.commit_num) { //XXX: ?
            //  AND your_last_per_commitment_secret is correct for that next_remote_revocation_number minus 1:
            uint8_t secret[BTC_SZ_PRIVKEY];
            ln_derkey_local_storage_create_per_commitment_secret(&pChannel->keys_local, secret, LN_SECRET_INDEX_INIT - (msg.next_remote_revocation_number - 1));
            LOGD("secret: ");
            DUMPD(secret, BTC_SZ_PRIVKEY);
            if (memcmp(secret, msg.p_your_last_per_commitment_secret, BTC_SZ_PRIVKEY) == 0) {
                //MUST NOT broadcast its commitment transaction.
                //SHOULD fail the channel.
                //SHOULD store my_current_per_commitment_point to retrieve funds should the sending node broadcast its commitment transaction on-chain.
                LOGE("MUST NOT broadcast its commitment transaction\n");
            } else {
                //SHOULD fail the channel.
                LOGE("SHOULD fail the channel\n");
                ret = false;
                goto LABEL_EXIT;
            }
        } else {
            //SHOULD fail the channel.
            LOGE("SHOULD fail the channel\n");
            ret = false;
            goto LABEL_EXIT;
        }
    }

    ln_callback(pChannel, LN_CB_REESTABLISH_RECV, NULL);

    ret = true;

LABEL_EXIT:
    if (ret) {
        pChannel->init_flag |= M_INIT_FLAG_REEST_RECV;
    }
    return ret;
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
    btc_tx_free(&pChannel->tx_funding);

    //vout 2-of-2
    btc_script_2of2_create_redeem_sorted(&pChannel->funding_tx.wit_script, &pChannel->funding_tx.key_order,
                pChannel->keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING], pChannel->keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING]);

    if (pChannel->establish.p_fundin != NULL) {
        //output
        ln_funding_set_txindex(pChannel, M_FUNDING_INDEX);      //TODO: vout#0は2-of-2、vout#1はchangeにしている
        //vout#0:P2WSH - 2-of-2 : M_FUNDING_INDEX
        btc_sw_add_vout_p2wsh_wit(&pChannel->tx_funding, pChannel->funding_tx.funding_satoshis, &pChannel->funding_tx.wit_script);

        //vout#1:P2WPKH - change(amountは後で代入)
        btc_tx_add_vout_spk(&pChannel->tx_funding, (uint64_t)-1, &pChannel->establish.p_fundin->change_spk);

        //input
        //vin#0
        btc_tx_add_vin(&pChannel->tx_funding, pChannel->establish.p_fundin->txid, pChannel->establish.p_fundin->index);

        //FEE計算
        // LEN+署名(72) + LEN+公開鍵(33)
        //  この時点では、pChannel->tx_funding に scriptSig(23byte)とwitness(1+72+1+33)が入っていない。
        //  feeを決めるためにvsizeを算出したいが、
        //
        //      version:4
        //      flag:1
        //      mark:1
        //      vin_cnt: 1
        //          txid+index: 36
        //          scriptSig: 1+23
        //          sequence: 4
        //      vout_cnt: 2
        //          amount: 8
        //          scriptPubKey: 1+34
        //          amount: 8
        //          scriptPubKey: 1+23
        //      wit_item_cnt: 2
        //          sig: 1+72
        //          pub: 1+33
        //      locktime: 4
    #warning issue #344: nested in BIP16 size
        uint64_t fee = ln_calc_fee(LN_SZ_FUNDINGTX_VSIZE, pChannel->feerate_per_kw);
        LOGD("fee=%" PRIu64 "\n", fee);
        if (pChannel->establish.p_fundin->amount >= pChannel->funding_tx.funding_satoshis + fee) {
            pChannel->tx_funding.vout[1].value = pChannel->establish.p_fundin->amount - pChannel->funding_tx.funding_satoshis - fee;
        } else {
            LOGE("fail: amount too short:\n");
            LOGD("    amount=%" PRIu64 "\n", pChannel->establish.p_fundin->amount);
            LOGD("    funding_satoshis=%" PRIu64 "\n", pChannel->funding_tx.funding_satoshis);
            LOGD("    fee=%" PRIu64 "\n", fee);
            return false;
        }
    } else {
        //for SPV
        //fee計算と署名はSPVに任せる(LN_CB_SIGN_FUNDINGTX_REQで吸収する)
        //その代わり、ln_funding_txindex(pChannel)は固定値にならない。
        btc_sw_add_vout_p2wsh_wit(&pChannel->tx_funding, pChannel->funding_tx.funding_satoshis, &pChannel->funding_tx.wit_script);
        btc_tx_add_vin(&pChannel->tx_funding, ln_funding_txid(pChannel), 0); //dummy
    }

    //sign
    if (!bSign) return true; //not sign

    ln_cb_funding_sign_t param;
    param.p_tx =  &pChannel->tx_funding;
    if (pChannel->establish.p_fundin != NULL) {
        param.amount = pChannel->establish.p_fundin->amount;
    } else {
        param.amount = 0;
    }
    ln_callback(pChannel, LN_CB_SIGN_FUNDINGTX_REQ, &param);
    if (!param.ret) {
        LOGE("fail: signature\n");
        btc_tx_free(&pChannel->tx_funding);
        return false;
    }

    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(&pChannel->tx_funding, txid);
    ln_funding_set_txid(pChannel, txid);
    LOGD("***** funding_tx *****\n");
    M_DBG_PRINT_TX(&pChannel->tx_funding);

    //search funding vout
    utl_buf_t two_of_two = UTL_BUF_INIT;
    btc_script_p2wsh_create_scriptpk(&two_of_two, &pChannel->funding_tx.wit_script);
    uint32_t lp;
    for (lp = 0; lp < pChannel->tx_funding.vout_cnt; lp++) {
        if (utl_buf_equal(&pChannel->tx_funding.vout[lp].script, &two_of_two)) break;
    }
    utl_buf_free(&two_of_two);
    if (lp == pChannel->tx_funding.vout_cnt) {
        //not found
        btc_tx_free(&pChannel->tx_funding);
        return false;
    }
    ln_funding_set_txindex(pChannel, lp);
    LOGD("funding_txindex=%d\n", ln_funding_txindex(pChannel));
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
    ln_cb_funding_t funding;

    //commitment numberは0から始まる
    //  BOLT#0
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/00-introduction.md#glossary-and-terminology-guide
    //が、opening時を1回とカウントするので、Normal Operationでは1から始まる
    //  BOLT#2
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#rationale-10
    pChannel->commit_tx_local.commit_num = 0;
    pChannel->commit_tx_local.revoke_num = (uint64_t)-1;
    pChannel->commit_tx_remote.commit_num = 0;
    pChannel->commit_tx_remote.revoke_num = (uint64_t)-1;
    // pChannel->htlc_id_num = 0;
    // pChannel->short_channel_id = 0;

    //storage_next_indexデクリメントおよびper_commit_secret更新
    ln_derkey_local_storage_update_per_commitment_point(&pChannel->keys_local);
    ln_update_script_pubkeys(pChannel);

    funding.b_send = bSendTx;
    if (bSendTx) {
        funding.p_tx_funding = &pChannel->tx_funding;
    }
    funding.b_result = false;
    ln_callback(pChannel, LN_CB_FUNDINGTX_WAIT, &funding);

    if (funding.b_result) {
        pChannel->status = LN_STATUS_ESTABLISH;

        M_DB_SECRET_SAVE(pChannel);
        M_DB_CHANNEL_SAVE(pChannel);
    } else {
        //上位で停止される
    }

    M_DBG_COMMITNUM(pChannel);
}
