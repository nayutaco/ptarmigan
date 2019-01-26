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

static bool check_peer_node(ln_self_t *self);

static void start_funding_wait(ln_self_t *self, bool bSendTx);
static bool create_funding_tx(ln_self_t *self, bool bSign);


/**************************************************************************
 * public functions
 **************************************************************************/

bool /*HIDDEN*/ ln_open_channel_send(
    ln_self_t *self, const ln_fundin_t *pFundin, uint64_t FundingSat, uint64_t PushSat, uint32_t FeeRate)
{
    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished.");
        return false;
    }
    if (!check_peer_node(self)) {
        M_SET_ERR(self, LNERR_NO_PEER, "no peer node_id");
        return false;
    }
    if (ln_is_funding(self)) {
        M_SET_ERR(self, LNERR_ALREADY_FUNDING, "already funding");
        return false;
    }
    if (FeeRate < LN_FEERATE_PER_KW_MIN) {
        //feerate_per_kw too low
        M_SET_ERR(self, LNERR_INV_VALUE, "feerate_per_kw too low");
        return false;
    }

    //temporary_channel_id
    btc_rng_rand(self->channel_id, LN_SZ_CHANNEL_ID);

    //generate keys
    ln_signer_create_channel_keys(self);
    ln_update_scriptkeys(self);

#if defined(USE_BITCOIND)
    self->establish.p_fundin = (ln_fundin_t *)UTL_DBG_MALLOC(sizeof(ln_fundin_t));
    memcpy(self->establish.p_fundin, pFundin, sizeof(ln_fundin_t));
#else
    (void)pFundin;
#endif

    //open_channel
    ln_msg_open_channel_t msg;
    msg.p_chain_hash = ln_genesishash_get();
    msg.p_temporary_channel_id = self->channel_id;
    msg.funding_satoshis = FundingSat;
    msg.push_msat = LN_SATOSHI2MSAT(PushSat);
    msg.dust_limit_satoshis = self->establish.estprm.dust_limit_sat;
    msg.max_htlc_value_in_flight_msat = self->establish.estprm.max_htlc_value_in_flight_msat;
    msg.channel_reserve_satoshis = self->establish.estprm.channel_reserve_sat;
    msg.htlc_minimum_msat = self->establish.estprm.htlc_minimum_msat;
    msg.feerate_per_kw = FeeRate;
    msg.to_self_delay = self->establish.estprm.to_self_delay;
    msg.max_accepted_htlcs = self->establish.estprm.max_accepted_htlcs;
    msg.p_funding_pubkey = self->funding_local.pubkeys[LN_FUND_IDX_FUNDING];
    msg.p_revocation_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_REVOCATION];
    msg.p_payment_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_PAYMENT];
    msg.p_delayed_payment_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_DELAYED];
    msg.p_htlc_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_HTLC];
    msg.p_first_per_commitment_point = self->funding_local.pubkeys[LN_FUND_IDX_PER_COMMIT];
    msg.channel_flags = CHANNEL_FLAGS_VALUE;
    msg.shutdown_len = 0;
    msg.p_shutdown_scriptpubkey = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_open_channel_write(&buf, &msg);
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    self->commit_local.dust_limit_sat = msg.dust_limit_satoshis;
    self->commit_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    self->commit_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    self->commit_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    self->commit_local.max_accepted_htlcs = msg.max_accepted_htlcs;
    self->our_msat = LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    self->their_msat = msg.push_msat;
    self->funding_sat = msg.funding_satoshis;
    self->feerate_per_kw = msg.feerate_per_kw;

    self->commit_remote.to_self_delay = msg.to_self_delay; //XXX:

    self->fund_flag = (ln_fundflag_t)(LN_FUNDFLAG_FUNDER | ((msg.channel_flags & 1) ? LN_FUNDFLAG_NO_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);
    return true;
}


bool HIDDEN ln_open_channel_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (ln_is_funder(self)) {
        M_SET_ERR(self, LNERR_INV_SIDE, "not fundee");
        return false;
    }
    if (ln_is_funding(self)) {
        M_SET_ERR(self, LNERR_ALREADY_FUNDING, "already funding");
        return false;
    }
    if (self->short_channel_id != 0) {
        M_SET_ERR(self, LNERR_ALREADY_FUNDING, "already established");
        return false;
    }

    ln_msg_open_channel_t msg;
    if (!ln_msg_open_channel_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(self->channel_id, msg.p_temporary_channel_id, LN_SZ_CHANNEL_ID);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_FUNDING], msg.p_funding_pubkey, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_REVOCATION], msg.p_revocation_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_PAYMENT], msg.p_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_DELAYED], msg.p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_HTLC], msg.p_htlc_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_PER_COMMIT], msg.p_first_per_commitment_point, BTC_SZ_PUBKEY);

    if (memcmp(ln_genesishash_get(), msg.p_chain_hash, BTC_SZ_HASH256)) {
        LOGE("fail: chain_hash mismatch\n");
        return false;
    }

    //check feerate_per_kw
    ln_callback(self, LN_CB_GET_LATEST_FEERATE, &self->feerate_per_kw);
    if ( (msg.feerate_per_kw < LN_FEERATE_PER_KW_MIN) ||
         !M_FEERATE_CHK_MIN_OK(self->feerate_per_kw, msg.feerate_per_kw) ) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "%s", "fail: feerate_per_kw is too low");
        return false;
    }
    if (!M_FEERATE_CHK_MAX_OK(self->feerate_per_kw, msg.feerate_per_kw)) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "%s", "fail: feerate_per_kw is too large");
        return false;
    }

    uint64_t fee = ln_estimate_initcommittx_fee(msg.feerate_per_kw);
    if (msg.funding_satoshis < fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN) {
        char str[256];
        sprintf(str, "funding_satoshis too low(%" PRIu64 " < %" PRIu64 ")",
            msg.funding_satoshis, fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN);
        M_SEND_ERR(self, LNERR_INV_VALUE, "%s", str);
        return false;
    }

    //BOLT02
    //  The sender:
    //      - MUST set channel_reserve_satoshis greater than or equal to dust_limit_satoshis from the open_channel message.
    //      - MUST set dust_limit_satoshis less than or equal to channel_reserve_satoshis from the open_channel message.
    if (self->establish.estprm.channel_reserve_sat < msg.dust_limit_satoshis) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "our channel_reserve_satoshis is lower than their dust_limit_satoshis");
        return false;
    }
    if (self->establish.estprm.dust_limit_sat > msg.channel_reserve_satoshis) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "our dust_limit_satoshis is greater than their channel_reserve_satoshis");
        return false;
    }

    //params for commit_remote
    self->commit_remote.dust_limit_sat = msg.dust_limit_satoshis;
    self->commit_remote.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    self->commit_remote.channel_reserve_sat = msg.channel_reserve_satoshis;
    self->commit_remote.htlc_minimum_msat = msg.htlc_minimum_msat;
    self->commit_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    self->commit_local.to_self_delay = msg.to_self_delay; //XXX:

    //copy first_per_commitment_point for the first revoke_and_ack
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[LN_FUND_IDX_PER_COMMIT], BTC_SZ_PUBKEY);

    //params for funding
    self->funding_sat = msg.funding_satoshis;
    self->feerate_per_kw = msg.feerate_per_kw;
    self->our_msat = msg.push_msat;
    self->their_msat = LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    self->fund_flag = (ln_fundflag_t)(((msg.channel_flags & 1) ? LN_FUNDFLAG_NO_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);

    //generate keys
    ln_signer_create_channel_keys(self);
    ln_update_scriptkeys(self);
    ln_print_keys(self);

    if (!ln_accept_channel_send(self)) {
        LOGE("fail: send accept_channel\n");
        return false;
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_accept_channel_send(ln_self_t *self)
{
    ln_msg_accept_channel_t msg;
    msg.p_temporary_channel_id = self->channel_id;
    msg.dust_limit_satoshis = self->establish.estprm.dust_limit_sat;
    msg.max_htlc_value_in_flight_msat = self->establish.estprm.max_htlc_value_in_flight_msat;
    msg.channel_reserve_satoshis = self->establish.estprm.channel_reserve_sat;
    msg.htlc_minimum_msat = self->establish.estprm.htlc_minimum_msat;
    msg.minimum_depth = self->establish.estprm.min_depth;
    msg.to_self_delay = self->establish.estprm.to_self_delay;
    msg.max_accepted_htlcs = self->establish.estprm.max_accepted_htlcs;
    msg.p_funding_pubkey = self->funding_local.pubkeys[LN_FUND_IDX_FUNDING];
    msg.p_revocation_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_REVOCATION];
    msg.p_payment_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_PAYMENT];
    msg.p_delayed_payment_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_DELAYED];
    msg.p_htlc_basepoint = self->funding_local.pubkeys[LN_FUND_IDX_HTLC];
    msg.p_first_per_commitment_point = self->funding_local.pubkeys[LN_FUND_IDX_PER_COMMIT];
    msg.shutdown_len = 0;
    msg.p_shutdown_scriptpubkey = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_accept_channel_write(&buf, &msg);
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    self->min_depth = msg.minimum_depth;
    self->commit_local.dust_limit_sat = msg.dust_limit_satoshis;
    self->commit_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    self->commit_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    self->commit_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    self->commit_local.max_accepted_htlcs = msg.max_accepted_htlcs;

    self->commit_remote.to_self_delay = msg.to_self_delay; //XXX:

    //obscured commitment tx number
    self->obscured = ln_script_calc_obscured_txnum(
        self->funding_remote.pubkeys[LN_FUND_IDX_PAYMENT], self->funding_local.pubkeys[LN_FUND_IDX_PAYMENT]);
    LOGD("obscured=0x%016" PRIx64 "\n", self->obscured);

    //vout 2-of-2
    if (!btc_script_2of2_create_redeem_sorted(&self->redeem_fund, &self->key_fund_sort,
        self->funding_local.pubkeys[LN_FUND_IDX_FUNDING], self->funding_remote.pubkeys[LN_FUND_IDX_FUNDING])) {
        M_SET_ERR(self, LNERR_CREATE_2OF2, "create 2-of-2");
        return false;
    }
    return true;
}


bool HIDDEN ln_accept_channel_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!ln_is_funder(self)) {
        M_SET_ERR(self, LNERR_INV_SIDE, "not funder");
        return false;
    }

    ln_msg_accept_channel_t msg;
    if (!ln_msg_accept_channel_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_FUNDING], msg.p_funding_pubkey, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_REVOCATION], msg.p_revocation_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_PAYMENT], msg.p_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_DELAYED], msg.p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_HTLC], msg.p_htlc_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_PER_COMMIT], msg.p_first_per_commitment_point, BTC_SZ_PUBKEY);

    //temporary_channel_id
    if (!ln_check_channel_id(msg.p_temporary_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //BOLT02
    // The receiver:
    //  - if channel_reserve_satoshis is less than dust_limit_satoshis within the open_channel message:
    //   - MUST reject the channel.
    //  - if channel_reserve_satoshis from the open_channel message is less than dust_limit_satoshis:
    //   - MUST reject the channel. Other fields have the same requirements as their counterparts in open_channel.
    if (self->commit_local.dust_limit_sat > msg.channel_reserve_satoshis) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "our dust_limit_satoshis is greater than their channel_reserve_satoshis");
        return false;
    }
    if (self->commit_local.channel_reserve_sat < msg.dust_limit_satoshis) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "our channel_reserve_satoshis is lower than their dust_limit_satoshis");
        return false;
    }

    self->min_depth = msg.minimum_depth;
    self->commit_remote.dust_limit_sat = msg.dust_limit_satoshis;
    self->commit_remote.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    self->commit_remote.channel_reserve_sat = msg.channel_reserve_satoshis;
    self->commit_remote.htlc_minimum_msat = msg.htlc_minimum_msat;
    self->commit_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    self->commit_local.to_self_delay = msg.to_self_delay; //XXX:

    //first_per_commitment_pointは初回revoke_and_ackのper_commitment_secretに対応する
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[LN_FUND_IDX_PER_COMMIT], BTC_SZ_PUBKEY);

    //generate keys
    ln_update_scriptkeys(self);
    ln_print_keys(self);

    //create funding_tx
    if (!create_funding_tx(self, true)) {
        M_SET_ERR(self, LNERR_CREATE_TX, "create funding_tx");
        return false;
    }

    //obscured commitment tx number
    self->obscured = ln_script_calc_obscured_txnum(
        self->funding_local.pubkeys[LN_FUND_IDX_PAYMENT], self->funding_remote.pubkeys[LN_FUND_IDX_PAYMENT]);
    LOGD("obscured=0x%016" PRIx64 "\n", self->obscured);

    //initial commit tx(Remoteが持つTo-Local)
    //  署名計算のみのため、計算後は破棄する
    //  HTLCは存在しないため、計算省略
    if (!ln_comtx_create_to_remote(self, &self->commit_remote,
        NULL, NULL, //close無し、署名作成無し
        0)) {
        //XXX:
        return false;
    }

    if (!ln_funding_created_send(self)) {
        //XXX:
        return false;
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_funding_created_send(ln_self_t *self)
{
    ln_msg_funding_created_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    msg.p_temporary_channel_id = self->channel_id;
    msg.p_funding_txid = self->funding_local.txid;
    msg.funding_output_index = self->funding_local.txindex;
    msg.p_signature = self->commit_remote.signature;
    ln_msg_funding_created_write(&buf, &msg);
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


bool HIDDEN ln_funding_created_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (ln_is_funder(self)) {
        M_SET_ERR(self, LNERR_INV_SIDE, "not fundee");
        return false;
    }

    ln_msg_funding_created_t msg;
    if (!ln_msg_funding_created_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(self->funding_local.txid, msg.p_funding_txid, BTC_SZ_TXID);
    memcpy(self->commit_local.signature, msg.p_signature, LN_SZ_SIGNATURE);

    //temporary_channel_id
    if (!ln_check_channel_id(msg.p_temporary_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    self->funding_local.txindex = msg.funding_output_index;

    //署名チェック用
    btc_tx_free(&self->tx_funding);
    for (int lp = 0; lp < self->funding_local.txindex; lp++) {
        //処理の都合上、voutの位置を調整している
        btc_tx_add_vout(&self->tx_funding, 0);
    }
    btc_sw_add_vout_p2wsh_wit(&self->tx_funding, self->funding_sat, &self->redeem_fund);
    //TODO: 実装上、vinが0、voutが1だった場合にsegwitと誤認してしまう
    btc_tx_add_vin(&self->tx_funding, self->funding_local.txid, 0);

    //署名チェック
    //  initial commit tx(自分が持つTo-Local)
    //    to-self-delayは自分の値(open_channel)を使う
    //    HTLCは存在しない
    if (!ln_comtx_create_to_local(self,
        NULL, NULL, 0,  //closeもHTLC署名も無し
        0, self->commit_local.to_self_delay, self->commit_local.dust_limit_sat)) {
        LOGE("fail: create_to_local\n");
        return false;
    }

    // initial commit tx(Remoteが持つTo-Local)
    //      署名計算のみのため、計算後は破棄する
    //      HTLCは存在しないため、計算省略
    if (!ln_comtx_create_to_remote(self, &self->commit_remote,
        NULL, NULL,     //close無し、署名作成無し
        0)) {
        LOGE("fail: create_to_remote\n");
        return false;
    }

    //temporary_channel_id -> channel_id
    ln_channel_id_calc(self->channel_id, self->funding_local.txid, self->funding_local.txindex);

    if (!ln_funding_signed_send(self)) {
        //XXX:
        return false;
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_funding_signed_send(ln_self_t *self)
{
    ln_msg_funding_signed_t msg;
    msg.p_channel_id = self->channel_id;
    msg.p_signature = self->commit_remote.signature;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_funding_signed_write(&buf, &msg);
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    //wait funding_tx
    start_funding_wait(self, false);
    return true;
}


bool HIDDEN ln_funding_signed_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!ln_is_funder(self)) {
        M_SET_ERR(self, LNERR_INV_SIDE, "not funder");
        return false;
    }

    ln_msg_funding_signed_t msg;
    if (!ln_msg_funding_signed_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(self->commit_local.signature, msg.p_signature, LN_SZ_SIGNATURE);

    //channel_id
    ln_channel_id_calc(self->channel_id, self->funding_local.txid, self->funding_local.txindex);
    if (!ln_check_channel_id(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //initial commit tx(自分が持つTo-Local)
    //  to-self-delayは相手の値(accept_channel)を使う
    //  HTLCは存在しない
    if (!ln_comtx_create_to_local(self,
        NULL, NULL, 0,      //closeもHTLC署名も無し
        0, self->commit_local.to_self_delay, self->commit_local.dust_limit_sat)) {
        LOGE("fail: create_to_local\n");
        return false;
    }

    //funding_tx安定待ち
    start_funding_wait(self, true);

    LOGD("END\n");
    return true;
}


bool /*HIDDEN*/ ln_funding_locked_send(ln_self_t *self)
{
    LOGD("\n");

    ln_msg_funding_locked_t msg;
    msg.p_channel_id = self->channel_id;
    msg.p_next_per_commitment_point = self->funding_local.pubkeys[LN_FUND_IDX_PER_COMMIT];
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_funding_locked_write(&buf, &msg)) return false;
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    //channel_reestablishと同じ扱いにする
    self->init_flag |= M_INIT_FLAG_REEST_SEND;

    M_DBG_COMMITNUM(self);
    return true;
}


/*
 * funding_lockedはお互い送信し合うことになる。
 *      open_channel送信側: funding_signed受信→funding_tx安定待ち→funding_locked送信→funding_locked受信→完了
 *      open_channel受信側: funding_locked受信→funding_tx安定待ち→完了
 *
 * funding_tx安定待ちで一度シーケンスが止まる。
 */
bool HIDDEN ln_funding_locked_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_funding_locked_t msg;
    if (!ln_msg_funding_locked_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel_id
    if (!ln_check_channel_id(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    LOGV("prev: ");
    DUMPV(self->funding_remote.pubkeys[LN_FUND_IDX_PER_COMMIT], BTC_SZ_PUBKEY);
    LOGV("next: ");
    DUMPV(msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);

    //prev_percommitはrevoke_and_ackでのみ更新する
    memcpy(self->funding_remote.pubkeys[LN_FUND_IDX_PER_COMMIT], msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);

    //funding中終了
    ln_establish_free(self);

    ln_update_scriptkeys(self);
    ln_print_keys(self);
    M_DB_SELF_SAVE(self);

    ln_callback(self, LN_CB_FUNDINGLOCKED_RECV, NULL);

    //channel_reestablishと同じ扱いにする
    self->init_flag |= M_INIT_FLAG_REEST_RECV;

    M_DBG_COMMITNUM(self);

    LOGD("END\n");
    return true;
}


bool /*HIDDEN*/ ln_channel_reestablish_send(ln_self_t *self)
{
    ln_msg_channel_reestablish_t msg;
    uint8_t your_last_per_commitment_secret[BTC_SZ_PRIVKEY] = {0};
    uint8_t my_current_per_commitment_point[BTC_SZ_PUBKEY] = {0};
    msg.p_channel_id = self->channel_id;
    msg.p_your_last_per_commitment_secret = your_last_per_commitment_secret;
    msg.p_my_current_per_commitment_point = my_current_per_commitment_point;

    M_DBG_COMMITNUM(self);

    //MUST set next_local_commitment_number to the commitment number
    //  of the next commitment_signed it expects to receive.
    msg.next_local_commitment_number = self->commit_local.commit_num + 1;
    //MUST set next_remote_revocation_number to the commitment number
    //  of the next revoke_and_ack message it expects to receive.
    msg.next_remote_revocation_number = self->commit_remote.revoke_num + 1;

    //option_data_loss_protect
    bool option_data_loss_protect = false;
    if (self->lfeature_local & LN_INIT_LF_OPT_DATALOSS) {
        option_data_loss_protect = true;

        if (self->commit_remote.commit_num) {
            if (!ln_derkey_storage_get_secret(
                your_last_per_commitment_secret, &self->peer_storage,
                (uint64_t)(LN_SECRET_INDEX_INIT - (self->commit_remote.commit_num - 1)))) {
                LOGD("no last secret\n");
                memset(your_last_per_commitment_secret, 0, BTC_SZ_PRIVKEY);
            }
        }

        uint8_t secret_buf[BTC_SZ_PRIVKEY];
        ln_signer_create_prev_per_commit_secret(self, secret_buf, my_current_per_commitment_point);
    }

    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_channel_reestablish_write(&buf, &msg, option_data_loss_protect)) return false;
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    self->init_flag |= M_INIT_FLAG_REEST_SEND;
    return true;
}


bool HIDDEN ln_channel_reestablish_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret = false;

    LOGD("BEGIN\n");

    ln_msg_channel_reestablish_t msg;
    bool option_data_loss_protect = (self->lfeature_local & LN_INIT_LF_OPT_DATALOSS);
    ret = ln_msg_channel_reestablish_read(&msg, pData, Len, option_data_loss_protect);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    option_data_loss_protect =
        option_data_loss_protect &&
        msg.p_your_last_per_commitment_secret &&
        msg.p_my_current_per_commitment_point;

    //channel_id
    if (!ln_check_channel_id(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    M_DBG_COMMITNUM(self);
    self->reest_commit_num = msg.next_local_commitment_number;
    self->reest_revoke_num = msg.next_remote_revocation_number;

    //BOLT#02
    //  commit_txは、作成する関数内でcommit_num+1している(インクリメントはしない)。
    //  そのため、(commit_num+1)がcommit_tx作成時のcommitment numberである。

    //  next_local_commitment_number
    bool chk_commit_num = true;
    if (self->commit_remote.commit_num + 1 == msg.next_local_commitment_number) {
        LOGD("next_local_commitment_number: OK\n");
    } else if (self->commit_remote.commit_num == msg.next_local_commitment_number) {
        //  if next_local_commitment_number is equal to the commitment number of the last commitment_signed message the receiving node has sent:
        //      * MUST reuse the same commitment number for its next commitment_signed.
        LOGD("next_local_commitment_number == remote commit_num: reuse\n");
    } else {
        // if next_local_commitment_number is not 1 greater than the commitment number of the last commitment_signed message the receiving node has sent:
        //      * SHOULD fail the channel.
        LOGE("fail: next commitment number[%" PRIu64 "(expect) != %" PRIu64 "(recv)]\n", self->commit_remote.commit_num + 1, msg.next_local_commitment_number);
        chk_commit_num = false;
    }

    //BOLT#02
    //  next_remote_revocation_number
    bool chk_revoke_num = true;
    if (self->commit_local.revoke_num + 1 == msg.next_remote_revocation_number) {
        LOGD("next_remote_revocation_number: OK\n");
    } else if (self->commit_local.revoke_num == msg.next_remote_revocation_number) {
        // if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack the receiving node sent, AND the receiving node hasn't already received a closing_signed:
        //      * MUST re-send the revoke_and_ack.
        LOGD("next_remote_revocation_number == local commit_num: resend\n");
    } else {
        LOGE("fail: next revocation number[%" PRIu64 "(expect) != %" PRIu64 "(recv)]\n", self->commit_local.revoke_num + 1, msg.next_remote_revocation_number);
        chk_revoke_num = false;
    }

    //BOLT#2
    //  if it supports option_data_loss_protect, AND the option_data_loss_protect fields are present:
    if ( !(chk_commit_num && chk_revoke_num) && option_data_loss_protect ) {
        //if next_remote_revocation_number is greater than expected above,
        if (msg.next_remote_revocation_number > self->commit_local.commit_num) {
            //  AND your_last_per_commitment_secret is correct for that next_remote_revocation_number minus 1:
            //
            //      [実装]
            //      self->priv_data.storage_indexは鍵導出後にデクリメントしている。
            //      最新のcommit_tx生成後は、次の次に生成するstorage_indexを指している。
            //      最後に交換したcommit_txは、storage_index+1。
            //      revoke_and_ackで渡すsecretは、storage_index+2。
            //      既にrevoke_and_ackで渡し終わったsecretは、storage_index+3。
            //      "next_remote_revocation_number minus 1"だから、storage_index+4。
            uint8_t secret[BTC_SZ_PRIVKEY];
            ln_derkey_storage_create_secret(secret, self->priv_data.storage_seed, self->priv_data.storage_index + 4);
            LOGD("storage_index(%016" PRIx64 ": ", self->priv_data.storage_index + 4);
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

    ln_callback(self, LN_CB_REESTABLISH_RECV, NULL);

    ret = true;

LABEL_EXIT:
    if (ret) {
        self->init_flag |= M_INIT_FLAG_REEST_RECV;
    }
    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

static bool check_peer_node(ln_self_t *self)
{
    if (self->peer_node_id[0] == 0x00) return false; //invalid value
    return true;
}


/** create funding_tx
 *
 * @param[in,out]       self
 */
static bool create_funding_tx(ln_self_t *self, bool bSign)
{
    btc_tx_free(&self->tx_funding);

    //vout 2-of-2
    btc_script_2of2_create_redeem_sorted(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.pubkeys[LN_FUND_IDX_FUNDING], self->funding_remote.pubkeys[LN_FUND_IDX_FUNDING]);

    if (self->establish.p_fundin != NULL) {
        //output
        self->funding_local.txindex = M_FUNDING_INDEX;      //TODO: vout#0は2-of-2、vout#1はchangeにしている
        //vout#0:P2WSH - 2-of-2 : M_FUNDING_INDEX
        btc_sw_add_vout_p2wsh_wit(&self->tx_funding, self->funding_sat, &self->redeem_fund);

        //vout#1:P2WPKH - change(amountは後で代入)
        btc_tx_add_vout_spk(&self->tx_funding, (uint64_t)-1, &self->establish.p_fundin->change_spk);

        //input
        //vin#0
        btc_tx_add_vin(&self->tx_funding, self->establish.p_fundin->txid, self->establish.p_fundin->index);

        //FEE計算
        // LEN+署名(72) + LEN+公開鍵(33)
        //  この時点では、self->tx_funding に scriptSig(23byte)とwitness(1+72+1+33)が入っていない。
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
        uint64_t fee = ln_calc_fee(LN_SZ_FUNDINGTX_VSIZE, self->feerate_per_kw);
        LOGD("fee=%" PRIu64 "\n", fee);
        if (self->establish.p_fundin->amount >= self->funding_sat + fee) {
            self->tx_funding.vout[1].value = self->establish.p_fundin->amount - self->funding_sat - fee;
        } else {
            LOGE("fail: amount too short:\n");
            LOGD("    amount=%" PRIu64 "\n", self->establish.p_fundin->amount);
            LOGD("    funding_satoshis=%" PRIu64 "\n", self->funding_sat);
            LOGD("    fee=%" PRIu64 "\n", fee);
            return false;
        }
    } else {
        //for SPV
        //fee計算と署名はSPVに任せる(LN_CB_SIGN_FUNDINGTX_REQで吸収する)
        //その代わり、self->funding_local.txindexは固定値にならない。
        btc_sw_add_vout_p2wsh_wit(&self->tx_funding, self->funding_sat, &self->redeem_fund);
        btc_tx_add_vin(&self->tx_funding, self->funding_local.txid, 0); //dummy
    }

    //sign
    if (!bSign) return true; //not sign

    ln_cb_funding_sign_t param;
    param.p_tx =  &self->tx_funding;
    if (self->establish.p_fundin != NULL) {
        param.amount = self->establish.p_fundin->amount;
    } else {
        param.amount = 0;
    }
    ln_callback(self, LN_CB_SIGN_FUNDINGTX_REQ, &param);
    if (!param.ret) {
        LOGE("fail: signature\n");
        btc_tx_free(&self->tx_funding);
        return false;
    }

    btc_tx_txid(&self->tx_funding, self->funding_local.txid);
    LOGD("***** funding_tx *****\n");
    M_DBG_PRINT_TX(&self->tx_funding);

    //search funding vout
    utl_buf_t two_of_two = UTL_BUF_INIT;
    btc_script_p2wsh_create_scriptsig(&two_of_two, &self->redeem_fund);
    uint32_t lp;
    for (lp = 0; lp < self->tx_funding.vout_cnt; lp++) {
        if (utl_buf_equal(&self->tx_funding.vout[lp].script, &two_of_two)) break;
    }
    utl_buf_free(&two_of_two);
    if (lp == self->tx_funding.vout_cnt) {
        //not found
        btc_tx_free(&self->tx_funding);
        return false;
    }
    self->funding_local.txindex = (uint16_t)lp;
    LOGD("funding_txindex=%d\n", self->funding_local.txindex);
    return true;
}


/** funding_tx minimum_depth待ち開始
 *
 * @param[in]   self
 * @param[in]   bSendTx     true:funding_txをbroadcastする
 *
 * @note
 *      - funding_signed送信後あるいはfunding_tx展開後のみ呼び出す
 */
static void start_funding_wait(ln_self_t *self, bool bSendTx)
{
    ln_cb_funding_t funding;

    //commitment numberは0から始まる
    //  BOLT#0
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/00-introduction.md#glossary-and-terminology-guide
    //が、opening時を1回とカウントするので、Normal Operationでは1から始まる
    //  BOLT#2
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#rationale-10
    self->commit_local.commit_num = 0;
    self->commit_local.revoke_num = (uint64_t)-1;
    self->commit_remote.commit_num = 0;
    self->commit_remote.revoke_num = (uint64_t)-1;
    // self->htlc_id_num = 0;
    // self->short_channel_id = 0;

    //storage_indexデクリメントおよびper_commit_secret更新
    ln_signer_keys_update_storage(self);
    ln_update_scriptkeys(self);

    funding.b_send = bSendTx;
    if (bSendTx) {
        funding.p_tx_funding = &self->tx_funding;
    }
    funding.b_result = false;
    ln_callback(self, LN_CB_FUNDINGTX_WAIT, &funding);

    if (funding.b_result) {
        self->status = LN_STATUS_ESTABLISH;

        M_DB_SECRET_SAVE(self);
        M_DB_SELF_SAVE(self);
    } else {
        //上位で停止される
    }

    M_DBG_COMMITNUM(self);
}
