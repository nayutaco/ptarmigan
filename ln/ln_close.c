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
/** @file   ln_close.c
 *  @brief  ln_close
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
#include "ln_msg_close.h"
#include "ln_local.h"
#include "ln_setupctl.h"
#include "ln_anno.h"
#include "ln_close.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SHDN_FLAG_EXCHANGED(flag)     (((flag) & (LN_SHDN_FLAG_SEND | LN_SHDN_FLAG_RECV)) == (LN_SHDN_FLAG_SEND | LN_SHDN_FLAG_RECV))


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool create_closing_tx(ln_self_t *self, btc_tx_t *pTx, uint64_t FeeSat, bool bVerify);


/**************************************************************************
 * public functions
 **************************************************************************/

bool /*HIDDEN*/ ln_shutdown_send(ln_self_t *self)
{
    LOGD("BEGIN\n");

    ln_msg_shutdown_t msg;
    msg.p_channel_id = self->channel_id;
    msg.len = self->shutdown_scriptpk_local.len;
    msg.p_scriptpubkey = self->shutdown_scriptpk_local.buf;
    utl_buf_t buf = UTL_BUF_INIT;
    if (!ln_msg_shutdown_write(&buf, &msg)) {
        LOGE("fail: create shutdown\n");
        return false;
    }

    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    self->shutdown_flag |= LN_SHDN_FLAG_SEND;
    M_DB_SELF_SAVE(self);
    ln_channel_update_disable(self);

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_shutdown_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    self->close_last_fee_sat = 0; //XXX:
    if (self->shutdown_flag & LN_SHDN_FLAG_RECV) {
        //既にshutdownを受信済みなら、何もしない
        //XXX: return false;
        return true;
    }

    ln_msg_shutdown_t msg;
    if (!ln_msg_shutdown_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    utl_buf_alloccopy(&self->shutdown_scriptpk_remote, msg.p_scriptpubkey, msg.len);

    //channel_id
    if (!ln_check_channel_id(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //scriptPubKey
    if (!ln_script_scriptpkh_check(&self->shutdown_scriptpk_remote)) {
        M_SET_ERR(self, LNERR_INV_PRIVKEY, "unknown scriptPubKey type");
        return false;
    }

    self->shutdown_flag |= LN_SHDN_FLAG_RECV;
    M_DB_SELF_SAVE(self);

    ln_callback(self, LN_CB_SHUTDOWN_RECV, NULL);

    if (!(self->shutdown_flag & LN_SHDN_FLAG_SEND)) {
        //shutdown has not been sent
        if (!ln_shutdown_send(self)) {
            M_SET_ERR(self, LNERR_CREATE_MSG, "send shutdown");
            return false;
        }
    }

    if (M_SHDN_FLAG_EXCHANGED(self->shutdown_flag)) {
        self->status = LN_STATUS_CLOSE_WAIT;
        M_DB_SELF_SAVE(self);

        if (ln_is_funder(self)) {
            if (!ln_closing_signed_send(self, NULL)) {
                LOGE("fail\n");
                return false;
            }
        }
    }

    LOGD("END\n");
    return true;
}


bool HIDDEN ln_closing_signed_send(ln_self_t *self, ln_msg_closing_signed_t *pClosingSignedMsg)
{
    LOGD("fee_sat: %" PRIu64 "\n", self->close_fee_sat);

    if (pClosingSignedMsg) {
        ln_cb_closed_fee_t closed_fee;
        closed_fee.fee_sat = pClosingSignedMsg->fee_satoshis;
        ln_callback(self, LN_CB_CLOSED_FEE, &closed_fee);
        //self->close_fee_sat updated
    } else {
        self->close_fee_sat = ln_closing_signed_initfee(self);
    }

    //we don't have remote sig
    //  don't verify sig
    btc_tx_free(&self->tx_closing);
    if (!create_closing_tx(self, &self->tx_closing, self->close_fee_sat, false)) {
        LOGE("fail: create close_t\n");
        return false;
    }

    ln_msg_closing_signed_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    msg.p_channel_id = self->channel_id;
    msg.fee_satoshis = self->close_fee_sat;
    msg.p_signature = self->commit_remote.signature;
    if (!ln_msg_closing_signed_write(&buf, &msg)) {
        LOGE("fail: create closeing_signed\n");
        return false;
    }
    self->close_last_fee_sat = self->close_fee_sat;
    ln_callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    M_DB_SELF_SAVE(self);
    return true;
}


bool HIDDEN ln_closing_signed_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!M_SHDN_FLAG_EXCHANGED(self->shutdown_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "shutdown status : %02x", self->shutdown_flag);
        return false;
    }

    ln_msg_closing_signed_t msg;
    if (!ln_msg_closing_signed_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(self->commit_local.signature, msg.p_signature, LN_SZ_SIGNATURE);

    //channel_id
    if (!ln_check_channel_id(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //BOLT#3
    //  A sending node MUST set fee_satoshis lower than or equal to the base fee
    //      of the final commitment transaction as calculated in BOLT #3.
    uint64_t feemax = ln_closing_signed_initfee(self);
    if (msg.fee_satoshis > feemax) {
        LOGE("fail: fee too large(%" PRIu64 " > %" PRIu64 ")\n", msg.fee_satoshis, feemax);
        return false;
    }

    //XXX: check lower limit for the inclusion in a block

    //verify
    btc_tx_free(&self->tx_closing);
    if (!create_closing_tx(self, &self->tx_closing, msg.fee_satoshis, true)) {
        LOGE("fail: create close_tx\n");
        return false;
    }

    if (self->close_last_fee_sat == msg.fee_satoshis) {
        //create closing_tx
        btc_tx_free(&self->tx_closing);
        if (!create_closing_tx(self, &self->tx_closing, self->close_fee_sat, true)) {
            LOGE("fail: create close_tx\n");
            return false;
        }

        //bloadcast closing_tx
        LOGD("same fee!\n");
        utl_buf_t txbuf = UTL_BUF_INIT;
        if (!btc_tx_write(&self->tx_closing, &txbuf)) {
            LOGE("fail: create closeing_tx\n");
            return false;
        }
        ln_cb_closed_t closed;
        closed.result = false;
        closed.p_tx_closing = &txbuf;
        ln_callback(self, LN_CB_CLOSED, &closed);
        if (!closed.result) {
            //XXX: retry to send closing_tx
            LOGE("fail: send closing_tx\n");
            utl_buf_free(&txbuf);
            return false;
        }
        utl_buf_free(&txbuf);

        //funding_txがspentになった
        LOGD("$$$ close waiting\n");
        self->status = LN_STATUS_CLOSE_SPENT;

        //clearはDB削除に任せる
        //channel_clear(self);

        M_DB_SELF_SAVE(self);
    } else {
        LOGD("different fee!\n");

        if (!ln_closing_signed_send(self, &msg)) {
            return false;
        }
    }

    LOGD("END\n");
    return true;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** closing tx作成
 *
 * @param[in]   FeeSat
 * @param[in]   bVerify     true:verifyを行う
 * @note
 *      - INPUT: 2-of-2(順番はself->key_fund_sort)
 *          - 自分：self->commit_remote.signature
 *          - 相手：self->commit_local.signature
 *      - OUTPUT:
 *          - 自分：self->shutdown_scriptpk_local, self->our_msat / 1000
 *          - 相手：self->shutdown_scriptpk_remote, self->their_msat / 1000
 *      - BIP69でソートする
 */
static bool create_closing_tx(ln_self_t *self, btc_tx_t *pTx, uint64_t FeeSat, bool bVerify)
{
    LOGD("BEGIN\n");

    if ((self->shutdown_scriptpk_local.len == 0) || (self->shutdown_scriptpk_remote.len == 0)) {
        LOGD("not mutual output set\n");
        return false;
    }

    uint64_t fee_local;
    uint64_t fee_remote;
    btc_vout_t *vout;
    utl_buf_t buf_sig = UTL_BUF_INIT;

    //BOLT#3: feeはfundedの方から引く
    if (ln_is_funder(self)) {
        fee_local = FeeSat;
        fee_remote = 0;
    } else {
        fee_local = 0;
        fee_remote = FeeSat;
    }

    //vout
    //vout#0 - local
    bool vout_local = (LN_MSAT2SATOSHI(self->our_msat) > fee_local + BTC_DUST_LIMIT);
    bool vout_remote = (LN_MSAT2SATOSHI(self->their_msat) > fee_remote + BTC_DUST_LIMIT);

    if (vout_local) {
        vout = btc_tx_add_vout(pTx, LN_MSAT2SATOSHI(self->our_msat) - fee_local);
        utl_buf_alloccopy(&vout->script, self->shutdown_scriptpk_local.buf, self->shutdown_scriptpk_local.len);
    }
    //vout#1 - remote
    if (vout_remote) {
        vout = btc_tx_add_vout(pTx, LN_MSAT2SATOSHI(self->their_msat) - fee_remote);
        utl_buf_alloccopy(&vout->script, self->shutdown_scriptpk_remote.buf, self->shutdown_scriptpk_remote.len);
    }

    //vin
    btc_tx_add_vin(pTx, self->funding_local.txid, self->funding_local.txindex);

    //BIP69
    btc_tx_sort_bip69(pTx);

    //sign
    uint8_t sighash[BTC_SZ_HASH256];
    if (!btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, self->funding_sat, &self->redeem_fund)) {
        LOGE("fail: sign p2wsh\n");
        btc_tx_free(pTx);
        return false;
    }
    if (!ln_signer_p2wsh(&buf_sig, sighash, &self->priv_data, LN_FUND_IDX_FUNDING)) {
        LOGE("fail: sign p2wsh\n");
        btc_tx_free(pTx);
        return false;
    }

    //送信用署名
    btc_sig_der2rs(self->commit_remote.signature, buf_sig.buf, buf_sig.len);

    //署名追加
    if (bVerify) {
        utl_buf_t buf_sig_from_remote = UTL_BUF_INIT;

        btc_sig_rs2der(&buf_sig_from_remote, self->commit_local.signature);
        ln_comtx_set_vin_p2wsh_2of2(pTx, 0, self->key_fund_sort, &buf_sig, &buf_sig_from_remote, &self->redeem_fund);
        utl_buf_free(&buf_sig_from_remote);

        //verify
        if (!btc_sw_verify_p2wsh_2of2(
            pTx, 0, sighash, &self->tx_funding.vout[self->funding_local.txindex].script)) {
            btc_tx_free(pTx);
            LOGD("fail: verify\n");
            return false;
        }
    } else {
        LOGD("no verify\n");
    }
    utl_buf_free(&buf_sig);

    LOGD("+++++++++++++ closing_tx[%016" PRIx64 "]\n", self->short_channel_id);
    M_DBG_PRINT_TX(pTx);

    //LOGD("END ret=%d\n", ret);
    //return ret;
    LOGD("END ret=%d\n", true);
    return true;
}


