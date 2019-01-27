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


/**************************************************************************
 * macros
 **************************************************************************/

#define M_HYSTE_CLTV_EXPIRY_MIN             (7)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_SOON            (1)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_FAR             (144 * 15)      ///< BOLT4 check:cltv_expiryのhysteresis(15日)

#define M_UPDATEFEE_CHK_MIN_OK(val,rate)    (val >= (uint32_t)(rate * 0.2))
#define M_UPDATEFEE_CHK_MAX_OK(val,rate)    (val <= (uint32_t)(rate * 5))

/// update_add_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_ADDHTLC         (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_OFFER) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)

/// update_fulfill_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_FULFILLHTLC     (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_RECV) | LN_HTLCFLAG_SFT_DELHTLC(LN_DELHTLC_FULFILL) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)

/// update_fail_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_FAILHTLC        (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_RECV) | LN_HTLCFLAG_SFT_DELHTLC(LN_DELHTLC_FAIL) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)

/// update_fail_malformed_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_MALFORMEDHTLC   (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_RECV) | LN_HTLCFLAG_SFT_DELHTLC(LN_DELHTLC_MALFORMED) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool msg_update_add_htlc_write(utl_buf_t *pBuf, const ln_update_add_htlc_t *pInfo);
static bool msg_update_add_htlc_read(ln_update_add_htlc_t *pInfo, const uint8_t *pData, uint16_t Len);
static bool check_recv_add_htlc_bolt2(ln_self_t *self, const ln_update_add_htlc_t *p_htlc);
static bool check_recv_add_htlc_bolt4_common(ln_self_t *self, utl_push_t *pPushReason);
static bool check_recv_add_htlc_bolt4_final(ln_self_t *self, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason, ln_update_add_htlc_t *pAddHtlc, uint8_t *pPreImage, int32_t Height);
static bool check_recv_add_htlc_bolt4_forward(ln_self_t *self, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason, ln_update_add_htlc_t *pAddHtlc,int32_t Height);
static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret);
static void clear_htlc_comrevflag(ln_update_add_htlc_t *p_htlc, uint8_t DelHtlc);
static void clear_htlc(ln_update_add_htlc_t *p_htlc);
static void add_htlc_create(ln_self_t *self, utl_buf_t *pAdd, uint16_t Idx);
static void fulfill_htlc_create(ln_self_t *self, utl_buf_t *pFulfill, uint16_t Idx);
static void fail_htlc_create(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx);
static void fail_malformed_htlc_create(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx);
static bool create_commitment_signed(ln_self_t *self, utl_buf_t *pCommSig);
static bool check_create_add_htlc(ln_self_t *self, uint16_t *pIdx, utl_buf_t *pReason, uint64_t amount_msat, uint32_t cltv_value);
static bool set_add_htlc(ln_self_t *self, uint64_t *pHtlcId, utl_buf_t *pReason, uint16_t *pIdx, const uint8_t *pPacket, uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash, uint64_t PrevShortChannelId, uint16_t PrevIdx, const utl_buf_t *pSharedSecrets);
static bool check_create_remote_commit_tx(ln_self_t *self, uint16_t Idx);
static void recv_idle_proc_final(ln_self_t *self);
static void recv_idle_proc_nonfinal(ln_self_t *self, uint32_t FeeratePerKw);

#ifdef M_DBG_COMMITNUM
static void dbg_htlcflag(const ln_htlcflag_t *p_flag);
static void dbg_htlcflagall(const ln_self_t *self);
#endif


/**************************************************************************
 * static inline
 **************************************************************************/

static inline const char *dbg_htlcflag_addhtlc_str(int addhtlc)
{
    switch (addhtlc) {
    case LN_ADDHTLC_NONE: return "NONE";
    case LN_ADDHTLC_OFFER: return "OFFER";
    case LN_ADDHTLC_RECV: return "RECV";
    default: return "unknown";
    }
}


static inline const char *dbg_htlcflag_delhtlc_str(int delhtlc)
{
    switch (delhtlc) {
    case LN_DELHTLC_NONE: return "NONE";
    case LN_DELHTLC_FULFILL: return "FULFILL";
    case LN_DELHTLC_FAIL: return "FAIL";
    case LN_DELHTLC_MALFORMED: return "MALFORMED";
    default: return "unknown";
    }
}


/**************************************************************************
 * public functions
 **************************************************************************/

bool HIDDEN ln_update_add_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    int idx;

    //空きHTLCチェック
    for (idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (LN_HTLC_EMPTY(&self->cnl_add_htlc[idx])) {
            break;
        }
    }
    if (idx >= LN_HTLC_MAX) {
        M_SET_ERR(self, LNERR_HTLC_FULL, "no free add_htlc");
        return false;
    }

    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    p_htlc->p_channel_id = channel_id;
    ret = msg_update_add_htlc_read(p_htlc, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel-idチェック
    ret = ln_check_channel_id(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }


    //
    // BOLT2 check
    //  NG時は、基本的にチャネルを失敗させる。
    //  「相手のamountより HTLCのamountの方が大きい」というような、あってはいけないチェックを行う。
    //  送金額が足りないのは、転送する先のチャネルにamountが足りていない場合になるため、
    //  それはupdate_add_htlcをrevoke_and_ackまで終わらせた後、update_fail_htlcを返すことになる。
    //
    ret = check_recv_add_htlc_bolt2(self, p_htlc);
    if (!ret) {
        LOGE("fail: BOLT2 check\n");
        return false;
    }


    //
    //BOLT4 check
    //  BOLT2 checkにより、update_add_htlcとしては受入可能。
    //  ただし、onionやpayeeのinvoiceチェックによりfailになる可能性がある。
    //
    //  [2018/09/07] N/A
    //      A2. 該当する状況なし
    //      A3. 該当する状況なし
    //      A4. node_announcement.featuresは未定義
    //      B6. channel_announcement.featuresは未定義

    ln_hop_dataout_t hop_dataout;   // update_add_htlc受信後のONION解析結果
    uint8_t preimage[LN_SZ_PREIMAGE];

    ln_cb_add_htlc_recv_t add_htlc;
    utl_push_t push_htlc;
    utl_buf_t buf_reason = UTL_BUF_INIT;
    utl_push_init(&push_htlc, &buf_reason, 0);

    ln_cb_add_htlc_result_t result = LN_CB_ADD_HTLC_RESULT_OK;
    ret = ln_onion_read_packet(p_htlc->buf_onion_reason.buf, &hop_dataout,
                    &p_htlc->buf_shared_secret,
                    &push_htlc,
                    p_htlc->buf_onion_reason.buf,
                    p_htlc->payment_sha256, BTC_SZ_HASH256);
    if (ret) {
        int32_t height = 0;
        ln_callback(self, LN_CB_GETBLOCKCOUNT, &height);
        if (height > 0) {
            if (hop_dataout.b_exit) {
                ret = check_recv_add_htlc_bolt4_final(self, &hop_dataout, &push_htlc, p_htlc, preimage, height);
                if (ret) {
                    p_htlc->prev_short_channel_id = UINT64_MAX; //final node
                    utl_buf_alloccopy(&p_htlc->buf_payment_preimage, preimage, LN_SZ_PREIMAGE);
                    utl_buf_free(&p_htlc->buf_onion_reason);
                }
            } else {
                ret = check_recv_add_htlc_bolt4_forward(self, &hop_dataout, &push_htlc, p_htlc, height);
            }
        } else {
            M_SET_ERR(self, LNERR_BITCOIND, "getblockcount");
            ret = false;
        }
    } else {
        //A1. if the realm byte is unknown:
        //      invalid_realm
        //B1. if the onion version byte is unknown:
        //      invalid_onion_version
        //B2. if the onion HMAC is incorrect:
        //      invalid_onion_hmac
        //B3. if the ephemeral key in the onion is unparsable:
        //      invalid_onion_key
        M_SET_ERR(self, LNERR_ONION, "onion-read");

        uint16_t failure_code = utl_int_pack_u16be(buf_reason.buf);
        if (failure_code & LNERR_ONION_BADONION) {
            //update_fail_malformed_htlc
            result = LN_CB_ADD_HTLC_RESULT_MALFORMED;
        } else {
            //update_fail_htlc
            result = LN_CB_ADD_HTLC_RESULT_FAIL;
        }
        utl_buf_free(&p_htlc->buf_onion_reason);
    }
    if (ret) {
        ret = check_recv_add_htlc_bolt4_common(self, &push_htlc);
    }
    if (!ret && (result == LN_CB_ADD_HTLC_RESULT_OK)) {
        //ここまでで、ret=falseだったら、resultはFAILになる
        //すなわち、ret=falseでresultがOKになることはない
        LOGE("fail\n");
        result = LN_CB_ADD_HTLC_RESULT_FAIL;
    }

    //BOLT#04チェック結果が成功にせよ失敗にせよHTLC追加
    //  失敗だった場合はここで処理せず、flag.fin_delhtlcにHTLC追加後に行うことを指示しておく
    p_htlc->stat.flag.addhtlc = LN_ADDHTLC_RECV;
    LOGD("HTLC add : id=%" PRIu64 ", amount_msat=%" PRIu64 "\n", p_htlc->id, p_htlc->amount_msat);

    LOGD("  ret=%d\n", ret);
    LOGD("  id=%" PRIu64 "\n", p_htlc->id);

    LOGD("  %s\n", (hop_dataout.b_exit) ? "intended recipient" : "forwarding HTLCs");
    //転送先
    LOGD("  FWD: short_channel_id: %016" PRIx64 "\n", hop_dataout.short_channel_id);
    LOGD("  FWD: amt_to_forward: %" PRIu64 "\n", hop_dataout.amt_to_forward);
    LOGD("  FWD: outgoing_cltv_value: %d\n", hop_dataout.outgoing_cltv_value);
    LOGD("  -------\n");
    //自分への通知
    LOGD("  amount_msat: %" PRIu64 "\n", p_htlc->amount_msat);
    LOGD("  cltv_expiry: %d\n", p_htlc->cltv_expiry);
    LOGD("  my fee : %" PRIu64 "\n", (uint64_t)(p_htlc->amount_msat - hop_dataout.amt_to_forward));
    LOGD("  cltv_expiry - outgoing_cltv_value(%" PRIu32") = %d\n",  hop_dataout.outgoing_cltv_value, p_htlc->cltv_expiry - hop_dataout.outgoing_cltv_value);

    ret = true;
    if (result == LN_CB_ADD_HTLC_RESULT_OK) {
        //update_add_htlc受信通知
        //  hop nodeの場合、転送先ln_self_tのcnl_add_htlc[]に設定まで行う
        add_htlc.id = p_htlc->id;
        add_htlc.p_payment = p_htlc->payment_sha256;
        add_htlc.p_hop = &hop_dataout;
        add_htlc.amount_msat = p_htlc->amount_msat;
        add_htlc.cltv_expiry = p_htlc->cltv_expiry;
        add_htlc.idx = idx;     //転送先にとっては、prev_idxになる
                                //戻り値は転送先のidx
        add_htlc.p_onion_reason = &p_htlc->buf_onion_reason;
        add_htlc.p_shared_secret = &p_htlc->buf_shared_secret;
        ln_callback(self, LN_CB_ADD_HTLC_RECV, &add_htlc);

        if (add_htlc.ret) {
            if (hop_dataout.b_exit) {
                LOGD("final node: will backwind fulfill_htlc\n");
                LOGD("[FIN_DELHTLC](%016" PRIx64 ")%d --> %d\n", self->short_channel_id, p_htlc->stat.flag.fin_delhtlc, LN_DELHTLC_FULFILL);
                p_htlc->stat.flag.fin_delhtlc = LN_DELHTLC_FULFILL;
            } else {
                LOGD("hop node: will forward another channel\n");
                p_htlc->next_short_channel_id = hop_dataout.short_channel_id;
                p_htlc->next_idx = add_htlc.idx;
            }
        } else {
            result = LN_CB_ADD_HTLC_RESULT_FAIL;

            utl_buf_t buf = UTL_BUF_INIT;
            bool retval = ln_channel_update_get_peer(self, &buf, NULL);
            if (retval) {
                LOGE("fail: --> temporary channel failure\n");
                utl_push_u16be(&push_htlc, LNONION_TMP_CHAN_FAIL);
                utl_push_u16be(&push_htlc, (uint16_t)buf.len);
                utl_push_data(&push_htlc, buf.buf, buf.len);
                utl_buf_free(&buf);
            } else {
                LOGE("fail: --> unknown next peer\n");
                utl_push_u16be(&push_htlc, LNONION_UNKNOWN_NEXT_PEER);
            }
        }
    }
    switch (result) {
    case LN_CB_ADD_HTLC_RESULT_OK:
        break;
    case LN_CB_ADD_HTLC_RESULT_FAIL:
        LOGE("fail: will backwind fail_htlc\n");
        LOGD("[FIN_DELHTLC](%016" PRIx64 ")%d --> %d\n", self->short_channel_id, p_htlc->stat.flag.fin_delhtlc, LN_DELHTLC_FAIL);
        p_htlc->stat.flag.fin_delhtlc = LN_DELHTLC_FAIL;
        utl_buf_free(&p_htlc->buf_onion_reason);
        //折り返しだけAPIが異なる
        ln_onion_failure_create(&p_htlc->buf_onion_reason, &p_htlc->buf_shared_secret, &buf_reason);
        break;
    case LN_CB_ADD_HTLC_RESULT_MALFORMED:
        LOGE("fail: will backwind malformed_htlc\n");
        LOGD("[FIN_DELHTLC](%016" PRIx64 ")%d --> %d\n", self->short_channel_id, p_htlc->stat.flag.fin_delhtlc, LN_DELHTLC_MALFORMED);
        p_htlc->stat.flag.fin_delhtlc = LN_DELHTLC_MALFORMED;
        utl_buf_free(&p_htlc->buf_onion_reason);
        utl_buf_alloccopy(&p_htlc->buf_onion_reason, buf_reason.buf, buf_reason.len);
        break;
    default:
        LOGE("fail: unknown fail: %d\n", result);
        ret = false;
        break;
    }
    utl_buf_free(&buf_reason);

    LOGD("END\n");
    return ret;
}


bool HIDDEN ln_update_fulfill_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_msg_update_fulfill_htlc_t msg;
    ret = ln_msg_update_fulfill_htlc_read(&msg, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel-idチェック
    ret = ln_check_channel_id(msg.p_channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    uint8_t sha256[BTC_SZ_HASH256];
    btc_md_sha256(sha256, msg.p_payment_preimage, BTC_SZ_PRIVKEY);
    LOGD("hash: ");
    DUMPD(sha256, sizeof(sha256));

    ln_update_add_htlc_t *p_htlc = NULL;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //受信したfulfillは、Offered HTLCについてチェックする
        LOGD("HTLC%d: id=%" PRIu64 ", flag=%04x: ", idx, self->cnl_add_htlc[idx].id, self->cnl_add_htlc[idx].stat.bits);
        DUMPD(self->cnl_add_htlc[idx].payment_sha256, BTC_SZ_HASH256);
        if ( (self->cnl_add_htlc[idx].id == msg.id) &&
             (self->cnl_add_htlc[idx].stat.flag.addhtlc == LN_ADDHTLC_OFFER) ) {
            if (memcmp(sha256, self->cnl_add_htlc[idx].payment_sha256, BTC_SZ_HASH256) == 0) {
                p_htlc = &self->cnl_add_htlc[idx];
            } else {
                LOGE("fail: match id, but fail payment_hash\n");
            }
            break;
        }
    }

    if (p_htlc != NULL) {
        //反映
        clear_htlc_comrevflag(p_htlc, LN_DELHTLC_FULFILL);

        //update_fulfill_htlc受信通知
        ln_cb_fulfill_htlc_recv_t fulfill;
        fulfill.ret = false;
        fulfill.prev_short_channel_id = p_htlc->prev_short_channel_id;
        fulfill.prev_idx = p_htlc->prev_idx;
        fulfill.p_preimage = msg.p_payment_preimage;
        fulfill.id = p_htlc->id;
        fulfill.amount_msat = p_htlc->amount_msat;
        ln_callback(self, LN_CB_FULFILL_HTLC_RECV, &fulfill);

        if (!fulfill.ret) {
            LOGE("fail: backwind\n");
        }
    } else {
        M_SET_ERR(self, LNERR_INV_ID, "fulfill");
    }

    LOGD("END\n");
    return ret;
}


bool HIDDEN ln_update_fail_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_msg_update_fail_htlc_t msg;
    ret = ln_msg_update_fail_htlc_read(&msg, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel-idチェック
    ret = ln_check_channel_id(msg.p_channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    ret = false;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //受信したfail_htlcは、Offered HTLCについてチェックする
        ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
        if ( (p_htlc->stat.flag.addhtlc == LN_ADDHTLC_OFFER) &&
             (p_htlc->id == msg.id)) {
            //id一致
            clear_htlc_comrevflag(p_htlc, LN_DELHTLC_FAIL);

            ln_cb_fail_htlc_recv_t fail_recv;
            fail_recv.result = false;
            fail_recv.prev_short_channel_id = p_htlc->prev_short_channel_id;
            utl_buf_t reason;
            utl_buf_init_2(&reason, (CONST_CAST uint8_t *)msg.p_reason, msg.len);
            fail_recv.p_reason = &reason;
            fail_recv.p_shared_secret = &p_htlc->buf_shared_secret;
            fail_recv.prev_idx = idx;
            fail_recv.orig_id = p_htlc->id;     //元のHTLC id
            fail_recv.p_payment_hash = p_htlc->payment_sha256;
            fail_recv.malformed_failure = 0;
            ln_callback(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);

            ret = fail_recv.result;
            break;
        }
    }

    return ret;
}


bool HIDDEN ln_commitment_signed_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_msg_commitment_signed_t commsig;
    ln_msg_revoke_and_ack_t revack;
    uint8_t bak_sig[LN_SZ_SIGNATURE];
    utl_buf_t buf = UTL_BUF_INIT;

    memcpy(bak_sig, self->commit_local.signature, LN_SZ_SIGNATURE);
    ret = ln_msg_commitment_signed_read(&commsig, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        goto LABEL_EXIT;
    }
    memcpy(self->commit_local.signature, commsig.p_signature, LN_SZ_SIGNATURE);

    //channel-idチェック
    ret = ln_check_channel_id(commsig.p_channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_EXIT;
    }

    //署名チェック＋保存: To-Local
    ret = ln_comtx_create_to_local(self,
            NULL, commsig.p_htlc_signature, commsig.num_htlcs,  //HTLC署名のみ(closeなし)
            self->commit_local.commit_num + 1,
            self->commit_local.to_self_delay,
            self->commit_local.dust_limit_sat);
    if (!ret) {
        LOGE("fail: create_to_local\n");
        goto LABEL_EXIT;
    }

    //for commitment_nubmer debug
    // {
    //     static int count;
    //     count++;
    //     if (count >= 2) {
    //         LOGE("**************ABORT*************\n");
    //         printf("**************ABORT*************\n");
    //         exit(-1);
    //     }
    // }

    //commitment_signed recv flag
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
        if ( LN_HTLC_ENABLE(p_htlc) &&
             ( LN_HTLC_ENABLE_LOCAL_ADDHTLC_OFFER(p_htlc) ||
               LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(p_htlc) ||
               LN_HTLC_ENABLE_LOCAL_DELHTLC_OFFER(p_htlc) ||
               LN_HTLC_ENABLE_LOCAL_DELHTLC_RECV(p_htlc) ) ) {
            LOGD(" [%d]comrecv=1\n", idx);
            p_htlc->stat.flag.comrecv = 1;
        }
    }

    uint8_t prev_secret[BTC_SZ_PRIVKEY];
    ln_signer_create_prev_per_commit_secret(self, prev_secret, NULL);

    //storage_indexデクリメントおよびper_commit_secret更新
    ln_signer_keys_update_per_commitment_secret(self);
    ln_update_scriptkeys(self);
    //ln_print_keys(&self->funding_local, &self->funding_remote);

    //チェックOKであれば、revoke_and_ackを返す
    //HTLCに変化がある場合、revoke_and_ack→commitment_signedの順で送信

    // //revokeするsecret
    // for (uint64_t index = 0; index <= self->commit_local.revoke_num + 1; index++) {
    //     uint8_t old_secret[BTC_SZ_PRIVKEY];
    //     ln_derkey_storage_create_secret(old_secret, self->priv_data.storage_seed, LN_SECRET_INDEX_INIT - index);
    //     LOGD("$$$ old_secret(%016" PRIx64 "): ", LN_SECRET_INDEX_INIT -index);
    //     DUMPD(old_secret, sizeof(old_secret));
    // }

    revack.p_channel_id = commsig.p_channel_id;
    revack.p_per_commitment_secret = prev_secret;
    revack.p_next_per_commitment_point = self->funding_local.pubkeys.per_commitment_point;
    LOGD("  revoke_and_ack.next_per_commitment_point=%" PRIu64 "\n", self->commit_local.commit_num);
    ret = ln_msg_revoke_and_ack_write(&buf, &revack);
    if (ret) {
        //revoke_and_ack send flag
        for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
            ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
            if ( LN_HTLC_ENABLE(p_htlc) &&
                ( LN_HTLC_ENABLE_LOCAL_ADDHTLC_OFFER(p_htlc) ||
                  LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(p_htlc) ||
                  LN_HTLC_ENABLE_LOCAL_DELHTLC_OFFER(p_htlc) ||
                  LN_HTLC_ENABLE_LOCAL_DELHTLC_RECV(p_htlc) ) ){
                LOGD(" [%d]revsend=1\n", idx);
                p_htlc->stat.flag.revsend = 1;
            }
        }
        ln_callback(self, LN_CB_SEND_REQ, &buf);
        utl_buf_free(&buf);
    } else {
        LOGE("fail: ln_msg_revoke_and_ack_create\n");
    }

LABEL_EXIT:
    if (ret) {
        //revoke_and_ackを返せた場合だけ保存することにする
        self->commit_local.revoke_num = self->commit_local.commit_num;
        self->commit_local.commit_num++;
        M_DBG_COMMITNUM(self);
        M_DB_SECRET_SAVE(self);
        M_DB_SELF_SAVE(self);
    } else {
        //戻す
        LOGE("fail: restore signature\n");
        memcpy(self->commit_local.signature, bak_sig, LN_SZ_SIGNATURE);
    }

    LOGD("END\n");
    return ret;
}


bool HIDDEN ln_revoke_and_ack_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_msg_revoke_and_ack_t msg;
    ret = ln_msg_revoke_and_ack_read(&msg, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        goto LABEL_EXIT;
    }

    //channel-idチェック
    ret = ln_check_channel_id(msg.p_channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_EXIT;
    }

    //prev_secretチェック
    //  受信したper_commitment_secretが、前回受信したper_commitment_pointと等しいこと
    //XXX: not check?
    uint8_t prev_commitpt[BTC_SZ_PUBKEY];
    ret = btc_keys_priv2pub(prev_commitpt, msg.p_per_commitment_secret);
    if (!ret) {
        LOGE("fail: prev_secret convert\n");
        goto LABEL_EXIT;
    }

    LOGD("$$$ revoke_num: %" PRIu64 "\n", self->commit_local.revoke_num);
    LOGD("$$$ prev per_commit_pt: ");
    DUMPD(prev_commitpt, BTC_SZ_PUBKEY);
    // uint8_t old_secret[BTC_SZ_PRIVKEY];
    // for (uint64_t index = 0; index <= self->commit_local.revoke_num + 1; index++) {
    //     ret = ln_derkey_storage_get_secret(old_secret, &self->peer_storage, LN_SECRET_INDEX_INIT - index);
    //     if (ret) {
    //         uint8_t pubkey[BTC_SZ_PUBKEY];
    //         btc_keys_priv2pub(pubkey, old_secret);
    //         //M_DB_SELF_SAVE(self);
    //         LOGD("$$$ old_secret(%016" PRIx64 "): ", LN_SECRET_INDEX_INIT - index);
    //         DUMPD(old_secret, sizeof(old_secret));
    //         LOGD("$$$ pubkey: ");
    //         DUMPD(pubkey, sizeof(pubkey));
    //     } else {
    //         LOGD("$$$ fail: get last secret\n");
    //         //goto LABEL_EXIT;
    //     }
    // }

    // if (memcmp(prev_commitpt, self->funding_remote.pubkeys.prev_per_commitment_point, BTC_SZ_PUBKEY) != 0) {
    //     LOGE("fail: prev_secret mismatch\n");

    //     //check re-send
    //     if (memcmp(new_commitpt, self->funding_remote.pubkeys.per_commitment_point, BTC_SZ_PUBKEY) == 0) {
    //         //current per_commitment_point
    //         LOGD("skip: same as previous next_per_commitment_point\n");
    //         ret = true;
    //     } else {
    //         LOGD("recv secret: ");
    //         DUMPD(prev_commitpt, BTC_SZ_PUBKEY);
    //         LOGD("my secret: ");
    //         DUMPD(self->funding_remote.pubkeys.prev_per_commitment_point, BTC_SZ_PUBKEY);
    //         ret = false;
    //     }
    //     goto LABEL_EXIT;
    // }

    //prev_secret保存
    ret = store_peer_percommit_secret(self, msg.p_per_commitment_secret);
    if (!ret) {
        LOGE("fail: store prev secret\n");
        goto LABEL_EXIT;
    }

    //per_commitment_point更新
    memcpy(self->funding_remote.pubkeys.prev_per_commitment_point, self->funding_remote.pubkeys.per_commitment_point, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys.per_commitment_point, msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);
    ln_update_scriptkeys(self);
    //ln_print_keys(&self->funding_local, &self->funding_remote);

    //revoke_and_ack受信フラグ
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
        if ( LN_HTLC_ENABLE(p_htlc) &&
             ( LN_HTLC_ENABLE_REMOTE_ADDHTLC_OFFER(p_htlc) ||
               LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(p_htlc) ||
               LN_HTLC_ENABLE_REMOTE_DELHTLC_OFFER(p_htlc) ||
               LN_HTLC_ENABLE_REMOTE_DELHTLC_RECV(p_htlc)) ){
            LOGD(" [%d]revrecv=1\n", idx);
            p_htlc->stat.flag.revrecv = 1;
        }
    }

    self->commit_remote.revoke_num = self->commit_remote.commit_num - 1;
    M_DBG_COMMITNUM(self);
    M_DB_SELF_SAVE(self);

LABEL_EXIT:
    LOGD("END\n");
    return ret;
}


bool HIDDEN ln_update_fee_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_msg_update_fee_t msg;
    uint32_t rate;
    uint32_t old_fee;

    ret = ln_msg_update_fee_read(&msg, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        goto LABEL_EXIT;
    }

    //channel-idチェック
    ret = ln_check_channel_id(msg.p_channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_EXIT;
    }

    //BOLT02
    //  A receiving node:
    //    if the sender is not responsible for paying the Bitcoin fee:
    //      MUST fail the channel.
    ret = !ln_is_funder(self);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_STATE, "not fundee");
        goto LABEL_EXIT;
    }

    ret = (msg.feerate_per_kw >= LN_FEERATE_PER_KW_MIN);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_VALUE, "too low feerate_per_kw");
        goto LABEL_EXIT;
    }

    ln_callback(self, LN_CB_GET_LATEST_FEERATE, &rate);
    ret = M_UPDATEFEE_CHK_MIN_OK(msg.feerate_per_kw, rate);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_VALUE, "too low feerate_per_kw from current");
        goto LABEL_EXIT;
    }
    ret = M_UPDATEFEE_CHK_MAX_OK(msg.feerate_per_kw, rate);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_VALUE, "too large feerate_per_kw from current");
        goto LABEL_EXIT;
    }

    //feerate_per_kw更新
    old_fee = self->feerate_per_kw;
    LOGD("change fee: %" PRIu32 " --> %" PRIu32 "\n", self->feerate_per_kw, msg.feerate_per_kw);
    self->feerate_per_kw = msg.feerate_per_kw;
    //M_DB_SELF_SAVE(self);    //確定するまでDB保存しない

    //fee更新通知
    ln_callback(self, LN_CB_UPDATE_FEE_RECV, &old_fee);

LABEL_EXIT:
    LOGD("END\n");
    return ret;
}


bool HIDDEN ln_update_fail_malformed_htlc_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    (void)self; (void)pData; (void)Len;

    LOGD("BEGIN\n");

    ln_msg_update_fail_malformed_htlc_t msg;
    bool ret = ln_msg_update_fail_malformed_htlc_read(&msg, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel-idチェック
    ret = ln_check_channel_id(msg.p_channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //failure_code check
    if ((msg.failure_code & LNERR_ONION_BADONION) == 0) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "no BADONION bit");
        return false;
    }

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
        //受信したmal_htlcは、Offered HTLCについてチェックする。
        //仕様としては、sha256_of_onionを確認し、再送か別エラーにするなので、
        //  ここでは受信したfailure_codeでエラーを作る。
        //
        // BOLT#02
        //  if the sha256_of_onion in update_fail_malformed_htlc doesn't match the onion it sent:
        //      MAY retry or choose an alternate error response.
        if ( (p_htlc->stat.flag.addhtlc == LN_ADDHTLC_OFFER) &&
             (p_htlc->id == msg.id)) {
            //id一致
            clear_htlc_comrevflag(p_htlc, LN_DELHTLC_MALFORMED);

            utl_buf_t reason = UTL_BUF_INIT;
            utl_push_t push_rsn;
            utl_push_init(&push_rsn, &reason, sizeof(uint16_t) + BTC_SZ_HASH256);
            utl_push_u16be(&push_rsn, msg.failure_code);
            utl_push_data(&push_rsn, msg.p_sha256_of_onion, BTC_SZ_HASH256);

            ln_cb_fail_htlc_recv_t fail_recv;
            fail_recv.result = false;
            fail_recv.prev_short_channel_id = p_htlc->prev_short_channel_id;
            fail_recv.p_reason = &reason;
            fail_recv.p_shared_secret = &p_htlc->buf_shared_secret;
            fail_recv.prev_idx = idx;
            fail_recv.orig_id = p_htlc->id;     //元のHTLC id
            fail_recv.p_payment_hash = p_htlc->payment_sha256;
            fail_recv.malformed_failure = msg.failure_code;
            ln_callback(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);
            utl_buf_free(&reason);

            ret = fail_recv.result;
            break;
        }
    }

    LOGD("END\n");
    return ret;
}


bool ln_add_htlc_set(ln_self_t *self,
            uint64_t *pHtlcId,
            utl_buf_t *pReason,
            const uint8_t *pPacket,
            uint64_t AmountMsat,
            uint32_t CltvValue,
            const uint8_t *pPaymentHash,
            uint64_t PrevShortChannelId,
            uint16_t PrevIdx,
            const utl_buf_t *pSharedSecrets)
{
    LOGD("BEGIN\n");

    //BOLT2
    //  MUST NOT send an update_add_htlc after a shutdown.
    if (self->shutdown_flag != 0) {
        M_SET_ERR(self, LNERR_INV_STATE, "shutdown: not allow add_htlc");
        return false;
    }

    uint16_t idx;
    bool ret = set_add_htlc(self, pHtlcId, pReason, &idx,
                    pPacket, AmountMsat, CltvValue, pPaymentHash,
                    PrevShortChannelId, PrevIdx, pSharedSecrets);
    if (ret) {
        self->cnl_add_htlc[idx].stat.flag.addhtlc = LN_ADDHTLC_OFFER;
    }

    return ret;
}


bool ln_add_htlc_set_fwd(ln_self_t *self,
            uint64_t *pHtlcId,
            utl_buf_t *pReason,
            uint16_t *pNextIdx,
            const uint8_t *pPacket,
            uint64_t AmountMsat,
            uint32_t CltvValue,
            const uint8_t *pPaymentHash,
            uint64_t PrevShortChannelId,
            uint16_t PrevIdx,
            const utl_buf_t *pSharedSecrets)
{
    LOGD("BEGIN\n");

    //BOLT2
    //  MUST NOT send an update_add_htlc after a shutdown.
    if (self->shutdown_flag != 0) {
        M_SET_ERR(self, LNERR_INV_STATE, "shutdown: not allow add_htlc");
        return false;
    }

    bool ret = set_add_htlc(self, pHtlcId, pReason, pNextIdx,
                    pPacket, AmountMsat, CltvValue, pPaymentHash,
                    PrevShortChannelId, PrevIdx, pSharedSecrets);
    //flag.addhtlcは #ln_recv_idle_proc()のHTLC final経由で #ln_add_htlc_start_fwd()を呼び出して設定
    dbg_htlcflag(&self->cnl_add_htlc[PrevIdx].stat.flag);

    return ret;
}


void ln_add_htlc_start_fwd(ln_self_t *self, uint16_t Idx)
{
    LOGD("forwarded HTLC\n");
    self->cnl_add_htlc[Idx].stat.flag.addhtlc = LN_ADDHTLC_OFFER;
    dbg_htlcflag(&self->cnl_add_htlc[Idx].stat.flag);
}


bool ln_fulfill_htlc_set(ln_self_t *self, uint16_t Idx, const uint8_t *pPreImage)
{
    LOGD("BEGIN\n");

    //self->cnl_add_htlc[Idx]にupdate_fulfill_htlcが作成出来るだけの情報を設定
    //  final nodeにふさわしいかのチェックはupdate_add_htlc受信時に行われている
    //  update_fulfill_htlc未送信状態にしておきたいが、このタイミングではadd_htlcのcommitは済んでいない

    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    clear_htlc_comrevflag(p_htlc, LN_DELHTLC_FULFILL);
    utl_buf_alloccopy(&p_htlc->buf_payment_preimage, pPreImage, LN_SZ_PREIMAGE);
    M_DB_SELF_SAVE(self);
    LOGD("self->cnl_add_htlc[%d].flag = 0x%04x\n", Idx, self->cnl_add_htlc[Idx].stat.bits);
    dbg_htlcflag(&self->cnl_add_htlc[Idx].stat.flag);
    return true;
}


bool ln_fail_htlc_set(ln_self_t *self, uint16_t Idx, const utl_buf_t *pReason)
{
    LOGD("BEGIN\n");

    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    clear_htlc_comrevflag(p_htlc, LN_DELHTLC_FAIL);
    utl_buf_free(&p_htlc->buf_onion_reason);
    ln_onion_failure_forward(&p_htlc->buf_onion_reason, &p_htlc->buf_shared_secret, pReason);

    LOGD("END: self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, p_htlc->stat.bits);
    LOGD("   reason: ");
    DUMPD(pReason->buf, pReason->len);
    dbg_htlcflag(&p_htlc->stat.flag);
    return true;
}


bool ln_fail_htlc_set_bwd(ln_self_t *self, uint16_t Idx, const utl_buf_t *pReason)
{
    LOGD("BEGIN\n");

    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    clear_htlc_comrevflag(p_htlc, p_htlc->stat.flag.delhtlc);
    p_htlc->stat.flag.fin_delhtlc = LN_DELHTLC_FAIL;
    utl_buf_free(&p_htlc->buf_onion_reason);
    ln_onion_failure_forward(&p_htlc->buf_onion_reason, &p_htlc->buf_shared_secret, pReason);

    LOGD("END: self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, p_htlc->stat.bits);
    LOGD("   reason: ");
    DUMPD(pReason->buf, pReason->len);
    dbg_htlcflag(&p_htlc->stat.flag);
    return true;
}


void ln_del_htlc_start_bwd(ln_self_t *self, uint16_t Idx)
{
    LOGD("backward HTLC\n");
    self->cnl_add_htlc[Idx].stat.flag.delhtlc = self->cnl_add_htlc[Idx].stat.flag.fin_delhtlc;
    dbg_htlcflag(&self->cnl_add_htlc[Idx].stat.flag);
}


void ln_recv_idle_proc(ln_self_t *self, uint32_t FeeratePerKw)
{
    int htlc_num = 0;
    bool b_final = true;    //true: HTLCの追加から反映までが完了した状態
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
        if (LN_HTLC_ENABLE(p_htlc)) {
            htlc_num++;
            ln_htlcflag_t *p_flag = &p_htlc->stat.flag;
            if (!p_flag->comsend || !p_flag->revrecv || !p_flag->comrecv || !p_flag->revsend) {
                //HTLCとして有効なのに、commitment_signed/revoke_and_ackの送受信が完了していない
                b_final = false;
                break;
            }
        }
    }
    if ( (htlc_num == 0) &&
         ((self->short_channel_id == 0) || (self->feerate_per_kw == FeeratePerKw))) {
        return;
    }
    if (htlc_num == 0) {
        LOGD("$$$ update_fee: %" PRIu32 " ==> %" PRIu32 "\n", self->feerate_per_kw, FeeratePerKw);
        b_final = false;
    }
    if (b_final) {
        recv_idle_proc_final(self);
    } else {
        recv_idle_proc_nonfinal(self, FeeratePerKw);
    }
}


void ln_channel_reestablish_after(ln_self_t *self)
{
    M_DBG_COMMITNUM(self);
    M_DBG_HTLCFLAGALL(self);

    LOGD("self->reest_revoke_num=%" PRIu64 "\n", self->reest_revoke_num);
    LOGD("self->reest_commit_num=%" PRIu64 "\n", self->reest_commit_num);

    //
    //BOLT#02
    //  commit_txは、作成する関数内でcommit_num+1している(インクリメントはしない)。
    //  そのため、(commit_num+1)がcommit_tx作成時のcommitment numberである。

    //  next_local_commitment_number
    if (self->commit_remote.commit_num == self->reest_commit_num) {
        //  if next_local_commitment_number is equal to the commitment number of the last commitment_signed message the receiving node has sent:
        //      * MUST reuse the same commitment number for its next commitment_signed.
        //remote.per_commitment_pointを1つ戻して、キャンセルされたupdateメッセージを再送する

        LOGD("$$$ resend: previous update message\n");
        int idx;
        for (idx = 0; idx < LN_HTLC_MAX; idx++) {
            ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
            if (LN_HTLC_ENABLE(p_htlc)) {
                utl_buf_t buf = UTL_BUF_INIT;
                switch (p_htlc->stat.bits & ~LN_HTLCFLAG_MASK_FINDELHTLC) {
                case M_HTLCFLAG_BITS_ADDHTLC:
                    //update_add_htlc送信
                    LOGD("resend: update_add_htlc\n");
                    p_htlc->p_channel_id = self->channel_id;
                    (void)msg_update_add_htlc_write(&buf, p_htlc);
                    break;
                case M_HTLCFLAG_BITS_FULFILLHTLC:
                    //update_fulfill_htlc送信
                    LOGD("resend: update_fulfill_htlc\n");
                    fulfill_htlc_create(self, &buf, idx);
                    break;
                case M_HTLCFLAG_BITS_FAILHTLC:
                    //update_fail_htlc送信
                    LOGD("resend: update_fail_htlc\n");
                    fail_htlc_create(self, &buf, idx);
                    break;
                case M_HTLCFLAG_BITS_MALFORMEDHTLC:
                    //update_fail_malformed_htlc送信
                    LOGD("resend: update_fail_malformed_htlc\n");
                    fail_malformed_htlc_create(self, &buf, idx);
                    break;
                default:
                    //none
                    break;
                }
                if (buf.len > 0) {
                    p_htlc->stat.flag.comsend = 0;
                    ln_callback(self, LN_CB_SEND_REQ, &buf);
                    utl_buf_free(&buf);
                    self->cnl_add_htlc[idx].stat.flag.updsend = 1;
                    self->commit_remote.commit_num--;
                    M_DB_SELF_SAVE(self);
                    break;
                }
            }
        }
        if (idx >= LN_HTLC_MAX) {
            LOGE("fail: cannot find HTLC to process\n");
        }
    }

    //BOLT#02
    //  next_remote_revocation_number
    if (self->commit_local.revoke_num == self->reest_revoke_num) {
        // if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack the receiving node sent, AND the receiving node hasn't already received a closing_signed:
        //      * MUST re-send the revoke_and_ack.
        LOGD("$$$ next_remote_revocation_number == local commit_num: resend\n");

        uint8_t prev_secret[BTC_SZ_PRIVKEY];
        ln_signer_create_prev_per_commit_secret(self, prev_secret, NULL);

        utl_buf_t buf = UTL_BUF_INIT;
        ln_msg_revoke_and_ack_t revack;
        revack.p_channel_id = self->channel_id;
        revack.p_per_commitment_secret = prev_secret;
        revack.p_next_per_commitment_point = self->funding_local.pubkeys.per_commitment_point;
        LOGD("  send revoke_and_ack.next_per_commitment_point=%" PRIu64 "\n", self->funding_local.pubkeys.per_commitment_point);
        bool ret = ln_msg_revoke_and_ack_write(&buf, &revack);
        if (ret) {
            ln_callback(self, LN_CB_SEND_REQ, &buf);
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

static bool msg_update_add_htlc_write(utl_buf_t *pBuf, const ln_update_add_htlc_t *pInfo)
{
    ln_msg_update_add_htlc_t msg;
    msg.p_channel_id = pInfo->p_channel_id;
    msg.id = pInfo->id;
    msg.amount_msat = pInfo->amount_msat;
    msg.p_payment_hash = pInfo->payment_sha256;
    msg.cltv_expiry = pInfo->cltv_expiry;
    msg.p_onion_routing_packet = pInfo->buf_onion_reason.buf;
    return ln_msg_update_add_htlc_write(pBuf, &msg);
}


static bool msg_update_add_htlc_read(ln_update_add_htlc_t *pInfo, const uint8_t *pData, uint16_t Len)
{
    ln_msg_update_add_htlc_t msg;
    if (!ln_msg_update_add_htlc_read(&msg, pData, Len)) return false;
    memcpy(pInfo->p_channel_id, msg.p_channel_id, LN_SZ_CHANNEL_ID);
    pInfo->id = msg.id;
    pInfo->amount_msat = msg.amount_msat;
    memcpy(pInfo->payment_sha256, msg.p_payment_hash, BTC_SZ_HASH256);
    pInfo->cltv_expiry = msg.cltv_expiry;
    return utl_buf_alloccopy(&pInfo->buf_onion_reason, msg.p_onion_routing_packet, LN_SZ_ONION_ROUTE);
}


/** [BOLT#2]ln_update_add_htlc_recv()のチェック項目
 *
 */
static bool check_recv_add_htlc_bolt2(ln_self_t *self, const ln_update_add_htlc_t *p_htlc)
{
    //shutdown
    if (self->shutdown_flag & LN_SHDN_FLAG_RECV) {
        M_SET_ERR(self, LNERR_INV_STATE, "already shutdown received");
        return false;
    }

    //amount_msatが0の場合、チャネルを失敗させる。
    //amount_msatが自分のhtlc_minimum_msat未満の場合、チャネルを失敗させる。
    //  receiving an amount_msat equal to 0, OR less than its own htlc_minimum_msat
    if (p_htlc->amount_msat < self->commit_local.htlc_minimum_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "amount_msat < local htlc_minimum_msat");
        return false;
    }

    //送信側が現在のfeerate_per_kwで支払えないようなamount_msatの場合、チャネルを失敗させる。
    //  receiving an amount_msat that the sending node cannot afford at the current feerate_per_kw
    if (self->their_msat < p_htlc->amount_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "their_msat too small(%" PRIu64 " < %" PRIu64 ")", self->their_msat, p_htlc->amount_msat);
        return false;
    }

    //追加した結果が自分のmax_accepted_htlcsより多くなるなら、チャネルを失敗させる。
    //  if a sending node adds more than its max_accepted_htlcs HTLCs to its local commitment transaction
    if (self->commit_local.max_accepted_htlcs < self->commit_local.htlc_num) {
        M_SET_ERR(self, LNERR_INV_VALUE, "over max_accepted_htlcs : %d", self->commit_local.htlc_num);
        return false;
    }

    //加算した結果が自分のmax_htlc_value_in_flight_msatを超えるなら、チャネルを失敗させる。
    //      adds more than its max_htlc_value_in_flight_msat worth of offered HTLCs to its local commitment transaction
    uint64_t max_htlc_value_in_flight_msat = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].stat.flag.addhtlc == LN_ADDHTLC_OFFER) {
            max_htlc_value_in_flight_msat += self->cnl_add_htlc[idx].amount_msat;
        }
    }
    if (max_htlc_value_in_flight_msat > self->commit_local.max_htlc_value_in_flight_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "exceed local max_htlc_value_in_flight_msat");
        return false;
    }

    //cltv_expiryが500000000以上の場合、チャネルを失敗させる。
    //  if sending node sets cltv_expiry to greater or equal to 500000000
    if (p_htlc->cltv_expiry >= BTC_TX_LOCKTIME_LIMIT) {
        M_SET_ERR(self, LNERR_INV_VALUE, "cltv_expiry >= 500000000");
        return false;
    }

    //for channels with chain_hash identifying the Bitcoin blockchain, if the four most significant bytes of amount_msat are not 0
    if (p_htlc->amount_msat & (uint64_t)0xffffffff00000000) {
        M_SET_ERR(self, LNERR_INV_VALUE, "Bitcoin amount_msat must 4 MSByte not 0");
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


static bool check_recv_add_htlc_bolt4_common(ln_self_t *self, utl_push_t *pPushReason)
{
    (void)pPushReason;

    //shutdown
    if (self->shutdown_flag & LN_SHDN_FLAG_SEND) {
        M_SET_ERR(self, LNERR_INV_STATE, "already shutdown sent");
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
 *      self->cnl_add_htlc[Index]: update_add_htlcパラメータ
 *      pDataOut                 : onionパラメータ
 *
 * +------+                          +------+                          +------+
 * |node_A|------------------------->|node_B|------------------------->|node_C|
 * +------+  update_add_htlc         +------+  update_add_htlc         +------+
 *             amount_msat_AB                    amount_msat_BC
 *             onion_routing_packet_AB           onion_routing_packet_BC
 *               amt_to_forward_BC
 *
 * @param[in,out]       self
 * @param[out]          pDataOut        onion packetデコード結果
 * @param[out]          pPushReason     error reason
 * @param[in,out]       pAddHtlc        activeなself->cnl_add_htlc[Index]
 * @param[out]          pPreImage       pAddHtlc->payment_sha256に該当するpreimage
 * @param[in]           Height          current block height
 * @retval  true    成功
 */
static bool check_recv_add_htlc_bolt4_final(ln_self_t *self,
                    ln_hop_dataout_t *pDataOut,
                    utl_push_t *pPushReason,
                    ln_update_add_htlc_t *pAddHtlc,
                    uint8_t *pPreImage,
                    int32_t Height)
{
    bool ret;

    //preimage検索
    ln_db_preimg_t preimg;
    uint8_t preimage_hash[BTC_SZ_HASH256];

    preimg.amount_msat = (uint64_t)-1;
    preimg.expiry = 0;
    void *p_cur;
    ret = ln_db_preimg_cur_open(&p_cur);
    while (ret) {
        bool detect;
        ret = ln_db_preimg_cur_get(p_cur, &detect, &preimg);     //from invoice
        if (detect) {
            memcpy(pPreImage, preimg.preimage, LN_SZ_PREIMAGE);
            ln_preimage_hash_calc(preimage_hash, pPreImage);
            if (memcmp(preimage_hash, pAddHtlc->payment_sha256, BTC_SZ_HASH256) == 0) {
                //一致
                LOGD("match preimage: ");
                DUMPD(pPreImage, LN_SZ_PREIMAGE);
                break;
            }
        }
    }
    ln_db_preimg_cur_close(p_cur);

    if (!ret) {
        //C1. if the payment hash has already been paid:
        //      ★(採用)MAY treat the payment hash as unknown.★
        //      MAY succeed in accepting the HTLC.
        //C3. if the payment hash is unknown:
        //      unknown_payment_hash
        M_SET_ERR(self, LNERR_INV_VALUE, "preimage mismatch");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_PAY_HASH);
        //no data

        return false;
    }

    //C2. if the amount paid is less than the amount expected:
    //      incorrect_payment_amount
    if (pAddHtlc->amount_msat < preimg.amount_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "incorrect_payment_amount(final) : %" PRIu64 " < %" PRIu64, pDataOut->amt_to_forward, preimg.amount_msat);
        ret = false;
        utl_push_u16be(pPushReason, LNONION_INCORR_PAY_AMT);
        //no data

        return false;
    }

    //C4. if the amount paid is more than twice the amount expected:
    //      incorrect_payment_amount
    if (preimg.amount_msat * 2 < pAddHtlc->amount_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "large amount_msat : %" PRIu64 " < %" PRIu64, preimg.amount_msat * 2, pDataOut->amt_to_forward);
        ret = false;
        utl_push_u16be(pPushReason, LNONION_INCORR_PAY_AMT);
        //no data

        return false;
    }

    //C5. if the cltv_expiry value is unreasonably near the present:
    //      final_expiry_too_soon
    //          今のところ、min_final_cltv_expiryは固定値(#LN_MIN_FINAL_CLTV_EXPIRY)しかない。
    LOGD("outgoing_cltv_value=%" PRIu32 ", min_final_cltv_expiry=%" PRIu16 ", height=%" PRId32 "\n", pDataOut->outgoing_cltv_value, LN_MIN_FINAL_CLTV_EXPIRY, Height);
    if ( (pDataOut->outgoing_cltv_value + M_HYSTE_CLTV_EXPIRY_SOON < (uint32_t)Height + LN_MIN_FINAL_CLTV_EXPIRY) ||
         (pDataOut->outgoing_cltv_value < (uint32_t)Height + M_HYSTE_CLTV_EXPIRY_MIN) ) {
        LOGD("%" PRIu32 " < %" PRId32 "\n", pDataOut->outgoing_cltv_value + M_HYSTE_CLTV_EXPIRY_SOON, Height + M_HYSTE_CLTV_EXPIRY_MIN);
        M_SET_ERR(self, LNERR_INV_VALUE, "cltv_expiry too soon(final)");
        utl_push_u16be(pPushReason, LNONION_FINAL_EXPIRY_TOO_SOON);

        return false;
    }

    //C6. if the outgoing_cltv_value does NOT correspond with the cltv_expiry from the final node's HTLC:
    //      final_incorrect_cltv_expiry
    if (pDataOut->outgoing_cltv_value != pAddHtlc->cltv_expiry) {
        LOGD("%" PRIu32 " --- %" PRIu32 "\n", pDataOut->outgoing_cltv_value, ln_cltv_expily_delta(self));
        M_SET_ERR(self, LNERR_INV_VALUE, "incorrect cltv expiry(final)");
        utl_push_u16be(pPushReason, LNONION_FINAL_INCORR_CLTV_EXP);
        //[4:cltv_expiry]
        utl_push_u32be(pPushReason, pDataOut->outgoing_cltv_value);

        return false;
    }

    //C7. if the amt_to_forward is greater than the incoming_htlc_amt from the final node's HTLC:
    //      final_incorrect_htlc_amount
    if (pDataOut->amt_to_forward > pAddHtlc->amount_msat) {
        LOGD("%" PRIu64 " --- %" PRIu64 "\n", pDataOut->amt_to_forward, pAddHtlc->amount_msat);
        M_SET_ERR(self, LNERR_INV_VALUE, "incorrect_payment_amount(final)");
        utl_push_u16be(pPushReason, LNONION_FINAL_INCORR_HTLC_AMT);
        //[4:incoming_htlc_amt]
        utl_push_u32be(pPushReason, pAddHtlc->amount_msat);

        return false;
    }

    return true;
}


/** [BOLT#4]ln_update_add_htlc_recv()のチェック(forward node)
 *
 * @param[in,out]       self
 * @param[out]          pDataOut        onion packetデコード結果
 * @param[out]          pPushReason     error reason
 * @param[in,out]       pAddHtlc        activeなself->cnl_add_htlc[Index]
 * @param[in]           Height          current block height
 * @retval  true    成功
 */
static bool check_recv_add_htlc_bolt4_forward(ln_self_t *self,
                    ln_hop_dataout_t *pDataOut,
                    utl_push_t *pPushReason,
                    ln_update_add_htlc_t *pAddHtlc,
                    int32_t Height)
{
    //処理前呼び出し
    //  転送先取得(final nodeの場合は、p_next_selfにNULLが返る)
    ln_cb_add_htlc_recv_prev_t recv_prev;
    recv_prev.p_next_self = NULL;
    if (pDataOut->short_channel_id != 0) {
        recv_prev.next_short_channel_id = pDataOut->short_channel_id;
        ln_callback(self, LN_CB_ADD_HTLC_RECV_PREV, &recv_prev);
    }

    //B6. if the outgoing channel has requirements advertised in its channel_announcement's features, which were NOT included in the onion:
    //      required_channel_feature_missing
    //
    //      2018/09/07: channel_announcement.features not defined

    //B7. if the receiving peer specified by the onion is NOT known:
    //      unknown_next_peer
    if ( (pDataOut->short_channel_id == 0) ||
         (recv_prev.p_next_self == NULL) ||
         (ln_status_get(recv_prev.p_next_self) != LN_STATUS_NORMAL) ) {
        //転送先がない
        M_SET_ERR(self, LNERR_INV_VALUE, "no next channel");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        //no data

        return false;
    }

    //channel_update読み込み
    ln_msg_channel_update_t cnlupd;
    utl_buf_t cnlupd_buf = UTL_BUF_INIT;
    uint8_t peer_id[BTC_SZ_PUBKEY];
    bool ret = ln_node_search_node_id(peer_id, pDataOut->short_channel_id);
    if (ret) {
        uint8_t dir = ln_sort_to_dir(ln_node_id_sort(self, peer_id));
        ret = ln_db_annocnlupd_load(&cnlupd_buf, NULL, pDataOut->short_channel_id, dir);
        if (!ret) {
            LOGE("fail: ln_db_annocnlupd_load: %016" PRIx64 ", dir=%d\n", pDataOut->short_channel_id, dir);
        }
    } else {
        LOGE("fail: ln_node_search_node_id\n");
    }
    if (ret) {
        ret = ln_msg_channel_update_read(&cnlupd, cnlupd_buf.buf, cnlupd_buf.len);
        if (!ret) {
            LOGE("fail: ln_msg_channel_update_read\n");
        }
    }
    if (!ret) {
        //channel_updateがない
        M_SET_ERR(self, LNERR_INV_VALUE, "no channel_update");
        utl_push_u16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        //no data

        return false;
    }
    LOGD("short_channel_id=%016" PRIx64 "\n", pDataOut->short_channel_id);

    //B8. if the HTLC amount is less than the currently specified minimum amount:
    //      amount_below_minimum
    //      (report the amount of the incoming HTLC and the current channel setting for the outgoing channel.)
    if (pDataOut->amt_to_forward < recv_prev.p_next_self->commit_remote.htlc_minimum_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "lower than htlc_minimum_msat : %" PRIu64 " < %" PRIu64, pDataOut->amt_to_forward, recv_prev.p_next_self->commit_remote.htlc_minimum_msat);
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
    uint64_t fwd_fee = ln_forward_fee(self, pDataOut->amt_to_forward);
    if (pAddHtlc->amount_msat < pDataOut->amt_to_forward + fwd_fee) {
        M_SET_ERR(self, LNERR_INV_VALUE, "fee not enough : %" PRIu32 " < %" PRIu32, fwd_fee, pAddHtlc->amount_msat - pDataOut->amt_to_forward);
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
    if ( (pAddHtlc->cltv_expiry <= pDataOut->outgoing_cltv_value) ||
            (pAddHtlc->cltv_expiry + ln_cltv_expily_delta(recv_prev.p_next_self) < pDataOut->outgoing_cltv_value) ) {
        M_SET_ERR(self, LNERR_INV_VALUE, "cltv not enough : %" PRIu32, ln_cltv_expily_delta(recv_prev.p_next_self));
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
    LOGD("cltv_value=%" PRIu32 ", expiry_delta=%" PRIu16 ", height=%" PRId32 "\n", pAddHtlc->cltv_expiry, cnlupd.cltv_expiry_delta, Height);
    if ( (pAddHtlc->cltv_expiry + M_HYSTE_CLTV_EXPIRY_SOON < (uint32_t)Height + cnlupd.cltv_expiry_delta) ||
         (pAddHtlc->cltv_expiry < (uint32_t)Height + M_HYSTE_CLTV_EXPIRY_MIN) ) {
        LOGD("%" PRIu32 " < %" PRId32 "\n", pAddHtlc->cltv_expiry + M_HYSTE_CLTV_EXPIRY_SOON, Height + cnlupd.cltv_expiry_delta);
        M_SET_ERR(self, LNERR_INV_VALUE, "expiry too soon : %" PRIu32, ln_cltv_expily_delta(recv_prev.p_next_self));
        utl_push_u16be(pPushReason, LNONION_EXPIRY_TOO_SOON);
        //[2:len]
        utl_push_u16be(pPushReason, cnlupd_buf.len);
        //[len:channel_update]
        utl_push_data(pPushReason, cnlupd_buf.buf, cnlupd_buf.len);

        return false;
    }

    //B12. if the cltv_expiry is unreasonably far in the future:
    //      expiry_too_far
    if (pAddHtlc->cltv_expiry > (uint32_t)Height + cnlupd.cltv_expiry_delta + M_HYSTE_CLTV_EXPIRY_FAR) {
        LOGD("%" PRIu32 " > %" PRId32 "\n", pAddHtlc->cltv_expiry, Height + cnlupd.cltv_expiry_delta + M_HYSTE_CLTV_EXPIRY_FAR);
        M_SET_ERR(self, LNERR_INV_VALUE, "expiry too far : %" PRIu32, ln_cltv_expily_delta(recv_prev.p_next_self));
        utl_push_u16be(pPushReason, LNONION_EXPIRY_TOO_FAR);

        return false;
    }

    return true;
}


/** peerから受信したper_commitment_secret保存
 *
 * ln_derkey_storage_get_current_index()に保存後、ln_derkey_storage_get_current_index()をデクリメントする。
 *
 * @param[in,out]   self            チャネル情報
 * @param[in]       p_prev_secret   受信したper_commitment_secret
 * @retval  true    成功
 * @note
 *      - indexを進める
 */
static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret)
{
    //LOGD("I=%016" PRIx64 "\n", ln_derkey_storage_get_current_index());
    //DUMPD(p_prev_secret, BTC_SZ_PRIVKEY);
    uint8_t pub[BTC_SZ_PUBKEY];
    btc_keys_priv2pub(pub, p_prev_secret);
    //DUMPD(pub, BTC_SZ_PUBKEY);
    bool ret = ln_derkey_storage_insert_secret(&self->peer_storage, p_prev_secret);
    if (ret) {
        //M_DB_SELF_SAVE(self);    //保存は呼び出し元で行う
        LOGD("I=%016" PRIx64 " --> %016" PRIx64 "\n",
            ln_derkey_storage_get_current_index(&self->peer_storage) + 1,
            ln_derkey_storage_get_current_index(&self->peer_storage));

        //for (uint64_t idx = LN_SECRET_INDEX_INIT; idx > ln_derkey_storage_get_current_index(); idx--) {
        //    LOGD("I=%016" PRIx64 "\n", idx);
        //    LOGD2("  ");
        //    uint8_t sec[BTC_SZ_PRIVKEY];
        //    ret = ln_derkey_storage_get_secret(sec, &self->peer_storage, idx);
        //    assert(ret);
        //    LOGD2("  pri:");
        //    DUMPD(sec, BTC_SZ_PRIVKEY);
        //    LOGD2("  pub:");
        //    btc_keys_priv2pub(pub, sec);
        //    DUMPD(pub, BTC_SZ_PUBKEY);
        //}
    } else {
        assert(0);
    }
    return ret;
}


static void clear_htlc_comrevflag(ln_update_add_htlc_t *p_htlc, uint8_t DelHtlc)
{
    ln_htlcflag_t *p_flag = &p_htlc->stat.flag;
    if (p_flag->comsend && p_flag->revrecv && p_flag->comrecv && p_flag->revsend) {
        //commitment_signed--revoke_and_ackの交換が終わっている場合のみフラグ削除
        LOGD("[DELHTLC]%d --> %d\n", p_flag->delhtlc, DelHtlc);
        p_flag->delhtlc = DelHtlc;
        p_flag->comsend = 0;
        p_flag->revrecv = 0;
        p_flag->comrecv = 0;
        p_flag->revsend = 0;
        dbg_htlcflag(p_flag);
    } else {
        LOGD("not clear: comsend=%d, revrecv=%d, comrecv=%d, revsend=%d\n",
                p_flag->comsend, p_flag->revrecv, p_flag->comrecv, p_flag->revsend);
    }
}


static void clear_htlc(ln_update_add_htlc_t *p_htlc)
{
    LOGD("DELHTLC=%s, FIN_DELHTLC=%s\n",
            dbg_htlcflag_delhtlc_str(p_htlc->stat.flag.delhtlc),
            dbg_htlcflag_delhtlc_str(p_htlc->stat.flag.fin_delhtlc));

    ln_db_preimg_del(p_htlc->buf_payment_preimage.buf);
    utl_buf_free(&p_htlc->buf_payment_preimage);
    utl_buf_free(&p_htlc->buf_onion_reason);
    utl_buf_free(&p_htlc->buf_shared_secret);
    memset(p_htlc, 0, sizeof(ln_update_add_htlc_t));
}


/** 受信アイドル処理(HTLC final)
 */
static void recv_idle_proc_final(ln_self_t *self)
{
    //LOGD("HTLC final\n");

    bool db_upd = false;
    bool revack = false;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
        if (LN_HTLC_ENABLE(p_htlc)) {
            ln_htlcflag_t *p_flag = &p_htlc->stat.flag;
            // LOGD(" [%d]addhtlc=%s, delhtlc=%s, updsend=%d, %d%d%d%d, next=%" PRIx64 "(%d), fin_del=%s\n",
            //         idx,
            //         dbg_htlcflag_addhtlc_str(p_flag->addhtlc),
            //         dbg_htlcflag_delhtlc_str(p_flag->delhtlc),
            //         p_flag->updsend,
            //         p_flag->comsend, p_flag->revrecv, p_flag->comrecv, p_flag->revsend,
            //         p_htlc->next_short_channel_id, p_htlc->next_idx,
            //         dbg_htlcflag_delhtlc_str(p_flag->fin_delhtlc));
            if (LN_HTLC_ENABLE_LOCAL_ADDHTLC_OFFER(p_htlc)) {
                //ADD_HTLC後: update_add_htlc送信側
                //self->our_msat -= p_htlc->amount_msat;
            } else if (LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(p_htlc)) {
                //ADD_HTLC後: update_add_htlc受信側
                //self->their_msat -= p_htlc->amount_msat;

                //ADD_HTLC転送
                if (p_htlc->next_short_channel_id != 0) {
                    LOGD("forward: %d\n", p_htlc->next_idx);

                    ln_cb_fwd_add_htlc_t fwd;
                    fwd.short_channel_id = p_htlc->next_short_channel_id;
                    fwd.idx = p_htlc->next_idx;
                    ln_callback(self, LN_CB_FWD_ADDHTLC_START, &fwd);
                    p_htlc->next_short_channel_id = 0;
                    db_upd = true;
                }

                if (LN_DBG_FULFILL()) {
                    //DEL_HTLC開始
                    if (p_flag->fin_delhtlc != LN_DELHTLC_NONE) {
                        LOGD("del htlc: %d\n", p_flag->fin_delhtlc);
                        ln_del_htlc_start_bwd(self, idx);
                        clear_htlc_comrevflag(p_htlc, p_flag->fin_delhtlc);
                        db_upd = true;
                    }
                }
            } else {
                //DEL_HTLC後
                switch (p_flag->addhtlc) {
                case LN_ADDHTLC_OFFER:
                    //DEL_HTLC後: update_add_htlc送信側
                    if (p_flag->delhtlc == LN_DELHTLC_FULFILL) {
                        self->our_msat -= p_htlc->amount_msat;
                        self->their_msat += p_htlc->amount_msat;
                    } else if ((p_flag->delhtlc != LN_DELHTLC_NONE) && (p_htlc->prev_short_channel_id != 0)) {
                        LOGD("backward fail_htlc!\n");

                        ln_cb_bwd_del_htlc_t bwd;
                        bwd.short_channel_id = p_htlc->prev_short_channel_id;
                        bwd.fin_delhtlc = p_flag->delhtlc;
                        bwd.idx = p_htlc->prev_idx;
                        ln_callback(self, LN_CB_BWD_DELHTLC_START, &bwd);
                        clear_htlc_comrevflag(p_htlc, p_flag->delhtlc);
                    }

                    if (p_htlc->prev_short_channel_id == 0) {
                        if (p_flag->delhtlc != LN_DELHTLC_FULFILL) {
                            //origin nodeで失敗 --> 送金の再送
                            ln_callback(self, LN_CB_PAYMENT_RETRY, p_htlc->payment_sha256);
                        }
                    }
                    break;
                case LN_ADDHTLC_RECV:
                    //DEL_HTLC後: update_add_htlc受信側
                    if (p_flag->delhtlc == LN_DELHTLC_FULFILL) {
                        self->our_msat += p_htlc->amount_msat;
                        self->their_msat -= p_htlc->amount_msat;
                    }
                    break;
                default:
                    //nothing
                    break;
                }

                LOGD("clear_htlc: %016" PRIx64 " htlc[%d]\n", self->short_channel_id, idx);
                clear_htlc(p_htlc);

                db_upd = true;
                revack = true;
            }
        }
    }

    if (db_upd) {
        M_DB_SELF_SAVE(self);
        if (revack) {
            ln_callback(self, LN_CB_REV_AND_ACK_EXCG, NULL);
        }
    }
}


/** 受信アイドル処理(HTLC non-final)
 *
 * HTLCとして有効だが、commitment_signed/revoke_and_ackの送受信が完了していないものがある
 */
static void recv_idle_proc_nonfinal(ln_self_t *self, uint32_t FeeratePerKw)
{
    bool b_comsiging = false;   //true: commitment_signed〜revoke_and_ackの途中
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if ( ( ((self->cnl_add_htlc[idx].stat.bits & LN_HTLCFLAG_MASK_COMSIG1) == 0) ||
               ((self->cnl_add_htlc[idx].stat.bits & LN_HTLCFLAG_MASK_COMSIG1) == LN_HTLCFLAG_MASK_COMSIG1) ) &&
             ( ((self->cnl_add_htlc[idx].stat.bits & LN_HTLCFLAG_MASK_COMSIG2) == 0) ||
               ((self->cnl_add_htlc[idx].stat.bits & LN_HTLCFLAG_MASK_COMSIG2) == LN_HTLCFLAG_MASK_COMSIG2) ) ) {
            //[send commitment_signed] && [recv revoke_and_ack] or NONE
            //  &&
            //[recv commitment_signed] && [send revoke_and_ack] or NONE
            //  -->OK
        } else {
            //commitment_signedの送受信だけしか行っていないHTLCがある
            b_comsiging = true;
            break;
        }
    }

    bool b_comsig = false;      //true: commitment_signed送信可能
    bool b_updfee = false;      //true: update_fee送信
    if (!b_comsiging) {
        for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
            ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
            if (LN_HTLC_ENABLE(p_htlc)) {
                ln_htlcflag_t *p_flag = &p_htlc->stat.flag;
                // LOGD(" [%d]addhtlc=%s, delhtlc=%s, updsend=%d, %d%d%d%d, next=%" PRIx64 "(%d), fin_del=%s\n",
                //         idx,
                //         dbg_htlcflag_addhtlc_str(p_flag->addhtlc),
                //         dbg_htlcflag_delhtlc_str(p_flag->delhtlc),
                //         p_flag->updsend,
                //         p_flag->comsend, p_flag->revrecv, p_flag->comrecv, p_flag->revsend,
                //         p_htlc->next_short_channel_id, p_htlc->next_idx,
                //         dbg_htlcflag_delhtlc_str(p_flag->fin_delhtlc));
                utl_buf_t buf = UTL_BUF_INIT;
                if (LN_HTLC_WILL_ADDHTLC(p_htlc)) {
                    //update_add_htlc送信
                    add_htlc_create(self, &buf, idx);
                } else if (LN_HTLC_WILL_DELHTLC(p_htlc)) {
                    if (!LN_DBG_FULFILL() || !LN_DBG_FULFILL_BWD()) {
                        LOGD("DBG: no fulfill mode\n");
                    } else {
                        //update_fulfill/fail/fail_malformed_htlc送信
                        switch (p_flag->delhtlc) {
                        case LN_DELHTLC_FULFILL:
                            fulfill_htlc_create(self, &buf, idx);
                            break;
                        case LN_DELHTLC_FAIL:
                            fail_htlc_create(self, &buf, idx);
                            break;
                        case LN_DELHTLC_MALFORMED:
                            fail_malformed_htlc_create(self, &buf, idx);
                            break;
                        default:
                            break;
                        }
                    }
                } else if (LN_HTLC_WILL_COMSIG_OFFER(p_htlc) ||
                            LN_HTLC_WILL_COMSIG_RECV(p_htlc)) {
                    //commitment_signed送信可能
                    b_comsig = true;
                } else {
                    //???
                }
                if (buf.len > 0) {
                    uint16_t type = utl_int_pack_u16be(buf.buf);
                    LOGD("send: %s\n", ln_msg_name(type));
                    ln_callback(self, LN_CB_SEND_REQ, &buf);
                    utl_buf_free(&buf);
                    self->cnl_add_htlc[idx].stat.flag.updsend = 1;
                } else {
                    //nothing to do or fail create packet
                }
            }
        }
    }
    if (!b_comsig && ((FeeratePerKw != 0) && (self->feerate_per_kw != FeeratePerKw))) {
        utl_buf_t buf = UTL_BUF_INIT;
        bool ret = ln_update_fee_create(self, &buf, FeeratePerKw);
        if (ret) {
            ln_callback(self, LN_CB_SEND_REQ, &buf);
            b_updfee = true;
        }
        utl_buf_free(&buf);
    }
    if (b_comsig || b_updfee) {
        //commitment_signed送信
        utl_buf_t buf = UTL_BUF_INIT;
        bool ret = create_commitment_signed(self, &buf);
        if (ret) {
            ln_callback(self, LN_CB_SEND_REQ, &buf);

            if (b_comsig) {
                //commitment_signed送信済みフラグ
                for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
                    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
                    if ( LN_HTLC_ENABLE(p_htlc) &&
                        ( LN_HTLC_ENABLE_REMOTE_ADDHTLC_OFFER(p_htlc) ||
                        LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(p_htlc) ||
                        LN_HTLC_ENABLE_REMOTE_DELHTLC_OFFER(p_htlc) ||
                        LN_HTLC_ENABLE_REMOTE_DELHTLC_RECV(p_htlc) ) ) {
                        LOGD(" [%d]comsend=1\n", idx);
                        p_htlc->stat.flag.comsend = 1;
                    }
                }
            } else {
                LOGD("$$$ commitment_signed for update_fee\n");
            }

            M_DBG_COMMITNUM(self);
            M_DB_SELF_SAVE(self);
        } else {
            //commit_txの作成に失敗したので、commitment_signedは送信できない
            LOGE("fail: create commit_tx(0x%" PRIx64 ")\n", ln_short_channel_id(self));
            ln_callback(self, LN_CB_QUIT, NULL);
        }
        utl_buf_free(&buf);
    }
}


static bool create_commitment_signed(ln_self_t *self, utl_buf_t *pCommSig)
{
    LOGD("BEGIN\n");

    bool ret;

    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished");
        return false;
    }

    //相手に送る署名を作成
    uint8_t *p_htlc_sigs = NULL;    //必要があればcreate_to_remote()でMALLOC()する
    ret = ln_comtx_create_to_remote(self,
                &self->commit_remote,
                NULL, &p_htlc_sigs,
                self->commit_remote.commit_num + 1);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_ERROR, "create remote commit_tx");
        return false;
    }

    //commitment_signedを受信していないと想定してはいけないようなので、ここでインクリメントする。
    self->commit_remote.commit_num++;

    ln_msg_commitment_signed_t msg;
    msg.p_channel_id = self->channel_id;
    msg.p_signature = self->commit_remote.signature;     //相手commit_txに行った自分の署名
    msg.num_htlcs = self->commit_remote.htlc_num;
    msg.p_htlc_signature = p_htlc_sigs;
    ret = ln_msg_commitment_signed_write(pCommSig, &msg);
    UTL_DBG_FREE(p_htlc_sigs);

    LOGD("END\n");
    return ret;
}


/** update_add_htlc作成前チェック
 *
 * @param[in,out]       self        #M_SET_ERR()で書込む
 * @param[out]          pIdx        HTLCを追加するself->cnl_add_htlc[*pIdx]
 * @param[out]          pReason     (非NULL時かつ戻り値がfalse)onion reason
 * @param[in]           amount_msat
 * @param[in]           cltv_value
 * @retval      true    チェックOK
 */
static bool check_create_add_htlc(
                ln_self_t *self,
                uint16_t *pIdx,
                utl_buf_t *pReason,
                uint64_t amount_msat,
                uint32_t cltv_value)
{
    bool ret = false;
    uint64_t max_htlc_value_in_flight_msat = 0;
    uint64_t close_fee_msat = LN_SATOSHI2MSAT(ln_closing_signed_initfee(self));

    //cltv_expiryは、500000000未満にしなくてはならない
    if (cltv_value >= BTC_TX_LOCKTIME_LIMIT) {
        M_SET_ERR(self, LNERR_INV_VALUE, "cltv_value >= 500000000");
        goto LABEL_EXIT;
    }

    //相手が指定したchannel_reserve_satは残しておく必要あり
    if (self->our_msat < amount_msat + LN_SATOSHI2MSAT(self->commit_remote.channel_reserve_sat)) {
        M_SET_ERR(self, LNERR_INV_VALUE, "our_msat(%" PRIu64 ") - amount_msat(%" PRIu64 ") < channel_reserve msat(%" PRIu64 ")",
                    self->our_msat, amount_msat, LN_SATOSHI2MSAT(self->commit_remote.channel_reserve_sat));
        goto LABEL_EXIT;
    }

    //現在のfeerate_per_kwで支払えないようなamount_msatを指定してはいけない
    if (self->our_msat < amount_msat + close_fee_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "our_msat(%" PRIu64 ") - amount_msat(%" PRIu64 ") < closing_fee_msat(%" PRIu64 ")",
                    self->our_msat, amount_msat, close_fee_msat);
        goto LABEL_EXIT;
    }

    //追加した結果が相手のmax_accepted_htlcsより多くなるなら、追加してはならない。
    if (self->commit_remote.max_accepted_htlcs <= self->commit_remote.htlc_num) {
        M_SET_ERR(self, LNERR_INV_VALUE, "over max_accepted_htlcs : %d <= %d",
                    self->commit_remote.max_accepted_htlcs, self->commit_remote.htlc_num);
        goto LABEL_EXIT;
    }

    //amount_msatは、0より大きくなくてはならない。
    //amount_msatは、相手のhtlc_minimum_msat未満にしてはならない。
    if ((amount_msat == 0) || (amount_msat < self->commit_remote.htlc_minimum_msat)) {
        M_SET_ERR(self, LNERR_INV_VALUE, "amount_msat(%" PRIu64 ") < remote htlc_minimum_msat(%" PRIu64 ")",
                    amount_msat, self->commit_remote.htlc_minimum_msat);
        goto LABEL_EXIT;
    }

    //加算した結果が相手のmax_htlc_value_in_flight_msatを超えるなら、追加してはならない。
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].stat.flag.addhtlc == LN_ADDHTLC_OFFER) {
            max_htlc_value_in_flight_msat += self->cnl_add_htlc[idx].amount_msat;
        }
    }
    if (max_htlc_value_in_flight_msat > self->commit_remote.max_htlc_value_in_flight_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "exceed remote max_htlc_value_in_flight_msat(%" PRIu64 ")", self->commit_remote.max_htlc_value_in_flight_msat);
        goto LABEL_EXIT;
    }

    int idx;
    for (idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (LN_HTLC_EMPTY(&self->cnl_add_htlc[idx])) {
            break;
        }
    }
    if (idx >= LN_HTLC_MAX) {
        M_SET_ERR(self, LNERR_HTLC_FULL, "no free add_htlc");
        goto LABEL_EXIT;
    }

    *pIdx = idx;
    ret = true;

LABEL_EXIT:
    if (pReason != NULL) {
        utl_buf_t buf = UTL_BUF_INIT;
        ln_msg_channel_update_t upd;

        bool retval = ln_channel_update_get_peer(self, &buf, NULL);
        if (retval) {
            memset(&upd, 0, sizeof(upd));
            retval = ln_msg_channel_update_read(&upd, buf.buf, buf.len);
        }
        if (ret) {
            if (retval) {
                if (upd.channel_flags & LN_CNLUPD_CHFLAGS_DISABLE) {
                    //B13. if the channel is disabled:
                    //      channel_disabled
                    //      (report the current channel setting for the outgoing channel.)
                    LOGE("fail: channel_disabled\n");

                    utl_push_t push_htlc;
                    utl_push_init(&push_htlc, pReason,
                                        sizeof(uint16_t) + sizeof(uint16_t) + buf.len);
                    utl_push_u16be(&push_htlc, LNONION_CHAN_DISABLE);
                    utl_push_u16be(&push_htlc, (uint16_t)buf.len);
                    utl_push_data(&push_htlc, buf.buf, buf.len);
                } else {
                    LOGD("OK\n");
                }
            } else {
                //channel_updateは必ずしも受信しているとは限らないため、ここではスルー
                LOGD("OK\n");
            }
        } else {
            if (retval) {
                //B4. if during forwarding to its receiving peer, an otherwise unspecified, transient error occurs in the outgoing channel (e.g. channel capacity reached, too many in-flight HTLCs, etc.):
                //      temporary_channel_failure
                LOGE("fail: temporary_channel_failure\n");

                utl_push_t push_htlc;
                utl_push_init(&push_htlc, pReason,
                                    sizeof(uint16_t) + sizeof(uint16_t) + buf.len);
                utl_push_u16be(&push_htlc, LNONION_TMP_CHAN_FAIL);
                utl_push_u16be(&push_htlc, (uint16_t)buf.len);
                utl_push_data(&push_htlc, buf.buf, buf.len);
            } else {
                //B5. if an otherwise unspecified, permanent error occurs during forwarding to its receiving peer (e.g. channel recently closed):
                //      permanent_channel_failure
                LOGE("fail: permanent_channel_failure\n");

                utl_push_t push_htlc;
                utl_push_init(&push_htlc, pReason, sizeof(uint16_t));
                utl_push_u16be(&push_htlc, LNONION_PERM_CHAN_FAIL);
            }
        }
    }
    return ret;
}


static bool set_add_htlc(ln_self_t *self,
            uint64_t *pHtlcId,
            utl_buf_t *pReason,
            uint16_t *pIdx,
            const uint8_t *pPacket,
            uint64_t AmountMsat,
            uint32_t CltvValue,
            const uint8_t *pPaymentHash,
            uint64_t PrevShortChannelId,
            uint16_t PrevIdx,
            const utl_buf_t *pSharedSecrets)
{
    LOGD("BEGIN\n");
    LOGD("  AmountMsat=%" PRIu64 "\n", AmountMsat);
    LOGD("  CltvValue=%d\n", CltvValue);
    LOGD("  paymentHash=");
    DUMPD(pPaymentHash, BTC_SZ_HASH256);
    LOGD("  PrevShortChannelId=%016" PRIx64 "\n", PrevShortChannelId);

    bool ret;
    uint16_t idx;
    ret = check_create_add_htlc(self, &idx, pReason, AmountMsat, CltvValue);
    if (ret) {
        LOGD("OK\n");
        self->cnl_add_htlc[idx].p_channel_id = self->channel_id;
        self->cnl_add_htlc[idx].id = self->htlc_id_num++;
        self->cnl_add_htlc[idx].amount_msat = AmountMsat;
        self->cnl_add_htlc[idx].cltv_expiry = CltvValue;
        memcpy(self->cnl_add_htlc[idx].payment_sha256, pPaymentHash, BTC_SZ_HASH256);
        utl_buf_alloccopy(&self->cnl_add_htlc[idx].buf_onion_reason, pPacket, LN_SZ_ONION_ROUTE);
        self->cnl_add_htlc[idx].prev_short_channel_id = PrevShortChannelId;
        self->cnl_add_htlc[idx].prev_idx = PrevIdx;
        utl_buf_free(&self->cnl_add_htlc[idx].buf_shared_secret);
        if (pSharedSecrets) {
            utl_buf_alloccopy(&self->cnl_add_htlc[idx].buf_shared_secret, pSharedSecrets->buf, pSharedSecrets->len);
        }

        ret = check_create_remote_commit_tx(self, idx);
        if (ret) {
            *pIdx = idx;
            *pHtlcId = self->cnl_add_htlc[idx].id;

            LOGD("HTLC add : prev_short_channel_id=%" PRIu64 "\n", self->cnl_add_htlc[idx].prev_short_channel_id);
            LOGD("           self->cnl_add_htlc[%d].flag = 0x%04x\n", idx, self->cnl_add_htlc[idx].stat.bits);
        } else {
            M_SET_ERR(self, LNERR_MSG_ERROR, "create remote commit_tx(check)");
            LOGD("clear_htlc: %016" PRIx64 " htlc[%d]\n", self->short_channel_id, idx);
            clear_htlc(&self->cnl_add_htlc[idx]);
        }
    } else {
        LOGE("fail: create update_add_htlc\n");
    }

    return ret;
}


/** update_add_htlcメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pAdd            生成したupdate_add_htlcメッセージ
 * @param[in]           Idx             生成するHTLCの内部管理index値
 * @note
 *  - 作成失敗時、pAddは解放する
 */
static void add_htlc_create(ln_self_t *self, utl_buf_t *pAdd, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%04x\n", Idx, self->cnl_add_htlc[Idx].stat.bits);
    bool ret = msg_update_add_htlc_write(pAdd, &self->cnl_add_htlc[Idx]);
    if (ret) {
        self->cnl_add_htlc[Idx].stat.flag.updsend = 1;
    } else {
        M_SEND_ERR(self, LNERR_ERROR, "internal error: add_htlc");
        utl_buf_free(pAdd);
    }
}


/** update_fulfill_htlcメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pFulfill        生成したupdate_fulfill_htlcメッセージ
 * @param[in]           Idx             生成するHTLCの内部管理index値
 * @note
 *  - 作成失敗時、pFulfillは解放する
 */
static void fulfill_htlc_create(ln_self_t *self, utl_buf_t *pFulfill, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%04x\n", Idx, self->cnl_add_htlc[Idx].stat.bits);

    ln_msg_update_fulfill_htlc_t msg;
    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    msg.p_channel_id = self->channel_id;
    msg.id = p_htlc->id;
    msg.p_payment_preimage = p_htlc->buf_payment_preimage.buf;
    bool ret = ln_msg_update_fulfill_htlc_write(pFulfill, &msg);
    if (ret) {
        p_htlc->stat.flag.updsend = 1;
    } else {
        M_SEND_ERR(self, LNERR_ERROR, "internal error: fulfill_htlc");
        utl_buf_free(pFulfill);
    }
}


/** update_fail_htlcメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pFail           生成したupdate_fail_htlcメッセージ
 * @param[in]           Idx             生成するHTLCの内部管理index値
 * @note
 *  - 作成失敗時、pFailは解放する
 */
static void fail_htlc_create(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, self->cnl_add_htlc[Idx].stat.bits);

    ln_msg_update_fail_htlc_t fail_htlc;
    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    fail_htlc.p_channel_id = self->channel_id;
    fail_htlc.id = p_htlc->id;
    fail_htlc.len = p_htlc->buf_onion_reason.len;
    fail_htlc.p_reason = p_htlc->buf_onion_reason.buf;
    bool ret = ln_msg_update_fail_htlc_write(pFail, &fail_htlc);
    if (ret) {
        p_htlc->stat.flag.updsend = 1;
    } else {
        M_SEND_ERR(self, LNERR_ERROR, "internal error: fail_htlc");
        utl_buf_free(pFail);
    }
}


/** update_fail_malformed_htlcメッセージ作成
 *
 * @param[in,out]       self            channel情報
 * @param[out]          pFail           生成したupdate_fail_htlcメッセージ
 * @param[in]           Idx             生成するHTLCの内部管理index値
 * @note
 *  - 作成失敗時、pFailは解放する
 */
static void fail_malformed_htlc_create(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%04x\n", Idx, self->cnl_add_htlc[Idx].stat.bits);

    ln_msg_update_fail_malformed_htlc_t msg;
    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];
    msg.p_channel_id = self->channel_id;
    msg.id = p_htlc->id;
    msg.p_sha256_of_onion = p_htlc->buf_onion_reason.buf + sizeof(uint16_t);
    msg.failure_code = utl_int_pack_u16be(p_htlc->buf_onion_reason.buf);
    bool ret = ln_msg_update_fail_malformed_htlc_write(pFail, &msg);
    if (ret) {
        p_htlc->stat.flag.updsend = 1;
    } else {
        M_SEND_ERR(self, LNERR_ERROR, "internal error: malformed_htlc");
        utl_buf_free(pFail);
    }
}


static bool check_create_remote_commit_tx(ln_self_t *self, uint16_t Idx)
{
    ln_commit_data_t dummy_remote;
    memcpy(&dummy_remote, &self->commit_remote, sizeof(dummy_remote));
    ln_htlcflag_t bak_flag = self->cnl_add_htlc[Idx].stat.flag;
    self->cnl_add_htlc[Idx].stat.bits = LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_OFFER) | LN_HTLCFLAG_SFT_UPDSEND;
    uint8_t *p_htlc_sigs = NULL;    //必要があればcreate_to_remote()でMALLOC()する
    bool ret = ln_comtx_create_to_remote(self,
                &dummy_remote,
                NULL, &p_htlc_sigs,
                self->commit_remote.commit_num + 1);
    self->cnl_add_htlc[Idx].stat.flag = bak_flag;
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_ERROR, "create remote commit_tx(check)");
    }
    UTL_DBG_FREE(p_htlc_sigs);

    return ret;
}


#ifdef M_DBG_COMMITHTLC
static void dbg_htlcflag(const ln_htlcflag_t *p_flag)
{
    LOGD("        addhtlc=%s, delhtlc=%s\n",
            dbg_htlcflag_addhtlc_str(p_flag->addhtlc), dbg_htlcflag_delhtlc_str(p_flag->delhtlc));
    LOGD("        updsend=%d\n",
            p_flag->updsend);
    LOGD("        comsend=%d, revrecv=%d\n",
            p_flag->comsend, p_flag->revrecv);
    LOGD("        comrecv=%d revsend=%d\n",
            p_flag->comrecv, p_flag->revsend);
    LOGD("        fin_del=%s\n",
            dbg_htlcflag_delhtlc_str(p_flag->fin_delhtlc));
}

static void dbg_htlcflagall(const ln_self_t *self)
{
    LOGD("------------------------------------------\n");
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        const ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[idx];
        if (LN_HTLC_ENABLE(p_htlc)) {
            const ln_htlcflag_t *p_flag = &p_htlc->stat.flag;
            LOGD("[%d]prev_short_channel_id=%016" PRIx64 "(%d), next_short_channel_id=%016" PRIx64 "(%d)\n",
                    idx,
                    p_htlc->prev_short_channel_id, p_htlc->prev_idx,
                    p_htlc->next_short_channel_id, p_htlc->next_idx);
            dbg_htlcflag(p_flag);
        }
    }
    LOGD("------------------------------------------\n");
}
#endif
