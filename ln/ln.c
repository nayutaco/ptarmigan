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
/** @file   ln.c
 *  @brief  Lightning Library main
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
#include "ln_misc.h"
#include "ln_msg_setupctl.h"
#include "ln_msg_establish.h"
#include "ln_msg_close.h"
#include "ln_msg_normalope.h"
#include "ln_msg_anno.h"
#include "ln_node.h"
#include "ln_enc_auth.h"
#include "ln_onion.h"
#include "ln_script.h"
#include "ln_comtx.h"
#include "ln_derkey.h"
#include "ln_signer.h"
#include "ln_local.h"

#define M_DBG_VERBOSE


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SZ_TO_LOCAL_TX(len)                   (213 + len) ///< to_local transaction長[byte]
                                                            // <version> 4
                                                            // <flag><marker> 2
                                                            // vin_cnt 1
                                                            //      outpoint 36
                                                            //      scriptSig 1
                                                            //      sequence 4
                                                            // witness 1
                                                            //      sig 73
                                                            //      1
                                                            //      script 77
                                                            // vout_cnt 1
                                                            //      amount 8
                                                            //      scriptpk 1+len
                                                            // locktime 4

#define M_SZ_TO_REMOTE_TX(len)                  (169 + len) ///< to_remote transaction長[byte]
                                                            // <version> 4
                                                            // <flag><marker> 2
                                                            // vin_cnt 1
                                                            //      outpoint 36
                                                            //      scriptSig 1
                                                            //      sequence 4
                                                            // witness 1
                                                            //      sig 73
                                                            //      1
                                                            //      pubkey 33
                                                            // vout_cnt 1
                                                            //      amount 8
                                                            //      scriptpk 1+len
                                                            // locktime 4

#define M_SZ_TO_LOCAL_PENALTY               (324)
#define M_SZ_OFFERED_PENALTY                (407)
#define M_SZ_RECEIVED_PENALTY               (413)

#define M_HTLCCHG_NONE                      (0)
#define M_HTLCCHG_FF_SEND                   (1)
#define M_HTLCCHG_FF_RECV                   (2)


// ln_self_t.init_flag
#define M_INIT_FLAG_SEND                    (0x01)
#define M_INIT_FLAG_RECV                    (0x02)
#define M_INIT_FLAG_EXCG                    (M_INIT_FLAG_SEND | M_INIT_FLAG_RECV)
#define M_INIT_FLAG_EXCHNAGED(flag)         (((flag) & M_INIT_FLAG_EXCG) == M_INIT_FLAG_EXCG)
#define M_INIT_FLAG_REEST_SEND              (0x04)
#define M_INIT_FLAG_REEST_RECV              (0x08)
#define M_INIT_FLAG_REEST_EXCG              (M_INIT_FLAG_REEST_SEND | M_INIT_FLAG_REEST_RECV)
#define M_INIT_FLAG_REEST_EXCHNAGED(flag)   (((flag) & M_INIT_FLAG_REEST_EXCG) == M_INIT_FLAG_REEST_EXCG)
#define M_INIT_FLAG_ALL                     (M_INIT_FLAG_EXCG | M_INIT_FLAG_REEST_EXCG)
#define M_INIT_CH_EXCHANGED(flag)           (((flag) & M_INIT_FLAG_ALL) == M_INIT_FLAG_ALL)
#define M_INIT_ANNOSIG_SENT                 (0x10)          ///< announcement_signatures送信/再送済み

// ln_self_t.anno_flag
#define M_ANNO_FLAG_SEND                    (0x01)          ///< announcement_signatures送信済み
#define M_ANNO_FLAG_RECV                    (0x02)          ///< announcement_signatures受信済み
//#define LN_ANNO_FLAG_END

// ln_self_t.shutdown_flag
#define M_SHDN_FLAG_EXCHANGED(flag)     (((flag) & (LN_SHDN_FLAG_SEND | LN_SHDN_FLAG_RECV)) == (LN_SHDN_FLAG_SEND | LN_SHDN_FLAG_RECV))


/// update_add_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_ADDHTLC         (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_OFFER) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)

/// update_fulfill_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_FULFILLHTLC     (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_RECV) | LN_HTLCFLAG_SFT_DELHTLC(LN_DELHTLC_FULFILL) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)

/// update_fail_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_FAILHTLC        (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_RECV) | LN_HTLCFLAG_SFT_DELHTLC(LN_DELHTLC_FAIL) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)

/// update_fail_malformed_htlc+commitment_signed送信直後
#define M_HTLCFLAG_BITS_MALFORMEDHTLC   (LN_HTLCFLAG_SFT_ADDHTLC(LN_ADDHTLC_RECV) | LN_HTLCFLAG_SFT_DELHTLC(LN_DELHTLC_MALFORMED) | LN_HTLCFLAG_SFT_UPDSEND | LN_HTLCFLAG_SFT_COMSEND)


#define M_FUNDING_INDEX                     (0)             ///< funding_txのvout

#define M_HYSTE_CLTV_EXPIRY_MIN             (7)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_SOON            (1)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_FAR             (144 * 15)      ///< BOLT4 check:cltv_expiryのhysteresis(15日)

//feerate: receive open_channel
// #define M_FEERATE_CHK_MIN_OK(our,their)     ( 0.5 * (our) < 1.0 * (their))  ///< feerate_per_kwのmin判定
// #define M_FEERATE_CHK_MAX_OK(our,their)     (10.0 * (our) > 1.0 * (their))  ///< feerate_per_kwのmax判定
#define M_FEERATE_CHK_MIN_OK(our,their)     (true)  ///< feerate_per_kwのmin判定(ALL OK)
#define M_FEERATE_CHK_MAX_OK(our,their)     (true)  ///< feerate_per_kwのmax判定(ALL OK)

//feerate: receive update_fee
#define M_UPDATEFEE_CHK_MIN_OK(val,rate)    (val >= (uint32_t)(rate * 0.2))
#define M_UPDATEFEE_CHK_MAX_OK(val,rate)    (val <= (uint32_t)(rate * 5))

//channel_update.timestamp
#define M_UPDCNL_TIMERANGE                  (uint32_t)(60 * 60)     //1hour

#if !defined(M_DBG_VERBOSE) && !defined(PTARM_USE_PRINTFUNC)
#define M_DBG_PRINT_TX(tx)      //NONE
//#define M_DBG_PRINT_TX(tx)    LOGD(""); btc_tx_print(tx)
#define M_DBG_PRINT_TX2(tx)     //NONE
#else
#define M_DBG_PRINT_TX(tx)      LOGD("\n"); btc_tx_print(tx)
#define M_DBG_PRINT_TX2(tx)     LOGD("\n"); btc_tx_print(tx)
#endif  //M_DBG_VERBOSE

#define M_DB_SELF_SAVE(self)    { bool ret = ln_db_self_save(self); LOGD("ln_db_self_save()=%d\n", ret); }
#define M_DB_SECRET_SAVE(self)  { bool ret = ln_db_secret_save(self); LOGD("ln_db_secret_save()=%d\n", ret); }

#define M_SET_ERR(self,err,fmt,...)     {\
        set_error(self,err,fmt,##__VA_ARGS__);\
        LOGE("[%s:%d]fail: %s\n", __func__, (int)__LINE__, self->err_msg);\
    }
#define M_SEND_ERR(self,err,fmt,...)    {\
        set_error(self,err,fmt,##__VA_ARGS__);\
        \
        ln_msg_error_t msg;\
        msg.p_channel_id = self->channel_id;\
        msg.p_data = (const uint8_t *)self->err_msg;\
        msg.len = strlen(self->err_msg);\
        send_error(self, &msg);\
        LOGE("[%s:%d]fail: %s\n", __func__, (int)__LINE__, self->err_msg);\
    }

#define M_DBG_COMMITHTLC
#ifdef M_DBG_COMMITHTLC
#define M_DBG_COMMITNUM(self) { LOGD("----- debug commit_num -----\n"); dbg_commitnum(self); }
#define M_DBG_HTLCFLAG(htlc) dbg_htlcflag(htlc)
#define M_DBG_HTLCFLAGALL(self) dbg_htlcflagall(self)
#else
#define M_DBG_COMMITNUM(self)   //none
#define M_DBG_HTLCFLAG(htlc)    //none
#define M_DBG_HTLCFLAGALL(self) //none
#endif


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef bool (*pRecvFunc_t)(ln_self_t *self,const uint8_t *pData, uint16_t Len);


/**************************************************************************
 * prototypes
 **************************************************************************/

static void channel_clear(ln_self_t *self);

//recv
static void recv_idle_proc_final(ln_self_t *self);
static void recv_idle_proc_nonfinal(ln_self_t *self, uint32_t FeeratePerKw);

static bool recv_init(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_error(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_ping(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_pong(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_open_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_accept_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_funding_created(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_funding_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_funding_locked(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_shutdown(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_closing_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_update_add_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_update_fulfill_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_update_fail_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_commitment_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_revoke_and_ack(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_update_fee(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_update_fail_malformed_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_channel_reestablish(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_announcement_signatures(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_channel_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_channel_update(ln_self_t *self, const uint8_t *pData, uint16_t Len);
static bool recv_node_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len);

//send
static bool send_pong(ln_self_t *self, ln_msg_ping_t *pPingMsg);
static bool send_accept_channel(ln_self_t *self);
static bool send_funding_created(ln_self_t *self);
static bool send_funding_signed(ln_self_t *self);
static bool send_closing_signed(ln_self_t *self);
static void send_error(ln_self_t *self, const ln_msg_error_t *pError);

static void start_funding_wait(ln_self_t *self, bool bSendTx);
static bool create_funding_tx(ln_self_t *self, bool bSign);
static bool create_basetx(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pScriptPk, uint32_t LockTime, const uint8_t *pTxid, int Index, bool bRevoked);
static bool create_commitment_signed(ln_self_t *self, utl_buf_t *pCommSig);
static bool create_closing_tx(ln_self_t *self, btc_tx_t *pTx, uint64_t FeeSat, bool bVerify);
static bool create_local_channel_announcement(ln_self_t *self);
static bool create_channel_update(ln_self_t *self, ln_msg_channel_update_t *pUpd, utl_buf_t *pCnlUpd, uint32_t TimeStamp, uint8_t Flag);

static bool check_create_add_htlc(ln_self_t *self, uint16_t *pIdx, utl_buf_t *pReason, uint64_t amount_msat, uint32_t cltv_value);
static bool check_recv_add_htlc_bolt2(ln_self_t *self, const ln_update_add_htlc_t *p_htlc);
static bool check_recv_add_htlc_bolt4_final(ln_self_t *self, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason, ln_update_add_htlc_t *pAddHtlc, uint8_t *pPreImage, int32_t Height);
static bool check_recv_add_htlc_bolt4_forward(ln_self_t *self, ln_hop_dataout_t *pDataOut, utl_push_t *pPushReason, ln_update_add_htlc_t *pAddHtlc,int32_t Height);
static bool check_recv_add_htlc_bolt4_common(ln_self_t *self, utl_push_t *pPushReason);

static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret);

static void proc_anno_sigs(ln_self_t *self);

static bool chk_peer_node(ln_self_t *self);
static bool get_nodeid_from_annocnl(ln_self_t *self, uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir);;
static bool set_add_htlc(ln_self_t *self, uint64_t *pHtlcId, utl_buf_t *pReason, uint16_t *pIdx, const uint8_t *pPacket, uint64_t AmountMsat, uint32_t CltvValue, const uint8_t *pPaymentHash, uint64_t PrevShortChannelId, uint16_t PrevIdx, const utl_buf_t *pSharedSecrets);
static bool check_create_remote_commit_tx(ln_self_t *self, uint16_t Idx);

static bool msg_update_add_htlc_write(utl_buf_t *pBuf, const ln_update_add_htlc_t *pInfo);
static bool msg_update_add_htlc_read(ln_update_add_htlc_t *pInfo, const uint8_t *pData, uint16_t Len);

static void add_htlc_create(ln_self_t *self, utl_buf_t *pAdd, uint16_t Idx);
static void fulfill_htlc_create(ln_self_t *self, utl_buf_t *pFulfill, uint16_t Idx);
static void fail_htlc_create(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx);
static void fail_malformed_htlc_create(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx);
static void clear_htlc_comrevflag(ln_update_add_htlc_t *p_htlc, uint8_t DelHtlc);
static void clear_htlc(ln_update_add_htlc_t *p_htlc);
static bool chk_channelid(const uint8_t *recv_id, const uint8_t *mine_id);
static void close_alloc(ln_close_force_t *pClose, int Num);
static void disable_channel_update(ln_self_t *self);
static void free_establish(ln_self_t *self, bool bEndEstablish);
static btc_script_pubkey_order_t sort_nodeid(const ln_self_t *self, const uint8_t *pNodeId);
static inline uint8_t ln_sort_to_dir(btc_script_pubkey_order_t Sort);
static uint64_t calc_commit_num(const ln_self_t *self, const btc_tx_t *pTx);
static inline void callback(ln_self_t *self, ln_cb_t Req, void *pParam);

static void set_error(ln_self_t *self, int Err, const char *pFormat, ...);
#ifdef M_DBG_COMMITNUM
static void dbg_commitnum(const ln_self_t *self);
static void dbg_htlcflag(const ln_htlcflag_t *p_flag);
static void dbg_htlcflagall(const ln_self_t *self);
#endif


/**************************************************************************
 * const variables
 **************************************************************************/

static const struct {
    uint16_t        type;
    pRecvFunc_t     func;
} RECV_FUNC[] = {
    { MSGTYPE_INIT,                         recv_init },
    { MSGTYPE_ERROR,                        recv_error },
    { MSGTYPE_PING,                         recv_ping },
    { MSGTYPE_PONG,                         recv_pong },
    { MSGTYPE_OPEN_CHANNEL,                 recv_open_channel },
    { MSGTYPE_ACCEPT_CHANNEL,               recv_accept_channel },
    { MSGTYPE_FUNDING_CREATED,              recv_funding_created },
    { MSGTYPE_FUNDING_SIGNED,               recv_funding_signed },
    { MSGTYPE_FUNDING_LOCKED,               recv_funding_locked },
    { MSGTYPE_SHUTDOWN,                     recv_shutdown },
    { MSGTYPE_CLOSING_SIGNED,               recv_closing_signed },
    { MSGTYPE_UPDATE_ADD_HTLC,              recv_update_add_htlc },
    { MSGTYPE_UPDATE_FULFILL_HTLC,          recv_update_fulfill_htlc },
    { MSGTYPE_UPDATE_FAIL_HTLC,             recv_update_fail_htlc },
    { MSGTYPE_COMMITMENT_SIGNED,            recv_commitment_signed },
    { MSGTYPE_REVOKE_AND_ACK,               recv_revoke_and_ack },
    { MSGTYPE_UPDATE_FEE,                   recv_update_fee },
    { MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC,   recv_update_fail_malformed_htlc },
    { MSGTYPE_CHANNEL_REESTABLISH,          recv_channel_reestablish },
    { MSGTYPE_CHANNEL_ANNOUNCEMENT,         recv_channel_announcement },
    { MSGTYPE_NODE_ANNOUNCEMENT,            recv_node_announcement },
    { MSGTYPE_CHANNEL_UPDATE,               recv_channel_update },
    { MSGTYPE_ANNOUNCEMENT_SIGNATURES,      recv_announcement_signatures }
};


/**************************************************************************
 * static variables
 **************************************************************************/

//< 32: chain-hash
uint8_t HIDDEN gGenesisChainHash[BTC_SZ_HASH256];

//blockhash at node creation
//      usage: search blockchain limit
uint8_t HIDDEN gCreationBlockHash[BTC_SZ_HASH256];

/// init.localfeaturesデフォルト値
static uint8_t mInitLocalFeatures[1];

static unsigned long mDebug;


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

bool ln_init(ln_self_t *self, const uint8_t *pSeed, const ln_anno_prm_t *pAnnoPrm, ln_callback_t pFunc)
{
    LOGD("BEGIN : pSeed=%p\n", pSeed);

    ln_noise_t noise_sbak;
    ln_noise_t noise_rbak;
    void *ptr_bak;

    //noise protocol handshake済みの場合があるため、初期値かどうかに関係なく残す
    memcpy(&noise_sbak, &self->noise_send, sizeof(noise_sbak));
    memcpy(&noise_rbak, &self->noise_recv, sizeof(noise_rbak));
    ptr_bak = self->p_param;
    memset(self, 0, sizeof(ln_self_t));
    memcpy(&self->noise_recv, &noise_rbak, sizeof(noise_rbak));
    memcpy(&self->noise_send, &noise_sbak, sizeof(noise_sbak));
    self->p_param = ptr_bak;

    utl_buf_init(&self->shutdown_scriptpk_local);
    utl_buf_init(&self->shutdown_scriptpk_remote);
    utl_buf_init(&self->redeem_fund);
    utl_buf_init(&self->cnl_anno);
    utl_buf_init(&self->revoked_sec);
    self->p_revoked_vout = NULL;
    self->p_revoked_wit = NULL;
    self->p_revoked_type = NULL;

    btc_tx_init(&self->tx_funding);
    btc_tx_init(&self->tx_closing);

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        utl_buf_init(&self->cnl_add_htlc[idx].buf_payment_preimage);
        utl_buf_init(&self->cnl_add_htlc[idx].buf_onion_reason);
        utl_buf_init(&self->cnl_add_htlc[idx].buf_shared_secret);
    }

    self->lfeature_remote = 0;

    self->p_callback = pFunc;

    memcpy(&self->anno_prm, pAnnoPrm, sizeof(ln_anno_prm_t));
    LOGD("cltv_expiry_delta=%" PRIu16 "\n", self->anno_prm.cltv_expiry_delta);
    LOGD("htlc_minimum_msat=%" PRIu64 "\n", self->anno_prm.htlc_minimum_msat);
    LOGD("fee_base_msat=%" PRIu32 "\n", self->anno_prm.fee_base_msat);
    LOGD("fee_prop_millionths=%" PRIu32 "\n", self->anno_prm.fee_prop_millionths);

    //seed
    ln_signer_init(self, pSeed);
    self->peer_storage_index = LN_SECINDEX_INIT;

    self->commit_local.commit_num = 0;
    self->commit_remote.commit_num = 0;

    LOGD("END\n");

    return true;
}


void ln_term(ln_self_t *self)
{
    channel_clear(self);

    ln_signer_term(self);
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        utl_buf_free(&self->cnl_add_htlc[idx].buf_payment_preimage);
        utl_buf_free(&self->cnl_add_htlc[idx].buf_onion_reason);
        utl_buf_free(&self->cnl_add_htlc[idx].buf_shared_secret);
    }
    //LOGD("END\n");
}


bool ln_status_load(ln_self_t *self)
{
    return ln_db_self_load_status(self);
}


const char *ln_status_string(const ln_self_t *self)
{
    const char *p_str_stat;
    switch (self->status) {
    case LN_STATUS_NONE:
        p_str_stat = "none";
        break;
    case LN_STATUS_ESTABLISH:
        p_str_stat = "establishing";
        break;
    case LN_STATUS_NORMAL:
        p_str_stat = "normal operation";
        break;
    case LN_STATUS_CLOSE_WAIT:
        p_str_stat = "close waiting";
        break;
    case LN_STATUS_CLOSE_SPENT:
        p_str_stat = "funding spent";
        break;
    case LN_STATUS_CLOSE_MUTUAL:
        p_str_stat = "mutual close";
        break;
    case LN_STATUS_CLOSE_UNI_LOCAL:
        p_str_stat = "unilateral close(local)";
        break;
    case LN_STATUS_CLOSE_UNI_REMOTE:
        p_str_stat = "unilateral close(remote)";
        break;
    case LN_STATUS_CLOSE_REVOKED:
        p_str_stat = "revoked transaction close";
        break;
    default:
        p_str_stat = "???";
    }
    return p_str_stat;
}


void ln_genesishash_set(const uint8_t *pHash)
{
    memcpy(gGenesisChainHash, pHash, BTC_SZ_HASH256);
    btc_block_chain_t gen = btc_block_get_chain(gGenesisChainHash);
    LOGD("genesis(%d)=", (int)gen);
    DUMPD(gGenesisChainHash, BTC_SZ_HASH256);
    if (gen == BTC_BLOCK_CHAIN_UNKNOWN) {
        LOGE("fail: unknown genesis block hash\n");
    }
}


const uint8_t* ln_genesishash_get(void)
{
    return gGenesisChainHash;
}


void ln_creationhash_set(const uint8_t *pHash)
{
    memcpy(gCreationBlockHash, pHash, BTC_SZ_HASH256);

    LOGD("block hash=");
    DUMPD(gCreationBlockHash, BTC_SZ_HASH256);
}


const uint8_t *ln_creationhash_get(void)
{
    return gCreationBlockHash;
}


void ln_peer_set_nodeid(ln_self_t *self, const uint8_t *pNodeId)
{
    memcpy(self->peer_node_id, pNodeId, BTC_SZ_PUBKEY);
}


void ln_init_localfeatures_set(uint8_t lf)
{
    LOGD("localfeatures=0x%02x\n", lf);
    mInitLocalFeatures[0] = lf;
}


bool ln_establish_alloc(ln_self_t *self, const ln_establish_prm_t *pEstPrm)
{
    LOGD("BEGIN\n");

    if (self->p_establish != 0) {
        LOGD("already set\n");
        return true;
    }

    self->p_establish = (ln_establish_t *)UTL_DBG_MALLOC(sizeof(ln_establish_t));   //UTL_DBG_FREE:proc_established()

    if (pEstPrm != NULL) {
        self->p_establish->p_fundin = NULL;       //open_channel送信側が設定する

        memcpy(&self->p_establish->estprm, pEstPrm, sizeof(ln_establish_prm_t));
        LOGD("dust_limit_sat= %" PRIu64 "\n", self->p_establish->estprm.dust_limit_sat);
        LOGD("max_htlc_value_in_flight_msat= %" PRIu64 "\n", self->p_establish->estprm.max_htlc_value_in_flight_msat);
        LOGD("channel_reserve_sat= %" PRIu64 "\n", self->p_establish->estprm.channel_reserve_sat);
        LOGD("htlc_minimum_msat= %" PRIu64 "\n", self->p_establish->estprm.htlc_minimum_msat);
        LOGD("to_self_delay= %" PRIu16 "\n", self->p_establish->estprm.to_self_delay);
        LOGD("max_accepted_htlcs= %" PRIu16 "\n", self->p_establish->estprm.max_accepted_htlcs);
        LOGD("min_depth= %" PRIu16 "\n", self->p_establish->estprm.min_depth);
    }

    LOGD("END\n");

    return true;
}


void ln_establish_free(ln_self_t *self)
{
    free_establish(self, true);
}


void ln_short_channel_id_set_param(ln_self_t *self, uint32_t Height, uint32_t Index)
{
    uint64_t short_channel_id = ln_misc_calc_short_channel_id(Height, Index, ln_funding_txindex(self));
    self->short_channel_id = short_channel_id;
    self->status = LN_STATUS_NORMAL;
    M_DB_SELF_SAVE(self);
}


void ln_short_channel_id_get_param(uint32_t *pHeight, uint32_t *pIndex, uint32_t *pVIndex, uint64_t ShortChannelId)
{
    ln_misc_get_short_channel_id_param(pHeight, pIndex, pVIndex, ShortChannelId);
}


void ln_funding_blockhash_set(ln_self_t *self, const uint8_t *pMinedHash)
{
    LOGD("save minedHash=");
    TXIDD(pMinedHash);
    memcpy(self->funding_bhash, pMinedHash, BTC_SZ_HASH256);
    M_DB_SELF_SAVE(self);
}


void ln_short_channel_id_string(char *pStr, uint64_t ShortChannelId)
{
    uint32_t height;
    uint32_t bindex;
    uint32_t vindex;
    ln_short_channel_id_get_param(&height, &bindex, &vindex, ShortChannelId);
    snprintf(pStr, LN_SZ_SHORTCHANNELID_STR, "%" PRIu32 "x%" PRIu32 "x%" PRIu32, height, bindex, vindex);
}


#if 0
bool ln_set_shutdown_vout_pubkey(ln_self_t *self, const uint8_t *pShutdownPubkey, int ShutdownPref)
{
    bool ret = false;

    if ((ShutdownPref == BTC_PREF_P2PKH) || (ShutdownPref == BTC_PREF_P2WPKH)) {
        const utl_buf_t pub = { (CONST_CAST uint8_t *)pShutdownPubkey, BTC_SZ_PUBKEY };
        utl_buf_t spk = UTL_BUF_INIT;

        ln_script_scriptpkh_write(&spk, &pub, ShutdownPref);
        utl_buf_free(&self->shutdown_scriptpk_local);
        utl_buf_alloccopy(&self->shutdown_scriptpk_local, spk.buf, spk.len);
        utl_buf_free(&spk);

        ret = true;
    } else {
        M_SET_ERR(self, LNERR_INV_PREF, "invalid prefix");
    }

    return ret;
}
#endif


void ln_shutdown_set_vout_addr(ln_self_t *self, const utl_buf_t *pScriptPk)
{
    LOGD("set close addr: ");
    DUMPD(pScriptPk->buf, pScriptPk->len);
    utl_buf_free(&self->shutdown_scriptpk_local);
    utl_buf_alloccopy(&self->shutdown_scriptpk_local, pScriptPk->buf, pScriptPk->len);
}


bool ln_handshake_start(ln_self_t *self, utl_buf_t *pBuf, const uint8_t *pNodeId)
{
    if (!ln_enc_auth_handshake_init(self, pNodeId)) return false;
    if (pNodeId != NULL) {
        if (!ln_enc_auth_handshake_start(self, pBuf, pNodeId)) return false;
    }
    return true;
}


bool ln_handshake_recv(ln_self_t *self, bool *pCont, utl_buf_t *pBuf)
{
    if (!ln_enc_auth_handshake_recv(self, pBuf)) return false;
    //continue?
    *pCont = ln_enc_auth_handshake_state(self);
    return true;
}


void ln_handshake_free(ln_self_t *self)
{
    ln_enc_auth_handshake_free(self);
}


bool ln_noise_enc(ln_self_t *self, utl_buf_t *pBufEnc, const utl_buf_t *pBufIn)
{
    return ln_enc_auth_enc(self, pBufEnc, pBufIn);
}


uint16_t ln_noise_dec_len(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    return ln_enc_auth_dec_len(self, pData, Len);
}


bool ln_noise_dec_msg(ln_self_t *self, utl_buf_t *pBuf)
{
    return ln_enc_auth_dec_msg(self, pBuf);
}


bool ln_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    uint16_t type = utl_int_pack_u16be(pData);

    if (type != MSGTYPE_INIT && !M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init received : %04x", type);
        return false;
    }

    size_t lp;
    for (lp = 0; lp < ARRAY_SIZE(RECV_FUNC); lp++) {
        if (type != RECV_FUNC[lp].type) continue;
        if (!(*RECV_FUNC[lp].func)(self, pData, Len)) {
            LOGE("fail: type=%04x\n", type);
            return false;
        }
        break;
    }
    if (lp == ARRAY_SIZE(RECV_FUNC)) {
        LOGD("not match: type=%04x\n", type);
        return (type & 1);     //ok to be odd rule --> 奇数ならエラーにしない
    }
    return true;
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


bool ln_channel_reestablish_create(ln_self_t *self, utl_buf_t *pReEst)
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
            bool ret = ln_derkey_storage_get_secret(your_last_per_commitment_secret,
                            &self->peer_storage,
                            (uint64_t)(LN_SECINDEX_INIT - (self->commit_remote.commit_num - 1)));
            if (!ret) {
                LOGD("no last secret\n");
                memset(your_last_per_commitment_secret, 0, BTC_SZ_PRIVKEY);
            }
        }

        uint8_t secret[BTC_SZ_PRIVKEY];
        ln_signer_create_prev_percommitsec(self, secret, my_current_per_commitment_point);
    }

    bool ret = ln_msg_channel_reestablish_write(pReEst, &msg, option_data_loss_protect);
    if (ret) {
        self->init_flag |= M_INIT_FLAG_REEST_SEND;
    }
    return ret;
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
                    callback(self, LN_CB_SEND_REQ, &buf);
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
        ln_signer_create_prev_percommitsec(self, prev_secret, NULL);

        utl_buf_t buf = UTL_BUF_INIT;
        ln_msg_revoke_and_ack_t revack;
        revack.p_channel_id = self->channel_id;
        revack.p_per_commitment_secret = prev_secret;
        revack.p_next_per_commitment_point = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
        LOGD("  send revoke_and_ack.next_per_commitment_point=%" PRIu64 "\n", self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
        bool ret = ln_msg_revoke_and_ack_write(&buf, &revack);
        if (ret) {
            callback(self, LN_CB_SEND_REQ, &buf);
            LOGD("OK: re-send revoke_and_ack\n");
        } else {
            LOGE("fail: re-send revoke_and_ack\n");
        }
        utl_buf_free(&buf);
    }

#if 0
        uint8_t secret[BTC_SZ_PRIVKEY];
        if (self->commit_local.commit_num == 0) {
            memset(secret, 0, BTC_SZ_PRIVKEY);
        } else {
            // self->priv_data.storage_indexは鍵導出後にデクリメントしている。
            // 最新のcommit_tx生成後は、次の次に生成するstorage_indexを指している。
            // 最後に交換したcommit_txは、storage_index+1。
            // revoke_and_ackで渡すsecretは、storage_index+2。
            // 既にrevoke_and_ackで渡し終わったsecretは、storage_index+3。
            //
            ln_derkey_create_secret(secret, self->priv_data.storage_seed, self->priv_data.storage_index + 3);
            LOGD("storage_index(%016" PRIx64 ": ", self->priv_data.storage_index + 3);
            DUMPD(secret, BTC_SZ_PRIVKEY);
        }
        if ( (memcmp(reest.your_last_per_commitment_secret, secret, BTC_SZ_PRIVKEY) == 0) &&
          (memcmp(reest.my_current_per_commitment_point, self->funding_remote.prev_percommit, BTC_SZ_PUBKEY) == 0) ) {
            //一致
            LOGD("OK!\n");
        } else {
            //
            LOGE("NG...\n");
            LOGE("secret: ");
            DUMPE(secret, BTC_SZ_PRIVKEY);
            LOGE("prevpt: ");
            DUMPE(self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);
        }

#endif
}


bool ln_funding_locked_check_need(const ln_self_t *self)
{
    return (self->short_channel_id != 0) &&
        (
            ((self->commit_local.commit_num == 0) && (self->commit_remote.commit_num == 0)) ||
            ((self->reest_commit_num == 1) && (self->reest_revoke_num == 0))
        );
}


bool ln_funding_locked_create(ln_self_t *self, utl_buf_t *pLocked)
{
    LOGD("\n");

    //funding_locked
    ln_msg_funding_locked_t msg;
    msg.p_channel_id = self->channel_id;
    msg.p_next_per_commitment_point = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    bool ret = ln_msg_funding_locked_write(pLocked, &msg);
    if (ret) {
        //channel_reestablishと同じ扱いにする
        self->init_flag |= M_INIT_FLAG_REEST_SEND;
    }

    M_DBG_COMMITNUM(self);

    return ret;
}


/********************************************************************
 * Establish関係
 ********************************************************************/

#if 0
uint64_t ln_estimate_fundingtx_fee(uint32_t Feerate)
{
    LOGD("Feerate:   %" PRIu32 "\n", Feerate);

    ln_self_t *dummy = (ln_self_t *)UTL_DBG_MALLOC(sizeof(ln_self_t));
    uint8_t seed[LN_SZ_SEED];
    ln_anno_prm_t annoprm;
    ln_establish_t est;
    ln_fundin_t fundin;

    memset(dummy, 0, sizeof(ln_self_t));
    memset(seed, 1, sizeof(seed));
    memset(&annoprm, 0, sizeof(annoprm));
    memset(&est, 0, sizeof(est));
    memset(&fundin, 0, sizeof(fundin));

    uint8_t zero[100];
    memset(zero, 0, sizeof(zero));
    fundin.change_spk.buf = zero;
    fundin.change_spk.len = 23;
    fundin.amount = (uint64_t)0xffffffffffffffff;

    est.estprm.dust_limit_sat = BTC_DUST_LIMIT;
    est.estprm.to_self_delay = 100;
    est.cnl_open.feerate_per_kw = Feerate;
    est.cnl_open.funding_satoshis = 100000000;
    est.p_fundin = &fundin;

    ln_init(dummy, seed, &annoprm, NULL);
    memcpy(dummy->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING],
            dummy->funding_local.pubkeys[MSG_FUNDIDX_FUNDING],
            BTC_SZ_PUBKEY);
    dummy->p_establish = &est;
    bool ret = create_funding_tx(dummy, false);
    uint64_t fee = 0;
    if (ret) {
        dummy->tx_funding.vin[0].script.buf = zero;
        dummy->tx_funding.vin[0].script.len = 23;


        utl_buf_t wit[2];
        utl_buf_init(&wit[0]);
        utl_buf_init(&wit[1]);
        wit[0].buf = zero;
        wit[0].len = 72;
        wit[1].buf = zero;
        wit[1].len = 33;
        dummy->tx_funding.vin[0].wit_item_cnt = 2;
        dummy->tx_funding.vin[0].witness = wit;

        M_DBG_PRINT_TX(&dummy->tx_funding);
        uint64_t sum = 0;
        for (uint32_t lp = 0; lp < dummy->tx_funding.vout_cnt; lp++) {
            sum += dummy->tx_funding.vout[lp].value;
        }
        fee = 0xffffffffffffffff - sum;

        dummy->tx_funding.vin[0].script.buf = NULL;
        dummy->tx_funding.vin[0].script.len = 0;
        dummy->tx_funding.vin[0].wit_item_cnt = 0;
        dummy->tx_funding.vin[0].witness = NULL;
    } else {
        LOGE("fail: create_funding_tx()\n");
    }

    fundin.change_spk.buf = NULL;
    fundin.change_spk.len = 0;
    est.p_fundin = NULL;
    dummy->p_establish = NULL;
    ln_term(dummy);

    UTL_DBG_FREE(dummy);
    return fee;
}
#endif


bool ln_open_channel_create(ln_self_t *self, utl_buf_t *pOpen,
            const ln_fundin_t *pFundin, uint64_t FundingSat, uint64_t PushSat, uint32_t FeeRate)
{
    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished.");
        return false;
    }
    if (!chk_peer_node(self)) {
        M_SET_ERR(self, LNERR_NO_PEER, "no peer node_id");
        return false;
    }
    if (ln_is_funding(self)) {
        //既にfunding中
        M_SET_ERR(self, LNERR_ALREADY_FUNDING, "already funding");
        return false;
    }
    if (FeeRate < LN_FEERATE_PER_KW_MIN) {
        //feerate_per_kw too low
        M_SET_ERR(self, LNERR_INV_VALUE, "feerate_per_kw too low");
        return false;
    }

    //仮チャネルID
    btc_rng_rand(self->channel_id, LN_SZ_CHANNEL_ID);

    //鍵生成
    ln_signer_create_channelkeys(self);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

#if defined(USE_BITCOIND)
    //funding_tx作成用に保持
    self->p_establish->p_fundin = (ln_fundin_t *)UTL_DBG_MALLOC(sizeof(ln_fundin_t));     //free: free_establish()
    memcpy(self->p_establish->p_fundin, pFundin, sizeof(ln_fundin_t));
#else
    (void)pFundin;
#endif

    //open_channel
    ln_msg_open_channel_t msg;
    msg.p_chain_hash = gGenesisChainHash;
    msg.p_temporary_channel_id = self->channel_id;
    msg.funding_satoshis = FundingSat;
    msg.push_msat = LN_SATOSHI2MSAT(PushSat);
    msg.dust_limit_satoshis = self->p_establish->estprm.dust_limit_sat;
    msg.max_htlc_value_in_flight_msat = self->p_establish->estprm.max_htlc_value_in_flight_msat;
    msg.channel_reserve_satoshis = self->p_establish->estprm.channel_reserve_sat;
    msg.htlc_minimum_msat = self->p_establish->estprm.htlc_minimum_msat;
    msg.feerate_per_kw = FeeRate;
    msg.to_self_delay = self->p_establish->estprm.to_self_delay;
    msg.max_accepted_htlcs = self->p_establish->estprm.max_accepted_htlcs;
    msg.p_funding_pubkey = self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING];
    msg.p_revocation_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_REVOCATION];
    msg.p_payment_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_PAYMENT];
    msg.p_delayed_payment_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_DELAYED];
    msg.p_htlc_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_HTLC];
    msg.p_first_per_commitment_point = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    msg.channel_flags = CHANNEL_FLAGS_VALUE;
    msg.shutdown_len = 0;
    msg.p_shutdown_scriptpubkey = NULL;
    ln_msg_open_channel_write(pOpen, &msg);

    self->commit_local.dust_limit_sat = msg.dust_limit_satoshis;
    self->commit_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    self->commit_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    self->commit_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    self->commit_local.to_self_delay = msg.to_self_delay;
    self->commit_local.max_accepted_htlcs = msg.max_accepted_htlcs;
    self->our_msat = LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    self->their_msat = msg.push_msat;
    self->funding_sat = msg.funding_satoshis;
    self->feerate_per_kw = msg.feerate_per_kw;

    self->fund_flag = (ln_fundflag_t)(LN_FUNDFLAG_FUNDER | ((msg.channel_flags & 1) ? LN_FUNDFLAG_NO_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);

    return true;
}


bool ln_announce_signs_create(ln_self_t *self, utl_buf_t *pBufAnnoSigns)
{
    bool ret;

    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    if (self->cnl_anno.buf == NULL) {
        create_local_channel_announcement(self);
    }

    ln_msg_channel_announcement_get_sigs(self->cnl_anno.buf, &p_sig_node, &p_sig_btc, true, sort_nodeid(self, NULL));

    ln_msg_announcement_signatures_t msg;
    msg.p_channel_id = self->channel_id;
    msg.short_channel_id = self->short_channel_id;
    msg.p_node_signature = p_sig_node;
    msg.p_bitcoin_signature = p_sig_btc;
    ret = ln_msg_announcement_signatures_write(pBufAnnoSigns, &msg);
    if (ret) {
        self->anno_flag |= M_ANNO_FLAG_SEND;
        proc_anno_sigs(self);
        M_DB_SELF_SAVE(self);
        self->init_flag |= M_INIT_ANNOSIG_SENT;
    }
    return ret;
}


bool ln_channel_update_create(ln_self_t *self, utl_buf_t *pCnlUpd)
{
    bool ret;

    uint32_t now = (uint32_t)utl_time_time();
    ln_msg_channel_update_t upd;
    ret = create_channel_update(self, &upd, pCnlUpd, now, 0);
    if (ret) {
        LOGD("create: channel_update\n");
        ret = ln_db_annocnlupd_save(pCnlUpd, &upd, NULL);
        if (self->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) {
            //announcement_signatures後であればコールバックする
            //そうでない場合は、announcement前のprivate channel通知をしている
            ln_cb_update_annodb_t annodb;
            annodb.anno = LN_CB_UPDATE_ANNODB_CNL_UPD;
            callback(self, LN_CB_UPDATE_ANNODB, &annodb);
        }
    } else {
        LOGE("fail: create channel_update\n");
    }

    return ret;
}


bool ln_channel_update_get_peer(const ln_self_t *self, utl_buf_t *pCnlUpd, ln_msg_channel_update_t *pMsg)
{
    bool ret;

    btc_script_pubkey_order_t sort = sort_nodeid(self, NULL);
    uint8_t dir = (sort == BTC_SCRYPT_PUBKEY_ORDER_OTHER) ? 0 : 1;  //相手のchannel_update
    ret = ln_db_annocnlupd_load(pCnlUpd, NULL, self->short_channel_id, dir);
    if (ret && (pMsg != NULL)) {
        ret = ln_msg_channel_update_read(pMsg, pCnlUpd->buf, pCnlUpd->len);
    }

    return ret;
}


bool ln_channel_update_get_params(ln_msg_channel_update_t *pUpd, const uint8_t *pData, uint16_t Len)
{
    bool ret = ln_msg_channel_update_read(pUpd, pData, Len);
    return ret;
}


/********************************************************************
 * Close関係
 ********************************************************************/

void ln_shutdown_update_fee(ln_self_t *self, uint64_t Fee)
{
    //BOLT#3
    //  A sending node MUST set fee_satoshis lower than or equal to the base fee
    //      of the final commitment transaction as calculated in BOLT #3.
    uint64_t feemax = ln_closing_signed_initfee(self);
    if (Fee > feemax) {
        LOGD("closing fee limit(%" PRIu64 " > %" PRIu64 ")\n", Fee, feemax);
        Fee = feemax;
    }

    self->close_fee_sat = Fee;
    LOGD("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
}


bool ln_shutdown_create(ln_self_t *self, utl_buf_t *pShutdown)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_msg_shutdown_t msg;

    msg.p_channel_id = self->channel_id;
    msg.len = self->shutdown_scriptpk_local.len;
    msg.p_scriptpubkey = self->shutdown_scriptpk_local.buf;
    ret = ln_msg_shutdown_write(pShutdown, &msg);
    if (ret) {
        self->shutdown_flag |= LN_SHDN_FLAG_SEND;
        M_DB_SELF_SAVE(self);
        disable_channel_update(self);
    }

    LOGD("END\n");
    return ret;
}


void ln_close_change_stat(ln_self_t *self, const btc_tx_t *pCloseTx, void *pDbParam)
{
    LOGD("BEGIN: status=%d\n", (int)self->status);
    if ((self->status == LN_STATUS_NORMAL) || (self->status == LN_STATUS_CLOSE_WAIT)) {
        self->status = LN_STATUS_CLOSE_SPENT;
        ln_db_self_save_status(self, pDbParam);
    } else if (self->status == LN_STATUS_CLOSE_SPENT) {
        M_DBG_PRINT_TX(pCloseTx);

        uint8_t txid[BTC_SZ_TXID];
        bool ret = btc_tx_txid(pCloseTx, txid);
        if (!ret) {
            LOGE("fail: txid\n");
            return;
        }

        if ( (ln_shutdown_scriptpk_local(self)->len > 0) &&
             (ln_shutdown_scriptpk_remote(self)->len > 0) &&
             (pCloseTx->vout_cnt <= 2) &&
             ( utl_buf_cmp(&pCloseTx->vout[0].script, ln_shutdown_scriptpk_local(self)) ||
               utl_buf_cmp(&pCloseTx->vout[0].script, ln_shutdown_scriptpk_remote(self)) ) ) {
            //mutual close
            self->status = LN_STATUS_CLOSE_MUTUAL;
        } else if (memcmp(txid, self->commit_local.txid, BTC_SZ_TXID) == 0) {
            //unilateral close(local)
            self->status = LN_STATUS_CLOSE_UNI_LOCAL;
        } else {
            //commitment numberの復元
            uint64_t commit_num = calc_commit_num(self, pCloseTx);

            utl_buf_alloc(&self->revoked_sec, BTC_SZ_PRIVKEY);
            bool ret = ln_derkey_storage_get_secret(self->revoked_sec.buf, &self->peer_storage, (uint64_t)(LN_SECINDEX_INIT - commit_num));
            if (ret) {
                //revoked transaction close(remote)
                self->status = LN_STATUS_CLOSE_REVOKED;
                btc_keys_priv2pub(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], self->revoked_sec.buf);
            } else {
                //unilateral close(remote)
                self->status = LN_STATUS_CLOSE_UNI_REMOTE;
                utl_buf_free(&self->revoked_sec);
            }
        }
        ln_db_self_save_status(self, pDbParam);

        disable_channel_update(self);
    }
    LOGD("END: type=%d\n", (int)self->status);
}


/*
 * 自分がunilateral closeを行いたい場合に呼び出す。
 * または、funding_txがspentで、local commit_txのtxidがgetrawtransactionできる状態で呼ばれる。
 * (local commit_txが展開＝自分でunilateral closeした)
 *
 * 現在のcommitment_transactionを取得する場合にも呼び出されるため、値を元に戻す。
 */
bool ln_close_create_unilateral_tx(ln_self_t *self, ln_close_force_t *pClose)
{
    LOGD("BEGIN\n");

    //to_local送金先設定確認
    assert(self->shutdown_scriptpk_local.len > 0);

    //復元用
    uint8_t bak_percommit[BTC_SZ_PRIVKEY];
    uint8_t bak_remotecommit[BTC_SZ_PUBKEY];
    memcpy(bak_percommit, self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT], sizeof(bak_percommit));
    memcpy(bak_remotecommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], sizeof(bak_remotecommit));

    //local
    ln_signer_create_prev_percommitsec(self,
                self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT],
                self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //remote
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);

    //update keys
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + self->commit_local.htlc_num);

    //local commit_tx
    bool ret = ln_comtx_create_to_local(self,
                pClose, NULL, 0,        //closeのみ(HTLC署名無し)
                self->commit_local.commit_num,
                self->commit_remote.to_self_delay,
                self->commit_local.dust_limit_sat);
    if (!ret) {
        LOGE("fail: create_to_local\n");
        ln_close_free_forcetx(pClose);
    }

    //元に戻す
    memcpy(self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT],
            bak_percommit, sizeof(bak_percommit));
    btc_keys_priv2pub(self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT]);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            bak_remotecommit, sizeof(bak_remotecommit));
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    LOGD("END: %d\n", ret);

    return ret;
}


/*
 * funding_txがspentで、remote commit_txのtxidがgetrawtransactionできる状態で呼ばれる。
 * (remote commit_txが展開＝相手がunilateral closeした)
 */
bool ln_close_create_tx(ln_self_t *self, ln_close_force_t *pClose)
{
    LOGD("BEGIN\n");

    //復元用
    uint8_t bak_percommit[BTC_SZ_PRIVKEY];
    uint8_t bak_remotecommit[BTC_SZ_PUBKEY];
    memcpy(bak_percommit, self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT], sizeof(bak_percommit));
    memcpy(bak_remotecommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], sizeof(bak_remotecommit));

    //local
    ln_signer_create_prev_percommitsec(self,
                self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT],
                self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //remote
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);

    //update keys
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + self->commit_remote.htlc_num);

    //remote commit_tx
    bool ret = ln_comtx_create_to_remote(self,
                &self->commit_remote,
                pClose, NULL,
                self->commit_remote.commit_num);
    if (!ret) {
        LOGE("fail: create_to_remote\n");
        ln_close_free_forcetx(pClose);
    }

    //元に戻す
    memcpy(self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT],
            bak_percommit, sizeof(bak_percommit));
    btc_keys_priv2pub(self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT]);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            bak_remotecommit, sizeof(bak_remotecommit));
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    LOGD("END\n");
    return ret;
}


void ln_close_free_forcetx(ln_close_force_t *pClose)
{
    for (int lp = 0; lp < pClose->num; lp++) {
        btc_tx_free(&pClose->p_tx[lp]);
    }
    pClose->num = 0;
    UTL_DBG_FREE(pClose->p_tx);
    pClose->p_tx = NULL;
    UTL_DBG_FREE(pClose->p_htlc_idx);
    pClose->p_htlc_idx = NULL;

    int num = pClose->tx_buf.len / sizeof(btc_tx_t);
    btc_tx_t *p_tx = (btc_tx_t *)pClose->tx_buf.buf;
    for (int lp = 0; lp < num; lp++) {
        btc_tx_free(&p_tx[lp]);
    }
    utl_buf_free(&pClose->tx_buf);
}


/* 相手にrevoked transaction closeされた場合に1回だけ呼び出す。
 * これ以降、鍵などは相手が送信したrevoked transaction当時のものに戻される。
 *      1. sequenceとlocktimeからcommitment number復元
 *      2. localとremoteの per_commitment_secret復元
 *      3. 鍵復元
 *      4. HTLCごと
 *          4.1 DBから当時のpayment_hashを検索
 *          4.2 script復元
 */
bool ln_close_remoterevoked(ln_self_t *self, const btc_tx_t *pRevokedTx, void *pDbParam)
{
    //取り戻す必要があるvout数
    self->revoked_cnt = 0;
    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        if (pRevokedTx->vout[lp].script.len != BTC_SZ_WITPROG_P2WPKH) {
            //to_remote output以外はスクリプトを作って取り戻す
            self->revoked_cnt++;
        }
    }
    LOGD("revoked_cnt=%d\n", self->revoked_cnt);
    self->revoked_num = 1 + self->revoked_cnt;      //p_revoked_vout[0]にto_local系を必ず入れるため、+1しておく
                                                    //(to_local自体が無くても、HTLC txの送金先がto_localと同じtxになるため)
    ln_revoked_buf_alloc(self);

    //
    //相手がrevoked_txを展開した前提で、スクリプトを再現
    //

    //commitment numberの復元
    uint64_t commit_num = calc_commit_num(self, pRevokedTx);

    //remote per_commitment_secretの復元
    utl_buf_alloc(&self->revoked_sec, BTC_SZ_PRIVKEY);
    bool ret = ln_derkey_storage_get_secret(self->revoked_sec.buf, &self->peer_storage, (uint64_t)(LN_SECINDEX_INIT - commit_num));
    if (!ret) {
        LOGE("fail: ln_derkey_storage_get_secret()\n");
        abort();
    }
    btc_keys_priv2pub(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], self->revoked_sec.buf);
    //LOGD2("  pri:");
    //DUMPD(self->revoked_sec.buf, BTC_SZ_PRIVKEY);
    //LOGD2("  pub:");
    //DUMPD(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);

    //local per_commitment_secretの復元
    ln_signer_keys_update_force(self, (uint64_t)(LN_SECINDEX_INIT - commit_num));

    //鍵の復元
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);
    //commitment number(for obscured commitment number)
    //self->commit_remote.commit_num = commit_num;

    //to_local outputとHTLC Timeout/Success Txのoutputは同じ形式のため、to_local outputの有無にかかわらず作っておく。
    //p_revoked_vout[0]にはscriptPubKey、p_revoked_wit[0]にはwitnessProgramを作る。
    ln_script_create_tolocal(&self->p_revoked_wit[LN_RCLOSE_IDX_TOLOCAL],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                self->commit_local.to_self_delay);
    utl_buf_init(&self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL]);
    btc_script_p2wsh_create_scriptsig(&self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL], &self->p_revoked_wit[LN_RCLOSE_IDX_TOLOCAL]);
    // LOGD("calc to_local vout: ");
    // DUMPD(self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].buf, self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].len);

    int htlc_cnt = 0;
    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        LOGD("vout[%d]: ", lp);
        DUMPD(pRevokedTx->vout[lp].script.buf, pRevokedTx->vout[lp].script.len);
        if (pRevokedTx->vout[lp].script.len == BTC_SZ_WITPROG_P2WPKH) {
            //to_remote output
            LOGD("[%d]to_remote_output\n", lp);
            utl_buf_init(&self->p_revoked_wit[LN_RCLOSE_IDX_TOREMOTE]);
            utl_buf_alloccopy(&self->p_revoked_vout[LN_RCLOSE_IDX_TOREMOTE], pRevokedTx->vout[lp].script.buf, pRevokedTx->vout[lp].script.len);
        } else if (utl_buf_cmp(&pRevokedTx->vout[lp].script, &self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL])) {
            //to_local output
            LOGD("[%d]to_local_output\n", lp);
        } else {
            //HTLC Tx
            //  DBには、vout(SHA256後)をkeyにして、payment_hashを保存している。
            ln_htlctype_t type;
            uint8_t payhash[BTC_SZ_HASH256];
            uint32_t expiry;
            bool srch = ln_db_phash_search(payhash, &type, &expiry,
                            pRevokedTx->vout[lp].script.buf, pDbParam);
            if (srch) {
                int htlc_idx = LN_RCLOSE_IDX_HTLC + htlc_cnt;
                ln_script_htlcinfo_script(&self->p_revoked_wit[htlc_idx],
                        type,
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                        payhash,
                        expiry);
                utl_buf_init(&self->p_revoked_vout[htlc_idx]);
                btc_script_p2wsh_create_scriptsig(&self->p_revoked_vout[htlc_idx], &self->p_revoked_wit[htlc_idx]);
                self->p_revoked_type[htlc_idx] = type;

                LOGD("[%d]%s(%d) HTLC output%d\n", lp, (type == LN_HTLCTYPE_OFFERED) ? "offered" : "recieved", type, htlc_idx);
                htlc_cnt++;
            } else {
                LOGD("[%d]not detect\n", lp);
            }
        }
    }

    LOGD("ret=%d\n", ret);
    return ret;
}


/********************************************************************
 * Normal Operation関係
 ********************************************************************/

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


bool ln_update_fee_create(ln_self_t *self, utl_buf_t *pUpdFee, uint32_t FeeratePerKw)
{
    LOGD("BEGIN: %" PRIu32 " --> %" PRIu32 "\n", self->feerate_per_kw, FeeratePerKw);

    bool ret;

    if (!M_INIT_CH_EXCHANGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init/channel_reestablish finished");
        return false;
    }

    //BOLT02
    //  The node not responsible for paying the Bitcoin fee:
    //    MUST NOT send update_fee.
    if (!ln_is_funder(self)) {
        M_SET_ERR(self, LNERR_INV_STATE, "not funder");
        return false;
    }

    if (self->feerate_per_kw == FeeratePerKw) {
        //same
        M_SET_ERR(self, LNERR_INV_STATE, "same feerate_per_kw");
        return false;
    }
    if (FeeratePerKw < LN_FEERATE_PER_KW_MIN) {
        //too low
        M_SET_ERR(self, LNERR_INV_STATE, "feerate_per_kw too low");
        return false;
    }

    ln_msg_update_fee_t msg;
    msg.p_channel_id = self->channel_id;
    msg.feerate_per_kw = FeeratePerKw;
    ret = ln_msg_update_fee_write(pUpdFee, &msg);
    if (ret) {
        self->feerate_per_kw = FeeratePerKw;
    } else {
        LOGE("fail\n");
    }

    LOGD("END\n");
    return ret;
}


/********************************************************************
 * ping/pong
 ********************************************************************/

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


bool ln_pong_create(ln_self_t *self, utl_buf_t *pPong, uint16_t NumPongBytes)
{
    (void)self;

    ln_msg_pong_t msg;

    msg.byteslen = NumPongBytes;
    msg.p_ignored = NULL;
    bool ret = ln_msg_pong_write(pPong, &msg);

    return ret;
}


/********************************************************************
 * others
 ********************************************************************/

bool ln_wallet_create_tolocal(const ln_self_t *self, btc_tx_t *pTx,uint64_t Value, uint32_t ToSelfDelay,
                const utl_buf_t *pScript, const uint8_t *pTxid, int Index, bool bRevoked)
{
    bool ret = create_basetx(pTx, Value,
                NULL, ToSelfDelay, pTxid, Index, bRevoked);
    if (ret) {
        btc_keys_t sigkey;
        ln_signer_tolocal_key(self, &sigkey, bRevoked);
        ret = ln_script_tolocal_wit(pTx, &sigkey, pScript, bRevoked);
    }
    return ret;
}


bool ln_wallet_create_toremote(
            const ln_self_t *self, btc_tx_t *pTx, uint64_t Value,
            const uint8_t *pTxid, int Index)
{
    bool ret = create_basetx(pTx, Value,
                NULL, 0, pTxid, Index, false);
    if (ret) {
        btc_keys_t sigkey;
        ln_signer_toremote_key(self, &sigkey);
        ln_script_toremote_wit(pTx, &sigkey);
    }

    return ret;
}


bool ln_revokedhtlc_create_spenttx(const ln_self_t *self, btc_tx_t *pTx, uint64_t Value,
                int WitIndex, const uint8_t *pTxid, int Index)
{
    ln_script_feeinfo_t feeinfo;
    feeinfo.feerate_per_kw = self->feerate_per_kw;
    ln_script_fee_calc(&feeinfo, NULL, 0);
    uint64_t fee = (self->p_revoked_type[WitIndex] == LN_HTLCTYPE_OFFERED) ? feeinfo.htlc_timeout : feeinfo.htlc_success;
    LOGD("Value=%" PRIu64 ", fee=%" PRIu64 "\n", Value, fee);

    ln_script_htlctx_create(pTx, Value - fee, &self->shutdown_scriptpk_local, self->p_revoked_type[WitIndex], 0, pTxid, Index);
    M_DBG_PRINT_TX2(pTx);

    btc_keys_t signkey;
    ln_signer_get_revokesec(self, &signkey,
                    self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
                    self->revoked_sec.buf);
    // LOGD("key-priv: ");
    // DUMPD(signkey.priv, BTC_SZ_PRIVKEY);
    // LOGD("key-pub : ");
    // DUMPD(signkey.pub, BTC_SZ_PUBKEY);

    ln_script_htlcsign_t htlcsign = LN_HTLCSIGN_NONE;
    switch (self->p_revoked_type[WitIndex]) {
    case LN_HTLCTYPE_OFFERED:
        htlcsign = LN_HTLCSIGN_REVOKE_OFFER;
        break;
    case LN_HTLCTYPE_RECEIVED:
        htlcsign = LN_HTLCSIGN_REVOKE_RECV;
        break;
    default:
        LOGD("index=%d, %d\n", WitIndex, self->p_revoked_type[WitIndex]);
        assert(0);
    }
    bool ret;
    if (htlcsign != LN_HTLCSIGN_NONE) {
        utl_buf_t buf_sig = UTL_BUF_INIT;
        ret = ln_script_htlctx_sign(pTx,
                &buf_sig,
                Value,
                &signkey,
                &self->p_revoked_wit[WitIndex]);
        if (ret) {
            ret = ln_script_htlctx_wit(pTx,
                &buf_sig,
                &signkey,
                NULL,
                NULL,
                &self->p_revoked_wit[WitIndex],
                htlcsign);
        }
        utl_buf_free(&buf_sig);
    } else {
        ret = false;
    }

    return ret;
}


void ln_preimage_hash_calc(uint8_t *pHash, const uint8_t *pPreImage)
{
    btc_md_sha256(pHash, pPreImage, LN_SZ_PREIMAGE);
}


/* [routing用]channel_announcementデータ解析
 *
 * @param[out]  p_short_channel_id
 * @param[out]  pNodeId1
 * @param[out]  pNodeId2
 * @param[in]   pData
 * @param[in]   Len
 * @retval  true        解析成功
 */
bool ln_getids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len)
{
    ln_msg_channel_announcement_t msg;
    bool ret = ln_msg_channel_announcement_read(&msg, pData, Len);
    if (ret && (msg.short_channel_id != 0)) {
        *p_short_channel_id = msg.short_channel_id;
        memcpy(pNodeId1, msg.p_node_id_1, BTC_SZ_PUBKEY);
        memcpy(pNodeId2, msg.p_node_id_2, BTC_SZ_PUBKEY);
    } else {
        LOGE("fail\n");
    }
    return ret;
}


void ln_last_connected_addr_set(ln_self_t *self, const ln_nodeaddr_t *pAddr)
{
    memcpy(&self->last_connected_addr, pAddr, sizeof(ln_nodeaddr_t));
    LOGD("addr[%d]: %d.%d.%d.%d:%d\n", pAddr->type,
            pAddr->addrinfo.ipv4.addr[0], pAddr->addrinfo.ipv4.addr[1],
            pAddr->addrinfo.ipv4.addr[2], pAddr->addrinfo.ipv4.addr[3],
            pAddr->port);
    M_DB_SELF_SAVE(self);
}


/* [非公開]デバッグ用オプション設定
 *
 */
void ln_debug_set(unsigned long debug)
{
    mDebug = debug;
    LOGD("debug flag: 0x%lx\n", mDebug);
    if (!mDebug) LOGD("normal mode\n");
    if (!LN_DBG_FULFILL()) LOGD("no fulfill\n");
    if (!LN_DBG_CLOSING_TX()) LOGD("no send closing_tx\n");
    if (!LN_DBG_MATCH_PREIMAGE()) LOGD("HTLC preimage mismatch\n");
}


/* [非公開]デバッグ用オプション取得
 *
 */
unsigned long ln_debug_get(void)
{
    return mDebug;
}


/**************************************************************************
 * getter/setter
 **************************************************************************/

const uint8_t *ln_channel_id(const ln_self_t *self)
{
    return self->channel_id;
}


uint64_t ln_short_channel_id(const ln_self_t *self)
{
    return self->short_channel_id;
}


void ln_short_channel_id_clr(ln_self_t *self)
{
    self->short_channel_id = 0;
}


void *ln_get_param(ln_self_t *self)
{
    return self->p_param;
}


ln_status_t ln_status_get(const ln_self_t *self)
{
    return self->status;
}


bool ln_status_is_closing(const ln_self_t *self)
{
    return self->status > LN_STATUS_NORMAL;
}


uint64_t ln_our_msat(const ln_self_t *self)
{
    return self->our_msat;
}


uint64_t ln_their_msat(const ln_self_t *self)
{
    return self->their_msat;
}


const uint8_t *ln_funding_txid(const ln_self_t *self)
{
    return self->funding_local.txid;
}


uint32_t ln_funding_txindex(const ln_self_t *self)
{
    return self->funding_local.txindex;
}


const utl_buf_t *ln_funding_redeem(const ln_self_t *self)
{
    return &self->redeem_fund;
}


uint32_t ln_minimum_depth(const ln_self_t *self)
{
    return self->min_depth;
}


bool ln_is_funder(const ln_self_t *self)
{
    return (self->fund_flag & LN_FUNDFLAG_FUNDER);
}


bool ln_is_funding(const ln_self_t *self)
{
    return (self->fund_flag & LN_FUNDFLAG_FUNDING);
}


const btc_tx_t *ln_funding_tx(const ln_self_t *self)
{
    return &self->tx_funding;
}


const uint8_t *ln_funding_blockhash(const ln_self_t *self)
{
    return self->funding_bhash;
}


uint32_t ln_last_conf_get(const ln_self_t *self)
{
    return self->last_confirm;
}


void ln_last_conf_set(ln_self_t *self, uint32_t Conf)
{
    if (Conf > self->last_confirm) {
        self->last_confirm = Conf;
    }
}


bool ln_need_init_routing_sync(const ln_self_t *self)
{
    return self->lfeature_remote & LN_INIT_LF_ROUTE_SYNC;
}


bool ln_is_announced(const ln_self_t *self)
{
    return (self->anno_flag & LN_ANNO_FLAG_END);
}


uint32_t ln_feerate_per_kw_calc(uint64_t feerate_kb)
{
    return (uint32_t)(feerate_kb / 4);
}


uint64_t ln_calc_fee(uint32_t vsize, uint64_t feerate_kw)
{
    return vsize * feerate_kw * 4 / 1000;
}


uint32_t ln_feerate_per_kw(const ln_self_t *self)
{
    return self->feerate_per_kw;
}


void ln_feerate_per_kw_set(ln_self_t *self, uint32_t FeeratePerKw)
{
    self->feerate_per_kw = FeeratePerKw;
}


uint64_t ln_estimate_fundingtx_fee(uint32_t FeeratePerKw)
{
    return ln_calc_fee(LN_SZ_FUNDINGTX_VSIZE, FeeratePerKw);
}


uint64_t ln_estimate_initcommittx_fee(uint32_t FeeratePerKw)
{
    return (LN_FEE_COMMIT_BASE * FeeratePerKw / 1000);
}


bool ln_is_shutdown_sent(const ln_self_t *self)
{
    return self->shutdown_flag & LN_SHDN_FLAG_SEND;
}


uint64_t ln_closing_signed_initfee(const ln_self_t *self)
{
    return (LN_FEE_COMMIT_BASE * self->feerate_per_kw / 1000);
}


const ln_commit_data_t *ln_commit_local(const ln_self_t *self)
{
    return &self->commit_local;
}


const ln_commit_data_t *ln_commit_remote(const ln_self_t *self)
{
    return &self->commit_remote;
}


const utl_buf_t *ln_shutdown_scriptpk_local(const ln_self_t *self)
{
    return &self->shutdown_scriptpk_local;
}


const utl_buf_t *ln_shutdown_scriptpk_remote(const ln_self_t *self)
{
    return &self->shutdown_scriptpk_remote;
}


const ln_update_add_htlc_t *ln_update_add_htlc(const ln_self_t *self, uint16_t htlc_idx)
{
    return (htlc_idx < LN_HTLC_MAX) ? &self->cnl_add_htlc[htlc_idx] : NULL;
}


bool ln_is_offered_htlc_timeout(const ln_self_t *self, uint16_t htlc_idx, uint32_t BlkCnt)
{
    return (htlc_idx < LN_HTLC_MAX) &&
            ((self->cnl_add_htlc[htlc_idx].stat.bits & LN_HTLCFLAG_MASK_ALL) == LN_HTLCFLAG_SFT_TIMEOUT) &&
            (self->cnl_add_htlc[htlc_idx].cltv_expiry <= BlkCnt);
}


const utl_buf_t *ln_preimage_remote(const btc_tx_t *pTx)
{
    return (pTx->vin[0].wit_item_cnt == 5) ? &pTx->vin[0].witness[3] : NULL;
}


uint16_t ln_revoked_cnt(const ln_self_t *self)
{
    return self->revoked_cnt;
}


bool ln_revoked_cnt_dec(ln_self_t *self)
{
    self->revoked_cnt--;
    return self->revoked_cnt == 0;
}


uint16_t ln_revoked_num(const ln_self_t *self)
{
    return self->revoked_num;
}


void ln_set_revoked_confm(ln_self_t *self, uint32_t confm)
{
    self->revoked_chk = confm;
}


uint32_t ln_revoked_confm(const ln_self_t *self)
{
    return self->revoked_chk;
}


const utl_buf_t* ln_revoked_vout(const ln_self_t *self)
{
    return self->p_revoked_vout;
}


const utl_buf_t* ln_revoked_wit(const ln_self_t *self)
{
    return self->p_revoked_wit;
}


bool ln_open_channel_announce(const ln_self_t *self)
{
    bool ret = (self->fund_flag & LN_FUNDFLAG_NO_ANNO_CH);

    //コメントアウトすると、announcement_signatures交換済みかどうかにかかわらず、
    //送信しても良い状況であればannouncement_signaturesを起動時に送信する
    if (ret) {
        utl_buf_t buf_cnl_anno = UTL_BUF_INIT;
        bool havedb = ln_db_annocnl_load(&buf_cnl_anno, self->short_channel_id);
        if (havedb) {
            ln_msg_channel_announcement_print(buf_cnl_anno.buf, buf_cnl_anno.len);
        }
        utl_buf_free(&buf_cnl_anno);
        ret = !havedb;
    }
    LOGD("announcement_signatures request:%d\n", ret);
    return ret;
}


const uint8_t *ln_their_node_id(const ln_self_t *self)
{
    return self->peer_node_id;
}


uint32_t ln_cltv_expily_delta(const ln_self_t *self)
{
    return self->anno_prm.cltv_expiry_delta;
}


uint64_t ln_forward_fee(const ln_self_t *self, uint64_t AmountMsat)
{
    return (uint64_t)self->anno_prm.fee_base_msat +
            (AmountMsat * (uint64_t)self->anno_prm.fee_prop_millionths / (uint64_t)1000000);
}


const ln_nodeaddr_t *ln_last_connected_addr(const ln_self_t *self)
{
    return &self->last_connected_addr;
}


int ln_err(const ln_self_t *self)
{
    return self->err;
}


const char *ln_errmsg(const ln_self_t *self)
{
    return self->err_msg;
}


int ln_cnlupd_direction(const ln_msg_channel_update_t *pCnlUpd)
{
    return (pCnlUpd->channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION) ? 1 : 0;
}


bool ln_cnlupd_enable(const ln_msg_channel_update_t *pCnlUpd)
{
    return !(pCnlUpd->channel_flags & LN_CNLUPD_CHFLAGS_DISABLE);
}


/********************************************************************
 * package functions
 ********************************************************************/

/** revoked transaction close関連のメモリ確保
 *
 */
void HIDDEN ln_revoked_buf_alloc(ln_self_t *self)
{
    LOGD("alloc(%d)\n", self->revoked_num);

    self->p_revoked_vout = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * self->revoked_num);
    self->p_revoked_wit = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * self->revoked_num);
    self->p_revoked_type = (ln_htlctype_t *)UTL_DBG_MALLOC(sizeof(ln_htlctype_t) * self->revoked_num);
    for (int lp = 0; lp < self->revoked_num; lp++) {
        utl_buf_init(&self->p_revoked_vout[lp]);
        utl_buf_init(&self->p_revoked_wit[lp]);
        self->p_revoked_type[lp] = LN_HTLCTYPE_NONE;
    }
}


/** #ln_revoked_buf_alloc()で確保したメモリの解放
 *
 */
void HIDDEN ln_revoked_buf_free(ln_self_t *self)
{
    if (self->revoked_num == 0) {
        return;
    }

    for (int lp = 0; lp < self->revoked_num; lp++) {
        utl_buf_free(&self->p_revoked_vout[lp]);
        utl_buf_free(&self->p_revoked_wit[lp]);
    }
    UTL_DBG_FREE(self->p_revoked_vout);
    UTL_DBG_FREE(self->p_revoked_wit);
    UTL_DBG_FREE(self->p_revoked_type);
    self->revoked_num = 0;
    self->revoked_cnt = 0;

    LOGD("free\n");
}


/********************************************************************
 * private functions
 ********************************************************************/

/** チャネル情報消去
 *
 * @param[in,out]       self
 * @note
 *      - channelが閉じたときに呼び出すこと
 */
static void channel_clear(ln_self_t *self)
{
    utl_buf_free(&self->shutdown_scriptpk_local);
    utl_buf_free(&self->shutdown_scriptpk_remote);
    utl_buf_free(&self->redeem_fund);
    utl_buf_free(&self->cnl_anno);
    utl_buf_free(&self->revoked_sec);
    ln_revoked_buf_free(self);

    btc_tx_free(&self->tx_funding);
    btc_tx_free(&self->tx_closing);

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        utl_buf_free(&self->cnl_add_htlc[idx].buf_payment_preimage);
        utl_buf_free(&self->cnl_add_htlc[idx].buf_onion_reason);
        utl_buf_free(&self->cnl_add_htlc[idx].buf_shared_secret);
    }

    memset(self->peer_node_id, 0, BTC_SZ_PUBKEY);
    self->anno_flag = 0;
    self->shutdown_flag = 0;

    ln_enc_auth_handshake_free(self);

    free_establish(self, true);
}


/********************************************************************
 * メッセージ受信
 ********************************************************************/

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
                    callback(self, LN_CB_FWD_ADDHTLC_START, &fwd);
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
                        callback(self, LN_CB_BWD_DELHTLC_START, &bwd);
                        clear_htlc_comrevflag(p_htlc, p_flag->delhtlc);
                    }

                    if (p_htlc->prev_short_channel_id == 0) {
                        if (p_flag->delhtlc != LN_DELHTLC_FULFILL) {
                            //origin nodeで失敗 --> 送金の再送
                            callback(self, LN_CB_PAYMENT_RETRY, p_htlc->payment_sha256);
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
            callback(self, LN_CB_REV_AND_ACK_EXCG, NULL);
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
                    LOGD("send: %s\n", ln_misc_msgname(type));
                    callback(self, LN_CB_SEND_REQ, &buf);
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
            callback(self, LN_CB_SEND_REQ, &buf);
            b_updfee = true;
        }
        utl_buf_free(&buf);
    }
    if (b_comsig || b_updfee) {
        //commitment_signed送信
        utl_buf_t buf = UTL_BUF_INIT;
        bool ret = create_commitment_signed(self, &buf);
        if (ret) {
            callback(self, LN_CB_SEND_REQ, &buf);

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
            callback(self, LN_CB_QUIT, NULL);
        }
        utl_buf_free(&buf);
    }
}


static bool recv_init(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    callback(self, LN_CB_INIT_RECV, &initial_routing_sync);

LABEL_EXIT:
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_FEATURE, "init error");
    }

    return ret;
}


static bool recv_error(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    if (ln_is_funding(self)) {
        LOGD("stop funding\n");
        free_establish(self, false);    //切断せずに継続する場合もあるため、残す
    }

    ln_msg_error_t msg;
    ln_msg_error_read(&msg, pData, Len);
    callback(self, LN_CB_ERROR, &msg);
    return true;
}


static bool recv_ping(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    bool ret;

    ln_msg_ping_t msg;
    ret = ln_msg_ping_read(&msg, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    ret = send_pong(self, &msg);

    //LOGD("END\n");
    return ret;
}


static bool send_pong(ln_self_t *self, ln_msg_ping_t *pPingMsg)
{
    bool ret = false;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_pong_t msg;

    msg.byteslen = pPingMsg->num_pong_bytes;
    msg.p_ignored = NULL;
    if (!ln_msg_pong_write(&buf, &msg)) goto LABEL_EXIT;
    callback(self, LN_CB_SEND_REQ, &buf);

    ret = true;

LABEL_EXIT:
    utl_buf_free(&buf);
    return ret;
}


static bool recv_pong(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    callback(self, LN_CB_PONG_RECV, &pongrecv);

    //LOGD("END\n");
    return pongrecv.result;
}


static bool recv_open_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING], msg.p_funding_pubkey, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_REVOCATION], msg.p_revocation_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PAYMENT], msg.p_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_DELAYED], msg.p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_HTLC], msg.p_htlc_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], msg.p_first_per_commitment_point, BTC_SZ_PUBKEY);

    if (memcmp(gGenesisChainHash, msg.p_chain_hash, sizeof(gGenesisChainHash))) {
        LOGE("fail: chain_hash mismatch\n");
        return false;
    }

    //check feerate_per_kw
    callback(self, LN_CB_GET_LATEST_FEERATE, &self->feerate_per_kw);
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
    if (self->p_establish->estprm.channel_reserve_sat < msg.dust_limit_satoshis) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "our channel_reserve_satoshis is lower than their dust_limit_satoshis");
        return false;
    }
    if (self->p_establish->estprm.dust_limit_sat > msg.channel_reserve_satoshis) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "our dust_limit_satoshis is greater than their channel_reserve_satoshis");
        return false;
    }

    //params for commit_remote
    self->commit_remote.dust_limit_sat = msg.dust_limit_satoshis;
    self->commit_remote.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    self->commit_remote.channel_reserve_sat = msg.channel_reserve_satoshis;
    self->commit_remote.htlc_minimum_msat = msg.htlc_minimum_msat;
    self->commit_remote.to_self_delay = msg.to_self_delay;
    self->commit_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    //copy first_per_commitment_point for the first revoke_and_ack
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);

    //params for funding
    self->funding_sat = msg.funding_satoshis;
    self->feerate_per_kw = msg.feerate_per_kw;
    self->our_msat = msg.push_msat;
    self->their_msat = LN_SATOSHI2MSAT(msg.funding_satoshis) - msg.push_msat;
    self->fund_flag = (ln_fundflag_t)(((msg.channel_flags & 1) ? LN_FUNDFLAG_NO_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);

    //generate keys
    ln_signer_create_channelkeys(self);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    if (!send_accept_channel(self)) {
        LOGE("fail: send accept_channel\n");
        return false;
    }

    LOGD("END\n");
    return true;
}


static bool send_accept_channel(ln_self_t *self)
{
    ln_msg_accept_channel_t msg;
    msg.p_temporary_channel_id = self->channel_id;
    msg.dust_limit_satoshis = self->p_establish->estprm.dust_limit_sat;
    msg.max_htlc_value_in_flight_msat = self->p_establish->estprm.max_htlc_value_in_flight_msat;
    msg.channel_reserve_satoshis = self->p_establish->estprm.channel_reserve_sat;
    msg.htlc_minimum_msat = self->p_establish->estprm.htlc_minimum_msat;
    msg.minimum_depth = self->p_establish->estprm.min_depth;
    msg.to_self_delay = self->p_establish->estprm.to_self_delay;
    msg.max_accepted_htlcs = self->p_establish->estprm.max_accepted_htlcs;
    msg.p_funding_pubkey = self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING];
    msg.p_revocation_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_REVOCATION];
    msg.p_payment_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_PAYMENT];
    msg.p_delayed_payment_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_DELAYED];
    msg.p_htlc_basepoint = self->funding_local.pubkeys[MSG_FUNDIDX_HTLC];
    msg.p_first_per_commitment_point = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    msg.shutdown_len = 0;
    msg.p_shutdown_scriptpubkey = NULL;
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_accept_channel_write(&buf, &msg);
    callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    self->min_depth = msg.minimum_depth;
    self->commit_local.dust_limit_sat = msg.dust_limit_satoshis;
    self->commit_local.max_htlc_value_in_flight_msat = msg.max_htlc_value_in_flight_msat;
    self->commit_local.channel_reserve_sat = msg.channel_reserve_satoshis;
    self->commit_local.htlc_minimum_msat = msg.htlc_minimum_msat;
    self->commit_local.to_self_delay = msg.to_self_delay;
    self->commit_local.max_accepted_htlcs = msg.max_accepted_htlcs;

    //obscured commitment tx number
    self->obscured = ln_script_calc_obscured_txnum(
        self->funding_remote.pubkeys[MSG_FUNDIDX_PAYMENT], self->funding_local.pubkeys[MSG_FUNDIDX_PAYMENT]);
    LOGD("obscured=0x%016" PRIx64 "\n", self->obscured);

    //vout 2-of-2
    if (!btc_script_2of2_create_redeem_sorted(&self->redeem_fund, &self->key_fund_sort,
        self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING], self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING])) {
        M_SET_ERR(self, LNERR_CREATE_2OF2, "create 2-of-2");
        return false;
    }
    return true;
}


static bool recv_accept_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING], msg.p_funding_pubkey, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_REVOCATION], msg.p_revocation_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PAYMENT], msg.p_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_DELAYED], msg.p_delayed_payment_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_HTLC], msg.p_htlc_basepoint, BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], msg.p_first_per_commitment_point, BTC_SZ_PUBKEY);

    //temporary_channel_id
    if (!chk_channelid(msg.p_temporary_channel_id, self->channel_id)) {
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
    self->commit_remote.to_self_delay = msg.to_self_delay;
    self->commit_remote.max_accepted_htlcs = msg.max_accepted_htlcs;

    //first_per_commitment_pointは初回revoke_and_ackのper_commitment_secretに対応する
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);

    //generate keys
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    //create funding_tx
    if (!create_funding_tx(self, true)) {
        M_SET_ERR(self, LNERR_CREATE_TX, "create funding_tx");
        return false;
    }

    //obscured commitment tx number
    self->obscured = ln_script_calc_obscured_txnum(
        self->funding_local.pubkeys[MSG_FUNDIDX_PAYMENT], self->funding_remote.pubkeys[MSG_FUNDIDX_PAYMENT]);
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

    if (!send_funding_created(self)) {
        //XXX:
        return false;
    }

    LOGD("END\n");
    return true;
}


static bool send_funding_created(ln_self_t *self)
{
    ln_msg_funding_created_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    msg.p_temporary_channel_id = self->channel_id;
    msg.p_funding_txid = self->funding_local.txid;
    msg.funding_output_index = self->funding_local.txindex;
    msg.p_signature = self->commit_remote.signature;
    ln_msg_funding_created_write(&buf, &msg);
    callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


static bool recv_funding_created(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    if (!chk_channelid(msg.p_temporary_channel_id, self->channel_id)) {
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
        0, self->commit_remote.to_self_delay, self->commit_local.dust_limit_sat)) {
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
    ln_misc_calc_channel_id(self->channel_id, self->funding_local.txid, self->funding_local.txindex);

    if (!send_funding_signed(self)) {
        //XXX:
        return false;
    }

    LOGD("END\n");
    return true;
}


static bool send_funding_signed(ln_self_t *self)
{
    ln_msg_funding_signed_t msg;
    utl_buf_t buf = UTL_BUF_INIT;
    msg.p_channel_id = self->channel_id;
    msg.p_signature = self->commit_remote.signature;
    ln_msg_funding_signed_write(&buf, &msg);
    callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);

    //wait funding_tx
    start_funding_wait(self, false);
    return true;
}


static bool recv_funding_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ln_misc_calc_channel_id(self->channel_id, self->funding_local.txid, self->funding_local.txindex);
    if (!chk_channelid(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //initial commit tx(自分が持つTo-Local)
    //  to-self-delayは相手の値(accept_channel)を使う
    //  HTLCは存在しない
    if (!ln_comtx_create_to_local(self,
        NULL, NULL, 0,      //closeもHTLC署名も無し
        0, self->commit_remote.to_self_delay, self->commit_local.dust_limit_sat)) {
        LOGE("fail: create_to_local\n");
        return false;
    }

    //funding_tx安定待ち
    start_funding_wait(self, true);

    LOGD("END\n");
    return true;
}


/*
 * funding_lockedはお互い送信し合うことになる。
 *      open_channel送信側: funding_signed受信→funding_tx安定待ち→funding_locked送信→funding_locked受信→完了
 *      open_channel受信側: funding_locked受信→funding_tx安定待ち→完了
 *
 * funding_tx安定待ちで一度シーケンスが止まる。
 */
static bool recv_funding_locked(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    ln_msg_funding_locked_t msg;
    if (!ln_msg_funding_locked_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel_id
    if (!chk_channelid(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    LOGV("prev: ");
    DUMPV(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    LOGV("next: ");
    DUMPV(msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);

    //prev_percommitはrevoke_and_ackでのみ更新する
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);

    //funding中終了
    free_establish(self, true);

    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);
    M_DB_SELF_SAVE(self);

    callback(self, LN_CB_FUNDINGLOCKED_RECV, NULL);

    //channel_reestablishと同じ扱いにする
    self->init_flag |= M_INIT_FLAG_REEST_RECV;

    M_DBG_COMMITNUM(self);

    LOGD("END\n");
    return true;
}


static bool recv_shutdown(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (self->shutdown_flag & LN_SHDN_FLAG_RECV) {
        //既にshutdownを受信済みなら、何もしない
        return false;
    }

    ln_msg_shutdown_t msg;
    if (!ln_msg_shutdown_read(&msg, pData, Len)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    utl_buf_alloccopy(&self->shutdown_scriptpk_remote, msg.p_scriptpubkey, msg.len);

    //channel_id
    if (!chk_channelid(msg.p_channel_id, self->channel_id)) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //scriptPubKey
    if (!ln_script_scriptpkh_check(&self->shutdown_scriptpk_remote)) {
        M_SET_ERR(self, LNERR_INV_PRIVKEY, "unknown scriptPubKey type");
        return false;
    }

    //shutdown受信済み
    self->shutdown_flag |= LN_SHDN_FLAG_RECV;
    M_DB_SELF_SAVE(self);

    self->close_last_fee_sat = 0;

    if (!(self->shutdown_flag & LN_SHDN_FLAG_SEND)) {
        //shutdown未送信の場合 == shutdownを要求された方

        //feeと送金先を設定してもらう
        callback(self, LN_CB_SHUTDOWN_RECV, NULL);

        utl_buf_t buf = UTL_BUF_INIT;
        if (!ln_shutdown_create(self, &buf)) {
            M_SET_ERR(self, LNERR_CREATE_MSG, "create shutdown");
            return false;
        }
        callback(self, LN_CB_SEND_REQ, &buf);
        utl_buf_free(&buf);
    }

    if (M_SHDN_FLAG_EXCHANGED(self->shutdown_flag)) {
        //shutdown交換完了
        self->status = LN_STATUS_CLOSE_WAIT;
        M_DB_SELF_SAVE(self);
    }

    if (M_SHDN_FLAG_EXCHANGED(self->shutdown_flag) && ln_is_funder(self)) {
        //shutdown交換完了 && funder --> 最初のclosing_signed送信

        //remoteの署名はないので、verifyしない
        btc_tx_free(&self->tx_closing);
        if (!create_closing_tx(self, &self->tx_closing, self->close_fee_sat, false)) {
            LOGE("fail: create close_t\n");
            return false;
        }

        if (!send_closing_signed(self)) {
            LOGE("fail\n");
            return false;
        }

        //署名送信により相手がbroadcastできるようになるので、一度保存する
        M_DB_SELF_SAVE(self);
    }

    LOGD("END\n");
    return true;
}


static bool send_closing_signed(ln_self_t *self)
{
    LOGD("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
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
    callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
    return true;
}


static bool recv_closing_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    if (!chk_channelid(msg.p_channel_id, self->channel_id)) {
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

    //相手が要求するFEEでverify
    btc_tx_free(&self->tx_closing);
    if (!create_closing_tx(self, &self->tx_closing, msg.fee_satoshis, true)) {
        LOGE("fail: create close_t\n");
        return false;
    }

    bool need_closetx = (self->close_last_fee_sat == msg.fee_satoshis);
    if (!need_closetx) {
        //送信feeと受信feeが不一致なので、上位層にfeeを設定してもらう
        ln_cb_closed_fee_t closed_fee;
        closed_fee.fee_sat = msg.fee_satoshis;
        callback(self, LN_CB_CLOSED_FEE, &closed_fee);
        //self->close_fee_satが更新される
    }

    //closing_tx作成
    btc_tx_free(&self->tx_closing);
    if (!create_closing_tx(self, &self->tx_closing, self->close_fee_sat, need_closetx)) {
        LOGE("fail: create close_t\n");
        return false;
    }

    if (need_closetx) {
        //closing_txを展開する
        LOGD("same fee!\n");
        utl_buf_t txbuf = UTL_BUF_INIT;
        if (!btc_tx_write(&self->tx_closing, &txbuf)) {
            LOGE("fail: create closeing_tx\n");
            return false;
        }
        ln_cb_closed_t closed;
        closed.result = false;
        closed.p_tx_closing = &txbuf;
        callback(self, LN_CB_CLOSED, &closed);

        //funding_txがspentになった
        if (closed.result) {
            LOGD("$$$ close waiting\n");
            self->status = LN_STATUS_CLOSE_SPENT;

            //clearはDB削除に任せる
            //channel_clear(self);
        } else {
            //XXX: retry to send closing_tx
            LOGE("fail: send closing_tx\n");
            utl_buf_free(&txbuf);
            return false;
        }
        utl_buf_free(&txbuf);
    } else {
        //closing_singnedを送信する
        LOGD("different fee!\n");
        if (!send_closing_signed(self)) {
            return false;
        }
    }
    M_DB_SELF_SAVE(self);

    LOGD("END\n");
    return true;
}


static bool recv_update_add_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ret = chk_channelid(channel_id, self->channel_id);
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
        callback(self, LN_CB_GETBLOCKCOUNT, &height);
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
        callback(self, LN_CB_ADD_HTLC_RECV, &add_htlc);

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
                ln_misc_push16be(&push_htlc, LNONION_TMP_CHAN_FAIL);
                ln_misc_push16be(&push_htlc, (uint16_t)buf.len);
                utl_push_data(&push_htlc, buf.buf, buf.len);
                utl_buf_free(&buf);
            } else {
                LOGE("fail: --> unknown next peer\n");
                ln_misc_push16be(&push_htlc, LNONION_UNKNOWN_NEXT_PEER);
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


static bool recv_update_fulfill_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ret = chk_channelid(msg.p_channel_id, self->channel_id);
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
        callback(self, LN_CB_FULFILL_HTLC_RECV, &fulfill);

        if (!fulfill.ret) {
            LOGE("fail: backwind\n");
        }
    } else {
        M_SET_ERR(self, LNERR_INV_ID, "fulfill");
    }

    LOGD("END\n");
    return ret;
}


static bool recv_update_fail_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ret = chk_channelid(msg.p_channel_id, self->channel_id);
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
            callback(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);

            ret = fail_recv.result;
            break;
        }
    }

    return ret;
}


static bool recv_commitment_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ret = chk_channelid(commsig.p_channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_EXIT;
    }

    //署名チェック＋保存: To-Local
    ret = ln_comtx_create_to_local(self,
            NULL, commsig.p_htlc_signature, commsig.num_htlcs,  //HTLC署名のみ(closeなし)
            self->commit_local.commit_num + 1,
            self->commit_remote.to_self_delay,
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
    ln_signer_create_prev_percommitsec(self, prev_secret, NULL);

    //storage_indexデクリメントおよびper_commit_secret更新
    ln_signer_keys_update_storage(self);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    //ln_print_keys(&self->funding_local, &self->funding_remote);

    //チェックOKであれば、revoke_and_ackを返す
    //HTLCに変化がある場合、revoke_and_ack→commitment_signedの順で送信

    // //revokeするsecret
    // for (uint64_t index = 0; index <= self->commit_local.revoke_num + 1; index++) {
    //     uint8_t old_secret[BTC_SZ_PRIVKEY];
    //     ln_derkey_create_secret(old_secret, self->priv_data.storage_seed, LN_SECINDEX_INIT - index);
    //     LOGD("$$$ old_secret(%016" PRIx64 "): ", LN_SECINDEX_INIT -index);
    //     DUMPD(old_secret, sizeof(old_secret));
    // }

    revack.p_channel_id = commsig.p_channel_id;
    revack.p_per_commitment_secret = prev_secret;
    revack.p_next_per_commitment_point = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
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
        callback(self, LN_CB_SEND_REQ, &buf);
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


static bool recv_revoke_and_ack(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ret = chk_channelid(msg.p_channel_id, self->channel_id);
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
    //     ret = ln_derkey_storage_get_secret(old_secret, &self->peer_storage, LN_SECINDEX_INIT - index);
    //     if (ret) {
    //         uint8_t pubkey[BTC_SZ_PUBKEY];
    //         btc_keys_priv2pub(pubkey, old_secret);
    //         //M_DB_SELF_SAVE(self);
    //         LOGD("$$$ old_secret(%016" PRIx64 "): ", LN_SECINDEX_INIT - index);
    //         DUMPD(old_secret, sizeof(old_secret));
    //         LOGD("$$$ pubkey: ");
    //         DUMPD(pubkey, sizeof(pubkey));
    //     } else {
    //         LOGD("$$$ fail: get last secret\n");
    //         //goto LABEL_EXIT;
    //     }
    // }

    // if (memcmp(prev_commitpt, self->funding_remote.prev_percommit, BTC_SZ_PUBKEY) != 0) {
    //     LOGE("fail: prev_secret mismatch\n");

    //     //check re-send
    //     if (memcmp(new_commitpt, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY) == 0) {
    //         //current per_commitment_point
    //         LOGD("skip: same as previous next_per_commitment_point\n");
    //         ret = true;
    //     } else {
    //         LOGD("recv secret: ");
    //         DUMPD(prev_commitpt, BTC_SZ_PUBKEY);
    //         LOGD("my secret: ");
    //         DUMPD(self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);
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
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], msg.p_next_per_commitment_point, BTC_SZ_PUBKEY);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
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


static bool recv_update_fee(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ret = chk_channelid(msg.p_channel_id, self->channel_id);
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

    callback(self, LN_CB_GET_LATEST_FEERATE, &rate);
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
    callback(self, LN_CB_UPDATE_FEE_RECV, &old_fee);

LABEL_EXIT:
    LOGD("END\n");
    return ret;
}


static bool recv_update_fail_malformed_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
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
    ret = chk_channelid(msg.p_channel_id, self->channel_id);
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
            ln_misc_push16be(&push_rsn, msg.failure_code);
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
            callback(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);
            utl_buf_free(&reason);

            ret = fail_recv.result;
            break;
        }
    }

    LOGD("END\n");
    return ret;
}


static bool recv_channel_reestablish(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;

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

    //channel-idチェック
    ret = chk_channelid(msg.p_channel_id, self->channel_id);
    if (!ret) {
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
            ln_derkey_create_secret(secret, self->priv_data.storage_seed, self->priv_data.storage_index + 4);
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

    //reestablish受信通知
    callback(self, LN_CB_REESTABLISH_RECV, NULL);

LABEL_EXIT:
    if (ret) {
        self->init_flag |= M_INIT_FLAG_REEST_RECV;
    }
    return ret;
}


static bool recv_announcement_signatures(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    if (self->fund_flag == 0) { //XXX: after `funding_locked`
        LOGE("fail: not open peer\n");
        return false;
    }

    if (self->cnl_anno.buf == NULL) {
        create_local_channel_announcement(self);
    }

    //channel_announcementを埋める
    btc_script_pubkey_order_t sort = sort_nodeid(self, NULL);
    ln_msg_channel_announcement_get_sigs(self->cnl_anno.buf, &p_sig_node, &p_sig_btc, false, sort);

    ln_msg_announcement_signatures_t msg;
    ret = ln_msg_announcement_signatures_read(&msg, pData, Len);
    if (!ret || (msg.short_channel_id == 0)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }
    memcpy(p_sig_node, msg.p_node_signature, LN_SZ_SIGNATURE);
    memcpy(p_sig_btc, msg.p_bitcoin_signature, LN_SZ_SIGNATURE);

    //channel-idチェック
    ret = chk_channelid(msg.p_channel_id, self->channel_id);
    if (!ret) {
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

    if ((self->anno_flag & LN_ANNO_FLAG_END) == 0) {
        self->short_channel_id = msg.short_channel_id;
        ret = ln_msg_channel_announcement_update_short_channel_id(self->cnl_anno.buf, self->short_channel_id);
        if (!ret) {
            LOGE("fail: update short_channel_id\n");
            return false;
        }
        ret = ln_msg_channel_announcement_sign(
            self->cnl_anno.buf, self->cnl_anno.len,
            self->priv_data.priv[MSG_FUNDIDX_FUNDING],
            sort);
        if (!ret) {
            LOGE("fail: sign\n");
            return false;
        }
        self->anno_flag |= M_ANNO_FLAG_RECV;
        proc_anno_sigs(self);
        M_DB_SELF_SAVE(self);
    } else if ((self->init_flag & M_INIT_ANNOSIG_SENT) == 0) {
        //BOLT07
        //  MUST respond to the first announcement_signatures message with its own announcement_signatures message.
        //
        // LN_ANNO_FLAG_ENDであっても再接続後の初回のみは送信する
        LOGD("respond announcement_signatures\n");
        utl_buf_t buf = UTL_BUF_INIT;
        bool ret = ln_announce_signs_create(self, &buf);
        if (ret) {
            callback(self, LN_CB_SEND_REQ, &buf);
        }
        self->init_flag |= M_INIT_ANNOSIG_SENT;
    }

    return ret;
}


/** channel_announcement受信
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pData           受信データ
 * @param[in]           Len             pData長
 * @retval      true    解析成功
 */
static bool recv_channel_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    ln_msg_channel_announcement_t msg;
    ln_cb_update_annodb_t db;

    bool ret = ln_msg_channel_announcement_read(&msg, pData, Len);
    if (!ret || (msg.short_channel_id == 0)) {
        LOGE("fail: do nothing\n");
        return true;
    }

    if (memcmp(gGenesisChainHash, msg.p_chain_hash, sizeof(gGenesisChainHash))) {
        LOGE("fail: chain_hash mismatch\n");
        return false;
    }

    //XXX: check sign
    //ln_msg_channel_announcement_verify

    utl_buf_t buf = UTL_BUF_INIT;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;

    //DB保存
    ret = ln_db_annocnl_save(&buf, msg.short_channel_id, ln_their_node_id(self), msg.p_node_id_1, msg.p_node_id_2);
    if (ret) {
        LOGD("save channel_announcement: %016" PRIx64 "\n", msg.short_channel_id);
        db.anno = LN_CB_UPDATE_ANNODB_CNL_ANNO;
    } else {
        db.anno = LN_CB_UPDATE_ANNODB_NONE;
    }
    callback(self, LN_CB_UPDATE_ANNODB, &db);

    return true;
}


/** channel_update受信
 *
 * @params[in,out]      self            channel情報
 * @param[in]           pData           受信データ
 * @param[in]           Len             pData長
 * @retval      true    解析成功
 */
static bool recv_channel_update(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    (void)self;

    bool ret;
    ln_msg_channel_update_t msg;
    memset(&msg, 0, sizeof(msg));

    ret = ln_msg_channel_update_read(&msg, pData, Len);
    if (ret) {
        //timestamp check
        uint64_t now = (uint64_t)utl_time_time();
        if (ln_db_annocnlupd_is_prune(now, msg.timestamp)) {
            //ret = false;
            char time[UTL_SZ_TIME_FMT_STR + 1];
            LOGD("older channel: not save(%016" PRIx64 "): %s\n", msg.short_channel_id, utl_time_fmt(time, msg.timestamp));
            return true;
        }
    } else {
        LOGE("fail: decode\n");
        return true;
    }

    if (memcmp(gGenesisChainHash, msg.p_chain_hash, sizeof(gGenesisChainHash))) {
        LOGE("fail: chain_hash mismatch\n");
        return true;
    }

    LOGV("recv channel_upd%d: %016" PRIx64 "\n", (int)(1 + (msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION)), msg.short_channel_id);

    //short_channel_id と dir から node_id を取得する
    uint8_t node_id[BTC_SZ_PUBKEY];

    ret = get_nodeid_from_annocnl(self, node_id, msg.short_channel_id, msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION);
    if (ret && btc_keys_check_pub(node_id)) {
        ret = ln_msg_channel_update_verify(node_id, pData, Len);
        if (!ret) {
            LOGE("fail: verify\n");
        }
    } else {
        //該当するchannel_announcementが見つからない
        //  BOLT#11
        //      r fieldでchannel_update相当のデータを送信したい場合に備えて保持する
        //      https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001220.html
        LOGD("through: not found channel_announcement in DB, but save\n");
        ret = true;
    }

    //BOLT07
    //  if the timestamp is unreasonably far in the future:
    //    MAY discard the channel_update.
    time_t now = utl_time_time();
    if (msg.timestamp > now + M_UPDCNL_TIMERANGE) {
        LOGD("through: timestamp is unreasonably far\n");
        ret = false;
    }

    ln_cb_update_annodb_t db;
    db.anno = LN_CB_UPDATE_ANNODB_NONE;
    if (ret) {
        //DB保存
        utl_buf_t buf = UTL_BUF_INIT;
        buf.buf = (CONST_CAST uint8_t *)pData;
        buf.len = Len;
        ret = ln_db_annocnlupd_save(&buf, &msg, ln_their_node_id(self));
        if (ret) {
            LOGD("save channel_update: %016" PRIx64 ":%d\n", msg.short_channel_id, msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION);
            db.anno = LN_CB_UPDATE_ANNODB_CNL_UPD;
        } else {
            LOGE("fail: db save\n");
        }
        ret = true;
    } else {
        //スルーするだけにとどめる
        ret = true;
    }
    callback(self, LN_CB_UPDATE_ANNODB, &db);

    return ret;
}


/** node_announcement受信
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pData           受信データ
 * @param[in]           Len             pData長
 * @retval      true    解析成功
 */
static bool recv_node_announcement(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    ln_msg_node_announcement_t msg;
    ret = ln_msg_node_announcement_read(&msg, pData, Len);
    if (!ret) {
        LOGE("fail: read message\n");
        return false;
    }
    ret = ln_msg_node_announcement_verify(&msg, pData, Len);
    if (!ret) {
        LOGD("fail: verify\n");
        return false;
    }

    LOGV("node_id:");
    DUMPV(msg.p_node_id, BTC_SZ_PUBKEY);

    utl_buf_t buf_ann = UTL_BUF_INIT;
    buf_ann.buf = (CONST_CAST uint8_t *)pData;
    buf_ann.len = Len;
    ret = ln_db_annonod_save(&buf_ann, &msg, ln_their_node_id(self));
    if (ret) {
        LOGD("save node_announcement: ");
        DUMPD(msg.p_node_id, BTC_SZ_PUBKEY);

        ln_cb_update_annodb_t db;
        db.anno = LN_CB_UPDATE_ANNODB_NODE_ANNO;
        callback(self, LN_CB_UPDATE_ANNODB, &db);
    }

    return true;
}


static void send_error(ln_self_t *self, const ln_msg_error_t *pError)
{
    utl_buf_t buf = UTL_BUF_INIT;
    ln_msg_error_write(&buf, pError);
    callback(self, LN_CB_SEND_REQ, &buf);
    utl_buf_free(&buf);
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
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    funding.b_send = bSendTx;
    if (bSendTx) {
        funding.p_tx_funding = &self->tx_funding;
    }
    funding.b_result = false;
    callback(self, LN_CB_FUNDINGTX_WAIT, &funding);

    if (funding.b_result) {
        self->status = LN_STATUS_ESTABLISH;

        M_DB_SECRET_SAVE(self);
        M_DB_SELF_SAVE(self);
    } else {
        //上位で停止される
    }

    M_DBG_COMMITNUM(self);
}


/********************************************************************
 * Transaction作成
 ********************************************************************/

static bool create_basetx(btc_tx_t *pTx,
                uint64_t Value, const utl_buf_t *pScriptPk, uint32_t LockTime,
                const uint8_t *pTxid, int Index, bool bRevoked)
{
    //vout
    btc_vout_t* vout = btc_tx_add_vout(pTx, Value);
    if (pScriptPk != NULL) {
        utl_buf_alloccopy(&vout->script, pScriptPk->buf, pScriptPk->len);
    }

    //vin
    btc_tx_add_vin(pTx, pTxid, Index);
    if (!bRevoked) {
        pTx->vin[0].sequence = LockTime;
    }

    return true;
}


/** funding_tx作成
 *
 * @param[in,out]       self
 */
static bool create_funding_tx(ln_self_t *self, bool bSign)
{
    btc_tx_free(&self->tx_funding);

    //vout 2-of-2
    btc_script_2of2_create_redeem_sorted(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING], self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);

    if (self->p_establish->p_fundin != NULL) {
        //output
        self->funding_local.txindex = M_FUNDING_INDEX;      //TODO: vout#0は2-of-2、vout#1はchangeにしている
        //vout#0:P2WSH - 2-of-2 : M_FUNDING_INDEX
        btc_sw_add_vout_p2wsh_wit(&self->tx_funding, self->funding_sat, &self->redeem_fund);

        //vout#1:P2WPKH - change(amountは後で代入)
        btc_tx_add_vout_spk(&self->tx_funding, (uint64_t)-1, &self->p_establish->p_fundin->change_spk);

        //input
        //vin#0
        btc_tx_add_vin(&self->tx_funding, self->p_establish->p_fundin->txid, self->p_establish->p_fundin->index);

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
        if (self->p_establish->p_fundin->amount >= self->funding_sat + fee) {
            self->tx_funding.vout[1].value = self->p_establish->p_fundin->amount - self->funding_sat - fee;
        } else {
            LOGE("fail: amount too short:\n");
            LOGD("    amount=%" PRIu64 "\n", self->p_establish->p_fundin->amount);
            LOGD("    funding_satoshis=%" PRIu64 "\n", self->funding_sat);
            LOGD("    fee=%" PRIu64 "\n", fee);
            return false;
        }
    } else {
        //SPVの場合、fee計算と署名はSPVに任せる(LN_CB_SIGN_FUNDINGTX_REQで吸収する)
        //その代わり、self->funding_local.txindexは固定値にならない。
        btc_sw_add_vout_p2wsh_wit(&self->tx_funding, self->funding_sat, &self->redeem_fund);
        //INPUTもダミーで入れておく
        btc_tx_add_vin(&self->tx_funding, self->funding_local.txid, 0);
    }

    //署名
    bool ret;
    if (bSign) {
        ln_cb_funding_sign_t sig;
        sig.p_tx =  &self->tx_funding;
        if (self->p_establish->p_fundin != NULL) {
            sig.amount = self->p_establish->p_fundin->amount;
        } else {
            sig.amount = 0;
        }
        callback(self, LN_CB_SIGN_FUNDINGTX_REQ, &sig);
        ret = sig.ret;
        if (ret) {
            btc_tx_txid(&self->tx_funding, self->funding_local.txid);
            LOGD("***** funding_tx *****\n");
            M_DBG_PRINT_TX(&self->tx_funding);

            //search funding vout
            ret = false;
            utl_buf_t two_of_two = UTL_BUF_INIT;
            btc_script_p2wsh_create_scriptsig(&two_of_two, &self->redeem_fund);
            for (uint32_t lp = 0; lp < self->tx_funding.vout_cnt; lp++) {
                if (utl_buf_cmp(&self->tx_funding.vout[lp].script, &two_of_two)) {
                    self->funding_local.txindex = (uint16_t)lp;
                    ret = true;
                    LOGD("funding_txindex=%d\n", self->funding_local.txindex);
                    break;
                }
            }
            utl_buf_free(&two_of_two);
        } else {
            LOGE("fail: signature\n");
            btc_tx_free(&self->tx_funding);
        }
    } else {
        //not sign
        ret = true;
    }

    return ret;
}


/** commitment_signed作成
 *
 *
 */
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

    bool ret;
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

    //署名
    uint8_t sighash[BTC_SZ_HASH256];
    ret = btc_sw_sighash_p2wsh_wit(pTx, sighash, 0, self->funding_sat, &self->redeem_fund);
    if (ret) {
        ret = ln_signer_p2wsh(&buf_sig, sighash, &self->priv_data, MSG_FUNDIDX_FUNDING);
    }
    if (!ret) {
        LOGE("fail: sign p2wsh\n");
        btc_tx_free(pTx);
        return false;
    }
    //送信用署名
    ln_misc_sigtrim(self->commit_remote.signature, buf_sig.buf);

    //署名追加
    if (bVerify) {
        utl_buf_t buf_sig_from_remote = UTL_BUF_INIT;

        ln_misc_sigexpand(&buf_sig_from_remote, self->commit_local.signature);
        ln_comtx_set_vin_p2wsh_2of2(pTx, 0, self->key_fund_sort,
                                &buf_sig,
                                &buf_sig_from_remote,
                                &self->redeem_fund);
        utl_buf_free(&buf_sig_from_remote);

        //
        // 署名verify
        //
        ret = btc_sw_verify_p2wsh_2of2(pTx, 0, sighash,
                        &self->tx_funding.vout[self->funding_local.txindex].script);
    } else {
        LOGD("no verify\n");
    }
    utl_buf_free(&buf_sig);

    LOGD("+++++++++++++ closing_tx[%016" PRIx64 "]\n", self->short_channel_id);
    M_DBG_PRINT_TX(pTx);

    LOGD("END ret=%d\n", ret);
    return ret;
}


// channel_announcement用データ(自分の枠)
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
    msg.p_chain_hash = gGenesisChainHash;
    msg.short_channel_id = self->short_channel_id;
    btc_script_pubkey_order_t sort = sort_nodeid(self, NULL);
    if (sort == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
        msg.p_node_id_1 = ln_node_getid();
        msg.p_node_id_2 = self->peer_node_id;
        msg.p_bitcoin_key_1 = self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING];
        msg.p_bitcoin_key_2 = self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING];
    } else {
        msg.p_node_id_1 = self->peer_node_id;
        msg.p_node_id_2 = ln_node_getid();
        msg.p_bitcoin_key_1 = self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING];
        msg.p_bitcoin_key_2 = self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING];
    }
    bool ret = ln_msg_channel_announcement_write(&self->cnl_anno, &msg);
    if (ret) {
        ret = ln_msg_channel_announcement_sign(
            self->cnl_anno.buf, self->cnl_anno.len,
            self->priv_data.priv[MSG_FUNDIDX_FUNDING],
            sort);
    }
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
                ln_self_t *self,
                ln_msg_channel_update_t *pUpd,
                utl_buf_t *pCnlUpd,
                uint32_t TimeStamp,
                uint8_t Flag)
{
    uint8_t dummy_signature[LN_SZ_SIGNATURE] = {0};
    memset(dummy_signature, 0xcc, sizeof(dummy_signature));
    pUpd->p_signature = dummy_signature;
    pUpd->p_chain_hash = gGenesisChainHash;
    pUpd->short_channel_id = self->short_channel_id;
    pUpd->timestamp = TimeStamp;
    pUpd->message_flags = 0;
    pUpd->channel_flags = Flag | ln_sort_to_dir(sort_nodeid(self, NULL));
    pUpd->cltv_expiry_delta = self->anno_prm.cltv_expiry_delta;
    pUpd->htlc_minimum_msat = self->anno_prm.htlc_minimum_msat;
    pUpd->fee_base_msat = self->anno_prm.fee_base_msat;
    pUpd->fee_proportional_millionths = self->anno_prm.fee_prop_millionths;
    pUpd->htlc_maximum_msat = 0;
    if (!ln_msg_channel_update_write(pCnlUpd, pUpd)) return false;
    return ln_msg_channel_update_sign(pCnlUpd->buf, pCnlUpd->len);
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
                    ln_misc_push16be(&push_htlc, LNONION_CHAN_DISABLE);
                    ln_misc_push16be(&push_htlc, (uint16_t)buf.len);
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
                ln_misc_push16be(&push_htlc, LNONION_TMP_CHAN_FAIL);
                ln_misc_push16be(&push_htlc, (uint16_t)buf.len);
                utl_push_data(&push_htlc, buf.buf, buf.len);
            } else {
                //B5. if an otherwise unspecified, permanent error occurs during forwarding to its receiving peer (e.g. channel recently closed):
                //      permanent_channel_failure
                LOGE("fail: permanent_channel_failure\n");

                utl_push_t push_htlc;
                utl_push_init(&push_htlc, pReason, sizeof(uint16_t));
                ln_misc_push16be(&push_htlc, LNONION_PERM_CHAN_FAIL);
            }
        }
    }
    return ret;
}


/** [BOLT#2]recv_update_add_htlc()のチェック項目
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


/** [BOLT#4]recv_update_add_htlc()のチェック(final node)
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
        ln_misc_push16be(pPushReason, LNONION_UNKNOWN_PAY_HASH);
        //no data

        return false;
    }

    //C2. if the amount paid is less than the amount expected:
    //      incorrect_payment_amount
    if (pAddHtlc->amount_msat < preimg.amount_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "incorrect_payment_amount(final) : %" PRIu64 " < %" PRIu64, pDataOut->amt_to_forward, preimg.amount_msat);
        ret = false;
        ln_misc_push16be(pPushReason, LNONION_INCORR_PAY_AMT);
        //no data

        return false;
    }

    //C4. if the amount paid is more than twice the amount expected:
    //      incorrect_payment_amount
    if (preimg.amount_msat * 2 < pAddHtlc->amount_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "large amount_msat : %" PRIu64 " < %" PRIu64, preimg.amount_msat * 2, pDataOut->amt_to_forward);
        ret = false;
        ln_misc_push16be(pPushReason, LNONION_INCORR_PAY_AMT);
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
        ln_misc_push16be(pPushReason, LNONION_FINAL_EXPIRY_TOO_SOON);

        return false;
    }

    //C6. if the outgoing_cltv_value does NOT correspond with the cltv_expiry from the final node's HTLC:
    //      final_incorrect_cltv_expiry
    if (pDataOut->outgoing_cltv_value != pAddHtlc->cltv_expiry) {
        LOGD("%" PRIu32 " --- %" PRIu32 "\n", pDataOut->outgoing_cltv_value, ln_cltv_expily_delta(self));
        M_SET_ERR(self, LNERR_INV_VALUE, "incorrect cltv expiry(final)");
        ln_misc_push16be(pPushReason, LNONION_FINAL_INCORR_CLTV_EXP);
        //[4:cltv_expiry]
        ln_misc_push32be(pPushReason, pDataOut->outgoing_cltv_value);

        return false;
    }

    //C7. if the amt_to_forward is greater than the incoming_htlc_amt from the final node's HTLC:
    //      final_incorrect_htlc_amount
    if (pDataOut->amt_to_forward > pAddHtlc->amount_msat) {
        LOGD("%" PRIu64 " --- %" PRIu64 "\n", pDataOut->amt_to_forward, pAddHtlc->amount_msat);
        M_SET_ERR(self, LNERR_INV_VALUE, "incorrect_payment_amount(final)");
        ln_misc_push16be(pPushReason, LNONION_FINAL_INCORR_HTLC_AMT);
        //[4:incoming_htlc_amt]
        ln_misc_push32be(pPushReason, pAddHtlc->amount_msat);

        return false;
    }

    return true;
}


/** [BOLT#4]recv_update_add_htlc()のチェック(forward node)
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
        callback(self, LN_CB_ADD_HTLC_RECV_PREV, &recv_prev);
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
        ln_misc_push16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        //no data

        return false;
    }

    //channel_update読み込み
    ln_msg_channel_update_t cnlupd;
    utl_buf_t cnlupd_buf = UTL_BUF_INIT;
    uint8_t peer_id[BTC_SZ_PUBKEY];
    bool ret = ln_node_search_nodeid(peer_id, pDataOut->short_channel_id);
    if (ret) {
        uint8_t dir = ln_sort_to_dir(sort_nodeid(self, peer_id));
        ret = ln_db_annocnlupd_load(&cnlupd_buf, NULL, pDataOut->short_channel_id, dir);
        if (!ret) {
            LOGE("fail: ln_db_annocnlupd_load: %016" PRIx64 ", dir=%d\n", pDataOut->short_channel_id, dir);
        }
    } else {
        LOGE("fail: ln_node_search_nodeid\n");
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
        ln_misc_push16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        //no data

        return false;
    }
    LOGD("short_channel_id=%016" PRIx64 "\n", pDataOut->short_channel_id);

    //B8. if the HTLC amount is less than the currently specified minimum amount:
    //      amount_below_minimum
    //      (report the amount of the incoming HTLC and the current channel setting for the outgoing channel.)
    if (pDataOut->amt_to_forward < recv_prev.p_next_self->commit_remote.htlc_minimum_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "lower than htlc_minimum_msat : %" PRIu64 " < %" PRIu64, pDataOut->amt_to_forward, recv_prev.p_next_self->commit_remote.htlc_minimum_msat);
        ln_misc_push16be(pPushReason, LNONION_AMT_BELOW_MIN);
        //[8:htlc_msat]
        //[2:len]
        ln_misc_push16be(pPushReason, cnlupd_buf.len);
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
        ln_misc_push16be(pPushReason, LNONION_FEE_INSUFFICIENT);
        //[8:htlc_msat]
        //[2:len]
        ln_misc_push16be(pPushReason, cnlupd_buf.len);
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
        ln_misc_push16be(pPushReason, LNONION_INCORR_CLTV_EXPIRY);
        //[4:cltv_expiry]
        //[2:len]
        ln_misc_push16be(pPushReason, cnlupd_buf.len);
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
        ln_misc_push16be(pPushReason, LNONION_EXPIRY_TOO_SOON);
        //[2:len]
        ln_misc_push16be(pPushReason, cnlupd_buf.len);
        //[len:channel_update]
        utl_push_data(pPushReason, cnlupd_buf.buf, cnlupd_buf.len);

        return false;
    }

    //B12. if the cltv_expiry is unreasonably far in the future:
    //      expiry_too_far
    if (pAddHtlc->cltv_expiry > (uint32_t)Height + cnlupd.cltv_expiry_delta + M_HYSTE_CLTV_EXPIRY_FAR) {
        LOGD("%" PRIu32 " > %" PRId32 "\n", pAddHtlc->cltv_expiry, Height + cnlupd.cltv_expiry_delta + M_HYSTE_CLTV_EXPIRY_FAR);
        M_SET_ERR(self, LNERR_INV_VALUE, "expiry too far : %" PRIu32, ln_cltv_expily_delta(recv_prev.p_next_self));
        ln_misc_push16be(pPushReason, LNONION_EXPIRY_TOO_FAR);

        return false;
    }

    return true;
}


static bool check_recv_add_htlc_bolt4_common(ln_self_t *self, utl_push_t *pPushReason)
{
    (void)pPushReason;

    //shutdown
    if (self->shutdown_flag & LN_SHDN_FLAG_SEND) {
        M_SET_ERR(self, LNERR_INV_STATE, "already shutdown sent");
        ln_misc_push16be(pPushReason, LNONION_PERM_CHAN_FAIL);
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


/** peerから受信したper_commitment_secret保存
 *
 * self->peer_storage_indexに保存後、self->peer_storage_indexをデクリメントする。
 *
 * @param[in,out]   self            チャネル情報
 * @param[in]       p_prev_secret   受信したper_commitment_secret
 * @retval  true    成功
 * @note
 *      - indexを進める
 */
static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret)
{
    //LOGD("I=%016" PRIx64 "\n", self->peer_storage_index);
    //DUMPD(p_prev_secret, BTC_SZ_PRIVKEY);
    uint8_t pub[BTC_SZ_PUBKEY];
    btc_keys_priv2pub(pub, p_prev_secret);
    //DUMPD(pub, BTC_SZ_PUBKEY);
    bool ret = ln_derkey_storage_insert_secret(&self->peer_storage, p_prev_secret, self->peer_storage_index);
    if (ret) {
        self->peer_storage_index--;
        //M_DB_SELF_SAVE(self);    //保存は呼び出し元で行う
        LOGD("I=%016" PRIx64 " --> %016" PRIx64 "\n", (uint64_t)(self->peer_storage_index + 1), self->peer_storage_index);

        //for (uint64_t idx = LN_SECINDEX_INIT; idx > self->peer_storage_index; idx--) {
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


static void proc_anno_sigs(ln_self_t *self)
{
    if ( (self->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) &&
         (self->short_channel_id != 0) ) {
        //announcement_signatures送受信済み
        LOGD("announcement_signatures sent and recv: %016" PRIx64 "\n", self->short_channel_id);

        //channel_announcement
        bool ret1 = ln_db_annocnl_save(&self->cnl_anno, self->short_channel_id, NULL,
                                ln_their_node_id(self), ln_node_getid());
        if (ret1) {
            utl_buf_free(&self->cnl_anno);
        } else {
            LOGE("fail\n");
        }

        //channel_update
        utl_buf_t buf_upd = UTL_BUF_INIT;
        uint32_t now = (uint32_t)utl_time_time();
        ln_msg_channel_update_t upd;
        bool ret2 = create_channel_update(self, &upd, &buf_upd, now, 0);
        if (ret2) {
            ln_db_annocnlupd_save(&buf_upd, &upd, NULL);
        } else {
            LOGE("fail\n");
        }
        utl_buf_free(&buf_upd);

        self->anno_flag |= LN_ANNO_FLAG_END;
    } else {
        LOGD("yet: anno_flag=%02x, short_channel_id=%016" PRIx64 "\n", self->anno_flag, self->short_channel_id);
    }
}


static bool chk_peer_node(ln_self_t *self)
{
    return self->peer_node_id[0];       //先頭が0の場合は不正
}


//channel_announcementからのnode_id取得
static bool get_nodeid_from_annocnl(ln_self_t *self, uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir)
{
    bool ret;

    pNodeId[0] = 0x00;

    utl_buf_t buf_cnl_anno = UTL_BUF_INIT;
    ret = ln_db_annocnl_load(&buf_cnl_anno, short_channel_id);
    if (ret) {
        ln_msg_channel_announcement_t msg;
        ret = ln_msg_channel_announcement_read(&msg, buf_cnl_anno.buf, buf_cnl_anno.len);
        if (ret) {
            memcpy(pNodeId, Dir ? msg.p_node_id_2 : msg.p_node_id_1, BTC_SZ_PUBKEY);
        } else {
            LOGE("fail\n");
        }
    } else {
        if (short_channel_id == self->short_channel_id) {
            // DBには無いが、このchannelの情報
            btc_script_pubkey_order_t mysort = sort_nodeid(self, NULL);
            if ( ((mysort == BTC_SCRYPT_PUBKEY_ORDER_ASC) && (Dir == 0)) ||
                 ((mysort == BTC_SCRYPT_PUBKEY_ORDER_OTHER) && (Dir == 1)) ) {
                //自ノード
                LOGD("this channel: my node\n");
                memcpy(pNodeId, ln_node_getid(), BTC_SZ_PUBKEY);
            } else {
                //相手ノード
                LOGD("this channel: peer node\n");
                memcpy(pNodeId, self->peer_node_id, BTC_SZ_PUBKEY);
            }
            ret = true;
        }
    }
    utl_buf_free(&buf_cnl_anno);

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


//clear HTLC data
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


static bool chk_channelid(const uint8_t *recv_id, const uint8_t *mine_id)
{
    bool ret = (memcmp(recv_id, mine_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        LOGD("channel-id mismatch\n");
        LOGD("mine:");
        DUMPD(mine_id, LN_SZ_CHANNEL_ID);
        LOGD("get :");
        DUMPD(recv_id, LN_SZ_CHANNEL_ID);
        return false;
    }

    return ret;
}


/** ln_close_force_tのメモリ確保
 *
 *
 */
static void close_alloc(ln_close_force_t *pClose, int Num)
{
    pClose->num = Num;
    pClose->p_tx = (btc_tx_t *)UTL_DBG_MALLOC(sizeof(btc_tx_t) * pClose->num);
    pClose->p_htlc_idx = (uint8_t *)UTL_DBG_MALLOC(sizeof(uint8_t) * pClose->num);
    for (int lp = 0; lp < pClose->num; lp++) {
        btc_tx_init(&pClose->p_tx[lp]);
        pClose->p_htlc_idx[lp] = LN_CLOSE_IDX_NONE;
    }
    utl_buf_init(&pClose->tx_buf);
    LOGD("TX num: %d\n", pClose->num);
}


static void disable_channel_update(ln_self_t *self)
{
    utl_buf_t buf_upd = UTL_BUF_INIT;
    uint32_t now = (uint32_t)utl_time_time();
    ln_msg_channel_update_t upd;
    bool ret = create_channel_update(self, &upd, &buf_upd, now, LN_CNLUPD_CHFLAGS_DISABLE);
    if (ret) {
        ln_db_annocnlupd_save(&buf_upd, &upd, ln_their_node_id(self));
        utl_buf_free(&buf_upd);
    }
}


/** establish用メモリ解放
 *
 * @param[in]   bEndEstablish   true: funding用メモリ解放
 */
static void free_establish(ln_self_t *self, bool bEndEstablish)
{
    if (self->p_establish != NULL) {
        if (self->p_establish->p_fundin != NULL) {
            LOGD("self->p_establish->p_fundin=%p\n", self->p_establish->p_fundin);
            UTL_DBG_FREE(self->p_establish->p_fundin);  //UTL_DBG_MALLOC: ln_open_channel_create()
            LOGD("free\n");
        }
        if (bEndEstablish) {
            UTL_DBG_FREE(self->p_establish);        //UTL_DBG_MALLOC: ln_establish_alloc()
            LOGD("free\n");
        }
    }
    self->fund_flag = (ln_fundflag_t)((self->fund_flag & ~LN_FUNDFLAG_FUNDING) | LN_FUNDFLAG_OPENED);
}


/**
 *
 * @param[in]   self
 * @param[in]   pNodeId
 * @retval      BTC_SCRYPT_PUBKEY_ORDER_ASC     自ノードが先
 * @retval      BTC_SCRYPT_PUBKEY_ORDER_OTHER   相手ノードが先
 */
static btc_script_pubkey_order_t sort_nodeid(const ln_self_t *self, const uint8_t *pNodeId)
{
    btc_script_pubkey_order_t sort;

    int lp;
    const uint8_t *p_nodeid = ln_node_getid();
    const uint8_t *p_peerid;
    if (pNodeId == NULL) {
        p_peerid = self->peer_node_id;
    } else {
        p_peerid = pNodeId;
    }
    for (lp = 0; lp < BTC_SZ_PUBKEY; lp++) {
        if (p_nodeid[lp] != p_peerid[lp]) {
            break;
        }
    }
    if ((lp < BTC_SZ_PUBKEY) && (p_nodeid[lp] < p_peerid[lp])) {
        LOGD("my node= first\n");
        sort = BTC_SCRYPT_PUBKEY_ORDER_ASC;
    } else {
        LOGD("my node= second\n");
        sort = BTC_SCRYPT_PUBKEY_ORDER_OTHER;
    }

    return sort;
}


/** btc_script_pubkey_order_t --> Direction変換
 *
 */
static inline uint8_t ln_sort_to_dir(btc_script_pubkey_order_t Sort)
{
    return (uint8_t)Sort;
}


/** transactionからcommitment numberを復元
 *
 */
static uint64_t calc_commit_num(const ln_self_t *self, const btc_tx_t *pTx)
{
    uint64_t commit_num = ((uint64_t)(pTx->vin[0].sequence & 0xffffff)) << 24;
    commit_num |= (uint64_t)(pTx->locktime & 0xffffff);
    commit_num ^= self->obscured;
    LOGD("commit_num=%" PRIu64 "\n", commit_num);
    return commit_num;
}


static inline void callback(ln_self_t *self, ln_cb_t Req, void *pParam)
{
    if (self->p_callback != NULL) {
        (*self->p_callback)(self, Req, pParam);
    } else {
        LOGE("fail: not callback(%d)\n", (int)Req);
    }
}


static void set_error(ln_self_t *self, int Err, const char *pFormat, ...)
{
    va_list ap;

    self->err = Err;

    va_start(ap, pFormat);
    vsnprintf(self->err_msg, LN_SZ_ERRMSG, pFormat, ap);
    va_end(ap);
}


#ifdef M_DBG_COMMITHTLC
/** commitment_number debug output
 *
 */
static void dbg_commitnum(const ln_self_t *self)
{
    LOGD("------------------------------------------\n");
    LOGD("storage_index      = %016" PRIx64 "\n", self->priv_data.storage_index);
    LOGD("peer_storage_index = %016" PRIx64 "\n", self->peer_storage_index);
    LOGD("------------------------------------------\n");
    LOGD("local.commit_num  = %" PRIu64 "\n", self->commit_local.commit_num);
    LOGD("remote.commit_num = %" PRIu64 "\n", self->commit_remote.commit_num);
    LOGD("local.revoke_num  = %" PRId64 "\n", (int64_t)self->commit_local.revoke_num);
    LOGD("remote.revoke_num = %" PRId64 "\n", (int64_t)self->commit_remote.revoke_num);
    LOGD("------------------------------------------\n");
    LOGD("htlc_id_num: %" PRIu64 "\n", self->htlc_id_num);
    LOGD("------------------------------------------\n");
}


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
