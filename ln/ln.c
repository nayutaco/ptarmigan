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
 *  @brief  Lightningライブラリ
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "utl_misc.h"
#include "utl_buf.h"
#include "utl_dbg.h"

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
#include "ln_derkey.h"
#include "ln_signer.h"
#include "ln_local.h"

#define M_DBG_VERBOSE


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SZ_TO_LOCAL_TX(len)                   (213+len)   ///< to_local transaction長[byte]
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

#define M_SZ_TO_REMOTE_TX(len)                  (169+len)   ///< to_remote transaction長[byte]
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

#define M_SZ_TO_LOCAL_PENALTY                   (324)
#define M_SZ_OFFERED_PENALTY                    (407)
#define M_SZ_RECEIVED_PENALTY                   (413)


#define M_HTLCCHG_NONE                          (0)
#define M_HTLCCHG_FF_SEND                       (1)
#define M_HTLCCHG_FF_RECV                       (2)

// ln_self_t.init_flag
#define M_INIT_FLAG_SEND                    (0x01)
#define M_INIT_FLAG_RECV                    (0x02)
#define M_INIT_FLAG_EXCHNAGED(flag)         (((flag) & (M_INIT_FLAG_SEND | M_INIT_FLAG_RECV)) == (M_INIT_FLAG_SEND | M_INIT_FLAG_RECV))

// ln_self_t.anno_flag
#define M_ANNO_FLAG_SEND                    (0x01)          ///< announcement_signatures送信済み
#define M_ANNO_FLAG_RECV                    (0x02)          ///< announcement_signatures受信済み
//#define LN_ANNO_FLAG_END

// ln_self_t.shutdown_flag
#define M_SHDN_FLAG_SEND                    (0x01)          ///< shutdown送信済み
#define M_SHDN_FLAG_RECV                    (0x02)          ///< shutdown受信済み
#define M_SHDN_FLAG_EXCHANGED(flag)         (((flag) & (M_SHDN_FLAG_SEND | M_SHDN_FLAG_RECV)) == (M_SHDN_FLAG_SEND | M_SHDN_FLAG_RECV))

// comrev_state()
#define M_STAT_STABLE                       (0x00)
#define M_STAT_SENDER                       (0x40)
#define M_STAT_RECEIVER                     (0x80)
#define M_STAT_MASK_DIR(f)                  ((f) & 0xf0)
#define M_STAT_MASK_NUM(f)                  ((f) & 0x0f)
#define M_STAT_SEND1                        ((uint8_t)(M_STAT_SENDER | 1))
#define M_STAT_SEND2                        ((uint8_t)(M_STAT_SENDER | 2))
#define M_STAT_SEND3                        ((uint8_t)(M_STAT_SENDER | 3))
#define M_STAT_RECV1                        ((uint8_t)(M_STAT_RECEIVER | 1))
#define M_STAT_RECV2                        ((uint8_t)(M_STAT_RECEIVER | 2))
#define M_STAT_RECV3                        ((uint8_t)(M_STAT_RECEIVER | 3))

#define M_PONG_MISSING                      (50)            ///< pongが返ってこないエラー上限

#define M_FUNDING_INDEX                     (0)             ///< funding_txのvout

#define M_HYSTE_CLTV_EXPIRY_MIN             (7)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_SOON            (1)             ///< BOLT4 check:cltv_expiryのhysteresis
#define M_HYSTE_CLTV_EXPIRY_FAR             (144 * 15)      ///< BOLT4 check:cltv_expiryのhysteresis(15日)

// #define M_FEERATE_CHK_MIN_OK(our,their)     ( 0.5 * (our) < 1.0 * (their))  ///< feerate_per_kwのmin判定
// #define M_FEERATE_CHK_MAX_OK(our,their)     (10.0 * (our) > 1.0 * (their))  ///< feerate_per_kwのmax判定
#define M_FEERATE_CHK_MIN_OK(our,their)     (true)  ///< feerate_per_kwのmin判定(ALL OK)
#define M_FEERATE_CHK_MAX_OK(our,their)     (true)  ///< feerate_per_kwのmax判定(ALL OK)

#if !defined(M_DBG_VERBOSE) && !defined(PTARM_USE_PRINTFUNC)
#define M_DBG_PRINT_TX(tx)      //NONE
//#define M_DBG_PRINT_TX(tx)    LOGD(""); btc_print_tx(tx)
#define M_DBG_PRINT_TX2(tx)     //NONE
#else
#define M_DBG_PRINT_TX(tx)      LOGD("\n"); btc_print_tx(tx)
#define M_DBG_PRINT_TX2(tx)     LOGD("\n"); btc_print_tx(tx)
#endif  //M_DBG_VERBOSE

#define M_DB_SELF_SAVE(self)    { bool ret = ln_db_self_save(self); LOGD("ln_db_self_save()=%d\n", ret); }
#define M_DB_SECRET_SAVE(self)  { bool ret = ln_db_secret_save(self); LOGD("ln_db_secret_save()=%d\n", ret); }

#define M_SET_ERR(self,err,fmt,...)     {\
        set_error(self,err,fmt,##__VA_ARGS__);\
        LOGD("[%s:%d]fail: %s\n", __func__, (int)__LINE__, self->err_msg);\
    }
#define M_SEND_ERR(self,err,fmt,...)    {\
        set_error(self,err,fmt,##__VA_ARGS__);\
        \
        ln_error_t err;\
        err.channel_id = self->channel_id;\
        err.p_data = self->err_msg;\
        err.len = strlen(err.p_data);\
        send_error(self, &err);\
        LOGD("[%s:%d]fail: %s\n", __func__, (int)__LINE__, self->err_msg);\
    }

#define M_DBG_COMMITHTLC
#ifdef M_DBG_COMMITHTLC
#define M_DBG_COMMITNUM(self) { LOGD("----- debug commit_num -----\n"); dbg_commitnum(self); }
#else
#define M_DBG_COMMITNUM(self)   //none
#endif


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef bool (*pRecvFunc_t)(ln_self_t *self,const uint8_t *pData, uint16_t Len);


/** #search_preimage()用
 *
 */
typedef struct {
    uint8_t         *image;             ///< [out]preimage
    const uint8_t   *hash;              ///< [in]payment_hash
    bool            b_closing;          ///< true:一致したexpiryをUINT32_MAXに変更する
} preimg_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

static void channel_clear(ln_self_t *self);
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
static void send_error(ln_self_t *self, const ln_error_t *pError);
static void start_funding_wait(ln_self_t *self, bool bSendTx);
static bool set_vin_p2wsh_2of2(btc_tx_t *pTx, int Index, btc_keys_sort_t Sort,
                    const utl_buf_t *pSig1,
                    const utl_buf_t *pSig2,
                    const utl_buf_t *pWit2of2);
static bool create_funding_tx(ln_self_t *self, bool bSign);
static bool create_to_local(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat);
static bool create_to_local_sign(ln_self_t *self,
                    btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufSig);
static bool create_to_local_spent(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo,
                    uint32_t to_self_delay);
static bool create_to_local_close(ln_self_t *self,
                    btc_tx_t *pTxHtlcs,
                    btc_tx_t *pTxHtlc,
                    utl_push_t *pPush,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const btc_util_keys_t *pHtlcKey,
                    uint8_t htlc_num,
                    int vout_idx,
                    const uint8_t *pPayHash,
                    const uint8_t *pSig,
                    uint32_t to_self_delay);
static bool create_to_remote(ln_self_t *self,
                    ln_close_force_t *pClose,
                    uint8_t **pp_htlc_sigs,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat);
static bool create_to_remote_spent(ln_self_t *self,
                    ln_close_force_t *pClose,
                    uint8_t *p_htlc_sigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo);
static bool create_to_remote_htlcsign(ln_self_t *self,
                    btc_tx_t *pTxHtlcs,
                    uint8_t *p_htlc_sigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const btc_util_keys_t *pHtlcKey,
                    const utl_buf_t *pBufRemoteSig,
                    uint64_t fee,
                    uint8_t htlc_num,
                    int vout_idx,
                    const uint8_t *pPayHash,
                    bool bClosing);
static bool create_commit_signed(ln_self_t *self, utl_buf_t *pCommSig);
static bool create_closing_tx(ln_self_t *self, btc_tx_t *pTx, uint64_t FeeSat, bool bVerify);
static bool create_local_channel_announcement(ln_self_t *self);
static bool create_channel_update(
                ln_self_t *self,
                ln_cnl_update_t *pUpd,
                utl_buf_t *pCnlUpd,
                uint32_t TimeStamp,
                uint8_t Flag);
static bool check_create_add_htlc(
                ln_self_t *self,
                int *pIdx,
                utl_buf_t *pReason,
                uint64_t amount_msat,
                uint32_t cltv_value);
static bool check_recv_add_htlc_bolt2(ln_self_t *self, const ln_update_add_htlc_t *p_htlc);
static bool check_recv_add_htlc_bolt4_final(ln_self_t *self,
                    ln_hop_dataout_t *pDataOut,
                    utl_push_t *pPushReason,
                    ln_update_add_htlc_t *pAddHtlc,
                    uint8_t *pPreImage,
                    int32_t Height);
static bool check_recv_add_htlc_bolt4_forward(ln_self_t *self,
                    ln_hop_dataout_t *pDataOut,
                    utl_push_t *pPushReason,
                    ln_update_add_htlc_t *pAddHtlc,
                    int32_t Height);
static bool check_recv_add_htlc_bolt4_common(utl_push_t *pPushReason);
static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret);

static void proc_anno_sigs(ln_self_t *self);
static void proc_rev_and_ack(ln_self_t *self);

static bool chk_peer_node(ln_self_t *self);
static bool get_nodeid_from_annocnl(ln_self_t *self, uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir);;
static void clear_htlc(ln_self_t *self, ln_update_add_htlc_t *p_htlc);
static bool search_preimage(uint8_t *pPreImage, const uint8_t *pPayHash, bool bClosing);
static bool search_preimage_func(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);
static bool chk_channelid(const uint8_t *recv_id, const uint8_t *mine_id);
static void close_alloc(ln_close_force_t *pClose, int Num);
static void free_establish(ln_self_t *self, bool bEndEstablish);
static btc_keys_sort_t sort_nodeid(const ln_self_t *self, const uint8_t *pNodeId);
static inline uint8_t ln_sort_to_dir(btc_keys_sort_t Sort);
static void set_error(ln_self_t *self, int Err, const char *pFormat, ...);
static int commitment_state(const ln_self_t *self);
static int revocation_state(const ln_self_t *self);
static uint8_t comrev_state(const ln_self_t *self);
#ifdef M_DBG_COMMITNUM
static void dbg_commitnum(const ln_self_t *self);
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
uint8_t HIDDEN gGenesisChainHash[LN_SZ_HASH];

/// init.localfeaturesデフォルト値
static uint8_t mInitLocalFeatures[1];

static unsigned long mDebug;


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


void ln_set_status(ln_self_t *self, ln_status_t Status)
{
    LOGD("status: %02x --> %02x\n", (uint8_t)self->status, Status);
    self->status = Status;
    M_DB_SELF_SAVE(self);
}


ln_status_t ln_get_status(const ln_self_t *self)
{
    return self->status;
}


void ln_set_genesishash(const uint8_t *pHash)
{
    memcpy(gGenesisChainHash, pHash, LN_SZ_HASH);
    //LOGD("genesis=");
    //DUMPD(gGenesisChainHash, LN_SZ_HASH);
}


const uint8_t* ln_get_genesishash(void)
{
    return gGenesisChainHash;
}


void ln_set_peer_nodeid(ln_self_t *self, const uint8_t *pNodeId)
{
    memcpy(self->peer_node_id, pNodeId, BTC_SZ_PUBKEY);
}


void ln_set_init_localfeatures(uint8_t lf)
{
    LOGD("localfeatures=0x%02x\n", lf);
    mInitLocalFeatures[0] = lf;
}


bool ln_set_establish(ln_self_t *self, const ln_establish_prm_t *pEstPrm)
{
    LOGD("BEGIN\n");

    if (self->p_establish != 0) {
        LOGD("already set\n");
        return true;
    }

    self->p_establish = (ln_establish_t *)UTL_DBG_MALLOC(sizeof(ln_establish_t));   //UTL_DBG_FREE:proc_established()

    if (pEstPrm != NULL) {
#ifndef USE_SPV
        self->p_establish->p_fundin = NULL;       //open_channel送信側が設定する
#endif
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


void ln_free_establish(ln_self_t *self)
{
    free_establish(self, true);
}


bool ln_set_short_channel_id_param(ln_self_t *self, uint32_t Height, uint32_t Index, uint32_t FundingIndex, const uint8_t *pMinedHash)
{
    uint64_t short_channel_id = ln_misc_calc_short_channel_id(Height, Index, FundingIndex);
    if (self->short_channel_id == 0) {
        self->short_channel_id = short_channel_id;
#ifndef USE_SPV
        (void)pMinedHash;
#else
        memcpy(self->funding_bhash, pMinedHash, BTC_SZ_SHA256);
        self->funding_bheight = Height;
#endif
        M_DB_SELF_SAVE(self);
    }

    return (short_channel_id != 0) && (self->short_channel_id == short_channel_id);
}


void ln_get_short_channel_id_param(uint32_t *pHeight, uint32_t *pIndex, uint32_t *pVIndex, uint64_t ShortChannelId)
{
    ln_misc_get_short_channel_id_param(pHeight, pIndex, pVIndex, ShortChannelId);
}


#if 0
bool ln_set_shutdown_vout_pubkey(ln_self_t *self, const uint8_t *pShutdownPubkey, int ShutdownPref)
{
    bool ret = false;

    if ((ShutdownPref == BTC_PREF_P2PKH) || (ShutdownPref == BTC_PREF_NATIVE)) {
        const utl_buf_t pub = { (CONST_CAST uint8_t *)pShutdownPubkey, BTC_SZ_PUBKEY };
        utl_buf_t spk;

        ln_create_scriptpkh(&spk, &pub, ShutdownPref);
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


void ln_set_shutdown_vout_addr(ln_self_t *self, const utl_buf_t *pScriptPk)
{
    LOGD("set close addr: ");
    DUMPD(pScriptPk->buf, pScriptPk->len);
    utl_buf_free(&self->shutdown_scriptpk_local);
    utl_buf_alloccopy(&self->shutdown_scriptpk_local, pScriptPk->buf, pScriptPk->len);
}


bool ln_handshake_start(ln_self_t *self, utl_buf_t *pBuf, const uint8_t *pNodeId)
{
    bool ret;

    ret = ln_enc_auth_handshake_init(self, pNodeId);
    if (ret && (pNodeId != NULL)) {
        ret = ln_enc_auth_handshake_start(self, pBuf, pNodeId);
    }

    return ret;
}


bool ln_handshake_recv(ln_self_t *self, bool *pCont, utl_buf_t *pBuf)
{
    bool ret;

    ret = ln_enc_auth_handshake_recv(self, pBuf);
    if (ret) {
        //次も受信を続けるかどうか
        *pCont = ln_enc_auth_handshake_state(self);
    }

    return ret;
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


/*
 * BOLTのメッセージはデータ長が載っていない。
 * socket通信はwrite()した回数とrecv()の数は一致せず、ストリームになっているため、
 * 今回のように「受信したパケットを全部解析する」というやり方は合わない。
 * そう思っていたが、Noise Protocolによって全パケット受信してから解析するため、問題ない。
 */
bool ln_recv(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret = false;
    uint16_t type = ln_misc_get16be(pData);

    //LOGD("short_channel_id= %016" PRIx64 "\n", self->short_channel_id);
    if ((type != MSGTYPE_INIT) && (!M_INIT_FLAG_EXCHNAGED(self->init_flag))) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init received : %04x", type);
        return false;
    }
    if ( (type != MSGTYPE_CLOSING_SIGNED) &&
         !MSGTYPE_IS_ANNOUNCE(type) && !MSGTYPE_IS_PINGPONG(type) &&
         (type != MSGTYPE_ERROR) &&
         M_SHDN_FLAG_EXCHANGED(self->shutdown_flag) ) {
        M_SET_ERR(self, LNERR_INV_STATE, "not closing_signed received : %04x", type);
        ret = type & 1;     //ok to be odd rule --> 奇数ならエラーにしない
        goto LABEL_EXIT;
    }

    size_t lp;
    for (lp = 0; lp < ARRAY_SIZE(RECV_FUNC); lp++) {
        if (type == RECV_FUNC[lp].type) {
            //LOGD("type=%04x: Len=%d\n", type, Len);
            ret = (*RECV_FUNC[lp].func)(self, pData, Len);
            if (!ret) {
                LOGD("fail: type=%04x\n", type);
            }
            break;
        }
    }
    if (lp == ARRAY_SIZE(RECV_FUNC)) {
        LOGD("not match: type=%04x\n", type);
        ret = type & 1;     //ok to be odd rule --> 奇数ならエラーにしない
    }

LABEL_EXIT:
    return ret;
}


//init作成
bool ln_create_init(ln_self_t *self, utl_buf_t *pInit, bool bHaveCnl)
{
    (void)bHaveCnl;

    if (self->init_flag & M_INIT_FLAG_SEND) {
        M_SEND_ERR(self, LNERR_INV_STATE, "init already sent");
        return false;
    }

    ln_init_t msg;

    utl_buf_init(&msg.globalfeatures);
    utl_buf_alloccopy(&msg.localfeatures, mInitLocalFeatures, sizeof(mInitLocalFeatures));
    bool ret = ln_msg_init_create(pInit, &msg);
    if (ret) {
        self->init_flag |= M_INIT_FLAG_SEND;
    }
    utl_buf_free(&msg.localfeatures);
    utl_buf_free(&msg.globalfeatures);

    //HTLC確定フラグが立っていないHTLCがあれば、消す
    M_DBG_COMMITNUM(self);
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat != 0) {
            LOGD("[%d]HTLC(num=%d): id=%" PRIu64 ", flag=%02x, amount_msat=%" PRIu64 "\n", idx, self->htlc_num, self->cnl_add_htlc[idx].id, self->cnl_add_htlc[idx].flag, self->cnl_add_htlc[idx].amount_msat);
            if ((self->cnl_add_htlc[idx].flag & (LN_HTLC_FLAG_COMMIT_SEND | LN_HTLC_FLAG_COMMIT_RECV)) == 0) {
                //未確定ならば、消す
                if (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_OFFER) {
                    //offeredならば、amountを戻し、HTLC idも戻す
                    LOGD("  rollback htlc[%d]\n", idx);
                    self->our_msat += self->cnl_add_htlc[idx].amount_msat;
                    self->htlc_num--;
                    self->htlc_id_num--;
                }
                utl_buf_free(&self->cnl_add_htlc[idx].buf_payment_preimage);
                utl_buf_free(&self->cnl_add_htlc[idx].buf_onion_reason);
                utl_buf_free(&self->cnl_add_htlc[idx].buf_shared_secret);
                memset(&self->cnl_add_htlc[idx], 0x00, sizeof(ln_update_add_htlc_t));
                LOGD("  -->remove\n");
            }
        }
    }
    M_DB_SELF_SAVE(self);

    return ret;
}


//channel_reestablish作成
bool ln_create_channel_reestablish(ln_self_t *self, utl_buf_t *pReEst)
{
    ln_channel_reestablish_t msg;
    msg.p_channel_id = self->channel_id;

    M_DBG_COMMITNUM(self);

    //MUST set next_local_commitment_number to the commitment number
    //  of the next commitment_signed it expects to receive.
    msg.next_local_commitment_number = self->commit_local.commit_num + 1;
    //MUST set next_remote_revocation_number to the commitment number
    //  of the next revoke_and_ack message it expects to receive.
    msg.next_remote_revocation_number = self->commit_remote.revoke_num + 1;

    //option_data_loss_protect
    if (mInitLocalFeatures[0] & INIT_LF_MASK_DATALOSS) {
        msg.option_data_loss_protect = true;

        if (self->commit_remote.commit_num == 0) {
            memset(msg.your_last_per_commitment_secret, 0, BTC_SZ_PRIVKEY);
        } else {
            bool ret = ln_derkey_storage_get_secret(msg.your_last_per_commitment_secret,
                            &self->peer_storage,
                            (uint64_t)(LN_SECINDEX_INIT - (self->commit_remote.commit_num - 1)));
            if (!ret) {
                LOGD("fail: get last secret\n");
                memset(msg.your_last_per_commitment_secret, 0, BTC_SZ_PRIVKEY);
            }
        }

        uint8_t secret[BTC_SZ_PRIVKEY];
        ln_signer_create_prev_percommitsec(self, secret, msg.my_current_per_commitment_point);
    } else {
        msg.option_data_loss_protect = false;
    }

    bool ret = ln_msg_channel_reestablish_create(pReEst, &msg);
    return ret;
}


bool ln_check_need_funding_locked(const ln_self_t *self)
{
    return (self->short_channel_id != 0) && (self->commit_local.commit_num == 0) && (self->commit_remote.commit_num == 0);
}


bool ln_create_funding_locked(ln_self_t *self, utl_buf_t *pLocked)
{
    //funding_locked
    ln_funding_locked_t cnl_funding_locked;
    cnl_funding_locked.p_channel_id = self->channel_id;
    cnl_funding_locked.p_per_commitpt = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    LOGD("  next_per_commitment_point=%" PRIu64 "\n", self->funding_local.current_commit_num);
    bool ret = ln_msg_funding_locked_create(pLocked, &cnl_funding_locked);

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
    est.cnl_open.funding_sat = 100000000;
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
        wit[0].buf = zero;
        wit[0].len = 72;
        wit[1].buf = zero;
        wit[1].len = 33;
        dummy->tx_funding.vin[0].wit_cnt = 2;
        dummy->tx_funding.vin[0].witness = wit;

        M_DBG_PRINT_TX(&dummy->tx_funding);
        uint64_t sum = 0;
        for (uint32_t lp = 0; lp < dummy->tx_funding.vout_cnt; lp++) {
            sum += dummy->tx_funding.vout[lp].value;
        }
        fee = 0xffffffffffffffff - sum;

        dummy->tx_funding.vin[0].script.buf = NULL;
        dummy->tx_funding.vin[0].script.len = 0;
        dummy->tx_funding.vin[0].wit_cnt = 0;
        dummy->tx_funding.vin[0].witness = NULL;
    } else {
        LOGD("fail: create_funding_tx()\n");
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


//open_channel生成
bool ln_create_open_channel(ln_self_t *self, utl_buf_t *pOpen,
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

    //仮チャネルID
    btc_util_random(self->channel_id, LN_SZ_CHANNEL_ID);

    //鍵生成
    ln_signer_create_channelkeys(self);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

#ifndef USE_SPV
    //funding_tx作成用に保持
    assert(self->p_establish->p_fundin == NULL);
    self->p_establish->p_fundin = (ln_fundin_t *)UTL_DBG_MALLOC(sizeof(ln_fundin_t));     //free: free_establish()
    memcpy(self->p_establish->p_fundin, pFundin, sizeof(ln_fundin_t));
#else
    (void)pFundin;
#endif

    //open_channel
    ln_open_channel_t *open_ch = &self->p_establish->cnl_open;
    open_ch->funding_sat = FundingSat;
    open_ch->push_msat = LN_SATOSHI2MSAT(PushSat);
    open_ch->dust_limit_sat = self->p_establish->estprm.dust_limit_sat;
    open_ch->max_htlc_value_in_flight_msat = self->p_establish->estprm.max_htlc_value_in_flight_msat;
    open_ch->channel_reserve_sat = self->p_establish->estprm.channel_reserve_sat;
    open_ch->htlc_minimum_msat = self->p_establish->estprm.htlc_minimum_msat;
    open_ch->feerate_per_kw = FeeRate;
    open_ch->to_self_delay = self->p_establish->estprm.to_self_delay;
    open_ch->max_accepted_htlcs = self->p_establish->estprm.max_accepted_htlcs;
    open_ch->p_temp_channel_id = self->channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        open_ch->p_pubkeys[lp] = self->funding_local.pubkeys[lp];
    }
    open_ch->channel_flags = CHANNEL_FLAGS_VALUE;
    ln_msg_open_channel_create(pOpen, open_ch);

    self->commit_local.dust_limit_sat = open_ch->dust_limit_sat;
    self->commit_local.max_htlc_value_in_flight_msat = open_ch->max_htlc_value_in_flight_msat;
    self->commit_local.channel_reserve_sat = open_ch->channel_reserve_sat;
    self->commit_local.htlc_minimum_msat = open_ch->htlc_minimum_msat;
    self->commit_local.to_self_delay = open_ch->to_self_delay;
    self->commit_local.max_accepted_htlcs = open_ch->max_accepted_htlcs;
    self->our_msat = LN_SATOSHI2MSAT(open_ch->funding_sat) - open_ch->push_msat;
    self->their_msat = open_ch->push_msat;
    self->funding_sat = open_ch->funding_sat;
    self->feerate_per_kw = open_ch->feerate_per_kw;

    self->fund_flag = (ln_fundflag_t)(LN_FUNDFLAG_FUNDER | ((open_ch->channel_flags & 1) ? LN_FUNDFLAG_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);

    return true;
}


void ln_open_announce_channel_clr(ln_self_t *self)
{
    self->fund_flag = (ln_fundflag_t)(self->fund_flag & ~LN_FUNDFLAG_ANNO_CH);
    M_DB_SELF_SAVE(self);
}


//announcement_signaturesを交換すると channel_announcementが完成する。
bool ln_create_announce_signs(ln_self_t *self, utl_buf_t *pBufAnnoSigns)
{
    bool ret;

    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    if (self->cnl_anno.buf == NULL) {
        create_local_channel_announcement(self);
    }

    ln_msg_get_anno_signs(self, &p_sig_node, &p_sig_btc, true, sort_nodeid(self, NULL));

    ln_announce_signs_t anno_signs;

    anno_signs.p_channel_id = self->channel_id;
    anno_signs.short_channel_id = self->short_channel_id;
    anno_signs.p_node_signature = p_sig_node;
    anno_signs.p_btc_signature = p_sig_btc;
    ret = ln_msg_announce_signs_create(pBufAnnoSigns, &anno_signs);
    if (ret) {
        self->anno_flag |= M_ANNO_FLAG_SEND;
        proc_anno_sigs(self);
        M_DB_SELF_SAVE(self);
    }

    return ret;
}


bool ln_create_channel_update(ln_self_t *self, utl_buf_t *pCnlUpd)
{
    bool ret;

    uint32_t now = (uint32_t)time(NULL);
    ln_cnl_update_t upd;
    ret = create_channel_update(self, &upd, pCnlUpd, now, 0);
    if (ret) {
        LOGD("create: channel_update\n");
        ret = ln_db_annocnlupd_save(pCnlUpd, &upd, NULL);
        if (self->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) {
            //announcement_signatures後であればコールバックする
            //そうでない場合は、announcement前のprivate channel通知をしている
            ln_cb_update_annodb_t anno;
            anno.anno = LN_CB_UPDATE_ANNODB_CNL_UPD;
            (*self->p_callback)(self, LN_CB_UPDATE_ANNODB, &anno);
        }
    } else {
        LOGD("fail: create channel_update\n");
    }

    return ret;
}


bool ln_get_channel_update_peer(const ln_self_t *self, utl_buf_t *pCnlUpd, ln_cnl_update_t *pMsg)
{
    bool ret;

    btc_keys_sort_t sort = sort_nodeid(self, NULL);
    uint8_t dir = (sort == BTC_KEYS_SORT_OTHER) ? 0 : 1;  //相手のchannel_update
    ret = ln_db_annocnlupd_load(pCnlUpd, NULL, self->short_channel_id, dir);
    if (ret && (pMsg != NULL)) {
        ret = ln_msg_cnl_update_read(pMsg, pCnlUpd->buf, pCnlUpd->len);
    }

    return ret;
}


/********************************************************************
 * Close関係
 ********************************************************************/

void ln_update_shutdown_fee(ln_self_t *self, uint64_t Fee)
{
    //BOLT#3
    //  A sending node MUST set fee_satoshis lower than or equal to the base fee
    //      of the final commitment transaction as calculated in BOLT #3.
    uint64_t feemax = ln_calc_max_closing_fee(self);
    if (Fee > feemax) {
        LOGD("closing fee limit(%" PRIu64 " > %" PRIu64 ")\n", Fee, feemax);
        Fee = feemax;
    }

    self->close_fee_sat = Fee;
    LOGD("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
}


bool ln_create_shutdown(ln_self_t *self, utl_buf_t *pShutdown)
{
    LOGD("BEGIN\n");

    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished");
        return false;
    }
    if (self->shutdown_flag & M_SHDN_FLAG_SEND) {
        //送信済み
        M_SET_ERR(self, LNERR_INV_STATE, "already shutdown sent");
        return false;
    }
    if (self->htlc_num != 0) {
        //cleanではない
        M_SET_ERR(self, LNERR_NOT_CLEAN, "HTLC remains: %d", self->htlc_num);
        return false;
    }

    bool ret;
    ln_shutdown_t shutdown_msg;

    shutdown_msg.p_channel_id = self->channel_id;
    shutdown_msg.p_scriptpk = &self->shutdown_scriptpk_local;
    ret = ln_msg_shutdown_create(pShutdown, &shutdown_msg);
    if (ret) {
        self->shutdown_flag |= M_SHDN_FLAG_SEND;
    }

    LOGD("END\n");
    return ret;
}


void ln_goto_closing(ln_self_t *self, void *pDbParam)
{
    LOGD("BEGIN\n");
    if ((self->fund_flag & LN_FUNDFLAG_CLOSE) == 0) {
        //closing中フラグを立てる
        self->fund_flag = (ln_fundflag_t)(self->fund_flag | LN_FUNDFLAG_CLOSE);
        ln_db_self_save_closeflg(self, pDbParam);

        //自分のchannel_updateをdisableにする(相手のは署名できないので、自分だけ)
        utl_buf_t buf_upd = UTL_BUF_INIT;
        uint32_t now = (uint32_t)time(NULL);
        ln_cnl_update_t upd;
        bool ret = create_channel_update(self, &upd, &buf_upd, now, LN_CNLUPD_FLAGS_DISABLE);
        if (ret) {
            ln_db_annocnlupd_save(&buf_upd, &upd, ln_their_node_id(self));
            utl_buf_free(&buf_upd);
        }
    }
    LOGD("END\n");
}


/*
 * 自分がunilateral closeを行いたい場合に呼び出す。
 * または、funding_txがspentで、local commit_txのtxidがgetrawtransactionできる状態で呼ばれる。
 * (local commit_txが展開＝自分でunilateral closeした)
 *
 * 現在のcommitment_transactionを取得する場合にも呼び出されるため、値を元に戻す。
 */
bool ln_create_close_unilateral_tx(ln_self_t *self, ln_close_force_t *pClose)
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
    self->funding_local.current_commit_num = self->commit_local.commit_num;

    //remote
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);
    self->funding_remote.current_commit_num = self->commit_remote.commit_num;

    //update keys
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + self->commit_local.htlc_num);

    //local commit_tx
    bool ret = create_to_local(self, pClose, NULL, 0,
                self->commit_remote.to_self_delay,
                self->commit_local.dust_limit_sat);
    if (!ret) {
        LOGD("fail: create_to_local\n");
        ln_free_close_force_tx(pClose);
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
bool ln_create_closed_tx(ln_self_t *self, ln_close_force_t *pClose)
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
    self->funding_local.current_commit_num = self->commit_local.commit_num;

    //remote
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);
    self->funding_remote.current_commit_num = self->commit_remote.commit_num;

    //update keys
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + self->commit_remote.htlc_num);

    //remote commit_tx
    bool ret = create_to_remote(self, pClose, NULL,
                self->commit_local.to_self_delay,
                self->commit_remote.dust_limit_sat);
    if (!ret) {
        LOGD("fail: create_to_remote\n");
        ln_free_close_force_tx(pClose);
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


void ln_free_close_force_tx(ln_close_force_t *pClose)
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
bool ln_close_ugly(ln_self_t *self, const btc_tx_t *pRevokedTx, void *pDbParam)
{
    //取り戻す必要があるvout数
    self->revoked_cnt = 0;
    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        if (pRevokedTx->vout[lp].script.len != LNL_SZ_WITPROG_WPKH) {
            //to_remote output以外はスクリプトを作って取り戻す
            self->revoked_cnt++;
        }
    }
    LOGD("revoked_cnt=%d\n", self->revoked_cnt);
    self->revoked_num = 1 + self->revoked_cnt;      //p_revoked_vout[0]にto_local系を必ず入れるため、+1しておく
                                                    //(to_local自体が無くても、HTLC txの送金先がto_localと同じtxになるため)
    ln_alloc_revoked_buf(self);

    //
    //相手がrevoked_txを展開した前提で、スクリプトを再現
    //

    //commitment numberの復元
    uint64_t commit_num = ((uint64_t)(pRevokedTx->vin[0].sequence & 0xffffff)) << 24;
    commit_num |= (uint64_t)(pRevokedTx->locktime & 0xffffff);
    commit_num ^= self->obscured;
    LOGD("commit_num=%" PRIu64 "\n", commit_num);

    //remote per_commitment_secretの復元
    utl_buf_alloc(&self->revoked_sec, BTC_SZ_PRIVKEY);
    bool ret = ln_derkey_storage_get_secret(self->revoked_sec.buf, &self->peer_storage, (uint64_t)(LN_SECINDEX_INIT - commit_num));
    if (!ret) {
        LOGD("FATAL: ln_derkey_storage_get_secret()\n");
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
    ln_create_script_local(&self->p_revoked_wit[LN_RCLOSE_IDX_TOLOCAL],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                self->commit_local.to_self_delay);
    utl_buf_alloc(&self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL], LNL_SZ_WITPROG_WSH);
    btc_sw_wit2prog_p2wsh(self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].buf, &self->p_revoked_wit[LN_RCLOSE_IDX_TOLOCAL]);
    LOGD("calc to_local vout: ");
    DUMPD(self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].buf, self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].len);

    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        LOGD("vout[%d]: ", lp);
        DUMPD(pRevokedTx->vout[lp].script.buf, pRevokedTx->vout[lp].script.len);
        if (pRevokedTx->vout[lp].script.len == LNL_SZ_WITPROG_WPKH) {
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
            uint8_t payhash[LN_SZ_HASH];
            uint32_t expiry;
            bool srch = ln_db_phash_search(payhash, &type, &expiry,
                            pRevokedTx->vout[lp].script.buf, pDbParam);
            if (srch) {
                LOGD("[%d]detect!\n", lp);

                ln_create_htlcinfo(&self->p_revoked_wit[LN_RCLOSE_IDX_HTLC + lp],
                        type,
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                        payhash,
                        expiry);
                utl_buf_alloc(&self->p_revoked_vout[LN_RCLOSE_IDX_HTLC + lp], LNL_SZ_WITPROG_WSH);
                btc_sw_wit2prog_p2wsh(self->p_revoked_vout[LN_RCLOSE_IDX_HTLC + lp].buf, &self->p_revoked_wit[LN_RCLOSE_IDX_HTLC + lp]);
                self->p_revoked_type[LN_RCLOSE_IDX_HTLC + lp] = type;
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

bool ln_set_add_htlc(ln_self_t *self,
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

    bool ret;
    int idx;
    ret = check_create_add_htlc(self, &idx, pReason, AmountMsat, CltvValue);
    if (ret) {
        self->cnl_add_htlc[idx].flag = LN_HTLC_FLAG_OFFER;        //送信=offered HTLC
        self->cnl_add_htlc[idx].p_channel_id = self->channel_id;
        self->cnl_add_htlc[idx].id = self->htlc_id_num;
        self->cnl_add_htlc[idx].amount_msat = AmountMsat;
        self->cnl_add_htlc[idx].cltv_expiry = CltvValue;
        memcpy(self->cnl_add_htlc[idx].payment_sha256, pPaymentHash, LN_SZ_HASH);
        utl_buf_alloccopy(&self->cnl_add_htlc[idx].buf_onion_reason, pPacket, LN_SZ_ONION_ROUTE);
        self->cnl_add_htlc[idx].prev_short_channel_id = PrevShortChannelId;
        self->cnl_add_htlc[idx].prev_idx = PrevIdx;
        utl_buf_free(&self->cnl_add_htlc[idx].buf_shared_secret);
        if (pSharedSecrets) {
            utl_buf_alloccopy(&self->cnl_add_htlc[idx].buf_shared_secret, pSharedSecrets->buf, pSharedSecrets->len);
        }

        *pHtlcId = self->cnl_add_htlc[idx].id;
        LOGD("HTLC add : next htlc_num=%d, prev_short_channel_id=%" PRIu64 "\n", self->htlc_num, self->cnl_add_htlc[idx].prev_short_channel_id);
        LOGD("           self->cnl_add_htlc[%d].flag = 0x%02x\n", idx, self->cnl_add_htlc[idx].flag);
    } else {
        M_SET_ERR(self, LNERR_MSG_ERROR, "create update_add_htlc");
    }

    return ret;
}


void ln_create_add_htlc(ln_self_t *self, utl_buf_t *pAdd, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, self->cnl_add_htlc[Idx].flag);
    (void)ln_msg_update_add_htlc_create(pAdd, &self->cnl_add_htlc[Idx]);

    self->cnl_add_htlc[Idx].flag |= LN_HTLC_FLAG_ADDHTLC;
    self->our_msat -= self->cnl_add_htlc[Idx].amount_msat;
    self->htlc_id_num++;
    self->htlc_num++;
    self->uncommit = true;
}


bool ln_set_fulfill_htlc(ln_self_t *self, uint16_t Idx, const uint8_t *pPreImage)
{
    LOGD("BEGIN\n");

    //self->cnl_add_htlc[Idx]にupdate_fulfill_htlcが作成出来るだけの情報を設定
    //  final nodeにふさわしいかのチェックはupdate_add_htlc受信時に行われている
    //  update_fulfill_htlc未送信状態にしておきたいが、このタイミングではadd_htlcのcommitは済んでいない

    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    p_htlc->flag |= LN_HTLC_FLAG_FULFILLHTLC;
    utl_buf_alloccopy(&p_htlc->buf_payment_preimage, pPreImage, LN_SZ_PREIMAGE);

    LOGD("END: self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, self->cnl_add_htlc[Idx].flag);
    return true;
}


void ln_create_fulfill_htlc(ln_self_t *self, utl_buf_t *pFulfill, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, self->cnl_add_htlc[Idx].flag);

    ln_update_fulfill_htlc_t fulfill_htlc;
    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    fulfill_htlc.p_channel_id = self->channel_id;
    fulfill_htlc.id = p_htlc->id;
    fulfill_htlc.p_payment_preimage = p_htlc->buf_payment_preimage.buf;
    (void)ln_msg_update_fulfill_htlc_create(pFulfill, &fulfill_htlc);

    self->our_msat += p_htlc->amount_msat;
    //self->their_msat -= p_htlc->amount_msat;   //add_htlc受信時に引いているので、ここでは不要
    clear_htlc(self, p_htlc);   //TODO: revoke_and_ack後がよいか？

    self->uncommit = true;
}


bool ln_set_fail_htlc(ln_self_t *self, uint16_t Idx, const utl_buf_t *pReason)
{
    LOGD("BEGIN\n");

    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    p_htlc->flag |= LN_HTLC_FLAG_FULFILLHTLC;
    utl_buf_free(&self->cnl_add_htlc[Idx].buf_onion_reason);
    ln_onion_failure_forward(&self->cnl_add_htlc[Idx].buf_onion_reason, &p_htlc->buf_shared_secret, pReason);

    LOGD("END: self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, self->cnl_add_htlc[Idx].flag);
    LOGD("   reason: ");
    DUMPD(pReason->buf, pReason->len);
    return true;
}


void ln_create_fail_htlc(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, self->cnl_add_htlc[Idx].flag);

    ln_update_fail_htlc_t fail_htlc;
    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    fail_htlc.p_channel_id = self->channel_id;
    fail_htlc.id = p_htlc->id;
    fail_htlc.p_reason = &p_htlc->buf_onion_reason;
    (void)ln_msg_update_fail_htlc_create(pFail, &fail_htlc);

    self->their_msat += p_htlc->amount_msat;   //add_htlc受信時に引いた分を戻す
    clear_htlc(self, p_htlc);

    self->uncommit = true;
}


void ln_create_fail_malformed_htlc(ln_self_t *self, utl_buf_t *pFail, uint16_t Idx)
{
    LOGD("self->cnl_add_htlc[%d].flag = 0x%02x\n", Idx, self->cnl_add_htlc[Idx].flag);

    ln_update_fail_malformed_htlc_t mal_htlc;
    ln_update_add_htlc_t *p_htlc = &self->cnl_add_htlc[Idx];

    uint16_t failure_code = utl_misc_be16(p_htlc->buf_onion_reason.buf);
    mal_htlc.p_channel_id = self->channel_id;
    mal_htlc.id = p_htlc->id;
    memcpy(mal_htlc.sha256_onion, p_htlc->buf_onion_reason.buf + sizeof(uint16_t), BTC_SZ_SHA256);
    mal_htlc.failure_code = failure_code;
    (void)ln_msg_update_fail_malformed_htlc_create(pFail, &mal_htlc);

    self->their_msat += p_htlc->amount_msat;   //add_htlc受信時に引いた分を戻す
    clear_htlc(self, p_htlc);

    self->uncommit = true;
}


bool ln_create_commit_signed(ln_self_t *self, utl_buf_t *pCommSig)
{
    LOGD("BEGIN\n");
    return create_commit_signed(self, pCommSig);
}


bool ln_create_update_fee(ln_self_t *self, utl_buf_t *pUpdFee, uint32_t FeeratePerKw)
{
    LOGD("BEGIN: %" PRIu32 " --> %" PRIu32 "\n", self->feerate_per_kw, FeeratePerKw);

    bool ret;

    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished");
        return false;
    }

    ln_update_fee_t updfee;
    updfee.p_channel_id = self->channel_id;
    updfee.feerate_per_kw = FeeratePerKw;
    ret = ln_msg_update_fee_create(pUpdFee, &updfee);
    if (ret) {
        self->uncommit = true;
    }

    LOGD("END\n");
    return ret;
}


/********************************************************************
 * ping/pong
 ********************************************************************/

bool ln_create_ping(ln_self_t *self, utl_buf_t *pPing)
{
    ln_ping_t ping;

    // if (self->last_num_pong_bytes != 0) {
    //     LOGD("not receive pong(last_num_pong_bytes=%d)\n", self->last_num_pong_bytes);
    //     return false;
    // }

#if 1
    // https://github.com/lightningnetwork/lightning-rfc/issues/373
    //  num_pong_bytesが大きすぎると無視される？
    uint8_t r;
    btc_util_random(&r, 1);
    self->last_num_pong_bytes = r;
    btc_util_random(&r, 1);
    ping.byteslen = r;
#else
    btc_util_random((uint8_t *)&self->last_num_pong_bytes, 2);
    btc_util_random((uint8_t *)&ping.byteslen, 2);
#endif
    ping.num_pong_bytes = self->last_num_pong_bytes;
    bool ret = ln_msg_ping_create(pPing, &ping);
    if (ret) {
        self->missing_pong_cnt++;
        //if (self->missing_pong_cnt > M_PONG_MISSING) {
        //    M_SET_ERR(self, LNERR_PINGPONG, "many pong missing...(%d)\n", self->missing_pong_cnt);
        //    ret = false;
        //}
    }

    return ret;
}


bool ln_create_pong(ln_self_t *self, utl_buf_t *pPong, uint16_t NumPongBytes)
{
    (void)self;

    ln_pong_t pong;

    pong.byteslen = NumPongBytes;
    bool ret = ln_msg_pong_create(pPong, &pong);

    return ret;
}


/********************************************************************
 * others
 ********************************************************************/

bool ln_htlc_is_stable(const ln_self_t *self)
{
    return comrev_state(self) == M_STAT_STABLE;
}


bool ln_have_outdated_htlc(const ln_self_t *self, int32_t Height)
{
    bool ret = false;

    if (Height > 0) {
        for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
            if ( (self->cnl_add_htlc[lp].amount_msat > 0) &&
                 (self->cnl_add_htlc[lp].flag & LN_HTLC_FLAG_OFFER) &&
                 (self->cnl_add_htlc[lp].cltv_expiry <= (uint32_t)Height) ) {
                LOGD("HTLC timeouted[%d] expiry:%" PRIu32 " <= height:%" PRId32 "\n", lp, self->cnl_add_htlc[lp].cltv_expiry, Height);
                ret = true;
                break;
            }
        }
    }

    return ret;
}


bool ln_create_tolocal_spent(const ln_self_t *self, btc_tx_t *pTx, uint64_t Value, uint32_t to_self_delay,
                const utl_buf_t *pScript, const uint8_t *pTxid, int Index, bool bRevoked)
{
    bool ret;
    uint64_t val;

    //to_localのFEE
    uint64_t fee_tolocal = ln_calc_fee(M_SZ_TO_LOCAL_TX(self->shutdown_scriptpk_local.len), self->feerate_per_kw);
    LOGD("fee_tolocal=%" PRIu64 "\n", fee_tolocal);
    if (Value < BTC_DUST_LIMIT + fee_tolocal) {
        LOGD("fail: vout below dust: value=%" PRIu64 "< DUST(%" PRIu64 ")+fee(%" PRIu64 ")\n", Value, BTC_DUST_LIMIT, fee_tolocal);
        goto LABEL_EXIT;
    }
    val = Value - fee_tolocal;
    ret = ln_create_tolocal_tx(pTx, val,
            &self->shutdown_scriptpk_local, to_self_delay, pTxid, Index, bRevoked);
    if (!ret) {
        goto LABEL_EXIT;
    }

    ret = ln_signer_tolocal_tx(self, pTx, Value, pScript, bRevoked);

LABEL_EXIT:
    return ret;
}


bool ln_create_toremote_spent(const ln_self_t *self, btc_tx_t *pTx, uint64_t Value, const uint8_t *pTxid, int Index)
{
    bool ret;
    btc_util_keys_t signkey;

    //to_remoteのFEE
    uint64_t fee_toremote = ln_calc_fee(M_SZ_TO_REMOTE_TX(self->shutdown_scriptpk_local.len), self->feerate_per_kw);
    if (Value < BTC_DUST_LIMIT + fee_toremote) {
        LOGD("fail: vout below dust(value=%" PRIu64 ", fee=%" PRIu64 ")\n", Value, fee_toremote);
        ret = false;
        goto LABEL_EXIT;
    }

    // remotekeyへの支払いを self->shutdown_scriptpk_local に送金する
    //  通常のP2WPKHなので、bRevoedはfalse扱い
    //  to_local用の関数を使っているが、最低限の設定をしているだけなので同じ処理でよい
    btc_tx_init(pTx);

    ret = ln_create_tolocal_tx(pTx, Value - fee_toremote,
            &self->shutdown_scriptpk_local, 0, pTxid, Index, false);
    if (!ret) {
        LOGD("fail: create to_remote tx\n");
        goto LABEL_EXIT;
    }
    //<remotesecretkey>
    //  revoked transaction close後はremotekeyも当時のものになっているため、同じ処理でよい
    ln_signer_get_secret(self, &signkey, MSG_FUNDIDX_PAYMENT,
        self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
    if (memcmp(signkey.pub, self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY], BTC_SZ_PUBKEY) != 0) {
        LOGD("FATAL: pubkey mismatch\n");
        abort();
    }
    //LOGD("key-priv: ");
    //DUMPD(signkey.priv, BTC_SZ_PRIVKEY);
    //LOGD("key-pub : ");
    //DUMPD(signkey.pub, BTC_SZ_PUBKEY);

    //vinは1つしかない
    ret = ln_signer_p2wpkh(pTx, 0, Value, &signkey);

LABEL_EXIT:
    return ret;
}


bool ln_create_revokedhtlc_spent(const ln_self_t *self, btc_tx_t *pTx, uint64_t Value,
                int WitIndex, const uint8_t *pTxid, int Index)
{
    ln_feeinfo_t feeinfo;
    feeinfo.feerate_per_kw = self->feerate_per_kw;
    ln_fee_calc(&feeinfo, NULL, 0);
    uint64_t fee = (self->p_revoked_type[WitIndex] == LN_HTLCTYPE_OFFERED) ? feeinfo.htlc_timeout : feeinfo.htlc_success;
    LOGD("Value=%" PRIu64 ", fee=%" PRIu64 "\n", Value, fee);

    ln_create_htlc_tx(pTx, Value - fee, &self->shutdown_scriptpk_local, self->p_revoked_type[WitIndex], 0, pTxid, Index);
    M_DBG_PRINT_TX2(pTx);

    btc_util_keys_t signkey;
    ln_signer_get_revokesec(self, &signkey,
                    self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
                    self->revoked_sec.buf);
    // LOGD("key-priv: ");
    // DUMPD(signkey.priv, BTC_SZ_PRIVKEY);
    // LOGD("key-pub : ");
    // DUMPD(signkey.pub, BTC_SZ_PUBKEY);

    utl_buf_t buf_sig;
    ln_htlcsign_t htlcsign = LN_HTLCSIGN_NONE;
    switch (self->p_revoked_type[WitIndex]) {
    case LN_HTLCTYPE_OFFERED:
        htlcsign = LN_HTLCSIGN_RV_OFFERED;
        break;
    case LN_HTLCTYPE_RECEIVED:
        htlcsign = LN_HTLCSIGN_RV_RECEIVED;
        break;
    default:
        LOGD("index=%d, %d\n", WitIndex, self->p_revoked_type[WitIndex]);
        assert(0);
    }
    bool ret;
    if (htlcsign != LN_HTLCSIGN_NONE) {
        ret = ln_sign_htlc_tx(pTx,
                &buf_sig,
                Value,
                &signkey,
                NULL,
                NULL,
                &self->p_revoked_wit[WitIndex],
                htlcsign);
        utl_buf_free(&buf_sig);
    } else {
        ret = false;
    }

    return ret;
}


void ln_calc_preimage_hash(uint8_t *pHash, const uint8_t *pPreImage)
{
    btc_util_sha256(pHash, pPreImage, LN_SZ_PREIMAGE);
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
    ln_cnl_announce_read_t ann;

    bool ret = ln_msg_cnl_announce_read(&ann, pData, Len);
    if (ret && (ann.short_channel_id != 0)) {
        *p_short_channel_id = ann.short_channel_id;
        memcpy(pNodeId1, ann.node_id1, BTC_SZ_PUBKEY);
        memcpy(pNodeId2, ann.node_id2, BTC_SZ_PUBKEY);
    } else {
        LOGD("fail\n");
    }

    return ret;
}


/** [routing用]channel_updateデータ解析
 *
 * @param[out]  pUpd
 * @param[in]   pData
 * @param[in]   Len
 * @retval  true        解析成功
 */
bool ln_getparams_cnl_upd(ln_cnl_update_t *pUpd, const uint8_t *pData, uint16_t Len)
{
    bool ret = ln_msg_cnl_update_read(pUpd, pData, Len);
    return ret;
}


/* [非公開]デバッグ用オプション設定
 *
 */
void ln_set_debug(unsigned long debug)
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
unsigned long ln_get_debug(void)
{
    return mDebug;
}


/********************************************************************
 * package functions
 ********************************************************************/

/** revoked transaction close関連のメモリ確保
 *
 */
void HIDDEN ln_alloc_revoked_buf(ln_self_t *self)
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


/** #ln_alloc_revoked_buf()で確保したメモリの解放
 *
 */
void HIDDEN ln_free_revoked_buf(ln_self_t *self)
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
    ln_free_revoked_buf(self);

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

static bool recv_init(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;

    if (self->init_flag & M_INIT_FLAG_RECV) {
        //TODO: 2回init受信した場合はエラーにする
        M_SEND_ERR(self, LNERR_MSG_INIT, "multiple init receive");
        return false;
    }

    ln_init_t msg;
    utl_buf_init(&msg.globalfeatures);
    utl_buf_init(&msg.localfeatures);
    ret = ln_msg_init_read(&msg, pData, Len);
    if (ret) {
        //2018/06/27(comit: f6312d9a702ede0f85e094d75fd95c5e3b245bcf)
        //      https://github.com/lightningnetwork/lightning-rfc/blob/f6312d9a702ede0f85e094d75fd95c5e3b245bcf/09-features.md#assigned-globalfeatures-flags
        //  globalfeatures not assigned
        ret &= (msg.globalfeatures.len == 0);
    }

    bool initial_routing_sync = false;
    if (ret) {
        ret &= (msg.localfeatures.len <= 1);
        if (msg.localfeatures.len == 1) {
            //2018/06/27(comit: f6312d9a702ede0f85e094d75fd95c5e3b245bcf)
            //      https://github.com/lightningnetwork/lightning-rfc/blob/f6312d9a702ede0f85e094d75fd95c5e3b245bcf/09-features.md#assigned-localfeatures-flags
            //  bit0/1 : option_data_loss_protect
            //  bit3   : initial_routing_sync
            //  bit4/5 : option_upfront_shutdown_script
            //  bit6/7 : gossip_queries
            if (ret) {
                //flagは未知のフラグ
                uint8_t flag = (msg.localfeatures.buf[0] & (~INIT_LF_MASK));
                if (flag & 0x55) {
                    //even bit: 未対応のため、エラーにする
                    ret = false;
                } else {
                    //odd bit: 未知でもスルー
                }
            }
            initial_routing_sync = (msg.localfeatures.buf[0] & LN_INIT_LF_ROUTE_SYNC);
        }
    }
    if (ret) {
        if (msg.localfeatures.len > 0) {
            self->lfeature_remote = msg.localfeatures.buf[0];
        }
        self->init_flag |= M_INIT_FLAG_RECV;

        //init受信通知
        (*self->p_callback)(self, LN_CB_INIT_RECV, &initial_routing_sync);
    } else {
        M_SET_ERR(self, LNERR_INV_FEATURE, "init error");
    }
    utl_buf_free(&msg.localfeatures);
    utl_buf_free(&msg.globalfeatures);

    return ret;
}


static bool recv_error(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    if (ln_is_funding(self)) {
        LOGD("stop funding\n");
        free_establish(self, false);    //切断せずに継続する場合もあるため、残す
    }

    ln_error_t err;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    err.channel_id = channel_id;
    ln_msg_error_read(&err, pData, Len);
    (*self->p_callback)(self, LN_CB_ERROR, &err);
    UTL_DBG_FREE(err.p_data);

    return true;
}


static bool recv_ping(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    bool ret;

    ln_ping_t ping;
    ret = ln_msg_ping_read(&ping, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //脊髄反射的にpongを返す
    utl_buf_t buf_bolt;
    ret = ln_create_pong(self, &buf_bolt, ping.num_pong_bytes);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    utl_buf_free(&buf_bolt);

    //LOGD("END\n");
    return ret;
}


static bool recv_pong(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //LOGD("BEGIN\n");

    bool ret;

    ln_pong_t pong;
    ret = ln_msg_pong_read(&pong, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //pongのbyteslenはpingのnum_pong_bytesであること
    ret = (pong.byteslen == self->last_num_pong_bytes);
    if (ret) {
        self->missing_pong_cnt--;
        //LOGD("missing_pong_cnt: %d / last_num_pong_bytes: %d\n", self->missing_pong_cnt, self->last_num_pong_bytes);
        self->last_num_pong_bytes = 0;
    } else {
        LOGD("fail: pong.byteslen(%" PRIu16 ") != self->last_num_pong_bytes(%" PRIu16 ")\n", pong.byteslen, self->last_num_pong_bytes);
    }

    //LOGD("END\n");
    return true;
}


static bool recv_open_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;

    if (ln_is_funder(self)) {
        //open_channel受信側ではない
        M_SET_ERR(self, LNERR_INV_SIDE, "not fundee");
        return false;
    }
    if (ln_is_funding(self)) {
        //既にfunding中
        M_SET_ERR(self, LNERR_ALREADY_FUNDING, "already funding");
        return false;
    }
    if (self->short_channel_id != 0) {
        //establish済み
        M_SET_ERR(self, LNERR_ALREADY_FUNDING, "already established");
        return false;
    }

    ln_open_channel_t *open_ch = &self->p_establish->cnl_open;

    open_ch->p_temp_channel_id = self->channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        open_ch->p_pubkeys[lp] = self->funding_remote.pubkeys[lp];
    }
    ret = ln_msg_open_channel_read(open_ch, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //feerate_per_kw更新
    (*self->p_callback)(self, LN_CB_SET_LATEST_FEERATE, NULL);

    //feerate_per_kwの許容チェック
    const char *p_err = NULL;
    if ( (open_ch->feerate_per_kw < LN_FEERATE_PER_KW_MIN) ||
         !M_FEERATE_CHK_MIN_OK(self->feerate_per_kw, open_ch->feerate_per_kw) ) {
        p_err = "fail: feerate_per_kw is too short";
    } else if (!M_FEERATE_CHK_MAX_OK(self->feerate_per_kw, open_ch->feerate_per_kw)) {
        p_err = "fail: feerate_per_kw is too large";
    }
    if (p_err != NULL) {
        M_SEND_ERR(self, LNERR_INV_VALUE, "%s", p_err);
        return false;
    }

    uint64_t fee = ln_estimate_initcommittx_fee(open_ch->feerate_per_kw);
    if (open_ch->funding_sat < fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN) {
        char str[256];
        sprintf(str, "funding_sat too low(%" PRIu64 " < %" PRIu64 ")\n",
                open_ch->funding_sat, fee + BTC_DUST_LIMIT + LN_FUNDSAT_MIN);
        M_SEND_ERR(self, LNERR_INV_VALUE, "%s", str);
        return false;
    }

    self->commit_remote.dust_limit_sat = open_ch->dust_limit_sat;
    self->commit_remote.max_htlc_value_in_flight_msat = open_ch->max_htlc_value_in_flight_msat;
    self->commit_remote.channel_reserve_sat = open_ch->channel_reserve_sat;
    self->commit_remote.htlc_minimum_msat = open_ch->htlc_minimum_msat;
    self->commit_remote.to_self_delay = open_ch->to_self_delay;
    self->commit_remote.max_accepted_htlcs = open_ch->max_accepted_htlcs;

    //first_per_commitment_pointは初回revoke_and_ackのper_commitment_secretに対応する
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    self->funding_remote.current_commit_num = 0;
    LOGD("  funding_remote.current_commit_num=%" PRIu64 "\n", self->funding_remote.current_commit_num);

    self->funding_sat = open_ch->funding_sat;
    self->feerate_per_kw = open_ch->feerate_per_kw;
    self->our_msat = open_ch->push_msat;
    self->their_msat = LN_SATOSHI2MSAT(open_ch->funding_sat) - open_ch->push_msat;

    //鍵生成 && スクリプト用鍵生成
    ln_signer_create_channelkeys(self);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    ln_accept_channel_t *acc_ch = &self->p_establish->cnl_accept;
    acc_ch->dust_limit_sat = self->p_establish->estprm.dust_limit_sat;
    acc_ch->max_htlc_value_in_flight_msat = self->p_establish->estprm.max_htlc_value_in_flight_msat;
    acc_ch->channel_reserve_sat = self->p_establish->estprm.channel_reserve_sat;
    acc_ch->min_depth = self->p_establish->estprm.min_depth;
    acc_ch->htlc_minimum_msat = self->p_establish->estprm.htlc_minimum_msat;
    acc_ch->to_self_delay = self->p_establish->estprm.to_self_delay;
    acc_ch->max_accepted_htlcs = self->p_establish->estprm.max_accepted_htlcs;
    acc_ch->p_temp_channel_id = self->channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        acc_ch->p_pubkeys[lp] = self->funding_local.pubkeys[lp];
    }
    utl_buf_t buf_bolt;
    ln_msg_accept_channel_create(&buf_bolt, acc_ch);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    utl_buf_free(&buf_bolt);

    self->min_depth = acc_ch->min_depth;
    self->commit_local.dust_limit_sat = acc_ch->dust_limit_sat;
    self->commit_local.max_htlc_value_in_flight_msat = acc_ch->max_htlc_value_in_flight_msat;
    self->commit_local.channel_reserve_sat = acc_ch->channel_reserve_sat;
    self->commit_local.htlc_minimum_msat = acc_ch->htlc_minimum_msat;
    self->commit_local.to_self_delay = acc_ch->to_self_delay;
    self->commit_local.max_accepted_htlcs = acc_ch->max_accepted_htlcs;

    //obscured commitment tx numberは共通
    //  1番目:open_channelのpayment-basepoint
    //  2番目:accept_channelのpayment-basepoint
    self->obscured = ln_calc_obscured_txnum(
                                open_ch->p_pubkeys[MSG_FUNDIDX_PAYMENT],
                                acc_ch->p_pubkeys[MSG_FUNDIDX_PAYMENT]);
    LOGD("obscured=0x%016" PRIx64 "\n", self->obscured);

    //vout 2-of-2
    ret = btc_util_create2of2(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING], self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);
    if (ret) {
        self->htlc_num = 0;
        self->fund_flag = (ln_fundflag_t)(((open_ch->channel_flags & 1) ? LN_FUNDFLAG_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING);
    } else {
        M_SET_ERR(self, LNERR_CREATE_2OF2, "create 2-of-2");
    }

    LOGD("END\n");
    return ret;
}


static bool recv_accept_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;

    if (!ln_is_funder(self)) {
        //open_channel送信側ではない
        M_SET_ERR(self, LNERR_INV_SIDE, "not funder");
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ln_accept_channel_t *acc_ch = &self->p_establish->cnl_accept;
    acc_ch->p_temp_channel_id = channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        acc_ch->p_pubkeys[lp] = self->funding_remote.pubkeys[lp];
    }
    ret = ln_msg_accept_channel_read(acc_ch, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //temporary-channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    self->min_depth = acc_ch->min_depth;
    self->commit_remote.dust_limit_sat = acc_ch->dust_limit_sat;
    self->commit_remote.max_htlc_value_in_flight_msat = acc_ch->max_htlc_value_in_flight_msat;
    self->commit_remote.channel_reserve_sat = acc_ch->channel_reserve_sat;
    self->commit_remote.htlc_minimum_msat = acc_ch->htlc_minimum_msat;
    self->commit_remote.to_self_delay = acc_ch->to_self_delay;
    self->commit_remote.max_accepted_htlcs = acc_ch->max_accepted_htlcs;

    //first_per_commitment_pointは初回revoke_and_ackのper_commitment_secretに対応する
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    self->funding_remote.current_commit_num = 0;
    LOGD("  funding_remote.current_commit_num=%" PRIu64 "\n", self->funding_remote.current_commit_num);

    //スクリプト用鍵生成
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    self->htlc_num = 0;

    //funding_tx作成
    ret = create_funding_tx(self, true);
    if (!ret) {
        M_SET_ERR(self, LNERR_CREATE_TX, "create funding_tx");
        return false;
    }

    //obscured commitment tx numberは共通
    //  1番目:open_channelのpayment-basepoint
    //  2番目:accept_channelのpayment-basepoint
    self->obscured = ln_calc_obscured_txnum(
                                self->p_establish->cnl_open.p_pubkeys[MSG_FUNDIDX_PAYMENT],
                                acc_ch->p_pubkeys[MSG_FUNDIDX_PAYMENT]);
    LOGD("obscured=0x%016" PRIx64 "\n", self->obscured);

    //
    // initial commit tx(Remoteが持つTo-Local)
    //      署名計算のみのため、計算後は破棄する
    //      HTLCは存在しないため、計算省略
    ret = create_to_remote(self, NULL, NULL,
                self->p_establish->cnl_open.to_self_delay, acc_ch->dust_limit_sat);
    if (ret) {
        //funding_created
        ln_funding_created_t *fundc = &self->p_establish->cnl_funding_created;
        fundc->p_temp_channel_id = self->channel_id;
        fundc->funding_output_idx = self->funding_local.txindex;
        fundc->p_funding_txid = self->funding_local.txid;
        fundc->p_signature = self->commit_local.signature;

        utl_buf_t buf_bolt;
        ln_msg_funding_created_create(&buf_bolt, fundc);
        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        utl_buf_free(&buf_bolt);
    }

    LOGD("END\n");
    return ret;
}


static bool recv_funding_created(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;

    if (ln_is_funder(self)) {
        //open_channel受信側ではない
        M_SET_ERR(self, LNERR_INV_SIDE, "not fundee");
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ln_funding_created_t *fundc = &self->p_establish->cnl_funding_created;
    fundc->p_temp_channel_id = channel_id;
    fundc->p_funding_txid = self->funding_local.txid;
    fundc->p_signature = self->commit_remote.signature;
    ret = ln_msg_funding_created_read(&self->p_establish->cnl_funding_created, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //temporary-channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    self->funding_local.txindex = fundc->funding_output_idx;

    //署名チェック用
    btc_tx_free(&self->tx_funding);
    for (int lp = 0; lp < self->funding_local.txindex; lp++) {
        //処理の都合上、voutの位置を調整している
        btc_tx_add_vout(&self->tx_funding, 0);
    }
    btc_sw_add_vout_p2wsh(&self->tx_funding, self->p_establish->cnl_open.funding_sat, &self->redeem_fund);
    //TODO: 実装上、vinが0、voutが1だった場合にsegwitと誤認してしまう
    btc_tx_add_vin(&self->tx_funding, self->funding_local.txid, 0);

    //署名チェック
    // initial commit tx(自分が持つTo-Local)
    //      to-self-delayは自分の値(open_channel)を使う
    //      HTLCは存在しない
    ret = create_to_local(self, NULL, NULL, 0,
                self->p_establish->cnl_open.to_self_delay, self->p_establish->cnl_accept.dust_limit_sat);
    if (!ret) {
        LOGD("fail: create_to_local\n");
        return false;
    }

    // initial commit tx(Remoteが持つTo-Local)
    //      署名計算のみのため、計算後は破棄する
    //      HTLCは存在しないため、計算省略
    ret = create_to_remote(self, NULL, NULL,
                self->p_establish->cnl_accept.to_self_delay, self->p_establish->cnl_open.dust_limit_sat);
    if (!ret) {
        LOGD("fail: create_to_remote\n");
        return false;
    }

    //正式チャネルID
    ln_misc_calc_channel_id(self->channel_id, self->funding_local.txid, self->funding_local.txindex);

    //funding_signed
    self->p_establish->cnl_funding_signed.p_channel_id = self->channel_id;
    self->p_establish->cnl_funding_signed.p_signature = self->commit_local.signature;

    utl_buf_t buf_bolt;
    ln_msg_funding_signed_create(&buf_bolt, &self->p_establish->cnl_funding_signed);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    utl_buf_free(&buf_bolt);

    //funding_tx安定待ち
    start_funding_wait(self, false);
    ln_set_status(self, LN_STATUS_ESTABLISH);

    LOGD("END\n");
    return true;
}


static bool recv_funding_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;

    if (!ln_is_funder(self)) {
        //open_channel送信側ではない
        M_SET_ERR(self, LNERR_INV_SIDE, "not funder");
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    self->p_establish->cnl_funding_signed.p_channel_id = channel_id;
    self->p_establish->cnl_funding_signed.p_signature = self->commit_remote.signature;
    ret = ln_msg_funding_signed_read(&self->p_establish->cnl_funding_signed, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel-id生成
    ln_misc_calc_channel_id(self->channel_id, self->funding_local.txid, self->funding_local.txindex);

    //channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //
    // initial commit tx(自分が持つTo-Local)
    //      to-self-delayは相手の値(accept_channel)を使う
    //      HTLCは存在しない
    ret = create_to_local(self, NULL, NULL, 0,
                self->p_establish->cnl_accept.to_self_delay, self->p_establish->cnl_open.dust_limit_sat);
    if (!ret) {
        LOGD("fail: create_to_local\n");
        return false;
    }

    //funding_tx安定待ち
    start_funding_wait(self, true);
    ln_set_status(self, LN_STATUS_ESTABLISH);

    LOGD("END\n");
    return ret;
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

    bool ret;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t per_commitpt[BTC_SZ_PUBKEY];
    ln_funding_locked_t cnl_funding_locked;

    cnl_funding_locked.p_channel_id = channel_id;
    cnl_funding_locked.p_per_commitpt = per_commitpt;
    ret = ln_msg_funding_locked_read(&cnl_funding_locked, pData, Len);
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

    LOGV("prev: ");
    DUMPV(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    LOGV("next: ");
    DUMPV(per_commitpt, BTC_SZ_PUBKEY);

    //prev_percommitはrevoke_and_ackでのみ更新する
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], per_commitpt, BTC_SZ_PUBKEY);
    self->funding_remote.current_commit_num = 1;
    LOGD("  funding_remote.current_commit_num=%" PRIu64 "\n", self->funding_remote.current_commit_num);

    //funding中終了
    free_establish(self, true);

    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);
    M_DB_SELF_SAVE(self);

    (*self->p_callback)(self, LN_CB_FUNDINGLOCKED_RECV, NULL);

    M_DBG_COMMITNUM(self);

    LOGD("END\n");
    return true;
}


static bool recv_shutdown(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;

    if (self->shutdown_flag & M_SHDN_FLAG_RECV) {
        //既にshutdownを受信済みなら、何もしない
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ln_shutdown_t cnl_shutdown;
    cnl_shutdown.p_channel_id = channel_id;
    cnl_shutdown.p_scriptpk = &self->shutdown_scriptpk_remote;
    ret = ln_msg_shutdown_read(&cnl_shutdown, pData, Len);
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

    //scriptPubKeyチェック
    ret = ln_check_scriptpkh(&self->shutdown_scriptpk_remote);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_PRIVKEY, "unknown scriptPubKey type");
        return false;
    }

    //HTLCが残っていたらfalse
    if (self->htlc_num != 0) {
        M_SET_ERR(self, LNERR_NOT_CLEAN, "HTLC num : %d", self->htlc_num);
        return false;
    }

    //shutdown受信済み
    self->shutdown_flag |= M_SHDN_FLAG_RECV;

    //  相手がshutdownを送ってきたということは、HTLCは持っていないはず。
    //  相手は持っていなくて自分は持っているという状況は発生しない。

    self->close_last_fee_sat = 0;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    if (!(self->shutdown_flag & M_SHDN_FLAG_SEND)) {
        //shutdown未送信の場合 == shutdownを要求された方

        //feeと送金先を設定してもらう
        (*self->p_callback)(self, LN_CB_SHUTDOWN_RECV, NULL);

        ret = ln_create_shutdown(self, &buf_bolt);
        if (ret) {
            (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
            utl_buf_free(&buf_bolt);
        } else {
            M_SET_ERR(self, LNERR_CREATE_MSG, "create shutdown");
        }
    }

    if (M_SHDN_FLAG_EXCHANGED(self->shutdown_flag)) {
        //shutdown交換完了
        M_DB_SELF_SAVE(self);
    }

    if (M_SHDN_FLAG_EXCHANGED(self->shutdown_flag) && ln_is_funder(self)) {
        //shutdown交換完了 && funder --> 最初のclosing_signed送信
        LOGD("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
        ln_closing_signed_t cnl_close;
        cnl_close.p_channel_id = self->channel_id;
        cnl_close.fee_sat = self->close_fee_sat;
        cnl_close.p_signature = self->commit_local.signature;

        //remoteの署名はないので、verifyしない
        btc_tx_free(&self->tx_closing);
        ret = create_closing_tx(self, &self->tx_closing, self->close_fee_sat, false);
        if (ret) {
            ret = ln_msg_closing_signed_create(&buf_bolt, &cnl_close);
        } else {
            LOGD("fail: create close_t\n");
        }
        if (ret) {
            self->close_last_fee_sat = self->close_fee_sat;
            (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
            utl_buf_free(&buf_bolt);

            //署名送信により相手がbroadcastできるようになるので、一度保存する
            M_DB_SELF_SAVE(self);
        } else {
            LOGD("fail\n");
        }
    }

    LOGD("END\n");
    return ret;
}


static bool recv_closing_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    if (!M_SHDN_FLAG_EXCHANGED(self->shutdown_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "shutdown status : %02x", self->shutdown_flag);
        return false;
    }

    bool ret;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ln_closing_signed_t cnl_close;
    cnl_close.p_channel_id = channel_id;
    cnl_close.p_signature = self->commit_remote.signature;
    ret = ln_msg_closing_signed_read(&cnl_close, pData, Len);
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

    //BOLT#3
    //  A sending node MUST set fee_satoshis lower than or equal to the base fee
    //      of the final commitment transaction as calculated in BOLT #3.
    uint64_t feemax = ln_calc_max_closing_fee(self);
    if (cnl_close.fee_sat > feemax) {
        LOGD("fail: fee too large(%" PRIu64 " > %" PRIu64 ")\n", cnl_close.fee_sat, feemax);
        return false;
    }

    //相手が要求するFEEでverify
    btc_tx_free(&self->tx_closing);
    ret = create_closing_tx(self, &self->tx_closing, cnl_close.fee_sat, true);
    if (!ret) {
        LOGD("fail: create close_t\n");
        assert(false);
    }

    cnl_close.p_channel_id = self->channel_id;
    cnl_close.p_signature = self->commit_local.signature;
    bool need_closetx = (self->close_last_fee_sat == cnl_close.fee_sat);

    if (!need_closetx) {
        //送信feeと受信feeが不一致なので、上位層にfeeを設定してもらう
        ln_cb_closed_fee_t closed_fee;
        closed_fee.fee_sat = cnl_close.fee_sat;
        (*self->p_callback)(self, LN_CB_CLOSED_FEE, &closed_fee);
        //self->close_fee_satが更新される
    }

    //closing_tx作成
    btc_tx_free(&self->tx_closing);
    ret = create_closing_tx(self, &self->tx_closing, self->close_fee_sat, need_closetx);
    if (!ret) {
        LOGD("fail: create close_t\n");
        assert(false);
    }

    if (need_closetx) {
        //closing_txを展開する
        LOGD("same fee!\n");
        utl_buf_t txbuf = UTL_BUF_INIT;
        ret = btc_tx_create(&txbuf, &self->tx_closing);
        if (ret) {
            ln_cb_closed_t closed;

            closed.p_tx_closing = &txbuf;
            (*self->p_callback)(self, LN_CB_CLOSED, &closed);

            //clearはDB削除に任せる
            //channel_clear(self);
        } else {
            LOGD("fail: create closeing_tx\n");
            assert(0);
        }
        utl_buf_free(&txbuf);
    } else {
        //closing_singnedを送信する
        LOGD("different fee!\n");
        utl_buf_t buf_bolt = UTL_BUF_INIT;
        ret = ln_msg_closing_signed_create(&buf_bolt, &cnl_close);
        if (ret) {
            self->close_last_fee_sat = self->close_fee_sat;
            (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        } else {
            LOGD("fail: create closeing_signed\n");
            assert(0);
        }
        utl_buf_free(&buf_bolt);
    }

    LOGD("END\n");
    return ret;
}


static bool recv_update_add_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    int idx;

    //空きHTLCチェック
    for (idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat == 0) {
            //BOLT#2: MUST offer amount-msat greater than 0
            //  だから、0の場合は空き
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
    ret = ln_msg_update_add_htlc_read(p_htlc, pData, Len);
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
        LOGD("fail: BOLT2 check\n");
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

    add_htlc.result = LN_CB_ADD_HTLC_RESULT_OK;
    ret = ln_onion_read_packet(p_htlc->buf_onion_reason.buf, &hop_dataout,
                    &p_htlc->buf_shared_secret,
                    &push_htlc,
                    p_htlc->buf_onion_reason.buf,
                    p_htlc->payment_sha256, LN_SZ_HASH);
    if (ret) {
        int32_t height = 0;
        (*self->p_callback)(self, LN_CB_GETBLOCKCOUNT, &height);
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

        uint16_t failure_code = utl_misc_be16(buf_reason.buf);
        if (failure_code & LNERR_ONION_BADONION) {
            //update_fail_malformed_htlc
            add_htlc.result = LN_CB_ADD_HTLC_RESULT_MALFORMED;
        } else {
            //update_fail_htlc
            add_htlc.result = LN_CB_ADD_HTLC_RESULT_FAIL;
        }
        utl_buf_free(&p_htlc->buf_onion_reason);
    }
    if (ret) {
        ret = check_recv_add_htlc_bolt4_common(&push_htlc);
    }

    //failにせよfail_malformedにせよ、HTLCを受け入れるのでuncommit状態にする
    self->uncommit = true;

    //成功にせよ失敗にせよ、相手のamountから差し引いて、HTLC追加
    self->their_msat -= p_htlc->amount_msat;
    self->htlc_num++;
    p_htlc->flag = LN_HTLC_FLAG_RECV;       //受信=received HTLC
    LOGD("HTLC add : htlc_num=%d, id=%" PRIu64 ", amount_msat=%" PRIu64 "\n", self->htlc_num, p_htlc->id, p_htlc->amount_msat);

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

    //update_add_htlc受信通知
    if (!ret && (add_htlc.result == LN_CB_ADD_HTLC_RESULT_OK)) {
        add_htlc.result = LN_CB_ADD_HTLC_RESULT_FAIL;
    }
    add_htlc.id = p_htlc->id;
    add_htlc.p_payment = p_htlc->payment_sha256;
    add_htlc.p_preimage = (hop_dataout.b_exit) ? p_htlc->buf_payment_preimage.buf : NULL;
    add_htlc.p_hop = &hop_dataout;
    add_htlc.amount_msat = p_htlc->amount_msat;
    add_htlc.cltv_expiry = p_htlc->cltv_expiry;
    add_htlc.idx = idx;     //転送先にとっては、prev_idxになる
    add_htlc.p_onion_reason = &p_htlc->buf_onion_reason;
    add_htlc.p_shared_secret = &p_htlc->buf_shared_secret;
    (*self->p_callback)(self, LN_CB_ADD_HTLC_RECV, &add_htlc);

    if (ret && hop_dataout.b_exit) {
        //final node
        LOGD("final node: backwind fulfill_htlc start\n");
        p_htlc->flag |= LN_HTLC_FLAG_FULFILLHTLC;
        ln_db_preimg_del(p_htlc->buf_payment_preimage.buf);

        if (!LN_DBG_FULFILL()) {
            LOGD("DBG: no fulfill mode\n");
            self->cnl_add_htlc[idx].flag &= LN_HTLC_FLAG_FULFILLHTLC;
        }
    } else if (!ret) {
        p_htlc->flag |= LN_HTLC_FLAG_FULFILLHTLC;
        switch (add_htlc.result) {
        case LN_CB_ADD_HTLC_RESULT_FAIL:
            LOGD("fail: backwind fail_htlc start: ");

            utl_buf_free(&p_htlc->buf_onion_reason);
            ln_onion_failure_create(&p_htlc->buf_onion_reason, &p_htlc->buf_shared_secret, &buf_reason);
            break;
        case LN_CB_ADD_HTLC_RESULT_MALFORMED:
            LOGD("fail: backwind malformed_htlc: ");

            p_htlc->flag |= LN_HTLC_FLAG_MALFORMED;
            utl_buf_free(&p_htlc->buf_onion_reason);
            utl_buf_alloccopy(&p_htlc->buf_onion_reason, buf_reason.buf, buf_reason.len);
            break;

        default:
            LOGD("fail: unknown fail: %d\n", add_htlc.result);
            assert(0);
            break;
        }
        DUMPD(buf_reason.buf, buf_reason.len);

    } else {
        //ret==true && not last node
    }
    utl_buf_free(&buf_reason);

    LOGD("END\n");
    return true;
}


static bool recv_update_fulfill_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_update_fulfill_htlc_t    fulfill_htlc;

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t preimage[LN_SZ_PREIMAGE];
    fulfill_htlc.p_channel_id = channel_id;
    fulfill_htlc.p_payment_preimage = preimage;
    ret = ln_msg_update_fulfill_htlc_read(&fulfill_htlc, pData, Len);
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

    uint8_t sha256[LN_SZ_HASH];
    btc_util_sha256(sha256, preimage, sizeof(preimage));

    ln_update_add_htlc_t *p_htlc = NULL;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //受信したfulfillは、Offered HTLCについてチェックする
        LOGD("HTLC%d: id=%" PRIu64 ", flag=%02x: ", idx, self->cnl_add_htlc[idx].id, self->cnl_add_htlc[idx].flag);
        DUMPD(self->cnl_add_htlc[idx].payment_sha256, LN_SZ_HASH);
        if ( (self->cnl_add_htlc[idx].id == fulfill_htlc.id) &&
             (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_OFFER) ) {
            if (memcmp(sha256, self->cnl_add_htlc[idx].payment_sha256, LN_SZ_HASH) == 0) {
                p_htlc = &self->cnl_add_htlc[idx];
            } else {
                LOGD("fail: match id, but fail payment_hash\n");
            }
            break;
        }
    }

    if (p_htlc != NULL) {
        //反映
        //self->our_msat -= p_htlc->amount_msat; //add_htlc送信時に引いているので、ここでは不要
        self->their_msat += p_htlc->amount_msat;
        self->uncommit = true;

        //update_fulfill_htlc受信通知
        ln_cb_fulfill_htlc_recv_t fulfill;
        fulfill.prev_short_channel_id = p_htlc->prev_short_channel_id;
        fulfill.prev_idx = p_htlc->prev_idx;
        fulfill.p_preimage = preimage;
        fulfill.id = p_htlc->id;
        (*self->p_callback)(self, LN_CB_FULFILL_HTLC_RECV, &fulfill);

        clear_htlc(self, p_htlc);
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
    ln_update_fail_htlc_t    fail_htlc;

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    utl_buf_t reason = UTL_BUF_INIT;

    fail_htlc.p_channel_id = channel_id;
    fail_htlc.p_reason = &reason;
    ret = ln_msg_update_fail_htlc_read(&fail_htlc, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        utl_buf_free(&reason);
        return false;
    }

    ret = false;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //受信したfail_htlcは、Offered HTLCについてチェックする
        if ( (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_OFFER) &&
             (self->cnl_add_htlc[idx].id == fail_htlc.id)) {
            //id一致
            self->our_msat += self->cnl_add_htlc[idx].amount_msat;
            self->uncommit = true;

            ln_cb_fail_htlc_recv_t fail_recv;
            fail_recv.prev_short_channel_id = self->cnl_add_htlc[idx].prev_short_channel_id;
            fail_recv.p_reason = &reason;
            fail_recv.p_shared_secret = &self->cnl_add_htlc[idx].buf_shared_secret;
            fail_recv.prev_idx = idx;
            fail_recv.orig_id = self->cnl_add_htlc[idx].id;     //元のHTLC id
            fail_recv.p_payment_hash = self->cnl_add_htlc[idx].payment_sha256;
            fail_recv.malformed_failure = 0;
            (*self->p_callback)(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);

            clear_htlc(self, &self->cnl_add_htlc[idx]);
            ret = true;
            break;
        }
    }

    utl_buf_free(&reason);

    return ret;
}


static bool recv_commitment_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_commit_signed_t commsig;
    ln_revoke_and_ack_t revack;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t bak_sig[LN_SZ_SIGNATURE];
    utl_buf_t buf_bolt = UTL_BUF_INIT;

    memcpy(bak_sig, self->commit_remote.signature, LN_SZ_SIGNATURE);
    commsig.p_channel_id = channel_id;
    commsig.p_signature = self->commit_remote.signature;
    commsig.p_htlc_signature = NULL;        //ln_msg_commit_signed_read()でMALLOCする
    ret = ln_msg_commit_signed_read(&commsig, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        goto LABEL_EXIT;
    }

    //channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_EXIT;
    }

    //署名チェック＋保存: To-Local
    ret = create_to_local(self, NULL, commsig.p_htlc_signature, commsig.num_htlcs,
                self->commit_remote.to_self_delay, self->commit_local.dust_limit_sat);
    UTL_DBG_FREE(commsig.p_htlc_signature);
    if (!ret) {
        LOGD("fail: create_to_local\n");
        goto LABEL_EXIT;
    }

    //自分のcommitment_numberをインクリメント
    self->commit_local.commit_num++;
    M_DBG_COMMITNUM(self);

    //commitment_signed受信フラグ
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat != 0) {
            self->cnl_add_htlc[idx].flag |= LN_HTLC_FLAG_COMMIT_RECV;
        }
    }

    uint8_t prev_secret[BTC_SZ_PRIVKEY];
    ln_signer_create_prev_percommitsec(self, prev_secret, NULL);

    //storage_indexデクリメントおよびper_commit_secret更新
    ln_signer_keys_update_storage(self);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);
    M_DB_SECRET_SAVE(self);

    //commitment_signed受信により、自分のcommit_txが確定する
    M_DB_SELF_SAVE(self);

    //チェックOKであれば、revoke_and_ackを返す
    //HTLCに変化がある場合、revoke_and_ack→commitment_signedの順で送信

    // //revokeするsecret
    // for (uint64_t index = 0; index <= self->commit_local.revoke_num + 1; index++) {
    //     uint8_t old_secret[BTC_SZ_PRIVKEY];
    //     ln_derkey_create_secret(old_secret, self->priv_data.storage_seed, LN_SECINDEX_INIT - index);
    //     LOGD("$$$ old_secret(%016" PRIx64 "): ", LN_SECINDEX_INIT -index);
    //     DUMPD(old_secret, sizeof(old_secret));
    // }

    revack.p_channel_id = channel_id;
    revack.p_per_commit_secret = prev_secret;
    revack.p_per_commitpt = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    LOGD("  revoke_and_ack.next_per_commitment_point=%" PRIu64 "\n", self->funding_local.current_commit_num);
    ret = ln_msg_revoke_and_ack_create(&buf_bolt, &revack);
    if (ret) {
        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        utl_buf_free(&buf_bolt);

        //最後に送信したrevoke_and_ackでのcommitment_numberを保持(channel_reestablish)
        self->commit_local.revoke_num = self->commit_local.commit_num - 1;
        M_DBG_COMMITNUM(self);
        M_DB_SELF_SAVE(self);

        //commitment_signed受信通知
        (*self->p_callback)(self, LN_CB_COMMIT_SIG_RECV, NULL);

        proc_rev_and_ack(self);
    } else {
        LOGD("fail: ln_msg_revoke_and_ack_create\n");
    }

LABEL_EXIT:
    //戻す
    if (!ret) {
        LOGD("fail restore\n");
        memcpy(self->commit_remote.signature, bak_sig, LN_SZ_SIGNATURE);
    }

    LOGD("END\n");
    return ret;
}


static bool recv_revoke_and_ack(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_revoke_and_ack_t revack;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t prev_secret[BTC_SZ_PRIVKEY];
    uint8_t new_commitpt[BTC_SZ_PUBKEY];
    uint8_t prev_commitpt[BTC_SZ_PUBKEY];

    revack.p_channel_id = channel_id;
    revack.p_per_commit_secret = prev_secret;
    revack.p_per_commitpt = new_commitpt;
    ret = ln_msg_revoke_and_ack_read(&revack, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        goto LABEL_EXIT;
    }

    //channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_EXIT;
    }

    //prev_secretチェック
    //  受信したper_commitment_secretが、前回受信したper_commitment_pointと等しいこと
    ret = btc_keys_priv2pub(prev_commitpt, prev_secret);
    if (!ret) {
        LOGD("fail: prev_secret convert\n");
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

    if (memcmp(prev_commitpt, self->funding_remote.prev_percommit, BTC_SZ_PUBKEY) != 0) {
        LOGD("fail: prev_secret mismatch\n");

        //check re-send
        if (memcmp(new_commitpt, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY) == 0) {
            //current per_commitment_point
            LOGD("skip: same as previous next_per_commitment_point\n");
            ret = true;
        } else {
            LOGD("recv secret: ");
            DUMPD(prev_commitpt, BTC_SZ_PUBKEY);
            LOGD("my secret: ");
            DUMPD(self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);
            ret = false;
        }
        goto LABEL_EXIT;
    }

    //prev_secret保存
    ret = store_peer_percommit_secret(self, prev_secret);
    if (!ret) {
        LOGD("fail: store prev secret\n");
        goto LABEL_EXIT;
    }

    //per_commitment_point更新
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], new_commitpt, BTC_SZ_PUBKEY);
    self->funding_remote.current_commit_num++;
    LOGD("  funding_remote.current_commit_num=%" PRIu64 "\n", self->funding_remote.current_commit_num);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(&self->funding_local, &self->funding_remote);

    self->commit_remote.revoke_num = self->commit_remote.commit_num - 1;
    M_DBG_COMMITNUM(self);
    M_DB_SELF_SAVE(self);

    //revoke_and_ack交換チェック
    proc_rev_and_ack(self);

LABEL_EXIT:
    LOGD("END\n");
    return ret;
}


static bool recv_update_fee(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    LOGD("BEGIN\n");

    bool ret;
    ln_update_fee_t upfee;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint32_t old_fee;

    upfee.p_channel_id = channel_id;
    ret = ln_msg_update_fee_read(&upfee, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        goto LABEL_EXIT;
    }

    //channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        goto LABEL_EXIT;
    }

    LOGD("change fee: %" PRIu32 " --> %" PRIu32 "\n", self->feerate_per_kw, upfee.feerate_per_kw);
    old_fee = self->feerate_per_kw;
    self->feerate_per_kw = upfee.feerate_per_kw;
    //M_DB_SELF_SAVE(self);    //確定するまでDB保存しない

    //fee更新通知
    (*self->p_callback)(self, LN_CB_UPDATE_FEE_RECV, &old_fee);

LABEL_EXIT:
    LOGD("END\n");
    return ret;
}


static bool recv_update_fail_malformed_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    (void)self; (void)pData; (void)Len;

    LOGD("BEGIN\n");

    ln_update_fail_malformed_htlc_t mal_htlc;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];

    mal_htlc.p_channel_id = channel_id;
    bool ret = ln_msg_update_fail_malformed_htlc_read(&mal_htlc, pData, Len);
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

    //failure_code check
    if ((mal_htlc.failure_code & LNERR_ONION_BADONION) == 0) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "no BADONION bit");
        return false;
    }

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //受信したmal_htlcは、Offered HTLCについてチェックする。
        //仕様としては、sha256_of_onionを確認し、再送か別エラーにするなので、
        //  ここでは受信したfailure_codeでエラーを作る。
        //
        // BOLT#02
        //  if the sha256_of_onion in update_fail_malformed_htlc doesn't match the onion it sent:
        //      MAY retry or choose an alternate error response.
        if ( (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_OFFER) &&
             (self->cnl_add_htlc[idx].id == mal_htlc.id)) {
            //id一致
            self->our_msat += self->cnl_add_htlc[idx].amount_msat;
            self->uncommit = true;

            utl_buf_t reason;
            utl_push_t push_rsn;
            utl_push_init(&push_rsn, &reason, sizeof(uint16_t) + BTC_SZ_SHA256);
            ln_misc_push16be(&push_rsn, mal_htlc.failure_code);
            utl_push_data(&push_rsn, mal_htlc.sha256_onion, BTC_SZ_SHA256);

            ln_cb_fail_htlc_recv_t fail_recv;
            fail_recv.prev_short_channel_id = self->cnl_add_htlc[idx].prev_short_channel_id;
            fail_recv.p_reason = &reason;
            fail_recv.p_shared_secret = &self->cnl_add_htlc[idx].buf_shared_secret;
            fail_recv.prev_idx = idx;
            fail_recv.orig_id = self->cnl_add_htlc[idx].id;     //元のHTLC id
            fail_recv.p_payment_hash = self->cnl_add_htlc[idx].payment_sha256;
            fail_recv.malformed_failure = mal_htlc.failure_code;
            (*self->p_callback)(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);
            utl_buf_free(&reason);

            clear_htlc(self, &self->cnl_add_htlc[idx]);
            ret = true;
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

    ln_channel_reestablish_t reest;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];

    reest.p_channel_id = channel_id;
    ret = ln_msg_channel_reestablish_read(&reest, pData, Len);
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

    M_DBG_COMMITNUM(self);
    uint8_t stat = comrev_state(self);

    //BOLT#02
    //  commit_txは、作成する関数内でcommit_num+1している(インクリメントはしない)。
    //  そのため、(commit_num+1)がcommit_tx作成時のcommitment numberである。

    //  next_local_commitment_number
    bool chk_commit_num = true;
    if (self->commit_remote.commit_num + 1 == reest.next_local_commitment_number) {
        LOGD("next_local_commitment_number: OK\n");
    } else if (self->commit_remote.commit_num == reest.next_local_commitment_number) {
        //  if next_local_commitment_number is equal to the commitment number of the last commitment_signed message the receiving node has sent:
        //      * MUST reuse the same commitment number for its next commitment_signed.
        LOGD("next_local_commitment_number == local commit_num: reuse\n");

        //remote.per_commitment_pointを1つ戻して、commitment_signedを再送する
        self->commit_remote.commit_num--;
        M_DBG_COMMITNUM(self);

        //1回以上commitment_signedを返している
        if (M_STAT_MASK_NUM(stat) >= 2) {
            LOGD("resend: commitment_signed\n");
            utl_buf_t buf_bolt = UTL_BUF_INIT;
            bool ret = create_commit_signed(self, &buf_bolt);
            if (ret) {
                (*self->p_callback)(self, LN_CB_SEND_QUEUE, &buf_bolt);
                LOGD("OK: re-send commigment_signed\n");
                //utl_buf_free(&buf_bolt);    //そのまま使うのでfreeしない
            } else {
                LOGD("fail: re-send commitment_signed\n");
                utl_buf_free(&buf_bolt);
            }
        } else {
            LOGD("reuse: commitment_number\n");
        }
    } else {
        // if next_local_commitment_number is not 1 greater than the commitment number of the last commitment_signed message the receiving node has sent:
        //      * SHOULD fail the channel.
        LOGD("number mismatch : FAIL\n");
        chk_commit_num = false;
    }

    //BOLT#02
    //  next_remote_revocation_number
    bool chk_revoke_num = true;
    if (self->commit_local.revoke_num + 1 == reest.next_remote_revocation_number) {
        LOGD("next_remote_revocation_number: OK\n");
    } else if (self->commit_local.revoke_num - 1 == reest.next_remote_revocation_number) {
        // if next_remote_revocation_number is equal to the commitment number of the last revoke_and_ack the receiving node sent, AND the receiving node hasn't already received a closing_signed:
        //      * MUST re-send the revoke_and_ack.
        LOGD("next_remote_revocation_number: \n");

        uint8_t prev_secret[BTC_SZ_PRIVKEY];
        ln_signer_create_prev_percommitsec(self, prev_secret, NULL);

        utl_buf_t buf_bolt = UTL_BUF_INIT;
        ln_revoke_and_ack_t revack;
        revack.p_channel_id = channel_id;
        revack.p_per_commit_secret = prev_secret;
        revack.p_per_commitpt = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
        LOGD("  send revoke_and_ack.next_per_commitment_point=%" PRIu64 "\n", self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
        ret = ln_msg_revoke_and_ack_create(&buf_bolt, &revack);
        if (ret) {
            (*self->p_callback)(self, LN_CB_SEND_QUEUE, &buf_bolt);
            LOGD("OK: re-send revoke_and_ack\n");
            //utl_buf_free(&buf_bolt);    //そのまま使うのでfreeしない
        } else {
            LOGD("fail: re-send revoke_and_ack\n");
            utl_buf_free(&buf_bolt);
        }
        utl_buf_free(&buf_bolt);
    } else {
        LOGD("number mismatch: FAIL\n");
        chk_revoke_num = false;
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
            LOGD("NG...\n");
            LOGD("secret: ");
            DUMPD(secret, BTC_SZ_PRIVKEY);
            LOGD("prevpt: ");
            DUMPD(self->funding_remote.prev_percommit, BTC_SZ_PUBKEY);
        }

#endif

    //BOLT#2
    //  if it supports option_data_loss_protect, AND the option_data_loss_protect fields are present:
    if ( !(chk_commit_num && chk_revoke_num) &&
         (mInitLocalFeatures[0] & INIT_LF_MASK_DATALOSS) &&
         reest.option_data_loss_protect ) {
        //if next_remote_revocation_number is greater than expected above,
        if (reest.next_remote_revocation_number > self->commit_local.commit_num) {
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
            if (memcmp(secret, reest.your_last_per_commitment_secret, BTC_SZ_PRIVKEY) == 0) {
                //MUST NOT broadcast its commitment transaction.
                //SHOULD fail the channel.
                //SHOULD store my_current_per_commitment_point to retrieve funds should the sending node broadcast its commitment transaction on-chain.
                LOGD("MUST NOT broadcast its commitment transaction\n");
            } else {
                //SHOULD fail the channel.
                LOGD("SHOULD fail the channel\n");
                ret = false;
                goto LABEL_EXIT;
            }
        } else {
            //SHOULD fail the channel.
            LOGD("SHOULD fail the channel\n");
            ret = false;
            goto LABEL_EXIT;
        }
    }

    //reestablish受信通知
    (*self->p_callback)(self, LN_CB_REESTABLISH_RECV, NULL);

LABEL_EXIT:
    return ret;
}


static bool recv_announcement_signatures(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    if (self->fund_flag == 0) {
        LOGD("fail: not open peer\n");
        return false;
    }

    if (self->cnl_anno.buf == NULL) {
        create_local_channel_announcement(self);
    }

    //channel_announcementを埋める
    btc_keys_sort_t sort = sort_nodeid(self, NULL);
    ln_msg_get_anno_signs(self, &p_sig_node, &p_sig_btc, false, sort);

    ln_announce_signs_t anno_signs;
    anno_signs.p_channel_id = channel_id;
    anno_signs.short_channel_id = self->short_channel_id;
    anno_signs.p_node_signature = p_sig_node;
    anno_signs.p_btc_signature = p_sig_btc;
    ret = ln_msg_announce_signs_read(&anno_signs, pData, Len);
    if (!ret || (anno_signs.short_channel_id == 0)) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //channel-idチェック
    ret = chk_channelid(channel_id, self->channel_id);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_CHANNEL, "channel_id not match");
        return false;
    }

    //0だった場合はfunding_lockedまでの値
    //0以外だった場合はln_msg_announce_signs_read()で一致していることを確認済み
    self->short_channel_id = anno_signs.short_channel_id;
    ret = ln_msg_cnl_announce_update_short_cnl_id(self, self->short_channel_id, sort);
    if (ret) {
        self->anno_flag |= M_ANNO_FLAG_RECV;
        proc_anno_sigs(self);
        M_DB_SELF_SAVE(self);
    } else {
        LOGD("fail: update short_channel_id\n");
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
    ln_cnl_announce_read_t ann;

    bool ret = ln_msg_cnl_announce_read(&ann, pData, Len);
    if (!ret || (ann.short_channel_id == 0)) {
        LOGD("fail: do nothing\n");
        return true;
    }

    utl_buf_t buf;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;

    //DB保存
    ret = ln_db_annocnl_save(&buf, ann.short_channel_id, ln_their_node_id(self),
                                ann.node_id1, ann.node_id2);
    ln_cb_update_annodb_t anno;
    if (ret) {
        LOGD("save channel_announcement: %016" PRIx64 "\n", ann.short_channel_id);
        anno.anno = LN_CB_UPDATE_ANNODB_CNL_ANNO;
    } else {
        anno.anno = LN_CB_UPDATE_ANNODB_NONE;
    }
    (*self->p_callback)(self, LN_CB_UPDATE_ANNODB, &anno);

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
    ln_cnl_update_t upd;
    memset(&upd, 0, sizeof(upd));

    ret = ln_msg_cnl_update_read(&upd, pData, Len);
    if (ret) {
        //timestamp check
        uint64_t now = (uint64_t)time(NULL);
        if (ln_db_annocnlupd_is_prune(now, upd.timestamp)) {
            //ret = false;
            char tmstr[UTL_SZ_DTSTR + 1];
            utl_misc_strftime(tmstr, upd.timestamp);
            LOGD("older channel: not save(%016" PRIx64 "): %s\n", upd.short_channel_id, tmstr);
            return true;
        }
    } else {
        LOGD("fail: decode\n");
        return true;
    }

    LOGV("recv channel_upd%d: %016" PRIx64 "\n", (int)(1 + (upd.flags & LN_CNLUPD_FLAGS_DIRECTION)), upd.short_channel_id);

    //short_channel_id と dir から node_id を取得する
    uint8_t node_id[BTC_SZ_PUBKEY];

    ret = get_nodeid_from_annocnl(self, node_id, upd.short_channel_id, upd.flags & LN_CNLUPD_FLAGS_DIRECTION);
    if (ret && btc_keys_chkpub(node_id)) {
        ret = ln_msg_cnl_update_verify(node_id, pData, Len);
        if (!ret) {
            LOGD("fail: verify\n");
        }
    } else {
        //該当するchannel_announcementが見つからない
        //  BOLT#11
        //      r fieldでchannel_update相当のデータを送信したい場合に備えて保持する
        //      https://lists.linuxfoundation.org/pipermail/lightning-dev/2018-April/001220.html
        LOGD("through: not found channel_announcement in DB, but save\n");
        ret = true;
    }

    ln_cb_update_annodb_t anno;
    anno.anno = LN_CB_UPDATE_ANNODB_NONE;
    if (ret) {
        //DB保存
        utl_buf_t buf;
        buf.buf = (CONST_CAST uint8_t *)pData;
        buf.len = Len;
        ret = ln_db_annocnlupd_save(&buf, &upd, ln_their_node_id(self));
        if (ret) {
            LOGD("save channel_update: %016" PRIx64 ":%d\n", upd.short_channel_id, upd.flags & LN_CNLUPD_FLAGS_DIRECTION);
            anno.anno = LN_CB_UPDATE_ANNODB_CNL_UPD;
        } else {
            LOGD("fail: db save\n");
        }
        ret = true;
    } else {
        //スルーするだけにとどめる
        ret = true;
    }
    (*self->p_callback)(self, LN_CB_UPDATE_ANNODB, &anno);

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
    ln_node_announce_t anno;
    uint8_t node_id[BTC_SZ_PUBKEY];
    char node_alias[LN_SZ_ALIAS + 1];

    anno.p_node_id = node_id;
    anno.p_alias = node_alias;
    ret = ln_msg_node_announce_read(&anno, pData, Len);
    if (!ret) {
        LOGD("fail: read message\n");
        return false;
    }

    LOGV("node_id:");
    DUMPV(node_id, sizeof(node_id));

    utl_buf_t buf_ann;
    buf_ann.buf = (CONST_CAST uint8_t *)pData;
    buf_ann.len = Len;
    ret = ln_db_annonod_save(&buf_ann, &anno, ln_their_node_id(self));
    if (ret) {
        LOGD("save node_announcement: ");
        DUMPD(anno.p_node_id, BTC_SZ_PUBKEY);

        ln_cb_update_annodb_t anno;
        anno.anno = LN_CB_UPDATE_ANNODB_NODE_ANNO;
        (*self->p_callback)(self, LN_CB_UPDATE_ANNODB, &anno);
    }

    return true;
}


static void send_error(ln_self_t *self, const ln_error_t *pError)
{
    utl_buf_t buf_bolt = UTL_BUF_INIT;
    ln_msg_error_create(&buf_bolt, pError);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    utl_buf_free(&buf_bolt);
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
    (*self->p_callback)(self, LN_CB_FUNDINGTX_WAIT, &funding);

    if (funding.b_result) {
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

/** P2WSH署名 - 2-of-2 トランザクション更新
 *
 * @param[in,out]   pTx         TX情報
 * @param[in]       Index
 * @param[in]       Sort
 * @param[in]       pSig1
 * @param[in]       pSig2
 * @param[in]       pWit2of2
 * @return      true:成功
 *
 * @note
 *      - pTx
 *      - #btc_util_create2of2()の公開鍵順序と、pSig1, pSig2の順序は同じにすること。
 *          例えば、先に自分のデータ、後に相手のデータ、など。
 */
static bool set_vin_p2wsh_2of2(btc_tx_t *pTx, int Index, btc_keys_sort_t Sort,
                    const utl_buf_t *pSig1,
                    const utl_buf_t *pSig2,
                    const utl_buf_t *pWit2of2)
{
    // 0
    // <sig1>
    // <sig2>
    // <script>
    const utl_buf_t wit0 = { NULL, 0 };
    const utl_buf_t *wits[] = {
        &wit0,
        NULL,
        NULL,
        pWit2of2
    };
    if (Sort == BTC_KEYS_SORT_ASC) {
        wits[1] = pSig1;
        wits[2] = pSig2;
    } else {
        wits[1] = pSig2;
        wits[2] = pSig1;
    }

    bool ret;

    ret = btc_sw_set_vin_p2wsh(pTx, Index, (const utl_buf_t **)wits, 4);
    return ret;
}


/** funding_tx作成
 *
 * @param[in,out]       self
 */
static bool create_funding_tx(ln_self_t *self, bool bSign)
{
    btc_tx_free(&self->tx_funding);

    //vout 2-of-2
    btc_util_create2of2(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING], self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);

#ifndef USE_SPV
    //output
    self->funding_local.txindex = M_FUNDING_INDEX;      //TODO: vout#0は2-of-2、vout#1はchangeにしている
    //vout#0:P2WSH - 2-of-2 : M_FUNDING_INDEX
    btc_sw_add_vout_p2wsh(&self->tx_funding, self->p_establish->cnl_open.funding_sat, &self->redeem_fund);

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
    //      wit_cnt: 2
    //          sig: 1+72
    //          pub: 1+33
    //      locktime: 4
#warning issue #344: nested in BIP16 size
    uint64_t fee = ln_calc_fee(LN_SZ_FUNDINGTX_VSIZE, self->p_establish->cnl_open.feerate_per_kw);
    LOGD("fee=%" PRIu64 "\n", fee);
    if (self->p_establish->p_fundin->amount >= self->p_establish->cnl_open.funding_sat + fee) {
        self->tx_funding.vout[1].value = self->p_establish->p_fundin->amount - self->p_establish->cnl_open.funding_sat - fee;
    } else {
        LOGD("fail: amount too short:\n");
        LOGD("    amount=%" PRIu64 "\n", self->p_establish->p_fundin->amount);
        LOGD("    funding_sat=%" PRIu64 "\n", self->p_establish->cnl_open.funding_sat);
        LOGD("    fee=%" PRIu64 "\n", fee);
        return false;
    }
#else
    //SPVの場合、fee計算と署名はSPVに任せる(LN_CB_SIGN_FUNDINGTX_REQで吸収する)
    //その代わり、self->funding_local.txindexは固定値にならない。
#endif

    //署名
    bool ret;
    if (bSign) {
        ln_cb_funding_sign_t sig;
        sig.p_tx =  &self->tx_funding;
#ifndef USE_SPV
        sig.amount = self->p_establish->p_fundin->amount;
#else
        //SPVは未使用
        sig.amount = 0;
#endif
        (*self->p_callback)(self, LN_CB_SIGN_FUNDINGTX_REQ, &sig);
        ret = sig.ret;
        if (ret) {
            btc_tx_txid(self->funding_local.txid, &self->tx_funding);
        } else {
            LOGD("fail: signature\n");
        }

        LOGD("***** funding_tx *****\n");
        M_DBG_PRINT_TX(&self->tx_funding);
    } else {
        //not sign
        ret = true;
    }

    return ret;
}


/** 自分用commitment transaction作成
 *
 * 自分用(自分が送信することができる)commit_txの署名および受信署名のverifyを行う。
 * また、unilateral closeする際に必要となるデータを作成する。
 *      - funding_created/funding_signed受信による署名verify
 *      - commitment_signed受信による署名verify
 *      - 自分がunilateral closeを行った際に取り戻すtx作成
 *          - to_local output
 *          - 各HTLC output
 *
 *   1. to_local script作成
 *   2. HTLC情報設定
 *   3. commit_tx作成 + 署名 + txid計算
 *   4. commit_txの送金先処理
 *   5. メモリ解放
 *
 * @param[in,out]       self
 * @param[out]          pClose              非NULL:自分がunilateral closeした情報を返す
 * @param[in]           p_htlc_sigs         commitment_signedで受信したHTLCの署名(NULL時はHTLC署名無し)
 * @param[in]           htlc_sigs_num       p_htlc_sigsの署名数
 * @param[in]           to_self_delay       remoteのto_self_delay
 * @param[in]           dust_limit_sat      localのdust_limit_sat
 * @retval      true    成功
 * @note
 *      - pubkeys[MSG_FUNDIDX_PER_COMMIT]にはself->funding_local.current_commit_numに対応するper_commitment_pointが入っている前提。
 */
static bool create_to_local(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat)
{
    LOGD("BEGIN\n");

    bool ret;
    utl_buf_t buf_ws = UTL_BUF_INIT;
    utl_buf_t buf_sig = UTL_BUF_INIT;
    ln_feeinfo_t feeinfo;
    ln_tx_cmt_t lntx_commit;
    btc_tx_t tx_commit = BTC_TX_INIT;

    //To-Local
    ln_create_script_local(&buf_ws,
                self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                to_self_delay);

    //HTLC
    ln_htlcinfo_t **pp_htlcinfo = (ln_htlcinfo_t **)UTL_DBG_MALLOC(sizeof(ln_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            pp_htlcinfo[cnt] = (ln_htlcinfo_t *)UTL_DBG_MALLOC(sizeof(ln_htlcinfo_t));
            ln_htlcinfo_init(pp_htlcinfo[cnt]);
            if (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_RECV) {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_RECEIVED;
            } else {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_OFFERED;
            }
            pp_htlcinfo[cnt]->add_htlc_idx = idx;
            pp_htlcinfo[cnt]->expiry = self->cnl_add_htlc[idx].cltv_expiry;
            pp_htlcinfo[cnt]->amount_msat = self->cnl_add_htlc[idx].amount_msat;
            pp_htlcinfo[cnt]->preimage_hash = self->cnl_add_htlc[idx].payment_sha256;
            LOGD(" [%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, self->cnl_add_htlc[idx].id, self->cnl_add_htlc[idx].amount_msat);
            cnt++;
        }
    }
    LOGD("-------\n");
    LOGD("cnt=%d, htlc_num=%d\n", cnt, self->htlc_num);
    LOGD("our_msat   %" PRIu64 " --> %" PRIu64 "\n", self->our_msat, self->our_msat);
    LOGD("their_msat %" PRIu64 " --> %" PRIu64 "\n", self->their_msat, self->their_msat);
    for (int lp = 0; lp < cnt; lp++) {
        LOGD("  [%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type == LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //FEE
    feeinfo.feerate_per_kw = self->feerate_per_kw;
    feeinfo.dust_limit_satoshi = dust_limit_sat;
    ln_fee_calc(&feeinfo, (const ln_htlcinfo_t **)pp_htlcinfo, cnt);

    //scriptPubKey作成
    for (int lp = 0; lp < cnt; lp++) {
        ln_create_htlcinfo(&pp_htlcinfo[lp]->script,
                        pp_htlcinfo[lp]->type,
                        self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                        self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                        self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                        pp_htlcinfo[lp]->preimage_hash,
                        pp_htlcinfo[lp]->expiry);
    }

    //commitment transaction
    lntx_commit.fund.txid = self->funding_local.txid;
    lntx_commit.fund.txid_index = self->funding_local.txindex;
    lntx_commit.fund.satoshi = self->funding_sat;
    lntx_commit.fund.p_script = &self->redeem_fund;
    lntx_commit.local.satoshi = LN_MSAT2SATOSHI(self->our_msat);
    lntx_commit.local.p_script = &buf_ws;
    lntx_commit.remote.satoshi = LN_MSAT2SATOSHI(self->their_msat);
    lntx_commit.remote.pubkey = self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY];
    lntx_commit.obscured = self->obscured ^ self->funding_local.current_commit_num;
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;

    LOGD("local commitment_number=%016" PRIx64 "\n", self->funding_local.current_commit_num);
    ret = ln_create_commit_tx(&tx_commit, &buf_sig, &lntx_commit, ln_is_funder(self), &self->priv_data);
    if (ret) {
        ret = create_to_local_sign(self, &tx_commit, &buf_sig);
    } else {
        LOGD("fail\n");
    }
    if (ret) {
        ret = btc_tx_txid(self->commit_local.txid, &tx_commit);
        LOGD("local commit_txid: ");
        TXIDD(self->commit_local.txid);
    }

    if (ret) {
        if (tx_commit.vout_cnt > 0) {
            ret = create_to_local_spent(self, pClose,
                        p_htlc_sigs, htlc_sigs_num,
                        &tx_commit, &buf_ws,
                        (const ln_htlcinfo_t **)pp_htlcinfo,
                        &feeinfo,
                        to_self_delay);
        } else {
            self->commit_local.htlc_num = 0;
        }
    }


    LOGD("free: ret=%d\n", ret);
    utl_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_htlcinfo_free(pp_htlcinfo[lp]);
        UTL_DBG_FREE(pp_htlcinfo[lp]);
    }
    UTL_DBG_FREE(pp_htlcinfo);

    utl_buf_free(&buf_sig);
    if (pClose != NULL) {
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
    } else {
        btc_tx_free(&tx_commit);
    }

    return ret;
}


/** commit_tx署名
 *
 * @param[in,out]   self
 * @param[in,out]   pTxCommit   [in]commit_tx(署名無し) / [out]commit_tx(署名あり)
 * @param[in]       pBufSig     相手の署名
 * @retval  true    成功
 */
static bool create_to_local_sign(ln_self_t *self,
                    btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufSig)
{
    LOGD("local sign\n");

    bool ret;
    utl_buf_t buf_sig_from_remote = UTL_BUF_INIT;
    utl_buf_t script_code = UTL_BUF_INIT;
    uint8_t sighash[BTC_SZ_SIGHASH];

    //署名追加
    ln_misc_sigexpand(&buf_sig_from_remote, self->commit_remote.signature);
    set_vin_p2wsh_2of2(pTxCommit, 0, self->key_fund_sort,
                            pBufSig,
                            &buf_sig_from_remote,
                            &self->redeem_fund);
    LOGD("++++++++++++++ 自分のcommit txに署名: [%016" PRIx64 "]\n", self->short_channel_id);
    M_DBG_PRINT_TX(pTxCommit);

    // 署名verify
    btc_sw_scriptcode_p2wsh(&script_code, &self->redeem_fund);
    ret = btc_sw_sighash(sighash, pTxCommit, 0, self->funding_sat, &script_code);
    if (ret) {
        ret = btc_sw_verify_2of2(pTxCommit, 0, sighash,
                &self->tx_funding.vout[self->funding_local.txindex].script);
    }

    utl_buf_free(&buf_sig_from_remote);
    utl_buf_free(&script_code);

    return ret;
}


/** local commit_txの送金先処理
 *
 * commitment_signedとclose処理で共用している。
 * commitment_signedの場合は、HTLC Success/Timeout Tx署名のみ必要。
 *
 *  1. [close]HTLC署名用local_htlcsecret取得
 *  2. voutごとの処理
 *      2.1. vout indexから対応するpp_htlcinfo[]を得る --> htlc_idx
 *      2.2. htlc_idxで分岐
 *          2.2.1. [to_local]
 *              -# [close]to_local tx作成 + 署名 --> 戻り値
 *          2.2.2. [to_remote]
 *              -# 処理なし
 *          2.2.3. [各HTLC]
 *              -# fee計算
 *              -# commit_txのvout amountが、dust + fee以上
 *                  -# HTLC tx作成
 *                  -# [署名inputあり]
 *                      - commitment_signedで受信したhtlc_signatureのverify
 *                      - HTLC txのverify
 *                      - verify失敗なら、3へ飛ぶ
 *                      - signatureの保存
 *                  -# [close]
 *                      - commit_txの送金先 tx作成 + 署名 --> 戻り値
 *  3. [署名inputあり]input署名数と処理したHTLC数が不一致なら、エラー
 *
 * @param[in,out]   self
 * @param[out]      pClose
 * @param[in]       p_htlc_sigs
 * @param[in]       htlc_sigs_num
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       pp_htlcinfo
 * @param[in]       p_feeinfo
 * @param[in]       to_self_delay
 * @retval  true    成功
 */
static bool create_to_local_spent(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo,
                    uint32_t to_self_delay)
{
    bool ret = true;
    int htlc_num = 0;
    btc_tx_t *pTxToLocal = NULL;
    btc_tx_t *pTxHtlcs = NULL;
    utl_push_t push;
    btc_util_keys_t htlckey;

    LOGD("local spent: local.current_commit_num=%" PRIu64 "\n", self->funding_local.current_commit_num);

    if (pClose != NULL) {
        pTxToLocal = &pClose->p_tx[LN_CLOSE_IDX_TOLOCAL];
        pTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];

        utl_push_init(&push, &pClose->tx_buf, 0);

        //HTLC署名用鍵
        ln_signer_get_secret(self, &htlckey, MSG_FUNDIDX_HTLC,
            self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
        assert(memcmp(htlckey.pub, self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY], BTC_SZ_PUBKEY) == 0);
    } else {
        push.data = NULL;
    }

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint8_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_HTLCTYPE_TOLOCAL) {
            LOGD("+++[%d]to_local\n", vout_idx);
            if (pTxToLocal != NULL) {
                btc_tx_t tx = BTC_TX_INIT;

                //vout.valueはfeeが引かれた値
                ret = ln_create_tolocal_spent(self, &tx, pTxCommit->vout[vout_idx].value, to_self_delay,
                        pBufWs, self->commit_local.txid, vout_idx, false);
                if (ret) {
                    M_DBG_PRINT_TX(&tx);
                    memcpy(pTxToLocal, &tx, sizeof(tx));
                    btc_tx_init(&tx);     //txはfreeさせない
                } else {
                    btc_tx_free(&tx);
                }
            }
        } else if (htlc_idx == LN_HTLCTYPE_TOREMOTE) {
            LOGD("+++[%d]to_remote\n", vout_idx);
        } else {
            const ln_htlcinfo_t *p_htlcinfo = pp_htlcinfo[htlc_idx];
            uint64_t fee_sat = (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? p_feeinfo->htlc_timeout : p_feeinfo->htlc_success;
            if (pTxCommit->vout[vout_idx].value >= p_feeinfo->dust_limit_satoshi + fee_sat) {
                LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? "offered" : "received");
                btc_tx_t tx = BTC_TX_INIT;

                ln_create_htlc_tx(&tx, pTxCommit->vout[vout_idx].value - fee_sat, pBufWs,
                            p_htlcinfo->type, p_htlcinfo->expiry,
                            self->commit_local.txid, vout_idx);
                M_DBG_PRINT_TX2(&tx);

                if ((p_htlc_sigs != NULL) && (htlc_sigs_num != 0)) {
                    //署名チェック
                    utl_buf_t buf_sig;
                    ln_misc_sigexpand(&buf_sig, p_htlc_sigs + htlc_num * LN_SZ_SIGNATURE);
                    ret = ln_verify_htlc_tx(&tx,
                                pTxCommit->vout[vout_idx].value,
                                NULL,
                                self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                                NULL,
                                &buf_sig,
                                &p_htlcinfo->script);
                    utl_buf_free(&buf_sig);
                    if (!ret) {
                        LOGD("fail: verify vout[%d]\n", vout_idx);
                        btc_tx_free(&tx);
                        break;
                    }

                    //OKなら各HTLCに保持
                    //  相手がunilateral closeした後に送信しなかったら、この署名を使う
                    memcpy(self->cnl_add_htlc[p_htlcinfo->add_htlc_idx].signature, p_htlc_sigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
                }

                if (pClose != NULL) {
                    const uint8_t *p_payhash = self->cnl_add_htlc[p_htlcinfo->add_htlc_idx].payment_sha256;
                    const uint8_t *p_sig = self->cnl_add_htlc[p_htlcinfo->add_htlc_idx].signature;
                    ret = create_to_local_close(self,
                                    pTxHtlcs, &tx, &push,
                                    pTxCommit, pBufWs,
                                    p_htlcinfo, &htlckey,
                                    htlc_num, vout_idx,
                                    p_payhash, p_sig,
                                    to_self_delay);
                    if (ret) {
                        pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                    } else {
                        LOGD("fail: sign vout[%d]\n", vout_idx);
                        break;
                    }
                }
                btc_tx_free(&tx);

                htlc_num++;
            } else {
                LOGD("cut HTLC[%d] %" PRIu64 " > %" PRIu64 "\n",
                            vout_idx, pTxCommit->vout[vout_idx].value,
                            p_feeinfo->dust_limit_satoshi + fee_sat);
            }
        }
    }

    if ((p_htlc_sigs != NULL) && (htlc_num != htlc_sigs_num)) {
        LOGD("署名数不一致: %d, %d\n", htlc_num, htlc_sigs_num);
        ret = false;
    }

    self->commit_local.htlc_num = htlc_num;

    return ret;
}


/** local close用HTLC作成
 *
 *  1. input署名をASN.1形式に展開
 *  2. [received HTLC]DBからpreimage検索
 *  3. HTLC Success/Timeout tx署名(呼び元でtx作成済み)
 *      - エラー時はここで終了
 *  4. [(received HTLC && preimageあり) || offered HTLC]
 *      -# 署名したHTLC txを処理結果にコピー
 *      -# HTLC txの送金を取り戻すtxを作成 + 署名(形はto_localと同じ) --> キューに積む
 *
 * @param[in,out]   self
 * @param[out]      pTxHtlcs        処理結果のHTLC tx配列(末尾に追加)
 * @param[in,out]   pTxHtlc         [in]処理中のHTLC tx(署名無し) / [out]HTLC tx(署名あり)
 * @param[out]      pPush           HTLC txから取り戻すtx
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       pp_htlcinfo
 * @param[in]       pHtlcKey
 * @param[in]       htlc_num
 * @param[in]       vout_idx
 * @param[in]       pPayHash
 * @param[in]       pSig
 * @param[in]       to_self_delay
 * @retval  true    成功
 */
static bool create_to_local_close(ln_self_t *self,
                    btc_tx_t *pTxHtlcs,
                    btc_tx_t *pTxHtlc,
                    utl_push_t *pPush,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const btc_util_keys_t *pHtlcKey,
                    uint8_t htlc_num,
                    int vout_idx,
                    const uint8_t *pPayHash,
                    const uint8_t *pSig,
                    uint32_t to_self_delay)
{
    bool ret;

    utl_buf_t buf_sig;
    ln_misc_sigexpand(&buf_sig, pSig);

    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    if (p_htlcinfo->type == LN_HTLCTYPE_RECEIVED) {
        //Receivedであればpreimageを所持している可能性がある
        ret_img = search_preimage(preimage, pPayHash, true);
        LOGD("[received]%d\n", ret_img);
    } else {
        ret_img = false;
        LOGD("[offered]%d\n", ret_img);
    }

    //署名:HTLC Success/Timeout Transaction
    utl_buf_t buf_local_sig;
    ret = ln_sign_htlc_tx(pTxHtlc,
                &buf_local_sig,                 //<localsig>
                pTxCommit->vout[vout_idx].value,
                pHtlcKey,
                &buf_sig,                       //<remotesig>
                (ret_img) ? preimage : NULL,
                &p_htlcinfo->script,
                LN_HTLCSIGN_TO_SUCCESS);
    utl_buf_free(&buf_sig);
    utl_buf_free(&buf_local_sig);
    if (!ret) {
        LOGD("fail: ln_sign_htlc_tx: vout[%d]\n", vout_idx);
        return false;
    }

    if ( ((p_htlcinfo->type == LN_HTLCTYPE_RECEIVED) && ret_img) ||
            (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ) {
        LOGD("create HTLC tx[%d]\n", htlc_num);
        M_DBG_PRINT_TX2(pTxHtlc);
        memcpy(&pTxHtlcs[htlc_num], pTxHtlc, sizeof(btc_tx_t));

        // HTLC Timeout/Success Txを作った場合はそれを取り戻すトランザクションも作る
        btc_tx_t tx = BTC_TX_INIT;
        uint8_t txid[BTC_SZ_TXID];
        btc_tx_txid(txid, pTxHtlc);
        //pTxHtlc->vout[0].valueはfeeが引かれた値
        ret = ln_create_tolocal_spent(self, &tx,
                    pTxHtlc->vout[0].value, to_self_delay,
                    pBufWs, txid, 0, false);
        if (ret) {
            LOGD("*** HTLC out Tx ***\n");
            M_DBG_PRINT_TX2(&tx);

            //HTLC txから取り戻すtxをキューに積む
            utl_push_data(pPush, &tx, sizeof(btc_tx_t));
        } else {
            btc_tx_free(&tx);
            ret = true;     //no to_local
        }
        btc_tx_init(pTxHtlc);     //txはfreeさせない(pTxHtlcsに任せる)
    } else {
        LOGD("skip create HTLC tx[%d]\n", htlc_num);
        btc_tx_init(&pTxHtlcs[htlc_num]);
    }

    return ret;
}


/** 相手用 commitment transaction作成
 *
 * 相手用(相手が送信することができる)commit_txの署名、および関連するトランザクションの署名を行う。
 *      - funding_created/funding_singed用の署名作成
 *      - commitment_signed用の署名作成
 *      - 相手がunilateral closeを行った際に取り戻すtx作成
 *          - to_remote output
 *          - 各HTLC output
 *
 * 作成した署名は、To-Localはself->commit_local.signatureに、HTLCはself->cnl_add_htlc[].signature 代入する
 *
 *   1. to_local script作成
 *   2. HTLC情報設定
 *          - 相手がugly closeした場合のためにpreimage_hashをDB保存
 *   3. commit_tx作成 + 署名 + txid計算
 *   4. commit_txの送金先処理
 *   5. メモリ解放
 *
 * @param[in,out]       self
 * @param[out]          pClose              非NULL:相手がunilateral closeした場合の情報を返す
 * @param[out]          pp_htlc_sigs        commitment_signed送信用署名(NULLの場合は代入しない)
 * @param[in]           to_self_delay       localのto_self_delay
 * @param[in]           dust_limit_sat      remoteのdust_limit_sat
 * @retval  true    成功
 */
static bool create_to_remote(ln_self_t *self,
                    ln_close_force_t *pClose,
                    uint8_t **pp_htlc_sigs,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat)
{
    LOGD("BEGIN\n");

    bool ret;
    utl_buf_t buf_ws = UTL_BUF_INIT;
    utl_buf_t buf_sig = UTL_BUF_INIT;
    ln_feeinfo_t feeinfo;
    ln_tx_cmt_t lntx_commit;
    btc_tx_t tx_commit = BTC_TX_INIT;

    //To-Local(Remote)
    ln_create_script_local(&buf_ws,
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                to_self_delay);

    //HTLC(Remote)
    ln_htlcinfo_t **pp_htlcinfo = (ln_htlcinfo_t **)UTL_DBG_MALLOC(sizeof(ln_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;    //commit_txのvout数
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            pp_htlcinfo[cnt] = (ln_htlcinfo_t *)UTL_DBG_MALLOC(sizeof(ln_htlcinfo_t));
            ln_htlcinfo_init(pp_htlcinfo[cnt]);
            //OFFEREDとRECEIVEDが逆になる
            if (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_RECV) {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_OFFERED;
            } else {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_RECEIVED;
            }
            pp_htlcinfo[cnt]->add_htlc_idx = idx;
            pp_htlcinfo[cnt]->expiry = self->cnl_add_htlc[idx].cltv_expiry;
            pp_htlcinfo[cnt]->amount_msat = self->cnl_add_htlc[idx].amount_msat;
            pp_htlcinfo[cnt]->preimage_hash = self->cnl_add_htlc[idx].payment_sha256;
            LOGD(" [%d][id=%" PRIu64 "](%p)\n", idx, self->cnl_add_htlc[idx].id, self);
            cnt++;
        }
    }
    LOGD("-------\n");
    LOGD("cnt=%d, htlc_num=%d\n", cnt, self->htlc_num);
    LOGD("(remote)our_msat   %" PRIu64 " --> %" PRIu64 "\n", self->their_msat, self->their_msat);
    LOGD("(remote)their_msat %" PRIu64 " --> %" PRIu64 "\n", self->our_msat, self->our_msat);
    for (int lp = 0; lp < cnt; lp++) {
        LOGD("  have HTLC[%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type != LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //FEE(Remote)
    feeinfo.feerate_per_kw = self->feerate_per_kw;
    feeinfo.dust_limit_satoshi = dust_limit_sat;
    ln_fee_calc(&feeinfo, (const ln_htlcinfo_t **)pp_htlcinfo, cnt);

    //scriptPubKey作成(Remote)
    for (int lp = 0; lp < cnt; lp++) {
        ln_create_htlcinfo(&pp_htlcinfo[lp]->script,
                        pp_htlcinfo[lp]->type,
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                        pp_htlcinfo[lp]->preimage_hash,
                        pp_htlcinfo[lp]->expiry);

#ifdef LN_UGLY_NORMAL
        //payment_hash, type, expiry保存
        uint8_t vout[LNL_SZ_WITPROG_WSH];
        btc_sw_wit2prog_p2wsh(vout, &pp_htlcinfo[lp]->script);
        ln_db_phash_save(pp_htlcinfo[lp]->preimage_hash,
                        vout,
                        pp_htlcinfo[lp]->type,
                        pp_htlcinfo[lp]->expiry);
#endif  //LN_UGLY_NORMAL
    }

    //commitment transaction(Remote)
    lntx_commit.fund.txid = self->funding_local.txid;
    lntx_commit.fund.txid_index = self->funding_local.txindex;
    lntx_commit.fund.satoshi = self->funding_sat;
    lntx_commit.fund.p_script = &self->redeem_fund;
    lntx_commit.local.satoshi = LN_MSAT2SATOSHI(self->their_msat);
    lntx_commit.local.p_script = &buf_ws;
    lntx_commit.remote.satoshi = LN_MSAT2SATOSHI(self->our_msat);
    lntx_commit.remote.pubkey = self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY];
    lntx_commit.obscured = self->obscured ^ self->funding_remote.current_commit_num;
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;

    LOGD("remote commitment_number=%016" PRIx64 "\n", self->funding_remote.current_commit_num);
    ret = ln_create_commit_tx(&tx_commit, &buf_sig, &lntx_commit, !ln_is_funder(self), &self->priv_data);
    if (ret) {
        LOGD("++++++++++++++ 相手のcommit tx: tx_commit[%016" PRIx64 "]\n", self->short_channel_id);
        M_DBG_PRINT_TX(&tx_commit);

        ret = btc_tx_txid(self->commit_remote.txid, &tx_commit);
        LOGD("remote commit_txid: ");
        TXIDD(self->commit_remote.txid);
    }

    if (ret) {
        //送信用 commitment_signed.signature
        ln_misc_sigtrim(self->commit_local.signature, buf_sig.buf);
    }

    if (ret) {
        if (cnt > 0) {
            uint8_t *p_htlc_sigs = NULL;
            if (pp_htlc_sigs != NULL) {
                //送信用 commitment_signed.htlc_signature
                *pp_htlc_sigs = (uint8_t *)UTL_DBG_MALLOC(LN_SZ_SIGNATURE * cnt);
                p_htlc_sigs = *pp_htlc_sigs;
            }
            ret = create_to_remote_spent(self, pClose,
                        p_htlc_sigs,
                        &tx_commit, &buf_ws,
                        (const ln_htlcinfo_t **)pp_htlcinfo,
                        &feeinfo);
        } else {
            self->commit_remote.htlc_num = 0;
        }
    }

    LOGD("free: ret=%d\n", ret);
    utl_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_htlcinfo_free(pp_htlcinfo[lp]);
        UTL_DBG_FREE(pp_htlcinfo[lp]);
    }
    UTL_DBG_FREE(pp_htlcinfo);

    utl_buf_free(&buf_sig);
    if (pClose != NULL) {
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(btc_tx_t));
    } else {
        btc_tx_free(&tx_commit);
    }

    return ret;
}


/** remote commit_txの送金先処理
 *
 *  1. [close]HTLC署名用local_htlcsecret取得
 *  2. voutごとの処理
 *      2.1. vout indexから対応するpp_htlcinfo[]を得る --> htlc_idx
 *      2.2. htlc_idxで分岐
 *          2.2.1. [to_local]
 *              -# 処理なし
 *          2.2.2. [to_remote]
 *              -# [close]to_remote tx作成 + 署名 --> 戻り値
 *          2.2.3. [各HTLC]
 *              -# fee計算
 *              -# commit_txのvout amountが、dust + fee以上
 *                  -# HTLC tx作成 + 署名 --> 戻り値
 *
 * @param[in,out]   self
 * @param[out]      pClose
 * @param[out]      p_htlc_sigs
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       pp_htlcinfo
 * @param[in]       p_feeinfo
 * @retval  true    成功
 */
static bool create_to_remote_spent(ln_self_t *self,
                    ln_close_force_t *pClose,
                    uint8_t *p_htlc_sigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo)
{
    bool ret = true;
    uint8_t htlc_num = 0;

    LOGD("remote spent: remote.current_commit_num=%" PRIu64 "\n", self->funding_remote.current_commit_num);

    btc_tx_t *pTxHtlcs = NULL;
    if (pClose != NULL) {
        pTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];
    }

    utl_buf_t buf_remotesig = UTL_BUF_INIT;
    ln_misc_sigexpand(&buf_remotesig, self->commit_remote.signature);

    //HTLC署名用鍵
    btc_util_keys_t htlckey;
    ln_signer_get_secret(self, &htlckey, MSG_FUNDIDX_HTLC,
                self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        //各HTLCのHTLC Timeout/Success Transactionを作って署名するために、
        //BIP69ソート後のtx_commit.voutからpp_htlcinfo[]のindexを取得する
        uint8_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_HTLCTYPE_TOLOCAL) {
            LOGD("---[%d]to_local\n", vout_idx);
        } else if (htlc_idx == LN_HTLCTYPE_TOREMOTE) {
            LOGD("---[%d]to_remote\n", vout_idx);
            if (pClose != NULL) {
                btc_tx_t tx = BTC_TX_INIT;

                ret = ln_create_toremote_spent(self, &tx, pTxCommit->vout[vout_idx].value,
                            self->commit_remote.txid, vout_idx);
                if (ret) {
                    M_DBG_PRINT_TX2(&tx);
                    memcpy(&pClose->p_tx[LN_CLOSE_IDX_TOREMOTE], &tx, sizeof(tx));
                    btc_tx_init(&tx);     //txはfreeさせない
                } else {
                    LOGD("no to_remote output\n");
                    btc_tx_free(&tx);
                    ret = true;     //継続する
                }
            }
        } else {
            const ln_htlcinfo_t *p_htlcinfo = pp_htlcinfo[htlc_idx];
            const uint8_t *p_payhash = self->cnl_add_htlc[p_htlcinfo->add_htlc_idx].payment_sha256;
            uint64_t fee_sat = (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? p_feeinfo->htlc_timeout : p_feeinfo->htlc_success;
            if (pTxCommit->vout[vout_idx].value >= p_feeinfo->dust_limit_satoshi + fee_sat) {
                ret = create_to_remote_htlcsign(self,
                                pTxHtlcs, p_htlc_sigs,
                                pTxCommit, pBufWs,
                                p_htlcinfo, &htlckey,
                                &buf_remotesig, fee_sat,
                                htlc_num, vout_idx, p_payhash,
                                (pClose != NULL));
                if (ret) {
                    if (pClose != NULL) {
                        pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                    }
                } else {
                    LOGD("fail: sign vout[%d]\n", vout_idx);
                    break;
                }

                htlc_num++;
            } else {
                LOGD("cut HTLC[%d] %" PRIu64 " > %" PRIu64 "\n",
                            vout_idx, pTxCommit->vout[vout_idx].value,
                            p_feeinfo->dust_limit_satoshi + fee_sat);
            }
        }
    }
    utl_buf_free(&buf_remotesig);

    self->commit_remote.htlc_num = htlc_num;

    return ret;
}


/** remote HTLC署名作成
 *
 *  1. HTLC tx作成
 *  2. HTLC Success txを作成する予定にする
 *  3. HTLC種別での分岐
 *      3.1 [offered HTLC]preimage検索
 *          - [close && 検索成功]
 *              - preimageがあるofferedなので、即時broadcast可能tx作成にする
 *      3.2 [else]
 *          - [close]
 *              - HTLC Timeout tx作成にする
 *  4. HTLC tx署名
 *  5. [close]
 *      5.1. [(offered HTLC && preimageあり) || received HTLC]
 *          -# 署名したHTLC txを処理結果にコピー
 *
 * @param[in,out]   self
 * @param[out]      pTxHtlcs        処理結果のHTLC tx配列(末尾に追加)
 * @param[out]      p_htlc_sigs     HTLC署名
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       p_htlcinfo
 * @param[in]       pHtlcKey
 * @param[in]       pBufRemoteSig
 * @param[in]       fee
 * @param[in]       htlc_num
 * @param[in]       vout_idx
 * @param[in]       pPayHash
 * @param[in]       bClosing        true:close処理
 * @retval  true    成功
 */
static bool create_to_remote_htlcsign(ln_self_t *self,
                    btc_tx_t *pTxHtlcs,
                    uint8_t *p_htlc_sigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const btc_util_keys_t *pHtlcKey,
                    const utl_buf_t *pBufRemoteSig,
                    uint64_t fee,
                    uint8_t htlc_num,
                    int vout_idx,
                    const uint8_t *pPayHash,
                    bool bClosing)
{
    bool ret;
    btc_tx_t tx = BTC_TX_INIT;

    LOGD("---[%d]%s HTLC\n", vout_idx, (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? "offered" : "received");
    ln_create_htlc_tx(&tx, pTxCommit->vout[vout_idx].value - fee, pBufWs,
                p_htlcinfo->type, p_htlcinfo->expiry,
                self->commit_remote.txid, vout_idx);
    M_DBG_PRINT_TX2(&tx);

    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    ln_htlcsign_t htlcsign = LN_HTLCSIGN_TO_SUCCESS;
    if (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) {
        //remoteのoffered=localのreceivedなのでpreimageを所持している可能性がある
        ret_img = search_preimage(preimage, pPayHash, bClosing);
        LOGD("[offered]%d\n", ret_img);
        if (ret_img && (pTxHtlcs != NULL)) {
            //offeredかつpreimageがあるので、即時使用可能
            utl_buf_free(&tx.vout[0].script);      //HTLC Success Txを止める
            //close時の出力先に変更
            utl_buf_alloccopy(&tx.vout[0].script,
                    self->shutdown_scriptpk_local.buf, self->shutdown_scriptpk_local.len);
            tx.locktime = 0;
            htlcsign = LN_HTLCSIGN_OF_PREIMG;
        }
    } else {
        ret_img = false;
        LOGD("[received]%d\n", ret_img);
        if (pTxHtlcs != NULL) {
            //タイムアウト待ち
            utl_buf_free(&tx.vout[0].script);      //HTLC Success Txを止める
            //close時の出力先に変更
            utl_buf_alloccopy(&tx.vout[0].script,
                    self->shutdown_scriptpk_local.buf, self->shutdown_scriptpk_local.len);
            tx.locktime = p_htlcinfo->expiry;
            htlcsign = LN_HTLCSIGN_RV_TIMEOUT;
        }
    }

    //署名
    utl_buf_t buf_sig;
    ret = ln_sign_htlc_tx(&tx,
                &buf_sig,                       //<localsig>
                pTxCommit->vout[vout_idx].value,
                pHtlcKey,
                pBufRemoteSig,                  //<remotesig>
                (ret_img) ? preimage : NULL,
                &p_htlcinfo->script,
                htlcsign);
    if (ret && (p_htlc_sigs != NULL)) {
        ln_misc_sigtrim(p_htlc_sigs + LN_SZ_SIGNATURE * htlc_num, buf_sig.buf);
    }
    utl_buf_free(&buf_sig);
    if (!ret) {
        LOGD("fail: ln_sign_htlc_tx: vout[%d]\n", vout_idx);
        goto LABEL_EXIT;
    }

    if (pTxHtlcs != NULL) {
        if ( ((p_htlcinfo->type == LN_HTLCTYPE_OFFERED) && ret_img) ||
                (p_htlcinfo->type == LN_HTLCTYPE_RECEIVED) ) {
            LOGD("create HTLC tx[%d]\n", htlc_num);
            M_DBG_PRINT_TX2(&tx);
            memcpy(&pTxHtlcs[htlc_num], &tx, sizeof(tx));
            btc_tx_init(&tx);     //txはfreeさせない(pTxHtlcsに任せる)
        } else {
            LOGD("skip create HTLC tx[%d]\n", htlc_num);
            btc_tx_init(&pTxHtlcs[htlc_num]);
        }
    }

LABEL_EXIT:
    btc_tx_free(&tx);

    return ret;
}


/** commitment_signed作成
 *
 *
 */
static bool create_commit_signed(ln_self_t *self, utl_buf_t *pCommSig)
{
    LOGD("BEGIN\n");

    bool ret;

    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished");
        return false;
    }

    //相手に送る署名を作成
    uint8_t *p_htlc_sigs = NULL;    //必要があればcreate_to_remote()でMALLOC()する
    ret = create_to_remote(self, NULL, &p_htlc_sigs,
                self->commit_local.to_self_delay, self->commit_remote.dust_limit_sat);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_ERROR, "create remote commit_tx");
        return false;
    }

    ln_commit_signed_t commsig;

    commsig.p_channel_id = self->channel_id;
    commsig.p_signature = self->commit_local.signature;     //相手commit_txに行った自分の署名
    commsig.num_htlcs = self->commit_remote.htlc_num;
    commsig.p_htlc_signature = p_htlc_sigs;
    ret = ln_msg_commit_signed_create(pCommSig, &commsig);
    UTL_DBG_FREE(p_htlc_sigs);

    if (ret) {
        //commitment_signed送信済みフラグ
        for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
            if (self->cnl_add_htlc[idx].amount_msat != 0) {
                self->cnl_add_htlc[idx].flag |= LN_HTLC_FLAG_COMMIT_SEND;
            }
        }

        //相手のcommitment_numberをインクリメント(channel_reestablish用)
        self->commit_remote.commit_num++;
        M_DBG_COMMITNUM(self);
        M_DB_SELF_SAVE(self);
    }

    LOGD("END\n");
    return ret;
}


/** closing tx作成
 *
 * @param[in]   FeeSat
 * @param[in]   bVerify     true:verifyを行う
 * @note
 *      - INPUT: 2-of-2(順番はself->key_fund_sort)
 *          - 自分：self->commit_local.signature
 *          - 相手：self->commit_remote.signature
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
    btc_util_sort_bip69(pTx);

    //署名
    uint8_t sighash[BTC_SZ_SIGHASH];
    ret = btc_util_calc_sighash_p2wsh(sighash, pTx, 0, self->funding_sat, &self->redeem_fund);
    if (ret) {
        ret = ln_signer_p2wsh(&buf_sig, sighash, &self->priv_data, MSG_FUNDIDX_FUNDING);
    }
    if (!ret) {
        LOGD("fail: sign p2wsh\n");
        btc_tx_free(pTx);
        return false;
    }
    //送信用署名
    ln_misc_sigtrim(self->commit_local.signature, buf_sig.buf);

    //署名追加
    if (bVerify) {
        utl_buf_t buf_sig_from_remote = UTL_BUF_INIT;

        ln_misc_sigexpand(&buf_sig_from_remote, self->commit_remote.signature);
        set_vin_p2wsh_2of2(pTx, 0, self->key_fund_sort,
                                &buf_sig,
                                &buf_sig_from_remote,
                                &self->redeem_fund);
        utl_buf_free(&buf_sig_from_remote);

        //
        // 署名verify
        //
        ret = btc_sw_verify_2of2(pTx, 0, sighash,
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

    ln_cnl_announce_create_t anno;

    anno.short_channel_id = self->short_channel_id;
    anno.p_my_node_pub = ln_node_getid();
    anno.p_peer_node_pub = self->peer_node_id;
    anno.p_my_funding_pub = self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING];
    anno.p_peer_funding_pub = self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING];
    anno.sort = sort_nodeid(self, NULL);
    bool ret = ln_msg_cnl_announce_create(self, &self->cnl_anno, &anno);

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
                ln_cnl_update_t *pUpd,
                utl_buf_t *pCnlUpd,
                uint32_t TimeStamp,
                uint8_t Flag)
{
    pUpd->short_channel_id = self->short_channel_id;
    pUpd->timestamp = TimeStamp;
    pUpd->cltv_expiry_delta = self->anno_prm.cltv_expiry_delta;
    pUpd->htlc_minimum_msat = self->anno_prm.htlc_minimum_msat;
    pUpd->fee_base_msat = self->anno_prm.fee_base_msat;
    pUpd->fee_prop_millionths = self->anno_prm.fee_prop_millionths;
    pUpd->flags = Flag | ln_sort_to_dir(sort_nodeid(self, NULL));
    bool ret = ln_msg_cnl_update_create(pCnlUpd, pUpd);

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
                int *pIdx,
                utl_buf_t *pReason,
                uint64_t amount_msat,
                uint32_t cltv_value)
{
    bool ret = false;
    bool retval;
    uint64_t max_htlc_value_in_flight_msat = 0;
    uint64_t close_fee_msat = LN_SATOSHI2MSAT(ln_calc_max_closing_fee(self));

    //cltv_expiryは、500000000未満にしなくてはならない
    if (cltv_value >= 500000000) {
        M_SET_ERR(self, LNERR_INV_VALUE, "cltv_value >= 500000000");
        goto LABEL_EXIT;
    }

    //相手が指定したchannel_reserve_satは残しておく必要あり
    if (self->our_msat < amount_msat + LN_SATOSHI2MSAT(self->commit_remote.channel_reserve_sat)) {
        M_SET_ERR(self, LNERR_INV_VALUE, "our_msat - amount_msat < channel_reserve_sat(%" PRIu64 ")", self->commit_remote.channel_reserve_sat);
        goto LABEL_EXIT;
    }

    //現在のfeerate_per_kwで支払えないようなamount_msatを指定してはいけない
    if (self->our_msat < amount_msat + close_fee_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "our_msat - amount_msat < closing_fee_msat(%" PRIu64 ")", close_fee_msat);
        goto LABEL_EXIT;
    }

    //追加した結果が相手のmax_accepted_htlcsより多くなるなら、追加してはならない。
    if (self->commit_remote.max_accepted_htlcs <= self->htlc_num) {
        M_SET_ERR(self, LNERR_INV_VALUE, "over max_accepted_htlcs");
        goto LABEL_EXIT;
    }

    //amount_msatは、0より大きくなくてはならない。
    //amount_msatは、相手のhtlc_minimum_msat未満にしてはならない。
    if ((amount_msat == 0) || (amount_msat < self->commit_remote.htlc_minimum_msat)) {
        M_SET_ERR(self, LNERR_INV_VALUE, "amount_msat(%" PRIu64 ") < remote htlc_minimum_msat(%" PRIu64 ")", amount_msat, self->commit_remote.htlc_minimum_msat);
        goto LABEL_EXIT;
    }

    //加算した結果が相手のmax_htlc_value_in_flight_msatを超えるなら、追加してはならない。
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_OFFER) {
            max_htlc_value_in_flight_msat += self->cnl_add_htlc[idx].amount_msat;
        }
    }
    if (max_htlc_value_in_flight_msat > self->commit_remote.max_htlc_value_in_flight_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "exceed remote max_htlc_value_in_flight_msat(%" PRIu64 ")", self->commit_remote.max_htlc_value_in_flight_msat);
        goto LABEL_EXIT;
    }

    int idx;
    for (idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat == 0) {
            //BOLT#2: MUST offer amount-msat greater than 0
            //  だから、0の場合は空き
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
        utl_buf_t buf_bolt = UTL_BUF_INIT;
        ln_cnl_update_t upd;

        retval = ln_get_channel_update_peer(self, &buf_bolt, NULL);
        if (retval) {
            memset(&upd, 0, sizeof(upd));
            retval = ln_msg_cnl_update_read(&upd, buf_bolt.buf, buf_bolt.len);
        }
        if (ret) {
            if (upd.flags & LN_CNLUPD_FLAGS_DISABLE) {
                //B13. if the channel is disabled:
                //      channel_disabled
                //      (report the current channel setting for the outgoing channel.)
                LOGD("fail: channel_disabled\n");

                utl_push_t push_htlc;
                utl_push_init(&push_htlc, pReason,
                                    sizeof(uint16_t) + sizeof(uint16_t) + buf_bolt.len);
                ln_misc_push16be(&push_htlc, LNONION_CHAN_DISABLE);
                ln_misc_push16be(&push_htlc, (uint16_t)buf_bolt.len);
                utl_push_data(&push_htlc, buf_bolt.buf, buf_bolt.len);
            }
        } else if (!ret) {
            if (retval) {
                //B4. if during forwarding to its receiving peer, an otherwise unspecified, transient error occurs in the outgoing channel (e.g. channel capacity reached, too many in-flight HTLCs, etc.):
                //      temporary_channel_failure
                LOGD("fail: temporary_channel_failure\n");

                utl_push_t push_htlc;
                utl_push_init(&push_htlc, pReason,
                                    sizeof(uint16_t) + sizeof(uint16_t) + buf_bolt.len);
                ln_misc_push16be(&push_htlc, LNONION_TMP_CHAN_FAIL);
                ln_misc_push16be(&push_htlc, (uint16_t)buf_bolt.len);
                utl_push_data(&push_htlc, buf_bolt.buf, buf_bolt.len);
            } else {
                //B5. if an otherwise unspecified, permanent error occurs during forwarding to its receiving peer (e.g. channel recently closed):
                //      permanent_channel_failure
                LOGD("fail: permanent_channel_failure\n");

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
    if (self->commit_local.max_accepted_htlcs <= self->htlc_num) {
        M_SET_ERR(self, LNERR_INV_VALUE, "over max_accepted_htlcs : %d", self->htlc_num);
        return false;
    }

    //加算した結果が自分のmax_htlc_value_in_flight_msatを超えるなら、チャネルを失敗させる。
    //      adds more than its max_htlc_value_in_flight_msat worth of offered HTLCs to its local commitment transaction
    uint64_t max_htlc_value_in_flight_msat = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_OFFER) {
            max_htlc_value_in_flight_msat += self->cnl_add_htlc[idx].amount_msat;
        }
    }
    if (max_htlc_value_in_flight_msat > self->commit_local.max_htlc_value_in_flight_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "exceed local max_htlc_value_in_flight_msat");
        return false;
    }

    //cltv_expiryが500000000以上の場合、チャネルを失敗させる。
    //  if sending node sets cltv_expiry to greater or equal to 500000000
    if (p_htlc->cltv_expiry >= 500000000) {
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
    uint8_t preimage_hash[LN_SZ_HASH];

    preimg.amount_msat = (uint64_t)-1;
    preimg.expiry = 0;
    void *p_cur;
    ret = ln_db_preimg_cur_open(&p_cur);
    while (ret) {
        bool detect;
        ret = ln_db_preimg_cur_get(p_cur, &detect, &preimg);     //from invoice
        if (detect) {
            memcpy(pPreImage, preimg.preimage, LN_SZ_PREIMAGE);
            ln_calc_preimage_hash(preimage_hash, pPreImage);
            if (memcmp(preimage_hash, pAddHtlc->payment_sha256, LN_SZ_HASH) == 0) {
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
        (*self->p_callback)(self, LN_CB_ADD_HTLC_RECV_PREV, &recv_prev);
    }

    //B6. if the outgoing channel has requirements advertised in its channel_announcement's features, which were NOT included in the onion:
    //      required_channel_feature_missing
    //
    //      2018/09/07: channel_announcement.features not defined

    //B7. if the receiving peer specified by the onion is NOT known:
    //      unknown_next_peer
    if ((pDataOut->short_channel_id == 0) || (recv_prev.p_next_self == NULL)) {
        //転送先がない
        M_SET_ERR(self, LNERR_INV_VALUE, "no next channel");
        ln_misc_push16be(pPushReason, LNONION_UNKNOWN_NEXT_PEER);
        //no data

        return false;
    }

    //channel_update読み込み
    ln_cnl_update_t cnlupd;
    utl_buf_t cnlupd_buf = UTL_BUF_INIT;
    uint8_t peer_id[BTC_SZ_PUBKEY];
    bool ret = ln_node_search_nodeid(peer_id, pDataOut->short_channel_id);
    if (ret) {
        uint8_t dir = ln_sort_to_dir(sort_nodeid(self, peer_id));
        ret = ln_db_annocnlupd_load(&cnlupd_buf, NULL, pDataOut->short_channel_id, dir);
        if (!ret) {
            LOGD("fail: ln_db_annocnlupd_load: %016" PRIx64 ", dir=%d\n", pDataOut->short_channel_id, dir);
        }
    } else {
        LOGD("fail: ln_node_search_nodeid\n");
    }
    if (ret) {
        ret = ln_msg_cnl_update_read(&cnlupd, cnlupd_buf.buf, cnlupd_buf.len);
        if (!ret) {
            LOGD("fail: ln_msg_cnl_update_read\n");
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


static bool check_recv_add_htlc_bolt4_common(utl_push_t *pPushReason)
{
    (void)pPushReason;

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
            LOGD("fail\n");
        }

        //channel_update
        utl_buf_t buf_upd = UTL_BUF_INIT;
        uint32_t now = (uint32_t)time(NULL);
        ln_cnl_update_t upd;
        bool ret2 = create_channel_update(self, &upd, &buf_upd, now, 0);
        if (ret2) {
            ln_db_annocnlupd_save(&buf_upd, &upd, NULL);
        } else {
            LOGD("fail\n");
        }
        utl_buf_free(&buf_upd);

        self->anno_flag |= LN_ANNO_FLAG_END;
    } else {
        LOGD("yet: anno_flag=%02x, short_channel_id=%016" PRIx64 "\n", self->anno_flag, self->short_channel_id);
    }
}


/** revoke_and_ack交換完了後
 *
 */
static void proc_rev_and_ack(ln_self_t *self)
{
    uint8_t stat = comrev_state(self);
    if (stat == M_STAT_STABLE) {
        //revoke_and_ack交換通知
        (*self->p_callback)(self, LN_CB_REV_AND_ACK_EXCG, NULL);
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
        ln_cnl_announce_read_t ann;

        ret = ln_msg_cnl_announce_read(&ann, buf_cnl_anno.buf, buf_cnl_anno.len);
        if (ret) {
            const uint8_t *p_node_id;
            if (Dir == 0) {
                p_node_id = ann.node_id1;
            } else {
                p_node_id = ann.node_id2;
            }
            memcpy(pNodeId, p_node_id, BTC_SZ_PUBKEY);
        } else {
            LOGD("fail\n");
        }
    } else {
        if (short_channel_id == self->short_channel_id) {
            // DBには無いが、このchannelの情報
            btc_keys_sort_t mysort = sort_nodeid(self, NULL);
            if ( ((mysort == BTC_KEYS_SORT_ASC) && (Dir == 0)) ||
                 ((mysort == BTC_KEYS_SORT_OTHER) && (Dir == 1)) ) {
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


//HTLC削除(HTLC idは維持する)
static void clear_htlc(ln_self_t *self, ln_update_add_htlc_t *p_htlc)
{
    LOGD("HTLC remove prev: htlc_num=%d\n", self->htlc_num);
    assert(self->htlc_num > 0);

    utl_buf_free(&p_htlc->buf_payment_preimage);
    utl_buf_free(&p_htlc->buf_onion_reason);
    utl_buf_free(&p_htlc->buf_shared_secret);
    memset(p_htlc, 0, sizeof(ln_update_add_htlc_t));
    self->htlc_num--;
    LOGD("   --> htlc_num=%d\n", self->htlc_num);
}


/** payment_hashと一致するpreimage検索
 *
 * @param[out]      pPreImage
 * @param[in]       pPayHash        payment_hash
 * @param[in]       bClosing        true:一致したexpiryをUINT32_MAXに変更する
 * @retval  true    検索成功
 */
static bool search_preimage(uint8_t *pPreImage, const uint8_t *pPayHash, bool bClosing)
{
    if (!LN_DBG_MATCH_PREIMAGE()) {
        LOGD("DBG: HTLC preimage mismatch\n");
        return false;
    }
    //LOGD("bClosing=%d\n", bClosing);

    preimg_t prm;
    prm.image = pPreImage;
    prm.hash = pPayHash;
    prm.b_closing = bClosing;
    bool ret = ln_db_preimg_search(search_preimage_func, &prm);

    return ret;
}


/** search_preimage用処理関数
 *
 * SHA256(preimage)がpayment_hashと一致した場合にtrueを返す。
 * bClosingがtrueの場合、該当するpreimageのexpiryをUINT32_MAXにする(自動削除させないため)。
 */
static bool search_preimage_func(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param)
{
    (void)Amount; (void)Expiry;

    preimg_t *prm = (preimg_t *)p_param;
    uint8_t preimage_hash[LN_SZ_HASH];
    bool ret = false;

    //LOGD("compare preimage : ");
    //DUMPD(pPreImage, LN_SZ_PREIMAGE);
    ln_calc_preimage_hash(preimage_hash, pPreImage);
    if (memcmp(preimage_hash, prm->hash, LN_SZ_HASH) == 0) {
        //一致
        //LOGD("preimage match!: ");
        //DUMPD(pPreImage, LN_SZ_PREIMAGE);
        memcpy(prm->image, pPreImage, LN_SZ_PREIMAGE);
        if ((prm->b_closing) && (Expiry != UINT32_MAX)) {
            //期限切れによる自動削除をしない
            ln_db_preimg_set_expiry(p_db_param, UINT32_MAX);
        }
        ret = true;
    }

    return ret;
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


/** establish用メモリ解放
 *
 * @param[in]   bEndEstablish   true: funding用メモリ解放
 */
static void free_establish(ln_self_t *self, bool bEndEstablish)
{
    if (self->p_establish != NULL) {
#ifndef USE_SPV
        if (self->p_establish->p_fundin != NULL) {
            LOGD("self->p_establish->p_fundin=%p\n", self->p_establish->p_fundin);
            UTL_DBG_FREE(self->p_establish->p_fundin);  //UTL_DBG_MALLOC: ln_create_open_channel()
            LOGD("free\n");
        }
#endif
        if (bEndEstablish) {
            UTL_DBG_FREE(self->p_establish);        //UTL_DBG_MALLOC: ln_set_establish()
            LOGD("free\n");
        }
    }
    self->fund_flag = (ln_fundflag_t)((self->fund_flag & ~LN_FUNDFLAG_FUNDING) | LN_FUNDFLAG_OPENED);
}


/**
 *
 * @param[in]   self
 * @param[in]   pNodeId
 * @retval      BTC_KEYS_SORT_ASC     自ノードが先
 * @retval      BTC_KEYS_SORT_OTHER   相手ノードが先
 */
static btc_keys_sort_t sort_nodeid(const ln_self_t *self, const uint8_t *pNodeId)
{
    btc_keys_sort_t sort;

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
        sort = BTC_KEYS_SORT_ASC;
    } else {
        LOGD("my node= second\n");
        sort = BTC_KEYS_SORT_OTHER;
    }

    return sort;
}


/** btc_keys_sort_t --> Direction変換
 *
 */
static inline uint8_t ln_sort_to_dir(btc_keys_sort_t Sort)
{
    return (uint8_t)Sort;
}


static void set_error(ln_self_t *self, int Err, const char *pFormat, ...)
{
    va_list ap;

    self->err = Err;

    va_start(ap, pFormat);
    vsnprintf(self->err_msg, LN_SZ_ERRMSG, pFormat, ap);
    va_end(ap);
}


/** commitment_number状態
 *
 *  @retval 0   state-A: local.commit_num <  remote.commit_num
 *  @retval 1   state-B: local.commit_num >  remote.commit_num
 *  @retval 2   state-C: local.commit_num == remote.commit_num
 */
static int commitment_state(const ln_self_t *self)
{
    int commit_stat;
    if (self->commit_local.commit_num == self->commit_remote.commit_num) {
        commit_stat = 2;    //C
    } else if (self->commit_local.commit_num + (uint64_t)1 == self->commit_remote.commit_num) {
        commit_stat = 0;    //A
    } else if (self->commit_local.commit_num == self->commit_remote.commit_num + (uint64_t)1) {
        commit_stat = 1;    //B
    } else {
        LOGD("err: invalid commit_num(local=%" PRIu64 ", remote=%" PRIu64 ")\n", self->commit_local.commit_num, self->commit_remote.commit_num);
        commit_stat = -1;
    }
    return commit_stat;
}


/** revocation_number状態
 *
 *  @retval 0   state-a: local.revoke_num <  remote.revoke_num
 *  @retval 1   state-b: local.revoke_num >  remote.revoke_num
 *  @retval 2   state-c: local.revoke_num == remote.revoke_num
 */
static int revocation_state(const ln_self_t *self)
{
    int revoke_stat;
    if (self->commit_local.revoke_num == self->commit_remote.revoke_num) {
        revoke_stat = 2;    //c
    } else if (self->commit_local.revoke_num + (uint64_t)1 == self->commit_remote.revoke_num) {
        revoke_stat = 0;    //a
    } else if (self->commit_local.revoke_num == self->commit_remote.revoke_num + (uint64_t)1) {
        revoke_stat = 1;    //b
    } else {
        LOGD("err: invalid revoke_num(local=%" PRIu64 ", remote=%" PRIu64 ")\n", self->commit_local.revoke_num, self->commit_remote.revoke_num);
        revoke_stat = -1;
    }
    return revoke_stat;
}


/** commitment/revocation状態
 *
 * #commitment_state(), #revocation_state()とセットになっている。
 *
 *      * 安定
 *      * 状態1: A→B: commitment_signed後
 *          * A送信-B未受信:
 *          * A送信-B受信:
 *      * 状態2: A←B: revoke_and_ack後
 *          * B送信-A未受信:
 *          * B送信-A受信:
 *      * 状態3: A←B: commitment_signed後
 *          * B送信-A未受信:
 *          * B送信-A受信:
 *      * 安定 : A→B: revoke_and_ack後
 *          * A送信-B未受信:
 *          * A送信-B受信:
 */
static uint8_t comrev_state(const ln_self_t *self)
{
    int stat;
    int commit_stat = commitment_state(self);
    int revoke_stat = revocation_state(self);
    //update message sender  :
    //      0: C-c (stable)
    //      1: A-c
    //      2: A-a
    //      3: C-a
    //      4: C-c (stable)
    //update message receiver:
    //      0: C-c (stable)
    //      1: B-c
    //      2: B-b
    //      3: C-b
    //      4: C-c (stable)
    if ((commit_stat == 2) && (revoke_stat == 2)) {
        stat = M_STAT_STABLE;
    } else if ((commit_stat == 0) && (revoke_stat == 2)) {
        //      sender-1: A-c
        stat = M_STAT_SEND1;
    } else if ((commit_stat == 0) && (revoke_stat == 0)) {
        //      sender-2: A-a
        stat = M_STAT_SEND2;
    } else if ((commit_stat == 2) && (revoke_stat == 0)) {
        //      sender-3: C-a
        stat = M_STAT_SEND3;
    } else if ((commit_stat == 1) && (revoke_stat == 2)) {
        //      receiver-1: B-c
        stat = M_STAT_RECV1;
    } else if ((commit_stat == 1) && (revoke_stat == 1)) {
        //      receiver-2: B-b
        stat = M_STAT_RECV2;
    } else if ((commit_stat == 2) && (revoke_stat == 1)) {
        //      receiver-3: C-b
        stat = M_STAT_RECV3;
    } else {
        stat = 0xff;
    }
    return stat;
}


#ifdef M_DBG_COMMITHTLC
/** commitment_number debug output
 *
 */
static void dbg_commitnum(const ln_self_t *self)
{
    uint8_t stat = comrev_state(self);
    LOGD("------------------------------------------\n");
    LOGD("storage_index      = %016" PRIx64 "\n", self->priv_data.storage_index);
    LOGD("peer_storage_index = %016" PRIx64 "\n", self->peer_storage_index);
    LOGD("------------------------------------------\n");
    LOGD("local.current_commit_num  = %" PRIu64 "\n", self->funding_local.current_commit_num);
    LOGD("remote.current_commit_num = %" PRIu64 "\n", self->funding_remote.current_commit_num);
    LOGD("------------------------------------------\n");
    LOGD("local.commit_num  = %" PRIu64 "\n", self->commit_local.commit_num);
    LOGD("remote.commit_num = %" PRIu64 "\n", self->commit_remote.commit_num);
    LOGD("local.revoke_num  = %" PRId64 "\n", (int64_t)self->commit_local.revoke_num);
    LOGD("remote.revoke_num = %" PRId64 "\n", (int64_t)self->commit_remote.revoke_num);
    LOGD("------------------------------------------\n");
    LOGD("htlc_num: %" PRIu64 "\n", self->htlc_num);
    LOGD("htlc_id_num: %" PRIu64 "\n", self->htlc_id_num);
    LOGD("------------------------------------------\n");

    if (stat == M_STAT_STABLE) {
        LOGD("    stable\n");
    } else {
        int dir = M_STAT_MASK_DIR(stat);
        int num = M_STAT_MASK_NUM(stat);
        switch (dir) {
        case 0:
            break;
        case M_STAT_SENDER:
            LOGD("    sender-");
            break;
        case M_STAT_RECEIVER:
            LOGD("    receiver-");
            break;
        default:
            LOGD("    ???? ");
        }
        LOGD2("%d\n", num);
    }
    LOGD("------------------------------------------\n");
}
#endif
