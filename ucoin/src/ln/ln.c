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

#define M_DBG_VERBOSE

/**************************************************************************
 * macros
 **************************************************************************/

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))  ///< 配列要素数

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
#define M_ANNO_FLAG_END                     (0x80)          ///< 送受信完了後の処理済み

// ln_self_t.shutdown_flag
#define M_SHDN_FLAG_SEND                    (0x01)          ///< shutdown送信済み
#define M_SHDN_FLAG_RECV                    (0x02)          ///< shutdown受信済み
#define M_SHDN_FLAG_EXCHANGED(flag)         (((flag) & (M_SHDN_FLAG_SEND | M_SHDN_FLAG_RECV)) == (M_SHDN_FLAG_SEND | M_SHDN_FLAG_RECV))

// ln_self_t.comsig_flag
#define M_COMISG_FLAG_SEND                  (0x01)          ///< commitment_signed送信済み
#define M_COMISG_FLAG_RECV                  (0x02)          ///< commitment_signed受信済み

// ln_self_t.revack_flag
#define M_REVACK_FLAG_SEND                  (0x01)          ///< revoke_and_ack送信済み
#define M_REVACK_FLAG_RECV                  (0x02)          ///< revoke_and_ack受信済み

#define M_PONG_MISSING                      (50)            ///< pongが返ってこないエラー上限

#define M_FUNDING_INDEX                     (0)             ///< funding_txのvout

#define M_FEERATE_MARGIN(fr)                ((fr) * 0.1)    ///< feerate_per_kwの許容範囲[kw]

#ifndef M_DBG_VERBOSE
//#define M_DBG_PRINT_TX(tx)      //NONE
#define M_DBG_PRINT_TX(tx)      fprintf(DEBUGOUT, "[%s:%d]", __func__, (int)__LINE__); ucoin_print_tx(tx)
#define M_DBG_PRINT_TX2(tx)     //NONE
#else
#define M_DBG_PRINT_TX(tx)      fprintf(DEBUGOUT, "[%s:%d]", __func__, (int)__LINE__); ucoin_print_tx(tx)
#define M_DBG_PRINT_TX2(tx)     fprintf(DEBUGOUT, "[%s:%d]", __func__, (int)__LINE__); ucoin_print_tx(tx)
#endif  //M_DBG_VERBOSE

#define M_SET_ERR(self,err,fmt,...)     set_err(self,err,fmt,##__VA_ARGS__); fprintf(DEBUGOUT, "[%s:%d]fail: %s\n", __func__, (int)__LINE__, self->err_msg)


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef bool (*pRecvFunc_t)(ln_self_t *self,const uint8_t *pData, uint16_t Len);


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
static void start_funding_wait(ln_self_t *self, bool bSendTx);
static bool set_vin_p2wsh_2of2(ucoin_tx_t *pTx, int Index, ucoin_keys_sort_t Sort,
                    const ucoin_buf_t *pSig1,
                    const ucoin_buf_t *pSig2,
                    const ucoin_buf_t *pWit2of2);
static bool create_funding_tx(ln_self_t *self);
static bool create_to_local(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat);
static bool create_to_local_sign(ln_self_t *self,
                    ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufSig);
static bool create_to_local_spent(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo,
                    uint32_t to_self_delay);
static bool create_to_local_close(ln_self_t *self,
                    ucoin_tx_t *pTxHtlcs,
                    ucoin_tx_t *pTxHtlc,
                    ucoin_push_t *pPush,
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const ucoin_util_keys_t *pHtlcKey,
                    uint8_t htlc_num,
                    int vout_idx,
                    uint8_t htlc_idx,
                    uint32_t to_self_delay);
static bool create_to_remote(ln_self_t *self,
                    ln_close_force_t *pClose,
                    uint8_t **pp_htlc_sigs,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat);
static bool create_to_remote_spent(ln_self_t *self,
                    ln_close_force_t *pClose,
                    uint8_t *p_htlc_sigs,
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo);
static bool create_to_remote_htlcsign(ln_self_t *self,
                    ucoin_tx_t *pTxHtlcs,
                    uint8_t *p_htlc_sigs,
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const ucoin_util_keys_t *pHtlcKey,
                    const ucoin_buf_t *pBufRemoteSig,
                    uint64_t fee,
                    uint8_t htlc_num,
                    int vout_idx,
                    uint8_t htlc_idx);
static bool create_closing_tx(ln_self_t *self, ucoin_tx_t *pTx, uint64_t FeeSat, bool bVerify);
static bool create_local_channel_announcement(ln_self_t *self);
static bool create_channel_update(
                ln_self_t *self,
                ln_cnl_update_t *pUpd,
                ucoin_buf_t *pCnlUpd,
                uint32_t TimeStamp,
                uint8_t Flag);
static bool check_create_add_htlc(
                ln_self_t *self,
                int *pIdx,
                ucoin_buf_t *pReason,
                uint64_t amount_msat,
                uint32_t cltv_value);
static bool check_recv_add_htlc_bolt2(ln_self_t *self, int idx);
static bool check_recv_add_htlc_bolt4(ln_self_t *self,
                    ln_hop_dataout_t *pDataOut,
                    uint8_t **pp_payment,
                    uint8_t *p_preimage,
                    ucoin_buf_t *pReason,
                    int idx);
static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret);

static void proc_commitment_signed(ln_self_t *self, uint8_t Flag);
static void proc_rev_and_ack(ln_self_t *self, uint8_t Flag);

static bool chk_peer_node(ln_self_t *self);
static bool get_nodeid(ln_self_t *self, uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir);;
static void clear_htlc(ln_self_t *self, ln_update_add_htlc_t *p_add);
static bool search_preimage(uint8_t *pPreImage, const uint8_t *pHtlcHash);
static bool chk_channelid(const uint8_t *recv_id, const uint8_t *mine_id);
static void close_alloc(ln_close_force_t *pClose, int Num);
static void free_establish(ln_self_t *self, bool bEndEstablish);
static ucoin_keys_sort_t sort_nodeid(ln_self_t *self);
static void set_err(ln_self_t *self, int Err, const char *pFormat, ...);


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
    { MSGTYPE_NODE_ANNOUNCEMENT,            ln_node_recv_node_announcement },
    { MSGTYPE_CHANNEL_UPDATE,               recv_channel_update },
    { MSGTYPE_ANNOUNCEMENT_SIGNATURES,      recv_announcement_signatures }
};


//< 32: chain-hash
uint8_t HIDDEN gGenesisChainHash[LN_SZ_HASH];


static unsigned long mDebug;


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_init(ln_self_t *self, const uint8_t *pSeed, const ln_anno_prm_t *pAnnoPrm, ln_callback_t pFunc)
{
    DBG_PRINTF("BEGIN : pSeed=%p\n", pSeed);

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

    ucoin_buf_init(&self->shutdown_scriptpk_local);
    ucoin_buf_init(&self->shutdown_scriptpk_remote);
    ucoin_buf_init(&self->redeem_fund);
    ucoin_buf_init(&self->cnl_anno);
    ucoin_buf_init(&self->revoked_sec);
    self->p_revoked_vout = NULL;
    self->p_revoked_wit = NULL;
    self->p_revoked_type = NULL;

    ucoin_tx_init(&self->tx_funding);
    ucoin_tx_init(&self->tx_closing);

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        self->cnl_add_htlc[idx].p_onion_route = NULL;
        ucoin_buf_init(&self->cnl_add_htlc[idx].shared_secret);
    }

    self->lfeature_remote = 0;

    self->p_callback = pFunc;

    memcpy(&self->anno_prm, pAnnoPrm, sizeof(ln_anno_prm_t));
    DBG_PRINTF("cltv_expiry_delta=%" PRIu16 "\n", self->anno_prm.cltv_expiry_delta);
    DBG_PRINTF("htlc_minimum_msat=%" PRIu64 "\n", self->anno_prm.htlc_minimum_msat);
    DBG_PRINTF("fee_base_msat=%" PRIu32 "\n", self->anno_prm.fee_base_msat);
    DBG_PRINTF("fee_prop_millionths=%" PRIu32 "\n", self->anno_prm.fee_prop_millionths);

    //seed
    ln_signer_init(self, pSeed);
    self->peer_storage_index = LN_SECINDEX_INIT;

    self->commit_local.commit_num = (uint64_t)-1;
    self->commit_remote.commit_num = (uint64_t)-1;

    DBG_PRINTF("END\n");

    return true;
}


void ln_term(ln_self_t *self)
{
    channel_clear(self);

    ln_signer_term(self);
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        self->cnl_add_htlc[idx].p_onion_route = NULL;
        ucoin_buf_free(&self->cnl_add_htlc[idx].shared_secret);
    }
    //DBG_PRINTF("END\n");
}


void ln_set_genesishash(const uint8_t *pHash)
{
    memcpy(gGenesisChainHash, pHash, LN_SZ_HASH);
    //DBG_PRINTF("genesis=");
    //DUMPBIN(gGenesisChainHash, LN_SZ_HASH);
}


const uint8_t* ln_get_genesishash(void)
{
    return gGenesisChainHash;
}


void ln_set_peer_nodeid(ln_self_t *self, const uint8_t *pNodeId)
{
    memcpy(self->peer_node_id, pNodeId, UCOIN_SZ_PUBKEY);
}


bool ln_set_establish(ln_self_t *self, const ln_establish_prm_t *pEstPrm)
{
    DBG_PRINTF("BEGIN\n");

    if (self->p_establish != 0) {
        DBG_PRINTF("already set\n");
        return true;
    }

    self->p_establish = (ln_establish_t *)M_MALLOC(sizeof(ln_establish_t));   //M_FREE:proc_established()

    if (pEstPrm != NULL) {
        self->p_establish->p_fundin = NULL;       //open_channel送信側が設定する
        memcpy(&self->p_establish->estprm, pEstPrm, sizeof(ln_establish_prm_t));
        DBG_PRINTF("dust_limit_sat= %" PRIu64 "\n", self->p_establish->estprm.dust_limit_sat);
        DBG_PRINTF("max_htlc_value_in_flight_msat= %" PRIu64 "\n", self->p_establish->estprm.max_htlc_value_in_flight_msat);
        DBG_PRINTF("channel_reserve_sat= %" PRIu64 "\n", self->p_establish->estprm.channel_reserve_sat);
        DBG_PRINTF("htlc_minimum_msat= %" PRIu64 "\n", self->p_establish->estprm.htlc_minimum_msat);
        DBG_PRINTF("to_self_delay= %" PRIu16 "\n", self->p_establish->estprm.to_self_delay);
        DBG_PRINTF("max_accepted_htlcs= %" PRIu16 "\n", self->p_establish->estprm.max_accepted_htlcs);
        DBG_PRINTF("min_depth= %" PRIu16 "\n", self->p_establish->estprm.min_depth);
    }

    DBG_PRINTF("END\n");

    return true;
}


void ln_free_establish(ln_self_t *self)
{
    free_establish(self, true);
}


void ln_set_short_channel_id_param(ln_self_t *self, uint32_t Height, uint32_t Index, uint32_t FundingIndex)
{
    uint64_t short_channel_id = ln_misc_calc_short_channel_id(Height, Index, FundingIndex);
    if (self->short_channel_id == 0) {
        self->short_channel_id = short_channel_id;
        ln_db_self_save(self);
    }
}


void ln_get_short_channel_id_param(uint32_t *pHeight, uint32_t *pIndex, uint32_t *pVIndex, uint64_t short_channel_id)
{
    ln_misc_get_short_channel_id_param(pHeight, pIndex, pVIndex, short_channel_id);
}


bool ln_set_shutdown_vout_pubkey(ln_self_t *self, const uint8_t *pShutdownPubkey, int ShutdownPref)
{
    bool ret = false;

    if ((ShutdownPref == UCOIN_PREF_P2PKH) || (ShutdownPref == UCOIN_PREF_NATIVE)) {
        const ucoin_buf_t pub = { (CONST_CAST uint8_t *)pShutdownPubkey, UCOIN_SZ_PUBKEY };
        ucoin_buf_t spk;

        ln_create_scriptpkh(&spk, &pub, ShutdownPref);
        ucoin_buf_alloccopy(&self->shutdown_scriptpk_local, spk.buf, spk.len);
        ucoin_buf_free(&spk);

        ret = true;
    } else {
        M_SET_ERR(self, LNERR_INV_PREF, "invalid prefix");
    }

    return ret;
}


bool ln_set_shutdown_vout_addr(ln_self_t *self, const char *pAddr)
{
    ucoin_buf_t spk = UCOIN_BUF_INIT;

    bool ret = ucoin_keys_addr2spk(&spk, pAddr);
    if (ret) {
        ucoin_buf_alloccopy(&self->shutdown_scriptpk_local, spk.buf, spk.len);
    } else {
        M_SET_ERR(self, LNERR_INV_ADDR, "invalid address");
    }
    ucoin_buf_free(&spk);

    return ret;
}


bool ln_handshake_start(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pNodeId)
{
    bool ret;

    ret = ln_enc_auth_handshake_init(self, pNodeId);
    if (ret && (pNodeId != NULL)) {
        ret = ln_enc_auth_handshake_start(self, pBuf, pNodeId);
    }

    return ret;
}


bool ln_handshake_recv(ln_self_t *self, bool *pCont, ucoin_buf_t *pBuf)
{
    bool ret;

    ret = ln_enc_auth_handshake_recv(self, pBuf);
    if (ret) {
        //次も受信を続けるかどうか
        *pCont = ln_enc_auth_handshake_state(self);
    }

    return ret;
}


bool ln_noise_enc(ln_self_t *self, ucoin_buf_t *pBufEnc, const ucoin_buf_t *pBufIn)
{
    return ln_enc_auth_enc(self, pBufEnc, pBufIn);
}


uint16_t ln_noise_dec_len(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    return ln_enc_auth_dec_len(self, pData, Len);
}


bool ln_noise_dec_msg(ln_self_t *self, ucoin_buf_t *pBuf)
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

    //DBG_PRINTF("short_channel_id= %" PRIx64 "\n", self->short_channel_id);
    if ((type != MSGTYPE_INIT) && (!M_INIT_FLAG_EXCHNAGED(self->init_flag))) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init received : %04x", type);
        return false;
    }
    if ( (type != MSGTYPE_CLOSING_SIGNED) &&
         !MSGTYPE_IS_ANNOUNCE(type) && !MSGTYPE_IS_PINGPONG(type) &&
         (type != MSGTYPE_ERROR) &&
         M_SHDN_FLAG_EXCHANGED(self->shutdown_flag) ) {
        M_SET_ERR(self, LNERR_INV_STATE, "not closing_signed received : %04x", type);
        return false;
    }

    size_t lp;
    for (lp = 0; lp < ARRAY_SIZE(RECV_FUNC); lp++) {
        if (type == RECV_FUNC[lp].type) {
            //DBG_PRINTF("type=%04x: Len=%d\n", type, Len);
            ret = (*RECV_FUNC[lp].func)(self, pData, Len);
            if (!ret) {
                DBG_PRINTF("fail: type=%04x\n", type);
            }
            break;
        }
    }
    if (lp == ARRAY_SIZE(RECV_FUNC)) {
        DBG_PRINTF("not match: type=%04x\n", type);
    }

    return ret;
}


//init作成
bool ln_create_init(ln_self_t *self, ucoin_buf_t *pInit, bool bHaveCnl)
{
    (void)bHaveCnl;

    if (self->init_flag & M_INIT_FLAG_SEND) {
        M_SET_ERR(self, LNERR_INV_STATE, "init already sent.");
        return false;
    }

    ln_init_t msg;

    //TODO: globalfeatures と localfeatures
    ucoin_buf_init(&msg.globalfeatures);

#if 1
    //init_routing_sync=0のままでは既存のannouncementを送ってこない
    const uint8_t INIT_VAL[] = { INIT_LF_ROUTE_SYNC };
    ucoin_buf_alloccopy(&msg.localfeatures, INIT_VAL, sizeof(INIT_VAL));
#else
    if (bHaveCnl) {
        const uint8_t INIT_VAL[] = { INIT_LF_ROUTE_SYNC };
        ucoin_buf_alloccopy(&msg.localfeatures, INIT_VAL, sizeof(INIT_VAL));
    } else {
        ucoin_buf_init(&msg.localfeatures);
    }
#endif

//#ifdef INIT_LF_VALUE

//#if INIT_LF_SZ_VALUE > 0
//    const uint8_t INIT_VAL[] = INIT_LF_VALUE;
//    ucoin_buf_alloccopy(&msg.localfeatures, INIT_VAL, INIT_LF_SZ_VALUE);
//#else
//#error feature support
//#endif

//#else
//    ucoin_buf_init(&msg.localfeatures);
//#endif

    bool ret = ln_msg_init_create(pInit, &msg);
    if (ret) {
        self->init_flag |= M_INIT_FLAG_SEND;
    }
    ucoin_buf_free(&msg.localfeatures);
    ucoin_buf_free(&msg.globalfeatures);

    return ret;
}


void ln_flag_proc(ln_self_t *self)
{
    if (self->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) {
        //announcement_signatures送受信済み
        DBG_PRINTF("announcement_signatures sent and recv\n");

        ln_cb_anno_sigs_t anno;
        anno.sort = sort_nodeid(self);
        (*self->p_callback)(self, LN_CB_ANNO_SIGSED, &anno);

        self->anno_flag |= M_ANNO_FLAG_END;
        ucoin_buf_free(&self->cnl_anno);
        ln_db_self_save(self);
    }
}


//channel_reestablish作成
bool ln_create_channel_reestablish(ln_self_t *self, ucoin_buf_t *pReEst)
{
    ln_channel_reestablish_t msg;
    msg.p_channel_id = self->channel_id;
    msg.next_local_commitment_number = self->commit_local.commit_num + 1;
    msg.next_remote_revocation_number = self->commit_remote.commit_num;

    bool ret = ln_msg_channel_reestablish_create(pReEst, &msg);
    return ret;
}


bool ln_check_need_funding_locked(const ln_self_t *self)
{
    return (self->short_channel_id != 0) && (self->commit_local.commit_num == 0) && (self->commit_remote.commit_num == 0);
}


bool ln_create_funding_locked(ln_self_t *self, ucoin_buf_t *pLocked)
{
    //funding_locked
    ln_funding_locked_t cnl_funding_locked;
    cnl_funding_locked.p_channel_id = self->channel_id;
    cnl_funding_locked.p_per_commitpt = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    bool ret = ln_msg_funding_locked_create(pLocked, &cnl_funding_locked);

    return ret;
}


/********************************************************************
 * Establish関係
 ********************************************************************/

//open_channel生成
bool ln_create_open_channel(ln_self_t *self, ucoin_buf_t *pOpen,
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
    ucoin_util_random(self->channel_id, LN_SZ_CHANNEL_ID);

    //鍵生成
    bool ret = ln_signer_create_channelkeys(self);
    if (!ret) {
        M_SET_ERR(self, LNERR_INV_PRIVKEY, "ln_signer_create_channelkeys");
        return false;
    }

    //funding_tx作成用に保持
    assert(self->p_establish->p_fundin == NULL);
    self->p_establish->p_fundin = (ln_fundin_t *)M_MALLOC(sizeof(ln_fundin_t));     //free: free_establish()
    memcpy(self->p_establish->p_fundin, pFundin, sizeof(ln_fundin_t));

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

    self->fund_flag = LN_FUNDFLAG_FUNDER | ((open_ch->channel_flags & 1) ? LN_FUNDFLAG_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING;

    return true;
}


void ln_open_announce_channel_clr(ln_self_t *self)
{
    self->fund_flag &= ~LN_FUNDFLAG_ANNO_CH;
    ln_db_self_save(self);
}


//announcement_signaturesを交換すると channel_announcementが完成する。
bool ln_create_announce_signs(ln_self_t *self, ucoin_buf_t *pBufAnnoSigns)
{
    bool ret;

    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    if (self->cnl_anno.buf == NULL) {
        create_local_channel_announcement(self);
    }

    //  self->cnl_annoはfundindg_lockedメッセージ作成時に行っている
    //  localのsignature
    ucoin_keys_sort_t sort = sort_nodeid(self);
    ln_msg_get_anno_signs(self, &p_sig_node, &p_sig_btc, true, sort);

    ln_announce_signs_t anno_signs;

    anno_signs.p_channel_id = self->channel_id;
    anno_signs.short_channel_id = self->short_channel_id;
    anno_signs.p_node_signature = p_sig_node;
    anno_signs.p_btc_signature = p_sig_btc;
    ret = ln_msg_announce_signs_create(pBufAnnoSigns, &anno_signs);
    if (ret) {
        self->anno_flag |= M_ANNO_FLAG_SEND;
        ln_db_self_save(self);
    }

    return ret;
}


#if 0
bool ln_update_channel_update(ln_self_t *self, ucoin_buf_t *pCnlUpd)
{
    bool ret;
    ucoin_buf_t buf_upd = UCOIN_BUF_INIT;
    ln_cnl_update_t upd;

    uint32_t timestamp;
    ucoin_keys_sort_t sort = sort_nodeid(self);
    ret = ln_db_annocnlupd_load(&buf_upd, &timestamp, ln_short_channel_id(self), sort);
    if (ret) {
        ret = ln_msg_cnl_update_read(&upd, buf_upd.buf, buf_upd.len);
    }
    if (ret) {
        ln_msg_cnl_update_print(&upd);

        if ( (upd.cltv_expiry_delta != self->anno_prm.cltv_expiry_delta) ||
             (upd.htlc_minimum_msat != self->anno_prm.htlc_minimum_msat) ||
             (upd.fee_base_msat != self->anno_prm.fee_base_msat) ||
             (upd.fee_prop_millionths != self->anno_prm.fee_prop_millionths) ) {
            DBG_PRINTF("update channel_update\n");

            uint32_t now = (uint32_t)time(NULL);
            ret = create_channel_update(self, &upd, pCnlUpd, now, 0);

            //DB保存
            bool dbret = ln_db_annocnlupd_save(pCnlUpd, &upd, ln_their_node_id(self));
            assert(dbret);
        } else {
            //DBG_PRINTF("same channel_update\n");
            ret = false;
        }
    } else {
        DBG_PRINTF("fail\n");
    }

    ucoin_buf_free(&buf_upd);

    return ret;
}
#endif


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
        DBG_PRINTF("closing fee limit(%" PRIu64 " > %" PRIu64 ")\n", Fee, feemax);
        Fee = feemax;
    }

    self->close_fee_sat = Fee;
    DBG_PRINTF("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
}


bool ln_create_shutdown(ln_self_t *self, ucoin_buf_t *pShutdown)
{
    DBG_PRINTF("BEGIN\n");

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

    DBG_PRINTF("END\n");
    return ret;
}


void ln_goto_closing(ln_self_t *self, void *pDbParam)
{
    DBG_PRINTF("BEGIN\n");
    if ((self->fund_flag & LN_FUNDFLAG_CLOSE) == 0) {
        //closing中フラグを立てる
        self->fund_flag |= LN_FUNDFLAG_CLOSE;
        ln_db_self_save_closeflg(self, pDbParam);

        //自分のchannel_updateをdisableにする(相手のは署名できないので、自分だけ)
        ucoin_buf_t buf_upd = UCOIN_BUF_INIT;
        uint32_t now = (uint32_t)time(NULL);
        ln_cnl_update_t upd;
        bool ret = create_channel_update(self, &upd, &buf_upd, now, LN_CNLUPD_FLAGS_DISABLE);
        if (ret) {
            ln_db_annocnlupd_save(&buf_upd, &upd, ln_their_node_id(self));
            ucoin_buf_free(&buf_upd);
        }
    }
    DBG_PRINTF("END\n");
}


/*
 * 自分がunilateral closeを行いたい場合に呼び出す。
 * または、funding_txがspentで、local commit_txのtxidがgetrawtransactionできる状態で呼ばれる。
 * (local commit_txが展開＝自分でunilateral closeした)
 *
 * 現在のcommitment_transactionを取得する場合にも呼び出されるため、値を元に戻す。
 */
bool ln_create_close_force_tx(ln_self_t *self, ln_close_force_t *pClose)
{
    DBG_PRINTF("BEGIN\n");

    //to_local送金先設定確認
    assert(self->shutdown_scriptpk_local.len > 0);

    //ln_print_keys(PRINTOUT, &self->funding_local, &self->funding_remote);

    //復元用
    uint8_t bak_percommit[UCOIN_SZ_PRIVKEY];
    uint8_t bak_remotecommit[UCOIN_SZ_PUBKEY];
    memcpy(bak_percommit, self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT], sizeof(bak_percommit));
    memcpy(bak_remotecommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], sizeof(bak_remotecommit));
    uint64_t bak_commit_num = self->commit_local.commit_num;

    //local
    //  +0: 次に送信するnext_per_commitment_secret
    //  +1: 現在のnext_per_commitment_secret
    //  +2: 現在のper_commitment_secret
    ln_signer_keys_update(self, 2);
    //commitment number(for obscured commitment number)
    self->commit_local.commit_num--;        //create_to_local()内でインクリメントされるため、引いておく

    //remote
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->funding_remote.prev_percommit, UCOIN_SZ_PUBKEY);

    //update keys
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + self->commit_local.htlc_num);

    //local commit_tx
    bool ret = create_to_local(self, pClose, NULL, 0,
                self->commit_remote.to_self_delay,
                self->commit_local.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create_to_local\n");
        ln_free_close_force_tx(pClose);
    }

    //元に戻す
    self->commit_local.commit_num = bak_commit_num;
    memcpy(self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT],
            bak_percommit, sizeof(bak_percommit));
    ucoin_keys_priv2pub(self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT]);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            bak_remotecommit, sizeof(bak_remotecommit));
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    DBG_PRINTF("END: %d\n", ret);

    return ret;
}


/*
 * funding_txがspentで、remote commit_txのtxidがgetrawtransactionできる状態で呼ばれる。
 * (remote commit_txが展開＝相手がunilateral closeした)
 */
bool ln_create_closed_tx(ln_self_t *self, ln_close_force_t *pClose)
{
    DBG_PRINTF("BEGIN\n");

    //local
    //  +0: 次に送信するnext_per_commitment_secret
    //  +1: 現在のnext_per_commitment_secret
    //  +2: 現在のper_commitment_secret
    ln_signer_keys_update(self, 2);

    //remote
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
            self->funding_remote.prev_percommit, UCOIN_SZ_PUBKEY);
    //commitment number(for obscured commitment number)
    self->commit_remote.commit_num--;   //create_to_remote()内でインクリメントされるため、引いておく

    //update keys
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + self->commit_remote.htlc_num);

    //remote commit_tx
    bool ret = create_to_remote(self, pClose, NULL,
                self->commit_local.to_self_delay,
                self->commit_remote.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create_to_remote\n");
        ln_free_close_force_tx(pClose);
    }

    DBG_PRINTF("END\n");
    return ret;
}


void ln_free_close_force_tx(ln_close_force_t *pClose)
{
    for (int lp = 0; lp < pClose->num; lp++) {
        ucoin_tx_free(&pClose->p_tx[lp]);
    }
    pClose->num = 0;
    M_FREE(pClose->p_tx);
    pClose->p_tx = NULL;
    M_FREE(pClose->p_htlc_idx);
    pClose->p_htlc_idx = NULL;

    int num = pClose->tx_buf.len / sizeof(ucoin_tx_t);
    ucoin_tx_t *p_tx = (ucoin_tx_t *)pClose->tx_buf.buf;
    for (int lp = 0; lp < num; lp++) {
        ucoin_tx_free(&p_tx[lp]);
    }
    ucoin_buf_free(&pClose->tx_buf);
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
bool ln_close_ugly(ln_self_t *self, const ucoin_tx_t *pRevokedTx, void *pDbParam)
{
    //取り戻す必要があるvout数
    self->revoked_cnt = 0;
    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        if (pRevokedTx->vout[lp].script.len != LNL_SZ_WITPROG_WPKH) {
            //to_remote output以外はスクリプトを作って取り戻す
            self->revoked_cnt++;
        }
    }
    DBG_PRINTF("revoked_cnt=%d\n", self->revoked_cnt);
    self->revoked_num = LN_RCLOSE_IDX_HTLC + self->revoked_cnt;  //[0]to_local, [1]to_remote, [2-]HTLC
    ln_alloc_revoked_buf(self);

    //
    //相手がrevoked_txを展開した前提で、スクリプトを再現
    //

    //commitment numberの復元
    uint64_t commit_num = ((uint64_t)(pRevokedTx->vin[0].sequence & 0xffffff)) << 24;
    commit_num |= (uint64_t)(pRevokedTx->locktime & 0xffffff);
    commit_num ^= self->obscured;
    DBG_PRINTF("commit_num=%" PRIx64 "\n", commit_num);

    //remote per_commitment_secretの復元
    ucoin_buf_alloc(&self->revoked_sec, UCOIN_SZ_PRIVKEY);
    bool ret = ln_derkey_storage_get_secret(self->revoked_sec.buf, &self->peer_storage, (uint64_t)(LN_SECINDEX_INIT - commit_num));
    assert(ret);
    ucoin_keys_priv2pub(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], self->revoked_sec.buf);
    //DBG_PRINTF2("  pri:");
    //DUMPBIN(self->revoked_sec.buf, UCOIN_SZ_PRIVKEY);
    //DBG_PRINTF2("  pub:");
    //DUMPBIN(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);

    //local per_commitment_secretの復元
    ln_signer_keys_update_force(self, (uint64_t)(LN_SECINDEX_INIT - commit_num));

    //鍵の復元
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    //commitment number(for obscured commitment number)
    self->commit_remote.commit_num = commit_num;

    //to_local outputとHTLC Timeout/Success Txのoutputは同じ形式のため、to_local outputの有無にかかわらず作っておく。
    //p_revoked_vout[0]にはscriptPubKey、p_revoked_wit[0]にはwitnessProgramを作る。
    ln_create_script_local(&self->p_revoked_wit[LN_RCLOSE_IDX_TOLOCAL],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                self->commit_local.to_self_delay);
    ucoin_buf_alloc(&self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL], LNL_SZ_WITPROG_WSH);
    ucoin_sw_wit2prog_p2wsh(self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].buf, &self->p_revoked_wit[LN_RCLOSE_IDX_TOLOCAL]);
    DBG_PRINTF("calc to_local vout: ");
    DUMPBIN(self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].buf, self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL].len);

    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        DBG_PRINTF("vout[%d]: ", lp);
        DUMPBIN(pRevokedTx->vout[lp].script.buf, pRevokedTx->vout[lp].script.len);
        if (pRevokedTx->vout[lp].script.len == LNL_SZ_WITPROG_WPKH) {
            //to_remote output
            DBG_PRINTF("[%d]to_remote_output\n", lp);
            ucoin_buf_init(&self->p_revoked_wit[LN_RCLOSE_IDX_TOREMOTE]);
            ucoin_buf_alloccopy(&self->p_revoked_vout[LN_RCLOSE_IDX_TOREMOTE], pRevokedTx->vout[lp].script.buf, pRevokedTx->vout[lp].script.len);
        } else if (ucoin_buf_cmp(&pRevokedTx->vout[lp].script, &self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL])) {
            //to_local output
            DBG_PRINTF("[%d]to_local_output\n", lp);
        } else {
            //HTLC Tx
            //  DBには、vout(SHA256後)をkeyにして、payment_hashを保存している。
            ln_htlctype_t type;
            uint8_t payhash[LN_SZ_HASH];
            uint32_t expiry;
            bool srch = ln_db_phash_search(payhash, &type, &expiry,
                            pRevokedTx->vout[lp].script.buf, pDbParam);
            if (srch) {
                DBG_PRINTF("[%d]detect!\n", lp);

                ln_create_htlcinfo(&self->p_revoked_wit[LN_RCLOSE_IDX_HTLC + lp],
                        type,
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                        payhash,
                        expiry);
                ucoin_buf_alloc(&self->p_revoked_vout[LN_RCLOSE_IDX_HTLC + lp], LNL_SZ_WITPROG_WSH);
                ucoin_sw_wit2prog_p2wsh(self->p_revoked_vout[LN_RCLOSE_IDX_HTLC + lp].buf, &self->p_revoked_wit[LN_RCLOSE_IDX_HTLC + lp]);
                self->p_revoked_type[LN_RCLOSE_IDX_HTLC + lp] = type;
            } else {
                DBG_PRINTF("[%d]not detect\n", lp);
            }
        }
    }

    DBG_PRINTF("ret=%d\n", ret);
    return ret;
}


/********************************************************************
 * Normal Operation関係
 ********************************************************************/

bool ln_create_add_htlc(ln_self_t *self,
            ucoin_buf_t *pAdd,
            uint64_t *pHtlcId,
            ucoin_buf_t *pReason,
            const uint8_t *pPacket,
            uint64_t amount_msat,
            uint32_t cltv_value,
            const uint8_t *pPaymentHash,
            uint64_t prev_short_channel_id,
            uint64_t prev_id,
            const ucoin_buf_t *pSharedSecrets)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;
    int idx;
    ret = check_create_add_htlc(self, &idx, pReason, amount_msat, cltv_value);
    if (ret) {
        self->cnl_add_htlc[idx].flag = LN_HTLC_FLAG_SEND;        //送信
        self->cnl_add_htlc[idx].p_channel_id = self->channel_id;
        self->cnl_add_htlc[idx].id = self->htlc_id_num;
        self->cnl_add_htlc[idx].amount_msat = amount_msat;
        self->cnl_add_htlc[idx].cltv_expiry = cltv_value;
        memcpy(self->cnl_add_htlc[idx].payment_sha256, pPaymentHash, LN_SZ_HASH);
        self->cnl_add_htlc[idx].p_onion_route = (CONST_CAST uint8_t *)pPacket;
        self->cnl_add_htlc[idx].prev_short_channel_id = prev_short_channel_id;
        self->cnl_add_htlc[idx].prev_id = prev_id;
        ucoin_buf_free(&self->cnl_add_htlc[idx].shared_secret);
        if (pSharedSecrets) {
            ucoin_buf_alloccopy(&self->cnl_add_htlc[idx].shared_secret, pSharedSecrets->buf, pSharedSecrets->len);
        }
        ret = ln_msg_update_add_htlc_create(pAdd, &self->cnl_add_htlc[idx]);
        if (!ret && (pReason != NULL)) {
            DBG_PRINTF("fail: temporary_node_failure\n");
            ln_create_reason_temp_node(pReason);
        }
    }
    if (ret) {
        self->our_msat -= amount_msat;
        self->htlc_id_num++;        //offer時にインクリメント
        self->htlc_num++;
        *pHtlcId = self->cnl_add_htlc[idx].id;
        DBG_PRINTF("HTLC add : htlc_num=%d, prev_short_channel_id=%" PRIu64 "\n", self->htlc_num, self->cnl_add_htlc[idx].prev_short_channel_id);
    } else {
        M_SET_ERR(self, LNERR_MSG_ERROR, "create update_add_htlc");
    }

    DBG_PRINTF("END\n");
    return ret;
}


bool ln_create_fulfill_htlc(ln_self_t *self, ucoin_buf_t *pFulfill, uint64_t id, const uint8_t *pPreImage)
{
    DBG_PRINTF("BEGIN\n");

    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished");
        return false;
    }
    uint8_t sha256[LN_SZ_HASH];
    ucoin_util_sha256(sha256, pPreImage, LN_SZ_PREIMAGE);
    DBG_PRINTF("id= %" PRIu64 "\n", id);
    DBG_PRINTF("recv payment_sha256= ");
    DUMPBIN(sha256, LN_SZ_PREIMAGE);
    ln_update_add_htlc_t *p_add = NULL;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //fulfill送信はReceived Outputに対して行う
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            DBG_PRINTF("LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag)=%d\n", LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag));
            DBG_PRINTF("htlc_id=%" PRIu64 "\n", self->cnl_add_htlc[idx].id);
            DBG_PRINTF("payment_sha256= ");
            DUMPBIN(self->cnl_add_htlc[idx].payment_sha256, LN_SZ_PREIMAGE);
            if ( LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag) &&
                 (id == self->cnl_add_htlc[idx].id) &&
                 (memcmp(sha256, self->cnl_add_htlc[idx].payment_sha256, LN_SZ_HASH) == 0) ) {
                //
                p_add = &self->cnl_add_htlc[idx];
                break;
            }
        }
    }
    if (p_add == NULL) {
        M_SET_ERR(self, LNERR_INV_PREIMAGE, "preimage not mismatch");
        return false;
    }
    if (p_add->amount_msat == 0) {
        M_SET_ERR(self, LNERR_INV_ID, "invalid id");
        return false;
    }

    bool ret;
    ln_update_fulfill_htlc_t fulfill_htlc;

    fulfill_htlc.p_channel_id = self->channel_id;
    fulfill_htlc.id = p_add->id;
    fulfill_htlc.p_payment_preimage = (CONST_CAST uint8_t *)pPreImage;
    ret = ln_msg_update_fulfill_htlc_create(pFulfill, &fulfill_htlc);
    if (ret) {
        //反映
        self->our_msat += p_add->amount_msat;
        //self->their_msat -= p_add->amount_msat;   //add_htlc受信時に引いているので、ここでは不要

        clear_htlc(self, p_add);
    } else {
        M_SET_ERR(self, LNERR_MSG_ERROR, "create update_fulfill_htlc");
    }

    DBG_PRINTF("END\n");
    return ret;
}


bool ln_create_fail_htlc(ln_self_t *self, ucoin_buf_t *pFail, uint64_t id, const ucoin_buf_t *pReason)
{
    DBG_PRINTF("BEGIN\n");

    if (!M_INIT_FLAG_EXCHNAGED(self->init_flag)) {
        M_SET_ERR(self, LNERR_INV_STATE, "no init finished");
        return false;
    }
    ln_update_add_htlc_t *p_add = NULL;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //fulfill送信はReceived Outputに対して行う
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            DBG_PRINTF("id=%" PRIx64 ", htlc_id=%" PRIu64 "\n", id, self->cnl_add_htlc[idx].id);
            if ( LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag) &&
                 (id == self->cnl_add_htlc[idx].id) ) {
                p_add = &self->cnl_add_htlc[idx];
                break;
            }
        }
    }
    if (p_add == NULL) {
        M_SET_ERR(self, LNERR_INV_ID, "invalid id 1");
        return false;
    }
    if (p_add->amount_msat == 0) {
        M_SET_ERR(self, LNERR_INV_ID, "invalid id 2");
        return false;
    }

    bool ret;
    ln_update_fail_htlc_t fail_htlc;

    fail_htlc.p_channel_id = self->channel_id;
    fail_htlc.id = p_add->id;
    fail_htlc.p_reason = (CONST_CAST ucoin_buf_t *)pReason;
    ret = ln_msg_update_fail_htlc_create(pFail, &fail_htlc);
    if (ret) {
        //反映
        self->their_msat += p_add->amount_msat;   //add_htlc受信時に引いた分を戻す

        clear_htlc(self, p_add);
    } else {
        M_SET_ERR(self, LNERR_MSG_ERROR, "create update_fail_htlc");
    }

    DBG_PRINTF("END\n");
    return ret;
}


bool ln_create_commit_signed(ln_self_t *self, ucoin_buf_t *pCommSig)
{
    DBG_PRINTF("BEGIN\n");

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
    M_FREE(p_htlc_sigs);

    proc_commitment_signed(self, M_COMISG_FLAG_SEND);

    DBG_PRINTF("END\n");
    return ret;
}


/********************************************************************
 * その他
 ********************************************************************/

bool ln_create_ping(ln_self_t *self, ucoin_buf_t *pPing)
{
    ln_ping_t ping;

    // if (self->last_num_pong_bytes != 0) {
    //     DBG_PRINTF("not receive pong(last_num_pong_bytes=%d)\n", self->last_num_pong_bytes);
    //     return false;
    // }

#if 1
    // https://github.com/lightningnetwork/lightning-rfc/issues/373
    //  num_pong_bytesが大きすぎると無視される？
    uint8_t r;
    ucoin_util_random(&r, 1);
    self->last_num_pong_bytes = r;
    ucoin_util_random(&r, 1);
    ping.byteslen = r;
#else
    ucoin_util_random((uint8_t *)&self->last_num_pong_bytes, 2);
    ucoin_util_random((uint8_t *)&ping.byteslen, 2);
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


bool ln_create_pong(ln_self_t *self, ucoin_buf_t *pPong, uint16_t NumPongBytes)
{
    (void)self;

    ln_pong_t pong;

    pong.byteslen = NumPongBytes;
    bool ret = ln_msg_pong_create(pPong, &pong);

    return ret;
}


bool ln_create_tolocal_spent(const ln_self_t *self, ucoin_tx_t *pTx, uint64_t Value, uint32_t to_self_delay,
                const ucoin_buf_t *pScript, const uint8_t *pTxid, int Index, bool bRevoked)
{
    bool ret;

    //to_localのFEE
    uint64_t fee_tolocal = ln_calc_fee(M_SZ_TO_LOCAL_TX(self->shutdown_scriptpk_local.len), self->feerate_per_kw);
    DBG_PRINTF("fee_tolocal=%" PRIu64 "\n", fee_tolocal);
    if (Value < UCOIN_DUST_LIMIT + fee_tolocal) {
        DBG_PRINTF("fail: vout below dust(value=%" PRIu64 ", fee=%" PRIu64 ")\n", Value, fee_tolocal);
        goto LABEL_EXIT;
    }
    ret = ln_create_tolocal_tx(pTx, Value - fee_tolocal,
            &self->shutdown_scriptpk_local, to_self_delay, pTxid, Index, bRevoked);
    if (!ret) {
        goto LABEL_EXIT;
    }

    ret = ln_signer_tolocal_tx(self, pTx, Value, pScript, bRevoked);

LABEL_EXIT:
    return ret;
}


bool ln_create_toremote_spent(const ln_self_t *self, ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pTxid, int Index)
{
    bool ret;
    ucoin_util_keys_t signkey;

    //to_remoteのFEE
    uint64_t fee_toremote = ln_calc_fee(M_SZ_TO_REMOTE_TX(self->shutdown_scriptpk_local.len), self->feerate_per_kw);
    if (Value < UCOIN_DUST_LIMIT + fee_toremote) {
        DBG_PRINTF("fail: vout below dust(value=%" PRIu64 ", fee=%" PRIu64 ")\n", Value, fee_toremote);
        ret = false;
        goto LABEL_EXIT;
    }

    // remotekeyへの支払いを self->shutdown_scriptpk_local に送金する
    //  通常のP2WPKHなので、bRevoedはfalse扱い
    //  to_local用の関数を使っているが、最低限の設定をしているだけなので同じ処理でよい
    ucoin_tx_init(pTx);

    ret = ln_create_tolocal_tx(pTx, Value - fee_toremote,
            &self->shutdown_scriptpk_local, 0, pTxid, Index, false);
    if (!ret) {
        DBG_PRINTF("fail: create to_remote tx\n");
        goto LABEL_EXIT;
    }
    //<remotesecretkey>
    //  revoked transaction close後はremotekeyも当時のものになっているため、同じ処理でよい
    ln_signer_get_secret(self, &signkey, MSG_FUNDIDX_PAYMENT,
        self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
    assert(memcmp(signkey.pub, self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY], UCOIN_SZ_PUBKEY) == 0);
    //DBG_PRINTF("key-priv: ");
    //DUMPBIN(signkey.priv, UCOIN_SZ_PRIVKEY);
    //DBG_PRINTF("key-pub : ");
    //DUMPBIN(signkey.pub, UCOIN_SZ_PUBKEY);

    //vinは1つしかない
    ret = ln_signer_p2wpkh(pTx, 0, Value, &signkey);

LABEL_EXIT:
    return ret;
}


bool ln_create_revokedhtlc_spent(const ln_self_t *self, ucoin_tx_t *pTx, uint64_t Value,
                int WitIndex, const uint8_t *pTxid, int Index)
{
    ln_feeinfo_t feeinfo;
    feeinfo.feerate_per_kw = self->feerate_per_kw;
    ln_fee_calc(&feeinfo, NULL, 0);
    uint64_t fee = (self->p_revoked_type[WitIndex] == LN_HTLCTYPE_OFFERED) ? feeinfo.htlc_timeout : feeinfo.htlc_success;
    DBG_PRINTF("Value=%" PRIu64 ", fee=%" PRIu64 "\n", Value, fee);

    ln_create_htlc_tx(pTx, Value - fee, &self->shutdown_scriptpk_local, self->p_revoked_type[WitIndex], 0, pTxid, Index);
    M_DBG_PRINT_TX2(pTx);

    ucoin_util_keys_t signkey;
    ln_signer_get_revokesec(self, &signkey,
                    self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
                    self->revoked_sec.buf);
    // DBG_PRINTF("key-priv: ");
    // DUMPBIN(signkey.priv, UCOIN_SZ_PRIVKEY);
    // DBG_PRINTF("key-pub : ");
    // DUMPBIN(signkey.pub, UCOIN_SZ_PUBKEY);

    ucoin_buf_t buf_sig;
    ln_htlcsign_t htlcsign = HTLCSIGN_NONE;
    switch (self->p_revoked_type[WitIndex]) {
    case LN_HTLCTYPE_OFFERED:
        htlcsign = HTLCSIGN_RV_OFFERED;
        break;
    case LN_HTLCTYPE_RECEIVED:
        htlcsign = HTLCSIGN_RV_RECEIVED;
        break;
    default:
        DBG_PRINTF("index=%d, %d\n", WitIndex, self->p_revoked_type[WitIndex]);
        assert(0);
    }
    bool ret;
    if (htlcsign != HTLCSIGN_NONE) {
        ret = ln_sign_htlc_tx(pTx,
                &buf_sig,
                Value,
                &signkey,
                NULL,
                NULL,
                &self->p_revoked_wit[WitIndex],
                htlcsign);
        ucoin_buf_free(&buf_sig);
    } else {
        ret = false;
    }

    return ret;
}


void ln_calc_preimage_hash(uint8_t *pHash, const uint8_t *pPreImage)
{
    ucoin_util_sha256(pHash, pPreImage, LN_SZ_PREIMAGE);
}


void ln_create_reason_temp_node(ucoin_buf_t *pReason)
{
    //A2. if an otherwise unspecified transient error occurs for the entire node:
    //      temporary_node_failure
    uint16_t code = (LNONION_TMP_NODE_FAIL >> 8) | ((LNONION_TMP_NODE_FAIL & 0xff) << 8);
    ucoin_buf_alloccopy(pReason, (uint8_t *)&code, sizeof(code));
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
    if (ret) {
        *p_short_channel_id = ann.short_channel_id;
        memcpy(pNodeId1, ann.node_id1, UCOIN_SZ_PUBKEY);
        memcpy(pNodeId2, ann.node_id2, UCOIN_SZ_PUBKEY);
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
    DBG_PRINTF("debug flag: 0x%lx\n", mDebug);
    if (!mDebug) DBG_PRINTF("normal mode\n");
    if (!LN_DBG_FULFILL()) DBG_PRINTF("no fulfill\n");
    if (!LN_DBG_CLOSING_TX()) DBG_PRINTF("no send closing_tx\n");
    if (!LN_DBG_MATCH_PREIMAGE()) DBG_PRINTF("HTLC preimage mismatch\n");
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
    DBG_PRINTF("alloc(%d)\n", self->revoked_num);

    self->p_revoked_vout = (ucoin_buf_t *)M_MALLOC(sizeof(ucoin_buf_t) * self->revoked_num);
    self->p_revoked_wit = (ucoin_buf_t *)M_MALLOC(sizeof(ucoin_buf_t) * self->revoked_num);
    self->p_revoked_type = (ln_htlctype_t *)M_MALLOC(sizeof(ln_htlctype_t) * self->revoked_num);
    for (int lp = 0; lp < self->revoked_num; lp++) {
        ucoin_buf_init(&self->p_revoked_vout[lp]);
        ucoin_buf_init(&self->p_revoked_wit[lp]);
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
        ucoin_buf_free(&self->p_revoked_vout[lp]);
        ucoin_buf_free(&self->p_revoked_wit[lp]);
    }
    M_FREE(self->p_revoked_vout);
    M_FREE(self->p_revoked_wit);
    M_FREE(self->p_revoked_type);
    self->revoked_num = 0;
    self->revoked_cnt = 0;

    DBG_PRINTF("free\n");
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
    //DBG_PRINTF2("***************************************************\n");
    //DBG_PRINTF("\n");
    //DBG_PRINTF2("***************************************************\n");

    ucoin_buf_free(&self->shutdown_scriptpk_local);
    ucoin_buf_free(&self->shutdown_scriptpk_remote);
    ucoin_buf_free(&self->redeem_fund);
    ucoin_buf_free(&self->cnl_anno);
    ucoin_buf_free(&self->revoked_sec);
    ln_free_revoked_buf(self);

    ucoin_tx_free(&self->tx_funding);
    ucoin_tx_free(&self->tx_closing);

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        self->cnl_add_htlc[idx].p_onion_route = NULL;
        ucoin_buf_free(&self->cnl_add_htlc[idx].shared_secret);
    }

    memset(self->peer_node_id, 0, UCOIN_SZ_PUBKEY);
    self->anno_flag = 0;
    self->shutdown_flag = 0;

    free_establish(self, true);
}


/********************************************************************
 * メッセージ受信
 ********************************************************************/

static bool recv_init(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;

    if (self->init_flag & M_INIT_FLAG_RECV) {
        //TODO: 2回init受信した場合はどうする？
        DBG_PRINTF("???: multiple init received.\n");
    }

    ln_init_t msg;
    ucoin_buf_init(&msg.globalfeatures);
    ucoin_buf_init(&msg.localfeatures);
    ret = ln_msg_init_read(&msg, pData, Len);
#warning issue#45
    if (ret) {
        ret &= (msg.globalfeatures.len == 0);
    }

    bool initial_routing_sync = false;
    if (ret) {
        ret &= (msg.localfeatures.len <= 1);
        if (msg.localfeatures.len == 1) {
            //2018/01/31(comit: 2c3466a2af8e62215b9240f9932256a509652b5d)
            //      https://github.com/lightningnetwork/lightning-rfc/blob/2c3466a2af8e62215b9240f9932256a509652b5d/09-features.md#assigned-localfeatures-flags
            //  bit0/1 : option-data-loss-protect
            //  bit3   : initial_routing_sync
            //  bit4/5 : option_upfront_shutdown_script
            ret &= ((msg.localfeatures.buf[0] & (~INIT_LF_MASK)) == 0);
            initial_routing_sync = (msg.localfeatures.buf[0] & INIT_LF_ROUTE_SYNC);
        }
    }
    if (ret) {
        self->init_flag |= M_INIT_FLAG_RECV;

        //init受信通知
        (*self->p_callback)(self, LN_CB_INIT_RECV, &initial_routing_sync);
    } else {
        M_SET_ERR(self, LNERR_INV_FEATURE, "init error");
    }
    ucoin_buf_free(&msg.localfeatures);
    ucoin_buf_free(&msg.globalfeatures);

    return ret;
}


static bool recv_error(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("\n");

    if (ln_is_funding(self)) {
        DBG_PRINTF("stop funding\n");
        free_establish(self, false);    //切断せずに継続する場合もあるため、残す
    }

    ln_error_t err;
    ln_msg_error_read(&err, pData, Len);
    (*self->p_callback)(self, LN_CB_ERROR, &err);
    M_SET_ERR(self, LNERR_MSG_ERROR, err.p_data);
    M_FREE(err.p_data);

    return true;
}


static bool recv_ping(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //DBG_PRINTF("BEGIN\n");

    bool ret;

    ln_ping_t ping;
    ret = ln_msg_ping_read(&ping, pData, Len);
    if (!ret) {
        M_SET_ERR(self, LNERR_MSG_READ, "read message");
        return false;
    }

    //脊髄反射的にpongを返す
    ucoin_buf_t buf_bolt;
    ret = ln_create_pong(self, &buf_bolt, ping.num_pong_bytes);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //DBG_PRINTF("END\n");
    return ret;
}


static bool recv_pong(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    //DBG_PRINTF("BEGIN\n");

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
        //DBG_PRINTF("missing_pong_cnt: %d / last_num_pong_bytes: %d\n", self->missing_pong_cnt, self->last_num_pong_bytes);
        self->last_num_pong_bytes = 0;
    } else {
        DBG_PRINTF("fail: pong.byteslen(%" PRIu16 ") != self->last_num_pong_bytes(%" PRIu16 ")\n", pong.byteslen, self->last_num_pong_bytes);
    }

    //DBG_PRINTF("END\n");
    return true;
}


static bool recv_open_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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
    (*self->p_callback)(self, LN_CB_FEERATE_REQ, NULL);

    //feerate_per_kwの許容チェック
    const uint32_t MARGIN = M_FEERATE_MARGIN(self->feerate_per_kw);
    if (self->feerate_per_kw - MARGIN > open_ch->feerate_per_kw) {
        DBG_PRINTF("fail: feerate_per_kw is too short\n");
        return false;
    }
    if (self->feerate_per_kw + MARGIN < open_ch->feerate_per_kw) {
        DBG_PRINTF("fail: feerate_per_kw is too large\n");
        return false;
    }

    self->commit_remote.dust_limit_sat = open_ch->dust_limit_sat;
    self->commit_remote.max_htlc_value_in_flight_msat = open_ch->max_htlc_value_in_flight_msat;
    self->commit_remote.channel_reserve_sat = open_ch->channel_reserve_sat;
    self->commit_remote.htlc_minimum_msat = open_ch->htlc_minimum_msat;
    self->commit_remote.to_self_delay = open_ch->to_self_delay;
    self->commit_remote.max_accepted_htlcs = open_ch->max_accepted_htlcs;

    //first_per_commitment_pointは初回revoke_and_ackのper_commitment_secretに対応する
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);

    self->funding_sat = open_ch->funding_sat;
    self->feerate_per_kw = open_ch->feerate_per_kw;
    self->our_msat = open_ch->push_msat;
    self->their_msat = LN_SATOSHI2MSAT(open_ch->funding_sat) - open_ch->push_msat;

    //鍵生成 && スクリプト用鍵生成
    ret = ln_signer_create_channelkeys(self);
    if (!ret) {
        DBG_PRINTF("fail: ln_signer_create_channelkeys\n");
        return false;
    }

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
    ucoin_buf_t buf_bolt;
    ln_msg_accept_channel_create(&buf_bolt, acc_ch);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

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
    DBG_PRINTF("obscured=0x%" PRIx64 "\n", self->obscured);

    //vout 2-of-2
    ret = ucoin_util_create2of2(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING], self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);
    if (ret) {
        self->htlc_num = 0;
        self->fund_flag = ((open_ch->channel_flags & 1) ? LN_FUNDFLAG_ANNO_CH : 0) | LN_FUNDFLAG_FUNDING;
    } else {
        M_SET_ERR(self, LNERR_CREATE_2OF2, "create 2-of-2");
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_accept_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);

    //スクリプト用鍵生成
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    self->htlc_num = 0;

    //funding_tx作成
    ret = create_funding_tx(self);
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
    DBG_PRINTF("obscured=0x%" PRIx64 "\n", self->obscured);

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

        ucoin_buf_t buf_bolt;
        ln_msg_funding_created_create(&buf_bolt, fundc);
        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_funding_created(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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
    ucoin_tx_free(&self->tx_funding);
    for (int lp = 0; lp < self->funding_local.txindex; lp++) {
        //処理の都合上、voutの位置を調整している
        ucoin_tx_add_vout(&self->tx_funding, 0);
    }
    ucoin_sw_add_vout_p2wsh(&self->tx_funding, self->p_establish->cnl_open.funding_sat, &self->redeem_fund);
    //TODO: 実装上、vinが0、voutが1だった場合にsegwitと誤認してしまう
    ucoin_tx_add_vin(&self->tx_funding, self->funding_local.txid, 0);

    //署名チェック
    // initial commit tx(自分が持つTo-Local)
    //      to-self-delayは自分の値(open_channel)を使う
    //      HTLCは存在しない
    ret = create_to_local(self, NULL, NULL, 0,
                self->p_establish->cnl_open.to_self_delay, self->p_establish->cnl_accept.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create_to_local\n");
        return false;
    }

    // initial commit tx(Remoteが持つTo-Local)
    //      署名計算のみのため、計算後は破棄する
    //      HTLCは存在しないため、計算省略
    ret = create_to_remote(self, NULL, NULL,
                self->p_establish->cnl_accept.to_self_delay, self->p_establish->cnl_open.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create_to_remote\n");
        return false;
    }

    //正式チャネルID
    ln_misc_calc_channel_id(self->channel_id, self->funding_local.txid, self->funding_local.txindex);

    //funding_signed
    self->p_establish->cnl_funding_signed.p_channel_id = self->channel_id;
    self->p_establish->cnl_funding_signed.p_signature = self->commit_local.signature;

    ucoin_buf_t buf_bolt;
    ln_msg_funding_signed_create(&buf_bolt, &self->p_establish->cnl_funding_signed);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    //funding_tx安定待ち(シーケンスの再開はアプリ指示)
    start_funding_wait(self, false);

    DBG_PRINTF("END\n");
    return true;
}


static bool recv_funding_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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
        DBG_PRINTF("fail: create_to_local\n");
        return false;
    }

    //funding_tx安定待ち(シーケンスの再開はアプリ指示)
    start_funding_wait(self, true);

    DBG_PRINTF("END\n");
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
    DBG_PRINTF("BEGIN\n");

    bool ret;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t per_commitpt[UCOIN_SZ_PUBKEY];
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

    DBG_PRINTF("prev: ");
    DUMPBIN(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);
    DBG_PRINTF("next: ");
    DUMPBIN(per_commitpt, UCOIN_SZ_PUBKEY);

    //prev_percommitはrevoke_and_ackでのみ更新する
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], per_commitpt, UCOIN_SZ_PUBKEY);

    //funding中終了
    free_establish(self, true);

    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_db_self_save(self);

    (*self->p_callback)(self, LN_CB_FUNDINGLOCKED_RECV, NULL);

    DBG_PRINTF("END\n");
    return true;
}


static bool recv_shutdown(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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

    ucoin_buf_t buf_bolt = UCOIN_BUF_INIT;
    if (!(self->shutdown_flag & M_SHDN_FLAG_SEND)) {
        //shutdown未送信の場合 == shutdownを要求された方

        //feeと送金先を設定してもらう
        (*self->p_callback)(self, LN_CB_SHUTDOWN_RECV, NULL);

        ret = ln_create_shutdown(self, &buf_bolt);
        if (ret) {
            (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
            ucoin_buf_free(&buf_bolt);
        } else {
            M_SET_ERR(self, LNERR_CREATE_MSG, "create shutdown");
        }
    }

    if (M_SHDN_FLAG_EXCHANGED(self->shutdown_flag) && ln_is_funder(self)) {
        //shutdown交換完了 && funder --> 最初のclosing_signed送信
        DBG_PRINTF("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
        ln_closing_signed_t cnl_close;
        cnl_close.p_channel_id = self->channel_id;
        cnl_close.fee_sat = self->close_fee_sat;
        cnl_close.p_signature = self->commit_local.signature;

        //remoteの署名はないので、verifyしない
        ucoin_tx_free(&self->tx_closing);
        ret = create_closing_tx(self, &self->tx_closing, self->close_fee_sat, false);
        if (ret) {
            ret = ln_msg_closing_signed_create(&buf_bolt, &cnl_close);
        } else {
            DBG_PRINTF("fail: create close_t\n");
        }
        if (ret) {
            self->close_last_fee_sat = self->close_fee_sat;
            (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
            ucoin_buf_free(&buf_bolt);
        } else {
            DBG_PRINTF("fail\n");
        }
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_closing_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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
        DBG_PRINTF("fail: fee too large(%" PRIu64 " > %" PRIu64 ")\n", cnl_close.fee_sat, feemax);
        return false;
    }

    //相手が要求するFEEでverify
    ucoin_tx_free(&self->tx_closing);
    ret = create_closing_tx(self, &self->tx_closing, cnl_close.fee_sat, true);
    if (!ret) {
        DBG_PRINTF("fail: create close_t\n");
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
    ucoin_tx_free(&self->tx_closing);
    ret = create_closing_tx(self, &self->tx_closing, self->close_fee_sat, need_closetx);
    if (!ret) {
        DBG_PRINTF("fail: create close_t\n");
        assert(false);
    }

    if (need_closetx) {
        //closing_txを展開する
        DBG_PRINTF("same fee!\n");
        ucoin_buf_t txbuf = UCOIN_BUF_INIT;
        ret = ucoin_tx_create(&txbuf, &self->tx_closing);
        if (ret) {
            ln_cb_closed_t closed;

            closed.p_tx_closing = &txbuf;
            (*self->p_callback)(self, LN_CB_CLOSED, &closed);

            //clearはDB削除に任せる
            //channel_clear(self);
        } else {
            DBG_PRINTF("fail: create closeing_tx\n");
            assert(0);
        }
        ucoin_buf_free(&txbuf);
    } else {
        //closing_singnedを送信する
        DBG_PRINTF("different fee!\n");
        ucoin_buf_t buf_bolt = UCOIN_BUF_INIT;
        ret = ln_msg_closing_signed_create(&buf_bolt, &cnl_close);
        if (ret) {
            self->close_last_fee_sat = self->close_fee_sat;
            (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        } else {
            DBG_PRINTF("fail: create closeing_signed\n");
            assert(0);
        }
        ucoin_buf_free(&buf_bolt);
    }

    //closing_signedの交換を1度でも行っていたら、obscuredを0にしてしまう(フラグ代わり)
    if (!ln_is_closing_signed_recvd(self)) {
        DBG_PRINTF("closing_signed exchanged\n");
        self->obscured = 0;
        ln_db_self_save(self);
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_update_add_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t onion_route[LN_SZ_ONION_ROUTE];
    self->cnl_add_htlc[idx].p_channel_id = channel_id;
    self->cnl_add_htlc[idx].p_onion_route = onion_route;
    ret = ln_msg_update_add_htlc_read(&self->cnl_add_htlc[idx], pData, Len);
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
    ret = check_recv_add_htlc_bolt2(self, idx);
    if (!ret) {
        DBG_PRINTF("fail: BOLT2 check\n");
        return false;
    }


    //
    //BOLT4 check
    //  BOLT2 checkにより、update_add_htlcとしては受入可能。
    //  ただし、onionやpayeeのinvoiceチェックによりfailになる可能性がある。
    //
    ln_hop_dataout_t hop_dataout;   // update_add_htlc受信後のONION解析結果
    ln_cb_add_htlc_recv_t add_htlc;
    const uint8_t *p_payment = NULL;
    uint8_t preimage[LN_SZ_PREIMAGE];

    ret = check_recv_add_htlc_bolt4(self, &hop_dataout, (uint8_t **)&p_payment, preimage, &add_htlc.reason, idx);


    //相手のamountから差し引いて、HTLC追加
    self->their_msat -= self->cnl_add_htlc[idx].amount_msat;
    self->htlc_num++;
    DBG_PRINTF("HTLC add : htlc_num=%d, id=%" PRIx64 ", amount_msat=%" PRIu64 "\n", self->htlc_num, self->cnl_add_htlc[idx].id, self->cnl_add_htlc[idx].amount_msat);

    DBG_PRINTF2("  ret=%d\n", ret);
    DBG_PRINTF2("  id=%" PRIu64 "\n", self->cnl_add_htlc[idx].id);

    DBG_PRINTF2("  %s\n", (hop_dataout.b_exit) ? "intended recipient" : "forwarding HTLCs");
    //転送先
    DBG_PRINTF2("  FWD: short_channel_id: %" PRIx64 "\n", hop_dataout.short_channel_id);
    DBG_PRINTF2("  FWD: amt_to_forward: %" PRIu64 "\n", hop_dataout.amt_to_forward);
    DBG_PRINTF2("  FWD: outgoing_cltv_value: %d\n", hop_dataout.outgoing_cltv_value);
    DBG_PRINTF2("  -------\n");
    //自分への通知
    DBG_PRINTF2("  amount_msat: %" PRIu64 "\n", self->cnl_add_htlc[idx].amount_msat);
    DBG_PRINTF2("  cltv_expiry: %d\n", self->cnl_add_htlc[idx].cltv_expiry);
    DBG_PRINTF2("  my fee : %" PRIu64 "\n", (uint64_t)(self->cnl_add_htlc[idx].amount_msat - hop_dataout.amt_to_forward));
    DBG_PRINTF2("  cltv_expiry - outgoing_cltv_value(%" PRIu32") = %d\n",  hop_dataout.outgoing_cltv_value, self->cnl_add_htlc[idx].cltv_expiry - hop_dataout.outgoing_cltv_value);

    //update_add_htlc受信通知
    add_htlc.ok = ret;
    add_htlc.id = self->cnl_add_htlc[idx].id;
    add_htlc.p_payment = p_payment;     //(hop_dataout.b_exit==true) ? preimage : payment_hash
    add_htlc.p_hop = &hop_dataout;
    add_htlc.amount_msat = self->cnl_add_htlc[idx].amount_msat;
    add_htlc.cltv_expiry = self->cnl_add_htlc[idx].cltv_expiry;
    add_htlc.p_onion_route = self->cnl_add_htlc[idx].p_onion_route;
    add_htlc.p_shared_secret = &self->cnl_add_htlc[idx].shared_secret;
    if (add_htlc.ok) {
        DBG_PRINTF("ok\n");
        ucoin_buf_init(&add_htlc.reason);
    } else {
        //reason作成
        //      ここでfail_htlcを送信するのは早すぎる。
        //      commitment_signed/revoke_and_ack交換後まで待つ必要あり。
    }
    (*self->p_callback)(self, LN_CB_ADD_HTLC_RECV, &add_htlc);
    ucoin_buf_free(&add_htlc.reason);

    DBG_PRINTF("END\n");
    return true;
}


static bool recv_update_fulfill_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

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

    ln_update_add_htlc_t *p_add = NULL;
    ret = false;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //受信したfulfillは、Offered HTLCについてチェックする
        if (!LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag) && (self->cnl_add_htlc[idx].id == fulfill_htlc.id)) {
            uint8_t sha256[LN_SZ_HASH];

            ucoin_util_sha256(sha256, preimage, sizeof(preimage));
            if (memcmp(sha256, self->cnl_add_htlc[idx].payment_sha256, LN_SZ_HASH) == 0) {
                p_add = &self->cnl_add_htlc[idx];
                ret = true;
            } else {
                DBG_PRINTF("fail: match id, but fail payment_hash\n");
            }
            break;
        }
    }

    if (ret) {
        //反映
        //self->our_msat -= p_add->amount_msat; //add_htlc送信時に引いているので、ここでは不要
        self->their_msat += p_add->amount_msat;

        uint64_t prev_short_channel_id = p_add->prev_short_channel_id; //CB用
        uint64_t prev_id = p_add->prev_id;  //CB用

        clear_htlc(self, p_add);

        //update_fulfill_htlc受信通知
        ln_cb_fulfill_htlc_recv_t fulfill;
        fulfill.prev_short_channel_id = prev_short_channel_id;
        fulfill.p_preimage = preimage;
        fulfill.id = prev_id;
        (*self->p_callback)(self, LN_CB_FULFILL_HTLC_RECV, &fulfill);
    } else {
        M_SET_ERR(self, LNERR_INV_ID, "fulfill");
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_update_fail_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;
    ln_update_fail_htlc_t    fail_htlc;

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ucoin_buf_t             reason = UCOIN_BUF_INIT;

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
        ucoin_buf_free(&reason);
        return false;
    }

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //受信したfail_htlcは、Offered HTLCについてチェックする
        if (!LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag) && (self->cnl_add_htlc[idx].id == fail_htlc.id)) {
            //id一致
            self->our_msat += self->cnl_add_htlc[idx].amount_msat;

            ln_cb_fail_htlc_recv_t fail_recv;
            fail_recv.prev_short_channel_id = self->cnl_add_htlc[idx].prev_short_channel_id;
            fail_recv.p_reason = &reason;
            fail_recv.p_shared_secret = &self->cnl_add_htlc[idx].shared_secret;
            fail_recv.prev_id = self->cnl_add_htlc[idx].prev_id;     //戻したいHTLC id
            fail_recv.orig_id = self->cnl_add_htlc[idx].id;     //元のHTLC id
            fail_recv.p_payment_hash = self->cnl_add_htlc[idx].payment_sha256;
            (*self->p_callback)(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);

            clear_htlc(self, &self->cnl_add_htlc[idx]);
            break;
        }
    }

    ucoin_buf_free(&reason);

    return true;
}


static bool recv_commitment_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;
    ln_commit_signed_t commsig;
    ln_revoke_and_ack_t revack;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t bak_sig[LN_SZ_SIGNATURE];

    //処理前呼び出し
    (*self->p_callback)(self, LN_CB_COMMIT_SIG_RECV_PREV, NULL);

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
    M_FREE(commsig.p_htlc_signature);
    if (!ret) {
        DBG_PRINTF("fail: create_to_local\n");
        goto LABEL_EXIT;
    }

    //自分のcommitment_numberをインクリメント
    self->commit_local.commit_num++;
    DBG_PRINTF("self->commit_local.commit_num=%" PRIx64 "\n", self->commit_local.commit_num);

    uint8_t prev_secret[UCOIN_SZ_PRIVKEY];
    ln_signer_get_prevkey(self, prev_secret);

    //storage_indexデクリメントおよびper_commit_secret更新
    ln_signer_update_percommit_secret(self);
    ln_db_secret_save(self);

    //commitment_signed受信により、自分のcommit_txが確定する
    ln_db_self_save(self);

    //チェックOKであれば、revoke_and_ackを返す
    //HTLCに変化がある場合、revoke_and_ack→commitment_signedの順で送信

    ucoin_buf_t buf_bolt = UCOIN_BUF_INIT;

    revack.p_channel_id = channel_id;
    revack.p_per_commit_secret = prev_secret;
    revack.p_per_commitpt = self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    ret = ln_msg_revoke_and_ack_create(&buf_bolt, &revack);
    if (ret) {
        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        ucoin_buf_free(&buf_bolt);

        if ((self->comsig_flag & M_COMISG_FLAG_SEND) == 0) {
            //commitment_signed未送信
            ret = ln_create_commit_signed(self, &buf_bolt);
            if (ret) {
                (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
                ucoin_buf_free(&buf_bolt);
            }
        }

    }
    if (ret) {
        //commitment_signed受信通知
        (*self->p_callback)(self, LN_CB_COMMIT_SIG_RECV, NULL);

        proc_commitment_signed(self, M_COMISG_FLAG_RECV);
        proc_rev_and_ack(self, M_REVACK_FLAG_SEND);
    }

LABEL_EXIT:
    //戻す
    if (!ret) {
        DBG_PRINTF("fail restore\n");
        memcpy(self->commit_remote.signature, bak_sig, LN_SZ_SIGNATURE);
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_revoke_and_ack(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;
    ln_revoke_and_ack_t revack;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t prev_secret[UCOIN_SZ_PRIVKEY];
    uint8_t new_commitpt[UCOIN_SZ_PUBKEY];

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
    uint8_t prev_commitpt[UCOIN_SZ_PUBKEY];
    ret = ucoin_keys_priv2pub(prev_commitpt, prev_secret);
    if (!ret) {
        DBG_PRINTF("fail: prev_secret convert\n");
        goto LABEL_EXIT;
    }
    if (memcmp(prev_commitpt, self->funding_remote.prev_percommit, UCOIN_SZ_PUBKEY) != 0) {
        DBG_PRINTF("fail: prev_secret mismatch\n");
        DBG_PRINTF("recv prev: ");
        DUMPBIN(prev_commitpt, UCOIN_SZ_PUBKEY);
        DBG_PRINTF("my prev:   ");
        DUMPBIN(self->funding_remote.prev_percommit, UCOIN_SZ_PUBKEY);
        ret = false;
        goto LABEL_EXIT;
    }

    //相手のcommitment_numberをインクリメント(channel_reestablish用)
    self->commit_remote.commit_num++;
    DBG_PRINTF("self->commit_remote.commit_num=%" PRIx64 "\n", self->commit_remote.commit_num);

    //prev_secret保存
    ret = store_peer_percommit_secret(self, prev_secret);
    if (!ret) {
        DBG_PRINTF("fail: store prev secret\n");
        goto LABEL_EXIT;
    }

    //per_commitment_point更新
    memcpy(self->funding_remote.prev_percommit, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], new_commitpt, UCOIN_SZ_PUBKEY);
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);

    ln_db_self_save(self);

    proc_rev_and_ack(self, M_REVACK_FLAG_RECV);

LABEL_EXIT:
    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_update_fee(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;
    ln_update_fee_t upfee;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];

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

    DBG_PRINTF("change fee: %" PRIu32 " --> %" PRIu32 "\n", self->feerate_per_kw, upfee.feerate_per_kw);
    self->feerate_per_kw = upfee.feerate_per_kw;
    ln_db_self_save(self);

LABEL_EXIT:
    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_update_fail_malformed_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    (void)self; (void)pData; (void)Len;
    DBG_PRINTF("BEGIN\n");
#warning not implemented
    return true;
}


static bool recv_channel_reestablish(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;

    DBG_PRINTF("BEGIN\n");

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

    if (self->commit_remote.commit_num + 1 != reest.next_local_commitment_number) {
        DBG_PRINTF("number mismatch : update remote commit_num\n");
        DBG_PRINTF("  next_local_commitment_number: %" PRIu64 "(own) != %" PRIu64 "(recv)\n", self->commit_remote.commit_num, reest.next_local_commitment_number);
        self->commit_remote.commit_num = reest.next_local_commitment_number - 1;
        ln_db_self_save(self);
    }
    if (self->commit_local.commit_num != reest.next_remote_revocation_number) {
        DBG_PRINTF("number mismatch\n");
        DBG_PRINTF("  next_remote_revocation_number:%" PRIu64 "(own) <- %" PRIu64 "(recv)\n", self->commit_local.commit_num, reest.next_remote_revocation_number);
        return false;
    }

    //reestablish受信通知
    (*self->p_callback)(self, LN_CB_REESTABLISH_RECV, NULL);

    return ret;
}


static bool recv_announcement_signatures(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    //short_channel_idで検索
    uint64_t short_channel_id = ln_msg_announce_signs_read_short_cnl_id(pData, Len, self->channel_id);
    if (short_channel_id == 0) {
        DBG_PRINTF("fail: invalid packet\n");
        return false;
    }
    if (self->cnl_anno.buf == NULL) {
        create_local_channel_announcement(self);
    }

    //channel_announcementを埋める
    ucoin_keys_sort_t sort = sort_nodeid(self);
    ln_msg_get_anno_signs(self, &p_sig_node, &p_sig_btc, false, sort);

    ln_announce_signs_t anno_signs;
    anno_signs.p_channel_id = channel_id;
    anno_signs.p_node_signature = p_sig_node;
    anno_signs.p_btc_signature = p_sig_btc;
    ret = ln_msg_announce_signs_read(&anno_signs, pData, Len);
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

    DBG_PRINTF("+++ channel_announcement[%" PRIx64 "] +++\n", self->short_channel_id);
    ln_msg_cnl_announce_print(self->cnl_anno.buf, self->cnl_anno.len);

    //channel_update
    ucoin_buf_t buf_upd = UCOIN_BUF_INIT;
    uint32_t now = (uint32_t)time(NULL);
    ln_cnl_update_t upd;
    ret = create_channel_update(self, &upd, &buf_upd, now, 0);
    if (!ret) {
        DBG_PRINTF("fail\n");
        goto LABEL_EXIT;
    }
    ret = ln_db_annocnl_save(&self->cnl_anno, ln_short_channel_id(self), ln_their_node_id(self));
    if (!ret) {
        DBG_PRINTF("fail: ln_db_annocnl_save\n");
        //goto LABEL_EXIT;
    }
    ret = ln_db_annocnlupd_save(&buf_upd, &upd, ln_their_node_id(self));
    if (!ret) {
        DBG_PRINTF("fail: but through\n");
    }
    ret = true;

    self->anno_flag |= M_ANNO_FLAG_RECV;
    ln_db_self_save(self);

LABEL_EXIT:
    ucoin_buf_free(&buf_upd);

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
    DBG_PRINTF("\n");

    ln_cnl_announce_read_t ann;
    ln_cb_channel_anno_recv_t param;

    param.is_unspent = true;
    bool ret = ln_msg_cnl_announce_read(&ann, pData, Len);
    if (ret) {
        //is_unspent更新
        param.short_channel_id = ann.short_channel_id;
        (*self->p_callback)(self, LN_CB_CHANNEL_ANNO_RECV, &param);
    } else {
        DBG_PRINTF("fail: do nothing\n");
        return true;
    }

    ucoin_buf_t buf;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;

    if (param.is_unspent) {
        //DB保存
        ret = ln_db_annocnl_save(&buf, ann.short_channel_id, ln_their_node_id(self));
        if (!ret) {
            DBG_PRINTF("fail: db save\n");
        }
    } else {
        //closeされたとみなして削除
        ret = ln_db_annocnlall_del(ann.short_channel_id);
        DBG_PRINTF("remove db: %0" PRIx64 "(ret=%d)\n", ann.short_channel_id, ret);
    }

    return true;
}


/** channel_update受信
 *
 * @param[in,out]       self            channel情報
 * @param[in]           pData           受信データ
 * @param[in]           Len             pData長
 * @retval      true    解析成功
 */
static bool recv_channel_update(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    (void)self;
    DBG_PRINTF("\n");

    ln_cnl_update_t upd;
    memset(&upd, 0, sizeof(upd));

    bool ret = ln_msg_cnl_update_read(&upd, pData, Len);
    if (ret) {
        DBG_PRINTF("recv channel_upd%d: %" PRIx64 "\n", (int)(1 + (upd.flags & LN_CNLUPD_FLAGS_DIRECTION)), upd.short_channel_id);

        //short_channel_id と dir から node_id を取得する
        uint8_t node_id[UCOIN_SZ_PUBKEY];

        ret = get_nodeid(self, node_id, upd.short_channel_id, upd.flags & LN_CNLUPD_FLAGS_DIRECTION);
        if (ret && ucoin_keys_chkpub(node_id)) {
            ret = ln_msg_cnl_update_verify(node_id, pData, Len);
            if (!ret) {
                DBG_PRINTF("fail: verify\n");
            }
        } else {
            DBG_PRINTF("fail: maybe not found channel_announcement in DB\n");
            ret = true;
        }
    } else {
        DBG_PRINTF("fail: channel_update\n");
    }

    if (ret) {
        //DB保存
        ucoin_buf_t buf;
        buf.buf = (CONST_CAST uint8_t *)pData;
        buf.len = Len;
        ret = ln_db_annocnlupd_save(&buf, &upd, ln_their_node_id(self));
        if (!ret) {
            DBG_PRINTF("fail: db save\n");
        }
        ret = true;
    } else {
        //スルーするだけにとどめる
        ret = true;
    }

    return ret;
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
    DBG_PRINTF("\n");

    ln_cb_funding_t funding;

    //commitment numberは0から始まる
    //  BOLT#0
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/00-introduction.md#glossary-and-terminology-guide
    //が、opening時を1回とカウントするので、Normal Operationでは1から始まる
    //  BOLT#2
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/02-peer-protocol.md#rationale-10
    self->commit_local.commit_num = 0;
    self->commit_remote.commit_num = 0;
    // self->htlc_id_num = 0;
    // self->short_channel_id = 0;

    //per_commit_secret更新
    ln_signer_update_percommit_secret(self);

    funding.b_send = bSendTx;
    if (bSendTx) {
        funding.p_tx_funding = &self->tx_funding;
    }
    (*self->p_callback)(self, LN_CB_FUNDINGTX_WAIT, &funding);

    ln_db_secret_save(self);
    ln_db_self_save(self);
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
 *      - #ucoin_util_create2of2()の公開鍵順序と、pSig1, pSig2の順序は同じにすること。
 *          例えば、先に自分のデータ、後に相手のデータ、など。
 */
static bool set_vin_p2wsh_2of2(ucoin_tx_t *pTx, int Index, ucoin_keys_sort_t Sort,
                    const ucoin_buf_t *pSig1,
                    const ucoin_buf_t *pSig2,
                    const ucoin_buf_t *pWit2of2)
{
    // 0
    // <sig1>
    // <sig2>
    // <script>
    const ucoin_buf_t wit0 = { NULL, 0 };
    const ucoin_buf_t *wits[] = {
        &wit0,
        NULL,
        NULL,
        pWit2of2
    };
    if (Sort == UCOIN_KEYS_SORT_ASC) {
        wits[1] = pSig1;
        wits[2] = pSig2;
    } else {
        wits[1] = pSig2;
        wits[2] = pSig1;
    }

    bool ret;

    ret = ucoin_sw_set_vin_p2wsh(pTx, Index, (const ucoin_buf_t **)wits, 4);
    return ret;
}


/** funding_tx作成
 *
 * @param[in,out]       self
 */
static bool create_funding_tx(ln_self_t *self)
{
    ucoin_tx_free(&self->tx_funding);

    //vout 2-of-2
    ucoin_util_create2of2(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING], self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);

    //output
    //vout#0:P2WSH - 2-of-2 : M_FUNDING_INDEX
    ucoin_sw_add_vout_p2wsh(&self->tx_funding, self->p_establish->cnl_open.funding_sat, &self->redeem_fund);

    //vout#1:P2WPKH - change(amountは後で代入)
    ucoin_tx_add_vout_addr(&self->tx_funding, (uint64_t)-1, self->p_establish->p_fundin->change_addr);

    //input
    //vin#0
    ucoin_tx_add_vin(&self->tx_funding, self->p_establish->p_fundin->txid, self->p_establish->p_fundin->index);


    //FEE計算
    ucoin_buf_t txbuf = UCOIN_BUF_INIT;
    ucoin_tx_create(&txbuf, &self->tx_funding);

    DBG_PRINTF("\n***** funding_tx(no signature) *****\n");
    M_DBG_PRINT_TX(&self->tx_funding);

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
    DBG_PRINTF("fee=%" PRIu64 "\n", fee);
    if (self->p_establish->p_fundin->amount >= self->p_establish->cnl_open.funding_sat + fee) {
        self->tx_funding.vout[1].value = self->p_establish->p_fundin->amount - self->p_establish->cnl_open.funding_sat - fee;
    } else {
        DBG_PRINTF("fail: amount too short:\n");
        DBG_PRINTF("    amount=%" PRIu64 "\n", self->p_establish->p_fundin->amount);
        DBG_PRINTF("    funding_sat=%" PRIu64 "\n", self->p_establish->cnl_open.funding_sat);
        DBG_PRINTF("    fee=%" PRIu64 "\n", fee);
        return false;
    }
    ucoin_buf_free(&txbuf);
    self->funding_local.txindex = M_FUNDING_INDEX;      //TODO: vout#0は2-of-2、vout#1はchangeにしている

    //署名
    bool ret;
    ln_cb_funding_sign_t sig;
    sig.p_tx =  &self->tx_funding;
    (*self->p_callback)(self, LN_CB_SIGN_FUNDINGTX_REQ, &sig);
    ret = sig.ret;
    ucoin_tx_txid(self->funding_local.txid, &self->tx_funding);

    DBG_PRINTF("\n***** funding_tx *****\n");
    M_DBG_PRINT_TX(&self->tx_funding);

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
 *      - pubkeys[MSG_FUNDIDX_PER_COMMIT]には次のper_commitment_pointが入っている前提。
 *          self->commit_local.commit_num + 1して commitment transactionを作成する。
 *      - funding_created/funding_signed時は、pubkeys[MSG_FUNDIDX_PER_COMMIT]にfirst_per_commitment_pointを入れ、
 *          self->commit_local.commit_num に (uint64_t)-1 を入れること(+1され、commitment_number==0になる)
 */
static bool create_to_local(ln_self_t *self,
                    ln_close_force_t *pClose,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;
    ucoin_buf_t buf_ws = UCOIN_BUF_INIT;
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_feeinfo_t feeinfo;
    ln_tx_cmt_t lntx_commit;
    ucoin_tx_t tx_commit = UCOIN_TX_INIT;

    //To-Local
    ln_create_script_local(&buf_ws,
                self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                to_self_delay);

    //HTLC
    ln_htlcinfo_t **pp_htlcinfo = (ln_htlcinfo_t **)M_MALLOC(sizeof(ln_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            pp_htlcinfo[cnt] = (ln_htlcinfo_t *)M_MALLOC(sizeof(ln_htlcinfo_t));
            ln_htlcinfo_init(pp_htlcinfo[cnt]);
            if (LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag)) {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_RECEIVED;
            } else {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_OFFERED;
            }
            pp_htlcinfo[cnt]->expiry = self->cnl_add_htlc[idx].cltv_expiry;
            pp_htlcinfo[cnt]->amount_msat = self->cnl_add_htlc[idx].amount_msat;
            pp_htlcinfo[cnt]->preimage_hash = self->cnl_add_htlc[idx].payment_sha256;
            DBG_PRINTF(" [%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, self->cnl_add_htlc[idx].id, self->cnl_add_htlc[idx].amount_msat);
            cnt++;
        }
    }
    DBG_PRINTF("-------\n");
    DBG_PRINTF("cnt=%d, htlc_num=%d\n", cnt, self->htlc_num);
    DBG_PRINTF("our_msat   %" PRIu64 " --> %" PRIu64 "\n", self->our_msat, self->our_msat);
    DBG_PRINTF("their_msat %" PRIu64 " --> %" PRIu64 "\n", self->their_msat, self->their_msat);
    for (int lp = 0; lp < cnt; lp++) {
        DBG_PRINTF("  [%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type == LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    DBG_PRINTF("-------\n");

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
    lntx_commit.obscured = self->obscured ^ (self->commit_local.commit_num + 1);
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;

    DBG_PRINTF("self->commit_local.commit_num=%" PRIx64 "\n", self->commit_local.commit_num + 1);
    ret = ln_create_commit_tx(&tx_commit, &buf_sig, &lntx_commit, ln_is_funder(self), &self->priv_data);
    if (ret) {
        ret = create_to_local_sign(self, &tx_commit, &buf_sig);
    } else {
        DBG_PRINTF("fail\n");
    }
    if (ret) {
        ret = ucoin_tx_txid(self->commit_local.txid, &tx_commit);
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


    DBG_PRINTF("free: ret=%d\n", ret);
    ucoin_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_htlcinfo_free(pp_htlcinfo[lp]);
        M_FREE(pp_htlcinfo[lp]);
    }
    M_FREE(pp_htlcinfo);

    ucoin_buf_free(&buf_sig);
    if (pClose != NULL) {
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(ucoin_tx_t));
    } else {
        ucoin_tx_free(&tx_commit);
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
                    ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufSig)
{
    DBG_PRINTF("local sign\n");

    bool ret;
    ucoin_buf_t buf_sig_from_remote = UCOIN_BUF_INIT;
    ucoin_buf_t script_code = UCOIN_BUF_INIT;
    uint8_t sighash[UCOIN_SZ_SIGHASH];

    //署名追加
    ln_misc_sigexpand(&buf_sig_from_remote, self->commit_remote.signature);
    set_vin_p2wsh_2of2(pTxCommit, 0, self->key_fund_sort,
                            pBufSig,
                            &buf_sig_from_remote,
                            &self->redeem_fund);
    DBG_PRINTF("++++++++++++++ 自分のcommit txに署名: [%" PRIx64 "]\n", self->short_channel_id);
    M_DBG_PRINT_TX(pTxCommit);

    // 署名verify
    ucoin_sw_scriptcode_p2wsh(&script_code, &self->redeem_fund);
    ucoin_sw_sighash(sighash, pTxCommit, 0, self->funding_sat, &script_code);
    ret = ucoin_sw_verify_2of2(pTxCommit, 0, sighash,
                &self->tx_funding.vout[self->funding_local.txindex].script);
    if (ret) {
        DBG_PRINTF("verify OK\n");
    } else {
        DBG_PRINTF("fail: ucoin_sw_verify_2of2\n");
    }

    ucoin_buf_free(&buf_sig_from_remote);
    ucoin_buf_free(&script_code);

    return ret;
}


/** local commit_txの送金先処理
 *
 * commitment_signedとclose処理で共用している。
 * commitment_signedの場合は、HTLC Success/Timeout Tx署名のみ必要。
 *
 *  1. [close]HTLC署名用local_htlcsecret取得
 *  2. voutごとの処理
 *      2.1. vout indexから対応するself->cnl_add_htlc[]を得る --> htlc_idx
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
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo,
                    uint32_t to_self_delay)
{
    bool ret = true;
    int htlc_num = 0;
    ucoin_tx_t *pTxToLocal = NULL;
    ucoin_tx_t *pTxHtlcs = NULL;
    ucoin_push_t push;
    ucoin_util_keys_t htlckey;

    DBG_PRINTF("local spent\n");

    if (pClose != NULL) {
        pTxToLocal = &pClose->p_tx[LN_CLOSE_IDX_TOLOCAL];
        pTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];

        ucoin_push_init(&push, &pClose->tx_buf, 0);

        //HTLC署名用鍵
        ln_signer_get_secret(self, &htlckey, MSG_FUNDIDX_HTLC,
            self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
        assert(memcmp(htlckey.pub, self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY], UCOIN_SZ_PUBKEY) == 0);
    } else {
        push.data = NULL;
    }

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint8_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_HTLCTYPE_TOLOCAL) {
            DBG_PRINTF("+++[%d]to_local\n", vout_idx);
            if (pTxToLocal != NULL) {
                ucoin_tx_t tx = UCOIN_TX_INIT;

                ret = ln_create_tolocal_spent(self, &tx, pTxCommit->vout[vout_idx].value, to_self_delay,
                        pBufWs, self->commit_local.txid, vout_idx, false);
                if (ret) {
                    M_DBG_PRINT_TX(&tx);
                    memcpy(pTxToLocal, &tx, sizeof(tx));
                    ucoin_tx_init(&tx);     //txはfreeさせない
                } else {
                    ucoin_tx_free(&tx);
                }
            }
        } else if (htlc_idx == LN_HTLCTYPE_TOREMOTE) {
            DBG_PRINTF("+++[%d]to_remote\n", vout_idx);
        } else {
            const ln_htlcinfo_t *p_htlcinfo = pp_htlcinfo[htlc_idx];
            uint64_t fee_sat = (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? p_feeinfo->htlc_timeout : p_feeinfo->htlc_success;
            if (pTxCommit->vout[vout_idx].value >= p_feeinfo->dust_limit_satoshi + fee_sat) {
                DBG_PRINTF("+++[%d]%s HTLC\n", vout_idx, (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? "offered" : "received");
                ucoin_tx_t tx = UCOIN_TX_INIT;

                ln_create_htlc_tx(&tx, pTxCommit->vout[vout_idx].value - fee_sat, pBufWs,
                            p_htlcinfo->type, p_htlcinfo->expiry,
                            self->commit_local.txid, vout_idx);
                M_DBG_PRINT_TX2(&tx);

                if ((p_htlc_sigs != NULL) && (htlc_sigs_num != 0)) {
                    //署名チェック
                    ucoin_buf_t buf_sig;
                    ln_misc_sigexpand(&buf_sig, p_htlc_sigs + htlc_num * LN_SZ_SIGNATURE);
                    ret = ln_verify_htlc_tx(&tx,
                                pTxCommit->vout[vout_idx].value,
                                NULL,
                                self->funding_local.scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                                NULL,
                                &buf_sig,
                                &p_htlcinfo->script);
                    ucoin_buf_free(&buf_sig);
                    if (!ret) {
                        DBG_PRINTF("fail: verify vout[%d]\n", vout_idx);
                        ucoin_tx_free(&tx);
                        break;
                    }

                    //OKなら各HTLCに保持
                    //  相手がunilateral closeした後に送信しなかったら、この署名を使う
                    memcpy(self->cnl_add_htlc[htlc_idx].signature, p_htlc_sigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
                }

                if (pClose != NULL) {
                    ret = create_to_local_close(self,
                                    pTxHtlcs, &tx, &push,
                                    pTxCommit, pBufWs,
                                    p_htlcinfo, &htlckey,
                                    htlc_num, vout_idx, htlc_idx,
                                    to_self_delay);
                    if (ret) {
                        pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                    } else {
                        DBG_PRINTF("fail: sign vout[%d]\n", vout_idx);
                        break;
                    }
                }
                ucoin_tx_free(&tx);

                htlc_num++;
            } else {
                DBG_PRINTF("cut HTLC[%d] %" PRIu64 " > %" PRIu64 "\n",
                            vout_idx, pTxCommit->vout[vout_idx].value,
                            p_feeinfo->dust_limit_satoshi + fee_sat);
            }
        }
    }

    if ((p_htlc_sigs != NULL) && (htlc_num != htlc_sigs_num)) {
        DBG_PRINTF("署名数不一致: %d, %d\n", htlc_num, htlc_sigs_num);
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
 * @param[in]       htlc_idx
 * @param[in]       to_self_delay
 * @retval  true    成功
 */
static bool create_to_local_close(ln_self_t *self,
                    ucoin_tx_t *pTxHtlcs,
                    ucoin_tx_t *pTxHtlc,
                    ucoin_push_t *pPush,
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const ucoin_util_keys_t *pHtlcKey,
                    uint8_t htlc_num,
                    int vout_idx,
                    uint8_t htlc_idx,
                    uint32_t to_self_delay)
{
    bool ret;

    ucoin_buf_t buf_sig;
    ln_misc_sigexpand(&buf_sig, self->cnl_add_htlc[htlc_idx].signature);

    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    if (p_htlcinfo->type == LN_HTLCTYPE_RECEIVED) {
        //Receivedであればpreimageを所持している可能性がある
        ret_img = search_preimage(preimage, self->cnl_add_htlc[htlc_idx].payment_sha256);
        DBG_PRINTF("[received]%d\n", ret_img);
    } else {
        ret_img = false;
        DBG_PRINTF("[offered]%d\n", ret_img);
    }

    //署名:HTLC Success/Timeout Transaction
    ucoin_buf_t buf_local_sig;
    ret = ln_sign_htlc_tx(pTxHtlc,
                &buf_local_sig,                 //<localsig>
                pTxCommit->vout[vout_idx].value,
                pHtlcKey,
                &buf_sig,                       //<remotesig>
                (ret_img) ? preimage : NULL,
                &p_htlcinfo->script,
                HTLCSIGN_TO_SUCCESS);
    ucoin_buf_free(&buf_sig);
    ucoin_buf_free(&buf_local_sig);
    if (!ret) {
        DBG_PRINTF("fail: ln_sign_htlc_tx: vout[%d]\n", vout_idx);
        return false;
    }

    if ( ((p_htlcinfo->type == LN_HTLCTYPE_RECEIVED) && ret_img) ||
            (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ) {
        DBG_PRINTF("create HTLC tx[%d]\n", htlc_num);
        M_DBG_PRINT_TX2(pTxHtlc);
        memcpy(&pTxHtlcs[htlc_num], pTxHtlc, sizeof(ucoin_tx_t));

        // HTLC Timeout/Success Txを作った場合はそれを取り戻すトランザクションも作る
        ucoin_tx_t tx = UCOIN_TX_INIT;
        uint8_t txid[UCOIN_SZ_TXID];
        ucoin_tx_txid(txid, pTxHtlc);
        ret = ln_create_tolocal_spent(self, &tx,
                    pTxHtlc->vout[0].value, to_self_delay,
                    pBufWs, txid, 0, false);
        if (ret) {
            DBG_PRINTF("*** HTLC out Tx ***\n");
            M_DBG_PRINT_TX2(&tx);

            //HTLC txから取り戻すtxをキューに積む
            ucoin_push_data(pPush, &tx, sizeof(ucoin_tx_t));
        } else {
            ucoin_tx_free(&tx);
        }
        ucoin_tx_init(pTxHtlc);     //txはfreeさせない(pTxHtlcsに任せる)
    } else {
        DBG_PRINTF("skip create HTLC tx[%d]\n", htlc_num);
        ucoin_tx_init(&pTxHtlcs[htlc_num]);
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
    DBG_PRINTF("BEGIN\n");

    bool ret;
    ucoin_buf_t buf_ws = UCOIN_BUF_INIT;
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_feeinfo_t feeinfo;
    ln_tx_cmt_t lntx_commit;
    ucoin_tx_t tx_commit = UCOIN_TX_INIT;

    //To-Local(Remote)
    ln_create_script_local(&buf_ws,
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                to_self_delay);

    //HTLC(Remote)
    ln_htlcinfo_t **pp_htlcinfo = (ln_htlcinfo_t **)M_MALLOC(sizeof(ln_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;    //commit_txのvout数
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            pp_htlcinfo[cnt] = (ln_htlcinfo_t *)M_MALLOC(sizeof(ln_htlcinfo_t));
            ln_htlcinfo_init(pp_htlcinfo[cnt]);
            //localとは逆になる
            if (LN_HTLC_FLAG_IS_RECV(self->cnl_add_htlc[idx].flag)) {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_OFFERED;
            } else {
                pp_htlcinfo[cnt]->type = LN_HTLCTYPE_RECEIVED;
            }
            pp_htlcinfo[cnt]->expiry = self->cnl_add_htlc[idx].cltv_expiry;
            pp_htlcinfo[cnt]->amount_msat = self->cnl_add_htlc[idx].amount_msat;
            pp_htlcinfo[cnt]->preimage_hash = self->cnl_add_htlc[idx].payment_sha256;
            DBG_PRINTF(" [%d][id=%" PRIx64 "](%p)\n", idx, self->cnl_add_htlc[idx].id, self);
            cnt++;
        }
    }
    DBG_PRINTF("-------\n");
    DBG_PRINTF("cnt=%d, htlc_num=%d\n", cnt, self->htlc_num);
    DBG_PRINTF("(remote)our_msat   %" PRIu64 " --> %" PRIu64 "\n", self->their_msat, self->their_msat);
    DBG_PRINTF("(remote)their_msat %" PRIu64 " --> %" PRIu64 "\n", self->our_msat, self->our_msat);
    for (int lp = 0; lp < cnt; lp++) {
        DBG_PRINTF("  have HTLC[%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type != LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    DBG_PRINTF("-------\n");

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
        ucoin_sw_wit2prog_p2wsh(vout, &pp_htlcinfo[lp]->script);
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
    lntx_commit.obscured = self->obscured ^ (self->commit_remote.commit_num + 1);
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;

    DBG_PRINTF("self->commit_remote.commit_num=%" PRIx64 "\n", self->commit_remote.commit_num + 1);
    ret = ln_create_commit_tx(&tx_commit, &buf_sig, &lntx_commit, !ln_is_funder(self), &self->priv_data);
    if (ret) {
        DBG_PRINTF("++++++++++++++ 相手のcommit tx: tx_commit[%" PRIx64 "]\n", self->short_channel_id);
        M_DBG_PRINT_TX(&tx_commit);

        ret = ucoin_tx_txid(self->commit_remote.txid, &tx_commit);
    }

    if (ret) {
        //送信用 commitment_signed.signature
        ln_misc_sigtrim(self->commit_local.signature, buf_sig.buf);
    }

    if (ret) {
        if (cnt > 0) {
            uint8_t *p_htlc_sigs = NULL;;
            if (pp_htlc_sigs != NULL) {
                //送信用 commitment_signed.htlc_signature
                *pp_htlc_sigs = (uint8_t *)M_MALLOC(LN_SZ_SIGNATURE * cnt);
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

    DBG_PRINTF("free: ret=%d\n", ret);
    ucoin_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_htlcinfo_free(pp_htlcinfo[lp]);
        M_FREE(pp_htlcinfo[lp]);
    }
    M_FREE(pp_htlcinfo);

    ucoin_buf_free(&buf_sig);
    if (pClose != NULL) {
        memcpy(&pClose->p_tx[LN_CLOSE_IDX_COMMIT], &tx_commit, sizeof(ucoin_tx_t));
    } else {
        ucoin_tx_free(&tx_commit);
    }

    return ret;
}


/** remote commit_txの送金先処理
 *
 *  1. [close]HTLC署名用local_htlcsecret取得
 *  2. voutごとの処理
 *      2.1. vout indexから対応するself->cnl_add_htlc[]を得る --> htlc_idx
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
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t **pp_htlcinfo,
                    const ln_feeinfo_t *p_feeinfo)
{
    bool ret = true;
    uint8_t htlc_num = 0;

    DBG_PRINTF("remote spent\n");

    ucoin_tx_t *pTxHtlcs = NULL;
    if (pClose != NULL) {
        pTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];
    }

    ucoin_buf_t buf_remotesig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_remotesig, self->commit_remote.signature);

    //HTLC署名用鍵
    ucoin_util_keys_t htlckey;
    ln_signer_get_secret(self, &htlckey, MSG_FUNDIDX_HTLC,
                self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        //各HTLCのHTLC Timeout/Success Transactionを作って署名するために、
        //BIP69ソート後のtx_commit.voutからpp_htlcinfo[]のindexを取得する
        uint8_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_HTLCTYPE_TOLOCAL) {
            DBG_PRINTF("---[%d]to_local\n", vout_idx);
        } else if (htlc_idx == LN_HTLCTYPE_TOREMOTE) {
            DBG_PRINTF("---[%d]to_remote\n", vout_idx);
            if (pClose != NULL) {
                ucoin_tx_t tx = UCOIN_TX_INIT;

                ret = ln_create_toremote_spent(self, &tx, pTxCommit->vout[vout_idx].value,
                            self->commit_remote.txid, vout_idx);
                if (ret) {
                    M_DBG_PRINT_TX2(&tx);
                    memcpy(&pClose->p_tx[LN_CLOSE_IDX_TOREMOTE], &tx, sizeof(tx));
                    ucoin_tx_init(&tx);     //txはfreeさせない
                } else {
                    DBG_PRINTF("no to_remote output\n");
                    ucoin_tx_free(&tx);
                    ret = true;     //継続する
                }
            }
        } else {
            const ln_htlcinfo_t *p_htlcinfo = pp_htlcinfo[htlc_idx];
            uint64_t fee_sat = (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? p_feeinfo->htlc_timeout : p_feeinfo->htlc_success;
            if (pTxCommit->vout[vout_idx].value >= p_feeinfo->dust_limit_satoshi + fee_sat) {
                ret = create_to_remote_htlcsign(self,
                                pTxHtlcs, p_htlc_sigs,
                                pTxCommit, pBufWs,
                                p_htlcinfo, &htlckey,
                                &buf_remotesig, fee_sat,
                                htlc_num, vout_idx, htlc_idx);
                if (ret) {
                    if (pClose != NULL) {
                        pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                    }
                } else {
                    DBG_PRINTF("fail: sign vout[%d]\n", vout_idx);
                    break;
                }

                htlc_num++;
            } else {
                DBG_PRINTF("cut HTLC[%d] %" PRIu64 " > %" PRIu64 "\n",
                            vout_idx, pTxCommit->vout[vout_idx].value,
                            p_feeinfo->dust_limit_satoshi + fee_sat);
            }
        }
    }
    ucoin_buf_free(&buf_remotesig);

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
 * @param[in]       htlc_idx
 * @retval  true    成功
 */
static bool create_to_remote_htlcsign(ln_self_t *self,
                    ucoin_tx_t *pTxHtlcs,
                    uint8_t *p_htlc_sigs,
                    const ucoin_tx_t *pTxCommit,
                    const ucoin_buf_t *pBufWs,
                    const ln_htlcinfo_t *p_htlcinfo,
                    const ucoin_util_keys_t *pHtlcKey,
                    const ucoin_buf_t *pBufRemoteSig,
                    uint64_t fee,
                    uint8_t htlc_num,
                    int vout_idx,
                    uint8_t htlc_idx)
{
    bool ret;
    ucoin_tx_t tx = UCOIN_TX_INIT;

    DBG_PRINTF("---[%d]%s HTLC\n", vout_idx, (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? "offered" : "received");
    ln_create_htlc_tx(&tx, pTxCommit->vout[vout_idx].value - fee, pBufWs,
                p_htlcinfo->type, p_htlcinfo->expiry,
                self->commit_remote.txid, vout_idx);
    M_DBG_PRINT_TX2(&tx);

    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    ln_htlcsign_t htlcsign = HTLCSIGN_TO_SUCCESS;
    if (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) {
        //remoteのoffered=localのreceivedなのでpreimageを所持している可能性がある
        ret_img = search_preimage(preimage, self->cnl_add_htlc[htlc_idx].payment_sha256);
        DBG_PRINTF("[offered]%d\n", ret_img);
        if (ret_img && (pTxHtlcs != NULL)) {
            //offeredかつpreimageがあるので、即時使用可能
            ucoin_buf_free(&tx.vout[0].script);      //HTLC Success Txを止める
            //close時の出力先に変更
            ucoin_buf_alloccopy(&tx.vout[0].script,
                    self->shutdown_scriptpk_local.buf, self->shutdown_scriptpk_local.len);
            tx.locktime = 0;
            htlcsign = HTLCSIGN_OF_PREIMG;
        }
    } else {
        ret_img = false;
        DBG_PRINTF("[received]%d\n", ret_img);
        if (pTxHtlcs != NULL) {
            //タイムアウト待ち
            ucoin_buf_free(&tx.vout[0].script);      //HTLC Success Txを止める
            //close時の出力先に変更
            ucoin_buf_alloccopy(&tx.vout[0].script,
                    self->shutdown_scriptpk_local.buf, self->shutdown_scriptpk_local.len);
            tx.locktime = p_htlcinfo->expiry;
            htlcsign = HTLCSIGN_RV_TIMEOUT;
        }
    }

    //署名
    ucoin_buf_t buf_sig;
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
    ucoin_buf_free(&buf_sig);
    if (!ret) {
        DBG_PRINTF("fail: ln_sign_htlc_tx: vout[%d]\n", vout_idx);
        goto LABEL_EXIT;
    }

    if (pTxHtlcs != NULL) {
        if ( ((p_htlcinfo->type == LN_HTLCTYPE_OFFERED) && ret_img) ||
                (p_htlcinfo->type == LN_HTLCTYPE_RECEIVED) ) {
            DBG_PRINTF("create HTLC tx[%d]\n", htlc_num);
            M_DBG_PRINT_TX2(&tx);
            memcpy(&pTxHtlcs[htlc_num], &tx, sizeof(tx));
            ucoin_tx_init(&tx);     //txはfreeさせない(pTxHtlcsに任せる)
        } else {
            DBG_PRINTF("skip create HTLC tx[%d]\n", htlc_num);
            ucoin_tx_init(&pTxHtlcs[htlc_num]);
        }
    }

LABEL_EXIT:
    ucoin_tx_free(&tx);

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
static bool create_closing_tx(ln_self_t *self, ucoin_tx_t *pTx, uint64_t FeeSat, bool bVerify)
{
    DBG_PRINTF("BEGIN\n");

    if ((self->shutdown_scriptpk_local.len == 0) || (self->shutdown_scriptpk_remote.len == 0)) {
        DBG_PRINTF("not mutual output set\n");
        return false;
    }

    bool ret;
    uint64_t fee_local;
    uint64_t fee_remote;
    ucoin_vout_t *vout;
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;

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
    bool vout_local = (LN_MSAT2SATOSHI(self->our_msat) > fee_local + UCOIN_DUST_LIMIT);
    bool vout_remote = (LN_MSAT2SATOSHI(self->their_msat) > fee_remote + UCOIN_DUST_LIMIT);

    if (vout_local) {
        vout = ucoin_tx_add_vout(pTx, LN_MSAT2SATOSHI(self->our_msat) - fee_local);
        ucoin_buf_alloccopy(&vout->script, self->shutdown_scriptpk_local.buf, self->shutdown_scriptpk_local.len);
    }
    //vout#1 - remote
    if (vout_remote) {
        vout = ucoin_tx_add_vout(pTx, LN_MSAT2SATOSHI(self->their_msat) - fee_remote);
        ucoin_buf_alloccopy(&vout->script, self->shutdown_scriptpk_remote.buf, self->shutdown_scriptpk_remote.len);
    }

    //vin
    ucoin_tx_add_vin(pTx, self->funding_local.txid, self->funding_local.txindex);

    //BIP69
    ucoin_util_sort_bip69(pTx);

    //署名
    uint8_t sighash[UCOIN_SZ_SIGHASH];
    ucoin_util_calc_sighash_p2wsh(sighash, pTx, 0, self->funding_sat, &self->redeem_fund);
    ret = ln_signer_p2wsh(&buf_sig, sighash, &self->priv_data, MSG_FUNDIDX_FUNDING);
    if (!ret) {
        DBG_PRINTF("fail: sign p2wsh\n");
        ucoin_tx_free(pTx);
        return false;
    }
    //送信用署名
    ln_misc_sigtrim(self->commit_local.signature, buf_sig.buf);

    //署名追加
    if (bVerify) {
        ucoin_buf_t buf_sig_from_remote = UCOIN_BUF_INIT;

        ln_misc_sigexpand(&buf_sig_from_remote, self->commit_remote.signature);
        set_vin_p2wsh_2of2(pTx, 0, self->key_fund_sort,
                                &buf_sig,
                                &buf_sig_from_remote,
                                &self->redeem_fund);
        ucoin_buf_free(&buf_sig_from_remote);

        //
        // 署名verify
        //
        ret = ucoin_sw_verify_2of2(pTx, 0, sighash,
                        &self->tx_funding.vout[self->funding_local.txindex].script);
    } else {
        DBG_PRINTF("no verify\n");
    }
    ucoin_buf_free(&buf_sig);

    DBG_PRINTF("+++++++++++++ closing_tx[%" PRIx64 "]\n", self->short_channel_id);
    M_DBG_PRINT_TX(pTx);

    DBG_PRINTF("END ret=%d\n", ret);
    return ret;
}


// channel_announcement用データ(自分の枠)
//  short_channel_id決定後に呼び出す
static bool create_local_channel_announcement(ln_self_t *self)
{
    DBG_PRINTF("short_channel_id=%016" PRIu64 "\n", self->short_channel_id);
    ucoin_buf_free(&self->cnl_anno);

    ln_cnl_announce_create_t anno;

    anno.short_channel_id = self->short_channel_id;
    anno.p_my_node_pub = ln_node_getid();
    anno.p_peer_node_pub = self->peer_node_id;
    anno.p_my_funding_pub = self->funding_local.pubkeys[MSG_FUNDIDX_FUNDING];
    anno.p_peer_funding_pub = self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING];
    anno.sort = sort_nodeid(self);
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
                ucoin_buf_t *pCnlUpd,
                uint32_t TimeStamp,
                uint8_t Flag)
{
    pUpd->short_channel_id = self->short_channel_id;
    pUpd->timestamp = TimeStamp;
    //announce
    pUpd->cltv_expiry_delta = self->anno_prm.cltv_expiry_delta;
    pUpd->htlc_minimum_msat = self->anno_prm.htlc_minimum_msat;
    pUpd->fee_base_msat = self->anno_prm.fee_base_msat;
    pUpd->fee_prop_millionths = self->anno_prm.fee_prop_millionths;
    //署名
    pUpd->flags = Flag | sort_nodeid(self);
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
                ucoin_buf_t *pReason,
                uint64_t amount_msat,
                uint32_t cltv_value)
{
    bool ret = false;
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
        if (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_SEND) {
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
    if (!ret && (pReason != NULL)) {
        //channel_update
        ucoin_buf_t buf_bolt = UCOIN_BUF_INIT;
        uint32_t timestamp;
        ucoin_keys_sort_t sort = sort_nodeid(self);
        uint8_t dir = (sort == UCOIN_KEYS_SORT_OTHER) ? 0 : 1;  //相手のchannel_update

        bool b = ln_db_annocnlupd_load(&buf_bolt, &timestamp, ln_short_channel_id(self), dir);
        ucoin_push_t push_htlc;
        if (b) {
            //B4. if during forwarding to its receiving peer, an otherwise unspecified, transient error occurs in the outgoing channel (e.g. channel capacity reached, too many in-flight HTLCs, etc.):
            //      temporary_channel_failure
            DBG_PRINTF("fail: temporary_channel_failure\n");
            ucoin_push_init(&push_htlc, pReason,
                                sizeof(uint16_t) + sizeof(uint16_t) + buf_bolt.len);
            ln_misc_push16be(&push_htlc, LNONION_TMP_CHAN_FAIL);
            ln_misc_push16be(&push_htlc, (uint16_t)buf_bolt.len);
            ucoin_push_data(&push_htlc, buf_bolt.buf, buf_bolt.len);
        } else {
            DBG_PRINTF("fail: temporary_node_failure\n");
            ln_create_reason_temp_node(pReason);
        }
    }
    return ret;
}


/** recv_update_add_htlc()のBOLT#2チェック
 *
 */
static bool check_recv_add_htlc_bolt2(ln_self_t *self, int Index)
{
    //amount_msatが0の場合、チャネルを失敗させる。
    //amount_msatが自分のhtlc_minimum_msat未満の場合、チャネルを失敗させる。
    //  receiving an amount_msat equal to 0, OR less than its own htlc_minimum_msat
    if (self->cnl_add_htlc[Index].amount_msat < self->commit_local.htlc_minimum_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "amount_msat < local htlc_minimum_msat");
        return false;
    }

    //送信側が現在のfeerate_per_kwで支払えないようなamount_msatの場合、チャネルを失敗させる。
    //  receiving an amount_msat that the sending node cannot afford at the current feerate_per_kw
    if (self->their_msat < self->cnl_add_htlc[Index].amount_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "their_msat too small(%" PRIu64 " < %" PRIu64 ")", self->their_msat, self->cnl_add_htlc[Index].amount_msat);
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
        if (self->cnl_add_htlc[idx].flag & LN_HTLC_FLAG_SEND) {
            max_htlc_value_in_flight_msat += self->cnl_add_htlc[idx].amount_msat;
        }
    }
    if (max_htlc_value_in_flight_msat > self->commit_local.max_htlc_value_in_flight_msat) {
        M_SET_ERR(self, LNERR_INV_VALUE, "exceed local max_htlc_value_in_flight_msat");
        return false;
    }

    //cltv_expiryが500000000以上の場合、チャネルを失敗させる。
    //  if sending node sets cltv_expiry to greater or equal to 500000000
    if (self->cnl_add_htlc[Index].cltv_expiry >= 500000000) {
        M_SET_ERR(self, LNERR_INV_VALUE, "cltv_expiry >= 500000000");
        return false;
    }

    //for channels with chain_hash identifying the Bitcoin blockchain, if the four most significant bytes of amount_msat are not 0
    if (self->cnl_add_htlc[Index].amount_msat & (uint64_t)0xffffffff00000000) {
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


/** recv_update_add_htlc()のBOLT#4チェック
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
 * @param[out]          pDataOut
 * @param[out]          pp_payment
 * @param[out]          p_preimage
 * @param[out]          pReason
 * @param[in]           Index
 * @retval  true    成功
 */
static bool check_recv_add_htlc_bolt4(ln_self_t *self,
                    ln_hop_dataout_t *pDataOut,
                    uint8_t **pp_payment,
                    uint8_t *p_preimage,
                    ucoin_buf_t *pReason,
                    int Index)
{
    bool ret;

    ucoin_push_t push_htlc;
    ucoin_push_init(&push_htlc, pReason, sizeof(uint16_t));

    ret = ln_onion_read_packet(self->cnl_add_htlc[Index].p_onion_route, pDataOut,
                    &self->cnl_add_htlc[Index].shared_secret,
                    &push_htlc,
                    self->cnl_add_htlc[Index].p_onion_route,
                    self->cnl_add_htlc[Index].payment_sha256, LN_SZ_HASH);
    if (!ret) {
        //A1. if the realm byte is unknown:
        //      invalid_realm
        //B1. if the onion version byte is unknown:
        //      invalid_onion_version
        //B2. if the onion HMAC is incorrect:
        //      invalid_onion_hmac
        //B3. if the ephemeral key in the onion is unparsable:
        //      invalid_onion_key
        M_SET_ERR(self, LNERR_ONION, "onion-read");
        goto LABEL_EXIT;
    }

    if (pDataOut->b_exit) {
        //自分宛(final node)

        //preimage-hashチェック
        uint64_t inv_amount = (uint64_t)-1;
        uint8_t preimage_hash[LN_SZ_HASH];

        void *p_cur;
        ret = ln_db_preimg_cur_open(&p_cur);
        while (ret) {
            ret = ln_db_preimg_cur_get(p_cur, p_preimage, &inv_amount);     //from invoice
            if (ret) {
                ln_calc_preimage_hash(preimage_hash, p_preimage);
                if (memcmp(preimage_hash, self->cnl_add_htlc[Index].payment_sha256, LN_SZ_HASH) == 0) {
                    //一致
                    DBG_PRINTF("match preimage: ");
                    DUMPBIN(p_preimage, LN_SZ_PREIMAGE);
                    *pp_payment = p_preimage;
                    break;
                }
            }
        }
        ln_db_preimg_cur_close(p_cur);

        if (ret) {
            //
            //An intermediate hop MUST NOT, but the final node:
            //  self->cnl_add_htlc[Index].amount_msat >= pDataOut->amt_to_forwardを認めているため、
            //  HTLCとしてはself->cnl_add_htlc[Index].amount_msatを使用する。
            //

            //C2. if the amount paid is less than the amount expected:
            //      incorrect_payment_amount
            if (self->cnl_add_htlc[Index].amount_msat < inv_amount) {
                M_SET_ERR(self, LNERR_INV_VALUE, "incorrect_payment_amount(final) : %" PRIu64 " < %" PRIu64, pDataOut->amt_to_forward, inv_amount);
                ret = false;
                ln_misc_push16be(&push_htlc, LNONION_INCORR_PAY_AMT);
                //no data
                goto LABEL_EXIT;
            }

            //C4. if the amount paid is more than twice the amount expected:
            //      incorrect_payment_amount
            if (inv_amount * 2 < self->cnl_add_htlc[Index].amount_msat) {
                M_SET_ERR(self, LNERR_INV_VALUE, "large amount_msat : %" PRIu64 " < %" PRIu64, inv_amount * 2, pDataOut->amt_to_forward);
                ret = false;
                ln_misc_push16be(&push_htlc, LNONION_INCORR_PAY_AMT);
                //no data
                goto LABEL_EXIT;
            }

            //TODO: implement
            //C5. if the cltv_expiry value is unreasonably near the present:
            //      final_expiry_too_soon

            //C6. if the outgoing_cltv_value does NOT correspond with the cltv_expiry from the final node's HTLC:
            //      final_incorrect_cltv_expiry
            if (pDataOut->outgoing_cltv_value != self->cnl_add_htlc[Index].cltv_expiry) {
                DBG_PRINTF("%" PRIu32 " --- %" PRIu32 "\n", pDataOut->outgoing_cltv_value, ln_cltv_expily_delta(self));
                M_SET_ERR(self, LNERR_INV_VALUE, "incorrect cltv expiry(final)");
                ln_misc_push16be(&push_htlc, LNONION_FINAL_INCORR_CLTV_EXP);
                //[4:cltv_expiry]
                ln_misc_push32be(&push_htlc, pDataOut->outgoing_cltv_value);
                goto LABEL_EXIT;
            }

            //C7. if the amt_to_forward is greater than the incoming_htlc_amt from the final node's HTLC:
            //      final_incorrect_htlc_amount
            if (pDataOut->amt_to_forward > self->cnl_add_htlc[Index].amount_msat) {
                DBG_PRINTF("%" PRIu64 " --- %" PRIu64 "\n", pDataOut->amt_to_forward, self->cnl_add_htlc[Index].amount_msat);
                M_SET_ERR(self, LNERR_INV_VALUE, "incorrect_payment_amount(final)");
                ln_misc_push16be(&push_htlc, LNONION_FINAL_INCORR_HTLC_AMT);
                //[4:incoming_htlc_amt]
                ln_misc_push32be(&push_htlc, self->cnl_add_htlc[Index].amount_msat);
                goto LABEL_EXIT;
            }
        } else {
            memset(p_preimage, 0, LN_SZ_PREIMAGE);

            //C1. if the payment hash has already been paid:
            //      ★(採用)MAY treat the payment hash as unknown.★
            //      MAY succeed in accepting the HTLC.
            //C3. if the payment hash is unknown:
            //      unknown_payment_hash
            M_SET_ERR(self, LNERR_INV_VALUE, "preimage mismatch");
            ln_misc_push16be(&push_htlc, LNONION_UNKNOWN_PAY_HASH);
            //no data
            goto LABEL_EXIT;
        }
    } else {
        //
        //A forwarding node MAY, but a final node MUST NOT:
        //TODO: implement
        //

        ret = false;

        //処理前呼び出し
        //  転送先取得(final nodeの場合はNULLが返る)
        ln_cb_add_htlc_recv_prev_t recv_prev;
        recv_prev.p_next_self = NULL;
        if (pDataOut->short_channel_id != 0) {
            recv_prev.next_short_channel_id = pDataOut->short_channel_id;
            (*self->p_callback)(self, LN_CB_ADD_HTLC_RECV_PREV, &recv_prev);
        } else {
            DBG_PRINTF("no next channel\n");
        }

        //B5. if an otherwise unspecified, permanent error occurs during forwarding to its receiving peer (e.g. channel recently closed):
        //      permanent_channel_failure

        //B6. if the outgoing channel has requirements advertised in its channel_announcement's features, which were NOT included in the onion:
        //      required_channel_feature_missing

        //B7. if the receiving peer specified by the onion is NOT known:
        //      unknown_next_peer
        if ((pDataOut->short_channel_id == 0) || (recv_prev.p_next_self == NULL)) {
            //転送先がない
            M_SET_ERR(self, LNERR_INV_VALUE, "no next channel");
            ln_misc_push16be(&push_htlc, LNONION_UNKNOWN_NEXT_PEER);
            //no data
            goto LABEL_EXIT;
        }

        //B8. if the HTLC amount is less than the currently specified minimum amount:
        //      amount_below_minimum
        //      (report the amount of the incoming HTLC and the current channel setting for the outgoing channel.)
        if (pDataOut->amt_to_forward < recv_prev.p_next_self->commit_remote.htlc_minimum_msat) {
            M_SET_ERR(self, LNERR_INV_VALUE, "lower than htlc_minimum_msat : %" PRIu64 " < %" PRIu64, pDataOut->amt_to_forward, recv_prev.p_next_self->commit_remote.htlc_minimum_msat);
            ln_misc_push16be(&push_htlc, LNONION_AMT_BELOW_MIN);
            //[8:htlc_msat]
            //[2:len]
            //[len:channel_update]
            goto LABEL_EXIT;
        }

        //B9. if the HTLC does NOT pay a sufficient fee:
        //      fee_insufficient
        //      (report the amount of the incoming HTLC and the current channel setting for the outgoing channel.)
        uint64_t fwd_fee = ln_forward_fee(self, pDataOut->amt_to_forward);
        if (self->cnl_add_htlc[Index].amount_msat < pDataOut->amt_to_forward + fwd_fee) {
            M_SET_ERR(self, LNERR_INV_VALUE, "fee not enough : %" PRIu32 " < %" PRIu32, fwd_fee, self->cnl_add_htlc[Index].amount_msat - pDataOut->amt_to_forward);
            ln_misc_push16be(&push_htlc, LNONION_FEE_INSUFFICIENT);
            //[8:htlc_msat]
            //[2:len]
            //[len:channel_update]
            goto LABEL_EXIT;
        }

        //B10. if the outgoing_cltv_value does NOT match the update_add_htlc's cltv_expiry minus the cltv_expiry_delta for the outgoing channel:
        //      incorrect_cltv_expiry
        //      (report the cltv_expiry and the current channel setting for the outgoing channel.)
        if ( (self->cnl_add_htlc[Index].cltv_expiry <= pDataOut->outgoing_cltv_value) ||
             (self->cnl_add_htlc[Index].cltv_expiry + ln_cltv_expily_delta(recv_prev.p_next_self) < pDataOut->outgoing_cltv_value) ) {
            M_SET_ERR(self, LNERR_INV_VALUE, "cltv not enough : %" PRIu32, ln_cltv_expily_delta(recv_prev.p_next_self));
            ln_misc_push16be(&push_htlc, LNONION_INCORR_CLTV_EXPIRY);
            //[4:cltv_expiry]
            //[2:len]
            //[len:channel_update]
            goto LABEL_EXIT;
        }

        //B11. if the cltv_expiry is unreasonably near the present:
        //      expiry_too_soon
        //      (report the current channel setting for the outgoing channel.)

        //B12. if the cltv_expiry is unreasonably far in the future:
        //      expiry_too_far

        //B13. if the channel is disabled:
        //      channel_disabled
        //      (report the current channel setting for the outgoing channel.)

        *pp_payment = self->cnl_add_htlc[Index].payment_sha256;
        ret = true;
    }

    //共通チェック
    if (ret) {
        //
        // Any erring node MAY:
        //TODO: implement
        //

        //A3. if an otherwise unspecified permanent error occurs for the entire node:
        //      permanent_node_failure

        //A4. if a node has requirements advertised in its node_announcement features, which were NOT included in the onion:
        //      required_node_feature_missing
    }

LABEL_EXIT:
    return ret;
}


/** peerから受信したper_commitment_secret保存
 *
 * @param[in,out]   self            チャネル情報
 * @param[in]       p_prev_secret   受信したper_commitment_secret
 * @retval  true    成功
 * @note
 *      - indexを進める
 */
static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret)
{
    //DBG_PRINTF("I=%" PRIx64 "\n", self->peer_storage_index);
    //DUMPBIN(p_prev_secret, UCOIN_SZ_PRIVKEY);
    uint8_t pub[UCOIN_SZ_PUBKEY];
    ucoin_keys_priv2pub(pub, p_prev_secret);
    //DUMPBIN(pub, UCOIN_SZ_PUBKEY);
    bool ret = ln_derkey_storage_insert_secret(&self->peer_storage, p_prev_secret, self->peer_storage_index);
    if (ret) {
        self->peer_storage_index--;
        //ln_db_self_save(self);    //保存は呼び出し元で行う
        DBG_PRINTF("I=%" PRIx64 " --> %" PRIx64 "\n", (uint64_t)(self->peer_storage_index + 1), self->peer_storage_index);

        //for (uint64_t idx = LN_SECINDEX_INIT; idx > self->peer_storage_index; idx--) {
        //    DBG_PRINTF("I=%" PRIx64 "\n", idx);
        //    DBG_PRINTF2("  ");
        //    uint8_t sec[UCOIN_SZ_PRIVKEY];
        //    ret = ln_derkey_storage_get_secret(sec, &self->peer_storage, idx);
        //    assert(ret);
        //    DBG_PRINTF2("  pri:");
        //    DUMPBIN(sec, UCOIN_SZ_PRIVKEY);
        //    DBG_PRINTF2("  pub:");
        //    ucoin_keys_priv2pub(pub, sec);
        //    DUMPBIN(pub, UCOIN_SZ_PUBKEY);
        //}
    } else {
        assert(0);
    }
    return ret;
}


/** commitment_signed交換完了後
 * 
 */
static void proc_commitment_signed(ln_self_t *self, uint8_t Flag)
{
    self->comsig_flag |= Flag;
    if (self->comsig_flag == (M_COMISG_FLAG_SEND | M_COMISG_FLAG_RECV)) {
        self->comsig_flag = 0;
    }
}


/** revoke_and_ack交換完了後
 * 
 */
static void proc_rev_and_ack(ln_self_t *self, uint8_t Flag)
{
    self->revack_flag |= Flag;
    if (self->revack_flag == (M_REVACK_FLAG_SEND | M_REVACK_FLAG_RECV)) {

        //revoke_and_ack受信通知
        (*self->p_callback)(self, LN_CB_REV_AND_ACK_RECV, NULL);

        self->revack_flag = 0;
    }
}


static bool chk_peer_node(ln_self_t *self)
{
    return self->peer_node_id[0];       //先頭が0の場合は不正
}


//node_id取得
static bool get_nodeid(ln_self_t *self, uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir)
{
    bool ret;

    pNodeId[0] = 0x00;

    ucoin_buf_t buf_cnl_anno = UCOIN_BUF_INIT;
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
            memcpy(pNodeId, p_node_id, UCOIN_SZ_PUBKEY);
        } else {
            DBG_PRINTF("ret=%d\n", ret);
        }
    } else {
        if (short_channel_id == self->short_channel_id) {
            // DBには無いが、このchannelの情報
            ucoin_keys_sort_t mydir = sort_nodeid(self);
            if ( ((mydir == UCOIN_KEYS_SORT_ASC) && (Dir == 0)) ||
                 ((mydir == UCOIN_KEYS_SORT_OTHER) && (Dir == 1)) ) {
                //自ノード
                DBG_PRINTF("this channel: my node\n");
                memcpy(pNodeId, ln_node_getid(), UCOIN_SZ_PUBKEY);
            } else {
                //相手ノード
                DBG_PRINTF("this channel: peer node\n");
                memcpy(pNodeId, self->peer_node_id, UCOIN_SZ_PUBKEY);
            }
            ret = true;
        }
    }
    ucoin_buf_free(&buf_cnl_anno);

    return ret;
}


//HTLC削除
static void clear_htlc(ln_self_t *self, ln_update_add_htlc_t *p_add)
{
    DBG_PRINTF("HTLC remove prev: htlc_num=%d\n", self->htlc_num);
    assert(self->htlc_num > 0);

    ucoin_buf_free(&p_add->shared_secret);
    memset(p_add, 0, sizeof(ln_update_add_htlc_t));
    self->htlc_num--;
    DBG_PRINTF("   --> htlc_num=%d\n", self->htlc_num);
}


static bool search_preimage(uint8_t *pPreImage, const uint8_t *pHtlcHash)
{
    if (!LN_DBG_MATCH_PREIMAGE()) {
        DBG_PRINTF("DBG: HTLC preimage mismatch\n");
        return false;
    }

    uint64_t amount;
    uint8_t preimage_hash[LN_SZ_HASH];
    void *p_cur;
    bool ret = ln_db_preimg_cur_open(&p_cur);
    while (ret) {
        DBG_PRINTF("ret=%d\n", ret);
        ret = ln_db_preimg_cur_get(p_cur, pPreImage, &amount);
        if (ret) {
            DBG_PRINTF("compare preimage : ");
            DUMPBIN(pPreImage, UCOIN_SZ_PRIVKEY);
            ln_calc_preimage_hash(preimage_hash, pPreImage);
            if (memcmp(preimage_hash, pHtlcHash, LN_SZ_HASH) == 0) {
                //一致
                DBG_PRINTF("preimage match!: ");
                DUMPBIN(pPreImage, UCOIN_SZ_PRIVKEY);
                break;
            }
        }
    }
    ln_db_preimg_cur_close(p_cur);

    return ret;
}


static bool chk_channelid(const uint8_t *recv_id, const uint8_t *mine_id)
{
    bool ret = (memcmp(recv_id, mine_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
        DBG_PRINTF2("mine:");
        DUMPBIN(mine_id, LN_SZ_CHANNEL_ID);
        DBG_PRINTF2("get :");
        DUMPBIN(recv_id, LN_SZ_CHANNEL_ID);
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
    pClose->p_tx = (ucoin_tx_t *)M_MALLOC(sizeof(ucoin_tx_t) * pClose->num);
    pClose->p_htlc_idx = (uint8_t *)M_MALLOC(sizeof(uint8_t) * pClose->num);
    for (int lp = 0; lp < pClose->num; lp++) {
        ucoin_tx_init(&pClose->p_tx[lp]);
        pClose->p_htlc_idx[lp] = LN_CLOSE_IDX_NONE;
    }
    ucoin_buf_init(&pClose->tx_buf);
    DBG_PRINTF("TX num: %d\n", pClose->num);
}


/** establish用メモリ解放
 *
 * @param[in]   bEndEstablish   true: funding用メモリ解放
 */
static void free_establish(ln_self_t *self, bool bEndEstablish)
{
    if (self->p_establish != NULL) {
        if (self->p_establish->p_fundin != NULL) {
            DBG_PRINTF("self->p_establish->p_fundin=%p\n", self->p_establish->p_fundin);
            M_FREE(self->p_establish->p_fundin);  //M_MALLOC: ln_create_open_channel()
            DBG_PRINTF("free\n");
        }
        if (bEndEstablish) {
            M_FREE(self->p_establish);        //M_MALLOC: ln_set_establish()
            DBG_PRINTF("free\n");
        }
    }
    self->fund_flag &= ~LN_FUNDFLAG_FUNDING;
}


/**
 *
 * @param[in]   self
 * @retval      UCOIN_KEYS_SORT_ASC     自ノードが先
 * @retval      UCOIN_KEYS_SORT_OTHER   相手ノードが先
 */
static ucoin_keys_sort_t sort_nodeid(ln_self_t *self)
{
    ucoin_keys_sort_t sort;

    int lp;
    const uint8_t *p_nodeid = ln_node_getid();
    for (lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        if (p_nodeid[lp] != self->peer_node_id[lp]) {
            break;
        }
    }
    if ((lp < UCOIN_SZ_PUBKEY) && (p_nodeid[lp] < self->peer_node_id[lp])) {
        DBG_PRINTF("my node= first\n");
        sort = UCOIN_KEYS_SORT_ASC;
    } else {
        DBG_PRINTF("my node= second\n");
        sort = UCOIN_KEYS_SORT_OTHER;
    }

    return sort;
}


static void set_err(ln_self_t *self, int Err, const char *pFormat, ...)
{
    va_list ap;

    self->err = Err;

    va_start(ap, pFormat);
    vsprintf(self->err_msg, pFormat, ap);
    va_end(ap);
}
