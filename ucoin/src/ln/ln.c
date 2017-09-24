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
#include <assert.h>

#include "ln_db.h"
#include "ln/ln_misc.h"
#include "ln/ln_msg_setupctl.h"
#include "ln/ln_msg_establish.h"
#include "ln/ln_msg_close.h"
#include "ln/ln_msg_normalope.h"
#include "ln/ln_msg_anno.h"
#include "ln/ln_node.h"
#include "ln/ln_enc_auth.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define ARRAY_SIZE(a)       (sizeof(a) / sizeof(a[0]))  ///< 配列要素数

//TODO:暫定
#define M_DFL_DUST_LMIT_SAT                     (546)
#define M_DFL_MAX_HTLC_VALUE_IN_FLIGHT_MSAT     (UINT64_MAX)
#define M_DFL_CHANNEL_RESERVE_SAT               (700)
#define M_DFL_HTLC_MIN_MSAT                     (9000)
#define M_DFL_TO_SELF_DELAY                     (90)
#define M_DFL_MAX_ACCEPTED_HTLC                 (LN_HTLC_MAX)
#define M_DFL_MIN_DEPTH                         (5)

#define M_DFL_CLTV_EXPILY_DELTA                 (10)
#define M_DFL_HTLC_MINIMUM_MSAT                 M_DFL_HTLC_MIN_MSAT
#define M_DFL_FEE_BASE_MSAT                     (10000)
#define M_DFL_FEE_PROP_MILLIONTHS               (5000)

#define M_HTLCCHG_NONE                          (0)
#define M_HTLCCHG_FF_SEND                       (1)
#define M_HTLCCHG_FF_RECV                       (2)

#define M_SECINDEX_INIT     ((uint64_t)0xffffffffffff)      ///< per-commitment secret生成用indexの初期値
                                                            ///< https://github.com/nayuta-ueno/lightning-rfc/blob/master/03-transactions.md#per-commitment-secret-requirements

// ln_self_t.flck_flag
#define M_FLCK_FLAG_SEND                    (0x01)          ///< 1:funding_locked送信あり
#define M_FLCK_FLAG_RECV                    (0x02)          ///< 1:funding_locked受信あり
#define M_FLCK_FLAG_END                     (0x80)

// ln_self_t.anno_flag
#define M_ANNO_FLAG_SEND                    (0x01)          ///< 1:announcement_signatures送信あり
#define M_ANNO_FLAG_RECV                    (0x02)          ///< 1:announcement_signatures受信あり
#define M_ANNO_FLAG_END                     (0x80)

// ln_self_t.shutdown_flag
#define M_SHDN_FLAG_SEND                    (0x01)          ///< 1:shutdown送信あり
#define M_SHDN_FLAG_RECV                    (0x02)          ///< 1:shutdown受信あり
#define M_SHDN_FLAG_END                     (0x80)


#define M_PONG_MISSING                      (5)             ///< pongが返ってこないエラー上限

#define M_FUND_NONE                         (0)             ///< fund無し
#define M_FUND_FUNDER                       (1)             ///< funder
#define M_FUND_FUNDEE                       (2)             ///< fundee

#define M_FUNDING_INDEX                     (0)             ///< funding_txのvout


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    M_IS_OPENSIDE()
 *  @brief  true: open_channelを送信した側
 *  @note
 *      - Establish時しか使用しない
 */
#define M_IS_OPENSIDE(self)     (self->fund_flag == M_FUND_FUNDER)


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
static bool recv_funding_locked_first(ln_self_t *self);
static bool recv_funding_locked_reestablish(ln_self_t *self);
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
static bool create_funding_tx(ln_self_t *self);
static bool create_to_local(ln_self_t *self,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat);
static bool create_to_remote(ln_self_t *self,
                    uint8_t **pp_htlc_sigs,
                    uint8_t *p_htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat);
static bool create_closing_tx(ln_self_t *self, ucoin_tx_t *pTx, bool bVerify);
static bool create_channelkeys(ln_self_t *self);
static bool create_local_channel_announcement(ln_self_t *self);
static void update_percommit_secret(ln_self_t *self);
static void get_prev_percommit_secret(ln_self_t *self, uint8_t *p_prev_secret);
static bool store_peer_percommit_secret(ln_self_t *self, const uint8_t *p_prev_secret);
static bool proc_established(ln_self_t *self);
static void proc_announce_sigsed(ln_self_t *self);
static bool chk_peer_node(ln_self_t *self);
static bool get_nodeid(uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir);;
static void clear_htlc(ln_self_t *self, ln_update_add_htlc_t *p_add, uint8_t chg_flag);


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


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_init(ln_self_t *self, ln_node_t *node, const uint8_t *pSeed, ln_callback_t pFunc)
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

    ucoin_tx_init(&self->tx_funding);
    ucoin_tx_init(&self->tx_closing);

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        self->cnl_add_htlc[idx].p_onion_route = NULL;
        ucoin_buf_init(&self->cnl_add_htlc[idx].shared_secret);
    }

    //クリア
    self->lfeature_remote = NODE_LF_INIT;

    //初期値
    self->p_node = node;
    self->p_callback = pFunc;
    self->cltv_expiry_delta = M_DFL_CLTV_EXPILY_DELTA;
    self->htlc_minimum_msat = M_DFL_HTLC_MINIMUM_MSAT;
    self->fee_base_msat = M_DFL_FEE_BASE_MSAT;
    self->fee_prop_millionths = M_DFL_FEE_PROP_MILLIONTHS;

    //seed
    self->storage_index = M_SECINDEX_INIT;
    self->peer_storage_index = M_SECINDEX_INIT;
    if (pSeed) {
        memcpy(self->storage_seed, pSeed, UCOIN_SZ_PRIVKEY);
        ln_derkey_storage_init(&self->peer_storage);
    }

    DBG_PRINTF("END\n");

    return true;
}


void ln_term(ln_self_t *self)
{
    channel_clear(self);

    memset(self->storage_seed, 0, UCOIN_SZ_PRIVKEY);
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        self->cnl_add_htlc[idx].p_onion_route = NULL;
        ucoin_buf_free(&self->cnl_add_htlc[idx].shared_secret);
    }
}


void ln_set_genesishash(const uint8_t *pHash)
{
    memcpy(gGenesisChainHash, pHash, LN_SZ_HASH);
    DBG_PRINTF("genesis=");
    DUMPBIN(gGenesisChainHash, LN_SZ_HASH);
}


bool ln_set_establish(ln_self_t *self, ln_establish_t *pEstablish, const uint8_t *pNodeId)
{
    DBG_PRINTF("BEGIN\n");

    self->p_est = pEstablish;

    //デフォルト値
    if (pEstablish) {
        self->p_est->p_fundin = NULL;       //open_channel送信側が設定する

        self->p_est->defval.dust_limit_sat = M_DFL_DUST_LMIT_SAT;
        self->p_est->defval.max_htlc_value_in_flight_msat = M_DFL_MAX_HTLC_VALUE_IN_FLIGHT_MSAT;
        self->p_est->defval.channel_reserve_sat = M_DFL_CHANNEL_RESERVE_SAT;
        self->p_est->defval.htlc_minimum_msat = M_DFL_HTLC_MIN_MSAT;
        self->p_est->defval.to_self_delay = M_DFL_TO_SELF_DELAY;
        self->p_est->defval.max_accepted_htlcs = M_DFL_MAX_ACCEPTED_HTLC;
        self->p_est->defval.min_depth = M_DFL_MIN_DEPTH;
    }

    if ((pNodeId != NULL) && !ucoin_keys_chkpub(pNodeId)) {
        DBG_PRINTF("fail: invalid node_id\n");
        DUMPBIN(pNodeId, UCOIN_SZ_PUBKEY);
        return false;
    }

    if (pNodeId) {
        memcpy(self->peer_node.node_id, pNodeId, UCOIN_SZ_PUBKEY);
        int lp;
        for (lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
            if (self->p_node->keys.pub[lp] != self->peer_node.node_id[lp]) {
                break;
            }
        }
        if (self->p_node->keys.pub[lp] < self->peer_node.node_id[lp]) {
            self->peer_node.sort = UCOIN_KEYS_SORT_ASC;
        } else {
            self->peer_node.sort = UCOIN_KEYS_SORT_OTHER;
        }
    }

    DBG_PRINTF("END\n");

    return true;
}


bool ln_set_funding_wif(ln_self_t *self, const char *pWif)
{
    bool ret = ucoin_util_wif2keys(&self->funding_local.keys[MSG_FUNDIDX_FUNDING], pWif);
    //DBG_PRINTF("funding wif: %s\n", pWif);
    //DBG_PRINTF("funding pubkey: ");
    //DUMPBIN(self->funding_local.keys[MSG_FUNDIDX_FUNDING].pub, UCOIN_SZ_PUBKEY);

    return ret;
}


void ln_set_short_channel_id_param(ln_self_t *self, uint32_t Height, uint32_t Index)
{
    self->short_channel_id = ln_misc_calc_short_channel_id(Height, Index, M_FUNDING_INDEX);

    //announcement_signatures受信用
    create_local_channel_announcement(self);
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
    }

    return ret;
}


bool ln_set_shutdown_vout_addr(ln_self_t *self, const char *pAddr)
{
    ucoin_buf_t spk;

    ucoin_buf_init(&spk);
    bool ret = ucoin_keys_addr2spk(&spk, pAddr);
    if (ret) {
        ucoin_buf_alloccopy(&self->shutdown_scriptpk_local, spk.buf, spk.len);
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


bool ln_handshake_recv(ln_self_t *self, bool *pCont, ucoin_buf_t *pBuf, const uint8_t *pNodeId)
{
    bool ret;

    ret = ln_enc_auth_handshake_recv(self, pBuf, pNodeId);
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

    DBG_PRINTF("channel= %" PRIx64 "\n", self->short_channel_id);
    if ((type != MSGTYPE_INIT) && (!INIT_FLAG_INITED(self->init_flag))) {
        DBG_PRINTF("fail: no init received : %04x\n", type);
        return false;
    }

    for (int lp = 0; lp < ARRAY_SIZE(RECV_FUNC); lp++) {
        if (type == RECV_FUNC[lp].type) {
            DBG_PRINTF("type=%04x: Len=%d\n", type, Len);
            ret = (*RECV_FUNC[lp].func)(self, pData, Len);
            DBG_PRINTF("type=%04x, ret=%d\n", type, ret);
            break;
        }
    }

    return ret;
}


//init作成
bool ln_create_init(ln_self_t *self, ucoin_buf_t *pInit)
{
    if (self->init_flag & INIT_FLAG_SEND) {
        DBG_PRINTF("fail: init already sent.\n");
        return false;
    }

    ln_init_t msg;
    msg.gflen = 0;
    msg.lflen = 0;
    //msg.localfeatures[0] = NODE_LOCALFEATURES;

    //TODO: 本当は送信したタイミングがよい
    bool ret = ln_msg_init_create(pInit, &msg);
    if (ret) {
        self->init_flag |= INIT_FLAG_SEND;
    }
    return ret;
}


void ln_flag_proc(ln_self_t *self)
{
    bool ret = proc_established(self);
    if (!ret) {
        DBG_PRINTF("fail: proc_established\n");
    }
    proc_announce_sigsed(self);
}


//channel_reestablish作成
bool ln_create_channel_reestablish(ln_self_t *self, ucoin_buf_t *pReEst)
{
    if (self->init_flag & INIT_FLAG_REEST_SEND) {
        DBG_PRINTF("fail: channel_reestablish already sent.\n");
        return false;
    }

    ln_channel_reestablish_t msg;
    msg.p_channel_id = self->channel_id;
    msg.next_local_commitment_number = self->commit_num;
    msg.next_remote_revocation_number = self->remote_revoke_num;

    //TODO: 本当は送信したタイミングがよい
    bool ret = ln_msg_channel_reestablish_create(pReEst, &msg);
    if (ret) {
        self->init_flag |= INIT_FLAG_REEST_SEND;
    }
    return ret;
}


//open_channel生成
bool ln_create_open_channel(ln_self_t *self, ucoin_buf_t *pOpen,
            const ln_fundin_t *pFundin, uint64_t FundingSat, uint64_t PushSat, uint32_t FeeRate)
{
    if (!INIT_FLAG_INITED(self->init_flag)) {
        DBG_PRINTF("fail: no init finished\n");
        return false;
    }
    if (!chk_peer_node(self)) {
        DBG_PRINTF("fail: no peer node_id\n");
        return false;
    }

    //TODO: 仮チャネルID
    ucoin_util_random(self->channel_id, LN_SZ_CHANNEL_ID);

    //鍵生成
    bool ret = create_channelkeys(self);
    if (!ret) {
        DBG_PRINTF("fail: create_channelkeys\n");
        return false;
    }

    //funding鍵設定要求
    //アプリからの設定漏れがチェックできるように、funding鍵を0で初期化
    memset(&self->funding_local.keys[MSG_FUNDIDX_FUNDING], 0, sizeof(self->funding_local.keys[MSG_FUNDIDX_FUNDING]));
    (*self->p_callback)(self, LN_CB_FINDINGWIF_REQ, NULL);
    ret = ucoin_keys_chkpriv(self->funding_local.keys[MSG_FUNDIDX_FUNDING].priv);
    if (!ret) {
        DBG_PRINTF("fail: no funding key\n");
        return false;
    }

    ln_print_keys(PRINTOUT, &self->funding_local, &self->funding_remote);

    //funding_tx作成用に保持
    self->p_est->p_fundin = pFundin;

    //open_channel
    ln_open_channel_t *open_ch = &self->p_est->cnl_open;
    open_ch->funding_sat = FundingSat;
    open_ch->push_msat = LN_SATOSHI2MSAT(PushSat);
    open_ch->dust_limit_sat = self->p_est->defval.dust_limit_sat;
    open_ch->max_htlc_value_in_flight_msat = self->p_est->defval.max_htlc_value_in_flight_msat;
    open_ch->channel_reserve_sat = self->p_est->defval.channel_reserve_sat;
    open_ch->htlc_minimum_msat = self->p_est->defval.htlc_minimum_msat;
    open_ch->feerate_per_kw = FeeRate;
    open_ch->to_self_delay = self->p_est->defval.to_self_delay;
    open_ch->max_accepted_htlcs = self->p_est->defval.max_accepted_htlcs;
    open_ch->p_temp_channel_id = self->channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        open_ch->p_pubkeys[lp] = self->funding_local.keys[lp].pub;
    }
    open_ch->channel_flags = CHANNEL_FLAGS;
    ln_msg_open_channel_create(pOpen, open_ch);

    self->commit_local.accept_htlcs = open_ch->max_accepted_htlcs;
    self->commit_local.minimum_msat = open_ch->htlc_minimum_msat;
    self->commit_local.in_flight_msat = open_ch->max_htlc_value_in_flight_msat;
    self->commit_local.to_self_delay = open_ch->to_self_delay;
    self->commit_local.dust_limit_sat = open_ch->dust_limit_sat;
    self->our_msat = LN_SATOSHI2MSAT(open_ch->funding_sat) - open_ch->push_msat;
    self->their_msat = open_ch->push_msat;
    self->funding_sat = open_ch->funding_sat;
    self->feerate_per_kw = open_ch->feerate_per_kw;

    self->fund_flag = M_FUND_FUNDER;

    return true;
}


//funding_txをブロードキャストして安定した後に呼ぶ
//  funding_locked送信
/*
 * funding_lockedはお互い送信し合うことになる。
 *      open_channel送信側: funding_signed受信→funding_tx安定待ち→funding_locked送信→funding_locked受信→完了
 *      open_channel受信側: funding_locked受信→funding_tx安定待ち→完了
 *
 * funding_tx安定待ちで一度シーケンスが止まる。
 */
bool ln_funding_tx_stabled(ln_self_t *self)
{
    DBG_PRINTF("BEGIN\n");

    if (!INIT_FLAG_INITED(self->init_flag)) {
        DBG_PRINTF("fail: no init finished\n");
        return false;
    }
    if (self->short_channel_id == 0) {
        DBG_PRINTF("fail: not stabled\n");
        return false;
    }

    //per-commit-secret更新
    update_percommit_secret(self);

    //funding_locked
    ucoin_buf_t buf;
    ln_funding_locked_t cnl_funding_locked;
    cnl_funding_locked.p_channel_id = self->channel_id;
    cnl_funding_locked.p_per_commitpt = self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].pub;
    ln_msg_funding_locked_create(&buf, &cnl_funding_locked);

    //送信
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf);
    ucoin_buf_free(&buf);

    self->flck_flag |= M_FLCK_FLAG_SEND;

    return true;
}


//announcement_signaturesを交換すると channel_announcementが完成する。
bool ln_create_announce_signs(ln_self_t *self, ucoin_buf_t *pBufAnnoSigns)
{
    bool ret;

    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    //  self->cnl_annoはfundindg_lockedメッセージ作成時に行っている
    //  localのsignature
    ln_msg_get_anno_signs(self, &p_sig_node, &p_sig_btc, true);

    ln_announce_signs_t anno_signs;

    anno_signs.p_channel_id = self->channel_id;
    anno_signs.short_channel_id = self->short_channel_id;
    anno_signs.p_node_signature = p_sig_node;
    anno_signs.p_btc_signature = p_sig_btc;
    ret = ln_msg_announce_signs_create(pBufAnnoSigns, &anno_signs);
    if (ret) {
        self->anno_flag |= M_ANNO_FLAG_SEND;
    }

    return ret;
}


bool ln_create_channel_update(ln_self_t *self, ucoin_buf_t *pCnlUpd, uint32_t TimeStamp)
{
    ln_cnl_update_t upd;

    upd.short_channel_id = self->short_channel_id;
    upd.timestamp = TimeStamp;

    upd.cltv_expiry_delta = self->cltv_expiry_delta;
    upd.htlc_minimum_msat = self->htlc_minimum_msat;
    upd.fee_base_msat = self->fee_base_msat;
    upd.fee_prop_millionths = self->fee_prop_millionths;
    //署名
    upd.p_key = self->p_node->keys.priv;
    upd.sort = self->peer_node.sort;
    bool ret = ln_msg_cnl_update_create(pCnlUpd, &upd);

    return ret;
}


void ln_update_shutdown_fee(ln_self_t *self, uint64_t Fee)
{
    self->close_fee_sat = Fee;
    DBG_PRINTF("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
}


bool ln_create_shutdown(ln_self_t *self, ucoin_buf_t *pShutdown)
{
    DBG_PRINTF("BEGIN\n");

    if (!INIT_FLAG_INITED(self->init_flag)) {
        DBG_PRINTF("fail: no init finished\n");
        return false;
    }
    if (self->shutdown_flag & M_SHDN_FLAG_SEND) {
        //送信済み
        DBG_PRINTF("fail: already shutdown sent\n");
        return false;
    }
    if (self->htlc_num != 0) {
        //cleanではない
        DBG_PRINTF("fail: HTLC remains: %d\n", self->htlc_num);
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


bool ln_create_add_htlc(ln_self_t *self, ucoin_buf_t *pAdd,
            const uint8_t *pPacket,
            uint64_t amount_msat,
            uint32_t cltv_value,
            const uint8_t *pPaymentHash,
            uint64_t prev_short_channel_id,
            const ucoin_buf_t *pSharedSecrets)
{
    DBG_PRINTF("BEGIN\n");

    if (!INIT_FLAG_INITED(self->init_flag)) {
        DBG_PRINTF("fail: no init finished\n");
        return false;
    }

    //cltv_expiryは、500000000未満にしなくてはならない
    if (cltv_value >= 500000000) {
        DBG_PRINTF("fail: cltv_value >= 500000000\n");
        return false;
    }

    //現在のfeerate_per_kwで支払えないようなamount_msatを指定してはいけない
    if (amount_msat > self->our_msat) {
        DBG_PRINTF("fail: our_msat too small\n");
        return false;
    }

    bool ret;

    //追加した結果が相手のmax_accepted_htlcsより多くなるなら、追加してはならない。
    if (self->commit_remote.accept_htlcs <= self->htlc_num) {
        DBG_PRINTF("fail: over max_accepted_htlcs\n");
        return false;
    }

    //amount_msatは、0より大きくなくてはならない。
    //amount_msatは、相手のhtlc_minimum_msat未満にしてはならない。
    if ((amount_msat == 0) || (amount_msat < self->commit_remote.minimum_msat)) {
        DBG_PRINTF("fail: amount_msat(%" PRIu64 ") < remote htlc_minimum_msat(%" PRIu64 ")\n", amount_msat, self->commit_remote.minimum_msat);
        return false;
    }

    //加算した結果が相手のmax_htlc_value_in_flight_msatを超えるなら、追加してはならない。
    uint64_t in_flight_msat = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //TODO: OfferedとReceivedの見分けは不要？
        in_flight_msat += self->cnl_add_htlc[idx].amount_msat;
    }
    if (in_flight_msat > self->commit_remote.in_flight_msat) {
        DBG_PRINTF("fail: exceed remote max_htlc_value_in_flight_msat\n");
        return false;
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
        DBG_PRINTF("fail: no free add_htlc\n");
        return false;
    }

    self->cnl_add_htlc[idx].flag = LN_HTLC_FLAG_SEND;        //送信
    self->cnl_add_htlc[idx].p_channel_id = self->channel_id;
    self->cnl_add_htlc[idx].id = self->htlc_id_num;
    self->cnl_add_htlc[idx].amount_msat = amount_msat;
    self->cnl_add_htlc[idx].cltv_expiry = cltv_value;
    memcpy(self->cnl_add_htlc[idx].payment_sha256, pPaymentHash, LN_SZ_HASH);
    self->cnl_add_htlc[idx].p_onion_route = (CONST_CAST uint8_t *)pPacket;
    self->cnl_add_htlc[idx].prev_short_channel_id = prev_short_channel_id;
    ucoin_buf_free(&self->cnl_add_htlc[idx].shared_secret);
    if (pSharedSecrets) {
        self->cnl_add_htlc[idx].shared_secret.buf = pSharedSecrets->buf;
        self->cnl_add_htlc[idx].shared_secret.len = pSharedSecrets->len;
    }
    ret = ln_msg_update_add_htlc_create(pAdd, &self->cnl_add_htlc[idx]);

    //TODO: commit前に戻せるようにしておかなくてはならない
    if (ret) {
        self->our_msat -= amount_msat;
        self->htlc_id_num++;        //offer時にインクリメント
        self->htlc_num++;
        DBG_PRINTF("HTLC add : htlc_num=%d\n", self->htlc_num);
    }

    DBG_PRINTF("END\n");
    return ret;
}


bool ln_create_fulfill_htlc(ln_self_t *self, ucoin_buf_t *pFulfill, uint64_t id, const uint8_t *pPreImage)
{
    DBG_PRINTF("BEGIN\n");

    if (!INIT_FLAG_INITED(self->init_flag)) {
        DBG_PRINTF("fail: no init finished\n");
        return false;
    }
    uint8_t sha256[LN_SZ_HASH];
    ucoin_util_sha256(sha256, pPreImage, LN_SZ_PREIMAGE);
    ln_update_add_htlc_t *p_add = NULL;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //fulfill送信はReceived Outputに対して行う
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            DBG_PRINTF("id=%" PRIx64 ", htlc_id=%" PRIu64 "\n", id, self->cnl_add_htlc[idx].id);
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
        DBG_PRINTF("fail: preimage not mismatch\n");
        return false;
    }
    if (p_add->amount_msat == 0) {
        DBG_PRINTF("fail: invalid id\n");
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

        clear_htlc(self, p_add, M_HTLCCHG_FF_SEND);
    }

    DBG_PRINTF("END\n");
    return ret;
}


bool ln_create_fail_htlc(ln_self_t *self, ucoin_buf_t *pFail, uint64_t id, const ucoin_buf_t *pReason)
{
    DBG_PRINTF("BEGIN\n");

    if (!INIT_FLAG_INITED(self->init_flag)) {
        DBG_PRINTF("fail: no init finished\n");
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
        DBG_PRINTF("fail: id not mismatch\n");
        return false;
    }
    if (p_add->amount_msat == 0) {
        DBG_PRINTF("fail: invalid id\n");
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

        clear_htlc(self, p_add, M_HTLCCHG_FF_SEND);
    }

    DBG_PRINTF("END\n");
    return ret;
}


bool ln_create_commit_signed(ln_self_t *self, ucoin_buf_t *pCommSig)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    if (!INIT_FLAG_INITED(self->init_flag)) {
        DBG_PRINTF("fail: no init finished\n");
        return false;
    }

    //相手に送る署名を作成
    uint8_t htlc_sigs_num;
    uint8_t *p_htlc_sigs = NULL;    //必要があればcreate_to_remote()でMALLOC()する
    ret = create_to_remote(self, &p_htlc_sigs, &htlc_sigs_num,
                self->commit_remote.to_self_delay, self->commit_remote.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create remote sign");
        return false;
    }

    ln_commit_signed_t commsig;

    commsig.p_channel_id = self->channel_id;
    commsig.p_signature = self->commit_local.signature;     //相手commit_txに行った自分の署名
    commsig.num_htlcs = htlc_sigs_num;
    commsig.p_htlc_signature = p_htlc_sigs;
    ret = ln_msg_commit_signed_create(pCommSig, &commsig);
    M_FREE(p_htlc_sigs);

    //自分のcommitment_numberをインクリメント(channel_reestablish用)
    self->commit_num++;

    DBG_PRINTF("END\n");
    return ret;
}


bool ln_create_ping(ln_self_t *self, ucoin_buf_t *pPing)
{
    ln_ping_t ping;

    uint8_t rnd;
    ucoin_util_random(&rnd, 1);     //TODO:仕様上は2byteだが、そんなにいらないだろう
    self->last_num_pong_bytes = (uint16_t)rnd;
    ping.num_pong_bytes = self->last_num_pong_bytes;
    ucoin_util_random(&rnd, 1);     //TODO:仕様上は2byteだが、そんなにいらないだろう
    ping.byteslen = (uint16_t)rnd;
    bool ret = ln_msg_ping_create(pPing, &ping);
    if (ret) {
        self->missing_pong_cnt++;
        if (self->missing_pong_cnt > M_PONG_MISSING) {
            DBG_PRINTF("many pong missing...(%d)\n", self->missing_pong_cnt);
            ret = false;
        }
    }

    return ret;
}


bool ln_create_pong(ln_self_t *self, ucoin_buf_t *pPong, uint16_t NumPongBytes)
{
    ln_pong_t pong;

    pong.byteslen = NumPongBytes;
    bool ret = ln_msg_pong_create(pPong, &pong);

    return ret;
}


void ln_calc_preimage_hash(uint8_t *pHash, const uint8_t *pPreImage)
{
    ucoin_util_sha256(pHash, pPreImage, LN_SZ_PREIMAGE);
}


/** [routing用]channel_announcementデータ解析
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
 * @param[out]  pDelta
 * @param[out]  pMiniMsat
 * @param[out]  pBaseMsat
 * @param[out]  pPropMil
 * @param[in]   pData
 * @param[in]   Len
 * @retval  true        解析成功
 */
bool ln_getparams_cnl_upd(uint16_t *pDelta, uint64_t *pMiniMsat, uint32_t *pBaseMsat, uint32_t *pPropMil, const uint8_t *pData, uint16_t Len)
{
    ln_cnl_update_t upd;

    bool ret = ln_msg_cnl_update_read(&upd, pData, Len);
    if (ret) {
        *pDelta = upd.cltv_expiry_delta;
        *pMiniMsat = upd.htlc_minimum_msat;
        *pBaseMsat = upd.fee_base_msat;
        *pPropMil = upd.fee_prop_millionths;
    }

    return ret;
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

    ucoin_tx_free(&self->tx_funding);
    ucoin_tx_free(&self->tx_closing);

    if (self->p_node) {
        self->p_node = NULL;
    }

    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        self->cnl_add_htlc[idx].p_onion_route = NULL;
        ucoin_buf_free(&self->cnl_add_htlc[idx].shared_secret);
    }

    memset(&self->peer_node, 0, sizeof(ln_node_info_t));
    self->flck_flag = 0;
    self->anno_flag = 0;
    self->shutdown_flag = 0;

    //TODO: クリア漏れ調査
}


/********************************************************************
 * メッセージ受信
 ********************************************************************/

static bool recv_init(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;

    if (self->init_flag & INIT_FLAG_RECV) {
        //TODO: 2回init受信した場合はどうする？
        DBG_PRINTF("???: multiple init received.\n");
    }

    ln_init_t msg;
    ret = ln_msg_init_read(&msg, pData, Len);
    if (ret) {
        //有効なfeature以外のビットが立っていないこと
        ret = (msg.gflen == 0) &&
            (
                (msg.lflen == 0) ||
                ((msg.lflen == 1) && ((msg.localfeatures[0] & NODE_LF_INIT) == 0))
            );
    }
    if (ret) {
        self->init_flag |= INIT_FLAG_RECV;
        self->lfeature_remote = msg.localfeatures[0];

        //if (INIT_FLAG_INITED(self->init_flag) && ((self->init_flag & INIT_FLAG_REEST_SEND) == 0)) {
        //    //init送受信済みでchannel_reestablish未送信ならば、channel_reestablishを送信
        //} else if ((self->init_flag & INIT_FLAG_SEND) == 0) {
        //    //init未送信の場合
        //}

        //init受信通知
        (*self->p_callback)(self, LN_CB_INIT_RECV, NULL);
    } else {
        DBG_PRINTF("init error\n");
    }

    return ret;
}


static bool recv_error(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("\n");

    ln_msg_error_read(NULL, pData, Len);

    return true;
}


static bool recv_ping(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    ln_ping_t ping;
    ret = ln_msg_ping_read(&ping, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //脊髄反射的にpongを返す
    ucoin_buf_t buf_bolt;
    ret = ln_create_pong(self, &buf_bolt, ping.num_pong_bytes);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_pong(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    ln_pong_t pong;
    ret = ln_msg_pong_read(&pong, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //pongのbyteslenはpingのnum_pong_bytesであること
    ret = (pong.byteslen == self->last_num_pong_bytes);
    if (ret) {
        self->missing_pong_cnt--;
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_open_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    if (M_IS_OPENSIDE(self)) {
        //open_channel受信側ではない
        DBG_PRINTF("fail: invalid receiver\n");
        return false;
    }

    ln_open_channel_t *open_ch = &self->p_est->cnl_open;

    open_ch->p_temp_channel_id = self->channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        open_ch->p_pubkeys[lp] = self->funding_remote.pubkeys[lp];
    }
    ret = ln_msg_open_channel_read(open_ch, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    if (self->p_est->defval.min_depth < 1) {
        //minimum_depthが1より小さいと、ブロックに入らないため short_channel_idが計算できない
        DBG_PRINTF("*** minimum_depth < 1(%d) ***\n", self->p_est->defval.min_depth);
        self->p_est->defval.min_depth = 1;
    }

    self->commit_remote.accept_htlcs = open_ch->max_accepted_htlcs;
    self->commit_remote.minimum_msat = open_ch->htlc_minimum_msat;
    self->commit_remote.in_flight_msat = open_ch->max_htlc_value_in_flight_msat;
    self->commit_remote.to_self_delay = open_ch->to_self_delay;
    self->commit_remote.dust_limit_sat = open_ch->dust_limit_sat;

    self->funding_sat = open_ch->funding_sat;
    self->feerate_per_kw = open_ch->feerate_per_kw;
    self->our_msat = open_ch->push_msat;
    self->their_msat = LN_SATOSHI2MSAT(open_ch->funding_sat) - open_ch->push_msat;

    //鍵生成
    ret = create_channelkeys(self);
    if (!ret) {
        DBG_PRINTF("fail: create_channelkeys\n");
        return false;
    }

    //funding鍵設定要求
    //アプリからの設定漏れがチェックできるように、funding鍵を0で初期化
    memset(&self->funding_local.keys[MSG_FUNDIDX_FUNDING], 0, sizeof(self->funding_local.keys[MSG_FUNDIDX_FUNDING]));
    (*self->p_callback)(self, LN_CB_FINDINGWIF_REQ, NULL);
    ret = ucoin_keys_chkpriv(self->funding_local.keys[MSG_FUNDIDX_FUNDING].priv);
    if (!ret) {
        DBG_PRINTF("fail: no funding key\n");
        return false;
    }

    //スクリプト用鍵生成
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(PRINTOUT, &self->funding_local, &self->funding_remote);

    ln_accept_channel_t *acc_ch = &self->p_est->cnl_accept;
    acc_ch->dust_limit_sat = self->p_est->defval.dust_limit_sat;
    acc_ch->max_htlc_value_in_flight_msat = self->p_est->defval.max_htlc_value_in_flight_msat;
    acc_ch->channel_reserve_sat = self->p_est->defval.channel_reserve_sat;
    acc_ch->min_depth = self->p_est->defval.min_depth;
    acc_ch->htlc_minimum_msat = self->p_est->defval.htlc_minimum_msat;
    acc_ch->to_self_delay = self->p_est->defval.to_self_delay;
    acc_ch->max_accepted_htlcs = self->p_est->defval.max_accepted_htlcs;
    acc_ch->p_temp_channel_id = self->channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        acc_ch->p_pubkeys[lp] = self->funding_local.keys[lp].pub;
    }
    ucoin_buf_t buf_bolt;
    ln_msg_accept_channel_create(&buf_bolt, acc_ch);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    self->commit_local.accept_htlcs = acc_ch->max_accepted_htlcs;
    self->commit_local.minimum_msat = acc_ch->htlc_minimum_msat;
    self->commit_local.in_flight_msat = acc_ch->max_htlc_value_in_flight_msat;
    self->commit_local.to_self_delay = acc_ch->to_self_delay;
    self->commit_local.dust_limit_sat = acc_ch->dust_limit_sat;

    //obscured commitment tx numberは共通
    //  1番目:open_channelのpayment-basepoint
    //  2番目:accept_channelのpayment-basepoint
    self->obscured = ln_calc_obscured_txnum(
                                open_ch->p_pubkeys[MSG_FUNDIDX_PAYMENT],
                                acc_ch->p_pubkeys[MSG_FUNDIDX_PAYMENT]);
    DBG_PRINTF("obscured=%llx\n", (unsigned long long)self->obscured);

    //vout 2-of-2
    ret = ucoin_util_create2of2(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.keys[MSG_FUNDIDX_FUNDING].pub, self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);
    if (ret) {
        self->htlc_num = 0;
        self->fund_flag = M_FUND_FUNDEE;
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_accept_channel(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    if (!M_IS_OPENSIDE(self)) {
        //open_channel送信側ではない
        DBG_PRINTF("fail: invalid receiver\n");
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ln_accept_channel_t *acc_ch = &self->p_est->cnl_accept;
    acc_ch->p_temp_channel_id = channel_id;
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        acc_ch->p_pubkeys[lp] = self->funding_remote.pubkeys[lp];
    }
    ret = ln_msg_accept_channel_read(acc_ch, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //temporary-channel-idチェック
    if (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) != 0) {
        DBG_PRINTF("temporary-channel-id mismatch\n");
        return false;
    }

    self->commit_remote.accept_htlcs = acc_ch->max_accepted_htlcs;
    self->commit_remote.minimum_msat = acc_ch->htlc_minimum_msat;
    self->commit_remote.in_flight_msat = acc_ch->max_htlc_value_in_flight_msat;
    self->commit_remote.to_self_delay = acc_ch->to_self_delay;
    self->commit_remote.dust_limit_sat = acc_ch->dust_limit_sat;

    //スクリプト用鍵生成
    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
    ln_print_keys(PRINTOUT, &self->funding_local, &self->funding_remote);

    self->htlc_num = 0;

    //funding_tx作成
    ret = create_funding_tx(self);
    if (!ret) {
        DBG_PRINTF("fail: create_funding_tx\n");
        return false;
    }

    //obscured commitment tx numberは共通
    //  1番目:open_channelのpayment-basepoint
    //  2番目:accept_channelのpayment-basepoint
    self->obscured = ln_calc_obscured_txnum(
                                self->p_est->cnl_open.p_pubkeys[MSG_FUNDIDX_PAYMENT],
                                acc_ch->p_pubkeys[MSG_FUNDIDX_PAYMENT]);
    DBG_PRINTF("obscured=%llx\n", (unsigned long long)self->obscured);

    //
    // initial commit tx(Remoteが持つTo-Local)
    //      署名計算のみのため、計算後は破棄する
    //      HTLCは存在しないため、計算省略
    ret = create_to_remote(self, NULL, NULL,
                self->p_est->cnl_open.to_self_delay, acc_ch->dust_limit_sat);
    if (ret) {
        //funding_created
        ln_funding_created_t *fundc = &self->p_est->cnl_funding_created;
        fundc->p_temp_channel_id = self->channel_id;
        fundc->funding_output_idx = self->funding_local.funding_txindex;
        fundc->p_funding_txid = self->funding_local.funding_txid;
        fundc->p_signature = self->commit_local.signature;

        ucoin_buf_t buf_bolt;
        ln_msg_funding_created_create(&buf_bolt, fundc);
        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    } else {
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_funding_created(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    if (M_IS_OPENSIDE(self)) {
        //open_channel受信側ではない
        DBG_PRINTF("fail: invalid receiver\n");
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ln_funding_created_t *fundc = &self->p_est->cnl_funding_created;
    fundc->p_temp_channel_id = channel_id;
    fundc->p_funding_txid = self->funding_local.funding_txid;
    fundc->p_signature = self->commit_remote.signature;
    ret = ln_msg_funding_created_read(&self->p_est->cnl_funding_created, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //temporary-channel-idチェック
    if (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) != 0) {
        DBG_PRINTF("temporary-channel-id mismatch\n");
        return false;
    }

    self->funding_local.funding_txindex = fundc->funding_output_idx;

    //署名チェック用
    ucoin_tx_free(&self->tx_funding);
    for (int lp = 0; lp < self->funding_local.funding_txindex; lp++) {
        //処理の都合上、voutの位置を調整している
        ucoin_tx_add_vout(&self->tx_funding, 0);
    }
    ucoin_sw_add_vout_p2wsh(&self->tx_funding, self->p_est->cnl_open.funding_sat, &self->redeem_fund);
    //TODO: 実装上、vinが0、voutが1だった場合にsegwitと誤認してしまう
    ucoin_tx_add_vin(&self->tx_funding, self->funding_local.funding_txid, 0);

    //署名チェック
    // initial commit tx(自分が持つTo-Local)
    //      to-self-delayは相手の値(open_channel)を使う
    //      HTLCは存在しない
    ret = create_to_local(self, NULL, 0,
                self->p_est->cnl_accept.to_self_delay, self->p_est->cnl_accept.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create_to_local\n");
        return false;
    }

    // initial commit tx(Remoteが持つTo-Local)
    //      署名計算のみのため、計算後は破棄する
    //      HTLCは存在しないため、計算省略
    ret = create_to_remote(self, NULL, NULL,
                self->p_est->cnl_open.to_self_delay, self->p_est->cnl_open.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create_to_remote\n");
        return false;
    }

    //正式チャネルID
    ln_misc_calc_channel_id(self->channel_id, self->funding_local.funding_txid, self->funding_local.funding_txindex);

    //funding_signed
    self->p_est->cnl_funding_signed.p_channel_id = self->channel_id;
    self->p_est->cnl_funding_signed.p_signature = self->commit_local.signature;

    ucoin_buf_t buf_bolt;
    ln_msg_funding_signed_create(&buf_bolt, &self->p_est->cnl_funding_signed);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    ucoin_buf_free(&buf_bolt);

    DBG_PRINTF("END\n");
    return true;
}


static bool recv_funding_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    if (!M_IS_OPENSIDE(self)) {
        //open_channel送信側ではない
        DBG_PRINTF("fail: invalid receiver\n");
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    self->p_est->cnl_funding_signed.p_channel_id = channel_id;
    self->p_est->cnl_funding_signed.p_signature = self->commit_remote.signature;
    ret = ln_msg_funding_signed_read(&self->p_est->cnl_funding_signed, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-id生成
    ln_misc_calc_channel_id(self->channel_id, self->funding_local.funding_txid, self->funding_local.funding_txindex);

    //channel-idチェック
    if (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) != 0) {
        DBG_PRINTF("channel-id mismatch\n");
        return false;
    }

    //
    // initial commit tx(自分が持つTo-Local)
    //      to-self-delayは相手の値(accept_channel)を使う
    //      HTLCは存在しない
    ret = create_to_local(self, NULL, 0,
                self->p_est->cnl_accept.to_self_delay, self->p_est->cnl_open.dust_limit_sat);
    if (!ret) {
        DBG_PRINTF("fail: create_to_local\n");
        return false;
    }

    //funding_tx安定待ち(シーケンスの再開はアプリ指示)
    self->short_channel_id = 0;
    ln_cb_funding_t funding;
    funding.p_tx_funding = &self->tx_funding;
    funding.p_txid = self->funding_local.funding_txid;
    funding.min_depth = self->p_est->cnl_accept.min_depth;
    funding.b_send = true;  //sendrawtransactionする
    (*self->p_callback)(self, LN_CB_FUNDINGTX_WAIT, &funding);

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
    ln_funding_locked_t cnl_funding_locked;

    cnl_funding_locked.p_channel_id = channel_id;
    cnl_funding_locked.p_per_commitpt = self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT];
    ret = ln_msg_funding_locked_read(&cnl_funding_locked, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
        return false;
    }

    if (INIT_FLAG_REESTED(self->init_flag)) {
        ret = recv_funding_locked_reestablish(self);
    } else {
        //Establish直後
        ret = recv_funding_locked_first(self);
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_funding_locked_first(ln_self_t *self)
{
    DBG_PRINTF("\n");

    //commitment numberは0から始まる
    //  BOLT#0
    //  https://github.com/nayuta-ueno/lightning-rfc/blob/master/00-introduction.md#glossary-and-terminology-guide
    //が、opening時を1回とカウントするので、Normal Operationでは1から始まる
    //  BOLT#2
    //  https://github.com/nayuta-ueno/lightning-rfc/blob/master/02-peer-protocol.md#rationale-10
    self->commit_num = 1;
    self->remote_commit_num = 1;
    self->revoke_num = 0;
    self->remote_revoke_num = 0;
    //update_add_htlcのidも0から始まる(インクリメントするタイミングはcommitment numberと異なる)
    self->htlc_id_num = 0;

    self->flck_flag |= M_FLCK_FLAG_RECV;
    bool ret = proc_established(self);
    if (!ret) {
        DBG_PRINTF("fail: proc_established\n");
        return false;
    }

    if (self->flck_flag == M_FLCK_FLAG_RECV) {
        //funding_locked未送信

        //funding_tx安定待ち(シーケンスの再開はアプリ指示)
        self->short_channel_id = 0;
        ln_cb_funding_t funding;

        funding.p_tx_funding = &self->tx_funding;
        funding.p_txid = self->funding_local.funding_txid;
        funding.min_depth = self->p_est->cnl_accept.min_depth;
        funding.b_send = false;
        (*self->p_callback)(self, LN_CB_FUNDINGTX_WAIT, &funding);
    }

    return true;
}


static bool recv_funding_locked_reestablish(ln_self_t *self)
{
    DBG_PRINTF("\n");

    bool ret;

    self->flck_flag |= M_FLCK_FLAG_RECV;
    ret = proc_established(self);
    if (ret && (self->flck_flag != (M_FLCK_FLAG_SEND | M_FLCK_FLAG_RECV))) {
        //funding_locked未送信
        ret = ln_funding_tx_stabled(self);
    } else {
        DBG_PRINTF("fail: proc_established\n");
    }

    return ret;
}


static bool recv_shutdown(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;

    if (self->short_channel_id == 0) {
        DBG_PRINTF("already closed\n");
        return true;
    }

    if (self->shutdown_flag & M_SHDN_FLAG_RECV) {
        //既にshutdownを受信済みなら、何もしない
        return false;
    }

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    self->cnl_shutdown.p_channel_id = channel_id;
    self->cnl_shutdown.p_scriptpk = &self->shutdown_scriptpk_remote;
    ret = ln_msg_shutdown_read(&self->cnl_shutdown, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    if (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) != 0) {
        DBG_PRINTF("channel-id mismatch\n");
        return false;
    }

    //scriptPubKeyチェック
    ret = ln_check_scriptpkh(&self->shutdown_scriptpk_remote);
    if (!ret) {
        DBG_PRINTF("unknown scriptPubKey type\n");
        return false;
    }

    //TODO:HTLCが残っていたらfalse
    //  相手がshutdownを送ってきたということは、HTLCは持っていないはず。
    //  相手は持っていなくて自分は持っているという状況は発生しないと思っている。

    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    if (!(self->shutdown_flag & M_SHDN_FLAG_SEND)) {
        //shutdown未送信の場合 == shutdownを要求された方
        ret = ln_create_shutdown(self, &buf_bolt);
        if (ret) {
            self->shutdown_flag |= M_SHDN_FLAG_SEND;
        }
    } else if (!(self->shutdown_flag & M_SHDN_FLAG_RECV)) {
        //shutdown未受信の場合 == shutdownを要求した方
        DBG_PRINTF("fee_sat: %" PRIu64 "\n", self->close_fee_sat);
        self->cnl_closing_signed.p_channel_id = self->channel_id;
        self->cnl_closing_signed.fee_sat = self->close_fee_sat;
        self->cnl_closing_signed.p_signature = self->commit_local.signature;

        //remoteの署名はないので、verifyしない
        ucoin_tx_free(&self->tx_closing);
        ret = create_closing_tx(self, &self->tx_closing, false);
        if (ret) {
            ret = ln_msg_closing_signed_create(&buf_bolt, &self->cnl_closing_signed);
        }
    }

    if (buf_bolt.len > 0) {
        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    }

    //shutdown受信済み
    self->shutdown_flag |= M_SHDN_FLAG_RECV;

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_closing_signed(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    if (self->short_channel_id == 0) {
        DBG_PRINTF("already closed\n");
        return true;
    }

    if (self->shutdown_flag != (M_SHDN_FLAG_SEND | M_SHDN_FLAG_RECV)) {
        DBG_PRINTF("bad status : %02x\n", self->shutdown_flag);
        return false;
    }

    bool ret;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    self->cnl_closing_signed.p_channel_id = channel_id;
    self->cnl_closing_signed.p_signature = self->commit_remote.signature;
    ret = ln_msg_closing_signed_read(&self->cnl_closing_signed, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    if (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) != 0) {
        DBG_PRINTF("channel-id mismatch\n");
        return false;
    }

    self->cnl_closing_signed.p_channel_id = self->channel_id;
    self->cnl_closing_signed.p_signature = self->commit_local.signature;

    //TODO: 今回は受信したfeeでclosing_tx生成し、署名する
    ucoin_tx_free(&self->tx_closing);
    ret = create_closing_tx(self, &self->tx_closing, true);

    //ノード情報からチャネル削除
    //ln_node_del_channel(self->p_node, self->short_channel_id);

    ucoin_buf_t buf_bolt;
    ucoin_buf_init(&buf_bolt);
    if (ret) {
        ret = ln_msg_closing_signed_create(&buf_bolt, &self->cnl_closing_signed);
    }

    if (ret) {
        ucoin_buf_t txbuf;
        ucoin_buf_init(&txbuf);
        ucoin_tx_create(&txbuf, &self->tx_closing);

        ln_cb_closed_t closed;
        closed.p_buf_bolt = &buf_bolt;
        closed.p_tx_closing = &txbuf;
        (*self->p_callback)(self, LN_CB_CLOSED, &closed);
        ucoin_buf_free(&txbuf);
    }
    ucoin_buf_free(&buf_bolt);

    //ここでクリアすると、shutdown_flagもクリアされるので、2回受信しても送信はしなくなる。
    channel_clear(self);

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_update_add_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    if (self->short_channel_id == 0) {
        DBG_PRINTF("already closed\n");
        return true;
    }

    bool ret;
    int idx;

    for (idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat == 0) {
            //BOLT#2: MUST offer amount-msat greater than 0
            //  だから、0の場合は空き
            break;
        }
    }
    if (idx >= LN_HTLC_MAX) {
        DBG_PRINTF("fail: no free add_htlc\n");
        return false;
    }

    //処理前呼び出し
    (*self->p_callback)(self, LN_CB_ADD_HTLC_RECV_PREV, NULL);

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t onion_route[LN_SZ_ONION_ROUTE];
    self->cnl_add_htlc[idx].p_channel_id = channel_id;
    self->cnl_add_htlc[idx].p_onion_route = onion_route;
    ret = ln_msg_update_add_htlc_read(&self->cnl_add_htlc[idx], pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
        return false;
    }

#warning TODO: HTLCチェック
    //送信側が現在のfeerate_per_kwで支払えないようなamount_msatの場合、チャネルを失敗させる。
    //同じpayment-hashを複数回受信しても、許容する。
    //再接続後に、送信側に受入(acknowledge)されていない前と同じidを送ってきても、無視する。
    //破壊するようなidを送ってきたら、チャネルを失敗させる。

    uint64_t in_flight_msat = 0;
    //uint64_t bak_msat = self->their_msat;
    //uint16_t bak_num = self->htlc_num;

    //追加した結果が自分のmax_accepted_htlcsより多くなるなら、チャネルを失敗させる。
    if (self->commit_local.accept_htlcs <= self->htlc_num) {
        DBG_PRINTF("fail: over max_accepted_htlcs : %d\n", self->htlc_num);
        goto LABEL_ERR;
    }

    //amount_msatが0の場合、チャネルを失敗させる。
    //amount_msatが自分のhtlc_minimum_msat未満の場合、チャネルを失敗させる。
    if ((self->cnl_add_htlc[idx].amount_msat == 0) || (self->cnl_add_htlc[idx].amount_msat < self->commit_local.minimum_msat)) {
        DBG_PRINTF("fail: amount_msat < local htlc_minimum_msat\n");
        goto LABEL_ERR;
    }
    //BOLT#2
    //  For channels with chain_hash identifying the Bitcoin blockchain,
    //  the sending node MUST set the 4 most significant bytes of amount_msat to zero.
    if (self->cnl_add_htlc[idx].amount_msat & (uint64_t)0xffffffff00000000) {
        DBG_PRINTF("fail: Bitcoin amount_msat must 4 MSByte not 0\n");
        goto LABEL_ERR;
    }

    //加算した結果が自分のmax_htlc_value_in_flight_msatを超えるなら、チャネルを失敗させる。
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        //TODO: OfferedとReceivedの見分けは不要？
        in_flight_msat += self->cnl_add_htlc[idx].amount_msat;
    }
    if (in_flight_msat > self->commit_local.in_flight_msat) {
        DBG_PRINTF("fail: exceed local max_htlc_value_in_flight_msat\n");
        goto LABEL_ERR;
    }

    ln_hop_dataout_t hop_dataout;   // update_add_htlc受信後のONION解析結果
    ret = ln_onion_read_packet(self->cnl_add_htlc[idx].p_onion_route, &hop_dataout,
                    &self->cnl_add_htlc[idx].shared_secret,
                    self->cnl_add_htlc[idx].p_onion_route, self->p_node->keys.priv, NULL, 0);
    if (!ret) {
        DBG_PRINTF("fail: onion-read\n");
        goto LABEL_ERR;
    }

    if (self->their_msat < self->cnl_add_htlc[idx].amount_msat) {
        DBG_PRINTF("fail: their_msat too small(%" PRIu64 " < %" PRIu64 ")\n", self->their_msat, self->cnl_add_htlc[idx].amount_msat);
        goto LABEL_ERR;
    }


    //cltv_expiryが500000000以上の場合、チャネルを失敗させる。
    if (self->cnl_add_htlc[idx].cltv_expiry >= 500000000) {
        DBG_PRINTF("fail: cltv_expiry >= 500000000\n");
        goto LABEL_ERR;
    }
    if (!hop_dataout.b_exit) {
        //転送先のcltv_expiryの方が大きかったり、cltv_expiry_deltaを満たしていない
        if ( (self->cnl_add_htlc[idx].cltv_expiry <= hop_dataout.outgoing_cltv_value) ||
             (self->cnl_add_htlc[idx].cltv_expiry - hop_dataout.outgoing_cltv_value < ln_cltv_expily_delta(self)) ) {
            DBG_PRINTF("fail: cltv not enough : %" PRIu32 "\n", ln_cltv_expily_delta(self));
            goto LABEL_ERR;
        }
    }

    //相手からの受信は無条件でHTLC追加
    self->their_msat -= self->cnl_add_htlc[idx].amount_msat;
    self->htlc_num++;
    DBG_PRINTF("HTLC add : htlc_num=%d, id=%" PRIx64 ", amount_msat=%" PRIu64 "\n", self->htlc_num, self->cnl_add_htlc[idx].id, self->cnl_add_htlc[idx].amount_msat);

    //update_add_htlc受信通知
    ln_cb_add_htlc_recv_t add_htlc;
    add_htlc.ok = false;
    add_htlc.id = self->cnl_add_htlc[idx].id;
    add_htlc.p_payment_hash = self->cnl_add_htlc[idx].payment_sha256;
    add_htlc.p_hop = &hop_dataout;
    add_htlc.amount_msat = self->cnl_add_htlc[idx].amount_msat;
    add_htlc.cltv_expiry = self->cnl_add_htlc[idx].cltv_expiry;
    add_htlc.p_onion_route = self->cnl_add_htlc[idx].p_onion_route;
    add_htlc.p_shared_secret = &self->cnl_add_htlc[idx].shared_secret;
    (*self->p_callback)(self, LN_CB_ADD_HTLC_RECV, &add_htlc);
    if (!add_htlc.ok) {
        DBG_PRINTF("fail: application\n");
        //self->their_msat = bak_msat;  //ln_create_fail_htlc()でtheir_msatを戻す
        //self->htlc_num = bak_num;    //ln_create_fail_htlc()でhtlc_numを減らす
        goto LABEL_ERR;
    }

    DBG_PRINTF("END\n");
    return true;

LABEL_ERR:
    DBG_PRINTF("fail restore[%d]=%d\n", idx, self->cnl_add_htlc[idx].shared_secret.len);

    //ln_cb_fail_htlc_recv_t fail_recv;
    ucoin_buf_t buf_bolt;
    ucoin_buf_t buf_reason;

#warning reasonダミー
    const uint8_t dummy_reason_data[] = { 0x20, 0x02 };
    const ucoin_buf_t dummy_reason = { (uint8_t *)dummy_reason_data, sizeof(dummy_reason_data) };

    ln_onion_failure_create(&buf_reason, &self->cnl_add_htlc[idx].shared_secret, &dummy_reason);
    ret = ln_create_fail_htlc(self, &buf_bolt, self->cnl_add_htlc[idx].id, &buf_reason);
    assert(ret);
    (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
    ucoin_buf_free(&buf_reason);
    ucoin_buf_free(&buf_bolt);
    return true;
}


static bool recv_update_fulfill_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    if (self->short_channel_id == 0) {
        DBG_PRINTF("already closed\n");
        return true;
    }

    bool ret;
    ln_update_fulfill_htlc_t    fulfill_htlc;

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t preimage[LN_SZ_PREIMAGE];
    fulfill_htlc.p_channel_id = channel_id;
    fulfill_htlc.p_payment_preimage = preimage;
    ret = ln_msg_update_fulfill_htlc_read(&fulfill_htlc, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
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

    //TODO: commit前に戻せるようにしておかなくてはならない
    if (ret) {
        //反映
        //self->our_msat -= p_add->amount_msat; //add_htlc送信時に引いているので、ここでは不要
        self->their_msat += p_add->amount_msat;

        uint64_t prev_short_channel_id = p_add->prev_short_channel_id; //CB用
        uint64_t prev_id = fulfill_htlc.id;  //CB用

        clear_htlc(self, p_add, M_HTLCCHG_FF_RECV);

        //update_fulfill_htlc受信通知
        ln_cb_fulfill_htlc_recv_t fulfill;
        fulfill.prev_short_channel_id = prev_short_channel_id;
        fulfill.p_preimage = preimage;
        fulfill.id = prev_id;
        (*self->p_callback)(self, LN_CB_FULFILL_HTLC_RECV, &fulfill);
    } else {
        DBG_PRINTF("fail: fulfill\n");
    }

    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_update_fail_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");

    if (self->short_channel_id == 0) {
        DBG_PRINTF("already closed\n");
        return true;
    }

    bool ret;
    ln_update_fail_htlc_t    fail_htlc;

    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    ucoin_buf_t             reason;

    fail_htlc.p_channel_id = channel_id;
    ucoin_buf_init(&reason);
    fail_htlc.p_reason = &reason;
    ret = ln_msg_update_fail_htlc_read(&fail_htlc, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
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
            fail_recv.id = self->cnl_add_htlc[idx].id;
            (*self->p_callback)(self, LN_CB_FAIL_HTLC_RECV, &fail_recv);

            clear_htlc(self, &self->cnl_add_htlc[idx], M_HTLCCHG_FF_RECV);
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

    memcpy(bak_sig, self->commit_remote.signature, LN_SZ_SIGNATURE);
    commsig.p_channel_id = channel_id;
    commsig.p_signature = self->commit_remote.signature;
    commsig.p_htlc_signature = NULL;        //ln_msg_commit_signed_read()でMALLOCする
    ret = ln_msg_commit_signed_read(&commsig, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        goto LABEL_EXIT;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
        goto LABEL_EXIT;
    }

    //署名チェック＋保存: To-Local
    ret = create_to_local(self, commsig.p_htlc_signature, commsig.num_htlcs,
                self->commit_local.to_self_delay, self->commit_local.dust_limit_sat);
    M_FREE(commsig.p_htlc_signature);
    if (!ret) {
        DBG_PRINTF("fail: create_to_local\n");
        goto LABEL_EXIT;
    }

    //相手のcommitment_numberをインクリメント(channel_reestablish用)
    self->remote_commit_num++;

    uint8_t prev_secret[UCOIN_SZ_PRIVKEY];
    get_prev_percommit_secret(self, prev_secret);

    //per-commit-secret更新
    update_percommit_secret(self);

    //チェックOKであれば、revoke_and_ackを返す
    //HTLCに変化がある場合、revoke_and_ack→commitment_signedの順で送信したい

    ucoin_buf_t buf_revack;

    ucoin_buf_init(&buf_revack);
    revack.p_channel_id = channel_id;
    revack.p_per_commit_secret = prev_secret;
    revack.p_per_commitpt = self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].pub;
    ret = ln_msg_revoke_and_ack_create(&buf_revack, &revack);
    if (ret) {
        //自分のrevoke_numberをインクリメント(channel_reestablish用)
        self->revoke_num++;

        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_revack);
    }
    ucoin_buf_free(&buf_revack);

    if (ret) {
        //commitment_signed受信通知
        //ln_cb_commsig_recv_t commsig;
        (*self->p_callback)(self, LN_CB_COMMIT_SIG_RECV, NULL);
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
        DBG_PRINTF("fail: read message\n");
        goto LABEL_EXIT;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
        goto LABEL_EXIT;
    }
    //prev_secretチェック
    uint8_t prev_commitpt[UCOIN_SZ_PUBKEY];
    ret = ucoin_keys_priv2pub(prev_commitpt, prev_secret);
    if (!ret) {
        DBG_PRINTF("fail: prev_secret convert\n");
        goto LABEL_EXIT;
    }
    if (memcmp(prev_commitpt, self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY) != 0) {
        DBG_PRINTF("fail: prev_secret mismatch\n");
        DBG_PRINTF("recv prev: ");
        DUMPBIN(prev_commitpt, UCOIN_SZ_PUBKEY);
        DBG_PRINTF("used pub : ");
        DUMPBIN(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);
        ret = false;
        goto LABEL_EXIT;
    }

    //相手のrevoke_numberをインクリメント(channel_reestablish用)
    self->remote_revoke_num++;

    //prev_secret保存
    ret = store_peer_percommit_secret(self, prev_secret);
    if (!ret) {
        DBG_PRINTF("fail: store prev secret\n");
        goto LABEL_EXIT;
    }

    //per_commitment_point更新
    memcpy(self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT], new_commitpt, UCOIN_SZ_PUBKEY);

    //HTLC変化通知
    //ln_cb_htlc_changed_t htlc_chg;
    (*self->p_callback)(self, LN_CB_HTLC_CHANGED, NULL);

LABEL_EXIT:
    DBG_PRINTF("END\n");
    return ret;
}


static bool recv_update_fee(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");
    return false;
}


static bool recv_update_fail_malformed_htlc(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    DBG_PRINTF("BEGIN\n");
    return false;
}


static bool recv_channel_reestablish(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;

    DBG_PRINTF("BEGIN\n");

    if (self->init_flag & INIT_FLAG_REEST_RECV) {
        //TODO: 2回channel_reestablish受信した場合はどうする？
        DBG_PRINTF("???: multiple channel_reestablish received.\n");
    }

    ln_channel_reestablish_t reest;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];

    reest.p_channel_id = channel_id;
    ret = ln_msg_channel_reestablish_read(&reest, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("channel-id mismatch\n");
        return false;
    }

    if ( (self->remote_commit_num != reest.next_local_commitment_number) ||
         (self->revoke_num != reest.next_remote_revocation_number) ) {
        DBG_PRINTF("number mismatch\n");
        DBG_PRINTF("  %" PRIu64 " .. %" PRIu64 "\n", self->remote_commit_num, reest.next_local_commitment_number);
        DBG_PRINTF("  %" PRIu64 " .. %" PRIu64 "\n", self->revoke_num, reest.next_remote_revocation_number);
        return false;
    }

    self->init_flag |= INIT_FLAG_REEST_RECV;

    //reestablish受信通知
    (*self->p_callback)(self, LN_CB_REESTABLISH_RECV, NULL);


    if ((self->init_flag & INIT_FLAG_REEST_SEND) == 0) {
        //返送
        reest.next_local_commitment_number = self->commit_num;
        reest.next_remote_revocation_number = self->remote_revoke_num;

        ucoin_buf_t buf_bolt;
        ret = ln_msg_channel_reestablish_create(&buf_bolt, &reest);
        if (ret) {
            self->init_flag |= INIT_FLAG_REEST_SEND;
        }
        (*self->p_callback)(self, LN_CB_SEND_REQ, &buf_bolt);
        ucoin_buf_free(&buf_bolt);
    }

    return ret;
}


static bool recv_announcement_signatures(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    bool ret;
    ln_announce_signs_t anno_signs;
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint8_t *p_sig_node;
    uint8_t *p_sig_btc;

    DBG_PRINTF("node=%p\n", self->p_node);

    //announcement_signaturesを受信したときの状態として、以下が考えられる。
    //      - 相手から初めて受け取り、まだ自分からは送信していない
    //      - 自分から送信していて、相手から初めて受け取った
    //      - 持っているけど、また受け取った
    //
    //  また、announcement_signatures はチャネル間メッセージだが、
    //  channel_announcment はノードとして管理する情報になる。
    //  ここら辺が紛らわしくなってくる理由だろう。

    //short_channel_idで検索
    uint64_t short_channel_id = ln_msg_announce_signs_read_short_cnl_id(pData, Len, self->channel_id);
    if (short_channel_id == 0) {
        DBG_PRINTF("fail: invalid packet\n");
        return false;
    }
    DBG_PRINTF("short_channel_id = %" PRIx64 "\n", short_channel_id);
    if (short_channel_id != self->short_channel_id) {
        DBG_PRINTF("fail: short_channel_id mismatch\n");
        return false;
    }

    //channel_announcementを埋める
    //  self->cnl_annoはfundindg_lockedメッセージ作成時に行っている
    //  remoteのsignature
    ln_msg_get_anno_signs(self, &p_sig_node, &p_sig_btc, false);

    anno_signs.p_channel_id = channel_id;
    anno_signs.p_node_signature = p_sig_node;
    anno_signs.p_btc_signature = p_sig_btc;
    ret = ln_msg_announce_signs_read(&anno_signs, pData, Len);
    if (!ret) {
        DBG_PRINTF("fail: read message\n");
        return false;
    }

    //channel-idチェック
    ret = (memcmp(channel_id, self->channel_id, LN_SZ_CHANNEL_ID) == 0);
    if (!ret) {
        DBG_PRINTF("fail: channel-id mismatch\n");
        return false;
    }

    DBG_PRINTF("+++ channel_announcement[%" PRIx64 "] +++\n", self->short_channel_id);
    ln_msg_cnl_announce_print(self->cnl_anno.buf, self->cnl_anno.len);


    //channel_update
    ucoin_buf_t buf_upd;
    ucoin_buf_init(&buf_upd);
    uint32_t now = (uint32_t)time(NULL);
    ret = ln_create_channel_update(self, &buf_upd, now);
    if (!ret) {
        DBG_PRINTF("fail: ln_create_channel_update\n");
        return false;
    }

    //DB保存
    ret = ln_db_save_anno_channel(&self->cnl_anno, ln_short_channel_id(self), ln_their_node_id(self));
    if (!ret) {
        DBG_PRINTF("fail: ln_db_save_anno_channel\n");
        return false;
    }
    ret = ln_db_save_anno_channel_upd(&buf_upd, ln_short_channel_id(self), self->peer_node.sort);
    if (!ret) {
        DBG_PRINTF("fail: ln_db_save_anno_channel_upd\n");
        return false;
    }

    ucoin_buf_free(&buf_upd);
    self->anno_flag |= M_ANNO_FLAG_RECV;

    return true;
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

    bool ret = ln_msg_cnl_announce_read(&ann, pData, Len);
    if (ret) {
        ln_cb_channel_anno_recv_t param;

        param.short_channel_id = ann.short_channel_id;
        (*self->p_callback)(self, LN_CB_CHANNEL_ANNO_RECV, &param);
    } else {
        DBG_PRINTF("err\n");
    }

    ucoin_buf_t buf;
    buf.buf = (CONST_CAST uint8_t *)pData;
    buf.len = Len;

    //DB読込み
    ucoin_buf_t buf_bolt;
    ret = ln_db_load_anno_channel(&buf_bolt, ann.short_channel_id);
    if (ret) {
        // BOLT#7
        //  https://github.com/nayuta-ueno/lightning-rfc/blob/master/07-routing-gossip.md#requirements-1
        //
        // If it has previously received a valid channel_announcement
        // for the same transaction in the same block, but different node_id_1 or node_id_2,
        // it SHOULD blacklist the previous message's node_id_1 and node_id_2 as well as
        // this node_id_1 and node_id_2 and forget channels connected to them,
        // otherwise it SHOULD store this channel_announcement.
        if (ucoin_buf_cmp(&buf_bolt, &buf)) {
            DBG_PRINTF("同じものが送られてきたので、スルー\n");
        } else {
            DBG_PRINTF("不一致のためblacklist入りする予定\n");
            assert(0);
        }
    }

    //DB保存
    ret = ln_db_save_anno_channel(&buf, ann.short_channel_id, ln_their_node_id(self));

    return ret;
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
    DBG_PRINTF("\n");

    ln_cnl_update_t upd;

    //verify
    bool ret = ln_msg_cnl_update_read(&upd, pData, Len);
    DBG_PRINTF("ret=%d\n", ret);

    if (ret) {
        //short_channel_id と dir から node_id を取得する
        uint8_t node_id[UCOIN_SZ_PUBKEY];

        ret = get_nodeid(node_id, upd.short_channel_id, upd.flags & 0x0001);
        if (ret && ucoin_keys_chkpub(node_id)) {
            ret = ln_msg_cnl_update_verify(node_id, pData, Len);
        } else {
            DBG_PRINTF("err\n");
        }
    }

    if (ret) {
        //DB保存
        ucoin_buf_t buf;
        buf.buf = (CONST_CAST uint8_t *)pData;
        buf.len = Len;
        ret = ln_db_save_anno_channel_upd(&buf, upd.short_channel_id, upd.flags & 0x0001);
    } else {
        DBG_PRINTF("err\n");
    }

    return ret;
}


/********************************************************************
 * Transaction作成
 ********************************************************************/

/** funding_tx作成
 *
 * @param[in,out]       self
 */
static bool create_funding_tx(ln_self_t *self)
{
    ucoin_tx_free(&self->tx_funding);

    //vout 2-of-2
    ucoin_util_create2of2(&self->redeem_fund, &self->key_fund_sort,
                self->funding_local.keys[MSG_FUNDIDX_FUNDING].pub, self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING]);

    //output
    //vout#0:P2WSH - 2-of-2 : M_FUNDING_INDEX
    ucoin_sw_add_vout_p2wsh(&self->tx_funding, self->p_est->cnl_open.funding_sat, &self->redeem_fund);

    //vout#1:P2WPKH - change(後で代入)
    if (self->p_est->p_fundin->p_change_pubkey) {
        ucoin_sw_add_vout_p2wpkh_pub(&self->tx_funding, (uint64_t)-1, self->p_est->p_fundin->p_change_pubkey);
    } else {
        ucoin_tx_add_vout_addr(&self->tx_funding, (uint64_t)-1, self->p_est->p_fundin->p_change_addr);
    }

    //input
    //vin#0
    ucoin_tx_add_vin(&self->tx_funding, self->p_est->p_fundin->p_txid, self->p_est->p_fundin->index);


    //FEE計算
    //      txサイズに署名の中間サイズと公開鍵サイズを加えたサイズにする
    //          http://bitcoin.stackexchange.com/questions/1195/how-to-calculate-transaction-size-before-sending
    ucoin_buf_t txbuf;
    ucoin_buf_init(&txbuf);
    ucoin_tx_create(&txbuf, &self->tx_funding);

    // LEN+署名(72) + LEN+公開鍵(33)
    uint64_t fee = (txbuf.len + 1 + 72 + 1 + 33) * 4 * self->p_est->cnl_open.feerate_per_kw / 1000;
    if (self->p_est->p_fundin->amount >= self->p_est->cnl_open.funding_sat + fee) {
        self->tx_funding.vout[1].value = self->p_est->p_fundin->amount - self->p_est->cnl_open.funding_sat - fee;
    } else {
        DBG_PRINTF("fail: amount too short:\n");
        DBG_PRINTF("    amount=%" PRIu64 "\n", self->p_est->p_fundin->amount);
        DBG_PRINTF("    funding_sat=%" PRIu64 "\n", self->p_est->cnl_open.funding_sat);
        DBG_PRINTF("    fee=%" PRIu64 "\n", fee);
        return false;
    }
    ucoin_buf_free(&txbuf);

    //署名
    self->funding_local.funding_txindex = M_FUNDING_INDEX;      //TODO: vout#0は2-of-2、vout#1はchangeにしている
    ucoin_util_sign_p2wpkh_native(&self->tx_funding, self->funding_local.funding_txindex,
                        self->p_est->p_fundin->amount, self->p_est->p_fundin->p_keys, self->p_est->p_fundin->b_native);
    ucoin_tx_txid(self->funding_local.funding_txid, &self->tx_funding);

    return true;
}


//    INPUT      OUTPUT             INPUT        OUTPUT
//    +---------+-----------+       +-----------+--------------+
//    |Alice    | To-Local  +------>| To-Local  | any...       |
//    |[P2WPKH] | [script]  |       | [script]  |              |
//    |         |-----------+       +-----------+--------------+
//    |         | To-Remote |
//    |         | [direct]  |         INPUT               OUTPUT               INPUT          OUTPUT
//    |.........|-----------+         +------------------+--------------+     +--------------+---------+
//    |Bob      | Offered   +-------->| Offered/Received | HTLC-Timeout +---->| HTLC-Timeout | any..   |
//    |[P2WPKH] | [script]  |         | [script]         | [script]     |     | [script]     |         |
//    |         |-----------+         +------------------+--------------+     +--------------+---------+
//    |         | Received  +-----+
//    |         | [script]  |     |   INPUT               OUTPUT               INPUT          OUTPUT
//    +---------+-----------+     |   +------------------+--------------+     +--------------+---------+
//                                +-->| Offered/Received | HTLC-Success +---->| HTLC-Success | any..   |
//                                    |    +             | [script]     |     | [script]     |         |
//                                    | preimage         |              |     +--------------+---------+
//                                    | [script]         |              |
//                                    +------------------+--------------+
//
// Offeredは、取りあえずHTLC-Timeout Transactionを公開する。
// ただ、locktimeが設定してあるため、すぐにはマイニングされない。
// 相手はそれまでの間にpreimageが入手できれば、locktime以内に「<remotesig> <payment_preimage>」で取り戻せる。
//
// Receivedは、HTLC-Success Transactionを公開する。
// こちらはlocktimeはないが、OP_CLTVがある。
// もし

/** 自分用To-Local
 *
 * self->commit_remote.signatureを相手からの署名として追加し、verifyを行う
 *
 * @param[in,out]       self
 * @param[in]           p_htlc_sigs         commitment_signedの署名
 * @param[in]           htlc_sigs_num       commitment_signedの署名数
 * @param[in]           to_self_delay
 * @param[in]           dust_limit_sat
 * @retval      true    成功
 */
static bool create_to_local(ln_self_t *self,
                    const uint8_t *p_htlc_sigs,
                    uint8_t htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat)
{
    DBG_PRINTF("BEGIN\n");

    bool ret;
    ucoin_buf_t buf_ws;
    ucoin_buf_t buf_sig;
    ln_feeinfo_t feeinfo;
    ln_tx_cmt_t lntx_commit;
    ucoin_tx_t tx_local;

    ucoin_tx_init(&tx_local);
    ucoin_buf_init(&buf_sig);
    ucoin_buf_init(&buf_ws);

    //To-Local
    ln_create_script_local(&buf_ws,
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                self->funding_local.scriptkeys[MSG_SCRIPTIDX_DELAYED].pub,
                to_self_delay);

    //HTLC
    //TODO: データの持たせ方は要検討
    ln_htlcinfo_t **pp_htlcinfo = (ln_htlcinfo_t **)M_MALLOC(sizeof(ln_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;
    uint64_t local_add = 0;
    uint64_t remote_add = 0;
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
            pp_htlcinfo[cnt]->preimage = NULL;
            pp_htlcinfo[cnt]->preimage_hash = self->cnl_add_htlc[idx].payment_sha256;
            DBG_PRINTF(" [%d][id=%" PRIx64 "](%p)\n", idx, self->cnl_add_htlc[idx].id, self);
            cnt++;
        }
    }
    DBG_PRINTF("-------\n");
    DBG_PRINTF("cnt=%d, htlc_num=%d\n", cnt, self->htlc_num);
    DBG_PRINTF("our_msat   %" PRIu64 " --> %" PRIu64 "\n", self->our_msat, self->our_msat + local_add);
    DBG_PRINTF("their_msat %" PRIu64 " --> %" PRIu64 "\n", self->their_msat, self->their_msat + remote_add);
    for (int lp = 0; lp < cnt; lp++) {
        DBG_PRINTF("  [%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type == LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    DBG_PRINTF("-------\n");

    if ((cnt > 0) && (p_htlc_sigs == NULL)) {
        DBG_PRINTF("fail: HTLCがあるのに署名は無いと考えている\n");
        return false;
    }

    //FEE
    feeinfo.feerate_per_kw = self->feerate_per_kw;
    feeinfo.dust_limit_satoshi = dust_limit_sat;
    ln_fee_calc(&feeinfo, (const ln_htlcinfo_t **)pp_htlcinfo, cnt);

    //scriptPubKey作成
    ln_create_htlcinfo((ln_htlcinfo_t **)pp_htlcinfo, cnt,
                            self->funding_local.scriptkeys[MSG_SCRIPTIDX_KEY].pub,
                            self->funding_local.scriptkeys[MSG_SCRIPTIDX_REVOCATION].pub,
                            self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_DELAYED]);

    //commitment transaction
    lntx_commit.fund.txid = self->funding_local.funding_txid;
    lntx_commit.fund.txid_index = self->funding_local.funding_txindex;
    lntx_commit.fund.satoshi = self->funding_sat;
    lntx_commit.fund.p_script = &self->redeem_fund;
    lntx_commit.fund.p_keys = &self->funding_local.keys[MSG_FUNDIDX_FUNDING];
    lntx_commit.local.satoshi = LN_MSAT2SATOSHI(self->our_msat + local_add);
    lntx_commit.local.p_script = &buf_ws;
    lntx_commit.remote.satoshi = LN_MSAT2SATOSHI(self->their_msat + remote_add);
    lntx_commit.remote.pubkey = self->funding_local.scriptkeys[MSG_SCRIPTIDX_KEY].pub;
    lntx_commit.obscured = self->obscured;
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;

    ret = ln_cmt_create(&tx_local, &buf_sig, &lntx_commit, M_IS_OPENSIDE(self));
    if (!ret) {
        DBG_PRINTF("fail: ln_cmt_create\n");
        return false;
    }

    if (cnt > 0) {
        //各HTLCの署名(commitment_signed用)
        DBG_PRINTF("HTLC-Timeout/Success sign\n");

        int htlc_num = 0;
        uint8_t txid[UCOIN_SZ_TXID];
        ucoin_buf_t buf_remotesig;
        ucoin_tx_t tx;
        ucoin_buf_t buf_sig;

        ucoin_buf_free(&buf_ws);
        ucoin_buf_init(&buf_remotesig);
        ucoin_buf_init(&buf_sig);
        ucoin_tx_init(&tx);
        ret = ucoin_tx_txid(txid, &tx_local);
        if (!ret) {
            DBG_PRINTF("fail: ucoin_tx_txid\n");
            return false;
        }
        ln_misc_sigexpand(&buf_remotesig, self->commit_remote.signature);

        for (int vout_idx = 0; vout_idx < tx_local.vout_cnt; vout_idx++) {
            uint8_t htlc_idx = tx_local.vout[vout_idx].opt;
            if (htlc_idx != VOUT_OPT_NONE) {
                uint64_t fee = (pp_htlcinfo[htlc_idx]->type == LN_HTLCTYPE_OFFERED) ? feeinfo.htlc_timeout : feeinfo.htlc_success;
                if (tx_local.vout[vout_idx].value >= feeinfo.dust_limit_satoshi + fee) {
                    //スクリプトはHTLC-TimeoutもSuccessも同じ(To-Localも)
                    ln_create_script_timeout(&buf_ws,
                                    self->funding_local.keys[MSG_FUNDIDX_REVOCATION].pub,
                                    self->funding_local.keys[MSG_FUNDIDX_DELAYED_PAYMENT].pub,
                                    pp_htlcinfo[htlc_idx]->expiry);

#ifdef UCOIN_USE_PRINTFUNC
                    DBG_PRINTF("HTLC script:\n");
                    ucoin_print_script(buf_ws.buf, buf_ws.len);
#endif  //UCOIN_USE_PRINTFUNC

                    //vout
                    ret = ucoin_sw_add_vout_p2wsh(&tx,
                                    tx_local.vout[vout_idx].value - fee, &buf_ws);
                    if (!ret) {
                        DBG_PRINTF("fail: ucoin_sw_add_vout_p2wsh\n");
                        break;
                    }

                    //ln_sign_p2wsh_success_timeout()用
                    tx.vout[tx.vout_cnt - 1].opt = pp_htlcinfo[htlc_idx]->type;

                    //vin
                    ucoin_tx_add_vin(&tx, txid, vout_idx);

#ifdef UCOIN_USE_PRINTFUNC
                    DBG_PRINTF("\n++++++++++++++ HTLC検証: vout[%d]\n", vout_idx);
                    ucoin_print_tx(&tx);
#endif  //UCOIN_USE_PRINTFUNC

                    //署名チェック
                    ln_misc_sigexpand(&buf_sig, p_htlc_sigs + htlc_num * LN_SZ_SIGNATURE);
                    ret = ln_verify_p2wsh_success_timeout(&tx,
                                tx_local.vout[vout_idx].value,
                                NULL,
                                self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING],
                                NULL,
                                &buf_sig,
                                pp_htlcinfo[htlc_idx]->expiry,
                                &pp_htlcinfo[htlc_idx]->script);
                    if (!ret) {
                        DBG_PRINTF("fail: ln_verify_p2wsh_success_timeout\n");
                        break;
                    }

                    //OKなら各HTLCに保持
                    memcpy(self->cnl_add_htlc[htlc_idx].signature, p_htlc_sigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);

#ifdef UCOIN_USE_PRINTFUNC
                    DBG_PRINTF("\n++++++++++++++ 自分のHTLC verify: vout[%d]\n", vout_idx);
                    ucoin_print_tx(&tx);
#endif  //UCOIN_USE_PRINTFUNC

                    ucoin_buf_free(&buf_sig);
                    ucoin_buf_free(&buf_ws);
                    ucoin_tx_free(&tx);
                    htlc_num++;

                    DBG_PRINTF("HTLC Timeout vout:%d - htlc:%d\n", vout_idx, htlc_idx);
                } else {
                    DBG_PRINTF("[%d] %" PRIu64 " > %" PRIu64 "\n", vout_idx, tx_local.vout[vout_idx].value, feeinfo.dust_limit_satoshi + fee);
                }
            } else {
                DBG_PRINTF("[%d]htlc_idx == VOUT_OPT_NONE\n", vout_idx);
            }
        }

        ucoin_buf_free(&buf_sig);
        ucoin_buf_free(&buf_ws);
        ucoin_tx_free(&tx);
        ucoin_buf_free(&buf_remotesig);

        if (htlc_num != htlc_sigs_num) {
            DBG_PRINTF("署名数不一致: %d, %d\n", htlc_num, htlc_sigs_num);
            ret = false;
        }
    }

    DBG_PRINTF("free\n");
    ucoin_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_htlcinfo_free(pp_htlcinfo[lp]);
        M_FREE(pp_htlcinfo[lp]);
    }
    M_FREE(pp_htlcinfo);

    if (ret) {
        DBG_PRINTF("sign\n");

        ucoin_buf_t buf_sig_from_remote;
        ucoin_buf_t script_code;
        uint8_t sighash[UCOIN_SZ_SIGHASH];

        ucoin_buf_init(&buf_sig_from_remote);
        ucoin_buf_init(&script_code);

        //署名追加
        ln_misc_sigexpand(&buf_sig_from_remote, self->commit_remote.signature);
        ucoin_util_sign_p2wsh_3_2of2(&tx_local, 0, self->key_fund_sort,
                                &buf_sig,
                                &buf_sig_from_remote,
                                &self->redeem_fund);
#ifdef UCOIN_USE_PRINTFUNC
        DBG_PRINTF("++++++++++++++ 自分のcommit txに署名: tx_local[%" PRIx64 "]\n", self->short_channel_id);
        ucoin_print_tx(&tx_local);
#endif  //UCOIN_USE_PRINTFUNC

        //
        // 署名verify
        //
        DBG_PRINTF("verify\n");
        ucoin_sw_scriptcode_p2wsh(&script_code, &self->redeem_fund);
        ucoin_sw_sighash(sighash, &tx_local, 0, self->funding_sat, &script_code);
        ret = ucoin_sw_verify_2of2(&tx_local, 0, sighash,
                    &self->tx_funding.vout[self->funding_local.funding_txindex].script);
        if (ret) {
            DBG_PRINTF("verify OK\n");
        } else {
            DBG_PRINTF("fail: ucoin_sw_verify_2of2\n");
        }

        ucoin_buf_free(&buf_sig_from_remote);
        ucoin_buf_free(&script_code);
    } else {
        DBG_PRINTF("fail\n");
    }
    ucoin_buf_free(&buf_sig);
    ucoin_tx_free(&tx_local);

    return ret;
}


/** 相手用To-Local
 *
 * 署名を、To-Localはself->commit_local.signatureに、HTLCはself->cnl_add_htlc[].signature 代入する
 *
 * @param[in,out]       self
 * @param[out]          pp_htlc_sigs        commitment_signed送信用署名
 * @param[out]          p_htlc_sigs_num     pp_htlc_sigsに格納した署名数
 * @param[in]           to_self_delay
 * @param[in]           dust_limit_sat
 */
static bool create_to_remote(ln_self_t *self,
                    uint8_t **pp_htlc_sigs,
                    uint8_t *p_htlc_sigs_num,
                    uint32_t to_self_delay,
                    uint64_t dust_limit_sat)
{
    DBG_PRINTF("BEGIN\n");

    ucoin_tx_t tx_remote;
    ucoin_buf_t buf_sig;
    ucoin_buf_t buf_ws;
    ln_feeinfo_t feeinfo;
    ln_tx_cmt_t lntx_commit;

    ucoin_tx_init(&tx_remote);
    ucoin_buf_init(&buf_sig);
    ucoin_buf_init(&buf_ws);

    //To-Local(Remote)
    ln_create_script_local(&buf_ws,
                self->funding_local.scriptkeys[MSG_SCRIPTIDX_REVOCATION].pub,
                self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                to_self_delay);

    //HTLC(Remote)
    //TODO: データの持たせ方は要検討
    ln_htlcinfo_t **pp_htlcinfo = (ln_htlcinfo_t **)M_MALLOC(sizeof(ln_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;
    uint64_t local_add = 0;
    uint64_t remote_add = 0;
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
            pp_htlcinfo[cnt]->preimage = NULL;
            pp_htlcinfo[cnt]->preimage_hash = self->cnl_add_htlc[idx].payment_sha256;
            DBG_PRINTF(" [%d][id=%" PRIx64 "](%p)\n", idx, self->cnl_add_htlc[idx].id, self);
            cnt++;
        }
    }
    DBG_PRINTF("-------\n");
    DBG_PRINTF("cnt=%d, htlc_num=%d\n", cnt, self->htlc_num);
    DBG_PRINTF("(remote)our_msat   %" PRIu64 " --> %" PRIu64 "\n", self->their_msat, self->their_msat + remote_add);
    DBG_PRINTF("(remote)their_msat %" PRIu64 " --> %" PRIu64 "\n", self->our_msat, self->our_msat + local_add);
    for (int lp = 0; lp < cnt; lp++) {
        DBG_PRINTF("  have HTLC[%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type != LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    DBG_PRINTF("-------\n");

    //FEE(Remote)
    feeinfo.feerate_per_kw = self->feerate_per_kw;
    feeinfo.dust_limit_satoshi = dust_limit_sat;
    ln_fee_calc(&feeinfo, (const ln_htlcinfo_t **)pp_htlcinfo, cnt);

    //scriptPubKey作成(Remote)
    ln_create_htlcinfo((ln_htlcinfo_t **)pp_htlcinfo, cnt,
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_KEY],
                        self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                        self->funding_local.scriptkeys[MSG_SCRIPTIDX_DELAYED].pub);

    //commitment transaction(Remote)
    lntx_commit.fund.txid = self->funding_local.funding_txid;
    lntx_commit.fund.txid_index = self->funding_local.funding_txindex;
    lntx_commit.fund.satoshi = self->funding_sat;
    lntx_commit.fund.p_script = &self->redeem_fund;
    lntx_commit.fund.p_keys = &self->funding_local.keys[MSG_FUNDIDX_FUNDING];
    lntx_commit.local.satoshi = LN_MSAT2SATOSHI(self->their_msat + remote_add);
    lntx_commit.local.p_script = &buf_ws;
    lntx_commit.remote.satoshi = LN_MSAT2SATOSHI(self->our_msat + local_add);
    lntx_commit.remote.pubkey = self->funding_remote.scriptpubkeys[MSG_SCRIPTIDX_KEY];
    lntx_commit.obscured = self->obscured;
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;

    bool ret = ln_cmt_create(&tx_remote, &buf_sig, &lntx_commit, !M_IS_OPENSIDE(self));
    if (!ret) {
        DBG_PRINTF("fail: ln_cmt_create(Remote)\n");
    }
#ifdef UCOIN_USE_PRINTFUNC
    DBG_PRINTF("++++++++++++++ 相手のcommit txに署名: tx_remote[%" PRIx64 "]\n", self->short_channel_id);
    ucoin_print_tx(&tx_remote);
#endif  //UCOIN_USE_PRINTFUNC

    if ((cnt > 0) && (pp_htlc_sigs != NULL)) {
        //各HTLCの署名(commitment_signed用)(Remote)
        DBG_PRINTF("HTLC-Timeout/Success sign(Remote): %d\n", cnt);

        *pp_htlc_sigs = (uint8_t *)M_MALLOC(LN_SZ_SIGNATURE * cnt);

        uint8_t txid[UCOIN_SZ_TXID];
        ucoin_buf_t buf_remotesig;
        ucoin_tx_t tx;
        ucoin_buf_t buf_sig;

        ucoin_buf_free(&buf_ws);
        ucoin_buf_init(&buf_remotesig);
        ucoin_buf_init(&buf_sig);
        ucoin_tx_init(&tx);
        ret = ucoin_tx_txid(txid, &tx_remote);
        if (!ret) {
            DBG_PRINTF("fail: ucoin_tx_txid\n");
            return false;
        }
        ln_misc_sigexpand(&buf_remotesig, self->commit_remote.signature);

        int htlc_num = 0;
        for (int vout_idx = 0; vout_idx < tx_remote.vout_cnt; vout_idx++) {
            //各HTLCのHTLC Timeout/Success Transactionを作って署名するために、
            //BIP69ソート後のtx_remote.voutからpp_htlcinfo[]のindexを取得する
            uint8_t htlc_idx = tx_remote.vout[vout_idx].opt;
            DBG_PRINTF("[%d]htlc_idx=%d\n", vout_idx, htlc_idx);
            if (htlc_idx != VOUT_OPT_NONE) {
                uint64_t fee = (pp_htlcinfo[htlc_idx]->type == LN_HTLCTYPE_OFFERED) ? feeinfo.htlc_timeout : feeinfo.htlc_success;
                if (tx_remote.vout[vout_idx].value >= feeinfo.dust_limit_satoshi + fee) {
                    //スクリプトはHTLC-TimeoutもSuccessも同じ(To-Localも)
                    ln_create_script_timeout(&buf_ws,
                                    self->funding_remote.pubkeys[MSG_FUNDIDX_REVOCATION],
                                    self->funding_remote.pubkeys[MSG_FUNDIDX_DELAYED_PAYMENT],
                                    pp_htlcinfo[htlc_idx]->expiry);
#ifdef UCOIN_USE_PRINTFUNC
                    DBG_PRINTF("HTLC script:\n");
                    ucoin_print_script(buf_ws.buf, buf_ws.len);
#endif  //UCOIN_USE_PRINTFUNC

                    //vout
                    ret = ucoin_sw_add_vout_p2wsh(&tx,
                                    tx_remote.vout[vout_idx].value - fee, &buf_ws);
                    if (!ret) {
                        DBG_PRINTF("fail: ucoin_sw_add_vout_p2wsh\n");
                        break;
                    }

                    //ln_sign_p2wsh_success_timeout()用
                    tx.vout[tx.vout_cnt - 1].opt = pp_htlcinfo[htlc_idx]->type;

                    //vin
                    ucoin_tx_add_vin(&tx, txid, vout_idx);

                    //署名
                    ret = ln_sign_p2wsh_success_timeout(&tx, &buf_sig,
                                tx_remote.vout[vout_idx].value,
                                &self->funding_local.keys[MSG_FUNDIDX_FUNDING],
                                &buf_remotesig,
                                NULL,
                                pp_htlcinfo[htlc_idx]->expiry,
                                &pp_htlcinfo[htlc_idx]->script);
                    if (!ret) {
                        DBG_PRINTF("fail: ln_sign_p2wsh_success_timeout\n");
                        break;
                    }
                    //RAW変換
                    ln_misc_sigtrim(*pp_htlc_sigs + LN_SZ_SIGNATURE * htlc_num, buf_sig.buf);

#ifdef UCOIN_USE_PRINTFUNC
                    DBG_PRINTF("\n++++++++++++++ 相手のHTLCに署名: vout[%d]\n", vout_idx);
                    ucoin_print_tx(&tx);
#endif  //UCOIN_USE_PRINTFUNC
                    DBG_PRINTF("signature: ");
                    DUMPBIN(buf_sig.buf, buf_sig.len);

                    ucoin_buf_free(&buf_sig);
                    ucoin_buf_free(&buf_ws);
                    ucoin_tx_free(&tx);

                    htlc_num++;
                } else {
                    DBG_PRINTF("cut HTLC[%d] %" PRIu64 " > %" PRIu64 "\n", vout_idx, tx_remote.vout[vout_idx].value, feeinfo.dust_limit_satoshi + fee);
                }
            } else {
                DBG_PRINTF("[%d]htlc_idx == VOUT_OPT_NONE\n", vout_idx);
            }
        }
        ucoin_buf_free(&buf_sig);
        ucoin_buf_free(&buf_ws);
        ucoin_tx_free(&tx);
        ucoin_buf_free(&buf_remotesig);

        *p_htlc_sigs_num = htlc_num;
    }

    //送信用署名
    ln_misc_sigtrim(self->commit_local.signature, buf_sig.buf);
    ucoin_buf_free(&buf_sig);

    DBG_PRINTF("free\n");
    ucoin_tx_free(&tx_remote);
    ucoin_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_htlcinfo_free(pp_htlcinfo[lp]);
        M_FREE(pp_htlcinfo[lp]);
    }
    M_FREE(pp_htlcinfo);

    return ret;
}


/** closing tx作成
 *
 * @note
 *      - INPUT: 2-of-2(順番はself->key_fund_sort)
 *          - 自分：self->commit_local.signature
 *          - 相手：self->commit_remote.signature
 *      - OUTPUT:
 *          - 自分：self->shutdown_scriptpk_local, self->our_msat / 1000
 *          - 相手：self->shutdown_scriptpk_remote, self->their_msat / 1000
 *      - BIP69でソートする
 */
static bool create_closing_tx(ln_self_t *self, ucoin_tx_t *pTx, bool bVerify)
{
    if ((self->shutdown_scriptpk_local.len == 0) || (self->shutdown_scriptpk_remote.len == 0)) {
        DBG_PRINTF("not mutual output set\n");
        return false;
    }

    DBG_PRINTF("BEGIN\n");

    bool ret;
    uint64_t fee_local;
    uint64_t fee_remote;
    ucoin_vout_t *vout;
    ucoin_buf_t buf_sig;

    ucoin_buf_init(&buf_sig);
    ucoin_tx_free(pTx);
    ucoin_tx_init(pTx);
    pTx->version = 1;       //BOLT#3

    //BOLT#3: feeはfundedの方から引く
    if (M_IS_OPENSIDE(self)) {
        fee_local = self->cnl_closing_signed.fee_sat;
        fee_remote = 0;
    } else {
        fee_local = 0;
        fee_remote = self->cnl_closing_signed.fee_sat;
    }

    //vout
    //vout#0 - local
    bool vout_local = (LN_MSAT2SATOSHI(self->our_msat) > fee_local + self->commit_local.dust_limit_sat);
    bool vout_remote = (LN_MSAT2SATOSHI(self->their_msat) > fee_remote + self->commit_local.dust_limit_sat);

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
    ucoin_tx_add_vin(pTx, self->funding_local.funding_txid, self->funding_local.funding_txindex);

    //BIP69
    ucoin_util_sort_bip69(pTx);

    //署名
    uint8_t sighash[UCOIN_SZ_SIGHASH];
    ucoin_util_sign_p2wsh_1(sighash, pTx, 0, self->funding_sat, &self->redeem_fund);
    ret = ucoin_util_sign_p2wsh_2(&buf_sig, sighash, &self->funding_local.keys[MSG_FUNDIDX_FUNDING]);
    if (!ret) {
        DBG_PRINTF("fail: ucoin_util_sign_p2wsh_2\n");
        ucoin_tx_free(pTx);
        return false;
    }
    //送信用署名
    ln_misc_sigtrim(self->commit_local.signature, buf_sig.buf);

    //署名追加
    if (ret && bVerify) {
        ucoin_buf_t buf_sig_from_remote;

        ucoin_buf_init(&buf_sig_from_remote);
        ln_misc_sigexpand(&buf_sig_from_remote, self->commit_remote.signature);
        ucoin_util_sign_p2wsh_3_2of2(pTx, 0, self->key_fund_sort,
                                &buf_sig,
                                &buf_sig_from_remote,
                                &self->redeem_fund);
        ucoin_buf_free(&buf_sig_from_remote);

        //
        // 署名verify
        //
        ret = ucoin_sw_verify_2of2(pTx, 0, sighash,
                        &self->tx_funding.vout[self->funding_local.funding_txindex].script);
    }
    ucoin_buf_free(&buf_sig);

#ifdef UCOIN_USE_PRINTFUNC
    DBG_PRINTF("+++++++++++++ closing_tx[%" PRIx64 "]\n", self->short_channel_id);
    ucoin_print_tx(pTx);
#endif  //UCOIN_USE_PRINTFUNC

    DBG_PRINTF("END ret=%d\n", ret);
    return ret;
}


/** チャネル用鍵生成
 *
 * @param[in,out]   self        チャネル情報
 * @retval  true    成功
 * @note
 *      - open_channel/accept_channelの送信前に使用する想定
 */
static bool create_channelkeys(ln_self_t *self)
{
    //鍵生成
    //  open_channel/accept_channelの鍵は保持しなくてよいため、ln_derkeyは使わない
    for (int lp = MSG_FUNDIDX_REVOCATION; lp < LN_FUNDIDX_MAX; lp++) {
        do {
            ucoin_util_random(self->funding_local.keys[lp].priv, UCOIN_SZ_PRIVKEY);
        } while (!ucoin_keys_chkpriv(self->funding_local.keys[lp].priv));
        ucoin_keys_priv2pub(self->funding_local.keys[lp].pub, self->funding_local.keys[lp].priv);
    }

    return true;
}


// channel_announcement用データ(自分の枠)
//  short_channel_id決定後に呼び出す
static bool create_local_channel_announcement(ln_self_t *self)
{
    ucoin_buf_free(&self->cnl_anno);

    ln_cnl_announce_create_t anno;

    anno.short_channel_id = self->short_channel_id;
    anno.p_my_node = &self->p_node->keys;
    anno.p_peer_node_pub = self->peer_node.node_id;
    anno.p_my_funding = &self->funding_local.keys[MSG_FUNDIDX_FUNDING];
    anno.p_peer_funding_pub = self->funding_remote.pubkeys[MSG_FUNDIDX_FUNDING];
    anno.sort = self->peer_node.sort;
    bool ret = ln_msg_cnl_announce_create(&self->cnl_anno, &anno);

    return ret;
}


/** per_commitment_secret更新
 *
 * @param[in,out]   self        チャネル情報
 * @note
 *      - indexを進める
 */
static void update_percommit_secret(ln_self_t *self)
{
    ln_derkey_create_secret(self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].priv, self->storage_seed, self->storage_index);
    ucoin_keys_priv2pub(self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].pub, self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].priv);
    self->storage_index--;

    DBG_PRINTF("self->storage_index = %" PRIx64 "\n", self->storage_index);
    ln_print_keys(PRINTOUT, &self->funding_local, &self->funding_remote);
}


/** 1つ前のper_commit_secret取得
 *
 * @param[in,out]   self            チャネル情報
 * @param[out]      p_prev_secret   1つ前のper_commit_secret
 */
static void get_prev_percommit_secret(ln_self_t *self, uint8_t *p_prev_secret)
{
    ln_derkey_create_secret(p_prev_secret, self->storage_seed, self->storage_index + 1);

    DBG_PRINTF("prev self->storage_index = %" PRIx64 "\n", self->storage_index + 1);
    DUMPBIN(p_prev_secret, UCOIN_SZ_PRIVKEY);
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
    DBG_PRINTF("I=%" PRIx64 "\n", self->peer_storage_index);
    DUMPBIN(p_prev_secret, UCOIN_SZ_PRIVKEY);
    bool ret = ln_derkey_storage_insert_secret(&self->peer_storage, p_prev_secret, self->peer_storage_index);
    if (ret) {
        self->peer_storage_index--;
        DBG_PRINTF("I=%" PRIx64 "\n", self->peer_storage_index);
    }
    return ret;
}


static bool proc_established(ln_self_t *self)
{
    bool ret = true;

    if (self->flck_flag == (M_FLCK_FLAG_SEND | M_FLCK_FLAG_RECV)) {
        //funding_locked送受信済み
        DBG_PRINTF("funding_locked sent and recv\n");

        //channel_reestablish済みと同じ状態にしておく
        self->init_flag |= INIT_FLAG_REEST_SEND | INIT_FLAG_REEST_RECV;

        //チャネルDB保存
        ret = ln_db_save_channel(self);
        if (ret) {
            //Establish完了通知
            DBG_PRINTF("Establish完了通知");
            ln_cb_funding_t funding;

            funding.p_tx_funding = &self->tx_funding;
            funding.p_txid = self->funding_local.funding_txid;
            funding.min_depth = 0;
            funding.b_send = false;
            funding.annosigs = (self->p_est) ? (self->p_est->cnl_open.channel_flags) : false;
            (*self->p_callback)(self, LN_CB_ESTABLISHED, &funding);

            //Normal Operation可能
            self->p_est = NULL;

            DBG_PRINTF("Normal Operation可能\n");
            self->flck_flag |= M_FLCK_FLAG_END;
        }
    }

    return ret;
}


static void proc_announce_sigsed(ln_self_t *self)
{
    if (self->anno_flag == (M_ANNO_FLAG_SEND | M_ANNO_FLAG_RECV)) {
        //announcement_signatures送受信済み
        DBG_PRINTF("announcement_signatures sent and recv\n");

        ln_cb_anno_sigs_t anno;

        anno.sort = self->peer_node.sort;
        (*self->p_callback)(self, LN_CB_ANNO_SIGSED, &anno);

        self->anno_flag |= M_ANNO_FLAG_END;
    }
}


static bool chk_peer_node(ln_self_t *self)
{
    return self->peer_node.node_id[0];      //先頭が0の場合は不正
}


//node_id取得
static bool get_nodeid(uint8_t *pNodeId, uint64_t short_channel_id, uint8_t Dir)
{
    bool ret;

    pNodeId[0] = 0x00;

    ucoin_buf_t buf_cnl_anno;
    ucoin_buf_init(&buf_cnl_anno);
    ret = ln_db_load_anno_channel(&buf_cnl_anno, short_channel_id);
    if (ret) {
        ln_cnl_announce_read_t ann;

        ret = ln_msg_cnl_announce_read(&ann, buf_cnl_anno.buf, buf_cnl_anno.len);
        DBG_PRINTF("ret=%d\n", ret);
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
        DBG_PRINTF("ret=%d\n", ret);
    }
    ucoin_buf_free(&buf_cnl_anno);

    return ret;
}


//HTLC削除
static void clear_htlc(ln_self_t *self, ln_update_add_htlc_t *p_add, uint8_t chg_flag)
{
    DBG_PRINTF("HTLC remove prev: htlc_num=%d\n", self->htlc_num);
    assert(self->htlc_num > 0);

    ucoin_buf_free(&p_add->shared_secret);
    memset(p_add, 0, sizeof(ln_update_add_htlc_t));
    self->htlc_num--;
    DBG_PRINTF("   --> htlc_num=%d\n", self->htlc_num);
}
