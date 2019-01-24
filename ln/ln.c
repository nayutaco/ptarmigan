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

#include "ln_setupctl.h"
#include "ln_establish.h"
#include "ln_close.h"
#include "ln_normalope.h"
#include "ln_anno.h"

#include "ln_node.h"
#include "ln_noise.h"
#include "ln_onion.h"
#include "ln_script.h"
#include "ln_comtx.h"
#include "ln_derkey.h"
#include "ln_signer.h"
#include "ln_local.h"
#include "ln_msg.h"

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


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef bool (*pRecvFunc_t)(ln_self_t *self,const uint8_t *pData, uint16_t Len);


/**************************************************************************
 * prototypes
 **************************************************************************/

static void channel_clear(ln_self_t *self);
static bool create_basetx(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pScriptPk, uint32_t LockTime, const uint8_t *pTxid, int Index, bool bRevoked);
static void close_alloc(ln_close_force_t *pClose, int Num);
static uint64_t calc_commit_num(const ln_self_t *self, const btc_tx_t *pTx);


/**************************************************************************
 * const variables
 **************************************************************************/

static const struct {
    uint16_t        type;
    pRecvFunc_t     func;
} RECV_FUNC[] = {
    { MSGTYPE_INIT,                         ln_init_recv },
    { MSGTYPE_ERROR,                        ln_error_recv },
    { MSGTYPE_PING,                         ln_ping_recv },
    { MSGTYPE_PONG,                         ln_pong_recv },
    { MSGTYPE_OPEN_CHANNEL,                 ln_open_channel_recv },
    { MSGTYPE_ACCEPT_CHANNEL,               ln_accept_channel_recv },
    { MSGTYPE_FUNDING_CREATED,              ln_funding_created_recv },
    { MSGTYPE_FUNDING_SIGNED,               ln_funding_signed_recv },
    { MSGTYPE_FUNDING_LOCKED,               ln_funding_locked_recv },
    { MSGTYPE_SHUTDOWN,                     ln_shutdown_recv },
    { MSGTYPE_CLOSING_SIGNED,               ln_closing_signed_recv },
    { MSGTYPE_UPDATE_ADD_HTLC,              ln_update_add_htlc_recv },
    { MSGTYPE_UPDATE_FULFILL_HTLC,          ln_update_fulfill_htlc_recv },
    { MSGTYPE_UPDATE_FAIL_HTLC,             ln_update_fail_htlc_recv },
    { MSGTYPE_COMMITMENT_SIGNED,            ln_commitment_signed_recv },
    { MSGTYPE_REVOKE_AND_ACK,               ln_revoke_and_ack_recv },
    { MSGTYPE_UPDATE_FEE,                   ln_update_fee_recv },
    { MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC,   ln_update_fail_malformed_htlc_recv },
    { MSGTYPE_CHANNEL_REESTABLISH,          ln_channel_reestablish_recv },
    { MSGTYPE_CHANNEL_ANNOUNCEMENT,         ln_channel_announcement_recv },
    { MSGTYPE_NODE_ANNOUNCEMENT,            ln_node_announcement_recv },
    { MSGTYPE_CHANNEL_UPDATE,               ln_channel_update_recv },
    { MSGTYPE_ANNOUNCEMENT_SIGNATURES,      ln_announcement_signatures_recv }
};


/**************************************************************************
 * static variables
 **************************************************************************/

//< 32: chain-hash
uint8_t HIDDEN gGenesisChainHash[BTC_SZ_HASH256];

//blockhash at node creation
//      usage: search blockchain limit
uint8_t HIDDEN gCreationBlockHash[BTC_SZ_HASH256];

static unsigned long mDebug;


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_init(ln_self_t *self, const uint8_t *pSeed, const ln_anno_prm_t *pAnnoPrm, ln_callback_t pFunc)
{
    LOGD("BEGIN : pSeed=%p\n", pSeed);

    ln_noise_t noise_bak;
    void *ptr_bak;

    //noise protocol handshake済みの場合があるため、初期値かどうかに関係なく残す
    memcpy(&noise_bak, &self->noise, sizeof(noise_bak));
    ptr_bak = self->p_param;
    memset(self, 0, sizeof(ln_self_t));
    memcpy(&self->noise, &noise_bak, sizeof(noise_bak));
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


bool ln_establish_alloc(ln_self_t *self, const ln_establish_prm_t *pEstPrm)
{
    LOGD("BEGIN\n");

    if (pEstPrm != NULL) {
        self->establish.p_fundin = NULL;       //open_channel送信側が設定する

        memcpy(&self->establish.estprm, pEstPrm, sizeof(ln_establish_prm_t));
        LOGD("dust_limit_sat= %" PRIu64 "\n", self->establish.estprm.dust_limit_sat);
        LOGD("max_htlc_value_in_flight_msat= %" PRIu64 "\n", self->establish.estprm.max_htlc_value_in_flight_msat);
        LOGD("channel_reserve_sat= %" PRIu64 "\n", self->establish.estprm.channel_reserve_sat);
        LOGD("htlc_minimum_msat= %" PRIu64 "\n", self->establish.estprm.htlc_minimum_msat);
        LOGD("to_self_delay= %" PRIu16 "\n", self->establish.estprm.to_self_delay);
        LOGD("max_accepted_htlcs= %" PRIu16 "\n", self->establish.estprm.max_accepted_htlcs);
        LOGD("min_depth= %" PRIu16 "\n", self->establish.estprm.min_depth);
    }

    LOGD("END\n");

    return true;
}


void ln_establish_free(ln_self_t *self)
{
    if (self->establish.p_fundin != NULL) {
        LOGD("self->establish.p_fundin=%p\n", self->establish.p_fundin);
        UTL_DBG_FREE(self->establish.p_fundin);
        LOGD("free\n");
    }
    self->fund_flag = (ln_fundflag_t)((self->fund_flag & ~LN_FUNDFLAG_FUNDING) | LN_FUNDFLAG_OPENED);
}


uint64_t HIDDEN ln_short_channel_id_calc(uint32_t Height, uint32_t BIndex, uint32_t VIndex)
{
    //[0:2]block height
    //[3:5]index of tx
    //[6:7]index of vout
    uint64_t id = ((uint64_t)(Height & 0xffffff) << 40) | (uint64_t)(BIndex & 0xffffff) << 16 | (uint64_t)(VIndex & 0xffff);
    //LOGD("short_channel_id= %016" PRIx64 "(height=%u, bindex=%u, vindex=%u)\n", id, Height, BIndex, VIndex);
    return id;
}


void ln_short_channel_id_set_param(ln_self_t *self, uint32_t Height, uint32_t Index)
{
    self->short_channel_id = ln_short_channel_id_calc(Height, Index, ln_funding_txindex(self));
    self->status = LN_STATUS_NORMAL;
    M_DB_SELF_SAVE(self);
}


void ln_short_channel_id_get_param(uint32_t *pHeight, uint32_t *pBIndex, uint32_t *pVIndex, uint64_t ShortChannelId)
{
    *pHeight = ShortChannelId >> 40;
    *pBIndex = (ShortChannelId >> 16) & 0xffffff;
    *pVIndex = ShortChannelId & 0xffff;
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
    if (!ln_noise_handshake_init(&self->noise, pNodeId)) return false;
    if (pNodeId != NULL) {
        if (!ln_noise_handshake_start(&self->noise, pBuf, pNodeId)) return false;
    }
    return true;
}


bool ln_handshake_recv(ln_self_t *self, bool *pCont, utl_buf_t *pBuf)
{
    if (!ln_noise_handshake_recv(&self->noise, pBuf)) return false;
    //continue?
    *pCont = ln_noise_handshake_state(&self->noise);
    return true;
}


void ln_handshake_free(ln_self_t *self)
{
    ln_noise_handshake_free(&self->noise);
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


bool ln_funding_locked_check_need(const ln_self_t *self)
{
    return (self->short_channel_id != 0) &&
        (
            ((self->commit_local.commit_num == 0) && (self->commit_remote.commit_num == 0)) ||
            ((self->reest_commit_num == 1) && (self->reest_revoke_num == 0))
        );
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
    memcpy(&dummy->establish, est, sizeof((est));
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
    ln_term(dummy);

    UTL_DBG_FREE(dummy);
    return fee;
}
#endif


void HIDDEN ln_channel_id_calc(uint8_t *pChannelId, const uint8_t *pTxid, uint16_t Index)
{
    //combining the funding-txid and the funding-output-index using big-endian exclusive-OR
    memcpy(pChannelId, pTxid, LN_SZ_CHANNEL_ID - sizeof(uint16_t));
    pChannelId[LN_SZ_CHANNEL_ID - 2] = pTxid[LN_SZ_CHANNEL_ID - 2] ^ (Index >> 8);
    pChannelId[LN_SZ_CHANNEL_ID - 1] = pTxid[LN_SZ_CHANNEL_ID - 1] ^ (Index & 0xff);
}


bool ln_channel_update_get_peer(const ln_self_t *self, utl_buf_t *pCnlUpd, ln_msg_channel_update_t *pMsg)
{
    bool ret;

    btc_script_pubkey_order_t sort = ln_node_id_sort(self, NULL);
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
             ( utl_buf_equal(&pCloseTx->vout[0].script, ln_shutdown_scriptpk_local(self)) ||
               utl_buf_equal(&pCloseTx->vout[0].script, ln_shutdown_scriptpk_remote(self)) ) ) {
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

        ln_channel_update_disable(self);
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
    ln_update_scriptkeys(&self->funding_local, &self->funding_remote);

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
    ln_update_scriptkeys(&self->funding_local, &self->funding_remote);
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
    ln_update_scriptkeys(&self->funding_local, &self->funding_remote);
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
    ln_update_scriptkeys(&self->funding_local, &self->funding_remote);

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
    ln_update_scriptkeys(&self->funding_local, &self->funding_remote);
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
        } else if (utl_buf_equal(&pRevokedTx->vout[lp].script, &self->p_revoked_vout[LN_RCLOSE_IDX_TOLOCAL])) {
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


void ln_last_connected_addr_set(ln_self_t *self, const ln_node_addr_t *pAddr)
{
    memcpy(&self->last_connected_addr, pAddr, sizeof(ln_node_addr_t));
    LOGD("addr[%d]: %d.%d.%d.%d:%d\n", pAddr->type,
            pAddr->addr[0], pAddr->addr[1],
            pAddr->addr[2], pAddr->addr[3],
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


const ln_node_addr_t *ln_last_connected_addr(const ln_self_t *self)
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


void ln_callback(ln_self_t *self, ln_cb_t Req, void *pParam)
{
    if (self->p_callback == NULL) {
        LOGE("fail: not callback(%d)\n", (int)Req);
        return;
    }

    (*self->p_callback)(self, Req, pParam);
}


/**
 *
 * @param[in]   self
 * @param[in]   pNodeId
 * @retval      BTC_SCRYPT_PUBKEY_ORDER_ASC     自ノードが先
 * @retval      BTC_SCRYPT_PUBKEY_ORDER_OTHER   相手ノードが先
 */
btc_script_pubkey_order_t ln_node_id_sort(const ln_self_t *self, const uint8_t *pNodeId)
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
uint8_t ln_sort_to_dir(btc_script_pubkey_order_t Sort)
{
    return (uint8_t)Sort;
}


//  localkey, remotekey, local_delayedkey, remote_delayedkey
//      pubkey = basepoint + SHA256(per_commitment_point || basepoint)*G
//
//  revocationkey
//      revocationkey = revocation_basepoint * SHA256(revocation_basepoint || per_commitment_point) + per_commitment_point*SHA256(per_commitment_point || revocation_basepoint)
//
void HIDDEN ln_update_scriptkeys(ln_funding_local_data_t *pLocal, ln_funding_remote_data_t *pRemote)
{
    //
    //local
    //

    //remotekey = local per_commitment_point & remote payment
    //LOGD("local: remotekey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY],
                pRemote->pubkeys[MSG_FUNDIDX_PAYMENT], pLocal->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //delayedkey = local per_commitment_point & local delayed_payment
    //LOGD("local: delayedkey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                pLocal->pubkeys[MSG_FUNDIDX_DELAYED], pLocal->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //revocationkey = remote per_commitment_point & local revocation_basepoint
    //LOGD("local: revocationkey\n");
    ln_derkey_revocationkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                pRemote->pubkeys[MSG_FUNDIDX_REVOCATION], pLocal->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //local_htlckey = local per_commitment_point & local htlc_basepoint
    //LOGD("local: local_htlckey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                pLocal->pubkeys[MSG_FUNDIDX_HTLC], pLocal->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //remote_htlckey = local per_commitment_point & remote htlc_basepoint
    //LOGD("local: remote_htlckey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                pRemote->pubkeys[MSG_FUNDIDX_HTLC], pLocal->pubkeys[MSG_FUNDIDX_PER_COMMIT]);


    //
    //remote
    //

    //remotekey = remote per_commitment_point & local payment
    //LOGD("remote: remotekey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY],
                pLocal->pubkeys[MSG_FUNDIDX_PAYMENT], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //delayedkey = remote per_commitment_point & remote delayed_payment
    //LOGD("remote: delayedkey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                pRemote->pubkeys[MSG_FUNDIDX_DELAYED], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //revocationkey = local per_commitment_point & remote revocation_basepoint
    //LOGD("remote: revocationkey\n");
    ln_derkey_revocationkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                pLocal->pubkeys[MSG_FUNDIDX_REVOCATION], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //local_htlckey = remote per_commitment_point & remote htlc_basepoint
    //LOGD("remote: local_htlckey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                pRemote->pubkeys[MSG_FUNDIDX_HTLC], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //remote_htlckey = remote per_commitment_point & local htlc_basepoint
    //LOGD("remote: remote_htlckey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                pLocal->pubkeys[MSG_FUNDIDX_HTLC], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);
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

    ln_handshake_free(self);

    ln_establish_free(self);
}


/********************************************************************
 * メッセージ受信
 ********************************************************************/



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


bool ln_check_channel_id(const uint8_t *recv_id, const uint8_t *mine_id)
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


/** commitment_number debug output
 *
 */
void ln_dbg_commitnum(const ln_self_t *self)
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
