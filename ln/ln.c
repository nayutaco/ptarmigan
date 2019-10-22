/*
 *  Copyright (C) 2017 Ptarmigan Project
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
#include "ln_onion.h"
#include "ln_script.h"
#include "ln_commit_tx.h"
#include "ln_commit_tx_util.h"
#include "ln_derkey.h"
#include "ln_signer.h"
#include "ln_local.h"
#include "ln_msg.h"
#include "ln_htlc_tx.h"
#include "ln_wallet.h"
#include "ln.h"

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

typedef bool (*pRecvFunc_t)(ln_channel_t *pChannel,const uint8_t *pData, uint16_t Len);


/**************************************************************************
 * prototypes
 **************************************************************************/

static void channel_clear(ln_channel_t *pChannel);
static void close_alloc(ln_close_force_t *pClose, int Num);
static uint64_t calc_commit_num(const ln_commit_info_t *pCommitInfo, const btc_tx_t *pTx);


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
    { MSGTYPE_ANNOUNCEMENT_SIGNATURES,      ln_announcement_signatures_recv },
    { MSGTYPE_QUERY_SHORT_CHANNEL_IDS,      ln_query_short_channel_ids_recv },
    { MSGTYPE_REPLY_SHORT_CHANNEL_IDS_END,  ln_reply_short_channel_ids_end_recv },
    { MSGTYPE_QUERY_CHANNEL_RANGE,          ln_query_channel_range_recv },
    { MSGTYPE_REPLY_CHANNEL_RANGE,          ln_reply_channel_range_recv },
    { MSGTYPE_GOSSIP_TIMESTAMP_FILTER,      ln_gossip_timestamp_filter_recv }
};


/**************************************************************************
 * static variables
 **************************************************************************/

//< 32: chain-hash
static uint8_t mGenesisChainHash[BTC_SZ_HASH256];

//blockhash at node creation
//  usage: search blockchain limit
static uint8_t mCreationBlockHash[BTC_SZ_HASH256];

// feerate_per_kw limit percent
static uint16_t mFeerateMin;
static uint16_t mFeerateMax;

static unsigned long mDebug;


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_init(
    ln_channel_t *pChannel, const ln_anno_param_t *pAnnoParam,
    const uint8_t *pPeerNodeId, ln_callback_t pFunc, void *pParam) {
    memset(pChannel, 0x00, sizeof(ln_channel_t));

    utl_buf_init(&pChannel->shutdown_scriptpk_local);
    utl_buf_init(&pChannel->shutdown_scriptpk_remote);
    utl_buf_init(&pChannel->funding_info.wit_script);
    utl_buf_init(&pChannel->cnl_anno);
    utl_buf_init(&pChannel->revoked_sec);
    pChannel->p_revoked_vout = NULL;
    pChannel->p_revoked_wit = NULL;
    pChannel->p_revoked_type = NULL;

    btc_tx_init(&pChannel->funding_info.tx_data);
    btc_tx_init(&pChannel->tx_closing);

    ln_update_info_init(&pChannel->update_info);

    pChannel->lfeature_remote = 0;

    if (pAnnoParam) {
        memcpy(&pChannel->anno_param, pAnnoParam, sizeof(ln_anno_param_t));
        LOGD("cltv_expiry_delta=%" PRIu16 "\n", pChannel->anno_param.cltv_expiry_delta);
        LOGD("htlc_minimum_msat=%" PRIu64 "\n", pChannel->anno_param.htlc_minimum_msat);
        LOGD("fee_base_msat=%" PRIu32 "\n", pChannel->anno_param.fee_base_msat);
        LOGD("fee_prop_millionths=%" PRIu32 "\n", pChannel->anno_param.fee_prop_millionths);
    }

    if (pPeerNodeId) {
        memcpy(pChannel->peer_node_id, pPeerNodeId, BTC_SZ_PUBKEY);
    }

    pChannel->p_callback = pFunc;
    pChannel->p_param = pParam;

    //seed
    ln_derkey_init(&pChannel->keys_local, &pChannel->keys_remote);

    pChannel->commit_info_local.commit_num = 0;
    pChannel->commit_info_remote.commit_num = 0;

    pChannel->commit_info_local.p_funding_info =
        pChannel->commit_info_remote.p_funding_info =
        &pChannel->funding_info;

#ifdef USE_GOSSIP_QUERY
    SLIST_INIT(&pChannel->gossip_query.request.send_encoded_ids);
#endif

    LOGD("END\n");

    return true;
}


void ln_term(ln_channel_t *pChannel)
{
    channel_clear(pChannel);

    ln_derkey_term(&pChannel->keys_local, &pChannel->keys_remote);
    ln_update_info_free(&pChannel->update_info);
    //LOGD("END\n");
}


const char *ln_status_string(const ln_channel_t *pChannel)
{
    const char *p_str_stat;
    switch (pChannel->status) {
    case LN_STATUS_NONE:
        p_str_stat = "none";
        break;
    case LN_STATUS_ESTABLISH:
        p_str_stat = "establishing";
        break;
    case LN_STATUS_NORMAL_OPE:
        p_str_stat = "normal operation";
        break;
    case LN_STATUS_CLOSE_WAIT:
        p_str_stat = "close waiting";
        break;
    case LN_STATUS_CLOSE_MUTUAL:
        p_str_stat = "mutual close";
        break;
    case LN_STATUS_CLOSE_UNI_LOCAL:
        p_str_stat = "unilateral close (local)";
        break;
    case LN_STATUS_CLOSE_UNI_REMOTE_LAST:
        p_str_stat = "unilateral close (remote last)";
        break;
    case LN_STATUS_CLOSE_UNI_REMOTE_SECOND_LAST:
        p_str_stat = "unilateral close (remote second last)";
        break;
    case LN_STATUS_CLOSE_REVOKED:
        p_str_stat = "revoked transaction close";
        break;
    case LN_STATUS_CLOSE_UNKNOWN:
        p_str_stat = "unknown close";
        break;
    case LN_STATUS_CLOSED:
        p_str_stat = "closed";
        break;
    default:
        p_str_stat = "???";
    }
    return p_str_stat;
}


btc_block_chain_t ln_genesishash_set(const uint8_t *pHash)
{
    memcpy(mGenesisChainHash, pHash, BTC_SZ_HASH256);
    btc_block_chain_t gen = btc_block_get_chain(mGenesisChainHash);
    LOGD("genesis(%d)=", (int)gen);
    DUMPD(mGenesisChainHash, BTC_SZ_HASH256);
    if (gen == BTC_BLOCK_CHAIN_UNKNOWN) {
        LOGE("fail: unknown genesis block hash\n");
    }
    return gen;
}


const uint8_t* ln_genesishash_get(void)
{
    return mGenesisChainHash;
}


void ln_creationhash_set(const uint8_t *pHash)
{
    memcpy(mCreationBlockHash, pHash, BTC_SZ_HASH256);

    LOGD("block hash=");
    DUMPD(mCreationBlockHash, BTC_SZ_HASH256);
}


const uint8_t *ln_creationhash_get(void)
{
    return mCreationBlockHash;
}


void ln_peer_set_node_id(ln_channel_t *pChannel, const uint8_t *pNodeId)
{
    memcpy(pChannel->peer_node_id, pNodeId, BTC_SZ_PUBKEY);
}


bool ln_establish_alloc(ln_channel_t *pChannel, const ln_establish_param_t *pParam)
{
    LOGD("BEGIN\n");

    if (pParam) {
        memcpy(&pChannel->establish.param, pParam, sizeof(ln_establish_param_t));
        LOGD("dust_limit_sat= %" PRIu64 "\n", pChannel->establish.param.dust_limit_sat);
        LOGD("max_htlc_value_in_flight_msat= %" PRIu64 "\n", pChannel->establish.param.max_htlc_value_in_flight_msat);
        LOGD("channel_reserve_sat= %" PRIu64 "\n", pChannel->establish.param.channel_reserve_sat);
        LOGD("htlc_minimum_msat= %" PRIu64 "\n", pChannel->establish.param.htlc_minimum_msat);
        LOGD("to_self_delay= %" PRIu16 "\n", pChannel->establish.param.to_self_delay);
        LOGD("max_accepted_htlcs= %" PRIu16 "\n", pChannel->establish.param.max_accepted_htlcs);
        LOGD("min_depth= %" PRIu16 "\n", pChannel->establish.param.min_depth);
    }

    LOGD("END\n");

    return true;
}


void ln_establish_free(ln_channel_t *pChannel)
{
    pChannel->funding_info.state = (ln_funding_state_t)((pChannel->funding_info.state & ~LN_FUNDING_STATE_STATE_FUNDING) | LN_FUNDING_STATE_STATE_OPENED);
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


void ln_short_channel_id_set_param(ln_channel_t *pChannel, uint32_t Height, uint32_t Index)
{
    pChannel->short_channel_id = ln_short_channel_id_calc(Height, Index, ln_funding_info_txindex(&pChannel->funding_info));
    M_DB_CHANNEL_SAVE(pChannel);
}


void ln_short_channel_id_get_param(uint32_t *pHeight, uint32_t *pBIndex, uint32_t *pVIndex, uint64_t ShortChannelId)
{
    *pHeight = ShortChannelId >> 40;
    *pBIndex = (ShortChannelId >> 16) & 0xffffff;
    *pVIndex = ShortChannelId & 0xffff;
}


const uint8_t *ln_funding_blockhash(const ln_channel_t *pChannel)
{
    return pChannel->funding_blockhash;
}


uint32_t ln_funding_last_confirm_get(const ln_channel_t *pChannel)
{
    return pChannel->funding_last_confirm;
}


void ln_funding_last_confirm_set(ln_channel_t *pChannel, uint32_t Confirm)
{
    if (Confirm > pChannel->funding_last_confirm) {
        pChannel->funding_last_confirm = Confirm;
    }
}


void ln_funding_blockhash_set(ln_channel_t *pChannel, const uint8_t *pBlockHash)
{
    LOGD("save funding blockhash=");
    TXIDD(pBlockHash);
    memcpy(pChannel->funding_blockhash, pBlockHash, BTC_SZ_HASH256);
    M_DB_CHANNEL_SAVE(pChannel);
}


void ln_short_channel_id_string(char *pStr, uint64_t ShortChannelId)
{
    uint32_t height;
    uint32_t bindex;
    uint32_t vindex;
    ln_short_channel_id_get_param(&height, &bindex, &vindex, ShortChannelId);
    snprintf(pStr, LN_SZ_SHORT_CHANNEL_ID_STR, "%" PRIu32 "x%" PRIu32 "x%" PRIu32, height, bindex, vindex);
}


#if 0
bool ln_set_shutdown_vout_pubkey(ln_channel_t *pChannel, const uint8_t *pShutdownPubkey, int ShutdownPref)
{
    bool ret = false;

    if ((ShutdownPref == BTC_PREF_P2PKH) || (ShutdownPref == BTC_PREF_P2WPKH)) {
        const utl_buf_t pub = { (CONST_CAST uint8_t *)pShutdownPubkey, BTC_SZ_PUBKEY };
        utl_buf_t spk = UTL_BUF_INIT;

        ln_script_scriptpkh_write(&spk, &pub, ShutdownPref);
        utl_buf_free(&pChannel->shutdown_scriptpk_local);
        utl_buf_alloccopy(&pChannel->shutdown_scriptpk_local, spk.buf, spk.len);
        utl_buf_free(&spk);

        ret = true;
    } else {
        M_SET_ERR(pChannel, LNERR_INV_PREF, "invalid prefix");
    }

    return ret;
}
#endif


void ln_shutdown_set_vout_addr(ln_channel_t *pChannel, const utl_buf_t *pScriptPk)
{
    LOGD("set close addr: ");
    DUMPD(pScriptPk->buf, pScriptPk->len);
    utl_buf_free(&pChannel->shutdown_scriptpk_local);
    utl_buf_alloccopy(&pChannel->shutdown_scriptpk_local, pScriptPk->buf, pScriptPk->len);
}


bool ln_recv(ln_channel_t *pChannel, const uint8_t *pData, uint16_t Len)
{
    uint16_t type = utl_int_pack_u16be(pData);

    if (type != MSGTYPE_INIT && !M_INIT_FLAG_EXCHNAGED(pChannel->init_flag)) {
        M_SET_ERR(pChannel, LNERR_INV_STATE, "no init received : %04x", type);
        return false;
    }

    size_t lp;
    for (lp = 0; lp < ARRAY_SIZE(RECV_FUNC); lp++) {
        if (type != RECV_FUNC[lp].type) continue;
        if (!(*RECV_FUNC[lp].func)(pChannel, pData, Len)) {
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


bool ln_funding_locked_needs(const ln_channel_t *pChannel)
{
    if (!pChannel->short_channel_id) return false;

    //initial
    if ((pChannel->commit_info_local.commit_num == 0) && (pChannel->commit_info_remote.commit_num == 0)) return true;

    //if next_local_commitment_number is 1 in both the channel_reestablish it sent and received:
    //  `next_local_commitment_number` is local_commitment_number + 1*/
    if ((pChannel->commit_info_local.commit_num == 0) && (pChannel->reest_next_local_commit_num == 1)) return true;

    return false;
}




/********************************************************************
 * Establish関係
 ********************************************************************/

void HIDDEN ln_channel_id_calc(uint8_t *pChannelId, const uint8_t *pTxid, uint16_t Index)
{
    //combining the funding-txid and the funding-output-index using big-endian exclusive-OR
    memcpy(pChannelId, pTxid, LN_SZ_CHANNEL_ID - sizeof(uint16_t));
    pChannelId[LN_SZ_CHANNEL_ID - 2] = pTxid[LN_SZ_CHANNEL_ID - 2] ^ (Index >> 8);
    pChannelId[LN_SZ_CHANNEL_ID - 1] = pTxid[LN_SZ_CHANNEL_ID - 1] ^ (Index & 0xff);
}


bool ln_channel_update_get_peer(const ln_channel_t *pChannel, utl_buf_t *pCnlUpd, ln_msg_channel_update_t *pMsg)
{
    bool ret;

    btc_script_pubkey_order_t order = ln_node_id_order(pChannel, NULL);
    uint8_t dir = (order == BTC_SCRYPT_PUBKEY_ORDER_OTHER) ? 0 : 1;  //相手のchannel_update
    ret = ln_db_cnlupd_load(pCnlUpd, NULL, pChannel->short_channel_id, dir, NULL);
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

void ln_shutdown_update_fee(ln_channel_t *pChannel, uint64_t Fee)
{
    //BOLT#3
    //  A sending node MUST set fee_satoshis lower than or equal to the base fee
    //      of the final commitment transaction as calculated in BOLT #3.
    uint64_t feemax = ln_closing_signed_initfee(pChannel);
    if (Fee > feemax) {
        LOGD("closing fee limit(%" PRIu64 " > %" PRIu64 ")\n", Fee, feemax);
        Fee = feemax;
    }

    pChannel->close_fee_sat = Fee;
    LOGD("fee_sat: %" PRIu64 "\n", pChannel->close_fee_sat);
}


void ln_close_change_stat(ln_channel_t *pChannel, const btc_tx_t *pCloseTx, void *pDbParam)
{
    LOGD("BEGIN: status=%d\n", (int)pChannel->status);
    if (pCloseTx == NULL) {
        //funding_tx is spent but spent_tx isn't mining
        if (pChannel->status < LN_STATUS_CLOSE_WAIT) {
            ln_status_set(pChannel, LN_STATUS_CLOSE_WAIT);
            ln_db_channel_save_status(pChannel, pDbParam);
        }
    } else {
        //funding_tx is spent and spent_tx is mined
        M_DBG_PRINT_TX(pCloseTx);

        uint8_t txid[BTC_SZ_TXID];
        bool ret = btc_tx_txid(pCloseTx, txid);
        if (!ret) {
            LOGE("fail: txid\n");
            return;
        }

        if ( (ln_shutdown_scriptpk_local(pChannel)->len > 0) &&
             (ln_shutdown_scriptpk_remote(pChannel)->len > 0) &&
             (pCloseTx->vout_cnt <= 2) &&
             ( utl_buf_equal(&pCloseTx->vout[0].script, ln_shutdown_scriptpk_local(pChannel)) ||
               utl_buf_equal(&pCloseTx->vout[0].script, ln_shutdown_scriptpk_remote(pChannel)) ) ) {
            ln_status_set(pChannel, LN_STATUS_CLOSE_MUTUAL);
        } else if (memcmp(txid, pChannel->commit_info_local.txid, BTC_SZ_TXID) == 0) {
            ln_status_set(pChannel, LN_STATUS_CLOSE_UNI_LOCAL);
        } else {
            uint64_t commit_num = calc_commit_num(&pChannel->commit_info_remote, pCloseTx);

            utl_buf_alloc(&pChannel->revoked_sec, BTC_SZ_PRIVKEY);
            bool ret = ln_derkey_remote_storage_get_secret(&pChannel->keys_remote, pChannel->revoked_sec.buf, (uint64_t)(LN_SECRET_INDEX_INIT - commit_num));
            if (ret) {
                ln_status_set(pChannel, LN_STATUS_CLOSE_REVOKED);
                btc_keys_priv2pub(pChannel->keys_remote.per_commitment_point, pChannel->revoked_sec.buf);
            } else if (commit_num == pChannel->commit_info_remote.commit_num) {
                ln_status_set(pChannel, LN_STATUS_CLOSE_UNI_REMOTE_LAST);
                utl_buf_free(&pChannel->revoked_sec);
            } else if (commit_num == pChannel->commit_info_remote.commit_num - 1) {
                ln_status_set(pChannel, LN_STATUS_CLOSE_UNI_REMOTE_SECOND_LAST);
                utl_buf_free(&pChannel->revoked_sec);
            } else {
                LOGE("fail: unknown close\n");
                ln_status_set(pChannel, LN_STATUS_CLOSE_UNKNOWN);
                utl_buf_free(&pChannel->revoked_sec);
            }
        }
        ln_db_channel_save_status(pChannel, pDbParam);

        ln_channel_update_disable(pChannel);
    }
    LOGD("END: type=%d\n", (int)pChannel->status);
}


/*
 * 自分がunilateral closeを行いたい場合に呼び出す。
 * または、funding_txがspentで、local commit_txのtxidがgetrawtransactionできる状態で呼ばれる。
 * (local commit_txが展開＝自分でunilateral closeした)
 *
 * 現在のcommitment_transactionを取得する場合にも呼び出されるため、値を元に戻す。
 */
bool ln_close_create_unilateral_tx(ln_channel_t *pChannel, ln_close_force_t *pClose)
{
    LOGD("BEGIN\n");

    //to_local送金先設定確認
    assert(pChannel->shutdown_scriptpk_local.len > 0);

    ln_derkey_local_keys_t  keys_local_work = pChannel->keys_local;
    ln_derkey_remote_keys_t keys_remote_work = pChannel->keys_remote;

    //local
    ln_derkey_local_storage_create_prev_per_commitment_secret(
        &keys_local_work,
        keys_local_work.per_commitment_secret,
        keys_local_work.per_commitment_point);

    //remote
    memcpy(
        keys_remote_work.per_commitment_point,
        keys_remote_work.prev_per_commitment_point, BTC_SZ_PUBKEY);

    //update keys
    ln_derkey_update_script_pubkeys(&keys_local_work, &keys_remote_work);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + pChannel->commit_info_local.num_htlc_outputs);

    //local commit_tx
    bool ret = ln_commit_tx_create_local_close(
        &pChannel->commit_info_local, &pChannel->update_info,
        &keys_local_work, &keys_remote_work, pClose);
    if (!ret) {
        LOGE("fail: create_to_local\n");
        ln_close_free_forcetx(pClose);
    }

    LOGD("END: %d\n", ret);
    return ret;
}


/*
 * funding_txがspentで、remote commit_txのtxidがgetrawtransactionできる状態で呼ばれる。
 * (remote commit_txが展開＝相手がunilateral closeした)
 */
bool ln_close_create_tx(ln_channel_t *pChannel, ln_close_force_t *pClose)
{
    LOGD("BEGIN\n");

    switch (pChannel->status) {
    case LN_STATUS_CLOSE_UNI_REMOTE_LAST:
        break;
    case LN_STATUS_CLOSE_UNI_REMOTE_SECOND_LAST:
        //XXX: this process is destructive
        memcpy(pChannel->commit_info_remote.txid, pChannel->prev_remote_commit_txid, BTC_SZ_TXID);
        ln_commit_tx_rewind_one_commit_remote(&pChannel->commit_info_remote, &pChannel->update_info);
        break;
    default:
        LOGE("fail: invalid status=%s\n", ln_status_string(pChannel));
    }

    ln_derkey_local_keys_t  keys_local_work = pChannel->keys_local;
    ln_derkey_remote_keys_t keys_remote_work = pChannel->keys_remote;

    //local
    ln_derkey_local_storage_create_prev_per_commitment_secret(
        &keys_local_work,
        keys_local_work.per_commitment_secret,
        keys_local_work.per_commitment_point);

    //remote
    memcpy(
        keys_remote_work.per_commitment_point,
        keys_remote_work.prev_per_commitment_point, BTC_SZ_PUBKEY);

    //update keys
    ln_derkey_update_script_pubkeys(&keys_local_work, &keys_remote_work);
    ln_print_keys_2(&pChannel->funding_info, &keys_local_work, &keys_remote_work);

    //[0]commit_tx, [1]to_local, [2]to_remote, [3...]HTLC
    close_alloc(pClose, LN_CLOSE_IDX_HTLC + pChannel->commit_info_remote.num_htlc_outputs);

    //remote commit_tx
    bool ret = ln_commit_tx_create_remote_close(
        &pChannel->commit_info_remote, &pChannel->update_info,
        &keys_local_work, &keys_remote_work, &pChannel->shutdown_scriptpk_local,
        pClose);
    if (!ret) {
        LOGE("fail: create_to_remote\n");
        ln_close_free_forcetx(pClose);
    }

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
    UTL_DBG_FREE(pClose->p_htlc_idxs);
    pClose->p_htlc_idxs = NULL;

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
bool ln_close_remote_revoked(ln_channel_t *pChannel, const btc_tx_t *pRevokedTx, void *pDbParam)
{
    ln_derkey_local_keys_t  keys_local_work = pChannel->keys_local;
    ln_derkey_remote_keys_t keys_remote_work = pChannel->keys_remote;

    //取り戻す必要があるvout数
    pChannel->revoked_cnt = 0;
    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        if (pRevokedTx->vout[lp].script.len != BTC_SZ_WITPROG_P2WPKH) {
            //to_remote output以外はスクリプトを作って取り戻す
            pChannel->revoked_cnt++;
        }
    }
    LOGD("revoked_cnt=%d\n", pChannel->revoked_cnt);
    pChannel->revoked_num = 1 + pChannel->revoked_cnt;      //p_revoked_vout[0]にto_local系を必ず入れるため、+1しておく
                                                    //(to_local自体が無くても、HTLC txの送金先がto_localと同じtxになるため)
    ln_revoked_buf_alloc(pChannel);

    //
    //相手がrevoked_txを展開した前提で、スクリプトを再現
    //

    //commitment numberの復元
    uint64_t commit_num = calc_commit_num(&pChannel->commit_info_remote, pRevokedTx);

    //remote per_commitment_secretの復元
    utl_buf_free(&pChannel->revoked_sec);
    utl_buf_alloc(&pChannel->revoked_sec, BTC_SZ_PRIVKEY);
    bool ret = ln_derkey_remote_storage_get_secret(&keys_remote_work, pChannel->revoked_sec.buf, (uint64_t)(LN_SECRET_INDEX_INIT - commit_num));
    if (!ret) {
        LOGE("fail: ln_derkey_remote_storage_get_secret()\n");
        abort();
    }
    btc_keys_priv2pub(keys_remote_work.per_commitment_point, pChannel->revoked_sec.buf);
    //LOGD2("  pri:");
    //DUMPD(pChannel->revoked_sec.buf, BTC_SZ_PRIVKEY);
    //LOGD2("  pub:");
    //DUMPD(pChannel->pubkeys_remote.per_commitment_point, BTC_SZ_PUBKEY);

    //local per_commitment_secretの復元
    ln_derkey_local_storage_update_per_commitment_point_force(&keys_local_work, (uint64_t)(LN_SECRET_INDEX_INIT - commit_num));

    //鍵の復元
    ln_derkey_update_script_pubkeys(&keys_local_work, &keys_remote_work);
    ln_print_keys_2(&pChannel->funding_info, &keys_local_work, &keys_remote_work);

    //to_local outputとHTLC Timeout/Success Txのoutputは同じ形式のため、to_local outputの有無にかかわらず作っておく。
    //p_revoked_vout[0]にはscriptPubKey、p_revoked_wit[0]にはwitnessProgramを作る。
    ln_script_create_to_local(
        &pChannel->p_revoked_wit[LN_RCLOSE_IDX_TO_LOCAL],
        keys_remote_work.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
        keys_remote_work.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
        pChannel->commit_info_remote.to_self_delay);
    utl_buf_init(&pChannel->p_revoked_vout[LN_RCLOSE_IDX_TO_LOCAL]);
    btc_script_p2wsh_create_scriptpk(&pChannel->p_revoked_vout[LN_RCLOSE_IDX_TO_LOCAL], &pChannel->p_revoked_wit[LN_RCLOSE_IDX_TO_LOCAL]);
    // LOGD("calc to_local vout: ");
    // DUMPD(pChannel->p_revoked_vout[LN_RCLOSE_IDX_TO_LOCAL].buf, pChannel->p_revoked_vout[LN_RCLOSE_IDX_TO_LOCAL].len);

    int htlc_cnt = 0;
    for (uint32_t lp = 0; lp < pRevokedTx->vout_cnt; lp++) {
        LOGD("vout[%d]: ", lp);
        DUMPD(pRevokedTx->vout[lp].script.buf, pRevokedTx->vout[lp].script.len);
        if (pRevokedTx->vout[lp].script.len == BTC_SZ_WITPROG_P2WPKH) {
            //to_remote output
            LOGD("[%d]to_remote_output\n", lp);
            utl_buf_init(&pChannel->p_revoked_wit[LN_RCLOSE_IDX_TO_REMOTE]);
            utl_buf_alloccopy(&pChannel->p_revoked_vout[LN_RCLOSE_IDX_TO_REMOTE], pRevokedTx->vout[lp].script.buf, pRevokedTx->vout[lp].script.len);
        } else if (utl_buf_equal(&pRevokedTx->vout[lp].script, &pChannel->p_revoked_vout[LN_RCLOSE_IDX_TO_LOCAL])) {
            //to_local output
            LOGD("[%d]to_local_output\n", lp);
        } else {
            //HTLC Tx
            //  DBには、vout(SHA256後)をkeyにして、payment_hashを保存している。
            ln_commit_tx_output_type_t type;
            uint8_t payment_hash[BTC_SZ_HASH256];
            uint32_t expiry;
            if (ln_db_payment_hash_search(
                payment_hash, &type, &expiry, pRevokedTx->vout[lp].script.buf, pDbParam)) {
                uint16_t htlc_idx = LN_RCLOSE_IDX_HTLC + htlc_cnt;
                ln_script_create_htlc(
                    &pChannel->p_revoked_wit[htlc_idx], type,
                    keys_remote_work.script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
                    keys_remote_work.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
                    keys_remote_work.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
                    payment_hash, expiry);
                utl_buf_init(&pChannel->p_revoked_vout[htlc_idx]);
                btc_script_p2wsh_create_scriptpk(&pChannel->p_revoked_vout[htlc_idx], &pChannel->p_revoked_wit[htlc_idx]);
                pChannel->p_revoked_type[htlc_idx] = type;

                LOGD("[%d]%s(%d) HTLC output%d\n", lp, (type == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ? "offered" : "received", type, htlc_idx);
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
 * others
 ********************************************************************/

bool ln_revokedhtlc_create_spenttx(const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value,
                int WitIndex, const uint8_t *pTxid, int Index)
{
    ln_commit_tx_base_fee_info_t fee_info;
    fee_info.feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&pChannel->update_info, false);
    ln_commit_tx_base_fee_calc(&fee_info, NULL, 0);
    uint64_t fee = (pChannel->p_revoked_type[WitIndex] == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ? fee_info.htlc_timeout_fee : fee_info.htlc_success_fee;
    LOGD("Value=%" PRIu64 ", fee=%" PRIu64 "\n", Value, fee);

    ln_htlc_tx_create(pTx, Value - fee, NULL, pChannel->p_revoked_type[WitIndex], 0, pTxid, Index);
    btc_tx_add_vout_spk(pTx, Value - fee, &pChannel->shutdown_scriptpk_local);
    M_DBG_PRINT_TX2(pTx);

    btc_keys_t signkey;
    ln_signer_revocation_privkey(
        &signkey, &pChannel->keys_local,
        pChannel->keys_remote.per_commitment_point,
        pChannel->revoked_sec.buf);
    // LOGD("key-priv: ");
    // DUMPD(signkey.priv, BTC_SZ_PRIVKEY);
    // LOGD("key-pub : ");
    // DUMPD(signkey.pub, BTC_SZ_PUBKEY);

    ln_htlc_tx_sig_type_t htlcsign = LN_HTLC_TX_SIG_NONE;
    switch (pChannel->p_revoked_type[WitIndex]) {
    case LN_COMMIT_TX_OUTPUT_TYPE_OFFERED:
        htlcsign = LN_HTLC_TX_SIG_REVOKE_OFFER;
        break;
    case LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED:
        htlcsign = LN_HTLC_TX_SIG_REVOKE_RECV;
        break;
    default:
        LOGD("index=%d, %d\n", WitIndex, pChannel->p_revoked_type[WitIndex]);
        assert(0);
    }
    bool ret;
    if (htlcsign != LN_HTLC_TX_SIG_NONE) {
        uint8_t sig[LN_SZ_SIGNATURE];
        ret = ln_htlc_tx_sign_rs(pTx,
                sig,
                Value,
                &signkey,
                &pChannel->p_revoked_wit[WitIndex]);
        if (ret) {
            ret = ln_htlc_tx_set_vin0_rs(pTx,
                sig,
                NULL,
                NULL,
                &signkey,
                &pChannel->p_revoked_wit[WitIndex],
                htlcsign);
        }
    } else {
        ret = false;
    }

    return ret;
}


void ln_payment_hash_calc(uint8_t *pHash, const uint8_t *pPreimage)
{
    btc_md_sha256(pHash, pPreimage, LN_SZ_PREIMAGE);
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
bool ln_get_ids_cnl_anno(uint64_t *p_short_channel_id, uint8_t *pNodeId1, uint8_t *pNodeId2, const uint8_t *pData, uint16_t Len)
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


void ln_last_connected_addr_set(ln_channel_t *pChannel, const ln_node_addr_t *pAddr)
{
    memcpy(&pChannel->last_connected_addr, pAddr, sizeof(ln_node_addr_t));
    LOGD("addr[%d]: %d.%d.%d.%d:%d\n", pAddr->type,
            pAddr->addr[0], pAddr->addr[1],
            pAddr->addr[2], pAddr->addr[3],
            pAddr->port);
    M_DB_CHANNEL_SAVE(pChannel);
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

const uint8_t *ln_channel_id(const ln_channel_t *pChannel)
{
    return pChannel->channel_id;
}


uint64_t ln_short_channel_id(const ln_channel_t *pChannel)
{
    return pChannel->short_channel_id;
}


void ln_short_channel_id_clr(ln_channel_t *pChannel)
{
    pChannel->short_channel_id = 0;
}


void *ln_get_param(ln_channel_t *pChannel)
{
    return pChannel->p_param;
}


bool ln_status_set(ln_channel_t *pChannel, ln_status_t status)
{
    if (pChannel->status != status) {
        LOGD("%d ==> %d\n", pChannel->status, status);
        pChannel->status = status;
    }
    return true;
}


ln_status_t ln_status_get(const ln_channel_t *pChannel)
{
    return pChannel->status;
}


bool ln_status_is_closing(const ln_channel_t *pChannel)
{
    return pChannel->status > LN_STATUS_NORMAL_OPE;
}


bool ln_status_is_closed(const ln_channel_t *pChannel)
{
    return pChannel->status > LN_STATUS_CLOSE_WAIT;
}


uint64_t ln_local_msat(const ln_channel_t *pChannel)
{
    //XXX: need to consider the uncommitted offered HTLCs
    return pChannel->commit_info_remote.remote_msat; //remote's remote -> local
}


uint64_t ln_remote_msat(const ln_channel_t *pChannel)
{
    //XXX: need to consider the uncommitted offered HTLCs
    return pChannel->commit_info_remote.local_msat; //remote's local -> remote
}


uint64_t ln_local_payable_msat(const ln_channel_t *pChannel)
{
    //XXX: need to consider the uncommitted offered HTLCs
    uint64_t remote_reserve_msat = LN_SATOSHI2MSAT(pChannel->commit_info_remote.channel_reserve_sat);
    if (pChannel->commit_info_remote.remote_msat > remote_reserve_msat) { //remote's remote -> local
        return pChannel->commit_info_remote.remote_msat - remote_reserve_msat;
    } else {
        return 0;
    }
}


uint64_t ln_remote_payable_msat(const ln_channel_t *pChannel)
{
    //XXX: need to consider the uncommitted offered HTLCs
    uint64_t local_reserve_msat = LN_SATOSHI2MSAT(pChannel->commit_info_local.channel_reserve_sat);
    if (pChannel->commit_info_local.remote_msat > local_reserve_msat) { //local's remote -> remote
        return pChannel->commit_info_local.remote_msat - local_reserve_msat;
    } else {
        return 0;
    }
}


bool ln_announcement_is_gossip_query(const ln_channel_t *pChannel)
{
    return pChannel->init_flag & M_INIT_GOSSIP_QUERY;
}


bool ln_need_init_routing_sync(const ln_channel_t *pChannel)
{
    return pChannel->lfeature_remote & LN_INIT_LF_ROUTE_SYNC;
}


bool ln_is_announced(const ln_channel_t *pChannel)
{
    return (pChannel->anno_flag & LN_ANNO_FLAG_END);
}


void ln_feerate_limit_get(uint32_t *pMin, uint32_t *pMax, uint32_t feerate_per_kw)
{
    *pMin = (uint32_t)(feerate_per_kw * mFeerateMin / 100);
    *pMax = (uint32_t)(feerate_per_kw * mFeerateMax / 100);
    LOGD("feerate_limit_get: min=%d, max=%d\n", *pMin, *pMax);
}


void ln_feerate_limit_set(uint16_t Min, uint16_t Max)
{
    mFeerateMin = Min;
    mFeerateMax = Max;
}


uint32_t ln_feerate_per_kw_calc(uint64_t feerate_kb)
{
    uint64_t feerate_kw = (uint32_t)(feerate_kb / 4);
    if (feerate_kw < LN_FEERATE_PER_KW_MIN) {
        // estimatesmartfeeは1000satoshisが下限のようだが、c-lightningは1000/4=250ではなく253を下限としている。
        //      https://github.com/ElementsProject/lightning/issues/1443
        //      https://github.com/ElementsProject/lightning/issues/1391
        //LOGD("FIX: calc feerate_per_kw(%" PRIu32 ") < MIN\n", feerate_kw);
        feerate_kw = LN_FEERATE_PER_KW_MIN;
    }
    return feerate_kw;
}


uint64_t ln_calc_fee(uint32_t vsize, uint64_t feerate_kw)
{
    return vsize * feerate_kw * 4 / 1000;
}


uint32_t ln_feerate_per_kw(const ln_channel_t *pChannel)
{
    return ln_update_info_get_feerate_per_kw_committed(&pChannel->update_info, true);
}


uint64_t ln_estimate_fundingtx_fee(uint32_t FeeratePerKw)
{
    return ln_calc_fee(LN_SZ_FUNDINGTX_VSIZE, FeeratePerKw);
}


uint64_t ln_estimate_initcommittx_fee(uint32_t FeeratePerKw)
{
    return (LN_FEE_COMMIT_BASE_WEIGHT * FeeratePerKw / 1000);
}


bool ln_is_shutdown_sent(const ln_channel_t *pChannel)
{
    return pChannel->shutdown_flag & LN_SHDN_FLAG_SEND_SHDN;
}


uint64_t ln_closing_signed_initfee(const ln_channel_t *pChannel)
{
    uint32_t feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&pChannel->update_info, true);
    return (LN_FEE_COMMIT_BASE_WEIGHT * feerate_per_kw / 1000);
}


const ln_commit_info_t *ln_commit_info_local(const ln_channel_t *pChannel)
{
    return &pChannel->commit_info_local;
}


const ln_commit_info_t *ln_commit_info_remote(const ln_channel_t *pChannel)
{
    return &pChannel->commit_info_remote;
}


const utl_buf_t *ln_shutdown_scriptpk_local(const ln_channel_t *pChannel)
{
    return &pChannel->shutdown_scriptpk_local;
}


const utl_buf_t *ln_shutdown_scriptpk_remote(const ln_channel_t *pChannel)
{
    return &pChannel->shutdown_scriptpk_remote;
}


const ln_update_t *ln_update(const ln_channel_t *pChannel, uint16_t UpdateIdx)
{
    return (UpdateIdx < LN_UPDATE_MAX) ? &pChannel->update_info.updates[UpdateIdx] : NULL;
}


const ln_htlc_t *ln_htlc(const ln_channel_t *pChannel, uint16_t HtlcIdx)
{
    return (HtlcIdx < LN_HTLC_MAX) ? &pChannel->update_info.htlcs[HtlcIdx] : NULL;
}


bool ln_is_offered_htlc_timeout(const ln_channel_t *pChannel, uint16_t UpdateIdx, uint32_t BlockCount)
{
    return (UpdateIdx < LN_UPDATE_MAX) &&
        LN_UPDATE_USED(&pChannel->update_info.updates[UpdateIdx]) &&
        LN_UPDATE_TIMEOUT_CHECK_NEEDED(&pChannel->update_info.updates[UpdateIdx]) &&
        (pChannel->update_info.htlcs[pChannel->update_info.updates[UpdateIdx].type_specific_idx].cltv_expiry <= BlockCount);
}


const utl_buf_t *ln_preimage_remote(const btc_tx_t *pTx)
{
    utl_buf_t *p_buf = NULL;
    switch (pTx->vin[0].wit_item_cnt) {
    case 3: //offered HTLC outputs
        p_buf = &pTx->vin[0].witness[1];
        break;
    case 5: //HTLC success tx
        p_buf = &pTx->vin[0].witness[3];
        break;
    default:
        return NULL;
    }
    if (p_buf->len != LN_SZ_PREIMAGE) return NULL;
    return p_buf;
}


uint16_t ln_revoked_cnt(const ln_channel_t *pChannel)
{
    return pChannel->revoked_cnt;
}


bool ln_revoked_cnt_dec(ln_channel_t *pChannel)
{
    pChannel->revoked_cnt--;
    return pChannel->revoked_cnt == 0;
}


uint16_t ln_revoked_num(const ln_channel_t *pChannel)
{
    return pChannel->revoked_num;
}


void ln_set_revoked_confm(ln_channel_t *pChannel, uint32_t confm)
{
    pChannel->revoked_chk = confm;
}


uint32_t ln_revoked_confm(const ln_channel_t *pChannel)
{
    return pChannel->revoked_chk;
}


const utl_buf_t* ln_revoked_vout(const ln_channel_t *pChannel)
{
    return pChannel->p_revoked_vout;
}


const utl_buf_t* ln_revoked_wit(const ln_channel_t *pChannel)
{
    return pChannel->p_revoked_wit;
}


bool ln_open_channel_announce(const ln_channel_t *pChannel)
{
    bool ret = (pChannel->funding_info.state & LN_FUNDING_STATE_STATE_NO_ANNO_CH);

    //コメントアウトすると、announcement_signatures交換済みかどうかにかかわらず、
    //送信しても良い状況であればannouncement_signaturesを起動時に送信する
    if (ret) {
        utl_buf_t buf_cnl_anno = UTL_BUF_INIT;
        bool havedb = ln_db_cnlanno_load(&buf_cnl_anno, pChannel->short_channel_id);
        if (havedb) {
            ln_msg_channel_announcement_print(buf_cnl_anno.buf, buf_cnl_anno.len);
        }
        utl_buf_free(&buf_cnl_anno);
        ret = !havedb;
    }
    LOGD("announcement_signatures request:%d\n", ret);
    return ret;
}


const uint8_t *ln_remote_node_id(const ln_channel_t *pChannel)
{
    return pChannel->peer_node_id;
}


const ln_node_addr_t *ln_last_connected_addr(const ln_channel_t *pChannel)
{
    return &pChannel->last_connected_addr;
}


int ln_err(const ln_channel_t *pChannel)
{
    return pChannel->err;
}


const char *ln_errmsg(const ln_channel_t *pChannel)
{
    return pChannel->err_msg;
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
void HIDDEN ln_revoked_buf_alloc(ln_channel_t *pChannel)
{
    LOGD("alloc(%d)\n", pChannel->revoked_num);

    pChannel->p_revoked_vout = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pChannel->revoked_num);
    pChannel->p_revoked_wit = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pChannel->revoked_num);
    pChannel->p_revoked_type = (ln_commit_tx_output_type_t *)UTL_DBG_MALLOC(sizeof(ln_commit_tx_output_type_t) * pChannel->revoked_num);
    for (int lp = 0; lp < pChannel->revoked_num; lp++) {
        utl_buf_init(&pChannel->p_revoked_vout[lp]);
        utl_buf_init(&pChannel->p_revoked_wit[lp]);
        pChannel->p_revoked_type[lp] = LN_COMMIT_TX_OUTPUT_TYPE_NONE;
    }
}


/** #ln_revoked_buf_alloc()で確保したメモリの解放
 *
 */
void HIDDEN ln_revoked_buf_free(ln_channel_t *pChannel)
{
    if (pChannel->revoked_num == 0) {
        return;
    }

    for (int lp = 0; lp < pChannel->revoked_num; lp++) {
        utl_buf_free(&pChannel->p_revoked_vout[lp]);
        utl_buf_free(&pChannel->p_revoked_wit[lp]);
    }
    UTL_DBG_FREE(pChannel->p_revoked_vout);
    UTL_DBG_FREE(pChannel->p_revoked_wit);
    UTL_DBG_FREE(pChannel->p_revoked_type);
    pChannel->revoked_num = 0;
    pChannel->revoked_cnt = 0;

    LOGD("free\n");
}


void ln_callback(ln_channel_t *pChannel, ln_cb_type_t Req, void *pParam)
{
    if (pChannel->p_callback == NULL) {
        LOGE("fail: not callback(%d)\n", (int)Req);
        return;
    }

    (*pChannel->p_callback)(Req, pChannel->p_param, pParam);
}


/**
 *
 * @param[in]   pChannel
 * @param[in]   pNodeId
 * @retval      BTC_SCRYPT_PUBKEY_ORDER_ASC     自ノードが先
 * @retval      BTC_SCRYPT_PUBKEY_ORDER_OTHER   相手ノードが先
 */
btc_script_pubkey_order_t ln_node_id_order(const ln_channel_t *pChannel, const uint8_t *pNodeId)
{
    btc_script_pubkey_order_t order;

    int lp;
    const uint8_t *p_node_id = ln_node_get_id();
    const uint8_t *p_peerid;
    if (pNodeId == NULL) {
        p_peerid = pChannel->peer_node_id;
    } else {
        p_peerid = pNodeId;
    }
    for (lp = 0; lp < BTC_SZ_PUBKEY; lp++) {
        if (p_node_id[lp] != p_peerid[lp]) {
            break;
        }
    }
    if ((lp < BTC_SZ_PUBKEY) && (p_node_id[lp] < p_peerid[lp])) {
        LOGD("my node= first\n");
        order = BTC_SCRYPT_PUBKEY_ORDER_ASC;
    } else {
        LOGD("my node= second\n");
        order = BTC_SCRYPT_PUBKEY_ORDER_OTHER;
    }

    return order;
}


/** btc_script_pubkey_order_t --> Direction変換
 *
 */
uint8_t ln_order_to_dir(btc_script_pubkey_order_t Order)
{
    return (uint8_t)Order;
}


bool ln_wallet_create_to_local_2(
    const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value, uint32_t ToSelfDelay,
    const utl_buf_t *pWitScript, const uint8_t *pTxid, int Index, bool bRevoked)
{
    return ln_wallet_create_to_local(
        pTx, Value, ToSelfDelay, pWitScript, pTxid, Index,
        &pChannel->keys_local, &pChannel->keys_remote,
        bRevoked ? pChannel->revoked_sec.buf : NULL);
}


bool ln_wallet_create_to_remote_2(
    const ln_channel_t *pChannel, btc_tx_t *pTx, uint64_t Value, const uint8_t *pTxid, int Index)
{
    return ln_wallet_create_to_remote(
        pTx, Value, pTxid, Index,
        &pChannel->keys_local, &pChannel->keys_remote);
}


/********************************************************************
 * private functions
 ********************************************************************/

/** チャネル情報消去
 *
 * @param[in,out]       pChannel
 * @note
 *      - channelが閉じたときに呼び出すこと
 */
static void channel_clear(ln_channel_t *pChannel)
{
    utl_buf_free(&pChannel->shutdown_scriptpk_local);
    utl_buf_free(&pChannel->shutdown_scriptpk_remote);
    utl_buf_free(&pChannel->funding_info.wit_script);
    utl_buf_free(&pChannel->cnl_anno);
    utl_buf_free(&pChannel->revoked_sec);
    ln_revoked_buf_free(pChannel);

    btc_tx_free(&pChannel->funding_info.tx_data);
    btc_tx_free(&pChannel->tx_closing);

    for (uint16_t idx = 0; idx < LN_HTLC_MAX; idx++) {
        utl_buf_free(&pChannel->update_info.htlcs[idx].buf_preimage);
        utl_buf_free(&pChannel->update_info.htlcs[idx].buf_onion_reason);
        utl_buf_free(&pChannel->update_info.htlcs[idx].buf_shared_secret);
    }

    memset(pChannel->peer_node_id, 0, BTC_SZ_PUBKEY);
    pChannel->anno_flag = 0;
    pChannel->shutdown_flag = 0;

#ifdef USE_GOSSIP_QUERY
    ln_anno_encoded_ids_t *p = SLIST_FIRST(&pChannel->gossip_query.request.send_encoded_ids);
    while (p) {
        ln_anno_encoded_ids_t *p_bak = p;
        p = SLIST_NEXT(p, list);
        utl_buf_free(&p_bak->encoded_short_ids);
        UTL_DBG_FREE(p_bak);
    }
#endif

    ln_establish_free(pChannel);
}


/********************************************************************
 * メッセージ受信
 ********************************************************************/



/********************************************************************
 * Transaction作成
 ********************************************************************/

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
    pClose->p_htlc_idxs = (uint16_t *)UTL_DBG_MALLOC(sizeof(uint16_t) * pClose->num);
    for (int lp = 0; lp < pClose->num; lp++) {
        btc_tx_init(&pClose->p_tx[lp]);
        pClose->p_htlc_idxs[lp] = LN_CLOSE_IDX_NONE;
    }
    utl_buf_init(&pClose->tx_buf);
    LOGD("TX num: %d\n", pClose->num);
}


/** transactionからcommitment numberを復元
 *
 */
static uint64_t calc_commit_num(const ln_commit_info_t *pCommitInfo, const btc_tx_t *pTx)
{
    uint64_t commit_num = ln_commit_tx_calc_commit_num_from_tx(
        pTx->vin[0].sequence, pTx->locktime, pCommitInfo->obscured_commit_num_mask);
    LOGD("commit_num=%" PRIu64 "\n", commit_num);
    return commit_num;
}


/** commitment_number debug output
 *
 */
void ln_dbg_commitnum(const ln_channel_t *pChannel)
{
    LOGD("------------------------------------------\n");
    LOGD("storage_index      = %016" PRIx64 "\n", ln_derkey_local_storage_get_current_index(&pChannel->keys_local));
    LOGD("peer_storage_index = %016" PRIx64 "\n", ln_derkey_remote_storage_get_current_index(&pChannel->keys_remote));
    LOGD("------------------------------------------\n");
    LOGD("local.commit_num  = %" PRIu64 "\n", pChannel->commit_info_local.commit_num);
    LOGD("remote.commit_num = %" PRIu64 "\n", pChannel->commit_info_remote.commit_num);
    LOGD("local.revoke_num  = %" PRId64 "\n", (int64_t)pChannel->commit_info_local.revoke_num);
    LOGD("remote.revoke_num = %" PRId64 "\n", (int64_t)pChannel->commit_info_remote.revoke_num);
    LOGD("------------------------------------------\n");
    LOGD("next_htlc_id: %" PRIu64 "\n", pChannel->update_info.next_htlc_id);
    LOGD("------------------------------------------\n");
}
