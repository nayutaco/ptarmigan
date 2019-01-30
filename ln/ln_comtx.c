/*
 *  Copyright (C) 2019, Nayuta, Inc. All Rights Reserved
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
/** @file   ln_comtx.c
 *  @brief  commitment transaction
 */

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "utl_str.h"
#include "utl_buf.h"
#include "utl_dbg.h"

#include "btc_crypto.h"
#include "btc_script.h"
#include "btc_sw.h"

#include "ln_db.h"
#include "ln_script.h"
#include "ln_signer.h"
#include "ln_normalope.h"
#include "ln_local.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/** #search_preimage()用
 *
 */
typedef struct {
    uint8_t         *image;             ///< [out]preimage
    const uint8_t   *hash;              ///< [in]payment_hash
    bool            b_closing;          ///< true:一致したexpiryをUINT32_MAXに変更する
} preimg_t;


/********************************************************************
 * prototypes
 ********************************************************************/

static void create_to_local_htlcinfo_amount(const ln_channel_t *pChannel,
                    ln_script_htlcinfo_t **ppHtlcInfo,
                    int *pCnt,
                    uint64_t *pOurMsat,
                    uint64_t *pTheirMsat);
static bool create_to_local_sign_verify(const ln_channel_t *pChannel,
                    btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufSig);
static bool create_to_local_spent(ln_channel_t *pChannel,
                    ln_close_force_t *pClose,
                    const uint8_t *pHtlcSigs,
                    uint8_t HtlcSigsNum,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t **ppHtlcInfo,
                    const ln_script_feeinfo_t *pFeeInfo,
                    uint32_t ToSelfDelay);
static bool create_to_local_spentlocal(const ln_channel_t *pChannel,
                    btc_tx_t *pTxToLocal,
                    const utl_buf_t *pBufWs,
                    uint64_t Amount,
                    uint32_t VoutIdx,
                    uint32_t ToSelfDelay);
static bool create_to_local_htlcverify(const ln_channel_t *pChannel,
                    btc_tx_t *pTx,
                    const uint8_t *pHtlcSig,
                    const utl_buf_t *pScript,
                    uint64_t Amount);
static bool create_to_local_spenthtlc(const ln_channel_t *pChannel,
                    btc_tx_t *pCloseTxHtlc,
                    btc_tx_t *pTxHtlc,
                    utl_push_t *pPush,
                    uint64_t Amount,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t *pHtlcInfo,
                    const btc_keys_t *pHtlcKey,
                    uint32_t ToSelfDelay);

static void create_to_remote_htlcinfo(const ln_channel_t *pChannel,
                    ln_script_htlcinfo_t **ppHtlcInfo,
                    int *pCnt,
                    uint64_t *pOurMsat,
                    uint64_t *pTheirMsat);
static bool create_to_remote_spent(const ln_channel_t *pChannel,
                    ln_commit_tx_t *pCommit,
                    ln_close_force_t *pClose,
                    uint8_t *pHtlcSigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t **ppHtlcInfo,
                    const ln_script_feeinfo_t *pFeeInfo);
static bool create_to_remote_spenthtlc(
                    ln_commit_tx_t *pCommit,
                    btc_tx_t *pTxHtlcs,
                    uint8_t *pHtlcSigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t *pHtlcInfo,
                    const btc_keys_t *pHtlcKey,
                    const utl_buf_t *pBufRemoteSig,
                    uint64_t Fee,
                    uint8_t HtlcNum,
                    uint32_t VoutIdx,
                    const uint8_t *pPayHash,
                    bool bClosing);

static bool search_preimage(uint8_t *pPreImage, const uint8_t *pPayHash, bool bClosing);
static bool search_preimage_func(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);


/********************************************************************
 * public functions
 ********************************************************************/

bool ln_comtx_create_to_local(ln_channel_t *pChannel,
                    ln_close_force_t *pClose,
                    const uint8_t *pHtlcSigs,
                    uint8_t HtlcSigsNum,
                    uint64_t CommitNum,
                    uint32_t ToSelfDelay,
                    uint64_t DustLimitSat)
{
    LOGD("BEGIN\n");

    bool ret;
    utl_buf_t buf_ws = UTL_BUF_INIT;
    utl_buf_t buf_sig = UTL_BUF_INIT;
    ln_script_feeinfo_t feeinfo;
    ln_script_committx_t lntx_commit;
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint64_t our_msat = pChannel->our_msat;
    uint64_t their_msat = pChannel->their_msat;

    //To-Local
    ln_script_create_to_local(&buf_ws,
                pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
                pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
                ToSelfDelay);

    //HTLC info(amount)
    ln_script_htlcinfo_t **pp_htlcinfo = (ln_script_htlcinfo_t **)UTL_DBG_MALLOC(sizeof(ln_script_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;
    create_to_local_htlcinfo_amount(pChannel, pp_htlcinfo, &cnt, &our_msat, &their_msat);

    //HTLC info(script)
    for (int lp = 0; lp < cnt; lp++) {
        ln_script_htlcinfo_script(&pp_htlcinfo[lp]->script,
                        pp_htlcinfo[lp]->type,
                        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
                        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
                        pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
                        pp_htlcinfo[lp]->preimage_hash,
                        pp_htlcinfo[lp]->expiry);
    }

    LOGD("-------\n");
    LOGD("our_msat   %" PRIu64 " --> %" PRIu64 "\n", pChannel->our_msat, our_msat);
    LOGD("their_msat %" PRIu64 " --> %" PRIu64 "\n", pChannel->their_msat, their_msat);
    for (int lp = 0; lp < cnt; lp++) {
        LOGD("  [%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type == LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //FEE
    feeinfo.feerate_per_kw = pChannel->feerate_per_kw;
    feeinfo.dust_limit_satoshi = DustLimitSat;
    ln_script_fee_calc(&feeinfo, (const ln_script_htlcinfo_t **)pp_htlcinfo, cnt);

    //commitment transaction
    LOGD("local commitment_number=%" PRIu64 "\n", CommitNum);
    lntx_commit.fund.txid = ln_funding_txid(pChannel);
    lntx_commit.fund.txid_index = ln_funding_txindex(pChannel);
    lntx_commit.fund.satoshi = pChannel->funding_sat;
    lntx_commit.fund.p_script = &pChannel->redeem_fund;
    lntx_commit.local.satoshi = LN_MSAT2SATOSHI(our_msat);
    lntx_commit.local.p_script = &buf_ws;
    lntx_commit.remote.satoshi = LN_MSAT2SATOSHI(their_msat);
    lntx_commit.remote.pubkey = pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_PUBKEY];
    lntx_commit.obscured = pChannel->obscured ^ CommitNum;
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;
    ret = ln_script_committx_create(&tx_commit, &buf_sig, &lntx_commit, ln_is_funder(pChannel), &pChannel->keys_local);
    if (ret) {
        //2-of-2 verify
        ret = create_to_local_sign_verify(pChannel, &tx_commit, &buf_sig);
    } else {
        LOGE("fail\n");
    }
    if (ret) {
        ret = btc_tx_txid(&tx_commit, pChannel->commit_tx_local.txid);
        LOGD("local commit_txid: ");
        TXIDD(pChannel->commit_tx_local.txid);
    }
    if (ret) {
        ret = create_to_local_spent(pChannel,
                    pClose,
                    pHtlcSigs,
                    HtlcSigsNum,
                    &tx_commit,
                    &buf_ws,
                    (const ln_script_htlcinfo_t **)pp_htlcinfo,
                    &feeinfo,
                    ToSelfDelay);
    }

    LOGD("free: ret=%d\n", ret);
    utl_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_script_htlcinfo_free(pp_htlcinfo[lp]);
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


bool ln_comtx_create_to_remote(const ln_channel_t *pChannel,
                    ln_commit_tx_t *pCommit,
                    ln_close_force_t *pClose,
                    uint8_t **ppHtlcSigs,
                    uint64_t CommitNum)
{
    LOGD("BEGIN\n");

    bool ret;
    utl_buf_t buf_ws = UTL_BUF_INIT;
    utl_buf_t buf_sig = UTL_BUF_INIT;
    ln_script_feeinfo_t feeinfo;
    ln_script_committx_t lntx_commit;
    btc_tx_t tx_commit = BTC_TX_INIT;
    uint64_t our_msat = pChannel->their_msat;
    uint64_t their_msat = pChannel->our_msat;

    //To-Local
    ln_script_create_to_local(&buf_ws,
                pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
                pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_DELAYEDKEY],
                pChannel->commit_tx_remote.to_self_delay);

    //HTLC info(amount)
    ln_script_htlcinfo_t **pp_htlcinfo = (ln_script_htlcinfo_t **)UTL_DBG_MALLOC(sizeof(ln_script_htlcinfo_t*) * LN_HTLC_MAX);
    int cnt = 0;    //commit_txのvout数
    create_to_remote_htlcinfo(pChannel, pp_htlcinfo, &cnt, &our_msat, &their_msat);

    //HTLC info(script)
    for (int lp = 0; lp < cnt; lp++) {
        ln_script_htlcinfo_script(&pp_htlcinfo[lp]->script,
                        pp_htlcinfo[lp]->type,
                        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_LOCAL_HTLCKEY],
                        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REVOCATIONKEY],
                        pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
                        pp_htlcinfo[lp]->preimage_hash,
                        pp_htlcinfo[lp]->expiry);
#ifdef LN_UGLY_NORMAL
        //payment_hash, type, expiry保存
        utl_buf_t vout = UTL_BUF_INIT;
        btc_script_p2wsh_create_scriptsig(&vout, &pp_htlcinfo[lp]->script);
        ln_db_phash_save(pp_htlcinfo[lp]->preimage_hash,
                        vout.buf,
                        pp_htlcinfo[lp]->type,
                        pp_htlcinfo[lp]->expiry);
        utl_buf_free(&vout);
#endif  //LN_UGLY_NORMAL
    }

    LOGD("-------\n");
    LOGD("(remote)our_msat   %" PRIu64 " --> %" PRIu64 "\n", pChannel->their_msat, our_msat);
    LOGD("(remote)their_msat %" PRIu64 " --> %" PRIu64 "\n", pChannel->our_msat, their_msat);
    for (int lp = 0; lp < cnt; lp++) {
        LOGD("  have HTLC[%d] %" PRIu64 " (%s)\n", lp, pp_htlcinfo[lp]->amount_msat, (pp_htlcinfo[lp]->type != LN_HTLCTYPE_RECEIVED) ? "received" : "offered");
    }
    LOGD("-------\n");

    //FEE
    feeinfo.feerate_per_kw = pChannel->feerate_per_kw;
    feeinfo.dust_limit_satoshi = pCommit->dust_limit_sat;
    ln_script_fee_calc(&feeinfo, (const ln_script_htlcinfo_t **)pp_htlcinfo, cnt);

    //commitment transaction
    LOGD("remote commitment_number=%" PRIu64 "\n", CommitNum);
    lntx_commit.fund.txid = ln_funding_txid(pChannel);
    lntx_commit.fund.txid_index = ln_funding_txindex(pChannel);
    lntx_commit.fund.satoshi = pChannel->funding_sat;
    lntx_commit.fund.p_script = &pChannel->redeem_fund;
    lntx_commit.local.satoshi = LN_MSAT2SATOSHI(our_msat);
    lntx_commit.local.p_script = &buf_ws;
    lntx_commit.remote.satoshi = LN_MSAT2SATOSHI(their_msat);
    lntx_commit.remote.pubkey = pChannel->keys_remote.script_pubkeys[LN_SCRIPT_IDX_PUBKEY];
    lntx_commit.obscured = pChannel->obscured ^ CommitNum;
    lntx_commit.p_feeinfo = &feeinfo;
    lntx_commit.pp_htlcinfo = pp_htlcinfo;
    lntx_commit.htlcinfo_num = cnt;
    ret = ln_script_committx_create(&tx_commit, &buf_sig, &lntx_commit, !ln_is_funder(pChannel), &pChannel->keys_local);
    if (ret) {
        LOGD("++++++++++++++ remote commit tx: tx_commit[%016" PRIx64 "]\n", pChannel->short_channel_id);
        M_DBG_PRINT_TX(&tx_commit);

        ret = btc_tx_txid(&tx_commit, pCommit->txid);
        LOGD("remote commit_txid: ");
        TXIDD(pCommit->txid);
    }

    if (ret) {
        //送信用 commitment_signed.signature
        btc_sig_der2rs(pCommit->signature, buf_sig.buf, buf_sig.len);
    }

    if (ret) {
        uint8_t *p_htlc_sigs = NULL;
        if (cnt > 0) {
            if (ppHtlcSigs != NULL) {
                //送信用 commitment_signed.htlc_signature
                *ppHtlcSigs = (uint8_t *)UTL_DBG_MALLOC(LN_SZ_SIGNATURE * cnt);
                p_htlc_sigs = *ppHtlcSigs;
            }
        }
        ret = create_to_remote_spent(pChannel,
                    pCommit,
                    pClose,
                    p_htlc_sigs,
                    &tx_commit, &buf_ws,
                    (const ln_script_htlcinfo_t **)pp_htlcinfo,
                    &feeinfo);
    }

    LOGD("free: ret=%d\n", ret);
    utl_buf_free(&buf_ws);
    for (int lp = 0; lp < cnt; lp++) {
        ln_script_htlcinfo_free(pp_htlcinfo[lp]);
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


bool ln_comtx_set_vin_p2wsh_2of2(btc_tx_t *pTx, int Index, btc_script_pubkey_order_t Sort,
                    const utl_buf_t *pSig1,
                    const utl_buf_t *pSig2,
                    const utl_buf_t *pWit2of2)
{
    // 0
    // <sig1>
    // <sig2>
    // <script>
    const utl_buf_t wit0 = UTL_BUF_INIT;
    const utl_buf_t *wits[] = {
        &wit0,
        NULL,
        NULL,
        pWit2of2
    };
    if (Sort == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
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


/********************************************************************
 * private functions
 ********************************************************************/

static void create_to_local_htlcinfo_amount(const ln_channel_t *pChannel,
                    ln_script_htlcinfo_t **ppHtlcInfo,
                    int *pCnt,
                    uint64_t *pOurMsat,
                    uint64_t *pTheirMsat)
{
    int cnt = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        const ln_update_add_htlc_t *p_htlc = &pChannel->cnl_add_htlc[idx];
        if (LN_HTLC_ENABLE(p_htlc)) {
            bool htlcadd = false;
            if (LN_HTLC_ENABLE_LOCAL_ADDHTLC_OFFER(p_htlc) || LN_HTLC_ENABLE_LOCAL_FULFILL_OFFER(p_htlc)) {
                *pOurMsat -= p_htlc->amount_msat;

                if (LN_HTLC_ENABLE_LOCAL_ADDHTLC_OFFER(p_htlc)) {
                    LOGD("addhtlc_offer\n");
                    htlcadd = true;
                } else {
                    LOGD("delhtlc_offer\n");
                    *pTheirMsat += p_htlc->amount_msat;
                }
            }
            if (LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(p_htlc) || LN_HTLC_ENABLE_LOCAL_FULFILL_RECV(p_htlc)) {
                *pTheirMsat -= p_htlc->amount_msat;

                if (LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(p_htlc)) {
                    LOGD("addhtlc_recv\n");
                    htlcadd = true;
                } else {
                    LOGD("delhtlc_recv\n");
                    *pOurMsat += p_htlc->amount_msat;
                }
            }
            if (htlcadd) {
                ppHtlcInfo[cnt] = (ln_script_htlcinfo_t *)UTL_DBG_MALLOC(sizeof(ln_script_htlcinfo_t));
                ln_script_htlcinfo_init(ppHtlcInfo[cnt]);
                switch (p_htlc->stat.flag.addhtlc) {
                case LN_ADDHTLC_RECV:
                    ppHtlcInfo[cnt]->type = LN_HTLCTYPE_RECEIVED;
                    break;
                case LN_ADDHTLC_OFFER:
                    ppHtlcInfo[cnt]->type = LN_HTLCTYPE_OFFERED;
                    break;
                default:
                    LOGE("unknown flag: %04x\n", p_htlc->stat.bits);
                }
                ppHtlcInfo[cnt]->add_htlc_idx = idx;
                ppHtlcInfo[cnt]->expiry = p_htlc->cltv_expiry;
                ppHtlcInfo[cnt]->amount_msat = p_htlc->amount_msat;
                ppHtlcInfo[cnt]->preimage_hash = p_htlc->payment_sha256;

                LOGD(" ADD[%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, p_htlc->id, p_htlc->amount_msat);
                cnt++;
            } else {
                LOGD(" DEL[%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, p_htlc->id, p_htlc->amount_msat);
            }
        }
    }
    *pCnt = cnt;
}


/** commit_tx署名verify
 *
 * @param[in,out]   pChannel
 * @param[in,out]   pTxCommit   [in]commit_tx(署名無し) / [out]commit_tx(署名あり)
 * @param[in]       pBufSig     相手の署名
 * @retval  true    成功
 */
static bool create_to_local_sign_verify(const ln_channel_t *pChannel,
                    btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufSig)
{
    LOGD("local verify\n");

    bool ret;
    utl_buf_t buf_sig_from_remote = UTL_BUF_INIT;
    utl_buf_t script_code = UTL_BUF_INIT;
    uint8_t sighash[BTC_SZ_HASH256];

    //署名追加
    btc_sig_rs2der(&buf_sig_from_remote, pChannel->commit_tx_local.signature);
    ln_comtx_set_vin_p2wsh_2of2(pTxCommit, 0, pChannel->key_fund_sort,
                            pBufSig,
                            &buf_sig_from_remote,
                            &pChannel->redeem_fund);
    LOGD("++++++++++++++ local commit tx: [%016" PRIx64 "]\n", pChannel->short_channel_id);
    M_DBG_PRINT_TX(pTxCommit);

    // verify
    btc_script_p2wsh_create_scriptcode(&script_code, &pChannel->redeem_fund);
    ret = btc_sw_sighash(pTxCommit, sighash, 0, pChannel->funding_sat, &script_code);
    if (ret) {
        ret = btc_sw_verify_p2wsh_2of2(pTxCommit, 0, sighash,
                &pChannel->tx_funding.vout[ln_funding_txindex(pChannel)].script);
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
 * @param[in,out]   pChannel
 * @param[out]      pClose
 * @param[in]       pHtlcSigs
 * @param[in]       HtlcSigsNum
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       ppHtlcInfo
 * @param[in]       pFeeInfo
 * @param[in]       ToSelfDelay
 * @retval  true    成功
 */
static bool create_to_local_spent(ln_channel_t *pChannel,
                    ln_close_force_t *pClose,
                    const uint8_t *pHtlcSigs,
                    uint8_t HtlcSigsNum,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t **ppHtlcInfo,
                    const ln_script_feeinfo_t *pFeeInfo,
                    uint32_t ToSelfDelay)
{
    bool ret = true;
    uint16_t htlc_num = 0;
    btc_tx_t *pCloseTxToLocal = NULL;
    btc_tx_t *pCloseTxHtlcs = NULL;
    utl_push_t push;
    btc_keys_t htlckey;

    if (pClose != NULL) {
        pCloseTxToLocal = &pClose->p_tx[LN_CLOSE_IDX_TO_LOCAL];
        pCloseTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];

        utl_push_init(&push, &pClose->tx_buf, 0);

        //HTLC署名用鍵
        ln_signer_htlc_localkey(&htlckey, &pChannel->keys_local);
    } else {
        push.data = NULL;
    }

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        uint8_t htlc_idx = pTxCommit->vout[vout_idx].opt;
        if (htlc_idx == LN_HTLCTYPE_TO_LOCAL) {
            LOGD("+++[%d]to_local\n", vout_idx);
            ret = create_to_local_spentlocal(pChannel,
                        pCloseTxToLocal,
                        pBufWs,
                        pTxCommit->vout[vout_idx].value,
                        vout_idx,
                        ToSelfDelay);
        } else if (htlc_idx == LN_HTLCTYPE_TO_REMOTE) {
            LOGD("+++[%d]to_remote\n", vout_idx);
        } else {
            const ln_script_htlcinfo_t *p_htlcinfo = ppHtlcInfo[htlc_idx];
            uint64_t fee_sat = (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? pFeeInfo->htlc_timeout : pFeeInfo->htlc_success;
            LOGD("+++[%d]%s HTLC\n", vout_idx, (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? "offered" : "received");
            assert(pTxCommit->vout[vout_idx].value >= pFeeInfo->dust_limit_satoshi + fee_sat);

            btc_tx_t tx = BTC_TX_INIT;
            ln_script_htlctx_create(&tx,
                        pTxCommit->vout[vout_idx].value - fee_sat,
                        pBufWs,
                        p_htlcinfo->type,
                        p_htlcinfo->expiry,
                        pChannel->commit_tx_local.txid, vout_idx);

            if ((pHtlcSigs != NULL) && (HtlcSigsNum != 0)) {
                //HTLC署名があるなら、verify
                //  - commitment_signed受信
                ret = create_to_local_htlcverify(pChannel,
                            &tx,
                            pHtlcSigs + htlc_num * LN_SZ_SIGNATURE,
                            &p_htlcinfo->script,
                            pTxCommit->vout[vout_idx].value);
                if (ret) {
                    //OKなら各HTLCに保持
                    //  相手がunilateral closeした後に送信しなかったら、この署名を使う
                    memcpy(pChannel->cnl_add_htlc[p_htlcinfo->add_htlc_idx].signature, pHtlcSigs + htlc_num * LN_SZ_SIGNATURE, LN_SZ_SIGNATURE);
                } else {
                    break;
                }
            } else if (pClose != NULL) {
                //unilateral closeデータを作成
                //  - unilateral close要求
                ret = create_to_local_spenthtlc(pChannel,
                                &pCloseTxHtlcs[htlc_num],
                                &tx,
                                &push,
                                pTxCommit->vout[vout_idx].value,
                                pBufWs,
                                p_htlcinfo,
                                &htlckey,
                                ToSelfDelay);
                if (ret) {
                    pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                } else {
                    LOGE("fail: sign vout[%d]\n", vout_idx);
                    break;
                }
            } else {
                //HTLC署名なし、close要求なし
                //  - funding_created受信
                //  - funding_signed受信
            }
            btc_tx_free(&tx);

            htlc_num++;
        }
    }

    if ((pHtlcSigs != NULL) && (htlc_num != HtlcSigsNum)) {
        LOGE("署名数不一致: %d, %d\n", htlc_num, HtlcSigsNum);
        ret = false;
    }

    pChannel->commit_tx_local.htlc_num = htlc_num;

    return ret;
}


/** to_localをwalletに保存する情報作成
 *
 * @param[out]      pTxToLocal
 *
 * @note
 *  - pTxToLocalはbtc_tx_tフォーマットだが、blockchainに展開できるデータではない
 */
static bool create_to_local_spentlocal(const ln_channel_t *pChannel,
                    btc_tx_t *pTxToLocal,
                    const utl_buf_t *pBufWs,
                    uint64_t Amount,
                    uint32_t VoutIdx,
                    uint32_t ToSelfDelay)
{
    bool ret;
    if (pTxToLocal != NULL) {
        btc_tx_t tx = BTC_TX_INIT;
        ret = ln_wallet_create_to_local(pChannel, &tx,
                Amount,
                ToSelfDelay,
                pBufWs, pChannel->commit_tx_local.txid, VoutIdx, false);
        if (ret) {
            memcpy(pTxToLocal, &tx, sizeof(tx));
            btc_tx_init(&tx);     //txはfreeさせない
        } else {
            btc_tx_free(&tx);
        }
    } else {
        ret = true;
    }
    return ret;
}


static bool create_to_local_htlcverify(const ln_channel_t *pChannel,
                    btc_tx_t *pTx,
                    const uint8_t *pHtlcSig,
                    const utl_buf_t *pScript,
                    uint64_t Amount)
{
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, pHtlcSig);

    bool ret = ln_script_htlctx_verify(pTx,
                Amount,
                NULL,
                pChannel->keys_local.script_pubkeys[LN_SCRIPT_IDX_REMOTE_HTLCKEY],
                NULL,
                &buf_sig,
                pScript);
    utl_buf_free(&buf_sig);
    if (ret) {
        M_DBG_PRINT_TX2(pTx);
    } else {
        LOGE("fail: verify vout\n");
        btc_tx_free(pTx);
    }

    return ret;
}


/** local close後のHTLC_txからの送金情報作成
 *
 *  1. input署名をASN.1形式に展開
 *  2. [received HTLC]DBからpreimage検索
 *  3. HTLC Success/Timeout tx署名(呼び元でtx作成済み)
 *      - エラー時はここで終了
 *  4. [(received HTLC && preimageあり) || offered HTLC]
 *      -# 署名したHTLC txを処理結果にコピー
 *      -# HTLC txの送金を取り戻すtxを作成 + 署名(形はto_localと同じ) --> キューに積む
 *
 * @param[in,out]   pChannel
 * @param[out]      pCloseTxHtlcs   処理結果のHTLC tx配列(末尾に追加)
 * @param[in,out]   pTxHtlc         [in]処理中のHTLC tx(署名無し) / [out]HTLC tx(署名あり)
 * @param[out]      pPush           HTLC txから取り戻すtxのwallet情報
 * @param[in]       Amount
 * @param[in]       pBufWs
 * @param[in]       pHtlcInfo
 * @param[in]       pHtlcKey
 * @param[in]       ToSelfDelay
 * @retval  true    成功
 */
static bool create_to_local_spenthtlc(const ln_channel_t *pChannel,
                    btc_tx_t *pCloseTxHtlc,
                    btc_tx_t *pTxHtlc,
                    utl_push_t *pPush,
                    uint64_t Amount,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t *pHtlcInfo,
                    const btc_keys_t *pHtlcKey,
                    uint32_t ToSelfDelay)
{
    bool ret;
    utl_buf_t buf_local_sig = UTL_BUF_INIT;
    utl_buf_t buf_remote_sig = UTL_BUF_INIT;
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    uint8_t txid[BTC_SZ_TXID];

    btc_sig_rs2der(&buf_remote_sig,
                pChannel->cnl_add_htlc[pHtlcInfo->add_htlc_idx].signature);

    if (pHtlcInfo->type == LN_HTLCTYPE_RECEIVED) {
        //Receivedであればpreimageを所持している可能性がある
        ret_img = search_preimage(preimage,
                        pChannel->cnl_add_htlc[pHtlcInfo->add_htlc_idx].payment_sha256,
                        true);
        LOGD("[received]have preimage=%s\n", (ret_img) ? "yes" : "NO");
    } else {
        ret_img = false;
        LOGD("[offered]\n");
    }
    if ( ((pHtlcInfo->type == LN_HTLCTYPE_RECEIVED) && ret_img) ||
            (pHtlcInfo->type == LN_HTLCTYPE_OFFERED) ) {
        //継続
    } else {
        LOGD("skip create HTLC tx\n");
        btc_tx_init(pCloseTxHtlc);
        ret = true;
        goto LABEL_EXIT;
    }

    //署名:HTLC Success/Timeout Transaction
    ret = ln_script_htlctx_sign(pTxHtlc,
                &buf_local_sig,
                Amount,
                pHtlcKey,
                &pHtlcInfo->script);
    if (ret) {
        ret = ln_script_htlctx_wit(pTxHtlc,
                &buf_local_sig,
                pHtlcKey,
                &buf_remote_sig,
                (ret_img) ? preimage : NULL,
                &pHtlcInfo->script,
                LN_HTLCSIGN_TIMEOUT_SUCCESS);
    }
    utl_buf_free(&buf_remote_sig);
    utl_buf_free(&buf_local_sig);
    if (!ret) {
        LOGE("fail: sign_htlc_tx: vout\n");
        goto LABEL_EXIT;
    }
    M_DBG_PRINT_TX2(pTxHtlc);

    //署名したHTLC_txを上位に返して展開してもらう(sequence/locktimeのため展開されないかもしれない)
    memcpy(pCloseTxHtlc, pTxHtlc, sizeof(btc_tx_t));

    // HTLC Timeout/Success Txを作った場合はそれを取り戻す準備をする
    btc_tx_txid(pTxHtlc, txid);
    ret = ln_wallet_create_to_local(pChannel, &tx,
                pTxHtlc->vout[0].value,
                ToSelfDelay,
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

LABEL_EXIT:
    return ret;
}


static void create_to_remote_htlcinfo(const ln_channel_t *pChannel,
                    ln_script_htlcinfo_t **ppHtlcInfo,
                    int *pCnt,
                    uint64_t *pOurMsat,
                    uint64_t *pTheirMsat)
{
    int cnt = 0;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        const ln_update_add_htlc_t *p_htlc = &pChannel->cnl_add_htlc[idx];
        if (LN_HTLC_ENABLE(p_htlc)) {
            bool htlcadd = false;
            if (LN_HTLC_ENABLE_REMOTE_ADDHTLC_OFFER(p_htlc) || LN_HTLC_ENABLE_REMOTE_FULFILL_OFFER(p_htlc)) {
                *pTheirMsat -= p_htlc->amount_msat;

                if (LN_HTLC_ENABLE_REMOTE_ADDHTLC_OFFER(p_htlc)) {
                    LOGD("addhtlc_offer\n");
                    htlcadd = true;
                } else {
                    LOGD("delhtlc_offer\n");
                    *pOurMsat += p_htlc->amount_msat;
                }
            }
            if (LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(p_htlc) || LN_HTLC_ENABLE_REMOTE_FULFILL_RECV(p_htlc)) {
                *pOurMsat -= p_htlc->amount_msat;

                if (LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(p_htlc)) {
                    LOGD("addhtlc_recv\n");
                    htlcadd = true;
                } else {
                    LOGD("delhtlc_recv\n");
                    *pTheirMsat += p_htlc->amount_msat;
                }
            }
            if (htlcadd) {
                ppHtlcInfo[cnt] = (ln_script_htlcinfo_t *)UTL_DBG_MALLOC(sizeof(ln_script_htlcinfo_t));
                ln_script_htlcinfo_init(ppHtlcInfo[cnt]);
                //OFFEREDとRECEIVEDが逆になる
                switch (p_htlc->stat.flag.addhtlc) {
                case LN_ADDHTLC_RECV:
                    ppHtlcInfo[cnt]->type = LN_HTLCTYPE_OFFERED;
                    break;
                case LN_ADDHTLC_OFFER:
                    ppHtlcInfo[cnt]->type = LN_HTLCTYPE_RECEIVED;
                    break;
                default:
                    LOGE("unknown flag: %04x\n", p_htlc->stat.bits);
                }
                ppHtlcInfo[cnt]->add_htlc_idx = idx;
                ppHtlcInfo[cnt]->expiry = p_htlc->cltv_expiry;
                ppHtlcInfo[cnt]->amount_msat = p_htlc->amount_msat;
                ppHtlcInfo[cnt]->preimage_hash = p_htlc->payment_sha256;

                LOGD(" ADD[%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, p_htlc->id, p_htlc->amount_msat);
                cnt++;
            } else {
                LOGD(" DEL[%d][id=%" PRIu64 "](%" PRIu64 ")\n", idx, p_htlc->id, p_htlc->amount_msat);
            }
        }
    }

    *pCnt = cnt;
}


/** remote commit_txの送金先処理
 *
 *  1. [close]HTLC署名用local_htlcsecret取得
 *  2. voutごとの処理
 *      2.1. vout indexから対応するppHtlcInfo[]を得る --> htlc_idx
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
 * @param[in,out]   pChannel
 * @param[out]      pClose
 * @param[out]      pHtlcSigs
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       ppHtlcInfo
 * @param[in]       pFeeInfo
 * @retval  true    成功
 */
static bool create_to_remote_spent(const ln_channel_t *pChannel,
                    ln_commit_tx_t *pCommit,
                    ln_close_force_t *pClose,
                    uint8_t *pHtlcSigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t **ppHtlcInfo,
                    const ln_script_feeinfo_t *pFeeInfo)
{
    bool ret = true;
    uint16_t htlc_num = 0;

    btc_tx_t *pTxHtlcs = NULL;
    if (pClose != NULL) {
        pTxHtlcs = &pClose->p_tx[LN_CLOSE_IDX_HTLC];
    }

    utl_buf_t buf_remotesig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_remotesig, pChannel->commit_tx_local.signature);

    //HTLC署名用鍵
    btc_keys_t htlckey;
    ln_signer_htlc_remotekey(&htlckey, &pChannel->keys_local, &pChannel->keys_remote);

    for (uint32_t vout_idx = 0; vout_idx < pTxCommit->vout_cnt; vout_idx++) {
        //各HTLCのHTLC Timeout/Success Transactionを作って署名するために、
        //BIP69ソート後のtx_commit.voutからppHtlcInfo[]のindexを取得する
        uint8_t htlc_idx = pTxCommit->vout[vout_idx].opt;

        if (htlc_idx == LN_HTLCTYPE_TO_LOCAL) {
            LOGD("---[%d]to_local\n", vout_idx);
        } else if (htlc_idx == LN_HTLCTYPE_TO_REMOTE) {
            LOGD("---[%d]to_remote\n", vout_idx);
            if (pClose != NULL) {
                btc_tx_t tx = BTC_TX_INIT;

                //wallet保存用のデータ作成
                ret = ln_wallet_create_to_remote(
                            pChannel, &tx, pTxCommit->vout[vout_idx].value,
                            pCommit->txid, vout_idx);
                if (ret) {
                    memcpy(&pClose->p_tx[LN_CLOSE_IDX_TO_REMOTE], &tx, sizeof(tx));
                    btc_tx_init(&tx);     //txはfreeさせない
                } else {
                    LOGD("no to_remote output\n");
                    btc_tx_free(&tx);
                    ret = true;     //継続する
                }
            }
        } else {
            const ln_script_htlcinfo_t *p_htlcinfo = ppHtlcInfo[htlc_idx];
            const uint8_t *p_payhash = pChannel->cnl_add_htlc[p_htlcinfo->add_htlc_idx].payment_sha256;
            uint64_t fee_sat = (p_htlcinfo->type == LN_HTLCTYPE_OFFERED) ? pFeeInfo->htlc_timeout : pFeeInfo->htlc_success;
            if (pTxCommit->vout[vout_idx].value >= pFeeInfo->dust_limit_satoshi + fee_sat) {
                ret = create_to_remote_spenthtlc(
                                pCommit,
                                pTxHtlcs,
                                pHtlcSigs,
                                pTxCommit,
                                pBufWs,
                                p_htlcinfo,
                                &htlckey,
                                &buf_remotesig,
                                fee_sat,
                                htlc_num,
                                vout_idx,
                                p_payhash,
                                (pClose != NULL));
                if (ret) {
                    if (pClose != NULL) {
                        pClose->p_htlc_idx[LN_CLOSE_IDX_HTLC + htlc_num] = htlc_idx;
                    }
                } else {
                    LOGE("fail: sign vout[%d]\n", vout_idx);
                    break;
                }

                htlc_num++;
            } else {
                LOGD("cut HTLC[%d] %" PRIu64 " > %" PRIu64 "\n",
                            vout_idx, pTxCommit->vout[vout_idx].value,
                            pFeeInfo->dust_limit_satoshi + fee_sat);
            }
        }
    }
    utl_buf_free(&buf_remotesig);

    pCommit->htlc_num = htlc_num;

    return ret;
}


/** remote HTLCからの送金先情報作成
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
 * @param[in,out]   pChannel
 * @param[out]      pTxHtlcs        Close処理結果のHTLC tx配列(末尾に追加)
 * @param[out]      pHtlcSigs     HTLC署名
 * @param[in]       pTxCommit
 * @param[in]       pBufWs
 * @param[in]       pHtlcInfo
 * @param[in]       pHtlcKey
 * @param[in]       pBufRemoteSig
 * @param[in]       Fee
 * @param[in]       HtlcNum
 * @param[in]       VoutIdx
 * @param[in]       pPayHash
 * @param[in]       bClosing        true:close処理
 * @retval  true    成功
 */
static bool create_to_remote_spenthtlc(
                    ln_commit_tx_t *pCommit,
                    btc_tx_t *pTxHtlcs,
                    uint8_t *pHtlcSigs,
                    const btc_tx_t *pTxCommit,
                    const utl_buf_t *pBufWs,
                    const ln_script_htlcinfo_t *pHtlcInfo,
                    const btc_keys_t *pHtlcKey,
                    const utl_buf_t *pBufRemoteSig,
                    uint64_t Fee,
                    uint8_t HtlcNum,
                    uint32_t VoutIdx,
                    const uint8_t *pPayHash,
                    bool bClosing)
{
    bool ret = false;
    btc_tx_t tx = BTC_TX_INIT;

    LOGD("---HTLC[%d]\n", VoutIdx);
    ln_script_htlctx_create(&tx, pTxCommit->vout[VoutIdx].value - Fee, pBufWs,
                pHtlcInfo->type, pHtlcInfo->expiry,
                pCommit->txid, VoutIdx);

    uint8_t preimage[LN_SZ_PREIMAGE];
    bool ret_img;
    bool b_save = false;        //true: pTxHtlcs[HtlcNum]に残したい
    ln_script_htlcsign_t htlcsign = LN_HTLCSIGN_TIMEOUT_SUCCESS;
    if (pHtlcInfo->type == LN_HTLCTYPE_OFFERED) {
        //remoteのoffered=自分のreceivedなのでpreimageを所持している可能性がある
        ret_img = search_preimage(preimage, pPayHash, bClosing);
        if (ret_img && (pTxHtlcs != NULL)) {
            LOGD("[offered]have preimage\n");
            //offeredかつpreimageがあるので、即時使用可能

            utl_buf_free(&tx.vout[0].script);
            //wit[0]に署名用秘密鍵を設定しておく(wallet用)
            utl_buf_t buf_key = { (CONST_CAST uint8_t *)pHtlcKey->priv, BTC_SZ_PRIVKEY };
            tx.locktime = 0;
            ret = ln_script_htlctx_wit(&tx,
                &buf_key,
                pHtlcKey,
                NULL,
                (ret_img) ? preimage : NULL,
                &pHtlcInfo->script,
                LN_HTLCSIGN_REMOTE_OFFER);
            htlcsign = LN_HTLCSIGN_NONE;
        } else if (!ret_img) {
            //preimageがないためHTLCを解くことができない
            //  --> 署名はしてpTxHtlcs[HtlcNum]に残す
            LOGD("[offered]no preimage\n");
            //htlcsign = LN_HTLCSIGN_NONE;
            b_save = true;
            ret = true;
        } else {
            //署名のみ作成(commitment_signed用)
            LOGD("[offered]only sign\n");
            ret = true;
        }
    } else {
        //remoteのreceived=自分がofferedしているでtimeoutしたら取り戻す
        LOGD("[received]\n");

        ret_img = false;
        if (pTxHtlcs != NULL) {
            //タイムアウト待ち
            //  -->署名はしないがpTxHtlcs[HtlcNum]に残したい

            utl_buf_free(&tx.vout[0].script);
            //wit[0]に署名用秘密鍵を設定しておく(wallet用)
            utl_buf_t buf_key = { (CONST_CAST uint8_t *)pHtlcKey->priv, BTC_SZ_PRIVKEY };
            tx.locktime = pHtlcInfo->expiry;
            ret = ln_script_htlctx_wit(&tx,
                &buf_key,
                pHtlcKey,
                NULL,
                NULL,
                &pHtlcInfo->script,
                LN_HTLCSIGN_REMOTE_RECV);
            htlcsign = LN_HTLCSIGN_NONE;
        }
    }

    //署名
    if (htlcsign != LN_HTLCSIGN_NONE) {
        utl_buf_t buf_localsig = UTL_BUF_INIT;
        ret = ln_script_htlctx_sign(&tx,
                    &buf_localsig,
                    pTxCommit->vout[VoutIdx].value,
                    pHtlcKey,
                    &pHtlcInfo->script);
        if (ret && (pHtlcSigs != NULL)) {
            btc_sig_der2rs(pHtlcSigs + LN_SZ_SIGNATURE * HtlcNum, buf_localsig.buf, buf_localsig.len);
        }
        if (ret) {
            ret = ln_script_htlctx_wit(&tx,
                    &buf_localsig,
                    pHtlcKey,
                    pBufRemoteSig,
                    (ret_img) ? preimage : NULL,
                    &pHtlcInfo->script,
                    htlcsign);
        }
        utl_buf_free(&buf_localsig);
        if (!ret) {
            LOGE("fail: sign_htlc_tx: vout[%d]\n", VoutIdx);
            goto LABEL_EXIT;
        }
    }

    if (pTxHtlcs != NULL) {
        if ( ((pHtlcInfo->type == LN_HTLCTYPE_OFFERED) && ret_img) ||
                (pHtlcInfo->type == LN_HTLCTYPE_RECEIVED) ||
                b_save ) {
            LOGD("create HTLC tx[%d]\n", HtlcNum);
            memcpy(&pTxHtlcs[HtlcNum], &tx, sizeof(tx));
            btc_tx_init(&tx);     //txはfreeさせない(pTxHtlcsに任せる)
        } else {
            LOGD("skip create HTLC tx[%d]\n", HtlcNum);
            btc_tx_init(&pTxHtlcs[HtlcNum]);
        }
    }

LABEL_EXIT:
    btc_tx_free(&tx);

    return ret;
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
        LOGE("DBG: HTLC preimage mismatch\n");
        return false;
    }
    // LOGD("pPayHash(%d)=", bClosing);
    // DUMPD(pPayHash, BTC_SZ_HASH256);

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
    uint8_t preimage_hash[BTC_SZ_HASH256];
    bool ret = false;

    //LOGD("compare preimage : ");
    //DUMPD(pPreImage, LN_SZ_PREIMAGE);
    ln_preimage_hash_calc(preimage_hash, pPreImage);
    if (memcmp(preimage_hash, prm->hash, BTC_SZ_HASH256) == 0) {
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
