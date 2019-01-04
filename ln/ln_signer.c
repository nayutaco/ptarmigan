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
/** @file   ln_signer.c
 *  @brief  [LN]秘密鍵管理
 */

#include "btc_util.h"
#include "btc_segwit_addr.h"
#include "btc_sig.h"
#include "btc_script.h"
#include "btc_sw.h"

#include "ln_signer.h"
#include "ln_derkey.h"
#include "ln_node.h"
#include "ln_misc.h"
#include "ln_local.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static void create_percommitsec(const ln_self_t *self, uint8_t *pSecret, uint8_t *pPerCommitPt, uint64_t Offset);
static void get_secret(const ln_self_t *self, btc_keys_t *pKeys, int MsgFundIdx, const uint8_t *pPerCommit);


/**************************************************************************
 * library functions
 **************************************************************************/

void HIDDEN ln_signer_init(ln_self_t *self, const uint8_t *pSeed)
{
    if (pSeed) {
        memcpy(self->priv_data.storage_seed, pSeed, LN_SZ_SEED);
        ln_derkey_storage_init(&self->peer_storage);
    }
}


void HIDDEN ln_signer_term(ln_self_t *self)
{
    memset(self->priv_data.storage_seed, 0, BTC_SZ_PRIVKEY);
}


void HIDDEN ln_signer_create_channelkeys(ln_self_t *self)
{
    self->priv_data.storage_index = LN_SECINDEX_INIT;
    LOGD("storage_index = %016" PRIx64 "\n", self->priv_data.storage_index);

    //鍵生成
    //  open_channel/accept_channelの鍵は ln_signer_keys_update_storage()で生成
    for (int lp = MSG_FUNDIDX_FUNDING; lp < LN_FUNDIDX_MAX; lp++) {
        if (lp != MSG_FUNDIDX_PER_COMMIT) {
            btc_util_create_privkey(self->priv_data.priv[lp]);
            btc_keys_priv2pub(self->funding_local.pubkeys[lp], self->priv_data.priv[lp]);
        }
    }

    ln_signer_keys_update_storage(self);
}


void HIDDEN ln_signer_keys_update_storage(ln_self_t *self)
{
    ln_signer_keys_update_force(self, self->priv_data.storage_index);

    self->priv_data.storage_index--;
    LOGD("update storage_index = %016" PRIx64 "\n", self->priv_data.storage_index);
}


void HIDDEN ln_signer_keys_update_force(ln_self_t *self, uint64_t Index)
{
    create_percommitsec(self, self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT], self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT], Index);
    LOGD("shachain index=%" PRIu64 "\n", Index);
}


void HIDDEN ln_signer_create_prev_percommitsec(const ln_self_t *self, uint8_t *pSecret, uint8_t *pPerCommitPt)
{
    if (self->priv_data.storage_index + 2 <= LN_SECINDEX_INIT) {
        //  現在の funding_local.keys[MSG_FUNDIDX_PER_COMMIT]はself->storage_indexから生成されていて、「次のper_commitment_secret」になる。
        //  最後に使用した値は self->storage_index + 1で、これが「現在のper_commitment_secret」になる。
        //  そのため、「1つ前のper_commitment_secret」は self->storage_index + 2 となる。
        create_percommitsec(self, pSecret, pPerCommitPt, self->priv_data.storage_index + 2);
    } else {
        memset(pSecret, 0, BTC_SZ_PRIVKEY);
        if (pPerCommitPt != NULL) {
            memcpy(pPerCommitPt, self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT], BTC_SZ_PUBKEY);
        }
    }
}


void HIDDEN ln_signer_get_revokesec(const ln_self_t *self, btc_keys_t *pKeys, const uint8_t *pPerCommit, const uint8_t *pRevokedSec)
{
    ln_derkey_revocationprivkey(pKeys->priv,
                self->funding_local.pubkeys[MSG_FUNDIDX_REVOCATION],
                pPerCommit,
                self->priv_data.priv[MSG_FUNDIDX_REVOCATION],
                pRevokedSec);
    btc_keys_priv2pub(pKeys->pub, pKeys->priv);
}


bool HIDDEN ln_signer_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const ln_self_priv_t *pPrivData, int PrivIndex)
{
    return btc_sig_sign(pSig, pTxHash, pPrivData->priv[PrivIndex]);
}


bool HIDDEN ln_signer_p2wsh_force(utl_buf_t *pSig, const uint8_t *pTxHash, const btc_keys_t *pKeys)
{
    return btc_sig_sign(pSig, pTxHash, pKeys->priv);
}


bool HIDDEN ln_signer_p2wpkh(btc_tx_t *pTx, int Index, uint64_t Value, const btc_keys_t *pKeys)
{
    bool ret;
    uint8_t txhash[BTC_SZ_HASH256];
    utl_buf_t sigbuf = UTL_BUF_INIT;
    utl_buf_t script_code = UTL_BUF_INIT;

    btc_scriptcode_p2wpkh(&script_code, pKeys->pub);

    ret = btc_sw_sighash(txhash, pTx, Index, Value, &script_code);
    if (ret) {
        ret = btc_sig_sign(&sigbuf, txhash, pKeys->priv);
    }
    if (ret) {
        //mNativeSegwitがfalseの場合はscriptSigへの追加も行う
        btc_sw_set_vin_p2wpkh(pTx, Index, &sigbuf, pKeys->pub);
    }

    utl_buf_free(&sigbuf);
    utl_buf_free(&script_code);

    return ret;
}


bool HIDDEN ln_signer_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const ln_self_priv_t *pPrivData, int PrivIndex)
{
    return btc_sig_sign_rs(pRS, pTxHash, pPrivData->priv[PrivIndex]);
}


void HIDDEN ln_signer_tolocal_key(const ln_self_t *self, btc_keys_t *pKey, bool bRevoked)
{
    if (!bRevoked) {
        //<delayed_secretkey>
        get_secret(self, pKey, MSG_FUNDIDX_DELAYED,
            self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
    } else {
        //<revocationsecretkey>
        ln_signer_get_revokesec(self, pKey,
                    self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
                    self->revoked_sec.buf);
    }
}


void HIDDEN ln_signer_toremote_key(const ln_self_t *self, btc_keys_t *pKey)
{
    get_secret(self, pKey, MSG_FUNDIDX_PAYMENT,
        self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
}


void HIDDEN ln_signer_htlc_localkey(const ln_self_t *self, btc_keys_t *pKey)
{
    get_secret(self, pKey, MSG_FUNDIDX_HTLC,
        self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
}


void HIDDEN ln_signer_htlc_remotekey(const ln_self_t *self, btc_keys_t *pKey)
{
    get_secret(self, pKey, MSG_FUNDIDX_HTLC,
        self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
}


bool HIDDEN ln_signer_tolocal_tx(const ln_self_t *self, btc_tx_t *pTx,
                    utl_buf_t *pSig,
                    uint64_t Value,
                    const utl_buf_t *pWitScript, bool bRevoked)
{
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGD("fail: invalid vin/vout\n");
        return false;
    }

    btc_keys_t sigkey;
    ln_signer_tolocal_key(self, &sigkey, bRevoked);

    bool ret;
    uint8_t sighash[BTC_SZ_HASH256];

    //vinは1つしかないので、Indexは0固定
    ret = btc_util_calc_sighash_p2wsh(pTx, sighash, 0, Value, pWitScript);
    if (ret) {
        ret = btc_sig_sign(pSig, sighash, sigkey.priv);
    }

    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** 指定したper_commit_secret取得
 *
 * @param[in,out]   self            チャネル情報
 * @param[out]      pSecret         per_commit_secret
 * @param[in]       Offset          storage_indexからのオフセット値
 */
static void create_percommitsec(const ln_self_t *self, uint8_t *pSecret, uint8_t *pPerCommitPt, uint64_t Index)
{
    ln_derkey_create_secret(pSecret, self->priv_data.storage_seed, Index);
    uint8_t pub[BTC_SZ_PUBKEY];
    btc_keys_priv2pub(pub, pSecret);
    if (pPerCommitPt != NULL) {
        memcpy(pPerCommitPt, pub, BTC_SZ_PUBKEY);
    }

    LOGD("PER_COMMIT_SEC(%016" PRIx64 "): ", Index);
    DUMPD(pSecret, BTC_SZ_PRIVKEY);
    LOGD("       PER_COMMIT_PT: ");
    DUMPD(pub, BTC_SZ_PUBKEY);
}


static void get_secret(const ln_self_t *self, btc_keys_t *pKeys, int MsgFundIdx, const uint8_t *pPerCommit)
{
    ln_derkey_privkey(pKeys->priv,
                self->funding_local.pubkeys[MsgFundIdx],
                pPerCommit,
                self->priv_data.priv[MsgFundIdx]);
    btc_keys_priv2pub(pKeys->pub, pKeys->priv);
}
