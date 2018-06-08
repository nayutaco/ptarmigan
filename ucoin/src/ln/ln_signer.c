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
 *  @author ueno@nayuta.co
 */
#include "ln_signer.h"
#include "ln_derkey.h"
#include "ln_node.h"
#include "ln_misc.h"

#include "segwit_addr.h"


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
    memset(self->priv_data.storage_seed, 0, UCOIN_SZ_PRIVKEY);
}


bool HIDDEN ln_signer_create_channelkeys(ln_self_t *self)
{
    self->priv_data.storage_index = LN_SECINDEX_INIT;
    LOGD("storage_index = %" PRIx64 "\n", self->priv_data.storage_index);

    //鍵生成
    //  open_channel/accept_channelの鍵は ln_signer_update_percommit_secret()で生成
    for (int lp = MSG_FUNDIDX_FUNDING; lp < LN_FUNDIDX_MAX; lp++) {
        if (lp != MSG_FUNDIDX_PER_COMMIT) {
            ucoin_util_createprivkey(self->priv_data.priv[lp]);
            ucoin_keys_priv2pub(self->funding_local.pubkeys[lp], self->priv_data.priv[lp]);
        }
    }
    ln_print_keys(&self->funding_local, &self->funding_remote);

    ln_signer_update_percommit_secret(self);

    return true;
}


void HIDDEN ln_signer_update_percommit_secret(ln_self_t *self)
{
    ln_signer_keys_update(self, 0);

    self->priv_data.storage_index--;
    LOGD("storage_index = %" PRIx64 "\n", self->priv_data.storage_index);

    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
}


void HIDDEN ln_signer_keys_update(ln_self_t *self, int64_t Offset)
{
    ln_signer_keys_update_force(self, self->priv_data.storage_index + Offset);
}


void HIDDEN ln_signer_keys_update_force(ln_self_t *self, uint64_t Index)
{
    ln_derkey_create_secret(self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT], self->priv_data.storage_seed, Index);
    ucoin_keys_priv2pub(self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT], self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT]);

    LOGD("Index = %" PRIx64 "\n", Index);
    LOGD("PER_COMMIT_SEC: ");
    DUMPD(self->priv_data.priv[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PRIVKEY);
    LOGD("PER_COMMIT_PT : ");
    DUMPD(self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT], UCOIN_SZ_PUBKEY);
}


void HIDDEN ln_signer_get_prevkey(const ln_self_t *self, uint8_t *pSecret)
{
    //  現在の funding_local.keys[MSG_FUNDIDX_PER_COMMIT]はself->storage_indexから生成されていて、「次のper_commitment_secret」になる。
    //  最後に使用した値は self->storage_index + 1で、これが「現在のper_commitment_secret」になる。
    //  そのため、「1つ前のper_commitment_secret」は self->storage_index + 2 となる。
    ln_derkey_create_secret(pSecret, self->priv_data.storage_seed, self->priv_data.storage_index + 2);

    LOGD("prev_secret(%" PRIx64 "): ", self->priv_data.storage_index + 2);
    DUMPD(pSecret, UCOIN_SZ_PRIVKEY);
    LOGD("       pub: ");
    uint8_t pub[UCOIN_SZ_PUBKEY];
    ucoin_keys_priv2pub(pub, pSecret);
    DUMPD(pub, UCOIN_SZ_PUBKEY);
}


void HIDDEN ln_signer_get_secret(const ln_self_t *self, ucoin_util_keys_t *pKeys, int MsgFundIdx, const uint8_t *pPerCommit)
{
    ln_derkey_privkey(pKeys->priv,
                self->funding_local.pubkeys[MsgFundIdx],
                pPerCommit,
                self->priv_data.priv[MsgFundIdx]);
    ucoin_keys_priv2pub(pKeys->pub, pKeys->priv);
}


void HIDDEN ln_signer_get_revokesec(const ln_self_t *self, ucoin_util_keys_t *pKeys, const uint8_t *pPerCommit, const uint8_t *pRevokedSec)
{
    ln_derkey_revocationprivkey(pKeys->priv,
                self->funding_local.pubkeys[MSG_FUNDIDX_REVOCATION],
                pPerCommit,
                self->priv_data.priv[MSG_FUNDIDX_REVOCATION],
                pRevokedSec);
    ucoin_keys_priv2pub(pKeys->pub, pKeys->priv);
}


bool HIDDEN ln_signer_p2wsh(ucoin_buf_t *pSig, const uint8_t *pTxHash, const ln_self_priv_t *pPrivData, int PrivIndex)
{
    return ucoin_tx_sign(pSig, pTxHash, pPrivData->priv[PrivIndex]);
}


bool HIDDEN ln_signer_p2wsh_force(ucoin_buf_t *pSig, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys)
{
    return ucoin_tx_sign(pSig, pTxHash, pKeys->priv);
}


bool HIDDEN ln_signer_p2wpkh(ucoin_tx_t *pTx, int Index, uint64_t Value, const ucoin_util_keys_t *pKeys)
{
    bool ret;
    uint8_t txhash[UCOIN_SZ_HASH256];
    ucoin_buf_t sigbuf = UCOIN_BUF_INIT;
    ucoin_buf_t script_code = UCOIN_BUF_INIT;

    ucoin_sw_scriptcode_p2wpkh(&script_code, pKeys->pub);

    ucoin_sw_sighash(txhash, pTx, Index, Value, &script_code);
    ret = ucoin_tx_sign(&sigbuf, txhash, pKeys->priv);
    if (ret) {
        //mNativeSegwitがfalseの場合はscriptSigへの追加も行う
        ucoin_sw_set_vin_p2wpkh(pTx, Index, &sigbuf, pKeys->pub);
    }

    ucoin_buf_free(&sigbuf);
    ucoin_buf_free(&script_code);

    return ret;
}


bool HIDDEN ln_signer_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const ln_self_priv_t *pPrivData, int PrivIndex)
{
    return ucoin_tx_sign_rs(pRS, pTxHash, pPrivData->priv[PrivIndex]);
}


bool HIDDEN ln_signer_tolocal_tx(const ln_self_t *self, ucoin_tx_t *pTx,
                    uint64_t Value,
                    const ucoin_buf_t *pWitScript, bool bRevoked)
{
    if ((pTx->vin_cnt != 1) || (pTx->vout_cnt != 1)) {
        LOGD("fail: invalid vin/vout\n");
        return false;
    }

    ucoin_util_keys_t signkey;
    if (!bRevoked) {
        //<delayed_secretkey>
        ln_signer_get_secret(self, &signkey, MSG_FUNDIDX_DELAYED,
            self->funding_local.pubkeys[MSG_FUNDIDX_PER_COMMIT]);
    } else {
        //<revocationsecretkey>
        ln_signer_get_revokesec(self, &signkey,
                    self->funding_remote.pubkeys[MSG_FUNDIDX_PER_COMMIT],
                    self->revoked_sec.buf);
    }
    //LOGD("key-priv: ");
    //DUMPD(signkey.priv, UCOIN_SZ_PRIVKEY);
    //LOGD("key-pub : ");
    //DUMPD(signkey.pub, UCOIN_SZ_PUBKEY);

    ucoin_buf_t sig = UCOIN_BUF_INIT;
    bool ret;
    uint8_t sighash[UCOIN_SZ_SIGHASH];

    //vinは1つしかないので、Indexは0固定
    ucoin_util_calc_sighash_p2wsh(sighash, pTx, 0, Value, pWitScript);

    ret = ucoin_tx_sign(&sig, sighash, signkey.priv);
    if (ret) {
        // <delayedsig>
        // 0
        // <script>
        const uint8_t WIT1 = 0x01;
        const ucoin_buf_t wit0 = { NULL, 0 };
        const ucoin_buf_t wit1 = { (CONST_CAST uint8_t *)&WIT1, 1 };
        const ucoin_buf_t *wits[] = {
            &sig,
            NULL,
            pWitScript
        };
        wits[1] = (bRevoked) ? &wit1 : &wit0;

        ret = ucoin_sw_set_vin_p2wsh(pTx, 0, (const ucoin_buf_t **)wits, ARRAY_SIZE(wits));
    }

    ucoin_buf_free(&sig);

    return ret;
}
