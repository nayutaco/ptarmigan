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
    DBG_PRINTF("\n");

    if (pSeed) {
        memcpy(self->storage_seed, pSeed, LN_SZ_SEED);
        ln_derkey_storage_init(&self->peer_storage);
    }
}


void HIDDEN ln_signer_term(ln_self_t *self)
{
    DBG_PRINTF("\n");

    memset(self->storage_seed, 0, UCOIN_SZ_PRIVKEY);
}


void HIDDEN ln_signer_create_nodekey(ucoin_util_keys_t *pKeys)
{
    DBG_PRINTF("\n");

    ucoin_util_createkeys(pKeys);
}


bool HIDDEN ln_signer_create_channelkeys(ln_self_t *self)
{
    DBG_PRINTF("\n");

    self->storage_index = LN_SECINDEX_INIT;

    //鍵生成
    //  open_channel/accept_channelの鍵は ln_signer_update_percommit_secret()で生成
    for (int lp = MSG_FUNDIDX_FUNDING; lp < LN_FUNDIDX_MAX; lp++) {
        if (lp != MSG_FUNDIDX_PER_COMMIT) {
            ucoin_util_createkeys(&self->funding_local.keys[lp]);
        }
    }
    ln_print_keys(PRINTOUT, &self->funding_local, &self->funding_remote);

    ln_signer_update_percommit_secret(self);

    return true;
}


void HIDDEN ln_signer_update_percommit_secret(ln_self_t *self)
{
    DBG_PRINTF("\n");

    ln_signer_keys_update(self, 0);

    self->storage_index--;

    ln_misc_update_scriptkeys(&self->funding_local, &self->funding_remote);
}


void HIDDEN ln_signer_keys_update(ln_self_t *self, int64_t Offset)
{
    DBG_PRINTF("\n");

    ln_signer_keys_update_force(self, self->storage_index + Offset);
}


void HIDDEN ln_signer_keys_update_force(ln_self_t *self, uint64_t Index)
{
    DBG_PRINTF("\n");

    ln_derkey_create_secret(self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].priv, self->storage_seed, Index);
    ucoin_keys_priv2pub(self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].pub, self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].priv);

    // DBG_PRINTF("Index = %" PRIx64 "\n", Index);
    // DUMPBIN(self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].priv, UCOIN_SZ_PRIVKEY);
}


void HIDDEN ln_signer_get_prevkey(const ln_self_t *self, uint8_t *pSecret)
{
    DBG_PRINTF("\n");

    //  現在の funding_local.keys[MSG_FUNDIDX_PER_COMMIT]はself->storage_indexから生成されていて、「次のper_commitment_secret」になる。
    //  最後に使用した値は self->storage_index + 1で、これが「現在のper_commitment_secret」になる。
    //  そのため、「1つ前のper_commitment_secret」は self->storage_index + 2 となる。
    ln_derkey_create_secret(pSecret, self->storage_seed, self->storage_index + 2);

    DBG_PRINTF("prev_secret(%" PRIx64 "): ", self->storage_index + 2);
    DUMPBIN(pSecret, UCOIN_SZ_PRIVKEY);
    DBG_PRINTF("       pub: ");
    uint8_t pub[UCOIN_SZ_PUBKEY];
    ucoin_keys_priv2pub(pub, pSecret);
    DUMPBIN(pub, UCOIN_SZ_PUBKEY);
}


void HIDDEN ln_signer_get_secret(const ln_self_t *self, ucoin_util_keys_t *pKeys, int MsgFundIdx, const uint8_t *pPerCommit)
{
    DBG_PRINTF("\n");

    ln_derkey_privkey(pKeys->priv,
                self->funding_local.keys[MsgFundIdx].pub,
                pPerCommit,
                self->funding_local.keys[MsgFundIdx].priv);
    ucoin_keys_priv2pub(pKeys->pub, pKeys->priv);
}


void HIDDEN ln_signer_get_revokesec(const ln_self_t *self, ucoin_util_keys_t *pKeys, const uint8_t *pPerCommit, const uint8_t *pRevokedSec)
{
    DBG_PRINTF("\n");

    ln_derkey_revocationprivkey(pKeys->priv,
                self->funding_local.keys[MSG_FUNDIDX_REVOCATION].pub,
                pPerCommit,
                self->funding_local.keys[MSG_FUNDIDX_REVOCATION].priv,
                pRevokedSec);
    ucoin_keys_priv2pub(pKeys->pub, pKeys->priv);
}


bool HIDDEN ln_signer_p2wsh_2(ucoin_buf_t *pSig, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys)
{
    DBG_PRINTF("\n");

    return ucoin_tx_sign(pSig, pTxHash, pKeys->priv);
}


bool HIDDEN ln_signer_p2wpkh(ucoin_tx_t *pTx, int Index, uint64_t Value, const ucoin_util_keys_t *pKeys)
{
    DBG_PRINTF("\n");

    bool ret;
    uint8_t txhash[UCOIN_SZ_HASH256];
    ucoin_buf_t sigbuf;
    ucoin_buf_t script_code;

    ucoin_buf_init(&script_code);
    ucoin_buf_init(&sigbuf);
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
