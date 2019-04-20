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
/** @file   ln_close.c
 *  @brief  ln_close
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

/*
#include "utl_str.h"
#include "utl_buf.h"
#include "utl_time.h"
#include "utl_int.h"

#include "btc_crypto.h"
#include "btc_script.h"

#include "ln_db.h"
#include "ln_commit_tx.h"
#include "ln_derkey.h"
#include "ln_script.h"
#include "ln_msg_close.h"
#include "ln_local.h"
#include "ln_setupctl.h"
#include "ln_anno.h"
#include "ln_close.h"
*/

#include "utl_dbg.h"

#include "btc_sw.h"

#include "ln_local.h"
#include "ln_signer.h"
#include "ln_wallet.h"


/**************************************************************************
 * macros
 **************************************************************************/
/**************************************************************************
 * prototypes
 **************************************************************************/

static bool create_base_tx(
    btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pScriptPk, uint32_t LockTime, const uint8_t *pTxid, int Index, bool bRevoked);


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_wallet_create_to_local(
    btc_tx_t *pTx, uint64_t Value, uint32_t ToSelfDelay,
    const utl_buf_t *pWitScript, const uint8_t *pTxid, int Index,
    const ln_derkey_local_keys_t *pKeysLocal, const ln_derkey_remote_keys_t *pKeysRemote,
    const uint8_t *pRevokedPerCommitSecOrNull)
{
    bool b_revoked = pRevokedPerCommitSecOrNull ? true : false;
    if (!create_base_tx(pTx, Value, NULL, ToSelfDelay, pTxid, Index, b_revoked)) return false;
    btc_keys_t key;
    if (!ln_signer_to_local_key(
        &key, pKeysLocal, pKeysRemote, pRevokedPerCommitSecOrNull)) return false;
    if (!ln_wallet_script_to_local_set_vin0(pTx, &key, pWitScript, b_revoked)) return false;
    return true;
}


bool ln_wallet_create_to_remote(
    btc_tx_t *pTx, uint64_t Value,
    const uint8_t *pTxid, int Index,
    const ln_derkey_local_keys_t *pKeysLocal, const ln_derkey_remote_keys_t *pKeysRemote)
{
    if (!create_base_tx(pTx, Value, NULL, 0, pTxid, Index, false)) return false;
    btc_keys_t key;
    if (!ln_signer_to_remote_key(&key, pKeysLocal, pKeysRemote)) return false;
    if (!ln_wallet_script_to_remote_set_vin0(pTx, &key)) return false;
    return true;
}


bool HIDDEN ln_wallet_script_to_local_set_vin0(
    btc_tx_t *pTx,
    const btc_keys_t *pKey,
    const utl_buf_t *pWitScript,
    bool bRevoked)
{
    // <local_delayedsig>
    // 0
    // <witness script>

    // OR

    // <revocation_sig>
    // 1
    // <witness script>

    const utl_buf_t key = { (CONST_CAST uint8_t *)pKey->priv, BTC_SZ_PRIVKEY }; //XXX: privkey not sig (original form)
    const utl_buf_t zero = UTL_BUF_INIT;
    const utl_buf_t one = { (CONST_CAST uint8_t *)"\x01", 1 };
    const utl_buf_t *wit_items[] = { &key, (bRevoked) ? &one : &zero, pWitScript };
    if (!btc_sw_set_vin_p2wsh(pTx, 0, (const utl_buf_t **)wit_items, ARRAY_SIZE(wit_items))) return false;
    return true;
}


bool HIDDEN ln_wallet_script_to_remote_set_vin0(btc_tx_t *pTx, const btc_keys_t *pKey)
{
    utl_buf_t *p_wit_items = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * 2);
    if (!utl_buf_alloccopy(&p_wit_items[0], pKey->priv, BTC_SZ_PRIVKEY)) return false; //XXX: privkey not sig (original form)
    if (!utl_buf_alloccopy(&p_wit_items[1], pKey->pub, BTC_SZ_PUBKEY)) return false;
    pTx->vin[0].wit_item_cnt = 2;
    pTx->vin[0].witness = p_wit_items;
    return true;
}


bool HIDDEN ln_wallet_htlc_tx_set_vin0(
    btc_tx_t *pTx,
    const uint8_t *pHtlcPrivKey,
    const uint8_t *pPreimage,
    const utl_buf_t *pWitScript,
    ln_htlc_tx_sig_type_t HtlcSigType)
{
    switch (HtlcSigType) {
    case LN_HTLC_TX_SIG_REMOTE_OFFER:
        {
            // <remotehtlcsig> BUT set htlc private key (NOT BOLT)
            // <payment-preimage> BUT optional (NOT BOLT)
            // <witness script>
            const utl_buf_t htlc_privkey = { (CONST_CAST uint8_t *)pHtlcPrivKey, BTC_SZ_PRIVKEY };
            utl_buf_t preimage = UTL_BUF_INIT;
            if (pPreimage) {
                preimage.buf = (CONST_CAST uint8_t *)pPreimage;
                preimage.len = LN_SZ_PREIMAGE;
            }
            const utl_buf_t *wit_items[] = { &htlc_privkey, &preimage, pWitScript };
            LOGD("Offered HTLC + preimage sign: wit_item_num=%d\n", ARRAY_SIZE(wit_items));
            if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
        }
        break;
    case LN_HTLC_TX_SIG_REMOTE_RECV:
        {
            // <remotehtlcsig> BUT set htlc private key (NOT BOLT)
            // 0
            // <witness script>
            const utl_buf_t htlc_privkey = { (CONST_CAST uint8_t *)pHtlcPrivKey, BTC_SZ_PRIVKEY };
            const utl_buf_t zero = UTL_BUF_INIT;
            const utl_buf_t *wit_items[] = { &htlc_privkey, &zero, pWitScript};
            LOGD("Received HTLC sign: wit_item_num=%d\n", ARRAY_SIZE(wit_items));
            if (!btc_sw_set_vin_p2wsh(pTx, 0, wit_items, ARRAY_SIZE(wit_items))) return false;
        }
        break;
    default:
        LOGD("HtlcSigType=%d\n", (int)HtlcSigType);
        assert(0);
        return false;
    }
    return true;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static bool create_base_tx(btc_tx_t *pTx,
    uint64_t Value, const utl_buf_t *pScriptPk, uint32_t LockTime, const uint8_t *pTxid, int Index, bool bRevoked)
{
    //vout
    btc_vout_t* vout = btc_tx_add_vout(pTx, Value);
    if (pScriptPk) {
        if (!utl_buf_alloccopy(&vout->script, pScriptPk->buf, pScriptPk->len)) return false;
    }

    //vin
    btc_tx_add_vin(pTx, pTxid, Index);
    if (!bRevoked) {
        pTx->vin[0].sequence = LockTime;
    }
    return true;
}


