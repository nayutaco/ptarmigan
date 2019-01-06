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
/** @file   btc_test_util.c
 *  @brief  btc_test_util
 */
#include <sys/stat.h>
#include <sys/types.h>

#include "utl_dbg.h"

#include "btc_local.h"
#include "btc_segwit_addr.h"
#include "btc_script.h"
#include "btc_sig.h"
#include "btc_sw.h"
#include "btc_crypto.h"
#include "btc_tx_buf.h"


/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * private variables
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

/**************************************************************************
 *const variables
 **************************************************************************/

/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_test_util_sign_p2pkh(btc_tx_t *pTx, uint32_t Index, const btc_keys_t *pKeys)
{
    bool ret = false;
    btc_tx_valid_t txvalid;
    uint8_t pkh[BTC_SZ_HASH_MAX];
    utl_buf_t spk = UTL_BUF_INIT;
    const utl_buf_t *p_spks[8];
    uint8_t txhash[BTC_SZ_HASH256];

    txvalid = btc_tx_is_valid(pTx);
    if (txvalid != BTC_TXVALID_OK) goto LABEL_EXIT;

    btc_md_hash160(pkh, pKeys->pub, BTC_SZ_PUBKEY);
    if (!btc_script_scriptpk_create(&spk, pkh, BTC_PREF_P2PKH)) goto LABEL_EXIT;

    p_spks[0] = &spk;
    if (!btc_tx_sighash(pTx, txhash, p_spks, 1)) goto LABEL_EXIT;
    if (!btc_tx_sign_p2pkh(pTx, Index, txhash, pKeys->priv, pKeys->pub)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    if (!ret) {
        LOGD("fail\n");
    }
    utl_buf_free(&spk);
    return ret;
}


bool btc_test_util_verify_p2pkh_addr(btc_tx_t *pTx, uint32_t Index, const char *pAddr)
{
    bool ret = false;
    utl_buf_t spk = UTL_BUF_INIT;
    uint32_t sig_len;
    uint32_t pubkey_len;
    const uint8_t *p_pubkey;
    uint8_t pkh[BTC_SZ_HASH_MAX];
    const utl_buf_t *p_spks[8];
    uint8_t txhash[BTC_SZ_HASH256];

    //scriptpk
    //  1: sig_len
    //  sig_len: sig
    //  1: pubkey_len
    //  pubkey_len: pubkey
    if (pTx->vin[Index].script.len < 1) goto LABEL_EXIT;
    sig_len = pTx->vin[Index].script.buf[0];
    if (sig_len > OP_X_PUSHDATA_MAX) goto LABEL_EXIT;
    if (pTx->vin[Index].script.len < 1 + sig_len + 1) goto LABEL_EXIT;
    pubkey_len = pTx->vin[Index].script.buf[1 + sig_len + 1];
    if (pubkey_len != BTC_SZ_PUBKEY) goto LABEL_EXIT;
    if (pTx->vin[Index].script.len != 1 + sig_len + 1 + pubkey_len) goto LABEL_EXIT;

    p_pubkey = &pTx->vin[Index].script.buf[ 1 + sig_len + 1];

    btc_md_hash160(pkh, p_pubkey, BTC_SZ_PUBKEY);
    if (!btc_script_scriptpk_create(&spk, pkh, BTC_PREF_P2PKH)) goto LABEL_EXIT;

    p_spks[0] = &spk;
    if (!btc_tx_sighash(pTx, txhash, p_spks, 1)) goto LABEL_EXIT;
    if (!btc_tx_verify_p2pkh_addr(pTx, Index, txhash, pAddr)) goto LABEL_EXIT;

LABEL_EXIT:
    if (!ret) {
        LOGD("fail\n");
    }
    utl_buf_free(&spk);
    return ret;
}


bool btc_test_util_sign_p2wpkh(btc_tx_t *pTx, uint32_t Index, uint64_t Value, const btc_keys_t *pKeys)
{
    bool ret = false;
    btc_tx_valid_t txvalid;
    utl_buf_t script_code = UTL_BUF_INIT;
    uint8_t txhash[BTC_SZ_HASH256];
    utl_buf_t sig = UTL_BUF_INIT;

    txvalid = btc_tx_is_valid(pTx);
    if (txvalid != BTC_TXVALID_OK) goto LABEL_EXIT;

    if (!btc_script_p2wpkh_create_scriptcode(&script_code, pKeys->pub)) goto LABEL_EXIT;

    if (!btc_sw_sighash(pTx, txhash, Index, Value, &script_code)) goto LABEL_EXIT;
    if (!btc_sig_sign(&sig, txhash, pKeys->priv)) goto LABEL_EXIT;
    
    //if mNativeSegwit == true, then set witness
    //if mNativeSegwit == fase, then set scriptsig and witness
    if (!btc_sw_set_vin_p2wpkh(pTx, Index, &sig, pKeys->pub)) goto LABEL_EXIT;

    ret = true;
    
LABEL_EXIT:
    if (!ret) {
        LOGD("fail\n");
    }
    utl_buf_free(&sig);
    utl_buf_free(&script_code);
    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/


