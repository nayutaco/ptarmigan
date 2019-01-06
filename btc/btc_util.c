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
/** @file   btc_util.c
 *  @brief  bitcoin処理: 汎用処理
 */
#include <sys/stat.h>
#include <sys/types.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/ecp.h"
#include "libbase58.h"

#include "utl_dbg.h"
#include "utl_rng.h"

#include "btc_local.h"
#include "btc_segwit_addr.h"
#include "btc_script.h"
#include "btc_sig.h"
#include "btc_sw.h"
#include "btc_util.h"
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

//XXX: test
bool btc_util_sign_p2pkh(btc_tx_t *pTx, uint32_t Index, const btc_keys_t *pKeys)
{
    btc_tx_valid_t txvalid = btc_tx_is_valid(pTx);
    if (txvalid != BTC_TXVALID_OK) {
        LOGD("fail\n");
        return false;
    }

    utl_buf_t scrpk = UTL_BUF_INIT;
    uint8_t pkh[BTC_SZ_HASH_MAX];
    btc_util_hash160(pkh, pKeys->pub, BTC_SZ_PUBKEY);
    btc_scriptpk_create(&scrpk, pkh, BTC_PREF_P2PKH);

    const utl_buf_t *scrpks[] = { &scrpk };

    uint8_t txhash[BTC_SZ_HASH256];
    bool ret = btc_tx_sighash(pTx, txhash, (const utl_buf_t **)scrpks, 1);
    assert(ret);
    ret = btc_tx_sign_p2pkh(pTx, Index, txhash, pKeys->priv, pKeys->pub);
    assert(ret);
    utl_buf_free(&scrpk);

    return ret;
}


//XXX: test
bool btc_util_verify_p2pkh(btc_tx_t *pTx, uint32_t Index, const char *pAddrVout)
{
    //公開鍵(署名サイズ[1],署名[sz],公開鍵サイズ[1], 公開鍵、の順になっている)
    const uint8_t *p_pubkey = pTx->vin[Index].script.buf + 1 + pTx->vin[Index].script.buf[0] + 1;
    uint8_t pkh[BTC_SZ_HASH_MAX];
    utl_buf_t scrpk = UTL_BUF_INIT;
    btc_util_hash160(pkh, p_pubkey, BTC_SZ_PUBKEY);
    btc_scriptpk_create(&scrpk, pkh, BTC_PREF_P2PKH);
    const utl_buf_t *scrpks[] = { &scrpk };

    uint8_t txhash[BTC_SZ_HASH256];
    bool ret = btc_tx_sighash(pTx, txhash, (const utl_buf_t **)scrpks, 1);
    assert(ret);
    ret = btc_tx_verify_p2pkh_addr(pTx, Index, txhash, pAddrVout);
    assert(ret);
    utl_buf_free(&scrpk);

    return ret;
}


//XXX: test
bool btc_util_sign_p2wpkh(btc_tx_t *pTx, uint32_t Index, uint64_t Value, const btc_keys_t *pKeys)
{
    bool ret;
    uint8_t txhash[BTC_SZ_HASH256];
    utl_buf_t sigbuf = UTL_BUF_INIT;
    utl_buf_t script_code = UTL_BUF_INIT;

    btc_tx_valid_t txvalid = btc_tx_is_valid(pTx);
    if (txvalid != BTC_TXVALID_OK) {
        LOGD("fail\n");
        return false;
    }

    if (!btc_scriptcode_p2wpkh(&script_code, pKeys->pub)) {
        LOGD("fail\n");
        return false;
    }

    ret = btc_sw_sighash(pTx, txhash, Index, Value, &script_code);
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


//XXX: test
bool btc_util_sign_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const btc_keys_t *pKeys)
{
    return btc_sig_sign(pSig, pTxHash, pKeys->priv);
}


//XXX: test
bool btc_util_sign_p2wsh_rs(uint8_t *pRS, const uint8_t *pTxHash, const btc_keys_t *pKeys)
{
    return btc_sig_sign_rs(pRS, pTxHash, pKeys->priv);
}


/**************************************************************************
 * package functions
 **************************************************************************/

//XXX: tx
bool HIDDEN btcl_util_create_tx(utl_buf_t *pBuf, const btc_tx_t *pTx, bool enableSegWit)
{
    bool ret = false;

    utl_buf_truncate(pBuf);

    //is segwit?
    bool segwit = false;
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &(pTx->vin[lp]);
        if (enableSegWit && vin->wit_item_cnt) {
            segwit = true;
        }
    }

    btc_buf_w_t buf;
    if (!btc_tx_buf_w_init(&buf, 0)) goto LABEL_EXIT;

    //version[4]
    //mark[1]...segwit
    //flag[1]...segwit
    //vin_cnt[v]
    //  txid[32]
    //  index[4]
    //  script[v|data]
    //  sequence[4]
    //vout_cnt[v]
    //  value[8]
    //  script[v|data]
    //witness...segwit
    //  wit_item_cnt[v]
    //  script[v|data]
    //locktime[4]

    if (!btc_tx_buf_w_write_u32le(&buf, pTx->version)) goto LABEL_EXIT;

    if (segwit) {
        if (!btc_tx_buf_w_write_byte(&buf, 0x00)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_byte(&buf, 0x01)) goto LABEL_EXIT;
    }

    if (!btc_tx_buf_w_write_varint_len(&buf, pTx->vin_cnt)) goto LABEL_EXIT;
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &(pTx->vin[lp]);
        if (!btc_tx_buf_w_write_data(&buf, vin->txid, BTC_SZ_TXID)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_u32le(&buf, vin->index)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_varint_len_data(&buf, vin->script.buf, vin->script.len)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_u32le(&buf, vin->sequence)) goto LABEL_EXIT;
    }

    if (!btc_tx_buf_w_write_varint_len(&buf, pTx->vout_cnt)) goto LABEL_EXIT;
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        btc_vout_t *vout = &(pTx->vout[lp]);
        if (!btc_tx_buf_w_write_u64le(&buf, vout->value)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_varint_len_data(&buf, vout->script.buf, vout->script.len)) goto LABEL_EXIT;
    }

    if (segwit) {
        for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
            btc_vin_t *vin = &(pTx->vin[lp]);
            if (!btc_tx_buf_w_write_varint_len(&buf, vin->wit_item_cnt)) goto LABEL_EXIT;
            for (uint32_t lp2 = 0; lp2 < vin->wit_item_cnt; lp2++) {
                utl_buf_t *wit_item = &(vin->witness[lp2]);
                if (!btc_tx_buf_w_write_varint_len_data(&buf, wit_item->buf, wit_item->len)) goto LABEL_EXIT;
            }
        }
    }

    if (!btc_tx_buf_w_write_u32le(&buf, pTx->locktime)) goto LABEL_EXIT;

    pBuf->buf = btc_tx_buf_w_get_data(&buf);
    pBuf->len = btc_tx_buf_w_get_len(&buf);

    ret = true;

LABEL_EXIT:
    if (!ret) {
        btc_tx_buf_w_free(&buf);
    }

    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/


