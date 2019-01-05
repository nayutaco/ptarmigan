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
/** @file   btc_sw.c
 *  @brief  bitcoin処理: Segwitトランザクション生成関連
 */
#include "utl_dbg.h"
#include "utl_int.h"

#include "btc_local.h"
#include "btc_util.h"
#include "btc_script.h"
#include "btc_sig.h"
#include "btc_sw.h"
#include "btc_tx_buf.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_sw_add_vout_p2wpkh_pub(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey)
{
    return btcl_util_add_vout_pub(pTx, Value, pPubKey, (mNativeSegwit) ? BTC_PREF_P2WPKH : BTC_PREF_P2SH);
}


bool btc_sw_add_vout_p2wpkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash)
{
    return btcl_util_add_vout_pkh(pTx, Value, pPubKeyHash, (mNativeSegwit) ? BTC_PREF_P2WPKH : BTC_PREF_P2SH);
}


bool btc_sw_add_vout_p2wsh_wit(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pWitScript)
{
    if (!pWitScript->len) return false;

    if (mNativeSegwit) {
        btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
        if (!btc_scriptsig_create_p2wsh(&vout->script, pWitScript)) return false;
    } else {
        utl_buf_t script_sig = UTL_BUF_INIT;
        if (!btc_scriptsig_create_p2wsh(&script_sig, pWitScript)) {
            utl_buf_free(&script_sig);
            return false;
        }
        uint8_t sh[BTC_SZ_HASH_MAX];
        btc_util_hash160(sh, script_sig.buf, script_sig.len);
        utl_buf_free(&script_sig);
        if (!btc_tx_add_vout_p2sh(pTx, Value, sh)) return false;
    }
    return true;
}


bool btc_sw_scriptcode_p2wpkh_vin(utl_buf_t *pScriptCode, const btc_vin_t *pVin)
{
    //P2WPKH witness
    //      0: <signature>
    //      1: <pubkey>
    if (pVin->wit_item_cnt != 2) {
        return false;
    }

    return btc_scriptcode_p2wpkh(pScriptCode, pVin->witness[1].buf);
}


bool btc_sw_scriptcode_p2wsh_vin(utl_buf_t *pScriptCode, const btc_vin_t *pVin)
{
    //P2WSH witness
    //      ....
    //      wit_item_cnt - 1: witnessScript
    if (pVin->wit_item_cnt == 0) {
        return false;
    }

    return btc_scriptcode_p2wsh(pScriptCode, &pVin->witness[pVin->wit_item_cnt - 1]);
}


bool btc_sw_sighash(const btc_tx_t *pTx, uint8_t *pTxHash, uint32_t Index, uint64_t Value, const utl_buf_t *pScriptCode)
{
    // [transaction version : 4]
    // [hash_prevouts : 32]
    // [hash_sequence : 32]
    // [outpoint : 32 + 4]
    // [scriptcode : xx]
    // [amount : 8]
    // [sequence : 4]
    // [hash_outputs : 32]
    // [locktime : 4]
    // [hash_type : 4]

    bool ret = false;
    btc_buf_w_t buf_w;
    btc_buf_w_t buf_w_tmp;
    uint32_t lp;

    btc_tx_valid_t txvld = btc_tx_is_valid(pTx);
    if (txvld != BTC_TXVALID_OK) {
        LOGD("fail: invalid tx\n");
        return false;
    }

    if (!btc_buf_w_init(&buf_w, 0)) return false;
    if (!btc_buf_w_init(&buf_w_tmp, 0)) return false;

    //version
    if (!btc_buf_w_write_u32le(&buf_w, pTx->version)) goto LABEL_EXIT;

    //vin:
    // prev outs:

    //hash_prevouts: HASH256((txid(32) | index(4)) * n)
    btc_buf_w_truncate(&buf_w_tmp);
    for (lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &pTx->vin[lp];

        if (!btc_buf_w_write_data(&buf_w_tmp, vin->txid, BTC_SZ_TXID)) goto LABEL_EXIT;
        if (!btc_buf_w_write_u32le(&buf_w_tmp, vin->index)) goto LABEL_EXIT;
    }
    if (!btc_buf_w_write_hash256(&buf_w, btc_tx_buf_w_get_data(&buf_w_tmp), btc_tx_buf_w_get_len(&buf_w_tmp))) goto LABEL_EXIT;

    //hash_sequence: HASH256(sequence(4) * n)
    btc_buf_w_truncate(&buf_w_tmp);
    for (lp = 0; lp < pTx->vin_cnt; lp++) {
        if (!btc_buf_w_write_u32le(&buf_w_tmp, pTx->vin[lp].sequence)) goto LABEL_EXIT;
    }
    if (!btc_buf_w_write_hash256(&buf_w, btc_tx_buf_w_get_data(&buf_w_tmp), btc_tx_buf_w_get_len(&buf_w_tmp))) goto LABEL_EXIT;

    //outpoint: txid(32) | Index(4)
    if (!btc_buf_w_write_data(&buf_w, pTx->vin[Index].txid, BTC_SZ_TXID)) goto LABEL_EXIT;
    if (!btc_buf_w_write_u32le(&buf_w, pTx->vin[Index].index)) goto LABEL_EXIT;

    //scriptcode
    if (!btc_buf_w_write_data(&buf_w, pScriptCode->buf, pScriptCode->len)) goto LABEL_EXIT;

    //amount
    if (!btc_buf_w_write_u64le(&buf_w, Value)) goto LABEL_EXIT;

    //sequence
    if (!btc_buf_w_write_u32le(&buf_w, pTx->vin[Index].sequence)) goto LABEL_EXIT;

    //vout:
    // next vins:

    //hash_outputs: HASH256((value(8) | scriptPk) * n)
    btc_buf_w_truncate(&buf_w_tmp);
    for (lp = 0; lp < pTx->vout_cnt; lp++) {
        btc_vout_t *vout = &pTx->vout[lp];
        if (!btc_buf_w_write_u64le(&buf_w_tmp, vout->value)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_varint_len(&buf_w_tmp, vout->script.len)) goto LABEL_EXIT;
        if (!btc_buf_w_write_data(&buf_w_tmp, vout->script.buf, vout->script.len)) goto LABEL_EXIT;
    }
    if (!btc_buf_w_write_hash256(&buf_w, btc_tx_buf_w_get_data(&buf_w_tmp), btc_tx_buf_w_get_len(&buf_w_tmp))) goto LABEL_EXIT;

    //locktime
    if (!btc_buf_w_write_u32le(&buf_w, pTx->locktime)) goto LABEL_EXIT;

    //hashtype
    if (!btc_buf_w_write_u32le(&buf_w, SIGHASH_ALL)) goto LABEL_EXIT;

    btc_util_hash256(pTxHash, btc_tx_buf_w_get_data(&buf_w), btc_tx_buf_w_get_len(&buf_w));

    ret = true;

LABEL_EXIT:
    btc_tx_buf_w_free(&buf_w);
    btc_tx_buf_w_free(&buf_w_tmp);

    return ret;
}


bool btc_sw_set_vin_p2wpkh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSig, const uint8_t *pPubKey)
{
    btc_vin_t *vin = &(pTx->vin[Index]);

    //scriptsig
    if (mNativeSegwit) {
        //empty
        utl_buf_free(&vin->script);
    } else {
        if (!btc_scriptsig_create_p2sh_p2wpkh(&vin->script, pPubKey)) return false;
    }

    //witness
    return btc_witness_create_p2wpkh(&vin->witness, &vin->wit_item_cnt, pSig, pPubKey);
}


bool btc_sw_set_vin_p2wsh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pWitness[], int Num)
{
    if (!Num) return false;

    btc_vin_t *vin = &(pTx->vin[Index]);

    //scriptsig
    if (mNativeSegwit) {
        //empty
        utl_buf_free(&vin->script);
    } else {
        if (!btc_scriptsig_create_p2sh_p2wsh(&vin->script, pWitness[Num - 1])) return false;
    }

    //witness
    return btc_witness_create_p2wsh(&vin->witness, &vin->wit_item_cnt, pWitness, Num);
}


bool btc_sw_verify_p2wpkh(const btc_tx_t *pTx, uint32_t Index, uint64_t Value, const uint8_t *pHash)
{
    bool ret = false;
    btc_vin_t *vin = &(pTx->vin[Index]);
    utl_buf_t script_code = UTL_BUF_INIT;

    if (vin->wit_item_cnt != 2) return false;
    const utl_buf_t *p_sig = &vin->witness[0];
    const utl_buf_t *p_pub = &vin->witness[1];
    if (p_pub->len != BTC_SZ_PUBKEY) return false;

    //check pkh
    uint8_t hash[BTC_SZ_HASH_MAX];
    btc_util_hash160(hash, p_pub->buf, BTC_SZ_PUBKEY); //pkh
    if (!mNativeSegwit) {
        //P2SH-P2WPKH
        btc_util_hash160(hash, p_pub->buf, BTC_SZ_PUBKEY);
        btc_util_create_pkh2wpkh(hash, hash); //pkh -> sh
    }
    if (memcmp(hash, pHash, BTC_SZ_HASH160)) goto LABEL_EXIT;

    //check sig
    uint8_t txhash[BTC_SZ_HASH256];
    if (!btc_scriptcode_p2wpkh(&script_code, p_pub->buf)) goto LABEL_EXIT;
    if (!btc_sw_sighash(pTx, txhash, Index, Value, &script_code)) goto LABEL_EXIT;
    if (!btc_sig_verify(p_sig, txhash, p_pub->buf)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&script_code);
    return ret;
}


bool btc_sw_verify_p2wpkh_addr(const btc_tx_t *pTx, uint32_t Index, uint64_t Value, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;

    if (!btc_keys_addr2hash(hash, &pref, pAddr)) return false;
    if (mNativeSegwit) {
        if (pref != BTC_PREF_P2WPKH) return false;
    } else {
        if (pref != BTC_PREF_P2SH) return false;
    }
    return btc_sw_verify_p2wpkh(pTx, Index, Value, hash);
}


bool btc_sw_verify_p2wsh_2of2(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    return btc_witness_verify_p2wsh_2of2(pTx->vin[Index].witness, pTx->vin[Index].wit_item_cnt, pTxHash, pScriptPk);
}


#if 0   //今のところ使い道がない
/** WTXID計算
 *
 * @param[out]  pWTxId      計算結果(Little Endian)
 * @param[in]   pTx         対象トランザクション
 *
 * @note
 *      - pWTxIdにはLittleEndianで出力される
 */
bool btc_sw_wtxid(uint8_t *pWTxId, const btc_tx_t *pTx)
{
    utl_buf_t txbuf = UTL_BUF_INIT;

    //XXX: if tx is non-segwit, WTXID == TXID
    //if (!btc_sw_is_segwit(pTx)) {
    //    assert(0);
    //    return false;
    //}

    bool ret = btcl_util_create_tx(&txbuf, pTx, true);
    if (!ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    btc_util_hash256(pWTxId, txbuf.buf, txbuf.len);
    utl_buf_free(&txbuf);

LABEL_EXIT:
    return ret;
}


bool btc_sw_is_segwit(const btc_tx_t *pTx)
{
    //https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
    // If the witness is empty, the old serialization format should be used.

    bool ret = false;

    for (int lp = 0; lp < pTx->vin_cnt; lp++) {
        if (pTx->vin[lp].wit_item_cnt > 0) {
            ret = true;
            break;
        }
    }

    return ret;
}
#endif


void btc_sw_wit2prog_p2wsh(uint8_t *pWitProg, const utl_buf_t *pWitScript)
{
    pWitProg[0] = 0x00;
    pWitProg[1] = BTC_SZ_HASH256;
    btc_util_sha256(pWitProg + 2, pWitScript->buf, pWitScript->len);
}
