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
/** @file   btc_tx.c
 *  @brief  bitcoin処理: トランザクション生成関連
 */
#ifdef PTARM_USE_PRINTFUNC
#endif  //PTARM_USE_PRINTFUNC

#include "utl_dbg.h"
#include "utl_time.h"
#include "utl_int.h"
#include "utl_mem.h"

#include "btc_block.h"
#include "btc_local.h"
#include "btc_crypto.h"
#include "btc_segwit_addr.h"
#include "btc_script.h"
#include "btc_sig.h"
#include "btc_tx_buf.h"
#include "btc_tx.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

static bool btc_tx_write_2(utl_buf_t *pBuf, const btc_tx_t *pTx, bool enableSegWit);
#ifdef USE_ELEMENTS
static bool read_elements_vout_value(btc_buf_r_t *pTxBuf, uint8_t *pVersion, uint64_t *pValue, uint8_t *pCommitValue);
#endif


/**************************************************************************
 * const variables
 **************************************************************************/

/**************************************************************************
 * public functions
 **************************************************************************/

void btc_tx_init(btc_tx_t *pTx)
{
    pTx->version = BTC_TX_VERSION_INIT;
    pTx->vin_cnt = 0;
    pTx->vin = NULL;
    pTx->vout_cnt = 0;
    pTx->vout = NULL;
    pTx->locktime = 0;
}


void btc_tx_free(btc_tx_t *pTx)
{
    //vin
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &(pTx->vin[lp]);
        utl_buf_free(&(vin->script));
        for (uint32_t lp2 = 0; lp2 < vin->wit_item_cnt; lp2++) {
            utl_buf_free(&(vin->witness[lp2]));
        }
        if (vin->wit_item_cnt) {
            UTL_DBG_FREE(vin->witness);
            vin->wit_item_cnt = 0;
        }
    }
    if (pTx->vin_cnt) {
        UTL_DBG_FREE(pTx->vin);
        pTx->vin_cnt = 0;
    }
    //vout
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        btc_vout_t *vout = &(pTx->vout[lp]);
        utl_buf_free(&(vout->script));
    }
    if (pTx->vout_cnt) {
        UTL_DBG_FREE(pTx->vout);
        pTx->vout_cnt = 0;
    }
#ifdef PTARM_DEBUG
    memset(pTx, 0, sizeof(*pTx));
    pTx->version = BTC_TX_VERSION_INIT;
#endif  //PTARM_DEBUG
}


btc_tx_valid_t btc_tx_is_valid(const btc_tx_t *pTx)
{
    if (pTx == NULL) {
        LOGE("fail: null\n");
        return BTC_TXVALID_ARG_NULL;
    }
    if (pTx->version != 1 && pTx->version != 2) {
        LOGE("fail: version\n");
        return BTC_TXVALID_VERSION_BAD;
    }
    if (pTx->vin_cnt == 0) {
        LOGE("fail: vin_cnt\n");
        return BTC_TXVALID_VIN_NONE;
    }
    if (pTx->vin == NULL) {
        LOGE("fail: NULL vin\n");
        return BTC_TXVALID_VIN_NULL;
    }
    if (pTx->vout_cnt == 0) {
        LOGE("fail: vout_cnt\n");
        btc_tx_print(pTx);
        return BTC_TXVALID_VOUT_NONE;
    }
    if (pTx->vout == NULL) {
        LOGE("fail: NULL vout\n");
        return BTC_TXVALID_VOUT_NULL;
    }
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        const btc_vin_t *vin = &pTx->vin[lp];

        if ((vin->wit_item_cnt > 0) && (vin->witness == NULL)) {
            LOGE("fail: NULL witness[%u]\n", lp);
            return BTC_TXVALID_VIN_WIT_NULL;
        } else if ((vin->wit_item_cnt == 0) && (vin->witness != NULL)) {
            LOGE("fail: bad witness[%u]\n", lp);
            return BTC_TXVALID_VIN_WIT_BAD;
        } else {
            //OK
        }
        for (uint32_t wit = 0; wit < vin->wit_item_cnt; wit++) {
            const utl_buf_t *buf = &vin->witness[wit];
            if (buf == NULL) {
                LOGE("fail: NULL witness[%u][%u]", lp, wit);
                return BTC_TXVALID_VIN_WIT_NULL;
            }
            //OP_0はlen=0になるので、buf=NULLはあり得る
        }
    }
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        const btc_vout_t *vout = &pTx->vout[lp];

#if defined(USE_BITCOIN)
        if (vout->script.len == 0) {
            LOGE("fail: no scriptPubKeyHash[%u]\n", lp);
            return BTC_TXVALID_VOUT_SPKH_NONE;
        }
        if ((vout->value == 0) && !btc_script_scriptpk_is_op_return(&vout->script)) {
            LOGE("fail: no value[%u]\n", lp);
            return BTC_TXVALID_VOUT_VALUE_BAD;
        }
#elif defined(USE_ELEMENTS)
        switch (vout->type) {
        case BTC_TX_ELE_VOUT_ADDR:
            if (vout->script.len == 0) {
                LOGE("fail: no scriptPubKeyHash[%u]\n", lp);
                return BTC_TXVALID_VOUT_SPKH_NONE;
            }
            if ((vout->value == 0) && !btc_script_scriptpk_is_op_return(&vout->script)) {
                LOGE("fail: no value[%u]\n", lp);
                return BTC_TXVALID_VOUT_VALUE_BAD;
            }
            break;
        case BTC_TX_ELE_VOUT_FEE:
            break;
        case BTC_TX_ELE_VOUT_DATA:
        case BTC_TX_ELE_VOUT_BURN:
        default:
            LOGE("fail: no value[%u]\n", lp);
            return BTC_TXVALID_VOUT_VALUE_BAD;
        }
#endif
    }

    return BTC_TXVALID_OK;
}


btc_vin_t *btc_tx_add_vin(btc_tx_t *pTx, const uint8_t *pTxId, uint32_t Index)
{
    pTx->vin = (btc_vin_t *)UTL_DBG_REALLOC(pTx->vin, sizeof(btc_vin_t) * (pTx->vin_cnt + 1));
    if (!pTx->vin) return NULL;
    btc_vin_t *vin = &(pTx->vin[pTx->vin_cnt]);
    pTx->vin_cnt++;

    memcpy(vin->txid, pTxId, BTC_SZ_TXID);
    vin->index = Index;
    utl_buf_init(&vin->script);
    vin->wit_item_cnt = 0;
    vin->witness = NULL;
    vin->sequence = BTC_TX_SEQUENCE;
#ifdef USE_ELEMENTS
    vin->issuance = false;
    vin->pegin = false;
#endif
    return vin;
}


utl_buf_t *btc_tx_add_wit(btc_vin_t *pVin)
{
    pVin->witness = (utl_buf_t *)UTL_DBG_REALLOC(pVin->witness, sizeof(utl_buf_t) * (pVin->wit_item_cnt + 1));
    if (!pVin->witness) return NULL;
    utl_buf_t *p_buf = &(pVin->witness[pVin->wit_item_cnt]);
    pVin->wit_item_cnt++;

    utl_buf_init(p_buf);
    return p_buf;
}


btc_vout_t *btc_tx_add_vout(btc_tx_t *pTx, uint64_t Value)
{
    pTx->vout = (btc_vout_t *)UTL_DBG_REALLOC(pTx->vout, sizeof(btc_vout_t) * (pTx->vout_cnt + 1));
    if (!pTx->vout) return NULL;
    btc_vout_t *vout = &(pTx->vout[pTx->vout_cnt]);
    pTx->vout_cnt++;

    vout->value = Value;
    utl_buf_init(&vout->script);
    vout->opt = 0;
#ifdef USE_ELEMENTS
    memcpy(vout->asset, btc_get_param()->asset, BTC_SZ_HASH256);
    vout->type = BTC_TX_ELE_VOUT_ADDR;
    vout->ver_asset = BTC_TX_ELE_VOUT_VER_EXPLICIT;
    vout->ver_value = BTC_TX_ELE_VOUT_VER_EXPLICIT;
    vout->ver_nonce = BTC_TX_ELE_VOUT_VER_NULL;
#endif
    return vout;
}


bool btc_tx_add_vout_addr(btc_tx_t *pTx, uint64_t Value, const char *pAddr)
{
    bool ret;
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;

    ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret) {
        btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
        if (!vout) return false;
        if (!btc_script_scriptpk_create(&vout->script, hash, pref)) return false;
    }
    return ret;
}


bool btc_tx_add_vout_spk(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pScriptPk)
{
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    if (!vout) return false;
    return utl_buf_alloccopy(&vout->script, pScriptPk->buf, pScriptPk->len);
}


bool btc_tx_add_vout_p2pkh_pub(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey)
{
    uint8_t pkh[BTC_SZ_HASH_MAX];
    btc_md_hash160(pkh, pPubKey, BTC_SZ_PUBKEY);
    return btc_tx_add_vout_p2pkh(pTx, Value, pkh);
}


bool btc_tx_add_vout_p2pkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash)
{
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    if (!vout) return false;
    return btc_script_scriptpk_create(&vout->script, pPubKeyHash, BTC_PREF_P2PKH);
}


bool btc_tx_add_vout_fee(btc_tx_t *pTx, uint64_t Value)
{
#if defined(USE_BITCOIN)
    (void)pTx; (void)Value;
    return true;
#elif defined(USE_ELEMENTS)
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    if (vout != NULL) {
        vout->type = BTC_TX_ELE_VOUT_FEE;
        return true;
    } else {
        return false;
    }
#endif
}


// btc_vout_t *btc_tx_add_vout_burn(btc_tx_t *pTx, uint64_t Value)
// {
//     btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
//     if (!vout) return false;
//     utl_buf_alloc(&vout->script, 1);
//     vout->script.buf[0] = OP_RETURN;
//     return true;
// }


bool btc_tx_create_spk(utl_buf_t *pBuf, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret) {
        ret = btc_script_scriptpk_create(pBuf, hash, pref);
    }

    return ret;
}


bool btc_tx_create_spk_p2pkh(utl_buf_t *pBuf, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2PKH)) {
        ret = btc_script_scriptpk_create(pBuf, hash, pref);
    } else {
        ret = false;
    }

    return ret;
}


bool btc_tx_add_vout_p2pkh_addr(btc_tx_t *pTx, uint64_t Value, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2PKH)) {
        ret = btc_tx_add_vout_p2pkh(pTx, Value, hash);
    } else {
        ret = false;
    }

    return ret;
}


bool btc_tx_add_vout_p2sh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pScriptHash)
{
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    if (!vout) return false;
    return btc_script_scriptpk_create(&vout->script, pScriptHash, BTC_PREF_P2SH);
}


bool btc_tx_add_vout_p2sh_addr(btc_tx_t *pTx, uint64_t Value, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2SH)) {
        ret = btc_tx_add_vout_p2sh(pTx, Value, hash);
    } else {
        ret = false;
    }

    return ret;
}


bool btc_tx_add_vout_p2sh_redeem(btc_tx_t *pTx, uint64_t Value, const utl_buf_t *pRedeem)
{
    if (!pRedeem->len) return false;

    uint8_t sh[BTC_SZ_HASH_MAX];
    btc_md_hash160(sh, pRedeem->buf, pRedeem->len);
    return btc_tx_add_vout_p2sh(pTx, Value, sh);
}


bool btc_tx_set_vin_p2pkh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSig, const uint8_t *pPubKey)
{
    return btc_script_p2pkh_create_scriptsig(&(pTx->vin[Index].script), pSig, pPubKey);
}


bool btc_tx_set_vin_p2sh_multisig(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem)
{
    return btc_script_p2sh_multisig_create_scriptsig(&(pTx->vin[Index].script), pSigs, Num, pRedeem);
}


bool btc_tx_read(btc_tx_t *pTx, const uint8_t *pData, uint32_t Len)
{
    //XXX: check error
    // segwit but non-witness is not permitted

    bool ret = false;
    uint32_t tmp_u32;
    uint64_t tmp_u64;
    uint32_t i;

    btc_buf_r_t txbuf;
    btc_tx_buf_r_init(&txbuf, pData, Len);

    //version
    if (!btc_tx_buf_r_read_u32le(&txbuf, &tmp_u32)) goto LABEL_EXIT;
    pTx->version = (int32_t)tmp_u32;

    //mark, flag
    bool segwit;
    uint8_t flag;
#if defined(USE_BITCOIN)
    // version
    // (mark, flag)
    // vin_cnt
    // vin[vin_cnt]
    //      outpoint
    //      scriptSig
    //      sequence
    // vout_cnt
    // vout[vout_cnt]
    //      value
    //      scriptPubKey
    // (witness)
    //      (scripts)
    // locktime

    uint8_t mark;
    if (!btc_tx_buf_r_read_byte(&txbuf, &mark)) goto LABEL_EXIT;
    if (!btc_tx_buf_r_read_byte(&txbuf, &flag)) goto LABEL_EXIT;
    if (mark == 0x00 && flag == 0x01) { //2017/01/04:BIP-144
        segwit = true;
    } else if (mark == 0x00) {
        goto LABEL_EXIT;
    } else {
        segwit = false;
        if (!btc_tx_buf_r_seek(&txbuf, -2)) goto LABEL_EXIT; //rewind
    }

    //txin count
    if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
    if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
    pTx->vin_cnt = (uint32_t)tmp_u64;
    //XXX: if (pTx->vin_cnt == 0) goto LABEL_EXIT;

    //XXX:
    pTx->vin = (btc_vin_t *)UTL_DBG_MALLOC(sizeof(btc_vin_t) * pTx->vin_cnt);
    if (!pTx->vin) goto LABEL_EXIT;
    memset(pTx->vin, 0x00, sizeof(btc_vin_t) * pTx->vin_cnt);

    //txin
    for (i = 0; i < pTx->vin_cnt; i++) {
        btc_vin_t *vin = &(pTx->vin[i]);

        //txid
        if (!btc_tx_buf_r_read(&txbuf, vin->txid, BTC_SZ_TXID)) goto LABEL_EXIT;

        //index
        if (!btc_tx_buf_r_read_u32le(&txbuf, &vin->index)) goto LABEL_EXIT;

        //scriptSig
        if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
        if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
        if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) goto LABEL_EXIT;
        if (!utl_buf_alloccopy(&vin->script, btc_tx_buf_r_get_pos(&txbuf), (uint32_t)tmp_u64)) goto LABEL_EXIT;
        if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) goto LABEL_EXIT;

        //sequence
        if (!btc_tx_buf_r_read_u32le(&txbuf, &vin->sequence)) goto LABEL_EXIT;
    }

    //txout count
    if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
    if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
    pTx->vout_cnt = (uint32_t)tmp_u64;
    //XXX: if (pTx->vout_cnt == 0) goto LABEL_EXIT;

    //XXX:
    pTx->vout = (btc_vout_t *)UTL_DBG_MALLOC(sizeof(btc_vout_t) * pTx->vout_cnt);
    if (!pTx->vout) goto LABEL_EXIT;
    memset(pTx->vout, 0x00, sizeof(btc_vout_t) * pTx->vout_cnt);

    //txout
    for (i = 0; i < pTx->vout_cnt; i++) {
        btc_vout_t *vout = &(pTx->vout[i]);

        //value
        if (!btc_tx_buf_r_read_u64le(&txbuf, &vout->value)) goto LABEL_EXIT;

        //scriptPubKey
        if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
        if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
        if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) goto LABEL_EXIT;
        if (!utl_buf_alloccopy(&vout->script, btc_tx_buf_r_get_pos(&txbuf), (uint32_t)tmp_u64)) goto LABEL_EXIT;
        if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) goto LABEL_EXIT;
    }

    //witness
    if (segwit) {
        for (i = 0; i < pTx->vin_cnt; i++) {
            //witness item count
            if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
            if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
            if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) goto LABEL_EXIT;
            pTx->vin[i].wit_item_cnt = (uint32_t)tmp_u64;

            //XXX:
            pTx->vin[i].witness = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pTx->vin[i].wit_item_cnt);
            if (!pTx->vin[i].witness) goto LABEL_EXIT;
            memset(pTx->vin[i].witness, 0x00, sizeof(utl_buf_t) * pTx->vin[i].wit_item_cnt);

            //witness item
            for (uint32_t lp = 0; lp < pTx->vin[i].wit_item_cnt; lp++) {
                if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
                if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
                if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) goto LABEL_EXIT;
                if (!utl_buf_alloccopy(&pTx->vin[i].witness[lp], btc_tx_buf_r_get_pos(&txbuf), (uint32_t)tmp_u64)) goto LABEL_EXIT;
                if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) goto LABEL_EXIT;
            }
        }
    }

    //locktime
    if (!btc_tx_buf_r_read_u32le(&txbuf, &pTx->locktime)) goto LABEL_EXIT;
#elif defined(USE_ELEMENTS)
    // version
    // flag
    // vin_cnt
    // vin[vin_cnt]
    //      outpoint
    //      scriptSig
    //      sequence
    // vout_cnt
    // vout[vout_cnt]
    //      asset
    //      value
    //      nonce
    //      scriptPubKey
    // locktime
    // (witnessVin[vin_cnt])
    //      (issuanceAmountRangeProof)
    //      (inflationKeyRangeProof)
    //      (sciprts)
    //      (pegInWitness)
    // (witnessVout[vout_cnt])
    //      surjectionProof
    //      rangeProof

    if (!btc_tx_buf_r_read_byte(&txbuf, &flag)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    segwit = flag & 0x01;
    LOGD("segwit=%d\n", segwit);

    //txin count
    if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
        LOGE("fail: read vin_cnt\n");
        goto LABEL_EXIT;
    }
    if (tmp_u64 > UINT32_MAX) {
        LOGE("fail: too many vin_cnt\n");
        goto LABEL_EXIT;
    }
    pTx->vin_cnt = (uint32_t)tmp_u64;
    //XXX: if (pTx->vin_cnt == 0) goto LABEL_EXIT;

    //XXX:
    pTx->vin = (btc_vin_t *)UTL_DBG_MALLOC(sizeof(btc_vin_t) * pTx->vin_cnt);
    if (!pTx->vin) {
        LOGE("fail: vin_cnt==0\n");
        goto LABEL_EXIT;
    }
    memset(pTx->vin, 0x00, sizeof(btc_vin_t) * pTx->vin_cnt);
    //LOGD("vin_cnt=%d\n", (int)pTx->vin_cnt);

    //txin
    for (i = 0; i < pTx->vin_cnt; i++) {
        btc_vin_t *vin = &(pTx->vin[i]);

        //txid
        if (!btc_tx_buf_r_read(&txbuf, vin->txid, BTC_SZ_TXID)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }

        //index
        if (!btc_tx_buf_r_read_u32le(&txbuf, &vin->index)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        vin->issuance = !!(vin->index & BTC_TX_ELE_IDX_ISSUANCE);
        vin->pegin = !!(vin->index & BTC_TX_ELE_IDX_PEGIN);
        vin->index &= 0x3fffffff;

        //scriptSig
        if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (tmp_u64 > UINT32_MAX) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (!utl_buf_alloccopy(&vin->script, btc_tx_buf_r_get_pos(&txbuf), (uint32_t)tmp_u64)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }

        //sequence
        if (!btc_tx_buf_r_read_u32le(&txbuf, &vin->sequence)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }

        if (vin->issuance) {
            uint8_t asset_blinding_nonce[32];
            uint8_t asset_entropy[32];
            uint64_t asset_amount;
            uint64_t token_amount;
            btc_tx_buf_r_read(&txbuf, asset_blinding_nonce, 32);
            btc_tx_buf_r_read(&txbuf, asset_entropy, 32);
            uint8_t version;
            read_elements_vout_value(&txbuf, &version, &asset_amount, NULL);
            read_elements_vout_value(&txbuf, &version, &token_amount, NULL);
        }
    }

    //txout count
    if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    if (tmp_u64 > UINT32_MAX) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    pTx->vout_cnt = (uint32_t)tmp_u64;
    //XXX: if (pTx->vout_cnt == 0) goto LABEL_EXIT;
    //LOGD("vout_cnt=%d\n", (int)pTx->vout_cnt);

    //XXX:
    pTx->vout = (btc_vout_t *)UTL_DBG_MALLOC(sizeof(btc_vout_t) * pTx->vout_cnt);
    if (!pTx->vout) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }
    memset(pTx->vout, 0x00, sizeof(btc_vout_t) * pTx->vout_cnt);

    //txout
    for (i = 0; i < pTx->vout_cnt; i++) {
        btc_vout_t *vout = &(pTx->vout[i]);
        uint8_t dummy[BTC_TX_ELE_VOUT_EXPLICIT_SIZE];
        uint8_t version;

        //asset
        if (!btc_tx_buf_r_read_byte(&txbuf, &version)) {
            LOGE("fail: version\n");
            goto LABEL_EXIT;
        }
        switch (version) {
        case BTC_TX_ELE_VOUT_VER_NULL:
            break;
        case BTC_TX_ELE_VOUT_VER_EXPLICIT:
            if (!btc_tx_buf_r_read(&txbuf, vout->asset, BTC_SZ_HASH256)) {
                LOGE("fail: asset\n");
                goto LABEL_EXIT;
            }
            break;
        case BTC_TX_ELE_VOUT_VER_ASSET_PFA:
        case BTC_TX_ELE_VOUT_VER_ASSET_PFB:
            if (!btc_tx_buf_r_read(&txbuf, dummy, BTC_TX_ELE_VOUT_EXPLICIT_SIZE)) {
                LOGE("fail: confidential asset\n");
                goto LABEL_EXIT;
            }
            break;
        default:
            LOGE("fail: version=%02x\n", version);
            goto LABEL_EXIT;
        }
        vout->ver_asset = version;

        //value
        if (!read_elements_vout_value(&txbuf, &vout->ver_value, &vout->value, dummy)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }

        //nonce
        if (!btc_tx_buf_r_read_byte(&txbuf, &version)) {
            LOGE("fail: version\n");
            goto LABEL_EXIT;
        }
        switch (version) {
        case BTC_TX_ELE_VOUT_VER_NULL:
            break;
        case BTC_TX_ELE_VOUT_VER_EXPLICIT:
        case BTC_TX_ELE_VOUT_VER_NONCE_PFA:
        case BTC_TX_ELE_VOUT_VER_NONCE_PFB:
            if (!btc_tx_buf_r_read(&txbuf, dummy, BTC_TX_ELE_VOUT_EXPLICIT_SIZE)) {
                LOGE("fail: nonce\n");
                goto LABEL_EXIT;
            }
            break;
        default:
            LOGE("fail: version=%02x\n", version);
            goto LABEL_EXIT;
        }
        vout->ver_nonce = version;

        //scriptPubKey
        if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (tmp_u64 > UINT32_MAX) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (!utl_buf_alloccopy(&vout->script, btc_tx_buf_r_get_pos(&txbuf), (uint32_t)tmp_u64)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }
        if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) {
            LOGE("fail\n");
            goto LABEL_EXIT;
        }

        if (vout->value > 0) {
            //address or fee or burn
            if (vout->script.len == 0) {
                vout->type = BTC_TX_ELE_VOUT_FEE;
            } else if ((vout->script.len == 1) && (vout->script.buf[0] == OP_RETURN)) {
                vout->type = BTC_TX_ELE_VOUT_BURN;
            } else {
                vout->type = BTC_TX_ELE_VOUT_ADDR;
            }
        } else {
            //data or vdata
            vout->type = BTC_TX_ELE_VOUT_DATA;
        }
    }

    //locktime
    if (!btc_tx_buf_r_read_u32le(&txbuf, &pTx->locktime)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    //witness
    if (segwit) {
        //vinsegwit
        for (i = 0; i < pTx->vin_cnt; i++) {
            //issuanceAmountRangeProof
            if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            if (tmp_u64 != 0) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            //inflationKeyRangeProof
            if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            if (tmp_u64 != 0) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            //witnessScripts
            if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            if (tmp_u64 > UINT32_MAX) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            pTx->vin[i].wit_item_cnt = (uint32_t)tmp_u64;
            pTx->vin[i].witness = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pTx->vin[i].wit_item_cnt);
            if (!pTx->vin[i].witness) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            memset(pTx->vin[i].witness, 0x00, sizeof(utl_buf_t) * pTx->vin[i].wit_item_cnt);
            for (uint32_t lp = 0; lp < pTx->vin[i].wit_item_cnt; lp++) {
                if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
                    LOGE("fail\n");
                    goto LABEL_EXIT;
                }
                if (tmp_u64 > UINT32_MAX) {
                    LOGE("fail\n");
                    goto LABEL_EXIT;
                }
                if (tmp_u64 > btc_tx_buf_r_remains(&txbuf)) {
                    LOGE("fail\n");
                    goto LABEL_EXIT;
                }
                if (!utl_buf_alloccopy(&pTx->vin[i].witness[lp], btc_tx_buf_r_get_pos(&txbuf), (uint32_t)tmp_u64)) {
                    LOGE("fail\n");
                    goto LABEL_EXIT;
                }
                if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) {
                    LOGE("fail\n");
                    goto LABEL_EXIT;
                }
            }
            //pegInWitness
            if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
        }
        //voutsegwit
        for (i = 0; i < pTx->vout_cnt; i++) {
            //surjectionProof
            if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            //rangeProof
            if (!btc_tx_buf_r_read_varint(&txbuf, &tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
            if (!btc_tx_buf_r_seek(&txbuf, (uint32_t)tmp_u64)) {
                LOGE("fail\n");
                goto LABEL_EXIT;
            }
        }
    }
#else
    #error neither BITCOIN nor ELEMENTS
#endif

    //check the end of the data
    if (btc_tx_buf_r_remains(&txbuf)) {
        LOGE("fail\n");
        goto LABEL_EXIT;
    }

    ret = true;

LABEL_EXIT:
    if (!ret) {
        LOGE("fail: read_tx\n");
        btc_tx_free(pTx);
    }
    return ret;
}


bool btc_tx_write(const btc_tx_t *pTx, utl_buf_t *pBuf)
{
    return btc_tx_write_2(pBuf, pTx, true);
}


bool btc_tx_sighash(btc_tx_t *pTx, uint8_t *pTxHash, const utl_buf_t *pScriptPks[], uint32_t Num)
{
    bool ret = false;
    const uint32_t sigtype = (uint32_t)SIGHASH_ALL;
    utl_buf_t buf = UTL_BUF_INIT;

    btc_tx_valid_t txvld = btc_tx_is_valid(pTx);
    if (txvld != BTC_TXVALID_OK) {
        LOGE("fail: invalid tx\n");
        return false;
    }

    if (pTx->vin_cnt != Num) {
        LOGE("fail: invalid vin_cnt\n");
        return false;
    }

    //scriptSig -> tmp
    utl_buf_t *tmp_vinbuf = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pTx->vin_cnt);
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &pTx->vin[lp];

        tmp_vinbuf[lp].buf = vin->script.buf;
        tmp_vinbuf[lp].len = vin->script.len;
    }

    //scriptPubKey -> scriptSig
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &pTx->vin[lp];

        vin->script.buf = (uint8_t *)UTL_DBG_MALLOC(pScriptPks[lp]->len);
        if (!vin->script.buf) goto LABEL_EXIT;
        vin->script.len = pScriptPks[lp]->len;
        memcpy(vin->script.buf, pScriptPks[lp]->buf, pScriptPks[lp]->len);
    }

    //calc hash
    if (!btc_tx_write(pTx, &buf)) {
        assert(0);
        goto LABEL_EXIT;
    }
    if (!utl_buf_realloc(&buf, buf.len + sizeof(sigtype))) {
        utl_buf_free(&buf);
        goto LABEL_EXIT;
    }
    memcpy(buf.buf + buf.len - sizeof(sigtype), &sigtype, sizeof(sigtype));
    btc_md_hash256(pTxHash, buf.buf, buf.len);
    utl_buf_free(&buf);

    //tmp -> scriptSig
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &pTx->vin[lp];

        utl_buf_free(&vin->script);
        vin->script.buf = tmp_vinbuf[lp].buf;
        vin->script.len = tmp_vinbuf[lp].len;
    }
    UTL_DBG_FREE(tmp_vinbuf);

    ret = true;

LABEL_EXIT:
    return ret;
}


bool btc_tx_sign_p2pkh(btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey)
{
    uint8_t pubkey[BTC_SZ_PUBKEY];
    if (pPubKey == NULL) {
        if (!btc_keys_priv2pub(pubkey, pPrivKey)) {
            assert(0);
            return false;
        }
        pPubKey = pubkey;
    }
    return btc_script_p2pkh_sign_scriptsig(&(pTx->vin[Index].script), pTxHash, pPrivKey, pPubKey);
}


bool btc_tx_verify_p2pkh(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
{
    return btc_script_p2pkh_verify_scriptsig(&(pTx->vin[Index].script), pTxHash, pPubKeyHash);
}


bool btc_tx_verify_p2pkh_spk(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    return btc_script_p2pkh_verify_scriptsig_spk(&(pTx->vin[Index].script), pTxHash, pScriptPk);
}


bool btc_tx_verify_p2pkh_addr(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    if (!btc_keys_addr2hash(hash, &pref, pAddr)) return false;
    if (pref != BTC_PREF_P2PKH) return false;
    return btc_script_p2pkh_verify_scriptsig(&pTx->vin[Index].script, pTxHash, hash);
}


bool btc_tx_verify_p2sh_multisig(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pScriptHash)
{
    return btc_script_p2sh_multisig_verify_scriptsig(&(pTx->vin[Index].script), pTxHash, pScriptHash);
}


bool btc_tx_verify_p2sh_multisig_spk(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    return btc_script_p2sh_multisig_verify_scriptsig_spk(&(pTx->vin[Index].script), pTxHash, pScriptPk);
}


bool btc_tx_verify_p2sh_multisig_addr(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    if (!btc_keys_addr2hash(hash, &pref, pAddr)) return false;
    if (pref != BTC_PREF_P2SH) return false;
    return btc_script_p2sh_multisig_verify_scriptsig(&pTx->vin[Index].script, pTxHash, hash);
}


bool btc_tx_txid(const btc_tx_t *pTx, uint8_t *pTxId)
{
    utl_buf_t txbuf = UTL_BUF_INIT;

    bool ret = btc_tx_write_2(&txbuf, pTx, false);
    if (!ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    btc_md_hash256(pTxId, txbuf.buf, txbuf.len);
    utl_buf_free(&txbuf);

LABEL_EXIT:
    return ret;
}


bool btc_tx_txid_raw(uint8_t *pTxId, const utl_buf_t *pTxRaw)
{
    btc_md_hash256(pTxId, pTxRaw->buf, pTxRaw->len);
    return true;
}


// uint32_t btc_tx_get_vbyte(const btc_tx_t *pTx)
// {
//     //segwit判定
//     bool segwit = false;
//     for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
//         btc_vin_t *vin = &(pTx->vin[lp]);
//         if (vin->wit_item_cnt) {
//             segwit = true;
//         }
//     }
//     return 0;
// }


uint32_t btc_tx_get_vbyte_raw(const uint8_t *pData, uint32_t Len)
{
    //(旧format*3 + 新format) / 4を切り上げ
    uint32_t weight = btc_tx_get_weight_raw(pData, Len);
    uint32_t vsize = (weight + 3) / 4;
    LOGD("vsize=%" PRIu32 "\n", vsize);
    return vsize;
}


uint32_t btc_tx_get_weight_raw(const uint8_t *pData, uint32_t Len)
{
    //segwit判定
    bool segwit;
#if defined(USE_BITCOIN)
    uint8_t mark = pData[4];
    uint8_t flag = pData[5];
    if ((mark == 0x00) && (flag != 0x01)) {
        //2017/01/04:BIP-144ではflag==0x01のみ
        return 0;
    }
    segwit = ((mark == 0x00) && (flag == 0x01));
#elif defined(USE_ELEMENTS)
    segwit = pData[4] & 0x01;
#endif

    //https://bitcoincore.org/ja/segwit_wallet_dev/#transaction-fee-estimation
    uint32_t len;
    if (segwit) {
        //旧format*3 + 新format
        //  旧: nVersion            |txins|txouts        |nLockTime
        //  新: nVersion|marker|flag|txins|txouts|witness|nLockTime
        btc_tx_t txold = BTC_TX_INIT;
        utl_buf_t txbuf_old = UTL_BUF_INIT;

        if (!btc_tx_read(&txold, pData, Len)) {
            LOGE("fail: vbyte\n");
            len = 0;
            goto LABEL_EXIT;
        }

        if (!btc_tx_write_2(&txbuf_old, &txold, false)) {
            LOGE("fail: vbyte\n");
            len = 0;
            goto LABEL_EXIT;
        }

        uint32_t fmt_old = txbuf_old.len;
        uint32_t fmt_new = Len;
        len = fmt_old * 3 + fmt_new;
    } else {
        len = Len * 4;
    }

LABEL_EXIT:
    LOGD("weight=%" PRIu32 "\n", len);
    return len;
}


void btc_tx_sort_bip69(btc_tx_t *pTx)
{
    //sort vin
    //  key1: txid
    //  key2: index
    if (pTx->vin_cnt > 1) {
        for (uint32_t lp = 0; lp < pTx->vin_cnt - 1; lp++) {
            for (uint32_t lp2 = lp + 1; lp2 < pTx->vin_cnt; lp2++) {
                btc_vin_t *p_vin1 = &pTx->vin[lp];
                btc_vin_t *p_vin2 = &pTx->vin[lp2];
                uint8_t txid1[BTC_SZ_TXID];
                uint8_t txid2[BTC_SZ_TXID];
                utl_mem_reverse_byte(txid1, p_vin1->txid, BTC_SZ_TXID);
                utl_mem_reverse_byte(txid2, p_vin2->txid, BTC_SZ_TXID);
                int cmp = memcmp(txid1, txid2, BTC_SZ_TXID);
                if (cmp < 0) continue;
                if (cmp == 0) {
                    if (p_vin1->index < p_vin2->index) continue;
                }
                btc_vin_t tmp;
                utl_mem_swap(p_vin1, p_vin2, &tmp, sizeof(btc_vin_t));
            }
        }
    }

    //sort vout
    //  key1: amount (numerical order)
    //  key2: scriptPubKey
    if (pTx->vout_cnt > 1) {
        for (uint32_t lp = 0; lp < pTx->vout_cnt - 1; lp++) {
            for (uint32_t lp2 = lp + 1; lp2 < pTx->vout_cnt; lp2++) {
                btc_vout_t *p_vout1 = &pTx->vout[lp];
                btc_vout_t *p_vout2 = &pTx->vout[lp2];
#ifdef USE_ELEMENTS
                if (p_vout1->script.len == 0) {
                    // fee vout place last
                    btc_vout_t tmp;
                    utl_mem_swap(p_vout1, p_vout2, &tmp, sizeof(btc_vout_t));
                }
#endif
                if (p_vout1->value < p_vout2->value) continue;
                if (p_vout1->value == p_vout2->value) {
                    uint16_t min_len = (p_vout1->script.len < p_vout2->script.len) ?
                        p_vout1->script.len : p_vout2->script.len;
                    int cmp = memcmp(p_vout1->script.buf, p_vout2->script.buf, min_len);
                    if (cmp <= 0) continue;
                }
                btc_vout_t tmp;
                utl_mem_swap(p_vout1, p_vout2, &tmp, sizeof(btc_vout_t));
            }
        }
    }
}


#if defined(PTARM_USE_PRINTFUNC) && !defined(PTARM_UTL_LOG_MACRO_DISABLED)
void btc_tx_print(const btc_tx_t *pTx)
{
    LOGD2("======================================\n");
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);
    LOGD2("txid= ");
    TXIDD(txid);
    LOGD2("======================================\n");
    LOGD2(" version:%d\n", pTx->version);
    LOGD2("\n");
    LOGD2(" txin_cnt= %u\n", pTx->vin_cnt);
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        LOGD2(" [vin #%u]\n", lp);
        LOGD2("  txid= ");
        TXIDD(pTx->vin[lp].txid);
        LOGD2("       LE: ");
        DUMPD(pTx->vin[lp].txid, BTC_SZ_TXID);
        LOGD2("  index= %u\n", pTx->vin[lp].index);
#ifdef USE_ELEMENTS
        LOGD2("    issuance= %d\n", pTx->vin[lp].issuance);
        LOGD2("    pegin= %d\n", pTx->vin[lp].pegin);
#endif
        LOGD2("  scriptSig[%u]= ", pTx->vin[lp].script.len);
        DUMPD(pTx->vin[lp].script.buf, pTx->vin[lp].script.len);
        //btc_script_print(pTx->vin[lp].script.buf, pTx->vin[lp].script.len);
        ////p2sh-p2wsh
        //bool p2wsh = (pTx->vin[lp].script.len == 35) && //redeemScript
        //             (pTx->vin[lp].script.buf[1] == 0x00) && //witness program
        //             (pTx->vin[lp].script.buf[2] == 0x20);
        //bool p2wsh = (pTx->vin[lp].wit_item_cnt >= 3);
        LOGD2("  sequence= 0x%08x\n", pTx->vin[lp].sequence);
        for (uint32_t lp2 = 0; lp2 < pTx->vin[lp].wit_item_cnt; lp2++) {
            LOGD2("    wit[%u][%u]= ", lp2, pTx->vin[lp].witness[lp2].len);
            if (pTx->vin[lp].witness[lp2].len) {
                DUMPD(pTx->vin[lp].witness[lp2].buf, pTx->vin[lp].witness[lp2].len);
                // if (p2wsh &&(lp2 == pTx->vin[lp].wit_item_cnt - 1)) {
                //     //P2WSHの最後はwitnessScript
                //     //Native P2WSHでも表示させたかったが、識別する方法が思いつかない
                //     btc_script_print(pTx->vin[lp].witness[lp2].buf, pTx->vin[lp].witness[lp2].len);
                // }
            } else {
                LOGD2("<none>\n");
            }
        }
        LOGD2("\n");
    }
    LOGD2(" txout_cnt= %u\n", pTx->vout_cnt);
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        LOGD2(" [vout #%u]\n", lp);
#if defined(USE_BITCOIN)
        LOGD2("  value= %llu (%-.8lf " BTC_UNIT ")\n", (unsigned long long)pTx->vout[lp].value, BTC_SATOSHI2BTC(pTx->vout[lp].value));
        //DUMPD(((const uint8_t *)&pTx->vout[lp].value), sizeof(pTx->vout[lp].value));
        //LOGD2("    %10.5f m" BTC_UNIT ", %10.8f " BTC_UNIT "\n", BTC_SATOSHI2MBTC(pTx->vout[lp].value), BTC_SATOSHI2BTC(pTx->vout[lp].value));
#elif defined(USE_ELEMENTS)
        const char *p_type_str;
        switch (pTx->vout[lp].type) {
        case BTC_TX_ELE_VOUT_ADDR:
            p_type_str = "address";
            break;
        case BTC_TX_ELE_VOUT_DATA:
            p_type_str = "data";
            break;
        case BTC_TX_ELE_VOUT_BURN:
            p_type_str = "burn";
            break;
        case BTC_TX_ELE_VOUT_FEE:
            p_type_str = "fee";
            break;
        default:
            p_type_str = "unknown";
        }
        LOGD2("  type=%s\n", p_type_str);
        LOGD2("  asset(version=0x%02x)=", pTx->vout[lp].ver_asset);
        switch (pTx->vout[lp].ver_asset) {
        case BTC_TX_ELE_VOUT_VER_NULL:
            LOGD2("<NULL>\n");
            break;
        case BTC_TX_ELE_VOUT_VER_EXPLICIT:
            DUMPD(pTx->vout[lp].asset, BTC_SZ_HASH256);
            break;
        case BTC_TX_ELE_VOUT_VER_ASSET_PFA:
            LOGD2("<confidential:prefixA>\n");
            break;
        case BTC_TX_ELE_VOUT_VER_ASSET_PFB:
            LOGD2("<confidential:prefixB>\n");
            break;
        default:
            LOGD2("<confidential:unknown>\n");
        }

        LOGD2("  value(version=0x%02x)=", pTx->vout[lp].ver_value);
        switch (pTx->vout[lp].ver_value) {
        case BTC_TX_ELE_VOUT_VER_NULL:
            LOGD2("<NULL>\n");
            break;
        case BTC_TX_ELE_VOUT_VER_EXPLICIT:
            LOGD2("%llu (%-.8lf " BTC_UNIT ")\n",
                    (unsigned long long)pTx->vout[lp].value,
                    BTC_SATOSHI2BTC(pTx->vout[lp].value));
            break;
        case BTC_TX_ELE_VOUT_VER_VALUE_PFA:
            LOGD2("<confidential:prefixA>\n");
            break;
        case BTC_TX_ELE_VOUT_VER_VALUE_PFB:
            LOGD2("<confidential:prefixB>\n");
            break;
        default:
            LOGD2("<confidential:unknown>\n");
        }

        LOGD2("  nonce(version=0x%02x)=", pTx->vout[lp].ver_nonce);
        switch (pTx->vout[lp].ver_nonce) {
        case BTC_TX_ELE_VOUT_VER_NULL:
            LOGD2("<NULL>\n");
            break;
        case BTC_TX_ELE_VOUT_VER_EXPLICIT:
            LOGD2("...\n");
            break;
        case BTC_TX_ELE_VOUT_VER_NONCE_PFA:
            LOGD2("<confidential:prefixA>\n");
            break;
        case BTC_TX_ELE_VOUT_VER_NONCE_PFB:
            LOGD2("<confidential:prefixB>\n");
            break;
        default:
            LOGD2("<confidential:unknown>\n");
        }
#endif
        utl_buf_t *buf = &(pTx->vout[lp].script);
        LOGD2("  scriptPubKey[%u]= ", buf->len);
        DUMPD(buf->buf, buf->len);
        //btc_script_print(buf->buf, buf->len);
#if defined(USE_BITCOIN)
        char addr[BTC_SZ_ADDR_STR_MAX + 1];
        if (btc_keys_spk2addr(addr, buf)) {
            LOGD2("    (%s)\n", addr);
        }
#endif
        LOGD2("\n");
    }
    LOGD2(" locktime= 0x%08x : ", pTx->locktime);
    if (pTx->locktime < BTC_TX_LOCKTIME_LIMIT) {
        //ブロック高
        LOGD2("block height\n");
    } else {
        //epoch second
        char time[UTL_SZ_TIME_FMT_STR + 1];
        LOGD2("epoch second: %s\n", utl_time_fmt(time, pTx->locktime));
    }
    LOGD2("======================================\n");
}


void btc_tx_print_raw(const uint8_t *pData, uint32_t Len)
{
    btc_tx_t tx;
    bool ret = btc_tx_read(&tx, pData, Len);
    if (!ret) {
        return;
    }

    btc_tx_print(&tx);

    btc_tx_free(&tx);
}
#endif  //PTARM_USE_PRINTFUNC


/**************************************************************************
 * package functions
 **************************************************************************/

/** トランザクションデータ作成
 *
 * @param[out]      pBuf            変換後データ
 * @param[in]       pTx             対象データ
 * @param[in]       enableSegWit    false:pTxがsegwitでも、witnessを作らない(TXID計算用)
 *
 * @note
 *      - 動的にメモリ確保するため、pBufは使用後 #utl_buf_free()で解放すること
 *      - vin cntおよびvout cntは 252までしか対応しない(varint型の1byteまで)
 */
static bool btc_tx_write_2(utl_buf_t *pBuf, const btc_tx_t *pTx, bool enableSegWit)
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

#if defined(USE_BITCOIN)
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
#elif defined(USE_ELEMENTS)
    //version[4]
    //flag[1]...segwit
    //vin_cnt[v]
    //  txid[32]
    //  index[4]
    //  script[v|data]
    //  sequence[4]
    //vout_cnt[v]
    //  version[1] + asset[32]
    //  version[1] + value[8]
    //  version[1] + nonce[0]
    //  script[v|data]
    //locktime[4]
    //witness...segwit
    //  vin_witness
    //      issuanceAmountRangeProof[1]
    //      inflationKeyRangeProof[1]
    //      wit_item_cnt[v]
    //          script[v|data]
    //      pegInWitness[1]
    //  vout_witness
    //      surjectionProof[1]
    //      rangeProof[1]

    if (!btc_tx_buf_w_write_u32le(&buf, pTx->version)) goto LABEL_EXIT;
    if (!btc_tx_buf_w_write_byte(&buf, (segwit) ? 0x01 : 0x00)) goto LABEL_EXIT;

    if (!btc_tx_buf_w_write_varint_len(&buf, pTx->vin_cnt)) goto LABEL_EXIT;
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &(pTx->vin[lp]);
        if (!btc_tx_buf_w_write_data(&buf, vin->txid, BTC_SZ_TXID)) goto LABEL_EXIT;
        uint32_t index = vin->index;
        if (vin->issuance) index |= BTC_TX_ELE_IDX_ISSUANCE;
        if (vin->pegin) index |= BTC_TX_ELE_IDX_PEGIN;
        if (!btc_tx_buf_w_write_u32le(&buf, index)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_varint_len_data(&buf, vin->script.buf, vin->script.len)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_u32le(&buf, vin->sequence)) goto LABEL_EXIT;
    }

    if (!btc_tx_buf_w_write_varint_len(&buf, pTx->vout_cnt)) goto LABEL_EXIT;
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        const btc_vout_t *vout = &(pTx->vout[lp]);
        //asset
        if (!btc_tx_buf_w_write_byte(&buf, BTC_TX_ELE_VOUT_VER_EXPLICIT)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_data(&buf, vout->asset, BTC_SZ_HASH256)) goto LABEL_EXIT;
        //value
        if (!btc_tx_buf_w_write_byte(&buf, BTC_TX_ELE_VOUT_VER_EXPLICIT)) goto LABEL_EXIT;
        if (!btc_tx_buf_w_write_u64be(&buf, vout->value)) goto LABEL_EXIT;
        //nonce
        if (!btc_tx_buf_w_write_byte(&buf, BTC_TX_ELE_VOUT_VER_NULL)) goto LABEL_EXIT;
        //script
        if (!btc_tx_buf_w_write_varint_len_data(&buf, vout->script.buf, vout->script.len)) goto LABEL_EXIT;
    }

    if (!btc_tx_buf_w_write_u32le(&buf, pTx->locktime)) goto LABEL_EXIT;

    if (segwit) {
        for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
            btc_vin_t *vin = &(pTx->vin[lp]);
            //issuanceAmountRangeProof
            if (!btc_tx_buf_w_write_byte(&buf, 0)) goto LABEL_EXIT;
            //inflationKeyRangeProof
            if (!btc_tx_buf_w_write_byte(&buf, 0)) goto LABEL_EXIT;
            //witnessScript
            if (!btc_tx_buf_w_write_varint_len(&buf, vin->wit_item_cnt)) goto LABEL_EXIT;
            for (uint32_t lp2 = 0; lp2 < vin->wit_item_cnt; lp2++) {
                utl_buf_t *wit_item = &(vin->witness[lp2]);
                if (!btc_tx_buf_w_write_varint_len_data(&buf, wit_item->buf, wit_item->len)) goto LABEL_EXIT;
            }
            //pegInWitness
            if (!btc_tx_buf_w_write_byte(&buf, 0)) goto LABEL_EXIT;
        }
        for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
            //surjectionProof
            if (!btc_tx_buf_w_write_byte(&buf, 0)) goto LABEL_EXIT;
            //rangeProof
            if (!btc_tx_buf_w_write_byte(&buf, 0)) goto LABEL_EXIT;
        }
    }

    pBuf->buf = btc_tx_buf_w_get_data(&buf);
    pBuf->len = btc_tx_buf_w_get_len(&buf);
#endif

    ret = true;

LABEL_EXIT:
    if (!ret) {
        btc_tx_buf_w_free(&buf);
    }

    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

#ifdef USE_ELEMENTS
static bool read_elements_vout_value(btc_buf_r_t *pTxBuf, uint8_t *pVersion, uint64_t *pValue, uint8_t *pCommitValue)
{
    uint8_t version;

    if (!btc_tx_buf_r_read_byte(pTxBuf, &version)) {
        LOGE("fail: version\n");
        return false;
    }
    switch (version) {
    case BTC_TX_ELE_VOUT_VER_NULL:
        break;
    case BTC_TX_ELE_VOUT_VER_EXPLICIT:
        if (pValue == NULL) {
            return false;
        }
        if (!btc_tx_buf_r_read_u64be(pTxBuf, pValue)) {
            LOGE("fail: value\n");
            return false;
        }
        break;
    case BTC_TX_ELE_VOUT_VER_VALUE_PFA:
    case BTC_TX_ELE_VOUT_VER_VALUE_PFB:
        if (pCommitValue == NULL) {
            return false;
        }
        if (!btc_tx_buf_r_read(pTxBuf, pCommitValue, BTC_TX_ELE_VOUT_EXPLICIT_SIZE)) {
            LOGE("fail: confidential value\n");
            return false;
        }
        break;
    default:
        LOGE("fail: version=%02x\n", version);
        return false;
    }
    if (pVersion != NULL) {
        *pVersion = version;
    }

    return true;
}
#endif
