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
/** @file   btc_tx.c
 *  @brief  bitcoin処理: トランザクション生成関連
 */
#ifdef PTARM_USE_PRINTFUNC
#endif  //PTARM_USE_PRINTFUNC

#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"

#include "utl_dbg.h"
#include "utl_time.h"
#include "utl_int.h"

#include "btc_local.h"
#include "btc_segwit_addr.h"
#include "btc_script.h"


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    const uint8_t   *data;
    uint32_t        len;
    uint32_t        pos;
} tx_buf;


/**************************************************************************
 * prototypes
 **************************************************************************/

static void tx_buf_init(tx_buf *pBuf, const uint8_t *pData, uint32_t Len);
static const uint8_t *tx_buf_get_pos(tx_buf *pBuf);
static bool tx_buf_read(tx_buf *pBuf, uint8_t *pData, uint32_t Len);
static bool tx_buf_read_byte(tx_buf *pBuf, uint8_t *pByte);
static bool tx_buf_read_u32le(tx_buf *pBuf, uint32_t *U32);
static bool tx_buf_read_u64le(tx_buf *pBuf, uint64_t *U64);
static bool tx_buf_seek(tx_buf *pBuf, int32_t offset);
static uint32_t tx_buf_remains(tx_buf *pBuf);
static bool tx_buf_read_varint(tx_buf *pBuf, uint64_t *pValue);


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
    const uint8_t M_OP_RETURN = 0x6a;

    if (pTx == NULL) {
        LOGD("fail: null\n");
        return BTC_TXVALID_ARG_NULL;
    }
    if (pTx->version != 1 && pTx->version != 2) {
        LOGD("fail: version\n");
        return BTC_TXVALID_VERSION_BAD;
    }
    if (pTx->vin_cnt == 0) {
        LOGD("fail: vin_cnt\n");
        return BTC_TXVALID_VIN_NONE;
    }
    if (pTx->vin == NULL) {
        LOGD("fail: NULL vin\n");
        return BTC_TXVALID_VIN_NULL;
    }
    if (pTx->vout_cnt == 0) {
        LOGD("fail: vout_cnt\n");
        btc_tx_print(pTx);
        return BTC_TXVALID_VOUT_NONE;
    }
    if (pTx->vout == NULL) {
        LOGD("fail: NULL vout\n");
        return BTC_TXVALID_VOUT_NULL;
    }
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        const btc_vin_t *vin = &pTx->vin[lp];

        if ((vin->wit_item_cnt > 0) && (vin->witness == NULL)) {
            LOGD("fail: NULL witness[%u]\n", lp);
            return BTC_TXVALID_VIN_WIT_NULL;
        } else if ((vin->wit_item_cnt == 0) && (vin->witness != NULL)) {
            LOGD("fail: bad witness[%u]\n", lp);
            return BTC_TXVALID_VIN_WIT_BAD;
        } else {
            //OK
        }
        for (uint32_t wit = 0; wit < vin->wit_item_cnt; wit++) {
            const utl_buf_t *buf = &vin->witness[wit];
            if (buf == NULL) {
                LOGD("fail: NULL witness[%u][%u]", lp, wit);
                return BTC_TXVALID_VIN_WIT_NULL;
            }
            //OP_0はlen=0になるので、buf=NULLはあり得る
        }
    }
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        const btc_vout_t *vout = &pTx->vout[lp];

        if (vout->script.len == 0) {
            LOGD("fail: no scriptPubKeyHash[%u]\n", lp);
            return BTC_TXVALID_VOUT_SPKH_NONE;
        }
        if ((vout->value == 0) && (vout->script.buf[0] != M_OP_RETURN)) {
            LOGD("fail: no value[%u]\n", lp);
            return BTC_TXVALID_VOUT_VALUE_BAD;
        }
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
        if (!btc_script_pk_create(&vout->script, hash, pref)) return false;
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
    return btcl_util_add_vout_pub(pTx, Value, pPubKey, BTC_PREF_P2PKH);
}


bool btc_tx_add_vout_p2pkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash)
{
    return btcl_util_add_vout_pkh(pTx, Value, pPubKeyHash, BTC_PREF_P2PKH);
}


bool btc_tx_create_spk(utl_buf_t *pBuf, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret) {
        ret = btc_script_pk_create(pBuf, hash, pref);
    }

    return ret;
}


bool btc_tx_create_spk_p2pkh(utl_buf_t *pBuf, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2PKH)) {
        ret = btc_script_pk_create(pBuf, hash, pref);
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
    return btc_script_pk_create(&vout->script, pScriptHash, BTC_PREF_P2SH);
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
    btc_util_hash160(sh, pRedeem->buf, pRedeem->len);
    return btc_tx_add_vout_p2sh(pTx, Value, sh);
}


bool btc_tx_set_vin_p2pkh(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSig, const uint8_t *pPubKey)
{
    return btc_script_sig_create_p2pkh(&(pTx->vin[Index].script), pSig, pPubKey);
}


bool btc_tx_set_vin_p2sh_multisig(btc_tx_t *pTx, uint32_t Index, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem)
{
    return btc_script_sig_create_p2sh_multisig(&(pTx->vin[Index].script), pSigs, Num, pRedeem);
}


bool btc_tx_read(btc_tx_t *pTx, const uint8_t *pData, uint32_t Len)
{
    bool ret = false;
    uint32_t tmp_u32;
    uint64_t tmp_u64;
    uint32_t i;

    tx_buf txbuf;
    tx_buf_init(&txbuf, pData, Len);

    //version
    if (!tx_buf_read_u32le(&txbuf, &tmp_u32)) goto LABEL_EXIT;
    pTx->version = (int32_t)tmp_u32;

    //mark, flag
    bool segwit;
    uint8_t mark;
    uint8_t flag;
    if (!tx_buf_read_byte(&txbuf, &mark)) goto LABEL_EXIT;
    if (!tx_buf_read_byte(&txbuf, &flag)) goto LABEL_EXIT;
    if (mark == 0x00 && flag == 0x01) { //2017/01/04:BIP-144
        segwit = true;
    } else if (mark == 0x00) {
        goto LABEL_EXIT;
    } else {
        segwit = false;
        if (!tx_buf_seek(&txbuf, -2)) goto LABEL_EXIT; //rewind
    }

    //txin count
    if (!tx_buf_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
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
        if (!tx_buf_read(&txbuf, vin->txid, BTC_SZ_TXID)) goto LABEL_EXIT;

        //index
        if (!tx_buf_read_u32le(&txbuf, &vin->index)) goto LABEL_EXIT;

        //scriptSig
        if (!tx_buf_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
        if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
        if (tmp_u64 > tx_buf_remains(&txbuf)) goto LABEL_EXIT;
        if (!utl_buf_alloccopy(&vin->script, tx_buf_get_pos(&txbuf), (uint32_t)tmp_u64)) goto LABEL_EXIT;
        if (!tx_buf_seek(&txbuf, (uint32_t)tmp_u64)) goto LABEL_EXIT;

        //sequence
        if (!tx_buf_read_u32le(&txbuf, &vin->sequence)) goto LABEL_EXIT;
    }

    //txout count
    if (!tx_buf_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
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
        if (!tx_buf_read_u64le(&txbuf, &vout->value)) goto LABEL_EXIT;

        //scriptPubKey
        if (!tx_buf_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
        if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
        if (tmp_u64 > tx_buf_remains(&txbuf)) goto LABEL_EXIT;
        if (!utl_buf_alloccopy(&vout->script, tx_buf_get_pos(&txbuf), (uint32_t)tmp_u64)) goto LABEL_EXIT;
        if (!tx_buf_seek(&txbuf, (uint32_t)tmp_u64)) goto LABEL_EXIT;
    }

    //witness
    if (segwit) {
        for (i = 0; i < pTx->vin_cnt; i++) {
            //witness item count
            if (!tx_buf_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
            if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
            if (tmp_u64 > tx_buf_remains(&txbuf)) goto LABEL_EXIT;
            pTx->vin[i].wit_item_cnt = (uint32_t)tmp_u64;

            //XXX:
            pTx->vin[i].witness = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pTx->vin[i].wit_item_cnt);
            if (!pTx->vin[i].witness) goto LABEL_EXIT;
            memset(pTx->vin[i].witness, 0x00, sizeof(utl_buf_t) * pTx->vin[i].wit_item_cnt);

            //witness item
            for (uint32_t lp = 0; lp < pTx->vin[i].wit_item_cnt; lp++) {
                if (!tx_buf_read_varint(&txbuf, &tmp_u64)) goto LABEL_EXIT;
                if (tmp_u64 > UINT32_MAX) goto LABEL_EXIT;
                if (tmp_u64 > tx_buf_remains(&txbuf)) goto LABEL_EXIT;
                if (!utl_buf_alloccopy(&pTx->vin[i].witness[lp], tx_buf_get_pos(&txbuf), (uint32_t)tmp_u64)) goto LABEL_EXIT;
                if (!tx_buf_seek(&txbuf, (uint32_t)tmp_u64)) goto LABEL_EXIT;
            }
        }
    }

    //locktime
    if (!tx_buf_read_u32le(&txbuf, &pTx->locktime)) goto LABEL_EXIT;

    //check the end of the data
    if (tx_buf_remains(&txbuf)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    if (!ret) {
        btc_tx_free(pTx);
    }
    return ret;
}


bool btc_tx_write(const btc_tx_t *pTx, utl_buf_t *pBuf)
{
    return btcl_util_create_tx(pBuf, pTx, true);
}


bool btc_tx_sighash(btc_tx_t *pTx, uint8_t *pTxHash, const utl_buf_t *pScriptPks[], uint32_t Num)
{
    bool ret = false;
    const uint32_t sigtype = (uint32_t)SIGHASH_ALL;

    btc_tx_valid_t txvld = btc_tx_is_valid(pTx);
    if (txvld != BTC_TXVALID_OK) {
        LOGD("fail: invalid tx\n");
        return false;
    }

    if (pTx->vin_cnt != Num) {
        LOGD("fail: invalid vin_cnt\n");
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
    utl_buf_t buf;
    if (!btc_tx_write(pTx, &buf)) {
        assert(0);
        goto LABEL_EXIT;
    }
    if (!utl_buf_realloc(&buf, buf.len + sizeof(sigtype))) {
        utl_buf_free(&buf);
        goto LABEL_EXIT;
    }
    memcpy(buf.buf + buf.len - sizeof(sigtype), &sigtype, sizeof(sigtype));
    btc_util_hash256(pTxHash, buf.buf, buf.len);
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


bool btc_tx_sign_p2pkh(btc_tx_t *pTx, uint32_t Index,
                const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey)
{
    return btc_script_sig_sign_p2pkh(&(pTx->vin[Index].script), pTxHash, pPrivKey, pPubKey);
}


bool btc_tx_verify_p2pkh(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
{
    return btc_script_sig_verify_p2pkh(&(pTx->vin[Index].script), pTxHash, pPubKeyHash);
}


bool btc_tx_verify_p2pkh_spk(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    return btc_script_sig_verify_p2pkh_spk(&(pTx->vin[Index].script), pTxHash, pScriptPk);
}


bool btc_tx_verify_p2pkh_addr(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const char *pAddr)
{
    return btc_script_sig_verify_p2pkh_addr(&(pTx->vin[Index].script), pTxHash, pAddr);
}


bool btc_tx_verify_p2sh_multisig(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const uint8_t *pScriptHash)
{
    return btc_script_sig_verify_p2sh_multisig(&(pTx->vin[Index].script), pTxHash, pScriptHash);
}


bool btc_tx_verify_p2sh_multisig_spk(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    return btc_script_sig_verify_p2sh_multisig_spk(&(pTx->vin[Index].script), pTxHash, pScriptPk);
}


bool btc_tx_verify_p2sh_multisig_addr(const btc_tx_t *pTx, uint32_t Index, const uint8_t *pTxHash, const char *pAddr)
{
    return btc_script_sig_verify_p2sh_multisig_addr(&(pTx->vin[Index].script), pTxHash, pAddr);
}


bool btc_tx_txid(const btc_tx_t *pTx, uint8_t *pTxId)
{
    utl_buf_t txbuf;

    bool ret = btcl_util_create_tx(&txbuf, pTx, false);
    if (!ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    btc_util_hash256(pTxId, txbuf.buf, txbuf.len);
    utl_buf_free(&txbuf);

LABEL_EXIT:
    return ret;
}


bool btc_tx_txid_raw(uint8_t *pTxId, const utl_buf_t *pTxRaw)
{
    btc_util_hash256(pTxId, pTxRaw->buf, pTxRaw->len);
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
    //segwit判定
    bool segwit;
    uint8_t mark = pData[4];
    uint8_t flag = pData[5];
    if ((mark == 0x00) && (flag != 0x01)) {
        //2017/01/04:BIP-144ではflag==0x01のみ
        return 0;
    }
    segwit = ((mark == 0x00) && (flag == 0x01));

    //https://bitcoincore.org/ja/segwit_wallet_dev/#transaction-fee-estimation
    uint32_t len;
    if (segwit) {
        //(旧format*3 + 新format) / 4を切り上げ
        //  旧: nVersion            |txins|txouts        |nLockTime
        //  新: nVersion|marker|flag|txins|txouts|witness|nLockTime
        btc_tx_t txold = BTC_TX_INIT;
        utl_buf_t txbuf_old = UTL_BUF_INIT;

        if (!btc_tx_read(&txold, pData, Len)) {
            LOGD("fail: vbyte\n");
            len = 0;
            goto LABEL_EXIT;
        }

        if (!btcl_util_create_tx(&txbuf_old, &txold, false)) {
            LOGD("fail: vbyte\n");
            len = 0;
            goto LABEL_EXIT;
        }

        uint32_t fmt_old = txbuf_old.len;
        uint32_t fmt_new = Len;
        len = (fmt_old * 3 + fmt_new + 3) / 4;
    } else {
        len = Len;
    }

LABEL_EXIT:
    LOGD("vbyte=%" PRIu32 "\n", len);
    return len;
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
    LOGD2(" txin_cnt=%u\n", pTx->vin_cnt);
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        LOGD2(" [vin #%u]\n", lp);
        LOGD2("  txid= ");
        TXIDD(pTx->vin[lp].txid);
        LOGD2("       LE: ");
        DUMPD(pTx->vin[lp].txid, BTC_SZ_TXID);
        LOGD2("  index= %u\n", pTx->vin[lp].index);
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
        LOGD2("  value= %llu  : ", (unsigned long long)pTx->vout[lp].value);
        DUMPD(((const uint8_t *)&pTx->vout[lp].value), sizeof(pTx->vout[lp].value));
        LOGD2("    %10.5f mBTC, %10.8f BTC\n", BTC_SATOSHI2MBTC(pTx->vout[lp].value), BTC_SATOSHI2BTC(pTx->vout[lp].value));
        utl_buf_t *buf = &(pTx->vout[lp].script);
        LOGD2("  scriptPubKey[%u]= ", buf->len);
        DUMPD(buf->buf, buf->len);
        //btc_script_print(buf->buf, buf->len);
        char addr[BTC_SZ_ADDR_STR_MAX + 1];
        addr[0] = '\0';
        //standard transactions only(see bitcoind's `IsStandard`)
        if ( (buf->len == 25) && (buf->buf[0] == OP_DUP) && (buf->buf[1] == OP_HASH160) &&
             (buf->buf[2] == 0x14) && (buf->buf[23] == OP_EQUALVERIFY) && (buf->buf[24] == OP_CHECKSIG) ) {
            (void)btcl_util_keys_hash2addr(addr, &(buf->buf[3]), BTC_PREF_P2PKH);
        } else if ( (buf->len == 23) && (buf->buf[0] == OP_HASH160) && (buf->buf[1] == 0x14) && (buf->buf[22] == OP_EQUAL) ) {
            (void)btcl_util_keys_hash2addr(addr, &(buf->buf[2]), BTC_PREF_P2SH);
        } else if ( ((buf->len == 22) && (buf->buf[0] == 0x00) && (buf->buf[1] == 0x14)) ||
                    ((buf->len == 34) && (buf->buf[0] == 0x00) && (buf->buf[1] == 0x20)) ) {
            //bech32
            int hrp_type;
            switch (btc_get_chain()) {
            case BTC_MAINNET:
                hrp_type = BTC_SEGWIT_ADDR_MAINNET;
                break;
            case BTC_TESTNET:
                hrp_type = BTC_SEGWIT_ADDR_TESTNET;
                break;
            default:
                hrp_type = -1;
            }
            (void)btc_segwit_addr_encode(addr, sizeof(addr), hrp_type, buf->buf[0], &buf->buf[2], buf->buf[1]);
        }
        if (addr[0] != '\0') {
            LOGD2("    (%s)\n", addr);
        }
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
 * private functions
 **************************************************************************/

static void tx_buf_init(tx_buf *pBuf, const uint8_t *pData, uint32_t Len)
{
    pBuf->data = pData;
    pBuf->len = Len;
    pBuf->pos = 0;
}


static const uint8_t *tx_buf_get_pos(tx_buf *pBuf)
{
    return pBuf->data + pBuf->pos;
}


static bool tx_buf_read(tx_buf *pBuf, uint8_t *pData, uint32_t Len)
{
    if (pBuf->pos + Len > pBuf->len) return false;
    memcpy(pData, pBuf->data + pBuf->pos, Len);
    pBuf->pos += Len;
    return true;
}


static bool tx_buf_read_byte(tx_buf *pBuf, uint8_t *pByte)
{
    if (pBuf->pos + 1 > pBuf->len) return false;
    *pByte = *(pBuf->data + pBuf->pos);
    pBuf->pos++;
    return true;
}


static bool tx_buf_read_u32le(tx_buf *pBuf, uint32_t *U32)
{
    if (pBuf->pos + 4 > pBuf->len) return false;
    *U32 = utl_int_pack_u32le(pBuf->data + pBuf->pos);
    pBuf->pos += 4;
    return true;
}


static bool tx_buf_read_u64le(tx_buf *pBuf, uint64_t *U64)
{
    if (pBuf->pos + 8 > pBuf->len) return false;
    *U64 = utl_int_pack_u64le(pBuf->data + pBuf->pos);
    pBuf->pos += 8;
    return true;
}


static bool tx_buf_seek(tx_buf *pBuf, int32_t offset)
{
    if (offset > 0) {
        if (pBuf->pos + offset > pBuf->len) return false;
    } else {
        if (pBuf->pos < (uint32_t)-offset) return false;
    }
    pBuf->pos += offset;
    return true;
}


static uint32_t tx_buf_remains(tx_buf *pBuf)
{
    return pBuf->len - pBuf->pos;
}


static bool tx_buf_read_varint(tx_buf *pBuf, uint64_t *pValue)
{
    if (pBuf->pos + 1 > pBuf->len) return false;
    const uint8_t *data_pos = pBuf->data + pBuf->pos;
    if (*(data_pos) < 0xfd) {
        *pValue = *data_pos;
        pBuf->pos += 1;
    } else if (*(data_pos) == 0xfd) {
        if (pBuf->pos + 3 > pBuf->len) return false;
        *pValue = utl_int_pack_u16le(data_pos + 1);
        pBuf->pos += 3;
    } else if (*(data_pos) == 0xfe) {
        if (pBuf->pos + 5 > pBuf->len) return false;
        *pValue = utl_int_pack_u32le(data_pos + 1);
        pBuf->pos += 5;
    } else if (*(data_pos) == 0xff) {
        if (pBuf->pos + 9 > pBuf->len) return false;
        *pValue = utl_int_pack_u64le(data_pos + 1);
        pBuf->pos += 9;
    } else {
        assert(false);
        return false;
    }
    return true;
}
