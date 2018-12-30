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

static bool is_valid_signature_encoding(const uint8_t *sig, uint16_t size);
static int sign_rs(mbedtls_mpi *p_r, mbedtls_mpi *p_s, const uint8_t *pTxHash, const uint8_t *pPrivKey);
static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                    unsigned char *sig, size_t *slen );
static void tx_buf_init(tx_buf *pBuf, const uint8_t *pData, uint32_t Len);
static const uint8_t *tx_buf_get_pos(tx_buf *pBuf);
static bool tx_buf_read(tx_buf *pBuf, uint8_t *pData, uint32_t Len);
static bool tx_buf_read_byte(tx_buf *pBuf, uint8_t *pByte);
static bool tx_buf_read_u32le(tx_buf *pBuf, uint32_t *U32);
static bool tx_buf_read_u64le(tx_buf *pBuf, uint64_t *U64);
static bool tx_buf_seek(tx_buf *pBuf, int32_t offset);
static uint32_t tx_buf_remains(tx_buf *pBuf);
static bool tx_buf_read_varint(tx_buf *pBuf, uint64_t *pValue);

static bool recover_pubkey(uint8_t *pPubKey, int *pRecId, const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pOrgPubKey);

static int get_varint(uint16_t *pLen, const uint8_t *pData);


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
        for (uint32_t lp2 = 0; lp2 < vin->wit_cnt; lp2++) {
            utl_buf_free(&(vin->witness[lp2]));
        }
        if (vin->wit_cnt) {
            UTL_DBG_FREE(vin->witness);
            vin->wit_cnt = 0;
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


btc_txvalid_t btc_tx_is_valid(const btc_tx_t *pTx)
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
        btc_print_tx(pTx);
        return BTC_TXVALID_VOUT_NONE;
    }
    if (pTx->vout == NULL) {
        LOGD("fail: NULL vout\n");
        return BTC_TXVALID_VOUT_NULL;
    }
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        const btc_vin_t *vin = &pTx->vin[lp];

        if ((vin->wit_cnt > 0) && (vin->witness == NULL)) {
            LOGD("fail: NULL witness[%u]\n", lp);
            return BTC_TXVALID_VIN_WIT_NULL;
        } else if ((vin->wit_cnt == 0) && (vin->witness != NULL)) {
            LOGD("fail: bad witness[%u]\n", lp);
            return BTC_TXVALID_VIN_WIT_BAD;
        } else {
            //OK
        }
        for (uint32_t wit = 0; wit < vin->wit_cnt; wit++) {
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
        if ((vout->value == 0) && (vout->script.buf[0] != M_OP_RETURN)) { //XXX:
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
    vin->wit_cnt = 0;
    vin->witness = NULL;
    vin->sequence = BTC_TX_SEQUENCE;
    return vin;
}


utl_buf_t *btc_tx_add_wit(btc_vin_t *pVin)
{
    pVin->witness = (utl_buf_t *)UTL_DBG_REALLOC(pVin->witness, sizeof(utl_buf_t) * (pVin->wit_cnt + 1));
    if (!pVin->witness) return NULL;
    utl_buf_t *p_buf = &(pVin->witness[pVin->wit_cnt]);
    pVin->wit_cnt++;

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
        if (!btc_util_create_scriptpk(&vout->script, hash, pref)) return false;
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
        ret = btc_util_create_scriptpk(pBuf, hash, pref);
    }

    return ret;
}


bool btc_tx_create_spk_p2pkh(utl_buf_t *pBuf, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2PKH)) {
        ret = btc_util_create_scriptpk(pBuf, hash, pref);
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
    return btc_util_create_scriptpk(&vout->script, pScriptHash, BTC_PREF_P2SH);
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


bool btc_tx_set_vin_p2pkh(btc_tx_t *pTx, int Index, const utl_buf_t *pSig, const uint8_t *pPubKey)
{
    if (!pSig->len) return false;

    btc_vin_t *vin = &(pTx->vin[Index]);
    if (!utl_buf_realloc(&vin->script, 1 + pSig->len + 1 + BTC_SZ_PUBKEY)) return false;

    uint8_t *p = vin->script.buf;
    *p++ = pSig->len;
    memcpy(p, pSig->buf, pSig->len);
    p += pSig->len;
    *p++ = BTC_SZ_PUBKEY;
    memcpy(p, pPubKey, BTC_SZ_PUBKEY);
    return true;
}


bool btc_tx_set_vin_p2sh_multi(btc_tx_t *pTx, int Index, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem)
{
    if (!Num) return false;
    if (!pRedeem->len) return false;

    /*
     * OP_0
     * (sig-len + sig) * num
     * OP_PUSHDATAx
     * redeemScript-len
     * redeemScript
     */
    btc_vin_t *vin = &(pTx->vin[Index]);
    uint16_t len = 1 + Num + 1 + 1 + pRedeem->len;
    if (pRedeem->len >> 8) {
        len++;
    }
    for (int lp = 0; lp < Num; lp++) {
         len += pSigs[lp]->len;
    }
    if (!utl_buf_realloc(&vin->script, len)) return false;
    uint8_t *p = vin->script.buf;

    *p++ = OP_0;
    for (int lp = 0; lp < Num; lp++) {
        *p++ = pSigs[lp]->len;
        memcpy(p, pSigs[lp]->buf, pSigs[lp]->len);
        p += pSigs[lp]->len;
    }
    if (pRedeem->len >> 8) {
        *p++ = OP_PUSHDATA2;
        *p++ = pRedeem->len & 0xff;
        *p++ = pRedeem->len >> 8;
    } else {
        *p++ = OP_PUSHDATA1;
        *p++ = (uint8_t)pRedeem->len;
    }
    memcpy(p, pRedeem->buf, pRedeem->len);
    return true;
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
            pTx->vin[i].wit_cnt = (uint32_t)tmp_u64;

            //XXX:
            pTx->vin[i].witness = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pTx->vin[i].wit_cnt);
            if (!pTx->vin[i].witness) goto LABEL_EXIT;
            memset(pTx->vin[i].witness, 0x00, sizeof(utl_buf_t) * pTx->vin[i].wit_cnt);

            //witness item
            for (uint32_t lp = 0; lp < pTx->vin[i].wit_cnt; lp++) {
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


bool btc_tx_create(utl_buf_t *pBuf, const btc_tx_t *pTx)
{
    return btcl_util_create_tx(pBuf, pTx, true);
}


bool btc_tx_sighash(uint8_t *pTxHash, btc_tx_t *pTx, const utl_buf_t *pScriptPks[], uint32_t Num)
{
    const uint32_t sigtype = (uint32_t)SIGHASH_ALL;

    btc_txvalid_t txvld = btc_tx_is_valid(pTx);
    if (txvld != BTC_TXVALID_OK) {
        LOGD("fail: invalid tx\n");
        return false;
    }

    if (pTx->vin_cnt != Num) {
        LOGD("fail: invalid vin_cnt\n");
        return false;
    }

    //scriptSigをscriptPubKeyで置き換える
    utl_buf_t *tmp_vinbuf = (utl_buf_t *)UTL_DBG_MALLOC(sizeof(utl_buf_t) * pTx->vin_cnt);
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &pTx->vin[lp];

        tmp_vinbuf[lp].buf = vin->script.buf;
        tmp_vinbuf[lp].len = vin->script.len;
        vin->script.len = pScriptPks[lp]->len;
        vin->script.buf = (uint8_t *)UTL_DBG_MALLOC(vin->script.len);
        memcpy(vin->script.buf, pScriptPks[lp]->buf, vin->script.len);
    }

    utl_buf_t tx;
    bool ret = btc_tx_create(&tx, pTx);
    if (!ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    tx.buf = (uint8_t *)UTL_DBG_REALLOC(tx.buf, tx.len + sizeof(sigtype));
    memcpy(tx.buf + tx.len, &sigtype, sizeof(sigtype));
    tx.len += sizeof(sigtype);
    btc_util_hash256(pTxHash, tx.buf, tx.len);
    utl_buf_free(&tx);

    //scriptSigを元に戻す
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &pTx->vin[lp];

        utl_buf_free(&vin->script);
        vin->script.buf = tmp_vinbuf[lp].buf;
        vin->script.len = tmp_vinbuf[lp].len;
    }
    UTL_DBG_FREE(tmp_vinbuf);

LABEL_EXIT:
    return ret;
}


bool btc_tx_sign(utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPrivKey)
{
    int ret;
    bool bret;
    mbedtls_mpi r, s;
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN + 1];   //141 + 1 byte
    size_t slen = 0;

    utl_buf_init(pSig);

    ret = sign_rs(&r, &s, pTxHash, pPrivKey);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret = ecdsa_signature_to_asn1(&r, &s, sig, &slen);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    //HashType
    sig[slen] = SIGHASH_ALL;
    slen++;
    bret = is_valid_signature_encoding(sig, slen);
    if (!bret) {
        assert(0);
        ret = -1;
        goto LABEL_EXIT;
    }
    utl_buf_alloccopy(pSig, sig, slen);

LABEL_EXIT:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    if (ret) {
        LOGD("fail\n");
    }
    return ret == 0;
}


bool btc_tx_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPrivKey)
{
    int ret;
    mbedtls_mpi r, s;

    ret = sign_rs(&r, &s, pTxHash, pPrivKey);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret = mbedtls_mpi_write_binary(&r, pRS, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_write_binary(&s, pRS + 32, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    if (ret) {
        LOGD("fail\n");
    }
    return ret == 0;
}


bool btc_tx_verify(const utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPubKey)
{
    int ret;
    bool bret;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    if (pSig->buf[pSig->len - 1] != SIGHASH_ALL) {
        //assert(0);
        LOGD("fail: not SIGHASH_ALL\n");
        ret = -1;
        goto LABEL_EXIT;
    }
    bret = is_valid_signature_encoding(pSig->buf, pSig->len);
    if (!bret) {
        //assert(0);
        LOGD("fail: invalid signature\n");
        ret = -1;
        goto LABEL_EXIT;
    }

    ret = btcl_util_set_keypair(&keypair, pPubKey);
    if (!ret) {
        ret = mbedtls_ecdsa_read_signature((mbedtls_ecdsa_context *)&keypair,
                    pTxHash, BTC_SZ_HASH256,
                    pSig->buf, pSig->len - 1);
    } else {
        LOGD("fail keypair\n");
    }

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);

    if (ret == 0) {
        LOGD("ok: verify\n");
    } else {
        LOGD("fail ret=%d\n", ret);
        LOGD("pSig: ");
        DUMPD(pSig->buf, pSig->len);
        LOGD("txhash: ");
        DUMPD(pTxHash, BTC_SZ_HASH256);
        LOGD("pub: ");
        DUMPD(pPubKey, BTC_SZ_PUBKEY);
    }
    return ret == 0;
}


bool btc_tx_verify_rs(const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPubKey)
{
    int ret;
    mbedtls_mpi r, s;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    ret = mbedtls_mpi_read_binary(&r, pRS, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_read_binary(&s, pRS + 32, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = btcl_util_set_keypair(&keypair, pPubKey);
    if (!ret) {
        ret = mbedtls_ecdsa_verify(&keypair.grp, pTxHash, BTC_SZ_HASH256, &keypair.Q, &r, &s);
    } else {
        LOGD("fail keypair\n");
    }

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    if (ret == 0) {
        //LOGD("ok: verify\n");
    } else {
        LOGD("fail ret=%d\n", ret);
        LOGD("txhash: ");
        DUMPD(pTxHash, BTC_SZ_HASH256);
        LOGD("pub: ");
        DUMPD(pPubKey, BTC_SZ_PUBKEY);
    }
    return ret == 0;
}


bool btc_tx_sign_p2pkh(btc_tx_t *pTx, int Index,
                const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey)
{
    bool ret;
    uint8_t pubkey[BTC_SZ_PUBKEY];
    utl_buf_t sigbuf = UTL_BUF_INIT;

    if (pPubKey == NULL) {
        ret = btc_keys_priv2pub(pubkey, pPrivKey);
        if (!ret) {
            assert(0);
            goto LABEL_EXIT;
        }
        pPubKey = pubkey;
    }

    ret = btc_tx_sign(&sigbuf, pTxHash, pPrivKey);
    if (ret) {
        btc_tx_set_vin_p2pkh(pTx, Index, &sigbuf, pPubKey);
    }

LABEL_EXIT:
    utl_buf_free(&sigbuf);

    return ret;
}


bool btc_tx_verify_p2pkh(const btc_tx_t *pTx, int Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
{
    bool ret;

    const utl_buf_t *p_scriptsig = (const utl_buf_t *)&(pTx->vin[Index].script);
    const uint8_t *p = p_scriptsig->buf;
    const utl_buf_t sig = { (CONST_CAST uint8_t *)(p + 1), *p };      //P2PKHの署名は1byte長で収まる
    p += *p + 1;
    if (*p != BTC_SZ_PUBKEY) {
        assert(0);
        ret = false;
        goto LABEL_EXIT;
    }
    p++;
    ret = btc_tx_verify(&sig, pTxHash, p);
    if (ret) {
        uint8_t pkh[BTC_SZ_HASH_MAX];
        btc_util_hash160(pkh, p, BTC_SZ_PUBKEY);
        ret = (memcmp(pkh, pPubKeyHash, BTC_SZ_HASH160) == 0);
    }

LABEL_EXIT:
    return ret;
}


bool btc_tx_verify_p2pkh_spk(const btc_tx_t *pTx, int Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    bool ret = false;

    //P2PKHのscriptPubKey
    //  DUP HASH160 0x14 <20 bytes> EQUALVERIFY CHECKSIG
    if (pScriptPk->len != 3 + BTC_SZ_HASH160 + 2) {
        assert(0);
        goto LABEL_EXIT;
    }
    if ( (pScriptPk->buf[0] != OP_DUP) ||
         (pScriptPk->buf[1] != OP_HASH160) ||
         (pScriptPk->buf[2] != BTC_SZ_HASH160) ||
         (pScriptPk->buf[3 + BTC_SZ_HASH160] != OP_EQUALVERIFY) ||
         (pScriptPk->buf[3 + BTC_SZ_HASH160 + 1] != OP_CHECKSIG) ) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret =  btc_tx_verify_p2pkh(pTx, Index, pTxHash, pScriptPk->buf + 3);

LABEL_EXIT:
    return ret;
}


bool btc_tx_verify_p2pkh_addr(const btc_tx_t *pTx, int Index, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2PKH)) {
        ret = btc_tx_verify_p2pkh(pTx, Index, pTxHash, hash);
    } else {
        ret = false;
    }

    return ret;
}


bool btc_tx_verify_p2sh_multisig(const btc_tx_t *pTx, int Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
{
    const utl_buf_t *p_scriptsig = (const utl_buf_t *)&(pTx->vin[Index].script);
    const uint8_t *p = p_scriptsig->buf;

    //このvinはP2SHの予定
    //      1. 前のvoutのscriptHashが、redeemScriptから計算したscriptHashと一致するか確認
    //      2. 署名チェック
    //
    //  OP_0
    //  <署名> x いくつか
    //  <OP_PUSHDATAx>
    //  pushデータ長
    //  redeemScript
    if (*p != OP_0) {
        LOGD("top isnot OP_0\n");
        return false;
    }

    //署名数取得
    int signum = 0;
    int sigpos = 1;     //OP_0の次
    uint32_t pos = 1;
    while (pos < p_scriptsig->len) {
        uint8_t len = *(p + pos);
        if ((len == OP_PUSHDATA1) || (len == OP_PUSHDATA2)) {
            break;
        }
        signum++;
        pos += 1 + len;
    }
    if (pos >= p_scriptsig->len) {
        LOGD("no OP_PUSHDATAx(sign)\n");
        return false;
    }
    pos++;
    uint16_t redm_len;  //OP_PUSHDATAxの引数
    pos += get_varint(&redm_len, p + pos);
    if (signum != (*(p + pos) - OP_x)) {
        LOGD("OP_x mismatch(sign): signum=%d, OP_x=%d\n", signum, *(p + pos) - OP_x);
        return false;
    }
    pos++;
    //公開鍵数取得
    int pubnum = 0;
    int pubpos = pos;
    while (pos < p_scriptsig->len) {
        uint8_t len = *(p + pos);
        if ((OP_1 <= len) && (len <= OP_16)) {
            break;
        }
        if (len != BTC_SZ_PUBKEY) {
            LOGD("invalid pubkey len(%d)\n", len);
            return false;
        }
        pubnum++;
        pos += 1 + len;
    }
    if (pos >= p_scriptsig->len) {
        LOGD("no OP_PUSHDATAx(pubkey)\n");
        return false;
    }
    if (pubnum != (*(p + pos) - OP_x)) {
        LOGD("OP_x mismatch(pubkey): signum=%d, OP_x=%d\n", pubnum, *(p + pos) - OP_x);
        return false;
    }
    pos++;
    if (*(p + pos) != OP_CHECKMULTISIG) {
        LOGD("not OP_CHECKMULTISIG\n");
        return false;
    }
    pos++;
    if (pos != p_scriptsig->len) {
        LOGD("invalid data length\n");
        return false;
    }

    //scripthashチェック
    uint8_t sh[BTC_SZ_HASH_MAX];
    btc_util_hash160(sh, p_scriptsig->buf + pubpos - 1, p_scriptsig->len - pubpos + 1);
    bool ret = (memcmp(sh, pPubKeyHash, BTC_SZ_HASH160) == 0);
    if (!ret) {
        LOGD("scripthash mismatch.\n");
        return false;
    }

    //pubnum中、signum分のverifyが成功すればOK
    uint32_t chk_pos = 0;   //bitが立った公開鍵はチェック済み
    //公開鍵の重複チェック
    for (int lp = 0; lp < pubnum - 1; lp++) {
        const uint8_t *p1 = p_scriptsig->buf + pubpos + (1 + BTC_SZ_PUBKEY) * lp;
        for (int lp2 = lp + 1; lp2 < pubnum; lp2++) {
            const uint8_t *p2 = p_scriptsig->buf + pubpos + (1 + BTC_SZ_PUBKEY) * lp2;
            ret = (memcmp(p1, p2, 1 + BTC_SZ_PUBKEY) == 0);
            if (ret) {
                LOGD("same pubkey(%d, %d)\n", lp, lp2);
                return false;
            }
        }
    }
    //署名チェック
    //      おそらくbitcoindでは、NG数が最短になるように配置される前提になっている。
    //      そうするため、署名に一致する-公開鍵が見つかった場合、次はその公開鍵より後ろを検索する。
    //          [SigA, SigB][PubA, PubB, PubC] ... OK
    //              SigA=PubA(NG 0回), SigB=PubB(NG 0回)
    //          [SigB, SigA][PubA, PubB, PubC] ... NG
    //              SigB=PubB(NG 1回), SigA=none(PubC以降しか検索しないため)
    int ok_cnt = 0;
    int ng_cnt = pubnum - signum;
    for (int lp = 0; lp < signum; lp++) {
        int pubpos_now = pubpos;
        for (int lp2 = 0; lp2 < pubnum; lp2++) {
            if ((chk_pos & (1 << lp2)) == 0) {
                //未チェック公開鍵
                const utl_buf_t sig = { p_scriptsig->buf + sigpos + 1, *(p_scriptsig->buf + sigpos) };
                ret = *(p_scriptsig->buf + pubpos_now) == BTC_SZ_PUBKEY;
                if (ret) {
                    ret = btc_tx_verify(&sig, pTxHash, p_scriptsig->buf + pubpos_now + 1);
                }
                if (ret) {
                    ok_cnt++;
                    chk_pos |= (1 << (lp2 + 1)) - 1;    //以下を全部1にする(NG最短)
                    LOGD("   verify ok: sig=%d, pub=%d\n", lp, lp2);
                    break;
                } else {
                    ng_cnt--;
                    if (ng_cnt < 0) {
                        //NGとしてループを抜ける(NG最短)
                        ok_cnt = -1;
                        lp = signum;
                        break;
                    }
                }
            }
            pubpos_now += *(p_scriptsig->buf + pubpos_now) + 1;
        }
        sigpos += *(p_scriptsig->buf + sigpos) + 1;
    }
    LOGD("ok_cnt=%d, ng_cnt=%d, signum=%d, pubnum=%d\n", ok_cnt, ng_cnt, signum, pubnum);

    return ok_cnt == signum;
}


bool btc_tx_verify_p2sh_multisig_spk(const btc_tx_t *pTx, int Index, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    bool ret = false;

    //P2SHのscriptPubKey
    //  HASH160 0x14 <20 bytes> EQUAL
    if (pScriptPk->len != 2 + BTC_SZ_HASH160 + 1) {
        assert(0);
        goto LABEL_EXIT;
    }
    if ( (pScriptPk->buf[0] != OP_HASH160) ||
         (pScriptPk->buf[1] != BTC_SZ_HASH160) ||
         (pScriptPk->buf[2 + BTC_SZ_HASH160] != OP_EQUAL) ) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret =  btc_tx_verify_p2sh_multisig(pTx, Index, pTxHash, pScriptPk->buf + 2);

LABEL_EXIT:
    return ret;
}


bool btc_tx_verify_p2sh_multisig_addr(const btc_tx_t *pTx, int Index, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2SH)) {
        ret = btc_tx_verify_p2sh_multisig(pTx, Index, pTxHash, hash);
    } else {
        ret = false;
    }

    return ret;
}


bool btc_tx_recover_pubkey(uint8_t *pPubKey, int RecId, const uint8_t *pRS, const uint8_t *pTxHash)
{
    if ((RecId < 0) || (3 < RecId)) {
        LOGD("fail: invalid recid\n");
        return false;
    }

    return recover_pubkey(pPubKey, &RecId, pRS, pTxHash, NULL);
}


bool btc_tx_recover_pubkey_id(int *pRecId, const uint8_t *pPubKey, const uint8_t *pRS, const uint8_t *pTxHash)
{
    bool ret;
    uint8_t pub[BTC_SZ_PUBKEY];

    *pRecId = -1;       //負の数にすると自動で求める
    ret = recover_pubkey(pub, pRecId, pRS, pTxHash, pPubKey);
    if (!ret) {
        LOGD("not pubkey\n");
    }

    return ret;
}


bool btc_tx_txid(uint8_t *pTxId, const btc_tx_t *pTx)
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
//         if (vin->wit_cnt) {
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

        btc_tx_read(&txold, pData, Len);

        bool ret = btcl_util_create_tx(&txbuf_old, &txold, false);
        if (ret) {
            uint32_t fmt_old = txbuf_old.len;
            uint32_t fmt_new = Len;
            len = (fmt_old * 3 + fmt_new + 3) / 4;
        } else {
            LOGD("fail: vbyte\n");
            len = 0;
        }
    } else {
        len = Len;
    }

    LOGD("vbyte=%" PRIu32 "\n", len);
    return len;
}


#if defined(PTARM_USE_PRINTFUNC) && !defined(PTARM_UTL_LOG_MACRO_DISABLED)
void btc_print_tx(const btc_tx_t *pTx)
{
    LOGD2("======================================\n");
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(txid, pTx);
    LOGD2("txid= ");
    TXIDD(txid);
    LOGD2("======================================\n");
    LOGD2(" version:%d\n", pTx->version);
    LOGD2("\n");
    LOGD2(" txin_cnt=%u\n", pTx->vin_cnt);
    for(uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        LOGD2(" [vin #%u]\n", lp);
        LOGD2("  txid= ");
        TXIDD(pTx->vin[lp].txid);
        LOGD2("       LE: ");
        DUMPD(pTx->vin[lp].txid, BTC_SZ_TXID);
        LOGD2("  index= %u\n", pTx->vin[lp].index);
        LOGD2("  scriptSig[%u]= ", pTx->vin[lp].script.len);
        DUMPD(pTx->vin[lp].script.buf, pTx->vin[lp].script.len);
        //btc_print_scriptbtc_print_script(pTx->vin[lp].script.buf, pTx->vin[lp].script.len);
        //bool p2wsh = (pTx->vin[lp].script.len == 35) &&
        //             (pTx->vin[lp].script.buf[1] == 0x00) && (pTx->vin[lp].script.buf[2] == 0x20);
        //bool p2wsh = (pTx->vin[lp].wit_cnt >= 3);
        LOGD2("  sequence= 0x%08x\n", pTx->vin[lp].sequence);
        for(uint32_t lp2 = 0; lp2 < pTx->vin[lp].wit_cnt; lp2++) {
            LOGD2("    wit[%u][%u]= ", lp2, pTx->vin[lp].witness[lp2].len);
            if(pTx->vin[lp].witness[lp2].len) {
                DUMPD(pTx->vin[lp].witness[lp2].buf, pTx->vin[lp].witness[lp2].len);
                // if (p2wsh &&(lp2 == pTx->vin[lp].wit_cnt - 1)) {
                //     //P2WSHの最後はwitnessScript
                //     //nativeのP2WSHでも表示させたかったが、識別する方法が思いつかない
                //     btc_print_script(pTx->vin[lp].witness[lp2].buf, pTx->vin[lp].witness[lp2].len);
                // }
            } else {
                LOGD2("<none>\n");
            }
        }
        LOGD2("\n");
    }
    LOGD2(" txout_cnt= %u\n", pTx->vout_cnt);
    for(uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        LOGD2(" [vout #%u]\n", lp);
        LOGD2("  value= %llu  : ", (unsigned long long)pTx->vout[lp].value);
        DUMPD(((const uint8_t *)&pTx->vout[lp].value), sizeof(pTx->vout[lp].value));
        LOGD2("    %10.5f mBTC, %10.8f BTC\n", BTC_SATOSHI2MBTC(pTx->vout[lp].value), BTC_SATOSHI2BTC(pTx->vout[lp].value));
        utl_buf_t *buf = &(pTx->vout[lp].script);
        LOGD2("  scriptPubKey[%u]= ", buf->len);
        DUMPD(buf->buf, buf->len);
        //btc_print_script(buf->buf, buf->len);
        char addr[BTC_SZ_ADDR_STR_MAX + 1];
        addr[0] = '\0';
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


void btc_print_rawtx(const uint8_t *pData, uint32_t Len)
{
    btc_tx_t tx;
    bool ret = btc_tx_read(&tx, pData, Len);
    if (!ret) {
        return;
    }

    btc_print_tx(&tx);

    btc_tx_free(&tx);
}


void btc_print_script(const uint8_t *pData, uint16_t Len)
{
    const struct {
        uint8_t         op;
        const char      *name;
    } OP_DIC[] = {
        { OP_HASH160, "OP_HASH160" },
        { OP_EQUAL, "OP_EQUAL" },
        { OP_EQUALVERIFY, "OP_EQUALVERIFY" },
        { OP_CHECKSIG, "OP_CHECKSIG" },
        { OP_CHECKMULTISIG, "OP_CHECKMULTISIG" },
        { OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY" },
        { OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY" },
        { OP_DROP, "OP_DROP" },
        { OP_2DROP, "OP_2DROP" },
        { OP_DUP, "OP_DUP" },
        { OP_IF, "OP_IF" },
        { OP_NOTIF, "OP_NOTIF" },
        { OP_ELSE, "OP_ELSE" },
        { OP_ENDIF, "OP_ENDIF" },
        { OP_SWAP, "OP_SWAP" },
        { OP_ADD, "OP_ADD" },
        { OP_SIZE, "OP_SIZE" },
    };

    const uint8_t *end = pData + Len;
    const char INDENT[] = "      ";
    while (pData < end) {
        if (*pData <= 0x4b) {
            //スタックに載せる
            int len = *pData;
            LOGD("%s%02x ", INDENT, len);
            pData++;
            DUMPD(pData, len);
            pData += len;
        } else if ((OP_1 <= *pData) && (*pData <= OP_16)) {
            //OP_x
            LOGD("%s%02x [OP_%d]\n", INDENT, *pData, *pData - OP_x);
            pData++;
        } else if ((*pData == OP_PUSHDATA1) || (*pData == OP_PUSHDATA2)) {
            //スタックに載せる
            int len;
            if (*pData == OP_PUSHDATA1) {
                len = *(pData + 1);
                pData += 2;
            } else {
                len = *(pData + 1) | (*(pData + 2) << 8);
                pData += 3;
            }
            LOGD("%sOP_PUSHDATAx 0x%02x ", INDENT, len);
            DUMPD(pData, len);
            pData += len;
        } else {
            int op;
            for (op = 0; op < (int)ARRAY_SIZE(OP_DIC); op++) {
                if (*pData == OP_DIC[op].op) {
                    break;
                }
            }
            if (op != ARRAY_SIZE(OP_DIC)) {
                //知っているOP code
                LOGD("%s%02x [%s]\n", INDENT, OP_DIC[op].op, OP_DIC[op].name);
            } else {
                //unknown
                LOGD("%s%02x [??]\n", INDENT, *pData);
            }
            pData++;
        }
    }
}
#endif  //PTARM_USE_PRINTFUNC


/**************************************************************************
 * private functions
 **************************************************************************/

/** BIP66署名データチェック
 *
 * @param[in]       sig         署名データ(HashType付き)
 * @param[in]       size        sigサイズ
 * @return      true:BIP66チェックOK
 *
 * @note
 *      - https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
 */
static bool is_valid_signature_encoding(const uint8_t *sig, uint16_t size)
{
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (size < 9) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }
    if (size > 73) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) {
        LOGD("fail: is_valid_signature_encoding(%d - %02x)\n" ,__LINE__, sig[0]);
        return false;
    }

    // Make sure the length covers the entire signature.
    if (sig[1] != size - 3) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= size) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != size) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Zero-length integers are not allowed for R.
    if (lenR == 0) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Zero-length integers are not allowed for S.
    if (lenS == 0) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) {
        LOGD("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    return true;
}


/** 署名r/s
 *
 */
static int sign_rs(mbedtls_mpi *p_r, mbedtls_mpi *p_s, const uint8_t *pTxHash, const uint8_t *pPrivKey)
{
    int ret;
    mbedtls_ecp_keypair keypair;

    mbedtls_mpi_init(p_r);
    mbedtls_mpi_init(p_s);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_mpi_read_binary(&keypair.d, pPrivKey, BTC_SZ_PRIVKEY);
    if (ret) {
        LOGD("FAIL: ecdsa_sign: %d\n", ret);
        assert(0);
        goto LABEL_EXIT;
    }

    //canonizeするため、ecdsa.cのmbedtls_ecdsa_write_signature()をまねる
    ret = mbedtls_ecdsa_sign_det(&keypair.grp, p_r, p_s, &keypair.d,
                    pTxHash, BTC_SZ_HASH256, MBEDTLS_MD_SHA256);
    if (ret) {
        LOGD("FAIL: ecdsa_sign: %d\n", ret);
        assert(0);
        goto LABEL_EXIT;
    }
    mbedtls_mpi half_n;
    mbedtls_mpi_init(&half_n);
    mbedtls_mpi_copy(&half_n, &keypair.grp.N);
    mbedtls_mpi_shift_r(&half_n, 1);
    if (mbedtls_mpi_cmp_mpi(p_s, &half_n) == 1) {
        mbedtls_mpi_sub_mpi(p_s, &keypair.grp.N, p_s);
    }
    mbedtls_mpi_free(&half_n);

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);

    return ret;
}


//署名canonize処理用(mbedtls ecdsa.cからコピー)
/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                    unsigned char *sig, size_t *slen )
{
    int ret;        //MBEDTLS_ASN1_CHK_ADDで使用する
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, s ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, r ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, buf,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    memcpy( sig, p, len );
    *slen = len;

    return( 0 );
}


/**
 * @param[out]  pPubKey
 * @param[out]  pRecId
 * @param[in]   pRS
 * @param[in]   pTxHash
 * @retval  true    成功
 */
static bool recover_pubkey(uint8_t *pPubKey, int *pRecId, const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pOrgPubKey)
{
    bool bret = false;
    int ret;

    mbedtls_ecp_keypair keypair;
    mbedtls_mpi me;
    mbedtls_mpi r, s;
    mbedtls_mpi inv_r;
    mbedtls_mpi x;
    mbedtls_ecp_point R;
    mbedtls_ecp_point MR;
    mbedtls_ecp_point pub;

    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_init(&me);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&inv_r);
    mbedtls_mpi_init(&x);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&MR);
    mbedtls_ecp_point_init(&pub);
    const mbedtls_ecp_point *pR[2] = { &R, &MR };
    int is_zero;

    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    // 1.5
    //      e = Hash(M)
    //      me = -e
    ret = mbedtls_mpi_read_binary(&me, pTxHash, BTC_SZ_HASH256);
    assert(ret == 0);

    mbedtls_mpi zero;
    mbedtls_mpi_init(&zero);
    mbedtls_mpi_lset(&zero, 0);
    ret = mbedtls_mpi_sub_mpi(&me, &zero, &me);
    assert(ret == 0);
    ret = mbedtls_mpi_mod_mpi(&me, &me, &keypair.grp.N);
    assert(ret == 0);
    mbedtls_mpi_free(&zero);

    ret = mbedtls_mpi_read_binary(&r, pRS, BTC_SZ_FIELD);
    assert(ret == 0);
    ret = mbedtls_mpi_read_binary(&s, pRS + BTC_SZ_FIELD, BTC_SZ_FIELD);
    assert(ret == 0);

    //      inv_r = r^-1
    ret = mbedtls_mpi_inv_mod(&inv_r, &r, &keypair.grp.N);
    assert(ret == 0);

    int start_j;
    int start_k;
    if (*pRecId >= 0) {
        start_j = (*pRecId & 0x02) >> 1;
        start_k = *pRecId & 0x01;
    } else {
        start_j = 0;
        start_k = 0;
    }

    // Iのb1
    for (int j = start_j; j < 2; j++) {
        // 1.1
        //      x = r + jn
        mbedtls_mpi tmpx;
        mbedtls_mpi_init(&tmpx);
        ret = mbedtls_mpi_mul_int(&tmpx, &keypair.grp.N, j);
        assert(ret == 0);

        ret = mbedtls_mpi_add_mpi(&x, &r, &tmpx);
        assert(ret == 0);
        mbedtls_mpi_free(&tmpx);
        keypair.grp.modp(&x);

        // 1.3
        //      R = 02 || x
        uint8_t pubx[BTC_SZ_PUBKEY];
        pubx[0] = 0x02;
        ret = mbedtls_mpi_write_binary(&x, pubx + 1, BTC_SZ_FIELD);
        assert(ret == 0);
        ret = btc_util_ecp_point_read_binary2(&R, pubx);
        assert(ret == 0);

        // 1.6.3
        mbedtls_ecp_copy(&MR, &R);
        ret = mbedtls_mpi_sub_mpi(&MR.Y, &keypair.grp.P, &MR.Y);        // -R.Y = P - R.Yになる(mod P不要)
        assert(ret == 0);

        // 1.4
        //      error if nR != 0
        mbedtls_ecp_point nR;
        mbedtls_ecp_point_init(&nR);
        ret = mbedtls_ecp_mul(&keypair.grp, &nR, &keypair.grp.N, &R, NULL, NULL);
        is_zero = mbedtls_ecp_is_zero(&nR);
        mbedtls_ecp_point_free(&nR);
        if ((ret == 0) || !is_zero) {
            LOGD("[%d]1.4 error(ret=%04x)\n", j, ret);
            goto SKIP_LOOP;
        }

        // Iのb0
        for (int k = start_k; k < 2; k++) {
            // 1.6.1
            //      Q = r^-1 * (sR - eG)

            //      (sR - eG)
            ret = mbedtls_ecp_muladd(&keypair.grp, &pub, &s, pR[k], &me, &keypair.grp.G);
            assert(ret == 0);
            //      Q = r^-1 * Q
            ret = mbedtls_ecp_mul(&keypair.grp, &pub, &inv_r, &pub, NULL, NULL);
            assert(ret == 0);

            size_t sz;
            ret = mbedtls_ecp_point_write_binary(
                                &keypair.grp, &pub, MBEDTLS_ECP_PF_COMPRESSED,
                                &sz, pPubKey, BTC_SZ_PUBKEY);
            assert(ret == 0);

            if (ret == 0) {
                bret = btc_tx_verify_rs(pRS, pTxHash, pPubKey);
                if (bret && pOrgPubKey) {
                    bret = (memcmp(pOrgPubKey, pPubKey, BTC_SZ_PUBKEY) == 0);
                }
                if (bret) {
                    //LOGD("recover= ");
                    //DUMPD(pPubKey, BTC_SZ_PUBKEY);
                    if (*pRecId < 0) {
                        *pRecId = (j << 1) | k;
                    }
                    j = 2;
                    k = 2;
                    break;
                } else {
                    //LOGD("not match\n");
                }
            } else {
                LOGD("fail\n");
            }
            if (*pRecId >= 0) {
                break;
            }
        }

SKIP_LOOP:
        if (*pRecId >= 0) {
            break;
        }
    }

    mbedtls_ecp_point_free(&pub);
    mbedtls_ecp_point_free(&MR);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&inv_r);
    mbedtls_mpi_free(&me);
    mbedtls_ecp_keypair_free(&keypair);

    return bret;
}


/** varintのデータ長取得
 *
 * @param[out]      pPos        varint型のデータ長
 * @param[in]       pData       データ
 * @return      varint型のデータ長サイズ
 *
 * @note
 *      - #btcl_util_get_varint_len()との違いに注意すること
 *      - データ長は0xFFFFまでしか対応しない
 */
static int get_varint(uint16_t *pLen, const uint8_t *pData)
{
    int retval;

    //varint型は大きい数字を扱えるが、ここでは2byte長までしか対応しない
    if (*pData < VARINT_3BYTE_MIN) {
        //1byte
        *pLen = (uint16_t)*pData;
        retval = 1;
    } else {
        //2byte
        *pLen = (uint16_t)(*(pData + 1) | (*(pData + 2) << 8));
        retval = 3;
    }

    return retval;
}

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
