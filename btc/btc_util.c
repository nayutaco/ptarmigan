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

static btc_keys_sort_t pubkey_sort_2of2(const uint8_t *pPubKey1, const uint8_t *pPubKey2);


/**************************************************************************
 *const variables
 **************************************************************************/

/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_util_create_2of2(utl_buf_t *pRedeem, btc_keys_sort_t *pSort, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    *pSort = pubkey_sort_2of2(pPubKey1, pPubKey2);
    if (*pSort == BTC_KEYS_SORT_ASC) {
        return btc_redeem_create_2of2(pRedeem, pPubKey1, pPubKey2);
    } else {
        return btc_redeem_create_2of2(pRedeem, pPubKey2, pPubKey1);
    }
}


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


bool btc_util_calc_sighash_p2wsh(const btc_tx_t *pTx, uint8_t *pTxHash, uint32_t Index, uint64_t Value,
                    const utl_buf_t *pWitScript)
{
    utl_buf_t script_code = UTL_BUF_INIT;

    btc_tx_valid_t txvalid = btc_tx_is_valid(pTx);
    if (txvalid != BTC_TXVALID_OK) {
        LOGD("fail\n");
        return false;
    }

    if (!btc_scriptcode_p2wsh(&script_code, pWitScript)) return false;
    if (!btc_sw_sighash(pTxHash, pTx, Index, Value, &script_code)) return false;
    utl_buf_free(&script_code);
    return true;
}


bool btc_util_sign_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const btc_keys_t *pKeys)
{
    return btc_sig_sign(pSig, pTxHash, pKeys->priv);
}


bool btc_util_sign_p2wsh_rs(uint8_t *pRS, const uint8_t *pTxHash, const btc_keys_t *pKeys)
{
    return btc_sig_sign_rs(pRS, pTxHash, pKeys->priv);
}


void btc_util_ripemd160(uint8_t *pRipemd160, const uint8_t *pData, uint16_t Len)
{
    mbedtls_ripemd160(pData, Len, pRipemd160);
}


void btc_util_sha256(uint8_t *pSha256, const uint8_t *pData, uint16_t Len)
{
    mbedtls_sha256(pData, Len, pSha256, 0);
}


#if defined(PTARM_USE_PRINTFUNC) || defined(PTARM_DEBUG)
/** uint8[]の内容をFILE*出力
 *
 * @param[in]       fp          出力先
 * @param[in]       pData       対象データ
 * @param[in]       Len         pData長
 */
void btc_util_dumpbin(FILE *fp, const uint8_t *pData, uint32_t Len, bool bLf)
{
    for (uint32_t lp = 0; lp < Len; lp++) {
        fprintf(fp, "%02x", pData[lp]);
    }
    if (bLf) {
        fprintf(fp, "\n");
    }
}


/** uint8[]の内容をFILE*出力
 *
 * @param[in]       fp          出力先
 * @param[in]       pTxid
 */
void btc_util_dumptxid(FILE *fp, const uint8_t *pTxid)
{
    for (uint16_t lp = 0; lp < BTC_SZ_TXID; lp++) {
        fprintf(fp, "%02x", pTxid[BTC_SZ_TXID - lp - 1]);
    }
}
#endif  //PTARM_USE_PRINTFUNC || PTARM_DEBUG


/**************************************************************************
 * package functions
 **************************************************************************/

void btc_util_hash160(uint8_t *pHash160, const uint8_t *pData, uint16_t Len)
{
    uint8_t buf_sha256[BTC_SZ_HASH256];

    btc_util_sha256(buf_sha256, pData, Len);
    btc_util_ripemd160(pHash160, buf_sha256, sizeof(buf_sha256));
}


void btc_util_hash256(uint8_t *pHash256, const uint8_t *pData, uint16_t Len)
{
    btc_util_sha256(pHash256, pData, Len);
    btc_util_sha256(pHash256, pHash256, BTC_SZ_HASH256);
}


void btc_util_sha256cat(uint8_t *pSha256, const uint8_t *pData1, uint16_t Len1, const uint8_t *pData2, uint16_t Len2)
{
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pData1, Len1);
    mbedtls_sha256_update(&ctx, pData2, Len2);
    mbedtls_sha256_finish(&ctx, pSha256);
    mbedtls_sha256_free(&ctx);
}


int btc_util_ecp_point_read_binary2(void *pPoint, const uint8_t *pPubKey)
{
    int ret;
    uint8_t parity;
    size_t plen;
    mbedtls_mpi e, y2;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_point *point = (mbedtls_ecp_point *)pPoint;

    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&y2);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    ret = mbedtls_ecp_point_read_binary(&keypair.grp, point, pPubKey, BTC_SZ_PUBKEY);
    if (MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE != ret) {
        return ret;
    }

    if (0x02 == pPubKey[0]) {
        parity = 0;
    } else if (0x03 == pPubKey[0]) {
        parity = 1;
    } else {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    plen = mbedtls_mpi_size(&keypair.grp.P);
    if (BTC_SZ_PUBKEY != plen + 1) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ret = mbedtls_mpi_read_binary(&point->X, pPubKey + 1, plen);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_lset(&point->Z, 1);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    // Set y2 = X^3 + B
    ret = mbedtls_mpi_mul_mpi(&y2, &point->X, &point->X);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
#if 0
    ret = mbedtls_mpi_mod_mpi(&y2, &y2, &keypair.grp.P);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
#else
    keypair.grp.modp(&y2);
#endif
    ret = mbedtls_mpi_mul_mpi(&y2, &y2, &point->X);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_add_mpi(&y2, &y2, &keypair.grp.B);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
#if 0
    ret = mbedtls_mpi_mod_mpi(&y2, &y2, &keypair.grp.P);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
#else
    keypair.grp.modp(&y2);
#endif

    // Compute square root of y2
    ret = mbedtls_mpi_add_int(&e, &keypair.grp.P, 1);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_shift_r(&e, 2);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_exp_mod(&point->Y, &y2, &e, &keypair.grp.P, NULL);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    // Set parity
    if (mbedtls_mpi_get_bit(&point->Y, 0) != parity) {
        ret = mbedtls_mpi_sub_mpi(&point->Y, &keypair.grp.P, &point->Y);
    }

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&y2);

    return ret;
}


void btc_util_create_pkh2wpkh(uint8_t *pWPubKeyHash, const uint8_t *pPubKeyHash)
{
    //nested in P2SH
    if (mNativeSegwit) {
        assert(false);
    }

    uint8_t wit_prog[2 + BTC_SZ_HASH_MAX];

    wit_prog[0] = 0x00;
    wit_prog[1] = (uint8_t)BTC_SZ_HASH160;
    memcpy(wit_prog + 2, pPubKeyHash, BTC_SZ_HASH160);
    btc_util_hash160(pWPubKeyHash, wit_prog, BTC_SZ_WITPROG_P2WPKH);
}


int btc_util_ecp_muladd(uint8_t *pResult, const uint8_t *pPubKeyIn, const void *pA)
{
    int ret;
    mbedtls_ecp_point P1;
    mbedtls_ecp_point P2;
    mbedtls_mpi one;
    mbedtls_ecp_keypair keypair;

    mbedtls_ecp_point_init(&P1);
    mbedtls_ecp_point_init(&P2);
    mbedtls_mpi_init(&one);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    //P1: 前の公開鍵座標
    ret = btc_util_ecp_point_read_binary2(&P1, pPubKeyIn);
    if (ret) {
        goto LABEL_EXIT;
    }
    //P2 = a * G + 1 * P1
    //  aG + bG = (a + b)Gだが、a、G、P1しかわからない。
    //  よって、 a * G + 1 * P1、という計算にする。
    ret = mbedtls_mpi_lset(&one, 1);
    if (ret) {
        goto LABEL_EXIT;
    }
    ret = mbedtls_ecp_muladd(&keypair.grp, &P2, (const mbedtls_mpi *)pA, &keypair.grp.G, &one, &P1);
    if (ret) {
        goto LABEL_EXIT;
    }
    //P2 != infinity
    ret = mbedtls_mpi_cmp_int(&P2.Z, 0);
    if (ret == 0) {
        ret = 1;
        goto LABEL_EXIT;
    }

    //圧縮公開鍵
    size_t sz;
    ret = mbedtls_ecp_point_write_binary(&keypair.grp, &P2, MBEDTLS_ECP_PF_COMPRESSED, &sz, pResult, BTC_SZ_PUBKEY);

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&one);
    mbedtls_ecp_point_free(&P2);
    mbedtls_ecp_point_free(&P1);

    return ret;
}


bool btc_util_mul_pubkey(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pMul, int MulLen)
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    int ret = btcl_util_set_keypair(&keypair, pPubKey);
    if (!ret) {
        // keypair.Qに公開鍵(x, y)が入っている
        mbedtls_ecp_point pnt;
        mbedtls_mpi m;

        mbedtls_ecp_point_init(&pnt);
        mbedtls_mpi_init(&m);

        mbedtls_mpi_read_binary(&m, pMul, MulLen);
        mbedtls_ecp_mul(&keypair.grp, &pnt, &m, &keypair.Q, NULL, NULL);  //TODO: RNGを指定すべきか？

        //圧縮公開鍵
        size_t sz;
        ret = mbedtls_ecp_point_write_binary(&keypair.grp, &pnt, MBEDTLS_ECP_PF_COMPRESSED, &sz, pResult, BTC_SZ_PUBKEY);

        mbedtls_ecp_point_free(&pnt);
        mbedtls_mpi_free(&m);
    }
    mbedtls_ecp_keypair_free(&keypair);

    return ret == 0;
}


/**************************************************************************
 * package functions
 **************************************************************************/

int HIDDEN btcl_util_set_keypair(void *pKeyPair, const uint8_t *pPubKey)
{
    int ret;

    mbedtls_ecp_keypair *p_keypair = (mbedtls_ecp_keypair *)pKeyPair;
    ret = btc_util_ecp_point_read_binary2(&(p_keypair->Q), pPubKey);

    return ret;
}


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


bool HIDDEN btcl_util_add_vout_pub(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey, uint8_t Pref)
{
    uint8_t pkh[BTC_SZ_HASH_MAX];

    btc_util_hash160(pkh, pPubKey, BTC_SZ_PUBKEY);
    return btcl_util_add_vout_pkh(pTx, Value, pkh, Pref);
}


bool HIDDEN btcl_util_add_vout_pkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash, uint8_t Pref)
{
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    return btc_scriptpk_create(&vout->script, pPubKeyHash, Pref);
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** 2-of-2公開鍵ソート
 *
 * @param[in]       pPubKey1
 * @param[in]       pPubKey2
 * @retval      BTC_KEYS_SORT_ASC     引数の順番が昇順
 *
 */
static btc_keys_sort_t pubkey_sort_2of2(const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    int cmp = memcmp(pPubKey1, pPubKey2, BTC_SZ_PUBKEY);
    if (cmp < 0) {
        return BTC_KEYS_SORT_ASC;
    } else {
        return BTC_KEYS_SORT_OTHER;
    }
}

