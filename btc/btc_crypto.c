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
/** @file   btc_crypto.c
 *  @brief  btc_crypto
 */
#include <sys/stat.h>
#include <sys/types.h>

#ifdef USE_OPENSSL
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#endif

#include "mbedtls/error.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/ecp.h"
#ifndef PTARM_NO_USE_RNG
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#endif

#include "libbase58.h"

#include "utl_dbg.h"

#include "btc_local.h"
#include "btc_segwit_addr.h"
#include "btc_script.h"
#include "btc_sig.h"
#include "btc_sw.h"
#include "btc_tx_buf.h"
#include "btc_dbg.h"
#include "btc_crypto.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_RNG_APP_SPECIFIC_DATA_STR     "ptarmigan@nayuta"


/**************************************************************************
 * private variables
 **************************************************************************/

#ifndef PTARM_NO_USE_RNG
static mbedtls_entropy_context  mEntropy;
static mbedtls_ctr_drbg_context mRng;
#endif


/**************************************************************************
 * prototypes
 **************************************************************************/

/**************************************************************************
 *const variables
 **************************************************************************/

/**************************************************************************
 * public functions
 **************************************************************************/

void btc_md_ripemd160(uint8_t *pRipemd160, const uint8_t *pData, uint16_t Len)
{
#ifndef USE_OPENSSL
    mbedtls_ripemd160(pData, Len, pRipemd160);
#else
    RIPEMD160_CTX context;

    RIPEMD160_Init(&context);
    RIPEMD160_Update(&context, pData, Len);
    RIPEMD160_Final(pRipemd160, &context);
#endif
}


void btc_md_sha256(uint8_t *pSha256, const uint8_t *pData, uint16_t Len)
{
#ifndef USE_OPENSSL
    mbedtls_sha256(pData, Len, pSha256, 0);
#else
    SHA256_CTX context;

    SHA256_Init(&context);
    SHA256_Update(&context, pData, Len);
    SHA256_Final(pSha256, &context);
#endif
}


void btc_md_hash160(uint8_t *pHash160, const uint8_t *pData, uint16_t Len)
{
    uint8_t buf_sha256[BTC_SZ_HASH256];

    btc_md_sha256(buf_sha256, pData, Len);
    btc_md_ripemd160(pHash160, buf_sha256, sizeof(buf_sha256));
}


void btc_md_hash256(uint8_t *pHash256, const uint8_t *pData, uint16_t Len)
{
    btc_md_sha256(pHash256, pData, Len);
    btc_md_sha256(pHash256, pHash256, BTC_SZ_HASH256);
}


void btc_md_sha256cat(uint8_t *pSha256, const uint8_t *pData1, uint16_t Len1, const uint8_t *pData2, uint16_t Len2)
{
#ifndef USE_OPENSSL
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pData1, Len1);
    mbedtls_sha256_update(&ctx, pData2, Len2);
    mbedtls_sha256_finish(&ctx, pSha256);
    mbedtls_sha256_free(&ctx);
#else
    SHA256_CTX context;

    SHA256_Init(&context);
    SHA256_Update(&context, pData1, Len1);
    SHA256_Update(&context, pData2, Len2);
    SHA256_Final(pSha256, &context);
#endif
}


int btc_ecc_ecp_read_binary_pubkey(void *pPoint, const uint8_t *pPubKey) //XXX: mbed
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


int btc_ecc_ecp_add(uint8_t *pResult, const uint8_t *pPubKeyIn, const void *pA) //XXX: mbed
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
    ret = btc_ecc_ecp_read_binary_pubkey(&P1, pPubKeyIn);
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
    ret = mbedtls_ecp_muladd(&keypair.grp, &P2,
        (const mbedtls_mpi *)pA, &keypair.grp.G,
        &one, &P1);
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


bool btc_ecc_mul_pubkey(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pMul, int MulLen) //XXX: mbed
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    int ret = btc_ecc_set_keypair(&keypair, pPubKey);
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


bool btc_ecc_shared_secret_sha256(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pPrivKey)
{
    uint8_t pub[BTC_SZ_PUBKEY];
    if (!btc_ecc_mul_pubkey(pub, pPubKey, pPrivKey, BTC_SZ_PRIVKEY)) return false;
    btc_md_sha256(pResult, pub, sizeof(pub));
    return true;
}


bool btc_rng_init(void)
{
#ifndef PTARM_NO_USE_RNG
    mbedtls_entropy_init(&mEntropy);
    mbedtls_ctr_drbg_init(&mRng);

    //XXX: TODO: we not set the device-specific identifier yet
    if (mbedtls_ctr_drbg_seed(&mRng, mbedtls_entropy_func, &mEntropy,
        (const unsigned char *)M_RNG_APP_SPECIFIC_DATA_STR, strlen(M_RNG_APP_SPECIFIC_DATA_STR))) return false;

    mbedtls_ctr_drbg_set_prediction_resistance(&mRng, MBEDTLS_CTR_DRBG_PR_ON);
#endif
    return true;
}


bool btc_rng_rand(uint8_t *pData, uint16_t Len)
{
#ifndef PTARM_NO_USE_RNG
    int ret = mbedtls_ctr_drbg_random(&mRng, pData, Len);
    if (ret) {
        LOGE("fail: random=%d\n", ret);
        btc_crypto_error_print(ret);
        LOGE("\n");
        return false;
    }
#else
    for (uint16_t lp = 0; lp < Len; lp++) {
        pData[lp] = (uint8_t)(rand() % 256);
    }
#endif
    return true;
}


bool btc_rng_big_rand(uint8_t *pData, uint16_t Len)
{
    static const uint16_t UNIT = 256;
    while (Len) {
        uint16_t l = (Len <= UNIT) ? Len : UNIT;
        if (!btc_rng_rand(pData, l)) return false;
        pData += l;
        Len -= l;
    }
    return true;
}


void btc_rng_free(void)
{
#ifndef PTARM_NO_USE_RNG
    mbedtls_entropy_free(&mEntropy);
    mbedtls_ctr_drbg_free(&mRng);
#endif
}


void btc_crypto_error_print(int ErrNum)
{
    char buffer[1024];
    mbedtls_strerror(ErrNum, buffer, sizeof(buffer));
    LOGE("%s\n", buffer);
}


bool btc_hmac_sha256(uint8_t *pHmac, const uint8_t *pKey, int KeyLen, const uint8_t *pMsg, int MsgLen)
{
    //HMAC(SHA256)
    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(mdinfo, pKey, KeyLen, pMsg, MsgLen, pHmac);
    return ret == 0;
}


/**************************************************************************
 * package functions (btc_ecc)
 **************************************************************************/

int btc_ecc_set_keypair(void *pKeyPair, const uint8_t *pPubKey) //XXX: mbed
{
    int ret;

    mbedtls_ecp_keypair *p_keypair = (mbedtls_ecp_keypair *)pKeyPair;
    ret = btc_ecc_ecp_read_binary_pubkey(&(p_keypair->Q), pPubKey);

    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/


