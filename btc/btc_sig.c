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
/** @file   btc_sig.c
 *  @brief  btc_sig
 */
#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"

#include "utl_dbg.h"
#include "utl_int.h"

#include "btc_local.h"


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool is_valid_signature_encoding(const uint8_t *sig, uint16_t size);
static int sign_rs(mbedtls_mpi *p_r, mbedtls_mpi *p_s, const uint8_t *pTxHash, const uint8_t *pPrivKey);
static int rs_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s, unsigned char *sig, size_t *slen );


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_sig_sign(utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPrivKey)
{
    int ret;
    bool bret;
    mbedtls_mpi r, s;
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN + 1];   //sig + hashtype(1)
    size_t slen = 0;

    utl_buf_init(pSig);

    ret = sign_rs(&r, &s, pTxHash, pPrivKey);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret = rs_to_asn1(&r, &s, sig, &slen);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    //hashtype
    sig[slen] = SIGHASH_ALL;
    slen++;

    bret = is_valid_signature_encoding(sig, slen);
    if (!bret) {
        assert(0);
        ret = -1;
        goto LABEL_EXIT;
    }

    bret = utl_buf_alloccopy(pSig, sig, slen);
    if (!bret) {
        ret = -1;
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (ret) {
        LOGD("fail\n");
    }
    return ret == 0;
}


bool btc_sig_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPrivKey)
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
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    if (ret) {
        LOGD("fail\n");
    }
    return ret == 0;
}


bool btc_sig_verify(const utl_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPubKey)
{
    return btc_sig_verify_2(pSig->buf, pSig->len, pTxHash, pPubKey);
}

bool btc_sig_verify_2(const uint8_t *pSig, uint32_t Len, const uint8_t *pTxHash, const uint8_t *pPubKey)
{
    int ret;
    bool bret;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    if (pSig[Len - 1] != SIGHASH_ALL) {
        LOGD("fail: not SIGHASH_ALL\n");
        ret = -1;
        goto LABEL_EXIT;
    }

    bret = is_valid_signature_encoding(pSig, Len);
    if (!bret) {
        LOGD("fail: invalid sig\n");
        ret = -1;
        goto LABEL_EXIT;
    }

    ret = btcl_util_set_keypair(&keypair, pPubKey);
    if (ret) {
        LOGD("fail keypair\n");
        goto LABEL_EXIT;
    }

    ret = mbedtls_ecdsa_read_signature((mbedtls_ecdsa_context *)&keypair,
                pTxHash, BTC_SZ_HASH256, pSig, Len - 1);
    if (ret) {
        LOGD("fail vefiry sig\n");
        goto LABEL_EXIT;
    }


LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);

    if (ret == 0) {
        LOGD("ok: verify\n");
    } else {
        LOGD("fail ret=%d\n", ret);
        LOGD("pSig: ");
        DUMPD(pSig, Len);
        LOGD("txhash: ");
        DUMPD(pTxHash, BTC_SZ_HASH256);
        LOGD("pub: ");
        DUMPD(pPubKey, BTC_SZ_PUBKEY);
    }
    return ret == 0;
}


bool btc_sig_verify_rs(const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPubKey)
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
    if (ret) {
        LOGD("fail keypair\n");
        goto LABEL_EXIT;
    }

    ret = mbedtls_ecdsa_verify(&keypair.grp, pTxHash, BTC_SZ_HASH256, &keypair.Q, &r, &s);
    if (ret) {
        LOGD("fail verify\n");
        goto LABEL_EXIT;
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
        LOGD("fail: invalid sig\n");
        return false;
    }
    if (size > 73) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Make sure the length covers the entire signature.
    if (sig[1] != size - 3) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= size) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != size) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Zero-length integers are not allowed for R.
    if (lenR == 0) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Zero-length integers are not allowed for S.
    if (lenS == 0) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) {
        LOGD("fail: invalid sig\n");
        return false;
    }

    return true;
}


/** Sign to the hash
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

    ret = mbedtls_ecdsa_sign_det(&keypair.grp, p_r, p_s, &keypair.d,
                    pTxHash, BTC_SZ_HASH256, MBEDTLS_MD_SHA256);
    if (ret) {
        LOGD("FAIL: ecdsa_sign: %d\n", ret);
        assert(0);
        goto LABEL_EXIT;
    }

    //"canonical" ECDSA signature by BIP-62
    // we use `s < (N/2)`
    mbedtls_mpi half_n;
    mbedtls_mpi_init(&half_n);
    mbedtls_mpi_copy(&half_n, &keypair.grp.N);
    mbedtls_mpi_shift_r(&half_n, 1);
    if (mbedtls_mpi_cmp_mpi(p_s, &half_n) == 1) {
        ret = mbedtls_mpi_sub_mpi(p_s, &keypair.grp.N, p_s);
        if (ret) {
            LOGD("FAIL: ecdsa_sign: %d\n", ret);
            assert(0);
            goto LABEL_EXIT;
        }
    }
    mbedtls_mpi_free(&half_n);

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);

    return ret;
}


/** Convert a signature to ASN.1 DER
 *
 */
static int rs_to_asn1(const mbedtls_mpi *r, const mbedtls_mpi *s, unsigned char *sig, size_t *slen)
{
    int ret;    //use in MBEDTLS_ASN1_CHK_ADD
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;

    //see is_valid_signature_encoding()
    // mbedtls_asn1_write_mpi() works backwards in data buffer
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, s));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_mpi(&p, buf, r));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));

    memcpy(sig, p, len);
    *slen = len;

    return (0);
}


