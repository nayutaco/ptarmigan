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
/** @file   ln_derkey.c
 *  @brief  Key Derivation
 *  @note
 *      - https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation
 */

#include "mbedtls/sha256.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/ecp.h"

#include "btc.h"
#include "btc_crypto.h"

#include "ln_derkey.h"
#include "ln_local.h"
//#define M_DBG_PRINT //XXX: CAUTION!!: display secret

/**************************************************************************
 * prototypes
 **************************************************************************/

static void derive_secret(uint8_t *pOutput, const uint8_t *pBase, int bits, uint64_t Index);
static int where_to_put_secret(uint64_t Index);


/**************************************************************************
 * public functions
 **************************************************************************/

//pubkey = basepoint + SHA256(per-commitment-point || basepoint)*G
bool HIDDEN ln_derkey_pubkey(uint8_t *pPubKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint)
{
    int ret;

    //sha256(per-commitment-point || basepoint)
    uint8_t hash[BTC_SZ_HASH256];
    btc_md_sha256cat(hash, pPerCommitPoint, BTC_SZ_PUBKEY, pBasePoint, BTC_SZ_PUBKEY);

    mbedtls_mpi h;
    mbedtls_mpi_init(&h);
    mbedtls_mpi_read_binary(&h, hash, sizeof(hash));
    ret = btc_ecc_ecp_add(pPubKey, pBasePoint, &h);
    mbedtls_mpi_free(&h);

#ifdef M_DBG_PRINT
    LOGD("SHA256(per_commitment_point |+ basepoint)\n=> SHA256(");
    DUMPD(pPerCommitPoint, BTC_SZ_PUBKEY);
    LOGD2(" |+ ");
    DUMPD(pBasePoint, BTC_SZ_PUBKEY);
    LOGD2(" ==> ");
    DUMPD(pPubKey, BTC_SZ_PUBKEY);
#endif

    return ret == 0;
}


//////////////////////////////////////////////////
//secretkey = basepoint-secret + SHA256(per-commitment-point || basepoint)
bool HIDDEN ln_derkey_privkey(uint8_t *pPrivKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint,
            const uint8_t *pBaseSecret)
{
    int ret;

    //sha256(per-commitment-point || basepoint)
    btc_md_sha256cat(pPrivKey, pPerCommitPoint, BTC_SZ_PUBKEY, pBasePoint, BTC_SZ_PUBKEY);

    mbedtls_mpi a;
    mbedtls_mpi b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_read_binary(&a, pPrivKey, BTC_SZ_PRIVKEY);
    mbedtls_mpi_read_binary(&b, pBaseSecret, BTC_SZ_PRIVKEY);
    ret = mbedtls_mpi_add_mpi(&a, &a, &b);
    if (ret) goto LABEL_EXIT;
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_mpi_mod_mpi(&a, &a, &keypair.grp.N);
    if (ret) goto LABEL_EXIT;
    ret = mbedtls_mpi_write_binary(&a, pPrivKey, BTC_SZ_PRIVKEY);
    if (ret) goto LABEL_EXIT;

#ifdef M_DBG_PRINT
    LOGD("(priv)SHA256(per_commitment_point |+ basepoint)\n=> SHA256(");
    DUMPD(pPerCommitPoint, BTC_SZ_PUBKEY);
    LOGD2(" |+ ");
    DUMPD(pBasePoint, BTC_SZ_PUBKEY);
    LOGD2(" ==> (priv)");
    DUMPD(pBaseSecret, BTC_SZ_PRIVKEY);
#endif

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&a);

    return ret == 0;
}


//////////////////////////////////////////////////
//revocationkey = revocation-basepoint * SHA256(revocation-basepoint || per-commitment-point) +
//                per-commitment-point * SHA256(per-commitment-point || revocation-basepoint)
bool HIDDEN ln_derkey_revocation_pubkey(uint8_t *PubKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint)
{
    int ret;
    uint8_t hash1[BTC_SZ_HASH256];
    uint8_t hash2[BTC_SZ_HASH256];
    mbedtls_ecp_keypair keypair;

    //sha256(revocation-basepoint || per-commitment-point)
    btc_md_sha256cat(hash1, pBasePoint, BTC_SZ_PUBKEY, pPerCommitPoint, BTC_SZ_PUBKEY);

    //sha256(per-commitment-point || revocation-basepoint)
    btc_md_sha256cat(hash2, pPerCommitPoint, BTC_SZ_PUBKEY, pBasePoint, BTC_SZ_PUBKEY);

    size_t sz;
    mbedtls_mpi h1;
    mbedtls_mpi h2;
    mbedtls_ecp_point S1;
    mbedtls_ecp_point S2;
    mbedtls_ecp_point S;

    mbedtls_mpi_init(&h1);
    mbedtls_mpi_init(&h2);
    mbedtls_ecp_point_init(&S1);
    mbedtls_ecp_point_init(&S2);
    mbedtls_ecp_point_init(&S);
    mbedtls_ecp_keypair_init(&keypair);

    mbedtls_mpi_read_binary(&h1, hash1, sizeof(hash1));
    ret = btc_ecc_ecp_read_binary_pubkey(&S1, pBasePoint);
    if (ret) goto LABEL_EXIT;
    mbedtls_mpi_read_binary(&h2, hash2, sizeof(hash2));
    ret = btc_ecc_ecp_read_binary_pubkey(&S2, pPerCommitPoint);
    if (ret) goto LABEL_EXIT;
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_ecp_muladd(&keypair.grp, &S, &h1, &S1, &h2, &S2);
    if (ret) goto LABEL_EXIT;
    ret = mbedtls_ecp_point_write_binary(&keypair.grp, &S, MBEDTLS_ECP_PF_COMPRESSED, &sz, PubKey, BTC_SZ_PUBKEY);

#ifdef M_DBG_PRINT
    LOGD("SHA256(revocation_basepoint |x per_commitment_point)\n=> SHA256(");
    DUMPD(pBasePoint, BTC_SZ_PUBKEY);
    LOGD2(" |x ");
    DUMPD(pPerCommitPoint, BTC_SZ_PUBKEY);
    LOGD2(" ==> ");
    DUMPD(PubKey, BTC_SZ_PUBKEY);
#endif

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ecp_point_free(&S);
    mbedtls_mpi_free(&h1);
    mbedtls_mpi_free(&h2);
    mbedtls_ecp_point_free(&S1);
    mbedtls_ecp_point_free(&S2);

    return ret == 0;
}


//////////////////////////////////////////////////
//revocationsecretkey = revocation-basepoint-secret * SHA256(revocation-basepoint || per-commitment-point) +
//                      per-commitment-secret * SHA256(per-commitment-point || revocation-basepoint)
bool HIDDEN ln_derkey_revocation_privkey(uint8_t *pPrivKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint,
            const uint8_t *pBaseSecret, const uint8_t *pPerCommitSecret)
{
    int ret;
    uint8_t hash1[BTC_SZ_HASH256];
    uint8_t hash2[BTC_SZ_HASH256];
    mbedtls_ecp_keypair keypair;

    //sha256(revocation-basepoint || per-commitment-point)
    btc_md_sha256cat(hash1, pBasePoint, BTC_SZ_PUBKEY, pPerCommitPoint, BTC_SZ_PUBKEY);

    mbedtls_mpi a;
    mbedtls_mpi b;
    mbedtls_mpi c;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&c);
    mbedtls_ecp_keypair_init(&keypair);

    mbedtls_mpi_read_binary(&a, hash1, BTC_SZ_PRIVKEY);
    mbedtls_mpi_read_binary(&b, pBaseSecret, BTC_SZ_PRIVKEY);
    ret = mbedtls_mpi_mul_mpi(&a, &a, &b);
    if (ret) goto LABEL_EXIT;

    //sha256(per-commitment-point || revocation-basepoint)
    btc_md_sha256cat(hash2, pPerCommitPoint, BTC_SZ_PUBKEY, pBasePoint, BTC_SZ_PUBKEY);

    mbedtls_mpi_read_binary(&b, hash2, BTC_SZ_PRIVKEY);
    mbedtls_mpi_read_binary(&c, pPerCommitSecret, BTC_SZ_PRIVKEY);
    ret = mbedtls_mpi_mul_mpi(&b, &b, &c);
    if (ret) goto LABEL_EXIT;

    ret = mbedtls_mpi_add_mpi(&a, &a, &b);
    if (ret) goto LABEL_EXIT;
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_mpi_mod_mpi(&a, &a, &keypair.grp.N);
    if (ret) goto LABEL_EXIT;
    ret = mbedtls_mpi_write_binary(&a, pPrivKey, BTC_SZ_PRIVKEY);
    if (ret) goto LABEL_EXIT;

#ifdef M_DBG_PRINT
    LOGD("(priv)SHA256(revocation_basepoint |x per_commitment_point) x per_commitment_secret\n=>SHA256(");
    DUMPD(pBasePoint, BTC_SZ_PUBKEY);
    LOGD2(" x ");
    DUMPD(pPerCommitPoint, BTC_SZ_PUBKEY);
    LOGD2(" x ");
    DUMPD(pPerCommitSecret, BTC_SZ_PRIVKEY);
    LOGD2(" ==> (priv)");
    DUMPD(pPrivKey, BTC_SZ_PRIVKEY);
#endif

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&c);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&a);

    return ret == 0;
}


void HIDDEN ln_derkey_storage_create_secret(uint8_t *pSecret, const uint8_t *pSeed, uint64_t Index)
{
    LOGD("index=%016" PRIx64 "\n", Index);

    //generate_from_seed(seed, I):
    //    P = seed
    //    for B in 47 down to 0:
    //        if B set in I:
    //            flip(B) in P
    //            P = SHA256(P)
    //    return P

    derive_secret(pSecret, pSeed, 47, Index);
    LOGD("END\n");
}


void HIDDEN ln_derkey_storage_init(ln_derkey_storage_t *pStorage)
{
    memset(pStorage, 0xcc, sizeof(ln_derkey_storage_t));
}


bool HIDDEN ln_derkey_storage_insert_secret(ln_derkey_storage_t *pStorage, const uint8_t *pSecret, uint64_t Index)
{
    LOGD("BEGIN\n");

    //insert_secret(secret, I):
    //    B = where_to_put_secret(secret, I)
    //
    //    # This tracks the index of the secret in each bucket as we traverse.
    //    for b in 0 to B:
    //        if derive_secret(secret, B, known[b].index) != known[b].secret:
    //            error The secret for I is incorrect
    //            return
    //
    //    # Assuming this automatically extends known[] as required.
    //    known[B].index = I
    //    known[B].secret = secret

    uint8_t output[BTC_SZ_PRIVKEY];
    int bit = where_to_put_secret(Index);
    LOGD("I=%016" PRIx64 ", bit=%d\n", Index, bit);
    for (int lp = 0; lp < bit; lp++) {
        derive_secret(output, pSecret, bit - 1, pStorage->storage[lp].index);
        if (memcmp(output, pStorage->storage[lp].secret, BTC_SZ_PRIVKEY)) {
            LOGE("fail: secret mismatch(I=%016" PRIx64 "), bit=%d\n", Index, bit);
            return false;
        }
    }
    memcpy(pStorage->storage[bit].secret, pSecret, BTC_SZ_PRIVKEY);
    pStorage->storage[bit].index = Index;
    LOGD("END\n");
    return true;
}


bool HIDDEN ln_derkey_storage_get_secret(uint8_t *pSecret, const ln_derkey_storage_t *pStorage, uint64_t Index)
{
    LOGD("index=%016" PRIx64 "\n", Index);

    //derive_old_secret(I):
    //    for b in 0 to len(secrets):
    //        # Mask off the non-zero prefix of the index.
    //        MASK = ~((1 << b)-1)
    //        if (I & MASK) == secrets[b].index:
    //            return derive_secret(known, i, I)
    //    error We haven't received index I yet.

    bool ret = false;
    for (int lp = 48; lp >= 0; lp--) {
        const uint64_t MASK = ~(((uint64_t)1 << lp) - (uint64_t)1);
        if ((uint64_t)(Index & MASK) == pStorage->storage[lp].index) {
            if (Index == pStorage->storage[lp].index) {
                memcpy(pSecret, pStorage->storage[lp].secret, BTC_SZ_PRIVKEY);
            } else {
                uint64_t diff = Index - pStorage->storage[lp].index;
                derive_secret(pSecret, pStorage->storage[lp].secret, lp, diff);
            }
            ret = true;
            break;
        }
    }
    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** derive secret
 *
 */
static void derive_secret(uint8_t *pOutput, const uint8_t *pBase, int bit, uint64_t Index)
{
    uint8_t output[BTC_SZ_HASH256];

    //derive_secret(base, bits, I):
    //    P = base
    //    for B in bits - 1 down to 0:
    //        if B set in I:
    //            flip(B) in P
    //            P = SHA256(P)
    //    return P

    memcpy(output, pBase, BTC_SZ_HASH256);
    for (int lp = bit; lp >= 0; lp--) {
        if (Index & ((uint64_t)1 << lp)) {
            output[lp / 8] ^= (1 << (lp % 8));
            btc_md_sha256(output, output, BTC_SZ_HASH256);
        }
    }
    memcpy(pOutput, output, BTC_SZ_HASH256);
}


/** count trailing 0s
 *
 */
static int where_to_put_secret(uint64_t Index)
{
    //where_to_put_secret(I):
    //    for B in 0 to 47:
    //        if testbit(I) in B == 1:
    //            return B
    //    # I = 0, this is the seed.
    //        return 48

    int lp;
    /*if ((Index & UINT64_C(0xffffffffffff)) == 0) {
        return 48;
    }*/
    for (lp = 0; lp < 48; lp++) {
        if (Index & ((uint64_t)1 << lp)) break;
    }
    return lp;
}
