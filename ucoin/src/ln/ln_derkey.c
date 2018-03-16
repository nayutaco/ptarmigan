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
 *  @author ueno@nayuta.co
 *  @note
 *      - https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#key-derivation
 */
#include "ln_derkey.h"
//#define M_DBG_PRINT

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
    uint8_t base[UCOIN_SZ_HASH256];
    mbedtls_sha256_context ctx;

    //sha256(per-commitment-point || basepoint)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pPerCommitPoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pBasePoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base);
    mbedtls_sha256_free(&ctx);

    mbedtls_mpi bp;

    mbedtls_mpi_init(&bp);
    mbedtls_mpi_read_binary(&bp, base, sizeof(base));
    ret = ucoin_util_ecp_muladd(pPubKey, pBasePoint, &bp);
    mbedtls_mpi_free(&bp);

#ifdef M_DBG_PRINT
    DBG_PRINTF("SHA256(per_commitment_point |+ basepoint)\n=> SHA256(");
    DUMPBIN(pPerCommitPoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" |+ ");
    DUMPBIN(pBasePoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" ==> ");
    DUMPBIN(pPubKey, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("\n\n");
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
    mbedtls_sha256_context ctx;
    mbedtls_ecp_keypair keypair;

    //sha256(per-commitment-point || basepoint)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pPerCommitPoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pBasePoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, pPrivKey);
    mbedtls_sha256_free(&ctx);

    mbedtls_mpi a;
    mbedtls_mpi b;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_read_binary(&a, pPrivKey, UCOIN_SZ_PRIVKEY);
    mbedtls_mpi_read_binary(&b, pBaseSecret, UCOIN_SZ_PRIVKEY);
    ret = mbedtls_mpi_add_mpi(&a, &a, &b);
    if (ret) {
        goto LABEL_EXIT;
    }
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_mpi_mod_mpi(&a, &a, &keypair.grp.N);
    if (ret) {
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_write_binary(&a, pPrivKey, UCOIN_SZ_PRIVKEY);
    if (ret) {
        goto LABEL_EXIT;
    }

#ifdef M_DBG_PRINT
    DBG_PRINTF("(priv)SHA256(per_commitment_point |+ basepoint)\n=> SHA256(");
    DUMPBIN(pPerCommitPoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" |+ ");
    DUMPBIN(pBasePoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" ==> (priv)");
    DUMPBIN(pBaseSecret, UCOIN_SZ_PRIVKEY);
    DBG_PRINTF2("\n\n");
#endif

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&a);

    return ret == 0;
}


//////////////////////////////////////////////////
//revocationkey = revocation-basepoint * SHA256(revocation-basepoint || per-commitment-point)
//                  + per-commitment-point*SHA256(per-commitment-point || revocation-basepoint)
bool HIDDEN ln_derkey_revocationkey(uint8_t *pRevPubKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint)
{
    int ret;
    uint8_t base1[UCOIN_SZ_HASH256];
    uint8_t base2[UCOIN_SZ_HASH256];
    mbedtls_sha256_context ctx;
    mbedtls_ecp_keypair keypair;

    //sha256(revocation-basepoint || per-commitment-point)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pBasePoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pPerCommitPoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base1);
    mbedtls_sha256_free(&ctx);

    //sha256(per-commitment-point || revocation-basepoint)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pPerCommitPoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pBasePoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base2);
    mbedtls_sha256_free(&ctx);

    size_t sz;
    mbedtls_mpi bp1;
    mbedtls_mpi bp2;
    mbedtls_ecp_point S1;
    mbedtls_ecp_point S2;
    mbedtls_ecp_point S;

    mbedtls_mpi_init(&bp1);
    mbedtls_mpi_init(&bp2);
    mbedtls_ecp_point_init(&S1);
    mbedtls_ecp_point_init(&S2);
    mbedtls_ecp_point_init(&S);
    mbedtls_ecp_keypair_init(&keypair);

    mbedtls_mpi_read_binary(&bp1, base1, sizeof(base1));
    ret = ucoin_util_ecp_point_read_binary2(&S1, pBasePoint);
    if (ret) {
        goto LABEL_EXIT;
    }
    mbedtls_mpi_read_binary(&bp2, base2, sizeof(base2));
    ret = ucoin_util_ecp_point_read_binary2(&S2, pPerCommitPoint);
    if (ret) {
        goto LABEL_EXIT;
    }
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_ecp_muladd(&keypair.grp, &S, &bp1, &S1, &bp2, &S2);
    if (ret) {
        goto LABEL_EXIT;
    }
    ret = mbedtls_ecp_point_write_binary(&keypair.grp, &S, MBEDTLS_ECP_PF_COMPRESSED, &sz, pRevPubKey, UCOIN_SZ_PUBKEY);

#ifdef M_DBG_PRINT
    DBG_PRINTF("SHA256(revocation_basepoint |x per_commitment_point)\n=> SHA256(");
    DUMPBIN(pBasePoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" |x ");
    DUMPBIN(pPerCommitPoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" ==> ");
    DUMPBIN(pRevPubKey, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("\n\n");
#endif

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ecp_point_free(&S);
    mbedtls_mpi_free(&bp1);
    mbedtls_mpi_free(&bp2);
    mbedtls_ecp_point_free(&S1);
    mbedtls_ecp_point_free(&S2);

    return ret == 0;
}


//////////////////////////////////////////////////
//revocationsecretkey = revocation-basepoint-secret * SHA256(revocation-basepoint || per-commitment-point)
//                          + per-commitment-secret*SHA256(per-commitment-point || revocation-basepoint)
bool HIDDEN ln_derkey_revocationprivkey(uint8_t *pRevPrivKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint,
            const uint8_t *pBaseSecret, const uint8_t *pPerCommitSecret)
{
    int ret;
    uint8_t base2[UCOIN_SZ_HASH256];
    mbedtls_sha256_context ctx;
    mbedtls_ecp_keypair keypair;

    //sha256(revocation-basepoint || per-commitment-point)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pBasePoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pPerCommitPoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, pRevPrivKey);
    mbedtls_sha256_free(&ctx);

    mbedtls_mpi a;
    mbedtls_mpi b;
    mbedtls_mpi c;
    mbedtls_mpi_init(&a);
    mbedtls_mpi_init(&b);
    mbedtls_mpi_init(&c);
    mbedtls_ecp_keypair_init(&keypair);

    mbedtls_mpi_read_binary(&a, pRevPrivKey, UCOIN_SZ_PRIVKEY);
    mbedtls_mpi_read_binary(&b, pBaseSecret, UCOIN_SZ_PRIVKEY);
    ret = mbedtls_mpi_mul_mpi(&a, &a, &b);
    if (ret) {
        goto LABEL_EXIT;
    }

    //sha256(per-commitment-point || revocation-basepoint)
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pPerCommitPoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pBasePoint, UCOIN_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base2);
    mbedtls_sha256_free(&ctx);

    mbedtls_mpi_read_binary(&b, base2, UCOIN_SZ_PRIVKEY);
    mbedtls_mpi_read_binary(&c, pPerCommitSecret, UCOIN_SZ_PRIVKEY);
    ret = mbedtls_mpi_mul_mpi(&b, &b, &c);
    if (ret) {
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_add_mpi(&a, &a, &b);
    if (ret) {
        goto LABEL_EXIT;
    }
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_mpi_mod_mpi(&a, &a, &keypair.grp.N);
    if (ret) {
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_write_binary(&a, pRevPrivKey, UCOIN_SZ_PRIVKEY);
    if (ret) {
        goto LABEL_EXIT;
    }

#ifdef M_DBG_PRINT
    DBG_PRINTF("(priv)SHA256(revocation_basepoint |x per_commitment_point) x per_commitment_secret\n=>SHA256(");
    DUMPBIN(pBasePoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" x ");
    DUMPBIN(pPerCommitPoint, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2(" x ");
    DUMPBIN(pPerCommitSecret, UCOIN_SZ_PRIVKEY);
    DBG_PRINTF2(" ==> (priv)");
    DUMPBIN(pRevPrivKey, UCOIN_SZ_PRIVKEY);
    DBG_PRINTF2("\n\n");
#endif

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&c);
    mbedtls_mpi_free(&b);
    mbedtls_mpi_free(&a);

    return ret == 0;
}


//////////////////////////////////////////////////
//
//      https://github.com/rustyrussell/ccan/tree/master/ccan/crypto/shachain
void HIDDEN ln_derkey_create_secret(uint8_t *pPrivKey, const uint8_t *pSeed, uint64_t Index)
{
    DBG_PRINTF("index=%" PRIx64 "\n", Index);

    derive_secret(pPrivKey, pSeed, 47, Index);
}


void HIDDEN ln_derkey_storage_init(ln_derkey_storage *pStorage)
{
    for (int lp = 0; lp < 49; lp++) {
        memset(pStorage->storage[lp].secret, 0xcc, UCOIN_SZ_PRIVKEY);
        pStorage->storage[lp].index = 0x123456789abc;
    }
}


bool HIDDEN ln_derkey_storage_insert_secret(ln_derkey_storage *pStorage, const uint8_t *pSecret, uint64_t Index)
{
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
    //
    uint8_t output[UCOIN_SZ_PRIVKEY];

    int bit = where_to_put_secret(Index);
    DBG_PRINTF("I=%" PRIx64 ", bit=%d\n", Index, bit);
    for (int lp = 0; lp < bit; lp++) {
        derive_secret(output, pSecret, bit-1, pStorage->storage[lp].index);
        if (memcmp(output, pStorage->storage[lp].secret, UCOIN_SZ_PRIVKEY) != 0) {
            //error
            DBG_PRINTF("fail: secret mismatch(I=%" PRIx64 "), bit=%d\n", Index, bit);
            assert(0);
            return false;
        }
    }
    memcpy(pStorage->storage[bit].secret, pSecret, UCOIN_SZ_PRIVKEY);
    pStorage->storage[bit].index = Index;

    return true;
}


bool HIDDEN ln_derkey_storage_get_secret(uint8_t *pSecret, const ln_derkey_storage *pStorage, uint64_t Index)
{
    DBG_PRINTF("index=%" PRIx64 "\n", Index);

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
                memcpy(pSecret, pStorage->storage[lp].secret, UCOIN_SZ_PRIVKEY);
            } else {
                uint64_t diff = Index - pStorage->storage[lp].index;
                derive_secret(pSecret, pStorage->storage[lp].secret, lp, diff);
            }
            ret = true;
            break;
        }
    }
    assert(ret);
    return ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** 鍵生成
 *
 */
static void derive_secret(uint8_t *pOutput, const uint8_t *pBase, int bit, uint64_t Index)
{
    uint8_t output[UCOIN_SZ_SHA256];

    //generate_from_seed(seed, I):
    //    P = seed
    //    for B in 0 to 47:
    //        if B set in I:
    //            flip(B) in P
    //            P = SHA256(P)
    //    return P
    memcpy(output, pBase, UCOIN_SZ_SHA256);
    for (int lp = bit; lp >= 0; lp--) {
        if (Index & ((uint64_t)1 << lp)) {
            output[lp / 8] ^= (1 << (lp % 8));
            ucoin_util_sha256(output, output, UCOIN_SZ_SHA256);
        }
    }
    memcpy(pOutput, output, UCOIN_SZ_SHA256);
}


/** 0が続いた個数
 *
 */
static int where_to_put_secret(uint64_t Index)
{
    //where_to_put_secret(I):
    //  for B in 0 to 47:
    //      if testbit(I) in B == 1:
    //          return B
    //    # I = 0, this is the seed.
    //  return 48
    int lp;

    if ((Index & 0xffffffffffffLL) == 0) {
        return 48;
    }
    for (lp = 0; lp < 48; lp++) {
        if (Index & ((uint64_t)1 << lp)) {
            break;
        }
    }

    return lp;
}
