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
/** @file   ln_onion.c
 *  @brief  ONION関連
 *  @author ueno@nayuta.co
 *  @sa     https://github.com/cdecker/lightning-onion/blob/sphinx-hop-data/sphinx.go
 */
#include <sodium/crypto_stream_chacha20.h>
#include <sodium/randombytes.h>

#include "mbedtls/md.h"

#include "ln/ln_local.h"
#include "ln/ln_misc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_VERSION               ((uint8_t)0x00)
#define M_REALM_VAL             (0x00)

#define M_SZ_BLINDING_FACT      (32)
#define M_SZ_PAD                (12)
#define M_SZ_HMAC               (32)
#define M_SZ_REALM              ((int)sizeof(uint8_t))
#define M_SZ_CHANNEL_ID         ((int)sizeof(uint64_t))
#define M_SZ_AMT_TO_FORWARD     ((int)sizeof(uint64_t))
#define M_SZ_OUTGOING_CLTV_VAL  ((int)sizeof(uint32_t))
#define M_SZ_HOP_DATA           (M_SZ_REALM + M_SZ_CHANNEL_ID + M_SZ_AMT_TO_FORWARD + M_SZ_OUTGOING_CLTV_VAL + M_SZ_PAD + M_SZ_HMAC)
#define M_SZ_SHARED_SECRET      (32)
#define M_SZ_ROUTING_INFO       (LN_HOP_MAX * M_SZ_HOP_DATA)
#define M_SZ_STREAM_BYTES       (M_SZ_ROUTING_INFO + M_SZ_HOP_DATA)
#define M_SZ_KEYLEN             (32)

//#define M_DBG_FAIL


/**************************************************************************
 * typedefs
 **************************************************************************/


/**************************************************************************
 * const variables
 **************************************************************************/

static const uint8_t RHO[] = { 'r', 'h', 'o' };
static const uint8_t MU[] = { 'm', 'u' };
static const uint8_t UM[] = { 'u', 'm' };
static const uint8_t AMMAG[] = { 'a', 'm', 'm', 'a', 'g' };


/**************************************************************************
 * prototypes
 **************************************************************************/

static void multi_scalar_mul(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pBlindingFactors, int NumHops);
static bool blind_group_element(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pBlindingFactor);
static void compute_blinding_factor(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pSharedSecret);
static int generate_header_padding(uint8_t *pResult, const uint8_t *pKeyStr, int StrLen, int NumHops, const uint8_t *pSharedSecrets);
static bool generate_key(uint8_t *pResult, const uint8_t *pKeyStr, int StrLen, const uint8_t *pSharedSecret);
static void generate_cipher_stream(uint8_t *pResult, const uint8_t *pKey, int Len);
static void right_shift(uint8_t *pData);
static void xor_bytes(uint8_t *pResult, const uint8_t *pSrc1, const uint8_t *pSrc2, int Len);


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_onion_create_packet(uint8_t *pPacket,
            ucoin_buf_t *pSecrets,
            const ln_hop_datain_t *pHopData,
            int NumHops,
            const uint8_t *pSessionKey,
            const uint8_t *pAssocData, int AssocLen)
{
    if (NumHops > LN_HOP_MAX) {
        DBG_PRINTF("hops over\n");
        return false;
    }

    int filler_len;
    uint8_t next_hmac[M_SZ_HMAC];
    uint8_t rho_key[M_SZ_KEYLEN];
    uint8_t mu_key[M_SZ_KEYLEN];

    //メモリ確保
    uint8_t *eph_pubkeys = (uint8_t *)M_MALLOC(UCOIN_SZ_PUBKEY * NumHops);
    uint8_t *shd_secrets = (uint8_t *)M_MALLOC(M_SZ_SHARED_SECRET * NumHops);
    uint8_t *blind_factors = (uint8_t *)M_MALLOC(M_SZ_BLINDING_FACT * NumHops);
    uint8_t *filler = (uint8_t *)M_MALLOC(M_SZ_HOP_DATA * (LN_HOP_MAX - 1));
    //メモリ確保(初期値0)
    uint8_t *mix_header = (uint8_t *)M_CALLOC(1, M_SZ_ROUTING_INFO);
    uint8_t *stream_bytes = (uint8_t *)M_CALLOC(1, M_SZ_STREAM_BYTES);

    //[0]は最初に作る

    //セッション鍵のpubkey --> eph_pubkeys[0]
    ucoin_keys_priv2pub(eph_pubkeys, pSessionKey);

    //セッション鍵とpaymentPathの先頭から作った共有鍵のSHA256 --> shd_secrets[0]
    ucoin_util_generate_shared_secret(shd_secrets, pHopData[0].pubkey, pSessionKey);

    //eph_pubkeys[0]とshd_secrets[0]から計算 --> blind_factors[0]
    compute_blinding_factor(blind_factors, eph_pubkeys, shd_secrets);

    for (int lp = 1; lp < NumHops; lp++) {
        //eph_pubkeys[lp-1] * blind_factors[lp - 1] --> eph_pubkeys[lp]
        blind_group_element(eph_pubkeys + UCOIN_SZ_PUBKEY * lp,
                            eph_pubkeys + UCOIN_SZ_PUBKEY * (lp - 1),
                            blind_factors + M_SZ_BLINDING_FACT * (lp - 1));

        //paymentPath[lp] * セッション鍵 --> yToX(公開鍵)
        //yToXにblind_factors[0～lp]までを掛けていった結果をSHA256 --> shd_secrets[lp]
        uint8_t yToX[UCOIN_SZ_PUBKEY];
        uint8_t buf[UCOIN_SZ_PUBKEY];

        blind_group_element(yToX, pHopData[lp].pubkey, pSessionKey);
        multi_scalar_mul(buf, yToX, blind_factors, lp);
        ucoin_util_sha256(shd_secrets + M_SZ_SHARED_SECRET * lp, buf, sizeof(buf));

        //SHA256(eph_pubkeys[lp] || shd_secrets[lp]) --> blind_factors[lp]
        compute_blinding_factor(blind_factors + M_SZ_BLINDING_FACT * lp,
                            eph_pubkeys + UCOIN_SZ_PUBKEY * lp,
                            shd_secrets + M_SZ_SHARED_SECRET * lp);
    }

    filler_len = generate_header_padding(filler, RHO, sizeof(RHO), NumHops, shd_secrets);
#ifdef UNITTEST
    extern uint8_t *spEphPubkey;
    extern uint8_t *spShdSecret;
    extern uint8_t *spBlindFactor;
    spEphPubkey = (uint8_t *)M_MALLOC(UCOIN_SZ_PUBKEY * NumHops);
    spShdSecret = (uint8_t *)M_MALLOC(M_SZ_SHARED_SECRET * NumHops);
    spBlindFactor = (uint8_t *)M_MALLOC(M_SZ_BLINDING_FACT * NumHops);
    memcpy(spEphPubkey, eph_pubkeys, UCOIN_SZ_PUBKEY * NumHops);
    memcpy(spShdSecret, shd_secrets, M_SZ_SHARED_SECRET * NumHops);
    memcpy(spBlindFactor, blind_factors, M_SZ_BLINDING_FACT * NumHops);

    extern ucoin_buf_t sOnionBuffer;
    ucoin_buf_alloccopy(&sOnionBuffer, filler, filler_len);
#endif  //UNITTEST

    memset(next_hmac, 0, sizeof(next_hmac));

    //For each hop in the route in reverse order the sender applies the following operations:
    for (int lp = NumHops - 1; lp >= 0; lp--) {
        generate_key(rho_key, RHO, sizeof(RHO), shd_secrets + M_SZ_SHARED_SECRET * lp);
        generate_key(mu_key, MU, sizeof(MU), shd_secrets + M_SZ_SHARED_SECRET * lp);

        generate_cipher_stream(stream_bytes, rho_key, M_SZ_STREAM_BYTES);

        right_shift(mix_header);
        //[ 0] realm
        //[ 1] short_channel_id
        //[ 9] amt_to_forward
        //[17] outgoing_cltv_value
        //[21] padding
        //[33] hmac
        uint8_t *p = mix_header;
        *p = M_REALM_VAL;
        p++;
        ln_misc_setbe(p, &pHopData[lp].short_channel_id, M_SZ_CHANNEL_ID);
        p += M_SZ_CHANNEL_ID;
        ln_misc_setbe(p, &pHopData[lp].amt_to_forward, M_SZ_AMT_TO_FORWARD);
        p += M_SZ_AMT_TO_FORWARD;
        ln_misc_setbe(p, &pHopData[lp].outgoing_cltv_value, M_SZ_OUTGOING_CLTV_VAL);
        p += M_SZ_OUTGOING_CLTV_VAL;
        memset(p, 0, M_SZ_PAD);
        p += M_SZ_PAD;
        memcpy(p, next_hmac, M_SZ_HMAC);
        p += M_SZ_HMAC;

        xor_bytes(mix_header, mix_header, stream_bytes, M_SZ_ROUTING_INFO);      //TODO: M_SZ_ROUTING_INFOでよい？

        if (lp == NumHops - 1) {
            memcpy(mix_header + M_SZ_ROUTING_INFO - filler_len, filler, filler_len);
        }

        memcpy(pPacket, mix_header, M_SZ_ROUTING_INFO);
        if (AssocLen != 0) {
            memcpy(pPacket + M_SZ_ROUTING_INFO, pAssocData, AssocLen);
        }
        ucoin_util_calc_mac(next_hmac, mu_key, M_SZ_KEYLEN, pPacket, M_SZ_ROUTING_INFO + AssocLen);
    }

    pPacket[0] = M_VERSION;
    memcpy(pPacket + 1, eph_pubkeys, UCOIN_SZ_PUBKEY);
    memcpy(pPacket + 1 + UCOIN_SZ_PUBKEY, mix_header, M_SZ_ROUTING_INFO);
    memcpy(pPacket + 1 + UCOIN_SZ_PUBKEY + M_SZ_ROUTING_INFO, next_hmac, M_SZ_HMAC);

    if (pSecrets) {
        ucoin_buf_alloccopy(pSecrets, shd_secrets, M_SZ_SHARED_SECRET * NumHops);
    }

    //メモリ解放
    M_FREE(stream_bytes);
    M_FREE(mix_header);
    M_FREE(filler);
    M_FREE(blind_factors);
    M_FREE(shd_secrets);
    M_FREE(eph_pubkeys);

    return true;
}


bool HIDDEN ln_onion_read_packet(uint8_t *pNextPacket, ln_hop_dataout_t *pNextData,
            ucoin_buf_t *pSharedSecret,
            const uint8_t *pPacket,
            const uint8_t *pOnionPrivKey,
            const uint8_t *pAssocData, int AssocLen)
{
    bool ret;

    if (*pPacket != M_VERSION) {
        DBG_PRINTF("fail: invalid version : %02x\n", *pPacket);
        return false;
    }

    const uint8_t *p_dhkey = pPacket + 1;
    const uint8_t *p_route = p_dhkey + UCOIN_SZ_PUBKEY;
    const uint8_t *p_hmac = p_route + M_SZ_ROUTING_INFO;

    ret = ucoin_keys_chkpub(p_dhkey);
    if (!ret) {
        DBG_PRINTF("fail: invalid pubkey\n");
        return false;
    }

    uint8_t next_hmac[M_SZ_HMAC];
    uint8_t rho_key[M_SZ_KEYLEN];
    uint8_t mu_key[M_SZ_KEYLEN];
    uint8_t shared_secret[M_SZ_SHARED_SECRET];

    ucoin_util_generate_shared_secret(shared_secret, p_dhkey, pOnionPrivKey);

    int len = (M_SZ_HOP_DATA > AssocLen) ? M_SZ_HOP_DATA : AssocLen;
    uint8_t *p_msg = (uint8_t *)M_CALLOC(1, M_SZ_ROUTING_INFO + len);
    generate_key(mu_key, MU, sizeof(MU), shared_secret);
    memcpy(p_msg, p_route, M_SZ_ROUTING_INFO);
    if (AssocLen != 0) {
        memcpy(p_msg + M_SZ_ROUTING_INFO, pAssocData, AssocLen);
    }
    ucoin_util_calc_mac(next_hmac, mu_key, M_SZ_KEYLEN, p_msg, M_SZ_ROUTING_INFO + AssocLen);
    if (memcmp(next_hmac, p_hmac, M_SZ_HMAC) != 0) {
        DBG_PRINTF("fail: hmac not match\n");
        M_FREE(p_msg);
        return false;
    }

    uint8_t *stream_bytes = (uint8_t *)M_CALLOC(1, M_SZ_STREAM_BYTES);

    generate_key(rho_key, RHO, sizeof(RHO), shared_secret);
    generate_cipher_stream(stream_bytes, rho_key, M_SZ_STREAM_BYTES);
    memset(p_msg + M_SZ_ROUTING_INFO, 0, M_SZ_HOP_DATA);
    xor_bytes(stream_bytes, p_msg, stream_bytes, M_SZ_ROUTING_INFO);

    if (*stream_bytes != M_REALM_VAL) {
        DBG_PRINTF("fail: invalid realm\n");
        M_FREE(stream_bytes);
        M_FREE(p_msg);
        return false;
    }

    pNextData->short_channel_id = ln_misc_get64be(stream_bytes + M_SZ_REALM);
    pNextData->amt_to_forward = ln_misc_get64be(stream_bytes + M_SZ_REALM + M_SZ_CHANNEL_ID);
    pNextData->outgoing_cltv_value = ln_misc_get32be(stream_bytes + M_SZ_REALM + M_SZ_CHANNEL_ID + M_SZ_AMT_TO_FORWARD);

    uint8_t blind_factor[M_SZ_BLINDING_FACT];
    compute_blinding_factor(blind_factor, p_dhkey, shared_secret);

    uint8_t eph_pubkey[UCOIN_SZ_PUBKEY];
    blind_group_element(eph_pubkey, p_dhkey, blind_factor);

    // [   0]version
    *pNextPacket = *pPacket;
    pNextPacket++;
    // [   1]pubkey
    memcpy(pNextPacket, eph_pubkey, UCOIN_SZ_PUBKEY);
    pNextPacket += UCOIN_SZ_PUBKEY;
    // [  34]route info
    memcpy(pNextPacket, stream_bytes + M_SZ_HOP_DATA, M_SZ_ROUTING_INFO);
    pNextPacket += M_SZ_ROUTING_INFO - M_SZ_HOP_DATA;
    // [1334]hmac
    pNextPacket += M_SZ_HOP_DATA;
    memcpy(pNextPacket, stream_bytes + M_SZ_HOP_DATA - M_SZ_HMAC, M_SZ_HMAC);

    M_FREE(stream_bytes);
    M_FREE(p_msg);

    //check
    pNextData->b_exit = true;
    for (int lp = 0; lp < M_SZ_HMAC; lp++) {
        if (pNextPacket[lp] != 0) {
            pNextData->b_exit = false;
            break;
        }
    }

    if (pSharedSecret) {
        //BOLT#4
        //  Intermediate hops store the shared secret from the forward path
        //      and reuse it to obfuscate the error packet on each hop.
        ucoin_buf_alloccopy(pSharedSecret, shared_secret, sizeof(shared_secret));
    }

    return true;
}


void ln_onion_failure_create(ucoin_buf_t *pNextPacket,
            const ucoin_buf_t *pSharedSecret,
            const ucoin_buf_t *pReason)
{
    //data:

#ifdef M_DBG_FAIL
    DBG_PRINTF("ONI_shared_secrets=");
    DUMPBIN(pSharedSecret->buf, pSharedSecret->len);
#endif  //M_DBG_FAIL

    //    [32:hmac]
    //    [2:failure_len]
    //    [failure_len:failuremsg]
    //    [2:pad_len]
    //    [pad_len:pad]
    uint8_t um_key[M_SZ_KEYLEN];
    const int DATALEN = 256;

    ucoin_buf_t     buf_fail;
    ucoin_push_t    proto;

    generate_key(um_key, UM, sizeof(UM), pSharedSecret->buf);

    ucoin_push_init(&proto, &buf_fail, M_SZ_HMAC + 2 + 2 + DATALEN);

    //    [32:hmac]
    proto.pos = M_SZ_HMAC;

    //    [2:failure_len]
    ln_misc_push16be(&proto, pReason->len);

    //    [failure_len:failuremsg]
    ucoin_push_data(&proto, pReason->buf, pReason->len);

    //    [2:pad_len]
    ln_misc_push16be(&proto, DATALEN - pReason->len);

    //    [pad_len:pad]
    memset(buf_fail.buf + proto.pos, 0, DATALEN - pReason->len);
    proto.pos += DATALEN - pReason->len;

    //HMAC
    ucoin_util_calc_mac(buf_fail.buf, um_key, M_SZ_KEYLEN, buf_fail.buf + M_SZ_HMAC, proto.pos - M_SZ_HMAC);

#ifdef M_DBG_FAIL
    DBG_PRINTF("um_key=");
    DUMPBIN(um_key, sizeof(um_key));
    DBG_PRINTF("buf_fail=");
    DUMPBIN(buf_fail.buf, buf_fail.len);
#endif  //M_DBG_FAIL

    ln_onion_failure_forward(pNextPacket, pSharedSecret, &buf_fail);
    ucoin_buf_free(&buf_fail);
}


void ln_onion_failure_forward(ucoin_buf_t *pNextPacket,
            const ucoin_buf_t *pSharedSecret,
            const ucoin_buf_t *pPacket)
{
    uint8_t ammag_key[M_SZ_KEYLEN];
    uint8_t *stream_bytes = (uint8_t *)M_CALLOC(1, pPacket->len);

#ifdef M_DBG_FAIL
    DBG_PRINTF("oni_shared_secret=");
    DUMPBIN(pSharedSecret->buf, pSharedSecret->len);
#endif  //M_DBG_FAIL

    generate_key(ammag_key, AMMAG, sizeof(AMMAG), pSharedSecret->buf);
    ucoin_buf_alloc(pNextPacket, pPacket->len);
    generate_cipher_stream(stream_bytes, ammag_key, pPacket->len);
    xor_bytes(pNextPacket->buf, pPacket->buf, stream_bytes, pPacket->len);
    M_FREE(stream_bytes);

#ifdef M_DBG_FAIL
    DBG_PRINTF("pNextPacket=");
    DUMPBIN(pNextPacket->buf, pNextPacket->len);
#endif  //M_DBG_FAIL
}


bool ln_onion_failure_read(ucoin_buf_t *pReason,
            int *pHop,
            const ucoin_buf_t *pSharedSecrets,
            const ucoin_buf_t *pPacket)
{
    const uint32_t DATALEN = 256;

    int NumHops = pSharedSecrets->len / UCOIN_SZ_PRIVKEY;
    if (pHop != NULL) {
        *pHop = -1;
    }

#ifdef M_DBG_FAIL
    DBG_PRINTF("NumHops=%d\n", NumHops);
    DBG_PRINTF("oni_shared_secrets=");
    DUMPBIN(pSharedSecrets->buf, pSharedSecrets->len);
#endif  //M_DBG_FAIL

    ucoin_buf_t buf1;
    ucoin_buf_t buf2;
    ucoin_buf_t reason;

    ucoin_buf_alloccopy(&buf1, pPacket->buf, pPacket->len);
    ucoin_buf_init(&buf2);
    const ucoin_buf_t *p_in = &buf1;
    ucoin_buf_t *p_out = &buf2;
    bool bend = false;
    for (int lp = 0; lp < NumHops; lp++) {
        const ucoin_buf_t sharedsecret = { pSharedSecrets->buf + UCOIN_SZ_PRIVKEY * lp, UCOIN_SZ_PRIVKEY };
        ln_onion_failure_forward(p_out, &sharedsecret, p_in);
        reason.buf = p_out->buf + M_SZ_HMAC + 2;
        reason.len = ln_misc_get16be(p_out->buf + M_SZ_HMAC);
        if (reason.len < DATALEN) {
            uint32_t pad_len = ln_misc_get16be(p_out->buf + M_SZ_HMAC + 2 + reason.len);
            if (reason.len + pad_len == DATALEN) {
                uint32_t lp2;
                for (lp2 = 0; lp2 < pad_len; lp2++) {
                    if (p_out->buf[M_SZ_HMAC + 2 + reason.len + 2 + lp2] != 0) {
                        break;
                    }
                }
                if (lp2 == pad_len) {
                    //padも全部0で HMACが一致すればOK
                    uint8_t um_key[M_SZ_KEYLEN];
                    generate_key(um_key, UM, sizeof(UM), sharedsecret.buf);

                    uint8_t hmac[M_SZ_HMAC];
                    ucoin_util_calc_mac(hmac, um_key, M_SZ_KEYLEN,
                                    p_out->buf + M_SZ_HMAC, p_out->len - M_SZ_HMAC);

#ifdef M_DBG_FAIL
                    DBG_PRINTF("um_key=");
                    DUMPBIN(um_key, sizeof(um_key));
                    DBG_PRINTF("p_out=");
                    DUMPBIN(p_out->buf, p_out->len);
#endif //M_DBG_FAIL

                    bend = memcmp(p_out->buf, hmac, M_SZ_HMAC) == 0;
                    if (bend) {
                        DBG_PRINTF("decode hops=%d\n", lp);
                        if (pHop != NULL) {
                            *pHop = lp;
                        }
                        ucoin_buf_alloccopy(pReason, reason.buf, reason.len);
                    } else {
                        DBG_PRINTF("fail: HMAC not match!\n");
#ifdef M_DBG_FAIL
                        DUMPBIN(p_out->buf, M_SZ_HMAC);
                        DUMPBIN(hmac, M_SZ_HMAC);
#endif //M_DBG_FAIL
                    }
                    break;
                }
            }
        }
        if (p_in == &buf1) {
            p_in  = &buf2;
            p_out = &buf1;
        } else {
            p_in  = &buf1;
            p_out = &buf2;
        }
        ucoin_buf_free(p_out);
    }

    if (!bend) {
        DBG_PRINTF("fail reason\n");
    }

    ucoin_buf_free(&buf1);
    ucoin_buf_free(&buf2);

    return bend;
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** loop{ PubKey * BlindingFactor[lp] } --> pOutput
 *
 * @param[out]      pResult         UCOIN_SZ_PUBKEY
 */
static void multi_scalar_mul(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pBlindingFactors, int NumHops)
{
    memcpy(pResult, pPubKey, UCOIN_SZ_PUBKEY);
    for (int lp = 0; lp < NumHops; lp++) {
        //前の結果公開鍵 * pBlindingFactors[lp] --> 結果公開鍵
        blind_group_element(pResult, pResult, pBlindingFactors + M_SZ_BLINDING_FACT * lp);
    }
}


/** PubKey * BlindingFactor --> pResult
 *
 * @param[out]      pResult         UCOIN_SZ_PUBKEY
 */
static bool blind_group_element(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pBlindingFactor)
{
    bool ret = ucoin_util_mul_pubkey(pResult, pPubKey, pBlindingFactor, M_SZ_BLINDING_FACT);
    return ret;
}


/**
 *
 * @param[out]      pResult         M_SZ_BLINDING_FACT
 */
static void compute_blinding_factor(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pSharedSecret)
{
    uint8_t array[UCOIN_SZ_PUBKEY + M_SZ_SHARED_SECRET];

    //SHA256: PUBKEY || SharedSecret
    memcpy(array, pPubKey, UCOIN_SZ_PUBKEY);
    memcpy(array + UCOIN_SZ_PUBKEY, pSharedSecret, M_SZ_SHARED_SECRET);
    ucoin_util_sha256(pResult, array, sizeof(array));
}


/** filler
 *
 * @param[out]      pResult     M_SZ_HOP_DATA * (NumHops - 1)
 */
static int generate_header_padding(uint8_t *pResult, const uint8_t *pKeyStr, int StrLen, int NumHops, const uint8_t *pSharedSecrets)
{
    uint8_t *streamBytes = (uint8_t *)M_MALLOC(M_SZ_STREAM_BYTES);
    uint8_t streamKey[M_SZ_KEYLEN];
    int len = 0;

    memset(pResult, 0, M_SZ_HOP_DATA * (NumHops - 1));
    for (int lp = 1; lp < NumHops; lp++) {
        int sz = (LN_HOP_MAX - lp + 1) * M_SZ_HOP_DATA;
        generate_key(streamKey, pKeyStr, StrLen, pSharedSecrets + M_SZ_SHARED_SECRET * (lp - 1));

        //chacha20
        generate_cipher_stream(streamBytes, streamKey, M_SZ_STREAM_BYTES);

        //filler:      M_SZ_HOP_DATA * (NumHops - 1)
        //streamBytes: M_SZ_HOP_DATA * lp
        len = (M_SZ_HOP_DATA * (NumHops - 1) < M_SZ_HOP_DATA * lp) ? (M_SZ_HOP_DATA * (NumHops - 1)) : (M_SZ_HOP_DATA * lp);
        xor_bytes(pResult, pResult, streamBytes + sz, len);
    }

    M_FREE(streamBytes);

    return len;
}


static bool generate_key(uint8_t *pResult, const uint8_t *pKeyStr, int StrLen, const uint8_t *pSharedSecret)
{
    //const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    //int ret = mbedtls_md_hmac(mdinfo, pKeyStr, StrLen, pSharedSecret, M_SZ_SHARED_SECRET, pResult);
    //return ret == 0;
    return ucoin_util_calc_mac(pResult, pKeyStr, StrLen, pSharedSecret, M_SZ_SHARED_SECRET);
}


/**
 * @param[out]      pResult     Lenバイトの乱数
 * @param[in]       pKey        Key
 * @param[in]       Len         乱数長
 * @note
 *      - よくわからないので、lightningdをまねる
 */
static void generate_cipher_stream(uint8_t *pResult, const uint8_t *pKey, int Len)
{
    uint8_t nonce[8] = {0};
    crypto_stream_chacha20(pResult, Len, nonce, pKey);
}


static void right_shift(uint8_t *pData)
{
    for (int lp = M_SZ_ROUTING_INFO - M_SZ_HOP_DATA - 1; lp >= 0; lp--) {
        pData[M_SZ_HOP_DATA + lp] = pData[lp];
    }
    for (int lp = 0; lp < M_SZ_HOP_DATA; lp++) {
        pData[lp] = 0;
    }
}


static void xor_bytes(uint8_t *pResult, const uint8_t *pSrc1, const uint8_t *pSrc2, int Len)
{
    for (int lp = 0; lp < Len; lp++) {
        pResult[lp] = pSrc1[lp] ^ pSrc2[lp];
    }
}
