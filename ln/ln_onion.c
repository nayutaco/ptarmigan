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
/** @file   ln_onion.c
 *  @brief  ONION関連
 *  @sa     https://github.com/cdecker/lightning-onion/blob/sphinx-hop-data/sphinx.go
 */
//#define M_USE_SODIUM
#ifdef M_USE_SODIUM
#include <sodium/crypto_stream_chacha20.h>
#include <sodium/randombytes.h>
#else
#include "mbedtls/chacha20.h"
#endif
#include "mbedtls/md.h"

#include "utl_dbg.h"
#include "utl_int.h"

#include "btc_crypto.h"

#include "ln_onion.h"
#include "ln_node.h"
#include "ln_local.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_VERSION               ((uint8_t)0x00)
#define M_VERSION_INVALID       ((uint8_t)0xff)
#define M_REALM_VAL             ((uint8_t)0x00)
#define M_REALM_VAL_INVALID     ((uint8_t)0xff)

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

#define M_EXCHANGE_ENDIAN16(val)    ((uint16_t)((val) >> 8) | (((val) & 0xff) << 8))

//#define M_DBG_FAIL //XXX: CAUTION!!: display secret


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
static void set_reason_sha256(utl_push_t *pPushReason, const uint8_t *pPacket, uint16_t Code);


/**************************************************************************
 * public functions
 **************************************************************************/

bool ln_onion_create_packet(uint8_t *pPacket,
            utl_buf_t *pSecrets,
            const ln_hop_datain_t *pHopData,
            int NumHops,
            const uint8_t *pSessionKey,
            const uint8_t *pAssocData, int AssocLen)
{
    if (NumHops > LN_HOP_MAX) {
        LOGE("hops over\n");
        return false;
    }

    int filler_len;
    uint8_t next_hmac[M_SZ_HMAC];
    uint8_t rho_key[M_SZ_KEYLEN];
    uint8_t mu_key[M_SZ_KEYLEN];

    //メモリ確保
    uint8_t *eph_pubkeys = (uint8_t *)UTL_DBG_MALLOC(BTC_SZ_PUBKEY * NumHops);
    uint8_t *shd_secrets = (uint8_t *)UTL_DBG_MALLOC(M_SZ_SHARED_SECRET * NumHops);
    uint8_t *blind_factors = (uint8_t *)UTL_DBG_MALLOC(M_SZ_BLINDING_FACT * NumHops);
    uint8_t *filler = (uint8_t *)UTL_DBG_MALLOC(M_SZ_HOP_DATA * (LN_HOP_MAX - 1));
    //メモリ確保(初期値0)
    uint8_t *mix_header = (uint8_t *)UTL_DBG_CALLOC(1, M_SZ_ROUTING_INFO);
    uint8_t *stream_bytes = (uint8_t *)UTL_DBG_CALLOC(1, M_SZ_STREAM_BYTES);

    //[0]は最初に作る

    //セッション鍵のpubkey --> eph_pubkeys[0]
    btc_keys_priv2pub(eph_pubkeys, pSessionKey);

    //セッション鍵とpaymentPathの先頭から作った共有鍵のSHA256 --> shd_secrets[0]
    btc_ecc_shared_secret_sha256(shd_secrets, pHopData[0].pubkey, pSessionKey);

    //eph_pubkeys[0]とshd_secrets[0]から計算 --> blind_factors[0]
    compute_blinding_factor(blind_factors, eph_pubkeys, shd_secrets);

    for (int lp = 1; lp < NumHops; lp++) {
        //eph_pubkeys[lp-1] * blind_factors[lp - 1] --> eph_pubkeys[lp]
        blind_group_element(eph_pubkeys + BTC_SZ_PUBKEY * lp,
                            eph_pubkeys + BTC_SZ_PUBKEY * (lp - 1),
                            blind_factors + M_SZ_BLINDING_FACT * (lp - 1));

        //paymentPath[lp] * セッション鍵 --> yToX(公開鍵)
        //yToXにblind_factors[0～lp]までを掛けていった結果をSHA256 --> shd_secrets[lp]
        uint8_t yToX[BTC_SZ_PUBKEY];
        uint8_t buf[BTC_SZ_PUBKEY];

        blind_group_element(yToX, pHopData[lp].pubkey, pSessionKey);
        multi_scalar_mul(buf, yToX, blind_factors, lp);
        btc_md_sha256(shd_secrets + M_SZ_SHARED_SECRET * lp, buf, sizeof(buf));

        //SHA256(eph_pubkeys[lp] || shd_secrets[lp]) --> blind_factors[lp]
        compute_blinding_factor(blind_factors + M_SZ_BLINDING_FACT * lp,
                            eph_pubkeys + BTC_SZ_PUBKEY * lp,
                            shd_secrets + M_SZ_SHARED_SECRET * lp);
    }

    filler_len = generate_header_padding(filler, RHO, sizeof(RHO), NumHops, shd_secrets);
#ifdef UNITTEST
    extern uint8_t *spEphPubkey;
    extern uint8_t *spShdSecret;
    extern uint8_t *spBlindFactor;
    spEphPubkey = (uint8_t *)UTL_DBG_MALLOC(BTC_SZ_PUBKEY * NumHops);
    spShdSecret = (uint8_t *)UTL_DBG_MALLOC(M_SZ_SHARED_SECRET * NumHops);
    spBlindFactor = (uint8_t *)UTL_DBG_MALLOC(M_SZ_BLINDING_FACT * NumHops);
    memcpy(spEphPubkey, eph_pubkeys, BTC_SZ_PUBKEY * NumHops);
    memcpy(spShdSecret, shd_secrets, M_SZ_SHARED_SECRET * NumHops);
    memcpy(spBlindFactor, blind_factors, M_SZ_BLINDING_FACT * NumHops);

    extern utl_buf_t sOnionBuffer;
    utl_buf_alloccopy(&sOnionBuffer, filler, filler_len);
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
        if (LN_DBG_ONION_CREATE_NORMAL_REALM()) {
        *p = M_REALM_VAL;
        } else {
            *p = M_REALM_VAL_INVALID;
        }
        p++;
        utl_int_unpack_u64be(p, pHopData[lp].short_channel_id);
        p += M_SZ_CHANNEL_ID;
        utl_int_unpack_u64be(p, pHopData[lp].amt_to_forward);
        p += M_SZ_AMT_TO_FORWARD;
        utl_int_unpack_u32be(p, pHopData[lp].outgoing_cltv_value);
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
        btc_hmac_sha256(next_hmac, mu_key, M_SZ_KEYLEN, pPacket, M_SZ_ROUTING_INFO + AssocLen);
    }

    if (LN_DBG_ONION_CREATE_NORMAL_VERSION()) {
    pPacket[0] = M_VERSION;
    } else {
        pPacket[0] = M_VERSION_INVALID;
    }
    memcpy(pPacket + 1, eph_pubkeys, BTC_SZ_PUBKEY);
    memcpy(pPacket + 1 + BTC_SZ_PUBKEY, mix_header, M_SZ_ROUTING_INFO);
    memcpy(pPacket + 1 + BTC_SZ_PUBKEY + M_SZ_ROUTING_INFO, next_hmac, M_SZ_HMAC);

    if (pSecrets) {
        utl_buf_alloccopy(pSecrets, shd_secrets, M_SZ_SHARED_SECRET * NumHops);
    }

    //メモリ解放
    UTL_DBG_FREE(stream_bytes);
    UTL_DBG_FREE(mix_header);
    UTL_DBG_FREE(filler);
    UTL_DBG_FREE(blind_factors);
    UTL_DBG_FREE(shd_secrets);
    UTL_DBG_FREE(eph_pubkeys);

    return true;
}


bool HIDDEN ln_onion_read_packet(
    uint8_t *pNextPacket, ln_hop_dataout_t *pNextData, utl_buf_t *pSharedSecret, utl_push_t *pPushReason,
    const uint8_t *pPacket, const uint8_t *pAssocData, int AssocLen)
{
    bool ret;

    if (*pPacket != M_VERSION) {
        LOGE("fail: invalid version : %02x\n", *pPacket);

        //B1. if the onion version byte is unknown:
        //      invalid_onion_version
        set_reason_sha256(pPushReason, pPacket, LNONION_INV_ONION_VERSION);
        return false;
    }

    const uint8_t *p_dhkey = pPacket + 1;
    const uint8_t *p_route = p_dhkey + BTC_SZ_PUBKEY;
    const uint8_t *p_hmac = p_route + M_SZ_ROUTING_INFO;

    ret = btc_keys_check_pub(p_dhkey);
    if (!ret) {
        LOGE("fail: invalid pubkey\n");

        //B3. if the ephemeral key in the onion is unparsable:
        //      invalid_onion_key
        set_reason_sha256(pPushReason, pPacket, LNONION_INV_ONION_KEY);
        return false;
    }

    uint8_t next_hmac[M_SZ_HMAC];
    uint8_t rho_key[M_SZ_KEYLEN];
    uint8_t mu_key[M_SZ_KEYLEN];
    uint8_t shared_secret[M_SZ_SHARED_SECRET];

    ln_node_generate_shared_secret(shared_secret, p_dhkey);
    if (pSharedSecret) {
        //BOLT#4
        //  Intermediate hops store the shared secret from the forward path
        //      and reuse it to obfuscate the error packet on each hop.
        utl_buf_alloccopy(pSharedSecret, shared_secret, sizeof(shared_secret));
    }

    int len = (M_SZ_HOP_DATA > AssocLen) ? M_SZ_HOP_DATA : AssocLen;
    uint8_t *p_msg = (uint8_t *)UTL_DBG_CALLOC(1, M_SZ_ROUTING_INFO + len);
    generate_key(mu_key, MU, sizeof(MU), shared_secret);
    memcpy(p_msg, p_route, M_SZ_ROUTING_INFO);
    if (AssocLen != 0) {
        memcpy(p_msg + M_SZ_ROUTING_INFO, pAssocData, AssocLen);
    }
    btc_hmac_sha256(next_hmac, mu_key, M_SZ_KEYLEN, p_msg, M_SZ_ROUTING_INFO + AssocLen);
    if (memcmp(next_hmac, p_hmac, M_SZ_HMAC) != 0) {
        LOGE("fail: hmac not match\n");
        UTL_DBG_FREE(p_msg);

        //B2. if the onion HMAC is incorrect:
        //      invalid_onion_hmac
        set_reason_sha256(pPushReason, pPacket, LNONION_INV_ONION_HMAC);
        return false;
    }

    uint8_t *stream_bytes = (uint8_t *)UTL_DBG_CALLOC(1, M_SZ_STREAM_BYTES);

    generate_key(rho_key, RHO, sizeof(RHO), shared_secret);
    generate_cipher_stream(stream_bytes, rho_key, M_SZ_STREAM_BYTES);
    memset(p_msg + M_SZ_ROUTING_INFO, 0, M_SZ_HOP_DATA);
    xor_bytes(stream_bytes, p_msg, stream_bytes, M_SZ_ROUTING_INFO);

    if (*stream_bytes != M_REALM_VAL) {
        LOGE("fail: invalid realm\n");
        UTL_DBG_FREE(stream_bytes);
        UTL_DBG_FREE(p_msg);

        //A1. if the realm byte is unknown:
        //      invalid_realm
        utl_push_u16be(pPushReason, LNONION_INV_REALM);
        return false;
    }

    pNextData->short_channel_id = utl_int_pack_u64be(stream_bytes + M_SZ_REALM);
    pNextData->amt_to_forward = utl_int_pack_u64be(stream_bytes + M_SZ_REALM + M_SZ_CHANNEL_ID);
    pNextData->outgoing_cltv_value = utl_int_pack_u32be(stream_bytes + M_SZ_REALM + M_SZ_CHANNEL_ID + M_SZ_AMT_TO_FORWARD);

    uint8_t blind_factor[M_SZ_BLINDING_FACT];
    compute_blinding_factor(blind_factor, p_dhkey, shared_secret);

    uint8_t eph_pubkey[BTC_SZ_PUBKEY];
    blind_group_element(eph_pubkey, p_dhkey, blind_factor);

    // [   0]version
    *pNextPacket = *pPacket;
    pNextPacket++;
    // [   1]pubkey
    memcpy(pNextPacket, eph_pubkey, BTC_SZ_PUBKEY);
    pNextPacket += BTC_SZ_PUBKEY;
    // [  34]route info
    memcpy(pNextPacket, stream_bytes + M_SZ_HOP_DATA, M_SZ_ROUTING_INFO);
    pNextPacket += M_SZ_ROUTING_INFO - M_SZ_HOP_DATA;
    // [1334]hmac
    pNextPacket += M_SZ_HOP_DATA;
    memcpy(pNextPacket, stream_bytes + M_SZ_HOP_DATA - M_SZ_HMAC, M_SZ_HMAC);

    UTL_DBG_FREE(stream_bytes);
    UTL_DBG_FREE(p_msg);

    //check
    pNextData->b_exit = true;
    for (int lp = 0; lp < M_SZ_HMAC; lp++) {
        if (pNextPacket[lp] != 0) {
            pNextData->b_exit = false;
            break;
        }
    }

    return true;
}


void ln_onion_failure_create(utl_buf_t *pNextPacket,
            const utl_buf_t *pSharedSecret,
            const utl_buf_t *pReason)
{
    //data:

#ifdef M_DBG_FAIL
    LOGD("ONI_shared_secrets=");
    DUMPD(pSharedSecret->buf, pSharedSecret->len);
#endif  //M_DBG_FAIL

    //    [32:hmac]
    //    [2:failure_len]
    //    [failure_len:failuremsg]
    //    [2:pad_len]
    //    [pad_len:pad]
    uint8_t um_key[M_SZ_KEYLEN];
    const int DATALEN = 256;

    utl_buf_t     buf_fail = UTL_BUF_INIT;
    utl_push_t    proto;

    generate_key(um_key, UM, sizeof(UM), pSharedSecret->buf);

    utl_push_init(&proto, &buf_fail, M_SZ_HMAC + 2 + 2 + DATALEN);

    //    [32:hmac]
    proto.pos = M_SZ_HMAC;

    //    [2:failure_len]
    utl_push_u16be(&proto, pReason->len);

    //    [failure_len:failuremsg]
    utl_push_data(&proto, pReason->buf, pReason->len);

    //    [2:pad_len]
    utl_push_u16be(&proto, DATALEN - pReason->len);

    //    [pad_len:pad]
    memset(buf_fail.buf + proto.pos, 0, DATALEN - pReason->len);
    proto.pos += DATALEN - pReason->len;

    //HMAC
    btc_hmac_sha256(buf_fail.buf, um_key, M_SZ_KEYLEN, buf_fail.buf + M_SZ_HMAC, proto.pos - M_SZ_HMAC);

#ifdef M_DBG_FAIL
    LOGD("um_key=");
    DUMPD(um_key, sizeof(um_key));
    LOGD("buf_fail=");
    DUMPD(buf_fail.buf, buf_fail.len);
#endif  //M_DBG_FAIL

    ln_onion_failure_forward(pNextPacket, pSharedSecret, &buf_fail);
    utl_buf_free(&buf_fail);
}


void ln_onion_failure_forward(utl_buf_t *pNextPacket,
            const utl_buf_t *pSharedSecret,
            const utl_buf_t *pPacket)
{
    uint8_t ammag_key[M_SZ_KEYLEN];
    uint8_t *stream_bytes = (uint8_t *)UTL_DBG_CALLOC(1, pPacket->len);

#ifdef M_DBG_FAIL
    LOGD("oni_shared_secret=");
    DUMPD(pSharedSecret->buf, pSharedSecret->len);
#endif  //M_DBG_FAIL

    generate_key(ammag_key, AMMAG, sizeof(AMMAG), pSharedSecret->buf);
    utl_buf_alloc(pNextPacket, pPacket->len);
    generate_cipher_stream(stream_bytes, ammag_key, pPacket->len);
    xor_bytes(pNextPacket->buf, pPacket->buf, stream_bytes, pPacket->len);
    UTL_DBG_FREE(stream_bytes);

#ifdef M_DBG_FAIL
    LOGD("pNextPacket=");
    DUMPD(pNextPacket->buf, pNextPacket->len);
#endif  //M_DBG_FAIL
}


bool ln_onion_failure_read(utl_buf_t *pReason,
            int *pHop,
            const utl_buf_t *pSharedSecrets,
            const utl_buf_t *pPacket)
{
    const uint32_t DATALEN = 256;

    int NumHops = pSharedSecrets->len / BTC_SZ_PRIVKEY;
    if (pHop != NULL) {
        *pHop = -1;
    }

#ifdef M_DBG_FAIL
    LOGD("NumHops=%d\n", NumHops);
    LOGD("oni_shared_secrets=");
    DUMPD(pSharedSecrets->buf, pSharedSecrets->len);
#endif  //M_DBG_FAIL

    utl_buf_t buf1 = UTL_BUF_INIT;
    utl_buf_t buf2 = UTL_BUF_INIT;
    utl_buf_t reason = UTL_BUF_INIT;

    utl_buf_alloccopy(&buf1, pPacket->buf, pPacket->len);
    const utl_buf_t *p_in = &buf1;
    utl_buf_t *p_out = &buf2;
    bool bend = false;
    for (int lp = 0; lp < NumHops; lp++) {
        const utl_buf_t sharedsecret = { pSharedSecrets->buf + BTC_SZ_PRIVKEY * lp, BTC_SZ_PRIVKEY };
        ln_onion_failure_forward(p_out, &sharedsecret, p_in);
        reason.buf = p_out->buf + M_SZ_HMAC + 2;
        reason.len = utl_int_pack_u16be(p_out->buf + M_SZ_HMAC);
        if (reason.len < DATALEN) {
            uint32_t pad_len = utl_int_pack_u16be(p_out->buf + M_SZ_HMAC + 2 + reason.len);
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
                    btc_hmac_sha256(hmac, um_key, M_SZ_KEYLEN,
                                    p_out->buf + M_SZ_HMAC, p_out->len - M_SZ_HMAC);

#ifdef M_DBG_FAIL
                    LOGD("um_key=");
                    DUMPD(um_key, sizeof(um_key));
                    LOGD("p_out=");
                    DUMPD(p_out->buf, p_out->len);
#endif //M_DBG_FAIL

                    bend = memcmp(p_out->buf, hmac, M_SZ_HMAC) == 0;
                    if (bend) {
                        LOGD("decode hops=%d\n", lp);
                        if (pHop != NULL) {
                            *pHop = lp;
                        }
                        utl_buf_alloccopy(pReason, reason.buf, reason.len);
                    } else {
                        LOGE("fail: HMAC not match!\n");
#ifdef M_DBG_FAIL
                        DUMPE(p_out->buf, M_SZ_HMAC);
                        DUMPE(hmac, M_SZ_HMAC);
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
        utl_buf_free(p_out);
    }

    if (!bend) {
        LOGE("fail reason\n");
    }

    utl_buf_free(&buf1);
    utl_buf_free(&buf2);

    return bend;
}


bool ln_onion_read_err(ln_onion_err_t *pOnionErr, const utl_buf_t *pReason)
{
    pOnionErr->reason = ((uint16_t)pReason->buf[0] << 8) | pReason->buf[1];
    pOnionErr->p_data = NULL;   //TODO:reasonに応じた結果をUTL_DBG_MALLOCして代入
    return true;
}


void ln_onion_create_reason_temp_node(utl_buf_t *pReason)
{
    //A2. if an otherwise unspecified transient error occurs for the entire node:
    //      temporary_node_failure
    uint16_t code = M_EXCHANGE_ENDIAN16(LNONION_TMP_NODE_FAIL);
    utl_buf_alloccopy(pReason, (uint8_t *)&code, sizeof(code));
}


void ln_onion_create_reason_perm_node(utl_buf_t *pReason)
{
    //A3. if an otherwise unspecified permanent error occurs for the entire node:
    //      return a permanent_node_failure error.
    uint16_t code = M_EXCHANGE_ENDIAN16(LNONION_PERM_NODE_FAIL);
    utl_buf_alloccopy(pReason, (uint8_t *)&code, sizeof(code));
}


char *ln_onion_get_errstr(const ln_onion_err_t *pOnionErr)
{
    const struct {
        uint16_t err;
        const char *str;
    } ONIONERR[] = {
        { LNONION_INV_REALM, "invalid realm" },
        { LNONION_TMP_NODE_FAIL, "temporary_node_failure" },
        { LNONION_PERM_NODE_FAIL, "permanent_node_failure" },
        { LNONION_REQ_NODE_FTR_MISSING, "required_node_feature_missing" },
        { LNONION_INV_ONION_VERSION, "invalid_onion_version" },
        { LNONION_INV_ONION_HMAC, "invalid_onion_hmac" },
        { LNONION_INV_ONION_KEY, "invalid_onion_key" },
        { LNONION_TMP_CHAN_FAIL, "temporary_channel_failure" },
        { LNONION_PERM_CHAN_FAIL, "permanent_channel_failure" },
        { LNONION_REQ_CHAN_FTR_MISSING, "required_channel_feature_missing" },
        { LNONION_UNKNOWN_NEXT_PEER, "unknown_next_peer" },
        { LNONION_AMT_BELOW_MIN, "amount_below_minimum" },
        { LNONION_FEE_INSUFFICIENT, "fee_insufficient" },
        { LNONION_INCORR_CLTV_EXPIRY, "incorrect_cltv_expiry" },
        { LNONION_EXPIRY_TOO_SOON, "expiry_too_soon" },
        { LNONION_INCRR_OR_UNKNOWN_PAY, "incorrect_or_unknown_payment_details" },
        { LNONION_OBSOLETED_INCORR_PAY_AMT, "(obsoleted)incorrect_payment_amount" },
        { LNONION_FINAL_EXPIRY_TOO_SOON, "final_expiry_too_soon" },
        { LNONION_FINAL_INCORR_CLTV_EXP, "final_incorrect_cltv_expiry" },
        { LNONION_FINAL_INCORR_HTLC_AMT, "final_incorrect_htlc_amount" },
        { LNONION_CHAN_DISABLE, "channel_disabled" },
        { LNONION_EXPIRY_TOO_FAR, "expiry_too_far" },
    };

    const char *p_str = NULL;
    for (size_t lp = 0; lp < ARRAY_SIZE(ONIONERR); lp++) {
        if (pOnionErr->reason == ONIONERR[lp].err) {
            p_str = ONIONERR[lp].str;
            break;
        }
    }
    char str[128];
    if (p_str == NULL) {
        sprintf(str, "unknown reason[%04x]", pOnionErr->reason);
        p_str = str;
    }
    return UTL_DBG_STRDUP(p_str);
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** loop{ PubKey * BlindingFactor[lp] } --> pOutput
 *
 * @param[out]      pResult         BTC_SZ_PUBKEY
 */
static void multi_scalar_mul(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pBlindingFactors, int NumHops)
{
    memcpy(pResult, pPubKey, BTC_SZ_PUBKEY);
    for (int lp = 0; lp < NumHops; lp++) {
        //前の結果公開鍵 * pBlindingFactors[lp] --> 結果公開鍵
        blind_group_element(pResult, pResult, pBlindingFactors + M_SZ_BLINDING_FACT * lp);
    }
}


/** PubKey * BlindingFactor --> pResult
 *
 * @param[out]      pResult         BTC_SZ_PUBKEY
 */
static bool blind_group_element(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pBlindingFactor)
{
    bool ret = btc_ecc_mul_pubkey(pResult, pPubKey, pBlindingFactor, M_SZ_BLINDING_FACT);
    return ret;
}


/**
 *
 * @param[out]      pResult         M_SZ_BLINDING_FACT
 */
static void compute_blinding_factor(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pSharedSecret)
{
    uint8_t array[BTC_SZ_PUBKEY + M_SZ_SHARED_SECRET];

    //SHA256: PUBKEY || SharedSecret
    memcpy(array, pPubKey, BTC_SZ_PUBKEY);
    memcpy(array + BTC_SZ_PUBKEY, pSharedSecret, M_SZ_SHARED_SECRET);
    btc_md_sha256(pResult, array, sizeof(array));
}


/** filler
 *
 * @param[out]      pResult     M_SZ_HOP_DATA * (NumHops - 1)
 */
static int generate_header_padding(uint8_t *pResult, const uint8_t *pKeyStr, int StrLen, int NumHops, const uint8_t *pSharedSecrets)
{
    uint8_t *streamBytes = (uint8_t *)UTL_DBG_MALLOC(M_SZ_STREAM_BYTES);
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

    UTL_DBG_FREE(streamBytes);

    return len;
}


static bool generate_key(uint8_t *pResult, const uint8_t *pKeyStr, int StrLen, const uint8_t *pSharedSecret)
{
    //const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    //int ret = mbedtls_md_hmac(mdinfo, pKeyStr, StrLen, pSharedSecret, M_SZ_SHARED_SECRET, pResult);
    //return ret == 0;
    return btc_hmac_sha256(pResult, pKeyStr, StrLen, pSharedSecret, M_SZ_SHARED_SECRET);
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
#ifdef M_USE_SODIUM
   uint8_t nonce[8] = {0};
    crypto_stream_chacha20(pResult, Len, nonce, pKey);
#else
    uint8_t nonce[12] = {0};
    uint8_t *dummy = (uint8_t *)UTL_DBG_CALLOC(1, Len);
    int ret = mbedtls_chacha20_crypt(pKey, nonce, 0, Len, dummy, pResult);
    if (ret != 0) {
        LOGE("FATAL: mbedtls_chacha20_crypt\n");
        abort();
    }
    UTL_DBG_FREE(dummy);
#endif
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


/** reason設定()
 *
 */
static void set_reason_sha256(utl_push_t *pPushReason, const uint8_t *pPacket, uint16_t Code)
{
    utl_push_u16be(pPushReason, Code);
    //[32:sha256_of_onion]
    uint8_t sha256_of_onion[BTC_SZ_HASH256];
    btc_md_sha256(sha256_of_onion, pPacket, LN_SZ_ONION_ROUTE);
    utl_push_data(pPushReason, sha256_of_onion, sizeof(sha256_of_onion));
}
