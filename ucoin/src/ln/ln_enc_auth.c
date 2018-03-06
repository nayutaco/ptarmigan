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
/** @file   ln_enc_auth.c
 *  @brief  [LN]BOLT#8関連
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "ln_enc_auth.h"
#include "ln_misc.h"

#include "mbedtls/md.h"
#include "sodium/crypto_aead_chacha20poly1305.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_PROTOCOL_NAME "Noise_XK_secp256k1_ChaChaPoly_SHA256"
#define M_PROTOCOL_LEN  (36)
#define M_PROLOGUE      "lightning"
#define M_PROLOGUE_LEN  (9)


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @enum   state_t
 *  @brief  noise handshake state
 */
enum state_t {
    INIT,

    //initiator
    START_INITIATOR,
    WAIT_ACT_TWO,
    END_INITIATOR,

    //responder
    WAIT_ACT_ONE,
    WAIT_ACT_THREE,
    END_RESPONDER
} state;


/** @struct bolt8
 *  @brief  noise handshake data
 */
struct bolt8 {
    ucoin_util_keys_t   *keys;              //ノードの秘密鍵と公開鍵(node_id) ?
    ucoin_util_keys_t   e;                  //ephemeral key
    uint8_t     h[UCOIN_SZ_SHA256];         //h
    uint8_t     ck[UCOIN_SZ_SHA256];        //ck
    uint8_t     temp_k[UCOIN_SZ_SHA256];    //temp_k1,2,3

    enum state_t    state;
};


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool noise_hkdf(uint8_t *ck, uint8_t *k, const uint8_t *pSalt, const uint8_t *pIkm);
static bool actone_sender(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pRS);
static bool actone_receiver(ln_self_t *self, ucoin_buf_t *pBuf);
static bool acttwo_sender(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pRE);
static bool acttwo_receiver(ln_self_t *self, ucoin_buf_t *pBuf);
static bool actthree_sender(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pRE);
static bool actthree_receiver(ln_self_t *self, ucoin_buf_t *pBuf);


/********************************************************************
 * public functions
 ********************************************************************/

bool HIDDEN ln_enc_auth_handshake_init(ln_self_t *self, const uint8_t *pNodeId)
{
    bool ret;

    //handshake完了後にFREEする
    self->p_handshake = M_MALLOC(sizeof(struct bolt8));
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;

    //自ノード情報
    pBolt->keys = &(ln_node_get()->keys);

    //ephemeral key
    ret = ucoin_util_createkeys(&pBolt->e);
    if (!ret) {
        DBG_PRINTF("fail: ephemeral key\n");
        return false;
    }

    // ck = sha256(protocolName)
    ucoin_util_sha256(pBolt->ck, (const uint8_t *)M_PROTOCOL_NAME, M_PROTOCOL_LEN);

    // h = sha256(ck || prologue)
    ucoin_util_sha256cat(pBolt->h, pBolt->ck, UCOIN_SZ_SHA256, (const uint8_t *)M_PROLOGUE, M_PROLOGUE_LEN);


    if (pNodeId != NULL) {
        //noise handshake initiator
        DBG_PRINTF("initiator\n");
        pBolt->state = START_INITIATOR;
    } else {
        //nose handshake responder
        DBG_PRINTF("responder\n");
        pNodeId = ln_node_get()->keys.pub;
        pBolt->state = WAIT_ACT_ONE;
    }
    //initiatorは相手node_id, responderは自node_id
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, pNodeId, UCOIN_SZ_PUBKEY);

    return true;
}


bool HIDDEN ln_enc_auth_handshake_start(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pNodeId)
{
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;

    if ((pBolt == NULL) || (pBolt->state != START_INITIATOR)) {
        DBG_PRINTF("fail: not initiator\n");
        return false;
    }

    bool ret = actone_sender(self, pBuf, pNodeId);
    if (ret) {
        pBolt->state = WAIT_ACT_TWO;
    } else {
        //失敗したら最初からやり直す
        M_FREE(self->p_handshake);
        self->p_handshake = NULL;
    }

    return ret;
}


bool HIDDEN ln_enc_auth_handshake_recv(ln_self_t *self, ucoin_buf_t *pBuf)
{
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;
    bool ret;

    if (pBolt == NULL) {
        DBG_PRINTF("fail: handshake ended\n");
        return false;
    }

    switch (pBolt->state) {
    //initiator
    case WAIT_ACT_TWO:
        //
        ret = acttwo_receiver(self, pBuf);
        memcpy(self->noise_send.ck, pBolt->ck, UCOIN_SZ_SHA256);
        memcpy(self->noise_recv.ck, pBolt->ck, UCOIN_SZ_SHA256);
        M_FREE(self->p_handshake);
        self->p_handshake = NULL;
        self->noise_send.nonce = 0;
        self->noise_recv.nonce = 0;
        break;

    //responder
    case WAIT_ACT_ONE:
        //
        ret = actone_receiver(self, pBuf);
        pBolt->state = WAIT_ACT_THREE;
        break;
    case WAIT_ACT_THREE:
        //
        ret = actthree_receiver(self, pBuf);
        memcpy(self->noise_send.ck, pBolt->ck, UCOIN_SZ_SHA256);
        memcpy(self->noise_recv.ck, pBolt->ck, UCOIN_SZ_SHA256);
        M_FREE(self->p_handshake);
        self->p_handshake = NULL;
        self->noise_send.nonce = 0;
        self->noise_recv.nonce = 0;
        break;
    default:
        ret = false;
        break;
    }
    if (!ret) {
        //失敗したら最初からやり直す
        M_FREE(self->p_handshake);
        self->p_handshake = NULL;
    }

    return ret;
}


bool ln_enc_auth_handshake_state(ln_self_t *self)
{
    return self->p_handshake != NULL;
}


bool HIDDEN ln_enc_auth_enc(ln_self_t *self, ucoin_buf_t *pBufEnc, const ucoin_buf_t *pBufIn)
{
    bool ret = false;
    uint8_t nonce[12];
    uint16_t l = (pBufIn->len >> 8) | (pBufIn->len << 8);
    uint8_t *cl = (uint8_t *)M_MALLOC(sizeof(l) + crypto_aead_chacha20poly1305_IETF_ABYTES);
    uint8_t *cm = (uint8_t *)M_MALLOC(pBufIn->len + crypto_aead_chacha20poly1305_IETF_ABYTES);
    unsigned long long cllen;
    unsigned long long cmlen;
    int rc;

    memset(nonce, 0, 4);
    memcpy(nonce + 4, &self->noise_send.nonce, sizeof(uint64_t));
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    cl, &cllen,
                    (uint8_t *)&l, sizeof(l),   //message length
                    NULL, 0,                    //additional data
                    NULL,                       //combined modeではNULL
                    nonce, self->noise_send.key);     //nonce, key
    if ((rc != 0) || (cllen != sizeof(l) + crypto_aead_chacha20poly1305_IETF_ABYTES)) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
    self->noise_send.nonce++;
    if (self->noise_send.nonce == 1000) {
        DBG_PRINTF("???: This root shall not in.\n");
        goto LABEL_EXIT;
    }
    memcpy(nonce + 4, &self->noise_send.nonce, sizeof(uint64_t));

    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    cm, &cmlen,
                    pBufIn->buf, pBufIn->len,       //message length
                    NULL, 0,                    //additional data
                    NULL,                       //combined modeではNULL
                    nonce, self->noise_send.key);     //nonce, key
    if ((rc != 0) || (cmlen != pBufIn->len + crypto_aead_chacha20poly1305_IETF_ABYTES)) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
    self->noise_send.nonce++;
    if (self->noise_send.nonce == 1000) {
        //key rotation
        //ck', k' = HKDF(ck, k)
        noise_hkdf(self->noise_send.ck, self->noise_send.key, self->noise_send.ck, self->noise_send.key);
        self->noise_send.nonce = 0;
    }

    ucoin_buf_alloc(pBufEnc, cllen + cmlen);
    memcpy(pBufEnc->buf, cl, cllen);
    memcpy(pBufEnc->buf + cllen, cm, cmlen);
    ret = true;

LABEL_EXIT:
    M_FREE(cl);
    M_FREE(cm);

    return ret;
}


uint16_t HIDDEN ln_enc_auth_dec_len(ln_self_t *self, const uint8_t *pData, uint16_t Len)
{
    uint8_t nonce[12];
    uint8_t pl[sizeof(uint16_t)];
    unsigned long long pllen;
    uint16_t l = 0;
    int rc;

    if (Len != LN_SZ_NOISE_HEADER) {
        return 0;
    }

    memset(nonce, 0, 4);
    memcpy(nonce + 4, &self->noise_recv.nonce, sizeof(uint64_t));
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    pl, &pllen,
                    NULL,                       //combined modeではNULL
                    pData, LN_SZ_NOISE_HEADER,
                    NULL, 0,  //additional data
                    nonce, self->noise_recv.key);      //nonce, key
    if ((rc != 0) || (pllen != sizeof(uint16_t))) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        DBG_PRINTF("sn=%" PRIu64 ", rn=%" PRIu64 "\n", self->noise_send.nonce, self->noise_recv.nonce);
        goto LABEL_EXIT;
    }
    self->noise_recv.nonce++;
    if (self->noise_recv.nonce == 1000) {
        //key rotation
        //ck', k' = HKDF(ck, k)
        DBG_PRINTF("???: This root shall not in.\n");
        goto LABEL_EXIT;
    }

    //受信するデータ長
    l = ((pl[0] << 8) | pl[1]) + crypto_aead_chacha20poly1305_IETF_ABYTES;

LABEL_EXIT:
    return l;
}


bool HIDDEN ln_enc_auth_dec_msg(ln_self_t *self, ucoin_buf_t *pBuf)
{
    bool ret = false;
    uint16_t l = pBuf->len - crypto_aead_chacha20poly1305_IETF_ABYTES;
    uint8_t nonce[12];
    uint8_t *pm = (uint8_t *)M_MALLOC(l);
    unsigned long long pmlen;
    int rc;

    memset(nonce, 0, 4);
    memcpy(nonce + 4, &self->noise_recv.nonce, sizeof(uint64_t));
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    pm, &pmlen,
                    NULL,                       //combined modeではNULL
                    pBuf->buf, pBuf->len,
                    NULL, 0,  //additional data
                    nonce, self->noise_recv.key);      //nonce, key
    if ((rc != 0) || (pmlen != l)) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
    self->noise_recv.nonce++;
    if (self->noise_recv.nonce == 1000) {
        //key rotation
        //ck', k' = HKDF(ck, k)
        noise_hkdf(self->noise_recv.ck, self->noise_recv.key, self->noise_recv.ck, self->noise_recv.key);
        self->noise_recv.nonce = 0;
    }

    ucoin_buf_free(pBuf);
    ucoin_buf_alloc(pBuf, l);
    memcpy(pBuf->buf, pm, l);
    ret = true;

LABEL_EXIT:
    M_FREE(pm);

    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

//ccanの実装を参考にしていたが、noise protocolでは回数が決まっているので、独自実装になった
static bool noise_hkdf(uint8_t *ck, uint8_t *k, const uint8_t *pSalt, const uint8_t *pIkm)
{
    bool ret;
    uint8_t prk[UCOIN_SZ_SHA256];
    mbedtls_md_context_t ctx;

    uint8_t ikm_len = (pIkm) ? UCOIN_SZ_SHA256 : 0;
    ret = ucoin_util_calc_mac(prk, pSalt, UCOIN_SZ_SHA256, pIkm, ikm_len);
    if (!ret) {
        DBG_PRINTF("fail: calc_mac\n");
        return false;
    }

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    uint8_t c = 1;
    mbedtls_md_hmac_starts(&ctx, prk, UCOIN_SZ_SHA256);
    mbedtls_md_hmac_update(&ctx, &c, 1);
    mbedtls_md_hmac_finish(&ctx, ck);
    c++;
    mbedtls_md_hmac_reset(&ctx);
    mbedtls_md_hmac_update(&ctx, ck, UCOIN_SZ_SHA256);
    mbedtls_md_hmac_update(&ctx, &c, 1);
    mbedtls_md_hmac_finish(&ctx, k);
    mbedtls_md_free(&ctx);

    return true;
}


static bool actone_sender(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pRS)
{
    bool ret = false;
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;
    uint8_t ss[UCOIN_SZ_PRIVKEY];
    uint8_t c[crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t nonce[12];
    unsigned long long clen;
    int rc;

    // h = SHA-256(h || e.pub.serializeCompressed())
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, pBolt->e.pub, UCOIN_SZ_PUBKEY);

    // ss = ECDH(rs, e.priv)
    ucoin_util_generate_shared_secret(ss, pRS, pBolt->e.priv);

    // ck, temp_k1 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // c = encryptWithAD(temp_k1, 0, h, zero)
    memset(nonce, 0, sizeof(nonce));
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    c, &clen,
                    NULL, 0,                    //zero length data
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (clen != sizeof(c))) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }

    // h = SHA-256(h || c)
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, c, clen);

    // SEND: m = 0 || e.pub.serializeCompressed() || c to the responder over the network buffer.
    ucoin_buf_free(pBuf);
    ucoin_buf_alloc(pBuf, 1 + UCOIN_SZ_PUBKEY + clen);
    pBuf->buf[0] = 0x00;       //m=0
    memcpy(pBuf->buf + 1, pBolt->e.pub, UCOIN_SZ_PUBKEY);
    memcpy(pBuf->buf + 1 + UCOIN_SZ_PUBKEY, c, clen);
    ret = true;

LABEL_EXIT:
    return ret;
}


static bool actone_receiver(ln_self_t *self, ucoin_buf_t *pBuf)
{
    bool ret = false;
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;
    uint8_t re[UCOIN_SZ_PUBKEY];
    uint8_t c[crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t ss[UCOIN_SZ_PRIVKEY];
    uint8_t p[UCOIN_SZ_SHA256 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t nonce[12];
    unsigned long long plen;
    int rc;

    if ((pBuf->len != 50) || (pBuf->buf[0] != 0x00)) {
        DBG_PRINTF("fail: invalid length=%d\n", pBuf->len);
        DUMPBIN(pBuf->buf, pBuf->len);
        goto LABEL_EXIT;
    }
    memcpy(re, pBuf->buf + 1, sizeof(re));
    memcpy(c, pBuf->buf + 1 + sizeof(re), sizeof(c));

    // h = SHA-256(h || re.serializeCompressed())
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, re, UCOIN_SZ_PUBKEY);

    // ss = ECDH(re, s.priv)
    ucoin_util_generate_shared_secret(ss, re, pBolt->keys->priv);

    // ck, temp_k1 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // p = decryptWithAD(temp_k1, 0, h, c)
    memset(nonce, 0, sizeof(nonce));
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    p, &plen,
                    NULL,                       //combined modeではNULL
                    c, sizeof(c),               //ciphertext
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (plen != 0)) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }

    // h = SHA-256(h || c)
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, c, sizeof(c));

    ret = acttwo_sender(self, pBuf, re);

LABEL_EXIT:
    return ret;
}


static bool acttwo_sender(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pRE)
{
    bool ret = false;
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;
    uint8_t ss[UCOIN_SZ_PRIVKEY];
    uint8_t c[crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t nonce[12];
    unsigned long long clen;
    int rc;

    // h = SHA-256(h || e.pub.serializeCompressed())
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, pBolt->e.pub, UCOIN_SZ_PUBKEY);

    // ss = ECDH(re, e.priv)
    ucoin_util_generate_shared_secret(ss, pRE, pBolt->e.priv);

    // ck, temp_k2 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // c = encryptWithAD(temp_k2, 0, h, zero)
    memset(nonce, 0, sizeof(nonce));
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    c, &clen,
                    NULL, 0,                    //zero length data
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (clen != sizeof(c))) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }

    // h = SHA-256(h || c)
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, c, clen);

    // SEND: m = 0 || e.pub.serializeCompressed() || c to the responder over the network buffer.
    ucoin_buf_free(pBuf);
    ucoin_buf_alloc(pBuf, 1 + UCOIN_SZ_PUBKEY + clen);
    pBuf->buf[0] = 0x00;       //m=0
    memcpy(pBuf->buf + 1, pBolt->e.pub, UCOIN_SZ_PUBKEY);
    memcpy(pBuf->buf + 1 + UCOIN_SZ_PUBKEY, c, clen);
    ret = true;

LABEL_EXIT:
    return ret;
}


static bool acttwo_receiver(ln_self_t *self, ucoin_buf_t *pBuf)
{
    bool ret = false;
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;
    uint8_t re[UCOIN_SZ_PUBKEY];
    uint8_t c[crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t ss[UCOIN_SZ_PRIVKEY];
    uint8_t p[UCOIN_SZ_SHA256 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t nonce[12];
    unsigned long long plen;
    int rc;

    if ((pBuf->len != 50) || (pBuf->buf[0] != 0x00)) {
        DBG_PRINTF("fail: invalid length : len=%d, ver=%02x\n", pBuf->len, pBuf->buf[0]);
        goto LABEL_EXIT;
    }
    memcpy(re, pBuf->buf + 1, sizeof(re));
    memcpy(c, pBuf->buf + 1 + sizeof(re), sizeof(c));

    // h = SHA-256(h || re.serializeCompressed())
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, re, UCOIN_SZ_PUBKEY);

    // ss = ECDH(re, e.priv)
    ucoin_util_generate_shared_secret(ss, re, pBolt->e.priv);

    // ck, temp_k2 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // p = decryptWithAD(temp_k2, 0, h, c)
    memset(nonce, 0, sizeof(nonce));
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    p, &plen,
                    NULL,                       //combined modeではNULL
                    c, sizeof(c),               //ciphertext
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (plen != 0)) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }

    // h = SHA-256(h || c)
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, c, sizeof(c));

    ret = actthree_sender(self, pBuf, re);

LABEL_EXIT:
    return ret;
}


static bool actthree_sender(ln_self_t *self, ucoin_buf_t *pBuf, const uint8_t *pRE)
{
    bool ret = false;
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;
    uint8_t c[UCOIN_SZ_PUBKEY + crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t nonce[12];
    uint8_t ss[UCOIN_SZ_PRIVKEY];
    uint8_t t[crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long clen;
    unsigned long long tlen;
    int rc;

    // c = encryptWithAD(temp_k2, 1, h, s.pub.serializeCompressed())
    memset(nonce, 0, sizeof(nonce));
    nonce[4] = 0x01;
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    c, &clen,
                    pBolt->keys->pub, UCOIN_SZ_PUBKEY,   //s.pub.serializeCompressed()
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (clen != sizeof(c))) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }

    // h = SHA-256(h || c)
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, c, sizeof(c));

    // ss = ECDH(re, s.priv)
    ucoin_util_generate_shared_secret(ss, pRE, pBolt->keys->priv);

    // ck, temp_k3 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // t = encryptWithAD(temp_k3, 0, h, zero)
    memset(nonce, 0, sizeof(nonce));
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    t, &tlen,
                    NULL, 0,                    //zero length data
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (tlen != sizeof(t))) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }

    // sk, rk = HKDF(ck, zero)
    noise_hkdf(self->noise_send.key, self->noise_recv.key, pBolt->ck, NULL);

    // SEND: m = 0 || c || t   over the network buffer.
    ucoin_buf_free(pBuf);
    ucoin_buf_alloc(pBuf, 1 + clen + tlen);
    pBuf->buf[0] = 0x00;       //m=0
    memcpy(pBuf->buf + 1, c, clen);
    memcpy(pBuf->buf + 1 + clen, t, tlen);
    ret = true;

LABEL_EXIT:
    return ret;
}


static bool actthree_receiver(ln_self_t *self, ucoin_buf_t *pBuf)
{
    bool ret = false;
    struct bolt8 *pBolt = (struct bolt8 *)self->p_handshake;
    uint8_t c[UCOIN_SZ_PUBKEY + crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t t[crypto_aead_chacha20poly1305_IETF_ABYTES];
    uint8_t rs[UCOIN_SZ_PUBKEY];
    uint8_t nonce[12];
    uint8_t ss[UCOIN_SZ_PRIVKEY];
    uint8_t p[UCOIN_SZ_SHA256 + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long rslen;
    unsigned long long plen;
    int rc;

    if ((pBuf->len != 66) || (pBuf->buf[0] != 0x00)) {
        DBG_PRINTF("fail: invalid length\n");
        goto LABEL_EXIT;
    }
    memcpy(c, pBuf->buf + 1, sizeof(c));
    memcpy(t, pBuf->buf + 1 + sizeof(c), sizeof(t));

    // rs = decryptWithAD(temp_k2, 1, h, c)
    memset(nonce, 0, sizeof(nonce));
    nonce[4] = 0x01;
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    rs, &rslen,
                    NULL,                       //combined modeではNULL
                    c, sizeof(c),               //ciphertext
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (rslen != sizeof(rs))) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
    DBG_PRINTF("rs=");
    DUMPBIN(rs, sizeof(rs));

    // h = SHA-256(h || c)
    ucoin_util_sha256cat(pBolt->h, pBolt->h, UCOIN_SZ_SHA256, c, sizeof(c));

    // ss = ECDH(rs, e.priv)
    ucoin_util_generate_shared_secret(ss, rs, pBolt->e.priv);

    // ck, temp_k3 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // p = decryptWithAD(temp_k3, 0, h, t)
    nonce[4] = 0x00;
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    p, &plen,
                    NULL,                       //combined modeではNULL
                    t, sizeof(t),               //ciphertext
                    pBolt->h, UCOIN_SZ_SHA256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (plen != 0)) {
        DBG_PRINTF("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }

    // rk, sk = HKDF(ck, zero)
    noise_hkdf(self->noise_recv.key, self->noise_send.key, pBolt->ck, NULL);

    //Act Treeでは相手のnode_idを返す
    ucoin_buf_free(pBuf);
    ucoin_buf_alloccopy(pBuf, rs, sizeof(rs));

    ret = true;

LABEL_EXIT:
    return ret;
}
