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
/** @file   ln_noise.c
 *  @brief  [LN]BOLT#8関連
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
//#define M_USE_SODIUM
#ifdef M_USE_SODIUM
#include "sodium/crypto_aead_chacha20poly1305.h"
#else
#include "mbedtls/chachapoly.h"
#endif

#include "utl_dbg.h"

#include "btc_crypto.h"

#include "ln_noise.h"
#include "ln_misc.h"
#include "ln_node.h"
#include "ln_signer.h"
#include "ln_local.h"


/********************************************************************
 * macros
 ********************************************************************/

#define M_PROTOCOL_NAME "Noise_XK_secp256k1_ChaChaPoly_SHA256"
#define M_PROTOCOL_LEN  (36)
#define M_PROLOGUE      "lightning"
#define M_PROLOGUE_LEN  (9)

#define M_CHACHAPOLY_MAC     (16)


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


/** @struct bolt8_t
 *  @brief  noise handshake data
 */
struct bolt8_t {
    btc_keys_t  e;                  //ephemeral key
    uint8_t     h[BTC_SZ_HASH256];         //h
    uint8_t     ck[BTC_SZ_HASH256];        //ck
    uint8_t     temp_k[BTC_SZ_HASH256];    //temp_k1,2,3

    enum state_t    state;
};


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool noise_hkdf(uint8_t *ck, uint8_t *k, const uint8_t *pSalt, const uint8_t *pIkm);
static bool actone_sender(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pRS);
static bool actone_receiver(ln_noise_t *pCtx, utl_buf_t *pBuf);
static bool acttwo_sender(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pRE);
static bool acttwo_receiver(ln_noise_t *pCtx, utl_buf_t *pBuf);
static bool actthree_sender(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pRE);
static bool actthree_receiver(ln_noise_t *pCtx, utl_buf_t *pBuf);
static void dump_key(const uint8_t key[BTC_SZ_PRIVKEY], const uint8_t lengthMac[M_CHACHAPOLY_MAC]);


/********************************************************************
 * public functions
 ********************************************************************/

bool HIDDEN ln_noise_handshake_init(ln_noise_t *pCtx, const uint8_t *pNodeId)
{
    bool ret;

    //handshake完了後にFREEする
    pCtx->p_handshake = UTL_DBG_MALLOC(sizeof(struct bolt8_t));
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;

    //ephemeral key
    ret = btc_keys_create(&pBolt->e);
    if (!ret) {
        LOGE("fail: ephemeral key\n");
        UTL_DBG_FREE(pCtx->p_handshake);
        return false;
    }

    // ck = sha256(protocolName)
    btc_md_sha256(pBolt->ck, (const uint8_t *)M_PROTOCOL_NAME, M_PROTOCOL_LEN);

    // h = sha256(ck || prologue)
    btc_md_sha256cat(pBolt->h, pBolt->ck, BTC_SZ_HASH256, (const uint8_t *)M_PROLOGUE, M_PROLOGUE_LEN);


    if (pNodeId != NULL) {
        //noise handshake initiator
        LOGD("initiator\n");
        pBolt->state = START_INITIATOR;
    } else {
        //nose handshake responder
        LOGD("responder\n");
        pNodeId = ln_node_getid();
        pBolt->state = WAIT_ACT_ONE;
    }
    //initiatorは相手node_id, responderは自node_id
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, pNodeId, BTC_SZ_PUBKEY);

    return true;
}


bool HIDDEN ln_noise_handshake_start(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pNodeId)
{
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;

    if ((pBolt == NULL) || (pBolt->state != START_INITIATOR)) {
        LOGE("fail: not initiator\n");
        return false;
    }

    bool ret = actone_sender(pCtx, pBuf, pNodeId);
    if (ret) {
        pBolt->state = WAIT_ACT_TWO;
    } else {
        //失敗したら最初からやり直す
        UTL_DBG_FREE(pCtx->p_handshake);
    }

    return ret;
}


bool HIDDEN ln_noise_handshake_recv(ln_noise_t *pCtx, utl_buf_t *pBuf)
{
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;
    bool ret;

    if (pBolt == NULL) {
        LOGE("fail: handshake ended\n");
        return false;
    }

    switch (pBolt->state) {
    //initiator
    case WAIT_ACT_TWO:
        //
        ret = acttwo_receiver(pCtx, pBuf);
        memcpy(pCtx->send_ctx.ck, pBolt->ck, BTC_SZ_HASH256);
        memcpy(pCtx->recv_ctx.ck, pBolt->ck, BTC_SZ_HASH256);
        UTL_DBG_FREE(pCtx->p_handshake);
        pCtx->send_ctx.nonce = 0;
        pCtx->recv_ctx.nonce = 0;
        break;

    //responder
    case WAIT_ACT_ONE:
        //
        ret = actone_receiver(pCtx, pBuf);
        pBolt->state = WAIT_ACT_THREE;
        break;
    case WAIT_ACT_THREE:
        //
        ret = actthree_receiver(pCtx, pBuf);
        memcpy(pCtx->send_ctx.ck, pBolt->ck, BTC_SZ_HASH256);
        memcpy(pCtx->recv_ctx.ck, pBolt->ck, BTC_SZ_HASH256);
        UTL_DBG_FREE(pCtx->p_handshake);
        pCtx->send_ctx.nonce = 0;
        pCtx->recv_ctx.nonce = 0;
        break;
    default:
        ret = false;
        break;
    }
    if (!ret) {
        //失敗したら最初からやり直す
        UTL_DBG_FREE(pCtx->p_handshake);
    }

    return ret;
}


bool HIDDEN ln_noise_handshake_state(ln_noise_t *pCtx)
{
    return pCtx->p_handshake != NULL;
}


void HIDDEN ln_noise_handshake_free(ln_noise_t *pCtx)
{
    UTL_DBG_FREE(pCtx->p_handshake);
}


bool /*HIDDEN*/ ln_noise_enc(ln_noise_t *pCtx, utl_buf_t *pBufEnc, const utl_buf_t *pBufIn)
{
    bool ret = false;
    uint8_t nonce[12];
    uint16_t l = (pBufIn->len >> 8) | (pBufIn->len << 8);
    uint8_t *cl = (uint8_t *)UTL_DBG_MALLOC(sizeof(l) + M_CHACHAPOLY_MAC);
    uint8_t *cm = (uint8_t *)UTL_DBG_MALLOC(pBufIn->len + M_CHACHAPOLY_MAC);
    int rc;

    memset(nonce, 0, 4);
    memcpy(nonce + 4, &pCtx->send_ctx.nonce, sizeof(uint64_t));
#ifdef M_USE_SODIUM
    unsigned long long cllen;
    unsigned long long cmlen;

    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    cl, &cllen,
                    (uint8_t *)&l, sizeof(l),   //message length
                    NULL, 0,                    //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pCtx->send_ctx.key);     //nonce, key
    if ((rc != 0) || (cllen != sizeof(l) + crypto_aead_chacha20poly1305_IETF_ABYTES)) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pCtx->send_ctx.key);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                    sizeof(l),          //in length
                    nonce,              //12byte
                    NULL, 0,            //AAD
                    (const uint8_t *)&l,    //input
                    cl,                 //output
                    cl + sizeof(l));    //MAC
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_encrypt_and_tag rc=-%04x\n", -rc);
        assert(0);
        goto LABEL_EXIT;
    }
#endif

    if (pCtx->send_ctx.nonce == 0) {
        dump_key(pCtx->send_ctx.key, cl + sizeof(l));
    }

    pCtx->send_ctx.nonce++;
    if (pCtx->send_ctx.nonce == 1000) {
        LOGE("???: This root shall not in.\n");
        goto LABEL_EXIT;
    }
    memcpy(nonce + 4, &pCtx->send_ctx.nonce, sizeof(uint64_t));

#ifdef M_USE_SODIUM
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    cm, &cmlen,
                    pBufIn->buf, pBufIn->len,       //message length
                    NULL, 0,                    //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pCtx->send_ctx.key);     //nonce, key
    if ((rc != 0) || (cmlen != pBufIn->len + crypto_aead_chacha20poly1305_IETF_ABYTES)) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pCtx->send_ctx.key);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                    pBufIn->len,        //in length
                    nonce,              //12byte
                    NULL, 0,            //AAD
                    pBufIn->buf,        //input
                    cm,                 //output
                    cm + pBufIn->len);  //MAC
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_encrypt_and_tag rc=-%04x\n", -rc);
        assert(0);
        goto LABEL_EXIT;
    }
#endif

    pCtx->send_ctx.nonce++;
    if (pCtx->send_ctx.nonce == 1000) {
        //key rotation
        //ck', k' = HKDF(ck, k)
        noise_hkdf(pCtx->send_ctx.ck, pCtx->send_ctx.key, pCtx->send_ctx.ck, pCtx->send_ctx.key);
        pCtx->send_ctx.nonce = 0;
    }

    utl_buf_alloc(pBufEnc, sizeof(l) + pBufIn->len + 2 * M_CHACHAPOLY_MAC);
    memcpy(pBufEnc->buf, cl, sizeof(l) + M_CHACHAPOLY_MAC);
    memcpy(pBufEnc->buf + sizeof(l) + M_CHACHAPOLY_MAC, cm, pBufIn->len + M_CHACHAPOLY_MAC);
    ret = true;

LABEL_EXIT:
    UTL_DBG_FREE(cl);
    UTL_DBG_FREE(cm);

    return ret;
}


uint16_t /*HIDDEN*/ ln_noise_dec_len(ln_noise_t *pCtx, const uint8_t *pData, uint16_t Len)
{
    uint8_t nonce[12];
    uint8_t pl[sizeof(uint16_t)];
    uint16_t l = 0;
    int rc;

    if (Len != LN_SZ_NOISE_HEADER) {
        return 0;
    }

    memset(nonce, 0, 4);
    memcpy(nonce + 4, &pCtx->recv_ctx.nonce, sizeof(uint64_t));
#ifdef M_USE_SODIUM
    unsigned long long pllen;
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    pl, &pllen,
                    NULL,                       //combined modeではNULL
                    pData, LN_SZ_NOISE_HEADER,
                    NULL, 0,  //additional data
                    nonce, pCtx->recv_ctx.key);      //nonce, key
    if ((rc != 0) || (pllen != sizeof(uint16_t))) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        LOGD("sn=%" PRIu64 ", rn=%" PRIu64 "\n", pCtx->send_ctx.nonce, pCtx->recv_ctx.nonce);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pCtx->recv_ctx.key);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_auth_decrypt(&ctx,
                    sizeof(pl),             //in length
                    nonce,                  //12byte
                    NULL, 0,                //AAD
                    pData + sizeof(pl),     //MAC
                    pData,                  //input
                    pl);                    //output
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_auth_decrypt rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    if (pCtx->recv_ctx.nonce == 0) {
        dump_key(pCtx->recv_ctx.key, pData + sizeof(pl));
    }

    pCtx->recv_ctx.nonce++;
    if (pCtx->recv_ctx.nonce == 1000) {
        //key rotation
        //ck', k' = HKDF(ck, k)
        LOGE("???: This root shall not in.\n");
        goto LABEL_EXIT;
    }

    //受信するデータ長
    l = ((pl[0] << 8) | pl[1]) + M_CHACHAPOLY_MAC;

LABEL_EXIT:
    return l;
}


bool /*HIDDEN*/ ln_noise_dec_msg(ln_noise_t *pCtx, utl_buf_t *pBuf)
{
    bool ret = false;
    uint16_t l = pBuf->len - M_CHACHAPOLY_MAC;
    uint8_t nonce[12];
    uint8_t *pm = (uint8_t *)UTL_DBG_MALLOC(l);
    int rc;

    memset(nonce, 0, 4);
    memcpy(nonce + 4, &pCtx->recv_ctx.nonce, sizeof(uint64_t));
#ifdef M_USE_SODIUM
    unsigned long long pmlen;
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    pm, &pmlen,
                    NULL,                       //combined modeではNULL
                    pBuf->buf, pBuf->len,
                    NULL, 0,  //additional data
                    nonce, pCtx->recv_ctx.key);      //nonce, key
    if ((rc != 0) || (pmlen != l)) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pCtx->recv_ctx.key);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_auth_decrypt(&ctx,
                    l,                  //in length
                    nonce,              //12byte
                    NULL, 0,            //AAD
                    pBuf->buf + l,      //MAC
                    pBuf->buf,          //input
                    pm);                //output
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_auth_decrypt rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    pCtx->recv_ctx.nonce++;
    if (pCtx->recv_ctx.nonce == 1000) {
        //key rotation
        //ck', k' = HKDF(ck, k)
        noise_hkdf(pCtx->recv_ctx.ck, pCtx->recv_ctx.key, pCtx->recv_ctx.ck, pCtx->recv_ctx.key);
        pCtx->recv_ctx.nonce = 0;
    }

    utl_buf_free(pBuf);
    utl_buf_alloc(pBuf, l);
    memcpy(pBuf->buf, pm, l);
    ret = true;

LABEL_EXIT:
    UTL_DBG_FREE(pm);

    return ret;
}


/********************************************************************
 * private functions
 ********************************************************************/

//BOLT#8
//  HKDF(salt,ikm): a function defined in RFC 58693, evaluated with a zero-length info field
//      All invocations of HKDF implicitly return 64 bytes of cryptographic randomness
//          using the extract-and-expand component of the HKDF
static bool noise_hkdf(uint8_t *ck, uint8_t *k, const uint8_t *pSalt, const uint8_t *pIkm)
{
#if 1
    size_t ikm_len = (pIkm) ? BTC_SZ_HASH256 : 0;
    uint8_t okm[64];
    int retval = mbedtls_hkdf(
                    mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    pSalt, BTC_SZ_HASH256,
                    pIkm, ikm_len,
                    NULL, 0,
                    okm, sizeof(okm));
    if (retval == 0) {
        memcpy(ck, okm, BTC_SZ_HASH256);
        memcpy(k, okm + BTC_SZ_HASH256, BTC_SZ_HASH256);
    }
    return retval == 0;
#else
    bool ret;
    uint8_t prk[BTC_SZ_HASH256];
    mbedtls_md_context_t ctx;

    uint8_t ikm_len = (pIkm) ? BTC_SZ_HASH256 : 0;
    ret = ln_misc_calc_mac(prk, pSalt, BTC_SZ_HASH256, pIkm, ikm_len);
    if (!ret) {
        LOGE("fail: calc_mac\n");
        return false;
    }

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    uint8_t c = 1;
    mbedtls_md_hmac_starts(&ctx, prk, BTC_SZ_HASH256);
    mbedtls_md_hmac_update(&ctx, &c, 1);
    mbedtls_md_hmac_finish(&ctx, ck);
    c++;
    mbedtls_md_hmac_reset(&ctx);
    mbedtls_md_hmac_update(&ctx, ck, BTC_SZ_HASH256);
    mbedtls_md_hmac_update(&ctx, &c, 1);
    mbedtls_md_hmac_finish(&ctx, k);
    mbedtls_md_free(&ctx);

    return true;
#endif
}


static bool actone_sender(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pRS)
{
    bool ret = false;
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;
    uint8_t ss[BTC_SZ_PRIVKEY];
    uint8_t c[M_CHACHAPOLY_MAC];
    uint8_t nonce[12];
    int rc;

    // h = SHA-256(h || e.pub.serializeCompressed())
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, pBolt->e.pub, BTC_SZ_PUBKEY);

    // ss = ECDH(rs, e.priv)
    ln_misc_generate_shared_secret(ss, pRS, pBolt->e.priv);

    // ck, temp_k1 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // c = encryptWithAD(temp_k1, 0, h, zero)
    memset(nonce, 0, sizeof(nonce));
#ifdef M_USE_SODIUM
    unsigned long long clen;
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    c, &clen,
                    NULL, 0,                    //zero length data
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (clen != sizeof(c))) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                    0,                              //in length
                    nonce,                          //12byte
                    pBolt->h, BTC_SZ_HASH256,      //AAD
                    NULL,                           //input
                    NULL,                           //output
                    c);                             //MAC
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_encrypt_and_tag rc=-%04x\n", -rc);
        assert(0);
        goto LABEL_EXIT;
    }
#endif

    // h = SHA-256(h || c)
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, c, sizeof(c));

    // SEND: m = 0 || e.pub.serializeCompressed() || c to the responder over the network buffer.
    utl_buf_free(pBuf);
    utl_buf_alloc(pBuf, 1 + BTC_SZ_PUBKEY + sizeof(c));
    pBuf->buf[0] = 0x00;       //m=0
    memcpy(pBuf->buf + 1, pBolt->e.pub, BTC_SZ_PUBKEY);
    memcpy(pBuf->buf + 1 + BTC_SZ_PUBKEY, c, sizeof(c));
    ret = true;

LABEL_EXIT:
    return ret;
}


static bool actone_receiver(ln_noise_t *pCtx, utl_buf_t *pBuf)
{
    bool ret = false;
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;
    uint8_t re[BTC_SZ_PUBKEY];
    uint8_t c[M_CHACHAPOLY_MAC];
    uint8_t ss[BTC_SZ_PRIVKEY];
    uint8_t p[BTC_SZ_HASH256 + M_CHACHAPOLY_MAC];
    uint8_t nonce[12];
    int rc;

    if ((pBuf->len != 50) || (pBuf->buf[0] != 0x00)) {
        LOGE("fail: invalid length=%d\n", pBuf->len);
        DUMPD(pBuf->buf, pBuf->len);
        goto LABEL_EXIT;
    }
    memcpy(re, pBuf->buf + 1, sizeof(re));
    memcpy(c, pBuf->buf + 1 + sizeof(re), sizeof(c));

    // h = SHA-256(h || re.serializeCompressed())
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, re, BTC_SZ_PUBKEY);

    // ss = ECDH(re, s.priv)
    ln_node_generate_shared_secret(ss, re);

    // ck, temp_k1 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // p = decryptWithAD(temp_k1, 0, h, c)
    memset(nonce, 0, sizeof(nonce));
#ifdef M_USE_SODIUM
    unsigned long long plen;
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    p, &plen,
                    NULL,                       //combined modeではNULL
                    c, sizeof(c),               //ciphertext
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (plen != 0)) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_auth_decrypt(&ctx,
                    0,                  //in length
                    nonce,              //12byte
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    c,                  //MAC
                    NULL,               //input
                    p);                 //output
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_auth_decrypt rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    // h = SHA-256(h || c)
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, c, sizeof(c));

    ret = acttwo_sender(pCtx, pBuf, re);

LABEL_EXIT:
    return ret;
}


static bool acttwo_sender(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pRE)
{
    bool ret = false;
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;
    uint8_t ss[BTC_SZ_PRIVKEY];
    uint8_t c[M_CHACHAPOLY_MAC];
    uint8_t nonce[12];
    int rc;

    // h = SHA-256(h || e.pub.serializeCompressed())
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, pBolt->e.pub, BTC_SZ_PUBKEY);

    // ss = ECDH(re, e.priv)
    ln_misc_generate_shared_secret(ss, pRE, pBolt->e.priv);

    // ck, temp_k2 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // c = encryptWithAD(temp_k2, 0, h, zero)
    memset(nonce, 0, sizeof(nonce));
#ifdef M_USE_SODIUM
    unsigned long long clen;
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    c, &clen,
                    NULL, 0,                    //zero length data
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (clen != sizeof(c))) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                    0,                              //in length
                    nonce,                          //12byte
                    pBolt->h, BTC_SZ_HASH256,      //AAD
                    NULL,                           //input
                    NULL,                           //output
                    c);                             //MAC
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_encrypt_and_tag rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    // h = SHA-256(h || c)
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, c, sizeof(c));

    // SEND: m = 0 || e.pub.serializeCompressed() || c to the responder over the network buffer.
    utl_buf_free(pBuf);
    utl_buf_alloc(pBuf, 1 + BTC_SZ_PUBKEY + sizeof(c));
    pBuf->buf[0] = 0x00;       //m=0
    memcpy(pBuf->buf + 1, pBolt->e.pub, BTC_SZ_PUBKEY);
    memcpy(pBuf->buf + 1 + BTC_SZ_PUBKEY, c, sizeof(c));
    ret = true;

LABEL_EXIT:
    return ret;
}


static bool acttwo_receiver(ln_noise_t *pCtx, utl_buf_t *pBuf)
{
    bool ret = false;
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;
    uint8_t re[BTC_SZ_PUBKEY];
    uint8_t c[M_CHACHAPOLY_MAC];
    uint8_t ss[BTC_SZ_PRIVKEY];
    uint8_t p[BTC_SZ_HASH256 + M_CHACHAPOLY_MAC];
    uint8_t nonce[12];
    int rc;

    if ((pBuf->len != 50) || (pBuf->buf[0] != 0x00)) {
        LOGE("fail: invalid length : len=%d, ver=%02x\n", pBuf->len, pBuf->buf[0]);
        goto LABEL_EXIT;
    }
    memcpy(re, pBuf->buf + 1, sizeof(re));
    memcpy(c, pBuf->buf + 1 + sizeof(re), sizeof(c));

    // h = SHA-256(h || re.serializeCompressed())
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, re, BTC_SZ_PUBKEY);

    // ss = ECDH(re, e.priv)
    ln_misc_generate_shared_secret(ss, re, pBolt->e.priv);

    // ck, temp_k2 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // p = decryptWithAD(temp_k2, 0, h, c)
    memset(nonce, 0, sizeof(nonce));
#ifdef M_USE_SODIUM
    unsigned long long plen;
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    p, &plen,
                    NULL,                       //combined modeではNULL
                    c, sizeof(c),               //ciphertext
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (plen != 0)) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    memset(p, 0, sizeof(p));
    rc = mbedtls_chachapoly_auth_decrypt(&ctx,
                    0,                          //in length
                    nonce,                      //12byte
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    c,                          //MAC
                    NULL,                       //input
                    p);                         //output
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_auth_decrypt rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    // h = SHA-256(h || c)
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, c, sizeof(c));

    ret = actthree_sender(pCtx, pBuf, re);

LABEL_EXIT:
    return ret;
}


static bool actthree_sender(ln_noise_t *pCtx, utl_buf_t *pBuf, const uint8_t *pRE)
{
    bool ret = false;
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;
    uint8_t c[BTC_SZ_PUBKEY + M_CHACHAPOLY_MAC];
    uint8_t nonce[12];
    uint8_t ss[BTC_SZ_PRIVKEY];
    uint8_t t[M_CHACHAPOLY_MAC];
    int rc;

    // c = encryptWithAD(temp_k2, 1, h, s.pub.serializeCompressed())
    memset(nonce, 0, sizeof(nonce));
    nonce[4] = 0x01;
#ifdef M_USE_SODIUM
    unsigned long long clen;
    unsigned long long tlen;
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    c, &clen,
                    ln_node_getid(), BTC_SZ_PUBKEY,   //s.pub.serializeCompressed()
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (clen != sizeof(c))) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                    BTC_SZ_PUBKEY,                //in length
                    nonce,                          //12byte
                    pBolt->h, BTC_SZ_HASH256,      //AAD
                    ln_node_getid(),                //input
                    c,                              //output
                    c + BTC_SZ_PUBKEY);           //MAC
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_encrypt_and_tag rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    // h = SHA-256(h || c)
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, c, sizeof(c));

    // ss = ECDH(re, s.priv)
    ln_node_generate_shared_secret(ss, pRE);

    // ck, temp_k3 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // t = encryptWithAD(temp_k3, 0, h, zero)
    memset(nonce, 0, sizeof(nonce));
#ifdef M_USE_SODIUM
    rc = crypto_aead_chacha20poly1305_ietf_encrypt(
                    t, &tlen,
                    NULL, 0,                    //zero length data
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    NULL,                       //combined modeではNULL
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (tlen != sizeof(t))) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_encrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_encrypt_and_tag(&ctx,
                    0,                              //in length
                    nonce,                          //12byte
                    pBolt->h, BTC_SZ_HASH256,      //AAD
                    NULL,                           //input
                    NULL,                           //output
                    t);                             //MAC
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_encrypt_and_tag rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    // sk, rk = HKDF(ck, zero)
    noise_hkdf(pCtx->send_ctx.key, pCtx->recv_ctx.key, pBolt->ck, NULL);

    // SEND: m = 0 || c || t   over the network buffer.
    utl_buf_free(pBuf);
    utl_buf_alloc(pBuf, 1 + sizeof(c) + sizeof(t));
    pBuf->buf[0] = 0x00;       //m=0
    memcpy(pBuf->buf + 1, c, sizeof(c));
    memcpy(pBuf->buf + 1 + sizeof(c), t, sizeof(t));
    ret = true;

LABEL_EXIT:
    return ret;
}


static bool actthree_receiver(ln_noise_t *pCtx, utl_buf_t *pBuf)
{
    bool ret = false;
    struct bolt8_t *pBolt = (struct bolt8_t *)pCtx->p_handshake;
    uint8_t c[BTC_SZ_PUBKEY + M_CHACHAPOLY_MAC];
    uint8_t t[M_CHACHAPOLY_MAC];
    uint8_t rs[BTC_SZ_PUBKEY];
    uint8_t nonce[12];
    uint8_t ss[BTC_SZ_PRIVKEY];
    uint8_t p[BTC_SZ_HASH256 + M_CHACHAPOLY_MAC];
    int rc;

    if ((pBuf->len != 66) || (pBuf->buf[0] != 0x00)) {
        LOGE("fail: invalid length\n");
        goto LABEL_EXIT;
    }
    memcpy(c, pBuf->buf + 1, sizeof(c));
    memcpy(t, pBuf->buf + 1 + sizeof(c), sizeof(t));

    // rs = decryptWithAD(temp_k2, 1, h, c)
    memset(nonce, 0, sizeof(nonce));
    nonce[4] = 0x01;
#ifdef M_USE_SODIUM
    unsigned long long rslen;
    unsigned long long plen;
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    rs, &rslen,
                    NULL,                       //combined modeではNULL
                    c, sizeof(c),               //ciphertext
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (rslen != sizeof(rs))) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_auth_decrypt(&ctx,
                    BTC_SZ_PUBKEY,            //in length
                    nonce,                      //12byte
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    c + BTC_SZ_PUBKEY,        //MAC
                    c,                          //input
                    rs);                        //output
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_auth_decrypt rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    LOGD("rs=");
    DUMPD(rs, sizeof(rs));

    // h = SHA-256(h || c)
    btc_md_sha256cat(pBolt->h, pBolt->h, BTC_SZ_HASH256, c, sizeof(c));

    // ss = ECDH(rs, e.priv)
    ln_misc_generate_shared_secret(ss, rs, pBolt->e.priv);

    // ck, temp_k3 = HKDF(ck, ss)
    noise_hkdf(pBolt->ck, pBolt->temp_k, pBolt->ck, ss);

    // p = decryptWithAD(temp_k3, 0, h, t)
    nonce[4] = 0x00;
#ifdef M_USE_SODIUM
    rc = crypto_aead_chacha20poly1305_ietf_decrypt(
                    p, &plen,
                    NULL,                       //combined modeではNULL
                    t, sizeof(t),               //ciphertext
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    nonce, pBolt->temp_k);      //nonce, key
    if ((rc != 0) || (plen != 0)) {
        LOGE("fail: crypto_aead_chacha20poly1305_ietf_decrypt rc=%d\n", rc);
        goto LABEL_EXIT;
    }
#else
    mbedtls_chachapoly_init(&ctx);
    rc = mbedtls_chachapoly_setkey(&ctx, pBolt->temp_k);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_setkey rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
    rc = mbedtls_chachapoly_auth_decrypt(&ctx,
                    0,                          //in length
                    nonce,                      //12byte
                    pBolt->h, BTC_SZ_HASH256,  //additional data
                    t,                          //MAC
                    NULL,                       //input
                    p);                         //output
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        LOGE("fail: mbedtls_chachapoly_auth_decrypt rc=-%04x\n", -rc);
        goto LABEL_EXIT;
    }
#endif

    // rk, sk = HKDF(ck, zero)
    noise_hkdf(pCtx->recv_ctx.key, pCtx->send_ctx.key, pBolt->ck, NULL);

    //Act Treeでは相手のnode_idを返す
    utl_buf_free(pBuf);
    utl_buf_alloccopy(pBuf, rs, sizeof(rs));

    ret = true;

LABEL_EXIT:
    return ret;
}


static void dump_key(const uint8_t key[BTC_SZ_PRIVKEY], const uint8_t lengthMac[M_CHACHAPOLY_MAC])
{
#ifdef DEVELOPER_MODE
    char *dstPath = getenv("LIGHTNINGKEYLOGFILE");
    if (!dstPath) {
        return;
    }

    FILE *dstFile = fopen(dstPath, "a");
    if (!dstFile) {
        LOGE("fail: $LIGHTNINGKEYLOGFILE refers to non-existent dir\n");
        return;
    }

    char hexMac[33] = "";
    for (int i = 0; i < 16; i++) {
        sprintf(hexMac + strlen(hexMac), "%02x", lengthMac[i]);
    }

    char hexKey[65] = "";
    for (int i = 0; i < 32; i++) {
        sprintf(hexKey + strlen(hexKey), "%02x", key[i]);
    }

    fprintf(dstFile, "%s %s\n", hexMac, hexKey);
    fclose(dstFile);
#else
    (void)key[BTC_SZ_PRIVKEY]; (void)lengthMac[M_CHACHAPOLY_MAC];
#endif
}
