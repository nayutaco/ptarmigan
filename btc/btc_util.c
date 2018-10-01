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
 *  @author ueno@nayuta.co
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

#include "btc_local.h"
#include "segwit_addr.h"


/**************************************************************************
 * macros
 **************************************************************************/

/**************************************************************************
 * private variables
 **************************************************************************/

/**************************************************************************
 * prototypes
 **************************************************************************/

static void create_scriptpk_p2pkh(uint8_t *p, const uint8_t *pPubKeyHash);
static void create_scriptpk_p2sh(uint8_t *p, const uint8_t *pPubKeyHash);
static void create_scriptpk_native(uint8_t *p, const uint8_t *pPubKeyHash, uint8_t Len);
static btc_keys_sort_t keys_sort2of2(const uint8_t **pp1, const uint8_t **pp2, const uint8_t *pPubKey1, const uint8_t *pPubKey2);
static int set_le32(uint8_t *pData, uint32_t val);
static int set_le64(uint8_t *pData, uint64_t val);


/**************************************************************************
 *const variables
 **************************************************************************/

// https://github.com/lightningnetwork/lightning-rfc/issues/237
// https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
static const uint8_t M_BTC_GENESIS_MAIN[] = {
    // bitcoin mainnet
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_TEST[] = {
    // bitcoin testnet
    0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
    0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
    0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
    0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_REGTEST[] = {
    // bitcoin regtest
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
    0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
    0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
};


/**************************************************************************
 * public functions
 **************************************************************************/

void btc_util_random(uint8_t *pData, uint16_t Len)
{
#ifdef PTARM_USE_RNG
    mbedtls_ctr_drbg_random(&mRng, pData, Len);
#else   //PTARM_USE_RNG
    for (uint16_t lp = 0; lp < Len; lp++) {
        pData[lp] = (uint8_t)(rand() % 256);
    }
#endif  //PTARM_USE_RNG
}


bool btc_util_wif2keys(btc_util_keys_t *pKeys, btc_chain_t *pChain, const char *pWifPriv)
{
    bool ret;

    ret = btc_keys_wif2priv(pKeys->priv, pChain, pWifPriv);
    if (ret) {
        ret = btc_keys_priv2pub(pKeys->pub, pKeys->priv);
    }

    return ret;
}


void btc_util_createprivkey(uint8_t *pPriv)
{
    do {
        btc_util_random(pPriv, BTC_SZ_PRIVKEY);
    } while (!btc_keys_chkpriv(pPriv));
}


bool btc_util_createkeys(btc_util_keys_t *pKeys)
{
    btc_util_createprivkey(pKeys->priv);
    bool ret = btc_keys_priv2pub(pKeys->pub, pKeys->priv);
    return ret;
}


bool btc_util_create2of2(utl_buf_t *pRedeem, btc_keys_sort_t *pSort, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    bool ret;
    const uint8_t *p1;
    const uint8_t *p2;

    *pSort = keys_sort2of2(&p1, &p2, pPubKey1, pPubKey2);
    ret = btc_keys_create2of2(pRedeem, p1, p2);
    return ret;
}


bool btc_util_sign_p2pkh(btc_tx_t *pTx, int Index, const btc_util_keys_t *pKeys)
{
    utl_buf_t scrpk;
    uint8_t pkh[BTC_SZ_PUBKEYHASH];
    btc_util_hash160(pkh, pKeys->pub, BTC_SZ_PUBKEY);
    btc_util_create_scriptpk(&scrpk, pkh, BTC_PREF_P2PKH);

    const utl_buf_t *scrpks[] = { &scrpk };

    uint8_t txhash[BTC_SZ_SIGHASH];
    bool ret = btc_tx_sighash(txhash, pTx, (const utl_buf_t **)scrpks, 1);
    assert(ret);
    ret = btc_tx_sign_p2pkh(pTx, Index, txhash, pKeys->priv, pKeys->pub);
    assert(ret);
    utl_buf_free(&scrpk);

    return ret;
}


bool btc_util_verify_p2pkh(btc_tx_t *pTx, int Index, const char *pAddrVout)
{
    //公開鍵(署名サイズ[1],署名[sz],公開鍵サイズ[1], 公開鍵、の順になっている)
    const uint8_t *p_pubkey = pTx->vin[Index].script.buf + 1 + pTx->vin[Index].script.buf[0] + 1;
    uint8_t pkh[BTC_SZ_PUBKEYHASH];
    utl_buf_t scrpk;
    btc_util_hash160(pkh, p_pubkey, BTC_SZ_PUBKEY);
    btc_util_create_scriptpk(&scrpk, pkh, BTC_PREF_P2PKH);
    const utl_buf_t *scrpks[] = { &scrpk };

    uint8_t txhash[BTC_SZ_SIGHASH];
    bool ret = btc_tx_sighash(txhash, pTx, (const utl_buf_t **)scrpks, 1);
    assert(ret);
    ret = btc_tx_verify_p2pkh_addr(pTx, Index, txhash, pAddrVout);
    assert(ret);
    utl_buf_free(&scrpk);

    return ret;
}


bool btc_util_sign_p2wpkh(btc_tx_t *pTx, int Index, uint64_t Value, const btc_util_keys_t *pKeys)
{
    bool ret;
    uint8_t txhash[BTC_SZ_HASH256];
    utl_buf_t sigbuf = UTL_BUF_INIT;
    utl_buf_t script_code = UTL_BUF_INIT;

    btc_sw_scriptcode_p2wpkh(&script_code, pKeys->pub);

    ret = btc_sw_sighash(txhash, pTx, Index, Value, &script_code);
    if (ret) {
        ret = btc_tx_sign(&sigbuf, txhash, pKeys->priv);
    }
    if (ret) {
        //mNativeSegwitがfalseの場合はscriptSigへの追加も行う
        btc_sw_set_vin_p2wpkh(pTx, Index, &sigbuf, pKeys->pub);
    }

    utl_buf_free(&sigbuf);
    utl_buf_free(&script_code);

    return ret;
}


bool btc_util_calc_sighash_p2wsh(uint8_t *pTxHash, const btc_tx_t *pTx, int Index, uint64_t Value,
                    const utl_buf_t *pWitScript)
{
    utl_buf_t script_code = UTL_BUF_INIT;

    btc_sw_scriptcode_p2wsh(&script_code, pWitScript);
    bool ret = btc_sw_sighash(pTxHash, pTx, Index, Value, &script_code);
    utl_buf_free(&script_code);
    return ret;
}


bool btc_util_sign_p2wsh(utl_buf_t *pSig, const uint8_t *pTxHash, const btc_util_keys_t *pKeys)
{
    return btc_tx_sign(pSig, pTxHash, pKeys->priv);
}


bool btc_util_sign_p2wsh_rs(uint8_t *pRS, const uint8_t *pTxHash, const btc_util_keys_t *pKeys)
{
    return btc_tx_sign_rs(pRS, pTxHash, pKeys->priv);
}


void btc_util_sort_bip69(btc_tx_t *pTx)
{
    //INPUT
    //  1. output(txid)でソート
    //      --> 同じならindexでソート
    if (pTx->vin_cnt > 1) {
        for (uint32_t lp = 0; lp < pTx->vin_cnt - 1; lp++) {
            for (uint32_t lp2 = lp + 1; lp2 < pTx->vin_cnt; lp2++) {
                uint8_t vin1[BTC_SZ_TXID];
                uint8_t vin2[BTC_SZ_TXID];
                for (int lp3 = 0; lp3 < BTC_SZ_TXID / 2; lp3++) {
                    vin1[lp3] = pTx->vin[lp ].txid[BTC_SZ_TXID - 1 - lp3];
                    vin2[lp3] = pTx->vin[lp2].txid[BTC_SZ_TXID - 1 - lp3];
                }
                int cmp = memcmp(vin1, vin2, BTC_SZ_TXID);
                if (cmp < 0) {
                    //そのまま
                } else if (cmp > 0) {
                    //swap
                } else {
                    //index
                    if (pTx->vin[lp].index < pTx->vin[lp2].index) {
                        //そのまま
                        cmp = -1;
                    } else {
                        //swap
                        cmp = 1;
                    }
                }
                if (cmp > 0) {
                    //lpとlp2をswap
                    btc_vin_t swap;
                    memcpy(&swap, &pTx->vin[lp], sizeof(btc_vin_t));
                    memcpy(&pTx->vin[lp], &pTx->vin[lp2], sizeof(btc_vin_t));
                    memcpy(&pTx->vin[lp2], &swap, sizeof(btc_vin_t));
                }
            }
        }
    }

    //OUTPUT
    //  1. amountでソート(整数として)
    //      --> 同じならscriptPubKeyでソート
    if (pTx->vout_cnt > 1) {
        for (uint32_t lp = 0; lp < pTx->vout_cnt - 1; lp++) {
            for (uint32_t lp2 = lp + 1; lp2 < pTx->vout_cnt; lp2++) {
                int cmp;
                if (pTx->vout[lp].value < pTx->vout[lp2].value) {
                    //そのまま
                    cmp = -1;
                } else if (pTx->vout[lp].value > pTx->vout[lp2].value) {
                    //swap
                    cmp = 1;
                } else {
                    cmp = memcmp(pTx->vout[lp].script.buf, pTx->vout[lp2].script.buf,
                            (pTx->vout[lp].script.len < pTx->vout[lp2].script.len) ? pTx->vout[lp].script.len : pTx->vout[lp2].script.len);
                }
                if (cmp > 0) {
                    //lpとlp2をswap
                    btc_vout_t swap;
                    memcpy(&swap, &pTx->vout[lp], sizeof(btc_vout_t));
                    memcpy(&pTx->vout[lp], &pTx->vout[lp2], sizeof(btc_vout_t));
                    memcpy(&pTx->vout[lp2], &swap, sizeof(btc_vout_t));
                }
            }
        }
    }
}


btc_genesis_t btc_util_get_genesis(const uint8_t *pGenesisHash)
{
    btc_genesis_t ret;

    if (memcmp(pGenesisHash, M_BTC_GENESIS_MAIN, BTC_SZ_HASH256) == 0) {
        LOGD("  bitcoin mainnet\n");
        ret = BTC_GENESIS_BTCMAIN;
    } else if (memcmp(pGenesisHash, M_BTC_GENESIS_TEST, BTC_SZ_HASH256) == 0) {
        LOGD("  bitcoin testnet\n");
        ret = BTC_GENESIS_BTCTEST;
    } else if (memcmp(pGenesisHash, M_BTC_GENESIS_REGTEST, BTC_SZ_HASH256) == 0) {
        LOGD("  bitcoin regtest\n");
        ret = BTC_GENESIS_BTCREGTEST;
    } else {
        LOGD("  unknown genesis hash\n");
        ret = BTC_GENESIS_UNKNOWN;
    }
    return ret;
}


const uint8_t *btc_util_get_genesis_block(btc_genesis_t kind)
{
    switch (kind) {
    case BTC_GENESIS_BTCMAIN:
        return M_BTC_GENESIS_MAIN;
    case BTC_GENESIS_BTCTEST:
        return M_BTC_GENESIS_TEST;
    case BTC_GENESIS_BTCREGTEST:
        return M_BTC_GENESIS_REGTEST;
    default:
        LOGD("unknown kind: %02x\n", kind);
    }

    return NULL;
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
    uint8_t buf_sha256[BTC_SZ_SHA256];

    btc_util_sha256(buf_sha256, pData, Len);
    btc_util_ripemd160(pHash160, buf_sha256, sizeof(buf_sha256));
}


void btc_util_hash256(uint8_t *pHash256, const uint8_t *pData, uint16_t Len)
{
    btc_util_sha256(pHash256, pData, Len);
    btc_util_sha256(pHash256, pHash256, BTC_SZ_SHA256);
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
    if (!mNativeSegwit) {
        uint8_t wit_prog[2 + BTC_SZ_PUBKEYHASH];

        wit_prog[0] = 0x00;
        wit_prog[1] = (uint8_t)BTC_SZ_HASH160;
        memcpy(wit_prog + 2, pPubKeyHash, BTC_SZ_HASH160);
        btc_util_hash160(pWPubKeyHash, wit_prog, LNL_SZ_WITPROG_WPKH);
    } else {
        //nested in P2SH用
        assert(false);
    }
}


void btc_util_create_scriptpk(utl_buf_t *pBuf, const uint8_t *pPubKeyHash, int Prefix)
{
    switch (Prefix) {
    case BTC_PREF_P2PKH:
        //LOGD("BTC_PREF_P2PKH\n");
        utl_buf_alloc(pBuf, 3 + BTC_SZ_HASH160 + 2);
        create_scriptpk_p2pkh(pBuf->buf, pPubKeyHash);
        break;
    case BTC_PREF_P2SH:
        //LOGD("BTC_PREF_P2SH\n");
        utl_buf_alloc(pBuf, 2 + BTC_SZ_HASH160 + 1);
        create_scriptpk_p2sh(pBuf->buf, pPubKeyHash);
        break;
    case BTC_PREF_NATIVE:
        //LOGD("BTC_PREF_NATIVE\n");
        utl_buf_alloc(pBuf, 2 + BTC_SZ_HASH160);
        create_scriptpk_native(pBuf->buf, pPubKeyHash, BTC_SZ_HASH160);
        break;
    case BTC_PREF_NATIVE_SH:
        //LOGD("BTC_PREF_NATIVE_SH\n");
        utl_buf_alloc(pBuf, 2 + BTC_SZ_SHA256);
        create_scriptpk_native(pBuf->buf, pPubKeyHash, BTC_SZ_SHA256);
        break;
    default:
        assert(false);
    }
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


bool HIDDEN btcl_util_keys_pkh2addr(char *pAddr, const uint8_t *pPubKeyHash, uint8_t Prefix)
{
    bool ret;
    uint8_t buf_sha256[BTC_SZ_HASH256];

    if (Prefix == BTC_PREF_NATIVE) {
        uint8_t hrp_type;

        switch (btc_get_chain()) {
        case BTC_MAINNET:
            hrp_type = SEGWIT_ADDR_MAINNET;
            break;
        case BTC_TESTNET:
            hrp_type = SEGWIT_ADDR_TESTNET;
            break;
        default:
            return false;
        }
        ret = segwit_addr_encode(pAddr, hrp_type, 0x00, pPubKeyHash, BTC_SZ_HASH160);
    } else if (Prefix == BTC_PREF_NATIVE_SH) {
        uint8_t hrp_type;

        switch (btc_get_chain()) {
        case BTC_MAINNET:
            hrp_type = SEGWIT_ADDR_MAINNET;
            break;
        case BTC_TESTNET:
            hrp_type = SEGWIT_ADDR_TESTNET;
            break;
        default:
            return false;
        }
        ret = segwit_addr_encode(pAddr, hrp_type, 0x00, pPubKeyHash, BTC_SZ_SHA256);

    } else {
        uint8_t pkh[1 + BTC_SZ_HASH160 + 4];
        size_t sz = BTC_SZ_ADDR_MAX;

        pkh[0] = mPref[Prefix];
        memcpy(pkh + 1, pPubKeyHash, BTC_SZ_HASH160);
        btc_util_hash256(buf_sha256, pkh, 1 + BTC_SZ_HASH160);
        memcpy(pkh + 1 + BTC_SZ_HASH160, buf_sha256, 4);
        ret = b58enc(pAddr, &sz, pkh, sizeof(pkh));
    }

    return ret;
}


bool HIDDEN btcl_util_create_tx(utl_buf_t *pBuf, const btc_tx_t *pTx, bool enableSegWit)
{
    //version[4]
    //mark[1]...wit
    //flag[1]...wit
    //vin_cnt[1]
    //  txid[32]
    //  index[4]
    //  script[len]
    //  sequence[4]
    //vout_cnt[1]
    //  value[8]
    //  script[len]
    //witness...wit
    //locktime[4]

    //version + vin_cnt + vout_cnt
    uint32_t len = sizeof(uint32_t) + btcl_util_get_varint_len(pTx->vin_cnt) + btcl_util_get_varint_len(pTx->vout_cnt);
    bool segwit = false;

    //vin + witness
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &(pTx->vin[lp]);

        len += BTC_SZ_TXID + sizeof(uint32_t) + vin->script.len + sizeof(uint32_t);
        len += btcl_util_get_varint_len(vin->script.len);
        if (enableSegWit && vin->wit_cnt) {
            segwit = true;
            len++;          //wit_cnt
            for (uint32_t lp2 = 0; lp2 < vin->wit_cnt; lp2++) {
                utl_buf_t *buf = &(vin->witness[lp2]);
                len += buf->len;
                len += btcl_util_get_varint_len(buf->len);
            }
        }
    }
    if (segwit) {
        len += 2;       //mark + flag
    }
    //vout
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        btc_vout_t *vout = &(pTx->vout[lp]);

        len += sizeof(uint64_t) + vout->script.len;
        len += btcl_util_get_varint_len(vout->script.len);
    }
    //locktime
    len += sizeof(uint32_t);

    //LOGD("len=%d\n", len);

    pBuf->len = len;
    pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(len);

    uint8_t *p = pBuf->buf;

    p += set_le32(p, pTx->version);
    if (segwit) {
        *p++ = 0x00;
        *p++ = 0x01;
    }

    //vin
    p += btcl_util_set_varint_len(p, NULL, pTx->vin_cnt, false);
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        btc_vin_t *vin = &(pTx->vin[lp]);

        //txid
        memcpy(p, vin->txid, BTC_SZ_TXID);
        p += BTC_SZ_TXID;
        //index
        p += set_le32(p, vin->index);
        //scriptSig
        p += btcl_util_set_varint_len(p, vin->script.buf, vin->script.len, false);
        memcpy(p, vin->script.buf, vin->script.len);
        p += vin->script.len;
        //sequence
        p += set_le32(p, vin->sequence);
    }

    //vout
    p += btcl_util_set_varint_len(p, NULL, pTx->vout_cnt, false);
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        btc_vout_t *vout = &(pTx->vout[lp]);

        //value
        p += set_le64(p, vout->value);
        //scriptPubKey
        p += btcl_util_set_varint_len(p, vout->script.buf, vout->script.len, false);
        memcpy(p, vout->script.buf, vout->script.len);
        p += vout->script.len;
    }

    //segwit
    if (segwit) {
        for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
            btc_vin_t *vin = &(pTx->vin[lp]);

            p += btcl_util_set_varint_len(p, NULL, vin->wit_cnt, false);
            for (uint32_t lp2 = 0; lp2 < vin->wit_cnt; lp2++) {
                utl_buf_t *buf = &(vin->witness[lp2]);

                p += btcl_util_set_varint_len(p, buf->buf, buf->len, false);
                memcpy(p, buf->buf, buf->len);
                p += buf->len;
            }
        }
    }

    //locktime
    p += set_le32(p, pTx->locktime);

    return ((uint32_t)(p - pBuf->buf) == pBuf->len);
}


void HIDDEN btcl_util_add_vout_pub(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey, uint8_t Pref)
{
    uint8_t pkh[BTC_SZ_PUBKEYHASH];

    btc_util_hash160(pkh, pPubKey, BTC_SZ_PUBKEY);
    btcl_util_add_vout_pkh(pTx, Value, pkh, Pref);
}


void HIDDEN btcl_util_add_vout_pkh(btc_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash, uint8_t Pref)
{
    btc_vout_t *vout = btc_tx_add_vout(pTx, Value);
    btc_util_create_scriptpk(&vout->script, pPubKeyHash, Pref);
}


int HIDDEN btcl_util_get_varint_len(uint32_t Len)
{
    return (Len < VARINT_3BYTE_MIN) ? 1 : 3;
}


int HIDDEN btcl_util_set_varint_len(uint8_t *pData, const uint8_t *pOrg, uint32_t Len, bool isScript)
{
    int retval = 0;

    if (isScript && (Len == 1) && (1 <= pOrg[0]) && (pOrg[0] <= 16)) {
        //スクリプト用
        //データ長が1で値が1～16の場合はOP_1～OP_16を使う
        //実データでは使わないと思われるが、テスト用にOP_CSVの
        *pData = OP_x + pOrg[0];
        retval = 0;
    } else {
        //データ長が75より大きい場合、OP_PUSHDATA1などを使う必要があるかもしれない
        //P2SHのscriptSigは長くなりがちなので発生しやすい
        //witnessにはその制約がなさそうである
        if (Len < VARINT_3BYTE_MIN) {
            *pData = (uint8_t)Len;
            retval = 1;
        } else {
            *pData++ = VARINT_3BYTE_MIN;
            *pData++ = (uint8_t)Len;
            *pData++ = (uint8_t)(Len >> 8);
            retval = 3;
        }
    }

    return retval;
}


/**************************************************************************
 * private functions
 **************************************************************************/

/** scriptPubKey(P2PKH)のデータを設定する
 *
 *
 */
static void create_scriptpk_p2pkh(uint8_t *p, const uint8_t *pPubKeyHash)
{
    p[0] = OP_DUP;
    p[1] = OP_HASH160;
    p[2] = BTC_SZ_HASH160;
    memcpy(p + 3, pPubKeyHash, BTC_SZ_HASH160);
    p[23] = OP_EQUALVERIFY;
    p[24] = OP_CHECKSIG;
}


/** scriptPubKey(P2SH)のデータを設定する
 *
 *
 */
static void create_scriptpk_p2sh(uint8_t *p, const uint8_t *pPubKeyHash)
{
    p[0] = OP_HASH160;
    p[1] = BTC_SZ_HASH160;
    memcpy(p + 2, pPubKeyHash, BTC_SZ_HASH160);
    p[22] = OP_EQUAL;
}


/** scriptPubKey(P2WPKH native)のデータを設定する
 *
 *
 */
static void create_scriptpk_native(uint8_t *p, const uint8_t *pPubKeyHash, uint8_t Len)
{
    p[0] = 0x00;
    p[1] = Len;
    memcpy(p + 2, pPubKeyHash, Len);
}


/** 2-of-2公開鍵ソート
 *
 * @param[out]      pp1
 * @param[out]      pp2
 * @param[in]       pPubKey1
 * @param[in]       pPubKey2
 * @retval      BTC_KEYS_SORT_ASC     引数の順番が昇順
 *
 */
static btc_keys_sort_t keys_sort2of2(const uint8_t **pp1, const uint8_t **pp2, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    btc_keys_sort_t ret;

    int cmp = memcmp(pPubKey1, pPubKey2, BTC_SZ_PUBKEY);
    if (cmp < 0) {
        ret = BTC_KEYS_SORT_ASC;
        *pp1 = pPubKey1;
        *pp2 = pPubKey2;
    } else {
        ret = BTC_KEYS_SORT_OTHER;
        *pp1 = pPubKey2;
        *pp2 = pPubKey1;
    }

    return ret;
}


/** uint32-->uint8[4](little endian)
 *
 * @param[out]  pData       変換後データ
 * @param[in]   val         Little Endianデータ
 * @return      データ長(4)
 */
static int set_le32(uint8_t *pData, uint32_t val)
{
    uint8_t *p = (uint8_t *)&val;
    memcpy(pData, p, sizeof(uint32_t));

    return (int)sizeof(uint32_t);
}


/** uint64-->uint8[8](little endian)
 *
 * @param[out]  pData       変換後データ
 * @param[in]   val         Little Endianデータ
 * @return      データ長(8)
 */
static int set_le64(uint8_t *pData, uint64_t val)
{
    uint8_t *p = (uint8_t *)&val;
    memcpy(pData, p, sizeof(uint64_t));

    return (int)sizeof(uint64_t);
}
