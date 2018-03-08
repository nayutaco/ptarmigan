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
/** @file   ucoin_util.c
 *  @brief  bitcoin処理: 汎用処理
 *  @author ueno@nayuta.co
 */
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"

#include "ucoin_local.h"

#include "libbase58.h"


/**************************************************************************
 * private variables
 **************************************************************************/

#ifdef UCOIN_DEBUG_MEM
static int mcount = 0;
#endif  //UCOIN_DEBUG_MEM


/**************************************************************************
 * prototypes
 **************************************************************************/

static void create_scriptpk_p2pkh(uint8_t *p, const uint8_t *pPubKeyHash);
static void create_scriptpk_p2sh(uint8_t *p, const uint8_t *pPubKeyHash);
static void create_scriptpk_native(uint8_t *p, const uint8_t *pPubKeyHash, uint8_t Len);
static ucoin_keys_sort_t keys_sort2of2(const uint8_t **pp1, const uint8_t **pp2, const uint8_t *pPubKey1, const uint8_t *pPubKey2);
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

void ucoin_util_random(uint8_t *pData, uint16_t Len)
{
#ifdef UCOIN_USE_RNG
    mbedtls_ctr_drbg_random(&mRng, pData, Len);
#else   //UCOIN_USE_RNG
    for (uint16_t lp = 0; lp < Len; lp++) {
        pData[lp] = (uint8_t)(rand() % 256);
    }
#endif  //UCOIN_USE_RNG
}


bool ucoin_util_wif2keys(ucoin_util_keys_t *pKeys, ucoin_chain_t *pChain, const char *pWifPriv)
{
    bool ret;

    ret = ucoin_keys_wif2priv(pKeys->priv, pChain, pWifPriv);
    if (ret) {
        ret = ucoin_keys_priv2pub(pKeys->pub, pKeys->priv);
    }

    return ret;
}


bool ucoin_util_createkeys(ucoin_util_keys_t *pKeys)
{
    do {
        ucoin_util_random(pKeys->priv, UCOIN_SZ_PRIVKEY);
    } while (!ucoin_keys_chkpriv(pKeys->priv));

    bool ret = ucoin_keys_priv2pub(pKeys->pub, pKeys->priv);
    return ret;
}


bool ucoin_util_create2of2(ucoin_buf_t *pRedeem, ucoin_keys_sort_t *pSort, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    bool ret;
    const uint8_t *p1;
    const uint8_t *p2;

    *pSort = keys_sort2of2(&p1, &p2, pPubKey1, pPubKey2);
    ret = ucoin_keys_create2of2(pRedeem, p1, p2);
    return ret;
}


bool ucoin_util_sign_p2pkh(ucoin_tx_t *pTx, int Index, const ucoin_util_keys_t *pKeys)
{
    ucoin_buf_t scrpk;
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    ucoin_util_hash160(pkh, pKeys->pub, UCOIN_SZ_PUBKEY);
    ucoin_util_create_scriptpk(&scrpk, pkh, UCOIN_PREF_P2PKH);

    const ucoin_buf_t *scrpks[] = { &scrpk };

    uint8_t txhash[UCOIN_SZ_SIGHASH];
    bool ret = ucoin_tx_sighash(txhash, pTx, (const ucoin_buf_t **)scrpks, 1);
    assert(ret);
    ret = ucoin_tx_sign_p2pkh(pTx, Index, txhash, pKeys->priv, pKeys->pub);
    assert(ret);
    ucoin_buf_free(&scrpk);

    return ret;
}


bool ucoin_util_verify_p2pkh(ucoin_tx_t *pTx, int Index, const char *pAddrVout)
{
    //公開鍵(署名サイズ[1],署名[sz],公開鍵サイズ[1], 公開鍵、の順になっている)
    const uint8_t *p_pubkey = pTx->vin[Index].script.buf + 1 + pTx->vin[Index].script.buf[0] + 1;
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    ucoin_buf_t scrpk;
    ucoin_util_hash160(pkh, p_pubkey, UCOIN_SZ_PUBKEY);
    ucoin_util_create_scriptpk(&scrpk, pkh, UCOIN_PREF_P2PKH);
    const ucoin_buf_t *scrpks[] = { &scrpk };

    uint8_t txhash[UCOIN_SZ_SIGHASH];
    bool ret = ucoin_tx_sighash(txhash, pTx, (const ucoin_buf_t **)scrpks, 1);
    assert(ret);
    ret = ucoin_tx_verify_p2pkh_addr(pTx, Index, txhash, pAddrVout);
    assert(ret);
    ucoin_buf_free(&scrpk);

    return ret;
}


bool ucoin_util_sign_p2wpkh(ucoin_tx_t *pTx, int Index, uint64_t Value, const ucoin_util_keys_t *pKeys)
{
    bool ret;
    uint8_t txhash[UCOIN_SZ_HASH256];
    ucoin_buf_t sigbuf;
    ucoin_buf_t script_code;

    ucoin_buf_init(&script_code);
    ucoin_buf_init(&sigbuf);
    ucoin_sw_scriptcode_p2wpkh(&script_code, pKeys->pub);

    ucoin_sw_sighash(txhash, pTx, Index, Value, &script_code);
    ret = ucoin_tx_sign(&sigbuf, txhash, pKeys->priv);
    if (ret) {
        //mNativeSegwitがfalseの場合はscriptSigへの追加も行う
        ucoin_sw_set_vin_p2wpkh(pTx, Index, &sigbuf, pKeys->pub);
    }

    ucoin_buf_free(&sigbuf);
    ucoin_buf_free(&script_code);

    return ret;
}


void ucoin_util_sign_p2wsh_1(uint8_t *pTxHash, const ucoin_tx_t *pTx, int Index, uint64_t Value,
                    const ucoin_buf_t *pWitScript)
{
    ucoin_buf_t script_code;

    ucoin_buf_init(&script_code);
    ucoin_sw_scriptcode_p2wsh(&script_code, pWitScript);
    ucoin_sw_sighash(pTxHash, pTx, Index, Value, &script_code);
    ucoin_buf_free(&script_code);
}


bool ucoin_util_sign_p2wsh_2(ucoin_buf_t *pSig, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys)
{
    return ucoin_tx_sign(pSig, pTxHash, pKeys->priv);
}


bool ucoin_util_sign_p2wsh_rs_2(uint8_t *pRS, const uint8_t *pTxHash, const ucoin_util_keys_t *pKeys)
{
    return ucoin_tx_sign_rs(pRS, pTxHash, pKeys->priv);
}


bool ucoin_util_sign_p2wsh_3_2of2(ucoin_tx_t *pTx, int Index, ucoin_keys_sort_t Sort,
                    const ucoin_buf_t *pSig1,
                    const ucoin_buf_t *pSig2,
                    const ucoin_buf_t *pWit2of2)
{
    // 0
    // <sig1>
    // <sig2>
    // <script>
    const ucoin_buf_t wit0 = { NULL, 0 };
    const ucoin_buf_t *wits[] = {
        &wit0,
        NULL,
        NULL,
        pWit2of2
    };
    if (Sort == UCOIN_KEYS_SORT_ASC) {
        wits[1] = pSig1;
        wits[2] = pSig2;
    } else {
        wits[1] = pSig2;
        wits[2] = pSig1;
    }

    bool ret;

    ret = ucoin_sw_set_vin_p2wsh(pTx, Index, (const ucoin_buf_t **)wits, 4);
    return ret;
}


void ucoin_util_sort_bip69(ucoin_tx_t *pTx)
{
    //INPUT
    //  1. output(txid)でソート
    //      --> 同じならindexでソート
    if (pTx->vin_cnt > 1) {
        for (int lp = 0; lp < pTx->vin_cnt - 1; lp++) {
            for (int lp2 = lp + 1; lp2 < pTx->vin_cnt; lp2++) {
                uint8_t vin1[UCOIN_SZ_TXID];
                uint8_t vin2[UCOIN_SZ_TXID];
                for (int lp3 = 0; lp3 < UCOIN_SZ_TXID / 2; lp3++) {
                    vin1[lp3] = pTx->vin[lp ].txid[UCOIN_SZ_TXID - 1 - lp3];
                    vin2[lp3] = pTx->vin[lp2].txid[UCOIN_SZ_TXID - 1 - lp3];
                }
                int cmp = memcmp(vin1, vin2, UCOIN_SZ_TXID);
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
                    ucoin_vin_t swap;
                    memcpy(&swap, &pTx->vin[lp], sizeof(ucoin_vin_t));
                    memcpy(&pTx->vin[lp], &pTx->vin[lp2], sizeof(ucoin_vin_t));
                    memcpy(&pTx->vin[lp2], &swap, sizeof(ucoin_vin_t));
                }
            }
        }
    }

    //OUTPUT
    //  1. amountでソート(整数として)
    //      --> 同じならscriptPubKeyでソート
    if (pTx->vout_cnt > 1) {
        for (int lp = 0; lp < pTx->vout_cnt - 1; lp++) {
            for (int lp2 = lp + 1; lp2 < pTx->vout_cnt; lp2++) {
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
                    ucoin_vout_t swap;
                    memcpy(&swap, &pTx->vout[lp], sizeof(ucoin_vout_t));
                    memcpy(&pTx->vout[lp], &pTx->vout[lp2], sizeof(ucoin_vout_t));
                    memcpy(&pTx->vout[lp2], &swap, sizeof(ucoin_vout_t));
                }
            }
        }
    }
}


ucoin_genesis_t ucoin_util_get_genesis(const uint8_t *pGenesisHash)
{
    ucoin_genesis_t ret;

    if (memcmp(pGenesisHash, M_BTC_GENESIS_MAIN, UCOIN_SZ_HASH256) == 0) {
        ret = UCOIN_GENESIS_BTCMAIN;
    } else if (memcmp(pGenesisHash, M_BTC_GENESIS_TEST, UCOIN_SZ_HASH256) == 0) {
        ret = UCOIN_GENESIS_BTCTEST;
    } else if (memcmp(pGenesisHash, M_BTC_GENESIS_REGTEST, UCOIN_SZ_HASH256) == 0) {
        ret = UCOIN_GENESIS_BTCREGTEST;
    } else {
        DBG_PRINTF2("unknown genesis hash\n");
        ret = UCOIN_GENESIS_UNKNOWN;
    }
    return ret;
}


const uint8_t *ucoin_util_get_genesis_block(ucoin_genesis_t kind)
{
    switch (kind) {
    case UCOIN_GENESIS_BTCMAIN:
        return M_BTC_GENESIS_MAIN;
    case UCOIN_GENESIS_BTCTEST:
        return M_BTC_GENESIS_TEST;
    case UCOIN_GENESIS_BTCREGTEST:
        return M_BTC_GENESIS_REGTEST;
    default:
        DBG_PRINTF("unknown kind: %02x\n", kind);
    }

    return NULL;
}


#if defined(UCOIN_USE_PRINTFUNC) || defined(UCOIN_DEBUG)
/** uint8[]の内容をFILE*出力
 *
 * @param[in]       fp          出力先
 * @param[in]       pData       対象データ
 * @param[in]       Len         pData長
 */
void ucoin_util_dumpbin(FILE *fp, const uint8_t *pData, uint16_t Len, bool bLf)
{
    for (uint16_t lp = 0; lp < Len; lp++) {
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
void ucoin_util_dumptxid(FILE *fp, const uint8_t *pTxid)
{
    for (uint16_t lp = 0; lp < UCOIN_SZ_TXID; lp++) {
        fprintf(fp, "%02x", pTxid[UCOIN_SZ_TXID - lp - 1]);
    }
}
#endif  //UCOIN_USE_PRINTFUNC || UCOIN_DEBUG


#ifdef UCOIN_DEBUG_MEM
int ucoin_dbg_malloc_cnt(void)
{
    return mcount;
}

#endif  //UCOIN_DEBUG_MEM


/**************************************************************************
 * package functions
 **************************************************************************/

void ucoin_util_hash160(uint8_t *pHash160, const uint8_t *pData, uint16_t Len)
{
    uint8_t buf_sha256[UCOIN_SZ_SHA256];

    ucoin_util_sha256(buf_sha256, pData, Len);
    ucoin_util_ripemd160(pHash160, buf_sha256, sizeof(buf_sha256));
}


void HIDDEN ucoin_util_hash256(uint8_t *pHash256, const uint8_t *pData, uint16_t Len)
{
    ucoin_util_sha256(pHash256, pData, Len);
    ucoin_util_sha256(pHash256, pHash256, UCOIN_SZ_SHA256);
}


void HIDDEN ucoin_util_sha256cat(uint8_t *pSha256, const uint8_t *pData1, uint16_t Len1, const uint8_t *pData2, uint16_t Len2)
{
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pData1, Len1);
    mbedtls_sha256_update(&ctx, pData2, Len2);
    mbedtls_sha256_finish(&ctx, pSha256);
    mbedtls_sha256_free(&ctx);
}


/** 圧縮された公開鍵をkeypairに展開する
 *
 * @param[in]       pPubKey     圧縮された公開鍵
 * @return      0   成功
 * @note
 *      - https://bitcointalk.org/index.php?topic=644919.0
 *      - https://gist.github.com/flying-fury/6bc42c8bb60e5ea26631
 */
int HIDDEN ucoin_util_set_keypair(mbedtls_ecp_keypair *pKeyPair, const uint8_t *pPubKey)
{
    int ret;

    ret = ucoin_util_ecp_point_read_binary2(&(pKeyPair->Q), pPubKey);

    return ret;
}


/** 圧縮公開鍵を非圧縮公開鍵展開
 *
 * @param[out]  point       非圧縮公開鍵座標
 * @param[in]   pPubKey     圧縮公開鍵
 * @return      0...正常
 *
 * @note
 *      - https://gist.github.com/flying-fury/6bc42c8bb60e5ea26631
 */
int HIDDEN ucoin_util_ecp_point_read_binary2(mbedtls_ecp_point *point, const uint8_t *pPubKey)
{
    int ret;
    uint8_t parity;
    size_t plen;
    mbedtls_mpi e, y2;
    mbedtls_ecp_keypair keypair;

    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&y2);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    ret = mbedtls_ecp_point_read_binary(&keypair.grp, point, pPubKey, UCOIN_SZ_PUBKEY);
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
    if (UCOIN_SZ_PUBKEY != plen + 1) {
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


/** PubKeyHash(P2PKH)をPubKeyHash(P2WPKH)に変換
 *
 * [00][14][pubKeyHash] --> HASH160
 *
 * @param[out]      pWPubKeyHash    変換後データ(UCOIN_SZ_PUBKEYHASH以上のサイズを想定)
 * @param[in]       pPubKeyHash     対象データ(UCOIN_SZ_PUBKEYHASH)
 */
void HIDDEN ucoin_util_create_pkh2wpkh(uint8_t *pWPubKeyHash, const uint8_t *pPubKeyHash)
{
    if (!mNativeSegwit) {
        uint8_t wit_prog[2 + UCOIN_SZ_PUBKEYHASH];

        wit_prog[0] = 0x00;
        wit_prog[1] = (uint8_t)UCOIN_SZ_PUBKEYHASH;
        memcpy(wit_prog + 2, pPubKeyHash, UCOIN_SZ_PUBKEYHASH);
        ucoin_util_hash160(pWPubKeyHash, wit_prog, sizeof(wit_prog));
    } else {
        //nested in P2SH用
        assert(false);
    }
}


/** 種類に応じたscriptPubKey設定
 *
 * @param[out]      pBuf
 * @param[in]       pPubKeyHash
 * @param[in]       Prefix
 */
void HIDDEN ucoin_util_create_scriptpk(ucoin_buf_t *pBuf, const uint8_t *pPubKeyHash, int Prefix)
{
    switch (Prefix) {
    case UCOIN_PREF_P2PKH:
        //DBG_PRINTF("UCOIN_PREF_P2PKH\n");
        ucoin_buf_alloc(pBuf, 3 + UCOIN_SZ_PUBKEYHASH + 2);
        create_scriptpk_p2pkh(pBuf->buf, pPubKeyHash);
        break;
    case UCOIN_PREF_P2SH:
        //DBG_PRINTF("UCOIN_PREF_P2SH\n");
        ucoin_buf_alloc(pBuf, 2 + UCOIN_SZ_PUBKEYHASH + 1);
        create_scriptpk_p2sh(pBuf->buf, pPubKeyHash);
        break;
    case UCOIN_PREF_NATIVE:
        //DBG_PRINTF("UCOIN_PREF_NATIVE\n");
        ucoin_buf_alloc(pBuf, 2 + UCOIN_SZ_PUBKEYHASH);
        create_scriptpk_native(pBuf->buf, pPubKeyHash, UCOIN_SZ_PUBKEYHASH);
        break;
    case UCOIN_PREF_NATIVE_SH:
        //DBG_PRINTF("UCOIN_PREF_NATIVE_SH\n");
        ucoin_buf_alloc(pBuf, 2 + UCOIN_SZ_HASH256);
        create_scriptpk_native(pBuf->buf, pPubKeyHash, UCOIN_SZ_HASH256);
        break;
    default:
        assert(false);
    }
}


/** PubKeyHashをBitcoinアドレスに変換
 *
 * @param[out]      pAddr           変換後データ(UCOIN_SZ_ADDR_MAX以上のサイズを想定)
 * @param[in]       pPubKeyHash     対象データ(UCOIN_SZ_PUBKEY)
 * @param[in]       Prefix          UCOIN_PREF_xxx
 */
bool HIDDEN ucoin_util_keys_pkh2addr(char *pAddr, const uint8_t *pPubKeyHash, uint8_t Prefix)
{
    bool ret;
    uint8_t buf_sha256[UCOIN_SZ_HASH256];

    if (Prefix == UCOIN_PREF_NATIVE) {
        uint8_t pkh[3 + UCOIN_SZ_PUBKEYHASH + 4];
        size_t sz = UCOIN_SZ_WPKHADDR;

        pkh[0] = mPref[UCOIN_PREF_ADDRVER];
        pkh[1] = 0x00;
        pkh[2] = 0x00;
        memcpy(pkh + 3, pPubKeyHash, UCOIN_SZ_PUBKEYHASH);
        ucoin_util_hash256(buf_sha256, pkh, 3 + UCOIN_SZ_PUBKEYHASH);
        memcpy(pkh + 3 + UCOIN_SZ_PUBKEYHASH, buf_sha256, 4);
        ret = b58enc(pAddr, &sz, pkh, sizeof(pkh));
    } else {
        uint8_t pkh[1 + UCOIN_SZ_PUBKEYHASH + 4];
        size_t sz = UCOIN_SZ_ADDR_MAX;

        pkh[0] = mPref[Prefix];
        memcpy(pkh + 1, pPubKeyHash, UCOIN_SZ_PUBKEYHASH);
        ucoin_util_hash256(buf_sha256, pkh, 1 + UCOIN_SZ_PUBKEYHASH);
        memcpy(pkh + 1 + UCOIN_SZ_PUBKEYHASH, buf_sha256, 4);
        ret = b58enc(pAddr, &sz, pkh, sizeof(pkh));
    }

    return ret;
}


/**
 * pPubKeyOut = pPubKeyIn + pA * G
 *
 */
int HIDDEN ucoin_util_ecp_muladd(uint8_t *pResult, const uint8_t *pPubKeyIn, const mbedtls_mpi *pA)
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
    ret = ucoin_util_ecp_point_read_binary2(&P1, pPubKeyIn);
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
    ret = mbedtls_ecp_muladd(&keypair.grp, &P2, pA, &keypair.grp.G, &one, &P1);
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
    ret = mbedtls_ecp_point_write_binary(&keypair.grp, &P2, MBEDTLS_ECP_PF_COMPRESSED, &sz, pResult, UCOIN_SZ_PUBKEY);

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free(&one);
    mbedtls_ecp_point_free(&P2);
    mbedtls_ecp_point_free(&P1);

    return ret;
}


bool HIDDEN ucoin_util_mul_pubkey(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pMul, int MulLen)
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    int ret = ucoin_util_set_keypair(&keypair, pPubKey);
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
        ret = mbedtls_ecp_point_write_binary(&keypair.grp, &pnt, MBEDTLS_ECP_PF_COMPRESSED, &sz, pResult, UCOIN_SZ_PUBKEY);

        mbedtls_ecp_point_free(&pnt);
        mbedtls_mpi_free(&m);
    }
    mbedtls_ecp_keypair_free(&keypair);

    return ret == 0;
}


void HIDDEN ucoin_util_generate_shared_secret(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *pPrivKey)
{
    uint8_t pub[UCOIN_SZ_PUBKEY];
    ucoin_util_mul_pubkey(pub, pPubKey, pPrivKey, UCOIN_SZ_PRIVKEY);
    ucoin_util_sha256(pResult, pub, sizeof(pub));
}


bool HIDDEN ucoin_util_calc_mac(uint8_t *pMac, const uint8_t *pKeyStr, int StrLen,  const uint8_t *pMsg, int MsgLen)
{
    //HMAC(SHA256)
    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_md_hmac(mdinfo, pKeyStr, StrLen, pMsg, MsgLen, pMac);
    return ret == 0;
}


/** トランザクションデータ作成
 *
 * @param[out]      pBuf            変換後データ
 * @param[in]       pTx             対象データ
 * @param[in]       enableSegWit    false:pTxがsegwitでも、witnessを作らない(TXID計算用)
 *
 * @note
 *      - 動的にメモリ確保するため、pBufは使用後 #ucoin_buf_free()で解放すること
 *      - vin cntおよびvout cntは 252までしか対応しない(varint型の1byteまで)
 */
bool HIDDEN ucoin_util_create_tx(ucoin_buf_t *pBuf, const ucoin_tx_t *pTx, bool enableSegWit)
{
    //version[4]
    //mark[1]...wit
    //flag[1]...wit
    //vin_cnt[1]...252以下
    //  txid[32]
    //  index[4]
    //  script[len]
    //  sequence[4]
    //vout_cnt[1]...252以下
    //  value[8]
    //  script[len]
    //witness...wit
    //locktime[4]

    uint16_t len = sizeof(uint32_t) + 2;        //version + vin_cnt + vout_cnt
    bool segwit = false;

    //vin + witness
    for (int lp = 0; lp < pTx->vin_cnt; lp++) {
        ucoin_vin_t *vin = &(pTx->vin[lp]);

        len += UCOIN_SZ_TXID + sizeof(uint32_t) + vin->script.len + sizeof(uint32_t);
        len += ucoin_util_get_varint_len(vin->script.len);
        if (enableSegWit && vin->wit_cnt) {
            segwit = true;
            len++;          //wit_cnt
            for (int lp2 = 0; lp2 < vin->wit_cnt; lp2++) {
                ucoin_buf_t *buf = &(vin->witness[lp2]);
                len += buf->len;
                len += ucoin_util_get_varint_len(buf->len);
            }
        }
    }
    if (segwit) {
        len += 2;       //mark + flag
    }
    //vout
    for (int lp = 0; lp < pTx->vout_cnt; lp++) {
        ucoin_vout_t *vout = &(pTx->vout[lp]);

        len += sizeof(uint64_t) + vout->script.len;
        len += ucoin_util_get_varint_len(vout->script.len);
    }
    //locktime
    len += sizeof(uint32_t);

    //DBG_PRINTF("len=%d\n", len);

    pBuf->len = len;
    pBuf->buf = (uint8_t *)M_MALLOC(len);

    uint8_t *p = pBuf->buf;

    p += set_le32(p, pTx->version);
    if (segwit) {
        *p++ = 0x00;
        *p++ = 0x01;
    }

    //vin
    *p++ = pTx->vin_cnt;        //本来はvarint型
    for (int lp = 0; lp < pTx->vin_cnt; lp++) {
        ucoin_vin_t *vin = &(pTx->vin[lp]);

        //txid
        memcpy(p, vin->txid, UCOIN_SZ_TXID);
        p += UCOIN_SZ_TXID;
        //index
        p += set_le32(p, vin->index);
        //scriptSig
        p += ucoin_util_set_varint_len(p, vin->script.buf, vin->script.len, false);
        memcpy(p, vin->script.buf, vin->script.len);
        p += vin->script.len;
        //sequence
        p += set_le32(p, vin->sequence);
    }

    //vout
    *p++ = pTx->vout_cnt;       //本来はvarint型
    for (int lp = 0; lp < pTx->vout_cnt; lp++) {
        ucoin_vout_t *vout = &(pTx->vout[lp]);

        //value
        p += set_le64(p, vout->value);
        //scriptPubKey
        p += ucoin_util_set_varint_len(p, vout->script.buf, vout->script.len, false);
        memcpy(p, vout->script.buf, vout->script.len);
        p += vout->script.len;
    }

    //segwit
    if (segwit) {
        for (int lp = 0; lp < pTx->vin_cnt; lp++) {
            ucoin_vin_t *vin = &(pTx->vin[lp]);

            *p++ = vin->wit_cnt;
            for (int lp2 = 0; lp2 < vin->wit_cnt; lp2++) {
                ucoin_buf_t *buf = &(vin->witness[lp2]);

                p += ucoin_util_set_varint_len(p, buf->buf, buf->len, false);
                memcpy(p, buf->buf, buf->len);
                p += buf->len;
            }
        }
    }

    //locktime
    p += set_le32(p, pTx->locktime);

    //DBG_PRINTF("len2=%d(%d)\n", (int)(p - pBuf->buf), pBuf->len);
    return (p - pBuf->buf == pBuf->len);
}


void HIDDEN ucoin_util_add_vout_pub(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey, uint8_t Pref)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];

    ucoin_util_hash160(pkh, pPubKey, UCOIN_SZ_PUBKEY);
    ucoin_util_add_vout_pkh(pTx, Value, pkh, Pref);
}


void HIDDEN ucoin_util_add_vout_pkh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash, uint8_t Pref)
{
    ucoin_vout_t *vout = ucoin_tx_add_vout(pTx, Value);
    ucoin_util_create_scriptpk(&vout->script, pPubKeyHash, Pref);
}


/** varint型のデータ長サイズ取得
 *
 * @param[in]   Len         データ長(16bit長まで)
 * @return      varint型のデータ長サイズ
 *
 * @note
 *      - 補足:<br/>
 *          varint型はデータ長＋データという構成になっているが、データ長のサイズが可変になっている。<br/>
 *          データ長が0～0xfcまでは1バイト、0xfd～0xffffまでは3バイト、などとなる。<br/>
 *              https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
 */
int HIDDEN ucoin_util_get_varint_len(int Len)
{
    return (Len < VARINT_3BYTE_MIN) ? 1 : 3;
}


/** varint型のデータ長設定
 *
 * @param[out]      pData       設定先
 * @param[in]       pOrg        データ先頭(isScript==trueのみ)
 * @param[in]       Len         pOrg長
 * @param[in]       isScript    true:スクリプト作成中
 * @return      varintデータ長サイズ
 *
 * @note
 *      - pDataにvarint型のデータ長だけ書込む。pDataから戻り値だけ進んだところにpOrgを書込むとよい。
 */
int HIDDEN ucoin_util_set_varint_len(uint8_t *pData, const uint8_t *pOrg, uint16_t Len, bool isScript)
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


#ifdef UCOIN_DEBUG_MEM

#if 1
void HIDDEN *ucoin_dbg_malloc(size_t size)
{
    void *p = malloc(size);
    if (p) {
        mcount++;
    }
    return p;
}


void HIDDEN *ucoin_dbg_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if ((ptr == NULL) && p) {
        mcount++;
    }
    return p;
}


void HIDDEN *ucoin_dbg_calloc(size_t blk, size_t size)
{
    void *p = calloc(blk, size);
    if (p) {
        mcount++;
    }
    return p;
}


void HIDDEN ucoin_dbg_free(void *ptr)
{
    //NULL代入してfree()だけするパターンもあるため、NULLチェックする
    if (ptr) {
        mcount--;
    }
    free(ptr);
}


#else

static struct {
    int allocs;
    void *p;
} mem[100];

void HIDDEN *ucoin_dbg_malloc(size_t size)
{
    void *p = malloc(size);
    if (p) {
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == 0) {
                mem[lp].allocs++;
                mem[lp].p = p;
                break;
            }
        }
        mcount++;
    } else {
        printf("0 malloc\n");
    }
    printf("%s(%u)[%d] = %p\n", __func__, size, mcount, p);
    return p;
}


void HIDDEN *ucoin_dbg_realloc(void *ptr, size_t size)
{
    void *p = realloc(ptr, size);
    if (ptr && (ptr != p)) {
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == ptr) {
                printf("   realloc update\n");
                mem[lp].p = p;
                break;
            }
        }
    } else if ((ptr == NULL) && p) {
        mcount++;
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == 0) {
                mem[lp].allocs++;
                mem[lp].p = p;
                break;
            }
        }
    } else {
        printf("   realloc same\n");
    }
    printf("%s(%p, %u)[%d] = %p\n", __func__, ptr, size, mcount, p);
    return p;
}


void HIDDEN *ucoin_dbg_calloc(size_t blk, size_t size)
{
    void *p = calloc(blk, size);
    if (p) {
        mcount++;
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == 0) {
                mem[lp].allocs++;
                mem[lp].p = p;
                break;
            }
        }
    }
    printf("%s(%u, %u)[%d] = %p\n", __func__, blk, size, mcount, p);
    return p;
}


void HIDDEN ucoin_dbg_free(void *ptr)
{
    //NULL代入してfree()だけするパターンもあるため、NULLチェックする
    if (ptr) {
        mcount--;
        for (int lp = 0; lp < 100; lp++) {
            if (mem[lp].p == ptr) {
                mem[lp].allocs--;
                if (mem[lp].allocs == 0) {
                    mem[lp].p = NULL;
                }
                printf("%s(%p) allocs:%d\n", __func__, ptr, mem[lp].allocs);
                break;
            }
        }
    }
    printf("%s(%p)[%d]\n", __func__, ptr, mcount);
    free(ptr);
}

void ucoin_dbg_show_mem(void)
{
    for (int lp = 0; lp < 100; lp++) {
        if (mem[lp].p) {
            printf("[%2d]allocs=%d, p=%p\n", lp, mem[lp].allocs, mem[lp].p);
        }

    }
}
#endif

#endif  //UCOIN_DEBUG_MEM


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
    p[2] = UCOIN_SZ_PUBKEYHASH;
    memcpy(p + 3, pPubKeyHash, UCOIN_SZ_PUBKEYHASH);
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
    p[1] = UCOIN_SZ_PUBKEYHASH;
    memcpy(p + 2, pPubKeyHash, UCOIN_SZ_PUBKEYHASH);
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
 * @retval      UCOIN_KEYS_SORT_ASC     引数の順番が昇順
 *
 */
static ucoin_keys_sort_t keys_sort2of2(const uint8_t **pp1, const uint8_t **pp2, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    ucoin_keys_sort_t ret;

    int cmp = memcmp(pPubKey1, pPubKey2, UCOIN_SZ_PUBKEY);
    if (cmp < 0) {
        ret = UCOIN_KEYS_SORT_ASC;
        *pp1 = pPubKey1;
        *pp2 = pPubKey2;
    } else {
        ret = UCOIN_KEYS_SORT_OTHER;
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
