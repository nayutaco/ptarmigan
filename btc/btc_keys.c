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
/** @file   btc_keys.c
 *  @brief  bitcoin処理: 鍵関連
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"
#include "libbase58.h"

#include "btc_segwit_addr.h"
#include "btc_local.h"
#include "btc_script.h"
#include "btc_sw.h"
#include "btc_crypto.h"


/********************************************************************
 * prototypes
 ********************************************************************/

static bool addr_is_p2pkh(const char *pAddr);
static bool addr_is_p2sh(const char *pAddr);
static bool addr_is_segwit(const char *pAddr);

static bool hash2addr(char *pAddr, const uint8_t *pHash, uint8_t Prefix);


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_keys_wif2priv(uint8_t *pPrivKey, btc_chain_t *pChain, const char *pWifPriv)
{
    //WIF compressed (Base58Check decoded)
    // version prefix: 1byte --- 0x80
    // private key: 32bytes
    // compressed: 1byte --- 0x01
    // checksum: 4bytes
    uint8_t b58dec[1 + BTC_SZ_PRIVKEY + 1 + 4];
    size_t sz_priv = sizeof(b58dec);
    int idx;
    int tail;

    //b58tobin packs the data behind the buffer
    //if the data is larger than the buffer, skip leading zeros
    bool ret = b58tobin(b58dec, &sz_priv, pWifPriv, strlen(pWifPriv));
#if 1 //WIF compressed only
    ret &= (sz_priv == sizeof(b58dec));
#endif

    if (ret) {
        //chain
#if 1 //WIF compressed only
        idx = 0;        //先頭は[0]
        tail = 1;       //圧縮フラグあり
#else
        if (sz_priv == sizeof(b58dec)) {
            idx = 0;        //先頭は[0]
            tail = 1;       //圧縮フラグあり
        } else if (sz_priv == sizeof(b58dec) - 1) {
            idx = 1;        //先頭は[1]
            tail = 0;       //圧縮フラグ無し
        } else {
            ret = false;
        }
#endif
        switch (b58dec[idx]) {
        case 0x80:
            *pChain = BTC_MAINNET;
            break;
        case 0xef:
            *pChain = BTC_TESTNET;
            break;
        default:
            *pChain = BTC_UNKNOWN;
        }
        //checksum
        uint8_t buf_sha256[BTC_SZ_HASH256];
        btc_md_hash256(buf_sha256, b58dec + idx, 1 + BTC_SZ_PRIVKEY + tail);
        ret = (memcmp(buf_sha256, b58dec + sizeof(b58dec) - 4, 4) == 0);
    }
    if (ret) {
        memcpy(pPrivKey, b58dec + idx + 1, BTC_SZ_PRIVKEY);
    }
    memset(b58dec, 0, sizeof(b58dec));  //clear for security

    if (ret) {
        ret = btc_keys_check_priv(pPrivKey);
    }

    return ret;
}


bool btc_keys_priv2wif(char *pWifPriv, const uint8_t *pPrivKey)
{
    bool ret;
    uint8_t b58[1 + BTC_SZ_PRIVKEY + 1 + 4];
    uint8_t buf_sha256[BTC_SZ_HASH256];

    ret = btc_keys_check_priv(pPrivKey);
    if (!ret) {
        return false;
    }

    b58[0] = mPref[BTC_PREF_WIF];
    memcpy(b58 + 1, pPrivKey, BTC_SZ_PRIVKEY);
    b58[1 + BTC_SZ_PRIVKEY] = 0x01;     //WIF compressed only
    btc_md_hash256(buf_sha256, b58, 1 + BTC_SZ_PRIVKEY + 1);
    memcpy(b58 + 1 + BTC_SZ_PRIVKEY + 1, buf_sha256, 4);

    size_t sz = BTC_SZ_WIF_STR_MAX + 1;
    ret = b58enc(pWifPriv, &sz, b58, sizeof(b58));
    memset(b58, 0, sizeof(b58));        //clear for security
    return ret;
}


bool btc_keys_priv2pub(uint8_t *pPubKey, const uint8_t *pPrivKey) //XXX: mbed
{
    int ret;

    mbedtls_ecp_point P;
    mbedtls_mpi m;
    mbedtls_ecp_keypair keypair;

    mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&m);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    //P: The destination point
    //m: The integer by which to multiply
    //G: generator (The point to multiply)
    ret = mbedtls_mpi_read_binary(&m, pPrivKey, BTC_SZ_PRIVKEY);
    if (ret) {
        goto LABEL_EXIT;
    }
    ret = mbedtls_ecp_mul(&keypair.grp, &P, &m, &keypair.grp.G, NULL, NULL);
    if (ret) {
        goto LABEL_EXIT;
    }

    size_t sz;
    ret = mbedtls_ecp_point_write_binary(&keypair.grp, &P, MBEDTLS_ECP_PF_COMPRESSED, &sz, pPubKey, BTC_SZ_PUBKEY);

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_lset(&m, 0);            //clear for security
    mbedtls_mpi_free(&m);

    return ret == 0;
}


bool btc_keys_pub2p2pkh(char *pAddr, const uint8_t *pPubKey)
{
    uint8_t pkh[BTC_SZ_HASH_MAX];

    btc_md_hash160(pkh, pPubKey, BTC_SZ_PUBKEY);
    return hash2addr(pAddr, pkh, BTC_PREF_P2PKH);
}


bool btc_keys_pub2p2wpkh(char *pWAddr, const uint8_t *pPubKey)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    uint8_t pref;

    //BTC_SZ_PUBKEY_UNCOMP for the BIP142 test data
    btc_md_hash160(hash, pPubKey, (pPubKey[0] == 0x04) ? BTC_SZ_PUBKEY_UNCOMP : BTC_SZ_PUBKEY);

    if (mNativeSegwit) {
        pref = BTC_PREF_P2WPKH;
    } else {
        btc_script_p2sh_p2wpkh_create_scripthash_pkh(hash, hash);
        pref = BTC_PREF_P2SH;
    }
    if (!hash2addr(pWAddr, hash, pref)) return false;
    return true;
}


bool btc_keys_addr2p2wpkh(char *pWAddr, const char *pAddr)
{
    bool ret;
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;

    //extract pkh form addr
    ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (!ret || (pref != BTC_PREF_P2PKH)) {
        return false;
    }

    if (mNativeSegwit) {
        pref = BTC_PREF_P2WPKH;
    } else {
        btc_script_p2sh_p2wpkh_create_scripthash_pkh(hash, hash);
        pref = BTC_PREF_P2SH;
    }
    if (!hash2addr(pWAddr, hash, pref)) return false;
    return true;
}


bool btc_keys_wit2waddr(char *pWAddr, const utl_buf_t *pWitnessScript)
{
    bool ret;
    int pref;
    uint8_t hash[BTC_SZ_HASH_MAX];

    if (mNativeSegwit) {
        btc_md_sha256(hash, pWitnessScript->buf, pWitnessScript->len);
        pref = BTC_PREF_P2WSH;
    } else {
        uint8_t wit_prog[BTC_SZ_WITPROG_P2WSH];

        wit_prog[0] = 0x00;
        wit_prog[1] = BTC_SZ_HASH256;
        btc_md_sha256(wit_prog + 2, pWitnessScript->buf, pWitnessScript->len);
        btc_md_hash160(hash, wit_prog, sizeof(wit_prog));
        pref = BTC_PREF_P2SH;
    }
    ret = hash2addr(pWAddr, hash, pref);
    return ret;
}


bool btc_keys_uncomp_pub(uint8_t *pUncomp, const uint8_t *pPubKey) //XXX: mbed
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    int ret = btc_ecc_set_keypair(&keypair, pPubKey);
    if (!ret) {
        mbedtls_mpi_write_binary(&(keypair.Q.X), pUncomp, BTC_SZ_PUBKEY - 1);
        mbedtls_mpi_write_binary(&(keypair.Q.Y), pUncomp + BTC_SZ_PUBKEY - 1, BTC_SZ_PUBKEY - 1);
    }
    mbedtls_ecp_keypair_free(&keypair);

    return ret == 0;
}


bool btc_keys_check_priv(const uint8_t *pPrivKey) //XXX: mbed
{
    bool cmp;
    mbedtls_mpi priv;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    mbedtls_mpi_init(&priv);
    mbedtls_mpi_read_binary(&priv, pPrivKey, BTC_SZ_PRIVKEY);

    //pPrivKey = [0x01,  0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140]
    //chack that the private key is greater than 0
    cmp = (mbedtls_mpi_cmp_int(&priv, (mbedtls_mpi_sint)0) == 1);
    if (cmp) {
        //N: order of G
        //check that priv is lesser than N
        cmp = (mbedtls_mpi_cmp_mpi(&priv, &keypair.grp.N) == -1);
    }

    mbedtls_mpi_free(&priv);
    mbedtls_ecp_keypair_free(&keypair);

    return cmp;
}


bool btc_keys_check_pub(const uint8_t *pPubKey) //XXX: mbed
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    int ret = btc_ecc_set_keypair(&keypair, pPubKey);
    mbedtls_ecp_keypair_free(&keypair);

    return ret == 0;
}


bool btc_keys_addr2hash(uint8_t *pHash, int *pPrefix, const char *pAddr)
{
    bool ret;

    if (addr_is_p2pkh(pAddr) || addr_is_p2sh(pAddr)) {
        uint8_t bin[1 + BTC_SZ_HASH160 + 4];
        size_t sz = sizeof(bin);
        ret = b58tobin(bin, &sz, pAddr, strlen(pAddr));
        if (ret && sz == sizeof(bin)) {
            if (bin[0] == mPref[BTC_PREF_P2PKH]) {
                *pPrefix = BTC_PREF_P2PKH;
            } else if (bin[0] == mPref[BTC_PREF_P2SH]) {
                *pPrefix = BTC_PREF_P2SH;
            } else {
                ret = false;
            }
        } else {
            ret = false;
        }
        if (ret) {
            //checksum
            uint8_t buf[BTC_SZ_HASH256];
            btc_md_hash256(buf, bin, sz - 4);
            ret = memcmp(buf, bin + sz - 4, 4) == 0;
        }
        if (ret) {
            memcpy(pHash, bin + 1, BTC_SZ_HASH160);
        }
    } else if (addr_is_segwit(pAddr)) {
        uint8_t witprog[40];
        size_t witprog_len = sizeof(witprog);
        int witver;
        uint8_t hrp_type;
        switch (btc_get_chain()) {
        case BTC_MAINNET:
            hrp_type = BTC_SEGWIT_ADDR_MAINNET;
            break;
        case BTC_TESTNET:
            hrp_type = BTC_SEGWIT_ADDR_TESTNET;
            break;
        default:
            return false;
        }
        ret = btc_segwit_addr_decode(&witver, witprog, &witprog_len, hrp_type, pAddr);
        if (ret && (witver == 0x00)) {
            //if witver==0 than witness program == pubKeyHash
            if (witprog_len == BTC_SZ_HASH160) {
                *pPrefix = BTC_PREF_P2WPKH;
            } else if (witprog_len == BTC_SZ_HASH256) {
                *pPrefix = BTC_PREF_P2WSH;
            } else {
                ret = false;
            }
            if (ret) {
                memcpy(pHash, witprog, witprog_len);
            }
        } else {
            //witver!=0 is not supported
            ret = false;
        }
    } else {
        ret = false;
    }

    return ret;
}


bool btc_keys_addr2spk(utl_buf_t *pScriptPk, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];

    int pref;
    if (!btc_keys_addr2hash(hash, &pref, pAddr)) return false;
    if (!btc_script_scriptpk_create(pScriptPk, hash, pref)) return false;
    return true;
}


bool btc_keys_spk2addr(char *pAddr, const utl_buf_t *pScriptPk)
{
    const uint8_t *pkh;
    int prefix = btc_script_scriptpk_prefix(&pkh, pScriptPk);
    if (prefix == BTC_PREF_MAX) return false;
    if (!hash2addr(pAddr, pkh, prefix)) return false;
    return true;
}


bool btc_keys_wif2keys(btc_keys_t *pKeys, btc_chain_t *pChain, const char *pWifPriv)
{
    bool ret;

    ret = btc_keys_wif2priv(pKeys->priv, pChain, pWifPriv);
    if (ret) {
        ret = btc_keys_priv2pub(pKeys->pub, pKeys->priv);
    }

    return ret;
}


bool btc_keys_create_priv(uint8_t *pPriv)
{
    for (int i = 0; i < 1000; i++) {
        if (!btc_rng_rand(pPriv, BTC_SZ_PRIVKEY)) return false;
        if (btc_keys_check_priv(pPriv)) return true;
    }
    return false;
}


bool btc_keys_create(btc_keys_t *pKeys)
{
    if (!btc_keys_create_priv(pKeys->priv)) return false;
    return btc_keys_priv2pub(pKeys->pub, pKeys->priv);
}


/********************************************************************
 * private functions
 ********************************************************************/

static bool addr_is_p2pkh(const char *pAddr)
{
    if (strlen(pAddr) < 1) return false;

    if (pAddr[0] == '1') return true; //mainnet
    if (pAddr[0] == 'm') return true; //testnet
    if (pAddr[0] == 'n') return true; //testnet
    return false;
}

static bool addr_is_p2sh(const char *pAddr)
{
    if (strlen(pAddr) < 1) return false;

    if (pAddr[0] == '3') return true; //mainnet
    if (pAddr[0] == '2') return true; //testnet
    return false;
}

static bool addr_is_segwit(const char *pAddr)
{
    if (strlen(pAddr) < 3) return false;

    if (pAddr[0] == 'b' && pAddr[1] == 'c' && pAddr[2] == '1') return true; //mainnet
    if (pAddr[0] == 't' && pAddr[1] == 'b' && pAddr[2] == '1') return true; //testnet
    return false;
}


/** Hash(PKH/SH/WPKH/WSH)をBitcoinアドレスに変換
 *
 * @param[out]      pAddr           変換後データ(#BTC_SZ_ADDR_STR_MAX+1 以上のサイズを想定)
 * @param[in]       pHash           対象データ(最大#BTC_SZ_HASH_MAX)
 * @param[in]       Prefix          BTC_PREF_xxx
 * @note
 *      - if Prefix == #BTC_PREF_P2PKH then pHash is PKH(#BTC_SZ_HASH160)
 *      - if Prefix == #BTC_PREF_P2SH then pHash is SH(#BTC_SZ_HASH160)
 *      - if Prefix == #BTC_PREF_P2WPKH then pHash is WPKH(#BTC_SZ_HASH160)
 *      - if Prefix == #BTC_PREF_P2WSH then pHash is WSH(#BTC_SZ_HASH256)
 */
static bool hash2addr(char *pAddr, const uint8_t *pHash, uint8_t Prefix)
{
    bool ret;

    if (Prefix == BTC_PREF_P2WPKH || Prefix == BTC_PREF_P2WSH) {
        uint8_t hrp_type;

        switch (btc_get_chain()) {
        case BTC_MAINNET:
            hrp_type = BTC_SEGWIT_ADDR_MAINNET;
            break;
        case BTC_TESTNET:
            hrp_type = BTC_SEGWIT_ADDR_TESTNET;
            break;
        default:
            return false;
        }
        ret = btc_segwit_addr_encode(pAddr, BTC_SZ_ADDR_STR_MAX + 1, hrp_type, 0x00, pHash, (Prefix == BTC_PREF_P2WPKH) ? BTC_SZ_HASH160 : BTC_SZ_HASH256);
    } else if (Prefix == BTC_PREF_P2PKH || Prefix == BTC_PREF_P2SH) {
        uint8_t buf[1 + BTC_SZ_HASH160 + 4];
        uint8_t checksum[BTC_SZ_HASH256];
        size_t sz = BTC_SZ_ADDR_STR_MAX + 1;

        buf[0] = mPref[Prefix];
        memcpy(buf + 1, pHash, BTC_SZ_HASH160);
        btc_md_hash256(checksum, buf, 1 + BTC_SZ_HASH160);
        memcpy(buf + 1 + BTC_SZ_HASH160, checksum, 4);
        ret = b58enc(pAddr, &sz, buf, sizeof(buf));
    } else {
        ret = false;
    }

    return ret;
}


