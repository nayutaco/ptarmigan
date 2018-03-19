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
/** @file   ucoin_keys.c
 *  @brief  bitcoin処理: 鍵関連
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"
#include "libbase58.h"

#include "ucoin_local.h"


/**************************************************************************
 * public functions
 **************************************************************************/

bool ucoin_keys_wif2priv(uint8_t *pPrivKey, ucoin_chain_t *pChain, const char *pWifPriv)
{
    // [1byte][32bytes:privkey][1byte][4bytes]
    // プレフィクスの1byteは「圧縮された秘密鍵」
    uint8_t b58dec[1 + UCOIN_SZ_PRIVKEY + 1 + 4];
    size_t sz_priv = sizeof(b58dec);
    bool ret = b58tobin(b58dec, &sz_priv, pWifPriv, strlen(pWifPriv));
    if (ret) {
        //chain
        switch (b58dec[0]) {
        case 0x80:
            *pChain = UCOIN_MAINNET;
            break;
        case 0xef:
            *pChain = UCOIN_TESTNET;
            break;
        default:
            *pChain = UCOIN_UNKNOWN;
        }
        //checksum
        uint8_t buf_sha256[UCOIN_SZ_HASH256];
        int tail = (sz_priv == sizeof(b58dec)) ? 1 : 0;
        ucoin_util_hash256(buf_sha256, b58dec, 1 + UCOIN_SZ_PRIVKEY + tail);
        ret = (memcmp(buf_sha256, b58dec + 1 + UCOIN_SZ_PRIVKEY + tail, 4) == 0);
    } else {
        ret = false;
        assert(0);
    }
    if (ret) {
        memcpy(pPrivKey, b58dec + 1, UCOIN_SZ_PRIVKEY);
    }
    memset(b58dec, 0, sizeof(b58dec));      //clear for security

    if (ret) {
        ret = ucoin_keys_chkpriv(pPrivKey);
    }

    return ret;
}


bool ucoin_keys_priv2wif(char *pWifPriv, const uint8_t *pPrivKey)
{
    bool ret;
    uint8_t b58[1 + UCOIN_SZ_PRIVKEY + 1 + 4];
    uint8_t buf_sha256[UCOIN_SZ_HASH256];

    ret = ucoin_keys_chkpriv(pPrivKey);
    if (!ret) {
        return false;
    }

    b58[0] = mPref[UCOIN_PREF_WIF];
    memcpy(b58 + 1, pPrivKey, UCOIN_SZ_PRIVKEY);
    b58[1 + UCOIN_SZ_PRIVKEY] = 0x01;        //圧縮された秘密鍵のみ対応
    ucoin_util_hash256(buf_sha256, b58, 1 + UCOIN_SZ_PRIVKEY + 1);
    memcpy(b58 + 1 + UCOIN_SZ_PRIVKEY + 1, buf_sha256, 4);

    size_t sz = UCOIN_SZ_WIF_MAX;
    ret = b58enc(pWifPriv, &sz, b58, sizeof(b58));
    memset(b58, 0, sizeof(b58));        //clear for security
    return ret;
}


bool ucoin_keys_priv2pub(uint8_t *pPubKey, const uint8_t *pPrivKey)
{
    int ret;

    mbedtls_ecp_point P;
    mbedtls_mpi m;
    mbedtls_ecp_keypair keypair;

    mbedtls_ecp_point_init(&P);
    mbedtls_mpi_init(&m);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    //P:result, m:掛ける数値, grp.G:point
    ret = mbedtls_mpi_read_binary(&m, pPrivKey, UCOIN_SZ_PRIVKEY);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_ecp_mul(&keypair.grp, &P, &m, &keypair.grp.G, NULL, NULL);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    size_t sz;
    ret = mbedtls_ecp_point_write_binary(&keypair.grp, &P, MBEDTLS_ECP_PF_COMPRESSED, &sz, pPubKey, UCOIN_SZ_PUBKEY);

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_ecp_point_free(&P);
    mbedtls_mpi_lset(&m, 0);            //clear for security
    mbedtls_mpi_free(&m);

    return ret == 0;
}


bool ucoin_keys_pub2p2pkh(char *pAddr, const uint8_t *pPubKey)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];

    ucoin_util_hash160(pkh, pPubKey, UCOIN_SZ_PUBKEY);
    return ucoin_util_keys_pkh2addr(pAddr, pkh, UCOIN_PREF_P2PKH);
}


bool ucoin_keys_pub2p2wpkh(char *pWAddr, const uint8_t *pPubKey)
{
    bool ret;
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    uint8_t pref;

    //BIP142のテストデータが非圧縮公開鍵だったので、やむなくこうした
    ucoin_util_hash160(pkh, pPubKey, (pPubKey[0] == 0x04) ? UCOIN_SZ_PUBKEY_UNCOMP+1 : UCOIN_SZ_PUBKEY);
    if (mNativeSegwit) {
        pref = UCOIN_PREF_NATIVE;
    } else {
        ucoin_util_create_pkh2wpkh(pkh, pkh);
        pref = UCOIN_PREF_P2SH;
    }
    ret = ucoin_util_keys_pkh2addr(pWAddr, pkh, pref);
    return ret;
}


bool ucoin_keys_addr2p2wpkh(char *pWAddr, const char *pAddr)
{
    bool ret;

    if (mNativeSegwit) {
        uint8_t pkh[3 + UCOIN_SZ_PUBKEYHASH + 4];
        size_t sz = UCOIN_SZ_WPKHADDR;
        int pref;

        pkh[0] = mPref[UCOIN_PREF_ADDRVER];
        pkh[1] = 0x00;
        pkh[2] = 0x00;
        ret = ucoin_keys_addr2pkh(pkh + 3, &pref, pAddr);
        if (ret && (pref == UCOIN_PREF_P2PKH)) {
            uint8_t buf_sha256[UCOIN_SZ_HASH256];

            ucoin_util_hash256(buf_sha256, pkh, 3 + UCOIN_SZ_PUBKEYHASH);
            memcpy(pkh + 3 + UCOIN_SZ_PUBKEYHASH, buf_sha256, 4);
            ret = b58enc(pWAddr, &sz, pkh, sizeof(pkh));
        } else {
            ret = false;
        }
    } else {
        uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
        int pref;

        ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
        if (ret && (pref == UCOIN_PREF_P2PKH)) {
            ucoin_util_create_pkh2wpkh(pkh, pkh);
            ret = ucoin_util_keys_pkh2addr(pWAddr, pkh, UCOIN_PREF_P2SH);
        } else {
            ret = false;
        }
    }
    return ret;
}


bool ucoin_keys_wit2waddr(char *pWAddr, const ucoin_buf_t *pWitScript)
{
    bool ret;

    if (mNativeSegwit) {
        uint8_t buf_sha256[UCOIN_SZ_HASH256];
        uint8_t shash[3 + UCOIN_SZ_HASH256 + 4];
        size_t sz = UCOIN_SZ_WSHADDR;

        shash[0] = mPref[UCOIN_PREF_ADDRVER_SH];
        shash[1] = 0x00;
        shash[2] = 0x00;
        ucoin_util_sha256(shash + 3, pWitScript->buf, pWitScript->len);
        ucoin_util_hash256(buf_sha256, pWitScript->buf, pWitScript->len);
        memcpy(shash + 3 + UCOIN_SZ_HASH256, buf_sha256, 4);
        ret = b58enc(pWAddr, &sz, shash, sizeof(shash));
    } else {
        uint8_t wit_prog[LNL_SZ_WITPROG_WSH];
        uint8_t pkh[UCOIN_SZ_PUBKEYHASH];

        wit_prog[0] = 0x00;
        wit_prog[1] = UCOIN_SZ_HASH256;
        ucoin_util_sha256(wit_prog + 2, pWitScript->buf, pWitScript->len);
        ucoin_util_hash160(pkh, wit_prog, sizeof(wit_prog));
        ret = ucoin_util_keys_pkh2addr(pWAddr, pkh, UCOIN_PREF_P2SH);
    }
    return ret;
}


bool ucoin_keys_pubuncomp(uint8_t *pUncomp, const uint8_t *pPubKey)
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    int ret = ucoin_util_set_keypair(&keypair, pPubKey);
    if (!ret) {
        mbedtls_mpi_write_binary(&(keypair.Q.X), pUncomp, UCOIN_SZ_PUBKEY - 1);
        mbedtls_mpi_write_binary(&(keypair.Q.Y), pUncomp + UCOIN_SZ_PUBKEY - 1, UCOIN_SZ_PUBKEY - 1);
    }
    mbedtls_ecp_keypair_free(&keypair);

    return ret == 0;
}


bool ucoin_keys_chkpriv(const uint8_t *pPrivKey)
{
    bool cmp;
    mbedtls_mpi priv;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    mbedtls_mpi_init(&priv);
    mbedtls_mpi_read_binary(&priv, pPrivKey, UCOIN_SZ_PRIVKEY);

    //pPrivKey = [0x01,  0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140]
    cmp = (mbedtls_mpi_cmp_int(&priv, (mbedtls_mpi_sint)0) == 1);
    if (cmp) {
        cmp = (mbedtls_mpi_cmp_mpi(&priv, &keypair.grp.N) == -1);
    }

    mbedtls_mpi_free(&priv);
    mbedtls_ecp_keypair_free(&keypair);

    return cmp;
}


bool ucoin_keys_chkpub(const uint8_t *pPubKey)
{
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    int ret = ucoin_util_set_keypair(&keypair, pPubKey);
    mbedtls_ecp_keypair_free(&keypair);

    return ret == 0;
}


bool ucoin_keys_create2of2(ucoin_buf_t *pRedeem, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    ucoin_buf_alloc(pRedeem, LNL_SZ_2OF2);

    uint8_t *p = pRedeem->buf;

    /*
     * OP_2
     *   21 (pubkey1[33])
     *   21 (pubkey2[33])
     * OP_2
     * OP_CHECKMULTISIG
     */
    *p++ = OP_2;
    *p++ = (uint8_t)UCOIN_SZ_PUBKEY;
    memcpy(p, pPubKey1, UCOIN_SZ_PUBKEY);
    p += UCOIN_SZ_PUBKEY;
    *p++ = (uint8_t)UCOIN_SZ_PUBKEY;
    memcpy(p, pPubKey2, UCOIN_SZ_PUBKEY);
    p += UCOIN_SZ_PUBKEY;
    *p++ = OP_2;
    *p++ = OP_CHECKMULTISIG;
    return true;
}


bool ucoin_keys_createmulti(ucoin_buf_t *pRedeem, const uint8_t *pPubKeys[], int Num, int M)
{
    ucoin_buf_alloc(pRedeem, 3 + Num * (UCOIN_SZ_PUBKEY + 1));

    uint8_t *p = pRedeem->buf;

    /*
     * OP_n
     *   21 (pubkey1[33])
     *   ...
     *   21 (pubkeyn[33])
     * OP_m
     * OP_CHECKMULTISIG
     */
    *p++ = OP_x + M;
    for (int lp = 0; lp < Num; lp++) {
        *p++ = (uint8_t)UCOIN_SZ_PUBKEY;
        memcpy(p, pPubKeys[lp], UCOIN_SZ_PUBKEY);
        p += UCOIN_SZ_PUBKEY;
    }
    *p++ = OP_x + Num;
    *p++ = OP_CHECKMULTISIG;
    return true;
}


bool ucoin_keys_addr2pkh(uint8_t *pPubKeyHash, int *pPrefix, const char *pAddr)
{
    uint8_t bin[3 + UCOIN_SZ_PUBKEYHASH + 4];
    uint8_t *p_bin;
    uint8_t *p_pkh;
    size_t sz = sizeof(bin);
    bool ret = b58tobin(bin, &sz, pAddr, strlen(pAddr));
    if (ret) {
        if ((sz == 3 + UCOIN_SZ_PUBKEYHASH + 4) && (bin[0] == mPref[UCOIN_PREF_ADDRVER]) && (bin[1] == 0x00) && (bin[2] == 0x00)) {
            p_bin = bin;
            p_pkh = p_bin + 3;
            *pPrefix = UCOIN_PREF_NATIVE;
        } else if (sz == 1 + UCOIN_SZ_PUBKEYHASH + 4) {
            p_bin = bin + 2;
            p_pkh = p_bin + 1;
            if (p_bin[0] == mPref[UCOIN_PREF_P2PKH]) {
                *pPrefix = UCOIN_PREF_P2PKH;
            } else if (p_bin[0] == mPref[UCOIN_PREF_P2SH]) {
                *pPrefix = UCOIN_PREF_P2SH;
            } else {
                ret = false;
            }
        } else {
            ret = false;
        }
    }
    if (ret) {
        //CRC check
        uint8_t buf_sha256[UCOIN_SZ_HASH256];
        ucoin_util_hash256(buf_sha256, p_bin, sz - 4);
        ret = memcmp(buf_sha256, p_bin + sz - 4, 4) == 0;
    }
    if (ret) {
        memcpy(pPubKeyHash, p_pkh, UCOIN_SZ_PUBKEYHASH);
    }

    return ret;
}


bool ucoin_keys_addr2spk(ucoin_buf_t *pScriptPk, const char *pAddr)
{
    bool ret;
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];

    int pref;
    ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret) {
        ucoin_util_create_scriptpk(pScriptPk, pkh, pref);
    }

    return ret;
}
