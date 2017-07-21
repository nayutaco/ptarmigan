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
/** @file   ucoin_ekey.c
 *  @brief  bitcoin extended key
 *  @author ueno@nayuta.co
 */
#include "ucoin_local.h"

#include "libbase58.h"
#include "mbedtls/md.h"


/**************************************************************************
 * const variables
 **************************************************************************/

//secp256k1のorder
static const uint8_t SECP256K1_N[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};

static const uint32_t VERSION_BYTES[][2] = {
    //privkey     pubkey
    { 0x0488ade4, 0x0488b21e },     //mainnet
    { 0x04358394, 0x043587cf }      //testnet
};


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool ekey_hmac512(mbedtls_mpi *p_n, mbedtls_mpi *p_l_L, uint8_t *pChainCode, const uint8_t *pKey, int KeyLen, const uint8_t *pData, int DataLen);


/**************************************************************************
 * public functions
 **************************************************************************/

bool ucoin_ekey_prepare(ucoin_ekey_t *pEKey, uint8_t *pPrivKey, uint8_t *pPubKey, const uint8_t *pSeed, int SzSeed)
{
    bool ret = false;
    int retval;
    uint8_t output37[33 + 4];
    const uint8_t *p_key;
    const uint8_t *p_input;
    int key_len;
    int input_len;

    if ((pPrivKey != NULL) && (pEKey->type == UCOIN_EKEY_PRIV)) {
        //private parent key --> private child key
        if (pSeed == NULL) {
            //Child
            p_key = pEKey->chain_code;
            key_len = UCOIN_SZ_CHAINCODE;

            if (pEKey->child_number & UCOIN_EKEY_HARDENED) {
                output37[0] = 0x00;
                memcpy(output37 + 1, pPrivKey, UCOIN_SZ_PRIVKEY);
            } else {
                memcpy(output37, pPubKey, UCOIN_SZ_PUBKEY);
            }
            output37[UCOIN_SZ_PUBKEY    ] =  pEKey->child_number  >> 24;
            output37[UCOIN_SZ_PUBKEY + 1] = (pEKey->child_number  >> 16) & 0xff;
            output37[UCOIN_SZ_PUBKEY + 2] = (pEKey->child_number  >>  8) & 0xff;
            output37[UCOIN_SZ_PUBKEY + 3] =  pEKey->child_number         & 0xff;
            p_input = output37;
            input_len = 37;

            uint8_t h160[UCOIN_SZ_HASH160];
            ucoin_util_hash160(h160, pPubKey, UCOIN_SZ_PUBKEY);
            pEKey->fingerprint = (h160[0] << 24) | (h160[1] << 16) | (h160[2] << 8) | h160[3];
        } else {
            //Master
            p_key = (const uint8_t *)"Bitcoin seed";
            key_len = 12;
            p_input = pSeed;
            input_len = SzSeed;

            pEKey->fingerprint = 0;
        }
    } else if (pEKey->type == UCOIN_EKEY_PUB) {
        //public parent key --> public child key
        if (pEKey->child_number & UCOIN_EKEY_HARDENED) {
            return false;
        }
        p_key = pEKey->chain_code;
        key_len = UCOIN_SZ_CHAINCODE;

        memcpy(output37, pPubKey, UCOIN_SZ_PUBKEY);
        output37[UCOIN_SZ_PUBKEY    ] =  pEKey->child_number  >> 24;
        output37[UCOIN_SZ_PUBKEY + 1] = (pEKey->child_number  >> 16) & 0xff;
        output37[UCOIN_SZ_PUBKEY + 2] = (pEKey->child_number  >>  8) & 0xff;
        output37[UCOIN_SZ_PUBKEY + 3] =  pEKey->child_number         & 0xff;
        p_input = output37;
        input_len = 37;

        uint8_t h160[UCOIN_SZ_HASH160];
        ucoin_util_hash160(h160, pPubKey, UCOIN_SZ_PUBKEY);
        pEKey->fingerprint = (h160[0] << 24) | (h160[1] << 16) | (h160[2] << 8) | h160[3];
    } else {
        return false;
    }

    mbedtls_mpi n;
    mbedtls_mpi l_L;
    mbedtls_mpi_init(&l_L);
    mbedtls_mpi_init(&n);

    bool b = ekey_hmac512(&n, &l_L, pEKey->chain_code, p_key, key_len, p_input, input_len);
    if (!b) {
        //printf("fail : ekey_hmac512\n");
        goto LABEL_EXIT;
    }

    if ((pPrivKey != NULL) && (pEKey->type == UCOIN_EKEY_PRIV)) {
        //private parent key --> private child key
        if (pSeed == NULL) {
            //Child
            mbedtls_mpi k_i;
            mbedtls_mpi kpar;

            mbedtls_mpi_init(&k_i);
            mbedtls_mpi_init(&kpar);

            retval  = mbedtls_mpi_read_binary(&kpar, pPrivKey, UCOIN_SZ_PRIVKEY);
            retval += mbedtls_mpi_add_mpi(&k_i, &l_L, &kpar);
            retval += mbedtls_mpi_mod_mpi(&k_i, &k_i, &n);
            retval += mbedtls_mpi_write_binary(&k_i, pPrivKey, UCOIN_SZ_PRIVKEY);

            //k_i != 0
            ret = (retval == 0) && (mbedtls_mpi_cmp_int(&k_i, 0) != 0);
            assert(ret);

            mbedtls_mpi_free(&kpar);
            mbedtls_mpi_free(&k_i);
        } else {
            //Master
            retval = mbedtls_mpi_write_binary(&l_L, pPrivKey, UCOIN_SZ_PRIVKEY);
            ret = (retval == 0);
            assert(ret);
        }
        ucoin_keys_priv2pub(pPubKey, pPrivKey);
    } else if (pEKey->type == UCOIN_EKEY_PUB) {
        //public parent key --> public child key
        ret = (ucoin_util_ecp_muladd(pPubKey, pPubKey, &l_L) == 0);
    } else {
        //上でreturnするので、こっちは通らない
        //return false;
        assert(ret);
    }

LABEL_EXIT:
    mbedtls_mpi_free(&l_L);
    mbedtls_mpi_free(&n);
    memset(output37, 0, sizeof(output37));      //clear for security

    //TODO: check (l_L >=n or k_i == 0)
    return ret;
}


bool ucoin_ekey_create(uint8_t *pData, char *pAddr, const ucoin_ekey_t *pEKey)
{
    uint32_t ver;
    const uint8_t *p_ver = (const uint8_t *)&ver;
    const uint8_t *p_fgr = (const uint8_t *)&pEKey->fingerprint;
    const uint8_t *p_num = (const uint8_t *)&pEKey->child_number;

    if ((mPref[UCOIN_PREF] & 0x03) == 0) {
        //ucoin_init()未実施
        return false;
    }
    ver = VERSION_BYTES[mPref[UCOIN_PREF] - 1][pEKey->type];

    for (int lp = 0; lp < 4; lp++) {
        pData[3 - lp] = *p_ver++;           //[0- 3]version bytes
        pData[8 - lp] = *p_fgr++;       //[5- 8]fingerprint
        pData[12 - lp] = *p_num++;       //[9-12]child number
    }
    //[4]depth
    pData[4] = pEKey->depth;
    //[13-44]chain code
    memcpy(&pData[13], pEKey->chain_code, 32);
    //[45-77]key
    if (pEKey->type == UCOIN_EKEY_PRIV) {
        //privkey
        pData[45] = 0x00;
        memcpy(&pData[46], pEKey->key, UCOIN_SZ_PRIVKEY);
    } else {
        //pubkey
        memcpy(&pData[45], pEKey->key, UCOIN_SZ_PUBKEY);
    }
    //[78-81]checksum
    uint8_t chksum[UCOIN_SZ_HASH256];
    ucoin_util_hash256(chksum, pData, UCOIN_SZ_EKEY - 4);
    for (int lp = 0; lp < 4; lp++) {
        pData[78 + lp] = chksum[lp];
    }

    bool ret = true;

    if (pAddr) {
        size_t sz = UCOIN_SZ_EKEY_ADDR_MAX;
        ret = b58enc(pAddr, &sz, pData, UCOIN_SZ_EKEY);
    }

    return ret;
}


bool ucoin_ekey_read(ucoin_ekey_t *pEKey, const uint8_t *pData, int Len)
{
    if (Len != 82) {
        //printf("Not extended key.");
        return false;
    }

    const uint8_t *p = pData;

    uint32_t ver = (*p << 24) | (*(p + 1) << 16) | (*(p + 2) << 8) | *(p + 3);
    int net;
    switch (ver & 0xffff0000) {
    case 0x04880000:
        //mainnet
        net = UCOIN_MAINNET;

        switch (ver & 0x0000ffff) {
        case 0xade4:
            pEKey->type = UCOIN_EKEY_PRIV;
            break;
        case 0xb21e:
            pEKey->type = UCOIN_EKEY_PUB;
            break;
        default:
            return false;
        }
        break;
    case 0x04350000:
        //testnet
        net = UCOIN_TESTNET;

        switch (ver & 0x0000ffff) {
        case 0x8394:
            pEKey->type = UCOIN_EKEY_PRIV;
            break;
        case 0x87cf:
            pEKey->type = UCOIN_EKEY_PUB;
            break;
        default:
            return false;
        }
        break;
    default:
        return false;
    }
    if (net != mPref[UCOIN_PREF]) {
        return false;
    }
    p += 4;

    pEKey->depth = *p;
    p++;
    pEKey->fingerprint = (*p << 24) | (*(p + 1) << 16) | (*(p + 2) << 8) | *(p + 3);
    p += 4;
    pEKey->child_number = (*p << 24) | (*(p + 1) << 16) | (*(p + 2) << 8) | *(p + 3);
    p += 4;
    memcpy(pEKey->chain_code, p, 32);
    p += 32;
    int len;
    if (pEKey->type == UCOIN_EKEY_PRIV) {
        //privkey
        p++;
        len = 32;
    } else {
        //pubkey
        len = 33;
    }
    memcpy(pEKey->key, p, len);
    p += len;
    uint8_t chksum[UCOIN_SZ_HASH256];
    ucoin_util_hash256(chksum, pData, UCOIN_SZ_EKEY - 4);
    return memcmp(chksum, p, 4) == 0;
}


bool ucoin_ekey_read_addr(ucoin_ekey_t *pEKey, const char *pXAddr)
{
    bool ret;
    uint8_t bin[UCOIN_SZ_EKEY];

    size_t addr_len = strlen(pXAddr);
    if (addr_len >= UCOIN_SZ_EKEY_ADDR_MAX) {
        //UCOIN_SZ_EKEY_ADDR_MAXは\0も含んだサイズなので、>=になる
        return false;
    }

    size_t sz = UCOIN_SZ_EKEY;
    ret = b58tobin(bin, &sz, pXAddr, strlen(pXAddr));
    if (ret) {
        ret = ucoin_ekey_read(pEKey, bin, sizeof(bin));
    }

    return ret;
}


#ifdef UCOIN_USE_PRINTFUNC
void ucoin_print_extendedkey(const ucoin_ekey_t *pEKey)
{
    FILE *fp = PRINTOUT;

    fprintf(fp, "------------------------\n");
    fprintf(fp, "type: ");
    switch (pEKey->type) {
    case UCOIN_EKEY_PRIV:
        fprintf(fp, "privkey\n");
        break;
    case UCOIN_EKEY_PUB:
        fprintf(fp, "pubkey\n");
        break;
    default:
        fprintf(fp, "unknown version bytes\n");
        return;
    }

    fprintf(fp, "depth: %d\n", pEKey->depth);
    fprintf(fp, "fingerprint: %08x\n", pEKey->fingerprint);
    fprintf(fp, "child number: %08x\n", pEKey->child_number);
    fprintf(fp, "chain code: ");
    ucoin_util_dumpbin(fp, pEKey->chain_code, 32);
    if (pEKey->type == UCOIN_EKEY_PUB) {
        fprintf(fp, "pubkey: ");
        ucoin_util_dumpbin(fp, pEKey->key, 33);
    } else {
        fprintf(fp, "privkey: ");
        ucoin_util_dumpbin(fp, pEKey->key, 32);

        uint8_t pubkey[UCOIN_SZ_PUBKEY];
        ucoin_keys_priv2pub(pubkey, pEKey->key);
        fprintf(fp, "pubkey: ");
        ucoin_util_dumpbin(fp, pubkey, sizeof(pubkey));
    }
    fprintf(fp, "------------------------\n");
}
#endif  //UCOIN_USE_PRINTFUNC


/**************************************************************************
 * private functions
 **************************************************************************/

static bool ekey_hmac512(mbedtls_mpi *p_n, mbedtls_mpi *p_l_L, uint8_t *pChainCode, const uint8_t *pKey, int KeyLen, const uint8_t *pData, int DataLen)
{
    uint8_t output[64];

    //HMAC-SHA512
    const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    //key = "Bitcoin seed"
    //input = S
    int retval = mbedtls_md_hmac(mdinfo, pKey, KeyLen, pData, DataLen, output);
    if (!retval) {
        //OK
    } else {
        //printf("fail : mbedtls_md_hmac(%d)\n", retval);
        return false;
    }

    //output check
    bool ret = false;
    for (int lp = 0; lp < 32; lp++) {
        if (output[lp]) {
            ret = true;
            break;
        }
    }
    if (!ret) {
        //printf("l_L is zero.\n");
        return false;
    }
    retval  = mbedtls_mpi_read_binary(p_l_L, output, 32);
    retval += mbedtls_mpi_read_binary(p_n, SECP256K1_N, sizeof(SECP256K1_N));
    if (retval) {
        //printf("fail(%d): retval\n", __LINE__);
        return false;
    }
    if (mbedtls_mpi_cmp_mpi(p_l_L, p_n) != -1) {
        //printf("fail(%d): l_L >= n\n", __LINE__);
        return false;
    }
    memcpy(pChainCode, output + 32, UCOIN_SZ_CHAINCODE);

    return true;
}
