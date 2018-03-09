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
/** @file   ucoin_tx.c
 *  @brief  bitcoin処理: トランザクション生成関連
 *  @author ueno@nayuta.co
 */
#include "ucoin_local.h"

#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"

#ifdef UCOIN_USE_PRINTFUNC
#include <time.h>
#endif  //UCOIN_USE_PRINTFUNC


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool is_valid_signature_encoding(const uint8_t *sig, uint16_t size);
static int sign_rs(mbedtls_mpi *p_r, mbedtls_mpi *p_s, const uint8_t *pTxHash, const uint8_t *pPrivKey);
static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                    unsigned char *sig, size_t *slen );
static bool recover_pubkey(uint8_t *pPubKey, int *pRecId, const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pOrgPubKey);

static int get_varint(uint16_t *pLen, const uint8_t *pData);
//uint16_t get_le16(const uint8_t *pData);
static uint32_t get_le32(const uint8_t *pData);
static uint64_t get_le64(const uint8_t *pData);


/**************************************************************************
 * public functions
 **************************************************************************/

void ucoin_tx_init(ucoin_tx_t *pTx)
{
    pTx->version = 2;
    pTx->vin_cnt = 0;
    pTx->vin = NULL;
    pTx->vout_cnt = 0;
    pTx->vout = NULL;
    pTx->locktime = 0;
}


void ucoin_tx_free(ucoin_tx_t *pTx)
{
    //vin
    for (int lp = 0; lp < pTx->vin_cnt; lp++) {
        ucoin_vin_t *vin = &(pTx->vin[lp]);
        ucoin_buf_free(&(vin->script));
        for (int lp2 = 0; lp2 < vin->wit_cnt; lp2++) {
            ucoin_buf_free(&(vin->witness[lp2]));
        }
        if (vin->wit_cnt) {
            M_FREE(vin->witness);
            vin->witness = NULL;
            vin->wit_cnt = 0;
        }
    }
    if (pTx->vin_cnt) {
        M_FREE(pTx->vin);
        pTx->vin = NULL;
        pTx->vin_cnt = 0;
    }
    //vout
    for (int lp = 0; lp < pTx->vout_cnt; lp++) {
        ucoin_vout_t *vout = &(pTx->vout[lp]);
        ucoin_buf_free(&(vout->script));
    }
    if (pTx->vout_cnt) {
        M_FREE(pTx->vout);
        pTx->vout = NULL;
        pTx->vout_cnt = 0;
    }
#ifdef UCOIN_DEBUG
    memset(pTx, 0, sizeof(*pTx));
    pTx->version = 2;
#endif  //UCOIN_DEBUG
}


ucoin_vin_t *ucoin_tx_add_vin(ucoin_tx_t *pTx, const uint8_t *pTxId, int Index)
{
    if (pTx->vin_cnt >= VARINT_1BYTE_MAX) {
        DBG_PRINTF("vin_cnt max\n");
        return NULL;
    }

    pTx->vin = (ucoin_vin_t *)M_REALLOC(pTx->vin, sizeof(ucoin_vin_t) * (pTx->vin_cnt + 1));
    ucoin_vin_t *vin = &(pTx->vin[pTx->vin_cnt]);
    pTx->vin_cnt++;

    memcpy(vin->txid, pTxId, UCOIN_SZ_TXID);
    vin->index = Index;
    ucoin_buf_init(&vin->script);
    vin->wit_cnt = 0;
    vin->witness = NULL;
    vin->sequence = 0xffffffff;
    return vin;
}


ucoin_buf_t *ucoin_tx_add_wit(ucoin_vin_t *pVin)
{
    if (pVin->wit_cnt >= VARINT_1BYTE_MAX) {
        DBG_PRINTF("wit_cnt max\n");
        return NULL;
    }

    pVin->witness = (ucoin_buf_t *)M_REALLOC(pVin->witness, sizeof(ucoin_buf_t) * (pVin->wit_cnt + 1));
    ucoin_buf_t *buf = &(pVin->witness[pVin->wit_cnt]);
    pVin->wit_cnt++;

    ucoin_buf_init(buf);
    return buf;
}


ucoin_vout_t *ucoin_tx_add_vout(ucoin_tx_t *pTx, uint64_t Value)
{
    if (pTx->vout_cnt >= VARINT_1BYTE_MAX) {
        DBG_PRINTF("vout_cnt max\n");
        return NULL;
    }

    pTx->vout = (ucoin_vout_t *)M_REALLOC(pTx->vout, sizeof(ucoin_vout_t) * (pTx->vout_cnt + 1));
    ucoin_vout_t *vout = &(pTx->vout[pTx->vout_cnt]);
    pTx->vout_cnt++;

    vout->value = Value;
    ucoin_buf_init(&vout->script);
    vout->opt = 0;
    return vout;
}


bool ucoin_tx_add_vout_addr(ucoin_tx_t *pTx, uint64_t Value, const char *pAddr)
{
    bool ret;
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    int pref;

    ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret) {
        ucoin_vout_t *vout = ucoin_tx_add_vout(pTx, Value);
        ucoin_util_create_scriptpk(&vout->script, pkh, pref);
    }
    return ret;
}


bool ucoin_tx_add_vout_p2pkh_pub(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey)
{
    ucoin_util_add_vout_pub(pTx, Value, pPubKey, UCOIN_PREF_P2PKH);
    return true;
}


bool ucoin_tx_add_vout_p2pkh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash)
{
    ucoin_util_add_vout_pkh(pTx, Value, pPubKeyHash, UCOIN_PREF_P2PKH);
    return true;
}


bool ucoin_tx_create_vout(ucoin_buf_t *pBuf, const char *pAddr)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    int pref;
    bool ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret) {
        ucoin_util_create_scriptpk(pBuf, pkh, pref);
    }

    return ret;
}


bool ucoin_tx_create_vout_p2pkh(ucoin_buf_t *pBuf, const char *pAddr)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    int pref;
    bool ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret && (pref == UCOIN_PREF_P2PKH)) {
        ucoin_util_create_scriptpk(pBuf, pkh, pref);
    } else {
        ret = false;
    }

    return ret;
}


bool ucoin_tx_add_vout_p2pkh_addr(ucoin_tx_t *pTx, uint64_t Value, const char *pAddr)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    int pref;
    bool ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret && (pref == UCOIN_PREF_P2PKH)) {
        ucoin_tx_add_vout_p2pkh(pTx, Value, pkh);
    } else {
        ret = false;
    }

    return ret;
}


bool ucoin_tx_add_vout_p2sh(ucoin_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash)
{
    ucoin_vout_t *vout = ucoin_tx_add_vout(pTx, Value);
    ucoin_buf_alloc(&vout->script, 2 + UCOIN_SZ_PUBKEYHASH + 1);
    uint8_t *p = vout->script.buf;

    p[0] = OP_HASH160;
    p[1] = UCOIN_SZ_PUBKEYHASH;
    memcpy(p + 2, pPubKeyHash, UCOIN_SZ_PUBKEYHASH);
    p[22] = OP_EQUAL;
    return true;
}


bool ucoin_tx_add_vout_p2sh_addr(ucoin_tx_t *pTx, uint64_t Value, const char *pAddr)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    int pref;
    bool ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret && (pref == UCOIN_PREF_P2SH)) {
        ucoin_tx_add_vout_p2sh(pTx, Value, pkh);
    } else {
        ret = false;
    }

    return ret;
}


bool ucoin_tx_add_vout_p2sh_redeem(ucoin_tx_t *pTx, uint64_t Value, const ucoin_buf_t *pRedeem)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    ucoin_util_hash160(pkh, pRedeem->buf, pRedeem->len);
    ucoin_tx_add_vout_p2sh(pTx, Value, pkh);
    return true;
}


bool ucoin_tx_set_vin_p2pkh(ucoin_tx_t *pTx, int Index, const ucoin_buf_t *pSig, const uint8_t *pPubKey)
{
    ucoin_vin_t *vin = &(pTx->vin[Index]);
    ucoin_buf_t *p_buf = &vin->script;

    p_buf->len = 1 + pSig->len + 1 + UCOIN_SZ_PUBKEY;
    p_buf->buf = (uint8_t *)M_REALLOC(p_buf->buf, p_buf->len);
    uint8_t *p = pTx->vin[Index].script.buf;

    *p = pSig->len;
    p++;
    memcpy(p, pSig->buf, pSig->len);
    p += pSig->len;
    *p = UCOIN_SZ_PUBKEY;
    p++;
    memcpy(p, pPubKey, UCOIN_SZ_PUBKEY);
    return true;
}


bool ucoin_tx_set_vin_p2sh(ucoin_tx_t *pTx, int Index, const ucoin_buf_t *pSigs[], int Num, const ucoin_buf_t *pRedeem)
{
    ucoin_vin_t *vin = &(pTx->vin[Index]);
    ucoin_buf_t *p_buf = &vin->script;

    //OP_0
    //(len + 署名) * 署名数
    //OP_PUSHDATAx
    //redeemScript長
    //redeemScript
    bool op_push2 = false;
    p_buf->len = 1 + Num + 1 + 1 + pRedeem->len;
    if (pRedeem->len >= 0x100) {
        //OP_PUSHDATA2
        op_push2 = true;
        p_buf->len++;
    }
    for (int lp = 0; lp < Num; lp++) {
         p_buf->len += pSigs[lp]->len;
    }
    p_buf->buf = (uint8_t *)M_REALLOC(p_buf->buf, p_buf->len);
    uint8_t *p = pTx->vin[Index].script.buf;

    *p++ = OP_0;
    for (int lp = 0; lp < Num; lp++) {
        *p++ = pSigs[lp]->len;
        memcpy(p, pSigs[lp]->buf, pSigs[lp]->len);
        p += pSigs[lp]->len;
    }
    if (op_push2) {
        *p++ = OP_PUSHDATA2;
        *p++ = pRedeem->len & 0xff;
        *p++ = pRedeem->len >> 8;
    } else {
        *p++ = OP_PUSHDATA1;
        *p++ = (uint8_t)pRedeem->len;
    }
    memcpy(p, pRedeem->buf, pRedeem->len);
    return true;
}


bool ucoin_tx_read(ucoin_tx_t *pTx, const uint8_t *pData, uint32_t Len)
{
    if (Len < 8) {
        //version(4) + txin_cnt(1) + txout_cnt(1) + locktime(4)
        return false;
    }

    //version
    pTx->version = *(uint32_t *)pData;

    //segwit判定
    bool segwit;
    uint8_t mark = pData[4];
    uint8_t flag = pData[5];
    if ((mark == 0x00) && (flag != 0x01)) {
        //2017/01/04:BIP-144ではflag==0x01のみ
        return false;
    }
    uint32_t pos;
    if ((mark == 0x00) && (flag == 0x01)) {
        //BIP-144
        //DBG_PRINTF("segwit\n");
        segwit = true;
        pos = 6;
    } else {
        //DBG_PRINTF("not segwit\n");
        segwit = false;
        pos = 4;
    }
    //DBG_PRINTF("  version:%d\n", pTx->version);

    int state = 0;
    int tx_cnt = 0;
    int tmp;
    uint16_t var;
#ifdef UCOIN_DEBUG
    uint32_t prev_pos = pos - 1;
    uint32_t pos_cnt = 0;
#endif
    while (pos < Len) {
#ifdef UCOIN_DEBUG
        if(prev_pos == pos) {
            pos_cnt++;
            if(pos_cnt > 5) {
                DBG_PRINTF("???\n");
                break;
            }
        }
        prev_pos = pos;
#endif
        switch (state) {
        case 0:
            //txin count
            pos += get_varint(&var, pData + pos);
            pTx->vin_cnt = var;
            //DBG_PRINTF("state0: pos=%d, vin_cnt=%d\n", pos, pTx->vin_cnt);
            if (pTx->vin_cnt == 0) {
                //txin無し
                pTx->vin = NULL;
                // --> txout count
                state = 2;
            } else {
                pTx->vin = (ucoin_vin_t *)M_MALLOC(sizeof(ucoin_vin_t) * pTx->vin_cnt);
                // --> txin
                state = 1;
            }
            break;
        case 1:
            //txin
            //DBG_PRINTF("state1: pos=%d, tx_cnt=%d, Len=%d\n", pos, tx_cnt, Len);
            if (pos + 41 + 1 + 4 <= Len) {       // vin_min(41) + vout_cnt(1) + locktime(4)
                //scriptSig長
                tmp = pos + UCOIN_SZ_TXID + sizeof(uint32_t);
                tmp = get_varint(&var, pData + tmp);
            } else {
                // --> txout count
                state = 2;
                break;
            }
            if (pos + 40 + tmp + var + 1 + 4 <= Len) {
                ucoin_vin_t *vin = &(pTx->vin[tx_cnt]);
                tx_cnt++;

                //txid
                memcpy(vin->txid, pData + pos, UCOIN_SZ_TXID);
                pos += UCOIN_SZ_TXID;
                //DBG_PRINTF("  txid:");
                //DUMPBIN(vin->txid, UCOIN_SZ_TXID);
                //index
                vin->index = get_le32(pData + pos);
                pos += sizeof(uint32_t);
                //DBG_PRINTF("  index=%u\n", vin->index);
                //scriptSig
                pos += tmp;
                if (var != 0) {
                    ucoin_buf_alloccopy(&vin->script, pData + pos, var);
                    pos += vin->script.len;
                } else {
                    ucoin_buf_init(&vin->script);
                }
                //DBG_PRINTF("  script[%d]:", vin->script.len);
                //DUMPBIN(vin->script.buf, vin->script.len);
                //sequence
                vin->sequence = get_le32(pData + pos);
                pos += sizeof(uint32_t);
                //DBG_PRINTF("  sequence:%08x\n", vin->sequence);
                //witnessは後で取得
                vin->wit_cnt = 0;
                vin->witness = NULL;
            }
            if (tx_cnt >= pTx->vin_cnt) {
                // --> txout count
                state = 2;
            }
            break;
        case 2:
            //txout count
            pos += get_varint(&var, pData + pos);
            pTx->vout_cnt = var;
            //DBG_PRINTF("state2: pos=%d, vout_cnt=%d\n", pos, pTx->vout_cnt);
            if (pTx->vout_cnt == 0) {
                //txout無し
                pTx->vout = NULL;
                if (segwit) {
                    // --> witness
                    state = 4;
                } else {
                    // --> locktime
                    state = 5;
                }
            } else {
                pTx->vout = (ucoin_vout_t *)M_MALLOC(sizeof(ucoin_vout_t) * pTx->vout_cnt);
                state = 3;
            }
            tx_cnt = 0;
            break;
        case 3:
            //txout
            //DBG_PRINTF("state3: pos=%d, tx_cnt=%d, Len=%d\n", pos, tx_cnt, Len);
            if (pos + 9 + 4 <= Len) {       // vout_min(9) + locktime(4)
                //scriptPubKey長
                tmp = pos + sizeof(uint64_t);
                tmp = get_varint(&var, pData + tmp);
            } else {
                if (segwit) {
                    // --> witness
                    state = 4;
                } else {
                    // --> locktime
                    state = 5;
                }
                tx_cnt = 0;
                break;
            }
            if (pos + 8 + tmp + var + 4 <= Len) {
                ucoin_vout_t *vout = &(pTx->vout[tx_cnt]);
                tx_cnt++;

                //value:仕様上はint64_t
                vout->value = get_le64(pData + pos);
                pos += sizeof(uint64_t);
                //DBG_PRINTF("  value:%llu\n", (long long unsigned int)vout->value);
                //scriptPubKey
                pos += tmp;
                if (var != 0) {
                    ucoin_buf_alloccopy(&vout->script, pData + pos, var);
                    pos += vout->script.len;
                } else {
                    ucoin_buf_init(&vout->script);
                }
                //DBG_PRINTF("  script[%d]:", vout->script.len);
                //DUMPBIN(vout->script.buf, vout->script.len);
            } else {
                //DBG_PRINTF("out: tmp=%d, var=%d\n", tmp, var);
            }
            if (tx_cnt >= pTx->vout_cnt) {
                if (segwit) {
                    // --> witness
                    state = 4;
                } else {
                    // --> locktime
                    state = 5;
                }
                tx_cnt = 0;
            } else {
                //DBG_PRINTF("  continue\n");
            }
            break;
        case 4:
            //witness
            //DBG_PRINTF("state4: pos=%d, tx_cnt=%d\n", pos, tx_cnt);
            if ((pos + 4 <= Len) && (tx_cnt < pTx->vin_cnt)) {
                pos += get_varint(&var, pData + pos);   //item数
                pTx->vin[tx_cnt].wit_cnt = var;
                pTx->vin[tx_cnt].witness = (ucoin_buf_t *)M_MALLOC(pTx->vin[tx_cnt].wit_cnt * sizeof(ucoin_buf_t));
            } else {
                state = 5;
                break;
            }
            //DBG_PRINTF("  wit_cnt=%d\n", pTx->vin[tx_cnt].wit_cnt);
            for(uint8_t lp = 0; lp < pTx->vin[tx_cnt].wit_cnt; lp++) {
                pos += get_varint(&var, pData + pos);   //データ長
                //DBG_PRINTF("   var=%d\n", var);
                if (pos + var + 4 <= Len) {
                    ucoin_buf_t *wit = &(pTx->vin[tx_cnt].witness[lp]);
                    ucoin_buf_alloccopy(wit, pData + pos, var);
                    pos += wit->len;
                } else {
                    DBG_PRINTF("  out\n");
                }
            }
            tx_cnt++;
            if (tx_cnt >= pTx->vin_cnt) {
                // --> locktime
                state = 5;
            }
            break;
        case 5:
            //locktime
            pTx->locktime = get_le32(pData + pos);
            pos += sizeof(uint32_t);
            //DBG_PRINTF("state5: locktime=%08x\n", pTx->locktime);
            break;
        default:
            assert(0);
            ucoin_tx_free(pTx);
            return false;
        }
    }

    return true;
}


bool ucoin_tx_create(ucoin_buf_t *pBuf, const ucoin_tx_t *pTx)
{
    return ucoin_util_create_tx(pBuf, pTx, true);
}


bool ucoin_tx_sighash(uint8_t *pTxHash, ucoin_tx_t *pTx, const ucoin_buf_t *pScriptPks[], int Num)
{
    const uint32_t sigtype = (uint32_t)SIGHASH_ALL;

    if (pTx->vin_cnt != Num) {
        assert(0);
        return false;
    }

    //scriptSigをscriptPubKeyで置き換える
    ucoin_buf_t *tmp_vinbuf = (ucoin_buf_t *)M_MALLOC(sizeof(ucoin_buf_t) * pTx->vin_cnt);
    for (int lp = 0; lp < pTx->vin_cnt; lp++) {
        ucoin_vin_t *vin = &pTx->vin[lp];

        tmp_vinbuf[lp].buf = vin->script.buf;
        tmp_vinbuf[lp].len = vin->script.len;
        vin->script.len = pScriptPks[lp]->len;
        vin->script.buf = (uint8_t *)M_MALLOC(vin->script.len);
        memcpy(vin->script.buf, pScriptPks[lp]->buf, vin->script.len);
    }

    ucoin_buf_t tx;
    bool ret = ucoin_tx_create(&tx, pTx);
    if (!ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    tx.buf = (uint8_t *)M_REALLOC(tx.buf, tx.len + sizeof(sigtype));
    memcpy(tx.buf + tx.len, &sigtype, sizeof(sigtype));
    tx.len += sizeof(sigtype);
    ucoin_util_hash256(pTxHash, tx.buf, tx.len);
    ucoin_buf_free(&tx);

    //scriptSigを元に戻す
    for (int lp = 0; lp < pTx->vin_cnt; lp++) {
        ucoin_vin_t *vin = &pTx->vin[lp];

        ucoin_buf_free(&vin->script);
        vin->script.buf = tmp_vinbuf[lp].buf;
        vin->script.len = tmp_vinbuf[lp].len;
    }
    M_FREE(tmp_vinbuf);

LABEL_EXIT:
    return ret;
}


bool ucoin_tx_sign(ucoin_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPrivKey)
{
    int ret;
    bool bret;
    mbedtls_mpi r, s;
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN + 1];   //141 + 1 byte
    size_t slen = 0;

    ucoin_buf_init(pSig);

    ret = sign_rs(&r, &s, pTxHash, pPrivKey);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret = ecdsa_signature_to_asn1(&r, &s, sig, &slen);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    //HashType
    sig[slen] = SIGHASH_ALL;
    slen++;
    bret = is_valid_signature_encoding(sig, slen);
    if (!bret) {
        assert(0);
        ret = -1;
        goto LABEL_EXIT;
    }
    ucoin_buf_alloccopy(pSig, sig, slen);

LABEL_EXIT:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    if (ret) {
        DBG_PRINTF("fail\n");
    }
    return ret == 0;
}


bool ucoin_tx_sign_rs(uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPrivKey)
{
    int ret;
    mbedtls_mpi r, s;

    ret = sign_rs(&r, &s, pTxHash, pPrivKey);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret = mbedtls_mpi_write_binary(&r, pRS, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_write_binary(&s, pRS + 32, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    if (ret) {
        DBG_PRINTF("fail\n");
    }
    return ret == 0;
}


bool ucoin_tx_verify(const ucoin_buf_t *pSig, const uint8_t *pTxHash, const uint8_t *pPubKey)
{
    int ret;
    bool bret;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    if (pSig->buf[pSig->len - 1] != SIGHASH_ALL) {
        //assert(0);
        DBG_PRINTF("fail: not SIGHASH_ALL\n");
        ret = -1;
        goto LABEL_EXIT;
    }
    bret = is_valid_signature_encoding(pSig->buf, pSig->len);
    if (!bret) {
        //assert(0);
        DBG_PRINTF("fail: invalid signature\n");
        ret = -1;
        goto LABEL_EXIT;
    }

    ret = ucoin_util_set_keypair(&keypair, pPubKey);
    if (!ret) {
        ret = mbedtls_ecdsa_read_signature((mbedtls_ecdsa_context *)&keypair,
                    pTxHash, UCOIN_SZ_HASH256,
                    pSig->buf, pSig->len - 1);
    } else {
        DBG_PRINTF("fail keypair\n");
    }

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);

    if (ret == 0) {
        DBG_PRINTF("ok: verify\n");
    } else {
        DBG_PRINTF("fail ret=%d\n", ret);
        DBG_PRINTF("pSig: ");
        DUMPBIN(pSig->buf, pSig->len);
        DBG_PRINTF("txhash: ");
        DUMPBIN(pTxHash, UCOIN_SZ_SIGHASH);
        DBG_PRINTF("pub: ");
        DUMPBIN(pPubKey, UCOIN_SZ_PUBKEY);
    }
    return ret == 0;
}


bool ucoin_tx_verify_rs(const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pPubKey)
{
    int ret;
    mbedtls_mpi r, s;
    mbedtls_ecp_keypair keypair;
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    ret = mbedtls_mpi_read_binary(&r, pRS, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = mbedtls_mpi_read_binary(&s, pRS + 32, 32);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ret = ucoin_util_set_keypair(&keypair, pPubKey);
    if (!ret) {
        ret = mbedtls_ecdsa_verify(&keypair.grp, pTxHash, UCOIN_SZ_HASH256, &keypair.Q, &r, &s);
    } else {
        DBG_PRINTF("fail keypair\n");
    }

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );

    if (ret == 0) {
        //DBG_PRINTF("ok: verify\n");
    } else {
        DBG_PRINTF("fail ret=%d\n", ret);
        DBG_PRINTF("txhash: ");
        DUMPBIN(pTxHash, UCOIN_SZ_SIGHASH);
        DBG_PRINTF("pub: ");
        DUMPBIN(pPubKey, UCOIN_SZ_PUBKEY);
    }
    return ret == 0;
}


bool ucoin_tx_sign_p2pkh(ucoin_tx_t *pTx, int Index,
                const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey)
{
    bool ret;
    uint8_t pubkey[UCOIN_SZ_PUBKEY];
    ucoin_buf_t sigbuf;

    ucoin_buf_init(&sigbuf);
    if (pPubKey == NULL) {
        ret = ucoin_keys_priv2pub(pubkey, pPrivKey);
        if (!ret) {
            assert(0);
            goto LABEL_EXIT;
        }
        pPubKey = pubkey;
    }

    ret = ucoin_tx_sign(&sigbuf, pTxHash, pPrivKey);
    if (ret) {
        ucoin_tx_set_vin_p2pkh(pTx, Index, &sigbuf, pPubKey);
    }

LABEL_EXIT:
    ucoin_buf_free(&sigbuf);

    return ret;
}


bool ucoin_tx_verify_p2pkh(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
{
    bool ret;

    const ucoin_buf_t *p_scriptsig = (const ucoin_buf_t *)&(pTx->vin[Index].script);
    const uint8_t *p = p_scriptsig->buf;
    const ucoin_buf_t sig = { (CONST_CAST uint8_t *)(p + 1), *p };      //P2PKHの署名は1byte長で収まる
    p += *p + 1;
    if (*p != UCOIN_SZ_PUBKEY) {
        assert(0);
        ret = false;
        goto LABEL_EXIT;
    }
    p++;
    ret = ucoin_tx_verify(&sig, pTxHash, p);
    if (ret) {
        uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
        ucoin_util_hash160(pkh, p, UCOIN_SZ_PUBKEY);
        ret = (memcmp(pkh, pPubKeyHash, sizeof(pkh)) == 0);
    }

LABEL_EXIT:
    return ret;
}


bool ucoin_tx_verify_p2pkh_spk(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const ucoin_buf_t *pScriptPk)
{
    bool ret = false;

    //P2PKHのscriptPubKey
    //  DUP HASH160 0x14 <20 bytes> EQUALVERIFY CHECKSIG
    if (pScriptPk->len != 3 + UCOIN_SZ_PUBKEYHASH + 2) {
        assert(0);
        goto LABEL_EXIT;
    }
    if ( (pScriptPk->buf[0] != OP_DUP) ||
         (pScriptPk->buf[1] != OP_HASH160) ||
         (pScriptPk->buf[2] != UCOIN_SZ_PUBKEYHASH) ||
         (pScriptPk->buf[3 + UCOIN_SZ_PUBKEYHASH] != OP_EQUALVERIFY) ||
         (pScriptPk->buf[3 + UCOIN_SZ_PUBKEYHASH + 1] != OP_CHECKSIG) ) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret =  ucoin_tx_verify_p2pkh(pTx, Index, pTxHash, pScriptPk->buf + 3);

LABEL_EXIT:
    return ret;
}


bool ucoin_tx_verify_p2pkh_addr(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    int pref;
    bool ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret && (pref == UCOIN_PREF_P2PKH)) {
        ret =  ucoin_tx_verify_p2pkh(pTx, Index, pTxHash, pkh);
    } else {
        ret = false;
    }

    return ret;
}


bool ucoin_tx_verify_multisig(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
{
    const ucoin_buf_t *p_scriptsig = (const ucoin_buf_t *)&(pTx->vin[Index].script);
    const uint8_t *p = p_scriptsig->buf;

    //このvinはP2SHの予定
    //      1. 前のvoutのpubKeyHashが、redeemScriptから計算したpubKeyHashと一致するか確認
    //      2. 署名チェック
    //
    //  OP_0
    //  <署名> x いくつか
    //  <OP_PUSHDATAx>
    //  pushデータ長
    //  redeemScript
    if (*p != OP_0) {
        DBG_PRINTF("top isnot OP_0\n");
        return false;
    }

    //署名数取得
    int signum = 0;
    int sigpos = 1;     //OP_0の次
    uint32_t pos = 1;
    while (pos < p_scriptsig->len) {
        uint8_t len = *(p + pos);
        if ((len == OP_PUSHDATA1) || (len == OP_PUSHDATA2)) {
            break;
        }
        signum++;
        pos += 1 + len;
    }
    if (pos >= p_scriptsig->len) {
        DBG_PRINTF("no OP_PUSHDATAx(sign)\n");
        return false;
    }
    pos++;
    uint16_t redm_len;  //OP_PUSHDATAxの引数
    pos += get_varint(&redm_len, p + pos);
    if (signum != (*(p + pos) - OP_x)) {
        DBG_PRINTF("OP_x mismatch(sign): signum=%d, OP_x=%d\n", signum, *(p + pos) - OP_x);
        return false;
    }
    pos++;
    //公開鍵数取得
    int pubnum = 0;
    int pubpos = pos;
    while (pos < p_scriptsig->len) {
        uint8_t len = *(p + pos);
        if ((OP_1 <= len) && (len <= OP_16)) {
            break;
        }
        if (len != UCOIN_SZ_PUBKEY) {
            DBG_PRINTF("invalid pubkey len(%d)\n", len);
            return false;
        }
        pubnum++;
        pos += 1 + len;
    }
    if (pos >= p_scriptsig->len) {
        DBG_PRINTF("no OP_PUSHDATAx(pubkey)\n");
        return false;
    }
    if (pubnum != (*(p + pos) - OP_x)) {
        DBG_PRINTF("OP_x mismatch(pubkey): signum=%d, OP_x=%d\n", pubnum, *(p + pos) - OP_x);
        return false;
    }
    pos++;
    if (*(p + pos) != OP_CHECKMULTISIG) {
        DBG_PRINTF("not OP_CHECKMULTISIG\n");
        return false;
    }
    pos++;
    if (pos != p_scriptsig->len) {
        DBG_PRINTF("invalid data length\n");
        return false;
    }

    //pubkeyhashチェック
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    ucoin_util_hash160(pkh, p_scriptsig->buf + pubpos - 1, p_scriptsig->len - pubpos + 1);
    bool ret = (memcmp(pkh, pPubKeyHash, sizeof(pkh)) == 0);
    if (!ret) {
        DBG_PRINTF("pubkeyhash mismatch.\n");
        return false;
    }

    //pubnum中、signum分のverifyが成功すればOK
    uint32_t chk_pos = 0;   //bitが立った公開鍵はチェック済み
    //公開鍵の重複チェック
    for (int lp = 0; lp < pubnum - 1; lp++) {
        const uint8_t *p1 = p_scriptsig->buf + pubpos + (1 + UCOIN_SZ_PUBKEY) * lp;
        for (int lp2 = lp + 1; lp2 < pubnum; lp2++) {
            const uint8_t *p2 = p_scriptsig->buf + pubpos + (1 + UCOIN_SZ_PUBKEY) * lp2;
            ret = (memcmp(p1, p2, 1 + UCOIN_SZ_PUBKEY) == 0);
            if (ret) {
                DBG_PRINTF("same pubkey(%d, %d)\n", lp, lp2);
                return false;
            }
        }
    }
    //署名チェック
    //      おそらくbitcoindでは、NG数が最短になるように配置される前提になっている。
    //      そうするため、署名に一致する-公開鍵が見つかった場合、次はその公開鍵より後ろを検索する。
    //          [SigA, SigB][PubA, PubB, PubC] ... OK
    //              SigA=PubA(NG 0回), SigB=PubB(NG 0回)
    //          [SigB, SigA][PubA, PubB, PubC] ... NG
    //              SigB=PubB(NG 1回), SigA=none(PubC以降しか検索しないため)
    int ok_cnt = 0;
    int ng_cnt = pubnum - signum;
    for (int lp = 0; lp < signum; lp++) {
        int pubpos_now = pubpos;
        for (int lp2 = 0; lp2 < pubnum; lp2++) {
            if ((chk_pos & (1 << lp2)) == 0) {
                //未チェック公開鍵
                const ucoin_buf_t sig = { p_scriptsig->buf + sigpos + 1, *(p_scriptsig->buf + sigpos) };
                ret = *(p_scriptsig->buf + pubpos_now) == UCOIN_SZ_PUBKEY;
                if (ret) {
                    ret = ucoin_tx_verify(&sig, pTxHash, p_scriptsig->buf + pubpos_now + 1);
                }
                if (ret) {
                    ok_cnt++;
                    chk_pos |= (1 << (lp2 + 1)) - 1;    //以下を全部1にする(NG最短)
                    DBG_PRINTF("   verify ok: sig=%d, pub=%d\n", lp, lp2);
                    break;
                } else {
                    ng_cnt--;
                    if (ng_cnt < 0) {
                        //NGとしてループを抜ける(NG最短)
                        ok_cnt = -1;
                        lp = signum;
                        break;
                    }
                }
            }
            pubpos_now += *(p_scriptsig->buf + pubpos_now) + 1;
        }
        sigpos += *(p_scriptsig->buf + sigpos) + 1;
    }
    DBG_PRINTF("ok_cnt=%d, ng_cnt=%d, signum=%d, pubnum=%d\n", ok_cnt, ng_cnt, signum, pubnum);

    return ok_cnt == signum;
}


bool ucoin_tx_verify_p2sh_spk(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const ucoin_buf_t *pScriptPk)
{
    bool ret = false;

    //P2SHのscriptPubKey
    //  HASH160 0x14 <20 bytes> EQUAL
    if (pScriptPk->len != 2 + UCOIN_SZ_PUBKEYHASH + 1) {
        assert(0);
        goto LABEL_EXIT;
    }
    if ( (pScriptPk->buf[0] != OP_HASH160) ||
         (pScriptPk->buf[1] != UCOIN_SZ_PUBKEYHASH) ||
         (pScriptPk->buf[2 + UCOIN_SZ_PUBKEYHASH] != OP_EQUAL) ) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret =  ucoin_tx_verify_multisig(pTx, Index, pTxHash, pScriptPk->buf + 2);

LABEL_EXIT:
    return ret;
}


bool ucoin_tx_verify_p2sh_addr(const ucoin_tx_t *pTx, int Index, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    int pref;
    bool ret = ucoin_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret && (pref == UCOIN_PREF_P2SH)) {
        ret = ucoin_tx_verify_multisig(pTx, Index, pTxHash, pkh);
    } else {
        ret = false;
    }

    return ret;
}


bool ucoin_tx_recover_pubkey(uint8_t *pPubKey, int RecId, const uint8_t *pRS, const uint8_t *pTxHash)
{
    if ((RecId < 0) || (3 < RecId)) {
        DBG_PRINTF("fail: invalid recid\n");
        return false;
    }

    return recover_pubkey(pPubKey, &RecId, pRS, pTxHash, NULL);
}


bool ucoin_tx_recover_pubkey_id(int *pRecId, const uint8_t *pPubKey, const uint8_t *pRS, const uint8_t *pTxHash)
{
    bool ret = false;
    uint8_t pub[UCOIN_SZ_PUBKEY];

    *pRecId = -1;       //負の数にすると自動で求める
    ret = recover_pubkey(pub, pRecId, pRS, pTxHash, pPubKey);
    if (!ret) {
        DBG_PRINTF("not pubkey\n");
    }

    return ret;
}


bool ucoin_tx_txid(uint8_t *pTxId, const ucoin_tx_t *pTx)
{
    ucoin_buf_t txbuf;

    bool ret = ucoin_util_create_tx(&txbuf, pTx, false);
    if (!ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ucoin_util_hash256(pTxId, txbuf.buf, txbuf.len);
    ucoin_buf_free(&txbuf);

LABEL_EXIT:
    return ret;
}


bool ucoin_tx_txid_raw(uint8_t *pTxId, const ucoin_buf_t *pTxRaw)
{
    ucoin_util_hash256(pTxId, pTxRaw->buf, pTxRaw->len);
    return true;
}


#ifdef UCOIN_USE_PRINTFUNC
void ucoin_print_tx(const ucoin_tx_t *pTx)
{
    FILE *fp = PRINTOUT;

    fprintf(fp, "======================================\n");
    uint8_t txid[UCOIN_SZ_TXID];
    ucoin_tx_txid(txid, pTx);
    fprintf(fp, "txid= ");
    ucoin_util_dumptxid(fp, txid);
    fprintf(fp, "\n");
    fprintf(fp, "======================================\n");
    fprintf(fp, " version:%u\n\n", pTx->version);
    fprintf(fp, " txin_cnt=%d\n", pTx->vin_cnt);
    for(int lp = 0; lp < pTx->vin_cnt; lp++) {
        fprintf(fp, " [vin #%d]\n", lp);
        fprintf(fp, "  txid= ");
        ucoin_util_dumptxid(fp, pTx->vin[lp].txid);
        fprintf(fp, "\n");
        fprintf(fp, "       LE: ");
        ucoin_util_dumpbin(fp, pTx->vin[lp].txid, UCOIN_SZ_TXID, true);
        fprintf(fp, "  index= %u\n", pTx->vin[lp].index);
        fprintf(fp, "  scriptSig[%d]= ", pTx->vin[lp].script.len);
        ucoin_util_dumpbin(fp, pTx->vin[lp].script.buf, pTx->vin[lp].script.len, true);
        ucoin_print_script(pTx->vin[lp].script.buf, pTx->vin[lp].script.len);
        //bool p2wsh = (pTx->vin[lp].script.len == 35) &&
        //             (pTx->vin[lp].script.buf[1] == 0x00) && (pTx->vin[lp].script.buf[2] == 0x20);
        bool p2wsh = (pTx->vin[lp].wit_cnt >= 3);
        fprintf(fp, "  sequence= 0x%08x\n\n", pTx->vin[lp].sequence);
        for(uint8_t lp2 = 0; lp2 < pTx->vin[lp].wit_cnt; lp2++) {
            fprintf(fp, "  witness[%d][%d]= ", lp2, pTx->vin[lp].witness[lp2].len);
            if(pTx->vin[lp].witness[lp2].len) {
                ucoin_util_dumpbin(fp, pTx->vin[lp].witness[lp2].buf, pTx->vin[lp].witness[lp2].len, true);
                if (p2wsh &&(lp2 == pTx->vin[lp].wit_cnt - 1)) {
                    //P2WSHの最後はwitnessScript
                    //nativeのP2WSHでも表示させたかったが、識別する方法が思いつかない
                    ucoin_print_script(pTx->vin[lp].witness[lp2].buf, pTx->vin[lp].witness[lp2].len);
                }
            } else {
                fprintf(fp, "<none>\n");
            }
        }
    }
    fprintf(fp, "\n txout_cnt= %d\n", pTx->vout_cnt);
    for(int lp = 0; lp < pTx->vout_cnt; lp++) {
        fprintf(fp, " [vout #%d]\n", lp);
        fprintf(fp, "  value= %llu  ( ", (unsigned long long)pTx->vout[lp].value);
        ucoin_util_dumpbin(fp, ((const uint8_t *)&pTx->vout[lp].value), sizeof(pTx->vout[lp].value), false);
        fprintf(fp, " )\n");
        fprintf(fp, "    %f mBTC, %f BTC\n", UCOIN_SATOSHI2MBTC(pTx->vout[lp].value), UCOIN_SATOSHI2BTC(pTx->vout[lp].value));
        ucoin_buf_t *buf = &(pTx->vout[lp].script);
        fprintf(fp, "  scriptPubKey[%d]= ", buf->len);
        ucoin_util_dumpbin(fp, buf->buf, buf->len, true);
        ucoin_print_script(buf->buf, buf->len);
        if ( (buf->len == 25) && (buf->buf[0] == 0x76) && (buf->buf[1] == 0xa9) &&
             (buf->buf[2] == 0x14) && (buf->buf[23] == 0x88) && (buf->buf[24] == 0xac) ) {
            char addr[UCOIN_SZ_ADDR_MAX];
            bool ret = ucoin_util_keys_pkh2addr(addr, &(buf->buf[3]), UCOIN_PREF_P2PKH);
            assert(ret);
            if (!ret) {
                return;
            }
            fprintf(fp, "    (%s)\n", addr);
        }
    }
    fprintf(fp, "\n locktime= 0x%08x : ", pTx->locktime);
    if (pTx->locktime < 500000000L) {
        //ブロック高
        fprintf(fp, "block height\n");
    } else {
        //epoch second
        time_t tm = pTx->locktime;
        fprintf(fp, "epoch second: %s\n", ctime(&tm));
    }
    fprintf(fp, "======================================\n");
}


void ucoin_print_rawtx(const uint8_t *pData, uint32_t Len)
{
    ucoin_tx_t tx;
    bool ret = ucoin_tx_read(&tx, pData, Len);
    if (!ret) {
        return;
    }

    ucoin_print_tx(&tx);

    ucoin_tx_free(&tx);
}


void ucoin_print_script(const uint8_t *pData, uint16_t Len)
{
    FILE *fp = PRINTOUT;

    const struct {
        uint8_t         op;
        const char      *name;
    } OP_DIC[] = {
        { OP_HASH160, "OP_HASH160" },
        { OP_EQUAL, "OP_EQUAL" },
        { OP_EQUALVERIFY, "OP_EQUALVERIFY" },
        { OP_CHECKSIG, "OP_CHECKSIG" },
        { OP_CHECKMULTISIG, "OP_CHECKMULTISIG" },
        { OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY" },
        { OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY" },
        { OP_DROP, "OP_DROP" },
        { OP_2DROP, "OP_2DROP" },
        { OP_DUP, "OP_DUP" },
        { OP_IF, "OP_IF" },
        { OP_NOTIF, "OP_NOTIF" },
        { OP_ELSE, "OP_ELSE" },
        { OP_ENDIF, "OP_ENDIF" },
        { OP_SWAP, "OP_SWAP" },
        { OP_ADD, "OP_ADD" },
        { OP_SIZE, "OP_SIZE" },
    };

    const uint8_t *end = pData + Len;
    const char INDENT[] = "      ";
    while (pData < end) {
        if (*pData <= 0x4b) {
            //スタックに載せる
            int len = *pData;
            fprintf(fp, "%s%02x ", INDENT, len);
            pData++;
            ucoin_util_dumpbin(fp, pData, len, true);
            pData += len;
        } else if ((OP_1 <= *pData) && (*pData <= OP_16)) {
            //OP_x
            fprintf(fp, "%s%02x [OP_%d]\n", INDENT, *pData, *pData - OP_x);
            pData++;
        } else if ((*pData == OP_PUSHDATA1) || (*pData == OP_PUSHDATA2)) {
            //スタックに載せる
            int len;
            if (*pData == OP_PUSHDATA1) {
                len = *(pData + 1);
                pData += 2;
            } else {
                len = *(pData + 1) | (*(pData + 2) << 8);
                pData += 3;
            }
            fprintf(fp, "%sOP_PUSHDATAx 0x%02x ", INDENT, len);
            ucoin_util_dumpbin(fp, pData, len, true);
            pData += len;
        } else {
            int op;
            for (op = 0; op < (int)ARRAY_SIZE(OP_DIC); op++) {
                if (*pData == OP_DIC[op].op) {
                    break;
                }
            }
            if (op != ARRAY_SIZE(OP_DIC)) {
                //知っているOP code
                fprintf(fp, "%s%02x [%s]\n", INDENT, OP_DIC[op].op, OP_DIC[op].name);
            } else {
                //unknown
                fprintf(fp, "%s%02x [??]\n", INDENT, *pData);
            }
            pData++;
        }
    }
}
#endif  //UCOIN_USE_PRINTFUNC


/**************************************************************************
 * private functions
 **************************************************************************/

/** BIP66署名データチェック
 *
 * @param[in]       sig         署名データ(HashType付き)
 * @param[in]       size        sigサイズ
 * @return      true:BIP66チェックOK
 *
 * @note
 *      - https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
 */
static bool is_valid_signature_encoding(const uint8_t *sig, uint16_t size)
{
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (size < 9) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }
    if (size > 73) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d - %02x)\n" ,__LINE__, sig[0]);
        return false;
    }

    // Make sure the length covers the entire signature.
    if (sig[1] != size - 3) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= size) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != size) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Zero-length integers are not allowed for R.
    if (lenR == 0) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Zero-length integers are not allowed for S.
    if (lenS == 0) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) {
        DBG_PRINTF("fail: is_valid_signature_encoding(%d)\n" ,__LINE__);
        return false;
    }

    return true;
}


/** 署名r/s
 *
 */
static int sign_rs(mbedtls_mpi *p_r, mbedtls_mpi *p_s, const uint8_t *pTxHash, const uint8_t *pPrivKey)
{
    int ret;
    mbedtls_ecp_keypair keypair;

    mbedtls_mpi_init(p_r);
    mbedtls_mpi_init(p_s);
    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);
    ret = mbedtls_mpi_read_binary(&keypair.d, pPrivKey, UCOIN_SZ_PRIVKEY);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }

    //canonizeするため、ecdsa.cのmbedtls_ecdsa_write_signature()をまねる
    ret = mbedtls_ecdsa_sign_det(&keypair.grp, p_r, p_s, &keypair.d,
                    pTxHash, UCOIN_SZ_HASH256, MBEDTLS_MD_SHA256);
    if (ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    mbedtls_mpi half_n;
    mbedtls_mpi_init(&half_n);
    mbedtls_mpi_copy(&half_n, &keypair.grp.N);
    mbedtls_mpi_shift_r(&half_n, 1);
    if (mbedtls_mpi_cmp_mpi(p_s, &half_n) == 1) {
        mbedtls_mpi_sub_mpi(p_s, &keypair.grp.N, p_s);
    }
    mbedtls_mpi_free(&half_n);

LABEL_EXIT:
    mbedtls_ecp_keypair_free(&keypair);

    return ret;
}


//署名canonize処理用(mbedtls ecdsa.cからコピー)
/*
 * Convert a signature (given by context) to ASN.1
 */
static int ecdsa_signature_to_asn1( const mbedtls_mpi *r, const mbedtls_mpi *s,
                                    unsigned char *sig, size_t *slen )
{
    int ret;        //MBEDTLS_ASN1_CHK_ADDで使用する
    unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, s ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_mpi( &p, buf, r ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( &p, buf, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( &p, buf,
                                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) );

    memcpy( sig, p, len );
    *slen = len;

    return( 0 );
}


/**
 * @param[out]  pPubKey
 * @param[out]  pRecId
 * @param[in]   pRS
 * @param[in]   pTxHash
 * @retval  true    成功
 */
static bool recover_pubkey(uint8_t *pPubKey, int *pRecId, const uint8_t *pRS, const uint8_t *pTxHash, const uint8_t *pOrgPubKey)
{
    bool bret = false;
    int ret;

    mbedtls_ecp_keypair keypair;
    mbedtls_mpi me;
    mbedtls_mpi r, s;
    mbedtls_mpi inv_r;
    mbedtls_mpi x;
    mbedtls_ecp_point R;
    mbedtls_ecp_point MR;
    mbedtls_ecp_point pub;

    mbedtls_ecp_keypair_init(&keypair);
    mbedtls_mpi_init(&me);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&inv_r);
    mbedtls_mpi_init(&x);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&MR);
    mbedtls_ecp_point_init(&pub);
    const mbedtls_ecp_point *pR[2] = { &R, &MR };
    int is_zero;

    mbedtls_ecp_group_load(&(keypair.grp), MBEDTLS_ECP_DP_SECP256K1);

    // 1.5
    //      e = Hash(M)
    //      me = -e
    ret = mbedtls_mpi_read_binary(&me, pTxHash, UCOIN_SZ_SIGHASH);
    assert(ret == 0);

    mbedtls_mpi zero;
    mbedtls_mpi_init(&zero);
    mbedtls_mpi_lset(&zero, 0);
    ret = mbedtls_mpi_sub_mpi(&me, &zero, &me);
    assert(ret == 0);
    ret = mbedtls_mpi_mod_mpi(&me, &me, &keypair.grp.N);
    assert(ret == 0);
    mbedtls_mpi_free(&zero);

    ret = mbedtls_mpi_read_binary(&r, pRS, UCOIN_SZ_FIELD);
    assert(ret == 0);
    ret = mbedtls_mpi_read_binary(&s, pRS + UCOIN_SZ_FIELD, UCOIN_SZ_FIELD);
    assert(ret == 0);

    //      inv_r = r^-1
    ret = mbedtls_mpi_inv_mod(&inv_r, &r, &keypair.grp.N);
    assert(ret == 0);

    int start_j;
    int start_k;
    if (*pRecId >= 0) {
        start_j = (*pRecId & 0x02) >> 1;
        start_k = *pRecId & 0x01;
    } else {
        start_j = 0;
        start_k = 0;
    }

    // Iのb1
    for (int j = start_j; j < 2; j++) {
        // 1.1
        //      x = r + jn
        mbedtls_mpi tmpx;
        mbedtls_mpi_init(&tmpx);
        ret = mbedtls_mpi_mul_int(&tmpx, &keypair.grp.N, j);
        assert(ret == 0);

        ret = mbedtls_mpi_add_mpi(&x, &r, &tmpx);
        assert(ret == 0);
        mbedtls_mpi_free(&tmpx);
        keypair.grp.modp(&x);

        // 1.3
        //      R = 02 || x
        uint8_t pubx[UCOIN_SZ_PUBKEY];
        pubx[0] = 0x02;
        ret = mbedtls_mpi_write_binary(&x, pubx + 1, UCOIN_SZ_FIELD);
        assert(ret == 0);
        ret = ucoin_util_ecp_point_read_binary2(&R, pubx);
        assert(ret == 0);

        // 1.6.3
        mbedtls_ecp_copy(&MR, &R);
        ret = mbedtls_mpi_sub_mpi(&MR.Y, &keypair.grp.P, &MR.Y);        // -R.Y = P - R.Yになる(mod P不要)
        assert(ret == 0);

        // 1.4
        //      error if nR != 0
        mbedtls_ecp_point nR;
        mbedtls_ecp_point_init(&nR);
        ret = mbedtls_ecp_mul(&keypair.grp, &nR, &keypair.grp.N, &R, NULL, NULL);
        is_zero = mbedtls_ecp_is_zero(&nR);
        mbedtls_ecp_point_free(&nR);
        if ((ret == 0) || !is_zero) {
            DBG_PRINTF2("[%d]1.4 error(ret=%04x)\n", j, ret);
            goto SKIP_LOOP;
        }

        // Iのb0
        for (int k = start_k; k < 2; k++) {
            // 1.6.1
            //      Q = r^-1 * (sR - eG)

            //      (sR - eG)
            ret = mbedtls_ecp_muladd(&keypair.grp, &pub, &s, pR[k], &me, &keypair.grp.G);
            assert(ret == 0);
            //      Q = r^-1 * Q
            ret = mbedtls_ecp_mul(&keypair.grp, &pub, &inv_r, &pub, NULL, NULL);
            assert(ret == 0);

            size_t sz;
            ret = mbedtls_ecp_point_write_binary(
                                &keypair.grp, &pub, MBEDTLS_ECP_PF_COMPRESSED,
                                &sz, pPubKey, UCOIN_SZ_PUBKEY);
            assert(ret == 0);

            if (ret == 0) {
                bret = ucoin_tx_verify_rs(pRS, pTxHash, pPubKey);
                if (bret && pOrgPubKey) {
                    bret = (memcmp(pOrgPubKey, pPubKey, UCOIN_SZ_PUBKEY) == 0);
                }
                if (bret) {
                    //DBG_PRINTF("recover= ");
                    //DUMPBIN(pPubKey, UCOIN_SZ_PUBKEY);
                    if (*pRecId < 0) {
                        *pRecId = (j << 1) | k;
                    }
                    j = 2;
                    k = 2;
                    break;
                } else {
                    //DBG_PRINTF("not match\n");
                }
            } else {
                DBG_PRINTF("fail\n");
            }
            if (*pRecId >= 0) {
                break;
            }
        }

SKIP_LOOP:
        if (*pRecId >= 0) {
            break;
        }
    }

    mbedtls_ecp_point_free(&pub);
    mbedtls_ecp_point_free(&MR);
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&inv_r);
    mbedtls_mpi_free(&me);
    mbedtls_ecp_keypair_free(&keypair);

    return bret;
}


/** varintのデータ長取得
 *
 * @param[out]      pPos        varint型のデータ長
 * @param[in]       pData       データ
 * @return      varint型のデータ長サイズ
 *
 * @note
 *      - #ucoin_util_get_varint_len()との違いに注意すること
 *      - データ長は0xFFFFまでしか対応しない
 */
static int get_varint(uint16_t *pLen, const uint8_t *pData)
{
    int retval;

    //varint型は大きい数字を扱えるが、ここでは2byte長までしか対応しない
    if (*pData < VARINT_3BYTE_MIN) {
        //1byte
        *pLen = (uint16_t)*pData;
        retval = 1;
    } else {
        //2byte
        *pLen = (uint16_t)(*(pData + 1) | (*(pData + 2) << 8));
        retval = 3;
    }

    return retval;
}


//static uint16_t get_le16(const uint8_t *pData)
//{
//    return (uint16_t)(*pData | (*(pData + 1) << 8));
//}


/** uint8[4](little endian)-->uint32
 *
 * @param[in]   pData       Little Endianデータ
 * @return      32bit値
 */
static uint32_t get_le32(const uint8_t *pData)
{
    return (uint32_t)(*pData | (*(pData + 1) << 8) | (*(pData + 2) << 16) | (*(pData + 3) << 24));
}


/** uint8[8](little endian)-->uint64
 *
 * @param[in]   pData       Little Endianデータ
 * @return      64bit値
 */
static uint64_t get_le64(const uint8_t *pData)
{
    return (uint64_t)(*pData | ((uint64_t)*(pData + 1) << 8)  |
                               ((uint64_t)*(pData + 2) << 16) | ((uint64_t)*(pData + 3) << 24) |
                               ((uint64_t)*(pData + 4) << 32) | ((uint64_t)*(pData + 5) << 40) |
                               ((uint64_t)*(pData + 6) << 48) | ((uint64_t)*(pData + 7) << 56));
}
