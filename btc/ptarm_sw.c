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
/** @file   ptarm_sw.c
 *  @brief  bitcoin処理: Segwitトランザクション生成関連
 *  @author ueno@nayuta.co
 */
#include "ptarm_local.h"


/**************************************************************************
 * public functions
 **************************************************************************/

void ptarm_sw_add_vout_p2wpkh_pub(ptarm_tx_t *pTx, uint64_t Value, const uint8_t *pPubKey)
{
    ptarm_util_add_vout_pub(pTx, Value, pPubKey, (mNativeSegwit) ? PTARM_PREF_NATIVE : PTARM_PREF_P2SH);
}


void ptarm_sw_add_vout_p2wpkh(ptarm_tx_t *pTx, uint64_t Value, const uint8_t *pPubKeyHash)
{
    ptarm_util_add_vout_pkh(pTx, Value, pPubKeyHash, (mNativeSegwit) ? PTARM_PREF_NATIVE : PTARM_PREF_P2SH);
}


void ptarm_sw_add_vout_p2wsh(ptarm_tx_t *pTx, uint64_t Value, const ptarm_buf_t *pWitScript)
{
    uint8_t wit_prog[LNL_SZ_WITPROG_WSH];

    ptarm_sw_wit2prog_p2wsh(wit_prog, pWitScript);
    if (mNativeSegwit) {
        ptarm_vout_t *vout = ptarm_tx_add_vout(pTx, Value);
        ptarm_buf_alloccopy(&vout->script, wit_prog, sizeof(wit_prog));
    } else {
        uint8_t pkh[PTARM_SZ_PUBKEYHASH];

        ptarm_util_hash160(pkh, wit_prog, sizeof(wit_prog));
        ptarm_tx_add_vout_p2sh(pTx, Value, pkh);
    }
}


void ptarm_sw_scriptcode_p2wpkh(ptarm_buf_t *pScriptCode, const uint8_t *pPubKey)
{
    const uint8_t HEAD[] = { 0x19, OP_DUP, OP_HASH160, PTARM_SZ_HASH160 };
    const uint8_t TAIL[] = { OP_EQUALVERIFY, OP_CHECKSIG };
    uint8_t pkh[PTARM_SZ_PUBKEYHASH];
    int pos = 0;

    ptarm_buf_alloc(pScriptCode, 1 + 0x19);
    memcpy(pScriptCode->buf, HEAD, sizeof(HEAD));
    pos += sizeof(HEAD);
    ptarm_util_hash160(pkh, pPubKey, PTARM_SZ_PUBKEY);
    memcpy(&(pScriptCode->buf[pos]), pkh, PTARM_SZ_HASH160);
    pos += PTARM_SZ_HASH160;
    memcpy(&(pScriptCode->buf[pos]), TAIL, sizeof(TAIL));
}


bool ptarm_sw_scriptcode_p2wpkh_vin(ptarm_buf_t *pScriptCode, const ptarm_vin_t *pVin)
{
    //P2WPKHのwitness
    //      0:<signature>
    //      1:<pubkey>
    if (pVin->wit_cnt != 2) {
        return false;
    }

    ptarm_sw_scriptcode_p2wpkh(pScriptCode, pVin->witness[1].buf);
    return true;
}


void ptarm_sw_scriptcode_p2wsh(ptarm_buf_t *pScriptCode, const ptarm_buf_t *pWit)
{
    ptarm_buf_alloc(pScriptCode, ptarm_util_get_varint_len(pWit->len) + pWit->len);
    uint8_t *p = pScriptCode->buf;
    p += ptarm_util_set_varint_len(p, NULL, pWit->len, false);
    memcpy(p, pWit->buf, pWit->len);
}


bool ptarm_sw_scriptcode_p2wsh_vin(ptarm_buf_t *pScriptCode, const ptarm_vin_t *pVin)
{
    //P2WSHのwitness
    //      0:OP_0
    //      1:data 1
    //      2:data 2
    //      ....
    //      n:witnessScript
    if (pVin->wit_cnt == 0) {
        return false;
    }

    ptarm_sw_scriptcode_p2wsh(pScriptCode, &pVin->witness[pVin->wit_cnt - 1]);
    return true;
}


void ptarm_sw_sighash(uint8_t *pTxHash, const ptarm_tx_t *pTx, int Index, uint64_t Value,
                const ptarm_buf_t *pScriptCode)
{
    // [transaction version : 4]
    // [hash_prevouts : 32]
    // [hash_sequence : 32]
    // [outpoint : 32 + 4]
    // [scriptcode : xx]
    // [amount : 8]
    // [sequence : 4]
    // [hash_outputs : 32]
    // [locktime : 4]
    // [hash_type : 4]

    ptarm_buf_t preimg;
    ptarm_buf_t hash_prevouts;
    ptarm_buf_t hash_sequence;
    ptarm_buf_t hash_outputs;

    ptarm_buf_alloc(&preimg, 156 + pScriptCode->len);
    uint8_t *p = preimg.buf;

    ptarm_vin_t *vin_now = &pTx->vin[Index];

    //version
    memcpy(p, &pTx->version, sizeof(pTx->version));
    p += sizeof(pTx->version);

    //vin:
    //  txid(32) + index(4)を連結した SHA256
    //  sequence(4)を連結した SHA256
    ptarm_buf_alloc(&hash_prevouts, pTx->vin_cnt * (32 + 4));
    ptarm_buf_alloc(&hash_sequence, pTx->vin_cnt * 4);
    uint8_t *p_prevouts = hash_prevouts.buf;
    uint8_t *p_sequence = hash_sequence.buf;
    for (uint32_t lp = 0; lp < pTx->vin_cnt; lp++) {
        ptarm_vin_t *vin = &pTx->vin[lp];

        //hash_prevouts
        memcpy(p_prevouts, vin->txid, sizeof(vin->txid));
        p_prevouts += sizeof(vin->txid);
        memcpy(p_prevouts, &vin->index, sizeof(vin->index));
        p_prevouts += sizeof(vin->index);

        //hash_sequence
        memcpy(p_sequence, &vin->sequence, sizeof(vin->sequence));
        p_sequence += sizeof(vin->sequence);
    }
    ptarm_util_hash256(p, hash_prevouts.buf, hash_prevouts.len);
    p += PTARM_SZ_HASH256;
    ptarm_util_hash256(p, hash_sequence.buf, hash_sequence.len);
    p += PTARM_SZ_HASH256;

    //output
    //  vin[nIn]の txidとIndexを連結
    memcpy(p, vin_now->txid, sizeof(vin_now->txid));
    p += sizeof(pTx->vin[Index].txid);
    memcpy(p, &vin_now->index, sizeof(vin_now->index));
    p += sizeof(pTx->vin[Index].index);

    //scriptcode
    memcpy(p, pScriptCode->buf, pScriptCode->len);
    p += pScriptCode->len;

    //amount
    memcpy(p, &Value, sizeof(Value));
    p += sizeof(Value);

    //sequence
    memcpy(p, &vin_now->sequence, sizeof(vin_now->sequence));
    p += sizeof(vin_now->sequence);

    //vout:
    //  amountも含めtxoutを連結した SHA256
    int len = 0;
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        len += pTx->vout[lp].script.len;
    }
    ptarm_buf_alloc(&hash_outputs, pTx->vout_cnt * (8 + 1) + len);
    uint8_t *p_outputs = hash_outputs.buf;
    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        ptarm_vout_t *vout = &pTx->vout[lp];

        memcpy(p_outputs, &vout->value, sizeof(vout->value));
        p_outputs += sizeof(vout->value);
        *p_outputs = vout->script.len;
        p_outputs++;
        memcpy(p_outputs, vout->script.buf, vout->script.len);
        p_outputs += vout->script.len;
    }
    ptarm_util_hash256(p, hash_outputs.buf, hash_outputs.len);
    p += PTARM_SZ_HASH256;

    //locktime
    memcpy(p, &pTx->locktime, sizeof(pTx->locktime));
    p += sizeof(pTx->locktime);

    //hash type = 0x00000001
    uint32_t hashtype = 1;
    memcpy(p, &hashtype, sizeof(hashtype));
    //p += sizeof(hashtype);

    ptarm_util_hash256(pTxHash, preimg.buf, preimg.len);

    ptarm_buf_free(&hash_outputs);
    ptarm_buf_free(&hash_sequence);
    ptarm_buf_free(&hash_prevouts);
    ptarm_buf_free(&preimg);
}


bool ptarm_sw_set_vin_p2wpkh(ptarm_tx_t *pTx, int Index, const ptarm_buf_t *pSig, const uint8_t *pPubKey)
{
    //P2WPKH:
    //witness
    //  item[0]=sig
    //  item[1]=pubkey

    ptarm_vin_t *vin = &(pTx->vin[Index]);
    ptarm_buf_t *p_buf = &vin->script;

    if (p_buf->len != 0) {
        ptarm_buf_free(p_buf);
    }

    if (mNativeSegwit) {
        //vin
        //  空
    } else {
        //vin
        //  len + <witness program>
        p_buf->len = 3 + PTARM_SZ_HASH160;
        p_buf->buf = (uint8_t *)M_REALLOC(p_buf->buf, p_buf->len);
        p_buf->buf[0] = 0x16;
        //witness program
        p_buf->buf[1] = 0x00;
        p_buf->buf[2] = (uint8_t)PTARM_SZ_HASH160;
        ptarm_util_hash160(&p_buf->buf[3], pPubKey, PTARM_SZ_PUBKEY);
    }

    if (vin->wit_cnt != 0) {
        //一度解放する
        for (uint32_t lp = 0; lp < vin->wit_cnt; lp++) {
            ptarm_buf_free(&vin->witness[lp]);
        }
        vin->wit_cnt = 0;
    }
    //[0]signature
    ptarm_buf_t *p_sig = ptarm_tx_add_wit(vin);
    ptarm_buf_alloccopy(p_sig, pSig->buf, pSig->len);
    //[1]pubkey
    ptarm_buf_t *p_pub = ptarm_tx_add_wit(vin);
    ptarm_buf_alloccopy(p_pub, pPubKey, PTARM_SZ_PUBKEY);
    return true;
}


bool ptarm_sw_set_vin_p2wsh(ptarm_tx_t *pTx, int Index, const ptarm_buf_t *pWits[], int Num)
{
    //P2WSH:
    //vin
    //  len + <witness program>
    //witness
    //  パターンが固定できないので、pWitsに作ってあるものをそのまま載せる。
    ptarm_vin_t *vin = &(pTx->vin[Index]);
    ptarm_buf_t *p_buf = &vin->script;

    if(mNativeSegwit) {
        //vin
        //  空
    } else {
        //vin
        //  len + <witness program>
        p_buf->len = 3 + PTARM_SZ_HASH256;
        p_buf->buf = (uint8_t *)M_REALLOC(p_buf->buf, p_buf->len);
        p_buf->buf[0] = 0x22;
        //witness program
        p_buf->buf[1] = 0x00;
        p_buf->buf[2] = (uint8_t)PTARM_SZ_HASH256;
        //witnessScriptのSHA256値
        //  witnessScriptは一番最後に置かれる
        ptarm_util_sha256(p_buf->buf + 3, pWits[Num - 1]->buf, pWits[Num - 1]->len);
    }

    if (vin->wit_cnt != 0) {
        //一度解放する
        for (uint32_t lp = 0; lp < vin->wit_cnt; lp++) {
            ptarm_buf_free(&vin->witness[lp]);
        }
        vin->wit_cnt = 0;
    }
    for (int lp = 0; lp < Num; lp++) {
        ptarm_buf_t *p = ptarm_tx_add_wit(vin);
        ptarm_buf_alloccopy(p, pWits[lp]->buf, pWits[lp]->len);
    }
    return true;
}


bool ptarm_sw_verify_p2wpkh(const ptarm_tx_t *pTx, int Index, uint64_t Value, const uint8_t *pPubKeyHash)
{
    ptarm_vin_t *vin = &(pTx->vin[Index]);
    if (vin->wit_cnt != 2) {
        //P2WPKHのwitness itemは2
        return false;
    }

    const ptarm_buf_t *p_sig = &vin->witness[0];
    const ptarm_buf_t *p_pub = &vin->witness[1];

    if (p_pub->len != PTARM_SZ_PUBKEY) {
        return false;
    }

    ptarm_buf_t script_code;
    ptarm_sw_scriptcode_p2wpkh(&script_code, p_pub->buf);

    uint8_t txhash[PTARM_SZ_HASH256];
    ptarm_sw_sighash(txhash, pTx, Index, Value, &script_code);

    bool ret = ptarm_tx_verify(p_sig, txhash, p_pub->buf);
    if (ret) {
        //pubKeyHashチェック
        uint8_t pkh[PTARM_SZ_PUBKEYHASH];

        ptarm_util_hash160(pkh, p_pub->buf, PTARM_SZ_PUBKEY);
        if (!mNativeSegwit) {
            ptarm_util_create_pkh2wpkh(pkh, pkh);
        }
        ret = (memcmp(pkh, pPubKeyHash, PTARM_SZ_HASH160) == 0);
    }

    ptarm_buf_free(&script_code);

    return ret;
}


bool ptarm_sw_verify_p2wpkh_addr(const ptarm_tx_t *pTx, int Index, uint64_t Value, const char *pAddr)
{
    bool ret;
    uint8_t pkh[PTARM_SZ_PUBKEYHASH];

    int pref;
    ret = ptarm_keys_addr2pkh(pkh, &pref, pAddr);
    if (ret) {
        ret = ptarm_sw_verify_p2wpkh(pTx, Index, Value, pkh);
    }

    return ret;
}


bool ptarm_sw_verify_2of2(const ptarm_tx_t *pTx, int Index, const uint8_t *pTxHash, const ptarm_buf_t *pVout)
{
    if (pTx->vin[Index].wit_cnt != 4) {
        //2-of-2は4項目
        LOGD("items not 4.n");
        return false;
    }

    ptarm_buf_t *wits = pTx->vin[Index].witness;
    ptarm_buf_t *wit;

    //このvinはP2SHの予定
    //      1. 前のvoutのpubKeyHashが、redeemScriptから計算したpubKeyHashと一致するか確認
    //      2. 署名チェック
    //
    //  none
    //  <署名1>
    //  <署名2>
    //  redeemScript

    //none
    wit = &wits[0];
    if (wit->len != 0) {
        LOGD("top isnot none\n");
        return false;
    }

    //署名
    const ptarm_buf_t *sig1 = &wits[1];
    if ((sig1->len == 0) || (sig1->buf[sig1->len - 1] != SIGHASH_ALL)) {
        //SIGHASH_ALLではない
        LOGD("SIG1: not SIGHASH_ALL\n");
        return false;
    }
    const ptarm_buf_t *sig2 = &wits[2];
    if ((sig2->len == 0) || (sig2->buf[sig2->len - 1] != SIGHASH_ALL)) {
        //SIGHASH_ALLではない
        LOGD("SIG2: not SIGHASH_ALL\n");
        return false;
    }

    //witnessScript
    wit = &wits[3];
    if (wit->len != 71) {
        //2-of-2 witnessScriptのサイズではない
        LOGD("witScript: invalid length: %u\n", wit->len);
        return false;
    }
    const uint8_t *p = wit->buf;
    if ( (*p != OP_2) || (*(p + 1) != PTARM_SZ_PUBKEY) || (*(p + 35) != PTARM_SZ_PUBKEY) ||
         (*(p + 69) != OP_2) || (*(p + 70) != OP_CHECKMULTISIG) ) {
        //2-of-2のredeemScriptではない
        LOGD("witScript: invalid script\n");
        LOGD("1: %d\n", (*p != OP_2));
        LOGD("2: %d\n", (*(p + 1) != PTARM_SZ_PUBKEY));
        LOGD("3: %d\n", (*(p + 35) != PTARM_SZ_PUBKEY));
        LOGD("4: %d\n", (*(p + 69) != OP_2));
        LOGD("5: %d\n", (*(p + 70) != OP_CHECKMULTISIG));
        return false;
    }
    const uint8_t *pub1 = p + 2;
    const uint8_t *pub2 = p + 36;

    //pubkeyhashチェック
    //  native segwit
    //      00 [len] [pubkeyHash/scriptHash]
    if (pVout->buf[0] != 0x00) {
        LOGD("invalid previous vout(not native segwit)\n");
        return false;
    }
    if (pVout->buf[1] == PTARM_SZ_HASH256) {
        //native P2WSH
        uint8_t pkh[PTARM_SZ_SHA256];
        ptarm_util_sha256(pkh, wit->buf, wit->len);
        bool ret = (memcmp(pkh, &pVout->buf[2], PTARM_SZ_SHA256) == 0);
        if (!ret) {
            LOGD("pubkeyhash mismatch.\n");
            return false;
        }
    } else {
        LOGD("invalid previous vout length(not P2WSH)\n");
        return false;
    }

    //署名チェック
    //      2-of-2なので、順番通りに全一致
#if 1
    bool ret = ptarm_tx_verify(sig1, pTxHash, pub1);
    if (ret) {
        ret = ptarm_tx_verify(sig2, pTxHash, pub2);
        if (!ret) {
            LOGD("fail: ptarm_tx_verify(sig2)\n");
        }
    } else {
        LOGD("fail: ptarm_tx_verify(sig1)\n");
    }
#else
    bool ret1 = ptarm_tx_verify(sig1, pTxHash, pub1);
    bool ret2 = ptarm_tx_verify(sig2, pTxHash, pub2);
    bool ret3 = ptarm_tx_verify(sig1, pTxHash, pub2);
    bool ret4 = ptarm_tx_verify(sig2, pTxHash, pub1);
    bool ret = ret1 && ret2;
    printf("txhash=");
    DUMPD(pTxHash, PTARM_SZ_SIGHASH);
    printf("ret1=%d\n", ret1);
    printf("ret2=%d\n", ret2);
    printf("ret3=%d\n", ret3);
    printf("ret4=%d\n", ret4);
#endif

    return ret;
}


#if 0   //今のところ使い道がない
/** WTXID計算
 *
 * @param[out]  pWTxId      計算結果(Little Endian)
 * @param[in]   pTx         対象トランザクション
 *
 * @note
 *      - pWTxIdにはLittleEndianで出力される
 */
bool ptarm_sw_wtxid(uint8_t *pWTxId, const ptarm_tx_t *pTx)
{
    ptarm_buf_t txbuf;

    if (!ptarm_sw_is_segwit(pTx)) {
        assert(0);
        return false;
    }

    bool ret = ptarm_util_create_tx(&txbuf, pTx, true);
    if (!ret) {
        assert(0);
        goto LABEL_EXIT;
    }
    ptarm_util_hash256(pWTxId, txbuf.buf, txbuf.len);
    ptarm_buf_free(&txbuf);

LABEL_EXIT:
    return ret;
}


bool ptarm_sw_is_segwit(const ptarm_tx_t *pTx)
{
    bool ret = false;

    for (int lp = 0; lp < pTx->vin_cnt; lp++) {
        if (pTx->vin[lp].wit_cnt > 0) {
            ret = true;
            break;
        }
    }

    return ret;
}
#endif


void ptarm_sw_wit2prog_p2wsh(uint8_t *pWitProg, const ptarm_buf_t *pWitScript)
{
    pWitProg[0] = 0x00;
    pWitProg[1] = PTARM_SZ_SHA256;
    ptarm_util_sha256(pWitProg + 2, pWitScript->buf, pWitScript->len);
}
