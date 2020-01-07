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
/** @file   btc_script.c
 *  @brief  btc_script
 */
#ifdef PTARM_USE_PRINTFUNC
#endif  //PTARM_USE_PRINTFUNC

#include "utl_dbg.h"
#include "utl_time.h"
#include "utl_int.h"

#include "btc_local.h"
#include "btc_crypto.h"
#include "btc_segwit_addr.h"
#include "btc_sig.h"
#include "btc_script.h"
#include "btc_tx_buf.h"


/**************************************************************************
 * typedefs
 **************************************************************************/


/**************************************************************************
 * prototypes
 **************************************************************************/

static void create_scriptpk_p2pkh(uint8_t *p, const uint8_t *pHash);
static void create_scriptpk_p2sh(uint8_t *p, const uint8_t *pHash);
static void create_scriptpk_p2wpkh(uint8_t *p, const uint8_t *pHash);
static void create_scriptpk_p2wsh(uint8_t *p, const uint8_t *pHash);

static utl_buf_t *add_wit_item(utl_buf_t **ppWitness, uint32_t *pWitItemCnt);
static void free_witness(utl_buf_t **ppWitness, uint32_t *pWitItemCnt);

static btc_script_pubkey_order_t pubkey_order_2of2(const uint8_t *pPubKey1, const uint8_t *pPubKey2);


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_script_scriptpk_create(utl_buf_t *pScriptPk, const uint8_t *pHash, int Prefix)
{
    switch (Prefix) {
    case BTC_PREF_P2PKH:
        //LOGD("BTC_PREF_P2PKH\n");
        if (!utl_buf_realloc(pScriptPk, 3 + BTC_SZ_HASH160 + 2)) return false;
        create_scriptpk_p2pkh(pScriptPk->buf, pHash);
        break;
    case BTC_PREF_P2SH:
        //LOGD("BTC_PREF_P2SH\n");
        if (!utl_buf_realloc(pScriptPk, 2 + BTC_SZ_HASH160 + 1)) return false;
        create_scriptpk_p2sh(pScriptPk->buf, pHash);
        break;
    case BTC_PREF_P2WPKH:
        //LOGD("BTC_PREF_P2WPKH\n");
        if (!utl_buf_realloc(pScriptPk, 2 + BTC_SZ_HASH160)) return false;
        create_scriptpk_p2wpkh(pScriptPk->buf, pHash);
        break;
    case BTC_PREF_P2WSH:
        //LOGD("BTC_PREF_P2WSH\n");
        if (!utl_buf_realloc(pScriptPk, 2 + BTC_SZ_HASH256)) return false;
        create_scriptpk_p2wsh(pScriptPk->buf, pHash);
        break;
    default:
        assert(false);
        return false;
    }
    return true;
}


bool btc_script_p2pkh_create_scriptsig(utl_buf_t *pScriptSig, const utl_buf_t *pSig, const uint8_t *pPubKey)
{
    if (!pSig->len) return false;

    if (!utl_buf_realloc(pScriptSig, 1 + pSig->len + 1 + BTC_SZ_PUBKEY)) return false;

    uint8_t *p = pScriptSig->buf;
    *p++ = pSig->len;
    memcpy(p, pSig->buf, pSig->len);
    p += pSig->len;
    *p++ = BTC_SZ_PUBKEY;
    memcpy(p, pPubKey, BTC_SZ_PUBKEY);
    return true;
}


bool btc_script_p2sh_multisig_create_scriptsig(utl_buf_t *pScriptSig, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem)
{
    //XXX: should use push opcode 0x01-0x4b
    assert(false);
    return false;

    if (!Num) return false;
    if (!pRedeem->len) return false;

    /*
     * OP_0
     * (sig-len + sig) * num
     * OP_PUSHDATAx
     * redeemScript-len
     * redeemScript
     */
    uint16_t len = 1 + Num + 1 + 1 + pRedeem->len;
    if (pRedeem->len >> 8) {
        len++;
    }
    for (int lp = 0; lp < Num; lp++) {
         len += pSigs[lp]->len;
    }
    if (!utl_buf_realloc(pScriptSig, len)) return false;
    uint8_t *p = pScriptSig->buf;

    *p++ = OP_0;
    for (int lp = 0; lp < Num; lp++) {
        *p++ = pSigs[lp]->len;
        memcpy(p, pSigs[lp]->buf, pSigs[lp]->len);
        p += pSigs[lp]->len;
    }
    if (pRedeem->len >> 8) { //XXX:
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


bool btc_script_p2sh_p2wpkh_create_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pPubKey)
{
    if (!utl_buf_realloc(pScriptSig, 1 + 1 + 1 + BTC_SZ_HASH160)) return false;

    uint8_t *p = pScriptSig->buf;
    //len + <witness program>
    *p++ = 0x16;
    //witness program
    *p++ = 0x00;
    *p++ = (uint8_t)BTC_SZ_HASH160;
    btc_md_hash160(p, pPubKey, BTC_SZ_PUBKEY);
    return true;
}


bool btc_script_p2sh_p2wsh_create_scriptsig(utl_buf_t *pScriptSig, const utl_buf_t *pWitScript)
{
    if (!utl_buf_realloc(pScriptSig, 1 + 1 + 1 + BTC_SZ_HASH256)) return false;

    uint8_t *p = pScriptSig->buf;
    //len + <witness program>
    *p++ = 0x22;
    //witness program
    *p++ = 0x00;
    *p++ = (uint8_t)BTC_SZ_HASH256;
    btc_md_sha256(p, pWitScript->buf, pWitScript->len);
    return true;
}


bool btc_script_p2wsh_create_scriptpk(utl_buf_t *pScriptPk, const utl_buf_t *pWitScript)
{
    if (!utl_buf_realloc(pScriptPk, 1 + 1 + BTC_SZ_HASH256)) return false;

    uint8_t *p = pScriptPk->buf;
    *p++ = 0x00;
    *p++ = (uint8_t)BTC_SZ_HASH256;
    btc_md_sha256(p, pWitScript->buf, pWitScript->len);
    return true;
}


bool btc_script_p2pkh_sign_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey)
{
    assert(pPubKey);

    bool ret = false;
    utl_buf_t sigbuf = UTL_BUF_INIT;

    if (!btc_sig_sign(&sigbuf, pTxHash, pPrivKey)) goto LABEL_EXIT;
    if (!btc_script_p2pkh_create_scriptsig(pScriptSig, &sigbuf, pPubKey)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    utl_buf_free(&sigbuf);

    return ret;
}


bool btc_script_p2pkh_verify_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
{
    //scriptSig(P2PSH): <sig> <pubKey>

    bool ret = false;

    uint8_t *buf = pScriptSig->buf;

    uint32_t sig_len;
    const uint8_t *sig;
    uint32_t pubkey_len;
    uint8_t *pubkey;

    if (pScriptSig->len < 1) goto LABEL_EXIT;
    sig_len = *buf;
    sig = buf + 1;
    if (sig_len < OP_X_PUSHDATA_MIN) goto LABEL_EXIT;
    if (sig_len > OP_X_PUSHDATA_MAX) goto LABEL_EXIT;
    if (pScriptSig->len < 1 + sig_len + 1) goto LABEL_EXIT;
    pubkey_len = *(buf + 1 + sig_len);
    pubkey = buf + 1 + sig_len + 1;
    if (pubkey_len != BTC_SZ_PUBKEY) goto LABEL_EXIT;
    if (pScriptSig->len != 1 + sig_len + 1 + pubkey_len) goto LABEL_EXIT;

    uint8_t pkh[BTC_SZ_HASH160];
    btc_md_hash160(pkh, pubkey, BTC_SZ_PUBKEY);
    if (memcmp(pkh, pPubKeyHash, BTC_SZ_HASH160)) goto LABEL_EXIT;

    if (!btc_sig_verify_2(sig, sig_len, pTxHash, pubkey)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    return ret;
}


bool btc_script_p2pkh_verify_scriptsig_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    //scriptPubKey(P2PKH): DUP HASH160 0x14 <20 bytes> EQUALVERIFY CHECKSIG

    bool ret = false;

    if (pScriptPk->len != 3 + BTC_SZ_HASH160 + 2) {
        assert(0);
        goto LABEL_EXIT;
    }
    if ( (pScriptPk->buf[0] != OP_DUP) ||
         (pScriptPk->buf[1] != OP_HASH160) ||
         (pScriptPk->buf[2] != BTC_SZ_HASH160) ||
         (pScriptPk->buf[3 + BTC_SZ_HASH160] != OP_EQUALVERIFY) ||
         (pScriptPk->buf[3 + BTC_SZ_HASH160 + 1] != OP_CHECKSIG) ) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret =  btc_script_p2pkh_verify_scriptsig(pScriptSig, pTxHash, pScriptPk->buf + 3);

LABEL_EXIT:
    return ret;
}


bool btc_script_p2sh_multisig_verify_scriptsig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pScriptHash)
{
    //XXX: should impl stack operation
    //XXX: can't parse push opcode 0x01-0x4b
    assert(false);
    return false;

    const uint8_t *p = pScriptSig->buf;

    //このvinはP2SHの予定
    //      1. 前のvoutのscriptHashが、redeemScriptから計算したscriptHashと一致するか確認
    //      2. 署名チェック
    //
    //  OP_0
    //  <署名> x いくつか
    //  <OP_PUSHDATAx>
    //  pushデータ長
    //  redeemScript
    if (*p != OP_0) {
        LOGE("top isnot OP_0\n");
        return false;
    }

    //署名数取得
    int signum = 0;
    int sigpos = 1;     //OP_0の次
    uint32_t pos = 1;
    uint8_t op_pushdata;
    while (pos < pScriptSig->len) {
        uint8_t len = *(p + pos);
        if ((len == OP_PUSHDATA1) || (len == OP_PUSHDATA2)) { //XXX:
            op_pushdata = len;
            pos++;
            break;
        }
        signum++;
        pos += 1 + len;
    }
    if (pos >= pScriptSig->len) {
        LOGE("no OP_PUSHDATAx(sign)\n");
        return false;
    }
    uint16_t redm_len;  //OP_PUSHDATAxの引数
    if (op_pushdata == OP_PUSHDATA1) {
        redm_len = (uint16_t)*(p + pos);
        pos++;
    } else if (op_pushdata == OP_PUSHDATA2) {
        redm_len = (uint16_t)(*(p + pos) | (*(p + pos + 1) << 8));
        pos += 2;
    } else {
        LOGE("no OP_PUSHDATA-1or2\n");
        return false;
    }
    if (pScriptSig->len != pos + redm_len) {
        LOGE("invalid len\n");
        return false;
    }
    if (signum != (*(p + pos) - OP_X)) {
        LOGE("OP_X mismatch(sign): signum=%d, OP_X=%d\n", signum, *(p + pos) - OP_X);
        return false;
    }
    pos++;
    //公開鍵数取得
    int pubnum = 0;
    int pubpos = pos;
    while (pos < pScriptSig->len) {
        uint8_t len = *(p + pos);
        if ((OP_1 <= len) && (len <= OP_16)) {
            break;
        }
        if (len != BTC_SZ_PUBKEY) {
            LOGE("invalid pubkey len(%d)\n", len);
            return false;
        }
        pubnum++;
        pos += 1 + len;
    }
    if (pos >= pScriptSig->len) {
        LOGE("no OP_PUSHDATAx(pubkey)\n");
        return false;
    }
    if (pubnum != (*(p + pos) - OP_X)) {
        LOGE("OP_X mismatch(pubkey): signum=%d, OP_X=%d\n", pubnum, *(p + pos) - OP_X);
        return false;
    }
    pos++;
    if (*(p + pos) != OP_CHECKMULTISIG) {
        LOGE("not OP_CHECKMULTISIG\n");
        return false;
    }
    pos++;
    if (pos != pScriptSig->len) {
        LOGE("invalid data length\n");
        return false;
    }

    //scripthashチェック
    uint8_t sh[BTC_SZ_HASH_MAX];
    btc_md_hash160(sh, pScriptSig->buf + pubpos - 1, pScriptSig->len - pubpos + 1);
    bool ret = (memcmp(sh, pScriptHash, BTC_SZ_HASH160) == 0);
    if (!ret) {
        LOGE("scripthash mismatch.\n");
        return false;
    }

    //公開鍵の重複チェック
    for (int lp = 0; lp < pubnum - 1; lp++) {
        const uint8_t *p1 = pScriptSig->buf + pubpos + (1 + BTC_SZ_PUBKEY) * lp;
        for (int lp2 = lp + 1; lp2 < pubnum; lp2++) {
            const uint8_t *p2 = pScriptSig->buf + pubpos + (1 + BTC_SZ_PUBKEY) * lp2;
            ret = (memcmp(p1, p2, 1 + BTC_SZ_PUBKEY) == 0);
            if (ret) {
                LOGE("same pubkey(%d, %d)\n", lp, lp2);
                return false;
            }
        }
    }

    //署名チェック
    // signum分のverifyが成功すればOK（満たした時点で抜けていい？）
    // 許容される最大のverify失敗の数はpubnum - signum。それを即座に超えると抜けてNGとする
    //
    // ??? おそらくbitcoindでは、NG数が最短になるように配置される前提になっている。
    //     そうするため、署名に一致する-公開鍵が見つかった場合、次はその公開鍵より後ろを検索する。
    //         [SigA, SigB][PubA, PubB, PubC] ... OK
    //             SigA=PubA(NG 0回), SigB=PubB(NG 0回)
    //         [SigB, SigA][PubA, PubB, PubC] ... NG
    // ???         SigB=PubB(NG 1回), SigA=none(PubC以降しか検索しないため)
    uint32_t chk_pos = 0;   //bitが立った公開鍵はチェック済み
    int ok_cnt = 0;
    int ng_cnt = pubnum - signum;
    for (int lp = 0; lp < signum; lp++) {
        int pubpos_now = pubpos;
        for (int lp2 = 0; lp2 < pubnum; lp2++) {
            if ((chk_pos & (1 << lp2)) == 0) {
                //未チェック公開鍵
                const utl_buf_t sig = { pScriptSig->buf + sigpos + 1, *(pScriptSig->buf + sigpos) };
                ret = *(pScriptSig->buf + pubpos_now) == BTC_SZ_PUBKEY;
                if (ret) {
                    ret = btc_sig_verify(&sig, pTxHash, pScriptSig->buf + pubpos_now + 1);
                }
                if (ret) {
                    ok_cnt++;
                    chk_pos |= (1 << (lp2 + 1)) - 1;    //以下を全部1にする(NG最短)
                    LOGD("   verify ok: sig=%d, pub=%d\n", lp, lp2);
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
            pubpos_now += *(pScriptSig->buf + pubpos_now) + 1;
        }
        sigpos += *(pScriptSig->buf + sigpos) + 1;
    }
    LOGD("ok_cnt=%d, ng_cnt=%d, signum=%d, pubnum=%d\n", ok_cnt, ng_cnt, signum, pubnum);

    return ok_cnt == signum;
}


bool btc_script_p2sh_multisig_verify_scriptsig_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    bool ret = false;

    //P2SHのscriptPubKey(P2SH): HASH160 0x14 <20 bytes> EQUAL
    if (pScriptPk->len != 2 + BTC_SZ_HASH160 + 1) {
        assert(0);
        goto LABEL_EXIT;
    }
    if ( (pScriptPk->buf[0] != OP_HASH160) ||
         (pScriptPk->buf[1] != BTC_SZ_HASH160) ||
         (pScriptPk->buf[2 + BTC_SZ_HASH160] != OP_EQUAL) ) {
        assert(0);
        goto LABEL_EXIT;
    }

    ret =  btc_script_p2sh_multisig_verify_scriptsig(pScriptSig, pTxHash, pScriptPk->buf + 2);

LABEL_EXIT:
    return ret;
}


bool btc_script_2of2_create_redeem(utl_buf_t *pRedeem, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    if (!utl_buf_realloc(pRedeem, BTC_SZ_2OF2)) return false;

    uint8_t *p = pRedeem->buf;

    /*
     * OP_2
     * 0x21 (pubkey1[0x21])
     * 0x21 (pubkey2[0x21])
     * OP_2
     * OP_CHECKMULTISIG
     */
    *p++ = OP_2;
    *p++ = (uint8_t)BTC_SZ_PUBKEY;
    memcpy(p, pPubKey1, BTC_SZ_PUBKEY);
    p += BTC_SZ_PUBKEY;
    *p++ = (uint8_t)BTC_SZ_PUBKEY;
    memcpy(p, pPubKey2, BTC_SZ_PUBKEY);
    p += BTC_SZ_PUBKEY;
    *p++ = OP_2;
    *p++ = OP_CHECKMULTISIG;
    return true;
}


bool btc_script_2of2_create_redeem_sorted(utl_buf_t *pRedeem, btc_script_pubkey_order_t *pOrder, const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    *pOrder = pubkey_order_2of2(pPubKey1, pPubKey2);
    if (*pOrder == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
        return btc_script_2of2_create_redeem(pRedeem, pPubKey1, pPubKey2);
    } else {
        return btc_script_2of2_create_redeem(pRedeem, pPubKey2, pPubKey1);
    }
}


bool btc_script_p2sh_multisig_create_redeem(utl_buf_t *pRedeem, const uint8_t *pPubKeys[], uint8_t Num, uint8_t M)
{
    if (Num > 16) return false;
    if (M > 16) return false;
    if (M > Num) return false;

    if (!utl_buf_realloc(pRedeem, 3 + Num * (BTC_SZ_PUBKEY + 1))) return false;

    uint8_t *p = pRedeem->buf;

    /*
     * OP_n
     * 0x21 (pubkey1[0x21])
     *   ...
     * 0x21 (pubkeyn[0x21])
     * OP_m
     * OP_CHECKMULTISIG
     */
    *p++ = OP_X + M;
    for (int lp = 0; lp < Num; lp++) {
        *p++ = (uint8_t)BTC_SZ_PUBKEY;
        memcpy(p, pPubKeys[lp], BTC_SZ_PUBKEY);
        p += BTC_SZ_PUBKEY;
    }
    *p++ = OP_X + Num;
    *p++ = OP_CHECKMULTISIG;
    return true;
}


bool btc_script_p2sh_p2wpkh_create_redeem(utl_buf_t *pRedeem, const uint8_t *pPubKey)
{
    uint8_t pkh[BTC_SZ_HASH160];
    btc_md_hash160(pkh, pPubKey, BTC_SZ_PUBKEY);
    return btc_script_p2sh_p2wpkh_create_redeem_pkh(pRedeem, pkh);
}


bool btc_script_p2sh_p2wpkh_create_redeem_pkh(utl_buf_t *pRedeem, const uint8_t *pPubKeyHash)
{
    if (!utl_buf_realloc(pRedeem, 1 + 1 + BTC_SZ_HASH160)) return false;

    uint8_t *p = pRedeem->buf;

    *p++ = OP_0;
    *p++ = (uint8_t)BTC_SZ_HASH160;
    memcpy(p, pPubKeyHash, BTC_SZ_HASH160);
    return true;
}


bool btc_script_p2sh_p2wpkh_create_scripthash_pkh(uint8_t *pScriptHash, const uint8_t *pPubKeyHash)
{
    utl_buf_t redeem = UTL_BUF_INIT;
    if (!btc_script_p2sh_p2wpkh_create_redeem_pkh(&redeem, pPubKeyHash)) return false;
    btc_md_hash160(pScriptHash, redeem.buf, redeem.len);
    utl_buf_free(&redeem);
    return true;
}


bool btc_script_p2wpkh_create_witness(utl_buf_t **ppWitness, uint32_t *pWitItemCnt, const utl_buf_t *pSig, const uint8_t *pPubKey)
{
    free_witness(ppWitness, pWitItemCnt);

    utl_buf_t *p = add_wit_item(ppWitness, pWitItemCnt);
    if (!p) return false;
    if (!utl_buf_alloccopy(p, pSig->buf, pSig->len)) return false;
    p = add_wit_item(ppWitness, pWitItemCnt);
    if (!p) return false;
    if (!utl_buf_alloccopy(p, pPubKey, BTC_SZ_PUBKEY)) return false;
    return true;
}


bool btc_script_p2wsh_create_witness(utl_buf_t **ppWitness, uint32_t *pWitItemCnt, const utl_buf_t *pWitness[], int Num)
{
    free_witness(ppWitness, pWitItemCnt);

    for (int lp = 0; lp < Num; lp++) {
        utl_buf_t *p = add_wit_item(ppWitness, pWitItemCnt);
        if (!p) return false;
        // https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2016-August/013014.html
        //  non-mandatory-script-verify-flag (OP_IF/NOTIF argument must be minimal)
        if ((pWitness[lp]->len == 1) && (pWitness[lp]->buf[0] == 0x00)) return false;
        if (!utl_buf_alloccopy(p, pWitness[lp]->buf, pWitness[lp]->len)) return false;
    }
    return true;
}


bool btc_script_p2wsh_2of2_verify_witness(utl_buf_t *pWitness, uint32_t WitItemCnt, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
{
    if (WitItemCnt != 4) {
        LOGE("items not 4.n");
        return false;
    }

    utl_buf_t *wit_item;

    //verify P2WSH
    // 1. check witnessScriptHash
    // 2. check 2of2 multisig
    //
    //  NULL
    //  <sig1>
    //  <sig2>
    //  witnessScript
    //
    // Note: we support `MinimalPush` only.

    //check witnessScriptHash
    // scriptPk (P2WSH-witnessPorg)
    //      OP_0 <witnessScriptHash>
    if (pScriptPk->len != 1 + 1 + BTC_SZ_HASH256) {
        LOGE("invalid P2WSH-witnessProg\n");
        return false;
    }
    if (pScriptPk->buf[0] != OP_0) {
        LOGE("invalid P2WSH-witnessProg\n");
        return false;
    }
    if (pScriptPk->buf[1] != BTC_SZ_HASH256) {
        LOGE("invalid P2WSH-witnessProg\n");
        return false;
    }
    uint8_t sh[BTC_SZ_HASH256];
    wit_item = &pWitness[3];
    btc_md_sha256(sh, wit_item->buf, wit_item->len);
    if (memcmp(sh, &pScriptPk->buf[2], BTC_SZ_HASH256)) {
        LOGE("pubkeyhash mismatch.\n");
        return false;
    }

    //NULL
    wit_item = &pWitness[0];
    if (wit_item->len != 0) {
        LOGE("witness[0] is not NULL\n");
        return false;
    }

    //sigs
    const utl_buf_t *sig1 = &pWitness[1];
    if (sig1->len == 0) {
        LOGE("sig1: invalid\n");
        return false;
    }
    if (sig1->buf[sig1->len - 1] != SIGHASH_ALL) {
        LOGE("sig1: not SIGHASH_ALL\n");
        return false;
    }
    const utl_buf_t *sig2 = &pWitness[2];
    if (sig2->len == 0) {
        LOGE("sig2: invalid\n");
        return false;
    }
    if (sig2->buf[sig2->len - 1] != SIGHASH_ALL) {
        LOGE("sig2: not SIGHASH_ALL\n");
        return false;
    }

    //witnessScript
    wit_item = &pWitness[3];
    if (wit_item->len != 71) {
        // Note: we support `MinimalPush` only.
        LOGE("witnessScript: invalid length: %u\n", wit_item->len);
        return false;
    }
    const uint8_t *p = wit_item->buf;
    if ( (*p != OP_2) ||
         (*(p + 1) != BTC_SZ_PUBKEY) ||
         (*(p + 35) != BTC_SZ_PUBKEY) ||
         (*(p + 69) != OP_2) ||
         (*(p + 70) != OP_CHECKMULTISIG) ) {
        LOGE("witnessScript: non-standard 2-of-2\n");
        LOGE("1: %d\n", (*p != OP_2));
        LOGE("2: %d\n", (*(p + 1) != BTC_SZ_PUBKEY));
        LOGE("3: %d\n", (*(p + 35) != BTC_SZ_PUBKEY));
        LOGE("4: %d\n", (*(p + 69) != OP_2));
        LOGE("5: %d\n", (*(p + 70) != OP_CHECKMULTISIG));
        return false;
    }
    const uint8_t *pub1 = p + 2;
    const uint8_t *pub2 = p + 36;

    //verify sigs
#if 1
    if (!btc_sig_verify(sig1, pTxHash, pub1)) {
        LOGE("fail: btc_sig_verify(sig1)\n");
        return false;
    }
    if (!btc_sig_verify(sig2, pTxHash, pub2)) {
        LOGE("fail: btc_sig_verify(sig2)\n");
        return false;
    }
#else
    bool ret1 = btc_sig_verify(sig1, pTxHash, pub1);
    bool ret2 = btc_sig_verify(sig2, pTxHash, pub2);
    bool ret3 = btc_sig_verify(sig1, pTxHash, pub2);
    bool ret4 = btc_sig_verify(sig2, pTxHash, pub1);
    bool ret = ret1 && ret2;
    printf("txhash=");
    DUMPD(pTxHash, BTC_SZ_HASH256);
    printf("ret1=%d\n", ret1);
    printf("ret2=%d\n", ret2);
    printf("ret3=%d\n", ret3);
    printf("ret4=%d\n", ret4);
#endif

    return true;
}


bool btc_script_scriptpk_is_op_return(const utl_buf_t *pScriptPk)
{
    if (!pScriptPk->len) return false;
    if (pScriptPk->buf[0] != OP_RETURN) return false;
    return true;
}


bool btc_script_p2wpkh_create_scriptcode(utl_buf_t *pScriptCode, const uint8_t *pPubKey)
{
    //https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // scriptCode: 0x1976a914{20-byte keyhash}88ac
    uint8_t hash[BTC_SZ_HASH_MAX];
    btc_md_hash160(hash, pPubKey, BTC_SZ_PUBKEY);
    if (!utl_buf_realloc(pScriptCode, 1 + 3 + BTC_SZ_HASH160 + 2)) return false;
    pScriptCode->buf[0] = (uint8_t)pScriptCode->len - 1;
    create_scriptpk_p2pkh(pScriptCode->buf + 1, hash);
    return true;
}


bool btc_script_p2wsh_create_scriptcode(utl_buf_t *pScriptCode, const utl_buf_t *pWitScript)
{
    //https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // scriptCode: witnessScript
    // XXX: OP_CODESEPARATOR?

    bool ret = false;
    btc_buf_w_t buf_w;
    utl_buf_truncate(pScriptCode);
    if (!btc_tx_buf_w_init(&buf_w, 0)) return false;
    if (!btc_tx_buf_w_write_varint_len_data(&buf_w, pWitScript->buf, pWitScript->len)) goto LABEL_EXIT;
    pScriptCode->buf = btc_tx_buf_w_get_data(&buf_w);
    pScriptCode->len = btc_tx_buf_w_get_len(&buf_w);
    ret = true;

LABEL_EXIT:
    if (!ret) {
        btc_tx_buf_w_free(&buf_w);
    }
    return ret;
}


int btc_script_scriptpk_prefix(const uint8_t **ppHash, const utl_buf_t *pScriptPk)
{
    if ( (pScriptPk->len == 25) &&
         (pScriptPk->buf[0] == OP_DUP) &&
         (pScriptPk->buf[1] == OP_HASH160) &&
         (pScriptPk->buf[2] == BTC_SZ_HASH160) &&
         (pScriptPk->buf[23] == OP_EQUALVERIFY) &&
         (pScriptPk->buf[24] == OP_CHECKSIG) ) {
        *ppHash = pScriptPk->buf + 3;
        return BTC_PREF_P2PKH;
    }
    else if ( (pScriptPk->len == 23) &&
         (pScriptPk->buf[0] == OP_HASH160) &&
         (pScriptPk->buf[1] == BTC_SZ_HASH160) &&
         (pScriptPk->buf[22] == OP_EQUAL) ) {
        *ppHash = pScriptPk->buf + 2;
        return BTC_PREF_P2SH;
    }
    else if ( (pScriptPk->len == 22) &&
         (pScriptPk->buf[0] == 0x00) &&
         (pScriptPk->buf[1] == BTC_SZ_HASH160) ) {
        *ppHash = pScriptPk->buf + 2;
        return BTC_PREF_P2WPKH;
    }
    else if ( (pScriptPk->len == 34) &&
         (pScriptPk->buf[0] == 0x00) &&
         (pScriptPk->buf[1] == BTC_SZ_HASH256) ) {
        *ppHash = pScriptPk->buf + 2;
        return BTC_PREF_P2WSH;
    }
    return BTC_PREF_MAX;
}


#if defined(PTARM_USE_PRINTFUNC) && !defined(PTARM_UTL_LOG_MACRO_DISABLED)
void btc_script_print(const uint8_t *pData, uint16_t Len)
{
    bool ret = true;

    const struct {
        uint8_t         op;
        const char      *name;
    } OP_DIC[] = {
        { OP_HASH160, "OP_HASH160" },
        { OP_HASH256, "OP_HASH256" },
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
        if (*pData <= OP_X_PUSHDATA_MAX) {
            //pushdata
            uint8_t len = *pData;
            pData++;
            if (pData + len > end) {
                ret = false;
                break;
            }
            LOGD("%s%02x ", INDENT, len);
            DUMPD(pData, len);
            pData += len;
        } else if ((OP_1 <= *pData) && (*pData <= OP_16)) {
            //OP_X
            LOGD("%s%02x [OP_%d]\n", INDENT, *pData, *pData - OP_X);
            pData++;
        } else if (*pData == OP_PUSHDATA1) {
            //pushdata
            if (pData + 2 > end) {
                ret = false;
                break;
            }
            uint8_t len = *(pData + 1);
            pData += 2;
            if (pData + len > end) {
                ret = false;
                break;
            }
            LOGD("%sOP_PUSHDATA1 0x%02x ", INDENT, len);
            DUMPD(pData, len);
            pData += len;
        } else if (*pData == OP_PUSHDATA2) {
            //pushdata
            if (pData + 3 > end) {
                ret = false;
                break;
            }
            uint16_t len = *(pData + 1) | (*(pData + 2) << 8);
            pData += 3;
            if (pData + len > end) {
                ret = false;
                break;
            }
            LOGD("%sOP_PUSHDATA2 0x%02x ", INDENT, len);
            DUMPD(pData, len);
            pData += len;
        } else if (*pData == OP_PUSHDATA3) {
            //pushdata
            if (pData + 5 > end) {
                ret = false;
                break;
            }
            uint32_t len = *(pData + 1) | (*(pData + 2) << 8) | (*(pData + 3) << 16) | (*(pData + 4) << 24);
            pData += 5;
            if (pData + len > end) {
                ret = false;
                break;
            }
            LOGD("%sOP_PUSHDATA3 0x%02x ", INDENT, len);
            DUMPD(pData, len);
            pData += len;
        } else {
            int op;
            for (op = 0; op < (int)ARRAY_SIZE(OP_DIC); op++) {
                if (*pData == OP_DIC[op].op) {
                    break;
                }
            }
            if (op != ARRAY_SIZE(OP_DIC)) {
                LOGD("%s%02x [%s]\n", INDENT, OP_DIC[op].op, OP_DIC[op].name);
            } else {
                //unknown
                LOGE("%s%02x [??]\n", INDENT, *pData);
            }
            pData++;
        }
    }
    if (!ret) {
        LOGE("%sinvalid script length\n", INDENT);
    }
}
#endif  //PTARM_USE_PRINTFUNC


/**************************************************************************
 * private functions
 **************************************************************************/

static void create_scriptpk_p2pkh(uint8_t *p, const uint8_t *pPubKeyHash)
{
    p[0] = OP_DUP;
    p[1] = OP_HASH160;
    p[2] = BTC_SZ_HASH160;
    memcpy(p + 3, pPubKeyHash, BTC_SZ_HASH160);
    p[23] = OP_EQUALVERIFY;
    p[24] = OP_CHECKSIG;
}


static void create_scriptpk_p2sh(uint8_t *p, const uint8_t *pHash)
{
    p[0] = OP_HASH160;
    p[1] = BTC_SZ_HASH160;
    memcpy(p + 2, pHash, BTC_SZ_HASH160);
    p[22] = OP_EQUAL;
}


static void create_scriptpk_p2wpkh(uint8_t *p, const uint8_t *pHash)
{
    p[0] = 0x00;
    p[1] = BTC_SZ_HASH160;
    memcpy(p + 2, pHash, BTC_SZ_HASH160);
}


static void create_scriptpk_p2wsh(uint8_t *p, const uint8_t *pHash)
{
    p[0] = 0x00;
    p[1] = BTC_SZ_HASH256;
    memcpy(p + 2, pHash, BTC_SZ_HASH256);
}


static utl_buf_t *add_wit_item(utl_buf_t **ppWitness, uint32_t *pWitItemCnt)
{
    *ppWitness = (utl_buf_t *)UTL_DBG_REALLOC(*ppWitness, sizeof(utl_buf_t) * (*pWitItemCnt + 1));
    if (!*ppWitness) return NULL;
    utl_buf_t *p_buf = &((*ppWitness)[*pWitItemCnt]);
    (*pWitItemCnt)++;

    utl_buf_init(p_buf);
    return p_buf;
}


static void free_witness(utl_buf_t **ppWitness, uint32_t *pWitItemCnt)
{
    while (*pWitItemCnt) {
        utl_buf_free(&(*ppWitness)[--(*pWitItemCnt)]);
    }
}

/** get the order of the keys
 *
 * @param[in]       pPubKey1
 * @param[in]       pPubKey2
 * @retval      BTC_SCRYPT_PUBKEY_ORDER_ASC     引数の順番
 *
 */
static btc_script_pubkey_order_t pubkey_order_2of2(const uint8_t *pPubKey1, const uint8_t *pPubKey2)
{
    int cmp = memcmp(pPubKey1, pPubKey2, BTC_SZ_PUBKEY);
    if (cmp < 0) {
        return BTC_SCRYPT_PUBKEY_ORDER_ASC;
    } else {
        return BTC_SCRYPT_PUBKEY_ORDER_OTHER;
    }
}


