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
/** @file   btc_script.c
 *  @brief  btc_script
 */
#ifdef PTARM_USE_PRINTFUNC
#endif  //PTARM_USE_PRINTFUNC

#include "mbedtls/asn1write.h"
#include "mbedtls/ecdsa.h"

#include "utl_dbg.h"
#include "utl_time.h"
#include "utl_int.h"

#include "btc_local.h"
#include "btc_util.h"
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


/**************************************************************************
 * public functions
 **************************************************************************/

bool btc_script_pk_create(utl_buf_t *pScriptPk, const uint8_t *pHash, int Prefix)
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


bool btc_script_sig_create_p2pkh(utl_buf_t *pScriptSig, const utl_buf_t *pSig, const uint8_t *pPubKey)
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


bool btc_script_sig_create_p2sh_multisig(utl_buf_t *pScriptSig, const utl_buf_t *pSigs[], uint8_t Num, const utl_buf_t *pRedeem)
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


bool btc_script_sig_create_p2sh_p2wpkh(utl_buf_t *pScriptSig, const uint8_t *pPubKey)
{
    if (!utl_buf_realloc(pScriptSig, 1 + 1 + 1 + BTC_SZ_HASH160)) return false;

    uint8_t *p = pScriptSig->buf;
    //len + <witness program>
    *p++ = 0x16;
    //witness program
    *p++ = 0x00;
    *p++ = (uint8_t)BTC_SZ_HASH160;
    btc_util_hash160(p, pPubKey, BTC_SZ_PUBKEY);
    return true;
}


bool btc_script_sig_sign_p2pkh(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPrivKey, const uint8_t *pPubKey)
{
    bool ret;
    uint8_t pubkey[BTC_SZ_PUBKEY];
    utl_buf_t sigbuf = UTL_BUF_INIT;

    if (pPubKey == NULL) {
        ret = btc_keys_priv2pub(pubkey, pPrivKey);
        if (!ret) {
            assert(0);
            goto LABEL_EXIT;
        }
        pPubKey = pubkey;
    }

    ret = btc_sig_sign(&sigbuf, pTxHash, pPrivKey);
    if (!ret) {
        goto LABEL_EXIT;
    }

    ret = btc_script_sig_create_p2pkh(pScriptSig, &sigbuf, pPubKey);
    if (!ret) {
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    utl_buf_free(&sigbuf);

    return ret;
}


bool btc_script_sig_verify_p2pkh(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pPubKeyHash)
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
    if (sig_len < _OP_PUSHDATA_X_MIN) goto LABEL_EXIT;
    if (sig_len > _OP_PUSHDATA_X_MAX) goto LABEL_EXIT;
    if (pScriptSig->len < 1 + sig_len + 1) goto LABEL_EXIT;
    pubkey_len = *(buf + 1 + sig_len);
    pubkey = buf + 1 + sig_len + 1;
    if (pubkey_len != BTC_SZ_PUBKEY) goto LABEL_EXIT;
    if (pScriptSig->len != 1 + sig_len + 1 + pubkey_len) goto LABEL_EXIT;

    uint8_t pkh[BTC_SZ_HASH160];
    btc_util_hash160(pkh, pubkey, BTC_SZ_PUBKEY);
    if (memcmp(pkh, pPubKeyHash, BTC_SZ_HASH160)) goto LABEL_EXIT;

    if (!btc_sig_verify_2(sig, sig_len, pTxHash, pubkey)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    return ret;
}


bool btc_script_sig_verify_p2pkh_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
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

    ret =  btc_script_sig_verify_p2pkh(pScriptSig, pTxHash, pScriptPk->buf + 3);

LABEL_EXIT:
    return ret;
}


bool btc_script_sig_verify_p2pkh_addr(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2PKH)) {
        ret = btc_script_sig_verify_p2pkh(pScriptSig, pTxHash, hash);
    } else {
        ret = false;
    }

    return ret;
}


bool btc_script_sig_verify_p2sh_multisig(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const uint8_t *pScriptHash)
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
        LOGD("top isnot OP_0\n");
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
        LOGD("no OP_PUSHDATAx(sign)\n");
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
        LOGD("no OP_PUSHDATA-1or2\n");
        return false;
    }
    if (pScriptSig->len != pos + redm_len) {
        LOGD("invalid len\n");
        return false;
    }
    if (signum != (*(p + pos) - OP_x)) {
        LOGD("OP_x mismatch(sign): signum=%d, OP_x=%d\n", signum, *(p + pos) - OP_x);
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
            LOGD("invalid pubkey len(%d)\n", len);
            return false;
        }
        pubnum++;
        pos += 1 + len;
    }
    if (pos >= pScriptSig->len) {
        LOGD("no OP_PUSHDATAx(pubkey)\n");
        return false;
    }
    if (pubnum != (*(p + pos) - OP_x)) {
        LOGD("OP_x mismatch(pubkey): signum=%d, OP_x=%d\n", pubnum, *(p + pos) - OP_x);
        return false;
    }
    pos++;
    if (*(p + pos) != OP_CHECKMULTISIG) {
        LOGD("not OP_CHECKMULTISIG\n");
        return false;
    }
    pos++;
    if (pos != pScriptSig->len) {
        LOGD("invalid data length\n");
        return false;
    }

    //scripthashチェック
    uint8_t sh[BTC_SZ_HASH_MAX];
    btc_util_hash160(sh, pScriptSig->buf + pubpos - 1, pScriptSig->len - pubpos + 1);
    bool ret = (memcmp(sh, pScriptHash, BTC_SZ_HASH160) == 0);
    if (!ret) {
        LOGD("scripthash mismatch.\n");
        return false;
    }

    //公開鍵の重複チェック
    for (int lp = 0; lp < pubnum - 1; lp++) {
        const uint8_t *p1 = pScriptSig->buf + pubpos + (1 + BTC_SZ_PUBKEY) * lp;
        for (int lp2 = lp + 1; lp2 < pubnum; lp2++) {
            const uint8_t *p2 = pScriptSig->buf + pubpos + (1 + BTC_SZ_PUBKEY) * lp2;
            ret = (memcmp(p1, p2, 1 + BTC_SZ_PUBKEY) == 0);
            if (ret) {
                LOGD("same pubkey(%d, %d)\n", lp, lp2);
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


bool btc_script_sig_verify_p2sh_multisig_spk(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const utl_buf_t *pScriptPk)
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

    ret =  btc_script_sig_verify_p2sh_multisig(pScriptSig, pTxHash, pScriptPk->buf + 2);

LABEL_EXIT:
    return ret;
}


bool btc_script_sig_verify_p2sh_multisig_addr(utl_buf_t *pScriptSig, const uint8_t *pTxHash, const char *pAddr)
{
    uint8_t hash[BTC_SZ_HASH_MAX];
    int pref;
    bool ret = btc_keys_addr2hash(hash, &pref, pAddr);
    if (ret && (pref == BTC_PREF_P2SH)) {
        ret = btc_script_sig_verify_p2sh_multisig(pScriptSig, pTxHash, hash);
    } else {
        ret = false;
    }

    return ret;
}


bool btc_script_witness_create_p2wpkh(utl_buf_t **ppWitness, uint32_t *pWitItemCnt, const utl_buf_t *pSig, const uint8_t *pPubKey)
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


bool btc_script_code_p2wpkh(utl_buf_t *pScriptCode, const uint8_t *pPubKey)
{
    //https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // scriptCode: 0x1976a914{20-byte keyhash}88ac
    uint8_t hash[BTC_SZ_HASH_MAX];
    btc_util_hash160(hash, pPubKey, BTC_SZ_PUBKEY);
    if (!utl_buf_alloc(pScriptCode, 1 + 3 + BTC_SZ_HASH160 + 2)) return false;
    pScriptCode->buf[0] = (uint8_t)pScriptCode->len - 1;
    create_scriptpk_p2pkh(pScriptCode->buf + 1, hash);
    return true;
}


//XXX:
bool btc_script_code_p2wsh(utl_buf_t *pScriptCode, const utl_buf_t *pWitScript)
{
    //https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    // scriptCode: witnessScript
    // XXX: OP_CODESEPARATOR?
    bool ret = false;
    btc_buf_w_t buf_w;
    if (!btc_tx_buf_w_init(&buf_w, 0)) return false;
    if (!btc_tx_buf_w_write_varint_len(&buf_w, pWitScript->len)) goto LABEL_EXIT;
    if (!btc_tx_buf_w_write_data(&buf_w, pWitScript->buf, pWitScript->len)) goto LABEL_EXIT;
    if (!utl_buf_alloccopy(pScriptCode, btc_tx_buf_w_get_data(&buf_w), btc_tx_buf_w_get_len(&buf_w))) goto LABEL_EXIT;
    ret = true;

LABEL_EXIT:
    btc_tx_buf_w_free(&buf_w);
    return ret;
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
        if (*pData <= _OP_PUSHDATA_X_MAX) {
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
            //OP_x
            LOGD("%s%02x [OP_%d]\n", INDENT, *pData, *pData - OP_x);
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
                LOGD("%s%02x [??]\n", INDENT, *pData);
            }
            pData++;
        }
    }
    if (!ret) {
        LOGD("%sinvalid script length\n", INDENT);
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
