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
/** @file   ln_misc.c
 *  @brief  [LN]雑多
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ln_misc.h"


/********************************************************************
 * functions
 ********************************************************************/

void HIDDEN ln_misc_push8(ucoin_push_t *pPush, uint8_t Value)
{
    ucoin_push_data(pPush, &Value, sizeof(Value));
}


void HIDDEN ln_misc_push16be(ucoin_push_t *pPush, uint16_t Value)
{
    uint8_t data[sizeof(Value)];
    data[1] = (uint8_t)Value;
    data[0] = (uint8_t)(Value >> 8);
    ucoin_push_data(pPush, data, sizeof(data));
}


void HIDDEN ln_misc_push32be(ucoin_push_t *pPush, uint32_t Value)
{
    uint8_t data[sizeof(Value)];
    data[3] = (uint8_t)Value;
    data[2] = (uint8_t)(Value >>= 8);
    data[1] = (uint8_t)(Value >>= 8);
    data[0] = (uint8_t)(Value >> 8);
    ucoin_push_data(pPush, data, sizeof(data));
}


void HIDDEN ln_misc_push64be(ucoin_push_t *pPush, uint64_t Value)
{
    uint8_t data[sizeof(Value)];
    data[7] = (uint8_t)Value;
    data[6] = (uint8_t)(Value >>= 8);
    data[5] = (uint8_t)(Value >>= 8);
    data[4] = (uint8_t)(Value >>= 8);
    data[3] = (uint8_t)(Value >>= 8);
    data[2] = (uint8_t)(Value >>= 8);
    data[1] = (uint8_t)(Value >>= 8);
    data[0] = (uint8_t)(Value >> 8);
    ucoin_push_data(pPush, data, sizeof(data));
}


uint16_t HIDDEN ln_misc_get16be(const uint8_t *pData)
{
    return (pData[0] << 8) | pData[1];
}


uint32_t HIDDEN ln_misc_get32be(const uint8_t *pData)
{
    return (pData[0] << 24) | (pData[1] << 16) | (pData[2] << 8) | pData[3];
}


uint64_t HIDDEN ln_misc_get64be(const uint8_t *pData)
{
    return ((uint64_t)pData[0] << 56) | ((uint64_t)pData[1] << 48) |
                        ((uint64_t)pData[2] << 40) | ((uint64_t)pData[3] << 32) |
                        ((uint64_t)pData[4] << 24) | ((uint64_t)pData[5] << 16) |
                        ((uint64_t)pData[6] << 8) | (uint64_t)pData[7];
}


void HIDDEN ln_misc_setbe(uint8_t *pBuf, const void *pData, size_t Len)
{
    const uint8_t *p = (const uint8_t *)pData;
    for (size_t lp = 0; lp < Len; lp++) {
        pBuf[lp] = *(p + Len - lp - 1);
    }
}


bool HIDDEN ln_misc_sigtrim(uint8_t *pSig, const uint8_t *pBuf)
{
    //署名
    //  [30][4+r_len+s_len][02][r len][...][02][s_len][...][01]
    //
    //  基本的に、r=32byte, s=32byte
    //  しかし、DER形式のため以下の操作が発生する
    //      - 最上位bitが立っていると負の数と見なされてNGのため、0x00を付与する
    //      - 最上位バイトの0x00は負の数を回避する以外にはNGのため、取り除く
    //
    //  よって、例えばr=000...00, s=000...00だった場合、以下となる
    //      300602010002010001

    uint8_t sz = pBuf[1] - 4;
    uint8_t sz_r = pBuf[3];
    uint8_t sz_s = pBuf[4 + sz_r + 1];
    const uint8_t *p = pBuf + 4;

    if (sz != sz_r + sz_s) {
        return false;
    }

    //r
    //0除去
    for (int lp = 0; lp < sz_r - 1; lp++) {
        if (*p != 0) {
            break;
        }
        sz_r--;
        p++;
    }
    if (sz_r > 32) {
        return false;
    }
    if (sz_r < 32) {
        memset(pSig, 0, 32 - sz_r);
        pSig += 32 - sz_r;
    }
    memcpy(pSig, p, sz_r);
    pSig += sz_r;
    p += sz_r + 2;

    //s
    //0除去
    for (int lp = 0; lp < sz_s - 1; lp++) {
        if (*p != 0) {
            break;
        }
        sz_s--;
        p++;
    }
    if (sz_s > 32) {
        return false;
    }
    if (sz_s < 32) {
        memset(pSig, 0, 32 - sz_s);
        pSig += 32 - sz_s;
    }
    memcpy(pSig, p, sz_s);

    return true;
}


void HIDDEN ln_misc_sigexpand(ucoin_buf_t *pSig, const uint8_t *pBuf)
{
    ucoin_push_t    push;
    uint8_t r_len = 32;
    uint8_t s_len = 32;
    const uint8_t *r_p;
    const uint8_t *s_p;

    r_p = pBuf;
    for (int lp = 0; lp < 31; lp++) {
        if (*r_p != 0) {
            break;
        }
        r_p++;
        r_len--;
    }
    if (*r_p & 0x80) {
        r_len++;
    }

    s_p = pBuf + 32;
    for (int lp = 0; lp < 31; lp++) {
        if (*s_p != 0) {
            break;
        }
        s_p++;
        s_len--;
    }
    if (*s_p & 0x80) {
        s_len++;
    }

    //署名
    //  [30][4+r_len+s_len][02][r len][...][02][s_len][...][01]
    ucoin_push_init(&push, pSig, 7 + r_len + s_len);

    uint8_t buf[6];
    buf[0] = 0x30;
    buf[1] = (uint8_t)(4 + r_len + s_len);
    buf[2] = 0x02;
    buf[3] = r_len;
    buf[4] = 0x00;
    buf[5] = 0x01;
    ucoin_push_data(&push, buf, 4);
    if (*r_p & 0x80) {
        buf[0] = 0x00;
        ucoin_push_data(&push, buf, 1);
        r_len--;
    }
    ucoin_push_data(&push, r_p, r_len);

    buf[0] = 0x02;
    buf[1] = s_len;
    ucoin_push_data(&push, buf, 2);
    if (*s_p & 0x80) {
        buf[0] = 0x00;
        ucoin_push_data(&push, buf, 1);
        s_len--;
    }
    ucoin_push_data(&push, s_p, s_len);
    buf[0] = 0x01;
    ucoin_push_data(&push, buf, 1);        //SIGHASH_ALL
}


void HIDDEN ln_misc_update_scriptkeys(ln_funding_local_data_t *pLocal, ln_funding_remote_data_t *pRemote)
{
    //localkey
    //ln_derkey_privkey(pLocal->scriptkeys[MSG_SCRIPTIDX_KEY].priv,
    //            pLocal->keys[MSG_FUNDIDX_PAYMENT].pub, pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub,
    //            pLocal->keys[MSG_FUNDIDX_PAYMENT].priv);
    //ucoin_keys_priv2pub(pLocal->scriptkeys[MSG_SCRIPTIDX_KEY].pub, pLocal->scriptkeys[MSG_SCRIPTIDX_KEY].priv);
    memset(pLocal->scriptkeys[MSG_SCRIPTIDX_KEY].priv, 0, UCOIN_SZ_PRIVKEY);
    //  remote payment と local per_commitment_point
    ln_derkey_pubkey(pLocal->scriptkeys[MSG_SCRIPTIDX_KEY].pub,
                pRemote->pubkeys[MSG_FUNDIDX_PAYMENT], pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);

    //local delayedkey
    //ln_derkey_privkey(pLocal->scriptkeys[MSG_SCRIPTIDX_DELAYED].priv,
    //            pLocal->keys[MSG_FUNDIDX_DELAYED_PAYMENT].pub, pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub,
    //            pLocal->keys[MSG_FUNDIDX_DELAYED_PAYMENT].priv);
    //ucoin_keys_priv2pub(pLocal->scriptkeys[MSG_SCRIPTIDX_DELAYED].pub, pLocal->scriptkeys[MSG_SCRIPTIDX_DELAYED].priv);
    memset(pLocal->scriptkeys[MSG_SCRIPTIDX_DELAYED].priv, 0, UCOIN_SZ_PRIVKEY);
    //  local delayed_payment と local per_commitment_point
    ln_derkey_pubkey(pLocal->scriptkeys[MSG_SCRIPTIDX_DELAYED].pub,
                pLocal->keys[MSG_FUNDIDX_DELAYED_PAYMENT].pub, pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);

    //local revocationkey
    //ln_derkey_revocationprivkey(pLocal->scriptkeys[MSG_SCRIPTIDX_REVOCATION].priv,
    //            pLocal->keys[MSG_FUNDIDX_REVOCATION].pub, pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub,
    //            pLocal->keys[MSG_FUNDIDX_REVOCATION].priv, pLocal->keys[MSG_FUNDIDX_PER_COMMIT].priv);
    //ucoin_keys_priv2pub(pLocal->scriptkeys[MSG_SCRIPTIDX_REVOCATION].pub, pLocal->scriptkeys[MSG_SCRIPTIDX_REVOCATION].priv);
    memset(pLocal->scriptkeys[MSG_SCRIPTIDX_REVOCATION].priv, 0, UCOIN_SZ_PRIVKEY);
    //  local revocation_basepoint と remote per_commitment_point
    ln_derkey_revocationkey(pLocal->scriptkeys[MSG_SCRIPTIDX_REVOCATION].pub,
                pLocal->keys[MSG_FUNDIDX_REVOCATION].pub, pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);


    //remotekey
    //  local payment と remote per_commitment_point
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_KEY],
                pLocal->keys[MSG_FUNDIDX_PAYMENT].pub, pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //remote delayedkey
    //  remote delayed_payment と remote per_commitment_point
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                pRemote->pubkeys[MSG_FUNDIDX_DELAYED_PAYMENT], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //remote revocationkey
    //  remote revocation_basepoint と local per_commitment_point
    ln_derkey_revocationkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                pRemote->pubkeys[MSG_FUNDIDX_REVOCATION], pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);
}


void HIDDEN ln_misc_calc_channel_id(uint8_t *pChannelId, const uint8_t *pTxid, uint16_t Index)
{
    //combining the funding-txid and the funding-output-index using big-endian exclusive-OR
    memcpy(pChannelId, pTxid, LN_SZ_CHANNEL_ID - sizeof(uint16_t));
    pChannelId[LN_SZ_CHANNEL_ID - 2] = pTxid[LN_SZ_CHANNEL_ID - 2] ^ (Index >> 8);
    pChannelId[LN_SZ_CHANNEL_ID - 1] = pTxid[LN_SZ_CHANNEL_ID - 1] ^ (Index & 0xff);
}


uint64_t HIDDEN ln_misc_calc_short_channel_id(uint32_t Height, uint32_t BIndex, uint32_t VIndex)
{
    //[0～2]Funding Transactionのブロック高の3byte
    //[3～5]そのブロック中のIndex
    //[6～7]チャネルに支払ったvout index
    uint64_t id = ((uint64_t)(Height & 0xffffff) << 40) | (uint64_t)(BIndex & 0xffffff) << 16 | (uint64_t)(VIndex & 0xffff);
    DBG_PRINTF("short_channel_id= %" PRIx64 "(height=%u, bindex=%u, vindex=%u)\n", id, Height, BIndex, VIndex);
    return id;
}


void HIDDEN ln_misc_get_short_channel_id_param(uint32_t *pHeight, uint32_t *pBIndex, uint32_t *pVIndex, uint64_t short_channel_id)
{
    *pHeight = short_channel_id >> 40;
    *pBIndex = (short_channel_id >> 16) & 0xffffff;
    *pVIndex = short_channel_id & 0xffff;
}

/**************************************************************************
 * for Debug
 **************************************************************************/

void HIDDEN ln_misc_printkeys(FILE *fp, const ln_funding_local_data_t *pLocal, const ln_funding_remote_data_t *pRemote)
{
#ifdef UCOIN_DEBUG
    fprintf(fp, "-[local]-------------------------------\n");
    fprintf(fp, "funding_txid: ");
    ucoin_util_dumptxid(fp, pLocal->funding_txid);
    fprintf(fp, "\n");
    const char *KEYS_STR[] = {
        "FUNDING", "REVOCATION", "PAYMENT", "DELAYED", "PER_COMMIT"
    };
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        fprintf(fp, "%s pub: ", KEYS_STR[lp]);
        ucoin_util_dumpbin(fp, pLocal->keys[lp].pub, UCOIN_SZ_PUBKEY);
    }
    fprintf(fp, "\n");
    const char *SCR_STR[] = {
        "KEY", "DELAYED", "REVOCATION"
    };
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        fprintf(fp, "%s pub: ", SCR_STR[lp]);
        ucoin_util_dumpbin(fp, pLocal->scriptkeys[lp].pub, UCOIN_SZ_PUBKEY);
    }

    fprintf(fp, "\n-[remote]---------------------------------------\n");
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        fprintf(fp, "%s pub: ", KEYS_STR[lp]);
        ucoin_util_dumpbin(fp, pRemote->pubkeys[lp], UCOIN_SZ_PUBKEY);
    }
    fprintf(fp, "\n");
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        fprintf(fp, "%s pub: ", SCR_STR[lp]);
        ucoin_util_dumpbin(fp, pRemote->scriptpubkeys[lp], UCOIN_SZ_PUBKEY);
    }
    fprintf(fp, "----------------------------------------\n");
#endif
}
