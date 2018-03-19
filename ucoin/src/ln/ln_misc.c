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
#include "ln_derkey.h"

/********************************************************************
 * public functions
 ********************************************************************/

const char *ln_misc_msgname(uint16_t Type)
{
    const struct {
        uint16_t        type;
        const char      *name;
    } MESSAGE[] = {
        { 0x0010, "init" },
        { 0x0011, "error" },
        { 0x0012, "ping" },
        { 0x0013, "pong" },
        { 0x0020, "open_channel" },
        { 0x0021, "accept_channel" },
        { 0x0022, "funding_created" },
        { 0x0023, "funding_signed" },
        { 0x0024, "funding_locked" },
        { 0x0026, "shutdown" },
        { 0x0027, "closing_signed" },
        { 0x0080, "update_add_htlc" },
        { 0x0082, "update_fulfill_htlc" },
        { 0x0083, "update_fail_htlc" },
        { 0x0084, "commitment_signed" },
        { 0x0085, "revoke_and_ack" },
        { 0x0086, "update_fee" },
        { 0x0087, "update_fail_malformed_htlc" },
        { 0x0088, "channel_reestablish" },
        { 0x0100, "channel_announcement" },
        { 0x0101, "node_announcement" },
        { 0x0102, "channel_update" },
        { 0x0103, "announcement_signatures" },
    };
    for (size_t lp = 0; lp < ARRAY_SIZE(MESSAGE); lp++) {
        if (Type == MESSAGE[lp].type) {
            return MESSAGE[lp].name;
        }
    }
    return "UNKNOWN MESSAGE";
}


uint16_t ln_misc_get16be(const uint8_t *pData)
{
    return (pData[0] << 8) | pData[1];
}


uint32_t ln_misc_get32be(const uint8_t *pData)
{
    return (pData[0] << 24) | (pData[1] << 16) | (pData[2] << 8) | pData[3];
}


uint64_t ln_misc_get64be(const uint8_t *pData)
{
    return ((uint64_t)pData[0] << 56) | ((uint64_t)pData[1] << 48) |
                        ((uint64_t)pData[2] << 40) | ((uint64_t)pData[3] << 32) |
                        ((uint64_t)pData[4] << 24) | ((uint64_t)pData[5] << 16) |
                        ((uint64_t)pData[6] << 8) | (uint64_t)pData[7];
}


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


//  localkey, remotekey, local_delayedkey, remote_delayedkey
//      pubkey = basepoint + SHA256(per_commitment_point || basepoint)*G
//
//  revocationkey
//      revocationkey = revocation_basepoint * SHA256(revocation_basepoint || per_commitment_point) + per_commitment_point*SHA256(per_commitment_point || revocation_basepoint)
//
void HIDDEN ln_misc_update_scriptkeys(ln_funding_local_data_t *pLocal, ln_funding_remote_data_t *pRemote)
{
    DBG_PRINTF("BEGIN\n");

    //
    //local
    //

    //remotekey = local per_commitment_point & remote payment
    //DBG_PRINTF("local: remotekey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY],
                pRemote->pubkeys[MSG_FUNDIDX_PAYMENT], pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);

    //delayedkey = local per_commitment_point & local delayed_payment
    //DBG_PRINTF("local: delayedkey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                pLocal->keys[MSG_FUNDIDX_DELAYED].pub, pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);

    //revocationkey = remote per_commitment_point & local revocation_basepoint
    //DBG_PRINTF("local: revocationkey\n");
    ln_derkey_revocationkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                pRemote->pubkeys[MSG_FUNDIDX_REVOCATION], pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);

    //local_htlckey = local per_commitment_point & local htlc_basepoint
    //DBG_PRINTF("local: local_htlckey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                pLocal->keys[MSG_FUNDIDX_HTLC].pub, pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);

    //remote_htlckey = local per_commitment_point & remote htlc_basepoint
    //DBG_PRINTF("local: remote_htlckey\n");
    ln_derkey_pubkey(pLocal->scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                pRemote->pubkeys[MSG_FUNDIDX_HTLC], pLocal->keys[MSG_FUNDIDX_PER_COMMIT].pub);


    //
    //remote
    //

    //remotekey = remote per_commitment_point & local payment
    //DBG_PRINTF("remote: remotekey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_REMOTEKEY],
                pLocal->keys[MSG_FUNDIDX_PAYMENT].pub, pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //delayedkey = remote per_commitment_point & remote delayed_payment
    //DBG_PRINTF("remote: delayedkey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_DELAYED],
                pRemote->pubkeys[MSG_FUNDIDX_DELAYED], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //revocationkey = local per_commitment_point & remote revocation_basepoint
    //DBG_PRINTF("remote: revocationkey\n");
    ln_derkey_revocationkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_REVOCATION],
                pLocal->keys[MSG_FUNDIDX_REVOCATION].pub, pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //local_htlckey = remote per_commitment_point & remote htlc_basepoint
    //DBG_PRINTF("remote: local_htlckey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_LOCALHTLCKEY],
                pRemote->pubkeys[MSG_FUNDIDX_HTLC], pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);

    //remote_htlckey = remote per_commitment_point & local htlc_basepoint
    //DBG_PRINTF("remote: remote_htlckey\n");
    ln_derkey_pubkey(pRemote->scriptpubkeys[MSG_SCRIPTIDX_REMOTEHTLCKEY],
                pLocal->keys[MSG_FUNDIDX_HTLC].pub, pRemote->pubkeys[MSG_FUNDIDX_PER_COMMIT]);


    ln_print_keys(PRINTOUT, pLocal, pRemote);
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
    //DBG_PRINTF("short_channel_id= %" PRIx64 "(height=%u, bindex=%u, vindex=%u)\n", id, Height, BIndex, VIndex);
    return id;
}


void HIDDEN ln_misc_get_short_channel_id_param(uint32_t *pHeight, uint32_t *pBIndex, uint32_t *pVIndex, uint64_t short_channel_id)
{
    *pHeight = short_channel_id >> 40;
    *pBIndex = (short_channel_id >> 16) & 0xffffff;
    *pVIndex = short_channel_id & 0xffff;
}
