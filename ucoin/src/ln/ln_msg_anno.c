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
/** @file   ln_msg_anno.c
 *  @brief  [LN]Announcement関連
 *  @author ueno@nayuta.co
 *  @sa     https://github.com/nayuta-ueno/lightning-rfc/blob/master/07-routing-gossip.md
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "ln_msg_anno.h"
#include "ln_misc.h"


/********************************************************************
 * macros
 ********************************************************************/

//#define DBG_PRINT_CREATE
#define DBG_PRINT_READ


/**************************************************************************
 * prototypes
 **************************************************************************/

static void node_announce_print(const ln_node_announce_t *pMsg);
static void cnl_update_print(const ln_cnl_update_t *pMsg);
static void announce_signs_print(const ln_announce_signs_t *pMsg);


/********************************************************************
 * channel_announcement
 ********************************************************************/

bool HIDDEN ln_msg_cnl_announce_create(ucoin_buf_t *pBuf,
                uint8_t **ppSigNode, uint8_t **ppSigBtc, const ln_cnl_announce_t *pMsg)
{
    //    type: 256 (channel_announcement)
    //    data:
    //        [64:node_signature_1]
    //        [64:node_signature_2]
    //        [64:bitcoin_signature_1]
    //        [64:bitcoin_signature_2]
    //        [8:short_channel_id]
    //        [33:node_id_1]
    //        [33:node_id_2]
    //        [33:bitcoin_key_1]
    //        [33:bitcoin_key_2]
    //        [2:len]
    //        [len:features]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
//    ln_msg_cnl_announce_print(pMsg);
#endif  //DBG_PRINT_CREATE

    //len=0
    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 398);

    //    type: 256 (channel_announcement)
    ln_misc_push16be(&proto, MSGTYPE_CHANNEL_ANNOUNCEMENT);

//    //        [64:node_signature_1]
//    ucoin_push_data(&proto, pMsg->p_node_signature1, LN_SZ_SIGNATURE);
//
//    //        [64:node_signature_2]
//    ucoin_push_data(&proto, pMsg->p_node_signature2, LN_SZ_SIGNATURE);
//
//    //        [64:bitcoin_signature_1]
//    ucoin_push_data(&proto, pMsg->p_btc_signature1, LN_SZ_SIGNATURE);
//
//    //        [64:bitcoin_signature_2]
//    ucoin_push_data(&proto, pMsg->p_btc_signature2, LN_SZ_SIGNATURE);
    memset(pBuf->buf + proto.pos, 0xcc, LN_SZ_SIGNATURE * 4);
    proto.pos += LN_SZ_SIGNATURE * 4;

    //        [8:short_channel_id]
    ln_misc_push64be(&proto, pMsg->short_channel_id);

    const uint8_t *p_node_1;
    const uint8_t *p_node_2;
    const uint8_t *p_btc_1;
    const uint8_t *p_btc_2;
    int offset_sig;
    if (pMsg->sort == UCOIN_KEYS_SORT_ASC) {
        //自ノードが先
        p_node_1 = pMsg->p_my_node->pub;
        p_node_2 = pMsg->p_peer_node_pub;
        p_btc_1 = pMsg->p_my_funding->pub;
        p_btc_2 = pMsg->p_peer_funding_pub;
        offset_sig = 0;
    } else {
        p_node_1 = pMsg->p_peer_node_pub;
        p_node_2 = pMsg->p_my_node->pub;
        p_btc_1 = pMsg->p_peer_funding_pub;
        p_btc_2 = pMsg->p_my_funding->pub;
        offset_sig = LN_SZ_SIGNATURE;
    }
    //        [33:node_id_1]
    ucoin_push_data(&proto, p_node_1, UCOIN_SZ_PUBKEY);

    //        [33:node_id_2]
    ucoin_push_data(&proto, p_node_2, UCOIN_SZ_PUBKEY);

    //        [33:bitcoin_key_1]
    ucoin_push_data(&proto, p_btc_1, UCOIN_SZ_PUBKEY);

    //        [33:bitcoin_key_2]
    ucoin_push_data(&proto, p_btc_2, UCOIN_SZ_PUBKEY);

    //        [2:len]
    ln_misc_push16be(&proto, 0);

//    //        [len:features]
//    ln_misc_push8(&proto, pMsg->features);

    assert(sizeof(uint16_t) + 398 == pBuf->len);

    ucoin_push_trim(&proto);

    //署名-node
    uint8_t hash[UCOIN_SZ_HASH256];
    ucoin_buf_t buf_sig;
    bool ret;

    ucoin_buf_init(&buf_sig);
    ucoin_util_hash256(hash, pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE * 4,
                                pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE * 4));
    ret = ucoin_tx_sign(&buf_sig, hash, pMsg->p_my_node->priv);
    if (ret) {
        *ppSigNode = pBuf->buf + sizeof(uint16_t) + offset_sig;
        ret = ln_misc_sigtrim(*ppSigNode, buf_sig.buf);
    }
    ucoin_buf_free(&buf_sig);

    //署名-btc
    if (ret) {
        ret = ucoin_tx_sign(&buf_sig, hash, pMsg->p_my_funding->priv);
        if (ret) {
            *ppSigBtc = pBuf->buf + sizeof(uint16_t) + offset_sig + LN_SZ_SIGNATURE * 2;
            ret = ln_misc_sigtrim(*ppSigBtc, buf_sig.buf);
        }
        ucoin_buf_free(&buf_sig);
    }

    return ret;
}


bool HIDDEN ln_msg_cnl_announce_read(ln_cnl_announce_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    //len=0
    if (Len < sizeof(uint16_t) + 398) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_ANNOUNCEMENT) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [64:node_signature_1]
    const uint8_t *p_node_signature1 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [64:node_signature_2]
    const uint8_t *p_node_signature2 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_1]
    const uint8_t *p_btc_signature1 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_2]
    const uint8_t *p_btc_signature2 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [8:short_channel_id]
    pMsg->short_channel_id = ln_misc_get64be(pData + pos);
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [33:node_id_1]
    const uint8_t *p_node_id1 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    //        [33:node_id_2]
    const uint8_t *p_node_id2 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_1]
    const uint8_t *p_btc_key1 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_2]
    const uint8_t *p_btc_key2 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    if (len != 0) {
        DBG_PRINTF("fail: invalid len: %d\n", len);
        *pLen = 0;      //error
        return false;
    }
//    pos += sizeof(uint16_t);
//
//    //        [len:features]
//    pMsg->features = *(pData + pos);
//    //pos++;

    //署名verify
    uint8_t hash[UCOIN_SZ_HASH256];
    ucoin_buf_t buf_sig;
    bool ret;

    ucoin_util_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE * 4, 142 + len);

    ucoin_buf_init(&buf_sig);
    ln_misc_sigexpand(&buf_sig, p_node_signature1);
    ret = ucoin_tx_verify(&buf_sig, hash, p_node_id1);
    ucoin_buf_free(&buf_sig);

    if (ret) {
        ln_misc_sigexpand(&buf_sig, p_node_signature2);
        ret = ucoin_tx_verify(&buf_sig, hash, p_node_id2);
        ucoin_buf_free(&buf_sig);
    }
    if (ret) {
        ln_misc_sigexpand(&buf_sig, p_btc_signature1);
        ret = ucoin_tx_verify(&buf_sig, hash, p_btc_key1);
        ucoin_buf_free(&buf_sig);
    }
    if (ret) {
        ln_misc_sigexpand(&buf_sig, p_btc_signature2);
        ret = ucoin_tx_verify(&buf_sig, hash, p_btc_key2);
        ucoin_buf_free(&buf_sig);
    }

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    //ln_msg_cnl_announce_print(pData, Len);
#endif  //DBG_PRINT_READ

    return ret;
}


void HIDDEN ln_msg_cnl_announce_print(const uint8_t *pData, uint16_t Len)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[channel_announcement]-------------------------------\n\n");

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_ANNOUNCEMENT) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return;
    }
    int pos = sizeof(uint16_t);
    Len -= sizeof(uint16_t);

    //        [64:node_signature_1]
    const uint8_t *p_node_signature1 = pData + pos;
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:node_signature_2]
    const uint8_t *p_node_signature2 = pData + pos;
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_1]
    const uint8_t *p_btc_signature1 = pData + pos;
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_2]
    const uint8_t *p_btc_signature2 = pData + pos;
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [8:short_channel_id]
    uint64_t short_channel_id = ln_misc_get64be(pData + pos);
    pos += LN_SZ_SHORT_CHANNEL_ID;
    Len -= LN_SZ_SHORT_CHANNEL_ID;

    //        [33:node_id_1]
    const uint8_t *p_node_id1 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    //        [33:node_id_2]
    const uint8_t *p_node_id2 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_1]
    const uint8_t *p_btc_key1 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_2]
    const uint8_t *p_btc_key2 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);
    Len -= sizeof(uint16_t);

    DBG_PRINTF2("p_node_signature1: ");
    DUMPBIN(p_node_signature1, LN_SZ_SIGNATURE);
    DBG_PRINTF2("p_node_signature2: ");
    DUMPBIN(p_node_signature2, LN_SZ_SIGNATURE);
    DBG_PRINTF2("p_btc_signature1: ");
    DUMPBIN(p_btc_signature1, LN_SZ_SIGNATURE);
    DBG_PRINTF2("p_btc_signature2: ");
    DUMPBIN(p_btc_signature2, LN_SZ_SIGNATURE);
    DBG_PRINTF2("short_channel_id= %" PRIx64 "\n", short_channel_id);
    DBG_PRINTF2("p_node_id1: ");
    DUMPBIN(p_node_id1, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_node_id2: ");
    DUMPBIN(p_node_id2, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_btc_key1: ");
    DUMPBIN(p_btc_key1, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_btc_key2: ");
    DUMPBIN(p_btc_key2, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("len= %d\n", len);
    if (len > 0) {
        DUMPBIN(pData + pos, len);
        Len -= len;
    }
    if (Len != 0) {
        DBG_PRINTF2("remain Length = %d\n", Len);
    }
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * node_announcement
 ********************************************************************/

bool HIDDEN ln_msg_node_announce_create(ucoin_buf_t *pBuf, const ln_node_announce_t *pMsg)
{
    //    type: 257 (node_announcement)
    //    data:
    //        [64:signature]
    //        [4:timestamp]
    //        [33:node_id]
    //        [3:rgb_color]
    //        [32:alias]
    //        [2:flen]
    //        [flen:features]
    //        [2:addrlen]
    //        [addrlen:addresses]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    //node_announce_print(pMsg);
#endif  //DBG_PRINT_CREATE

    //flen=0, addrlen=1
    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 141);

    //    type: 257 (node_announcement)
    ln_misc_push16be(&proto, MSGTYPE_NODE_ANNOUNCEMENT);

    //        [64:signature]
    //ucoin_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);
    proto.pos += LN_SZ_SIGNATURE;

    //        [4:timestamp]
    ln_misc_push32be(&proto, pMsg->timestamp);

    //        [33:node_id]
    ucoin_push_data(&proto, pMsg->p_my_node->pub, UCOIN_SZ_PUBKEY);

    //        [3:rgb_color]
    uint32_t val = 0;
    ucoin_push_data(&proto, (const uint8_t *)&val, 3);

    //        [32:alias]
    char alias[LN_SZ_ALIAS];
    size_t len_alias = strlen(pMsg->p_alias);
    if (len_alias >= LN_SZ_ALIAS) {
        memcpy(alias, pMsg->p_alias, LN_SZ_ALIAS);
    } else {
        memcpy(alias, pMsg->p_alias, len_alias);
        memset(alias + len_alias, 0, LN_SZ_ALIAS - len_alias);
    }
    ucoin_push_data(&proto, pMsg->p_alias, LN_SZ_ALIAS);

    //        [2:flen]
    ln_misc_push16be(&proto, 0);

//    //        [len:features]
//    ln_misc_push8(&proto, pMsg->features);

    //        [2:addrlen]
    ln_misc_push16be(&proto, 1);

    //        [addrlen:addresses]
    ln_misc_push8(&proto, 0);        //アドレス無し
//    ln_misc_push8(&proto, 1);        //IPv4
//    ucoin_push_data(&proto, pMsg->ipaddr, 4);
//    ln_misc_push16be(&proto, pMsg->port);

    assert(sizeof(uint16_t) + 141 == pBuf->len);

    ucoin_push_trim(&proto);

    //署名
    uint8_t hash[UCOIN_SZ_HASH256];
    ucoin_buf_t buf_sig;

    ucoin_buf_init(&buf_sig);
    ucoin_util_hash256(hash, pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    bool ret = ucoin_tx_sign(&buf_sig, hash, pMsg->p_my_node->priv);
    if (ret) {
        ret = ln_misc_sigtrim(pBuf->buf + sizeof(uint16_t), buf_sig.buf);
    }
    ucoin_buf_free(&buf_sig);

    return ret;
}


bool HIDDEN ln_msg_node_announce_read(ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    //flen=0, addrlen=0
    if (Len < sizeof(uint16_t) + 140) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_NODE_ANNOUNCEMENT) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [64:signature]
    const uint8_t *p_signature = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [4:timestamp]
    pMsg->timestamp = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [33:node_id]
    memcpy(pMsg->p_node_id, pData + pos, UCOIN_SZ_PUBKEY);
    pos += UCOIN_SZ_PUBKEY;

    //        [3:rgb_color]
    uint8_t rgb[3];
    memcpy(rgb, pData + pos, 3);
    if ((rgb[0] != 0) || (rgb[1] != 0) || (rgb[2] != 0)) {
        DBG_PRINTF("fail: invalid rgb_color\n");
        *pLen = 0;      //error
        return false;
    }
    pos += 3;

    //        [32:alias]
    memcpy(pMsg->p_alias, pData + pos, LN_SZ_ALIAS);
    pos += LN_SZ_ALIAS;

    //        [2:flen]
    uint16_t flen = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [flen:features]
    if (flen > 0) {
        DBG_PRINTF("features=");
        DUMPBIN(pData + pos, flen);

        //pMsg->features = *(pData + pos);
        pos += flen;
    }

    //        [2:addrlen]
    uint16_t addrlen = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [addrlen:addresses]
    if (addrlen > 0) {
        DBG_PRINTF("addresses=");
        DUMPBIN(pData + pos, addrlen);

        uint8_t add = *(pData + pos);
        if (add != 0) {
            DBG_PRINTF("NOT SUPPORT addrtype\n");
        }
        pos += addrlen;
    }

    *pLen -= pos;

    //署名verify
    uint8_t hash[UCOIN_SZ_HASH256];
    ucoin_buf_t buf_sig;

    ucoin_buf_init(&buf_sig);
    ln_misc_sigexpand(&buf_sig, p_signature);

    // node_announcementからsignatureを除いたサイズ = 76 + flen + addlen
    ucoin_util_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                76 + flen + addrlen);
    bool ret = ucoin_tx_verify(&buf_sig, hash, pMsg->p_node_id);
    ucoin_buf_free(&buf_sig);


#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    node_announce_print(pMsg);
#endif  //DBG_PRINT_READ

    return ret;
}


static void node_announce_print(const ln_node_announce_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[node_announcement]-------------------------------\n\n");
//    DBG_PRINTF2("p_node_signature: ");
//    DUMPBIN(pMsg->p_signature, LN_SZ_SIGNATURE);
    time_t t = (time_t)pMsg->timestamp;
    DBG_PRINTF2("timestamp: 0x%08lx : %s", t, ctime(&t));
    DBG_PRINTF2("p_node_id: ");
    DUMPBIN(pMsg->p_node_id, UCOIN_SZ_PUBKEY);
    char alias[LN_SZ_ALIAS + 1];
    memset(alias, 0, sizeof(alias));
    memcpy(alias, pMsg->p_alias, LN_SZ_ALIAS);
    DBG_PRINTF2("alias=%s\n", alias);
//    DBG_PRINTF2("features= %u\n", pMsg->features);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * channel_update
 ********************************************************************/

bool HIDDEN ln_msg_cnl_update_create(ucoin_buf_t *pBuf, const ln_cnl_update_t *pMsg)
{
    //    type: 258 (channel_update)
    //    data:
    //        [64:signature]
    //        [8:short_channel_id]
    //        [4:timestamp]
    //        [2:flags]
    //        [2:cltv_expiry_delta]
    //        [8:htlc_minimum_msat]
    //        [4:fee_base_msat]
    //        [4:fee_proportional_millionths]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    cnl_update_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 92);

    //    type: 258 (channel_update)
    ln_misc_push16be(&proto, MSGTYPE_CHANNEL_UPDATE);

    //        [64:signature]
    ucoin_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);

    //        [8:short_channel_id]
    ln_misc_push64be(&proto, pMsg->short_channel_id);

    //        [4:timestamp]
    ln_misc_push32be(&proto, pMsg->timestamp);

    //        [2:flags]
    ln_misc_push16be(&proto, pMsg->flags);

    //        [2:cltv_expiry_delta]
    ln_misc_push16be(&proto, pMsg->cltv_expiry_delta);

    //        [8:htlc_minimum_msat]
    ln_misc_push64be(&proto, pMsg->htlc_minimum_msat);

    //        [4:fee_base_msat]
    ln_misc_push32be(&proto, pMsg->fee_base_msat);

    //        [4:fee_proportional_millionths]
    ln_misc_push32be(&proto, pMsg->fee_prop_millionths);

    assert(sizeof(uint16_t) + 92 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


bool HIDDEN ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    if (Len < sizeof(uint16_t) + 92) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_UPDATE) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [64:signature]
    memcpy(pMsg->p_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    //        [8:short_channel_id]
    pMsg->short_channel_id = ln_misc_get64be(pData + pos);
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [4:timestamp]
    pMsg->timestamp = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [2:flags]
    pMsg->flags = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [2:cltv_expiry_delta]
    pMsg->cltv_expiry_delta = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [8:htlc_minimum_msat]
    pMsg->htlc_minimum_msat = ln_misc_get64be(pData + pos);
    pos += sizeof(uint32_t);

    //        [4:fee_base_msat]
    pMsg->fee_base_msat = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [4:fee_proportional_millionths]
    pMsg->fee_prop_millionths = ln_misc_get16be(pData + pos);
    pos += sizeof(uint32_t);

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    cnl_update_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void cnl_update_print(const ln_cnl_update_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[channel_update]-------------------------------\n\n");
    DBG_PRINTF2("p_node_signature: ");
    DUMPBIN(pMsg->p_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("short_channel_id: %016lx\n", pMsg->short_channel_id);
    time_t t = (time_t)pMsg->timestamp;
    DBG_PRINTF2("timestamp: 0x%08lx : %s", t, ctime(&t));
    DBG_PRINTF2("flags= 0x%04x\n", pMsg->flags);
    DBG_PRINTF2("cltv_expiry_delta= %u\n", pMsg->cltv_expiry_delta);
    DBG_PRINTF2("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    DBG_PRINTF2("fee_base_msat= %u\n", pMsg->fee_base_msat);
    DBG_PRINTF2("fee_prop_millionths= %u\n", pMsg->fee_prop_millionths);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


/********************************************************************
 * announcement_signatures
 ********************************************************************/

bool HIDDEN ln_msg_announce_signs_create(ucoin_buf_t *pBuf, const ln_announce_signs_t *pMsg)
{
    //    type: 259 (announcement_signatures)
    //    data:
    //        [32:channel_id]
    //        [8:short_channel_id]
    //        [64:node_signature]
    //        [64:bitcoin_signature]

    ucoin_push_t    proto;

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    announce_signs_print(pMsg);
#endif  //DBG_PRINT_CREATE

    //len=1
    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 168);

    //    type: 259 (announcement_signatures)
    ln_misc_push16be(&proto, MSGTYPE_ANNOUNCEMENT_SIGNATURES);

    //        [32:channel-id]
    ucoin_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:short_channel_id]
    ln_misc_push64be(&proto, pMsg->short_channel_id);

    //        [64:node_signature]
    ucoin_push_data(&proto, pMsg->p_node_signature, LN_SZ_SIGNATURE);

    //        [64:bitcoin_signature]
    ucoin_push_data(&proto, pMsg->p_btc_signature, LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 168 == pBuf->len);

    ucoin_push_trim(&proto);

    return true;
}


uint64_t HIDDEN ln_msg_announce_signs_read_short_cnl_id(const uint8_t *pData, uint16_t Len, const uint8_t *pChannelId)
{
    //len=1
    if (Len < sizeof(uint16_t) + 168) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return 0;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_ANNOUNCEMENT_SIGNATURES) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return 0;
    }
    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    int cmp = memcmp(pChannelId, pData + pos, LN_SZ_CHANNEL_ID);
    if (cmp != 0) {
        DBG_PRINTF("fail: channel_id mismatch\n");
        return 0;
    }
    pos += LN_SZ_CHANNEL_ID;

    return ln_misc_get64be(pData + pos);
}


bool HIDDEN ln_msg_announce_signs_read(ln_announce_signs_t *pMsg, const uint8_t *pData, uint16_t *pLen)
{
    uint16_t Len = *pLen;

    //len=1
    if (Len < sizeof(uint16_t) + 168) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_ANNOUNCEMENT_SIGNATURES) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        *pLen = 0;      //error
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:short_channel_id]
    pMsg->short_channel_id = ln_misc_get64be(pData + pos);
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [64:node_signature]
    memcpy(pMsg->p_node_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature]
    memcpy(pMsg->p_btc_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    *pLen -= pos;

#ifdef DBG_PRINT_READ
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    announce_signs_print(pMsg);
#endif  //DBG_PRINT_READ

    return true;
}


static void announce_signs_print(const ln_announce_signs_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[announcement_signatures]-------------------------------\n\n");
    DBG_PRINTF2("channel_id: ");
    DUMPBIN(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    DBG_PRINTF2("short_channel_id: %016lx\n", pMsg->short_channel_id);
    DBG_PRINTF2("p_node_signature: ");
    DUMPBIN(pMsg->p_node_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("p_btc_signature: ");
    DUMPBIN(pMsg->p_btc_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}

