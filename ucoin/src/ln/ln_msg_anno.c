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
 *  @sa     https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md
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
#include "ln_node.h"


/********************************************************************
 * macros
 ********************************************************************/

#define DBG_PRINT_CREATE
#define DBG_PRINT_READ


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    const uint8_t   *p_node_signature1;                 ///< 64: node_signature_1
    const uint8_t   *p_node_signature2;                 ///< 64: node_signature_2
    const uint8_t   *p_btc_signature1;                  ///< 64: bitcoin_signature_1
    const uint8_t   *p_btc_signature2;                  ///< 64: bitcoin_signature_2

    uint64_t        short_channel_id;                   ///< 8:  short_channel_id

    const uint8_t   *p_node_id1;                        ///< 33: node_id_1
    const uint8_t   *p_node_id2;                        ///< 33: node_id_2
    const uint8_t   *p_btc_key1;                        ///< 33: bitcoin_key_1
    const uint8_t   *p_btc_key2;                        ///< 33: bitcoin_key_2
} cnl_announce_ptr_t;


/**************************************************************************
 * const variables
 **************************************************************************/

static const uint8_t M_ADDRLEN[] = { 0, 4, 16, 10, 35 };
static const uint8_t M_ADDRLEN2[] = { 0, 6, 18, 12, 37 };    //port考慮


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool cnl_announce_ptr(cnl_announce_ptr_t *pPtr, const uint8_t *pData, uint16_t Len);
static void node_announce_print(const ln_node_announce_t *pMsg);
static void announce_signs_print(const ln_announce_signs_t *pMsg);


/********************************************************************
 * channel_announcement
 ********************************************************************/

bool HIDDEN ln_msg_cnl_announce_create(ucoin_buf_t *pBuf, const ln_cnl_announce_create_t *pMsg)
{
    //    type: 256 (channel_announcement)
    //    data:
    //        [64:node_signature_1]
    //        [64:node_signature_2]
    //        [64:bitcoin_signature_1]
    //        [64:bitcoin_signature_2]
    //        [2:len]
    //        [len:features]
    //        [32:chain_hash]
    //        [8:short_channel_id]
    //        [33:node_id_1]
    //        [33:node_id_2]
    //        [33:bitcoin_key_1]
    //        [33:bitcoin_key_2]

    ucoin_push_t    proto;

#if 1
    DBG_PRINTF("--------------------------\n");
    DBG_PRINTF2("short_channel_id: %" PRIx64 "\n", pMsg->short_channel_id);
    DBG_PRINTF2("p_my_node_pub: ");
    DUMPBIN(pMsg->p_my_node_pub, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_peer_node_pub: ");
    DUMPBIN(pMsg->p_peer_node_pub, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_my_funding->pub: ");
    DUMPBIN(pMsg->p_my_funding->pub, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("p_peer_funding_pub: ");
    DUMPBIN(pMsg->p_peer_funding_pub, UCOIN_SZ_PUBKEY);
    DBG_PRINTF2("sort: %d\n", (int)pMsg->sort);
    DBG_PRINTF("--------------------------\n");
#endif

    //len=0
    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 430);

    //    type: 256 (channel_announcement)
    ln_misc_push16be(&proto, MSGTYPE_CHANNEL_ANNOUNCEMENT);

    //        [64:node_signature_1]
    //        [64:node_signature_2]
    //        [64:bitcoin_signature_1]
    //        [64:bitcoin_signature_2]
    memset(pBuf->buf + proto.pos, 0xcc, LN_SZ_SIGNATURE * 4);
    proto.pos += LN_SZ_SIGNATURE * 4;

    //        [2:len]
    ln_misc_push16be(&proto, 0);

//    //        [len:features]
//    ln_misc_push8(&proto, pMsg->features);

    //        [32:chain_hash]
    ucoin_push_data(&proto, gGenesisChainHash, sizeof(gGenesisChainHash));

    //        [8:short_channel_id]
    ln_misc_push64be(&proto, pMsg->short_channel_id);

    const uint8_t *p_node_1;
    const uint8_t *p_node_2;
    const uint8_t *p_btc_1;
    const uint8_t *p_btc_2;
    int offset_sig;
    if (pMsg->sort == UCOIN_KEYS_SORT_ASC) {
        //自ノードが先
        p_node_1 = pMsg->p_my_node_pub;
        p_node_2 = pMsg->p_peer_node_pub;
        p_btc_1 = pMsg->p_my_funding->pub;
        p_btc_2 = pMsg->p_peer_funding_pub;
        offset_sig = 0;
    } else {
        p_node_1 = pMsg->p_peer_node_pub;
        p_node_2 = pMsg->p_my_node_pub;
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

    assert(sizeof(uint16_t) + 430 == pBuf->len);

    ucoin_push_trim(&proto);

    //署名-node
    uint8_t hash[UCOIN_SZ_HASH256];
    bool ret;

    ucoin_util_hash256(hash, pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE * 4,
                                pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE * 4));
    //DBG_PRINTF("hash=");
    //DUMPBIN(hash, UCOIN_SZ_HASH256);

    ret = ln_node_sign_nodekey(pBuf->buf + sizeof(uint16_t) + offset_sig, hash);
    if (!ret) {
        DBG_PRINTF("fail: sign node\n");
        goto LABEL_EXIT;
    }

    //署名-btc
    ret = ucoin_tx_sign_rs(pBuf->buf + sizeof(uint16_t) + offset_sig + LN_SZ_SIGNATURE * 2,
                    hash, pMsg->p_my_funding->priv);
    if (!ret) {
        DBG_PRINTF("fail: sign btc\n");
        goto LABEL_EXIT;
    }

LABEL_EXIT:
#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    if (ret) {
        ln_msg_cnl_announce_print(pBuf->buf, pBuf->len);
    } else {
        DBG_PRINTF("something error\n");
    }
#endif  //DBG_PRINT_CREATE

    return ret;
}


bool HIDDEN ln_msg_cnl_announce_read(ln_cnl_announce_read_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //len=0
    if (Len < sizeof(uint16_t) + 430) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_ANNOUNCEMENT) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }

    cnl_announce_ptr_t ptr;
    bool ret = cnl_announce_ptr(&ptr, pData, Len);
    if (ret) {
        memcpy(pMsg->node_id1, ptr.p_node_id1, UCOIN_SZ_PUBKEY);
        memcpy(pMsg->node_id2, ptr.p_node_id2, UCOIN_SZ_PUBKEY);
        memcpy(pMsg->btc_key1, ptr.p_btc_key1, UCOIN_SZ_PUBKEY);
        memcpy(pMsg->btc_key2, ptr.p_btc_key2, UCOIN_SZ_PUBKEY);
        pMsg->short_channel_id = ptr.short_channel_id;
    }

    return ret;
}


bool HIDDEN ln_msg_cnl_announce_verify(const uint8_t *pData, uint16_t Len)
{
    //署名verify
    uint8_t hash[UCOIN_SZ_HASH256];
    bool ret;

    cnl_announce_ptr_t ptr;
    ret = cnl_announce_ptr(&ptr, pData, Len);
    if (!ret) {
        return false;
    }

    ucoin_util_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE * 4,
                                Len - (sizeof(uint16_t) + LN_SZ_SIGNATURE * 4));
    DBG_PRINTF("hash=");
    DUMPBIN(hash, UCOIN_SZ_HASH256);

    ret = ucoin_tx_verify_rs(ptr.p_node_signature1, hash, ptr.p_node_id1);
    assert(ret);

    if (ret) {
        ret = ucoin_tx_verify_rs(ptr.p_node_signature2, hash, ptr.p_node_id2);
        assert(ret);
    }
    if (ret) {
        ret = ucoin_tx_verify_rs(ptr.p_btc_signature1, hash, ptr.p_btc_key1);
        assert(ret);
    }
    if (ret) {
        ret = ucoin_tx_verify_rs(ptr.p_btc_signature2, hash, ptr.p_btc_key2);
        assert(ret);
    }

    return ret;
}


static bool cnl_announce_ptr(cnl_announce_ptr_t *pPtr, const uint8_t *pData, uint16_t Len)
{
    int pos = sizeof(uint16_t);

    //        [64:node_signature_1]
    pPtr->p_node_signature1 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [64:node_signature_2]
    pPtr->p_node_signature2 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_1]
    pPtr->p_btc_signature1 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_2]
    pPtr->p_btc_signature2 = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    pos += sizeof(len);

    //        [len:features]
    if (len > 0) {
        DBG_PRINTF("features(%d): ", len);
        DUMPBIN(pData + pos, len);
        pos += len;
    }

    //    [32:chain_hash]
    int cmp = memcmp(gGenesisChainHash, pData + pos, sizeof(gGenesisChainHash));
    if (cmp != 0) {
        DBG_PRINTF("fail: chain_hash mismatch\n");
        DBG_PRINTF2("node: ");
        DUMPBIN(gGenesisChainHash, LN_SZ_HASH);
        DBG_PRINTF2("msg:  ");
        DUMPBIN(pData + pos, LN_SZ_HASH);
        return false;
    }
    pos += sizeof(gGenesisChainHash);

    //        [8:short_channel_id]
    pPtr->short_channel_id = ln_misc_get64be(pData + pos);
    if (pPtr->short_channel_id == 0) {
        DBG_PRINTF("fail: short_channel_id == 0\n");
        return false;
    }
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [33:node_id_1]
    pPtr->p_node_id1 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    //        [33:node_id_2]
    pPtr->p_node_id2 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_1]
    pPtr->p_btc_key1 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_2]
    pPtr->p_btc_key2 = pData + pos;
    pos += UCOIN_SZ_PUBKEY;

    return Len == pos;
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
    DBG_PRINTF2("p_node_signature1: ");
    DUMPBIN(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:node_signature_2]
    DBG_PRINTF2("p_node_signature2: ");
    DUMPBIN(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_1]
    DBG_PRINTF2("p_btc_signature1: ");
    DUMPBIN(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_2]
    DBG_PRINTF2("p_btc_signature2: ");
    DUMPBIN(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    DBG_PRINTF2("len= %d\n", len);
    pos += sizeof(uint16_t);
    Len -= sizeof(uint16_t);

    //        [len:features]
    if (len > 0) {
        DUMPBIN(pData + pos, len);
        pos += len;
        Len -= len;
    }

    //    [32:chain_hash]
    DBG_PRINTF2("chain_hash: ");
    DUMPBIN(pData + pos, UCOIN_SZ_HASH256);
    pos += UCOIN_SZ_HASH256;
    Len -= UCOIN_SZ_HASH256;

    //        [8:short_channel_id]
    DBG_PRINTF2("short_channel_id= %016" PRIx64 "\n", ln_misc_get64be(pData + pos));
    pos += LN_SZ_SHORT_CHANNEL_ID;
    Len -= LN_SZ_SHORT_CHANNEL_ID;

    //        [33:node_id_1]
    DBG_PRINTF2("p_node_id1: ");
    DUMPBIN(pData + pos, UCOIN_SZ_PUBKEY);
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    //        [33:node_id_2]
    DBG_PRINTF2("p_node_id2: ");
    DUMPBIN(pData + pos, UCOIN_SZ_PUBKEY);
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_1]
    DBG_PRINTF2("p_btc_key1: ");
    DUMPBIN(pData + pos, UCOIN_SZ_PUBKEY);
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    //        [33:bitcoin_key_2]
    DBG_PRINTF2("p_btc_key2: ");
    DUMPBIN(pData + pos, UCOIN_SZ_PUBKEY);
    pos += UCOIN_SZ_PUBKEY;
    Len -= UCOIN_SZ_PUBKEY;

    if (Len != 0) {
        DBG_PRINTF2("remain Length = %d\n", Len);
    }
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}


void HIDDEN ln_msg_get_anno_signs(ln_self_t *self, uint8_t **pp_sig_node, uint8_t **pp_sig_btc, bool bLocal, ucoin_keys_sort_t Sort)
{
    if ( ((Sort == UCOIN_KEYS_SORT_ASC) && bLocal) ||
         ((Sort != UCOIN_KEYS_SORT_ASC) && !bLocal) ) {
        DBG_PRINTF("addr: 1\n");
        *pp_sig_node = self->cnl_anno.buf + sizeof(uint16_t);
    } else {
        DBG_PRINTF("addr: 2\n");
        *pp_sig_node = self->cnl_anno.buf + sizeof(uint16_t) + LN_SZ_SIGNATURE;
    }
    *pp_sig_btc = *pp_sig_node + LN_SZ_SIGNATURE * 2;

    ln_msg_cnl_announce_print(self->cnl_anno.buf, self->cnl_anno.len);
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
   node_announce_print(pMsg);
#endif  //DBG_PRINT_CREATE

    //flen=0
    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 141 + M_ADDRLEN2[pMsg->addr.type]);

    //    type: 257 (node_announcement)
    ln_misc_push16be(&proto, MSGTYPE_NODE_ANNOUNCEMENT);

    //        [64:signature]
    //ucoin_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);
    proto.pos += LN_SZ_SIGNATURE;

    //        [2:flen]
    ln_misc_push16be(&proto, 0);

//    //        [len:features]
//    ln_misc_push8(&proto, pMsg->features);

    //        [4:timestamp]
    ln_misc_push32be(&proto, pMsg->timestamp);

    //        [33:node_id]
    ucoin_push_data(&proto, pMsg->p_node_id, UCOIN_SZ_PUBKEY);

    //        [3:rgb_color]
    ucoin_push_data(&proto, pMsg->rgbcolor, 3);

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

    //        [2:addrlen]
    //        [addrlen:addresses]
    switch (pMsg->addr.type) {
    case LN_NODEDESC_NONE:
        //noneは登録しない
        ln_misc_push16be(&proto, 0);
        break;
    case LN_NODEDESC_IPV4:
    case LN_NODEDESC_IPV6:
    case LN_NODEDESC_ONIONV2:
    case LN_NODEDESC_ONIONV3:
        ln_misc_push16be(&proto, 1 + M_ADDRLEN2[pMsg->addr.type]);
        ln_misc_push8(&proto, pMsg->addr.type);
        ucoin_push_data(&proto, pMsg->addr.addrinfo.addr, M_ADDRLEN[pMsg->addr.type]);
        ln_misc_push16be(&proto, pMsg->addr.port);
        break;
    default:
        return false;
    }

    assert(sizeof(uint16_t) + 141 + M_ADDRLEN2[pMsg->addr.type] == pBuf->len);

    ucoin_push_trim(&proto);

    //署名
    uint8_t hash[UCOIN_SZ_HASH256];

    ucoin_util_hash256(hash, pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    //DBG_PRINTF("data=");
    //DUMPBIN(pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE, pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    //DBG_PRINTF("hash=");
    //DUMPBIN(hash, UCOIN_SZ_HASH256);

    bool ret = ln_node_sign_nodekey(pBuf->buf + sizeof(uint16_t), hash);

    return ret;
}


bool HIDDEN ln_msg_node_announce_read(ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //flen=0, addrlen=0
    if (Len < sizeof(uint16_t) + 140) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_NODE_ANNOUNCEMENT) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [64:signature]
    const uint8_t *p_signature = pData + pos;
    pos += LN_SZ_SIGNATURE;

    //        [2:flen]
    uint16_t flen = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [flen:features]
    if (flen > 0) {
        DBG_PRINTF("features(%d)=", flen);
        DUMPBIN(pData + pos, flen);

        //pMsg->features = *(pData + pos);
        pos += flen;
    }

    //        [4:timestamp]
    pMsg->timestamp = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [33:node_id]
    if (pMsg->p_node_id != NULL) {
        memcpy(pMsg->p_node_id, pData + pos, UCOIN_SZ_PUBKEY);
    }
    pos += UCOIN_SZ_PUBKEY;

    //        [3:rgb_color]
    memcpy(pMsg->rgbcolor, pData + pos, 3);
    pos += 3;

    //        [32:alias]
    if (pMsg->p_alias != NULL) {
        memcpy(pMsg->p_alias, pData + pos, LN_SZ_ALIAS);
    }
    pos += LN_SZ_ALIAS;

    //        [2:addrlen]
    uint16_t addrlen = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [addrlen:addresses]
    if (addrlen > 0) {
        //addr type
        pMsg->addr.type = *(pData + pos);
        if (pMsg->addr.type > LN_NODEDESC_MAX) {
            DBG_PRINTF("fail: unknown address descriptor(%02x)\n", pMsg->addr.type);
            return false;
        }
        addrlen--;
        if (addrlen < M_ADDRLEN2[pMsg->addr.type]) {
            DBG_PRINTF("fail: less addrlen(%02x:%d)\n", pMsg->addr.type, addrlen);
            return false;
        }
        pos++;

        //addr data
        if (pMsg->addr.type != LN_NODEDESC_NONE) {
            int addrpos = pos;
            memcpy(pMsg->addr.addrinfo.addr, pData + addrpos, M_ADDRLEN[pMsg->addr.type]);
            addrpos += M_ADDRLEN[pMsg->addr.type];
            pMsg->addr.port = ln_misc_get16be(pData + addrpos);
        }
    } else {
        pMsg->addr.type = LN_NODEDESC_NONE;
    }
    pos += addrlen;

    //assert(Len == pos);
    if (Len != pos) {
        DBG_PRINTF("length not match: Len=%d, pos=%d\n", Len, pos);
        DBG_PRINTF("addrlen=%" PRIu16 "\n", addrlen);
        node_announce_print(pMsg);
        DBG_PRINTF("raw=");
        DUMPBIN(pData + sizeof(uint16_t), Len - sizeof(uint16_t));
        DBG_PRINTF("over=");
        DUMPBIN(pData + pos, Len - pos);
    }

//#ifdef DBG_PRINT_READ
//   DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
//   node_announce_print(pMsg);
//#endif  //DBG_PRINT_READ

    bool ret = true;
    if (pMsg->p_node_id != NULL) {
        //署名verify
        uint8_t hash[UCOIN_SZ_HASH256];

        ucoin_util_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                    pos - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
        //DBG_PRINTF("data=");
        //DUMPBIN(pData + sizeof(uint16_t) + LN_SZ_SIGNATURE, Len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
        //DBG_PRINTF("hash=");
        //DUMPBIN(hash, UCOIN_SZ_HASH256);

        ret = ucoin_tx_verify_rs(p_signature, hash, pMsg->p_node_id);
        if (!ret) {
            DBG_PRINTF("fail: verify\n");
        }
    }

    return ret;
}


#if 1
static void node_announce_print(const ln_node_announce_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[node_announcement]-------------------------------\n\n");
    time_t t = (time_t)pMsg->timestamp;
    DBG_PRINTF2("timestamp: %lu : %s", (unsigned long)t, ctime(&t));
    if (pMsg->p_node_id != NULL) {
        DBG_PRINTF2("p_node_id: ");
        DUMPBIN(pMsg->p_node_id, UCOIN_SZ_PUBKEY);
    }
    if (pMsg->p_alias != NULL) {
        char alias[LN_SZ_ALIAS + 1];
        memset(alias, 0, sizeof(alias));
        memcpy(alias, pMsg->p_alias, LN_SZ_ALIAS);
        DBG_PRINTF2("alias=%s\n", alias);
    }
//    DBG_PRINTF2("features= %u\n", pMsg->features);
    DBG_PRINTF2("addr desc: %02x\n", pMsg->addr.type);
    if (pMsg->addr.type != LN_NODEDESC_NONE) {
        DBG_PRINTF2("port=%d\n", pMsg->addr.port);
        DBG_PRINTF2("addr=");
        DUMPBIN(pMsg->addr.addrinfo.addr, M_ADDRLEN[pMsg->addr.type]);
    }
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}
#endif


/********************************************************************
 * channel_update
 ********************************************************************/

bool HIDDEN ln_msg_cnl_update_create(ucoin_buf_t *pBuf, const ln_cnl_update_t *pMsg)
{
    //    type: 258 (channel_update)
    //    data:
    //        [64:signature]
    //        [32:chain_hash]
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
    ln_msg_cnl_update_print(pMsg);
#endif  //DBG_PRINT_CREATE

    ucoin_push_init(&proto, pBuf, sizeof(uint16_t) + 128);

    //    type: 258 (channel_update)
    ln_misc_push16be(&proto, MSGTYPE_CHANNEL_UPDATE);

    //        [64:signature]
    //ucoin_push_data(&proto, pMsg->signature, LN_SZ_SIGNATURE);
    proto.pos += LN_SZ_SIGNATURE;

    //        [32:chain_hash]
    ucoin_push_data(&proto, gGenesisChainHash, sizeof(gGenesisChainHash));

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

    assert(sizeof(uint16_t) + 128 == pBuf->len);

    //署名
    uint8_t hash[UCOIN_SZ_HASH256];
    bool ret;

    ucoin_util_hash256(hash, pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    DBG_PRINTF("hash=");
    DUMPBIN(hash, UCOIN_SZ_HASH256);

    ret = ln_node_sign_nodekey(pBuf->buf + sizeof(uint16_t), hash);
    if (ret) {
        ucoin_push_trim(&proto);
    } else {
        DBG_PRINTF("fail: sign\n");
    }

    return ret;
}


bool HIDDEN ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 128) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_UPDATE) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [64:signature]
    //memcpy(pMsg->signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    //    [32:chain_hash]
    bool chain_match = (memcmp(gGenesisChainHash, pData + pos, sizeof(gGenesisChainHash)) == 0);
    if (!chain_match) {
        DBG_PRINTF("fail: chain_hash mismatch\n");
        DBG_PRINTF2("node: ");
        DUMPBIN(gGenesisChainHash, LN_SZ_HASH);
        DBG_PRINTF2("msg:  ");
        DUMPBIN(pData + pos, LN_SZ_HASH);
    }
    pos += sizeof(gGenesisChainHash);

    //        [8:short_channel_id]
    pMsg->short_channel_id = ln_misc_get64be(pData + pos);
    if (pMsg->short_channel_id == 0) {
        DBG_PRINTF("fail: short_channel_id == 0\n");
        return false;
    }
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
    pos += sizeof(uint64_t);

    //        [4:fee_base_msat]
    pMsg->fee_base_msat = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [4:fee_proportional_millionths]
    pMsg->fee_prop_millionths = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    assert(Len == pos);

#ifdef DBG_PRINT_CREATE
    DBG_PRINTF("\n@@@@@ %s @@@@@\n", __func__);
    ln_msg_cnl_update_print(pMsg);
#endif  //DBG_PRINT_CREATE

    return chain_match;
}


bool HIDDEN ln_msg_cnl_update_verify(const uint8_t *pPubkey, const uint8_t *pData, uint16_t Len)
{
    //署名verify
    bool ret;
    uint8_t hash[UCOIN_SZ_HASH256];

    // channel_updateからsignatureを除いたサイズ
    ucoin_util_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                Len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    //DBG_PRINTF("hash=");
    //DUMPBIN(hash, UCOIN_SZ_HASH256);

    ret = ucoin_tx_verify_rs(pData + sizeof(uint16_t), hash, pPubkey);

    return ret;
}


void HIDDEN ln_msg_cnl_update_print(const ln_cnl_update_t *pMsg)
{
#ifdef UCOIN_DEBUG
    DBG_PRINTF2("-[channel_update]-------------------------------\n\n");
    //DBG_PRINTF2("p_node_signature: ");
    //DUMPBIN(pMsg->signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    time_t t = (time_t)pMsg->timestamp;
    DBG_PRINTF2("timestamp: %lu : %s", (unsigned long)t, ctime(&t));
    DBG_PRINTF2("flags= 0x%04x\n", pMsg->flags);
    DBG_PRINTF2("    direction: %s\n", ln_cnlupd_direction(pMsg) ? "node_2" : "node_1");
    DBG_PRINTF2("    %s\n", ln_cnlupd_enable(pMsg) ? "enable" : "disable");
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


bool HIDDEN ln_msg_announce_signs_read(ln_announce_signs_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //len=1
    if (Len < sizeof(uint16_t) + 168) {
        DBG_PRINTF("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_ANNOUNCEMENT_SIGNATURES) {
        DBG_PRINTF("fail: type not match: %04x\n", type);
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

    assert(Len == pos);

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
    DBG_PRINTF2("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    DBG_PRINTF2("p_node_signature: ");
    DUMPBIN(pMsg->p_node_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("p_btc_signature: ");
    DUMPBIN(pMsg->p_btc_signature, LN_SZ_SIGNATURE);
    DBG_PRINTF2("--------------------------------\n\n\n");
#endif  //UCOIN_DEBUG
}

