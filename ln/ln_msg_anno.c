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
 *  @sa     https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

#include "utl_time.h"

#include "btc_crypto.h"
#include "btc_sig.h"

#include "ln_msg_anno.h"
#include "ln_misc.h"
#include "ln_node.h"
#include "ln_signer.h"
#include "ln_local.h"


/********************************************************************
 * macros
 ********************************************************************/

#ifdef DEVELOPER_MODE
#define DBG_PRINT_READ_CNL
#define DBG_PRINT_READ_NOD
#define DBG_PRINT_READ_UPD
#endif
#define DBG_PRINT_CREATE_CNL
#define DBG_PRINT_CREATE_NOD
#define DBG_PRINT_CREATE_UPD
#define DBG_PRINT_CREATE_SIG
#define DBG_PRINT_READ_SIG


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

static bool cnl_announce_sign(const ln_self_t *self, uint8_t *pData, uint16_t Len, btc_script_pubkey_order_t Sort);
static bool cnl_announce_ptr(cnl_announce_ptr_t *pPtr, const uint8_t *pData, uint16_t Len);

#if defined(DBG_PRINT_CREATE_NOD) || defined(DBG_PRINT_READ_NOD)
static void node_announce_print(const ln_node_announce_t *pMsg);
#endif
#if defined(DBG_PRINT_CREATE_SIG) || defined(DBG_PRINT_READ_SIG)
static void announce_signs_print(const ln_announce_signs_t *pMsg);
#endif


/********************************************************************
 * channel_announcement
 ********************************************************************/

bool HIDDEN ln_msg_cnl_announce_create(const ln_self_t *self, utl_buf_t *pBuf, const ln_cnl_announce_create_t *pMsg)
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

    utl_push_t    proto;

#if 0
    LOGD("--------------------------\n");
    LOGD("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    LOGD("p_my_node_pub: ");
    DUMPD(pMsg->p_my_node_pub, BTC_SZ_PUBKEY);
    LOGD("p_peer_node_pub: ");
    DUMPD(pMsg->p_peer_node_pub, BTC_SZ_PUBKEY);
    LOGD("p_my_funding_pub: ");
    DUMPD(pMsg->p_my_funding_pub, BTC_SZ_PUBKEY);
    LOGD("p_peer_funding_pub: ");
    DUMPD(pMsg->p_peer_funding_pub, BTC_SZ_PUBKEY);
    LOGD("sort: %d\n", (int)pMsg->sort);
    LOGD("--------------------------\n");
#endif

    //len=0
    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 430);

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
    utl_push_data(&proto, gGenesisChainHash, sizeof(gGenesisChainHash));

    //        [8:short_channel_id]
    ln_misc_push64be(&proto, pMsg->short_channel_id);

    const uint8_t *p_node_1;
    const uint8_t *p_node_2;
    const uint8_t *p_btc_1;
    const uint8_t *p_btc_2;
    if (pMsg->sort == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
        //自ノードが先
        p_node_1 = pMsg->p_my_node_pub;
        p_node_2 = pMsg->p_peer_node_pub;
        p_btc_1 = pMsg->p_my_funding_pub;
        p_btc_2 = pMsg->p_peer_funding_pub;
    } else {
        p_node_1 = pMsg->p_peer_node_pub;
        p_node_2 = pMsg->p_my_node_pub;
        p_btc_1 = pMsg->p_peer_funding_pub;
        p_btc_2 = pMsg->p_my_funding_pub;
    }
    //        [33:node_id_1]
    utl_push_data(&proto, p_node_1, BTC_SZ_PUBKEY);

    //        [33:node_id_2]
    utl_push_data(&proto, p_node_2, BTC_SZ_PUBKEY);

    //        [33:bitcoin_key_1]
    utl_push_data(&proto, p_btc_1, BTC_SZ_PUBKEY);

    //        [33:bitcoin_key_2]
    utl_push_data(&proto, p_btc_2, BTC_SZ_PUBKEY);

    assert(sizeof(uint16_t) + 430 == pBuf->len);

    utl_push_trim(&proto);

    bool ret = cnl_announce_sign(self, pBuf->buf, pBuf->len, pMsg->sort);
    if (ret) {
#ifdef DBG_PRINT_CREATE_CNL
        LOGD("short_channel_id=%016" PRIx64 "\n", pMsg->short_channel_id);
        ln_msg_cnl_announce_print(pBuf->buf, pBuf->len);
#endif  //DBG_PRINT_CREATE_CNL
    } else {
        LOGD("something error\n");
    }

    return ret;
}


bool ln_msg_cnl_announce_read(ln_cnl_announce_read_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //len=0
    if (Len < sizeof(uint16_t) + 430) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_ANNOUNCEMENT) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }

    cnl_announce_ptr_t ptr;
    bool ret = cnl_announce_ptr(&ptr, pData, Len);
    if (ret) {
        memcpy(pMsg->node_id1, ptr.p_node_id1, BTC_SZ_PUBKEY);
        memcpy(pMsg->node_id2, ptr.p_node_id2, BTC_SZ_PUBKEY);
        memcpy(pMsg->btc_key1, ptr.p_btc_key1, BTC_SZ_PUBKEY);
        memcpy(pMsg->btc_key2, ptr.p_btc_key2, BTC_SZ_PUBKEY);
        pMsg->short_channel_id = ptr.short_channel_id;
#ifdef DBG_PRINT_READ_CNL
        LOGD("short_channel_id=%016" PRIx64 "\n", pMsg->short_channel_id);
        ln_msg_cnl_announce_print(pData, Len);
#endif
    } else {
        LOGD("something error\n");
    }

    return ret;
}


bool HIDDEN ln_msg_cnl_announce_verify(const uint8_t *pData, uint16_t Len)
{
    //署名verify
    uint8_t hash[BTC_SZ_HASH256];
    bool ret;

    cnl_announce_ptr_t ptr;
    ret = cnl_announce_ptr(&ptr, pData, Len);
    if (!ret) {
        return false;
    }

    btc_md_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE * 4,
                                Len - (sizeof(uint16_t) + LN_SZ_SIGNATURE * 4));
    // LOGD("hash=");
    // DUMPD(hash, BTC_SZ_HASH256);

    ret = btc_sig_verify_rs(ptr.p_node_signature1, hash, ptr.p_node_id1);
    assert(ret);

    if (ret) {
        ret = btc_sig_verify_rs(ptr.p_node_signature2, hash, ptr.p_node_id2);
        assert(ret);
    }
    if (ret) {
        ret = btc_sig_verify_rs(ptr.p_btc_signature1, hash, ptr.p_btc_key1);
        assert(ret);
    }
    if (ret) {
        ret = btc_sig_verify_rs(ptr.p_btc_signature2, hash, ptr.p_btc_key2);
        assert(ret);
    }

    return ret;
}


void HIDDEN ln_msg_cnl_announce_print(const uint8_t *pData, uint16_t Len)
{
#ifdef PTARM_DEBUG
    LOGD("-[channel_announcement]-------------------------------\n");

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_ANNOUNCEMENT) {
        LOGD("fail: type not match: %04x\n", type);
        DUMPD(pData, Len);
        return;
    }
    int pos = sizeof(uint16_t);
    Len -= sizeof(uint16_t);

    //        [64:node_signature_1]
    LOGD("p_node_signature1: ");
    DUMPD(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:node_signature_2]
    LOGD("p_node_signature2: ");
    DUMPD(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_1]
    LOGD("p_btc_signature1: ");
    DUMPD(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature_2]
    LOGD("p_btc_signature2: ");
    DUMPD(pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;
    Len -= LN_SZ_SIGNATURE;

    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    LOGD("len= %d\n", len);
    pos += sizeof(uint16_t);
    Len -= sizeof(uint16_t);

    //        [len:features]
    if (len > 0) {
        DUMPD(pData + pos, len);
        pos += len;
        Len -= len;
    }

    //    [32:chain_hash]
    LOGD("chain_hash: ");
    DUMPD(pData + pos, BTC_SZ_HASH256);
    pos += BTC_SZ_HASH256;
    Len -= BTC_SZ_HASH256;

    //        [8:short_channel_id]
    LOGD("short_channel_id= %016" PRIx64 "\n", ln_misc_get64be(pData + pos));
    pos += LN_SZ_SHORT_CHANNEL_ID;
    Len -= LN_SZ_SHORT_CHANNEL_ID;

    //        [33:node_id_1]
    LOGD("p_node_id1: ");
    DUMPD(pData + pos, BTC_SZ_PUBKEY);
    pos += BTC_SZ_PUBKEY;
    Len -= BTC_SZ_PUBKEY;

    //        [33:node_id_2]
    LOGD("p_node_id2: ");
    DUMPD(pData + pos, BTC_SZ_PUBKEY);
    pos += BTC_SZ_PUBKEY;
    Len -= BTC_SZ_PUBKEY;

    //        [33:bitcoin_key_1]
    LOGD("p_btc_key1: ");
    DUMPD(pData + pos, BTC_SZ_PUBKEY);
    pos += BTC_SZ_PUBKEY;
    Len -= BTC_SZ_PUBKEY;

    //        [33:bitcoin_key_2]
    LOGD("p_btc_key2: ");
    DUMPD(pData + pos, BTC_SZ_PUBKEY);
    //pos += BTC_SZ_PUBKEY;
    Len -= BTC_SZ_PUBKEY;

    if (Len != 0) {
        LOGD("remain Length = %d\n", Len);
    }
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


void HIDDEN ln_msg_get_anno_signs(ln_self_t *self, uint8_t **pp_sig_node, uint8_t **pp_sig_btc, bool bLocal, btc_script_pubkey_order_t Sort)
{
    if ( ((Sort == BTC_SCRYPT_PUBKEY_ORDER_ASC) && bLocal) ||
         ((Sort != BTC_SCRYPT_PUBKEY_ORDER_ASC) && !bLocal) ) {
        LOGD("addr: 1\n");
        *pp_sig_node = self->cnl_anno.buf + sizeof(uint16_t);
    } else {
        LOGD("addr: 2\n");
        *pp_sig_node = self->cnl_anno.buf + sizeof(uint16_t) + LN_SZ_SIGNATURE;
    }
    *pp_sig_btc = *pp_sig_node + LN_SZ_SIGNATURE * 2;

    // ln_msg_cnl_announce_print(self->cnl_anno.buf, self->cnl_anno.len);
}


bool HIDDEN ln_msg_cnl_announce_update_short_cnl_id(ln_self_t *self, uint64_t ShortChannelId, btc_script_pubkey_order_t Sort)
{
    uint8_t *pData = self->cnl_anno.buf;
    int pos = sizeof(uint16_t) + LN_SZ_SIGNATURE * 4;
    //        [2:len]
    uint16_t len = ln_misc_get16be(pData + pos);
    pos += sizeof(len) + len + BTC_SZ_HASH256;
    //        [8:short_channel_id]
    for (size_t lp = 0; lp < sizeof(uint64_t); lp++) {
        *(pData + pos + sizeof(uint64_t) - 1 - lp) = (uint8_t)ShortChannelId;
        ShortChannelId >>= 8;
    }

    return cnl_announce_sign(self, self->cnl_anno.buf, self->cnl_anno.len, Sort);
}


static bool cnl_announce_sign(const ln_self_t *self, uint8_t *pData, uint16_t Len, btc_script_pubkey_order_t Sort)
{
    int offset_sig;
    if (Sort == BTC_SCRYPT_PUBKEY_ORDER_ASC) {
        //自ノードが先
        offset_sig = 0;
    } else {
        offset_sig = LN_SZ_SIGNATURE;
    }

    //署名-node
    uint8_t hash[BTC_SZ_HASH256];
    bool ret;

    btc_md_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE * 4,
                                Len - (sizeof(uint16_t) + LN_SZ_SIGNATURE * 4));
    //LOGD("hash=");
    //DUMPD(hash, BTC_SZ_HASH256);

    ret = ln_node_sign_nodekey(pData + sizeof(uint16_t) + offset_sig, hash);
    if (!ret) {
        LOGD("fail: sign node\n");
        goto LABEL_EXIT;
    }

    //署名-btc
    ret = ln_signer_sign_rs(pData + sizeof(uint16_t) + offset_sig + LN_SZ_SIGNATURE * 2,
                    hash, &self->priv_data, MSG_FUNDIDX_FUNDING);
    if (!ret) {
        LOGD("fail: sign btc\n");
        //goto LABEL_EXIT;
    }

LABEL_EXIT:
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
        LOGD("features(%d): ", len);
        DUMPD(pData + pos, len);
        pos += len;
    }

    //    [32:chain_hash]
    int cmp = memcmp(gGenesisChainHash, pData + pos, sizeof(gGenesisChainHash));
    if (cmp != 0) {
        LOGD("fail: chain_hash mismatch\n");
        LOGD("node: ");
        DUMPD(gGenesisChainHash, BTC_SZ_HASH256);
        LOGD("msg:  ");
        DUMPD(pData + pos, BTC_SZ_HASH256);
        return false;
    }
    pos += sizeof(gGenesisChainHash);

    //        [8:short_channel_id]
    pPtr->short_channel_id = ln_misc_get64be(pData + pos);
    if (pPtr->short_channel_id == 0) {
        LOGD("fail: short_channel_id == 0\n");
    }
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [33:node_id_1]
    pPtr->p_node_id1 = pData + pos;
    pos += BTC_SZ_PUBKEY;

    //        [33:node_id_2]
    pPtr->p_node_id2 = pData + pos;
    pos += BTC_SZ_PUBKEY;

    //        [33:bitcoin_key_1]
    pPtr->p_btc_key1 = pData + pos;
    pos += BTC_SZ_PUBKEY;

    //        [33:bitcoin_key_2]
    pPtr->p_btc_key2 = pData + pos;
    pos += BTC_SZ_PUBKEY;

    return Len == pos;
}


/********************************************************************
 * node_announcement
 ********************************************************************/

bool HIDDEN ln_msg_node_announce_create(utl_buf_t *pBuf, const ln_node_announce_t *pMsg)
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

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE_NOD
   LOGD("@@@@@ %s @@@@@\n", __func__);
   node_announce_print(pMsg);
#endif  //DBG_PRINT_CREATE_NOD

    //flen=0
    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 141 + M_ADDRLEN2[pMsg->addr.type]);

    //    type: 257 (node_announcement)
    ln_misc_push16be(&proto, MSGTYPE_NODE_ANNOUNCEMENT);

    //        [64:signature]
    //utl_push_data(&proto, pMsg->p_signature, LN_SZ_SIGNATURE);
    proto.pos += LN_SZ_SIGNATURE;

    //        [2:flen]
    ln_misc_push16be(&proto, 0);

//    //        [len:features]
//    ln_misc_push8(&proto, pMsg->features);

    //        [4:timestamp]
    ln_misc_push32be(&proto, pMsg->timestamp);

    //        [33:node_id]
    utl_push_data(&proto, pMsg->p_node_id, BTC_SZ_PUBKEY);

    //        [3:rgb_color]
    utl_push_data(&proto, pMsg->rgbcolor, 3);

    //        [32:alias]
    char alias[LN_SZ_ALIAS + 1];
    size_t len_alias = strlen(pMsg->p_alias);
    if (len_alias >= LN_SZ_ALIAS) {
        memcpy(alias, pMsg->p_alias, LN_SZ_ALIAS);
    } else {
        memcpy(alias, pMsg->p_alias, len_alias);
        memset(alias + len_alias, 0, LN_SZ_ALIAS - len_alias);
    }
    utl_push_data(&proto, pMsg->p_alias, LN_SZ_ALIAS);

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
        utl_push_data(&proto, pMsg->addr.addrinfo.addr, M_ADDRLEN[pMsg->addr.type]);
        ln_misc_push16be(&proto, pMsg->addr.port);
        break;
    default:
        return false;
    }

    assert(sizeof(uint16_t) + 141 + M_ADDRLEN2[pMsg->addr.type] == pBuf->len);

    utl_push_trim(&proto);

    //署名
    uint8_t hash[BTC_SZ_HASH256];

    btc_md_hash256(hash, pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    //LOGD("data=");
    //DUMPD(pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE, pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    //LOGD("hash=");
    //DUMPD(hash, BTC_SZ_HASH256);

    bool ret = ln_node_sign_nodekey(pBuf->buf + sizeof(uint16_t), hash);

    return ret;
}


bool ln_msg_node_announce_read(ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //flen=0, addrlen=0
    if (Len < sizeof(uint16_t) + 140) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_NODE_ANNOUNCEMENT) {
        LOGD("fail: type not match: %04x\n", type);
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
        LOGD("features(%d)=", flen);
        DUMPD(pData + pos, flen);

        //pMsg->features = *(pData + pos);
        pos += flen;
    }

    //        [4:timestamp]
    pMsg->timestamp = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [33:node_id]
    if (pMsg->p_node_id != NULL) {
        memcpy(pMsg->p_node_id, pData + pos, BTC_SZ_PUBKEY);
    }
    pos += BTC_SZ_PUBKEY;

    //        [3:rgb_color]
    memcpy(pMsg->rgbcolor, pData + pos, 3);
    pos += 3;

    //        [32:alias]
    if (pMsg->p_alias != NULL) {
        memcpy(pMsg->p_alias, pData + pos, LN_SZ_ALIAS);
        pMsg->p_alias[LN_SZ_ALIAS] = '\0';
    }
    pos += LN_SZ_ALIAS;

    //        [2:addrlen]
    uint16_t addrlen = ln_misc_get16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [addrlen:addresses]
    if (addrlen > 0) {
        //addr type
        pMsg->addr.type = (ln_nodedesc_t)*(pData + pos);
        if (pMsg->addr.type > LN_NODEDESC_MAX) {
            LOGD("fail: unknown address descriptor(%02x)\n", pMsg->addr.type);
            return false;
        }
        addrlen--;
        if (addrlen < M_ADDRLEN2[pMsg->addr.type]) {
            LOGD("fail: less addrlen(%02x:%d)\n", pMsg->addr.type, addrlen);
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

    assert(Len >= pos);

#ifdef DBG_PRINT_READ_NOD
  LOGD("@@@@@ %s @@@@@\n", __func__);
  node_announce_print(pMsg);
#endif  //DBG_PRINT_READ_NOD

    bool ret = true;
    if (pMsg->p_node_id != NULL) {
        //署名verify
        uint8_t hash[BTC_SZ_HASH256];

        btc_md_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                    pos - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
        //LOGD("data=");
        //DUMPD(pData + sizeof(uint16_t) + LN_SZ_SIGNATURE, Len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
        //LOGD("hash=");
        //DUMPD(hash, BTC_SZ_HASH256);

        ret = btc_sig_verify_rs(p_signature, hash, pMsg->p_node_id);
        if (!ret) {
            LOGD("fail: verify\n");
        }
    }

    return ret;
}


#if defined(DBG_PRINT_CREATE_NOD) || defined(DBG_PRINT_READ_NOD)
static void node_announce_print(const ln_node_announce_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[node_announcement]-------------------------------\n");
    char time[UTL_SZ_TIME_FMT_STR + 1];
    LOGD("timestamp: %lu : %s\n", (unsigned long)pMsg->timestamp, utl_time_fmt(time, pMsg->timestamp));
    if (pMsg->p_node_id != NULL) {
        LOGD("p_node_id: ");
        DUMPD(pMsg->p_node_id, BTC_SZ_PUBKEY);
    }
    if (pMsg->p_alias != NULL) {
        char alias[LN_SZ_ALIAS + 1];
        memset(alias, 0, sizeof(alias));
        memcpy(alias, pMsg->p_alias, LN_SZ_ALIAS);
        LOGD("alias=%s\n", alias);
    }
//    LOGD("features= %u\n", pMsg->features);
    LOGD("addr desc: %02x\n", pMsg->addr.type);
    if (pMsg->addr.type != LN_NODEDESC_NONE) {
        LOGD("port=%d\n", pMsg->addr.port);
        LOGD("addr=");
        DUMPD(pMsg->addr.addrinfo.addr, M_ADDRLEN[pMsg->addr.type]);
    }
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif


/********************************************************************
 * channel_update
 ********************************************************************/

bool HIDDEN ln_msg_cnl_update_create(utl_buf_t *pBuf, const ln_cnl_update_t *pMsg)
{
    //    type: 258 (channel_update)
    //    data:
    //        [64:signature]
    //        [32:chain_hash]
    //        [8:short_channel_id]
    //        [4:timestamp]
    //        [1:message_flags]
    //        [1:channel_flags]
    //        [2:cltv_expiry_delta]
    //        [8:htlc_minimum_msat]
    //        [4:fee_base_msat]
    //        [4:fee_proportional_millionths]

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE_UPD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    ln_msg_cnl_update_print(pMsg);
#endif  //DBG_PRINT_CREATE_UPD

    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 128);

    //    type: 258 (channel_update)
    ln_misc_push16be(&proto, MSGTYPE_CHANNEL_UPDATE);

    //        [64:signature]
    //utl_push_data(&proto, pMsg->signature, LN_SZ_SIGNATURE);
    proto.pos += LN_SZ_SIGNATURE;

    //        [32:chain_hash]
    utl_push_data(&proto, gGenesisChainHash, sizeof(gGenesisChainHash));

    //        [8:short_channel_id]
    ln_misc_push64be(&proto, pMsg->short_channel_id);

    //        [4:timestamp]
    ln_misc_push32be(&proto, pMsg->timestamp);

    //        [1:message_flags]
    ln_misc_push8(&proto, pMsg->message_flags);

    //        [1:channel_flags]
    ln_misc_push8(&proto, pMsg->channel_flags);

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
    uint8_t hash[BTC_SZ_HASH256];
    bool ret;

    btc_md_hash256(hash, pBuf->buf + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                pBuf->len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    LOGD("hash=");
    DUMPD(hash, BTC_SZ_HASH256);

    ret = ln_node_sign_nodekey(pBuf->buf + sizeof(uint16_t), hash);
    if (ret) {
        utl_push_trim(&proto);
    } else {
        LOGD("fail: sign\n");
    }

    return ret;
}


bool ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 128) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_CHANNEL_UPDATE) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);
    bool result;

    //        [64:signature]
    //memcpy(pMsg->signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    //    [32:chain_hash]
    result = (memcmp(gGenesisChainHash, pData + pos, sizeof(gGenesisChainHash)) == 0);
    if (!result) {
        LOGD("fail: chain_hash mismatch\n");
        LOGD("node: ");
        DUMPD(gGenesisChainHash, BTC_SZ_HASH256);
        LOGD("msg:  ");
        DUMPD(pData + pos, BTC_SZ_HASH256);
    }
    pos += sizeof(gGenesisChainHash);

    //        [8:short_channel_id]
    pMsg->short_channel_id = ln_misc_get64be(pData + pos);
    if (pMsg->short_channel_id == 0) {
        LOGD("fail: short_channel_id == 0\n");
        return false;
    }
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [4:timestamp]
    pMsg->timestamp = ln_misc_get32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [1:message_flags]
    pMsg->message_flags = *(pData + pos);
    pos += sizeof(uint8_t);

    //        [1:channel_flags]
    pMsg->channel_flags = *(pData + pos);
    pos += sizeof(uint8_t);

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

    //        [8:htlc_maximum_msat] (option_channel_htlc_max)
    if (pMsg->message_flags & LN_CNLUPD_MSGFLAGS_HTLCMAX) {
        if (Len >= pos + sizeof(uint64_t)) {
            pMsg->htlc_maximum_msat = ln_misc_get64be(pData + pos);
            pos += sizeof(uint64_t);
        } else {
            result = false;
            LOGE("fail: NO option_channel_htlc_max field\n");
        }
    } else {
        pMsg->htlc_maximum_msat = 0;
    }

    assert(Len >= pos);

#ifdef DBG_PRINT_READ_UPD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    ln_msg_cnl_update_print(pMsg);
#endif  //DBG_PRINT_READ_UPD

    return result;
}


bool HIDDEN ln_msg_cnl_update_verify(const uint8_t *pPubkey, const uint8_t *pData, uint16_t Len)
{
    //署名verify
    bool ret;
    uint8_t hash[BTC_SZ_HASH256];

    // channel_updateからsignatureを除いたサイズ
    btc_md_hash256(hash, pData + sizeof(uint16_t) + LN_SZ_SIGNATURE,
                                Len - (sizeof(uint16_t) + LN_SZ_SIGNATURE));
    //LOGD("hash=");
    //DUMPD(hash, BTC_SZ_HASH256);

    ret = btc_sig_verify_rs(pData + sizeof(uint16_t), hash, pPubkey);

    return ret;
}


void HIDDEN ln_msg_cnl_update_print(const ln_cnl_update_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[channel_update]-------------------------------\n");
    //LOGD("p_node_signature: ");
    //DUMPD(pMsg->signature, LN_SZ_SIGNATURE);
    LOGD("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    char time[UTL_SZ_TIME_FMT_STR + 1];
    LOGD("timestamp: %lu : %s\n", (unsigned long)pMsg->timestamp, utl_time_fmt(time, pMsg->timestamp));
    LOGD("message_flags= 0x%02x\n", pMsg->message_flags);
    LOGD("   option_channel_htlc_max=%d\n", (pMsg->message_flags & LN_CNLUPD_MSGFLAGS_HTLCMAX));
    LOGD("channel_flags= 0x%02x\n", pMsg->channel_flags);
    LOGD("    direction: %s\n", ln_cnlupd_direction(pMsg) ? "node_2" : "node_1");
    LOGD("    %s\n", ln_cnlupd_enable(pMsg) ? "enable" : "disable");
    LOGD("cltv_expiry_delta= %u\n", pMsg->cltv_expiry_delta);
    LOGD("htlc_minimum_msat= %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    LOGD("fee_base_msat= %u\n", pMsg->fee_base_msat);
    LOGD("fee_prop_millionths= %u\n", pMsg->fee_prop_millionths);
    if (pMsg->htlc_maximum_msat > 0) {
        LOGD("htlc_maximum_msat= %" PRIu64 "\n", pMsg->htlc_maximum_msat);
    }
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


/********************************************************************
 * announcement_signatures
 ********************************************************************/

bool HIDDEN ln_msg_announce_signs_create(utl_buf_t *pBuf, const ln_announce_signs_t *pMsg)
{
    //    type: 259 (announcement_signatures)
    //    data:
    //        [32:channel_id]
    //        [8:short_channel_id]
    //        [64:node_signature]
    //        [64:bitcoin_signature]

    utl_push_t    proto;

#ifdef DBG_PRINT_CREATE_SIG
    LOGD("@@@@@ %s @@@@@\n", __func__);
    announce_signs_print(pMsg);
#endif  //DBG_PRINT_CREATE_SIG

    //len=1
    utl_push_init(&proto, pBuf, sizeof(uint16_t) + 168);

    //    type: 259 (announcement_signatures)
    ln_misc_push16be(&proto, MSGTYPE_ANNOUNCEMENT_SIGNATURES);

    //        [32:channel-id]
    utl_push_data(&proto, pMsg->p_channel_id, LN_SZ_CHANNEL_ID);

    //        [8:short_channel_id]
    ln_misc_push64be(&proto, pMsg->short_channel_id);

    //        [64:node_signature]
    utl_push_data(&proto, pMsg->p_node_signature, LN_SZ_SIGNATURE);

    //        [64:bitcoin_signature]
    utl_push_data(&proto, pMsg->p_btc_signature, LN_SZ_SIGNATURE);

    assert(sizeof(uint16_t) + 168 == pBuf->len);

    utl_push_trim(&proto);

    return true;
}


uint64_t HIDDEN ln_msg_announce_signs_read_short_cnl_id(const uint8_t *pData, uint16_t Len, const uint8_t *pChannelId)
{
    //len=1
    if (Len < sizeof(uint16_t) + 168) {
        LOGD("fail: invalid length: %d\n", Len);
        return 0;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_ANNOUNCEMENT_SIGNATURES) {
        LOGD("fail: type not match: %04x\n", type);
        return 0;
    }
    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    int cmp = memcmp(pChannelId, pData + pos, LN_SZ_CHANNEL_ID);
    if (cmp != 0) {
        LOGD("fail: channel_id mismatch\n");
        return 0;
    }
    pos += LN_SZ_CHANNEL_ID;

    return ln_misc_get64be(pData + pos);
}


bool HIDDEN ln_msg_announce_signs_read(ln_announce_signs_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //len=1
    if (Len < sizeof(uint16_t) + 168) {
        LOGD("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = ln_misc_get16be(pData);
    if (type != MSGTYPE_ANNOUNCEMENT_SIGNATURES) {
        LOGD("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [32:channel-id]
    memcpy(pMsg->p_channel_id, pData + pos, LN_SZ_CHANNEL_ID);
    pos += LN_SZ_CHANNEL_ID;

    //        [8:short_channel_id]
    uint64_t short_channel_id = ln_misc_get64be(pData + pos);
    if (pMsg->short_channel_id == 0) {
        pMsg->short_channel_id = short_channel_id;
    } else if (pMsg->short_channel_id != short_channel_id) {
        LOGD("fail: short_channel_id mismatch: %016" PRIx64 " != %016" PRIx64 "\n", pMsg->short_channel_id, short_channel_id);
        return false;
    }
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [64:node_signature]
    memcpy(pMsg->p_node_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    //        [64:bitcoin_signature]
    memcpy(pMsg->p_btc_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    assert(Len >= pos);

#ifdef DBG_PRINT_READ_SIG
    LOGD("@@@@@ %s @@@@@\n", __func__);
    announce_signs_print(pMsg);
#endif  //DBG_PRINT_READ_SIG

    return true;
}


#if defined(DBG_PRINT_CREATE_SIG) || defined(DBG_PRINT_READ_SIG)
static void announce_signs_print(const ln_announce_signs_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[announcement_signatures]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    LOGD("p_node_signature: ");
    DUMPD(pMsg->p_node_signature, LN_SZ_SIGNATURE);
    LOGD("p_btc_signature: ");
    DUMPD(pMsg->p_btc_signature, LN_SZ_SIGNATURE);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif
