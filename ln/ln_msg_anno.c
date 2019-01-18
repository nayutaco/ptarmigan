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

#include "utl_time.h"
#include "utl_int.h"

#include "btc_crypto.h"
#include "btc_sig.h"
#include "btc_buf.h"

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
#define DBG_PRINT_WRITE_CNL
#define DBG_PRINT_WRITE_NOD
#define DBG_PRINT_WRITE_UPD
#define DBG_PRINT_WRITE_SIG
#define DBG_PRINT_READ_SIG


/********************************************************************
 * typedefs
 ********************************************************************/

/**************************************************************************
 * const variables
 **************************************************************************/

static const uint8_t M_ADDRLEN[] = { 0, 4, 16, 10, 35 };
static const uint8_t M_ADDRLEN2[] = { 0, 6, 18, 12, 37 };    //port考慮


/**************************************************************************
 * prototypes
 **************************************************************************/

#if defined(DBG_PRINT_WRITE_SIG) || defined(DBG_PRINT_READ_SIG)
static void announcement_signatures_print(const ln_msg_announcement_signatures_t *pMsg);
#endif
#if defined(DBG_PRINT_WRITE_CNL) || defined(DBG_PRINT_READ_CNL)
static void channel_announcement_print(const ln_msg_channel_announcement_t *pMsg);
#endif
#if defined(DBG_PRINT_WRITE_NOD) || defined(DBG_PRINT_READ_NOD)
static void node_announce_print(const ln_node_announce_t *pMsg);
#endif


/********************************************************************
 * announcement_signatures
 ********************************************************************/

bool HIDDEN ln_msg_announcement_signatures_write(utl_buf_t *pBuf, const ln_msg_announcement_signatures_t *pMsg)
{
#ifdef DBG_PRINT_WRITE_SIG
    LOGD("@@@@@ %s @@@@@\n", __func__);
    announcement_signatures_print(pMsg);
#endif  //DBG_PRINT_WRITE_SIG

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_ANNOUNCEMENT_SIGNATURES)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_channel_id, LN_SZ_CHANNEL_ID)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->short_channel_id)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_node_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_bitcoin_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool HIDDEN ln_msg_announcement_signatures_read(ln_msg_announcement_signatures_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_ANNOUNCEMENT_SIGNATURES) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_channel_id, (int32_t)LN_SZ_CHANNEL_ID)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->short_channel_id)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_node_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_bitcoin_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ_SIG
    LOGD("@@@@@ %s @@@@@\n", __func__);
    announcement_signatures_print(pMsg);
#endif  //DBG_PRINT_READ_SIG
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


#if defined(DBG_PRINT_WRITE_SIG) || defined(DBG_PRINT_READ_SIG)
static void announcement_signatures_print(const ln_msg_announcement_signatures_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[announcement_signatures]-------------------------------\n");
    LOGD("channel_id: ");
    DUMPD(pMsg->p_channel_id, LN_SZ_CHANNEL_ID);
    LOGD("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    LOGD("node_signature: ");
    DUMPD(pMsg->p_node_signature, LN_SZ_SIGNATURE);
    LOGD("bitcoin_signature: ");
    DUMPD(pMsg->p_bitcoin_signature, LN_SZ_SIGNATURE);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}
#endif


/********************************************************************
 * channel_announcement
 ********************************************************************/

bool HIDDEN ln_msg_channel_announcement_write(utl_buf_t *pBuf, const ln_msg_channel_announcement_t *pMsg)
{
#ifdef DBG_PRINT_WRITE_CNL
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_announcement_print(pMsg);
#endif  //DBG_PRINT_WRITE_CNL

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_CHANNEL_ANNOUNCEMENT)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_node_signature_1, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_node_signature_2, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_bitcoin_signature_1, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_bitcoin_signature_2, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->len)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_features, pMsg->len)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_chain_hash, BTC_SZ_HASH256)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->short_channel_id)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_node_id_1, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_node_id_2, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_bitcoin_key_1, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_bitcoin_key_2, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool /*HIDDEN*/ ln_msg_channel_announcement_read(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_CHANNEL_ANNOUNCEMENT) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_node_signature_1, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_node_signature_2, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_bitcoin_signature_1, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_bitcoin_signature_2, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->len)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_features, pMsg->len)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_chain_hash, BTC_SZ_HASH256)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->short_channel_id)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_node_id_1, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_node_id_2, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_bitcoin_key_1, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_bitcoin_key_2, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ_CNL
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_announcement_print(pMsg);
#endif  //DBG_PRINT_READ_CNL
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void channel_announcement_print(const ln_msg_channel_announcement_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[channel_announcement]-------------------------------\n");
    LOGD("node_signature_1: ");
    DUMPD(pMsg->p_node_signature_1, LN_SZ_SIGNATURE);
    LOGD("node_signature_2: ");
    DUMPD(pMsg->p_node_signature_2, LN_SZ_SIGNATURE);
    LOGD("bitcoin_signature_1: ");
    DUMPD(pMsg->p_bitcoin_signature_1, LN_SZ_SIGNATURE);
    LOGD("bitcoin_signature_2: ");
    DUMPD(pMsg->p_bitcoin_signature_2, LN_SZ_SIGNATURE);
    LOGD("features: ");
    DUMPD(pMsg->p_features, pMsg->len);
    LOGD("chain_hash: ");
    DUMPD(pMsg->p_chain_hash, BTC_SZ_HASH256);
    LOGD("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    LOGD("node_id_1: ");
    DUMPD(pMsg->p_node_id_1, BTC_SZ_PUBKEY);
    LOGD("node_id_2: ");
    DUMPD(pMsg->p_node_id_2, BTC_SZ_PUBKEY);
    LOGD("bitcoin_key_1: ");
    DUMPD(pMsg->p_bitcoin_key_1, BTC_SZ_PUBKEY);
    LOGD("bitcoin_key_2: ");
    DUMPD(pMsg->p_bitcoin_key_2, BTC_SZ_PUBKEY);
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


bool HIDDEN ln_msg_channel_announcement_sign(uint8_t *pData, uint16_t Len, const uint8_t *pBtcPrivKey, btc_script_pubkey_order_t Order)
{
    uint16_t offset_preimg = sizeof(uint16_t) + LN_SZ_SIGNATURE * 4;
    uint16_t offset_sig = (Order == BTC_SCRYPT_PUBKEY_ORDER_ASC) ? 0 : LN_SZ_SIGNATURE;

    uint8_t hash[BTC_SZ_HASH256];
    btc_md_hash256(hash, pData + offset_preimg, Len - offset_preimg);
    if (!ln_node_sign_nodekey(pData + sizeof(uint16_t) + offset_sig, hash)) {
        LOGE("fail: sign node\n");
        return false;
    }

    if (!btc_sig_sign_rs(pData + sizeof(uint16_t) + offset_sig + LN_SZ_SIGNATURE * 2, hash, pBtcPrivKey)) {
        LOGE("fail: sign btc\n");
        return false;
    }
    return true;
}


bool HIDDEN ln_msg_channel_announcement_verify(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE * 4;
    btc_md_hash256(hash, pData + offset, Len - offset);
    if (!btc_sig_verify_rs(pMsg->p_node_signature_1, hash, pMsg->p_node_id_1)) return false;
    if (!btc_sig_verify_rs(pMsg->p_node_signature_2, hash, pMsg->p_node_id_2)) return false;
    if (!btc_sig_verify_rs(pMsg->p_bitcoin_signature_1, hash, pMsg->p_bitcoin_key_1)) return false;
    if (!btc_sig_verify_rs(pMsg->p_bitcoin_signature_2, hash, pMsg->p_bitcoin_key_2)) return false;
    return true;
}


bool HIDDEN ln_msg_channel_announcement_print(const uint8_t *pData, uint16_t Len)
{
    ln_msg_channel_announcement_t msg;
    if (!ln_msg_channel_announcement_read(&msg, pData, Len)) return false;
#ifndef DBG_PRINT_READ_CNL //ln_msg_channel_announcement_read don't print
    channel_announcement_print(&msg);
#endif
    return true;
}


void HIDDEN ln_msg_channel_announcement_get_sigs(uint8_t *pData, uint8_t **ppSigNode, uint8_t **ppSigBtc, bool bLocal, btc_script_pubkey_order_t Order)
{
    uint16_t offset;
    if ( ((Order == BTC_SCRYPT_PUBKEY_ORDER_ASC) && bLocal) ||
         ((Order != BTC_SCRYPT_PUBKEY_ORDER_ASC) && !bLocal) ) {
        LOGD("addr: 1\n");
        offset = 0;
    } else {
        LOGD("addr: 2\n");
        offset = LN_SZ_SIGNATURE;
    }
    *ppSigNode = pData + sizeof(uint16_t) + offset;
    *ppSigBtc = *ppSigNode + LN_SZ_SIGNATURE * 2;
}


bool HIDDEN ln_msg_channel_announcement_update_short_channel_id(uint8_t *pData, uint64_t ShortChannelId)
{
    uint16_t pos = sizeof(uint16_t); //type
    pos += LN_SZ_SIGNATURE * 4; //sigs
    uint16_t len = utl_int_pack_u16be(pData + pos);
    pos += 2; //len
    pos += len; //features
    pos += BTC_SZ_HASH256; //channel_hash
    utl_int_unpack_u64be(pData + pos, ShortChannelId);
    return true;
}


/********************************************************************
 * node_announcement
 ********************************************************************/

bool HIDDEN ln_msg_node_announce_write(utl_buf_t *pBuf, const ln_node_announce_t *pMsg)
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

#ifdef DBG_PRINT_WRITE_NOD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    node_announce_print(pMsg);
#endif  //DBG_PRINT_WRITE_NOD

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
    utl_push_data(&proto, pMsg->p_rgbcolor, LN_SZ_RGBCOLOR);

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

    utl_push_trim(&proto);

    return true;
}


bool /*HIDDEN*/ ln_msg_node_announce_read(ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    //flen=0, addrlen=0
    if (Len < sizeof(uint16_t) + 140) {
        LOGE("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_NODE_ANNOUNCEMENT) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [64:signature]
    pos += LN_SZ_SIGNATURE;

    //        [2:flen]
    uint16_t flen = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [flen:features]
    if (flen > 0) {
        LOGD("features(%d)=", flen);
        DUMPD(pData + pos, flen);

        //pMsg->features = *(pData + pos);
        pos += flen;
    }

    //        [4:timestamp]
    pMsg->timestamp = utl_int_pack_u32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [33:node_id]
    if (pMsg->p_node_id != NULL) {
        memcpy(pMsg->p_node_id, pData + pos, BTC_SZ_PUBKEY);
    }
    pos += BTC_SZ_PUBKEY;

    //        [3:rgb_color]
    memcpy(pMsg->p_rgbcolor, pData + pos, 3);
    pos += 3;

    //        [32:alias]
    if (pMsg->p_alias != NULL) {
        memcpy(pMsg->p_alias, pData + pos, LN_SZ_ALIAS);
        pMsg->p_alias[LN_SZ_ALIAS] = '\0';
    }
    pos += LN_SZ_ALIAS;

    //        [2:addrlen]
    uint16_t addrlen = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [addrlen:addresses]
    if (addrlen > 0) {
        //addr type
        pMsg->addr.type = (ln_nodedesc_t)*(pData + pos);
        if (pMsg->addr.type > LN_NODEDESC_MAX) {
            LOGE("fail: unknown address descriptor(%02x)\n", pMsg->addr.type);
            return false;
        }
        addrlen--;
        if (addrlen < M_ADDRLEN2[pMsg->addr.type]) {
            LOGE("fail: less addrlen(%02x:%d)\n", pMsg->addr.type, addrlen);
            return false;
        }
        pos++;

        //addr data
        if (pMsg->addr.type != LN_NODEDESC_NONE) {
            int addrpos = pos;
            memcpy(pMsg->addr.addrinfo.addr, pData + addrpos, M_ADDRLEN[pMsg->addr.type]);
            addrpos += M_ADDRLEN[pMsg->addr.type];
            pMsg->addr.port = utl_int_pack_u16be(pData + addrpos);
        }
    } else {
        pMsg->addr.type = LN_NODEDESC_NONE;
    }
    pos += addrlen;

    if (Len < pos) {
        LOGE("fail: length\n");
        return false;
    }

#ifdef DBG_PRINT_READ_NOD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    node_announce_print(pMsg);
#endif  //DBG_PRINT_READ_NOD
    return true;
}


bool HIDDEN ln_msg_node_announce_sign(uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return ln_node_sign_nodekey(pData + sizeof(uint16_t), hash);
}


bool HIDDEN ln_msg_node_announce_verify(const ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return btc_sig_verify_rs(pData + sizeof(uint16_t), hash, pMsg->p_node_id);
}


#if defined(DBG_PRINT_WRITE_NOD) || defined(DBG_PRINT_READ_NOD)
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

bool HIDDEN ln_msg_cnl_update_write(utl_buf_t *pBuf, const ln_cnl_update_t *pMsg)
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
    //        [8:htlc_maximum_msat] (option_channel_htlc_max)

    utl_push_t    proto;

#ifdef DBG_PRINT_WRITE_UPD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    ln_msg_cnl_update_print(pMsg);
#endif  //DBG_PRINT_WRITE_UPD

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

    if (pMsg->message_flags & LN_CNLUPD_MSGFLAGS_HTLCMAX) {
        //        [8:htlc_maximum_msat] (option_channel_htlc_max)
        ln_misc_push64be(&proto, pMsg->htlc_maximum_msat);
    }
    utl_push_trim(&proto);
    return true;
}


bool /*HIDDEN*/ ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    if (Len < sizeof(uint16_t) + 128) {
        LOGE("fail: invalid length: %d\n", Len);
        return false;
    }

    uint16_t type = utl_int_pack_u16be(pData);
    if (type != MSGTYPE_CHANNEL_UPDATE) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    int pos = sizeof(uint16_t);

    //        [64:signature]
    //memcpy(pMsg->p_signature, pData + pos, LN_SZ_SIGNATURE);
    pos += LN_SZ_SIGNATURE;

    //    [32:chain_hash]
    pMsg->p_chain_hash = pData + pos;
    pos += BTC_SZ_HASH256;

    //        [8:short_channel_id]
    pMsg->short_channel_id = utl_int_pack_u64be(pData + pos);
    if (pMsg->short_channel_id == 0) {
        LOGE("fail: short_channel_id == 0\n");
        return false;
    }
    pos += LN_SZ_SHORT_CHANNEL_ID;

    //        [4:timestamp]
    pMsg->timestamp = utl_int_pack_u32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [1:message_flags]
    pMsg->message_flags = *(pData + pos);
    pos += sizeof(uint8_t);

    //        [1:channel_flags]
    pMsg->channel_flags = *(pData + pos);
    pos += sizeof(uint8_t);

    //        [2:cltv_expiry_delta]
    pMsg->cltv_expiry_delta = utl_int_pack_u16be(pData + pos);
    pos += sizeof(uint16_t);

    //        [8:htlc_minimum_msat]
    pMsg->htlc_minimum_msat = utl_int_pack_u64be(pData + pos);
    pos += sizeof(uint64_t);

    //        [4:fee_base_msat]
    pMsg->fee_base_msat = utl_int_pack_u32be(pData + pos);
    pos += sizeof(uint32_t);

    //        [4:fee_proportional_millionths]
    pMsg->fee_prop_millionths = utl_int_pack_u32be(pData + pos);
    pos += sizeof(uint32_t);

    bool result = true;

    //        [8:htlc_maximum_msat] (option_channel_htlc_max)
    if (pMsg->message_flags & LN_CNLUPD_MSGFLAGS_HTLCMAX) {
        if (Len >= pos + sizeof(uint64_t)) {
            pMsg->htlc_maximum_msat = utl_int_pack_u64be(pData + pos);
            pos += sizeof(uint64_t);
        } else {
            result = false;
            LOGE("fail: NO option_channel_htlc_max field\n");
        }
    } else {
        pMsg->htlc_maximum_msat = 0;
    }

    if (Len < pos) {
        LOGE("fail: length\n");
        return false;
    }

#ifdef DBG_PRINT_READ_UPD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    ln_msg_cnl_update_print(pMsg);
#endif  //DBG_PRINT_READ_UPD

    return result;
}


bool HIDDEN ln_msg_cnl_update_sign(uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return ln_node_sign_nodekey(pData + sizeof(uint16_t), hash);
}


bool HIDDEN ln_msg_cnl_update_verify(const uint8_t *pNodePubKey, const uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return btc_sig_verify_rs(pData + sizeof(uint16_t), hash, pNodePubKey);
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


