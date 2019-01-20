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

#include "ln_misc.h"
#include "ln_node.h"
#include "ln_signer.h"
#include "ln_local.h"
#include "ln_msg_anno.h"


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

const ln_msg_address_descriptor_addr_len_t M_ADDR_LEN[LN_ADDR_DESC_TYPE_MAX + 1] = {
    (ln_msg_address_descriptor_addr_len_t)0,
    LN_ADDR_DESC_ADDR_LEN_IPV4,
    LN_ADDR_DESC_ADDR_LEN_IPV6,
    LN_ADDR_DESC_ADDR_LEN_TORV2,
    LN_ADDR_DESC_ADDR_LEN_TORV3,
};


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
static void node_announcement_print(const ln_msg_node_announcement_t *pMsg);
static void node_announcement_addresses_print(const ln_msg_node_announcement_addresses_t *pAddrs);
#endif
#if defined(DBG_PRINT_WRITE_UPD) || defined(DBG_PRINT_READ_UPD)
static void channel_update_print(const ln_msg_channel_update_t *pMsg);
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

bool HIDDEN ln_msg_node_announcement_write(utl_buf_t *pBuf, const ln_msg_node_announcement_t *pMsg)
{
#ifdef DBG_PRINT_WRITE_NOD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    node_announcement_print(pMsg);
#endif  //DBG_PRINT_WRITE_NOD

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_NODE_ANNOUNCEMENT)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->flen)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_features, pMsg->flen)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->timestamp)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_node_id, BTC_SZ_PUBKEY)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_rgb_color, LN_SZ_RGB_COLOR)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_alias, LN_SZ_ALIAS_STR)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->addrlen)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_addresses, pMsg->addrlen)) goto LABEL_ERROR;
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool /*HIDDEN*/ ln_msg_node_announcement_read(ln_msg_node_announcement_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_NODE_ANNOUNCEMENT) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->flen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_features, pMsg->flen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->timestamp)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_node_id, BTC_SZ_PUBKEY)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_rgb_color, LN_SZ_RGB_COLOR)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_alias, LN_SZ_ALIAS_STR)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->addrlen)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_addresses, pMsg->addrlen)) goto LABEL_ERROR_SYNTAX;

#ifdef DBG_PRINT_READ_NOD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    node_announcement_print(pMsg);
#endif  //DBG_PRINT_READ_NOD
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


#if defined(DBG_PRINT_WRITE_NOD) || defined(DBG_PRINT_READ_NOD)
static void node_announcement_print(const ln_msg_node_announcement_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[node_announcement]-------------------------------\n");
    LOGD("signature: ");
    DUMPD(pMsg->p_signature, LN_SZ_SIGNATURE);
    LOGD("features: ");
    DUMPD(pMsg->p_features, pMsg->flen);
    LOGD("timestamp: %u\n", pMsg->timestamp);
    char time[UTL_SZ_TIME_FMT_STR + 1];
    LOGD("timestamp(fmt): %s\n", utl_time_fmt(time, pMsg->timestamp));
    LOGD("node_id: ");
    DUMPD(pMsg->p_node_id, BTC_SZ_PUBKEY);
    LOGD("rgb_color: ");
    DUMPD(pMsg->p_rgb_color, LN_SZ_RGB_COLOR);
    LOGD("alias: ");
    DUMPD(pMsg->p_alias, LN_SZ_ALIAS_STR);
    LOGD("alias(str): %.*s\n", LN_SZ_ALIAS_STR, pMsg->p_alias);
    LOGD("addresses: ");
    DUMPD(pMsg->p_addresses, pMsg->addrlen);
    LOGD("--------------------------------\n");
#endif
}
#endif


bool HIDDEN ln_msg_node_announcement_addresses_write(utl_buf_t *pBuf, const ln_msg_node_announcement_addresses_t *pAddrs) {
#ifdef DBG_PRINT_WRITE_NOD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    node_announcement_addresses_print(pAddrs);
#endif  //DBG_PRINT_WRITE_NOD

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);
    for (uint32_t i = 0; i < pAddrs->num; i++) {
        if (!btc_buf_w_write_byte(&buf_w, pAddrs->addresses[i].type)) goto LABEL_ERROR;
        if (!btc_buf_w_write_data(&buf_w, pAddrs->addresses[i].p_addr, M_ADDR_LEN[pAddrs->addresses[i].type])) goto LABEL_ERROR;
        if (!btc_buf_w_write_u16be(&buf_w, pAddrs->addresses[i].port)) goto LABEL_ERROR;
    }
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool /*HIDDEN*/ ln_msg_node_announcement_addresses_read(ln_msg_node_announcement_addresses_t *pAddrs, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    for (pAddrs->num = 0; pAddrs->num < LN_ADDR_DESC_TYPE_NUM; pAddrs->num++) {
        ln_msg_node_announcement_address_descriptor_t *addr_desc = &pAddrs->addresses[pAddrs->num];
        if (!btc_buf_r_remains(&buf_r)) break;
        if (!btc_buf_r_read_byte(&buf_r, &addr_desc->type)) goto LABEL_ERROR_SYNTAX;
        if (addr_desc->type == LN_ADDR_DESC_TYPE_NONE) break; //now removed the type, ignore the remains
        if (addr_desc->type > LN_ADDR_DESC_TYPE_MAX) break; //ignore the remains
        if (!btc_buf_r_get_pos_and_seek(&buf_r, &addr_desc->p_addr, M_ADDR_LEN[addr_desc->type])) goto LABEL_ERROR_SYNTAX;
        if (!btc_buf_r_read_u16be(&buf_r, &addr_desc->port)) goto LABEL_ERROR_SYNTAX;
    }

#ifdef DBG_PRINT_READ_NOD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    node_announcement_addresses_print(pAddrs);
#endif  //DBG_PRINT_READ_NOD
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


#if defined(DBG_PRINT_WRITE_NOD) || defined(DBG_PRINT_READ_NOD)
static void node_announcement_addresses_print(const ln_msg_node_announcement_addresses_t *pAddrs)
{
#ifdef PTARM_DEBUG
    LOGD("-[node_announcement addresses]-------------------------------\n");
    for (uint32_t i = 0; i < pAddrs->num; i++) {
        const ln_msg_node_announcement_address_descriptor_t *addr_desc = &pAddrs->addresses[i];
        LOGD("type: %u\n", addr_desc->type);
        DUMPD(addr_desc->p_addr, M_ADDR_LEN[addr_desc->type]);
        LOGD("port: %u\n", addr_desc->port);
    }
    LOGD("--------------------------------\n");
#endif
}
#endif


bool HIDDEN ln_msg_node_announcement_sign(uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return ln_node_sign_nodekey(pData + sizeof(uint16_t), hash);
}


bool HIDDEN ln_msg_node_announcement_verify(const ln_msg_node_announcement_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return btc_sig_verify_rs(pData + sizeof(uint16_t), hash, pMsg->p_node_id);
}


/********************************************************************
 * channel_update
 ********************************************************************/

bool HIDDEN ln_msg_channel_update_write(utl_buf_t *pBuf, const ln_msg_channel_update_t *pMsg)
{
#ifdef DBG_PRINT_WRITE_UPD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_update_print(pMsg);
#endif  //DBG_PRINT_WRITE_UPD

    btc_buf_w_t buf_w;
    btc_buf_w_init(&buf_w, 0);

    if (!btc_buf_w_write_u16be(&buf_w, MSGTYPE_CHANNEL_UPDATE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR;
    if (!btc_buf_w_write_data(&buf_w, pMsg->p_chain_hash, BTC_SZ_HASH256)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->short_channel_id)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->timestamp)) goto LABEL_ERROR;
    if (!btc_buf_w_write_byte(&buf_w, pMsg->message_flags)) goto LABEL_ERROR;
    if (!btc_buf_w_write_byte(&buf_w, pMsg->channel_flags)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u16be(&buf_w, pMsg->cltv_expiry_delta)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u64be(&buf_w, pMsg->htlc_minimum_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->fee_base_msat)) goto LABEL_ERROR;
    if (!btc_buf_w_write_u32be(&buf_w, pMsg->fee_proportional_millionths)) goto LABEL_ERROR;
    if (pMsg->message_flags & LN_CHANNEL_UPDATE_MSGFLAGS_OPTION_CHANNEL_HTLC_MAX) {
        if (!btc_buf_w_write_u64be(&buf_w, pMsg->htlc_maximum_msat)) goto LABEL_ERROR;
    }
    btc_buf_w_move(&buf_w, pBuf);
    return true;

LABEL_ERROR:
    btc_buf_w_free(&buf_w);
    return false;
}


bool /*HIDDEN*/ ln_msg_channel_update_read(ln_msg_channel_update_t *pMsg, const uint8_t *pData, uint16_t Len)
{
    btc_buf_r_t buf_r;
    btc_buf_r_init(&buf_r, pData, Len);
    uint16_t type;
    if (!btc_buf_r_read_u16be(&buf_r, &type)) goto LABEL_ERROR_SYNTAX;
    if (type != MSGTYPE_CHANNEL_UPDATE) {
        LOGE("fail: type not match: %04x\n", type);
        return false;
    }
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_signature, LN_SZ_SIGNATURE)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_get_pos_and_seek(&buf_r, &pMsg->p_chain_hash, BTC_SZ_HASH256)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->short_channel_id)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->timestamp)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_byte(&buf_r, &pMsg->message_flags)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_byte(&buf_r, &pMsg->channel_flags)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u16be(&buf_r, &pMsg->cltv_expiry_delta)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u64be(&buf_r, &pMsg->htlc_minimum_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->fee_base_msat)) goto LABEL_ERROR_SYNTAX;
    if (!btc_buf_r_read_u32be(&buf_r, &pMsg->fee_proportional_millionths)) goto LABEL_ERROR_SYNTAX;
    if (pMsg->message_flags & LN_CHANNEL_UPDATE_MSGFLAGS_OPTION_CHANNEL_HTLC_MAX) {
        if (!btc_buf_r_read_u64be(&buf_r, &pMsg->htlc_maximum_msat)) goto LABEL_ERROR_SYNTAX; //XXX: black list
    } else {
        pMsg->htlc_maximum_msat = 0; //XXX:
    }

#ifdef DBG_PRINT_READ_UPD
    LOGD("@@@@@ %s @@@@@\n", __func__);
    channel_update_print(pMsg);
#endif  //DBG_PRINT_READ_UPD
    return true;

LABEL_ERROR_SYNTAX:
    LOGE("fail: invalid syntax\n");
    return false;
}


static void channel_update_print(const ln_msg_channel_update_t *pMsg)
{
#ifdef PTARM_DEBUG
    LOGD("-[channel_update]-------------------------------\n");
    //LOGD("signature: ");
    //DUMPD(pMsg->signature, LN_SZ_SIGNATURE);
    //LOGD("chain_hash: ");
    //DUMPD(pMsg->p_chain_hash, BTC_SZ_HASH256);
    LOGD("short_channel_id: %016" PRIx64 "\n", pMsg->short_channel_id);
    LOGD("timestamp: %u\n", pMsg->timestamp);
    char time[UTL_SZ_TIME_FMT_STR + 1];
    LOGD("timestamp(fmt): %s\n", utl_time_fmt(time, pMsg->timestamp));
    LOGD("message_flags: 0x%02x\n", pMsg->message_flags);
    LOGD("channel_flags: 0x%02x\n", pMsg->channel_flags);
    LOGD("  direction: %s\n", ln_cnlupd_direction(pMsg) ? "node_2" : "node_1"); //XXX:
    LOGD("  %s\n", ln_cnlupd_enable(pMsg) ? "enable" : "disable"); //XXX:
    LOGD("cltv_expiry_delta: %u\n", pMsg->cltv_expiry_delta);
    LOGD("htlc_minimum_msat: %" PRIu64 "\n", pMsg->htlc_minimum_msat);
    LOGD("fee_base_msat: %u\n", pMsg->fee_base_msat);
    LOGD("fee_proportional_millionths: %u\n", pMsg->fee_proportional_millionths);
    if (pMsg->message_flags & LN_CHANNEL_UPDATE_MSGFLAGS_OPTION_CHANNEL_HTLC_MAX) {
        LOGD("htlc_maximum_msat: %" PRIu64 "\n", pMsg->htlc_maximum_msat);
    }
    LOGD("--------------------------------\n");
#endif  //PTARM_DEBUG
}


bool HIDDEN ln_msg_channel_update_sign(uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return ln_node_sign_nodekey(pData + sizeof(uint16_t), hash);
}


bool HIDDEN ln_msg_channel_update_verify(const uint8_t *pNodePubKey, const uint8_t *pData, uint16_t Len)
{
    uint8_t hash[BTC_SZ_HASH256];
    uint16_t offset = sizeof(uint16_t) + LN_SZ_SIGNATURE;
    btc_md_hash256(hash, pData + offset, Len - offset);
    return btc_sig_verify_rs(pData + sizeof(uint16_t), hash, pNodePubKey);
}


bool HIDDEN ln_msg_channel_update_print(const uint8_t *pData, uint16_t Len)
{
    ln_msg_channel_update_t msg;
    if (!ln_msg_channel_update_read(&msg, pData, Len)) return false;
#ifndef DBG_PRINT_READ_UPD //ln_msg_channel_update_read don't print
    channel_update_print(&msg);
#endif
    return true;
}

