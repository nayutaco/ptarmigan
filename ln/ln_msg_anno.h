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
/** @file   ln_msg_anno.h
 *  @brief  [LN]Announce関連
 */
#ifndef LN_MSG_ANNO_H__
#define LN_MSG_ANNO_H__

#include "btc_script.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define LN_SZ_ALIAS_STR                 (32)        ///< (size) node alias //XXX:
#define LN_SZ_RGB_COLOR                 (3)         ///< (size) rgb color


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @struct     ln_msg_announcement_signatures_t
 *  @brief      announcement_signatures
 */
typedef struct {
    //type: 259 (announcement_signatures)
    //data:
    //  [32:channel_id]
    //  [8:short_channel_id]
    //  [64:node_signature]
    //  [64:bitcoin_signature]

    const uint8_t   *p_channel_id;
    uint64_t        short_channel_id;
    const uint8_t   *p_node_signature;
    const uint8_t   *p_bitcoin_signature;
} ln_msg_announcement_signatures_t;


/** @struct     ln_msg_channel_announcement_t
 *  @brief      channel_announcement
 */
typedef struct {
    //type: 256 (channel_announcement)
    //data:
    //  [64:node_signature_1]
    //  [64:node_signature_2]
    //  [64:bitcoin_signature_1]
    //  [64:bitcoin_signature_2]
    //  [2:len]
    //  [len:features]
    //  [32:chain_hash]
    //  [8:short_channel_id]
    //  [33:node_id_1]
    //  [33:node_id_2]
    //  [33:bitcoin_key_1]
    //  [33:bitcoin_key_2]

    const uint8_t   *p_node_signature_1;
    const uint8_t   *p_node_signature_2;
    const uint8_t   *p_bitcoin_signature_1;
    const uint8_t   *p_bitcoin_signature_2;
    uint16_t        len;
    const uint8_t   *p_features;
    const uint8_t   *p_chain_hash;
    uint64_t        short_channel_id;
    const uint8_t   *p_node_id_1;
    const uint8_t   *p_node_id_2;
    const uint8_t   *p_bitcoin_key_1;
    const uint8_t   *p_bitcoin_key_2;
} ln_msg_channel_announcement_t;


/** @struct     ln_msg_node_announcement_t
 *  @brief      node_announcement
 */
typedef struct {
    //type: 257 (node_announcement)
    //data:
    //  [64:signature]
    //  [2:flen]
    //  [flen:features]
    //  [4:timestamp]
    //  [33:node_id]
    //  [3:rgb_color]
    //  [32:alias]
    //  [2:addrlen]
    //  [addrlen:addresses]

    const uint8_t   *p_signature;
    uint16_t        flen;
    const uint8_t   *p_features;
    uint32_t        timestamp;
    const uint8_t   *p_node_id;
    const uint8_t   *p_rgb_color;
    const uint8_t   *p_alias;
    uint16_t        addrlen;
    const uint8_t   *p_addresses;
} ln_msg_node_announcement_t;


/** @enum   ln_msg_address_descriptor_type_t
  * @brief  node_announcement address descriptor
  */
typedef enum {
    LN_ADDR_DESC_TYPE_NONE = 0,     ///< 0: //removed
    LN_ADDR_DESC_TYPE_IPV4 = 1,     ///< 1: ipv4. data = [4:ipv4_addr][2:port] (length 6)
    LN_ADDR_DESC_TYPE_IPV6 = 2,     ///< 2: ipv6. data = [16:ipv6_addr][2:port] (length 18)
    LN_ADDR_DESC_TYPE_TORV2 = 3,    ///< 3: tor v2 onion service. data = [10:onion_addr][2:port] (length 12)
    LN_ADDR_DESC_TYPE_TORV3 = 4,    ///< 4: tor v3 onion service. data [35:onion_addr][2:port] (length 37)
    LN_ADDR_DESC_TYPE_MAX = LN_ADDR_DESC_TYPE_TORV3,
    LN_ADDR_DESC_TYPE_NUM = 4,      //1,2,3,4
} ln_msg_address_descriptor_type_t;


/** @enum   ln_msg_address_descriptor_addr_len_t
  * @brief  node_announcement address descriptor
  */
typedef enum {
    LN_ADDR_DESC_ADDR_LEN_IPV4 = 4,     ///< 1: ipv4. data = [4:ipv4_addr][2:port] (length 6)
    LN_ADDR_DESC_ADDR_LEN_IPV6 = 16,    ///< 2: ipv6. data = [16:ipv6_addr][2:port] (length 18)
    LN_ADDR_DESC_ADDR_LEN_TORV2 = 10,   ///< 3: tor v2 onion service. data = [10:onion_addr][2:port] (length 12)
    LN_ADDR_DESC_ADDR_LEN_TORV3 = 35,   ///< 4: tor v3 onion service. data [35:onion_addr][2:port] (length 37)
} ln_msg_address_descriptor_addr_len_t;


/** @struct     ln_msg_node_announcement_address_descriptor_t
 *  @brief      node_announcement address descriptor
 */
typedef struct {
    uint8_t         type;
    const uint8_t   *p_addr;
    uint16_t        port;
} ln_msg_node_announcement_address_descriptor_t;


/** @struct     ln_msg_node_announcement_addresses_t
 *  @brief      node_announcement addresses
 */
typedef struct {
    uint32_t                                        num;
    ln_msg_node_announcement_address_descriptor_t   addresses[LN_ADDR_DESC_TYPE_NUM];
} ln_msg_node_announcement_addresses_t;


/** @struct     ln_cnl_update_t
 *  @brief      channel_update
 */
typedef struct {
    const uint8_t   *p_chain_hash;
    uint64_t    short_channel_id;                   ///< 8:  short_channel_id
    uint64_t    htlc_minimum_msat;                  ///< 8:  htlc_minimum_msat
    uint64_t    htlc_maximum_msat;                  ///< 8:  htlc_maximum_msat(option_channel_htlc_max)
    uint32_t    timestamp;                          ///< 4:  timestamp
    uint32_t    fee_base_msat;                      ///< 4:  fee_base_msat
    uint32_t    fee_prop_millionths;                ///< 4:  fee_proportional_millionths
    uint16_t    cltv_expiry_delta;                  ///< 2:  cltv_expiry_delta
    uint8_t     message_flags;                      ///< 1:  message_flags
    uint8_t     channel_flags;                      ///< 1:  channel_flags
} ln_cnl_update_t;


/**************************************************************************
 * const variables
 **************************************************************************/

extern const ln_msg_address_descriptor_addr_len_t M_ADDR_LEN[LN_ADDR_DESC_TYPE_MAX + 1];


/********************************************************************
 * prototypes
 ********************************************************************/

/** write announcement_signatures
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_announcement_signatures_write(utl_buf_t *pBuf, const ln_msg_announcement_signatures_t *pMsg);


/** read announcement_signatures
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * @retval  true    成功
 */
bool HIDDEN ln_msg_announcement_signatures_read(ln_msg_announcement_signatures_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write channel_announcement
 *
 * @param[out]      pBuf        生成データ
 * @param[in]       pMsg        元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_announcement_write(utl_buf_t *pBuf, const ln_msg_channel_announcement_t *pMsg);


/** read channel_announcement
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_channel_announcement_read(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len);


/** sign channel_announcement
 *
 */
bool HIDDEN ln_msg_channel_announcement_sign(uint8_t *pData, uint16_t Len, const uint8_t *pBtcPrivKey, btc_script_pubkey_order_t Order);


/** verify channel_announcement
 *
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_announcement_verify(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len); //XXX: not used


/** print channel_announcement
 *
 */
bool HIDDEN ln_msg_channel_announcement_print(const uint8_t *pData, uint16_t Len);


/** get the addrs of sigs from channel_announcement
 *
 */
void HIDDEN ln_msg_channel_announcement_get_sigs(uint8_t *pData, uint8_t **ppSigNode, uint8_t **ppSigBtc, bool bLocal, btc_script_pubkey_order_t Order);


/** print channel_update
 *
 */
void HIDDEN ln_msg_cnl_update_print(const ln_cnl_update_t *pMsg);


/** write node_announcement
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_node_announcement_write(utl_buf_t *pBuf, const ln_msg_node_announcement_t *pMsg);


/** read node_announcement
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_node_announcement_read(ln_msg_node_announcement_t *pMsg, const uint8_t *pData, uint16_t Len);


//XXX:
bool HIDDEN ln_msg_node_announcement_addresses_write(utl_buf_t *pBuf, const ln_msg_node_announcement_addresses_t *pAddrs); 


//XXX:
bool /*HIDDEN*/ ln_msg_node_announcement_addresses_read(ln_msg_node_announcement_addresses_t *pAddrs, const uint8_t *pData, uint16_t Len); 


/** sign node_announcement
 *
 */
bool HIDDEN ln_msg_node_announcement_sign(uint8_t *pData, uint16_t Len);


/** vefiry node_announcement
 *
 */
bool HIDDEN ln_msg_node_announcement_verify(const ln_msg_node_announcement_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write channel_update
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_update_write(utl_buf_t *pBuf, const ln_cnl_update_t *pMsg);


/** read channel_update
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t Len);


/** sign channel_update
 *
 */
bool HIDDEN ln_msg_cnl_update_sign(uint8_t *pData, uint16_t Len);


/** verify channel_update
 *
 * @param[in]       pNodePubKey 公開鍵(node_id)
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_cnl_update_verify(const uint8_t *pNodePubKey, const uint8_t *pData, uint16_t Len);


/** short_channel_id書き換え //XXX:
 *
 */
bool HIDDEN ln_msg_channel_announcement_update_short_channel_id(uint8_t *pData, uint64_t ShortChannelId);

#endif /* LN_MSG_ANNO_H__ */
