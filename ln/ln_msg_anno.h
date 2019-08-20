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

// channel_update.message_flags
#define LN_CHANNEL_UPDATE_MSGFLAGS_OPTION_CHANNEL_HTLC_MAX      (0x01)      ///< b0: option_channel_htlc_max

// Message Queries
#define LN_GOSSIPQUERY_ENCODE_NONE	    (0x00)
#define LN_GOSSIPQUERY_ENCODE_ZLIB	    (0x01)


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
    LN_ADDR_DESC_ADDR_LEN_MAX = LN_ADDR_DESC_ADDR_LEN_TORV3,
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


/** @struct     ln_msg_channel_update_t
 *  @brief      channel_update
 */
typedef struct {
    //type: 258 (channel_update)
    //data:
    //  [64:signature]
    //  [32:chain_hash]
    //  [8:short_channel_id]
    //  [4:timestamp]
    //  [1:message_flags]
    //  [1:channel_flags]
    //  [2:cltv_expiry_delta]
    //  [8:htlc_minimum_msat]
    //  [4:fee_base_msat]
    //  [4:fee_proportional_millionths]
    //  [8:htlc_maximum_msat] (option_channel_htlc_max)

    const uint8_t *p_signature;
    const uint8_t *p_chain_hash;
    uint64_t short_channel_id;
    uint32_t timestamp;
    uint8_t message_flags;
    uint8_t channel_flags;
    uint16_t cltv_expiry_delta;
    uint64_t htlc_minimum_msat;
    uint32_t fee_base_msat;
    uint32_t fee_proportional_millionths;
    uint64_t htlc_maximum_msat;
} ln_msg_channel_update_t;


/** @struct     ln_msg_query_short_channel_ids_t
 *  @brief      query_short_channel_ids
 */
typedef struct ln_msg_query_short_channel_ids_t {
    //1. type: 261 (`query_short_channel_ids`) (`gossip_queries`)
    //2. data:
    //    * [`32`:`chain_hash`]
    //    * [`2`:`len`]
    //    * [`len`:`encoded_short_ids`]

    const uint8_t *p_chain_hash;
    uint16_t len;
    const uint8_t *p_encoded_short_ids;
} ln_msg_query_short_channel_ids_t;


/** @struct     ln_msg_reply_short_channel_ids_end_t
 *  @brief      reply_short_channel_ids_end
 */
typedef struct ln_msg_reply_short_channel_ids_end_t {
    //1. type: 262 (`reply_short_channel_ids_end`) (`gossip_queries`)
    //2. data:
    //    * [`32`:`chain_hash`]
    //    * [`1`:`complete`]

    const uint8_t *p_chain_hash;
    uint8_t complete;
} ln_msg_reply_short_channel_ids_end_t;


/** @struct     ln_msg_query_channel_range_t
 *  @brief      query_channel_range
 */
typedef struct ln_msg_query_channel_range_t {
    //1. type: 263 (`query_channel_range`) (`gossip_queries`)
    //2. data:
    //    * [`32`:`chain_hash`]
    //    * [`4`:`first_blocknum`]
    //    * [`4`:`number_of_blocks`]

    const uint8_t *p_chain_hash;
    uint32_t first_blocknum;
    uint32_t number_of_blocks;
} ln_msg_query_channel_range_t;


/** @struct     ln_msg_reply_channel_range_t
 *  @brief      reply_channel_range
 */
typedef struct ln_msg_reply_channel_range_t {
    //1. type: 264 (`reply_channel_range`) (`gossip_queries`)
    //2. data:
    //    * [`32`:`chain_hash`]
    //    * [`4`:`first_blocknum`]
    //    * [`4`:`number_of_blocks`]
    //    * [`1`:`complete`]
    //    * [`2`:`len`]
    //    * [`len`:`encoded_short_ids`]

    const uint8_t *p_chain_hash;
    uint32_t first_blocknum;
    uint32_t number_of_blocks;
    uint8_t complete;
    uint16_t len;
    const uint8_t *p_encoded_short_ids;
} ln_msg_reply_channel_range_t;


/** @struct     ln_msg_gossip_timestamp_filter_t
 *  @brief      gossip_timestamp_filter
 */
typedef struct ln_msg_gossip_timestamp_filter_t {
    //1. type: 265 (`gossip_timestamp_filter`) (`gossip_queries`)
    //2. data:
    //    * [`32`:`chain_hash`]
    //    * [`4`:`first_timestamp`]
    //    * [`4`:`timestamp_range`]

    const uint8_t *p_chain_hash;
    uint32_t first_timestamp;
    uint32_t timestamp_range;
} ln_msg_gossip_timestamp_filter_t;


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
bool HIDDEN ln_msg_channel_announcement_verify(const ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len); //XXX: not used


/** print channel_announcement
 *
 */
bool HIDDEN ln_msg_channel_announcement_print(const uint8_t *pData, uint16_t Len);


/** get the addrs of sigs from channel_announcement
 *
 */
void HIDDEN ln_msg_channel_announcement_get_sigs(uint8_t *pData, uint8_t **ppSigNode, uint8_t **ppSigBtc, bool bLocal, btc_script_pubkey_order_t Order);


/** short_channel_id書き換え //XXX:
 *
 */
bool HIDDEN ln_msg_channel_announcement_update_short_channel_id(uint8_t *pData, uint64_t ShortChannelId);


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
bool /*HIDDEN*/ ln_msg_node_announcement_read_2(
    ln_msg_node_announcement_t *pMsg, ln_msg_node_announcement_addresses_t *pAddrs, const uint8_t *pData, uint16_t Len);


bool HIDDEN ln_msg_node_announcement_print(const uint8_t *pData, uint16_t Len);


//XXX:
bool HIDDEN ln_msg_node_announcement_print_2(const uint8_t *pData, uint16_t Len);


//XXX:
bool HIDDEN ln_msg_node_announcement_addresses_write(utl_buf_t *pBuf, const ln_msg_node_announcement_addresses_t *pAddrs);


//XXX:
bool /*HIDDEN*/ ln_msg_node_announcement_addresses_read(ln_msg_node_announcement_addresses_t *pAddrs, const uint8_t *pData, uint16_t Len);


/** sign node_announcement
 *
 */
bool HIDDEN ln_msg_node_announcement_sign(uint8_t *pData, uint16_t Len);


/** verify node_announcement
 *
 */
bool HIDDEN ln_msg_node_announcement_verify(const ln_msg_node_announcement_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write channel_update
 *
 * @param[out]      pBuf    生成データ
 * @param[in]       pMsg    元データ
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_update_write(utl_buf_t *pBuf, const ln_msg_channel_update_t *pMsg);


/** read channel_update
 *
 * @param[out]      pMsg    読込み結果
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool /*HIDDEN*/ ln_msg_channel_update_read(ln_msg_channel_update_t *pMsg, const uint8_t *pData, uint16_t Len);


/** sign channel_update
 *
 */
bool HIDDEN ln_msg_channel_update_sign(uint8_t *pData, uint16_t Len);


/** verify channel_update
 *
 * @param[in]       pNodePubKey 公開鍵(node_id)
 * @param[in]       pData   対象データ
 * @param[in]       Len     pData長
 * retval   true    成功
 */
bool HIDDEN ln_msg_channel_update_verify(const uint8_t *pNodePubKey, const uint8_t *pData, uint16_t Len);


/** print channel_update
 *
 */
bool HIDDEN ln_msg_channel_update_print(const uint8_t *pData, uint16_t Len);


/** write query_short_channel_ids
 *
 */
bool HIDDEN ln_msg_query_short_channel_ids_write(utl_buf_t *pBuf, const ln_msg_query_short_channel_ids_t *pMsg);


/** read query_short_channel_ids
 *
 */
bool HIDDEN ln_msg_query_short_channel_ids_read(ln_msg_query_short_channel_ids_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write reply_short_channel_ids_end
 *
 */
bool HIDDEN ln_msg_reply_short_channel_ids_end_write(utl_buf_t *pBuf, const ln_msg_reply_short_channel_ids_end_t *pMsg);


/** write reply_short_channel_ids_end
 *
 */
bool HIDDEN ln_msg_reply_short_channel_ids_end_read(ln_msg_reply_short_channel_ids_end_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write query_channel_range
 *
 */
bool HIDDEN ln_msg_query_channel_range_write(utl_buf_t *pBuf, const ln_msg_query_channel_range_t *pMsg);


/** write query_channel_range
 *
 */
bool HIDDEN ln_msg_query_channel_range_read(ln_msg_query_channel_range_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write reply_channel_range
 *
 */
bool HIDDEN ln_msg_reply_channel_range_write(utl_buf_t *pBuf, const ln_msg_reply_channel_range_t *pMsg);


/** write reply_channel_range
 *
 */
bool HIDDEN ln_msg_reply_channel_range_read(ln_msg_reply_channel_range_t *pMsg, const uint8_t *pData, uint16_t Len);


/** write gossip_timestamp_filter
 *
 */
bool HIDDEN ln_msg_gossip_timestamp_filter_write(utl_buf_t *pBuf, const ln_msg_gossip_timestamp_filter_t *pMsg);


/** write gossip_timestamp_filter
 *
 */
bool HIDDEN ln_msg_gossip_timestamp_filter_read(ln_msg_gossip_timestamp_filter_t *pMsg, const uint8_t *pData, uint16_t Len);


/** decode encoded_short_ids
 *
 * @param[out]     pEncodedIds          encoded short_channel_id (utl_buf_free() after used)
 * @param[in]      pShortChannelIds     short_ids
 * @param[in]      Num                  num of pShortChannelIds
 * @retval      true    success
 * @attention
 *      - pEncodedIds is allocated by this function.
 */
bool HIDDEN ln_msg_gossip_ids_encode(utl_buf_t *pEncodedIds, const uint64_t *pShortChannelIds, size_t Num);


/** decode encoded_short_ids
 *
 * @param[out]     ppShortChannelIds       decoded short_channel_id (free() after used)
 * @param[out]     pNum                    num of ppShortChannelIds
 * @param[in]      pData                   encoded_short_ids
 * @param[in]      Len                     pData length
 * @retval      true    success
 * @attention
 *      - ppShortChannelIds is allocated by this function.
 */
bool HIDDEN ln_msg_gossip_ids_decode(uint64_t **ppShortChannelIds, size_t *pNum, const uint8_t *pData, size_t Len);

#endif /* LN_MSG_ANNO_H__ */
