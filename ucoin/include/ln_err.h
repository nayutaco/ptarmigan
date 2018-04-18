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
/** @file   ln_err.h
 *  @brief  Lightning Library Error Code
 *  @author ueno@nayuta.co
 */
#ifndef LN_ERR_H__
#define LN_ERR_H__


/**************************************************************************
 * library error
 **************************************************************************/

enum {
    LNERR_ERROR,
    LNERR_INV_NODEID,
    LNERR_INV_PRIVKEY,
    LNERR_INV_PREF,
    LNERR_INV_ADDR,
    LNERR_INV_STATE,
    LNERR_NO_PEER,
    LNERR_NO_CHANNEL,
    LNERR_INV_CHANNEL,
    LNERR_INV_SHORT_CHANNEL,
    LNERR_INV_VALUE,
    LNERR_INV_FEATURE,
    LNERR_INV_SIDE,
    LNERR_NOT_CLEAN,
    LNERR_HTLC_FULL,
    LNERR_HTLC_NUM,
    LNERR_INV_PREIMAGE,
    LNERR_INV_ID,
    LNERR_PINGPONG,
    LNERR_CREATE_2OF2,
    LNERR_CREATE_MSG,
    LNERR_CREATE_TX,
    LNERR_MSG_READ,
    LNERR_MSG_INIT,
    LNERR_MSG_ERROR,
    LNERR_ADDHTLC_APP,
    LNERR_ALREADY_FUNDING,
    LNERR_ONION,
};


/**************************************************************************
 * onion
 **************************************************************************/

#define LNERR_ONION_BADONION        ((uint16_t)0x8000)
#define LNERR_ONION_PERM            ((uint16_t)0x4000)
#define LNERR_ONION_NODE            ((uint16_t)0x2000)
#define LNERR_ONION_UPDATE          ((uint16_t)0x1000)

/**
 * @enum    lnerr_onion_t
 * @brief   ONION failure code
 */
typedef enum {
    /** invalid_realm
     * 
     * The realm byte was not understood by the processing node.
     */
    LNONION_INV_REALM               = ((uint16_t)(LNERR_ONION_PERM | 1)),

    /** temporary_node_failure
     * 
     * General temporary failure of the processing node.
     */
    LNONION_TMP_NODE_FAIL           = ((uint16_t)(LNERR_ONION_NODE | 2)),

    /** permanent_node_failure
     * 
     * General permanent failure of the processing node.
     */
    LNONION_PERM_NODE_FAIL          = ((uint16_t)(LNERR_ONION_PERM | LNERR_ONION_NODE | 2)),

    /** required_node_feature_missing
     * 
     * The processing node has a required feature which was not in this onion.
     */
    LNONION_REQ_NODE_FTR_MISSING    = ((uint16_t)(LNERR_ONION_PERM | LNERR_ONION_NODE | 3)),

    /** invalid_onion_version
     * 
     * The version byte was not understood by the processing node.
     * 
     * [32:sha256_of_onion]
     */
    LNONION_INV_ONION_VERSION       = ((uint16_t)(LNERR_ONION_BADONION | LNERR_ONION_PERM | 4)),

    /** invalid_onion_hmac
     * 
     * The HMAC of the onion was incorrect when it reached the processing node.
     * 
     * [32:sha256_of_onion]
     */
    LNONION_INV_ONION_HMAC          = ((uint16_t)(LNERR_ONION_BADONION | LNERR_ONION_PERM | 5)),

    /** invalid_onion_key
     * 
     * The ephemeral key was unparsable by the processing node.
     * 
     * [32:sha256_of_onion]
     */
    LNONION_INV_ONION_KEY           = ((uint16_t)(LNERR_ONION_BADONION | LNERR_ONION_PERM | 6)),

    /** temporary_channel_failure
     * 
     * The channel from the processing node was unable to handle this HTLC, 
     *      but may be able to handle it, or others, later.
     * 
     * an otherwise unspecified, transient error occurs in the outgoing channel
     *      (e.g. channel capacity reached, too many in-flight HTLCs, etc.)
     * 
     * [2:len]
     * [len:channel_update]
     */
    LNONION_TMP_CHAN_FAIL           = ((uint16_t)(LNERR_ONION_UPDATE | 7)),

    /** permanent_channel_failure
     * 
     * The channel from the processing node is unable to handle any HTLCs.
     * 
     * an otherwise unspecified, permanent error occurs during forwarding to its receiving peer
     *      (e.g. channel recently closed)
     */
    LNONION_PERM_CHAN_FAIL          = ((uint16_t)(LNERR_ONION_PERM | 8)),

    /** required_channel_feature_missing
     * 
     * The channel from the processing node requires features not present in the onion.
     */
    LNONION_REQ_CHAN_FTR_MISSING    = ((uint16_t)(LNERR_ONION_PERM | 9)),

    /** unknown_next_peer
     * 
     * The onion specified a short_channel_id 
     *      which doesn't match any leading from the processing node.
     */
    LNONION_UNKNOWN_NEXT_PEER       = ((uint16_t)(LNERR_ONION_PERM | 10)),

    /** amount_below_minimum
     * 
     * The HTLC amount was below the htlc_minimum_msat of the channel from the processing node.
     * 
     * [8:htlc_msat]
     * [2:len]
     * [len:channel_update]
     */
    LNONION_AMT_BELOW_MIN           = ((uint16_t)(LNERR_ONION_UPDATE | 11)),

    /** fee_insufficient
     * 
     * The fee amount was below that required by the channel from the processing node.
     * 
     * [8:htlc_msat]
     * [2:len]
     * [len:channel_update]
     */
    LNONION_FEE_INSUFFICIENT        = ((uint16_t)(LNERR_ONION_UPDATE | 12)),

    /** incorrect_cltv_expiry
     * 
     * The CLTV expiry in the HTLC doesn't match the value in the onion.
     * 
     * [4:cltv_expiry]
     * [2:len]
     * [len:channel_update]
     */
    LNONION_INCORR_CLTV_EXPIRY      = ((uint16_t)(LNERR_ONION_UPDATE | 13)),

    /** expiry_too_soon
     * 
     * The CLTV expiry is too close to the current block height for safe handling
     *      by the processing node.
     * 
     * [2:len]
     * [len:channel_update]
     */
    LNONION_EXPIRY_TOO_SOON         = ((uint16_t)(LNERR_ONION_UPDATE | 14)),

    /** unknown_payment_hash
     * 
     * The payment_hash is unknown to the final node.
     */
    LNONION_UNKNOWN_PAY_HASH        = ((uint16_t)(LNERR_ONION_PERM | 15)),

    /** incorrect_payment_amount
     * 
     * The amount for that payment_hash is incorrect.
     */
    LNONION_INCORR_PAY_AMT          = ((uint16_t)(LNERR_ONION_PERM | 16)),

    /** final_expiry_too_soon
     * 
     * The CLTV expiry is too close to the current block height 
     *      for safe handling by the final node.
     */
    LNONION_FINAL_EXPIRY_TOO_SOON   = ((uint16_t)(17)),

    /** final_incorrect_cltv_expiry
     * 
     * The CLTV expiry in the HTLC doesn't match the value in the onion.
     * 
     * [4:cltv_expiry]
     */
    LNONION_FINAL_INCORR_CLTV_EXP   = ((uint16_t)(18)),

    /** final_incorrect_htlc_amount
     * 
     * The amount in the HTLC doesn't match the value in the onion.
     * 
     * [4:incoming_htlc_amt]
     */
    LNONION_FINAL_INCORR_HTLC_AMT   = ((uint16_t)(19)),

    /** channel_disabled
     * 
     * The channel from the processing node has been disabled.
     * 
     * [2: flags]
     * [2:len]
     * [len:channel_update]
     */
    LNONION_CHAN_DISABLE            = ((uint16_t)(LNERR_ONION_UPDATE | 20)),

    /** expiry_too_far
     * 
     * The CLTV expiry in the HTLC is too far in the future.
     */
    LNONION_EXPIRY_TOO_FAR          = ((uint16_t)(21)),
} lnerr_onion_t;

#endif /* LN_ERR_H__ */
