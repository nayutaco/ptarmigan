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
/** @file   ln_cb.h
 *  @brief  ln_cb
 */
#ifndef LN_CB_H__
#define LN_CB_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln_msg_normalope.h"
#include "ln_msg_x_normalope.h"


/********************************************************************
 * typedefs
 ********************************************************************/

//forward definition
struct ln_channel_t;
typedef struct ln_channel_t ln_channel_t;


/** @enum   ln_cb_type_t
 *  @brief  callback type
 */
typedef enum {
    LN_CB_TYPE_STOP_CHANNEL,                ///< チャネルを停止(closeはしない)
    LN_CB_TYPE_NOTIFY_ERROR,                ///< エラー通知
    LN_CB_TYPE_NOTIFY_INIT_RECV,            ///< init受信通知
    LN_CB_TYPE_NOTIFY_REESTABLISH_RECV,     ///< channel_reestablish受信通知
    LN_CB_TYPE_SIGN_FUNDING_TX,             ///< funding_tx署名要求
    LN_CB_TYPE_WAIT_FUNDING_TX,             ///< funding_tx安定待ち要求
    LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV,  ///< funding_locked受信通知
    LN_CB_TYPE_NOTIFY_ANNODB_UPDATE,        ///< announcement DB更新通知
    LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV,        ///< update_add_htlc受信通知
    LN_CB_TYPE_START_BWD_DEL_HTLC,          ///< HTLC削除処理開始
    LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV,    ///< update_fulfill_htlc受信通知
    LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE, ///< revoke_and_ack交換通知
    LN_CB_TYPE_RETRY_PAYMENT,               ///< 送金リトライ
    LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV,      ///< update_fee受信通知
    LN_CB_TYPE_NOTIFY_SHUTDOWN_RECV,        ///< shutdown受信通知
    LN_CB_TYPE_UPDATE_CLOSING_FEE,          ///< closing_signed受信通知(FEE不一致)
    LN_CB_TYPE_NOTIFY_CLOSING_END,          ///< closing_signed受信通知(FEE一致)
    LN_CB_TYPE_SEND_MESSAGE,                ///< peerへの送信要求
    LN_CB_TYPE_GET_LATEST_FEERATE,          ///< feerate_per_kw取得要求
    LN_CB_TYPE_GET_BLOCK_COUNT,             ///< getblockcount
    LN_CB_TYPE_NOTIFY_PONG_RECV,            ///< pong received
    LN_CB_TYPE_MAX,
} ln_cb_type_t;


/** @typedef    ln_callback_t
 *  @brief      通知コールバック関数
 *  @note
 *      - p_paramで渡すデータを上位層で保持しておきたい場合、コピーを取ること
 */
typedef void (*ln_callback_t)(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam);


/** @struct ln_cb_param_sign_funding_tx_t
 *  @brief  funding_tx署名要求(#LN_CB_TYPE_SIGN_FUNDING_TX)
 */
typedef struct {
    btc_tx_t                *p_tx;
    utl_buf_t               buf_tx;                 //
    uint64_t                fundin_amount;          //(SPV未使用)fund-inするamount[satoshi]
    bool                    ret;                    //署名結果
} ln_cb_param_sign_funding_tx_t;


/** @struct ln_cb_param_wait_funding_tx_t
 *  @brief  funding_tx安定待ち要求(#LN_CB_TYPE_WAIT_FUNDING_TX)
 */
typedef struct {
    const btc_tx_t          *p_tx_funding;          ///< funding_tx
    const uint8_t           *p_txid;                ///< funding txid
    bool                    b_send;                 ///< true:funding_txを送信する
    bool                    anno_sigs;              ///< true:announce_signaturesを送信する
    bool                    ret;                    ///< true:funding_tx送信成功
} ln_cb_param_wait_funding_tx_t;


/** @struct ln_cb_param_nofity_add_htlc_recv_t
 *  @brief  update_add_htlc受信通知(#LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV)
 */
typedef struct {
    bool                    ret;                    ///< callback処理結果
    uint64_t                next_short_channel_id;
    uint64_t                prev_htlc_id;           ///< HTLC id
    const uint8_t           *p_payment_hash;        ///< payment_hash
    const ln_msg_x_update_add_htlc_t    *p_forward_param;
    uint64_t                amount_msat;            ///<
    uint32_t                cltv_expiry;            ///<
    utl_buf_t               *p_onion_reason;        ///< 変換後onionパケット(ok==true) or fail reason(ok==false)
    const utl_buf_t         *p_shared_secret;       ///< onion shared secret
} ln_cb_param_nofity_add_htlc_recv_t;


typedef struct {
    bool                    ret;
    uint8_t                 update_type;
    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    const utl_buf_t         *p_reason;              ///< reason
    //const utl_buf_t         *p_shared_secret;       ///< shared secret
    uint64_t                prev_htlc_id;           ///<
    const uint8_t           *p_payment_hash;        ///< payment_hash
    uint16_t                fail_malformed_failure_code;    ///< !0: malformed_htlcのfailure_code
} ln_cb_param_start_bwd_del_htlc_t;


/** @struct ln_cb_param_notify_fulfill_htlc_recv_t
 *  @brief  update_fulfill_htlc受信通知(#LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV)
 */
typedef struct {
    bool                    ret;                    ///< callback処理結果
    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    uint64_t                prev_htlc_id;           ///<
    const uint8_t           *p_preimage;            ///< update_fulfill_htlcで受信したpreimage(スタック)
    uint64_t                amount_msat;            ///< HTLC amount
} ln_cb_param_notify_fulfill_htlc_recv_t;


/** @struct ln_cb_param_update_closing_fee_t
 *  @brief  FEE不一致なおclosing_signed受信(#LN_CB_TYPE_UPDATE_CLOSING_FEE)
 */
typedef struct {
    uint64_t                fee_sat;                ///< 受信したfee
} ln_cb_param_update_closing_fee_t;


/** @struct ln_cb_param_notify_closing_end_t
 *  @brief  Mutual Close完了通知(#LN_CB_TYPE_NOTIFY_CLOSING_END)
 */
typedef struct {
    bool                    result;                 ///< true:closing_tx展開成功
    const utl_buf_t         *p_tx_closing;          ///< ブロックチェーンに公開するtx
} ln_cb_param_notify_closing_end_t;


/** @struct ln_cb_anno_type_t
 *  @brief  announcement DB更新通知値
 */
typedef enum {
    LN_CB_ANNO_TYPE_NONE,
    LN_CB_ANNO_TYPE_CNL_ANNO,       //channel_announcement
    LN_CB_ANNO_TYPE_CNL_UPD,        //channel_update
    LN_CB_ANNO_TYPE_NODE_ANNO,      //node_announcement
} ln_cb_anno_type_t;


/** @struct ln_cb_param_notify_annodb_update_t
 *  @brief  announcement DB更新通知(#LN_CB_TYPE_NOTIFY_ANNODB_UPDATE)
 */
typedef struct {
    ln_cb_anno_type_t      type;
} ln_cb_param_notify_annodb_update_t;


/** @struct ln_cb_param_notify_pong_recv_t
 *  @brief  pong received(#LN_CB_TYPE_NOTIFY_PONG_RECV)
 */
typedef struct {
    bool                            ret;         //true: lnapp check OK
    uint16_t                        byteslen;       //pong.byteslen
    const uint8_t                   *p_ignored;     //pong.ignored
} ln_cb_param_notify_pong_recv_t;


#endif /* LN_CB_H__ */
