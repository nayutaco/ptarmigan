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
    LN_CB_TYPE_QUIT,                 ///< チャネルを停止(closeはしない)
    LN_CB_TYPE_ERROR,                ///< エラー通知
    LN_CB_TYPE_INIT_RECV,            ///< init受信通知
    LN_CB_TYPE_REESTABLISH_RECV,     ///< channel_reestablish受信通知
    LN_CB_TYPE_SIGN_FUNDINGTX_REQ,   ///< funding_tx署名要求
    LN_CB_TYPE_FUNDINGTX_WAIT,       ///< funding_tx安定待ち要求
    LN_CB_TYPE_FUNDINGLOCKED_RECV,   ///< funding_locked受信通知
    LN_CB_TYPE_UPDATE_ANNODB,        ///< announcement DB更新通知
    LN_CB_TYPE_ADD_HTLC_RECV_PREV,   ///< update_add_htlc処理前通知
    LN_CB_TYPE_ADD_HTLC_RECV,        ///< update_add_htlc受信通知
    LN_CB_TYPE_FWD_ADDHTLC_START,    ///< update_add_htlc転送開始
    LN_CB_TYPE_BWD_DELHTLC_START,    ///< HTLC削除処理開始
    LN_CB_TYPE_FULFILL_HTLC_RECV,    ///< update_fulfill_htlc受信通知
    LN_CB_TYPE_FAIL_HTLC_RECV,       ///< update_fail_htlc受信通知
    LN_CB_TYPE_REV_AND_ACK_EXCG,     ///< revoke_and_ack交換通知
    LN_CB_TYPE_PAYMENT_RETRY,        ///< 送金リトライ
    LN_CB_TYPE_UPDATE_FEE_RECV,      ///< update_fee受信通知
    LN_CB_TYPE_SHUTDOWN_RECV,        ///< shutdown受信通知
    LN_CB_TYPE_CLOSED_FEE,           ///< closing_signed受信通知(FEE不一致)
    LN_CB_TYPE_CLOSED,               ///< closing_signed受信通知(FEE一致)
    LN_CB_TYPE_SEND_REQ,             ///< peerへの送信要求
    LN_CB_TYPE_SEND_QUEUE,           ///< 送信キュー保存(廃止予定)
    LN_CB_TYPE_GET_LATEST_FEERATE,   ///< feerate_per_kw取得要求
    LN_CB_TYPE_GETBLOCKCOUNT,        ///< getblockcount
    LN_CB_TYPE_PONG_RECV,            ///< pong received
    LN_CB_TYPE_MAX,
} ln_cb_type_t;


/** @typedef    ln_callback_t
 *  @brief      通知コールバック関数
 *  @note
 *      - p_paramで渡すデータを上位層で保持しておきたい場合、コピーを取ること
 */
typedef void (*ln_callback_t)(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param);


/** @struct ln_cb_funding_sign_t
 *  @brief  funding_tx署名要求(#LN_CB_TYPE_SIGN_FUNDINGTX_REQ)
 */
typedef struct {
    btc_tx_t                *p_tx;
    uint64_t                amount;     //(SPV未使用)fund-inするamount[satoshi]
    bool                    ret;        //署名結果
} ln_cb_funding_sign_t;


/** @struct ln_cb_funding_t
 *  @brief  funding_tx安定待ち要求(#LN_CB_TYPE_FUNDINGTX_WAIT) / Establish完了通知(#LN_CB_TYPE_ESTABLISHED)
 */
typedef struct {
    const btc_tx_t          *p_tx_funding;              ///< funding_tx
    const uint8_t           *p_txid;                    ///< funding txid
    bool                    b_send;                     ///< true:funding_txを送信する
    bool                    annosigs;                   ///< true:announce_signaturesを送信する
    bool                    b_result;                   ///< true:funding_tx送信成功
} ln_cb_funding_t;


/** @struct ln_cb_add_htlc_recv_prev_t
 *  @brief  update_add_htlc受信 前処理(#LN_CB_TYPE_ADD_HTLC_RECV_PREV)
 */
typedef struct {
    uint64_t                next_short_channel_id;
    const ln_channel_t      *p_next_channel;
} ln_cb_add_htlc_recv_prev_t;


/** @enum   ln_cb_add_htlc_result_t
 *  @brief  result of update_add_htlc processing
 */
typedef enum {
    LN_CB_ADD_HTLC_RESULT_OK,               ///< transfer update_add_htlc or backward update_fulfill_htlc
    LN_CB_ADD_HTLC_RESULT_FAIL,             ///< backward update_fail_htlc
    LN_CB_ADD_HTLC_RESULT_FAIL_MALFORMED,   ///< backward update_fail_malformed_htlc
} ln_cb_add_htlc_result_t;


/** @struct ln_cb_add_htlc_recv_t
 *  @brief  update_add_htlc受信通知(#LN_CB_TYPE_ADD_HTLC_RECV)
 */
typedef struct {
    bool                        ret;                    ///< callback処理結果
    uint64_t                    id;                     ///< HTLC id
    const uint8_t               *p_payment;             ///< payment_hash
    const ln_hop_dataout_t      *p_hop;                 ///< onion解析結果
    uint64_t                    amount_msat;            ///< pChannel->cnl_add_htlc[idx].amount_msat
    uint32_t                    cltv_expiry;            ///< pChannel->cnl_add_htlc[idx].cltv_expiry
    uint16_t                    idx;                    ///< pChannel->cnl_add_htlc[idx]
    utl_buf_t                   *p_onion_reason;        ///< 変換後onionパケット(ok==true) or fail reason(ok==false)
    const utl_buf_t             *p_shared_secret;       ///< onion shared secret
} ln_cb_add_htlc_recv_t;


typedef struct {
    uint64_t                    short_channel_id;
    uint16_t                    idx;
} ln_cb_fwd_add_htlc_t;


typedef struct {
    uint64_t                    short_channel_id;
    uint16_t                    idx;
    uint8_t                     fin_delhtlc;
} ln_cb_bwd_del_htlc_t;


/** @struct ln_cb_fulfill_htlc_recv_t
 *  @brief  update_fulfill_htlc受信通知(#LN_CB_TYPE_FULFILL_HTLC_RECV)
 */
typedef struct {
    bool                    ret;                    ///< callback処理結果
    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    uint16_t                prev_idx;               ///< pChannel->cnl_add_htlc[idx]
    const uint8_t           *p_preimage;            ///< update_fulfill_htlcで受信したpreimage(スタック)
    uint64_t                id;                     ///< HTLC id
    uint64_t                amount_msat;            ///< HTLC amount
} ln_cb_fulfill_htlc_recv_t;


/** @struct ln_cb_fail_htlc_recv_t
 *  @brief  update_fail_htlc受信通知(#LN_CB_TYPE_FAIL_HTLC_RECV)
 */
typedef struct {
    bool                    result;

    uint64_t                prev_short_channel_id;  ///< 転送元short_channel_id
    const utl_buf_t         *p_reason;              ///< reason
    const utl_buf_t         *p_shared_secret;       ///< shared secret
    uint16_t                prev_idx;               ///< pChannel->cnl_add_htlc[idx]
    uint64_t                orig_id;                ///< 元のHTLC id
    const uint8_t           *p_payment_hash;        ///< payment_hash
    uint16_t                fail_malformed_failure_code;    ///< !0: malformed_htlcのfailure_code
} ln_cb_fail_htlc_recv_t;


/** @struct ln_cb_closed_fee_t
 *  @brief  FEE不一致なおclosing_signed受信(#LN_CB_TYPE_CLOSED_FEE)
 */
typedef struct {
    uint64_t                fee_sat;                ///< 受信したfee
} ln_cb_closed_fee_t;


/** @struct ln_cb_closed_t
 *  @brief  Mutual Close完了通知(#LN_CB_TYPE_CLOSED)
 */
typedef struct {
    bool                    result;                 ///< true:closing_tx展開成功
    const utl_buf_t         *p_tx_closing;          ///< ブロックチェーンに公開するtx
} ln_cb_closed_t;


/** @struct ln_cb_anno_sigs_t
 *  @brief  announcement_signatures
 */
typedef struct {
    const utl_buf_t         *p_buf_bolt;            ///< 受信したannouncement_signatures
    uint8_t                 sort;
} ln_cb_anno_sigs_t;


/** @struct ln_cb_update_annodb_anno_t
 *  @brief  announcement DB更新通知値
 */
typedef enum {
    LN_CB_UPDATE_ANNODB_NONE,
    LN_CB_UPDATE_ANNODB_CNL_ANNO,       //channel_announcement
    LN_CB_UPDATE_ANNODB_CNL_UPD,        //channel_update
    LN_CB_UPDATE_ANNODB_NODE_ANNO,      //node_announcement
} ln_cb_update_annodb_anno_t;


/** @struct ln_cb_update_annodb_t
 *  @brief  announcement DB更新通知(#LN_CB_TYPE_UPDATE_ANNODB)
 */
typedef struct {
    ln_cb_update_annodb_anno_t      anno;
} ln_cb_update_annodb_t;


/** @struct ln_cb_pong_recv_t
 *  @brief  pong received(#LN_CB_TYPE_PONG_RECV)
 */
typedef struct {
    bool                            result;         //true: lnapp check OK
    uint16_t                        byteslen;       //pong.byteslen
    const uint8_t                   *p_ignored;     //pong.ignored
} ln_cb_pong_recv_t;


#endif /* LN_CB_H__ */
