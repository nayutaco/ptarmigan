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
/** @file   ln_htlc.h
 *  @brief  ln_htlc
 */
#ifndef LN_HTLC_H__
#define LN_HTLC_H__

#include <stdint.h>
#include <stdbool.h>

//XXX: unit test

/**************************************************************************
 * macro
 **************************************************************************/

// ln_htlc_flag_t.addhtlc
#define LN_ADDHTLC_NONE                 (0x00)
#define LN_ADDHTLC_SEND                 (0x01)      ///< Offered HTLC
#define LN_ADDHTLC_RECV                 (0x02)      ///< Received HTLC

// ln_htlc_flag_t.delhtlc, fin_delhtlc
#define LN_DELHTLC_NONE                 (0x00)
#define LN_DELHTLC_FULFILL              (0x01)      ///< update_fulfill_htlc/update_fail_htlc/update_fail_malformed_htlc送信済み
#define LN_DELHTLC_FAIL                 (0x02)      ///< update_fail_htlc
#define LN_DELHTLC_MALFORMED            (0x03)      ///< update_fail_malformed_htlc


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct ln_htlc_flag_t
 *  @brief  HTLC管理フラグ
 *  @note
 *      - uint16_tとunionする場合がある
 */
typedef struct {
    unsigned        addhtlc     : 2;    ///< LN_ADDHTLC_SEND/RECV
    unsigned        delhtlc     : 2;    ///< LN_DELHTLC_FULFILL/FAIL/MALFORMED
    unsigned        updsend     : 1;    ///< 1:update message sent
    unsigned        comsend     : 1;    ///< 1:commitment_signed sent
    unsigned        revrecv     : 1;    ///< 1:revoke_and_ack received
    unsigned        comrecv     : 1;    ///< 1:commitment_signed received
    unsigned        revsend     : 1;    ///< 1:revoke_and_ack sent
    unsigned        fin_delhtlc : 2;    ///< flag.addhtlc == RECV
                                        //      update_add_htlc受信 && final node時、irrevocably committed後のflag.delhtlc
    unsigned        reserved    : 5;
} ln_htlc_flag_t;


#define LN_HTLC_FLAG_MASK_HTLC           (0x000f)    ///< addhtlc, delhtlc
#define LN_HTLC_FLAG_MASK_UPDSEND        (0x0010)    ///< updsend
#define LN_HTLC_FLAG_MASK_COMSIG1        (0x0060)    ///< comsend, revrecv
#define LN_HTLC_FLAG_MASK_COMSIG2        (0x0180)    ///< comrecv, revsend
#define LN_HTLC_FLAG_MASK_COMSIG         ((LN_HTLC_FLAG_MASK_COMSIG1 | LN_HTLC_FLAG_MASK_COMSIG2))    ///< comsned, revrecv, comrecv, revsend
#define LN_HTLC_FLAG_MASK_FINDELHTLC     (0x0600)    ///< fin_delhtlc
#define LN_HTLC_FLAG_MASK_ALL            (LN_HTLC_FLAG_MASK_FINDELHTLC | LN_HTLC_FLAG_MASK_COMSIG | LN_HTLC_FLAG_MASK_UPDSEND | LN_HTLC_FLAG_MASK_HTLC)
#define LN_HTLC_FLAG_SFT_ADDHTLC(a)      ((uint16_t)(a))
#define LN_HTLC_FLAG_SFT_DELHTLC(a)      ((uint16_t)(a) << 2)
#define LN_HTLC_FLAG_SFT_UPDSEND         ((uint16_t)1 << 4)
#define LN_HTLC_FLAG_SFT_COMSEND         ((uint16_t)1 << 5)
#define LN_HTLC_FLAG_SFT_REVRECV         ((uint16_t)1 << 6)
#define LN_HTLC_FLAG_SFT_COMRECV         ((uint16_t)1 << 7)
#define LN_HTLC_FLAG_SFT_REVSEND         ((uint16_t)1 << 8)
#define LN_HTLC_FLAG_SFT_FINDELHTLC(a)   ((uint16_t)(a) << 9)
#define LN_HTLC_FLAG_SFT_UPDRECV         ((uint16_t)1 << 11)
#define LN_HTLC_FLAG_SFT_TIMEOUT         ( \
                                            LN_HTLC_FLAG_SFT_REVSEND | \
                                            LN_HTLC_FLAG_SFT_COMRECV | \
                                            LN_HTLC_FLAG_SFT_REVRECV | \
                                            LN_HTLC_FLAG_SFT_COMSEND | \
                                            LN_HTLC_FLAG_SFT_UPDSEND | \
                                            LN_HTLC_FLAG_SFT_ADDHTLC(LN_ADDHTLC_SEND) \
                                        )


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    LN_HTLC_EMPTY(htlc)
 *  @brief  ln_update_add_htlc_tの空き
 *  @note
 *      - HTLCの空き場所を探している場合には、(amount_msat != 0)も同時にチェックする
 */
#define LN_HTLC_EMPTY(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_NONE) && \
        ((htlc)->amount_msat == 0) \
    )

/** @def    LN_HTLC_ENABLE(htlc)
 *  @brief  ln_update_add_htlc_tとして有効
 *  @note
 *      - (amount_msat != 0)で判定していたが、update_add_htlcの転送の場合、
 *          update_add_htlc受信時に転送先にパラメータを全部設定して待たせておき、
 *          revoke_and_ackが完了してから指示だけを出すようにしたかった。
 */
//#define LN_HTLC_ENABLE(htlc)    ((htlc)->stat.flag.addhtlc != LN_ADDHTLC_NONE)
#define LN_HTLC_ENABLE(htlc)    (!LN_HTLC_EMPTY(htlc))


/** @def    LN_HTLC_ENABLE_LOCAL_ADDHTLC_SEND(htlc)
 *  @brief  local commit_txのHTLC追加として使用できる(update_add_htlc送信側)
 */
#define LN_HTLC_ENABLE_LOCAL_ADDHTLC_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_SEND) && \
        ((htlc)->stat.flag.delhtlc == LN_DELHTLC_NONE) && \
        ((htlc)->stat.flag.revrecv == 1) \
    )


/** @def    LN_HTLC_ENABLE_LOCAL_DELHTLC_RECV(htlc)
 *  @brief
 *    - commitment_signed受信時、local commit_tx作成に含む
 */
#define LN_HTLC_ENABLE_LOCAL_DELHTLC_RECV(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_SEND) && \
        ((htlc)->stat.flag.delhtlc != LN_DELHTLC_NONE) \
    )


/** @def    LN_HTLC_ENABLE_LOCAL_FULFILL_RECV(htlc)
 *  @brief  local commit_tx作成時、自分のamountから差し引く
 *  @note
 *    - #LN_HTLC_ENABLE_LOCAL_ADDHTLC_SEND()も差し引く対象になる
 */
#define LN_HTLC_ENABLE_LOCAL_FULFILL_RECV(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_SEND) && \
        ((htlc)->stat.flag.delhtlc == LN_DELHTLC_FULFILL) \
    )


/** @def    LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(htlc)
 *  @brief  local commit_txのHTLC追加として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_RECV) && \
        !( /*NOT*/ \
            ((htlc)->stat.flag.updsend == 1) && \
            ((htlc)->stat.flag.revrecv == 1) \
        ) \
    )


/** @def    LN_HTLC_ENABLE_LOCAL_DELHTLC_SEND(htlc)
 *  @brief  local commit_txのHTLC反映(commitment_signed)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_ENABLE_LOCAL_DELHTLC_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_RECV) && \
        ((htlc)->stat.flag.delhtlc != LN_DELHTLC_NONE) && \
        ((htlc)->stat.flag.revrecv == 1) \
    )


/** @def    LN_HTLC_ENABLE_LOCAL_FULFILL_SEND(htlc)
 *  @brief  local commit_txのHTLC反映(amount)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_ENABLE_LOCAL_FULFILL_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_RECV) && \
        ((htlc)->stat.flag.delhtlc == LN_DELHTLC_FULFILL) && \
        ((htlc)->stat.flag.revrecv == 1) \
    )


/** @def    LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(htlc)
 *  @brief  remote commit_txのHTLC追加として使用できる(update_add_htlc送信側)
 */
#define LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_SEND) && \
        ((htlc)->stat.flag.updsend == 1) && \
        !( /*NOT*/ \
            ((htlc)->stat.flag.delhtlc != LN_DELHTLC_NONE) && \
            ((htlc)->stat.flag.revsend == 1) \
        ) \
    )


/** @def    LN_HTLC_ENABLE_REMOTE_DELHTLC_SEND(htlc)
 *  @brief  remote commit_txのHTLC反映(commitment_signed)として使用できる(update_add_htlc送信側)
 */
#define LN_HTLC_ENABLE_REMOTE_DELHTLC_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_SEND) && \
        ((htlc)->stat.flag.delhtlc != LN_DELHTLC_NONE) && \
        ((htlc)->stat.flag.revsend == 1) \
    )


/** @def    LN_HTLC_ENABLE_REMOTE_FULFILL_SEND(htlc)
 *  @brief  remote commit_tx作成時、相手のamountから差し引く
 *  @note
 *    - #LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV()も差し引く対象になる
 */
#define LN_HTLC_ENABLE_REMOTE_FULFILL_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_SEND) && \
        ((htlc)->stat.flag.delhtlc == LN_DELHTLC_FULFILL) && \
        ((htlc)->stat.flag.revsend == 1) \
    )


/** @def    LN_HTLC_ENABLE_REMOTE_ADDHTLC_SEND(htlc)
 *  @brief  remote commit_txのHTLC追加として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_ENABLE_REMOTE_ADDHTLC_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_RECV) && \
        ((htlc)->stat.flag.updsend == 0) && \
        ((htlc)->stat.flag.revsend == 1) \
    )


/** @def    LN_HTLC_ENABLE_REMOTE_DELHTLC_RECV(htlc)
 *  @brief  remote commit_txのHTLC反映(commitment_signed)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_ENABLE_REMOTE_DELHTLC_RECV(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_RECV) && \
        ((htlc)->stat.flag.updsend == 1) \
    )


/** @def    LN_HTLC_ENABLE_REMOTE_FULFILL_RECV(htlc)
 *  @brief  remote commit_txのHTLC反映(amount)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_ENABLE_REMOTE_FULFILL_RECV(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_RECV) && \
        ((htlc)->stat.flag.updsend == 1) && \
        ((htlc)->stat.flag.delhtlc == LN_DELHTLC_FULFILL) \
    )


/** @def    LN_HTLC_WILL_ADDHTLC_SEND(htlc)
 *  @brief  update_add_htlc送信予定
 */
#define LN_HTLC_WILL_ADDHTLC_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_SEND) && \
        ((htlc)->stat.flag.updsend == 0) \
    )


/** @def    LN_HTLC_WILL_DELHTLC_SEND(htlc)
 *  @brief  update_fulfill/fail/fail_malformed_htlc送信予定
 *  @note
 *      - update_fulfill_htlc: #LN_HTLC_IS_FULFILL()がtrue
 *      - update_fail_malformed_htlc: #LN_HTLC_IS_MALFORMED()がtrue
 *      - update_fail_htlc: それ以外
 */
#define LN_HTLC_WILL_DELHTLC_SEND(htlc) \
    ( \
        ((htlc)->stat.flag.addhtlc == LN_ADDHTLC_RECV) && \
        ((htlc)->stat.flag.delhtlc != LN_DELHTLC_NONE) && \
        ((htlc)->stat.flag.updsend == 0) \
    )


/** @def    LN_HTLC_WILL_COMSIG_SEND_OFFERED_HTLC(htlc)
 *  @brief  commitment_signedを送信できる(update_add_htlc送信側)
 */
#define LN_HTLC_WILL_COMSIG_SEND_OFFERED_HTLC(htlc) \
    ( \
        ( \
            ( \
                LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(htlc) && \
                ((htlc)->stat.flag.delhtlc == LN_DELHTLC_NONE) \
            ) || \
            LN_HTLC_ENABLE_REMOTE_DELHTLC_SEND(htlc) \
        ) && \
        ((htlc)->stat.flag.comsend == 0) \
    )


/** @def    LN_HTLC_WILL_COMSIG_SEND_RECEIVED_HTLC(htlc)
 *  @brief  commitment_signedを送信できる(update_add_htlc受信側)
 */
#define LN_HTLC_WILL_COMSIG_SEND_RECEIVED_HTLC(htlc) \
    ( \
        ( \
            LN_HTLC_ENABLE_REMOTE_ADDHTLC_SEND(htlc) || \
            LN_HTLC_ENABLE_REMOTE_DELHTLC_RECV(htlc) \
        ) && \
        ((htlc)->stat.flag.comsend == 0) \
    )


#define LN_HTLC_WILL_COMSIG_SEND(htlc) \
    ( \
        LN_HTLC_WILL_COMSIG_SEND_OFFERED_HTLC(htlc) || \
        LN_HTLC_WILL_COMSIG_SEND_RECEIVED_HTLC(htlc) \
    )


#define LN_HTLC_ENABLE_ADDHTLC_SEND(htlc, b_local) \
    ((b_local) ? LN_HTLC_ENABLE_LOCAL_ADDHTLC_SEND(htlc) : LN_HTLC_ENABLE_REMOTE_ADDHTLC_SEND(htlc))


#define LN_HTLC_ENABLE_FULFILL_RECV(htlc, b_local) \
    ((b_local) ? LN_HTLC_ENABLE_LOCAL_FULFILL_RECV(htlc) : LN_HTLC_ENABLE_REMOTE_FULFILL_RECV(htlc))


#define LN_HTLC_ENABLE_ADDHTLC_RECV(htlc, b_local) \
    ((b_local) ? LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(htlc) : LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(htlc))


#define LN_HTLC_ENABLE_FULFILL_SEND(htlc, b_local) \
    ((b_local) ? LN_HTLC_ENABLE_LOCAL_FULFILL_SEND(htlc) : LN_HTLC_ENABLE_REMOTE_FULFILL_SEND(htlc))


#define LN_HTLC_ENABLE_LOCAL_SOME_UPDATE(htlc) ( \
    ( \
        LN_HTLC_ENABLE_LOCAL_ADDHTLC_SEND(htlc) || \
        LN_HTLC_ENABLE_LOCAL_DELHTLC_RECV(htlc) || \
        LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(htlc) || \
        LN_HTLC_ENABLE_LOCAL_DELHTLC_SEND(htlc) \
    ) \
)


#define LN_HTLC_ENABLE_REMOTE_SOME_UPDATE(htlc) ( \
    ( \
        LN_HTLC_ENABLE_REMOTE_ADDHTLC_SEND(htlc) || \
        LN_HTLC_ENABLE_REMOTE_DELHTLC_RECV(htlc) || \
        LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(htlc) || \
        LN_HTLC_ENABLE_REMOTE_DELHTLC_SEND(htlc) \
    ) \
)


//test
#define LN_HTLC_TEST_EXCLUSIVENESS(htlc) ( \
        !( /*NOT*/ \
            LN_HTLC_ENABLE_LOCAL_ADDHTLC_SEND(htlc) && \
            LN_HTLC_ENABLE_LOCAL_DELHTLC_RECV(htlc) \
        ) && \
        !( /*NOT*/ \
            LN_HTLC_ENABLE_LOCAL_ADDHTLC_RECV(htlc) && \
            LN_HTLC_ENABLE_LOCAL_DELHTLC_SEND(htlc) \
        ) && \
        !( /*NOT*/ \
            LN_HTLC_ENABLE_REMOTE_ADDHTLC_SEND(htlc) && \
            LN_HTLC_ENABLE_REMOTE_DELHTLC_RECV(htlc) \
        ) && \
        !( /*NOT*/ \
            LN_HTLC_ENABLE_REMOTE_ADDHTLC_RECV(htlc) && \
            LN_HTLC_ENABLE_REMOTE_DELHTLC_SEND(htlc) \
        ) \
    )


/********************************************************************
 * prototypes
 ********************************************************************/


#endif /* LN_HTLC_H__ */
