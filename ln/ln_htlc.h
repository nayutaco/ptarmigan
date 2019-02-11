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
 * macros
 **************************************************************************/

// ln_htlc_flags_t.addhtlc
#define LN_ADDHTLC_NONE                 (0x00)
#define LN_ADDHTLC_SEND                 (0x01)      ///< Offered HTLC
#define LN_ADDHTLC_RECV                 (0x02)      ///< Received HTLC

// ln_htlc_flags_t.delhtlc, fin_delhtlc
#define LN_DELHTLC_NONE                 (0x00)
#define LN_DELHTLC_FULFILL              (0x01)      ///< update_fulfill_htlc/update_fail_htlc/update_fail_malformed_htlc送信済み
#define LN_DELHTLC_FAIL                 (0x02)      ///< update_fail_htlc
#define LN_DELHTLC_FAIL_MALFORMED       (0x03)      ///< update_fail_malformed_htlc


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct ln_htlc_flags_t
 *  @brief  HTLC管理フラグ
 *  @note
 *      - uint16_tとunionする場合がある
 */
typedef struct {
    unsigned        addhtlc     : 2;    ///< LN_ADDHTLC_SEND/RECV
    unsigned        delhtlc     : 2;    ///< LN_DELHTLC_FULFILL/FAIL/FAIL_MALFORMED
    unsigned        updsend     : 1;    ///< 1:update message sent
    unsigned        comsend     : 1;    ///< 1:commitment_signed sent
    unsigned        revrecv     : 1;    ///< 1:revoke_and_ack received
    unsigned        comrecv     : 1;    ///< 1:commitment_signed received
    unsigned        revsend     : 1;    ///< 1:revoke_and_ack sent
    unsigned        fin_delhtlc : 2;    ///< flags.addhtlc == RECV
                                        //      update_add_htlc受信 && final node時、irrevocably committed後のflag.delhtlc
    unsigned        reserved    : 5;
} ln_htlc_flags_t;


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    LN_HTLC_EMPTY(pHtlc)
 *  @brief  ln_update_add_htlc_tの空き
 *  @note
 *      - HTLCの空き場所を探している場合には、(amount_msat != 0)も同時にチェックする
 */
#define LN_HTLC_EMPTY(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_NONE) && \
        ((pHtlc)->amount_msat == 0) \
    )

/** @def    LN_HTLC_ENABLED(pHtlc)
 *  @brief  ln_update_add_htlc_tとして有効
 *  @note
 *      - (amount_msat != 0)で判定していたが、update_add_htlcの転送の場合、
 *          update_add_htlc受信時に転送先にパラメータを全部設定して待たせておき、
 *          revoke_and_ackが完了してから指示だけを出すようにしたかった。
 */
//#define LN_HTLC_ENABLED(pHtlc)    ((pHtlc)->flags.addhtlc != LN_ADDHTLC_NONE)
#define LN_HTLC_ENABLED(pHtlc)    (!LN_HTLC_EMPTY(pHtlc))


/** @def    LN_HTLC_LOCAL_ADDHTLC_SEND_ENABLED(pHtlc)
 *  @brief  local commit_txのHTLC追加として使用できる(update_add_htlc送信側)
 */
#define LN_HTLC_LOCAL_ADDHTLC_SEND_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
        ((pHtlc)->flags.delhtlc == LN_DELHTLC_NONE) && \
        ((pHtlc)->flags.revrecv == 1) \
    )


/** @def    LN_HTLC_LOCAL_DELHTLC_RECV_ENABLED(pHtlc)
 *  @brief
 *    - commitment_signed受信時、local commit_tx作成に含む
 */
#define LN_HTLC_LOCAL_DELHTLC_RECV_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
        ((pHtlc)->flags.delhtlc != LN_DELHTLC_NONE) \
    )


/** @def    LN_HTLC_LOCAL_FULFILL_RECV_ENABLED(pHtlc)
 *  @brief  local commit_tx作成時、自分のamountから差し引く
 *  @note
 *    - #LN_HTLC_LOCAL_ADDHTLC_SEND_ENABLED()も差し引く対象になる
 */
#define LN_HTLC_LOCAL_FULFILL_RECV_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
        ((pHtlc)->flags.delhtlc == LN_DELHTLC_FULFILL) \
    )


/** @def    LN_HTLC_LOCAL_ADDHTLC_RECV_ENABLED(pHtlc)
 *  @brief  local commit_txのHTLC追加として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_LOCAL_ADDHTLC_RECV_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
        !( /*NOT*/ \
            ((pHtlc)->flags.updsend == 1) && \
            ((pHtlc)->flags.revrecv == 1) \
        ) \
    )


/** @def    LN_HTLC_LOCAL_DELHTLC_SEND_ENABLED(pHtlc)
 *  @brief  local commit_txのHTLC反映(commitment_signed)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_LOCAL_DELHTLC_SEND_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
        ((pHtlc)->flags.delhtlc != LN_DELHTLC_NONE) && \
        ((pHtlc)->flags.revrecv == 1) \
    )


/** @def    LN_HTLC_LOCAL_FULFILL_SEND_ENABLED(pHtlc)
 *  @brief  local commit_txのHTLC反映(amount)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_LOCAL_FULFILL_SEND_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
        ((pHtlc)->flags.delhtlc == LN_DELHTLC_FULFILL) && \
        ((pHtlc)->flags.revrecv == 1) \
    )


/** @def    LN_HTLC_REMOTE_ADDHTLC_RECV_ENABLED(pHtlc)
 *  @brief  remote commit_txのHTLC追加として使用できる(update_add_htlc送信側)
 */
#define LN_HTLC_REMOTE_ADDHTLC_RECV_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
        ((pHtlc)->flags.updsend == 1) && \
        !( /*NOT*/ \
            ((pHtlc)->flags.delhtlc != LN_DELHTLC_NONE) && \
            ((pHtlc)->flags.revsend == 1) \
        ) \
    )


/** @def    LN_HTLC_REMOTE_DELHTLC_SEND_ENABLED(pHtlc)
 *  @brief  remote commit_txのHTLC反映(commitment_signed)として使用できる(update_add_htlc送信側)
 */
#define LN_HTLC_REMOTE_DELHTLC_SEND_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
        ((pHtlc)->flags.delhtlc != LN_DELHTLC_NONE) && \
        ((pHtlc)->flags.revsend == 1) \
    )


/** @def    LN_HTLC_REMOTE_FULFILL_SEND_ENABLED(pHtlc)
 *  @brief  remote commit_tx作成時、相手のamountから差し引く
 *  @note
 *    - #LN_HTLC_REMOTE_ADDHTLC_RECV_ENABLED()も差し引く対象になる
 */
#define LN_HTLC_REMOTE_FULFILL_SEND_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
        ((pHtlc)->flags.delhtlc == LN_DELHTLC_FULFILL) && \
        ((pHtlc)->flags.revsend == 1) \
    )


/** @def    LN_HTLC_REMOTE_ADDHTLC_SEND_ENABLED(pHtlc)
 *  @brief  remote commit_txのHTLC追加として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_REMOTE_ADDHTLC_SEND_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
        ((pHtlc)->flags.updsend == 0) && \
        ((pHtlc)->flags.revsend == 1) \
    )


/** @def    LN_HTLC_REMOTE_DELHTLC_RECV_ENABLED(pHtlc)
 *  @brief  remote commit_txのHTLC反映(commitment_signed)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_REMOTE_DELHTLC_RECV_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
        ((pHtlc)->flags.updsend == 1) \
    )


/** @def    LN_HTLC_REMOTE_FULFILL_RECV_ENABLED(pHtlc)
 *  @brief  remote commit_txのHTLC反映(amount)として使用できる(update_add_htlc受信側)
 */
#define LN_HTLC_REMOTE_FULFILL_RECV_ENABLED(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
        ((pHtlc)->flags.updsend == 1) && \
        ((pHtlc)->flags.delhtlc == LN_DELHTLC_FULFILL) \
    )


/** @def    LN_HTLC_WILL_ADDHTLC_SEND(pHtlc)
 *  @brief  update_add_htlc送信予定
 */
#define LN_HTLC_WILL_ADDHTLC_SEND(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
        ((pHtlc)->flags.updsend == 0) \
    )


/** @def    LN_HTLC_WILL_DELHTLC_SEND(pHtlc)
 *  @brief  update_fulfill/fail/fail_malformed_htlc送信予定
 */
#define LN_HTLC_WILL_DELHTLC_SEND(pHtlc) \
    ( \
        ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
        ((pHtlc)->flags.delhtlc != LN_DELHTLC_NONE) && \
        ((pHtlc)->flags.updsend == 0) \
    )


/** @def    LN_HTLC_WILL_COMSIG_SEND_OFFERED_HTLC(pHtlc)
 *  @brief  commitment_signedを送信できる(update_add_htlc送信側)
 */
#define LN_HTLC_WILL_COMSIG_SEND_OFFERED_HTLC(pHtlc) \
    ( \
        ( \
            ( \
                LN_HTLC_REMOTE_ADDHTLC_RECV_ENABLED(pHtlc) && \
                ((pHtlc)->flags.delhtlc == LN_DELHTLC_NONE) \
            ) || \
            LN_HTLC_REMOTE_DELHTLC_SEND_ENABLED(pHtlc) \
        ) && \
        ((pHtlc)->flags.comsend == 0) \
    )


/** @def    LN_HTLC_WILL_COMSIG_SEND_RECEIVED_HTLC(pHtlc)
 *  @brief  commitment_signedを送信できる(update_add_htlc受信側)
 */
#define LN_HTLC_WILL_COMSIG_SEND_RECEIVED_HTLC(pHtlc) \
    ( \
        ( \
            LN_HTLC_REMOTE_ADDHTLC_SEND_ENABLED(pHtlc) || \
            LN_HTLC_REMOTE_DELHTLC_RECV_ENABLED(pHtlc) \
        ) && \
        ((pHtlc)->flags.comsend == 0) \
    )


#define LN_HTLC_WILL_COMSIG_SEND(pHtlc) \
    ( \
        LN_HTLC_WILL_COMSIG_SEND_OFFERED_HTLC(pHtlc) || \
        LN_HTLC_WILL_COMSIG_SEND_RECEIVED_HTLC(pHtlc) \
    )


#define LN_HTLC_ADDHTLC_SEND_ENABLED(pHtlc, b_local) \
    ((b_local) ? LN_HTLC_LOCAL_ADDHTLC_SEND_ENABLED(pHtlc) : LN_HTLC_REMOTE_ADDHTLC_SEND_ENABLED(pHtlc))


#define LN_HTLC_FULFILL_RECV_ENABLED(pHtlc, b_local) \
    ((b_local) ? LN_HTLC_LOCAL_FULFILL_RECV_ENABLED(pHtlc) : LN_HTLC_REMOTE_FULFILL_RECV_ENABLED(pHtlc))


#define LN_HTLC_ADDHTLC_RECV_ENABLED(pHtlc, b_local) \
    ((b_local) ? LN_HTLC_LOCAL_ADDHTLC_RECV_ENABLED(pHtlc) : LN_HTLC_REMOTE_ADDHTLC_RECV_ENABLED(pHtlc))


#define LN_HTLC_FULFILL_SEND_ENABLED(pHtlc, b_local) \
    ((b_local) ? LN_HTLC_LOCAL_FULFILL_SEND_ENABLED(pHtlc) : LN_HTLC_REMOTE_FULFILL_SEND_ENABLED(pHtlc))


#define LN_HTLC_LOCAL_SOME_UPDATE_ENABLED(pHtlc) \
( \
    LN_HTLC_LOCAL_ADDHTLC_SEND_ENABLED(pHtlc) || \
    LN_HTLC_LOCAL_DELHTLC_RECV_ENABLED(pHtlc) || \
    LN_HTLC_LOCAL_ADDHTLC_RECV_ENABLED(pHtlc) || \
    LN_HTLC_LOCAL_DELHTLC_SEND_ENABLED(pHtlc) \
)


#define LN_HTLC_REMOTE_SOME_UPDATE_ENABLED(pHtlc) \
( \
    LN_HTLC_REMOTE_ADDHTLC_SEND_ENABLED(pHtlc) || \
    LN_HTLC_REMOTE_DELHTLC_RECV_ENABLED(pHtlc) || \
    LN_HTLC_REMOTE_ADDHTLC_RECV_ENABLED(pHtlc) || \
    LN_HTLC_REMOTE_DELHTLC_SEND_ENABLED(pHtlc) \
)


#define LN_HTLC_COMSIGING(pHtlc) \
( \
    ((pHtlc)->flags.comsend && !(pHtlc)->flags.revrecv) || \
    ((pHtlc)->flags.comrecv && !(pHtlc)->flags.revsend) \
)


//update_add_htlc+commitment_signed送信直後
#define LN_HTLC_JUST_SEND_ADDHTLC_AND_COMSIG(pHtlc) \
( \
    ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
    ((pHtlc)->flags.delhtlc == LN_DELHTLC_NONE) && \
    ((pHtlc)->flags.updsend == 1) && \
    ((pHtlc)->flags.comsend == 1) && \
    ((pHtlc)->flags.revrecv == 0) && \
    ((pHtlc)->flags.comrecv == 0) && \
    ((pHtlc)->flags.revsend == 0) \
)


#define LN_HTLC_JUST_SEND_DELHTLC_AND_COMSIG(pHtlc, Delhtlc) \
( \
    ((pHtlc)->flags.addhtlc == LN_ADDHTLC_RECV) && \
    ((pHtlc)->flags.delhtlc == Delhtlc) && \
    ((pHtlc)->flags.updsend == 1) && \
    ((pHtlc)->flags.comsend == 1) && \
    ((pHtlc)->flags.revrecv == 0) && \
    ((pHtlc)->flags.comrecv == 0) && \
    ((pHtlc)->flags.revsend == 0) \
)


//update_fulfill_htlc+commitment_signed送信直後
#define LN_HTLC_JUST_SEND_FULFILL_AND_COMSIG(pHtlc) LN_HTLC_JUST_SEND_DELHTLC_AND_COMSIG(pHtlc, LN_DELHTLC_FULFILL)


//update_fail_htlc+commitment_signed送信直後
#define LN_HTLC_JUST_SEND_FAIL_AND_COMSIG(pHtlc) LN_HTLC_JUST_SEND_DELHTLC_AND_COMSIG(pHtlc, LN_DELHTLC_FAIL)


//update_fail_malformed_htlc+commitment_signed送信直後
#define LN_HTLC_JUST_SEND_FAIL_MALFORMED_AND_COMSIG(pHtlc) LN_HTLC_JUST_SEND_DELHTLC_AND_COMSIG(pHtlc, LN_DELHTLC_FAIL_MALFORMED)


#define LN_HTLC_REMOTE_ENABLE_ADDHTLC_SEND(pHtlc) { \
    memset(&(pHtlc)->flags, 0x00,  sizeof((pHtlc)->flags)); \
    (pHtlc)->flags.addhtlc = LN_ADDHTLC_SEND; \
    (pHtlc)->flags.updsend = 1; \
}


//XXX: probably the condition is wrong
#define LN_HTLC_TIMEOUT_CHECK_NEEDED(pHtlc) ( \
    ((pHtlc)->flags.addhtlc == LN_ADDHTLC_SEND) && \
    ((pHtlc)->flags.delhtlc == LN_DELHTLC_NONE) && \
    ((pHtlc)->flags.updsend == 1) && \
    ((pHtlc)->flags.comsend == 1) && \
    ((pHtlc)->flags.revrecv == 1) && \
    ((pHtlc)->flags.comrecv == 1) && \
    ((pHtlc)->flags.revsend == 1) && \
    ((pHtlc)->flags.fin_delhtlc == LN_DELHTLC_NONE) \
)


//test
#define LN_HTLC_TEST_EXCLUSIVENESS(pHtlc) \
( \
        !( /*NOT*/ \
            LN_HTLC_LOCAL_ADDHTLC_SEND_ENABLED(pHtlc) && \
            LN_HTLC_LOCAL_DELHTLC_RECV_ENABLED(pHtlc) \
        ) && \
        !( /*NOT*/ \
            LN_HTLC_LOCAL_ADDHTLC_RECV_ENABLED(pHtlc) && \
            LN_HTLC_LOCAL_DELHTLC_SEND_ENABLED(pHtlc) \
        ) && \
        !( /*NOT*/ \
            LN_HTLC_REMOTE_ADDHTLC_SEND_ENABLED(pHtlc) && \
            LN_HTLC_REMOTE_DELHTLC_RECV_ENABLED(pHtlc) \
        ) && \
        !( /*NOT*/ \
            LN_HTLC_REMOTE_ADDHTLC_RECV_ENABLED(pHtlc) && \
            LN_HTLC_REMOTE_DELHTLC_SEND_ENABLED(pHtlc) \
        ) \
    )


/**************************************************************************
 * static inline
 **************************************************************************/

static inline const char *ln_htlc_flags_addhtlc_str(int addhtlc)
{
    switch (addhtlc) {
    case LN_ADDHTLC_NONE: return "NONE";
    case LN_ADDHTLC_SEND: return "SEND";
    case LN_ADDHTLC_RECV: return "RECV";
    default: return "unknown";
    }
}


static inline const char *ln_htlc_flags_delhtlc_str(int delhtlc)
{
    switch (delhtlc) {
    case LN_DELHTLC_NONE: return "NONE";
    case LN_DELHTLC_FULFILL: return "FULFILL";
    case LN_DELHTLC_FAIL: return "FAIL";
    case LN_DELHTLC_FAIL_MALFORMED: return "FAIL_MALFORMED";
    default: return "unknown";
    }
}


/********************************************************************
 * prototypes
 ********************************************************************/

uint32_t ln_htlc_flags2u32(ln_htlc_flags_t Flags);


#endif /* LN_HTLC_H__ */
