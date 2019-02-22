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
/** @file   ln_update.h
 *  @brief  ln_update
 */
#ifndef LN_UPDATE_H__
#define LN_UPDATE_H__

#include <stdint.h>
#include <stdbool.h>

#include "ln_common.h"

//XXX: unit test


/**************************************************************************
 * macros
 **************************************************************************/

#define LN_UPDATE_FEE_MAX                   (2) //XXX: Probably `update_fee` needs up to 2 slots
#define LN_UPDATE_MAX                       (LN_HTLC_OFFERED_MAX_XXX * 2 + LN_HTLC_RECEIVED_MAX * 2 + LN_UPDATE_FEE_MAX)

// ln_update_flags_t.type
#define LN_UPDATE_TYPE_NONE                 (0x0)
#define LN_UPDATE_TYPE_ADD_HTLC             (0x1)
#define LN_UPDATE_TYPE_FULFILL_HTLC         (0x2)
#define LN_UPDATE_TYPE_FAIL_HTLC            (0x3)
#define LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC  (0x4)
#define LN_UPDATE_TYPE_FEE                  (0x5)


/********************************************************************
 * typedefs
 ********************************************************************/

//forward definition
//struct ln_channel_t;
//typedef struct ln_channel_t ln_channel_t;


/** @struct ln_update_flags_t
 *  @brief  UPDATE管理フラグ
 */
typedef struct {
    unsigned        up_send     : 1;    ///< update message sent
    unsigned        up_recv     : 1;    ///< update message received
    unsigned        cs_send     : 1;    ///< commitment_signed sent
    unsigned        cs_recv     : 1;    ///< commitment_signed received
    unsigned        ra_send     : 1;    ///< revoke_and_ack sent
    unsigned        ra_recv     : 1;    ///< revoke_and_ack received
    unsigned        reserved    : 2;    ///<
} ln_update_flags_t;


/** @struct     ln_update_t
 *  @brief      update message
 */
typedef struct {
    bool                enabled;                        ///< XXX: Interim. Soon abolished
    uint8_t             type;                           ///<
    ln_update_flags_t   flags;                          ///<
    uint16_t            htlc_idx;                       ///< index of `ln_htlc_t` array
    uint8_t             fin_type;                       ///<
} ln_update_t;


/** @struct     ln_htlc_t
 *  @brief      htlc
 */
typedef struct {
    bool                enabled;                        ///< XXX: Interim. Soon abolished
    uint64_t            id;                             ///< 8:  id
    uint64_t            amount_msat;                    ///< 8:  amount_msat
    uint32_t            cltv_expiry;                    ///< 4:  cltv_expirty
    uint8_t             payment_hash[BTC_SZ_HASH256];   ///< 32: payment_hash
    utl_buf_t           buf_payment_preimage;           ///< 32: payment_preimage
    utl_buf_t           buf_onion_reason;               ///<
                                                        //  update_add_htlc
                                                        //      1366: onion_routing_packet
                                                        //          final node: length == 0
                                                        //  update_fail_htlc
                                                        //      len:  reason
    uint8_t             remote_sig[LN_SZ_SIGNATURE];    ///< 受信した最新のHTLC署名
                                                        //      相手がunilateral close後にHTLC-txを送信しなかった場合に使用する
    utl_buf_t           buf_shared_secret;              ///< failuremsg暗号化用

    uint64_t            neighbor_short_channel_id;      ///<
    uint16_t            neighbor_idx;                   ///<
} ln_htlc_t;


/**************************************************************************
 * macro functions
 **************************************************************************/

/** @def    LN_UPDATE_EMPTY(pUpdate)
 *  @brief  ln_update_tの空き
 */
#define LN_UPDATE_EMPTY(pUpdate) \
    ( \
        ((pUpdate)->type == LN_UPDATE_TYPE_NONE) && \
        (!(pUpdate)->enabled) \
    )


/** @def    LN_UPDATE_ENABLED(pUpdate)
 *  @brief  ln_update_tとして有効
 */
#define LN_UPDATE_ENABLED(pUpdate)    (!LN_UPDATE_EMPTY(pUpdate))


#define LN_UPDATE_LOCAL_UNCOMMITTED(pUpdate) ((pUpdate)->flags.cs_recv == 0)
#define LN_UPDATE_REMOTE_UNCOMMITTED(pUpdate) ((pUpdate)->flags.cs_send == 0)
#define LN_UPDATE_UNCOMMITTED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_UNCOMMITTED(pUpdate) : LN_UPDATE_REMOTE_UNCOMMITTED(pUpdate))
#define LN_UPDATE_IRREVOCABLY_COMMITTED(pUpdate) \
    ( \
        ((pUpdate)->flags.cs_send == 1) && \
        ((pUpdate)->flags.cs_recv == 1) && \
        ((pUpdate)->flags.ra_send == 1) && \
        ((pUpdate)->flags.ra_recv == 1) \
    )


#define LN_UPDATE_LOCAL_SOME_SEND_ENABLED(pUpdate) \
    ( \
        ((pUpdate)->flags.up_send == 1) && \
        ((pUpdate)->flags.cs_send == 1) && \
        ((pUpdate)->flags.ra_recv == 1) \
    )
#define LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type == Type) && \
        LN_UPDATE_LOCAL_SOME_SEND_ENABLED(pUpdate) \
    )
#define LN_UPDATE_LOCAL_ADD_HTLC_SEND_ENABLED(pUpdate) \
    LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_ADD_HTLC)
#define LN_UPDATE_LOCAL_FULFILL_HTLC_SEND_ENABLED(pUpdate) \
    LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC)
#define LN_UPDATE_LOCAL_DEL_HTLC_SEND_ENABLED(pUpdate) \
    ( \
        LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC) || \
        LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_HTLC) || \
        LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC) \
    )


#define LN_UPDATE_LOCAL_SOME_RECV_ENABLED(pUpdate) \
    ( \
        ((pUpdate)->flags.up_recv == 1) \
    )
#define LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type == Type) && \
        LN_UPDATE_LOCAL_SOME_RECV_ENABLED(pUpdate) \
    )
#define LN_UPDATE_LOCAL_ADD_HTLC_RECV_ENABLED(pUpdate) \
    LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_ADD_HTLC)
#define LN_UPDATE_LOCAL_FULFILL_HTLC_RECV_ENABLED(pUpdate) \
    LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC)
#define LN_UPDATE_LOCAL_DEL_HTLC_RECV_ENABLED(pUpdate) \
    ( \
        LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC) || \
        LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_HTLC) || \
        LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC) \
    )


#define LN_UPDATE_REMOTE_SOME_SEND_ENABLED(pUpdate) \
    ( \
        ((pUpdate)->flags.up_recv == 1) && \
        ((pUpdate)->flags.cs_recv == 1) && \
        ((pUpdate)->flags.ra_send == 1) \
    )
#define LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type == Type) && \
        LN_UPDATE_REMOTE_SOME_SEND_ENABLED(pUpdate) \
    )
#define LN_UPDATE_REMOTE_ADD_HTLC_SEND_ENABLED(pUpdate) \
    LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_ADD_HTLC)
#define LN_UPDATE_REMOTE_FULFILL_HTLC_SEND_ENABLED(pUpdate) \
    LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC)
#define LN_UPDATE_REMOTE_DEL_HTLC_SEND_ENABLED(pUpdate) \
    ( \
        LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC) || \
        LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_HTLC) || \
        LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC) \
    )


#define LN_UPDATE_REMOTE_SOME_RECV_ENABLED(pUpdate) \
    ( \
        ((pUpdate)->flags.up_send == 1) \
    )
#define LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type == Type) && \
        LN_UPDATE_REMOTE_SOME_RECV_ENABLED(pUpdate) \
    )
#define LN_UPDATE_REMOTE_ADD_HTLC_RECV_ENABLED(pUpdate) \
    LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_ADD_HTLC)
#define LN_UPDATE_REMOTE_FULFILL_HTLC_RECV_ENABLED(pUpdate) \
    LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC)
#define LN_UPDATE_REMOTE_DEL_HTLC_RECV_ENABLED(pUpdate) \
    ( \
        LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FULFILL_HTLC) || \
        LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_HTLC) || \
        LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC) \
    )


#define LN_UPDATE_WILL_SEND(pUpdate) \
    ( \
        ((pUpdate)->type != LN_UPDATE_TYPE_NONE) && \
        ((pUpdate)->flags.up_send == 0) && \
        ((pUpdate)->flags.up_recv == 0) \
    )


#define LN_UPDATE_WILL_COMSIG_SEND(pUpdate) \
    ( \
        ( \
            LN_UPDATE_REMOTE_SOME_SEND_ENABLED(pUpdate) || \
            LN_UPDATE_REMOTE_SOME_RECV_ENABLED(pUpdate) \
        ) && \
        ( \
            ((pUpdate)->flags.cs_send == 0) \
        ) \
    )


#define LN_UPDATE_ADD_HTLC_SEND_ENABLED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_ADD_HTLC_SEND_ENABLED(pUpdate) : LN_UPDATE_REMOTE_ADD_HTLC_SEND_ENABLED(pUpdate))
#define LN_UPDATE_DEL_HTLC_RECV_ENABLED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_DEL_HTLC_RECV_ENABLED(pUpdate) : LN_UPDATE_REMOTE_DEL_HTLC_RECV_ENABLED(pUpdate))
#define LN_UPDATE_FULFILL_HTLC_RECV_ENABLED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_FULFILL_HTLC_RECV_ENABLED(pUpdate) : LN_UPDATE_REMOTE_FULFILL_HTLC_RECV_ENABLED(pUpdate))
#define LN_UPDATE_ADD_HTLC_RECV_ENABLED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_ADD_HTLC_RECV_ENABLED(pUpdate) : LN_UPDATE_REMOTE_ADD_HTLC_RECV_ENABLED(pUpdate))
#define LN_UPDATE_DEL_HTLC_SEND_ENABLED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_DEL_HTLC_SEND_ENABLED(pUpdate) : LN_UPDATE_REMOTE_DEL_HTLC_SEND_ENABLED(pUpdate))
#define LN_UPDATE_FULFILL_HTLC_SEND_ENABLED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_FULFILL_HTLC_SEND_ENABLED(pUpdate) : LN_UPDATE_REMOTE_FULFILL_HTLC_SEND_ENABLED(pUpdate))


#define LN_UPDATE_LOCAL_SOME_UPDATE_ENABLED(pUpdate) \
    ( \
        LN_UPDATE_LOCAL_SOME_SEND_ENABLED(pUpdate) || \
        LN_UPDATE_LOCAL_SOME_RECV_ENABLED(pUpdate) \
    )
#define LN_UPDATE_REMOTE_SOME_UPDATE_ENABLED(pUpdate) \
    ( \
        LN_UPDATE_REMOTE_SOME_SEND_ENABLED(pUpdate) || \
        LN_UPDATE_REMOTE_SOME_RECV_ENABLED(pUpdate) \
    )
#define LN_UPDATE_SOME_UPDATE_ENABLED(pUpdate, bLocal) \
    ((bLocal) ? LN_UPDATE_LOCAL_SOME_UPDATE_ENABLED(pUpdate) : LN_UPDATE_REMOTE_SOME_UPDATE_ENABLED(pUpdate))


#define LN_UPDATE_LOCAL_COMSIGING(pUpdate) \
    ((pUpdate)->flags.cs_recv && !(pUpdate)->flags.ra_send)
#define LN_UPDATE_REMOTE_COMSIGING(pUpdate) \
    ((pUpdate)->flags.cs_send && !(pUpdate)->flags.ra_recv)
#define LN_UPDATE_COMSIGING(pUpdate) \
    ( \
        LN_UPDATE_LOCAL_COMSIGING(pUpdate) || \
        LN_UPDATE_REMOTE_COMSIGING(pUpdate) \
    )


#define LN_UPDATE_REMOTE_ENABLE_ADD_HTLC_RECV(pUpdate) { \
    memset(&(pUpdate)->flags, 0x00,  sizeof((pUpdate)->flags)); \
    (pUpdate)->type = LN_UPDATE_TYPE_ADD_HTLC; \
    (pUpdate)->flags.up_send = 1; \
}


#define LN_UPDATE_TIMEOUT_CHECK_NEEDED(pHtlc) ( \
    ((pHtlc)->type == LN_UPDATE_TYPE_ADD_HTLC) && \
    ((pHtlc)->flags.up_send == 1) && \
    ((pHtlc)->flags.cs_send == 1) \
)


#define LN_UPDATE_ENABLE_RESEND_UPDATE(pUpdate) { \
    assert((pUpdate)->flags.up_recv == 0); \
    assert((pUpdate)->flags.cs_recv == 0); \
    assert((pUpdate)->flags.ra_send == 0); \
    assert((pUpdate)->flags.ra_recv == 0); \
    (pUpdate)->flags.up_send = 0; \
    (pUpdate)->flags.cs_send = 0; \
}


/**************************************************************************
 * static inline
 **************************************************************************/

static inline const char *ln_update_type_str(uint8_t type)
{
    switch (type) {
    case LN_UPDATE_TYPE_NONE: return "NONE";
    case LN_UPDATE_TYPE_ADD_HTLC: return "ADD_HTLC";
    case LN_UPDATE_TYPE_FULFILL_HTLC: return "FULFILL_HTLC";
    case LN_UPDATE_TYPE_FAIL_HTLC: return "FAIL_HTLC";
    case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC: return "FAIL_MALFORMED_HTLC";
    case LN_UPDATE_TYPE_FEE: return "FEE";
    default: return "UNKNOWN";
    }
}


/********************************************************************
 * prototypes
 ********************************************************************/

uint32_t ln_update_flags2u32(ln_update_flags_t Flags);


ln_update_t *ln_update_get_empty( ln_update_t *pUpdates, uint16_t *pUpdateIdx);


bool ln_update_get_corresponding_update(
    const ln_update_t *pUpdates, uint16_t *pCorrespondingUpdateIdx, uint16_t UpdateIdx);


ln_update_t *ln_update_set_del_htlc_send(ln_update_t *pUpdates, uint16_t HtlcIdx, uint8_t Type);


ln_update_t *ln_update_set_del_htlc_recv(ln_update_t *pUpdates, uint16_t HtlcIdx, uint8_t Type);


ln_update_t *ln_update_get_update_enabled_but_none(ln_update_t *pUpdates, uint16_t HtlcIdx);


ln_update_t *ln_update_get_update_add_htlc(ln_update_t *pUpdates, uint16_t HtlcIdx);


ln_update_t *ln_update_get_update_del_htlc(ln_update_t *pUpdates, uint16_t HtlcIdx);


const ln_update_t *ln_update_get_update_del_htlc_const(const ln_update_t *pUpdates, uint16_t HtlcIdx);


ln_htlc_t *ln_htlc_get_empty(ln_htlc_t *pHtlcs, uint16_t *pHtlcIdx);


#ifdef LN_DBG_PRINT
void ln_update_print(const ln_update_t *pUpdate);


void ln_update_updates_print(const ln_update_t *pUpdates);
#endif //LN_DBG_PRINT


#endif /* LN_UPDATE_H__ */
