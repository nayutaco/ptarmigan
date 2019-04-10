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

#include "utl_buf.h"

#include "btc_crypto.h"

#include "ln_common.h"

//XXX: unit test


/**************************************************************************
 * macros
 **************************************************************************/

#define LN_UPDATE_MAX                       (LN_HTLC_OFFERED_MAX * 2 + LN_HTLC_RECEIVED_MAX * 2 + LN_FEE_UPDATE_MAX)

// ln_update_flags_t.type
#define LN_UPDATE_TYPE_NONE                 (0)
#define LN_UPDATE_TYPE_ADD_HTLC             (1 << 0)
#define LN_UPDATE_TYPE_FULFILL_HTLC         (1 << 1)
#define LN_UPDATE_TYPE_FAIL_HTLC            (1 << 2)
#define LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC  (1 << 3)
#define LN_UPDATE_TYPE_FEE                  (1 << 4)


#define LN_UPDATE_TYPE_MASK_FAIL_HTLC       ( \
                                                LN_UPDATE_TYPE_FAIL_HTLC | \
                                                LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC \
                                            )
#define LN_UPDATE_TYPE_MASK_DEL_HTLC        ( \
                                                LN_UPDATE_TYPE_FULFILL_HTLC | \
                                                LN_UPDATE_TYPE_FAIL_HTLC | \
                                                LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC \
                                            )
#define LN_UPDATE_TYPE_MASK_HTLC            ( \
                                                LN_UPDATE_TYPE_ADD_HTLC | \
                                                LN_UPDATE_TYPE_FULFILL_HTLC | \
                                                LN_UPDATE_TYPE_FAIL_HTLC | \
                                                LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC \
                                            )
#define LN_UPDATE_TYPE_MASK_ALL             ( \
                                                LN_UPDATE_TYPE_ADD_HTLC | \
                                                LN_UPDATE_TYPE_FULFILL_HTLC | \
                                                LN_UPDATE_TYPE_FAIL_HTLC | \
                                                LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC | \
                                                LN_UPDATE_TYPE_FEE \
                                            )


#define LN_UPDATE_STATE_FLAG_UP_SEND        (1 << 0)
#define LN_UPDATE_STATE_FLAG_UP_RECV        (1 << 1)
#define LN_UPDATE_STATE_FLAG_CS_SEND        (1 << 2)
#define LN_UPDATE_STATE_FLAG_CS_RECV        (1 << 3)
#define LN_UPDATE_STATE_FLAG_RA_SEND        (1 << 4)
#define LN_UPDATE_STATE_FLAG_RA_RECV        (1 << 5)


#define LN_UPDATE_STATE_OFFERED_WAIT_SEND   (0)
#define LN_UPDATE_STATE_OFFERED_UP_SEND     (LN_UPDATE_STATE_OFFERED_WAIT_SEND | LN_UPDATE_STATE_FLAG_UP_SEND)
#define LN_UPDATE_STATE_OFFERED_CS_SEND     (LN_UPDATE_STATE_OFFERED_UP_SEND | LN_UPDATE_STATE_FLAG_CS_SEND)
#define LN_UPDATE_STATE_OFFERED_RA_RECV     (LN_UPDATE_STATE_OFFERED_CS_SEND | LN_UPDATE_STATE_FLAG_RA_RECV)
#define LN_UPDATE_STATE_OFFERED_CS_RECV     (LN_UPDATE_STATE_OFFERED_RA_RECV | LN_UPDATE_STATE_FLAG_CS_RECV)
#define LN_UPDATE_STATE_OFFERED_RA_SEND     (LN_UPDATE_STATE_OFFERED_CS_RECV | LN_UPDATE_STATE_FLAG_RA_SEND)


#define LN_UPDATE_STATE_RECEIVED_UP_RECV    (LN_UPDATE_STATE_FLAG_UP_RECV)
#define LN_UPDATE_STATE_RECEIVED_CS_RECV    (LN_UPDATE_STATE_RECEIVED_UP_RECV | LN_UPDATE_STATE_FLAG_CS_RECV)
#define LN_UPDATE_STATE_RECEIVED_RA_SEND    (LN_UPDATE_STATE_RECEIVED_CS_RECV | LN_UPDATE_STATE_FLAG_RA_SEND)
#define LN_UPDATE_STATE_RECEIVED_CS_SEND    (LN_UPDATE_STATE_RECEIVED_RA_SEND | LN_UPDATE_STATE_FLAG_CS_SEND)
#define LN_UPDATE_STATE_RECEIVED_RA_RECV    (LN_UPDATE_STATE_RECEIVED_CS_SEND | LN_UPDATE_STATE_FLAG_RA_RECV)


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct     ln_update_t
 *  @brief      update message
 */
typedef struct {
    bool                enabled;                        ///< XXX: Interim. Soon abolished
    uint8_t             type;                           ///<
    uint8_t             state;                          ///<
    uint16_t            type_specific_idx;              ///<
    bool                new_update;                     ///<
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
    utl_buf_t           buf_preimage;                   ///< 32: payment_preimage
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
    uint64_t            neighbor_id;                    ///<
} ln_htlc_t;



/** @struct     ln_fee_update_t
 *  @brief      update fee
 */
typedef struct {
    bool        enabled;
    uint64_t    id;
    uint32_t    feerate_per_kw;
} ln_fee_update_t;


/**************************************************************************
 * macro functions
 **************************************************************************/

#define LN_UPDATE_FLAG_SET(pUpdate, Flag) { \
    (pUpdate)->state |= (Flag); \
    (pUpdate)->new_update = true; \
}
#define LN_UPDATE_FLAG_UNSET(pUpdate, Flag) { /*for debug*/ \
    (pUpdate)->state &= ~(Flag); \
    (pUpdate)->new_update = true; \
}
#define LN_UPDATE_FLAG_IS_SET(pUpdate, Flag) ((pUpdate)->state & (Flag))
#define LN_UPDATE_FLAG_IS_NOT_SET(pUpdate, Flag) (!LN_UPDATE_FLAG_IS_SET(pUpdate, Flag))
#define LN_UPDATE_FLAG_IS_SUBSET_FLAGS(pUpdate, Flags) \
    ( \
        (((pUpdate)->state & (Flags)) == (Flags)) \
    )

    
#define LN_UPDATE_EMPTY(pUpdate) \
    ( \
        (!(pUpdate)->enabled) \
    )
#define LN_UPDATE_USED(pUpdate) (!LN_UPDATE_EMPTY(pUpdate))


#define _LN_UPDATE_LOCAL_UNCOMMITTED(pUpdate) \
    LN_UPDATE_FLAG_IS_NOT_SET((pUpdate), LN_UPDATE_STATE_FLAG_CS_RECV)
#define _LN_UPDATE_REMOTE_UNCOMMITTED(pUpdate) \
    LN_UPDATE_FLAG_IS_NOT_SET((pUpdate), LN_UPDATE_STATE_FLAG_CS_SEND)
#define LN_UPDATE_UNCOMMITTED(pUpdate, bLocal) \
    ( \
        (bLocal) ? \
        _LN_UPDATE_LOCAL_UNCOMMITTED(pUpdate) : \
        _LN_UPDATE_REMOTE_UNCOMMITTED(pUpdate) \
    )


#define LN_UPDATE_IRREVOCABLY_COMMITTED(pUpdate) \
    ( \
        (pUpdate)->state == LN_UPDATE_STATE_OFFERED_RA_SEND || \
        (pUpdate)->state == LN_UPDATE_STATE_RECEIVED_RA_RECV \
    )


//XXX: Private
#define _LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type & Type) && \
        LN_UPDATE_FLAG_IS_SUBSET_FLAGS(pUpdate, LN_UPDATE_STATE_OFFERED_RA_RECV) \
    )
#define _LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type & Type) && \
        LN_UPDATE_FLAG_IS_SUBSET_FLAGS(pUpdate, LN_UPDATE_STATE_RECEIVED_UP_RECV) \
    )
#define _LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type & Type) && \
        LN_UPDATE_FLAG_IS_SUBSET_FLAGS(pUpdate, LN_UPDATE_STATE_RECEIVED_RA_SEND) \
    )
#define _LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, Type) \
    ( \
        ((pUpdate)->type & Type) && \
        LN_UPDATE_FLAG_IS_SUBSET_FLAGS(pUpdate, LN_UPDATE_STATE_OFFERED_UP_SEND) \
    )


#define LN_UPDATE_SEND_ENABLED(pUpdate, Type, bLocal) \
    ( \
        (bLocal) ? \
        _LN_UPDATE_LOCAL_SEND_ENABLED(pUpdate, Type) : \
        _LN_UPDATE_REMOTE_SEND_ENABLED(pUpdate, Type) \
    )
#define LN_UPDATE_RECV_ENABLED(pUpdate, Type, bLocal) \
    ( \
        (bLocal) ? \
        _LN_UPDATE_LOCAL_RECV_ENABLED(pUpdate, Type) : \
        _LN_UPDATE_REMOTE_RECV_ENABLED(pUpdate, Type) \
    )
#define LN_UPDATE_ENABLED(pUpdate, Type, bLocal) \
    ( \
        LN_UPDATE_SEND_ENABLED(pUpdate, Type, bLocal) || \
        LN_UPDATE_RECV_ENABLED(pUpdate, Type, bLocal) \
    )


#define LN_UPDATE_WAIT_SEND(pUpdate) \
    ( \
        ((pUpdate)->state == LN_UPDATE_STATE_OFFERED_WAIT_SEND) \
    )


#define LN_UPDATE_WAIT_SEND_CS(pUpdate) \
    ( \
        ((pUpdate)->state == LN_UPDATE_STATE_OFFERED_UP_SEND) || \
        ((pUpdate)->state == LN_UPDATE_STATE_RECEIVED_RA_SEND) \
    )


//XXX: Deprecated
#define LN_UPDATE_LOCAL_COMSIGING(pUpdate) \
    ( \
        ((pUpdate)->state == LN_UPDATE_STATE_OFFERED_CS_RECV) || \
        ((pUpdate)->state == LN_UPDATE_STATE_RECEIVED_CS_RECV) \
    )
#define LN_UPDATE_REMOTE_COMSIGING(pUpdate) \
    ( \
        ((pUpdate)->state == LN_UPDATE_STATE_OFFERED_CS_SEND) || \
        ((pUpdate)->state == LN_UPDATE_STATE_RECEIVED_CS_SEND) \
    )
#define LN_UPDATE_COMSIGING(pUpdate) \
    ( \
        LN_UPDATE_LOCAL_COMSIGING(pUpdate) || \
        LN_UPDATE_REMOTE_COMSIGING(pUpdate) \
    )


#define LN_UPDATE_REMOTE_ENABLE_ADD_HTLC_RECV(pUpdate) \
    { \
        (pUpdate)->type = LN_UPDATE_TYPE_ADD_HTLC; \
        (pUpdate)->state = LN_UPDATE_STATE_OFFERED_UP_SEND; \
    }


#define LN_UPDATE_TIMEOUT_CHECK_NEEDED(pUpdate) \
    ( \
        ((pUpdate)->type == LN_UPDATE_TYPE_ADD_HTLC) && \
        LN_UPDATE_FLAG_IS_SUBSET_FLAGS(pUpdate, LN_UPDATE_STATE_OFFERED_CS_SEND) \
    )


#define LN_UPDATE_ENABLE_RESEND_UPDATE(pUpdate) \
    { \
        (pUpdate)->state = LN_UPDATE_STATE_OFFERED_WAIT_SEND; \
    }


#define LN_UPDATE_RECEIVED(pUpdate) \
    ( \
        ((pUpdate)->state & LN_UPDATE_STATE_FLAG_UP_RECV) \
    )
#define LN_UPDATE_OFFERED(pUpdate) \
    ( \
        !LN_UPDATE_RECEIVED(pUpdate) \
    )


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


static inline const char *ln_update_state_str(uint8_t state)
{
    switch (state) {
    case LN_UPDATE_STATE_OFFERED_WAIT_SEND: return "OFFERED_WAIT_SEND";
    case LN_UPDATE_STATE_OFFERED_UP_SEND: return "OFFERED_UP_SEND";
    case LN_UPDATE_STATE_OFFERED_CS_SEND: return "OFFERED_CS_SEND";
    case LN_UPDATE_STATE_OFFERED_RA_RECV: return "OFFERED_RA_RECV";
    case LN_UPDATE_STATE_OFFERED_CS_RECV: return "OFFERED_CS_RECV";
    case LN_UPDATE_STATE_OFFERED_RA_SEND: return "OFFERED_RA_SEND";
    case LN_UPDATE_STATE_RECEIVED_UP_RECV: return "RECEIVED_UP_RECV";
    case LN_UPDATE_STATE_RECEIVED_CS_RECV: return "RECEIVED_CS_RECV";
    case LN_UPDATE_STATE_RECEIVED_RA_SEND: return "RECEIVED_RA_SEND";
    case LN_UPDATE_STATE_RECEIVED_CS_SEND: return "RECEIVED_CS_SEND";
    case LN_UPDATE_STATE_RECEIVED_RA_RECV: return "RECEIVED_RA_RECV";
    default: return "UNKNOWN";
    }
}


/********************************************************************
 * prototypes
 ********************************************************************/

ln_update_t *ln_update_get_empty(ln_update_t *pUpdates, uint16_t *pUpdateIdx);


ln_htlc_t *ln_htlc_get_empty(ln_htlc_t *pHtlcs, uint16_t *pHtlcIdx);


ln_fee_update_t *ln_fee_update_get_empty(ln_fee_update_t *pFeeUpdates, uint16_t *pFeeUpdateIdx);


#ifdef LN_DBG_PRINT
void ln_update_print(const ln_update_t *pUpdate);


void ln_update_updates_print(const ln_update_t *pUpdates);
#endif //LN_DBG_PRINT


#endif /* LN_UPDATE_H__ */
