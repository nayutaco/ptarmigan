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
/** @file   ln_print.c
 *  @brief  デバッグ情報
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "utl_dbg.h"
#include "utl_int.h"

#include "btc_crypto.h"

#include "ln_db.h"
#include "ln_msg_anno.h"
#include "ln_node.h"
#include "ln_local.h"
#include "ln_msg.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value

#ifdef PTARM_USE_PRINTFUNC
static const char *KEYS_STR[LN_BASEPOINT_IDX_NUM + 1] = {
    "bp_funding", "bp_revocation", "bp_payment", "bp_delayed", "bp_htlc", "bp_per_commit"
};
static const char *SCR_STR[LN_SCRIPT_IDX_NUM] = {
    "remotekey", "delayedkey", "revocationkey", "local_htlckey", "remote_htlckey"
};
#endif  //PTARM_USE_PRINTFUNC


/**************************************************************************
 * public functions
 **************************************************************************/

#ifdef PTARM_USE_PRINTFUNC

/** [showdb/routing用]
 *
 *
 */
void ln_print_announce(const uint8_t *pData, uint16_t Len)
{
    uint16_t type = utl_int_pack_u16be(pData);

    switch (type) {
    case MSGTYPE_CHANNEL_ANNOUNCEMENT:
        ln_msg_channel_announcement_print(pData, Len);
        break;
    case MSGTYPE_NODE_ANNOUNCEMENT:
        ln_msg_node_announcement_print_2(pData, Len);
        break;
    case MSGTYPE_CHANNEL_UPDATE:
        ln_msg_channel_update_print(pData, Len);
        break;
    }
}


void ln_print_keys(ln_channel_t *pChannel)
{
    ln_derkey_local_keys_t          *p_local_keys = &pChannel->keys_local;
    ln_derkey_remote_keys_t         *p_remote_keys = &pChannel->keys_remote;

//#ifdef M_DBG_VERBOSE
#ifdef PTARM_DEBUG
    LOGD("  funding_txid: ");
    TXIDD(ln_funding_txid(pChannel));
    LOGD("  funding_txindex: %" PRIu16 "\n", ln_funding_txindex(pChannel));

    int lp;
    for (lp = 0; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        LOGD("    %s: ", KEYS_STR[lp]);
        DUMPD(p_local_keys->basepoints[lp], BTC_SZ_PUBKEY);
    }
    LOGD("    %s: ", KEYS_STR[lp]);
    DUMPD(p_local_keys->per_commitment_point, BTC_SZ_PUBKEY);

    for (lp = 0; lp < LN_SCRIPT_IDX_NUM; lp++) {
        LOGD("    %s: ", SCR_STR[lp]);
        DUMPD(p_local_keys->script_pubkeys[lp], BTC_SZ_PUBKEY);
    }

    for (lp = 0; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        LOGD("    %s: ", KEYS_STR[lp]);
        DUMPD(p_remote_keys->basepoints[lp], BTC_SZ_PUBKEY);
    }
    LOGD("    %s: ", KEYS_STR[lp]);
    DUMPD(p_remote_keys->per_commitment_point, BTC_SZ_PUBKEY);

    for (lp = 0; lp < LN_SCRIPT_IDX_NUM; lp++) {
        LOGD("    %s: ", SCR_STR[lp]);
        DUMPD(p_remote_keys->script_pubkeys[lp], BTC_SZ_PUBKEY);
    }

    LOGD("prev_percommit: ");
    DUMPD(pChannel->keys_remote.prev_per_commitment_point, BTC_SZ_PUBKEY);
#endif
//#else
//    (void)fp; (void)pLocal; (void)pRemote;
//#endif  //M_DBG_VERBOSE
}

#endif  //PTARM_USE_PRINTFUNC
