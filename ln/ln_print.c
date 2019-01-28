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


void ln_print_keys(ln_self_t *self)
{
    ln_derkey_pubkeys_t         *p_local_pubkeys = &self->funding_local.pubkeys;
    ln_derkey_pubkeys_t         *p_remote_pubkeys = &self->funding_remote.pubkeys;
    ln_derkey_script_pubkeys_t  *p_local_script_pubkeys = &self->commit_local.script_pubkeys;
    ln_derkey_script_pubkeys_t  *p_remote_script_pubkeys = &self->commit_remote.script_pubkeys;

//#ifdef M_DBG_VERBOSE
#ifdef PTARM_DEBUG
    LOGD("  funding_txid: ");
    TXIDD(ln_funding_txid(self));
    LOGD("  funding_txindex: %" PRIu16 "\n", ln_funding_txindex(self));

    int lp;
    for (lp = 0; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        LOGD("    %s: ", KEYS_STR[lp]);
        DUMPD(p_local_pubkeys->basepoints[lp], BTC_SZ_PUBKEY);
    }
    LOGD("    %s: ", KEYS_STR[lp]);
    DUMPD(p_local_pubkeys->per_commitment_point, BTC_SZ_PUBKEY);

    for (lp = 0; lp < LN_SCRIPT_IDX_NUM; lp++) {
        LOGD("    %s: ", SCR_STR[lp]);
        DUMPD(p_local_script_pubkeys->keys[lp], BTC_SZ_PUBKEY);
    }

    for (lp = 0; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        LOGD("    %s: ", KEYS_STR[lp]);
        DUMPD(p_remote_pubkeys->basepoints[lp], BTC_SZ_PUBKEY);
    }
    LOGD("    %s: ", KEYS_STR[lp]);
    DUMPD(p_remote_pubkeys->per_commitment_point, BTC_SZ_PUBKEY);

    for (lp = 0; lp < LN_SCRIPT_IDX_NUM; lp++) {
        LOGD("    %s: ", SCR_STR[lp]);
        DUMPD(p_remote_script_pubkeys->keys[lp], BTC_SZ_PUBKEY);
    }

    LOGD("prev_percommit: ");
    DUMPD(self->funding_remote.pubkeys.prev_per_commitment_point, BTC_SZ_PUBKEY);
#endif
//#else
//    (void)fp; (void)pLocal; (void)pRemote;
//#endif  //M_DBG_VERBOSE
}

#endif  //PTARM_USE_PRINTFUNC
