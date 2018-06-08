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
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "ln_db.h"
#include "ln/ln_misc.h"
#include "ln/ln_msg_anno.h"
#include "ln/ln_node.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value

#ifdef UCOIN_USE_PRINTFUNC
static const char *KEYS_STR[LN_FUNDIDX_MAX] = {
    "bp_funding", "bp_revocation", "bp_payment", "bp_delayed", "bp_htlc", "bp_per_commit"
};
static const char *SCR_STR[LN_SCRIPTIDX_MAX] = {
    "remotekey", "delayedkey", "revocationkey", "local_htlckey", "remote_htlckey"
};
#endif  //UCOIN_USE_PRINTFUNC


/**************************************************************************
 * public functions
 **************************************************************************/

#ifdef UCOIN_USE_PRINTFUNC

/** [showdb/routing用]
 *
 *
 */
void ln_print_announce(const uint8_t *pData, uint16_t Len)
{
    uint16_t type = ln_misc_get16be(pData);

    switch (type) {
    case MSGTYPE_CHANNEL_ANNOUNCEMENT:
        ln_msg_cnl_announce_print(pData, Len);
        break;
    case MSGTYPE_NODE_ANNOUNCEMENT:
        {
            ln_node_announce_t msg;
            uint8_t node_pub[UCOIN_SZ_PUBKEY];
            char node_alias[LN_SZ_ALIAS + 1];
            msg.p_node_id = node_pub;
            msg.p_alias = node_alias;
            ln_msg_node_announce_read(&msg, pData, Len);
        }
        break;
    case MSGTYPE_CHANNEL_UPDATE:
        {
            ln_cnl_update_t msg;
            ln_msg_cnl_update_read(&msg, pData, Len);
            ln_msg_cnl_update_print(&msg);
        }
        break;
    }
}


/** [showdb/routing用]
 *
 *
 */
void ln_print_announce_short(const uint8_t *pData, uint16_t Len)
{
    uint16_t type = ln_misc_get16be(pData);

    fprintf(PRINTOUT, "{\n");
    switch (type) {
    case MSGTYPE_CHANNEL_ANNOUNCEMENT:
        {
            ln_cnl_announce_read_t ann;

            bool ret = ln_msg_cnl_announce_read(&ann, pData, Len);
            if (ret) {
                fprintf(PRINTOUT, M_QQ("type") ": " M_QQ("channel_announcement") ",\n");
                fprintf(PRINTOUT, M_QQ("short_channel_id") ": " M_QQ("%016" PRIx64) ",\n", ann.short_channel_id);
                fprintf(PRINTOUT, M_QQ("node1") ": \"");
                ucoin_util_dumpbin(PRINTOUT, ann.node_id1, UCOIN_SZ_PUBKEY, false);
                fprintf(PRINTOUT, "\",\n");
                fprintf(PRINTOUT, M_QQ("node2") ": \"");
                ucoin_util_dumpbin(PRINTOUT, ann.node_id2, UCOIN_SZ_PUBKEY, false);
                fprintf(PRINTOUT, "\"");
            }
        }
        break;
    case MSGTYPE_NODE_ANNOUNCEMENT:
        {
            ln_node_announce_t msg;
            uint8_t node_pub[UCOIN_SZ_PUBKEY];
            char node_alias[LN_SZ_ALIAS + 1];
            msg.p_node_id = node_pub;
            msg.p_alias = node_alias;
            bool ret = ln_msg_node_announce_read(&msg, pData, Len);
            if (ret) {
                fprintf(PRINTOUT, M_QQ("node") ": \"");
                ucoin_util_dumpbin(PRINTOUT, node_pub, UCOIN_SZ_PUBKEY, false);
                fprintf(PRINTOUT, "\",\n");
                fprintf(PRINTOUT, M_QQ("alias") ": " M_QQ("%s") ",\n", node_alias);
                fprintf(PRINTOUT, M_QQ("rgbcolor") ": \"#%02x%02x%02x\",\n", msg.rgbcolor[0], msg.rgbcolor[1], msg.rgbcolor[2]);
                if (msg.addr.type == LN_NODEDESC_IPV4) {
                    fprintf(PRINTOUT, M_QQ("addr") ": " M_QQ("%d.%d.%d.%d:%d") ",\n",
                            msg.addr.addrinfo.ipv4.addr[0],
                            msg.addr.addrinfo.ipv4.addr[1],
                            msg.addr.addrinfo.ipv4.addr[2],
                            msg.addr.addrinfo.ipv4.addr[3],
                            msg.addr.port);
                } else {
                    fprintf(PRINTOUT, M_QQ("addrtype") ": %d,\n", msg.addr.type);
                }
                fprintf(PRINTOUT, M_QQ("timestamp") ": %" PRIu32 "\n", msg.timestamp);
            }
        }
        break;
    case MSGTYPE_CHANNEL_UPDATE:
        {
            ln_cnl_update_t ann;
            bool ret = ln_msg_cnl_update_read(&ann, pData, Len);
            if (ret) {
                fprintf(PRINTOUT, M_QQ("type") ": " M_QQ("channel_update %s") ",\n", (ann.flags & 1) ? "2" : "1");
                fprintf(PRINTOUT, M_QQ("short_channel_id") ": " M_QQ("%016" PRIx64) ",\n", ann.short_channel_id);
                //fprintf(PRINTOUT, M_QQ("node_sort") ": " M_QQ("%s") ",\n", (ann.flags & 1) ? "second" : "first");
                fprintf(PRINTOUT, M_QQ("flags") ": " M_QQ("%04x") ",\n", ann.flags);
                fprintf(PRINTOUT, M_QQ("cltv_expiry_delta") ": %d,\n", ann.cltv_expiry_delta);
                fprintf(PRINTOUT, M_QQ("htlc_minimum_msat") ": %" PRIu64 ",\n", ann.htlc_minimum_msat);
                fprintf(PRINTOUT, M_QQ("fee_base_msat") ": %" PRIu32 ",\n", ann.fee_base_msat);
                fprintf(PRINTOUT, M_QQ("fee_prop_millionths") ": %" PRIu32 ",\n", ann.fee_prop_millionths);
                fprintf(PRINTOUT, M_QQ("timestamp") ": %" PRIu32 "\n", ann.timestamp);
            }
        }
        break;
    }
    fprintf(PRINTOUT, "}\n");
}


void ln_print_peerconf(FILE *fp, const uint8_t *pData, uint16_t Len)
{
    uint16_t type = ln_misc_get16be(pData);

    if (type == MSGTYPE_NODE_ANNOUNCEMENT) {
        ln_node_announce_t msg;
        uint8_t node_pub[UCOIN_SZ_PUBKEY];
        char node_alias[LN_SZ_ALIAS + 1];
        msg.p_node_id = node_pub;
        msg.p_alias = node_alias;
        bool ret = ln_msg_node_announce_read(&msg, pData, Len);
        if (ret) {
            if (msg.addr.type == LN_NODEDESC_IPV4) {
                fprintf(fp, "ipaddr=%d.%d.%d.%d\n",
                        msg.addr.addrinfo.ipv4.addr[0],
                        msg.addr.addrinfo.ipv4.addr[1],
                        msg.addr.addrinfo.ipv4.addr[2],
                        msg.addr.addrinfo.ipv4.addr[3]);
            } else {
                fprintf(fp, "ipaddr=127.0.0.1\n");
            }
            fprintf(fp, "port=%d\n", msg.addr.port);
            fprintf(fp, "node_id=");
            ucoin_util_dumpbin(fp, node_pub, UCOIN_SZ_PUBKEY, true);
        }
    }

}


void ln_print_keys(const ln_funding_local_data_t *pLocal, const ln_funding_remote_data_t *pRemote)
{
//#ifdef M_DBG_VERBOSE
#ifdef UCOIN_DEBUG
    LOGD("local keys\n");
    LOGD("  funding_txid: ");
    TXIDD(pLocal->txid);
    LOGD("  funding_txindex: %" PRIu16 "\n", pLocal->txindex);

    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        LOGD("    %s: ", KEYS_STR[lp]);
        DUMPD(pLocal->pubkeys[lp], UCOIN_SZ_PUBKEY);
    }
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        LOGD("    %s: ", SCR_STR[lp]);
        DUMPD(pLocal->scriptpubkeys[lp], UCOIN_SZ_PUBKEY);
    }

    LOGD("remote keys\n");
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        LOGD("    %s: ", KEYS_STR[lp]);
        DUMPD(pRemote->pubkeys[lp], UCOIN_SZ_PUBKEY);
    }
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        LOGD("    %s: ", SCR_STR[lp]);
        DUMPD(pRemote->scriptpubkeys[lp], UCOIN_SZ_PUBKEY);
    }
    LOGD("prev_percommit: ");
    DUMPD(pRemote->prev_percommit, UCOIN_SZ_PUBKEY);
#endif
//#else
//    (void)fp; (void)pLocal; (void)pRemote;
//#endif  //M_DBG_VERBOSE
}

#endif  //UCOIN_USE_PRINTFUNC
