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


static const char *KEYS_STR[LN_FUNDIDX_MAX] = {
    "bp_funding", "bp_revocation", "bp_payment", "bp_delayed", "bp_htlc", "bp_per_commit"
};
static const char *SCR_STR[LN_SCRIPTIDX_MAX] = {
    "remotekey", "delayedkey", "revocationkey", "local_htlckey", "remote_htlckey"
};


/**************************************************************************
 * public functions
 **************************************************************************/

#ifdef UCOIN_USE_PRINTFUNC

void ln_print_wallet(const ln_self_t *self)
{
    fprintf(PRINTOUT, "{\n");
    fprintf(PRINTOUT, M_QQ("node_id") ": \"");
    ucoin_util_dumpbin(PRINTOUT, self->peer_node_id, UCOIN_SZ_PUBKEY, false);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("channel_id") ": \"");
    ucoin_util_dumpbin(PRINTOUT, self->channel_id, LN_SZ_CHANNEL_ID, false);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("short_channel_id") ": " M_QQ("%016" PRIx64) ",\n", self->short_channel_id);
    if (self->htlc_num != 0) {
        fprintf(PRINTOUT, M_QQ("htlc_num") ": %d,", self->htlc_num);
    }
    fprintf(PRINTOUT, M_QQ("our_msat") ": %" PRIu64 ",\n", self->our_msat);
    fprintf(PRINTOUT, M_QQ("their_msat") ": %" PRIu64 "\n", self->their_msat);
    fprintf(PRINTOUT, "}\n");
}


void ln_print_self(const ln_self_t *self)
{
    fprintf(PRINTOUT, "{\n");

    //peer_node
    fprintf(PRINTOUT, M_QQ("peer_node_id") ": \"");
    ucoin_util_dumpbin(PRINTOUT, self->peer_node_id, UCOIN_SZ_PUBKEY, false);
    fprintf(PRINTOUT, "\",");

    //key storage
    fprintf(PRINTOUT, M_QQ("storage_index") ": " M_QQ("%016" PRIx64) ",\n", self->storage_index);
    fprintf(PRINTOUT, M_QQ("storage_seed") ": \"");
    ucoin_util_dumpbin(PRINTOUT, self->storage_seed, UCOIN_SZ_PRIVKEY, false);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("peer_storage_index") ": " M_QQ("%016" PRIx64) ",\n", self->peer_storage_index);

    //funding
    fprintf(PRINTOUT, M_QQ("fund_flag") ": " M_QQ("%02x") ",", self->fund_flag);
    fprintf(PRINTOUT, M_QQ("funding_local") ": {\n");
    fprintf(PRINTOUT, M_QQ("funding_txid") ": \"");
    ucoin_util_dumptxid(PRINTOUT, self->funding_local.txid);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("funding_txindex") ": %d,\n", self->funding_local.txindex);
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        fprintf(PRINTOUT, M_QQ("%s") ": ", KEYS_STR[lp]);
        fprintf(PRINTOUT, "{");
        fprintf(PRINTOUT, M_QQ("priv") ": \"");
        ucoin_util_dumpbin(PRINTOUT, self->funding_local.keys[lp].priv, UCOIN_SZ_PRIVKEY, false);
        fprintf(PRINTOUT, "\",");
        fprintf(PRINTOUT, M_QQ("pub") ": \"");
        ucoin_util_dumpbin(PRINTOUT, self->funding_local.keys[lp].pub, UCOIN_SZ_PUBKEY, false);
        fprintf(PRINTOUT, "\"},\n");
    }
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        fprintf(PRINTOUT, M_QQ("%s") ": ", SCR_STR[lp]);
        fprintf(PRINTOUT, "{");
        fprintf(PRINTOUT, M_QQ("pub") ": \"");
        ucoin_util_dumpbin(PRINTOUT, self->funding_local.scriptpubkeys[lp], UCOIN_SZ_PUBKEY, false);
        if (lp != LN_SCRIPTIDX_MAX - 1) {
            fprintf(PRINTOUT, "\"},\n");
        } else {
            fprintf(PRINTOUT, "\"}\n");
        }
    }
    fprintf(PRINTOUT, "},\n");
    fprintf(PRINTOUT, M_QQ("funding_remote") ": {\n");
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        fprintf(PRINTOUT, M_QQ("%s") ": ", KEYS_STR[lp]);
        fprintf(PRINTOUT, "{");
        fprintf(PRINTOUT, M_QQ("pub") ": \"");
        ucoin_util_dumpbin(PRINTOUT, self->funding_remote.pubkeys[lp], UCOIN_SZ_PUBKEY, false);
        fprintf(PRINTOUT, "\"},\n");
    }
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        fprintf(PRINTOUT, M_QQ("%s") ": ", SCR_STR[lp]);
        fprintf(PRINTOUT, "{");
        fprintf(PRINTOUT, M_QQ("pub") ": \"");
        ucoin_util_dumpbin(PRINTOUT, self->funding_remote.scriptpubkeys[lp], UCOIN_SZ_PUBKEY, false);
        if (lp != LN_SCRIPTIDX_MAX - 1) {
            fprintf(PRINTOUT, "\"},\n");
        } else {
            fprintf(PRINTOUT, "\"}\n");
        }
    }
    fprintf(PRINTOUT, "},\n");
    fprintf(PRINTOUT, M_QQ("obscured") ": " M_QQ("%016" PRIx64) ",\n", self->obscured);
    fprintf(PRINTOUT, M_QQ("redeem_fund") ": \"");
    ucoin_util_dumpbin(PRINTOUT, self->redeem_fund.buf, self->redeem_fund.len, false);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("key_fund_sort") ": " M_QQ("%s") ",\n", (self->key_fund_sort == UCOIN_KEYS_SORT_ASC) ? "first" : "second");
    fprintf(PRINTOUT, M_QQ("flck_flag") ": " M_QQ("%02x") ",\n", self->flck_flag);

    //announce
    fprintf(PRINTOUT, M_QQ("anno_flag") ": " M_QQ("%02x") ",\n", self->anno_flag);
    fprintf(PRINTOUT, M_QQ("cltv_expiry_delta") ": %" PRIu16 ",\n", self->anno_prm.cltv_expiry_delta);
    fprintf(PRINTOUT, M_QQ("htlc_minimum_msat") ": %" PRIu64 ",\n", self->anno_prm.htlc_minimum_msat);
    fprintf(PRINTOUT, M_QQ("fee_base_msat") ": %" PRIu32 ",\n", self->anno_prm.fee_base_msat);
    fprintf(PRINTOUT, M_QQ("fee_prop_millionths") ": %" PRIu32 ",\n", self->anno_prm.fee_prop_millionths);

    //init
    fprintf(PRINTOUT, M_QQ("init_flag") ": " M_QQ("%02x") ",\n", self->init_flag);
    fprintf(PRINTOUT, M_QQ("lfeature_remote") ": " M_QQ("%02x") ",\n", self->lfeature_remote);

    //close
    fprintf(PRINTOUT, M_QQ("close_fee_sat") ": %" PRIu64 ",\n", self->close_fee_sat);

    //normal operation
    fprintf(PRINTOUT, M_QQ("htlc_num") ": %d,\n", self->htlc_num);
    fprintf(PRINTOUT, M_QQ("commit_num") ": %" PRIu64 ",\n", self->commit_num);
    fprintf(PRINTOUT, M_QQ("revoke_num") ": %" PRIu64 ",\n", self->revoke_num);
    fprintf(PRINTOUT, M_QQ("remote_commit_num") ": %" PRIu64 ",\n", self->remote_commit_num);
    fprintf(PRINTOUT, M_QQ("remote_revoke_num") ": %" PRIu64 ",\n", self->remote_revoke_num);
    fprintf(PRINTOUT, M_QQ("htlc_id_num") ": %" PRIu64 ",\n", self->htlc_id_num);
    fprintf(PRINTOUT, M_QQ("our_msat") ": %" PRIu64 ",\n", self->our_msat);
    fprintf(PRINTOUT, M_QQ("their_msat") ": %" PRIu64 ",\n", self->their_msat);
    fprintf(PRINTOUT, M_QQ("channel_id") ": \"");
    ucoin_util_dumpbin(PRINTOUT, self->channel_id, LN_SZ_CHANNEL_ID, false);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("short_channel_id") ": " M_QQ("%016" PRIx64) ",\n", self->short_channel_id);

    //ping pong
    fprintf(PRINTOUT, M_QQ("missing_pong_cnt") ": %d,\n", self->missing_pong_cnt);

    fprintf(PRINTOUT, M_QQ("htlc") ": [");
    bool cont = false;
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        if (self->cnl_add_htlc[idx].amount_msat > 0) {
            if (cont) {
                fprintf(PRINTOUT, ",\n");
            }
            fprintf(PRINTOUT, "{");
            fprintf(PRINTOUT, M_QQ("id") ": %" PRIu64 ",\n", self->cnl_add_htlc[idx].id);
            fprintf(PRINTOUT, M_QQ("amount_msat") ": %" PRIu64 ",\n", self->cnl_add_htlc[idx].amount_msat);
            fprintf(PRINTOUT, M_QQ("cltv_expiry") ": %" PRIu32 ",\n", self->cnl_add_htlc[idx].cltv_expiry);
            fprintf(PRINTOUT, M_QQ("payment-hash") ": \"");
            ucoin_util_dumpbin(PRINTOUT, self->cnl_add_htlc[idx].payment_sha256, UCOIN_SZ_SHA256, false);
            fprintf(PRINTOUT, "\",\n");
            fprintf(PRINTOUT, M_QQ("flag") ": " M_QQ("%02x") ",\n", self->cnl_add_htlc[idx].flag);
            fprintf(PRINTOUT, M_QQ("shared_secret_len") ": %d,\n", self->cnl_add_htlc[idx].shared_secret.len);
            fprintf(PRINTOUT, M_QQ("prev_short_channel_id") ": " M_QQ("%016" PRIx64) "\n", self->cnl_add_htlc[idx].prev_short_channel_id);
            fprintf(PRINTOUT, "}\n");
            cont = true;
        }
    }
    fprintf(PRINTOUT, "],\n");

    fprintf(PRINTOUT, M_QQ("commit_local") ": {\n");
    fprintf(PRINTOUT, M_QQ("accept_htlcs") ": %" PRIu32 ",\n", self->commit_local.accept_htlcs);
    fprintf(PRINTOUT, M_QQ("to_self_delay") ": %" PRIu32 ",\n", self->commit_local.to_self_delay);
    fprintf(PRINTOUT, M_QQ("minimum_msat") ": %" PRIu64 ",\n", self->commit_local.minimum_msat);
    fprintf(PRINTOUT, M_QQ("in_flight_msat") ": %" PRIu64 ",\n", self->commit_local.in_flight_msat);
    fprintf(PRINTOUT, M_QQ("dust_limit_sat") ": %" PRIu64 ",\n", self->commit_local.dust_limit_sat);
    fprintf(PRINTOUT, M_QQ("commit_txid") ": \"");
    ucoin_util_dumptxid(PRINTOUT, self->commit_local.txid);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("htlc_num") ": %" PRIu32 "\n", self->commit_local.htlc_num);

    fprintf(PRINTOUT, "},\n");

    fprintf(PRINTOUT, M_QQ("commit_remote") ": {\n");
    fprintf(PRINTOUT, M_QQ("accept_htlcs") ": %" PRIu32 ",\n", self->commit_remote.accept_htlcs);
    fprintf(PRINTOUT, M_QQ("to_self_delay") ": %" PRIu32 ",\n", self->commit_remote.to_self_delay);
    fprintf(PRINTOUT, M_QQ("minimum_msat")  ":%" PRIu64 ",\n", self->commit_remote.minimum_msat);
    fprintf(PRINTOUT, M_QQ("in_flight_msat") ": %" PRIu64 ",\n", self->commit_remote.in_flight_msat);
    fprintf(PRINTOUT, M_QQ("dust_limit_sat") ": %" PRIu64 ",\n", self->commit_remote.dust_limit_sat);
    fprintf(PRINTOUT, M_QQ("commit_txid") ": \"");
    ucoin_util_dumptxid(PRINTOUT, self->commit_remote.txid);
    fprintf(PRINTOUT, "\",\n");
    fprintf(PRINTOUT, M_QQ("htlc_num") ": %" PRIu32 "\n", self->commit_remote.htlc_num);
    fprintf(PRINTOUT, "},\n");

    fprintf(PRINTOUT, M_QQ("funding_sat") ": %" PRIu64 ",\n", self->funding_sat);
    fprintf(PRINTOUT, M_QQ("feerate_per_kw") ": %" PRIu32 ",\n", self->feerate_per_kw);

    fprintf(PRINTOUT, M_QQ("err") ": %d\n", self->err);

    fprintf(PRINTOUT, "}\n");
}


/** [showdb用]
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
            msg.p_key = NULL;
            ln_msg_cnl_update_read(&msg, pData, Len);
            ln_msg_cnl_update_print(&msg);
        }
        break;
    }
}


/** [showdb用]
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
            ann.p_key = NULL;
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


void ln_print_node(const ln_node_t *node)
{
    printf("=NODE=============================================\n");
    // printf("node_key: ");
    // ucoin_util_dumpbin(PRINTOUT, node->keys.priv, UCOIN_SZ_PRIVKEY, true);
    printf("node_id: ");
    ucoin_util_dumpbin(PRINTOUT, node->keys.pub, UCOIN_SZ_PUBKEY, true);
    printf("features= %02x\n", node->features);
    printf("alias= %s\n", node->alias);
    printf("addr.type=%d\n", node->addr.type);
    if (node->addr.type == LN_NODEDESC_IPV4) {
        printf("ipv4=%d.%d.%d.%d:%d\n",
                node->addr.addrinfo.ipv4.addr[0],
                node->addr.addrinfo.ipv4.addr[1],
                node->addr.addrinfo.ipv4.addr[2],
                node->addr.addrinfo.ipv4.addr[3],
                node->addr.port);
    } else {
        printf("port=%d\n", node->addr.port);
    }
    printf("=============================================\n\n\n");
}


void ln_print_keys(FILE *fp, const ln_funding_local_data_t *pLocal, const ln_funding_remote_data_t *pRemote)
{
#ifdef M_DBG_VERBOSE
#ifdef UCOIN_DEBUG
    fprintf(fp, "-[local]-------------------------------\n");
    fprintf(fp, "funding_txid: ");
    ucoin_util_dumptxid(fp, pLocal->txid);
    fprintf(fp, "\n");
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        fprintf(fp, "%s pri: ", KEYS_STR[lp]);
        ucoin_util_dumpbin(fp, pLocal->keys[lp].priv, UCOIN_SZ_PRIVKEY, true);
        fprintf(fp, "%s pub: ", KEYS_STR[lp]);
        ucoin_util_dumpbin(fp, pLocal->keys[lp].pub, UCOIN_SZ_PUBKEY, true);
    }
    fprintf(fp, "\n");
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        fprintf(fp, "%s pub: ", SCR_STR[lp]);
        ucoin_util_dumpbin(fp, pLocal->scriptpubkeys[lp], UCOIN_SZ_PUBKEY, true);
    }

    fprintf(fp, "\n-[remote]---------------------------------------\n");
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        fprintf(fp, "%s pub: ", KEYS_STR[lp]);
        ucoin_util_dumpbin(fp, pRemote->pubkeys[lp], UCOIN_SZ_PUBKEY, true);
    }
    fprintf(fp, "\n");
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        fprintf(fp, "%s pub: ", SCR_STR[lp]);
        ucoin_util_dumpbin(fp, pRemote->scriptpubkeys[lp], UCOIN_SZ_PUBKEY, true);
    }
    fprintf(fp, "prev_percommit: ");
    ucoin_util_dumpbin(fp, pRemote->prev_percommit, UCOIN_SZ_PUBKEY, true);
    fprintf(fp, "----------------------------------------\n");
#endif
#else
    (void)fp; (void)pLocal; (void)pRemote;
#endif  //M_DBG_VERBOSE
}

#endif  //UCOIN_USE_PRINTFUNC
