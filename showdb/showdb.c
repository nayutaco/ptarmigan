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
/** @file   showdb.c
 *  @brief  DB閲覧
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <assert.h>

#include "ptarmd.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"

#define M_SPOIL_STDERR


/********************************************************************
 * macros
 ********************************************************************/

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value

#define SHOW_SELF               (0x0001)
#define SHOW_WALLET             (0x0002)
#define SHOW_ANNOCNL            (0x0004)
#define SHOW_DEBUG              (0x0008)
#define SHOW_ANNONODE           (0x0010)
#define SHOW_LISTCH             (0x0020)
#define SHOW_ANNOINFO           (0x0040)
#define SHOW_VERSION            (0x0080)
#define SHOW_PREIMAGE           (0x0100)
#define SHOW_ROUTESKIP          (0x0200)
#define SHOW_INVOICE            (0x0400)
#define SHOW_CLOSED_CH          (0x0800)

#define M_SZ_ANNOINFO_CNL       (sizeof(uint64_t) + 1)
#define M_SZ_ANNOINFO_NODE      (BTC_SZ_PUBKEY)

//BOLT message
#define MSGTYPE_CHANNEL_ANNOUNCEMENT        ((uint16_t)0x0100)
#define MSGTYPE_NODE_ANNOUNCEMENT           ((uint16_t)0x0101)
#define MSGTYPE_CHANNEL_UPDATE              ((uint16_t)0x0102)
#define MSGTYPE_ANNOUNCEMENT_SIGNATURES     ((uint16_t)0x0103)


#define INDENT1                 "  "
#define INDENT2                 "    "
#define INDENT3                 "      "
#define INDENT4                 "        "
#define INDENT5                 "          "


/********************************************************************
 * prototypes
 ********************************************************************/

#ifdef PTARM_USE_PRINTFUNC
void ln_print_announce(const uint8_t *pData, uint16_t Len);
#else
#define ln_print_announce(...)          //nothing
#endif  //PTARM_USE_PRINTFUNC
void ln_print_peerconf(FILE *fp, const uint8_t *pData, uint16_t Len);
void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_node, MDB_env *p_anno);

bool ln_msg_cnl_announce_read(ln_cnl_announce_read_t *pMsg, const uint8_t *pData, uint16_t Len);
bool ln_msg_node_announce_read(ln_node_announce_t *pMsg, const uint8_t *pData, uint16_t Len);
bool ln_msg_cnl_update_read(ln_cnl_update_t *pMsg, const uint8_t *pData, uint16_t Len);


/********************************************************************
 * static variables
 ********************************************************************/

static uint16_t     showflag;
static int          cnt0;
static int          cnt1;
static int          cnt2;
static int          cnt4;
static int          cnt5;
static MDB_env      *mpDbSelf = NULL;
static MDB_env      *mpDbNode = NULL;
static MDB_env      *mpDbAnno = NULL;
static FILE         *fp_err;


static const char *KEYS_STR[LN_FUNDIDX_MAX] = {
    "bp_funding", "bp_revocation", "bp_payment", "bp_delayed", "bp_htlc", "bp_per_commit"
};
static const char *SCR_STR[LN_SCRIPTIDX_MAX] = {
    "remotekey", "delayedkey", "revocationkey", "local_htlckey", "remote_htlckey"
};


/********************************************************************
 * functions
 ********************************************************************/

static void ln_print_wallet(const ln_self_t *self)
{
    printf(INDENT2 "{\n");
    printf(INDENT3 M_QQ("node_id") ": \"");
    btc_util_dumpbin(stdout, self->peer_node_id, BTC_SZ_PUBKEY, false);
    printf("\",\n");
    printf(INDENT3 M_QQ("channel_id") ": \"");
    btc_util_dumpbin(stdout, self->channel_id, LN_SZ_CHANNEL_ID, false);
    printf("\",\n");
    printf(INDENT3 M_QQ("short_channel_id") ": " M_QQ("0x%016" PRIx64) ",\n", self->short_channel_id);
    if (self->htlc_num != 0) {
        printf(INDENT3 M_QQ("htlc_num") ": %d,\n", self->htlc_num);
    }
    printf(INDENT3 M_QQ("our_msat") ": %" PRIu64 ",\n", self->our_msat);
    printf(INDENT3 M_QQ("their_msat") ": %" PRIu64 "\n", self->their_msat);
    printf(INDENT2 "}");
}

static void ln_print_self(const ln_self_t *self)
{
    printf(INDENT2 "{\n");

    //peer_node
    printf(INDENT3 M_QQ("peer_node_id") ": \"");
    btc_util_dumpbin(stdout, self->peer_node_id, BTC_SZ_PUBKEY, false);
    printf("\",\n");

    //status
    printf(INDENT3 M_QQ("status") ": " M_QQ("0x%02x") ",\n", self->status);

    //key storage
    printf(INDENT3 M_QQ("storage_index") ": " M_QQ("0x%016" PRIx64) ",\n", self->priv_data.storage_index);
    // printf(M_QQ("storage_seed") ": \"");
    // btc_util_dumpbin(stdout, self->priv_data.storage_seed, BTC_SZ_PRIVKEY, false);
    // printf("\",\n");
    printf(INDENT3 M_QQ("peer_storage_index") ": " M_QQ("0x%016" PRIx64) ",\n", self->peer_storage_index);

    //funding
    printf(INDENT3 M_QQ("fund_flag") ": " M_QQ("0x%02x") ",\n", self->fund_flag);
    printf(INDENT3 M_QQ("funding_local") ": {\n");
    printf(INDENT4 M_QQ("funding_txid") ": \"");
    btc_util_dumptxid(stdout, self->funding_local.txid);
    printf("\",\n");
    printf(INDENT4 M_QQ("funding_txindex") ": %d,\n", self->funding_local.txindex);
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        printf(INDENT4 M_QQ("%s") ": {\n", KEYS_STR[lp]);
        // printf(INDENT4 M_QQ("priv") ": \"");
        // btc_util_dumpbin(stdout, self->funding_local.keys[lp].priv, BTC_SZ_PRIVKEY, false);
        // printf("\",");
        printf(INDENT5 M_QQ("pub") ": \"");
        btc_util_dumpbin(stdout, self->funding_local.pubkeys[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "},\n");
    }
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        if (lp != 0) {
            printf(",\n");
        }
        printf(INDENT4 M_QQ("%s") ": {\n", SCR_STR[lp]);
        printf(INDENT5 M_QQ("pub") ": \"");
        btc_util_dumpbin(stdout, self->funding_local.scriptpubkeys[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "}");
    }
    printf("\n");
    printf(INDENT3 "},\n");

    printf(INDENT3 M_QQ("funding_remote") ": {\n");
    for (int lp = 0; lp < LN_FUNDIDX_MAX; lp++) {
        printf(INDENT4 M_QQ("%s") ": {\n", KEYS_STR[lp]);
        printf(INDENT5 M_QQ("pub") ": \"");
        btc_util_dumpbin(stdout, self->funding_remote.pubkeys[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "},\n");
    }
    printf(INDENT4 M_QQ("%s") ": \"", "prev_percommit");
    btc_util_dumpbin(stdout, self->funding_remote.prev_percommit, BTC_SZ_PUBKEY, false);
    printf("\",\n");
    for (int lp = 0; lp < LN_SCRIPTIDX_MAX; lp++) {
        if (lp != 0) {
            printf(",\n");
        }
        printf(INDENT4 M_QQ("%s") ": {\n", SCR_STR[lp]);
        printf(INDENT5 M_QQ("pub") ": \"");
        btc_util_dumpbin(stdout, self->funding_remote.scriptpubkeys[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "}");
    }
    printf("\n");
    printf(INDENT3 "},\n");
    printf(INDENT3 M_QQ("obscured") ": " M_QQ("0x%016" PRIx64) ",\n", self->obscured);
    // printf(INDENT3 M_QQ("redeem_fund") ": \"");
    // btc_util_dumpbin(stdout, self->redeem_fund.buf, self->redeem_fund.len, false);
    // printf("\",\n");
    printf(INDENT3 M_QQ("key_fund_sort") ": " M_QQ("%s") ",\n", (self->key_fund_sort == BTC_KEYS_SORT_ASC) ? "first" : "second");
    printf(INDENT3 M_QQ("min_depth") ": %" PRIu32 ",\n", self->min_depth);

    //announce
    printf(INDENT3 M_QQ("anno_flag") ": " M_QQ("0x%02x") ",\n", self->anno_flag);

    //init
    printf(INDENT3 M_QQ("lfeature_remote") ": " M_QQ("0x%02x") ",\n", self->lfeature_remote);

    //close
    printf(INDENT3 M_QQ("close") ": {\n");
    printf(INDENT4 M_QQ("local_scriptPubKey") ": \"");
    btc_util_dumpbin(stdout, self->shutdown_scriptpk_local.buf, self->shutdown_scriptpk_local.len, false);
    printf("\",\n");
    printf(INDENT4 M_QQ("remote_scriptPubKey") ": \"");
    btc_util_dumpbin(stdout, self->shutdown_scriptpk_remote.buf, self->shutdown_scriptpk_remote.len, false);
    printf("\"\n");
    printf(INDENT3 "},\n");

    //normal operation
    printf(INDENT3 M_QQ("htlc_num") ": %d,\n", self->htlc_num);
    printf(INDENT3 M_QQ("htlc_id_num") ": %" PRIu64 ",\n", self->htlc_id_num);
    printf(INDENT3 M_QQ("our_msat") ": %" PRIu64 ",\n", self->our_msat);
    printf(INDENT3 M_QQ("their_msat") ": %" PRIu64 ",\n", self->their_msat);
    printf(INDENT3 M_QQ("channel_id") ": \"");
    btc_util_dumpbin(stdout, self->channel_id, LN_SZ_CHANNEL_ID, false);
    printf("\",\n");
    printf(INDENT3 M_QQ("short_channel_id") ": " M_QQ("0x%016" PRIx64) ",\n", self->short_channel_id);

    if (self->htlc_num > 0) {
        printf(INDENT3 M_QQ("add_htlc") ": [\n");
        int cnt = 0;
        for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
            if (self->cnl_add_htlc[lp].amount_msat > 0) {
                if (cnt > 0) {
                    printf(",\n");
                }
                printf(INDENT4 "{\n");
                printf(INDENT5 M_QQ("type") ": \"");
                if (self->cnl_add_htlc[lp].prev_short_channel_id == UINT64_MAX) {
                    printf("final node");
                } else if ((self->cnl_add_htlc[lp].prev_short_channel_id == 0) && (self->cnl_add_htlc[lp].flag & LN_HTLC_FLAG_OFFER)) {
                    //prev_short_channel_idが0になる
                    //      - origin node
                    //      - update_add_htlcの受信側
                    printf("origin node");
                } else {
                    printf("hop");
                }
                printf("\",\n");
                printf(INDENT5 M_QQ("id") ": %" PRIu64 ",\n", self->cnl_add_htlc[lp].id);
                printf(INDENT5 M_QQ("flag") ": " M_QQ("%s(0x%02x)") ",\n", ((self->cnl_add_htlc[lp].flag & LN_HTLC_FLAG_RECV) ? "Received" : "Offered"), self->cnl_add_htlc[lp].flag);
                printf(INDENT5 M_QQ("amount_msat") ": %" PRIu64 ",\n", self->cnl_add_htlc[lp].amount_msat);
                printf(INDENT5 M_QQ("cltv_expiry") ": %" PRIu32 ",\n", self->cnl_add_htlc[lp].cltv_expiry);
                printf(INDENT5 M_QQ("payhash") ": \"");
                btc_util_dumpbin(stdout, self->cnl_add_htlc[lp].payment_sha256, BTC_SZ_SHA256, false);
                printf("\",\n");
                printf(INDENT5 M_QQ("preimage") ": \"");
                btc_util_dumpbin(stdout, self->cnl_add_htlc[lp].buf_payment_preimage.buf, self->cnl_add_htlc[lp].buf_payment_preimage.len, false);
                printf("\",\n");
                printf(INDENT5 M_QQ("prev_short_channel_id") ": " M_QQ("0x%016" PRIx64) ",\n", self->cnl_add_htlc[lp].prev_short_channel_id);
                printf(INDENT5 M_QQ("prev_idx") ": %" PRIu16 ",\n", self->cnl_add_htlc[lp].prev_idx);
                printf(INDENT5 M_QQ("onion_reason") ": \"");
                if (self->cnl_add_htlc[lp].buf_onion_reason.len > 35) {
                    printf("length=%d, ", self->cnl_add_htlc[lp].buf_onion_reason.len);
                    btc_util_dumpbin(stdout, self->cnl_add_htlc[lp].buf_onion_reason.buf, 35, false);
                    printf("...");
                } else {
                    btc_util_dumpbin(stdout, self->cnl_add_htlc[lp].buf_onion_reason.buf, self->cnl_add_htlc[lp].buf_onion_reason.len, false);
                }
                printf("\",\n");
                printf(INDENT5 M_QQ("shared_secret") ": \"");
                btc_util_dumpbin(stdout, self->cnl_add_htlc[lp].buf_shared_secret.buf, self->cnl_add_htlc[lp].buf_shared_secret.len, false);
                printf("\",\n");
                printf(INDENT5 M_QQ("index") ": %d\n", lp);
                printf(INDENT4 "}");
                cnt++;
            }
        }
        printf(INDENT3 "],\n");
    }

    printf(INDENT3 M_QQ("commit_local") ": {\n");
    printf(INDENT4 M_QQ("dust_limit_sat") ": %" PRIu64 ",\n", self->commit_local.dust_limit_sat);
    printf(INDENT4 M_QQ("max_htlc_value_in_flight_msat") ": %" PRIu64 ",\n", self->commit_local.max_htlc_value_in_flight_msat);
    printf(INDENT4 M_QQ("channel_reserve_sat") ": %" PRIu64 ",\n", self->commit_local.channel_reserve_sat);
    printf(INDENT4 M_QQ("htlc_minimum_msat") ": %" PRIu64 ",\n", self->commit_local.htlc_minimum_msat);
    printf(INDENT4 M_QQ("to_self_delay") ": %" PRIu16 ",\n", self->commit_local.to_self_delay);
    printf(INDENT4 M_QQ("max_accepted_htlcs") ": %" PRIu16 ",\n", self->commit_local.max_accepted_htlcs);
    printf(INDENT4 M_QQ("commit_txid") ": \"");
    btc_util_dumptxid(stdout, self->commit_local.txid);
    printf("\",\n");
    printf(INDENT4 M_QQ("htlc_num") ": %" PRIu32 ",\n", self->commit_local.htlc_num);
    printf(INDENT4 M_QQ("commit_num") ": \"0x%016" PRIx64 "\",\n", self->commit_local.commit_num);
    printf(INDENT4 M_QQ("revoke_num") ": \"0x%016" PRIx64 "\"\n", self->commit_local.revoke_num);

    printf(INDENT3 "},\n");

    printf(INDENT3 M_QQ("commit_remote") ": {\n");
    printf(INDENT4 M_QQ("dust_limit_sat") ": %" PRIu64 ",\n", self->commit_remote.dust_limit_sat);
    printf(INDENT4 M_QQ("max_htlc_value_in_flight_msat") ": %" PRIu64 ",\n", self->commit_remote.max_htlc_value_in_flight_msat);
    printf(INDENT4 M_QQ("channel_reserve_sat") ": %" PRIu64 ",\n", self->commit_remote.channel_reserve_sat);
    printf(INDENT4 M_QQ("htlc_minimum_msat")  ":%" PRIu64 ",\n", self->commit_remote.htlc_minimum_msat);
    printf(INDENT4 M_QQ("to_self_delay") ": %" PRIu16 ",\n", self->commit_remote.to_self_delay);
    printf(INDENT4 M_QQ("max_accepted_htlcs") ": %" PRIu16 ",\n", self->commit_remote.max_accepted_htlcs);
    printf(INDENT4 M_QQ("commit_txid") ": \"");
    btc_util_dumptxid(stdout, self->commit_remote.txid);
    printf("\",\n");
    printf(INDENT4 M_QQ("htlc_num") ": %" PRIu32 ",\n", self->commit_remote.htlc_num);
    printf(INDENT4 M_QQ("commit_num") ": %" PRIu64 ",\n", self->commit_remote.commit_num);
    printf(INDENT4 M_QQ("revoke_num") ": %" PRIu64 "\n", self->commit_remote.revoke_num);
    printf(INDENT3 "},\n");

    printf(INDENT3 M_QQ("funding_sat") ": %" PRIu64 ",\n", self->funding_sat);
    printf(INDENT3 M_QQ("feerate_per_kw") ": %" PRIu32 ",\n", self->feerate_per_kw);

    printf(INDENT3 M_QQ("err") ": %d\n", self->err);

    printf(INDENT2 "}");
}


static void escape_json_string(char *pOut, const char *pIn)
{
    char *p = pOut;
    while (*pIn) {
        if (*pIn == '\"') {
            *p++ = '\\';
        }
        *p++ = *pIn++;
    }
    *p = '\0';
}


static void ln_print_announce_short(const uint8_t *pData, uint16_t Len)
{
    uint16_t type = ln_misc_get16be(pData);

    printf(INDENT2 "{\n");
    switch (type) {
    case MSGTYPE_CHANNEL_ANNOUNCEMENT:
        {
            ln_cnl_announce_read_t ann;

            bool ret = ln_msg_cnl_announce_read(&ann, pData, Len);
            if (ret) {
                printf(INDENT3 M_QQ("type") ": " M_QQ("channel_announcement") ",\n");
                printf(INDENT3 M_QQ("short_channel_id") ": " M_QQ("0x%016" PRIx64) ",\n", ann.short_channel_id);
                printf(INDENT3 M_QQ("node1") ": \"");
                btc_util_dumpbin(stdout, ann.node_id1, BTC_SZ_PUBKEY, false);
                printf("\",\n");
                printf(INDENT3 M_QQ("node2") ": \"");
                btc_util_dumpbin(stdout, ann.node_id2, BTC_SZ_PUBKEY, false);
                printf("\"\n");
            }
        }
        break;
    case MSGTYPE_NODE_ANNOUNCEMENT:
        {
            ln_node_announce_t msg;
            uint8_t node_pub[BTC_SZ_PUBKEY];
            char node_alias[LN_SZ_ALIAS + 1];
            msg.p_node_id = node_pub;
            msg.p_alias = node_alias;
            bool ret = ln_msg_node_announce_read(&msg, pData, Len);
            if (ret) {
                printf(INDENT3 M_QQ("node") ": \"");
                btc_util_dumpbin(stdout, node_pub, BTC_SZ_PUBKEY, false);
                printf("\",\n");
                char esc_alias[LN_SZ_ALIAS * 2 + 1];
                escape_json_string(esc_alias, node_alias);
                printf(INDENT3 M_QQ("alias") ": " M_QQ("%s") ",\n", esc_alias);
                printf(INDENT3 M_QQ("rgbcolor") ": \"#%02x%02x%02x\",\n", msg.rgbcolor[0], msg.rgbcolor[1], msg.rgbcolor[2]);
                if (msg.addr.type == LN_NODEDESC_IPV4) {
                    char addr[50];
                    sprintf(addr, "%d.%d.%d.%d:%d",
                            msg.addr.addrinfo.ipv4.addr[0],
                            msg.addr.addrinfo.ipv4.addr[1],
                            msg.addr.addrinfo.ipv4.addr[2],
                            msg.addr.addrinfo.ipv4.addr[3],
                            msg.addr.port);
                    printf(INDENT3 M_QQ("addr") ": " M_QQ("%s") ",\n", addr);
                    printf(INDENT3 M_QQ("connect") ": \"");
                    btc_util_dumpbin(stdout, node_pub, BTC_SZ_PUBKEY, false);
                    printf("@%s\",\n", addr);
                } else {
                    printf(INDENT3 M_QQ("addrtype") ": %d,\n", msg.addr.type);
                }
                printf(INDENT3 M_QQ("timestamp") ": %" PRIu32 "\n", msg.timestamp);
            }
        }
        break;
    case MSGTYPE_CHANNEL_UPDATE:
        {
            ln_cnl_update_t ann;
            bool ret = ln_msg_cnl_update_read(&ann, pData, Len);
            if (ret) {
                printf(INDENT3 M_QQ("type") ": " M_QQ("channel_update %s") ",\n", (ann.flags & 1) ? "2" : "1");
                printf(INDENT3 M_QQ("short_channel_id") ": " M_QQ("0x%016" PRIx64) ",\n", ann.short_channel_id);
                //printf(INDENT3 M_QQ("node_sort") ": " M_QQ("%s") ",\n", (ann.flags & 1) ? "second" : "first");
                printf(INDENT3 M_QQ("flags") ": " M_QQ("%04x") ",\n", ann.flags);
                printf(INDENT3 M_QQ("cltv_expiry_delta") ": %d,\n", ann.cltv_expiry_delta);
                printf(INDENT3 M_QQ("htlc_minimum_msat") ": %" PRIu64 ",\n", ann.htlc_minimum_msat);
                printf(INDENT3 M_QQ("fee_base_msat") ": %" PRIu32 ",\n", ann.fee_base_msat);
                printf(INDENT3 M_QQ("fee_prop_millionths") ": %" PRIu32 ",\n", ann.fee_prop_millionths);
                printf(INDENT3 M_QQ("timestamp") ": %" PRIu32 "\n", ann.timestamp);
            }
        }
        break;
    }
    printf(INDENT2 "}");
}


/********************************************************************
 *
 ********************************************************************/

static void dumpit_self(MDB_txn *txn, MDB_dbi dbi)
{
    //self
    if (showflag & (SHOW_SELF | SHOW_WALLET | SHOW_LISTCH)) {
        ln_self_t *p_self = (ln_self_t *)malloc(sizeof(ln_self_t));
        memset(p_self, 0, sizeof(ln_self_t));

        int retval = ln_lmdb_self_load(p_self, txn, dbi);
        if (retval != 0) {
            //printf(M_QQ("load") ":" M_QQ("%s"), mdb_strerror(retval));
            return;
        }
        const char *p_title;
        if (showflag & SHOW_SELF) {
            p_title = "channel_info";
        }
        if (showflag & SHOW_WALLET) {
            p_title = "wallet_info";
        }
        if (showflag & SHOW_LISTCH) {
            p_title = "peer_node_id";
        }

        if (cnt0) {
            printf(",\n");
        } else {
            printf(INDENT1 M_QQ("%s") ": [\n", p_title);
        }

        if (showflag & SHOW_SELF) {
            ln_print_self(p_self);
        }
        if (showflag & SHOW_WALLET) {
            ln_print_wallet(p_self);
        }
        if (showflag & SHOW_LISTCH) {
            printf(INDENT2 "\"");
            btc_util_dumpbin(stdout, p_self->peer_node_id, BTC_SZ_PUBKEY, false);
            printf("\"");
        }
        ln_term(p_self);
        free(p_self);
        cnt0++;
    }
}

static void dumpit_bkself(MDB_txn *txn, MDB_dbi dbi)
{
    //bkself
    if (showflag & (SHOW_CLOSED_CH)) {
        if (cnt5) {
            printf(",\n");
        } else {
            printf(INDENT1 M_QQ("closed_self") ": [\n");
        }
        printf(INDENT2 "{\n");
        ln_lmdb_bkself_show(txn, dbi);
        printf(INDENT2 "}");
        cnt5++;
    }
}

static void dumpit_channel(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag & SHOW_ANNOCNL) {
        if (cnt1) {
            printf(",");
        }

        MDB_cursor  *cursor;

        //ここでdbi, txnを使ってcursorを取得
        int retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        printf(INDENT1 M_QQ("channel_announcement_list") ": [\n");
        do {
            uint64_t short_channel_id;
            char type;
            uint32_t timestamp;
            utl_buf_t buf = UTL_BUF_INIT;

            ret = ln_lmdb_annocnl_cur_load(cursor, &short_channel_id, &type, &timestamp, &buf);
            if ((ret == 0) && (short_channel_id != 0)) {
                if (cnt1) {
                    printf(",\n");
                }
                if (!(showflag & SHOW_DEBUG)) {
                    ln_print_announce_short(buf.buf, buf.len);
                } else {
                    ln_print_announce(buf.buf, buf.len);
                }
                cnt1++;
                utl_buf_free(&buf);
            } else {
                //printf("end of announce\n");
            }
        } while (ret == 0);
        printf("\n" INDENT1 "]\n");
        mdb_cursor_close(cursor);
    }
}

static void dumpit_node(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag & SHOW_ANNONODE) {
        if (cnt2) {
            printf(",");
        } else {
            printf(INDENT1 M_QQ("node_announcement_list") ": [\n");
        }

        MDB_cursor  *cursor;

        //ここでdbi, txnを使ってcursorを取得
        int retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        do {
            utl_buf_t buf = UTL_BUF_INIT;
            uint32_t timestamp;
            uint8_t nodeid[BTC_SZ_PUBKEY];

            ret = ln_lmdb_annonod_cur_load(cursor, &buf, &timestamp, nodeid);
            if (ret == 0) {
                if (cnt2) {
                    printf(",\n");
                }
                if (!(showflag & SHOW_DEBUG)) {
                    ln_print_announce_short(buf.buf, buf.len);
                } else {
                    ln_print_announce(buf.buf, buf.len);
                }
                utl_buf_free(&buf);
                cnt2++;
            } else {
                //printf("end of announce\n");
            }
        } while (ret == 0);
        mdb_cursor_close(cursor);
    }
}

static void dumpit_annoinfo(MDB_txn *txn, MDB_dbi dbi, ln_lmdb_dbtype_t dbtype)
{
    if ((showflag & SHOW_ANNOINFO) == 0) {
        return;
    }

    MDB_cursor  *cursor;

    //ここでdbi, txnを使ってcursorを取得
    int retval = mdb_cursor_open(txn, dbi, &cursor);
    if (retval != 0) {
        fprintf(stderr, "cursor_open: %d\n", __LINE__);
        exit(-1);
    }

    MDB_val key, data;
    while ((retval = mdb_cursor_get(cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
        if ((dbtype == LN_LMDB_DBTYPE_ANNOINFO_CNL) && (key.mv_size == M_SZ_ANNOINFO_CNL)) {
            const uint8_t *keyname = (const uint8_t *)key.mv_data;
            switch (keyname[M_SZ_ANNOINFO_CNL - 1]) {
            case LN_DB_CNLANNO_ANNO:
                printf("channel_announcement: ");
                break;
            case LN_DB_CNLANNO_UPD1:
                printf("channel_update 1: ");
                break;
            case LN_DB_CNLANNO_UPD2:
                printf("channel_update 2: ");
                break;
            default:
                fprintf(stderr, "keyname=%02x: %d\n", keyname[M_SZ_ANNOINFO_CNL - 1], __LINE__);
                exit(-1);
            }

            uint64_t short_channel_id = *(uint64_t *)key.mv_data;
            printf("0x%016" PRIx64 "\n", short_channel_id);
        } else if ((dbtype == LN_LMDB_DBTYPE_ANNOINFO_NODE) && (key.mv_size == M_SZ_ANNOINFO_NODE)) {
            printf("node_announcement: ");
            btc_util_dumpbin(stdout, key.mv_data, M_SZ_ANNOINFO_NODE, true);
        } else {
            //skip
            continue;
        }

        int nums = data.mv_size / BTC_SZ_PUBKEY;
        const uint8_t *p_data = (const uint8_t *)data.mv_data;
        for (int lp = 0; lp < nums; lp++) {
            printf("  [%2d]", lp);
            btc_util_dumpbin(stdout, p_data, BTC_SZ_PUBKEY, true);
            p_data += BTC_SZ_PUBKEY;
        }
        printf("\n");
    }
    mdb_cursor_close(cursor);
}

static void dumpit_routeskip(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag == SHOW_ROUTESKIP) {
        printf(M_QQ("skiproute") ": [\n");

        MDB_cursor  *cursor;

        int retval = mdb_cursor_open(txn, dbi, &cursor);
        if (retval != 0) {
            LOGD("err: %s\n", mdb_strerror(retval));
            mdb_txn_abort(txn);
        }

        int cnt = 0;
        MDB_val key, data;
        while ((retval =  mdb_cursor_get(cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
            if (cnt > 0) {
                printf(",\n");
            }
            uint64_t short_channel_id = *(uint64_t *)key.mv_data;
            printf("[" M_QQ("0x%016" PRIx64) ",", short_channel_id);
            if (data.mv_size == 0) {
                printf(M_QQ("perm") "]");
            } else if ((data.mv_size == 1) && (*(uint8_t *)data.mv_data == 0x01)) {
                printf(M_QQ("temp") "]");
            } else {
                printf(M_QQ("unknown") "]");
            }
            cnt++;
        }
        mdb_cursor_close(cursor);

        printf("\n]");
    }
}

static void dumpit_invoice(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag == SHOW_INVOICE) {
        printf(M_QQ("payinvoice") ": [\n");

        MDB_cursor  *cursor;

        int retval = mdb_cursor_open(txn, dbi, &cursor);
        if (retval != 0) {
            LOGD("err: %s\n", mdb_strerror(retval));
            mdb_txn_abort(txn);
        }

        int cnt = 0;
        MDB_val key, data;
        while ((retval =  mdb_cursor_get(cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
            if (cnt > 0) {
                printf(",\n");
            }

            printf("[\"");
            btc_util_dumpbin(stdout, key.mv_data, key.mv_size, false);
            printf("\",");
            printf(M_QQ("%s") "]", (const char *)data.mv_data);
            cnt++;
        }
        mdb_cursor_close(cursor);

        printf("\n]");
    }
}

static void dumpit_preimage(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag == SHOW_PREIMAGE) {
        printf(M_QQ("preimage") ": [");

        lmdb_cursor_t cur;

        int retval = mdb_cursor_open(txn, dbi, &cur.cursor);
        if (retval != 0) {
            LOGD("err: %s\n", mdb_strerror(retval));
            mdb_txn_abort(txn);
        }

        bool ret = true;
        while (ret) {
            ln_db_preimg_t preimg;
            bool detect;
            ret = ln_db_preimg_cur_get(&cur, &detect, &preimg);
            if (detect) {
                if (cnt4) {
                    printf(",");
                }
                printf("{\n");
                printf(INDENT1 "\"");
                btc_util_dumpbin(stdout, preimg.preimage, LN_SZ_PREIMAGE, false);
                printf("\",\n");
                printf(INDENT1 M_QQ("amount") ": %" PRIu64 ",\n", preimg.amount_msat);
                printf(INDENT1 M_QQ("expiry") ": %" PRIu32 "\n", preimg.expiry);
                char dtstr[UTL_SZ_DTSTR];
                utl_misc_strftime(dtstr, preimg.creation_time);
                printf(INDENT1 M_QQ("creation") ": %s\n", dtstr);
                printf("}");
                cnt4++;
            }
        }
        mdb_cursor_close(cur.cursor);
    }
}

static void dumpit_version(MDB_txn *txn, MDB_dbi dbi)
{
    //version
    if (showflag == SHOW_VERSION) {
        int retval;
        MDB_val key, data;

        char wif[BTC_SZ_WIF_MAX] = "";
        char alias[LN_SZ_ALIAS + 1] = "";
        uint16_t port = 0;
        uint8_t genesis[LN_SZ_HASH];

        printf(INDENT1 M_QQ("version") ": {\n");

        retval = ln_db_lmdb_get_mynodeid(txn, dbi, wif, alias, &port, genesis);
        if (retval == 0) {
            btc_util_keys_t keys;
            btc_chain_t chain;
            btc_util_wif2keys(&keys, &chain, wif);
            // printf(INDENT2 M_QQ("wif") ": " M_QQ("%s") ",\n", wif);
            // printf(INDENT2 M_QQ("node_secret") ": \"");
            // btc_util_dumpbin(stdout, keys.priv, BTC_SZ_PRIVKEY, false);
            // printf("\",\n");
            printf(INDENT2 M_QQ("node_id") ": \"");
            btc_util_dumpbin(stdout, keys.pub, BTC_SZ_PUBKEY, false);
            printf("\",\n");
            printf(INDENT2 M_QQ("alias") ": " M_QQ("%s") ",\n", alias);
            printf(INDENT2 M_QQ("port") ": %" PRIu16 ",\n", port);
            printf(INDENT2 M_QQ("genesis") ": \"");
            btc_util_dumpbin(stdout, genesis, LN_SZ_HASH, false);
            printf("\",\n");
            const char *p_net;
            switch (chain) {
            case BTC_MAINNET:
                p_net = "mainnet";
                break;
            case BTC_TESTNET:
                p_net = "testnet";
                break;
            default:
                p_net = "unknown";
            }
            printf(INDENT2 M_QQ("network") ": " M_QQ("%s") ",\n", p_net);
        } else {
            printf(INDENT2 M_QQ("node_id") ": " M_QQ("fail") ",\n");
        }

        key.mv_size = LNDBK_LEN(LNDBK_VER);
        key.mv_data = LNDBK_VER;
        retval = mdb_get(txn, dbi, &key, &data);
        if (retval == 0) {
            int version = *(int *)data.mv_data;
            printf(INDENT2 M_QQ("version") ": %d\n", version);
        } else {
            printf(INDENT2 M_QQ("version") ": " M_QQ("fail") "\n");
        }
        printf(INDENT1 "}\n");
    }
}

int main(int argc, char *argv[])
{
    fp_err = stderr;

    int ret;
    int env = -1;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key;
    MDB_cursor  *cursor;
#ifdef M_SPOIL_STDERR
    bool        spoil_stderr = true;
#else
    bool        spoil_stderr = false;
#endif  //M_SPOIL_STDERR

    const struct option OPTIONS[] = {
        { "debug", no_argument, NULL, 'D' },
        { 0, 0, 0, 0 }
    };

    ln_lmdb_set_path(".");

    bool loop = true;
    int opt;
    while (loop && ((opt = getopt_long(argc, argv, "hd:swlqcnakivD9:", OPTIONS, NULL)) != -1)) {
        switch (opt) {
        case 'd':
            if (optarg[strlen(optarg) - 1] == '/') {
                optarg[strlen(optarg) - 1] = '\0';
            }
            ln_lmdb_set_path(optarg);
            break;
        case 'D':
            //デバッグでstderrを出力させたい場合
            spoil_stderr = false;
            break;

        case 's':
            showflag = SHOW_SELF;
            env = 0;
            break;
        case 'w':
            showflag = SHOW_WALLET;
            env = 0;
            break;
        case 'l':
            showflag = SHOW_LISTCH;
            env = 0;
            break;
        case 'q':
            showflag = SHOW_CLOSED_CH;
            env = 0;
            break;
        case 'c':
            showflag = SHOW_ANNOCNL;
            env = 2;
            break;
        case 'n':
            showflag = SHOW_ANNONODE;
            env = 2;
            break;
        case 'a':
            showflag = SHOW_ANNOINFO;
            env = 2;
            break;
        case 'k':
            showflag = SHOW_ROUTESKIP;
            env = 1;
            break;
        case 'i':
            showflag = SHOW_INVOICE;
            env = 1;
            break;
        case 'v':
            showflag = SHOW_VERSION;
            env = 0;
            break;
        case '9':
            switch (optarg[1]) {
            case '1':
                showflag = SHOW_ANNOCNL | SHOW_DEBUG;
                spoil_stderr = false;
                env = 2;
                break;
            case '2':
                showflag = SHOW_ANNONODE | SHOW_DEBUG;
                spoil_stderr = false;
                env = 2;
                break;
            case '3':
                showflag = SHOW_PREIMAGE;
                env = 0;
                break;
            }
            break;

        case 'h':
        default:
            loop = false;
            showflag = 0;
            break;
        }
    }

    if (showflag == 0) {
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "\t%s <option>\n", argv[0]);
        fprintf(stderr, "\t\t-v : node information\n");
        fprintf(stderr, "\t\t-d : dbptarm directory(use current directory's dbptarm if not set)\n");
        fprintf(stderr, "\t\t-w : wallet info\n");
        fprintf(stderr, "\t\t-s : self info\n");
        fprintf(stderr, "\t\t-l : channel list\n");
        fprintf(stderr, "\t\t-q : closed self info\n");
        fprintf(stderr, "\t\t-c : channel_announcement/channel_update\n");
        fprintf(stderr, "\t\t-n : node_announcement\n");
        //fprintf(stderr, "\t\t-a : (internal)announcement received/sent node_id list\n");
        fprintf(stderr, "\t\t-k : (internal)skip routing channel list\n");
        fprintf(stderr, "\t\t-i : (internal)paying invoice\n");
        return -1;
    }

    ret = mdb_env_create(&mpDbSelf);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbSelf, 10);
    assert(ret == 0);
    ret = mdb_env_open(mpDbSelf, ln_lmdb_get_selfpath(), MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", ln_lmdb_get_selfpath());
        return -1;
    }
    ret = mdb_env_create(&mpDbNode);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbNode, 10);
    assert(ret == 0);
    ret = mdb_env_open(mpDbNode, ln_lmdb_get_nodepath(), MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", ln_lmdb_get_nodepath());
        //return -1;
    }
    ret = mdb_env_create(&mpDbAnno);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbAnno, 10);
    assert(ret == 0);
    ret = mdb_env_open(mpDbAnno, ln_lmdb_get_annopath(), MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", ln_lmdb_get_annopath());
        //return -1;
    }
    ln_lmdb_setenv(mpDbSelf, mpDbNode, mpDbAnno);

    MDB_env *p_env;
    switch(env) {
    case 0:
        p_env = mpDbSelf;
        break;
    case 1:
        p_env = mpDbNode;
        break;
    case 2:
        p_env = mpDbAnno;
        break;
    default:
        assert(0);
    }

    btc_genesis_t gtype;
    bool bret = ln_db_ver_check(NULL, &gtype);
    if (!bret) {
        fprintf(stderr, "fail: DB version not match.\n");
        //return -1;
    }

    ln_set_genesishash(btc_util_get_genesis_block(gtype));
    switch (gtype) {
    case BTC_GENESIS_BTCMAIN:
        btc_init(BTC_MAINNET, true);
        break;
    case BTC_GENESIS_BTCTEST:
    case BTC_GENESIS_BTCREGTEST:
        btc_init(BTC_TESTNET, true);
        break;
    default:
        fprintf(fp_err, "fail: unknown chainhash in DB\n");
        return -1;
    }

    ret = mdb_txn_begin(p_env, NULL, MDB_RDONLY, &txn);
    assert(ret == 0);
    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    if (ret != 0) {
        fprintf(stderr, "fail: DB cannot open.\n");
        return -1;
    }
    ret = mdb_cursor_open(txn, dbi, &cursor);
    if (ret != 0) {
        fprintf(stderr, "fail: DB cursor cannot open.\n");
        return -1;
    }

    if (spoil_stderr) {
        //stderrを捨てる
        int fd_err = dup(2);
        fp_err = fdopen(fd_err, "w");
        close(2);
    }

    printf("{\n");
    int list = 0;
    while ((ret = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi dbi2;
        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        char *name = (char *)malloc(key.mv_size + 1);
        memcpy(name, key.mv_data, key.mv_size);
        name[key.mv_size] = '\0';
        ret = mdb_dbi_open(txn, name, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else {
                ln_lmdb_dbtype_t dbtype = ln_lmdb_get_dbtype(name);
                switch (dbtype) {
                case LN_LMDB_DBTYPE_SELF:
                    dumpit_self(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_SECRET:
                case LN_LMDB_DBTYPE_ADD_HTLC:
                    //LN_LMDB_DBTYPE_SELFで読み込むので、スルー
                    break;
                case LN_LMDB_DBTYPE_BKSELF:
                    dumpit_bkself(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_ANNO_CNL:
                    dumpit_channel(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_ANNO_NODE:
                    dumpit_node(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_ANNOINFO_CNL:
                case LN_LMDB_DBTYPE_ANNOINFO_NODE:
                    dumpit_annoinfo(txn, dbi2, dbtype);
                    break;
                case LN_LMDB_DBTYPE_ROUTE_SKIP:
                    dumpit_routeskip(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_INVOICE:
                    dumpit_invoice(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_PREIMAGE:
                    dumpit_preimage(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_VERSION:
                    dumpit_version(txn, dbi2);
                    break;
                default:
                    fprintf(stderr, "unknown name[%s]\n", name);
                    break;
                }
            }
            mdb_close(mdb_txn_env(txn), dbi2);
        }
        free(name);
    }
    if (cnt0 || cnt2 || cnt4 || cnt5) {
        printf("\n" INDENT1 "]\n");
    }
    printf("}\n");
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    mdb_env_close(mpDbAnno);
    mdb_env_close(mpDbNode);
    mdb_env_close(mpDbSelf);
}
