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

#define LOG_TAG     "showdb"
#include "utl_log.h"
#include "utl_time.h"
#include "utl_int.h"

#include "btc_crypto.h"
#include "btc_dbg.h"

#include "ln_db_lmdb.h"
#include "ln_msg_anno.h"

#include "ln_normalope.h"

#include "ptarmd.h"



/********************************************************************
 * macros
 ********************************************************************/

#define M_SPOIL_STDERR

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value

#define SHOW_CHANNEL            (0x0001)
#define SHOW_CHANNEL_WALLET     (0x0002)
#define SHOW_ANNOCNL            (0x0004)
#define SHOW_DEBUG              (0x0008)
#define SHOW_ANNONODE           (0x0010)
#define SHOW_CHANNEL_LISTCH     (0x0020)
#define SHOW_ANNOINFO           (0x0040)
#define SHOW_VERSION            (0x0080)
#define SHOW_PREIMAGE           (0x0100)
#define SHOW_ROUTESKIP          (0x0200)
#define SHOW_INVOICE            (0x0400)
#define SHOW_CLOSED_CH          (0x0800)
#define SHOW_WALLET             (0x1000)

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
#define INDENT6                 "            "


/********************************************************************
 * prototypes
 ********************************************************************/

#ifdef PTARM_USE_PRINTFUNC
void ln_print_announce(const uint8_t *pData, uint16_t Len);
#else
#define ln_print_announce(...)          //nothing
#endif  //PTARM_USE_PRINTFUNC
void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_node, MDB_env *p_anno, MDB_env *p_walt);


/********************************************************************
 * static variables
 ********************************************************************/

static uint16_t     showflag;
static int          cnt0;
static int          cnt1;
static int          cnt2;
static int          cnt4;
static int          cnt5;
static int          cnt6;
static MDB_env      *mpDbChannel = NULL;
static MDB_env      *mpDbNode = NULL;
static MDB_env      *mpDbAnno = NULL;
static MDB_env      *mpDbWalt = NULL;
static FILE         *fp_err;


static const char *KEYS_STR[LN_BASEPOINT_IDX_NUM + 1] = {
    "bp_funding", "bp_revocation", "bp_payment", "bp_delayed", "bp_htlc", "bp_per_commit"
};
static const char *SCR_STR[LN_SCRIPT_IDX_NUM] = {
    "remotekey", "delayedkey", "revocationkey", "local_htlckey", "remote_htlckey"
};


/********************************************************************
 * functions
 ********************************************************************/

static void ln_print_wallet(const ln_channel_t *pChannel)
{
    ln_status_t stat = ln_status_get(pChannel);
    if (stat == LN_STATUS_NORMAL) {
        printf(INDENT2 "{\n");
        printf(INDENT3 M_QQ("node_id") ": \"");
        utl_dbg_dump(stdout, pChannel->peer_node_id, BTC_SZ_PUBKEY, false);
        printf("\",\n");
        printf(INDENT3 M_QQ("channel_id") ": \"");
        utl_dbg_dump(stdout, pChannel->channel_id, LN_SZ_CHANNEL_ID, false);
        printf("\",\n");
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, pChannel->short_channel_id);
        printf(INDENT3 M_QQ("short_channel_id") ": " M_QQ("%s (%016" PRIx64 ")") ",\n", str_sci, pChannel->short_channel_id);
        printf(INDENT3 M_QQ("funding_tx") ": \"");
        btc_dbg_dump_txid(stdout, ln_funding_info_txid(&pChannel->funding_info));
        printf(":%d\",\n", ln_funding_info_txindex(&pChannel->funding_info));
        uint64_t offered = 0;
        uint64_t received = 0;
        printf(INDENT3 M_QQ("pending") ": [\n");
        int cnt = 0;
        for (int lp = 0; lp < LN_UPDATE_MAX; lp++) {
            const ln_update_t *p_update = &pChannel->update_info.updates[lp];
            if (!LN_UPDATE_ENABLED(p_update)) continue;
            if (p_update->type != LN_UPDATE_TYPE_ADD_HTLC) continue;
            const ln_htlc_t *p_htlc = &pChannel->update_info.htlcs[p_update->htlc_idx];
            if (cnt) {
                printf(",\n");
            }
            const char *p_dir = NULL;
            if (p_update->flags.up_send) {
                p_dir = "offered";
                offered += p_htlc->amount_msat;
            } else if (p_update->flags.up_recv) {
                p_dir = "received";
                received += p_htlc->amount_msat;
            } else {
                p_dir = "unknown";
            }
            printf(INDENT4 "{\n");
            printf(INDENT5 M_QQ("direction") ": " M_QQ("%s") ",\n", p_dir);
            printf(INDENT5 M_QQ("amount_msat") ": %" PRIu64 ",\n", p_htlc->amount_msat);
            printf(INDENT5 M_QQ("cltv_expiry") ": %" PRIu32 "\n", p_htlc->cltv_expiry);
            printf(INDENT4 "}");
            cnt++;
        }
        printf("\n" INDENT3 "],\n");
        //printf(INDENT3 M_QQ("local_msat") ": %" PRIu64 ",\n", pChannel->local_msat - offered);
        //printf(INDENT3 M_QQ("remote_msat") ": %" PRIu64 "\n", pChannel->remote_msat - received);
        printf(INDENT3 M_QQ("local_msat") ": %" PRIu64 ",\n", ln_local_msat(pChannel));
        printf(INDENT3 M_QQ("remote_msat") ": %" PRIu64 "\n", ln_remote_msat(pChannel));
        printf(INDENT2 "}");
    }
}

static void ln_print_channel(const ln_channel_t *pChannel)
{
    printf(INDENT2 "{\n");

    //peer_node
    printf(INDENT3 M_QQ("peer_node_id") ": \"");
    utl_dbg_dump(stdout, pChannel->peer_node_id, BTC_SZ_PUBKEY, false);
    printf("\",\n");

    //channel_id
    printf(INDENT3 M_QQ("channel_id") ": \"");
    utl_dbg_dump(stdout, pChannel->channel_id, LN_SZ_CHANNEL_ID, false);
    printf("\",\n");
    printf(INDENT3 M_QQ("short_channel_id") ": {\n");
    uint32_t height;
    uint32_t bindex;
    uint32_t vindex;
    ln_short_channel_id_get_param(&height, &bindex, &vindex, pChannel->short_channel_id);
    printf(INDENT4 M_QQ("hex") ": " M_QQ("0x%016" PRIx64) ",\n", pChannel->short_channel_id);
    char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
    ln_short_channel_id_string(str_sci, pChannel->short_channel_id);
    printf(INDENT4 M_QQ("str") ": " M_QQ("%s") ",\n", str_sci);
    printf(INDENT4 M_QQ("block_height") ": %" PRIu32 ",\n", height);
    printf(INDENT4 M_QQ("block_index") ": %" PRIu32 ",\n", bindex);
    printf(INDENT4 M_QQ("tx_vout") ": %" PRIu32 "\n", vindex);
    printf(INDENT3 "},\n");

    //amount
    printf(INDENT3 M_QQ("local_msat") ": %" PRIu64 ",\n", ln_local_msat(pChannel));
    printf(INDENT3 M_QQ("remote_msat") ": %" PRIu64 ",\n", ln_remote_msat(pChannel));
    printf(INDENT3 M_QQ("funding_satoshis") ": %" PRIu64 ",\n", pChannel->funding_info.funding_satoshis);
    printf(INDENT3 M_QQ("feerate_per_kw") ": %" PRIu32 ",\n", ln_feerate_per_kw(pChannel));

    //status
    const char *p_status_str = ln_status_string(pChannel);
    printf(INDENT3 M_QQ("status") ": " M_QQ("%s") ",\n", p_status_str);

    //key storage
    printf(INDENT3 M_QQ("storage_index") ": " M_QQ("0x%016" PRIx64) ",\n", ln_derkey_local_storage_get_current_index(&pChannel->keys_local));
    // printf(M_QQ("storage_seed") ": \"");
    // utl_dbg_dump(stdout, pChannel->keys_local.storage_seed, BTC_SZ_PRIVKEY, false);
    // printf("\",\n");
    printf(INDENT3 M_QQ("peer_storage_index") ": " M_QQ("0x%016" PRIx64) ",\n", ln_derkey_remote_storage_get_current_index(&pChannel->keys_remote));

    //funding
    printf(INDENT3 M_QQ("state") ": {\n");
    printf(INDENT4 M_QQ("state") ": " M_QQ("0x%02x") ",\n", pChannel->funding_info.state);
    printf(INDENT4 M_QQ("is_funder") ": %d,\n", (pChannel->funding_info.role == LN_FUNDING_ROLE_FUNDER));
    printf(INDENT4 M_QQ("announce_channel") ": %d,\n", ((pChannel->funding_info.state & LN_FUNDING_STATE_STATE_NO_ANNO_CH) == LN_FUNDING_STATE_STATE_NO_ANNO_CH));
    printf(INDENT4 M_QQ("is_funding") ": %d,\n", ((pChannel->funding_info.state & LN_FUNDING_STATE_STATE_FUNDING) == LN_FUNDING_STATE_STATE_FUNDING));
    printf(INDENT4 M_QQ("is_opened") ": %d\n", ((pChannel->funding_info.state & LN_FUNDING_STATE_STATE_OPENED) == LN_FUNDING_STATE_STATE_OPENED));
    printf(INDENT3 "},\n");
    printf(INDENT3 M_QQ("mined_block") ": \"");
    btc_dbg_dump_txid(stdout, pChannel->funding_blockhash);
    printf("\",\n");
    printf(INDENT3 M_QQ("last_confirm") ": %" PRIu32 ",\n", pChannel->funding_last_confirm);
    printf(INDENT3 M_QQ("funding_local") ": {\n");
    printf(INDENT4 M_QQ("funding_txid") ": \"");
    btc_dbg_dump_txid(stdout, ln_funding_info_txid(&pChannel->funding_info));
    printf("\",\n");
    printf(INDENT4 M_QQ("funding_txindex") ": %d,\n", ln_funding_info_txindex(&pChannel->funding_info));
    int lp;
    for (lp = 0; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        printf(INDENT4 M_QQ("%s") ": {\n", KEYS_STR[lp]);
        printf(INDENT5 M_QQ("pub") ": \"");
        utl_dbg_dump(stdout, pChannel->keys_local.basepoints[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "},\n");
    }
    printf(INDENT4 M_QQ("%s") ": {\n", KEYS_STR[lp]);
    printf(INDENT5 M_QQ("pub") ": \"");
    utl_dbg_dump(stdout, pChannel->keys_local.per_commitment_point, BTC_SZ_PUBKEY, false);
    printf("\"\n");
    printf(INDENT4 "},\n");
    for (lp = 0; lp < LN_SCRIPT_IDX_NUM; lp++) {
        if (lp != 0) {
            printf(",\n");
        }
        printf(INDENT4 M_QQ("%s") ": {\n", SCR_STR[lp]);
        printf(INDENT5 M_QQ("pub") ": \"");
        utl_dbg_dump(stdout, pChannel->keys_local.script_pubkeys[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "}");
    }
    printf("\n");
    printf(INDENT3 "},\n");

    printf(INDENT3 M_QQ("funding_remote") ": {\n");
    for (lp = 0; lp < LN_BASEPOINT_IDX_NUM; lp++) {
        printf(INDENT4 M_QQ("%s") ": {\n", KEYS_STR[lp]);
        printf(INDENT5 M_QQ("pub") ": \"");
        utl_dbg_dump(stdout, pChannel->keys_remote.basepoints[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "},\n");
    }
    printf(INDENT4 M_QQ("%s") ": {\n", KEYS_STR[lp]);
    printf(INDENT5 M_QQ("pub") ": \"");
    utl_dbg_dump(stdout, pChannel->keys_remote.per_commitment_point, BTC_SZ_PUBKEY, false);
    printf("\"\n");
    printf(INDENT4 "},\n");
    printf(INDENT4 M_QQ("%s") ": \"", "prev_percommit");
    utl_dbg_dump(stdout, pChannel->keys_remote.prev_per_commitment_point, BTC_SZ_PUBKEY, false);
    printf("\",\n");
    for (lp = 0; lp < LN_SCRIPT_IDX_NUM; lp++) {
        if (lp != 0) {
            printf(",\n");
        }
        printf(INDENT4 M_QQ("%s") ": {\n", SCR_STR[lp]);
        printf(INDENT5 M_QQ("pub") ": \"");
        utl_dbg_dump(stdout, pChannel->keys_remote.script_pubkeys[lp], BTC_SZ_PUBKEY, false);
        printf("\"\n");
        printf(INDENT4 "}");
    }
    printf("\n");
    printf(INDENT3 "},\n");
    printf(INDENT3 M_QQ("obscured_commit_num_mask") ": " M_QQ("0x%016" PRIx64) ",\n", pChannel->commit_info_local.obscured_commit_num_mask);
    // printf(INDENT3 M_QQ("redeem_fund") ": \"");
    // utl_dbg_dump(stdout, pChannel->funding_info.wit_script.buf, pChannel->funding_info.wit_script.len, false);
    // printf("\",\n");
    printf(INDENT3 M_QQ("key_order_of_fundtx") ": " M_QQ("%s") ",\n", (pChannel->funding_info.key_order == BTC_SCRYPT_PUBKEY_ORDER_ASC) ? "first" : "second");
    printf(INDENT3 M_QQ("minmum_depth") ": %" PRIu32 ",\n", pChannel->funding_info.minimum_depth);

    //announce
    printf(INDENT3 M_QQ("anno_flag") ": {\n");
    printf(INDENT4 M_QQ("value") ": " M_QQ("0x%02x") ",\n", pChannel->anno_flag);
    printf(INDENT4 M_QQ("announcement_signatures send") ": %d,\n", (pChannel->anno_flag & 0x01) == 0x01);
    printf(INDENT4 M_QQ("announcement_signatures recv") ": %d,\n", (pChannel->anno_flag & 0x02) == 0x02);
    printf(INDENT4 M_QQ("exchanged") ": %d\n", (pChannel->anno_flag & LN_ANNO_FLAG_END) == LN_ANNO_FLAG_END);
    printf(INDENT3 "},\n");

    //init
    printf(INDENT3 M_QQ("lfeature_remote") ": " M_QQ("0x%02x") ",\n", pChannel->lfeature_remote);

    //close
    printf(INDENT3 M_QQ("close") ": {\n");
    printf(INDENT4 M_QQ("shutdown_flag") ": {\n");
    printf(INDENT5 M_QQ("value") ": " M_QQ("0x%02x") ",\n", pChannel->shutdown_flag);
    printf(INDENT5 M_QQ("shutdown_send") ": %d,\n", (pChannel->shutdown_flag & 0x01) == 0x01);
    printf(INDENT5 M_QQ("shutdown_recv") ": %d\n", (pChannel->shutdown_flag & 0x02) == 0x02);
    printf(INDENT4 "},\n");
    printf(INDENT4 M_QQ("local_scriptPubKey") ": \"");
    utl_dbg_dump(stdout, pChannel->shutdown_scriptpk_local.buf, pChannel->shutdown_scriptpk_local.len, false);
    printf("\",\n");
    printf(INDENT4 M_QQ("remote_scriptPubKey") ": \"");
    utl_dbg_dump(stdout, pChannel->shutdown_scriptpk_remote.buf, pChannel->shutdown_scriptpk_remote.len, false);
    printf("\"\n");
    printf(INDENT3 "},\n");

    //normal operation
    printf(INDENT3 M_QQ("next_htlc_id") ": %" PRIu64 ",\n", pChannel->update_info.next_htlc_id);

    printf(INDENT3 M_QQ("htlcs") ": [\n");
    int cnt = 0;
    for (lp = 0; lp < LN_UPDATE_MAX; lp++) {
        const ln_update_t *p_update = &pChannel->update_info.updates[lp];
        if (!LN_UPDATE_ENABLED(p_update)) continue;
        if (p_update->type != LN_UPDATE_TYPE_ADD_HTLC) continue;
        const ln_htlc_t *p_htlc = &pChannel->update_info.htlcs[p_update->htlc_idx];
        if (cnt > 0) {
            printf(",\n");
        }
        printf(INDENT4 "{\n");
        printf(INDENT5 M_QQ("type") ": \"");
        if (p_htlc->neighbor_short_channel_id) {
            printf("hop");
        } else {
            if (p_update->flags.up_send) {
                printf("origin node");
            } else if (p_update->flags.up_recv) {
                printf("final node");
            } else {
                printf("unknown");
            }
        }
        printf("\",\n");
        printf(INDENT5 M_QQ("id") ": %" PRIu64 ",\n", p_htlc->id);
        // printf(INDENT5 M_QQ("flags") ": " M_QQ("%s(0x%04x)") ",\n",
        //             ((p_update->type == LN_UPDATE_TYPE_ADD_HTLC) ? "received" : "offered"),
        //             p_update->flags);
        printf(INDENT5 M_QQ("flags") ": {\n");
#if 0 //XXX:
        const char *p_str_type;
        const char *p_str_fin_type;
        switch (p_update->type) {
        case LN_ADDHTLC_NONE:
            p_str_type = "---";
            break;
        case LN_UPDATE_TYPE_ADD_HTLC:
            p_str_type = "offered";
            break;
        case LN_UPDATE_TYPE_ADD_HTLC:
            p_str_type = "received";
            break;
        case LN_UPDATE_TYPE_FULFILL_HTLC:
            p_str_type = "fulfill";
            break;
        case LN_UPDATE_TYPE_FAIL_HTLC:
            p_str_type = "fail";
            break;
        case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
            p_str_type = "fail_malformed";
            break;
        default:
            p_str_type = "unknown";
        }
        switch (p_update->fin_type) {
        case LN_DELHTLC_NONE:
            p_str_fin_type = "---";
            break;
        case LN_UPDATE_TYPE_FULFILL_HTLC:
            p_str_fin_type = "fulfill";
            break;
        case LN_UPDATE_TYPE_FAIL_HTLC:
            p_str_fin_type = "fail";
            break;
        case LN_UPDATE_TYPE_FAIL_MALFORMED_HTLC:
            p_str_fin_type = "fail_malformed";
            break;
        default:
            p_str_fin_type = "unknown";
        }
#endif
        printf(INDENT6 M_QQ("flags") ": " M_QQ("0x%04x") ",\n", ln_update_flags2u32(p_update->flags));
        //printf(INDENT6 M_QQ("type") ": " M_QQ("%s") ",\n", p_str_type);
        printf(INDENT6 M_QQ("up_send") ": %d,\n", p_update->flags.up_send);
        printf(INDENT6 M_QQ("cs_send") ": %d,\n", p_update->flags.cs_send);
        printf(INDENT6 M_QQ("ra_recv") ": %d,\n", p_update->flags.ra_recv);
        printf(INDENT6 M_QQ("cs_recv") ": %d,\n", p_update->flags.cs_recv);
        printf(INDENT6 M_QQ("ra_send") ": %d,\n", p_update->flags.ra_send);
        //printf(INDENT6 M_QQ("fin_type") ": " M_QQ("%s") "\n", p_str_fin_type);
        printf(INDENT5 "},\n");
        printf(INDENT5 M_QQ("amount_msat") ": %" PRIu64 ",\n", p_htlc->amount_msat);
        printf(INDENT5 M_QQ("cltv_expiry") ": %" PRIu32 ",\n", p_htlc->cltv_expiry);
        printf(INDENT5 M_QQ("payhash") ": \"");
        utl_dbg_dump(stdout, p_htlc->payment_hash, BTC_SZ_HASH256, false);
        printf("\",\n");
        printf(INDENT5 M_QQ("preimage") ": \"");
        utl_dbg_dump(stdout, p_htlc->buf_payment_preimage.buf, p_htlc->buf_payment_preimage.len, false);
        printf("\",\n");
        uint8_t sha[BTC_SZ_HASH256];
        btc_md_sha256(sha, p_htlc->buf_payment_preimage.buf, p_htlc->buf_payment_preimage.len);
        printf(INDENT5 M_QQ("preimage_check") ": ");
        if (memcmp(sha, p_htlc->payment_hash, BTC_SZ_HASH256) == 0) {
            printf(M_QQ("OK") ",\n");
        } else {
            printf(M_QQ("NG") ",\n");
        }
        char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
        ln_short_channel_id_string(str_sci, p_htlc->neighbor_short_channel_id);
        printf(INDENT5 M_QQ("neighbor_short_channel_id") ": " M_QQ("%s (%016" PRIx64 ")") ",\n",
            str_sci, p_htlc->neighbor_short_channel_id);
        printf(INDENT5 M_QQ("neighbor_idx") ": %" PRIu16 ",\n", p_htlc->neighbor_idx);
        printf(INDENT5 M_QQ("onion_reason") ": \"");
        if (p_htlc->buf_onion_reason.len > 35) {
            printf("length=%d, ", p_htlc->buf_onion_reason.len);
            utl_dbg_dump(stdout, p_htlc->buf_onion_reason.buf, 35, false);
            printf("...");
        } else {
            utl_dbg_dump(stdout, p_htlc->buf_onion_reason.buf, p_htlc->buf_onion_reason.len, false);
        }
        printf("\",\n");
        printf(INDENT5 M_QQ("shared_secret") ": \"");
        utl_dbg_dump(stdout, p_htlc->buf_shared_secret.buf, p_htlc->buf_shared_secret.len, false);
        printf("\",\n");
        printf(INDENT5 M_QQ("index") ": %d\n", lp);
        printf(INDENT4 "}");
        cnt++;
    }
    printf("\n");
    printf(INDENT3 "],\n");

    printf(INDENT3 M_QQ("commit_info_local") ": {\n");
    printf(INDENT4 M_QQ("dust_limit_sat") ": %" PRIu64 ",\n", pChannel->commit_info_local.dust_limit_sat);
    printf(INDENT4 M_QQ("max_htlc_value_in_flight_msat") ": %" PRIu64 ",\n", pChannel->commit_info_local.max_htlc_value_in_flight_msat);
    printf(INDENT4 M_QQ("channel_reserve_sat") ": %" PRIu64 ",\n", pChannel->commit_info_local.channel_reserve_sat);
    printf(INDENT4 M_QQ("htlc_minimum_msat") ": %" PRIu64 ",\n", pChannel->commit_info_local.htlc_minimum_msat);
    printf(INDENT4 M_QQ("to_self_delay") ": %" PRIu16 ",\n", pChannel->commit_info_local.to_self_delay);
    printf(INDENT4 M_QQ("max_accepted_htlcs") ": %" PRIu16 ",\n", pChannel->commit_info_local.max_accepted_htlcs);
    printf(INDENT4 M_QQ("commit_txid") ": \"");
    btc_dbg_dump_txid(stdout, pChannel->commit_info_local.txid);
    printf("\",\n");
    printf(INDENT4 M_QQ("num_htlc_outputs") ": %" PRIu32 ",\n", pChannel->commit_info_local.num_htlc_outputs);
    printf(INDENT4 M_QQ("commit_num") ": %" PRIu64 ",\n", pChannel->commit_info_local.commit_num);
    if (pChannel->commit_info_local.revoke_num != (uint64_t)-1) {
        printf(INDENT4 M_QQ("revoke_num") ": %" PRIu64 "\n", pChannel->commit_info_local.revoke_num);
    } else {
        printf(INDENT4 M_QQ("revoke_num") ": null\n");
    }

    printf(INDENT3 "},\n");

    printf(INDENT3 M_QQ("commit_info_remote") ": {\n");
    printf(INDENT4 M_QQ("dust_limit_sat") ": %" PRIu64 ",\n", pChannel->commit_info_remote.dust_limit_sat);
    printf(INDENT4 M_QQ("max_htlc_value_in_flight_msat") ": %" PRIu64 ",\n", pChannel->commit_info_remote.max_htlc_value_in_flight_msat);
    printf(INDENT4 M_QQ("channel_reserve_sat") ": %" PRIu64 ",\n", pChannel->commit_info_remote.channel_reserve_sat);
    printf(INDENT4 M_QQ("htlc_minimum_msat")  ":%" PRIu64 ",\n", pChannel->commit_info_remote.htlc_minimum_msat);
    printf(INDENT4 M_QQ("to_self_delay") ": %" PRIu16 ",\n", pChannel->commit_info_remote.to_self_delay);
    printf(INDENT4 M_QQ("max_accepted_htlcs") ": %" PRIu16 ",\n", pChannel->commit_info_remote.max_accepted_htlcs);
    printf(INDENT4 M_QQ("commit_txid") ": \"");
    btc_dbg_dump_txid(stdout, pChannel->commit_info_remote.txid);
    printf("\",\n");
    printf(INDENT4 M_QQ("num_htlc_outputs") ": %" PRIu32 ",\n", pChannel->commit_info_remote.num_htlc_outputs);
    printf(INDENT4 M_QQ("commit_num") ": %" PRIu64 ",\n", pChannel->commit_info_remote.commit_num);
    if (pChannel->commit_info_remote.revoke_num != (uint64_t)-1) {
        printf(INDENT4 M_QQ("revoke_num") ": %" PRIu64 "\n", pChannel->commit_info_remote.revoke_num);
    } else {
        printf(INDENT4 M_QQ("revoke_num") ": null\n");
    }
    printf(INDENT3 "},\n");

    //addr
    if (pChannel->last_connected_addr.type == LN_ADDR_DESC_TYPE_IPV4) {
        printf(INDENT3 M_QQ("last_connected IPv4") ": \"%d.%d.%d.%d:%d\",\n",
                    pChannel->last_connected_addr.addr[0],
                    pChannel->last_connected_addr.addr[1],
                    pChannel->last_connected_addr.addr[2],
                    pChannel->last_connected_addr.addr[3],
                    pChannel->last_connected_addr.port);
    }
    printf(INDENT3 M_QQ("err") ": %d\n", pChannel->err);

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
    uint16_t type = utl_int_pack_u16be(pData);

    printf(INDENT2 "{\n");
    switch (type) {
    case MSGTYPE_CHANNEL_ANNOUNCEMENT:
        {
            ln_msg_channel_announcement_t msg;
            bool ret = ln_msg_channel_announcement_read(&msg, pData, Len);
            if (ret) {
                printf(INDENT3 M_QQ("type") ": " M_QQ("channel_announcement") ",\n");
                char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
                ln_short_channel_id_string(str_sci, msg.short_channel_id);
                printf(INDENT3 M_QQ("short_channel_id") ": " M_QQ("%s (%016" PRIx64 ")") ",\n", str_sci, msg.short_channel_id);
                printf(INDENT3 M_QQ("node1") ": \"");
                utl_dbg_dump(stdout, msg.p_node_id_1, BTC_SZ_PUBKEY, false);
                printf("\",\n");
                printf(INDENT3 M_QQ("node2") ": \"");
                utl_dbg_dump(stdout, msg.p_node_id_2, BTC_SZ_PUBKEY, false);
                printf("\"\n");
            }
        }
        break;
    case MSGTYPE_NODE_ANNOUNCEMENT:
        {
            ln_msg_node_announcement_t msg;
            ln_msg_node_announcement_addresses_t addrs;
            if (ln_msg_node_announcement_read_2(&msg, &addrs, pData, Len)) {
                printf(INDENT3 M_QQ("node") ": \"");
                utl_dbg_dump(stdout, msg.p_node_id, BTC_SZ_PUBKEY, false);
                printf("\",\n");
                char alias[LN_SZ_ALIAS_STR + 1] = {0};
                strncpy(alias, (char *)msg.p_alias, LN_SZ_ALIAS_STR);
                char esc_alias[LN_SZ_ALIAS_STR * 2 + 1];
                escape_json_string(esc_alias, alias);
                printf(INDENT3 M_QQ("alias") ": " M_QQ("%s") ",\n", esc_alias);
                printf(INDENT3 M_QQ("rgbcolor") ": \"#%02x%02x%02x\",\n", msg.p_rgb_color[0], msg.p_rgb_color[1], msg.p_rgb_color[2]);
                if (addrs.num) {
                    ln_msg_node_announcement_address_descriptor_t *addr_desc = &addrs.addresses[0];
                    if (addr_desc->type == LN_ADDR_DESC_TYPE_IPV4) {
                        char addr[50];
                        sprintf(addr, "%d.%d.%d.%d:%d",
                                addr_desc->p_addr[0],
                                addr_desc->p_addr[1],
                                addr_desc->p_addr[2],
                                addr_desc->p_addr[3],
                                addr_desc->port);
                        printf(INDENT3 M_QQ("addr") ": " M_QQ("%s") ",\n", addr);
                        printf(INDENT3 M_QQ("connect") ": \"");
                        utl_dbg_dump(stdout, msg.p_node_id, BTC_SZ_PUBKEY, false);
                        printf("@%s\",\n", addr);
                    } else {
                        printf(INDENT3 M_QQ("addrtype") ": %d,\n", addr_desc->type);
                    }
                }
                printf(INDENT3 M_QQ("timestamp") ": %" PRIu32 "\n", msg.timestamp);
            }
        }
        break;
    case MSGTYPE_CHANNEL_UPDATE:
        {
            ln_msg_channel_update_t msg;
            bool ret = ln_msg_channel_update_read(&msg, pData, Len);
            if (ret) {
                printf(INDENT3 M_QQ("type") ": " M_QQ("channel_update %d") ",\n", (msg.channel_flags & LN_CNLUPD_CHFLAGS_DIRECTION));

                char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
                ln_short_channel_id_string(str_sci, msg.short_channel_id);
                printf(INDENT3 M_QQ("short_channel_id") ": " M_QQ("%s (%016" PRIx64 ")") ",\n", str_sci, msg.short_channel_id);
                //printf(INDENT3 M_QQ("node_sort") ": " M_QQ("%s") ",\n", (msg.flags & 1) ? "second" : "first");
                printf(INDENT3 M_QQ("message_flags") ": " M_QQ("%02x") ",\n", msg.message_flags);
                printf(INDENT3 M_QQ("channel_flags") ": " M_QQ("%02x") ",\n", msg.channel_flags);
                printf(INDENT3 M_QQ("cltv_expiry_delta") ": %d,\n", msg.cltv_expiry_delta);
                printf(INDENT3 M_QQ("htlc_minimum_msat") ": %" PRIu64 ",\n", msg.htlc_minimum_msat);
                printf(INDENT3 M_QQ("fee_base_msat") ": %" PRIu32 ",\n", msg.fee_base_msat);
                printf(INDENT3 M_QQ("fee_prop_millionths") ": %" PRIu32 ",\n", msg.fee_proportional_millionths);
                printf(INDENT3 M_QQ("timestamp") ": %" PRIu32 "\n", msg.timestamp);
            }
        }
        break;
    }
    printf(INDENT2 "}");
}


/********************************************************************
 *
 ********************************************************************/

static void dumpit_channel(MDB_txn *txn, MDB_dbi dbi)
{
    //channel
    if (showflag & (SHOW_CHANNEL | SHOW_CHANNEL_WALLET | SHOW_CHANNEL_LISTCH)) {
        ln_channel_t *p_channel = (ln_channel_t *)UTL_DBG_MALLOC(sizeof(ln_channel_t));
        memset(p_channel, 0, sizeof(ln_channel_t));

        int retval = ln_lmdb_channel_load(p_channel, txn, dbi, true);
        if (retval != 0) {
            //printf(M_QQ("load") ":" M_QQ("%s"), mdb_strerror(retval));
            return;
        }
        const char *p_title;
        if (showflag & SHOW_CHANNEL) {
            p_title = "channel_info";
        }
        if (showflag & SHOW_CHANNEL_WALLET) {
            p_title = "wallet_info";
        }
        if (showflag & SHOW_CHANNEL_LISTCH) {
            p_title = "peer_node_id";
        }

        if (cnt0) {
            printf(",\n");
        } else {
            printf(INDENT1 M_QQ("%s") ": [\n", p_title);
        }

        if (showflag & SHOW_CHANNEL) {
            ln_print_channel(p_channel);
        }
        if (showflag & SHOW_CHANNEL_WALLET) {
            ln_print_wallet(p_channel);
        }
        if (showflag & SHOW_CHANNEL_LISTCH) {
            printf(INDENT2 "\"");
            utl_dbg_dump(stdout, p_channel->peer_node_id, BTC_SZ_PUBKEY, false);
            printf("\"");
        }
        ln_term(p_channel);
        UTL_DBG_FREE(p_channel);
        cnt0++;
    }
}

static void dumpit_bkchannel(MDB_txn *txn, MDB_dbi dbi)
{
    //bkchannel
    if (showflag & (SHOW_CLOSED_CH)) {
        if (cnt5) {
            printf(",\n");
        } else {
            printf(INDENT1 M_QQ("closed_channel") ": [\n");
        }
        printf(INDENT2 "{\n");
        ln_lmdb_bkchannel_show(txn, dbi);
        printf(INDENT2 "}");
        cnt5++;
    }
}

static bool dumpit_wallet_func(const ln_db_wallet_t *pWallet, void *p_param)
{
    (void)p_param;

    if (cnt6 > 0) {
        printf(",\n");
    }
    printf(INDENT1 "\"");
    btc_dbg_dump_txid(stdout, pWallet->p_txid);
    printf(":%d\": {\n", pWallet->index);
    const char *p_type_str;
    switch (pWallet->type) {
    case LN_DB_WALLET_TYPE_TO_LOCAL:
        p_type_str = "to_local output";
        break;
    case LN_DB_WALLET_TYPE_TO_REMOTE:
        p_type_str = "to_remote output";
        break;
    case LN_DB_WALLET_TYPE_HTLCOUT:
        p_type_str = "HTLC_tx output";
        break;
    default:
        p_type_str = "unknown";
    }
    printf(INDENT2 M_QQ("type") ": " M_QQ("%s") ",\n", p_type_str);
    printf(INDENT2 M_QQ("amount") ": %" PRIu64 ",\n", pWallet->amount);
    printf(INDENT2 M_QQ("sequence") ": %" PRIu32 ",\n", pWallet->sequence);
    printf(INDENT2 M_QQ("locktime") ": %" PRIu32 ",\n", pWallet->locktime);
    if (pWallet->wit_item_cnt > 0) {
        printf(INDENT2 M_QQ("privkey") ": \"");
        utl_dbg_dump(stdout, pWallet->p_wit[0].buf, pWallet->p_wit[0].len, false);
        printf("\",\n");
    }
    if (pWallet->wit_item_cnt > 1) {
        printf(INDENT2 M_QQ("witness") ": [\n");
        for (uint32_t lp = 1; lp < pWallet->wit_item_cnt; lp++) {
            if (lp > 1) {
                printf(",\n");
            }
            printf(INDENT3 "\"");
            utl_dbg_dump(stdout, pWallet->p_wit[lp].buf, pWallet->p_wit[lp].len, false);
            printf("\"");
        }
        printf("\n");
        printf(INDENT2 "]\n");
    }
    printf(INDENT1 "}\n");
    // printf("cnt=%d\n", pWallet->wit_item_cnt);
    // for (uint8_t lp = 0; lp < pWallet->wit_item_cnt; lp++) {
    //     printf("[%d][%d]", lp, pWallet->p_wit[lp].len);
    //     utl_dbg_dump(stdout, pWallet->p_wit[lp].buf, pWallet->p_wit[lp].len, true);
    // }
    cnt6++;

    return false;
}

static void dumpit_wallet(MDB_txn *txn, MDB_dbi dbi)
{
    lmdb_cursor_t cur;
    cur.cursor = NULL;
    cur.txn = txn;
    cur.dbi = dbi;
    ln_lmdb_wallet_search(&cur, dumpit_wallet_func, NULL);
}

static void dumpit_channel_anno(MDB_txn *txn, MDB_dbi dbi)
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
            case LN_DB_CNLANNO_UPD0:
                printf("channel_update 0: ");
                break;
            case LN_DB_CNLANNO_UPD1:
                printf("channel_update 1: ");
                break;
            default:
                fprintf(stderr, "keyname=%02x: %d\n", keyname[M_SZ_ANNOINFO_CNL - 1], __LINE__);
                exit(-1);
            }

            uint64_t short_channel_id;
            char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
            memcpy(&short_channel_id, key.mv_data, sizeof(short_channel_id));
            ln_short_channel_id_string(str_sci, short_channel_id);
            printf("%s\n", str_sci);
        } else if ((dbtype == LN_LMDB_DBTYPE_ANNOINFO_NODE) && (key.mv_size == M_SZ_ANNOINFO_NODE)) {
            printf("node_announcement: ");
            utl_dbg_dump(stdout, key.mv_data, M_SZ_ANNOINFO_NODE, true);
        } else {
            //skip
            continue;
        }

        int nums = data.mv_size / BTC_SZ_PUBKEY;
        const uint8_t *p_data = (const uint8_t *)data.mv_data;
        for (int lp = 0; lp < nums; lp++) {
            printf("  [%2d]", lp);
            utl_dbg_dump(stdout, p_data, BTC_SZ_PUBKEY, true);
            p_data += BTC_SZ_PUBKEY;
        }
        printf("\n");
    }
    mdb_cursor_close(cursor);
}

static void dumpit_routeskip(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag == SHOW_ROUTESKIP) {
        printf(INDENT1 M_QQ("skiproute") ": [\n");

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
            uint64_t short_channel_id;
            char str_sci[LN_SZ_SHORTCHANNELID_STR + 1];
            memcpy(&short_channel_id, key.mv_data, sizeof(short_channel_id));
            ln_short_channel_id_string(str_sci, short_channel_id);
            printf(INDENT2 "[" M_QQ("%s (%016" PRIx64 ")") ",", str_sci, short_channel_id);
            if (data.mv_size == 0) {
                printf(M_QQ("perm") "]");
            } else if (data.mv_size == 1) {
                const uint8_t *p_data = (const uint8_t *)data.mv_data;
                switch (p_data[0]) {
                case LNDB_ROUTE_SKIP_TEMP:
                    printf(M_QQ("temp") "]");
                    break;
                case LNDB_ROUTE_SKIP_WORK:
                    printf(M_QQ("work") "]");
                    break;
                default:
                    printf(M_QQ("unknown") "]");
                    break;
                }
            } else {
                printf(M_QQ("unknown") "]");
            }
            cnt++;
        }
        mdb_cursor_close(cursor);

        printf("\n" INDENT1 "]\n");
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
            utl_dbg_dump(stdout, key.mv_data, key.mv_size, false);
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
            ln_db_preimage_t preimage;
            bool detect;
            ret = ln_db_preimage_cur_get(&cur, &detect, &preimage);
            if (detect) {
                if (cnt4) {
                    printf(",");
                }
                printf("{\n");
                printf(INDENT1 "\"");
                utl_dbg_dump(stdout, preimage.preimage, LN_SZ_PREIMAGE, false);
                printf("\",\n");
                printf(INDENT1 M_QQ("amount") ": %" PRIu64 ",\n", preimage.amount_msat);
                printf(INDENT1 M_QQ("expiry") ": %" PRIu32 "\n", preimage.expiry);
                char time[UTL_SZ_TIME_FMT_STR + 1];
                printf(INDENT1 M_QQ("creation") ": %s\n", utl_time_fmt(time, preimage.creation_time));
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
        int32_t version;
        char wif[BTC_SZ_WIF_STR_MAX + 1] = "";
        char alias[LN_SZ_ALIAS_STR + 1] = "";
        uint16_t port = 0;
        uint8_t genesis[BTC_SZ_HASH256];

        printf(INDENT1 M_QQ("version") ": {\n");

        retval = ln_db_lmdb_get_mynodeid(txn, dbi, &version, wif, alias, &port, genesis);
        if (retval == 0) {
            btc_keys_t keys;
            btc_chain_t chain;
            btc_keys_wif2keys(&keys, &chain, wif);
            // printf(INDENT2 M_QQ("wif") ": " M_QQ("%s") ",\n", wif);
            // printf(INDENT2 M_QQ("node_secret") ": \"");
            // utl_dbg_dump(stdout, keys.priv, BTC_SZ_PRIVKEY, false);
            // printf("\",\n");
            printf(INDENT2 M_QQ("node_id") ": \"");
            utl_dbg_dump(stdout, keys.pub, BTC_SZ_PUBKEY, false);
            printf("\",\n");
            printf(INDENT2 M_QQ("alias") ": " M_QQ("%s") ",\n", alias);
            printf(INDENT2 M_QQ("port") ": %" PRIu16 ",\n", port);
            printf(INDENT2 M_QQ("genesis") ": \"");
            btc_dbg_dump_txid(stdout, genesis);
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
            printf(INDENT2 M_QQ("version") ": %d,\n", version);
            printf(INDENT2 M_QQ("creation_bhash") ": \"");
            btc_dbg_dump_txid(stdout, ln_creationhash_get());
            printf("\"\n");
        } else {
            printf(INDENT2 M_QQ("node_id") ": " M_QQ("fail") ",\n");
        }
        printf(INDENT1 "}\n");
    }
}

int main(int argc, char *argv[])
{
    fp_err = stderr;

    int ret;
    MDB_env     *p_env;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key;
    MDB_cursor  *cursor;
    bool loop = true;
    int opt;
#ifdef M_SPOIL_STDERR
    bool        spoil_stderr = true;
#else
    bool        spoil_stderr = false;
    utl_log_init_stdout();
#endif  //M_SPOIL_STDERR
    const struct option OPTIONS[] = {
        { "debug", no_argument, NULL, 'D' },
        { 0, 0, 0, 0 }
    };

    ln_lmdb_set_path(".");

    while ((opt = getopt_long(argc, argv, "hd:swlqcnakiWvD9:", OPTIONS, NULL)) != -1) {
        switch (opt) {
        case 'd':
            if (optarg[strlen(optarg) - 1] == '/') {
                optarg[strlen(optarg) - 1] = '\0';
            }
            ln_lmdb_set_path(optarg);
            break;
        }
    }
    optind = 0;

    ret = mdb_env_create(&mpDbChannel);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbChannel, 10);
    assert(ret == 0);
    ret = mdb_env_open(mpDbChannel, ln_lmdb_get_chnlpath(), MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", ln_lmdb_get_chnlpath());
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
    ret = mdb_env_create(&mpDbWalt);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbWalt, 10);
    assert(ret == 0);
    ret = mdb_env_open(mpDbWalt, ln_lmdb_get_waltpath(), MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", ln_lmdb_get_annopath());
        //return -1;
    }

    while (loop && ((opt = getopt_long(argc, argv, "hd:swlqcnakiWvD9:", OPTIONS, NULL)) != -1)) {
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
            showflag = SHOW_CHANNEL;
            p_env = mpDbChannel;
            break;
        case 'w':
            showflag = SHOW_CHANNEL_WALLET;
            p_env = mpDbChannel;
            break;
        case 'l':
            showflag = SHOW_CHANNEL_LISTCH;
            p_env = mpDbChannel;
            break;
        case 'q':
            showflag = SHOW_CLOSED_CH;
            p_env = mpDbChannel;
            break;
        case 'c':
            showflag = SHOW_ANNOCNL;
            p_env = mpDbAnno;
            break;
        case 'n':
            showflag = SHOW_ANNONODE;
            p_env = mpDbAnno;
            break;
        case 'a':
            showflag = SHOW_ANNOINFO;
            p_env = mpDbAnno;
            break;
        case 'k':
            showflag = SHOW_ROUTESKIP;
            p_env = mpDbNode;
            break;
        case 'i':
            showflag = SHOW_INVOICE;
            p_env = mpDbNode;
            break;
        case 'W':
            showflag = SHOW_WALLET;
            p_env = mpDbWalt;
            break;
        case 'v':
            showflag = SHOW_VERSION;
            p_env = mpDbChannel;
            break;
        case '9':
            switch (optarg[1]) {
            case '1':
                showflag = SHOW_ANNOCNL | SHOW_DEBUG;
                spoil_stderr = false;
                p_env = mpDbAnno;
                break;
            case '2':
                showflag = SHOW_ANNONODE | SHOW_DEBUG;
                spoil_stderr = false;
                p_env = mpDbAnno;
                break;
            case '3':
                showflag = SHOW_PREIMAGE;
                p_env = mpDbChannel;
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
        fprintf(stderr, "\t\t-w : 2nd layer wallet info\n");
        fprintf(stderr, "\t\t-W : 1st layer wallet info\n");
        fprintf(stderr, "\t\t-s : channel info\n");
        fprintf(stderr, "\t\t-l : channel list\n");
        fprintf(stderr, "\t\t-q : closed channel info\n");
        fprintf(stderr, "\t\t-c : channel_announcement/channel_update\n");
        fprintf(stderr, "\t\t-n : node_announcement\n");
        fprintf(stderr, "\t\t-a : (internal)announcement received/sent node_id list\n");
        fprintf(stderr, "\t\t-k : (internal)skip routing channel list\n");
        fprintf(stderr, "\t\t-i : (internal)paying invoice\n");
        return -1;
    }


    ln_lmdb_setenv(mpDbChannel, mpDbNode, mpDbAnno, mpDbWalt);

    btc_block_chain_t gtype;
    bool bret = ln_db_ver_check(NULL, &gtype);
    if (!bret) {
        fprintf(stderr, "fail: DB version not match.\n");
        return -1;
    }

    ln_genesishash_set(btc_block_get_genesis_hash(gtype));
    switch (gtype) {
    case BTC_BLOCK_CHAIN_BTCMAIN:
        btc_init(BTC_MAINNET, true);
        break;
    case BTC_BLOCK_CHAIN_BTCTEST:
    case BTC_BLOCK_CHAIN_BTCREGTEST:
        btc_init(BTC_TESTNET, true);
        break;
    default:
        fprintf(fp_err, "fail: unknown chainhash in DB\n");
        return -1;
    }

    ret = mdb_txn_begin(p_env, NULL, MDB_RDONLY, &txn);
    if (ret != 0) {
        fprintf(stderr, "fail: DB cannot open.\n");
        return -1;
    }
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
        char *name = (char *)UTL_DBG_MALLOC(key.mv_size + 1);
        memcpy(name, key.mv_data, key.mv_size);
        name[key.mv_size] = '\0';
        ret = mdb_dbi_open(txn, name, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else {
                ln_lmdb_dbtype_t dbtype = ln_lmdb_get_dbtype(name);
                switch (dbtype) {
                case LN_LMDB_DBTYPE_CHANNEL:
                    dumpit_channel(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_SECRET:
                case LN_LMDB_DBTYPE_ADD_HTLC:
                    //LN_LMDB_DBTYPE_CHANNELで読み込むので、スルー
                    break;
                case LN_LMDB_DBTYPE_BKCHANNEL:
                    dumpit_bkchannel(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_WALLET:
                    dumpit_wallet(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_ANNO_CNL:
                    dumpit_channel_anno(txn, dbi2);
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
        UTL_DBG_FREE(name);
    }
    if (cnt0 || cnt2 || cnt4 || cnt5) {
        printf("\n" INDENT1 "]\n");
    }
    if (cnt6) {
        printf("\n");
    }
    printf("}\n");
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    mdb_env_close(mpDbWalt);
    mdb_env_close(mpDbAnno);
    mdb_env_close(mpDbNode);
    mdb_env_close(mpDbChannel);
}
