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
#include <assert.h>


#define UCOIN_USE_PRINTFUNC
#include "ucoind.h"
#include "ln_db_lmdb.h"


#define M_LMDB_ENV              "./dbucoin"

static MDB_env      *mpDbEnv = NULL;
static uint8_t my_node_id[UCOIN_SZ_PUBKEY];
static char my_alias[LN_SZ_ALIAS];
static uint8_t node_ids[LN_NODE_MAX][UCOIN_SZ_PUBKEY];
static char alias[LN_NODE_MAX][LN_SZ_ALIAS];


static void dumpbin(const uint8_t *pData, uint16_t Len)
{
    for (uint16_t lp = 0; lp < Len; lp++) {
        printf("%02x", pData[lp]);
    }
    printf("\n");
}


static void print_wallet(const ln_self_t *self)
{
    printf("===========================\n");
    printf("my node_id(%s): ", my_alias);
    dumpbin(my_node_id, UCOIN_SZ_PUBKEY);
    printf("peer node_id(%s): ", alias[self->node_idx]);
    dumpbin(node_ids[self->node_idx], UCOIN_SZ_PUBKEY);
    printf("short_channel_id= %" PRIx64 "\n", self->short_channel_id);
    printf("===========================\n");
    printf("our_msat  = %16" PRIu64 "\n", self->our_msat);
    printf("their_msat= %16" PRIu64 "\n", self->their_msat);
    printf("channel_id= ");
    dumpbin(self->channel_id, LN_SZ_CHANNEL_ID);
    printf("htlc_num= %d\n", self->htlc_num);
    printf("===========================\n");
}


/* Dump in BDB-compatible format */
static int dumpit(MDB_txn *txn, MDB_dbi dbi, const char *name, bool full)
{
    MDB_stat ms;
    MDB_envinfo info;
    unsigned int flags;
    int rc;

    rc = mdb_dbi_flags(txn, dbi, &flags);
    if (rc) {
        return rc;
    }

    rc = mdb_stat(txn, dbi, &ms);
    if (rc) {
        return rc;
    }

    rc = mdb_env_info(mdb_txn_env(txn), &info);
    if (rc) {
        return rc;
    }

    bool channel;
    if (name) {
        channel = (memcmp(name, "cnl_", 4) == 0);
        if (full) {
            printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
            printf("database: [%s]\n", name);
            printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n\n");
        }
    } else {
        channel = false;
    }

    if (channel) {
        //self
        ln_self_t self;
        memset(&self, 0, sizeof(self));

        ln_db_load_channel(&self, txn, &dbi);
        if (full) {
            ln_print_self(&self);
        } else {
            print_wallet(&self);
        }
        ln_term(&self);
    } else {
        //node
        ln_node_t node;
        memset(&node, 0, sizeof(node));

        ln_db_load_node(&node, txn, &dbi);

        if (full) {
            ln_print_node(&node);
        }
        memcpy(my_node_id, node.keys.pub, UCOIN_SZ_PUBKEY);
        strcpy(my_alias, node.alias);
        //dumpbin(my_node_id, UCOIN_SZ_PUBKEY);
        for (int lp = 0; lp < LN_NODE_MAX; lp++) {
            memcpy(node_ids[lp], node.node_info[lp].node_id, UCOIN_SZ_PUBKEY);
            strcpy(alias[lp], node.node_info[lp].alias);
        }
        ln_node_term(&node);
    }

    return 0;
}


int main(int argc, char *argv[])
{
    int ret;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key;
    MDB_cursor  *cursor;
    bool full;

    if (argc == 2) {
        full = false;
    } else {
        full = true;
    }

    ret = mdb_env_create(&mpDbEnv);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbEnv, 2);
    assert(ret == 0);
    ret = mdb_env_open(mpDbEnv, M_LMDB_ENV, MDB_RDONLY, 0664);
    assert(ret == 0);

    ret = mdb_txn_begin(mpDbEnv, NULL, MDB_RDONLY, &txn);
    assert(ret == 0);
    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    assert(ret == 0);

    ret = mdb_cursor_open(txn, dbi, &cursor);
    assert(ret == 0);

    int list = 0;
    while ((ret = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi db2;
        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        ret = mdb_open(txn, key.mv_data, 0, &db2);
        if (ret == 0) {
            if (list) {
                printf("[%s]\n", (const char *)key.mv_data);
                list++;
            } else {
                ret = dumpit(txn, db2, key.mv_data, full);
                if (ret) {
                    break;
                }
            }
            mdb_close(mpDbEnv, db2);
        }
    }
    mdb_cursor_close(cursor);
    mdb_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);
    mdb_env_close(mpDbEnv);
}
