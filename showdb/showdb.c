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
/** @file   sohwdb.c
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
#include <assert.h>


#define UCOIN_USE_PRINTFUNC
#include "ucoind.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"


#define M_LMDB_ENV              "./dbucoin"

#define MSGTYPE_CHANNEL_ANNOUNCEMENT        ((uint16_t)0x0100)
#define MSGTYPE_NODE_ANNOUNCEMENT           ((uint16_t)0x0101)
#define MSGTYPE_CHANNEL_UPDATE              ((uint16_t)0x0102)
#define MSGTYPE_ANNOUNCEMENT_SIGNATURES     ((uint16_t)0x0103)



void ln_print_announce(const uint8_t *pData, uint16_t Len);
void ln_print_announce_short(const uint8_t *pData, uint16_t Len);


static MDB_env      *mpDbEnv = NULL;

#define SHOW_SELF               0x01
#define SHOW_WALLET             0x02
#define SHOW_CNLANNO            0x04
#define SHOW_CNLANNO_SCI        0x08
#define SHOW_NODEANNO           0x10
#define SHOW_NODEANNO_NODE      0x20

#define SHOW_DEFAULT        (SHOW_SELF)
static uint8_t      showflag = SHOW_DEFAULT;


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
    printf("short_channel_id= %016" PRIx64 "\n", self->short_channel_id);
    printf("----------------\n");
    printf("our_msat  = %-10" PRIu64 "\n", self->our_msat);
    printf("their_msat= %-10" PRIu64 "\n", self->their_msat);
    printf("channel_id= ");
    dumpbin(self->channel_id, LN_SZ_CHANNEL_ID);
    printf("htlc_num= %d\n", self->htlc_num);
    printf("===========================\n");
}




/* Dump in BDB-compatible format */
static int dumpit(MDB_txn *txn, MDB_dbi dbi, const MDB_val *p_key)
{
    const char *name = (const char *)p_key->mv_data;
    int retval;

    int dbtype = -1;
    //printf("[[%s]](%d)\n", name, p_key->mv_size);
    if (strcmp(name, "channel_anno") == 0) {
        //channel_announcement
        dbtype = 1;
    } else if (strcmp(name, "node_anno") == 0) {
        //node_announcement
        dbtype = 2;
    } else if (p_key->mv_size == LN_SZ_SHORT_CHANNEL_ID * 2) {
        //self
        dbtype = 0;
    } else {
        //
    }

    ln_self_t self;
    switch (dbtype) {
    case 0:
        //self
        memset(&self, 0, sizeof(self));

        retval = ln_lmdb_load_channel(&self, txn, &dbi);
        assert(retval == 0);
        if (showflag & SHOW_SELF) {
            ln_print_self(&self);
        }
        if (showflag & SHOW_WALLET) {
            print_wallet(&self);
        }
        ln_term(&self);
        break;

    case 1:
        if (showflag & SHOW_CNLANNO) {
            printf("channel announcement list\n");

            MDB_dbi     dbi;
            MDB_cursor  *cursor;

            //ここでdbi, txnを使ってcursorを取得
            retval = mdb_dbi_open(txn, name, 0, &dbi);
            assert(retval == 0);
            retval = mdb_cursor_open(txn, dbi, &cursor);
            assert(retval == 0);
            int ret;

            do {
                uint64_t short_channel_id;
                char type;
                ucoin_buf_t buf;

                ucoin_buf_init(&buf);
                ret = ln_lmdb_load_anno_channel_cursor(cursor, &short_channel_id, &type, &buf);
                if (ret == 0) {
                    switch (type) {
                    case LN_DB_CNLANNO_SINFO:
                        printf("----------------------------------\n");
                        printf("[[channel send info]]");
                        break;
                    case LN_DB_CNLANNO_ANNO:
                        printf("[[channel_announcement]]");
                        break;
                    case LN_DB_CNLANNO_UPD1:
                        printf("[[channel_update node1]]");
                        break;
                    case LN_DB_CNLANNO_UPD2:
                        printf("[[channel_update node2]]");
                        break;
                    default:
                        assert(0);
                    }
                    printf("  short_channel_id=%016" PRIx64 "\n", short_channel_id);
                    if (type != LN_DB_CNLANNO_SINFO) {
                        if (!(showflag & SHOW_CNLANNO_SCI)) {
                            ln_print_announce(buf.buf, buf.len);
                        } else {
                            ln_print_announce_short(buf.buf, buf.len);
                        }
                    } else {
                        ln_db_channel_sinfo *p_sinfo = (ln_db_channel_sinfo *)buf.buf;
                        if (!(showflag & SHOW_CNLANNO_SCI)) {
                            printf("    sinfo: channel_announcement : %" PRIu32 "\n", p_sinfo->channel_anno);
                            printf("    sinfo: channel_update(1)    : %" PRIu32 "\n", p_sinfo->channel_upd[0]);
                            printf("    sinfo: channel_update(2)    : %" PRIu32 "\n", p_sinfo->channel_upd[1]);
                        }
                        printf("    sinfo: send_nodeid: ");
                        dumpbin(p_sinfo->send_nodeid, UCOIN_SZ_PUBKEY);
                    }
                } else {
                    //printf("end of announce\n");
                }
            } while (ret == 0);
            mdb_cursor_close(cursor);
            mdb_close(mpDbEnv, dbi);
        }
        break;
    case 2:
        if (showflag & SHOW_NODEANNO) {
            printf("node announcement list\n");
            printf("----------------------------------\n");

            MDB_dbi     dbi;
            MDB_cursor  *cursor;

            //ここでdbi, txnを使ってcursorを取得
            retval = mdb_dbi_open(txn, name, 0, &dbi);
            assert(retval == 0);
            retval = mdb_cursor_open(txn, dbi, &cursor);
            assert(retval == 0);
            int ret;

            do {
                ucoin_buf_t buf;
                uint32_t timestamp;
                uint8_t send_nodeid[UCOIN_SZ_PUBKEY];
                uint8_t nodeid[UCOIN_SZ_PUBKEY];

                ucoin_buf_init(&buf);
                ret = ln_lmdb_load_anno_node_cursor(cursor, &buf, &timestamp, send_nodeid, nodeid);
                if (ret == 0) {
                    if (!(showflag & SHOW_NODEANNO_NODE)) {
                        ln_print_announce(buf.buf, buf.len);
                    } else {
                        printf("[%lu]", (unsigned long)timestamp);
                        dumpbin(nodeid, UCOIN_SZ_PUBKEY);
                    }
                } else {
                    //printf("end of announce\n");
                }
            } while (ret == 0);
            mdb_cursor_close(cursor);
            mdb_close(mpDbEnv, dbi);
        }
        break;
    default:
        printf("dbtype=%d\n", dbtype);
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
    char        dbpath[50];

    strcpy(dbpath, M_LMDB_ENV);

    if (argc >= 2) {
        switch (argv[1][0]) {
        case '0':
            showflag = SHOW_SELF;
            break;
        case '1':
            showflag = SHOW_WALLET;
            break;
        case '2':
            showflag = SHOW_CNLANNO;
            break;
        case '3':
            showflag = SHOW_CNLANNO | SHOW_CNLANNO_SCI;
            break;
        case '4':
            showflag = SHOW_NODEANNO;
            break;
        case '5':
            showflag = SHOW_NODEANNO | SHOW_NODEANNO_NODE;
            break;
        }

        if (argc >= 3) {
            strcpy(dbpath, argv[2]);
        }
    }

    ret = mdb_env_create(&mpDbEnv);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbEnv, 2);
    assert(ret == 0);
    ret = mdb_env_open(mpDbEnv, dbpath, MDB_RDONLY, 0664);
    assert(ret == 0);

    ret = mdb_txn_begin(mpDbEnv, NULL, MDB_RDONLY, &txn);
    assert(ret == 0);
    ret = ln_lmdb_check_version(txn);
    assert(ret == 0);
    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    assert(ret == 0);

    ret = mdb_cursor_open(txn, dbi, &cursor);
    assert(ret == 0);

    int list = 0;
    while ((ret = mdb_cursor_get(cursor, &key, NULL, MDB_NEXT_NODUP)) == 0) {
        MDB_dbi dbi2;
        if (memchr(key.mv_data, '\0', key.mv_size)) {
            continue;
        }
        ret = mdb_open(txn, key.mv_data, 0, &dbi2);
        if (ret == 0) {
            if (list) {
                list++;
            } else {
                ret = dumpit(txn, dbi2, &key);
                if (ret) {
                    break;
                }
            }
            mdb_close(mpDbEnv, dbi2);
        }
    }
    mdb_cursor_close(cursor);
    mdb_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);
    mdb_env_close(mpDbEnv);
}
