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

#include "ucoind.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"


#define M_LMDB_ENV              "./dbucoin"

#define MSGTYPE_CHANNEL_ANNOUNCEMENT        ((uint16_t)0x0100)
#define MSGTYPE_NODE_ANNOUNCEMENT           ((uint16_t)0x0101)
#define MSGTYPE_CHANNEL_UPDATE              ((uint16_t)0x0102)
#define MSGTYPE_ANNOUNCEMENT_SIGNATURES     ((uint16_t)0x0103)

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_STR(item,value)   M_QQ(item) ":" M_QQ(value)
#define M_VAL(item,value)   M_QQ(item) ":" value


void ln_print_wallet(const ln_self_t *self);
void ln_print_self(const ln_self_t *self);
void ln_print_announce(const uint8_t *pData, uint16_t Len);
void ln_print_announce_short(const uint8_t *pData, uint16_t Len);
void ln_print_peerconf(FILE *fp, const uint8_t *pData, uint16_t Len);
void ln_lmdb_setenv(MDB_env *p_env);



#define SHOW_SELF               (0x0001)
#define SHOW_WALLET             (0x0002)
#define SHOW_CNLANNO            (0x0004)
#define SHOW_CNLANNO_SCI        (0x0008)
#define SHOW_NODEANNO           (0x0010)
#define SHOW_NODEANNO_NODE      (0x0020)
#define SHOW_NODEANNO_PEER      (0x0040)
#define SHOW_VERSION            (0x0080)
#define SHOW_PREIMAGE           (0x0100)

#define SHOW_DEFAULT        (SHOW_SELF)

static uint16_t     showflag = SHOW_DEFAULT;
static int          cnt0;
static int          cnt1;
static int          cnt2;
static int          cnt3;
static int          cnt4;
static MDB_env      *mpDbEnv = NULL;


// https://github.com/lightningnetwork/lightning-rfc/issues/237
// https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
static const uint8_t M_BTC_GENESIS_MAIN[] = {
    // bitcoin mainnet
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_TEST[] = {
    // bitcoin testnet
    0x43, 0x49, 0x7f, 0xd7, 0xf8, 0x26, 0x95, 0x71,
    0x08, 0xf4, 0xa3, 0x0f, 0xd9, 0xce, 0xc3, 0xae,
    0xba, 0x79, 0x97, 0x20, 0x84, 0xe9, 0x0e, 0xad,
    0x01, 0xea, 0x33, 0x09, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t M_BTC_GENESIS_REGTEST[] = {
    // bitcoin regtest
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59,
    0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f,
    0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
};


/* Dump in BDB-compatible format */
static int dumpit(MDB_txn *txn, MDB_dbi dbi, const MDB_val *p_key)
{
    const char *name = (const char *)p_key->mv_data;
    int retval;

    ln_lmdb_dbtype_t dbtype = ln_lmdb_get_dbtype(name);

    ln_self_t self;
    switch (dbtype) {
    case LN_LMDB_DBTYPE_SELF:
        //self
        if (showflag & (SHOW_SELF | SHOW_WALLET)) {
            if (cnt0) {
                printf(",");
            } else {
                printf(M_QQ("channel_info") ": [");
            }

            memset(&self, 0, sizeof(self));

            retval = ln_lmdb_load_channel(&self, txn, &dbi);
            assert(retval == 0);
            if (showflag & SHOW_SELF) {
                ln_print_self(&self);
            }
            if (showflag & SHOW_WALLET) {
                ln_print_wallet(&self);
            }
            ln_term(&self);
            cnt0++;
        }
        break;

    case LN_LMDB_DBTYPE_SHARED_SECRET:
        //shared secret
        if (showflag & (SHOW_SELF | SHOW_WALLET)) {
            retval = mdb_dbi_open(txn, name, 0, &dbi);
            assert(retval == 0);

            MDB_val key, data;

            for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
                key.mv_size = sizeof(int);
                key.mv_data = &lp;
                retval = mdb_get(txn, dbi, &key, &data);
                if (retval != 0) {
                    break;
                }
                //fprintf(stderr, "[%d] %lu\n", lp, data.mv_size);
            }
        }
        break;

    case LN_LMDB_DBTYPE_CHANNEL_ANNO:
        if (showflag & SHOW_CNLANNO) {
            if (cnt1) {
                printf(",");
            } else {
                printf(M_QQ("channel_announcement_list") ": [");
            }

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
                    if (type == LN_DB_CNLANNO_SINFO) {
                        if (cnt1) {
                            printf(",\n[\n");
                        } else {
                            printf("[\n");
                        }
                    }
                    //switch (type) {
                    //case LN_DB_CNLANNO_SINFO:
                    //    printf("----------------------------------\n");
                    //    printf("[[channel send info]]");
                    //    break;
                    //case LN_DB_CNLANNO_ANNO:
                    //    printf("[[channel_announcement]]");
                    //    break;
                    //case LN_DB_CNLANNO_UPD1:
                    //    printf("[[channel_update node1]]");
                    //    break;
                    //case LN_DB_CNLANNO_UPD2:
                    //    printf("[[channel_update node2]]");
                    //    break;
                    //default:
                    //    assert(0);
                    //}
                    //printf("  short_channel_id=%016" PRIx64 "\n", short_channel_id);
                    if (type != LN_DB_CNLANNO_SINFO) {
                        if (!(showflag & SHOW_CNLANNO_SCI)) {
                            ln_print_announce(buf.buf, buf.len);
                        } else {
                            ln_print_announce_short(buf.buf, buf.len);
                        }
                    } else {
                        //ln_db_channel_sinfo *p_sinfo = (ln_db_channel_sinfo *)buf.buf;
                        //if (!(showflag & SHOW_CNLANNO_SCI)) {
                        //    printf("    sinfo: channel_announcement : %" PRIu32 "\n", p_sinfo->channel_anno);
                        //    printf("    sinfo: channel_update(1)    : %" PRIu32 "\n", p_sinfo->channel_upd[0]);
                        //    printf("    sinfo: channel_update(2)    : %" PRIu32 "\n", p_sinfo->channel_upd[1]);
                        //}
                        //printf("    sinfo: send_nodeid: ");
                        //ucoin_util_dumpbin(stdout, p_sinfo->send_nodeid, UCOIN_SZ_PUBKEY, true);
                    }
                    if (type == LN_DB_CNLANNO_UPD2) {
                        printf("]");
                    }
                    cnt1++;
                } else {
                    //printf("end of announce\n");
                }
            } while (ret == 0);
            mdb_cursor_close(cursor);
            mdb_close(mpDbEnv, dbi);
        }
        break;

    case LN_LMDB_DBTYPE_NODE_ANNO:
        if (showflag & SHOW_NODEANNO) {
            if (!(showflag & SHOW_NODEANNO_PEER)) {
                if (cnt2) {
                    printf(",");
                } else {
                    printf(M_QQ("node_announcement_list") ": [");
                }
            }

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
                    if (!(showflag & SHOW_NODEANNO_PEER)) {
                        if (cnt2) {
                            printf(",\n");
                        }
                    }
                    if (showflag & SHOW_NODEANNO_PEER) {
                        char fname[100];
                        strcpy(fname, "peer_");
                        misc_bin2str(fname + 5, nodeid, sizeof(nodeid));
                        strcat(fname, ".conf");
                        FILE *fp = fopen(fname, "w");
                        ln_print_peerconf(fp, buf.buf, buf.len);
                        fclose(fp);
                    } else if (showflag & SHOW_NODEANNO_NODE) {
                        ln_print_announce_short(buf.buf, buf.len);
                    } else {
                        ln_print_announce(buf.buf, buf.len);
                    }
                    cnt2++;
                } else {
                    //printf("end of announce\n");
                }
            } while (ret == 0);
            mdb_cursor_close(cursor);
            mdb_close(mpDbEnv, dbi);
        }
        break;

    case LN_LMDB_DBTYPE_PREIMAGE:
        if (showflag == SHOW_PREIMAGE) {
            printf(M_QQ("preimage") ": [");

            struct {
                MDB_txn     *txn;
                MDB_dbi     dbi;
                MDB_cursor  *cursor;
            } cur;

            retval = mdb_cursor_open(txn, dbi, &cur.cursor);
            if (retval != 0) {
                DBG_PRINTF("err: %s\n", mdb_strerror(retval));
                mdb_txn_abort(txn);
            }

            bool ret = true;
            while (ret) {
                uint8_t preimage[LN_SZ_PREIMAGE];
                uint64_t amount;
                ret = ln_db_cursor_preimage_get(&cur, preimage, &amount);
                if (ret) {
                    if (cnt4) {
                        printf(",");
                    }
                    printf("[\"");
                    for (int lp = 0; lp < LN_SZ_PREIMAGE; lp++) {
                        printf("%02x", preimage[lp]);
                    }
                    printf("\", %" PRIu64 "]", amount);
                    cnt4++;
                }
            }
            mdb_cursor_close(cur.cursor);
        }
        break;

    case LN_LMDB_DBTYPE_VERSION:
        //version
        if (showflag == SHOW_VERSION) {
            if (cnt3) {
                printf(",");
            }

            MDB_dbi     dbi;
            retval = mdb_dbi_open(txn, name, 0, &dbi);
            if (retval == 0) {
                MDB_val key, data;

                key.mv_size = 3;
                key.mv_data = "ver";
                retval = mdb_get(txn, dbi, &key, &data);
                if (retval == 0) {
                    int version = *(int *)data.mv_data;
                    printf(M_QQ("version") ": [ %d\n", version);
                }

                key.mv_size = 8;
                key.mv_data = "mynodeid";
                retval = mdb_get(txn, dbi, &key, &data);
                if ((retval == 0) && (data.mv_size == UCOIN_SZ_PUBKEY)) {
                    const uint8_t *p = (const uint8_t *)data.mv_data;
                    printf(", \"");
                    for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
                        printf("%02x", p[lp]);
                    }
                    printf("\"");
                }
            }
            cnt3++;
        }
        break;

    default:
        break;
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

    if (argc >= 3) {
        switch (argv[2][0]) {
        case 's':
            showflag = SHOW_SELF;
            break;
        case 'w':
            showflag = SHOW_WALLET;
            break;
        case 'c':
            showflag = SHOW_CNLANNO | SHOW_CNLANNO_SCI;
            break;
        case 'n':
            showflag = SHOW_NODEANNO | SHOW_NODEANNO_NODE;
            break;
        case 'p':
            showflag = SHOW_NODEANNO | SHOW_NODEANNO_PEER;
            break;
        case 'v':
            showflag = SHOW_VERSION;
            break;
        case '9':
            switch (argv[2][1]) {
            case '1':
                showflag = SHOW_CNLANNO;
                break;
            case '2':
                showflag = SHOW_NODEANNO;
                break;
            case '3':
                showflag = SHOW_PREIMAGE;
                break;
            }
            break;
        }

        if (argc >= 4) {
            strcpy(dbpath, argv[3]);
        }
    } else {
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "\t%s [mainnet/testnet] [option] [db dir]\n", argv[0]);
        fprintf(stderr, "\t\twallet  : show wallet info\n");
        fprintf(stderr, "\t\tself    : show self info\n");
        fprintf(stderr, "\t\tchannel : show channel info\n");
        fprintf(stderr, "\t\tnode    : show node info\n");
        fprintf(stderr, "\t\tversion : version\n");
        return -1;
    }

    if (strcmp(argv[1], "mainnet") == 0) {
        ln_set_genesishash(M_BTC_GENESIS_MAIN);
    } else if (strcmp(argv[1], "testnet") == 0) {
        ln_set_genesishash(M_BTC_GENESIS_TEST);
    } else if (strcmp(argv[1], "regtest") == 0) {
        ln_set_genesishash(M_BTC_GENESIS_REGTEST);
    } else {
        fprintf(stderr, "mainnet or testnet only[%s]\n", argv[1]);
        return -1;
    }

    ret = mdb_env_create(&mpDbEnv);
    assert(ret == 0);
    ln_lmdb_setenv(mpDbEnv);
    ret = mdb_env_set_maxdbs(mpDbEnv, 2);
    assert(ret == 0);
    ret = mdb_env_open(mpDbEnv, dbpath, MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", dbpath);
        return -1;
    }

    ret = mdb_txn_begin(mpDbEnv, NULL, MDB_RDONLY, &txn);
    assert(ret == 0);
    ret = ln_lmdb_check_version(txn, NULL);
    assert(ret == 0);
    ret = mdb_dbi_open(txn, NULL, 0, &dbi);
    assert(ret == 0);

    ret = mdb_cursor_open(txn, dbi, &cursor);
    assert(ret == 0);

    if (!(showflag & SHOW_NODEANNO_PEER)) {
        printf("{\n");
    }
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
    if (!(showflag & SHOW_NODEANNO_PEER)) {
        if (cnt0 || cnt1 || cnt2 || cnt3 || cnt4) {
            printf("]");
        }
        printf("}\n");
    }
    mdb_cursor_close(cursor);
    mdb_close(mpDbEnv, dbi);
    mdb_txn_abort(txn);
    mdb_env_close(mpDbEnv);
}
