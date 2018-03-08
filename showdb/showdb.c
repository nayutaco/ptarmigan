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
#include <assert.h>

#include "ucoind.h"
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
#define SHOW_CNLANNO            (0x0004)
#define SHOW_CNLANNO_SCI        (0x0008)
#define SHOW_NODEANNO           (0x0010)
#define SHOW_NODEANNO_NODE      (0x0020)
#define SHOW_ANNOINFO           (0x0040)
#define SHOW_VERSION            (0x0080)
#define SHOW_PREIMAGE           (0x0100)
#define SHOW_ANNOSKIP           (0x0200)
#define SHOW_ANNOINVOICE        (0x0400)
#define SHOW_CLOSED_CH          (0x0800)
#define SHOW_CH                 (0x1000)

#define M_SZ_ANNOINFO_CNL       (sizeof(uint64_t) + 1)
#define M_SZ_ANNOINFO_NODE      (UCOIN_SZ_PUBKEY)

#define SHOW_DEFAULT        (SHOW_SELF)


/********************************************************************
 * prototypes
 ********************************************************************/

void ln_print_wallet(const ln_self_t *self);
void ln_print_self(const ln_self_t *self);
void ln_print_announce(const uint8_t *pData, uint16_t Len);
void ln_print_announce_short(const uint8_t *pData, uint16_t Len);
void ln_print_peerconf(FILE *fp, const uint8_t *pData, uint16_t Len);
void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_anno);


/********************************************************************
 * static variables
 ********************************************************************/

static uint16_t     showflag = SHOW_DEFAULT;
static int          cnt0;
static int          cnt1;
static int          cnt2;
static int          cnt3;
static int          cnt4;
static int          cnt5;
static MDB_env      *mpDbSelf = NULL;
static MDB_env      *mpDbNode = NULL;
static FILE         *fp_err;


/********************************************************************
 * functions
 ********************************************************************/

static void dumpit_self(MDB_txn *txn, MDB_dbi dbi)
{
    //self
    if (showflag & (SHOW_SELF | SHOW_WALLET | SHOW_CH)) {
        ln_self_t self;
        memset(&self, 0, sizeof(self));

        int retval = ln_lmdb_self_load(&self, txn, dbi);
        if (retval != 0) {
            printf(M_QQ("load") ":" M_QQ("%s"), mdb_strerror(retval));
            return;
        }
        const char *p_title;
        if (showflag & SHOW_SELF) {
            p_title = "channel_info";
        }
        if (showflag & SHOW_WALLET) {
            p_title = "wallet_info";
        }
        if (showflag & SHOW_CH) {
            p_title = "peer_node_id";
        }

        if (cnt0) {
            printf(",");
        } else {
            printf(M_QQ("%s") ": [", p_title);
        }

        if (showflag & SHOW_SELF) {
            ln_print_self(&self);
        }
        if (showflag & SHOW_WALLET) {
            ln_print_wallet(&self);
        }
        if (showflag & SHOW_CH) {
            printf("\"");
            ucoin_util_dumpbin(stdout, self.peer_node_id, UCOIN_SZ_PUBKEY, false);
            printf("\"");
        }
        ln_term(&self);
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
            printf(M_QQ("closed_self") ": [");
        }
        printf("{");
        ln_lmdb_bkself_show(txn, dbi);
        printf("}");
        cnt5++;
    }
}

static void dumpit_channel(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag & SHOW_CNLANNO) {
        if (cnt1) {
            printf(",");
        }

        MDB_cursor  *cursor;

        //ここでdbi, txnを使ってcursorを取得
        int retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        printf(M_QQ("channel_announcement_list") ": [");
        do {
            uint64_t short_channel_id;
            char type;
            uint32_t timestamp;
            ucoin_buf_t buf;

            ucoin_buf_init(&buf);
            ret = ln_lmdb_annocnl_cur_load(cursor, &short_channel_id, &type, &timestamp, &buf);
            if (ret == 0) {
                if (type == LN_DB_CNLANNO_ANNO) {
                    if (cnt1) {
                        printf("],");
                    }
                    printf("\n[\n");
                    cnt1 = 0;
                }
                if (cnt1) {
                    printf(",");
                }
                if (!(showflag & SHOW_CNLANNO_SCI)) {
                    ln_print_announce(buf.buf, buf.len);
                } else {
                    ln_print_announce_short(buf.buf, buf.len);
                }
                cnt1++;
                ucoin_buf_free(&buf);
            } else {
                //printf("end of announce\n");
            }
        } while (ret == 0);
        printf("]");
        mdb_cursor_close(cursor);
    }
}

static void dumpit_node(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag & SHOW_NODEANNO) {
        if (cnt2) {
            printf(",");
        } else {
            printf(M_QQ("node_announcement_list") ": [");
        }

        MDB_cursor  *cursor;

        //ここでdbi, txnを使ってcursorを取得
        int retval = mdb_cursor_open(txn, dbi, &cursor);
        assert(retval == 0);
        int ret;

        do {
            ucoin_buf_t buf;
            uint32_t timestamp;
            uint8_t nodeid[UCOIN_SZ_PUBKEY];

            ucoin_buf_init(&buf);
            ret = ln_lmdb_annonod_cur_load(cursor, &buf, &timestamp, nodeid);
            if (ret == 0) {
                if (cnt2) {
                    printf(",\n");
                }
                if (showflag & SHOW_NODEANNO_NODE) {
                    ln_print_announce_short(buf.buf, buf.len);
                } else {
                    ln_print_announce(buf.buf, buf.len);
                }
                ucoin_buf_free(&buf);
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
        size_t len;
        if ((dbtype == LN_LMDB_DBTYPE_CHANNEL_ANNOINFO) && (key.mv_size == M_SZ_ANNOINFO_CNL)) {
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
                assert(0);
            }
            len = M_SZ_ANNOINFO_CNL - 1;
        } else if ((dbtype == LN_LMDB_DBTYPE_NODE_ANNOINFO) && (key.mv_size == M_SZ_ANNOINFO_NODE)) {
            printf("node_announcement: ");
            len = M_SZ_ANNOINFO_NODE;
        } else {
            //skip
            continue;
        }
        ucoin_util_dumpbin(stdout, key.mv_data, len, true);

        int nums = data.mv_size / UCOIN_SZ_PUBKEY;
        const uint8_t *p_data = (const uint8_t *)data.mv_data;
        for (int lp = 0; lp < nums; lp++) {
            printf("  [%2d]", lp);
            ucoin_util_dumpbin(stdout, p_data, UCOIN_SZ_PUBKEY, true);
            p_data += UCOIN_SZ_PUBKEY;
        }
        printf("\n");
    }
    mdb_cursor_close(cursor);
}

static void dumpit_annoskip(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag == SHOW_ANNOSKIP) {
        printf(M_QQ("skiproute") ": [\n");

        MDB_cursor  *cursor;

        int retval = mdb_cursor_open(txn, dbi, &cursor);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            mdb_txn_abort(txn);
        }

        int cnt = 0;
        MDB_val key, data;
        while ((retval =  mdb_cursor_get(cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
            if (cnt > 0) {
                printf(",\n");
            }
            uint64_t short_channel_id = *(uint64_t *)key.mv_data;
            printf("\"%016" PRIx64 "\"", short_channel_id);
            cnt++;
        }
        mdb_cursor_close(cursor);

        printf("\n]");
    }
}

static void dumpit_annoinvoice(MDB_txn *txn, MDB_dbi dbi)
{
    if (showflag == SHOW_ANNOINVOICE) {
        printf(M_QQ("payinvoice") ": [\n");

        MDB_cursor  *cursor;

        int retval = mdb_cursor_open(txn, dbi, &cursor);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            mdb_txn_abort(txn);
        }

        int cnt = 0;
        MDB_val key, data;
        while ((retval =  mdb_cursor_get(cursor, &key, &data, MDB_NEXT_NODUP)) == 0) {
            if (cnt > 0) {
                printf(",\n");
            }

            printf("[\"");
            ucoin_util_dumpbin(stdout, key.mv_data, key.mv_size, false);
            printf("\",");
            printf("%s]", (const char *)data.mv_data);
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

        struct {
            MDB_txn     *txn;
            MDB_dbi     dbi;
            MDB_cursor  *cursor;
        } cur;

        int retval = mdb_cursor_open(txn, dbi, &cur.cursor);
        if (retval != 0) {
            DBG_PRINTF("err: %s\n", mdb_strerror(retval));
            mdb_txn_abort(txn);
        }

        bool ret = true;
        while (ret) {
            uint8_t preimage[LN_SZ_PREIMAGE];
            uint64_t amount;
            ret = ln_db_preimg_cur_get(&cur, preimage, &amount);
            if (ret) {
                if (cnt4) {
                    printf(",");
                }
                printf("[\"");
                ucoin_util_dumpbin(stdout, preimage, LN_SZ_PREIMAGE, false);
                printf("\", %" PRIu64 "]", amount);
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
        if (cnt3) {
            printf(",");
        }

        MDB_val key, data;

        key.mv_size = LNDBK_LEN(LNDBK_VER);
        key.mv_data = LNDBK_VER;
        int retval = mdb_get(txn, dbi, &key, &data);
        if (retval == 0) {
            int version = *(int *)data.mv_data;
            printf(M_QQ("version") ": [ %d\n", version);
        }

        key.mv_size = LNDBK_LEN(LNDBK_NODEID);
        key.mv_data = LNDBK_NODEID;
        retval = mdb_get(txn, dbi, &key, &data);
        if ((retval == 0) && (data.mv_size == UCOIN_SZ_PUBKEY)) {
            const uint8_t *p = (const uint8_t *)data.mv_data;
            printf(", \"");
            ucoin_util_dumpbin(stdout, p, UCOIN_SZ_PUBKEY, false);
            printf("\"");
        }
        cnt3++;
    }
}

int main(int argc, char *argv[])
{
    fp_err = stderr;

    int ret;
    MDB_txn     *txn;
    MDB_dbi     dbi;
    MDB_val     key;
    MDB_cursor  *cursor;
    char        selfpath[256];
    char        nodepath[256];

    strcpy(selfpath, LNDB_SELFENV);
    strcpy(nodepath, LNDB_NODEENV);

    int env = -1;
    if (argc >= 2) {
        switch (argv[1][0]) {
        case 's':
            showflag = SHOW_SELF;
            env = 0;
            break;
        case 'w':
            showflag = SHOW_WALLET;
            env = 0;
            break;
        case 'l':
            showflag = SHOW_CH;
            env = 0;
            break;
        case 'q':
            showflag = SHOW_CLOSED_CH;
            env = 0;
            break;
        case 'c':
            showflag = SHOW_CNLANNO | SHOW_CNLANNO_SCI;
            env = 1;
            break;
        case 'n':
            showflag = SHOW_NODEANNO | SHOW_NODEANNO_NODE;
            env = 1;
            break;
        case 'a':
            showflag = SHOW_ANNOINFO;
            env = 1;
            break;
        case 'k':
            showflag = SHOW_ANNOSKIP;
            env = 1;
            break;
        case 'i':
            showflag = SHOW_ANNOINVOICE;
            env = 1;
            break;
        case 'v':
            showflag = SHOW_VERSION;
            env = 0;
            break;
        case '9':
            switch (argv[1][1]) {
            case '1':
                showflag = SHOW_CNLANNO;
                env = 1;
                break;
            case '2':
                showflag = SHOW_NODEANNO;
                env = 1;
                break;
            case '3':
                showflag = SHOW_PREIMAGE;
                env = 0;
                break;
            }
            break;
        }

        if (argc >= 3) {
            if (argv[2][strlen(argv[2]) - 1] == '/') {
                argv[2][strlen(argv[2]) - 1] = '\0';
            }
            sprintf(selfpath, "%s%s", argv[2], LNDB_SELFENV_DIR);
            sprintf(nodepath, "%s%s", argv[2], LNDB_NODEENV_DIR);
        }
    } else {
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "\t%s <option> [<db dir>]\n", argv[0]);
        fprintf(stderr, "\t\tw : wallet info\n");
        fprintf(stderr, "\t\ts : self info\n");
        fprintf(stderr, "\t\tq : closed self info\n");
        fprintf(stderr, "\t\tc : channel_announcement/channel_update\n");
        fprintf(stderr, "\t\tn : node_announcement\n");
        fprintf(stderr, "\t\tv : DB version\n");
        fprintf(stderr, "\t\ta : (internal)announcement received/sent node_id list\n");
        fprintf(stderr, "\t\tk : (internal)skip routing channel list\n");
        fprintf(stderr, "\t\ti : (internal)paying invoice\n");
        return -1;
    }

    ret = mdb_env_create(&mpDbSelf);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbSelf, 5);
    assert(ret == 0);
    ret = mdb_env_open(mpDbSelf, selfpath, MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", selfpath);
        return -1;
    }
    ret = mdb_env_create(&mpDbNode);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(mpDbNode, 5);
    assert(ret == 0);
    ret = mdb_env_open(mpDbNode, nodepath, MDB_RDONLY, 0664);
    if (ret) {
        fprintf(stderr, "fail: cannot open[%s]\n", nodepath);
        return -1;
    }
    ln_lmdb_setenv(mpDbSelf, mpDbNode);

    MDB_env *p_env = (env == 0) ? mpDbSelf : mpDbNode;

    ucoin_genesis_t gtype;
    bool bret = ln_db_ver_check(NULL, &gtype);
    if (!bret) {
        fprintf(stderr, "fail: DB version not match.\n");
        return -1;
    }

    ln_set_genesishash(ucoin_util_get_genesis_block(gtype));
    switch (gtype) {
    case UCOIN_GENESIS_BTCMAIN:
        ucoin_init(UCOIN_MAINNET, true);
        break;
    case UCOIN_GENESIS_BTCTEST:
    case UCOIN_GENESIS_BTCREGTEST:
        ucoin_init(UCOIN_TESTNET, true);
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

#ifdef M_SPOIL_STDERR
    //stderrを捨てる
    int fd_err = dup(2);
    fp_err = fdopen(fd_err, "w");
    close(2);
#endif  //M_SPOIL_STDERR

    printf("{\n");
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
                const char *name = (const char *)key.mv_data;
                ln_lmdb_dbtype_t dbtype = ln_lmdb_get_dbtype(name);
                switch (dbtype) {
                case LN_LMDB_DBTYPE_SELF:
                    dumpit_self(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_ADD_HTLC:
                    //LN_LMDB_DBTYPE_SELFで読み込むので、スルー
                    break;
                case LN_LMDB_DBTYPE_BKSELF:
                    dumpit_bkself(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_CHANNEL_ANNO:
                    dumpit_channel(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_NODE_ANNO:
                    dumpit_node(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_CHANNEL_ANNOINFO:
                case LN_LMDB_DBTYPE_NODE_ANNOINFO:
                    dumpit_annoinfo(txn, dbi2, dbtype);
                    break;
                case LN_LMDB_DBTYPE_ANNO_SKIP:
                    dumpit_annoskip(txn, dbi2);
                    break;
                case LN_LMDB_DBTYPE_ANNO_INVOICE:
                    dumpit_annoinvoice(txn, dbi2);
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
    }
    if (cnt0 || cnt1 || cnt2 || cnt3 || cnt4 || cnt5) {
        printf("]");
    }
    printf("}\n");
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);

    mdb_env_close(mpDbNode);
    mdb_env_close(mpDbSelf);
}
