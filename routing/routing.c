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
/** @file   routing.c
 *  @brief  routing計算アプリ
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <assert.h>

#define LOG_TAG     "routing"
#include "utl_log.h"
#include "utl_str.h"
#include "utl_dbg.h"

#include "btc_crypto.h"

#include "ln_routing.h"
#include "ln.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SPOIL_STDERR                      // stderrへの出力を破棄する

#define OPT_SENDER                          (0x01)  // -s指定あり
#define OPT_RECVER                          (0x02)  // -r指定あり
#define OPT_CLEARSDB                        (0x40)  // clear skip db
#define OPT_HELP                            (0x80)  // help


static FILE *fp_err;


/********************************************************************
 * external prototypes
 ********************************************************************/

void ln_lmdb_set_env(MDB_env *pEnv, MDB_env *pNode, MDB_env *pAnno, MDB_env *pWallet);


/********************************************************************
 * main entry
 ********************************************************************/

int main(int argc, char* argv[])
{
    int ret;
    bool bret;

    utl_log_init_stderr();

    fp_err = stderr;

    uint8_t send_node_id[BTC_SZ_PUBKEY];
    uint8_t recv_node_id[BTC_SZ_PUBKEY];
    uint32_t cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    uint64_t amtmsat = 0;
    bool output_json = false;
    char *payment_hash = NULL;
    ln_lmdb_set_home_dir(".");

    int opt;
    int options = 0;
    while ((opt = getopt(argc, argv, "hd:s:r:a:e:p:jc")) != -1) {
        switch (opt) {
        case 'd':
            //db directory
            ln_lmdb_set_home_dir(optarg);
            break;
        case 's':
            //sender(payer)
            bret = utl_str_str2bin(send_node_id, sizeof(send_node_id), optarg);
            if (!bret) {
                fprintf(fp_err, "invalid arg: payer node id\n");
                return -1;
            }
            options |= OPT_SENDER;
            break;
        case 'r':
            //receiver(payee)
            bret = utl_str_str2bin(recv_node_id, sizeof(recv_node_id), optarg);
            if (!bret) {
                fprintf(fp_err, "invalid arg: payee node id\n");
                return -1;
            }
            options |= OPT_RECVER;
            break;
        case 'a':
            //amount
            errno = 0;
            amtmsat = (uint64_t)strtoull(optarg, NULL, 10);
            if (errno) {
                fprintf(fp_err, "errno=%s\n", strerror(errno));
                return -1;
            }
            break;
        case 'e':
            //min_final_expiry_delta
            cltv_expiry = (uint32_t)atoi(optarg);
            break;
        case 'p':
            //payment_hash
            payment_hash = UTL_DBG_STRDUP(optarg);
            break;
        case 'j':
            //JSON
            output_json = true;
            break;
        case 'c':
            //clear skip DB
            options |= OPT_CLEARSDB;
            break;
        case 'h':
        default:
            //help
            options |= OPT_HELP;
            break;
        }
    }

    if ((options == 0) || (options & OPT_HELP)) {
        fprintf(fp_err, "usage:");
        fprintf(fp_err, "\t%s -s PAYER_NODEID -r PAYEE_NODEID [-d DB_DIR] [-a AMOUNT_MSAT] [-e MIN_FINAL_CLTV_EXPIRY] [-p PAYMENT_HASH] [-j] [-c]\n", argv[0]);
        fprintf(fp_err, "\t\t-s : sender(payer) node_id\n");
        fprintf(fp_err, "\t\t-r : receiver(payee) node_id\n");
        fprintf(fp_err, "\t\t-d : db directory\n");
        fprintf(fp_err, "\t\t-a : amount_msat\n");
        fprintf(fp_err, "\t\t-e : min_final_cltv_expiry\n");
        fprintf(fp_err, "\t\t-p : payment_hash\n");
        fprintf(fp_err, "\t\t-j : output JSON format(default: CSV format)\n");
        fprintf(fp_err, "\t\t-c : clear routing skip channel list\n");
        return -1;
    }

    if ((options & OPT_CLEARSDB) == 0) {
        if (options != (OPT_SENDER | OPT_RECVER)) {
            fprintf(fp_err, "fail: need -s and -r\n");
            return -2;
        }
        if (memcmp(send_node_id, recv_node_id, BTC_SZ_PUBKEY) == 0) {
            fprintf(fp_err, "fail: same payer and payee\n");
            return -3;
        }
        if (output_json && (payment_hash == NULL)) {
            fprintf(fp_err, "fail: need PAYMENT_HASH if JSON output\n");
            return -4;
        }
    }

#ifdef M_SPOIL_STDERR
    //stderrを捨てる
    int fd_err = dup(2);
    fp_err = fdopen(fd_err, "w");
    close(2);
#endif  //M_SPOIL_STDERR


    MDB_env     *pDbChannel = NULL;
    MDB_env     *pDbNode = NULL;
    MDB_env     *pDbAnno = NULL;

    ret = mdb_env_create(&pDbChannel);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(pDbChannel, 10);
    assert(ret == 0);
    ret = mdb_env_open(pDbChannel, ln_lmdb_get_channel_db_path(), 0, 0664);
    if (ret) {
        fprintf(fp_err, "fail: cannot open[%s]\n", ln_lmdb_get_channel_db_path());
        return -5;
    }

    ret = mdb_env_create(&pDbNode);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(pDbNode, 10);
    assert(ret == 0);
    ret = mdb_env_open(pDbNode, ln_lmdb_get_node_db_path(), 0, 0664);
    if (ret) {
        fprintf(fp_err, "fail: cannot open[%s]\n", ln_lmdb_get_node_db_path());
        return -6;
    }

    ret = mdb_env_create(&pDbAnno);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(pDbAnno, 10);
    assert(ret == 0);
    ret = mdb_env_open(pDbAnno, ln_lmdb_get_anno_db_path(), 0, 0664);
    if (ret) {
        fprintf(fp_err, "fail: cannot open[%s]\n", ln_lmdb_get_anno_db_path());
        return -6;
    }
    ln_lmdb_set_env(pDbChannel, pDbNode, pDbAnno, NULL);

    uint8_t my_node_id[BTC_SZ_PUBKEY];
    btc_block_chain_t gtype;
    bret = ln_db_version_check(my_node_id, &gtype);
    if (!bret) {
        fprintf(fp_err, "fail: DB version mismatch\n");
        return -7;
    }

    ln_genesishash_set(btc_block_get_genesis_hash(gtype));
    btc_init(gtype, true);

    if ((options & OPT_CLEARSDB) == 0) {
        ln_routing_result_t result;
        lnerr_route_t rerr = ln_routing_calculate(&result, send_node_id,
                    recv_node_id, cltv_expiry, amtmsat, 0, NULL);
        if (rerr == LNROUTE_OK) {
            //pay.conf形式の出力
            if (payment_hash == NULL) {
                //CSV形式
                printf("hop_num=%d\n", result.hop_num);
                for (int lp = 0; lp < result.hop_num; lp++) {
                    printf("route%d=", lp);
                    utl_dbg_dump(stdout, result.hop_datain[lp].pubkey, BTC_SZ_PUBKEY, false);
                    printf(",%016" PRIx64 ",%" PRIu64 ",%" PRIu32 "\n",
                                result.hop_datain[lp].short_channel_id,
                                result.hop_datain[lp].amt_to_forward,
                                result.hop_datain[lp].outgoing_cltv_value);
                }
            } else {
                //JSON形式
                //  JSON-RPCの "PAY" コマンドも付加している
                printf("{\"method\":\"PAY\",\"params\":[\"%s\",%d, [", payment_hash, result.hop_num);
                for (int lp = 0; lp < result.hop_num; lp++) {
                    if (lp != 0) {
                        printf(",\n");
                    }
                    printf("[\"");
                    utl_dbg_dump(stdout, result.hop_datain[lp].pubkey, BTC_SZ_PUBKEY, false);
                    printf("\",\"%016" PRIx64 "\",%" PRIu64 ",%" PRIu32 "]",
                                result.hop_datain[lp].short_channel_id,
                                result.hop_datain[lp].amt_to_forward,
                                result.hop_datain[lp].outgoing_cltv_value);
                }
                printf("]]}\n");
            }
            ret = 0;
        } else {
            //error
            fprintf(fp_err, "fail\n");
            ret = -9;
        }

        UTL_DBG_FREE(payment_hash);
    } else {
        ln_routing_clear_skipdb();
    }

    ln_db_term();

#ifdef M_SPOIL_STDERR
    fclose(fp_err);
#endif  //M_SPOIL_STDERR

    return ret;
}
