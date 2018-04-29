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
/** @file   routing_main.cpp
 *  @brief  routing計算アプリ
 *  @author ueno@nayuta.co
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>

#include "ln.h"
#include "ln_db.h"
#include "ln_db_lmdb.h"

#include "misc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define M_SPOIL_STDERR                      // stderrへの出力を破棄する

#define M_SHADOW_ROUTE                      (0)     // shadow route extension
                                                    //  攪乱するためにオフセットとして加算するCLTV
                                                    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#recommendations-for-routing

#define OPT_SENDER                          (0x01)  // -s指定あり
#define OPT_RECVER                          (0x02)  // -r指定あり
#define OPT_CLEARSDB                        (0x40)  // clear skip db
#define OPT_HELP                            (0x80)  // help


static FILE *fp_err;


/********************************************************************
 * external prototypes
 ********************************************************************/

void ln_lmdb_setenv(MDB_env *p_env, MDB_env *p_anno);


/********************************************************************
 * main entry
 ********************************************************************/

int main(int argc, char* argv[])
{
    int ret;
    bool bret;

    fp_err = stderr;

    uint8_t send_nodeid[UCOIN_SZ_PUBKEY];
    uint8_t recv_nodeid[UCOIN_SZ_PUBKEY];
    uint32_t cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    uint64_t amtmsat = 0;
    bool output_json = false;
    char *payment_hash = NULL;
    char *dbdir = strdup(LNDB_DBDIR);

    int opt;
    int options = 0;
    while ((opt = getopt(argc, argv, "hd:s:r:a:e:p:jc")) != -1) {
        switch (opt) {
        case 'd':
            //db directory
            free(dbdir);
            dbdir = strdup(optarg);
            break;
        case 's':
            //sender(payer)
            bret = misc_str2bin(send_nodeid, sizeof(send_nodeid), optarg);
            if (!bret) {
                fprintf(fp_err, "invalid arg: payer node id\n");
                return -1;
            }
            options |= OPT_SENDER;
            break;
        case 'r':
            //receiver(payee)
            bret = misc_str2bin(recv_nodeid, sizeof(recv_nodeid), optarg);
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
            payment_hash = strdup(optarg);
            break;
        case 'j':
            //JSON
            output_json = true;
            break;
        case 'c':
            //clear skip DB
            options |= OPT_CLEARSDB;
            return 0;
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
            return -1;
        }
        if (memcmp(send_nodeid, recv_nodeid, UCOIN_SZ_PUBKEY) == 0) {
            fprintf(fp_err, "fail: same payer and payee\n");
            return -1;
        }
        if (output_json && (payment_hash == NULL)) {
            fprintf(fp_err, "fail: need PAYMENT_HASH if JSON output\n");
            return -1;
        }
    }

    cltv_expiry += M_SHADOW_ROUTE;

#ifdef M_SPOIL_STDERR
    //stderrを捨てる
    int fd_err = dup(2);
    fp_err = fdopen(fd_err, "w");
    close(2);
#endif  //M_SPOIL_STDERR


    MDB_env     *pDbSelf = NULL;
    MDB_env     *pDbNode = NULL;
    char        selfpath[256];
    char        nodepath[256];

    strcpy(selfpath, dbdir);
    size_t len = strlen(selfpath);
    if (selfpath[len - 1] == '/') {
        selfpath[len - 1] = '\0';
    }
    strcpy(nodepath, selfpath);
    strcat(selfpath, LNDB_SELFENV_DIR);
    strcat(nodepath, LNDB_NODEENV_DIR);

    ret = mdb_env_create(&pDbSelf);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(pDbSelf, 10);
    assert(ret == 0);
    ret = mdb_env_open(pDbSelf, selfpath, MDB_RDONLY, 0664);
    if (ret) {
        fprintf(fp_err, "fail: cannot open[%s]\n", selfpath);
        return -2;
    }

    ret = mdb_env_create(&pDbNode);
    assert(ret == 0);
    ret = mdb_env_set_maxdbs(pDbNode, 10);
    assert(ret == 0);
    ret = mdb_env_open(pDbNode, nodepath, 0, 0664);
    if (ret) {
        fprintf(fp_err, "fail: cannot open[%s]\n", nodepath);
        return -2;
    }
    ln_lmdb_setenv(pDbSelf, pDbNode);

    uint8_t my_nodeid[UCOIN_SZ_PUBKEY];
    ucoin_genesis_t gtype;
    bret = ln_db_ver_check(my_nodeid, &gtype);
    if (!bret) {
        fprintf(fp_err, "fail: DB version mismatch\n");
        return -3;
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
        return -4;
    }

    if ((options & OPT_CLEARSDB) == 0) {
        ln_routing_result_t result;
        ret = ln_routing_calculate(&result, send_nodeid, recv_nodeid, cltv_expiry,
                        amtmsat);
        if (ret == 0) {
            //pay.conf形式の出力
            if (payment_hash == NULL) {
                //CSV形式
                printf("hop_num=%d\n", result.hop_num);
                for (int lp = 0; lp < result.hop_num; lp++) {
                    printf("route%d=", lp);
                    ucoin_util_dumpbin(stdout, result.hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY, false);
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
                    ucoin_util_dumpbin(stdout, result.hop_datain[lp].pubkey, UCOIN_SZ_PUBKEY, false);
                    printf("\",\"%016" PRIx64 "\",%" PRIu64 ",%" PRIu32 "]",
                                result.hop_datain[lp].short_channel_id,
                                result.hop_datain[lp].amt_to_forward,
                                result.hop_datain[lp].outgoing_cltv_value);
                }
                printf("]]}\n");
            }
        } else {
            //error
            fprintf(fp_err, "fail: %d\n", ret);
        }

        free(dbdir);
        free(payment_hash);
    } else {
        ln_routing_clear_skipdb();
    }

    ln_db_term();

#ifdef M_SPOIL_STDERR
    fclose(fp_err);
#endif  //M_SPOIL_STDERR

    return ret;
}
