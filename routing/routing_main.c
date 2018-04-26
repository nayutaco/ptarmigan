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

//#define M_DEBUG
#define M_SPOIL_STDERR

#define M_SHADOW_ROUTE                      (0)     // shadow route extension
                                                    //  攪乱するためにオフセットとして加算するCLTV
                                                    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#recommendations-for-routing

#define OPT_SENDER                          (0x01)  // -s指定あり
#define OPT_RECVER                          (0x02)  // -r指定あり
#define OPT_CLEARSDB                        (0x40)  // clear skip db
#define OPT_HELP                            (0x80)  // help


static FILE *fp_err;


/********************************************************************
 * main entry
 ********************************************************************/

int main(int argc, char* argv[])
{
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

    ln_routing_result_t result;
    int ret = ln_routing_calculate(&result, send_nodeid, recv_nodeid, cltv_expiry,
                    amtmsat, payment_hash, dbdir, options & OPT_CLEARSDB);
    free(result.p_nodes);

    free(dbdir);
    free(payment_hash);

#ifdef M_SPOIL_STDERR
    fclose(fp_err);
#endif  //M_SPOIL_STDERR

    return ret;
}
