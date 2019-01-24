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
/** @file   ln_local.h
 *  @brief  [LN]内部管理用
 */
#ifndef LN_LOCAL_H__
#define LN_LOCAL_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "mbedtls/sha256.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/ecp.h"

#include "ln.h"
#define LOG_TAG "LN"
#include "utl_log.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define HIDDEN __attribute__((visibility("hidden")))
#define CONST_CAST      /* const外しキャストを検索しやすくするため */

//0～5は、open_channel/accept_channelのfunding_pubkey～first_per_commitment_pointの順にすること
//プロトコルで違いが生じた場合は、ソースを変更すること(ln_msg_establish.c)
#define MSG_FUNDIDX_FUNDING             (0)         ///< commitment tx署名用
#define MSG_FUNDIDX_REVOCATION          (1)         ///< revocation_basepoint
#define MSG_FUNDIDX_PAYMENT             (2)         ///< payment_basepoint
#define MSG_FUNDIDX_DELAYED             (3)         ///< delayed_payment_basepoint
#define MSG_FUNDIDX_HTLC                (4)         ///< htlc_basepoint
#define MSG_FUNDIDX_PER_COMMIT          (5)         ///< per_commitment_point
                                                    ///<    commitment_signedの際には、next_per_commitment_pointを入れる。
                                                    ///<    funding_created/funding_signedの際には、fist_per_commitment_pointを入れる。
                                                    ///<    unilateral closeの際には、現在のper_commitment_pointを入れる。
                                                    ///<    revoked transaction closeの際には、該当するper_commitment_pointを入れる。
#define MSG_FUNDIDX_MAX                 (MSG_FUNDIDX_PER_COMMIT+1)
#if LN_FUNDIDX_MAX != MSG_FUNDIDX_MAX
#error LN_FUNDIDX_MAX != MSG_FUNDIDX_MAX
#endif

//MSG_FUNDIDX_PER_COMMITを使用してスクリプトを作成する
#define MSG_SCRIPTIDX_REMOTEKEY         (0)         ///< remotekey
#define MSG_SCRIPTIDX_DELAYED           (1)         ///< delayedkey
#define MSG_SCRIPTIDX_REVOCATION        (2)         ///< revocationkey
#define MSG_SCRIPTIDX_LOCALHTLCKEY      (3)         ///< local_htlckey
#define MSG_SCRIPTIDX_REMOTEHTLCKEY     (4)         ///< remote_htlckey
#define MSG_SCRIPTIDX_MAX               (MSG_SCRIPTIDX_REMOTEHTLCKEY+1)
#if LN_SCRIPTIDX_MAX != MSG_SCRIPTIDX_MAX
#error LN_SCRIPTIDX_MAX != MSG_SCRIPTIDX_MAX
#endif

#define CHANNEL_FLAGS_ANNOCNL       (1 << 0)
#define CHANNEL_FLAGS_MASK          CHANNEL_FLAGS_ANNOCNL   ///< open_channel.channel_flagsのBOLT定義あり
#define CHANNEL_FLAGS_VALUE         CHANNEL_FLAGS_ANNOCNL   ///< TODO:open_channel.channel_flags

// https://github.com/lightningnetwork/lightning-rfc/blob/master/03-transactions.md#per-commitment-secret-requirements
#define LN_SECINDEX_INIT            ((uint64_t)0xffffffffffff)      ///< per-commitment secret生成用indexの初期値




/**************************************************************************
 * static variables(ln.c)
 **************************************************************************/

extern uint8_t HIDDEN gGenesisChainHash[BTC_SZ_HASH256];


//blockhash at node creation
//      usage: search blockchain limit
extern uint8_t HIDDEN gCreationBlockHash[BTC_SZ_HASH256];


/**************************************************************************
 * prototypes(ln.c)
 **************************************************************************/

/** revoked transaction close用のスクリプトバッファ確保
 *
 */
void HIDDEN ln_revoked_buf_alloc(ln_self_t *self);


/** revoked transaction close用のスクリプトバッファ解放
 *
 */
void HIDDEN ln_revoked_buf_free(ln_self_t *self);


/**************************************************************************
 * prototypes(ln_db_lmdb.c)
 **************************************************************************/

/** DBで保存している対象のデータだけコピーする
 *
 * @param[out]  pOutSelf    コピー先
 * @param[in]   pInSelf     コピー元
 */
void HIDDEN ln_db_copy_channel(ln_self_t *pOutSelf, const ln_self_t *pInSelf);

#endif /* LN_LOCAL_H__ */
