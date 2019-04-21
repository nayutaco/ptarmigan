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
/** @file   ln_commit_info.h
 *  @brief  ln_commit_info
 */
#ifndef LN_COMMIT_INFO_H__
#define LN_COMMIT_INFO_H__

#include <stdint.h>
#include <stdbool.h>


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct ln_commit_info_t
 *  @brief  commitment transaction info
 */
typedef struct {
    uint64_t            dust_limit_sat;                 ///< dust_limit_satoshis
    uint64_t            max_htlc_value_in_flight_msat;  ///< max_htlc_value_in_flight_msat
    uint64_t            channel_reserve_sat;            ///< channel_reserve_satoshis
    uint64_t            htlc_minimum_msat;              ///< htlc_minimum_msat
    uint16_t            to_self_delay;                  ///< to_self_delay
    uint16_t            max_accepted_htlcs;             ///< max_accepted_htlcs

    uint8_t             remote_sig[LN_SZ_SIGNATURE];    ///< remote's signature
                                                        // localには相手に送信する署名
                                                        // remoteには相手から受信した署名
    uint8_t             txid[BTC_SZ_TXID];              ///< txid
    uint16_t            num_htlc_outputs;               ///< commit_tx中のHTLC数
    uint64_t            commit_num;                     ///< commitment_number
                                                        //      commit_info_local:  commitment_signed受信後、インクリメント
                                                        //      commit_info_remote: commitment_signed送信後、インクリメント
    uint64_t            revoke_num;                     ///< 最後にrevoke_and_ack送信した時のcommitment_number
                                                        //      commit_info_local:  revoke_and_ack送信後、commit_info_local.commit_num - 1を代入
                                                        //      commit_info_remote: revoke_and_ack受信後、pChannel->commit_info_remote.commit_num - 1を代入
    uint64_t            local_msat;
    uint64_t            remote_msat;

    uint64_t            obscured_commit_num_mask;       ///< commitment numberをXORするとobscured commitment numberになる値。
    ln_funding_info_t   *p_funding_info;
} ln_commit_info_t;


#endif /* LN_COMMIT_INFO_H__ */
