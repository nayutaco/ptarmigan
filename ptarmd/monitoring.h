/*
 *  Copyright (C) 2017 Ptarmigan Project
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
/** @file   monitoring.h
 *  @brief  monitoring header
 */
#ifndef MONITORING_H__
#define MONITORING_H__


#ifdef __cplusplus
extern "C" {
#endif


/********************************************************************
 * prototypes
 ********************************************************************/

/** チャネル閉鎖監視スレッド開始
 *
 * @param[in]   pArg        未使用
 * @retval      未使用
 */
void *monitor_start(void *pArg);


/** モニタループ停止
 *
 */
void monitor_stop(void);


/** チャネルありnodeへの自動接続停止設定
 *
 * @param[in]   bDisable        true:自動接続停止
 */
void monitor_disable_autoconn(bool bDisable);


/** feerate_per_kw設定
 * 次回のfeerate更新周期で使用するfeerate_per_kwを手動設定する。
 * 0を指定した場合、bitcoind estimatesmartfeeから自動計算する。
 *
 * @param[in]   FeeratePerKw    feerate_per_kw
 */
void monitor_set_feerate_per_kw(uint32_t FeeratePerKw);


bool monitor_btc_getblockcount(int32_t *pBlockCount);
uint32_t monitor_btc_feerate_per_kw(void);


/** Unilateral Close(自分が展開)
 *
 * @param[in,out]       pChannel    チャネル情報
 */
bool monitor_close_unilateral_local(ln_channel_t *pChannel);


#ifdef __cplusplus
}
#endif

#endif  //MONITORING_H__
