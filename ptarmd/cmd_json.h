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
/** @file   cmd_json.h
 *  @brief  ptarmd JSON-RPC header
 */
#ifndef CMD_JSON_H__
#define CMD_JSON_H__

#include <inttypes.h>

/** ptarmd JSON-RPC動作開始
 *
 * @param[in]   Port        監視ポート
 */
void cmd_json_start(uint16_t Port);


/** ptarmd JSON-RPC動作停止
 * 
 */
void cmd_json_stop(void);


/** ノード接続
 *
 * @param[in]       pNodeId     接続先ノードID
 * @param[in]       pIpAddr     接続先IPv4
 * @param[in]       Port        接続先ポート番号
 * @return  Linuxエラーコード
 */
int cmd_json_connect(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port);


/** 送金依頼
 *
 * @param[in]       pInvoice        (NULL時はDBから取得)
 * @param[in]       AddAmountMsat   (pInvoiceがNULL時はDBから取得)
 * @return  Linuxエラーコード
 */
int cmd_json_pay(const char *pInvoice, uint64_t AddAmountMsat);

/** 再送
 *
 * @param[in]       pPayHash
 * @return  Linuxエラーコード
 */
int cmd_json_pay_retry(const uint8_t *pPayHash);

#endif  //CMD_JSON_H__
