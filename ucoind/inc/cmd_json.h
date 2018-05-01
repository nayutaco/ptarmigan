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
 *  @brief  ucoind JSON-RPC header
 */
#ifndef CMD_JSON_H__
#define CMD_JSON_H__

#include <inttypes.h>

/** ucoind JSON-RPC動作開始
 *
 * @param[in]   Port        監視ポート
 */
void cmd_json_start(uint16_t Port);


/**
 * @retval  ポート番号
 */
uint16_t cmd_json_get_port(void);


void cmd_json_pay_retry(const uint8_t *pPayHash, const char *pInvoice);

#endif  //CMD_JSON_H__
