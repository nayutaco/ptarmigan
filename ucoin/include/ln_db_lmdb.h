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
/** @file   ln_db_lmdb.h
 *  @brief  Lightning DB保存・復元
 *  @author ueno@nayuta.co
 */
#ifndef LN_DB_LMDB_H__
#define LN_DB_LMDB_H__

#include "lmdb.h"

#include "ln.h"

/********************************************************************
 * LMDB
 ********************************************************************/

/** node情報読込み
 *
 * @param[out]      node
 * @param[in]       txn
 * @param[in]       pdbi
 * @retval      true    成功
 */
bool ln_db_load_node(ln_node_t *node, MDB_txn *txn, MDB_dbi *pdbi);


/** node情報書込み
 *
 * @param[in]       node
 * @param[in,out]   txn
 * @param[in,out]   pdbi
 * @retval      true    成功
 */
bool ln_db_save_node(const ln_node_t *node, MDB_txn *txn, MDB_dbi *pdbi);


/** channel情報読込み
 *
 * @param[out]      self
 * @param[in]       txn
 * @param[in]       pdbi
 * @retval      true    成功
 * @attention
 *      -
 *      - 新規 self に読込を行う場合は、事前に #ln_self_ini()を行っておくこと(seedはNULLでよい)
 */
bool ln_db_load_channel(ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi);


/** channel情報書き込み
 *
 * @param[in]       self
 * @param[in,out]   txn
 * @param[in,out]   pdbi
 * @retval      true    成功
 */
bool ln_db_save_channel(const ln_self_t *self, MDB_txn *txn, MDB_dbi *pdbi);


#endif /* LN_DB_LMDB_H__ */
