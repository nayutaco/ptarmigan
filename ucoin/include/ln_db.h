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
/** @file   ln_db.h
 *  @brief  Lightning DB保存・復元
 *  @author ueno@nayuta.co
 */
#ifndef LN_DB_H__
#define LN_DB_H__

#include "ln.h"


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/********************************************************************
 * macros
 ********************************************************************/

#define LN_DB_CNLANNO_SINFO         '0'     ///< channel_announcement用KEYの末尾: sendinfo
#define LN_DB_CNLANNO_ANNO          '1'     ///< channel_announcement用KEYの末尾: channel_announcement
#define LN_DB_CNLANNO_UPD1          '2'     ///< channel_announcement用KEYの末尾: channel_update 1
#define LN_DB_CNLANNO_UPD2          '3'     ///< channel_announcement用KEYの末尾: channel_update 2


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    uint32_t        channel_anno;
    uint32_t        channel_upd[2];                 //0:node_1, 1:node_2
    uint8_t         send_nodeid[UCOIN_SZ_PUBKEY];   //channel_announcement送信元node_id
} ln_db_channel_sinfo;


/** 比較関数 #ln_db_search_channel()
 *
 * @param[in]       self
 * @param[in]       p_db_param      db
 * @param[in]       p_param
 * @retval  true    比較終了(戻り値もtrue)
 */
typedef bool (*ln_db_func_cmp_t)(ln_self_t *self, void *p_db_param, void *p_param);


/********************************************************************
 * prototypes
 ********************************************************************/

/** db終了
 *
 */
void ln_db_term(void);


////////////////////
// self
////////////////////

/** channel情報読込み
 *
 * @param[out]      self
 * @param[in]       pChannelId
 * @retval      true    成功
 * @attention
 *      -
 *      - 新規 self に読込を行う場合は、事前に #ln_self_ini()を行っておくこと(seedはNULLでよい)
 */
//bool ln_db_load_channel(ln_self_t *self, const uint8_t *pChannelId);


/** channel情報書き込み
 *
 * @param[in]       self
 * @retval      true    成功
 */
bool ln_db_save_channel(const ln_self_t *self);


/** channel削除
 *
 * @param[in]       self
 * @param[in,out]   p_db_param      呼び出されたコールバック関数のパラメータ
 * @retval      true    成功
 */
bool ln_db_del_channel(const ln_self_t *self, void *p_db_param);


/** channel情報検索
 *      比較関数を使用してchannel情報を検索する
 *
 * @param[in]       pFunc       検索関数
 * @param[in,out]   pFuncParam  検索関数に渡す引数
 * @retval      true    検索関数がtrueを戻した
 * @retval      false   検索関数が最後までtrueを返さなかった
 */
bool ln_db_search_channel(ln_db_func_cmp_t pFunc, void *pFuncParam);


////////////////////
// channel_announcement
////////////////////

/** channel_announcement読込み
 *
 * @param[out]      pCnlAnno
 * @param[in]       short_channel_id
 * @retval      true    成功
 */
bool ln_db_load_anno_channel(ucoin_buf_t *pCnlAnno, uint64_t short_channel_id);


/** channel_announcement書込み
 *
 * @param[in]       pCnlAnno
 * @param[in]       CnlSci      pCnlAnnoのshort_channel_id
 * @param[in]       pNodeId     pCnlAnnoの送信元node_id
 * @retval      true    成功
 */
bool ln_db_save_anno_channel(const ucoin_buf_t *pCnlAnno, uint64_t CnlSci, const uint8_t *pNodeId);


/** channel_update読込み
 *
 * @param[out]      pCnlAnno
 * @param[in]       short_channel_id
 * @param[in]       Dir
 * @retval      true    成功
 */
bool ln_db_load_anno_channel_upd(ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir);


/** channel_update書込み
 *
 * @param[in]       pCnlAnno
 * @param[in]       short_channel_id
 * @param[in]       Dir
 * @retval      true    成功
 */
bool ln_db_save_anno_channel_upd(const ucoin_buf_t *pCnlUpd, uint64_t short_channel_id, uint8_t Dir);


/** node_idを含むshort_channel_id検索
 *
 * @param[in]       pNodeId1
 * @param[in]       pNodeId2
 * @retval      0以外   成功
 * @retval      0       検索失敗
 */
uint64_t ln_db_search_channel_short_channel_id(const uint8_t *pNodeId1, const uint8_t *pNodeId2);


/**
 *
 */
bool ln_db_cursor_anno_channel_open(void **ppCur);


/**
 *
 */
void ln_db_cursor_anno_channel_close(void *pCur);


/**
 *
 */
bool ln_db_cursor_anno_channel_get(void *pCur, uint64_t *p_short_channel_id, char *p_type, ucoin_buf_t *pBuf);


/**
 *
 */
void ln_db_cursor_anno_sinfo(void *pCur, uint64_t short_channel_id, ln_db_channel_sinfo *pSInfo);


////////////////////
// node_announcement
////////////////////

/** node_announcement読込み
 *
 * @param[out]      pNodeAnno       node_announcement(NULL時は無視)
 * @param[out]      pTimeStamp      保存時間(NULL時は無視)
 * @param[out]      pSendId         送信元ノード(NULL時は無視)
 * @param[in]       pNodeId         検索するnode_id
 * @retval      true    成功
 */
bool ln_db_load_anno_node(ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, uint8_t *pSendId, const uint8_t *pNodeId, void *pDbParam);


/** node_announcement書込み
 *
 * @param[in]       pNodeAnno       node_announcement
 * @param[in]       pSendId         送信元ノード
 * @param[in]       pNodeId         node_id
 * @retval      true    成功
 * @note
 *      - タイムスタンプは呼び出し時になる
 */
bool ln_db_save_anno_node(const ucoin_buf_t *pNodeAnno, const uint8_t *pSendId, const uint8_t *pNodeId);


/**
 *
 *
 */
bool ln_db_cursor_anno_node_open(void **ppCur);


/**
 *
 *
 */
void ln_db_cursor_anno_node_close(void *pCur);

/**
 *
 *
 */
bool ln_db_cursor_anno_node_get(void *pCur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pSendId, uint8_t *pNodeId);


////////////////////
// payment_preimage
////////////////////

bool ln_db_save_preimage(const uint8_t *pPreImage, uint64_t Amount, void *pDbParam);
bool ln_db_del_preimage(const uint8_t *pPreImage);
bool ln_db_cursor_preimage_open(void **ppCur);
void ln_db_cursor_preimage_close(void *pCur);
bool ln_db_cursor_preimage_get(void *pCur, uint8_t *pPreImage, uint64_t *pAmount);


#ifdef LN_UGLY_NORMAL
////////////////////
// payment_hash
////////////////////

/** payment_hash保存
 *
 * @param[in]       pPayHash        保存するpayment_hash
 * @param[in]       pVout           pPayHashを含むvout
 * @param[in]       Type            pVout先のHTLC種別(LN_HTLCTYPE_OFFERED / LN_HTLCTYPE_RECEIVED)
 * @param[in]       Expiry          Expiry
 * @param[in,out]   pDbParam        DBパラメータ
 */
bool ln_db_save_payhash(const uint8_t *pPayHash, const uint8_t *pVout, ln_htlctype_t Type, uint32_t Expiry, void *pDbParam);


/** payment_hash検索
 *
 * @param[out]      pPayHash        保存するpayment_hash
 * @param[out]      pType           pVoutのHTLC種別(LN_HTLCTYPE_OFFERED / LN_HTLCTYPE_RECEIVED)
 * @param[out]      pExpiry         Expiry
 * @param[in]       pVout           検索するvout
 * @param[in,out]   pDbParam        DBパラメータ
 */
bool ln_db_search_payhash(uint8_t *pPayHash, ln_htlctype_t *pType, uint32_t *pExpiry, const uint8_t *pVout, void *pDbParam);

#endif  //LN_UGLY_NORMAL


////////////////////
// revoked transaction close
////////////////////

bool ln_db_load_revoked(ln_self_t *self, void *pDbParam);
bool ln_db_save_revoked(const ln_self_t *self, bool bUpdate, void *pDbParam);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_DB_H__ */
