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

#define LN_DB_CNLANNO_ANNO          'A'     ///< channel_announcement用KEYの末尾: channel_announcement
#define LN_DB_CNLANNO_UPD1          'B'     ///< channel_announcement用KEYの末尾: channel_update 1
#define LN_DB_CNLANNO_UPD2          'C'     ///< channel_announcement用KEYの末尾: channel_update 2


/**************************************************************************
 * typedefs
 **************************************************************************/

/** 比較関数 #ln_db_search_channel()
 *
 * @param[in]       self
 * @param[in]       p_db_param      db
 * @param[in]       p_param
 * @retval  true    比較終了(#ln_db_search_channel()の戻り値もtrue)
 */
typedef bool (*ln_db_func_cmp_t)(ln_self_t *self, void *p_db_param, void *p_param);


typedef enum {
    LN_DB_TXN_CNL,
    LN_DB_TXN_NODE
} ln_db_txn_t;


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
// announcement
////////////////////

bool ln_db_cursor_anno_transaction(void **ppDb, ln_db_txn_t Type);
void ln_db_cursor_anno_commit(void *pDb);


////////////////////
// channel_announcement
////////////////////


/** channel_announcement読込み
 *
 * @param[out]      pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
bool ln_db_load_anno_channel(ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId);


/** channel_announcement書込み
 *
 * @param[in]       pCnlAnno
 * @param[in]       ShortChannelId  pCnlAnnoのshort_channel_id
 * @param[in]       pSendId         pCnlAnnoの送信元/先node_id
 * @retval      true    成功
 */
bool ln_db_save_anno_channel(const ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId, const uint8_t *pSendId);


/** channel_update読込み
 *
 * @param[out]      pCnlAnno            channel_updateパケット
 * @param[out]      pTimeStamp          pCnlAnnoのTimeStamp
 * @param[in]       ShortChannelId
 * @param[in]       Dir
 * @retval      true    成功
 */
bool ln_db_load_anno_channel_upd(ucoin_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir);


/** channel_update書込み
 *
 * @param[in]       pCnlUpd             channel_updateパケット
 * @param[in]       pUpd                channel_update構造体
 * @param[in]       pSendId             channel_updateの送信元/先ノード
 * @retval      true    成功
 */
bool ln_db_save_anno_channel_upd(const ucoin_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd, const uint8_t *pSendId);


/** channel_announcement削除
 *
 * @param[in]       short_channel_id
 * @retval      true    成功
 */
bool ln_db_del_anno_channel(uint64_t short_channel_id);


/** channel_announcement系の送信元/先ノード追加
 *
 * @param[in,out]   pDb
 * @param[in]       ShortChannelId
 * @param[in]       Type
 * @param[in]       pSendId             送信元/先ノード
 */
bool ln_db_channel_anno_add_nodeid(void *pDb, uint64_t ShortChannelId, char Type, const uint8_t *pSendId);


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
bool ln_db_cursor_anno_channel_open(void **ppCur, void *pDb);


/**
 *
 */
void ln_db_cursor_anno_channel_close(void *pCur);


/** channel_announcement関連情報送信済み検索
 *
 */
bool ln_db_channel_anno_search_nodeid(void *pDb, uint64_t ShortChannelId, char Type, const uint8_t *pSendId);


/** channel_announcement関連情報の順次取得
 *
 * @param[in,out]   pCur                    #ln_db_cursor_anno_channel_open()でオープンした*ppCur
 * @param[out]      pShortChannelId         short_channel_id
 * @param[out]      pType                   LN_DB_CNLANNO_xxx(channel_announcement / channel_update)
 * @param[out]      pTimeStamp              channel_announcementのtimestamp
 * @param[out]      pBuf                    取得したデータ(p_typeに応じて内容は変わる)
 * @retval  true    成功
 */
bool ln_db_cursor_anno_channel_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, ucoin_buf_t *pBuf);


////////////////////
// node_announcement
////////////////////

/** node_announcement読込み
 *
 * @param[out]      pNodeAnno       node_announcement(NULL時は無視)
 * @param[out]      pTimeStamp      node_announcementのtimestamp(NULL時は無視)
 * @param[in]       pNodeId         検索するnode_id
 * @retval      true    成功
 */
bool ln_db_load_anno_node(ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId, void *pDbParam);


/** node_announcement書込み
 *
 * @param[in]       pNodeAnno       node_announcementパケット
 * @param[in]       pAnno           node_announcement構造体
 * @param[in]       pSendId         (非NULL)node_announcementの送信元/先ノード
 * @retval      true    成功
 * @note
 *      - タイムスタンプはAPI呼び出し時の値が保存される
 */
bool ln_db_save_anno_node(const ucoin_buf_t *pNodeAnno, const ln_node_announce_t *pAnno, const uint8_t *pSendId);


/** node_announcement送信済み検索
 *
 */
bool ln_db_node_anno_search_nodeid(void *pDb, const uint8_t *pNodeId, const uint8_t *pSendId);


/** node_announcement送信元/先ノード追加
 *
 * @param[in,out]   pDb
 * @param[in]       pNodeId
 * @param[in]       pSendId             送信元/先ノード
 */
bool ln_db_node_anno_add_nodeid(void *pDb, const uint8_t *pNodeId, const uint8_t *pSendId);


/** #ln_db_cursor_anno_node_get()用DB cursorオープン
 *
 *
 */
bool ln_db_cursor_anno_node_open(void **ppCur, void *pDb);


/** #ln_db_cursor_anno_node_get()用DB cursorクローズ
 *
 *
 */
void ln_db_cursor_anno_node_close(void *pCur);

/** node_announcement順次取得
 *
 * @param[in,out]   pCur            #ln_db_cursor_anno_node_open()でオープンしたDB cursor
 * @param[out]      pBuf            node_announcementパケット
 * @param[out]      pTimeStamp      保存時刻
 * @param[out]      pNodeId         node_announcementのnode_id
 * @retval      true    成功
 */
bool ln_db_cursor_anno_node_get(void *pCur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId);


////////////////////
// payment_preimage
////////////////////

bool ln_db_save_preimage(const uint8_t *pPreImage, uint64_t Amount, void *pDbParam);
bool ln_db_del_preimage(const uint8_t *pPreImage);
bool ln_db_del_preimage_hash(const uint8_t *pPreImageHash);
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
