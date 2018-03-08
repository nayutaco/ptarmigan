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

/** @typedef    ln_db_func_cmp_t
 *  @brief      比較関数(#ln_db_self_search())
 *
 * DB内からselfを順次取得しコールバックされる。
 * trueを返すまでコールバックが続けられる。
 * 最後までfalseを返し、DBの走査が終わると、#ln_db_self_search()はfalseを返す。
 *
 * @param[in]       self            DBから取得したself
 * @param[in]       p_db_param      DB情報(ln_dbで使用する)
 * @param[in]       p_param         #ln_db_self_search()に渡したデータポインタ
 * @retval  true    比較終了(#ln_db_self_search()の戻り値もtrue)
 */
typedef bool (*ln_db_func_cmp_t)(ln_self_t *self, void *p_db_param, void *p_param);


/** @typedef    ln_db_txn_t
 *  @brief      announcement種別
 */
typedef enum {
    LN_DB_TXN_CNL,          ///< channel_announcement/channel_update
    LN_DB_TXN_NODE,         ///< node_announcement
    LN_DB_TXN_SKIP          ///< routing skip channel
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
//bool ln_db_self_load(ln_self_t *self, const uint8_t *pChannelId);


/** channel情報書き込み
 *
 * @param[in]       self
 * @retval      true    成功
 */
bool ln_db_self_save(const ln_self_t *self);


/** channel削除(channel_id指定)
 * 
 * @param[in]       pChannelId      削除するselfのchannel_id
 * @retval      true    検索成功(削除成功かどうかは判断しない)
 */
bool ln_db_self_del(const uint8_t *pChannelId);


/** channel削除(DB paramあり)
 *
 * @param[in]       self
 * @param[in,out]   p_db_param      呼び出されたコールバック関数のパラメータ
 * @retval      true    成功
 * @note
 *      - #ln_db_self_search() 経由を想定
 */
bool ln_db_self_del_prm(const ln_self_t *self, void *p_db_param);


/** channel情報検索
 *      比較関数を使用してchannel情報を検索する
 *
 * @param[in]       pFunc       検索関数
 * @param[in,out]   pFuncParam  検索関数に渡す引数
 * @retval      true    検索関数がtrueを戻した
 * @retval      false   検索関数が最後までtrueを返さなかった
 */
bool ln_db_self_search(ln_db_func_cmp_t pFunc, void *pFuncParam);


bool ln_db_self_save_closeflg(const ln_self_t *self, void *pDbParam);


////////////////////
// announcement
////////////////////

/** announcement用DBのトランザクション取得およびDBオープン
 *
 * @param[out]  ppDb        取得したDB情報(ln_dbで使用する)
 * @param[in]   Type        オープンするDB(LN_DB_TXN_xx)
 * @retval  true    成功
 */
bool ln_db_node_cur_transaction(void **ppDb, ln_db_txn_t Type);


/** #ln_db_node_cur_transaction()で取得したトランザクションのcommit
 *
 * @param[out]  pDb         #ln_db_node_cur_transaction()取得したDB情報
 */
void ln_db_node_cur_commit(void *pDb);


////////////////////
// channel_announcement
////////////////////


/** channel_announcement読込み
 *
 * @param[out]      pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
bool ln_db_annocnl_load(ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId);


/** channel_announcement書込み
 *
 * @param[in]       pCnlAnno
 * @param[in]       ShortChannelId  pCnlAnnoのshort_channel_id
 * @param[in]       pSendId         pCnlAnnoの送信元/先node_id
 * @retval      true    成功
 */
bool ln_db_annocnl_save(const ucoin_buf_t *pCnlAnno, uint64_t ShortChannelId, const uint8_t *pSendId);


/** channel_update読込み
 *
 * @param[out]      pCnlAnno            channel_updateパケット
 * @param[out]      pTimeStamp          pCnlAnnoのTimeStamp
 * @param[in]       ShortChannelId
 * @param[in]       Dir
 * @retval      true    成功
 */
bool ln_db_annocnlupd_load(ucoin_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir);


/** channel_update書込み
 *
 * @param[in]       pCnlUpd             channel_updateパケット
 * @param[in]       pUpd                channel_update構造体
 * @param[in]       pSendId             channel_updateの送信元/先ノード
 * @retval      true    成功
 */
bool ln_db_annocnlupd_save(const ucoin_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd, const uint8_t *pSendId);


/** channel_announcement削除
 *
 * @param[in]       short_channel_id
 * @retval      true    成功
 */
bool ln_db_annocnlall_del(uint64_t short_channel_id);


/** channel_announcement系の送信元/先ノード追加
 *
 * @param[in,out]   pDb
 * @param[in]       ShortChannelId
 * @param[in]       Type
 * @param[in]       bClr                true:保存したノードを削除してから追加する
 * @param[in]       pSendId             送信元/先ノード
 */
bool ln_db_annocnls_add_nodeid(void *pDb, uint64_t ShortChannelId, char Type, bool bClr, const uint8_t *pSendId);


/** node_idを含むshort_channel_id検索
 *
 * @param[in]       pNodeId1
 * @param[in]       pNodeId2
 * @retval      0以外   成功
 * @retval      0       検索失敗
 */
//uint64_t ln_db_annocnlall_search_channel_short_channel_id(const uint8_t *pNodeId1, const uint8_t *pNodeId2);


/** DB curosrオープン
 *
 * @param[out]      ppCur   curosr情報(ln_dbで使用する)
 * @param[in,out]   pDb     #ln_db_node_cur_transaction()取得したDB情報
 */
bool ln_db_annocnl_cur_open(void **ppCur, void *pDb);


/** DB curosrクローズ
 *
 * @param[in]       pCur    #ln_db_annocnl_cur_open()で取得したcursor情報
 */
void ln_db_annocnl_cur_close(void *pCur);


/** channel_announcement関連情報送信済み検索
 *
 */
bool ln_db_annocnls_search_nodeid(void *pDb, uint64_t ShortChannelId, char Type, const uint8_t *pSendId);


/** channel_announcement関連情報の順次取得
 *
 * @param[in,out]   pCur                    #ln_db_annocnl_cur_open()でオープンした*ppCur
 * @param[out]      pShortChannelId         short_channel_id
 * @param[out]      pType                   LN_DB_CNLANNO_xxx(channel_announcement / channel_update)
 * @param[out]      pTimeStamp              channel_announcementのtimestamp
 * @param[out]      pBuf                    取得したデータ(p_typeに応じて内容は変わる)
 * @retval  true    成功
 */
bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, ucoin_buf_t *pBuf);


////////////////////
// channel_announcement
////////////////////

/** "route_skip" short_channel_id登録
 *
 * @param[in]   ShortChannelId      登録するshort_channel_id
 * @retval  true    成功
 */
bool ln_db_annoskip_save(uint64_t ShortChannelId);


/** "route_skip" short_channel_id検索
 *
 * @param[in,out]   pDb                 #ln_db_node_cur_transaction()取得したDB情報
 * @param[in]       ShortChannelId      検索するshort_channel_id
 * @retval  true    検出
 */
bool ln_db_annoskip_search(void *pDb, uint64_t ShortChannelId);


/** "route_skip" DB削除
 *
 */
bool ln_db_annoskip_drop(void);


/** "routepay" invoice保存
 *
 */
bool ln_db_annoskip_invoice_save(const char *pInvoice, const uint8_t *pPayHash);


/** "routepay" invoice取得
 *
 */
bool ln_db_annoskip_invoice_load(char **ppInvoice, const uint8_t *pPayHash);


/** "routepay" 全payment_hash取得
 *
 * @attention
 *      - 内部で realloc()するため、使用後に free()すること
 */
int ln_db_annoskip_invoice_get(uint8_t **ppPayHash);


/** "routepay" invoice削除
 *
 */
bool ln_db_annoskip_invoice_del(const uint8_t *pPayHash);


/** "routepay" DB削除
 *
 */
bool ln_db_annoskip_invoice_drop(void);


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
bool ln_db_annonod_load(ucoin_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);


/** node_announcement書込み
 *
 * @param[in]       pNodeAnno       node_announcementパケット
 * @param[in]       pAnno           node_announcement構造体
 * @param[in]       pSendId         (非NULL)node_announcementの送信元/先ノード
 * @retval      true    成功
 * @note
 *      - タイムスタンプはAPI呼び出し時の値が保存される
 */
bool ln_db_annonod_save(const ucoin_buf_t *pNodeAnno, const ln_node_announce_t *pAnno, const uint8_t *pSendId);


/** node_announcement送信済み検索
 *
 */
bool ln_db_annonod_search_nodeid(void *pDb, const uint8_t *pNodeId, const uint8_t *pSendId);


/** node_announcement送信元/先ノード追加
 *
 * @param[in,out]   pDb
 * @param[in]       pNodeId
 * @param[in]       bClr                true:保存したノードを削除してから追加する
 * @param[in]       pSendId             送信元/先ノード(NULLでbClr=true時はクリアのみ行う)
 */
bool ln_db_annonod_add_nodeid(void *pDb, const uint8_t *pNodeId, bool bClr, const uint8_t *pSendId);


/** #ln_db_annonod_cur_get()用DB cursorオープン
 *
 *
 */
bool ln_db_annonod_cur_open(void **ppCur, void *pDb);


/** #ln_db_annonod_cur_get()用DB cursorクローズ
 *
 *
 */
void ln_db_annonod_cur_close(void *pCur);

/** node_announcement順次取得
 *
 * @param[in,out]   pCur            #ln_db_annonod_cur_open()でオープンしたDB cursor
 * @param[out]      pBuf            node_announcementパケット
 * @param[out]      pTimeStamp      保存時刻
 * @param[out]      pNodeId         node_announcementのnode_id
 * @retval      true    成功
 */
bool ln_db_annonod_cur_get(void *pCur, ucoin_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId);


////////////////////
// payment_preimage
////////////////////

/** preimage保存
 *
 * @param[in]       pPreImage
 * @param[in]       Amount
 * @param[in,out]   pDb
 * @retval  true
 */
bool ln_db_preimg_save(const uint8_t *pPreImage, uint64_t Amount, void *pDb);


/** preimage削除
 *
 * @param[in]       pPreImage
 * @retval  true
 */
bool ln_db_preimg_del(const uint8_t *pPreImage);


/** preimage削除(payment_hash検索)
 *
 * @param[in]       pPreImageHash
 * @retval  true
 */
bool ln_db_preimg_del_hash(const uint8_t *pPreImageHash);


/** preimage curosrオープン
 *
 * @param[in,out]   ppCur
 * @retval  true
 */
bool ln_db_preimg_cur_open(void **ppCur);


/** preimage cursorクローズ
 *
 * @param[in]       pCur
 * @retval  true
 */
void ln_db_preimg_cur_close(void *pCur);


/** preimage取得
 *
 * @param[in]       pCur
 * @param[out]      pPreImage
 * @param[out]      pAmount
 * @retval  true
 */
bool ln_db_preimg_cur_get(void *pCur, uint8_t *pPreImage, uint64_t *pAmount);


#ifdef LN_UGLY_NORMAL
////////////////////
// payment_hash
////////////////////

/** payment_hash保存
 *
 * @param[in]       pPayHash        保存するpayment_hash
 * @param[in]       pVout           pPayHashを含むvoutスクリプトを#ucoin_sw_wit2prog_p2wsh()した結果。大きさはLNL_SZ_WITPROG_WSH。
 * @param[in]       Type            pVout先のHTLC種別(LN_HTLCTYPE_OFFERED / LN_HTLCTYPE_RECEIVED)
 * @param[in]       Expiry          Expiry
 * @retval  true
 */
bool ln_db_phash_save(const uint8_t *pPayHash, const uint8_t *pVout, ln_htlctype_t Type, uint32_t Expiry);


/** payment_hash検索
 *
 * @param[out]      pPayHash        保存するpayment_hash
 * @param[out]      pType           pVoutのHTLC種別(LN_HTLCTYPE_OFFERED / LN_HTLCTYPE_RECEIVED)
 * @param[out]      pExpiry         Expiry
 * @param[in]       pVout           検索するvout
 * @param[in,out]   pDbParam        DBパラメータ
 * @retval  true
 */
bool ln_db_phash_search(uint8_t *pPayHash, ln_htlctype_t *pType, uint32_t *pExpiry, const uint8_t *pVout, void *pDbParam);

#endif  //LN_UGLY_NORMAL


////////////////////
// revoked transaction close
////////////////////

/** revoked transaction情報読込み
 *
 * @param[in,out]   self
 * @param[in,out]   pDbParam
 * @retval  true        .
 */
bool ln_db_revtx_load(ln_self_t *self, void *pDbParam);


/** revoked transaction情報保存
 *
 * @param[in]       self
 * @param[in]       bUpdate
 * @param[in,out]   pDbParam
 * @retval  true        .
 */
bool ln_db_revtx_save(const ln_self_t *self, bool bUpdate, void *pDbParam);


////////////////////
// version
////////////////////

/** DB version check
 *
 * @param[out]      pMyNodeId       (非NULL時)node_id
 * @param[out]      pGType          (非NULL時)genesis hash type
 * @retval  true    チェックOK
 */
bool ln_db_ver_check(uint8_t *pMyNodeId, ucoin_genesis_t *pGType);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_DB_H__ */
