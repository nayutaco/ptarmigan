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

#define LN_DB_WALLET_TYPE_TOLOCAL   ((uint8_t)1)
#define LN_DB_WALLET_TYPE_TOREMOTE  ((uint8_t)2)
#define LN_DB_WALLET_TYPE_HTLCOUT   ((uint8_t)3)

#define LN_DB_WALLET_INIT(t)        { t/*type*/, NULL/*p_txid*/, 0/*index*/, 0/*amount*/, 0/*sequence*/, 0/*locktime*/, 0/*wit_item_cnt*/, NULL/*p_wit*/ }


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @typedef    ln_db_routeskip_t
 *  @brief      result ln_db_routeskip_search()
 */
typedef enum {
    LN_DB_ROUTESKIP_NONE,       ///< not found
    LN_DB_ROUTESKIP_TEMP,       ///< found: temporary skip
    LN_DB_ROUTESKIP_PERM,       ///< found: permanentry skip
    LN_DB_ROUTESKIP_WORK,       ///< low priority channel
    LN_DB_ROUTESKIP_ERROR       ///< DB error
} ln_db_routeskip_t;


/** @typedef    ln_db_cur_t
 *  @brief      cursorオープンするannouncement種別
 */
typedef enum {
    LN_DB_CUR_CNL,              ///< channel_announcement/channel_update
    LN_DB_CUR_NODE,             ///< node_announcement
    LN_DB_CUR_INFOCNL,          ///< channel_announcement/channel_update送信済み
    LN_DB_CUR_INFONODE,         ///< node_announcement送信済み
} ln_db_cur_t;


/** @typedef    ln_db_preimg_t
 *  @brief      preimage/invoice
 */
typedef struct {
    uint8_t     preimage[LN_SZ_PREIMAGE];
    uint64_t    amount_msat;
    uint64_t    creation_time;
    uint32_t    expiry;
} ln_db_preimg_t;


/** @typedef    ln_db_wallet_t
 *  @brief      ln_db_wallet
 *  @note
 *      - 変更した場合は、以下も変更すること
 *          - LN_DB_WALLET_INIT
 *          - ln_db_wallet_search()
 *          - ln_db_wallet_tの使用箇所
 */
typedef struct {
    uint8_t     type;                       ///< DBからの読み出し時のみ使用(LN_DB_WALLET_TYPE_xxx)
    uint8_t     *p_txid;                    ///< outpoint
    uint32_t    index;                      ///< outpoint
    uint64_t    amount;                     ///< satoshis
    uint32_t    sequence;                   ///< <sequence>
    uint32_t    locktime;                   ///< <locktime>
    uint32_t    wit_item_cnt;
    utl_buf_t   *p_wit;                     ///< p_wit[wit_item_cnt]
} ln_db_wallet_t;


/** @typedef    ln_db_func_cmp_t
 *  @brief      比較関数(#ln_db_self_search())
 *
 * DB内からselfを順次取得しコールバックされる(同期処理)。
 * trueを返すまでコールバックが続けられる。
 * 最後までfalseを返し、DBの走査が終わると、#ln_db_self_search()はfalseを返す。
 *
 * @param[in]       self            DBから取得したself
 * @param[in]       p_db_param      DB情報(ln_dbで使用する)
 * @param[in]       p_param         #ln_db_self_search()に渡したデータポインタ
 * @retval  true    比較終了(#ln_db_self_search()の戻り値もtrue)
 * @retval  false   比較継続
 */
typedef bool (*ln_db_func_cmp_t)(ln_self_t *self, void *p_db_param, void *p_param);


/** @typedef    ln_db_func_preimg_t
 *  @brief      比較関数(#ln_db_preimg_search())
 *
 * @param[in]       self            DBから取得したself
 * @param[in]       p_db_param      DB情報(ln_dbで使用する)
 * @param[in]       p_param         #ln_db_preimg_search()に渡したデータポインタ
 * @retval  true    比較終了
 * @retval  false   比較継続
 */
typedef bool (*ln_db_func_preimg_t)(const uint8_t *pPreImage, uint64_t Amount, uint32_t Expiry, void *p_db_param, void *p_param);


/** @typedef    ln_db_func_wallet_t
 *  @brief      比較関数(#ln_db_wallet_search())
 *
 * @param[in]       self            DBから取得したself
 * @param[in]       p_param         #ln_db_wallet_search()に渡したデータポインタ
 * @retval  true    比較終了
 * @retval  false   比較継続
 */
typedef bool (*ln_db_func_wallet_t)(const ln_db_wallet_t *pWallet, void *p_param);


/********************************************************************
 * prototypes
 ********************************************************************/

/** DB初期化
 *
 * DBを使用できるようにする。
 * また、新規の場合は引数をDBに書き込み、新規でない場合にはDBから読込む
 *
 * @param[in,out]   pWif            ノードの秘密鍵
 * @param[in,out]   pNodeName       ノード名
 * @param[in,out]   pPort           ポート番号
 * @param[in]       bStdErr         エラーをstderrに出力
 * @retval  true    初期化成功
 */
bool ln_db_init(char *pWif, char *pNodeName, uint16_t *pPort, bool bStdErr);


/** db終了
 *
 */
void ln_db_term(void);


/**　DBディレクトリの存在チェック
 *
 * @retval  true    カレントディレクトリにDBディレクトリがある
 */
bool ln_db_have_dbdir(void);


/********************************************************************
 * self
 ********************************************************************/

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
 * @note
 *      - 戻り値がtrueの場合、検索関数のselfは解放しない。必要があれば#ln_term()を実行すること。
 */
bool ln_db_self_search(ln_db_func_cmp_t pFunc, void *pFuncParam);
bool ln_db_self_search_readonly(ln_db_func_cmp_t pFunc, void *pFuncParam);


/** load self->status
 * 
 * @param[in,out]       self            channel info
 * @retval  load result
 * @note
 *      - update self->status
 */
bool ln_db_self_load_status(ln_self_t *self);


/** save self->status
 * 
 * @param[in]           self            channel info
 * @retval  load result
 */
bool ln_db_self_save_status(const ln_self_t *self, void *pDbParam);


/** short_channel_idが自分が持つチャネルかどうか
 *
 */
bool ln_db_self_chk_mynode(uint64_t ShortChannelId);


/** secret保存
 *
 */
bool ln_db_secret_save(ln_self_t *self);


/********************************************************************
 * anno用DB
 ********************************************************************/

/** announcement用DBのトランザクション取得およびDBオープン
 *
 * @retval  true    成功
 */
bool ln_db_anno_transaction(void);


/** #ln_db_anno_transaction()で取得したトランザクションのcommit
 *
 * @param[in]   bCommit         true:トランザクションをcommit
 */
void ln_db_anno_commit(bool bCommit);


/********************************************************************
 * [anno]channel_announcement / channel_update
 ********************************************************************/

/** channel_announcement読込み
 *
 * @param[out]      pCnlAnno
 * @param[in]       ShortChannelId
 * @retval      true    成功
 */
bool ln_db_annocnl_load(utl_buf_t *pCnlAnno, uint64_t ShortChannelId);


/** channel_announcement書込み
 *
 * @param[in]       pCnlAnno
 * @param[in]       ShortChannelId  pCnlAnnoのshort_channel_id
 * @param[in]       pSendId         pCnlAnnoの送信元/先node_id
 * @param[in]       pNodeId1        channel_announcementのnode_id1
 * @param[in]       pNodeId2        channel_announcementのnode_id2
 * @retval      true    成功
 */
bool ln_db_annocnl_save(const utl_buf_t *pCnlAnno, uint64_t ShortChannelId, const uint8_t *pSendId,
                        const uint8_t *pNodeId1, const uint8_t *pNodeId2);


/** channel_update読込み
 *
 * @param[out]      pCnlAnno            channel_updateパケット
 * @param[out]      pTimeStamp          pCnlAnnoのTimeStamp
 * @param[in]       ShortChannelId      読み込むshort_channel_id
 * @param[in]       Dir                 0:node1, 1:node2
 * @retval      true    成功
 */
bool ln_db_annocnlupd_load(utl_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir);


/** channel_update書込み
 *
 * @param[in]       pCnlUpd             channel_updateパケット
 * @param[in]       pUpd                channel_update構造体
 * @param[in]       pSendId             channel_updateの送信元/先ノード
 * @retval      true    成功
 */
bool ln_db_annocnlupd_save(const utl_buf_t *pCnlUpd, const ln_cnl_update_t *pUpd, const uint8_t *pSendId);


/** channel pruning判定
 *
 * @param[in]       Now             現在時刻(EPOCH)
 * @param[in]       TimeStamp       channel_updateの時刻(EPOCH)
 * @retval      true    削除してよし
 */
static inline bool ln_db_annocnlupd_is_prune(uint64_t Now, uint32_t TimesStamp) {
    //BOLT#7: Pruning the Network View
    //  if a channel's latest channel_updates timestamp is older than two weeks (1209600 seconds):
    //      MAY prune the channel.
    //  https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#recommendation-on-pruning-stale-entries
    return (uint64_t)TimesStamp + (uint64_t)1209600 < Now;
}


/** channel_announcement系の送受信情報削除
 *
 * channel_announcement/channel_updateの送信先・受信元ノードIDを削除する。
 *
 * @param[in]       short_channel_id(0の場合、全削除)
 * @retval      true    成功
 */
bool ln_db_annocnlall_del(uint64_t short_channel_id);


/********************************************************************
 * node_announcement
 ********************************************************************/

/** node_announcement読込み
 *
 * @param[out]      pNodeAnno       node_announcement(NULL時は無視)
 * @param[out]      pTimeStamp      node_announcementのtimestamp(NULL時は無視)
 * @param[in]       pNodeId         検索するnode_id
 * @retval      true    成功
 */
bool ln_db_annonod_load(utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);


/** node_announcement書込み
 *
 * @param[in]       pNodeAnno       node_announcementパケット
 * @param[in]       pAnno           node_announcement構造体
 * @param[in]       pSendId         (非NULL)node_announcementの送信元/先ノード
 * @retval      true    成功
 * @note
 *      - タイムスタンプはAPI呼び出し時の値が保存される
 */
bool ln_db_annonod_save(const utl_buf_t *pNodeAnno, const ln_node_announce_t *pAnno, const uint8_t *pSendId);


/********************************************************************
 * [anno]cursor
 ********************************************************************/

/** announcement用DBオープン
 *
 * @param[out]  pCur
 * @param[in]   Type        オープンするDB(LN_DB_TXN_xx)
 * @retval  true    成功
 */
bool ln_db_anno_cur_open(void **ppCur, ln_db_cur_t Type);


/** announcement用DBクローズ
 *
 * @param[out]  pCur
 */
void ln_db_anno_cur_close(void *pCur);


/** channel_announcement系の送受信情報追加
 *
 * channel_announcement/channel_updateの送信先・受信元ノードIDを追加する。
 *
 * @param[in,out]   pCur
 * @param[in]       ShortChannelId
 * @param[in]       Type
 * @param[in]       bClr                true:保存したノードを削除してから追加する
 * @param[in]       pSendId             送信元/先ノード
 */
bool ln_db_annocnlinfo_add_nodeid(void *pCur, uint64_t ShortChannelId, char Type, bool bClr, const uint8_t *pSendId);


/** channel_announcement関連情報送信済み検索
 *
 * @param[in]       pCur
 * @param[in]       ShortChannelId      検索するshort_channel_id
 * @param[in]       Type                検索するchannel_announcement/channel_update[1/2]
 * @param[in]       pSendId             対象node_id
 * @retval  true    pSendIdへ送信済み
 */
bool ln_db_annocnlinfo_search_nodeid(void *pCur, uint64_t ShortChannelId, char Type, const uint8_t *pSendId);


/** channel_announcement関連情報の順次取得
 *
 * @param[in]       pCur
 * @param[out]      pShortChannelId         short_channel_id
 * @param[out]      pType                   LN_DB_CNLANNO_xxx(channel_announcement / channel_update)
 * @param[out]      pTimeStamp              channel_announcementのtimestamp
 * @param[out]      pBuf                    取得したデータ(p_typeに応じて内容は変わる)
 * @retval  true    成功
 */
bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf);


/** channel_announcement関連情報の前方取得
 *
 * #ln_db_annocnl_cur_get()ではcursorが進んでしまうため、戻す場合に使う想定。
 *
 * @param[in]       pCur
 * @param[out]      pShortChannelId         short_channel_id
 * @param[out]      pType                   LN_DB_CNLANNO_xxx(channel_announcement / channel_update)
 * @param[out]      pTimeStamp              channel_announcementのtimestamp
 * @param[out]      pBuf                    取得したデータ(p_typeに応じて内容は変わる)
 * @retval  true    成功
 */
bool ln_db_annocnl_cur_getback(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf);


/** ln_db_annocnl_cur_get()したDBの削除
 *
 * @param[in]       pCur
 * @retval  true    成功
 */
bool ln_db_annocnl_cur_del(void *pCur);


/** node_announcement取得
 *
 */
bool ln_db_annonod_cur_load(void *pCur, utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);


/** node_announcement送信済み検索
 *
 * @retval  true        送信済み
 */
bool ln_db_annonodinfo_search_nodeid(void *pCur, const uint8_t *pNodeId, const uint8_t *pSendId);


/** node_announcement送信元/先ノード追加
 *
 * @param[in,out]   pCur
 * @param[in]       pNodeId
 * @param[in]       bClr                true:保存したノードを削除してから追加する
 * @param[in]       pSendId             送信元/先ノード(NULLでbClr=true時はクリアのみ行う)
 */
bool ln_db_annonodinfo_add_nodeid(void *pCur, const uint8_t *pNodeId, bool bClr, const uint8_t *pSendId);


/** node_announcement順次取得
 *
 * @param[in,out]   pCur            #ln_db_annonod_cur_open()でオープンしたDB cursor
 * @param[out]      pBuf            node_announcementパケット
 * @param[out]      pTimeStamp      保存時刻
 * @param[out]      pNodeId         node_announcementのnode_id
 * @retval      true    成功
 */
bool ln_db_annonod_cur_get(void *pCur, utl_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId);


/********************************************************************
 * [anno]own channel
 ********************************************************************/

/** 自short_channel_id登録
 *      受信したshort_channel_idが自分の持つものかどうか調べるためのDB
 *
 */
bool ln_db_annoown_save(uint64_t ShortChannelId);

/** 自short_channel_idチェック
 *
 * @retval  true    自short_channel_id DBに登録あり
 * @attention
 *      #ln_db_anno_transaction()でtransaction取得済みであること
 */
bool ln_db_annoown_check(uint64_t ShortChannelId);


/** 自short_channel_id削除
 *
 */
bool ln_db_annoown_del(uint64_t ShortChannelId);


/********************************************************************
 * annocnl, annonod共通
 ********************************************************************/

/** channel_announcement/channel_update/node_announcement送受信ノード情報削除
 * announcement送信済みのnode_idを保持しているので、起動時に全削除する。
 * また、チャネル接続時には接続先node_idの情報を削除する。
 *
 * @param[in]       pNodeId     削除対象のnode_id(NULL時は全削除)
 */
bool ln_db_annoinfos_del(const uint8_t *pNodeId);


/********************************************************************
 * skip routing list
 ********************************************************************/

/** "route_skip" short_channel_id登録
 *
 * @param[in]   ShortChannelId      登録するshort_channel_id
 * @param[in]   bTemp               true:一時的なskip
 * @retval  true    成功
 */
bool ln_db_routeskip_save(uint64_t ShortChannelId, bool bTemp);


/** "routeskip" temporary skip <--> temporary work
 * 
 * @param[in]   bWork               true:skip-->work, false:work-->skip
 */
bool ln_db_routeskip_work(bool bWork);


/** "route_skip" スキップ情報にshort_channel_idが登録されているか
 *
 * @param[in]       ShortChannelId      検索するshort_channel_id
 * @return      result
 */
ln_db_routeskip_t ln_db_routeskip_search(uint64_t ShortChannelId);


/** "route_skip" DB削除
 *
 * @param[in]   bTemp               true:一時的なskipのみ削除 / false:全削除
 */
bool ln_db_routeskip_drop(bool bTemp);


/********************************************************************
 * invoice
 ********************************************************************/

/** "routepay" invoice保存
 *
 */
bool ln_db_invoice_save(const char *pInvoice, uint64_t AddAmountMsat, const uint8_t *pPayHash);


/** "routepay" invoice取得
 *
 */
bool ln_db_invoice_load(char **ppInvoice, uint64_t *pAddAmountMsat, const uint8_t *pPayHash);


/** "routepay" 全payment_hash取得
 *
 * @attention
 *      - 内部で realloc()するため、使用後に free()すること
 */
int ln_db_invoice_get(uint8_t **ppPayHash);


/** "routepay" invoice削除
 *
 */
bool ln_db_invoice_del(const uint8_t *pPayHash);


/** "routepay" DB削除
 *
 */
bool ln_db_invoice_drop(void);


/********************************************************************
 * payment preimage
 ********************************************************************/

/** preimage保存
 *
 * @param[in,out]   pPreImg     creation_timeのみoutput
 * @param[in,out]   pDb
 * @retval  true
 */
bool ln_db_preimg_save(ln_db_preimg_t *pPreImg, void *pDb);


/** preimage削除
 *
 * @param[in]       pPreImage
 * @retval  true
 */
bool ln_db_preimg_del(const uint8_t *pPreImage);


/** preimage検索
 *
 * @param[in]       pFunc
 * @param[in,out]   p_param
 * @retval  true    pFuncがtrueを返した(その時点で検索を中断している)
 */
bool ln_db_preimg_search(ln_db_func_preimg_t pFunc, void *p_param);


/** preimage削除(payment_hash検索)
 *
 * @param[in]       pPreImageHash
 * @retval  true
 */
bool ln_db_preimg_del_hash(const uint8_t *pPreImageHash);


/** preimage cursorオープン
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
 * @param[out]      pDetect     true:取得成功
 * @param[out]      pPreImg
 * @retval  true        エラーでは無い
 */
bool ln_db_preimg_cur_get(void *pCur, bool *pDetect, ln_db_preimg_t *pPreImg);


/** preimage expiry更新
 *
 */
bool ln_db_preimg_set_expiry(void *pCur, uint32_t Expiry);


#ifdef LN_UGLY_NORMAL
/********************************************************************
 * payment_hash
 ********************************************************************/

/** payment_hash保存
 *
 * @param[in]       pPayHash        保存するpayment_hash
 * @param[in]       pVout           pPayHashを含むvoutスクリプトを#btc_sw_wit2prog_p2wsh()した結果。大きさはLNL_SZ_WITPROG_WSH。
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


/********************************************************************
 * revoked transaction close
 ********************************************************************/

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


/********************************************************************
 * wallet
 ********************************************************************/

/**
 *
 * @param[out]  pBuf    読込結果(非NULLの場合)
 * @param[in]   pTxid
 * @param[in]   Index
 * @retval  true    読み込み成功
 */
bool ln_db_wallet_load(utl_buf_t *pBuf, const uint8_t *pTxid, uint32_t Index);


/** 送金可能なINPUTを登録
 *
 * @retval  true    成功
 */
bool ln_db_wallet_add(const ln_db_wallet_t *pWallet);


/** wallet DB検索
 *  検索にヒットするとコールバック関数を呼び出す。
 */
bool ln_db_wallet_search(ln_db_func_wallet_t pWalletFunc, void *pFuncParam);


/** wallet DBから対象outpointを削除
 *
 */
bool ln_db_wallet_del(const uint8_t *pTxid, uint32_t Index);


/********************************************************************
 * version
 ********************************************************************/

/** DB version check
 *
 * @param[out]      pMyNodeId       (非NULL時)node_id
 * @param[out]      pGType          (非NULL時)genesis hash type
 * @retval  true    チェックOK
 */
bool ln_db_ver_check(uint8_t *pMyNodeId, btc_genesis_t *pGType);


/********************************************************************
 * others
 ********************************************************************/

/** DB reset
 * "version"以外を削除する
 *
 */
bool ln_db_reset(void);

#ifdef __cplusplus
}
#endif  //__cplusplus

#endif /* LN_DB_H__ */
