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
/** @file   ln_db.h
 *  @brief  Lightning DB保存・復元
 */
#ifndef LN_DB_H__
#define LN_DB_H__

#include "btc_block.h"

#include "ln.h"
#include "ln_msg_anno.h"
#include "ln_payment.h"


#ifdef __cplusplus
extern "C" {
#endif  //__cplusplus

/********************************************************************
 * macros
 ********************************************************************/

#define LN_DB_CNLANNO_ANNO          'A'     ///< channel_announcement用KEYの末尾: channel_announcement
#define LN_DB_CNLANNO_UPD0          'B'     ///< channel_announcement用KEYの末尾: channel_update dir=0
#define LN_DB_CNLANNO_UPD1          'C'     ///< channel_announcement用KEYの末尾: channel_update dir=1

#define LN_DB_WALLET_TYPE_TO_LOCAL      ((uint8_t)1)
#define LN_DB_WALLET_TYPE_TO_REMOTE     ((uint8_t)2)
#define LN_DB_WALLET_TYPE_HTLC_OUTPUT   ((uint8_t)3)

#define LN_DB_WALLET_INIT(t)    { t/*type*/, NULL/*p_txid*/, 0/*index*/, 0/*amount*/, 0/*sequence*/, 0/*locktime*/, 0/*wit_item_cnt*/, NULL/*p_wit_items*/, 0/*mined_height*/ }


/**************************************************************************
 * typedefs
 **************************************************************************/

/** @typedef    ln_db_route_skip_t
 *  @brief      result ln_db_route_skip_search()
 */
typedef enum {
    LN_DB_ROUTE_SKIP_NONE,       ///< not found
    LN_DB_ROUTE_SKIP_TEMP,       ///< found: temporary skip
    LN_DB_ROUTE_SKIP_PERM,       ///< found: permanentry skip
    LN_DB_ROUTE_SKIP_WORK,       ///< low priority channel
    LN_DB_ROUTE_SKIP_ERROR       ///< DB error
} ln_db_route_skip_t;


/** @typedef    ln_db_cur_t
 *  @brief      cursorオープンするannouncement種別
 */
typedef enum {
    LN_DB_CUR_CNLANNO,          ///< channel_announcement/channel_update
    LN_DB_CUR_NODEANNO,         ///< node_announcement
    LN_DB_CUR_CNLANNO_INFO,     ///< channel_announcement/channel_update送信済み
    LN_DB_CUR_NODEANNO_INFO,    ///< node_announcement送信済み
} ln_db_cur_t;


/** @typedef    ln_db_preimage_state_t
 *  @brief      created preimage status
 */
typedef enum {
    LN_DB_PREIMAGE_STATE_UNUSED = 0,    ///< unused(including outdated)
    LN_DB_PREIMAGE_STATE_USED = 1,      ///< used(already received)
    LN_DB_PREIMAGE_STATE_EXPIRE = 2,    ///< unused and expire(not save DB)
    LN_DB_PREIMAGE_STATE_UNKNOWN = UINT8_MAX
} ln_db_preimage_state_t;


/** @typedef    ln_db_preimage_t
 *  @brief      preimage/invoice
 */
typedef struct {
    uint8_t     preimage[LN_SZ_PREIMAGE];
    uint64_t    amount_msat;
    uint64_t    creation_time;
    uint32_t    expiry;
    ln_db_preimage_state_t  state;
} ln_db_preimage_t;


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
    utl_buf_t   *p_wit_items;               ///< p_wit_items[wit_item_cnt]
    uint32_t    mined_height;               ///< outpointがminingされたblockcount
} ln_db_wallet_t;


//XXX: comment
/** @typedef    ln_db_forward_t
 *  @brief      ln_db_forward
 */
typedef struct {
    uint64_t    next_short_channel_id;
    uint64_t    prev_short_channel_id;
    uint64_t    prev_htlc_id;
    utl_buf_t   *p_msg;
} ln_db_forward_t;


/** @typedef    ln_db_func_cmp_t
 *  @brief      比較関数(#ln_db_channel_search())
 *
 * DB内からpChannelを順次取得しコールバックされる(同期処理)。
 * trueを返すまでコールバックが続けられる。
 * 最後までfalseを返し、DBの走査が終わると、#ln_db_channel_search()はfalseを返す。
 *
 * @param[in]       pChannel        channel from DB
 * @param[in]       pDbParam      DB情報(ln_dbで使用する)
 * @param[in]       pParam         #ln_db_channel_search()に渡したデータポインタ
 * @retval  true    比較終了(#ln_db_channel_search()の戻り値もtrue)
 * @retval  false   比較継続
 */
typedef bool (*ln_db_func_cmp_t)(ln_channel_t *pChannel, void *pDbParam, void *pParam);


/** @typedef    ln_db_func_preimage_t
 *  @brief      比較関数(#ln_db_preimage_search())
 *
 * @param[in]       pChannel        channel from DB
 * @param[in]       pDbParam      DB情報(ln_dbで使用する)
 * @param[in]       pParam         #ln_db_preimage_search()に渡したデータポインタ
 * @retval  true    比較終了
 * @retval  false   比較継続
 */
typedef bool (*ln_db_func_preimage_t)(const uint8_t *pPreimage, uint64_t Amount, uint32_t Expiry, void *pDbParam, void *pParam);


/** @typedef    ln_db_func_wallet_t
 *  @brief      比較関数(#ln_db_wallet_search())
 *
 * @param[in]       pChannel        channel from DB
 * @param[in]       pParam         #ln_db_wallet_search()に渡したデータポインタ
 * @retval  true    比較終了
 * @retval  false   比較継続
 */
typedef bool (*ln_db_func_wallet_t)(const ln_db_wallet_t *pWallet, void *pParam);


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
 * @param[in]       bAutoUpdate     true:auto version update(if it can)
 * @param[in]       bStdErr         エラーをstderrに出力
 * @retval  true    初期化成功
 */
bool ln_db_init(char *pWif, char *pNodeName, uint16_t *pPort, bool bAutoUpdate, bool bStdErr);


/** db終了
 *
 */
void ln_db_term(void);


/**　DBディレクトリの存在チェック
 *
 * @retval  true    カレントディレクトリにDBディレクトリがある
 */
bool ln_db_have_db_dir(void);


/********************************************************************
 * channel
 ********************************************************************/

/** channel情報読込み
 *
 * @param[out]      pChannel
 * @param[in]       pChannelId
 * @retval      true    成功
 * @attention
 *      -
 *      - 新規 pChannel に読込を行う場合は、事前に #ln_init()???を行っておくこと(seedはNULLでよい)
 */
//bool ln_db_channel_load(ln_channel_t *pChannel, const uint8_t *pChannelId);


/** channel情報書き込み
 *
 * @param[in]       pChannel
 * @retval      true    成功
 */
bool ln_db_channel_save(const ln_channel_t *pChannel);


/** channel削除(channel_id指定)
 *
 * @param[in]       pChannelId      削除するpChannelのchannel_id
 * @retval      true    検索成功(削除成功かどうかは判断しない)
 */
bool ln_db_channel_del(const uint8_t *pChannelId);


/** channel削除(DB paramあり)
 *
 * @param[in]       pChannel
 * @param[in,out]   pDbParam      呼び出されたコールバック関数のパラメータ
 * @retval      true    成功
 * @note
 *      - #ln_db_channel_search() 経由を想定
 */
bool ln_db_channel_del_param(const ln_channel_t *pChannel, void *pDbParam);


/** channel情報検索
 *      比較関数を使用してchannel情報を検索する。
 *      最後はcommitされる。
 *
 * @param[in]       pFunc       検索関数
 * @param[in,out]   pFuncParam  検索関数に渡す引数
 * @retval      true    検索関数がtrueを戻した
 * @retval      false   検索関数が最後までtrueを返さなかった
 * @note
 *      - 戻り値がtrueの場合、検索関数のpChannelは解放しない。必要があれば#ln_term()を実行すること。
 */
bool ln_db_channel_search(ln_db_func_cmp_t pFunc, void *pFuncParam);


bool ln_db_channel_search_cont(ln_db_func_cmp_t pFunc, void *pFuncParam);


/** channel情報検索(read only)
 *      比較関数を使用してchannel情報を検索する。
 *      最後はcommitされない。
 *
 * @param[in]       pFunc       検索関数
 * @param[in,out]   pFuncParam  検索関数に渡す引数
 * @retval      true    検索関数がtrueを戻した
 * @retval      false   検索関数が最後までtrueを返さなかった
 * @note
 *      - 戻り値がtrueの場合、検索関数のpChannelは解放しない。必要があれば#ln_term()を実行すること。
 */
bool ln_db_channel_search_readonly(ln_db_func_cmp_t pFunc, void *pFuncParam);


/** channel情報検索(read only)(no key restore)
 *      比較関数を使用してchannel情報を検索する。
 *      鍵は復元されない。
 *      最後はcommitされない。
 *
 * @param[in]       pFunc       検索関数
 * @param[in,out]   pFuncParam  検索関数に渡す引数
 * @retval      true    検索関数がtrueを戻した
 * @retval      false   検索関数が最後までtrueを返さなかった
 * @note
 *      - 戻り値がtrueの場合、検索関数のpChannelは解放しない。必要があれば#ln_term()を実行すること。
 */
bool ln_db_channel_search_readonly_nokey(ln_db_func_cmp_t pFunc, void *pFuncParam);


/** load pChannel->status
 *
 * @param[in,out]       pChannel        channel info
 * @retval  load result
 * @note
 *      - update pChannel->status
 */
bool ln_db_channel_load_status(ln_channel_t *pChannel);


/** save pChannel->status
 *
 * @param[in]           pChannel        channel info
 * @retval  save result
 */
bool ln_db_channel_save_status(const ln_channel_t *pChannel, void *pDbParam);


/** save pChannel->last_confirm
 *
 * @param[in]           pChannel        channel info
 * @retval  save result
 */
bool ln_db_channel_save_last_confirm(const ln_channel_t *pChannel, void *pDbParam);


/** channel DB close
 */
void ln_db_channel_close(const uint8_t *pChannelId);


/** DBで保存している対象のデータだけコピーする
 *
 * @param[out]  pOutChannel
 * @param[in]   pInChannel
 */
void ln_db_copy_channel(ln_channel_t *pOutChannel, const ln_channel_t *pInChannel);


/** secret保存
 *
 */
bool ln_db_secret_save(ln_channel_t *pChannel);


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
bool ln_db_cnlanno_load(utl_buf_t *pCnlAnno, uint64_t ShortChannelId);


/** channel_announcement書込み
 *
 * @param[in]       pCnlAnno
 * @param[in]       ShortChannelId  pCnlAnnoのshort_channel_id
 * @param[in]       pSendId         pCnlAnnoの送信元/先node_id
 * @param[in]       pNodeId1        channel_announcementのnode_id1
 * @param[in]       pNodeId2        channel_announcementのnode_id2
 * @retval      true    成功
 */
bool ln_db_cnlanno_save(const utl_buf_t *pCnlAnno, uint64_t ShortChannelId, const uint8_t *pSendId,
                        const uint8_t *pNodeId1, const uint8_t *pNodeId2);


/** channel_update読込み
 *
 * @param[out]      pCnlAnno            channel_updateパケット
 * @param[out]      pTimeStamp          pCnlAnnoのTimeStamp
 * @param[in]       ShortChannelId      読み込むshort_channel_id
 * @param[in]       Dir                 0:node1, 1:node2
 * @param[in]       pDbParam            非NULL:指定されたdb paramを使用する
 * @retval      true    成功
 */
bool ln_db_cnlupd_load(utl_buf_t *pCnlUpd, uint32_t *pTimeStamp, uint64_t ShortChannelId, uint8_t Dir, void *pDbParam);


/** channel_update書込み
 *
 * @param[in]       pCnlUpd             channel_updateパケット
 * @param[in]       pUpd                channel_update構造体
 * @param[in]       pSendId             channel_updateの送信元/先ノード
 * @retval      true    成功
 */
bool ln_db_cnlupd_save(const utl_buf_t *pCnlUpd, const ln_msg_channel_update_t *pUpd, const uint8_t *pSendId);


/** channel pruning判定
 *
 * @param[in]       Now             現在時刻(EPOCH)
 * @param[in]       TimeStamp       channel_updateの時刻(EPOCH)
 * @retval      true    削除してよし
 */
bool ln_db_cnlupd_need_to_prune(uint64_t Now, uint32_t TimesStamp);


/** channel_announcement系の送受信情報削除
 *
 * channel_announcement/channel_updateの送信先・受信元ノードIDを削除する。
 *
 * @param[in]       short_channel_id(0の場合、全削除)
 * @retval      true    成功
 */
bool ln_db_cnlanno_del(uint64_t ShortChannelId);


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
bool ln_db_nodeanno_load(utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);


/** node_announcement書込み
 *
 * @param[in]       pNodeAnno       node_announcementパケット
 * @param[in]       pAnno           node_announcement構造体
 * @param[in]       pSendId         (非NULL)node_announcementの送信元/先ノード
 * @retval      true    成功
 * @note
 *      - タイムスタンプはAPI呼び出し時の値が保存される
 */
bool ln_db_nodeanno_save(const utl_buf_t *pNodeAnno, const ln_msg_node_announcement_t *pAnno, const uint8_t *pSendId);


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
 * @param[in]       bClear                true:保存したノードを削除してから追加する
 * @param[in]       pNodeId             追加するnode_id
 */
bool ln_db_cnlanno_info_add_node_id(void *pCur, uint64_t ShortChannelId, char Type, bool bClear, const uint8_t *pNodeId);


/** channel_announcement関連情報送信済み検索
 *
 * @param[in]       pCur
 * @param[in]       ShortChannelId      検索するshort_channel_id
 * @param[in]       Type                検索するchannel_announcement/channel_update[1/2]
 * @param[in]       pNodeId             対象node_id
 * @retval  true    pNodeIdへ送信済み
 */
bool ln_db_cnlanno_info_search_node_id(void *pCur, uint64_t ShortChannelId, char Type, const uint8_t *pNodeId);


/** channel_announcement関連情報の順次取得
 *
 * @param[in]       pCur
 * @param[out]      pShortChannelId         short_channel_id
 * @param[out]      pType                   LN_DB_CNLANNO_xxx(channel_announcement / channel_update)
 * @param[out]      pTimeStamp              channel_announcementのtimestamp
 * @param[out]      pBuf                    取得したデータ(p_typeに応じて内容は変わる)
 * @retval  true    成功
 */
bool ln_db_cnlanno_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf);


/** channel_announcement関連情報の前方移動
 *
 */
bool ln_db_cnlanno_cur_back(void *pCur);


/** ln_db_cnlanno_cur_get()したDBの削除
 *
 * @param[in]       pCur
 * @retval  true    成功
 */
bool ln_db_cnlanno_cur_del(void *pCur);


/** node_announcement取得
 *
 */
bool ln_db_nodeanno_cur_load(void *pCur, utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId);


/** node_announcement送信済み検索
 *
 * @retval  true        送信済み
 */
bool ln_db_nodeanno_info_search_node_id(void *pCur, const uint8_t *pNodeId, const uint8_t *pSendId);


/** node_announcement送信元/先ノード追加
 *
 * @param[in,out]   pCur
 * @param[in]       pNodeId
 * @param[in]       bClear                true:保存したノードを削除してから追加する
 * @param[in]       pSendId             送信元/先ノード(NULLでbClear=true時はクリアのみ行う)
 */
bool ln_db_nodeanno_info_add_node_id(void *pCur, const uint8_t *pNodeId, bool bClear, const uint8_t *pSendId);


/** node_announcement順次取得
 *
 * @param[in,out]   pCur            #ln_db_nodeanno_cur_open()でオープンしたDB cursor
 * @param[out]      pBuf            node_announcementパケット
 * @param[out]      pTimeStamp      保存時刻
 * @param[out]      pNodeId         node_announcementのnode_id
 * @retval      true    成功
 */
bool ln_db_nodeanno_cur_get(void *pCur, utl_buf_t *pBuf, uint32_t *pTimeStamp, uint8_t *pNodeId);


/********************************************************************
 * [anno]own channel
 ********************************************************************/

/** 自short_channel_id登録
 *      受信したshort_channel_idが自分の持つものかどうか調べるためのDB
 *
 */
bool ln_db_channel_owned_save(uint64_t ShortChannelId);

/** 自short_channel_idチェック
 *
 * @retval  true    自short_channel_id DBに登録あり
 * @attention
 *      #ln_db_anno_transaction()でtransaction取得済みであること
 */
bool ln_db_channel_owned_check(uint64_t ShortChannelId);


/** 自short_channel_id削除
 *
 */
bool ln_db_channel_owned_del(uint64_t ShortChannelId);


/********************************************************************
 * cnlanno, nodeanno共通
 ********************************************************************/

/** channel_announcement/channel_update/node_announcement送受信ノード情報削除
 * announcement送信済みnode_idから削除する。
 *
 * @param[in]       pNodeId     削除対象のnode_id(NULL時は全削除)
 * @param[in]       pShortChannelId     (pNodeId非NULL時)削除対象のshort_channel_id(NULL時は全削除)
 * @param[in]       Num                 pShortChannelId数
 */
bool ln_db_annoinfos_del_node_id(const uint8_t *pNodeId, const uint64_t *pShortChannelId, size_t Num);


/** channel_announcement/channel_update/node_announcement送受信ノード情報追加
 * announcement送信済みnode_idに追加する。
 *
 * @param[in]       pNodeId     削除対象のnode_id(NULL時は全削除)
 */
bool ln_db_annoinfos_add_node_id(const uint8_t *pNodeId);


/** channel_announcement/channel_update/node_announcement送受信ノード情報削除
 * announcement送信済みnode_idから削除する。
 *
 * @param[in]       pNodeId     削除対象のnode_id(NULL時は全削除)
 * @param[in]       TimeFirst
 * @param[in]       TimeRange
 */
bool ln_db_annoinfos_del_timestamp(const uint8_t *pNodeId, uint32_t TimeFirst, uint32_t TimeRange);


/********************************************************************
 * skip routing list
 ********************************************************************/

/** "route_skip" short_channel_id登録
 *
 * @param[in]   ShortChannelId      登録するshort_channel_id
 * @param[in]   bTemp               true:一時的なskip
 * @retval  true    成功
 */
bool ln_db_route_skip_save(uint64_t ShortChannelId, bool bTemp);


/** "route_skip" temporary skip <--> temporary work
 *
 * @param[in]   bWork               true:skip-->work, false:work-->skip
 */
bool ln_db_route_skip_work(bool bWork);


/** "route_skip" スキップ情報にshort_channel_idが登録されているか
 *
 * @param[in]       ShortChannelId      検索するshort_channel_id
 * @return      result
 */
ln_db_route_skip_t ln_db_route_skip_search(uint64_t ShortChannelId);


/** "route_skip" DB削除
 *
 * @param[in]   bTemp               true:一時的なskipのみ削除 / false:全削除
 */
bool ln_db_route_skip_drop(bool bTemp);


/********************************************************************
 * payment preimage
 ********************************************************************/

/** preimage保存
 *
 * @param[in]       pPreimage   preimage information
 * @param[in]       pBolt11     BOLT11 format invoice
 * @param[in,out]   pDb         (nullable)
 * @retval  true
 */
bool ln_db_preimage_save(const ln_db_preimage_t *pPreimage, const char *pBolt11, void *pDb);


/** preimage削除
 *
 * @param[in]       pPreimage
 * @retval  true
 */
bool ln_db_preimage_del(const uint8_t *pPreimage);


/** preimage検索
 *
 * @param[in]       pFunc
 * @param[in,out]   pFuncParam
 * @retval  true    pFuncがtrueを返した(その時点で検索を中断している)
 * @note
 *  - DB更新を行わない
 */
bool ln_db_preimage_search(ln_db_func_preimage_t pFunc, void *pFuncParam);


/** preimage削除(payment_hash検索)
 *
 * @param[in]       pPaymentHash
 * @retval  true
 */
bool ln_db_preimage_del_hash(const uint8_t *pPaymentHash);


/** preimage cursorオープン
 *
 * @param[in,out]   ppCur
 * @retval  true
 */
bool ln_db_preimage_cur_open(void **ppCur);


/** preimage cursorクローズ
 *
 * @param[in]       pCur
 * @param[in]       bCommit commit or abort
 * @retval  true
 */
void ln_db_preimage_cur_close(void *pCur, bool bCommit);


/** preimage取得
 *
 * @param[in]       pCur
 * @param[out]      pDetect     true:取得成功
 * @param[out]      pPreimage
 * @param[out]      ppBolt11    (not NULL)BOLT11 invoice string
 * @retval  true        エラーでは無い
 */
bool ln_db_preimage_cur_get(void *pCur, bool *pDetect, ln_db_preimage_t *pPreimage, const char **ppBolt11);


/** preimage使用済み
 *
 * @param[in]       pPreimage
 * @retval  true
 */
bool ln_db_preimage_used(const uint8_t *pPreimage);


/********************************************************************
 * payment_hash
 ********************************************************************/

/** payment_hash保存
 *
 * @param[in]       pPaymentHash        保存するpayment_hash
 * @param[in]       pVout           pPaymentHashを含むvoutスクリプトを#btc_script_p2wsh_create_scriptpk()した結果。大きさはLNL_SZ_WITPROG_WSH。
 * @param[in]       Type            pVout先のHTLC種別(LN_COMMIT_TX_OUTPUT_TYPE_OFFERED / LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED)
 * @param[in]       Expiry          Expiry
 * @retval  true
 */
bool ln_db_payment_hash_save(const uint8_t *pPaymentHash, const uint8_t *pVout, ln_commit_tx_output_type_t Type, uint32_t Expiry);


/** payment_hash検索
 *
 * @param[out]      pPaymentHash        保存するpayment_hash
 * @param[out]      pType           pVoutのHTLC種別(LN_COMMIT_TX_OUTPUT_TYPE_OFFERED / LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED)
 * @param[out]      pExpiry         Expiry
 * @param[in]       pVout           検索するvout
 * @param[in,out]   pDbParam        DBパラメータ
 * @retval  true
 */
bool ln_db_payment_hash_search(uint8_t *pPaymentHash, ln_commit_tx_output_type_t *pType, uint32_t *pExpiry, const uint8_t *pVout, void *pDbParam);


/********************************************************************
 * revoked transaction close
 ********************************************************************/

/** revoked transaction情報読込み
 *
 * @param[in,out]   pChannel
 * @param[in,out]   pDbParam
 * @retval  true        .
 */
bool ln_db_revoked_tx_load(ln_channel_t *pChannel, void *pDbParam);


/** revoked transaction情報保存
 *
 * @param[in]       pChannel
 * @param[in]       bUpdate
 * @param[in,out]   pDbParam
 * @retval  true        .
 */
bool ln_db_revoked_tx_save(const ln_channel_t *pChannel, bool bUpdate, void *pDbParam);


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
//bool ln_db_wallet_load(utl_buf_t *pBuf, const uint8_t *pTxid, uint32_t Index);


/** 送金可能なINPUTを登録
 *
 * @retval  true    成功
 */
bool ln_db_wallet_save(const ln_db_wallet_t *pWallet);


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
 * @param[out]      pBlockChain          (非NULL時)genesis hash type
 * @retval  true    チェックOK
 */
bool ln_db_version_check(uint8_t *pMyNodeId, btc_block_chain_t *pBlockChain);


/********************************************************************
 * forward
 ********************************************************************/

//XXX: comment
bool ln_db_forward_add_htlc_create(uint64_t NextShortChannelId);
bool ln_db_forward_add_htlc_save(const ln_db_forward_t *pForward);
bool ln_db_forward_add_htlc_del(uint64_t NextShortChannelId, uint64_t PrevShortChannelId, uint64_t PrevHtlcId);
bool ln_db_forward_add_htlc_drop(uint64_t NextShortChannelId);


//XXX: comment
bool ln_db_forward_del_htlc_create(uint64_t NextShortChannelId);
bool ln_db_forward_del_htlc_save(const ln_db_forward_t *pForward);
bool ln_db_forward_del_htlc_save_2(const ln_db_forward_t *pForward, void *pDbParam);
bool ln_db_forward_del_htlc_del(uint64_t NextShortChannelId, uint64_t PrevShortChannelId, uint64_t PrevHtlcId);
bool ln_db_forward_del_htlc_drop(uint64_t NextShortChannelId);


/********************************************************************
 * forward cursor
 ********************************************************************/

//XXX: comment
bool ln_db_forward_add_htlc_cur_open(void **ppCur, uint64_t NextShortChannelId);
void ln_db_forward_add_htlc_cur_close(void *pCur, bool bCommit);
bool ln_db_forward_add_htlc_cur_get(
    void *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg);
bool ln_db_forward_add_htlc_cur_del(void *pCur);


//XXX: comment
bool ln_db_forward_del_htlc_cur_open(void **ppCur, uint64_t NextShortChannelId);
void ln_db_forward_del_htlc_cur_close(void *pCur, bool bCommit);
bool ln_db_forward_del_htlc_cur_get(
    void *pCur, uint64_t *pPrevShortChannelId, uint64_t *pPrevHtlcId, utl_buf_t *pMsg);
bool ln_db_forward_del_htlc_cur_del(void *pCur);


/********************************************************************
 * payment
 ********************************************************************/

//XXX: comment
bool ln_db_payment_get_new_payment_id(uint64_t *pPaymentId);

//XXX: comment
bool ln_db_payment_shared_secrets_save(uint64_t PaymentId, const uint8_t *pData, uint32_t Len);
bool ln_db_payment_shared_secrets_load(utl_buf_t *pBuf, uint64_t PaymentId);
bool ln_db_payment_shared_secrets_del(uint64_t PaymentId);

//XXX: comment
bool ln_db_payment_route_save(uint64_t PaymentId, const uint8_t *pData, uint32_t Len);
bool ln_db_payment_route_load(utl_buf_t *pBuf, uint64_t PaymentId);
bool ln_db_payment_route_del(uint64_t PaymentId);

//XXX: comment
bool ln_db_payment_invoice_save(uint64_t PaymentId, const uint8_t *pData, uint32_t Len);
bool ln_db_payment_invoice_load(utl_buf_t *pBuf, uint64_t PaymentId);
bool ln_db_payment_invoice_load_2(utl_buf_t *pBuf, uint64_t PaymentId, void *pDbParam);
bool ln_db_payment_invoice_del(uint64_t PaymentId);

//XXX: comment
bool ln_db_payment_info_save(uint64_t PaymentId, const ln_payment_info_t *pInfo);
bool ln_db_payment_info_load(ln_payment_info_t *pInfo, uint64_t PaymentId);
bool ln_db_payment_info_del(uint64_t PaymentId);

bool ln_db_payment_del_all(uint64_t PaymentId);


/********************************************************************
 * payment cursor
 ********************************************************************/

//XXX: comment
bool ln_db_payment_info_cur_open(void **ppCur);
void ln_db_payment_info_cur_close(void *pCur, bool bCommit);
bool ln_db_payment_info_cur_get(void *pCur, uint64_t *pPaymentId, ln_payment_info_t *pInfo);
bool ln_db_payment_info_cur_del(void *pCur);


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
