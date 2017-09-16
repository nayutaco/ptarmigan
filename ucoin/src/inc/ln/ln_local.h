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
/** @file   ln_local.h
 *  @brief  [LN]内部管理用
 *  @author ueno@nayuta.co
 */
#ifndef LN_LOCAL_H__
#define LN_LOCAL_H__

#include "ucoin_local.h"
#include "ln.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define MSG_FUNDIDX_FUNDING             (0)         ///< commitment tx署名用
#define MSG_FUNDIDX_REVOCATION          (1)         ///< revocation-basepoint生成用
#define MSG_FUNDIDX_PAYMENT             (2)         ///< payment-basepoint生成用
#define MSG_FUNDIDX_DELAYED_PAYMENT     (3)         ///< delayed-payment-basepoint生成用
#define MSG_FUNDIDX_PER_COMMIT          (4)         ///< per-commitment-point

#define MSG_SCRIPTIDX_KEY               (0)         ///< [To-Remote]のP2WPKH
#define MSG_SCRIPTIDX_DELAYED           (1)         ///< [To-Local]delayedkey
#define MSG_SCRIPTIDX_REVOCATION        (2)         ///< [To-Local]revocation


/*
 * message type
 */
#define MSGTYPE_INIT                        ((uint16_t)0x0010)
#define MSGTYPE_ERROR                       ((uint16_t)0x0011)
#define MSGTYPE_PING                        ((uint16_t)0x0012)
#define MSGTYPE_PONG                        ((uint16_t)0x0013)

#define MSGTYPE_OPEN_CHANNEL                ((uint16_t)0x0020)
#define MSGTYPE_ACCEPT_CHANNEL              ((uint16_t)0x0021)
#define MSGTYPE_FUNDING_CREATED             ((uint16_t)0x0022)
#define MSGTYPE_FUNDING_SIGNED              ((uint16_t)0x0023)
#define MSGTYPE_FUNDING_LOCKED              ((uint16_t)0x0024)
#define MSGTYPE_SHUTDOWN                    ((uint16_t)0x0026)
#define MSGTYPE_CLOSING_SIGNED              ((uint16_t)0x0027)

#define MSGTYPE_UPDATE_ADD_HTLC             ((uint16_t)0x0080)
#define MSGTYPE_UPDATE_FULFILL_HTLC         ((uint16_t)0x0082)
#define MSGTYPE_UPDATE_FAIL_HTLC            ((uint16_t)0x0083)
#define MSGTYPE_COMMITMENT_SIGNED           ((uint16_t)0x0084)
#define MSGTYPE_REVOKE_AND_ACK              ((uint16_t)0x0085)
#define MSGTYPE_UPDATE_FEE                  ((uint16_t)0x0086)
#define MSGTYPE_UPDATE_FAIL_MALFORMED_HTLC  ((uint16_t)0x0087)
#define MSGTYPE_CHANNEL_REESTABLISH         ((uint16_t)0x0088)

#define MSGTYPE_CHANNEL_ANNOUNCEMENT        ((uint16_t)0x0100)
#define MSGTYPE_NODE_ANNOUNCEMENT           ((uint16_t)0x0101)
#define MSGTYPE_CHANNEL_UPDATE              ((uint16_t)0x0102)
#define MSGTYPE_ANNOUNCEMENT_SIGNATURES     ((uint16_t)0x0103)


// self.init_flag
#define INIT_FLAG_SEND              (0x01)
#define INIT_FLAG_RECV              (0x02)
#define INIT_FLAG_INITED(flag)      (flag & (INIT_FLAG_SEND | INIT_FLAG_RECV))
#define INIT_FLAG_REEST_SEND        (0x04)
#define INIT_FLAG_REEST_RECV        (0x08)
#define INIT_FLAG_REESTED(flag)     (flag & (INIT_FLAG_REEST_SEND | INIT_FLAG_REEST_RECV))
#define INIT_FLAG_ALL               (INIT_FLAG_INITED | INIT_FLAG_REESTED)

#define NODE_LF_INIT                (0x55)          ///< init未受信の判定および不要ビットマスク
                                                    //      [0]xx_00_00_00
                                                    //         ^^
#define NODE_LF_INIT_ROUTE_SYNC     (4)
#define NODE_LOCALFEATURES          (0)             ///< TODO:init.localfeaturesのデフォルト値

#define CHANNEL_FLAGS_MASK          (0xfe)          ///< open_channel.channel_flagsのマスク
#define CHANNEL_FLAGS               (1)             ///< TODO:open_channel.channel_flagsのデフォルト値
                                                    // 今のところ announce_channelのみで、1を期待

#define VOUT_OPT_NONE               (0xff)


/**************************************************************************
 * const variables
 **************************************************************************/

extern uint8_t HIDDEN gGenesisChainHash[LN_SZ_HASH];


/**************************************************************************
 * prototypes
 **************************************************************************/

/** Obscured Commitment Number計算
 *
 * @param[in]       pLocalBasePt
 * @param[in]       pRemoteBasePt
 * @return      Obscured Commitment Number
 */
uint64_t HIDDEN ln_calc_obscured_txnum(const uint8_t *pLocalBasePt, const uint8_t *pRemoteBasePt);


/** To-Localスクリプト作成
 *
 * @param[out]      pBuf                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocalDelayedKey    Local Delayed Key[33]
 * @param[in]       LocalDelay          Local Delay(OP_CSV)
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
void HIDDEN ln_create_script_local(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay);


/** @def        ln_create_script_success
 *  @brief      HTLC-Success Transactionスクリプト作成
 *  @note       #ln_create_script_local()と同じ
 */
#define ln_create_script_success  ln_create_script_local


/** @def        ln_create_script_timeout
 *  @brief      HTLC-Timeout Transactionスクリプト作成
 *  @note       #ln_create_script_local()と同じ
 */
#define ln_create_script_timeout  ln_create_script_local


/** Offered HTLCスクリプト作成
 *
 * @param[out]      pBuf                    生成したスクリプト
 * @param[in]       pLocalKey               LocalKey[33]
 * @param[in]       pLocalRevoKey           Local RevocationKey[33]
 * @param[in]       pLocalPreImageHash160   Local payment-preimage-hash[20]
 * @param[in]       pRemoteKey              RemoteKey[33]
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
void HIDDEN ln_create_script_offered(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalPreImageHash160,
                    const uint8_t *pRemoteKey);


/** Received HTLCスクリプト作成
 *
 * @param[out]      pBuf                    生成したスクリプト
 * @param[in]       pLocalKey               LocalKey[33]
 * @param[in]       pLocalRevoKey           Local RevocationKey[33]
 * @param[in]       pRemoteKey              RemoteKey[33]
 * @param[in]       pRemotePreImageHash160  Remote payment-preimage-hash[20]
 * @param[in]       RemoteExpiry            Expiry
 *
 * @note
 *      - 相手署名計算時は、LocalとRemoteを入れ替える
 */
void HIDDEN ln_create_script_received(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteKey,
                    const uint8_t *pRemotePreImageHash160,
                    uint32_t RemoteExpiry);


/** 公開鍵からscriptPubKeyを生成
 *
 * @param[out]      pBuf
 * @param[in]       pPub        公開鍵 or witnessScript
 * @param[in]       Prefix      UCOIN_PREF_xxx
 * @retval      true    成功
 * @retval      false   Prefix範囲外
 * @note
 *      - shutdownメッセージ用
 */
bool HIDDEN ln_create_scriptpkh(ucoin_buf_t *pBuf, const ucoin_buf_t *pPub, int Prefix);


/** scriptPubKeyのチェック(P2PKH/P2SH/P2WPKH/P2WSH)
 *
 * @param[in]       pBuf
 * @retval      true    チェックOK
 * @note
 *      - shutdownメッセージ受信用
 */
bool HIDDEN ln_check_scriptpkh(const ucoin_buf_t *pBuf);


/** HTLC情報初期化
 *
 *
 */
void HIDDEN ln_htlcinfo_init(ln_htlcinfo_t *pHtlcInfo);


void HIDDEN ln_htlcinfo_free(ln_htlcinfo_t *pHtlcInfo);


/** HTLC情報作成
 *
 * @param[in]       ppHtlcInfo  HTLC情報ポインタ配列
 * @param[in]       Num         HTLC数
 * @param[in]       pLocalKey           LocalKey[33]
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pRemoteKey          RemoteKey[33]
 *
 * @note
 *      - pHtlcInfoにtype, preimage_hash, expiryを代入しておくこと
 */
void HIDDEN ln_create_htlcinfo(ln_htlcinfo_t **ppHtlcInfo, int Num,
                    const uint8_t *pLocalKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteKey);


/** FEE計算
 *
 * feerate_per_kw, dust_limit_satoshiおよびHTLC情報から、HTLCおよびcommit txのFEEを算出する。
 *
 * @param[in,out]   pFeeInfo    FEE情報
 * @param[in]       ppHtlcInfo  HTLC情報ポインタ配列
 * @param[in]       Num         HTLC数
 * @return      actual FEE
 *
 * @note
 *      - pFeeInfoにfeerate_per_kwとdust_limit_satoshiを代入しておくこと
 */
uint64_t HIDDEN ln_fee_calc(ln_feeinfo_t *pFeeInfo, const ln_htlcinfo_t **ppHtlcInfo, int Num);


/** Commitment Transaction作成
 *
 * @param[out]      pTx         TX情報
 * @param[out]      pSig        local署名
 * @param[in]       pCmt        Commitment Transaction情報
 * @param[in]       Local       true:LocalがFEEを払う
 * @return      true:成功
 */
bool HIDDEN ln_cmt_create(ucoin_tx_t *pTx, ucoin_buf_t *pSig, const ln_tx_cmt_t *pCmt, bool Local);


/** P2WSH署名 - LN:HTLC-success/timeoutトランザクション更新
 *
 * @param[in,out]   pTx
 * @param[out]      pLocalSig       署名
 * @param[in]       Value           INPUTのamount
 * @param[in]       pKeys           CommitTxのlocal署名用
 * @param[in]       pRemoteSig      commit_tx相手からの署名
 * @param[in]       pPreImage       非NULL:payment_preimageでHTLC-Successとして署名, NULL:HTLC-Timeoutとして署名
 * @param[in]       CltvExpiry
 * @param[in]       pWitScript
 * @return      true:成功
 */
bool HIDDEN ln_sign_p2wsh_success_timeout(ucoin_tx_t *pTx, ucoin_buf_t *pLocalSig,
                    uint64_t Value,
                    const ucoin_util_keys_t *pKeys,
                    const ucoin_buf_t *pRemoteSig,
                    const uint8_t *pPreImage,
                    uint32_t CltvExpiry,
                    const ucoin_buf_t *pWitScript);


bool HIDDEN ln_verify_p2wsh_success_timeout(ucoin_tx_t *pTx,
                    uint64_t Value,
                    const uint8_t *pLocalPubKey,
                    const uint8_t *pRemotePubKey,
                    const ucoin_buf_t *pLocalSig,
                    const ucoin_buf_t *pRemoteSig,
                    uint32_t CltvExpiry,
                    const ucoin_buf_t *pWitScript);


/**************************************************************************
 * ONION
 **************************************************************************/

/** [ONION]blindGroupElement()相当
 *
 */
bool HIDDEN ln_mul_pubkey(uint8_t *pResult, const uint8_t *pPubKey, const uint8_t *Mul, int MulLen);


/** ONIONパラメータ復元
 *
 * @param[out]      pNextPacket         次に送るONIONパケット[LN_SZ_ONION_ROUTE]
 * @param[out]      pNextData           復元情報
 * @param[in]       pPacket             解析するONIONパケット
 * @param[in]       pOnionPrivKey       自ノード秘密鍵?
 * @param[in]       pAssocData          Associated Data
 * @param[in]       AssocLen            pAssocData長
 * @retval      true    成功
 * @note
 *      - pNextData->b_exitがtrueの場合、pNextPacketは無効
 *      - pNextPacketとpPacketに同じアドレスを指定できる
 */
bool HIDDEN ln_onion_read_packet(uint8_t *pNextPacket, ln_hop_dataout_t *pNextData,
            const uint8_t *pPacket,
            const uint8_t *pOnionPrivKey,
            const uint8_t *pAssocData, int AssocLen);


/**************************************************************************
 * Key Derivation
 **************************************************************************/

/** key導出
 *
 * @param[out]      pPubKey         pubkey
 * @param[in]       pBasePoint      BasePoint
 * @param[in]       pPerCommitPoint per Commitment Point
 */
bool HIDDEN ln_derkey_pubkey(uint8_t *pPubKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint);


/** private key導出
 *
 * @param[out]      pPrivKey        privatekey
 * @param[in]       pBasePoint      BasePoint
 * @param[in]       pPerCommitPoint per Commitment Point
 * @param[in]       pBaseSecret     Base Secret Point
 */
bool HIDDEN ln_derkey_privkey(uint8_t *pPrivKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint,
            const uint8_t *pBaseSecret);


/** revocation key導出
 *
 * @param[out]      pRevPubKey      Revocation key
 * @param[in]       pBasePoint      BasePoint
 * @param[in]       pPerCommitPoint per Commitment Point
 */
bool HIDDEN ln_derkey_revocationkey(uint8_t *pRevPubKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint);


/** revocation private key導出
 *
 * @param[out]      pPrivKey            Revocation privatekey
 * @param[in]       pBasePoint          BasePoint
 * @param[in]       pPerCommitPoint     per Commitment Point
 * @param[in]       pBaseSecret         Base Secret Point
 * @param[in]       pPerCommitSecret    per Commitment Secret Point
 */
bool HIDDEN ln_derkey_revocationprivkey(uint8_t *pRevPrivKey,
            const uint8_t *pBasePoint, const uint8_t *pPerCommitPoint,
            const uint8_t *pBaseSecret, const uint8_t *pPerCommitSecret);


/** per-commitment secret生成
 *
 * @param[out]      pPrivKey
 * @param[in]       pSeed(32byte)
 * @param[in]       Index(下位6byte使用)
 */
void HIDDEN ln_derkey_create_secret(uint8_t *pPrivKey, const uint8_t *pSeed, uint64_t Index);


/** per-commitment secret storage初期化
 *
 * @param[out]      pStorage
 */
void HIDDEN ln_derkey_storage_init(ln_derkey_storage *pStorage);


/** per-commitment secret storage追加
 *
 * @param[in,out]   pStorage
 * @param[in]       pSecret
 * @param[in]       Index
 * @return      true    成功
 */
bool HIDDEN ln_derkey_storage_insert_secret(ln_derkey_storage *pStorage, const uint8_t *pSecret, uint64_t Index);


/** per-commitment secret取得
 *
 * @param[out]      pSecret
 * @param[in]       pStorage
 * @param[in]       Index
 * @return      true    成功
 */
bool HIDDEN ln_derkey_storage_get_secret(uint8_t *pSecret, const ln_derkey_storage *pStorage, uint64_t Index);


/** DB初期化
 *
 *
 */
void HIDDEN ln_db_init(void);

#endif /* LN_LOCAL_H__ */
