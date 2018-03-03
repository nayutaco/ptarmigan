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

//0～5は、open_channel/accept_channelのfunding_pubkey～first_per_commitment_pointの順にすること
//プロトコルで違いが生じた場合は、ソースを変更すること(ln_msg_establish.c)
#define MSG_FUNDIDX_FUNDING             (0)         ///< commitment tx署名用
#define MSG_FUNDIDX_REVOCATION          (1)         ///< revocation_basepoint
#define MSG_FUNDIDX_PAYMENT             (2)         ///< payment_basepoint
#define MSG_FUNDIDX_DELAYED             (3)         ///< delayed_payment_basepoint
#define MSG_FUNDIDX_HTLC                (4)         ///< htlc_basepoint
#define MSG_FUNDIDX_PER_COMMIT          (5)         ///< per_commitment_point
#define MSG_FUNDIDX_MAX                 (MSG_FUNDIDX_PER_COMMIT+1)
#if LN_FUNDIDX_MAX != MSG_FUNDIDX_MAX
#error LN_FUNDIDX_MAX != MSG_FUNDIDX_MAX
#endif

#define MSG_SCRIPTIDX_REMOTEKEY         (0)         ///< remotekey
#define MSG_SCRIPTIDX_DELAYED           (1)         ///< delayedkey
#define MSG_SCRIPTIDX_REVOCATION        (2)         ///< revocationkey
#define MSG_SCRIPTIDX_LOCALHTLCKEY      (3)         ///< local_htlckey
#define MSG_SCRIPTIDX_REMOTEHTLCKEY     (4)         ///< remote_htlckey
#define MSG_SCRIPTIDX_MAX               (MSG_SCRIPTIDX_REMOTEHTLCKEY+1)
#if LN_SCRIPTIDX_MAX != MSG_SCRIPTIDX_MAX
#error LN_SCRIPTIDX_MAX != MSG_SCRIPTIDX_MAX
#endif


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

#define MSGTYPE_IS_PINGPONG(type)           (((type) == MSGTYPE_PING) || (type) == MSGTYPE_PONG) 
#define MSGTYPE_IS_ANNOUNCE(type)           ((MSGTYPE_CHANNEL_ANNOUNCEMENT <= (type)) && ((type) <= MSGTYPE_CHANNEL_UPDATE))

// init.localfeatures
#define INIT_LF_OPT_DATALOSS_REQ    (1 << 0)    ///< option-data-loss-protect
#define INIT_LF_OPT_DATALOSS_OPT    (1 << 1)    ///< option-data-loss-protect
#define INIT_LF_OPT_DATALOSS        (INIT_LF_OPT_DATALOSS_REQ | INIT_LF_OPT_DATALOSS_OPT)
#define INIT_LF_ROUTE_SYNC          (1 << 3)    ///< initial_routing_sync
#define INIT_LF_OPT_UPF_SHDN_REQ    (1 << 4)    ///< option_upfront_shutdown_script
#define INIT_LF_OPT_UPF_SHDN_OPT    (1 << 5)    ///< option_upfront_shutdown_script
#define INIT_LF_OPT_UPF_SHDN        (INIT_LF_OPT_UPF_SHDN_REQ | INIT_LF_OPT_UPF_SHDN_OPT)
#define INIT_LF_MASK                (INIT_LF_OPT_DATALOSS | INIT_LF_ROUTE_SYNC | INIT_LF_OPT_UPF_SHDN)
#define INIT_LF_VALUE               { INIT_LF_ROUTE_SYNC }
#define INIT_LF_SZ_VALUE            (1)

#define CHANNEL_FLAGS_ANNOCNL       (1 << 0)
#define CHANNEL_FLAGS_MASK          CHANNEL_FLAGS_ANNOCNL   ///< open_channel.channel_flagsのBOLT定義あり
#define CHANNEL_FLAGS_VALUE         CHANNEL_FLAGS_ANNOCNL   ///< TODO:open_channel.channel_flags


/**************************************************************************
 * const variables
 **************************************************************************/

typedef enum {
    HTLCSIGN_NONE,              ///< 未設定
    HTLCSIGN_TO_SUCCESS,        ///< HTLC Success
    HTLCSIGN_OF_PREIMG,         ///< 相手が送信したcommit_txのOffered HTLC
    HTLCSIGN_RV_TIMEOUT,        ///< 相手が送信したcommit_txのReceived HTLC
    HTLCSIGN_RV_RECEIVED,       ///< revoked transactionのreceived HTLC output
    HTLCSIGN_RV_OFFERED,        ///< revoked transactionのoffered HTLC output
} ln_htlcsign_t;


/**************************************************************************
 * const variables
 **************************************************************************/

extern uint8_t HIDDEN gGenesisChainHash[LN_SZ_HASH];


/**************************************************************************
 * prototypes
 **************************************************************************/

/** revoked transaction close用のスクリプトバッファ確保
 *
 */
void HIDDEN ln_alloc_revoked_buf(ln_self_t *self);


/** revoked transaction close用のスクリプトバッファ解放
 *
 */
void HIDDEN ln_free_revoked_buf(ln_self_t *self);


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


/**
 *
 */
bool HIDDEN ln_create_tolocal_tx(ucoin_tx_t *pTx,
                uint64_t Value, const ucoin_buf_t *pScriptPk, uint32_t LockTime,
                const uint8_t *pTxid, int Index, bool bRevoked);


/**
 *
 */
bool HIDDEN ln_sign_tolocal_tx(ucoin_tx_t *pTx, ucoin_buf_t *pSig,
                    uint64_t Value,
                    const ucoin_util_keys_t *pKeys,
                    const ucoin_buf_t *pWitScript, bool bRevoked);


/** HTLC-Timeout Txの出力先スクリプト作成
 *
 * @param[out]      pBuf                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocalDelayedKey    Local Delayed Key[33]
 * @param[in]       LocalDelay          Local Delay(OP_CSV)
 * @note
 *      - ln_create_script_local()と同じ
 */
static inline void ln_create_script_success(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay) {
    ln_create_script_local(pBuf, pLocalRevoKey, pLocalDelayedKey, LocalDelay);
}


/** HTLC-Success Txの出力先スクリプト作成
 *
 * @param[out]      pBuf                生成したスクリプト
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pLocalDelayedKey    Local Delayed Key[33]
 * @param[in]       LocalDelay          Local Delay(OP_CSV)
 * @note
 *      - ln_create_script_local()と同じ
 */
static inline void ln_create_script_timeout(ucoin_buf_t *pBuf,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pLocalDelayedKey,
                    uint32_t LocalDelay) {
    ln_create_script_local(pBuf, pLocalRevoKey, pLocalDelayedKey, LocalDelay);
}


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


/** HTLC情報初期化
 *
 *
 */
void HIDDEN ln_htlcinfo_free(ln_htlcinfo_t *pHtlcInfo);


/** HTLC Txスクリプト生成
 *
 * @param[out]      pScript             生成したスクリプト
 * @param[in]       Type                HTLC種別
 * @param[in]       pLocalHtlcKey       Local htlckey[33]
 * @param[in]       pLocalRevoKey       Local RevocationKey[33]
 * @param[in]       pRemoteHtlcKey      Remote htlckey[33]
 * @param[in]       pPaymentHash        payment_hash[32]
 * @param[in]       Expiry              expiry(HTLC-Success用)
 */
void HIDDEN ln_create_htlcinfo(ucoin_buf_t *pScript, ln_htlctype_t Type,
                    const uint8_t *pLocalHtlcKey,
                    const uint8_t *pLocalRevoKey,
                    const uint8_t *pRemoteHtlcKey,
                    const uint8_t *pPaymentHash,
                    uint32_t Expiry);


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
bool HIDDEN ln_create_commit_tx(ucoin_tx_t *pTx, ucoin_buf_t *pSig, const ln_tx_cmt_t *pCmt, bool Local);


/** Offered/Receveid HTLC Transaction作成
 *
 * @param[out]      pTx         TX情報
 * @param[in]       Value       vout amount
 * @param[in]       pScript     vout P2WSHスクリプト
 * @param[in]       Type        pScriptタイプ(LN_HTLCTYPE_xxx)
 * @param[in]       CltvExpiry  locktime(TypeがOffered HTLCの場合のみ)
 * @param[in]       pTxid       vin TXID
 * @param[in]       Index       vin index
 */
void HIDDEN ln_create_htlc_tx(ucoin_tx_t *pTx, uint64_t Value, const ucoin_buf_t *pScript,
                ln_htlctype_t Type, uint32_t CltvExpiry, const uint8_t *pTxid, int Index);


/** Offered/Receveid HTLC Transaction署名
 *
 * @param[in,out]   pTx
 * @param[out]      pLocalSig       署名
 * @param[in]       Value           INPUTのamount
 * @param[in]       pKeys           CommitTxのlocal署名用
 * @param[in]       pRemoteSig      commit_tx相手からの署名
 * @param[in]       pPreImage       非NULL:payment_preimageでHTLC-Successとして署名, NULL:HTLC-Timeoutとして署名
 * @param[in]       pWitScript      voutとなるスクリプト
 * @param[in]       HtlcSign        HTLCSIGN_xxx
 * @return      true:成功
 */
bool HIDDEN ln_sign_htlc_tx(ucoin_tx_t *pTx, ucoin_buf_t *pLocalSig,
                    uint64_t Value,
                    const ucoin_util_keys_t *pKeys,
                    const ucoin_buf_t *pRemoteSig,
                    const uint8_t *pPreImage,
                    const ucoin_buf_t *pWitScript,
                    ln_htlcsign_t HtlcSign);


/** Offered/Receveid HTLC Transaction署名verify
 *
 * @param[in]       pTx
 * @param[in]       Value           INPUTのamount
 * @param[in]       pLocalPubKey
 * @param[in]       pRemotePubKey
 * @param[in]       pLocalSig
 * @param[in]       pRemoteSig      commit_tx相手からの署名
 * @param[in]       pWitScript      voutとなるスクリプト
 * @return      true:成功
 */
bool HIDDEN ln_verify_htlc_tx(const ucoin_tx_t *pTx,
                    uint64_t Value,
                    const uint8_t *pLocalPubKey,
                    const uint8_t *pRemotePubKey,
                    const ucoin_buf_t *pLocalSig,
                    const ucoin_buf_t *pRemoteSig,
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
 * @param[out]      pSharedSecret       共有秘密鍵
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
            ucoin_buf_t *pSharedSecret,
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
 * DBを使用できるようにする。
 * また、新規の場合は引数をDBに書き込み、新規でない場合にはDBから読込む
 * 
 * @param[in,out]   pWif            ノードの秘密鍵
 * @param[in,out]   pNodeName       ノード名
 * @param[in,out]   pPort           ポート番号
 * @retval  true    初期化成功
 */
bool HIDDEN ln_db_init(char *pWif, char *pNodeName, uint16_t *pPort);


/** DBで保存している対象のデータだけコピーする
 *
 * @param[out]  pOutSelf    コピー先
 * @param[in]   pInSelf     コピー元
 */
void HIDDEN ln_db_copy_channel(ln_self_t *pOutSelf, const ln_self_t *pInSelf);

#endif /* LN_LOCAL_H__ */
