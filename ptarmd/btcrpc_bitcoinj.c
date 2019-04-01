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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "jni/btcj_jni.h"

#define LOG_TAG     "btcrpc"
#include "utl_log.h"
#include "utl_dbg.h"
#include "utl_mem.h"
#include "utl_str.h"

#include "btc_script.h"
#include "btc_sw.h"

#include "btcrpc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#if 0
#define LOGD_BTCTRACE(...)
#define LOGD_BTCRESULT(...)
#define DUMPD_BTCRESULT(...)
#define TXIDD_BTCRESULT(...)
#define LOGD_BTCFAIL(...)
#define LOGD_PTHREAD(...)
#define LOGD_JNI(...)
#else
#define LOGD_BTCTRACE       LOGD
#define LOGD_BTCRESULT      LOGD
#define DUMPD_BTCRESULT     DUMPD
#define TXIDD_BTCRESULT     TXIDD
#define LOGD_BTCFAIL        LOGD
#define LOGD_PTHREAD        LOGD
#define LOGD_JNI            LOGD
#endif


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    bool            ret;
    const uint8_t   *p_hash;
} setcreationhash_t;


typedef struct {
    bool        ret;
    int32_t     *p_cnt;
    uint8_t     *p_hash;
} getblockcount_t;


typedef struct {
    bool        ret;
    uint8_t     *p_hash;
} getgenesisblockhash_t;


typedef struct {
    bool            ret;
    uint32_t        *p_confirm;
    const uint8_t   *p_txid;
} getconfirmation_t;


typedef struct {
    bool            ret;
    const uint8_t   *p_peerid;
    int32_t         *p_b_height;
    int32_t         *p_b_index;
    uint8_t         *p_mined_hash;
    const uint8_t   *p_txid;
} getshortchannelparam_t;


typedef struct {
    bool            ret;
    btc_tx_t        *p_tx;
    uint32_t        blks;
    const uint8_t   *p_txid;
    uint32_t        v_index;
} searchoutpoint_t;


typedef struct {
    bool            ret;
    utl_buf_t       *p_txbuf;
    uint32_t        blks;
    const utl_buf_t *p_vout;
} searchvout_t;


typedef struct {
    bool            ret;
    btc_tx_t        *p_tx;
    const uint8_t   *p_scriptpubkey;
    size_t          len;
    uint64_t        amount;
} signrawtx_t;


typedef struct {
    bool            ret;
    uint8_t         *p_txid;
    int             *p_code;
    const uint8_t   *p_raw_data;
    uint32_t        len;
} sendrawtx_t;


typedef struct {
    bool            ret;
    const uint8_t   *p_txid;
} checkbroadcast_t;


typedef struct {
    bool            ret;
    bool            *p_unspent;
    const uint8_t   *p_peerid;
    const uint8_t   *p_txid;
    uint32_t        v_index;
} checkunspent_t;


typedef struct {
    bool            ret;
    char            *p_addr;
} getnewaddress_t;


typedef struct {
    bool            ret;
    uint64_t        *p_fee_satoshi;
    int             blks;
} estimatefee_t;


typedef struct {
    const uint8_t   *p_peer_id;
    uint64_t        short_channel_id;
    const uint8_t   *p_fundingtxid;
    int             fundingidx;
    const uint8_t   *p_scriptpubkey;
    const uint8_t   *mined_hash;
    uint32_t        last_confirm;
} setchannel_t;


typedef struct {
    const uint8_t   *p_peer_id;
} delchannel_t;


typedef struct {
    bool            ret;
    uint64_t        *p_amount;
} getbalance_t;


typedef struct {
    bool            ret;
    uint8_t         *p_txid;
    const char      *p_addr;
} emptywallet_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

static void call_jni(btcj_method_t Method, void *pParam);

static void *thread_jni_start(void *pArg);
static void jni_set_creationhash(void *pArg);
static void jni_get_blockcount(void *pArg);
static void jni_get_genesisblockhash(void *pArg);
static void jni_get_txconfirm(void *pArg);
static void jni_get_short_channel_param(void *pArg);
static void jni_get_txid_from_short_channel_id(void *pArg);
static void jni_search_outpoint(void *pArg);
static void jni_search_vout(void *pArg);
static void jni_sign_rawtx(void *pArg);
static void jni_send_rawtx(void *pArg);
static void jni_is_tx_broadcasted(void *pArg);
static void jni_check_unspent(void *pArg);
static void jni_get_newaddress(void *pArg);
static void jni_estimatefee(void *pArg);
static void jni_set_channel(void *pArg);
static void jni_del_channel(void *pArg);
static void jni_set_committxid(void *pArg);
static void jni_get_balance(void *pArg);
static void jni_empty_wallet(void *pArg);
static void jni_exit(void *pArg);


/**************************************************************************
 * static variables
 **************************************************************************/

static pthread_t            mTh;
static pthread_mutex_t      mMuxCall;
static pthread_mutex_t      mMuxApi;
static pthread_cond_t       mCondApi;        ///< APIの待ち合わせ

static volatile enum {
    JNILOOP_INI,
    JNILOOP_WORK,
    JNILOOP_STOP,
    JNILOOP_ABORT,
} mLoopJni;
static pthread_mutex_t      mMuxJni;
static pthread_cond_t       mCondJni;        ///< JNIの待ち合わせ
static struct {
    uint8_t     method;
    void        *p_arg;
} mMethodParam;


/**************************************************************************
 * const variables
 **************************************************************************/

static const struct {
    void (*p_func)(void *pArg);
} kJniFuncs[METHOD_PTARM_MAX] = {
    //METHOD_PTARM_SETCREATIONHASH
    { jni_set_creationhash },
    // METHOD_PTARM_GETBLOCKCOUNT,
    { jni_get_blockcount },
    // METHOD_PTARM_GETGENESISBLOCKHASH,
    { jni_get_genesisblockhash },
    // METHOD_PTARM_GETCONFIRMATION,
    { jni_get_txconfirm },
    // METHOD_PTARM_GETSHORTCHANNELPARAM,
    { jni_get_short_channel_param },
    // METHOD_PTARM_GETTXIDFROMSHORTCHANNELID,
    { jni_get_txid_from_short_channel_id },
    // METHOD_PTARM_SEARCHOUTPOINT,
    { jni_search_outpoint },
    // METHOD_PTARM_SEARCHVOUT,
    { jni_search_vout },
    // METHOD_PTARM_SIGNRAWTX,
    { jni_sign_rawtx },
    // METHOD_PTARM_SENDRAWTX,
    { jni_send_rawtx },
    // METHOD_PTARM_CHECKBROADCAST,
    { jni_is_tx_broadcasted },
    // METHOD_PTARM_CHECKUNSPENT,
    { jni_check_unspent },
    // METHOD_PTARM_GETNEWADDRESS,
    { jni_get_newaddress },
    // METHOD_PTARM_ESTIMATEFEE,
    { jni_estimatefee },
    // METHOD_PTARM_SETCHANNEL,
    { jni_set_channel },
    // METHOD_PTARM_DELCHANNEL,
    { jni_del_channel },
    // METHOD_PTARM_SETCOMMITTXID,
    { jni_set_committxid },
    // METHOD_PTARM_GETBALANCE,
    { jni_get_balance },
    // METHOD_PTARM_EMPTYWALLET,
    { jni_empty_wallet },
    // METHOD_PTARM_EXIT,
    { jni_exit },
};


/**************************************************************************
 * public functions
 **************************************************************************/

bool btcrpc_init(const rpc_conf_t *pRpcConf)
{
    pthread_mutex_init(&mMuxCall, NULL);
    pthread_mutex_init(&mMuxApi, NULL);
    pthread_cond_init(&mCondApi, NULL);
    pthread_mutex_init(&mMuxJni, NULL);
    pthread_cond_init(&mCondJni, NULL);

    mLoopJni = JNILOOP_INI;

    pthread_create(&mTh, NULL, &thread_jni_start, (CONST_CAST void*)pRpcConf);

    //wait jni start...
    int count = 60 * 1;       //1s * count
    LOGD("$$$ SYNC start\n");
    fprintf(stderr, "Java initialize...");

    //もしbitcoinjが、動作がうまく行かない場合でもメソッドから抜ける場合、
    //こちらでタイムアウトの監視をする必要はない。
    //しかし、bitcoinjが戻ってこないままになったらどうする？
    //その場合は、btcj_init()
    while ((mLoopJni == JNILOOP_INI) && (count > 0)) {
        //mLoopJni changes in thread_jni_start()
        sleep(1);
        fprintf(stderr, ".");
        LOGD("count=%d\n", count);
        count--;
    }
    if ((mLoopJni != JNILOOP_WORK) || (count <= 0)) {
        if (count == 0) {
            LOGE("fail: JNI timeout\n");
            mLoopJni = JNILOOP_ABORT;
        } else {
            LOGE("fail: JNI thread(%d)\n", mLoopJni);
        }
        fprintf(stderr, "JNI thread cannot start.\n");
        return false;
    }
    fprintf(stderr, "SYNC done\n");
    LOGD("$$$ SYNC done\n");

    int32_t bcnt;
    uint8_t bhash[BTC_SZ_HASH256];
    memset(bhash, 0xcc, sizeof(bhash));
    getblockcount_t param;
    param.p_cnt = &bcnt;
    param.p_hash = bhash;
    call_jni(METHOD_PTARM_GETBLOCKCOUNT, &param);
    ln_creationhash_set(bhash);

    return true;
}


void btcrpc_term(void)
{
    LOGD("\n");

    mLoopJni = JNILOOP_STOP;
    pthread_cond_signal(&mCondJni);
    pthread_cond_signal(&mCondApi);

    pthread_cond_destroy(&mCondJni);
    pthread_mutex_destroy(&mMuxJni);
    pthread_cond_destroy(&mCondApi);
    pthread_mutex_destroy(&mMuxApi);
    pthread_mutex_destroy(&mMuxCall);

    pthread_join(mTh, NULL);
    LOGD("join: btcrpcj\n");
}


void btcrpc_set_creationhash(const uint8_t *pHash)
{
    LOGD_BTCTRACE("\n");

    setcreationhash_t param;
    param.p_hash = pHash;
    call_jni(METHOD_PTARM_SETCREATIONHASH, &param);
}


bool btcrpc_getblockcount(int32_t *pBlockCount)
{
    LOGD_BTCTRACE("\n");

    getblockcount_t param;
    param.p_cnt = pBlockCount;
    param.p_hash = NULL;
    call_jni(METHOD_PTARM_GETBLOCKCOUNT, &param);

    if (param.ret) {
        LOGD_BTCRESULT("getblockcount=%d\n", *pBlockCount);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_getgenesisblock(uint8_t *pHash)
{
    LOGD_BTCTRACE("\n");

    getgenesisblockhash_t param;
    param.p_hash = pHash;
    call_jni(METHOD_PTARM_GETGENESISBLOCKHASH, &param);
    if (param.ret) {
        LOGD_BTCRESULT("genesis hash=");
        DUMPD_BTCRESULT(pHash, BTC_SZ_HASH256);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_get_confirm(uint32_t *pConfirm, const uint8_t *pTxid)
{
    if (utl_mem_is_all_zero(pTxid, BTC_SZ_TXID)) {
        return false;
    }

    LOGD_BTCTRACE("\n");

    getconfirmation_t param;
    param.p_confirm = pConfirm;
    param.p_txid = pTxid;
    call_jni(METHOD_PTARM_GETCONFIRMATION, &param);
    if (param.ret) {
        LOGD_BTCRESULT("confirm=%" PRId32 "\n", *pConfirm);
    } else {
        LOGD_BTCFAIL("confirm=fail\n");
    }
    return param.ret;
}


bool btcrpc_get_short_channel_param(const uint8_t *pPeerId, int32_t *pBHeight, int32_t *pBIndex, uint8_t *pMinedHash, const uint8_t *pTxid)
{
    LOGD_BTCTRACE("\n");

    getshortchannelparam_t param;
    param.p_peerid = pPeerId;
    param.p_b_height = pBHeight;
    param.p_b_index = pBIndex;
    param.p_mined_hash = pMinedHash;
    param.p_txid = pTxid;
    call_jni(METHOD_PTARM_GETSHORTCHANNELPARAM, &param);
    if (param.ret) {
        LOGD_BTCRESULT("b_height=%" PRId32 ", b_index=%" PRId32 ", mined_hash=", *pBHeight, *pBIndex);
        TXIDD_BTCRESULT(pMinedHash);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_gettxid_from_short_channel(uint8_t *pTxid, int BHeight, int BIndex)
{
    (void)pTxid; (void)BHeight; (void)BIndex;
    return true;
}


bool btcrpc_search_outpoint(btc_tx_t *pTx, uint32_t Blks, const uint8_t *pTxid, uint32_t VIndex)
{
    if (utl_mem_is_all_zero(pTxid, BTC_SZ_TXID)) {
        return false;
    }

    LOGD_BTCTRACE("\n");

    searchoutpoint_t param;
    param.p_tx = pTx;
    param.blks = Blks;
    param.p_txid = pTxid;
    param.v_index = VIndex;
    call_jni(METHOD_PTARM_SEARCHOUTPOINT, &param);
    if (param.ret) {
        btc_tx_print(pTx);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_search_vout(utl_buf_t *pTxBuf, uint32_t Blks, const utl_buf_t *pVout)
{
    LOGD_BTCTRACE("\n");

    searchvout_t param;
    param.p_txbuf = pTxBuf;
    param.blks = Blks;
    param.p_vout = pVout;
    call_jni(METHOD_PTARM_SEARCHVOUT, &param);
    if (param.ret) {
        int len = pTxBuf->len / sizeof(utl_buf_t);
        const utl_buf_t *p_buf = (const utl_buf_t *)pTxBuf->buf;
        for (int lp = 0; lp < len; lp++) {
            LOGD_BTCRESULT("----[%d]----\n", lp);
            const btc_tx_t *p = (const btc_tx_t *)p_buf[lp].buf;
            btc_tx_print(p);
        }
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_sign_fundingtx(btc_tx_t *pTx, const uint8_t *pData, uint32_t Len, uint64_t Amount)
{
    (void)pData; (void)Len; (void)Amount;

    //P2WSH
    const uint8_t *p_witprog = pTx->vout[0].script.buf;
    if (pTx->vout[0].script.len != BTC_SZ_WITPROG_P2WSH) {
        LOGE("fail: invalid length\n");
        return false;
    }
    if (p_witprog[0] != 0) {
        LOGE("fail: not P2WSH\n");
        return false;
    }
    if (p_witprog[1] != BTC_SZ_HASH256) {
        LOGE("fail: not P2WSH len\n");
        return false;
    }

    LOGD_BTCTRACE("\n");

    signrawtx_t param;
    param.p_tx = pTx;
    param.p_scriptpubkey = p_witprog + BTC_OFFSET_WITPROG;
    param.len = BTC_SZ_HASH256;
    param.amount = pTx->vout[0].value;
    call_jni(METHOD_PTARM_SIGNRAWTX, &param);
    if (param.ret) {
        LOGD_BTCRESULT("send ok\n");
    } else {
        LOGD_BTCFAIL("fail\n");
    }

    return param.ret;
}


bool btcrpc_send_rawtx(uint8_t *pTxid, int *pCode, const uint8_t *pRawData, uint32_t Len)
{
    LOGD_BTCTRACE("\n");

    sendrawtx_t param;
    param.p_txid = pTxid;
    param.p_code = pCode;
    param.p_raw_data = pRawData;
    param.len = Len;
    call_jni(METHOD_PTARM_SENDRAWTX, &param);
    if (param.ret) {
        LOGD_BTCRESULT("txid=");
        TXIDD_BTCRESULT(pTxid);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_is_tx_broadcasted(const uint8_t *pTxid)
{
    if (utl_mem_is_all_zero(pTxid, BTC_SZ_TXID)) {
        return false;
    }

    LOGD_BTCTRACE("\n");

    checkbroadcast_t param;
    param.p_txid = pTxid;
    call_jni(METHOD_PTARM_CHECKBROADCAST, &param);
    LOGD_BTCRESULT("result=%d\n", param.ret);
    return param.ret;
}


bool btcrpc_check_unspent(const uint8_t *pPeerId, bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex)
{
    (void)pSat;

    if (utl_mem_is_all_zero(pTxid, BTC_SZ_TXID)) {
        return false;
    }

    LOGD_BTCTRACE("\n");

    checkunspent_t param;
    param.p_unspent = pUnspent;
    param.p_peerid = pPeerId;
    param.p_txid = pTxid;
    param.v_index = VIndex;
    call_jni(METHOD_PTARM_CHECKUNSPENT, &param);
    if (param.ret) {
        LOGD_BTCRESULT("txid(vout=%d)=", VIndex);
        TXIDD_BTCRESULT(pTxid);
        LOGD_BTCRESULT("    unspent: %d\n", *pUnspent);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_getnewaddress(char pAddr[BTC_SZ_ADDR_STR_MAX + 1])
{
    LOGD_BTCTRACE("\n");

    getnewaddress_t param;
    param.p_addr = pAddr;
    call_jni(METHOD_PTARM_GETNEWADDRESS, &param);
    if (param.ret) {
        LOGD_BTCRESULT("addr=%s\n", pAddr);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_estimatefee(uint64_t *pFeeSatoshi, int nBlocks)
{
    LOGD_BTCTRACE("\n");

    estimatefee_t param;
    param.p_fee_satoshi = pFeeSatoshi;
    param.blks = nBlocks;
    call_jni(METHOD_PTARM_ESTIMATEFEE, &param);
    if (param.ret) {
        LOGD_BTCRESULT("fee=%" PRIu64 "\n", *param.p_fee_satoshi);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


void btcrpc_set_channel(const uint8_t *pPeerId,
                uint64_t ShortChannelId,
                const uint8_t *pFundingTxid,
                int FundingIdx,
                const utl_buf_t *pRedeemScript,
                const uint8_t *pMinedHash,
                uint32_t LastConfirm)
{
    LOGD_BTCTRACE("\n");

    uint8_t witprog[BTC_SZ_WITPROG_P2WSH];
    btc_sw_wit2prog_p2wsh(witprog, pRedeemScript);

    setchannel_t param;
    param.p_peer_id = pPeerId;
    param.short_channel_id = ShortChannelId;
    param.p_fundingtxid = pFundingTxid;
    param.fundingidx = FundingIdx;
    param.p_scriptpubkey = witprog + BTC_OFFSET_WITPROG;
    param.mined_hash = pMinedHash;
    param.last_confirm = LastConfirm;
    call_jni(METHOD_PTARM_SETCHANNEL, &param);
}


void btcrpc_del_channel(const uint8_t *pPeerId)
{
    LOGD_BTCTRACE("\n");

    delchannel_t param;
    param.p_peer_id = pPeerId;
    call_jni(METHOD_PTARM_DELCHANNEL, &param);
}


void btcrpc_set_committxid(const ln_channel_t *pChannel)
{
    (void)pChannel;
    LOGD("\n");
}


bool btcrpc_get_balance(uint64_t *pAmount)
{
    LOGD_BTCTRACE("\n");

    getbalance_t param;
    param.p_amount = pAmount;
    call_jni(METHOD_PTARM_GETBALANCE, &param);
    if (param.ret) {
        LOGD_BTCRESULT("amount=%" PRIu64 "\n", *param.p_amount);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


bool btcrpc_empty_wallet(uint8_t *pTxid, const char *pAddr)
{
    LOGD_BTCTRACE("\n");

    emptywallet_t param;
    param.p_txid = pTxid;
    param.p_addr = pAddr;
    call_jni(METHOD_PTARM_EMPTYWALLET, &param);
    if (param.ret) {
        LOGD_BTCRESULT("txid=");
        TXIDD_BTCRESULT(param.p_txid);
    } else {
        LOGD_BTCFAIL("fail\n");
    }
    return param.ret;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static void call_jni(btcj_method_t Method, void *pParam)
{
    pthread_mutex_lock(&mMuxCall);
    pthread_mutex_lock(&mMuxJni);
    mMethodParam.method = Method;
    mMethodParam.p_arg = pParam;
    LOGD_PTHREAD("BTC: send signal: %d\n", (int)mMethodParam.method);
    pthread_mutex_lock(&mMuxApi);
    pthread_cond_signal(&mCondJni);
    pthread_mutex_unlock(&mMuxJni);

    LOGD_PTHREAD("BTC: wait...: %d\n", (int)mMethodParam.method);
    pthread_cond_wait(&mCondApi, &mMuxApi);
    pthread_mutex_unlock(&mMuxApi);
    LOGD_PTHREAD("BTC: unlock: %d\n", (int)mMethodParam.method);
    pthread_mutex_unlock(&mMuxCall);
}


/**************************************************************************
 * private functions: JNI
 **************************************************************************/

static void *thread_jni_start(void *pArg)
{
    const rpc_conf_t *p_rpcconf = (const rpc_conf_t *)pArg;

    LOGD("[THREAD]jni initialize\n");

    bool ret = btcj_init(p_rpcconf->gen);
    if (!ret) {
        LOGE("fail: jvm init\n");
        mLoopJni = JNILOOP_ABORT;
        btcj_release();
        return NULL;
    }

    mLoopJni = JNILOOP_WORK;

    pthread_mutex_lock(&mMuxJni);
    while (mLoopJni == JNILOOP_WORK) {
        LOGD_PTHREAD("JNI: exec wait...\n");
        pthread_cond_wait(&mCondJni, &mMuxJni);
        if (mLoopJni != JNILOOP_WORK) {
            LOGD("stop: jni loop\n");
            break;
        }

        LOGD_PTHREAD("JNI: exec: %d\n", (int)mMethodParam.method);
        if (mMethodParam.method < ARRAY_SIZE(kJniFuncs)) {
            (*kJniFuncs[mMethodParam.method].p_func)(mMethodParam.p_arg);
        } else {
            LOGE("fail: invalid method(%d)\n", mMethodParam.method);
        }
        pthread_mutex_lock(&mMuxApi);
        LOGD_PTHREAD("JNI: send signal\n");
        pthread_cond_signal(&mCondApi);
        pthread_mutex_unlock(&mMuxApi);
    }
    pthread_mutex_unlock(&mMuxJni);

    btcj_release();
    LOGD("END\n");
    return NULL;
}


//METHOD_PTARM_SETCREATIONHASH
static void jni_set_creationhash(void *pArg)
{
    LOGD("\n");

    setcreationhash_t *p = (setcreationhash_t *)pArg;
    btcj_setcreationhash(p->p_hash);
    p->ret = true;
}


//METHOD_PTARM_GETBLOCKCOUNT
static void jni_get_blockcount(void *pArg)
{
    LOGD("\n");

    getblockcount_t *p = (getblockcount_t *)pArg;
    *p->p_cnt = btcj_getblockcount(p->p_hash);
    p->ret = true;
}


//METHOD_PTARM_GETGENESISBLOCKHASH
static void jni_get_genesisblockhash(void *pArg)
{
    LOGD("\n");

    getgenesisblockhash_t *p = (getgenesisblockhash_t *)pArg;
    p->ret = btcj_getgenesisblockhash(p->p_hash);
}


//METHOD_PTARM_GETCONFIRMATION
static void jni_get_txconfirm(void *pArg)
{
    LOGD("\n");

    getconfirmation_t *p = (getconfirmation_t *)pArg;
    int32_t val = btcj_gettxconfirm(p->p_txid);
    LOGD("val=%d\n", (int)val);
    if (val > 0) {
        *p->p_confirm = (uint32_t)val;
        p->ret = true;
    } else {
        p->ret = false;
    }
}


//METHOD_PTARM_GETSHORTCHANNELPARAM
static void jni_get_short_channel_param(void *pArg)
{
    LOGD("\n");

    getshortchannelparam_t *p = (getshortchannelparam_t *)pArg;
    p->ret = btcj_get_short_channel_param(p->p_peerid, p->p_b_height, p->p_b_index, p->p_mined_hash);
}


//METHOD_PTARM_GETTXIDFROMSHORTCHANNELID
static void jni_get_txid_from_short_channel_id(void *pArg)
{
    LOGD("\n");

    (void)pArg;
}


//METHOD_PTARM_SEARCHOUTPOINT
static void jni_search_outpoint(void *pArg)
{
    LOGD("\n");

    searchoutpoint_t *p = (searchoutpoint_t *)pArg;
    btcj_buf_t *p_txbuf;
    p->ret = btcj_search_outpoint(&p_txbuf, p->blks, p->p_txid, p->v_index);
    if (p->ret) {
        p->ret = btc_tx_read(p->p_tx, p_txbuf->buf, p_txbuf->len);
        UTL_DBG_FREE(p_txbuf->buf);
        UTL_DBG_FREE(p_txbuf);
    }
}


//METHOD_PTARM_SEARCHVOUT
static void jni_search_vout(void *pArg)
{
    LOGD("\n");

    searchvout_t *p = (searchvout_t *)pArg;
    btcj_buf_t *p_jtxbuf = NULL;    //btcj_buf_t*の配列
    btcj_buf_t vout = { p->p_vout->buf, p->p_vout->len };
    btcj_buf_t vouts = { (uint8_t *)&vout, sizeof(btcj_buf_t*) };
    p->ret = btcj_search_vout(&p_jtxbuf, p->blks, &vouts);
    if (p->ret) {
        int num = p_jtxbuf->len / sizeof(btcj_buf_t);
        utl_buf_alloc(p->p_txbuf, sizeof(btc_tx_t) * num);  //btc_tx_tの配列
        btc_tx_t *p_txs = (btc_tx_t *)p->p_txbuf->buf;
        btcj_buf_t *p_jbuf = (btcj_buf_t *)p_jtxbuf->buf;
        for (int lp = 0; lp < num; lp++) {
            p->ret &= btc_tx_read(&p_txs[lp], p_jbuf[lp].buf, p_jbuf[lp].len);
            UTL_DBG_FREE(p_jbuf->buf);
            UTL_DBG_FREE(p_jbuf);
        }
        UTL_DBG_FREE(p_jtxbuf);
    }
}


//METHOD_PTARM_SIGNRAWTX
static void jni_sign_rawtx(void *pArg)
{
    LOGD("\n");

    signrawtx_t *p = (signrawtx_t *)pArg;

    btcj_buf_t scriptpubkey = { (CONST_CAST uint8_t *)p->p_scriptpubkey, p->len };
    btcj_buf_t *p_tx = NULL;
    p->ret = btcj_signraw_tx(p->amount, &scriptpubkey, &p_tx);
    if (p->ret) {
        btc_tx_free(p->p_tx);
        p->ret = btc_tx_read(p->p_tx, p_tx->buf, p_tx->len);
    }
    if (p_tx != NULL) {
        UTL_DBG_FREE(p_tx->buf);
        UTL_DBG_FREE(p_tx);
    }
}


//METHOD_PTARM_SENDRAWTX
static void jni_send_rawtx(void *pArg)
{
    LOGD("\n");

    sendrawtx_t *p = (sendrawtx_t *)pArg;
    btcj_buf_t txdata = { (CONST_CAST uint8_t *)p->p_raw_data, p->len };
    p->ret = btcj_sendraw_tx(p->p_txid, p->p_code, &txdata);
}


//METHOD_PTARM_CHECKBROADCAST
static void jni_is_tx_broadcasted(void *pArg)
{
    LOGD("\n");

    checkbroadcast_t *p = (checkbroadcast_t *)pArg;
    p->ret = btcj_is_tx_broadcasted(p->p_txid);
}


//METHOD_PTARM_CHECKUNSPENT
static void jni_check_unspent(void *pArg)
{
    LOGD("\n");

    checkunspent_t *p = (checkunspent_t *)pArg;
    p->ret = btcj_check_unspent(p->p_peerid, p->p_unspent, p->p_txid, p->v_index);
}


//METHOD_PTARM_GETNEWADDRESS
static void jni_get_newaddress(void *pArg)
{
    LOGD("\n");

    getnewaddress_t *p = (getnewaddress_t *)pArg;
    (void)btcj_getnewaddress(p->p_addr);
    p->ret = true;
}


//METHOD_PTARM_ESTIMATEFEE
static void jni_estimatefee(void *pArg)
{
    LOGD("\n");

    estimatefee_t *p = (estimatefee_t *)pArg;
    p->ret = btcj_estimatefee(p->p_fee_satoshi, p->blks);
}


//METHOD_PTARM_SETCHANNEL
static void jni_set_channel(void *pArg)
{
    setchannel_t *p = (setchannel_t *)pArg;

    LOGD("peer=");
    DUMPD(p->p_peer_id, BTC_SZ_PUBKEY);
    LOGD("short_channel_id=%016" PRIx64 "\n", p->short_channel_id);
    LOGD("funding_txid=");
    TXIDD(p->p_fundingtxid);
    LOGD("funding_index=%d\n", p->fundingidx);
    LOGD("scriptPubKey=");
    DUMPD(p->p_scriptpubkey, BTC_SZ_HASH256);
    LOGD("mined_hash=");
    TXIDD(p->mined_hash);
    LOGD("last_confirm=%" PRIu32 "\n", p->last_confirm);

    btcj_set_channel(p->p_peer_id,
                p->short_channel_id,
                p->p_fundingtxid,
                p->fundingidx,
                p->p_scriptpubkey,
                p->mined_hash,
                p->last_confirm);
}


//METHOD_PTARM_DELCHANNEL
static void jni_del_channel(void *pArg)
{
    delchannel_t *p = (delchannel_t *)pArg;

    LOGD("peer=");
    DUMPD(p->p_peer_id, BTC_SZ_PUBKEY);

    btcj_del_channel(p->p_peer_id);
}


//METHOD_PTARM_SETCOMMITTXID
static void jni_set_committxid(void *pArg)
{
    LOGD("\n");

    (void)pArg;
}


//METHOD_PTARM_GETBALANCE
static void jni_get_balance(void *pArg)
{
    LOGD("\n");

    getbalance_t *p = (getbalance_t *)pArg;
    p->ret = btcj_getbalance(p->p_amount);
}


//METHOD_PTARM_EMPTYWALLET
static void jni_empty_wallet(void *pArg)
{
    LOGD("\n");

    emptywallet_t *p = (emptywallet_t *)pArg;
    p->ret = btcj_emptywallet(p->p_addr, p->p_txid);
}


//METHOD_PTARM_EXIT
static void jni_exit(void *pArg)
{
    (void)pArg;
    LOGD("\n");

    btcj_release();
}
