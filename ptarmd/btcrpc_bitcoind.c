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
#include <float.h>
#include <curl/curl.h>
#include <pthread.h>
#include "jansson.h"

#define LOG_TAG     "btcrpc"
#include "utl_log.h"
#include "utl_str.h"
#include "utl_push.h"

#include "btcrpc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define TXJSON_SIZE     (1024)              //rawtx JSON-RPC送信用バッファ
#define BUFFER_SIZE     (256 * 1024)        //JSON-RPCレスポンスバッファの初期サイズ

#define M_RPCHEADER         "\"jsonrpc\": \"1.0\", \"id\": \"ptarmdrpc\""
#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_JSON_STR(item,str)    M_QQ(item) ":" M_QQ(str)
#define M_JSON_NUM(item,ctrl)   M_QQ(item) ":" ctrl

#define M_MIN_BITCOIND_VERSION  (170000)        //必要とするバージョン

// #define M_DBG_SHOWRPC       //RPCの命令
// #define M_DBG_SHOWREPLY     //RPCの応答


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    char    **pp_data;
    int     pos;
    size_t  sz;
} write_result_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

static bool getblocktx(json_t **ppRoot, json_t **ppJsonTx, char **ppBufJson, int BHeight);
static bool getrawtx(json_t **ppRoot, json_t **ppResult, char **ppJson, const uint8_t *pTxid);
static bool getrawtxstr(btc_tx_t *pTx, const char *txid);
static bool signrawtx_with_wallet(btc_tx_t *pTx, const uint8_t *pRawTx, size_t Len, uint64_t Amount);
static bool gettxout(bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex);
static bool search_outpoint(btc_tx_t *pTx, int BHeight, const uint8_t *pTxid, uint32_t VIndex);
static bool search_vout_block(utl_buf_t *pTxBuf, int BHeight, const utl_buf_t *pVout);
static bool getversion(int64_t *pVersion);
static int create_funding_input(btc_tx_t *pTx, uint64_t *pSumAmount, uint64_t *pTxFee, uint64_t FundingSat, uint64_t FeeratePerKw);
static bool lockunspent(const char *pOutPoint);

static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream);
static bool getrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTxid, bool detail);
static bool signrawtransactionwithwallet_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction);
static bool sendrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction);
static bool gettxout_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTxid, int idx);
static bool getblock_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pBlock);
static bool getblockhash_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, int BHeight);
static bool getblockcount_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson);
static bool getnewaddress_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson);
static bool estimatefee_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, int nBlock);
static bool getnetworkinfo_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson);
static bool listunspent_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson);
static bool lockunspent_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pOutPoint);

static bool rpc_proc(json_t **ppRoot, json_t **ppResult, char **ppJson, char *pData);
static int error_result(json_t *p_root);


/**************************************************************************
 * static variables
 **************************************************************************/

static char             mRpcUrl[SZ_RPC_URL + 1 + 5 + 2];
static char             mRpcUserPwd[SZ_RPC_USER + 1 + SZ_RPC_PASSWD + 1];
static pthread_mutex_t  mMux;
static CURL             *mCurl;

static const char *M_RESULT         =   "result";
static const char *M_CONFIRMATIONS  =   "confirmations";
static const char *M_HEX            =   "hex";
static const char *M_BLOCKHASH      =   "blockhash";
static const char *M_HEIGHT         =   "height";
static const char *M_VALUE          =   "value";
static const char *M_TX             =   "tx";
static const char *M_ERROR          =   "error";
static const char *M_MESSAGE        =   "message";
static const char *M_CODE           =   "code";
static const char *M_FEERATE        =   "feerate";


/**************************************************************************
 * public functions
 **************************************************************************/

bool btcrpc_init(const rpc_conf_t *pRpcConf)
{
    pthread_mutex_init(&mMux, NULL);
    curl_global_init(CURL_GLOBAL_ALL);
    mCurl = curl_easy_init();
    if (mCurl == NULL) {
        LOGD("fatal: cannot init curl\n");
        return false;
    }

    sprintf(mRpcUrl, "%s:%d", pRpcConf->rpcurl, pRpcConf->rpcport);
    sprintf(mRpcUserPwd, "%s:%s", pRpcConf->rpcuser, pRpcConf->rpcpasswd);
    LOGD("URL=%s\n", mRpcUrl);
#ifdef M_DBG_SHOWRPC
    LOGD("RpcUserPwd=%s\n", mRpcUserPwd);
#endif //M_DBG_SHOWRPC

    int64_t version = -1;
    bool ret = getversion(&version);
    if (ret) {
        LOGD("bitcoind version: %" PRId64 "\n", version);
        if (version < M_MIN_BITCOIND_VERSION) {
            LOGD("fatal: minimum bitcoind version: %" PRId64 "\n", M_MIN_BITCOIND_VERSION);
            ret = false;
        }
    } else {
        LOGD("fatal: fail getnetworkinfo\n");
    }
    if (ret) {
        int32_t height = 0;
        uint8_t bhash[BTC_SZ_HASH256];
        char *p_json = NULL;
        json_t *p_root = NULL;
        json_t *p_result;

        ret = btcrpc_getblockcount(&height);
        if (ret) {
            ret = getblockhash_rpc(&p_root, &p_result, &p_json, height);
        }
        if (ret) {
            ret = json_is_string(p_result);
        }
        if (ret) {
            ret = utl_str_str2bin_rev(bhash, BTC_SZ_HASH256, (const char *)json_string_value(p_result));
        }
        if (ret) {
            ln_creationhash_set(bhash);
        }
        if (p_root != NULL) {
            json_decref(p_root);
        }
        UTL_DBG_FREE(p_json);
    }

    return ret;
}


void btcrpc_term(void)
{
    curl_easy_cleanup(mCurl);
    mCurl = NULL;
    curl_global_cleanup();
    pthread_mutex_destroy(&mMux);
}


bool btcrpc_getblockcount(int32_t *pBlockCount)
{
    bool retval = false;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getblockcount_rpc(&p_root, &p_result, &p_json);
    if (ret && json_is_integer(p_result)) {
        *pBlockCount = (int32_t)json_integer_value(p_result);
        retval = true;
    } else {
        LOGE("fail: getblockcount_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return retval;
}


bool btcrpc_getgenesisblock(uint8_t *pHash)
{
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getblockhash_rpc(&p_root, &p_result, &p_json, 0);
    if (ret && json_is_string(p_result)) {
        ret = utl_str_str2bin(pHash, BTC_SZ_HASH256, (const char *)json_string_value(p_result));
    } else {
        LOGE("fail: getblockhash_rpc\n");
    }
    if (ret) {
        // https://github.com/lightningnetwork/lightning-rfc/issues/237
        for (int lp = 0; lp < BTC_SZ_HASH256 / 2; lp++) {
            uint8_t tmp = pHash[lp];
            pHash[lp] = pHash[BTC_SZ_HASH256 - lp - 1];
            pHash[BTC_SZ_HASH256 - lp - 1] = tmp;
        }
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return ret;
}


bool btcrpc_get_confirmations(uint32_t *pConfm, const uint8_t *pTxid)
{
    bool    ret = false;
    char    *p_json = NULL;
    json_t  *p_root = NULL;
    json_t  *p_result;
    json_t  *p_confm;

    *pConfm = 0;

    if (!getrawtx(&p_root, &p_result, &p_json, pTxid)) {
        LOGE("fail: getrawtransaction_rpc\n");
        goto LABEL_EXIT;
    }

    p_confm = json_object_get(p_result, M_CONFIRMATIONS);
    if (!json_is_integer(p_confm)) {
        goto LABEL_EXIT;
    }

    if (json_integer_value(p_confm) <= 0) {
        LOGE("fail: ???\n");
        goto LABEL_EXIT;
    }
    *pConfm = (uint32_t)json_integer_value(p_confm);

    ret = true;

LABEL_EXIT:
    if (p_root) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);
    return ret;
}


bool btcrpc_get_short_channel_param(const uint8_t *pPeerId, int32_t *pBHeight, int32_t *pBIndex, uint8_t *pMinedHash, const uint8_t *pTxid)
{
    (void)pPeerId;

    bool ret;
    char *p_json = NULL;
    char blockhash[BTC_SZ_HASH256 * 2 + 1] = "NG";
    json_t *p_root = NULL;
    json_t *p_result;

    *pBHeight = -1;
    *pBIndex = -1;

    ret = getrawtx(&p_root, &p_result, &p_json, pTxid);
    if (ret) {
        json_t *p_bhash;

        p_bhash = json_object_get(p_result, M_BLOCKHASH);
        if (json_is_string(p_bhash)) {
            strncpy(blockhash, (const char *)json_string_value(p_bhash), sizeof(blockhash));
            blockhash[sizeof(blockhash) - 1] = '\0';
            if (pMinedHash != NULL) {
                utl_str_str2bin_rev(pMinedHash, BTC_SZ_HASH256,  blockhash);
            }
        }
    } else {
        LOGE("fail: getrawtransaction_rpc\n");
        goto LABEL_EXIT;
    }
    if (p_root != NULL) {
        json_decref(p_root);
        p_root = NULL;
    }
    UTL_DBG_FREE(p_json);

    ret = getblock_rpc(&p_root, &p_result, &p_json, blockhash);
    if (ret) {
        json_t *p_height;
        json_t *p_tx;

        p_height = json_object_get(p_result, M_HEIGHT);
        if (json_is_integer(p_height)) {
            *pBHeight = (int)json_integer_value(p_height);
        }
        p_tx = json_object_get(p_result, M_TX);

        char txid[BTC_SZ_TXID * 2 + 1];
        utl_str_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

        size_t index = 0;
        json_t *p_value = NULL;
        json_array_foreach(p_tx, index, p_value) {
            if (strcmp(txid, (const char *)json_string_value(p_value)) == 0) {
                *pBIndex = (int)index;
                break;
            }
        }
    } else {
        LOGE("fail: getblock_rpc\n");
    }

LABEL_EXIT:
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    if ((*pBIndex == -1) || (*pBHeight == -1)) {
        LOGE("fail\n");
        ret = false;
    }

    return ret;
}


//bitcoindのみ
bool btcrpc_gettxid_from_short_channel(uint8_t *pTxid, int BHeight, int BIndex)
{
    bool unspent = true;        //エラーでもunspentにしておく
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_tx = NULL;

    ret = getblocktx(&p_root, &p_tx, &p_json, BHeight);
    if (ret) {
        //検索
        size_t index = 0;
        json_t *p_value = NULL;

        json_array_foreach(p_tx, index, p_value) {
            if ((int)index == BIndex) {
                //TXIDはLE/BE変換
                utl_str_str2bin_rev(pTxid, BTC_SZ_TXID, (const char *)json_string_value(p_value));
                break;
            }
        }
    } else {
        LOGE("fail: getblocktx\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
        p_root = NULL;
    }
    UTL_DBG_FREE(p_json);

    return unspent;
}


bool btcrpc_search_outpoint(btc_tx_t *pTx, uint32_t Blks, const uint8_t *pTxid, uint32_t VIndex)
{
    if (Blks == 0) {
        return false;
    }

    bool ret;
    int32_t height;
    ret = btcrpc_getblockcount(&height);

    //現在からBlksの間に、使用したtransactionがあるかどうか
    if (ret) {
        if ((uint32_t)height < Blks) {
            Blks = height;
        }
        for (uint32_t lp = 0; lp < Blks; lp++) {
            ret = search_outpoint(pTx, height - lp, pTxid, VIndex);
            if (ret) {
                break;
            }
        }
    }

    LOGD("Blks=%" PRIu32 ", ret=%d\n", Blks, ret);
    return ret;
}


bool btcrpc_search_vout(utl_buf_t *pTxBuf, uint32_t Blks, const utl_buf_t *pVout)
{
    if (Blks == 0) {
        return false;
    }

    bool ret;
    int32_t height;
    ret = btcrpc_getblockcount(&height);

    //現在からBlksの間に使用したtransactionがあるかどうか
    if (ret) {
        if ((uint32_t)height < Blks) {
            Blks = height;
        }
        for (uint32_t lp = 0; lp < Blks; lp++) {
            ret = search_vout_block(pTxBuf, height - lp, pVout);
            if (ret) {
                break;
            }
        }
    }

    return ret;
}


bool btcrpc_sign_fundingtx(btc_tx_t *pTx, const utl_buf_t *pWitProg, uint64_t Amount)
{
    //pTxのINPUTを埋めてsignrawtx_with_wallet()する

    bool ret;

    uint64_t feerate_kb;
    ret = btcrpc_estimatefee(&feerate_kb, 6);
    if (!ret) {
        LOGE("fail: feerate\n");
        return false;
    }

    uint64_t sum_amount = 0;
    uint64_t change = 0;
    uint64_t txfee = 0;
    btc_tx_t tx_nosign = BTC_TX_INIT;
    int retval = create_funding_input(
                &tx_nosign, &sum_amount, &txfee, Amount,
                ln_feerate_per_kw_calc(feerate_kb));
    if (retval == 0) {
        change = sum_amount - Amount - txfee;
        LOGD("funding: %" PRIu64 "\n", Amount);
        LOGD("change : %" PRIu64 "\n", change);
        LOGD("fee    : %" PRIu64 "\n", txfee);
    } else {
        LOGE("fail: %d\n", retval);
        return false;
    }
    btc_tx_add_vout_spk(&tx_nosign, Amount, pWitProg);
    if (change > 0) {
        char change_addr[BTC_SZ_ADDR_STR_MAX + 1];
        ret = btcrpc_getnewaddress(change_addr);
        if (ret) {
            btc_tx_add_vout_addr(&tx_nosign, change, change_addr);
        } else {
            LOGE("fail: getnewaddress\n");
            return false;
        }
    }

    utl_buf_t buf_rawtx = UTL_BUF_INIT;
    ret = btc_tx_write(&tx_nosign, &buf_rawtx);
    if (ret) {
        ret = signrawtx_with_wallet(pTx, buf_rawtx.buf, buf_rawtx.len, Amount);
    } else {
        LOGE("fail: sign\n");
    }
    utl_buf_free(&buf_rawtx);
    btc_tx_free(&tx_nosign);
    return ret;
}


bool btcrpc_send_rawtx(uint8_t *pTxid, int *pCode, const uint8_t *pRawData, uint32_t Len)
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    char *transaction;
    json_t *p_root = NULL;
    json_t *p_result;

    transaction = (char *)UTL_DBG_MALLOC(Len * 2 + 1);
    utl_str_bin2str(transaction, pRawData, Len);

    ret = sendrawtransaction_rpc(&p_root, &p_result, &p_json, transaction);
    UTL_DBG_FREE(transaction);
    if (ret) {
        if (json_is_string(p_result)) {
            //TXIDはLE/BE変換
            utl_str_str2bin_rev(pTxid, BTC_SZ_TXID, (const char *)json_string_value(p_result));
            result = true;
        } else {
            int code = error_result(p_root);
            if (pCode) {
                *pCode = code;
            }
        }
    } else {
        LOGE("fail: sendrawtransaction_rpc()\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return result;
}


bool btcrpc_is_tx_broadcasted(const uint8_t *pTxid)
{
    char txid[BTC_SZ_TXID * 2 + 1];

    //TXIDはBE/LE変換
    utl_str_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

    return getrawtxstr(NULL, txid);
}


bool btcrpc_check_unspent(
    const uint8_t *pPeerId, bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex)
{
    (void)pPeerId;

    bool        unspent = true;
    uint64_t    sat = 0;
    bool        ret = gettxout(&unspent, &sat, pTxid, VIndex);

    if (pUnspent) {
        *pUnspent = unspent;
    }

    if (pSat) {
        *pSat = sat;
    }

    return ret;
}


bool btcrpc_getnewaddress(char pAddr[BTC_SZ_ADDR_STR_MAX + 1])
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getnewaddress_rpc(&p_root, &p_result, &p_json);
    if (ret) {
        if (json_is_string(p_result)) {
            if (strlen(json_string_value(p_result)) <= BTC_SZ_ADDR_STR_MAX) {
                strcpy(pAddr,  (const char *)json_string_value(p_result));
                result = true;
            }
        }
    } else {
        LOGE("fail: getnewaddress_rpc()\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return result;
}


bool btcrpc_estimatefee(uint64_t *pFeeSatoshi, int nBlocks)
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    if (nBlocks < 2) {
        LOGE("fail: nBlock < 2\n");
        return false;
    }

    ret = estimatefee_rpc(&p_root, &p_result, &p_json, nBlocks);
    if (ret) {
        json_t *p_feerate;

        p_feerate = json_object_get(p_result, M_FEERATE);
        if (p_feerate && json_is_real(p_feerate)) {
            *pFeeSatoshi = BTC_BTC2SATOSHI(json_real_value(p_feerate));
            //-1のときは失敗と見なす
            result = (*pFeeSatoshi + 1.0) > DBL_EPSILON;
            if (!result) {
                LOGE("fail: Unable to estimate fee\n");
            }
        } else {
            LOGE("fail: not real value\n");
        }
    } else {
        LOGE("fail: estimatefee_rpc()\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    if (!result) {
        //regtest
        if (btc_block_get_chain(ln_genesishash_get()) == BTC_BLOCK_CHAIN_BTCREGTEST) {
            LOGD("force regtest feerate\n");
            *pFeeSatoshi = 4 * LN_FEERATE_PER_KW;
            result = true;
        }
    }

    return result;
}


void btcrpc_set_creationhash(const uint8_t *pHash)
{
    (void)pHash;
}


void btcrpc_set_channel(const uint8_t *pPeerId,
                        uint64_t ShortChannelId,
                        const uint8_t *pFundingTxid,
                        int FundingIdx,
                        const utl_buf_t *pRedeemScript,
                        const uint8_t *pMinedHash,
                        uint32_t LastConfirm)
{
    (void)pPeerId; (void)ShortChannelId; (void)pFundingTxid;
    (void)FundingIdx; (void)pRedeemScript; (void)pMinedHash; (void)LastConfirm;
}


void btcrpc_del_channel(const uint8_t *pPeerId)
{
    (void)pPeerId;
}


void btcrpc_set_committxid(const ln_channel_t *pChannel)
{
    (void)pChannel;
}


bool btcrpc_get_balance(uint64_t *pAmount)
{
    (void)pAmount;
    return false;
}


bool btcrpc_empty_wallet(uint8_t *pTxid, const char *pAddr)
{
    (void)pTxid; (void)pAddr;
    return false;
}


/**************************************************************************
 * private functions
 **************************************************************************/

static bool getblocktx(json_t **ppRoot, json_t **ppJsonTx, char **ppBufJson, int BHeight)
{
    bool ret;
    json_t *p_root = NULL;
    json_t *p_result;
    json_t *p_height;
    char *p_json = NULL;
    char blockhash[BTC_SZ_HASH256 * 2 + 1];

    *ppJsonTx = NULL;
    *ppRoot = NULL;

    //ブロック高→ブロックハッシュ
    ret = getblockhash_rpc(&p_root, &p_result, &p_json, BHeight);
    if (!ret) {
        LOGE("fail: getblockhash_rpc\n");
        return false;
    }
    if (json_is_string(p_result)) {
        strcpy(blockhash, (const char *)json_string_value(p_result));
    } else {
        LOGD("error: M_RESULT\n");
        blockhash[0] = '\0';
    }
    json_decref(p_root);
    UTL_DBG_FREE(p_json);
    if (blockhash[0] == '\0') {
        return false;
    }


    //ブロックハッシュ→TXIDs
    ret = getblock_rpc(ppRoot, &p_result, ppBufJson, blockhash);
    if (!ret) {
        LOGE("fail: getblock_rpc\n");
        return false;
    }
    p_height = json_object_get(p_result, M_HEIGHT);
    if (!p_height || !json_is_integer(p_height)) {
        LOGD("error: M_HEIGHT\n");
        return false;
    }
    if ((int)json_integer_value(p_height) != BHeight) {
        LOGD("error: != height\n");
        return false;
    }
    *ppJsonTx = json_object_get(p_result, M_TX);
    if (!*ppJsonTx) {
        LOGD("error: M_TX\n");
        return false;
    }

    return true;
}


static bool getrawtx(json_t **ppRoot, json_t **ppResult, char **ppJson, const uint8_t *pTxid)
{
    char txid[BTC_SZ_TXID * 2 + 1];

    //TXIDはBE/LE変換
    utl_str_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

    return getrawtransaction_rpc(ppRoot, ppResult, ppJson, txid, true);
}


/** getrawtransaction(TXID文字列)
 *
 * @retval  true    取得成功
 * @retval  false   取得失敗 or bitcoindエラー
 */
static bool getrawtxstr(btc_tx_t *pTx, const char *txid)
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getrawtransaction_rpc(&p_root, &p_result, &p_json, txid, false);
    if (ret) {
        uint8_t *p_hex;
        const char *str_hex;
        uint32_t len;

        str_hex = (const char *)json_string_value(p_result);
        if (!str_hex) {
            //error_result(p_root);
            goto LABEL_EXIT;
        }
        len = strlen(str_hex);
        if (len & 1) {
            LOGD("error: len\n");
            goto LABEL_EXIT;
        }
        if (pTx) {
            len >>= 1;
            p_hex = (uint8_t *)UTL_DBG_MALLOC(len);
            utl_str_str2bin(p_hex, len, str_hex);
            btc_tx_read(pTx, p_hex, len);
            UTL_DBG_FREE(p_hex);
        }
        result = true;
    }
LABEL_EXIT:
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return result;
}


/**
 *
 * @param[out]      pTx         signed transaction
 * @param[in]       pRawTx      transaction for signature
 * @param[in]       Len         pRawTx length
 * @param[in]       Amount      previous amount
 */
static bool signrawtx_with_wallet(btc_tx_t *pTx, const uint8_t *pRawTx, size_t Len, uint64_t Amount)
{
    (void)Amount;

    bool result = false;
    bool ret;
    char *p_json = NULL;
    char *transaction;
    json_t *p_root = NULL;
    json_t *p_result;

    transaction = (char *)UTL_DBG_MALLOC(Len * 2 + 1);
    utl_str_bin2str(transaction, pRawTx, Len);

    ret = signrawtransactionwithwallet_rpc(&p_root, &p_result, &p_json, transaction);
    UTL_DBG_FREE(transaction);
    if (ret) {
        json_t *p_hex;

        p_hex = json_object_get(p_result, M_HEX);
        if (json_is_string(p_hex)) {
            const char *p_sigtx = (const char *)json_string_value(p_hex);
            size_t len = strlen(p_sigtx) / 2;
            uint8_t *p_buf = UTL_DBG_MALLOC(len);
            utl_str_str2bin(p_buf, len, p_sigtx);
            btc_tx_free(pTx);
            result = btc_tx_read(pTx, p_buf, len);
            UTL_DBG_FREE(p_buf);
        } else {
            int code = error_result(p_root);
            LOGD("err code=%d\n", code);
        }
    } else {
        LOGE("fail: signrawtransactionwithwallet_rpc()\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);
    LOGD("result=%d\n", result);

    return result;
}


static bool gettxout(bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex)
{
    bool ret;
    char *p_json = NULL;
    char txid[BTC_SZ_TXID * 2 + 1];
    *pUnspent = true;
    *pSat = 0;
    json_t *p_root = NULL;
    json_t *p_result;

    //TXIDはBE/LE変換
    utl_str_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

    //まずtxの存在確認を行う
    ret = getrawtxstr(NULL, txid);
    if (!ret) {
        //LOGE("fail: maybe not broadcasted\n");
        goto LABEL_EXIT;
    }

    ret = gettxout_rpc(&p_root, &p_result, &p_json, txid, VIndex);
    if (ret) {
        json_t *p_value;

        p_value = json_object_get(p_result, M_VALUE);
        if (p_value && json_is_real(p_value)) {
            double dval = json_real_value(p_value);
            *pSat = BTC_BTC2SATOSHI(dval);
        } else {
            *pUnspent = false;
        }
    } else {
        LOGE("fail: gettxout_rpc()\n");
    }

LABEL_EXIT:
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return ret;
}


/** [bitcoin rpc]blockからvin[0]のoutpointが一致するトランザクションを検索
 *
 * @param[out]  pTx         トランザクション情報
 * @param[in]   BHeight     block height
 * @param[in]   pTxid       検索するTXID
 * @param[in]   VIndex      vout index
 * @retval  true        検索成功
 * @note
 *      - 検索するvinはvin_cnt==1のみ
 *      - 内部処理(getrawtransaction)に失敗した場合でも、処理を継続する
 */
static bool search_outpoint(btc_tx_t *pTx, int BHeight, const uint8_t *pTxid, uint32_t VIndex)
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_tx = NULL;

    ret = getblocktx(&p_root, &p_tx, &p_json, BHeight);
    if (ret) {
        //検索
        size_t index = 0;
        json_t *p_value = NULL;
        char txid[BTC_SZ_TXID * 2 + 1] = "";

        json_array_foreach(p_tx, index, p_value) {
            strcpy(txid, (const char *)json_string_value(p_value));
            btc_tx_t tx = BTC_TX_INIT;

            ret = getrawtxstr(&tx, txid);
            //LOGD("txid=%s\n", txid);
            if ( ret &&
                    (tx.vin_cnt == 1) &&
                    (memcmp(tx.vin[0].txid, pTxid, BTC_SZ_TXID) == 0) &&
                    (tx.vin[0].index == VIndex) ) {
                //一致
                memcpy(pTx, &tx, sizeof(btc_tx_t));
                btc_tx_init(&tx);     //freeさせない
                result = true;
                break;
            }
            btc_tx_free(&tx);
        }
    } else {
        LOGE("fail: getblock_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return result;
}


/** [bitcoin rpc]blockからvoutが一致するtransactionを検索
 * @param[out]  pTxBuf      トランザクション情報(btc_tx_tの配列を保存する)
 * @param[in]   BHeight     block height
 * @param[in]   pVout       vout(utl_buf_tの配列)
 * @retval  true        検索成功(1つでも見つかった)
 * @note
 *      - pTxBufの扱いに注意すること
 *          - 成功時、btc_tx_tが複数入っている可能性がある(個数は、pTxBuf->len / sizeof(btc_tx_t))
 *          - クリアする場合、各btc_tx_tをクリア後、utl_buf_tをクリアすること
 *      - 内部処理(getrawtransaction)に失敗した場合でも、処理を継続する
 */
static bool search_vout_block(utl_buf_t *pTxBuf, int BHeight, const utl_buf_t *pVout)
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_tx = NULL;
    int vout_num = pVout->len / sizeof(utl_buf_t);
    //LOGD("vout_num: %d\n", vout_num);

    ret = getblocktx(&p_root, &p_tx, &p_json, BHeight);
    if (ret) {
        //検索
        utl_push_t push;
        utl_push_init(&push, pTxBuf, 0);
        size_t index = 0;
        json_t *p_value = NULL;
        char txid[BTC_SZ_TXID * 2 + 1] = "";

        json_array_foreach(p_tx, index, p_value) {
            strcpy(txid, (const char *)json_string_value(p_value));
            btc_tx_t tx = BTC_TX_INIT;

            ret = getrawtxstr(&tx, txid);
            if (ret) {
                for (uint32_t lp = 0; lp < tx.vout_cnt; lp++) {
                    for (int lp2 = 0; lp2 < vout_num; lp2++) {
                        if (utl_buf_equal(&tx.vout[0].script, &pVout[lp2])) {
                            //一致
                            LOGD("match: %s\n", txid);
                            utl_push_data(&push, &tx, sizeof(btc_tx_t));
                            LOGD("len=%u\n", pTxBuf->len);
                            btc_tx_init(&tx);     //freeさせない
                            result = true;
                            break;
                        }
                    }
                }
                btc_tx_free(&tx);
            }
        }
    } else {
        LOGE("fail: getblock_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return result;
}


/** bitcoind version取得(getnetworkinfo version)
 *
 * @param[out]  pVersion        bitcoind version
 */
static bool getversion(int64_t *pVersion)
{
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getnetworkinfo_rpc(&p_root, &p_result, &p_json);
    if (ret) {
        json_t *p_version;

        p_version = json_object_get(p_result, "version");
        if (json_is_integer(p_version)) {
            *pVersion = (int64_t)json_integer_value(p_version);
        } else {
            ret = false;
        }
    } else {
        LOGE("fail: getnetworkinfo_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return ret;
}


static int create_funding_input(btc_tx_t *pTx, uint64_t *pSumAmount, uint64_t *pTxFee, uint64_t FundingSat, uint64_t FeeratePerKw)
{
    int retval = RPCERR_FUNDING;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = listunspent_rpc(&p_root, &p_result, &p_json);
    if (ret) {
        size_t index = 0;
        json_t *p_value = NULL;
        uint64_t sum_amount = 0;
        uint64_t txfee_sat = 0;
        int p2wpkh = 0;
        int p2sh = 0;
        int p2pkh = 0;
        int inputs = 0;

        json_array_foreach(p_result, index, p_value) {
            //txid, vout, address, label, scriptPubKey, amount, confirmations, spendable, solvable, safe
            json_t *p;
            uint64_t tmp_amount;

            p = json_object_get(p_value, "amount");
            if (p && json_is_real(p)) {
                tmp_amount = (uint64_t)(json_real_value(p) * (uint64_t)100000000);
            } else {
                continue;
            }
            p = json_object_get(p_value, "scriptPubKey");
            if (p && json_string_length(p) > 2) {
                const char *p_str = json_string_value(p);
                if (memcmp(p_str, "00", 2) == 0) {
                    p2wpkh++;
                    //LOGD("native P2WPKH\n");
                } else if (memcmp(p_str, "a9", 2) == 0) {
                    p2sh++;
                    //LOGD("nested P2WPKH\n");
                } else if (memcmp(p_str, "76", 2) == 0) {
                    p2pkh++;
                    //LOGD("P2PKH\n");
                } else {
                    continue;
                }
            }
            p = json_object_get(p_value, "txid");
            if (!p || !json_is_string(p)) {
                continue;
            }
            char txid_str[BTC_SZ_TXID * 2 + 1];
            strncpy(txid_str, json_string_value(p), sizeof(txid_str));
            txid_str[64] = '\0';
            p = json_object_get(p_value, "vout");
            if (!p || !json_is_integer(p)) {
                continue;
            }
            int vout = (int)json_integer_value(p);

            char outpoint[256];
            snprintf(outpoint, sizeof(outpoint),
                    "{"
                        M_JSON_STR("txid", "%s") M_NEXT
                        M_JSON_NUM("vout", "%d")
                    "}",
                    txid_str, vout);
            ret = lockunspent(outpoint);
            LOGD("lockunspent: %s\n", outpoint);
            if (!ret) {
                LOGD("skip: lockunspent\n");
                continue;
            }

            uint8_t txid[BTC_SZ_TXID];
            utl_str_str2bin_rev(txid, BTC_SZ_TXID, txid_str);
            (void)btc_tx_add_vin(pTx, txid, vout);
            sum_amount += tmp_amount;
            inputs++;

            //[unit:weight]
            //
            // version(4*4)
            // mark,flags(2)
            // vin_cnt(4*n)
            // vin(signature length=73)
            //     native P2WPKH(273) = 4*(outpoint(36) + scriptSig(1) + sequence(4)) + witness(1 + 1+73 + 1+33)
            //     nested P2WPKH(361) = 4*(outpoint(36) + scriptSig(23) + sequence(4)) + witness(1 + 1+73 + 1+33)
            //     P2PKH(596)         = 4*(outpoint(36) + scriptSig(1 + 1+73 + 1+33) + sequence(4))
            // vout_cnt(4*1)
            // vout(4*75)
            //     mainoutput(172) = 4*(amount(8) + native P2WSH(1 + 34))
            //     change(128)     = 4*(amount(8) + nested P2WPKH(1 + 23))
            // locktime(4*4)
            //     (version + vout_cnt + vout + locktime) + mark,flags = 4*86 = 338
            const uint64_t OTHERS = 4 * (4 + 1 + 75 + 4) + 2;
            uint64_t estimate_weight = OTHERS + (p2wpkh * 273 + p2sh * 361 + p2pkh * 596);
            txfee_sat = (estimate_weight * FeeratePerKw + 999) / 1000;
            if (FundingSat + txfee_sat < sum_amount) {
                break;
            }
        }
        if (inputs > 0) {
            LOGD("INPUT    = %" PRIu64 "\n", sum_amount);
            LOGD("OUTPUT   = %" PRIu64 "\n", FundingSat);
            LOGD("txfee_btc= %" PRIu64 "\n", txfee_sat);
            if (sum_amount >= (FundingSat + txfee_sat)) {
                LOGD("  remain %" PRIu64 "\n", sum_amount - FundingSat - txfee_sat);
                *pSumAmount = sum_amount;
                *pTxFee = txfee_sat;
                retval = 0;
            } else {
                LOGE("less amount: -%" PRIu64 "\n", FundingSat + txfee_sat - sum_amount);
                retval = RPCERR_FUNDING_LESS_INPUT;
            }
        } else {
            LOGE("no input\n");
            retval = RPCERR_FUNDING_LESS_INPUT;
        }
    } else {
        LOGE("fail: listunspent\n");
        retval = RPCERR_BLOCKCHAIN;
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return retval;
}


static bool lockunspent(const char *pOutPoint)
{
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = lockunspent_rpc(&p_root, &p_result, &p_json, pOutPoint);
    if (ret) {
        ret = json_boolean_value(p_result);
    } else {
        LOGE("fail: lockunspent_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return ret;
}


/**************************************************************************
 * private functions: JSON-RPC
 **************************************************************************/

/** [cURL]受信結果保存
 *
 * @note
 *      - `The data passed to this function will not be zero terminated!`
 *          https://curl.haxx.se/libcurl/c/CURLOPT_WRITEFUNCTION.html
 */
static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t realsize = size * nmemb;
    write_result_t *result = (write_result_t *)stream;

    if (result->pos + realsize >= result->sz) {
        //enlarge
        result->sz += result->pos + realsize + 1;
        *result->pp_data = (char *)UTL_DBG_REALLOC(*result->pp_data, result->sz);
    }
#ifdef M_DBG_SHOWREPLY
    int pos = result->pos;
#endif //M_DBG_SHOWREPLY

    memcpy(*result->pp_data + result->pos, ptr, realsize);
    result->pos += realsize;

    // \0は付与されないので、毎回つける
    // バッファが足りなくなることは無いだろう
    *(*result->pp_data + result->pos) = 0;       //\0

#ifdef M_DBG_SHOWREPLY
    LOGD("@@@[size=%lu]\n%s@@@\n\n", realsize, *result->pp_data + pos);
#endif //M_DBG_SHOWREPLY

    return realsize;
}


/** [cURL]getrawtransaction
 *
 */
static bool getrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTxid, bool detail)
{
    char *data = (char *)UTL_DBG_MALLOC(TXJSON_SIZE);
    snprintf(data, TXJSON_SIZE,
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "getrawtransaction") M_NEXT
             M_QQ("params") ":[" M_QQ("%s") ", %s]"
             "}", pTxid, (detail) ? "true" : "false");

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);
    UTL_DBG_FREE(data);

    return ret;
}


/** [cURL]signrawtransactionwithwallet
 *
 */
static bool signrawtransactionwithwallet_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction)
{
    size_t len = 256 + strlen(pTransaction);
    char *data = (char *)UTL_DBG_MALLOC(len);
    snprintf(data, len,
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "signrawtransactionwithwallet") M_NEXT
             M_QQ("params") ":[" M_QQ("%s") "]"
             "}", pTransaction);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);
    UTL_DBG_FREE(data);

    return ret;
}


/** [cURL]sendrawtransaction
 *
 */
static bool sendrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction)
{
    size_t len = 256 + strlen(pTransaction);
    char *data = (char *)UTL_DBG_MALLOC(len);
    snprintf(data, len,
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "sendrawtransaction") M_NEXT
             M_QQ("params") ":[" M_QQ("%s") "]"
             "}", pTransaction);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);
    UTL_DBG_FREE(data);

    return ret;
}


static bool gettxout_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTxid, int Idx)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "gettxout") M_NEXT
             M_QQ("params") ":[" M_QQ("%s") ",%d]"
             "}", pTxid, Idx);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


static bool getblock_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pBlock)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "getblock") M_NEXT
             M_QQ("params") ":[" M_QQ("%s") "]"
             "}", pBlock);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


static bool getblockhash_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, int BHeight)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "getblockhash") M_NEXT
             M_QQ("params") ":[ %d ]"
             "}", BHeight);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** [cURL]getblockcount
 *
 */
static bool getblockcount_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "getblockcount") M_NEXT
             M_QQ("params") ":[]"
             "}");

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** [cURL]getnewaddress
 *
 */
static bool getnewaddress_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "getnewaddress") M_NEXT
             //M_QQ("params") ":[" M_QQ("") ", " M_QQ("bech32") "]"
             M_QQ("params") ":[" M_QQ("") ", " M_QQ("p2sh-segwit") "]"
             "}");

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** [cURL]estimatefee
 *
 */
static bool estimatefee_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, int nBlock)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "estimatesmartfee") M_NEXT
             M_QQ("params") ":[%d]"
             "}", nBlock);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** [cURL]getbnetworkinfo
 *
 */
static bool getnetworkinfo_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "getnetworkinfo") M_NEXT
             M_QQ("params") ":[]"
             "}");

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** [cURL]listunspent
 *
 */
static bool listunspent_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "listunspent") M_NEXT
             M_QQ("params") ":[0]"
             "}");

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** [cURL]lockunspent
 *
 */
static bool lockunspent_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pOutPoint)
{
    char data[512];
    snprintf(data, sizeof(data),
             "{"
             ///////////////////////////////////////////
             M_RPCHEADER M_NEXT

             ///////////////////////////////////////////
             M_JSON_STR("method", "lockunspent") M_NEXT
             M_QQ("params") ":[false,[%s]]"
             "}", pOutPoint);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** JSON-RPC処理
 *
 * @retval  true    成功
 */
static bool rpc_proc(json_t **ppRoot, json_t **ppResult, char **ppJson, char *pData)
{
#ifdef M_DBG_SHOWRPC
    LOGD("%s\n", pData);
#endif //M_DBG_SHOWRPC

    bool ret = false;
    pthread_mutex_lock(&mMux);

    struct curl_slist *headers = curl_slist_append(NULL, "content-type: text/plain;");
    curl_easy_setopt(mCurl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(mCurl, CURLOPT_URL, mRpcUrl);
    curl_easy_setopt(mCurl, CURLOPT_POSTFIELDSIZE, (long)strlen(pData));
    curl_easy_setopt(mCurl, CURLOPT_POSTFIELDS, pData);
    curl_easy_setopt(mCurl, CURLOPT_USERPWD, mRpcUserPwd);
    curl_easy_setopt(mCurl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    curl_easy_setopt(mCurl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(mCurl, CURLOPT_FORBID_REUSE, 1L);

    //取得データはメモリに持つ
    write_result_t result;
    result.sz = BUFFER_SIZE;
    *ppJson = (char *)UTL_DBG_MALLOC(result.sz);
    result.pp_data = ppJson;
    result.pos = 0;
    curl_easy_setopt(mCurl, CURLOPT_WRITEFUNCTION, write_response);
    curl_easy_setopt(mCurl, CURLOPT_WRITEDATA, &result);

    CURLcode retval;
    retval = curl_easy_perform(mCurl);
    if (retval != CURLE_OK) {
        LOGD("curl err: %d(%s)\n", retval, curl_easy_strerror(retval));
    }
    curl_slist_free_all(headers);

    pthread_mutex_unlock(&mMux);

    if (retval == CURLE_OK) {
        json_error_t error;

        *ppRoot = json_loads(*ppJson, 0, &error);
        if (*ppRoot != NULL) {
            //これ以降は終了時に json_decref()で参照を減らすこと
            *ppResult = json_object_get(*ppRoot, M_RESULT);
            if (*ppResult != NULL) {
                ret = true;
            } else {
                LOGE("fail: object_get [%s]\n", *ppJson);
                json_decref(*ppRoot);
                *ppRoot = NULL;
            }
        } else {
            LOGD("error: on line %d,%d: %s[%s]\n", error.line, error.column, error.text, *ppJson);
        }
        if (!ret) {
            UTL_DBG_FREE(*ppJson);
        }
    } else {
        LOGE("curl err: %d\n", retval);
    }

    return ret;
}


static int error_result(json_t *p_root)
{
    int err = -1;
    json_t *p_msg = NULL;
    json_t *p_code = NULL;
    json_t *p_err = json_object_get(p_root, M_ERROR);
    if (p_err) {
        p_msg = json_object_get(p_err, M_MESSAGE);
        p_code = json_object_get(p_err, M_CODE);
    }
    if (p_msg) {
        LOGD("message=[%s]\n", (const char *)json_string_value(p_msg));
    }
    if (p_code) {
        err = (int)json_integer_value(p_code);
        LOGD("code=%d\n", err);
    }
    if (!p_msg && !p_code) {
        LOGE("fail: json_is_string\n");
    }

    return err;
}


#if 0
/**************************************************************************
gcc -ggdb -W -Wall -o tst -DPTARM_USE_PRINTFUNC -DUSE_BITCOIND btcrpc_bitcoind.c -I../utl -I../libs/install/include -L../libs/install/lib -I../ln -I../btc -L../utl -pthread -L../btc -lbtc -L../ln -lln -lbtc -lutl -ljansson -lcurl -lrt -lz -llmdb -lbase58  -lmbedcrypto -lstdc++
 **************************************************************************/

#include <inttypes.h>

int main(void)
{
    utl_log_init_stderr();

    bool ret;
    rpc_conf_t rpc_conf;
    strcpy(rpc_conf.rpcuser, "bitcoinuser");
    strcpy(rpc_conf.rpcpasswd, "bitcoinpassword");
    strcpy(rpc_conf.rpcurl, "127.0.0.1");

    btc_block_chain_t chain = BTC_BLOCK_CHAIN_BTCREGTEST;
    rpc_conf.rpcport = 18443;
    btc_init(chain, true);
    ret = btcrpc_init(&rpc_conf);
    if (!ret) {
        printf("fail: btcrpc_init\n");
        return 0;
    }

    printf("-[getgenesisblock]-------------------------\n");
    uint8_t genesis[BTC_SZ_HASH256];
    ret = btcrpc_getgenesisblock(genesis);
    if (!ret) {
        printf("fail: getgenesisblock\n");
        return 0;
    }
    if (memcmp(btc_block_get_genesis_hash(chain), genesis, BTC_SZ_HASH256) != 0) {
        printf("fail: genesis not match\n");
        return 0;
    }

    btc_tx_t tx = BTC_TX_INIT;
    const uint8_t ADDR[] = {
        0x00, 0x14, 0x89, 0xf9, 0x11, 0x9e, 0xe0, 0xb7, 0xf0, 0x42, 0xd3, 0x3e, 0x5d, 0x62, 0x16, 0x6d,
        0x28, 0x65, 0xfa, 0x6d, 0x84, 0x18,
    };
    const utl_buf_t buf_addr = { .buf = (CONST_CAST uint8_t *)ADDR, .len = sizeof(ADDR) };
    ret = btcrpc_sign_fundingtx(&tx, &buf_addr, 100000);
    if (!ret) {
        printf("fail: fundingtx\n");
        return 0;
    }
    btc_tx_print(&tx);
    btc_tx_free(&tx);

    printf("--------------------------\n");

    btcrpc_term();
    btc_term();
}
#endif


#if 0
/**************************************************************************
	gcc -o tst -DUSE_BITCOIND btcrpc_bitcoind.c -I../utl -I../libs/install/include -L../libs/install/lib -I../ln -I../btc -L../utl -pthread -L../btc -lbtc -L../ln -lln -lbtc -lutl -ljansson -lcurl -lrt -lz -llmdb -lbase58  -lmbedcrypto -lstdc++
 **************************************************************************/

#include <inttypes.h>

int main(int argc, char *argv[])
{
    utl_log_init_stderr();

    rpc_conf_t rpc_conf;
    strcpy(rpc_conf.rpcuser, "bitcoinuser");
    strcpy(rpc_conf.rpcpasswd, "bitcoinpassword");
    strcpy(rpc_conf.rpcurl, "127.0.0.1");

    btc_block_chain_t chain = BTC_BLOCK_CHAIN_BTCTEST;
    rpc_conf.rpcport = 18332;
    btc_init(chain, true);
    btcrpc_init(&rpc_conf);

    //height: 1514192
    //index : 9
    const uint8_t TXID[] = {
        0x3f, 0x23, 0x6b, 0x93, 0xd3, 0x03, 0xf7, 0x90,
        0xfb, 0xd9, 0x22, 0x79, 0x24, 0xf4, 0xda, 0x42,
        0xa7, 0xb1, 0x9f, 0x20, 0x23, 0x37, 0xcd, 0x60,
        0x10, 0x6f, 0x7f, 0x10, 0x59, 0x78, 0x40, 0x8d,
    };

    const uint8_t TX[] = {
        0x02, 0x00, 0x00, 0x00, 0x01, 0xd8, 0xfe, 0xfd,
        0x5c, 0x3c, 0xe8, 0x3c, 0xed, 0x0d, 0x5a, 0xec,
        0xa6, 0xab, 0x77, 0x0c, 0x67, 0xbe, 0x59, 0x58,
        0xd1, 0xcb, 0x40, 0x87, 0x13, 0x7c, 0x11, 0xf3,
        0x8d, 0xf7, 0xf3, 0x20, 0x63, 0x00, 0x00, 0x00,
        0x00, 0x6b, 0x48, 0x30, 0x45, 0x02, 0x21, 0x00,
        0xd3, 0xfd, 0x15, 0xcb, 0x8d, 0x94, 0x29, 0xfa,
        0x16, 0x18, 0xb2, 0xf3, 0xef, 0x6b, 0x17, 0x0d,
        0xd9, 0x26, 0x74, 0x0c, 0x69, 0xb8, 0xd4, 0xc7,
        0x84, 0xc9, 0x4a, 0x12, 0x74, 0xf5, 0x77, 0xff,
        0x02, 0x20, 0x7a, 0x26, 0xaa, 0xfe, 0xef, 0x9f,
        0xa6, 0x4c, 0x14, 0xcd, 0x75, 0xff, 0xf0, 0x03,
        0x46, 0x20, 0x29, 0x8e, 0x44, 0xfa, 0x68, 0xf8,
        0xef, 0x8d, 0x1d, 0x02, 0x5e, 0xa5, 0xf6, 0x8c,
        0xef, 0x6d, 0x01, 0x21, 0x03, 0xd1, 0x5c, 0x91,
        0x43, 0x3a, 0xe1, 0xc5, 0x2b, 0x25, 0x22, 0x0f,
        0x6f, 0x01, 0xf5, 0xa0, 0x0f, 0x01, 0x98, 0xcc,
        0x25, 0x45, 0x3f, 0x33, 0x13, 0x0d, 0xe0, 0x78,
        0x68, 0x4a, 0x9a, 0x88, 0xe5, 0xff, 0xff, 0xff,
        0xff, 0x02, 0xb4, 0x19, 0x2f, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x19, 0x76, 0xa9, 0x14, 0xcb, 0x9b,
        0x23, 0x3d, 0x9c, 0xf8, 0x75, 0xe6, 0x29, 0x52,
        0x10, 0xe2, 0x02, 0x7e, 0x4c, 0xc6, 0x9f, 0x03,
        0x47, 0x3e, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x22, 0x6a, 0x20, 0x05,
        0x8e, 0x3c, 0x8d, 0x18, 0x0b, 0x69, 0x9a, 0xfd,
        0x8a, 0xd4, 0xaf, 0xd5, 0x09, 0x29, 0x58, 0x26,
        0x5d, 0x80, 0x68, 0xac, 0x05, 0x28, 0x65, 0x01,
        0x5f, 0x0b, 0x2e, 0xa3, 0xf2, 0xca, 0x7a, 0x00,
        0x00, 0x00, 0x00,
    };

    bool ret;

    printf("-[getgenesisblock]-------------------------\n");
    uint8_t genesis[BTC_SZ_HASH256];
    ret = btcrpc_getgenesisblock(genesis);
    if (!ret) {
        printf("fail: getgenesisblock\n");
        return 0;
    }
    if (memcmp(btc_block_get_genesis_hash(chain), genesis, BTC_SZ_HASH256) != 0) {
        printf("fail: genesis not match\n");
        return 0;
    }

    printf("-[getblockcount]-------------------------\n");
    int32_t blocks;
    ret = btcrpc_getblockcount(&blocks);
    if (!ret) {
        printf("fail: getblockcount\n");
        return 0;
    }
    printf("blocks = %d\n", blocks);

    printf("-[short_channel_info]-------------------------\n");
    int32_t bheight;
    int32_t bindex;
    ret = btcrpc_get_short_channel_param(NULL, &bheight, &bindex, NULL, TXID);
    if (!ret) {
        printf("fail: get short_channel_param\n");
        return 0;
    }
    printf("height = %d\n", bheight);
    printf("index = %d\n", bindex);
    if ((bheight != 1514192) || (bindex != 9)) {
        printf("fail: not height or bindex\n");
        return 0;
    }

    int32_t conf;
    printf("-conf-------------------------\n");
    ret = btcrpc_get_confirmations(&conf, TXID);
    if (!ret) {
        printf("fail: get confirmation\n");
        return 0;
    }
    printf("confirmations = %d\n", (int)conf);

    printf("-getnewaddress-------------------------\n");
    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    ret = btcrpc_getnewaddress(addr);
    if (!ret) {
        printf("fail: get newaddress\n");
        return 0;
    }
    printf("addr=%s\n", addr);

    printf("-check_unspent-------------------------\n");
    bool unspent;
    uint64_t value;
    ret = btcrpc_check_unspent(NULL, &unspent, &value, TXID, 1);
    if (!ret) {
        printf("fail: check unspent\n");
        return 0;
    }
    printf("unspent: %d\n", unspent);
    if (unspent) {
        printf("value: value=%" PRIu64 "\n", value);
        if (value != 7775309) {
            printf("fail: value not match\n");
            return 0;
        }
    }

    printf("-is_tx_broadcasted------------------------\n");
    ret = btcrpc_is_tx_broadcasted(TXID);
    if (!ret) {
        printf("fail: check broadcasted\n");
        return 0;
    }

//    printf("-sendrawtx-------------------------\n");
//    uint8_t txid[BTC_SZ_TXID];
//    ret = btcrpc_send_rawtx(txid, NULL, TX, sizeof(TX));
//    if (ret) {
//        for (int lp = 0; lp < sizeof(txid); lp++) {
//            printf("%02x", txid[lp]);
//        }
//        printf("\n");
//    }

    printf("-short_channel_id_get_param-------------------------\n");
    {
        uint32_t bheight;
        uint32_t bindex;
        uint32_t vindex;
        bool unspent;
        uint64_t short_channel_id;
        uint8_t txid[BTC_SZ_TXID];

        short_channel_id = 0x11a7810000440000ULL;
        ln_short_channel_id_get_param(&bheight, &bindex, &vindex, short_channel_id);
        unspent = btcrpc_gettxid_from_short_channel(txid, bheight, bindex);
        printf("%016" PRIx64 " = %d\n", short_channel_id, unspent);
        if ((bheight != 1156993) || (bindex != 68)) {
            printf("fail: short_channel_id\n");
            return 0;
        }

        short_channel_id = 0x11a2eb0000210000ULL;
        ln_short_channel_id_get_param(&bheight, &bindex, &vindex, short_channel_id);
        unspent = btcrpc_gettxid_from_short_channel(txid, bheight, bindex);
        printf("%016" PRIx64 " = %d\n", short_channel_id, unspent);
        if ((bheight != 1155819) || (bindex != 33)) {
            printf("fail: short_channel_id\n");
            return 0;
        }
    }

    printf("-estimatefee-------------------------\n");
    {
        uint64_t feeperrate;
        bool ret = btcrpc_estimatefee(&feeperrate, 3);
        if (ret) {
            printf("feeperate=%"PRIu64"\n", feeperrate);
        } else {
            printf("feeperate=failure\n");
        }
    }

    printf("--------------------------\n");

    btcrpc_term();
    btc_term();
}
#endif
