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

#include "utl_misc.h"
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
#define M_1(item,value)     M_QQ(item) ":" M_QQ(value)

#define M_MIN_BITCOIND_VERSION  (150000)        //必要とするバージョン

//#define M_DBG_SHOWRPC       //RPCの命令
//#define M_DBG_SHOWREPLY     //RPCの応答

#define M_BITCOIND_RPC_METHOD_DEPRECATED (-32) //ref. https://github.com/bitcoin/bitcoin/blob/master/src/rpc/protocol.h


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
static bool getraw_tx(json_t **ppRoot, json_t **ppResult, char **ppJson, const uint8_t *pTxid);
static bool getraw_txstr(btc_tx_t *pTx, const char *txid);
static bool signraw_tx(btc_tx_t *pTx, const uint8_t *pData, size_t Len, uint64_t Amount, int* pCode);
static bool signraw_tx_with_wallet(btc_tx_t *pTx, const uint8_t *pData, size_t Len, uint64_t Amount);
static bool gettxout(bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex);
static bool search_outpoint(btc_tx_t *pTx, int BHeight, const uint8_t *pTxid, uint32_t VIndex);
static bool search_vout_block(utl_buf_t *pTxBuf, int BHeight, const utl_buf_t *pVout);
static bool getversion(int64_t *pVersion);

static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream);
static bool getrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTxid, bool detail);
static bool signrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction);
static bool signrawtransactionwithwallet_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction);
static bool sendrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction);
static bool gettxout_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTxid, int idx);
static bool getblock_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pBlock);
static bool getblockhash_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, int BHeight);
static bool getblockcount_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson);
static bool getnewaddress_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson);
static bool estimatefee_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, int nBlock);
static bool getnetworkinfo_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson);
//static bool dumpprivkey_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pAddr);
static bool rpc_proc(json_t **ppRoot, json_t **ppResult, char **ppJson, char *pData);
static int error_result(json_t *p_root);


/**************************************************************************
 * static variables
 **************************************************************************/

static char     rpc_url[SZ_RPC_URL + 1 + 5 + 2];
static char     rpc_userpwd[SZ_RPC_USER + 1 + SZ_RPC_PASSWD + 1];
static pthread_mutex_t      mMux;
static CURL     *mCurl;

static const char *M_RESULT       =    "result";
static const char *M_CONFIRMATION =    "confirmations";
static const char *M_HEX          =    "hex";
static const char *M_BLOCKHASH    =    "blockhash";
static const char *M_HEIGHT       =    "height";
static const char *M_VALUE        =    "value";
static const char *M_TX           =    "tx";
static const char *M_ERROR        =    "error";
static const char *M_MESSAGE      =    "message";
static const char *M_CODE         =    "code";
static const char *M_FEERATE      =    "feerate";


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

    sprintf(rpc_url, "%s:%d", pRpcConf->rpcurl, pRpcConf->rpcport);
    sprintf(rpc_userpwd, "%s:%s", pRpcConf->rpcuser, pRpcConf->rpcpasswd);
    LOGD("URL=%s\n", rpc_url);
#ifdef M_DBG_SHOWRPC
    LOGD("rpc_userpwd=%s\n", rpc_userpwd);
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

    return ret;
}


void btcrpc_term(void)
{
    curl_easy_cleanup(mCurl);
    mCurl = NULL;
    curl_global_cleanup();
    pthread_mutex_destroy(&mMux);
}


int32_t btcrpc_getblockcount(void)
{
    bool ret;
    int32_t blocks = -1;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getblockcount_rpc(&p_root, &p_result, &p_json);
    if (ret && json_is_integer(p_result)) {
        blocks = (int32_t)json_integer_value(p_result);
    } else {
        LOGD("fail: getblockcount_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return blocks;
}


bool btcrpc_getgenesisblock(uint8_t *pHash)
{
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getblockhash_rpc(&p_root, &p_result, &p_json, 0);
    if (ret && json_is_string(p_result)) {
        ret = utl_misc_str2bin(pHash, LN_SZ_HASH, (const char *)json_string_value(p_result));
    } else {
        LOGD("fail: getblockhash_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return ret;
}


bool btcrpc_get_confirm(uint32_t *pConfirm, const uint8_t *pTxid)
{
    bool ret;
    bool retval = false;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getraw_tx(&p_root, &p_result, &p_json, pTxid);
    if (ret) {
        json_t *p_confirm;

        p_confirm = json_object_get(p_result, M_CONFIRMATION);
        if (json_is_integer(p_confirm)) {
            *pConfirm = (uint32_t)json_integer_value(p_confirm);
            retval = true;
        }
    } else {
        LOGD("fail: getrawtransaction_rpc\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return retval;
}


bool btcrpc_get_short_channel_param(const ln_self_t *self, int *pBHeight, int *pBIndex, uint8_t *pMinedHash, const uint8_t *pTxid)
{
    (void)self;
    (void)pMinedHash;

    bool ret;
    char *p_json = NULL;
    char blockhash[BTC_SZ_SHA256 * 2 + 1] = "NG";
    json_t *p_root = NULL;
    json_t *p_result;

    *pBHeight = -1;
    *pBIndex = -1;

    ret = getraw_tx(&p_root, &p_result, &p_json, pTxid);
    if (ret) {
        json_t *p_bhash;

        p_bhash = json_object_get(p_result, M_BLOCKHASH);
        if (json_is_string(p_bhash)) {
            strcpy(blockhash, (const char *)json_string_value(p_bhash));
        }
    } else {
        LOGD("fail: getrawtransaction_rpc\n");
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
        utl_misc_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

        size_t index = 0;
        json_t *p_value = NULL;
        json_array_foreach(p_tx, index, p_value) {
            if (strcmp(txid, (const char *)json_string_value(p_value)) == 0) {
                *pBIndex = (int)index;
                break;
            }
        }
    } else {
        LOGD("fail: getblock_rpc\n");
    }

LABEL_EXIT:
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    if ((*pBIndex == -1) || (*pBHeight == -1)) {
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
                utl_misc_str2bin_rev(pTxid, BTC_SZ_TXID, (const char *)json_string_value(p_value));
                break;
            }
        }
    } else {
        LOGD("fail: getblocktx\n");
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
    bool ret = false;
    int32_t height = btcrpc_getblockcount();

    //現在からBlksの間に、使用したtransactionがあるかどうか
    if (height > 0) {
        for (uint32_t lp = 0; lp < Blks; lp++) {
            ret = search_outpoint(pTx, height - lp, pTxid, VIndex);
            if (ret) {
                break;
            }
        }
    }

    return ret;
}


bool btcrpc_search_vout(utl_buf_t *pTxBuf, uint32_t Blks, const utl_buf_t *pVout)
{
    bool ret = false;
    int32_t height = btcrpc_getblockcount();

    //現在からBlksの間に使用したtransactionがあるかどうか
    if (height > 0) {
        for (uint32_t lp = 0; lp < Blks; lp++) {
            ret = search_vout_block(pTxBuf, height - lp, pVout);
            if (ret) {
                break;
            }
        }
    }

    return ret;
}


bool btcrpc_signraw_tx(btc_tx_t *pTx, const uint8_t *pData, size_t Len, uint64_t Amount)
{
    int code = 0;

    if (signraw_tx(pTx, pData, Len, Amount, &code)) return true;
    if (code != M_BITCOIND_RPC_METHOD_DEPRECATED) return false;
    return signraw_tx_with_wallet(pTx, pData, Len, Amount);
}


bool btcrpc_sendraw_tx(uint8_t *pTxid, int *pCode, const uint8_t *pRawData, uint32_t Len)
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    char *transaction;
    json_t *p_root = NULL;
    json_t *p_result;

    transaction = (char *)UTL_DBG_MALLOC(Len * 2 + 1);
    utl_misc_bin2str(transaction, pRawData, Len);

    ret = sendrawtransaction_rpc(&p_root, &p_result, &p_json, transaction);
    UTL_DBG_FREE(transaction);
    if (ret) {
        if (json_is_string(p_result)) {
            //TXIDはLE/BE変換
            utl_misc_str2bin_rev(pTxid, BTC_SZ_TXID, (const char *)json_string_value(p_result));
            result = true;
        } else {
            int code = error_result(p_root);
            if (pCode) {
                *pCode = code;
            }
        }
    } else {
        LOGD("fail: sendrawtransaction_rpc()\n");
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
    utl_misc_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

    return getraw_txstr(NULL, txid);
}


bool btcrpc_check_unspent(bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, uint32_t VIndex)
{
    bool unspent = true;
    uint64_t sat = 0;
    bool ret = gettxout(&unspent, &sat, pTxid, VIndex);
    if (pUnspent != NULL) {
        *pUnspent = unspent;
    }
    if (pSat != NULL) {
        *pSat = sat;
    }

    return ret;
}


bool btcrpc_getnewaddress(char pAddr[BTC_SZ_ADDR_MAX])
{
    bool result = false;
    bool ret;
    char *p_json = NULL;
    json_t *p_root = NULL;
    json_t *p_result;

    ret = getnewaddress_rpc(&p_root, &p_result, &p_json);
    if (ret) {
        if (json_is_string(p_result)) {
            if (strlen(json_string_value(p_result)) < BTC_SZ_ADDR_MAX) {
                strcpy(pAddr,  (const char *)json_string_value(p_result));
                result = true;
            }
        }
    } else {
        LOGD("fail: getnewaddress_rpc()\n");
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
        LOGD("fail: nBlock < 2\n");
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
                LOGD("fail: Unable to estimate fee\n");
            }
        } else {
            LOGD("fail: not real value\n");
        }
    } else {
        LOGD("fail: estimatefee_rpc()\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return result;
}


void btcrpc_add_channel(const ln_self_t *self, uint64_t shortChannelId, const uint8_t *pTxBuf, uint32_t Len, bool bUnspent, const uint8_t *pMinedHash)
{
    (void)self; (void)shortChannelId; (void)pTxBuf; (void)Len; (void)bUnspent; (void)pMinedHash;
}


void btcrpc_set_fundingtx(const ln_self_t *self, const uint8_t *pTxBuf, uint32_t Len)
{
    (void)self; (void)pTxBuf; (void)Len;
}


void btcrpc_set_committxid(const ln_self_t *self)
{
    (void)self;
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
    char blockhash[BTC_SZ_SHA256 * 2 + 1];

    *ppJsonTx = NULL;
    *ppRoot = NULL;

    //ブロック高→ブロックハッシュ
    ret = getblockhash_rpc(&p_root, &p_result, &p_json, BHeight);
    if (!ret) {
        LOGD("fail: getblockhash_rpc\n");
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
        LOGD("fail: getblock_rpc\n");
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


static bool getraw_tx(json_t **ppRoot, json_t **ppResult, char **ppJson, const uint8_t *pTxid)
{
    char txid[BTC_SZ_TXID * 2 + 1];

    //TXIDはBE/LE変換
    utl_misc_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

    bool ret = getrawtransaction_rpc(ppRoot, ppResult, ppJson, txid, true);
    return ret;
}


/** getrawtransaction(TXID文字列)
 *
 * @retval  true    取得成功
 * @retval  false   取得失敗 or bitcoindエラー
 */
static bool getraw_txstr(btc_tx_t *pTx, const char *txid)
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
            utl_misc_str2bin(p_hex, len, str_hex);
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


static bool signraw_tx(btc_tx_t *pTx, const uint8_t *pData, size_t Len, uint64_t Amount, int* pCode)
{
    (void)Amount;

    bool result = false;
    bool ret;
    char *p_json = NULL;
    char *transaction;
    json_t *p_root = NULL;
    json_t *p_result;

    *pCode = 0;
    transaction = (char *)UTL_DBG_MALLOC(Len * 2 + 1);
    utl_misc_bin2str(transaction, pData, Len);

    ret = signrawtransaction_rpc(&p_root, &p_result, &p_json, transaction);
    UTL_DBG_FREE(transaction);
    if (ret) {
        json_t *p_hex;

        p_hex = json_object_get(p_result, M_HEX);
        if (json_is_string(p_hex)) {
            const char *p_sigtx = (const char *)json_string_value(p_hex);
            size_t len = strlen(p_sigtx) / 2;
            uint8_t *p_buf = UTL_DBG_MALLOC(len);
            utl_misc_str2bin(p_buf, len, p_sigtx);
            btc_tx_free(pTx);
            result = btc_tx_read(pTx, p_buf, len);
            UTL_DBG_FREE(p_buf);
        } else {
            int code = error_result(p_root);
            LOGD("err code=%d\n", code);
            *pCode = code;
        }
    } else {
        LOGD("fail: signrawtransaction_rpc()\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

    return result;
}


static bool signraw_tx_with_wallet(btc_tx_t *pTx, const uint8_t *pData, size_t Len, uint64_t Amount)
{
    (void)Amount;

    bool result = false;
    bool ret;
    char *p_json = NULL;
    char *transaction;
    json_t *p_root = NULL;
    json_t *p_result;

    transaction = (char *)UTL_DBG_MALLOC(Len * 2 + 1);
    utl_misc_bin2str(transaction, pData, Len);

    ret = signrawtransactionwithwallet_rpc(&p_root, &p_result, &p_json, transaction);
    UTL_DBG_FREE(transaction);
    if (ret) {
        json_t *p_hex;

        p_hex = json_object_get(p_result, M_HEX);
        if (json_is_string(p_hex)) {
            const char *p_sigtx = (const char *)json_string_value(p_hex);
            size_t len = strlen(p_sigtx) / 2;
            uint8_t *p_buf = UTL_DBG_MALLOC(len);
            utl_misc_str2bin(p_buf, len, p_sigtx);
            btc_tx_free(pTx);
            result = btc_tx_read(pTx, p_buf, len);
            UTL_DBG_FREE(p_buf);
        } else {
            int code = error_result(p_root);
            LOGD("err code=%d\n", code);
        }
    } else {
        LOGD("fail: signrawtransactionwithwallet_rpc()\n");
    }
    if (p_root != NULL) {
        json_decref(p_root);
    }
    UTL_DBG_FREE(p_json);

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
    utl_misc_bin2str_rev(txid, pTxid, BTC_SZ_TXID);

    //まずtxの存在確認を行う
    ret = getraw_txstr(NULL, txid);
    if (!ret) {
        //LOGD("fail: maybe not broadcasted\n");
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
        LOGD("fail: gettxout_rpc()\n");
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

            ret = getraw_txstr(&tx, txid);
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
        LOGD("fail: getblock_rpc\n");
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

            ret = getraw_txstr(&tx, txid);
            if (ret) {
                for (uint32_t lp = 0; lp < tx.vout_cnt; lp++) {
                    for (int lp2 = 0; lp2 < vout_num; lp2++) {
                        if (utl_buf_cmp(&tx.vout[0].script, &pVout[lp2])) {
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
        LOGD("fail: getblock_rpc\n");
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
        LOGD("fail: getnetworkinfo_rpc\n");
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
    write_result_t *result = (write_result_t *)stream;

    if (result->pos + size * nmemb >= result->sz - 1) {
        //enlarge
        result->sz += size * nmemb * 2;   //倍程度確保する
        *result->pp_data = (char *)UTL_DBG_REALLOC(*result->pp_data, result->sz);
    }
#ifdef M_DBG_SHOWREPLY
    int pos = result->pos;
#endif //M_DBG_SHOWREPLY

    memcpy(*result->pp_data + result->pos, ptr, size * nmemb);
    result->pos += size * nmemb;

    // \0は付与されないので、毎回つける
    // バッファが足りなくなることは無いだろう
    *(*result->pp_data + result->pos) = 0;       //\0

#ifdef M_DBG_SHOWREPLY
    LOGD("@@@[%lu, %lu=%lu]\n%s@@@\n\n", size, nmemb, size * nmemb, *result->pp_data + pos);
#endif //M_DBG_SHOWREPLY

    return size * nmemb;
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
            M_1("method", "getrawtransaction") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") ", %s]"
        "}", pTxid, (detail) ? "true" : "false");

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);
    UTL_DBG_FREE(data);

    return ret;
}


/** [cURL]signrawtransaction
 *
 */
static bool signrawtransaction_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction)
{
    char *data = (char *)UTL_DBG_MALLOC(TXJSON_SIZE);
    snprintf(data, TXJSON_SIZE,
        "{"
            ///////////////////////////////////////////
            M_RPCHEADER M_NEXT

            ///////////////////////////////////////////
            M_1("method", "signrawtransaction") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") "]"
        "}", pTransaction);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);
    UTL_DBG_FREE(data);

    return ret;
}


/** [cURL]signrawtransactionwithwallet
 *
 */
static bool signrawtransactionwithwallet_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTransaction)
{
    char *data = (char *)UTL_DBG_MALLOC(TXJSON_SIZE);
    snprintf(data, TXJSON_SIZE,
        "{"
            ///////////////////////////////////////////
            M_RPCHEADER M_NEXT

            ///////////////////////////////////////////
            M_1("method", "signrawtransactionwithwallet") M_NEXT
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
    char *data = (char *)UTL_DBG_MALLOC(TXJSON_SIZE);
    snprintf(data, TXJSON_SIZE,
        "{"
            ///////////////////////////////////////////
            M_RPCHEADER M_NEXT

            ///////////////////////////////////////////
            M_1("method", "sendrawtransaction") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") "]"
        "}", pTransaction);

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);
    UTL_DBG_FREE(data);

    return ret;
}


static bool gettxout_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pTxid, int idx)
{
    char data[512];
    snprintf(data, sizeof(data),
        "{"
            ///////////////////////////////////////////
            M_RPCHEADER M_NEXT

            ///////////////////////////////////////////
            M_1("method", "gettxout") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") ",%d]"
        "}", pTxid, idx);

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
            M_1("method", "getblock") M_NEXT
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
            M_1("method", "getblockhash") M_NEXT
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
            M_1("method", "getblockcount") M_NEXT
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
            M_1("method", "getnewaddress") M_NEXT
            M_QQ("params") ":[]"
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
            M_1("method", "estimatesmartfee") M_NEXT
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
            M_1("method", "getnetworkinfo") M_NEXT
            M_QQ("params") ":[]"
        "}");

    bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

    return ret;
}


/** [cURL]dumpprivkey
 *
 */
// static bool dumpprivkey_rpc(json_t **ppRoot, json_t **ppResult, char **ppJson, const char *pAddr)
// {
//     char data[512];
//     snprintf(data, sizeof(data),
//         "{"
//             ///////////////////////////////////////////
//             M_RPCHEADER M_NEXT
//
//             ///////////////////////////////////////////
//             M_1("method", "dumpprivkey") M_NEXT
//             M_QQ("params") ":[" M_QQ("%s") "]"
//         "}", pAddr);

//     bool ret = rpc_proc(ppRoot, ppResult, ppJson, data);

//     return ret;
// }


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
    curl_easy_setopt(mCurl, CURLOPT_URL, rpc_url);
    curl_easy_setopt(mCurl, CURLOPT_POSTFIELDSIZE, (long)strlen(pData));
    curl_easy_setopt(mCurl, CURLOPT_POSTFIELDS, pData);
    curl_easy_setopt(mCurl, CURLOPT_USERPWD, rpc_userpwd);
    curl_easy_setopt(mCurl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    curl_easy_setopt(mCurl, CURLOPT_NOSIGNAL, 1);

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
                json_decref(*ppRoot);
                *ppRoot = NULL;
            }
        } else {
            LOGD("error: on line %d: %s\n", error.line, error.text);
        }
        if (!ret) {
            UTL_DBG_FREE(*ppJson);
        }
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
        LOGD("fail: json_is_string\n");
    }

    return err;
}


#ifdef JSONRPC_TEST
/**************************************************************************
	gcc -o tst -I.. -I../include -I../libs/install/include -I../ptarm/include -DNETKIND=1 -DJSONRPC_TEST misc.c btcrpc.c -L../libs/install/lib -lcurl -ljansson -L../ptarm -lptarm -lbase58 -lmbedcrypto -llmdb -pthread
 **************************************************************************/

#include <inttypes.h>

int main(int argc, char *argv[])
{
    const uint8_t TXID[] = {
        0x49, 0x19, 0x7d, 0x36, 0xaf, 0x1d, 0xa5, 0xa8,
        0x8d, 0x08, 0x44, 0x72, 0xdf, 0x34, 0x4d, 0xf1,
        0x2b, 0xa9, 0xa8, 0x1e, 0xf8, 0x98, 0xb1, 0x10,
        0xe4, 0x50, 0x6e, 0x93, 0xdb, 0x29, 0x81, 0xa4,
    };
//    const uint8_t TXID[] = {
//        0x87, 0x48, 0xc6, 0x00, 0x69, 0xad, 0xa7, 0x73,
//        0x47, 0x04, 0xe9, 0x9f, 0xb2, 0xd0, 0x0f, 0x83,
//        0x86, 0xad, 0xfa, 0x2e, 0xc7, 0x87, 0x78, 0x82,
//        0x7e, 0x5a, 0x11, 0xd1, 0x2f, 0xef, 0x7b, 0x78,
//    };

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

#ifndef NETKIND
#error not define NETKIND
#endif
#if NETKIND==0
    btc_init(PTARM_MAINNET, true);
#elif NETKIND==1
    btc_init(PTARM_TESTNET, true);
#endif

    rpc_conf_t rpc_conf;

    strcpy(rpc_conf.rpcuser, "bitcoinuser");
    strcpy(rpc_conf.rpcpasswd, "bitcoinpassword");
    strcpy(rpc_conf.rpcurl, "127.0.0.1");
    btcrpc_init(&rpc_conf);

    bool ret;

//    fprintf(stderr, "-[getblockcount]-------------------------\n");
//    int blocks = getblockcount();
//    fprintf(stderr, "blocks = %d\n", blocks);

//    fprintf(stderr, "-[short_channel_info]-------------------------\n");
//    int bindex;
//    int bheight;
//    ret = btcrpc_get_short_channel_param(NULL, &bindex, &bheight, NULL, TXID);
//    if (ret) {
//        fprintf(stderr, "index = %d\n", bindex);
//        fprintf(stderr, "height = %d\n", bheight);
//    }

//    uint32_t conf;
//    fprintf(stderr, "-conf-------------------------\n");
//    bool b = btcrpc_get_confirm(&conf, TXID);
//    fprintf(stderr, "confirmations = %d(%d)\n", (int)conf, b);

//    fprintf(stderr, "-getnewaddress-------------------------\n");
//    char addr[BTC_SZ_ADDR_MAX];
//    ret = btcrpc_getnewaddress(addr);
//    if (ret) {
//        fprintf(stderr, "addr=%s\n", addr);
//    }

//    fprintf(stderr, "-dumpprivkey-------------------------\n");
//    char wif[BTC_SZ_WIF_MAX];
//    ret = btcrpc_dumpprivkey(wif, addr);
//    if (ret) {
//        fprintf(stderr, "wif=%s\n", wif);
//    }

    //fprintf(stderr, "-gettxout-------------------------\n");
    //bool unspent;
    //uint64_t value;
    //ret = btcrpc_check_unspent(&unspent, &value, TXID, 1);
    //if (ret && unspent) {
    //    fprintf(stderr, "value=%" PRIu64 "\n", value);
    //}

//    fprintf(stderr, "-getrawtx------------------------\n");
//    ret = btcrpc_is_tx_broadcasted(TXID);
//    fprintf(stderr, "ret=%d\n", ret);

//    fprintf(stderr, "--------------------------\n");
//    uint8_t txid[BTC_SZ_TXID];
//    bool ret = btcrpc_sendraw_tx(txid, NULL, TX, sizeof(TX));
//    if (ret) {
//        for (int lp = 0; lp < sizeof(txid); lp++) {
//            fprintf(stderr, "%02x", txid[lp]);
//        }
//        fprintf(stderr, "\n");
//    }

    // fprintf(stderr, "--------------------------\n");
    // {
    //     uint32_t bheight;
    //     uint32_t bindex;
    //     uint32_t vindex;
    //     bool unspent;
    //     uint64_t short_channel_id;
    //     uint8_t txid[BTC_SZ_TXID];

    //     short_channel_id = 0x11a7810000440000ULL;
    //     ln_short_channel_id_get_param(&bheight, &bindex, &vindex, short_channel_id);
    //     unspent = btcrpc_gettxid_from_short_channel(txid, bheight, bindex);
    //     fprintf(stderr, "%016" PRIx64 " = %d\n", short_channel_id, unspent);

    //     short_channel_id = 0x11a2eb0000210000ULL;
    //     ln_short_channel_id_get_param(&bheight, &bindex, &vindex, short_channel_id);
    //     unspent = btcrpc_gettxid_from_short_channel(txid, bheight, bindex);
    //     fprintf(stderr, "%016" PRIx64 " = %d\n", short_channel_id, unspent);
    // }

    fprintf(stderr, "--------------------------\n");
    {
        uint64_t feeperrate;
        bool ret = btcrpc_estimatefee(&feeperrate, 3);
        if (ret) {
            printf("feeperate=%"PRIu64"\n", feeperrate);
        } else {
            printf("feeperate=failure\n");
        }
    }

    fprintf(stderr, "--------------------------\n");

    btcrpc_term();
    btc_term();
}
#endif
