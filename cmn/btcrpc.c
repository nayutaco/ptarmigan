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

#include "btcrpc.h"
#include "misc.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define RPCID           "ucoindrpc"

#define BUFFER_SIZE     (256 * 1024)

#define M_NEXT              ","
#define M_QQ(str)           "\"" str "\""
#define M_1(item,value)     M_QQ(item) ":" M_QQ(value)


#define M_RESULT            "result"
#define M_CONFIRMATION      "confirmations"
#define M_HEX               "hex"
#define M_BLOCKHASH         "blockhash"
#define M_HEIGHT            "height"
#define M_VALUE             "value"
#define M_TX                "tx"
#define M_ERROR             "error"
#define M_MESSAGE           "message"
#define M_CODE              "code"
#define M_FEERATE           "feerate"

//#define M_DBG_SHOWRPC       //RPCの命令
//#define M_DBG_SHOWREPLY     //RPCの応答


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

static size_t write_response(void *ptr, size_t size, size_t nmemb, void *stream);
static bool getraw_txstr(ucoin_tx_t *pTx, const char *txid);
static bool getrawtransaction_rpc(char **ppJson, const char *pTxid, bool detail);
static bool signrawtransaction_rpc(char **ppJson, const char *pTransaction);
static bool sendrawtransaction_rpc(char **ppJson, const char *pTransaction);
static bool gettxout_rpc(char **ppJson, const char *pTxid, int idx);
static bool getblock_rpc(char **ppJson, const char *pBlock);
static bool getblockhash_rpc(char **ppJson, int BHeight);
static bool getblockcount_rpc(char **ppJson);
static bool getnewaddress_rpc(char **ppJson);
static bool estimatefee_rpc(char **ppJson, int nBlock);
//static bool dumpprivkey_rpc(char **ppJson, const char *pAddr);
static bool rpc_proc(char **ppJson, char *pData);
static int error_result(json_t *p_root);


/**************************************************************************
 * static variables
 **************************************************************************/

static char     rpc_url[SZ_RPC_URL + 1 + 5 + 2];
static char     rpc_userpwd[SZ_RPC_USER + 1 + SZ_RPC_PASSWD + 1];
static pthread_mutex_t      mMux;
static CURL     *mCurl;


/**************************************************************************
 * public functions
 **************************************************************************/

void btcrpc_init(const rpc_conf_t *pRpcConf)
{
    pthread_mutex_init(&mMux, NULL);
    curl_global_init(CURL_GLOBAL_ALL);
    mCurl = curl_easy_init();
    if (mCurl == NULL) {
        LOGD("fatal: cannot init curl\n");
        abort();
    }

    sprintf(rpc_url, "%s:%d", pRpcConf->rpcurl, pRpcConf->rpcport);
    sprintf(rpc_userpwd, "%s:%s", pRpcConf->rpcuser, pRpcConf->rpcpasswd);
    LOGD("URL=%s\n", rpc_url);
#ifdef M_DBG_SHOWRPC
    LOGD("rpcuser=%s\n", rpc_userpwd);
#endif //M_DBG_SHOWRPC
}

void btcrpc_term(void)
{
    curl_easy_cleanup(mCurl);
    mCurl = NULL;
    curl_global_cleanup();
}


int32_t btcrpc_getblockcount(void)
{
    bool retval;
    int32_t blocks = -1;
    char *p_json = NULL;

    retval = getblockcount_rpc(&p_json);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result) {
            if (json_is_integer(p_result)) {
                blocks = (int32_t)json_integer_value(p_result);
            } else {
                LOGD("error: not integer\n");
            }
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: getblockcount_rpc\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return blocks;
}


bool btcrpc_getblockhash(uint8_t *pHash, int Height)
{
    bool ret = false;
    bool retval;
    char *p_json = NULL;

    retval = getblockhash_rpc(&p_json, Height);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result) {
            if (json_is_string(p_result)) {
                ret = misc_str2bin(pHash, LN_SZ_HASH, (const char *)json_string_value(p_result));
            }
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: getblockhash_rpc\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


uint32_t btcrpc_get_confirmation(const uint8_t *pTxid)
{
    bool retval;
    int64_t confirmation = 0;
    char *p_json = NULL;
    char txid[UCOIN_SZ_TXID * 2 + 1];

    //TXIDはBE/LE変換
    ucoin_util_bin2str_rev(txid, pTxid, UCOIN_SZ_TXID);

    retval = getrawtransaction_rpc(&p_json, txid, true);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_confirm;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result) {
            p_confirm = json_object_get(p_result, M_CONFIRMATION);
            if (json_is_integer(p_confirm)) {
                confirmation = (int64_t)json_integer_value(p_confirm);
            }
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: getrawtransaction_rpc\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return (uint32_t)confirmation;
}


bool btcrpc_get_short_channel_param(int *pBHeight, int *pBIndex, const uint8_t *pTxid)
{
    bool retval;
    char *p_json = NULL;
    char txid[UCOIN_SZ_TXID * 2 + 1];
    char blockhash[UCOIN_SZ_SHA256 * 2 + 1] = "NG";

    *pBHeight = -1;
    *pBIndex = -1;

    //TXIDはBE/LE変換
    ucoin_util_bin2str_rev(txid, pTxid, UCOIN_SZ_TXID);

    retval = getrawtransaction_rpc(&p_json, txid, true);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_bhash;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result) {
            p_bhash = json_object_get(p_result, M_BLOCKHASH);
            if (json_is_string(p_bhash)) {
                strcpy(blockhash, (const char *)json_string_value(p_bhash));
            }
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: getrawtransaction_rpc\n");
        goto LABEL_EXIT;
    }
    APP_FREE(p_json);

    retval = getblock_rpc(&p_json, blockhash);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_height;
        json_t *p_tx;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result) {
            p_height = json_object_get(p_result, M_HEIGHT);
            if (json_is_integer(p_height)) {
                *pBHeight = (int)json_integer_value(p_height);
            }
            p_tx = json_object_get(p_result, M_TX);
            size_t index = 0;
            json_t *p_value = NULL;
            json_array_foreach(p_tx, index, p_value) {
                if (strcmp(txid, (const char *)json_string_value(p_value)) == 0) {
                    *pBIndex = (int)index;
                    break;
                }
            }
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: getblock_rpc\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    if ((*pBIndex == -1) || (*pBHeight == -1)) {
        retval = false;
    }

    return retval;
}


bool btcrpc_is_short_channel_unspent(int BHeight, int BIndex, int VIndex)
{
    bool ret = true;        //エラーでもunspentにしておく
    bool retval;
    char *p_json = NULL;
    char txid[UCOIN_SZ_TXID * 2 + 1] = "";
    char blockhash[UCOIN_SZ_SHA256 * 2 + 1] = "NG";

    //ブロック高→ブロックハッシュ
    retval = getblockhash_rpc(&p_json, BHeight);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result) {
            if (json_is_string(p_result)) {
                strcpy(blockhash, (const char *)json_string_value(p_result));
            }
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: getblockhash_rpc\n");
        goto LABEL_EXIT;
    }
    APP_FREE(p_json);

    //ブロックハッシュ→TXID
    retval = getblock_rpc(&p_json, blockhash);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_height;
        json_t *p_tx;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF2;
        }
        p_height = json_object_get(p_result, M_HEIGHT);
        if ( !p_height || !json_is_integer(p_height) ||
             ((int)json_integer_value(p_height) != BHeight) ) {
            LOGD("error: M_HEIGHT\n");
            goto LABEL_DECREF2;
        }
        p_tx = json_object_get(p_result, M_TX);
        if (!p_tx) {
            LOGD("error: M_TX\n");
            goto LABEL_DECREF2;
        }

        size_t index = 0;
        json_t *p_value = NULL;
        json_array_foreach(p_tx, index, p_value) {
            if ((int)index == BIndex) {
                strcpy(txid, (const char *)json_string_value(p_value));
                break;
            }
        }
LABEL_DECREF2:
        json_decref(p_root);
    } else {
        LOGD("fail: getblock_rpc\n");
        goto LABEL_EXIT;
    }
    APP_FREE(p_json);

    //TXID→spent/unspent
    retval = gettxout_rpc(&p_json, txid, VIndex);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }
        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result) {
            ret = !json_is_null(p_result);
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: gettxout_rpc\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


bool btcrpc_search_txid_block(ucoin_tx_t *pTx, int BHeight, const uint8_t *pTxid, uint32_t VIndex)
{
    bool ret = false;
    bool retval;
    char *p_json = NULL;
    char txid[UCOIN_SZ_TXID * 2 + 1] = "";
    char blockhash[UCOIN_SZ_SHA256 * 2 + 1] = "NG";

    //ブロック高→ブロックハッシュ
    retval = getblockhash_rpc(&p_json, BHeight);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (p_result && json_is_string(p_result)) {
            strcpy(blockhash, (const char *)json_string_value(p_result));
        } else {
            LOGD("error: M_RESULT\n");
        }
        json_decref(p_root);
    } else {
        LOGD("fail: getblockhash_rpc\n");
        goto LABEL_EXIT;
    }
    APP_FREE(p_json);

    //ブロックハッシュ→TXIDs
    retval = getblock_rpc(&p_json, blockhash);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_height;
        json_t *p_tx;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF2;
        }
        p_height = json_object_get(p_result, M_HEIGHT);
        if ( !p_height || !json_is_integer(p_height) ||
             ((int)json_integer_value(p_height) != BHeight) ) {
            LOGD("error: M_HEIGHT\n");
            goto LABEL_DECREF2;
        }
        p_tx = json_object_get(p_result, M_TX);
        if (!p_tx) {
            LOGD("error: M_TX\n");
            goto LABEL_DECREF2;
        }

        //検索
        size_t index = 0;
        json_t *p_value = NULL;
        json_array_foreach(p_tx, index, p_value) {
            strcpy(txid, (const char *)json_string_value(p_value));
            ucoin_tx_t tx = UCOIN_TX_INIT;

            bool bret = getraw_txstr(&tx, txid);
            //LOGD("txid=%s\n", txid);
            if ( bret &&
                 (tx.vin_cnt == 1) &&
                 (memcmp(tx.vin[0].txid, pTxid, UCOIN_SZ_TXID) == 0) &&
                 (tx.vin[0].index == VIndex) ) {
                //一致
                memcpy(pTx, &tx, sizeof(ucoin_tx_t));
                ucoin_tx_init(&tx);     //freeさせない
                ret = true;
                break;
            }
            ucoin_tx_free(&tx);
        }
LABEL_DECREF2:
        json_decref(p_root);
    } else {
        LOGD("fail: getblock_rpc\n");
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


bool btcrpc_search_vout_block(ucoin_buf_t *pTxBuf, int BHeight, const ucoin_buf_t *pVout)
{
    bool ret = false;
    bool retval;
    char *p_json = NULL;
    char txid[UCOIN_SZ_TXID * 2 + 1] = "";
    char blockhash[UCOIN_SZ_SHA256 * 2 + 1] = "NG";

    //ブロック高→ブロックハッシュ
    retval = getblockhash_rpc(&p_json, BHeight);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF;
        }
        if (json_is_string(p_result)) {
            strcpy(blockhash, (const char *)json_string_value(p_result));
        }
LABEL_DECREF:
        json_decref(p_root);
    } else {
        LOGD("fail: getblockhash_rpc\n");
        goto LABEL_EXIT;
    }
    APP_FREE(p_json);

    //ブロックハッシュ→TXIDs
    retval = getblock_rpc(&p_json, blockhash);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_height;
        json_t *p_tx;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF2;
        }
        p_height = json_object_get(p_result, M_HEIGHT);
        if (json_is_integer(p_height)) {
            if ((int)json_integer_value(p_height) != BHeight) {
                LOGD("error: M_HEIGHT\n");
                goto LABEL_DECREF2;
            }
        }
        //検索
        p_tx = json_object_get(p_result, M_TX);
        ucoin_push_t push;
        ucoin_push_init(&push, pTxBuf, 0);
        size_t index = 0;
        json_t *p_value = NULL;
        json_array_foreach(p_tx, index, p_value) {
            strcpy(txid, (const char *)json_string_value(p_value));
            ucoin_tx_t tx = UCOIN_TX_INIT;

            bool bret = getraw_txstr(&tx, txid);
            if (!bret) {
                int cnt = pTxBuf->len / sizeof(ucoin_tx_t);
                ucoin_tx_t *p_tx = (ucoin_tx_t *)pTxBuf->buf;
                for (int lp = 0; lp < cnt; lp++) {
                    ucoin_tx_free(&p_tx[lp]);
                }
                ucoin_buf_free(pTxBuf);
                ucoin_tx_free(&tx);
                ret = false;
                break;
            }
            for (uint32_t lp = 0; lp < tx.vout_cnt; lp++) {
                if (ucoin_buf_cmp(&tx.vout[0].script, pVout)) {
                    //一致
                    LOGD("match: %s\n", txid);
                    ucoin_push_data(&push, &tx, sizeof(ucoin_tx_t));
                    LOGD("len=%u\n", pTxBuf->len);
                    ucoin_tx_init(&tx);     //freeさせない
                    ret = true;
                    break;
                }
            }
            ucoin_tx_free(&tx);
        }
LABEL_DECREF2:
        json_decref(p_root);
    } else {
        LOGD("fail: getblock_rpc\n");
        goto LABEL_EXIT;
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


bool btcrpc_signraw_tx(ucoin_tx_t *pTx, const uint8_t *pData, size_t Len)
{
    bool ret = false;
    bool retval;
    char *p_json = NULL;
    char *transaction;

    transaction = (char *)APP_MALLOC(Len * 2 + 1);
    ucoin_util_bin2str(transaction, pData, Len);

    retval = signrawtransaction_rpc(&p_json, transaction);
LOGD("%s\n", p_json);
    APP_FREE(transaction);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_hex;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF;
        }
        p_hex = json_object_get(p_result, M_HEX);
        if (json_is_string(p_hex)) {
            const char *p_sigtx = (const char *)json_string_value(p_hex);
            size_t len = strlen(p_sigtx) / 2;
            uint8_t *p_buf = APP_MALLOC(len);
            misc_str2bin(p_buf, len, p_sigtx);
            ucoin_tx_free(pTx);
            ret = ucoin_tx_read(pTx, p_buf, len);
            APP_FREE(p_buf);
        } else {
            int code = error_result(p_root);
            LOGD("err code=%d\n", code);
        }
LABEL_DECREF:
        json_decref(p_root);
    } else {
        LOGD("fail: signrawtransaction_rpc()\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


bool btcrpc_sendraw_tx(uint8_t *pTxid, int *pCode, const uint8_t *pData, uint32_t Len)
{
    bool ret = false;
    bool retval;
    char *p_json = NULL;
    char *transaction;

    transaction = (char *)APP_MALLOC(Len * 2 + 1);
    ucoin_util_bin2str(transaction, pData, Len);

    retval = sendrawtransaction_rpc(&p_json, transaction);
    APP_FREE(transaction);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF;
        }
        if (json_is_string(p_result)) {
            //TXIDはLE/BE変換
            misc_str2bin_rev(pTxid, UCOIN_SZ_TXID, (const char *)json_string_value(p_result));
            ret = true;
        } else {
            int code = error_result(p_root);
            if (pCode) {
                *pCode = code;
            }
        }
LABEL_DECREF:
        json_decref(p_root);
    } else {
        LOGD("fail: sendrawtransaction_rpc()\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


bool btcrpc_getraw_tx(ucoin_tx_t *pTx, const uint8_t *pTxid)
{
    char txid[UCOIN_SZ_TXID * 2 + 1];

    //TXIDはBE/LE変換
    ucoin_util_bin2str_rev(txid, pTxid, UCOIN_SZ_TXID);

    return btcrpc_getraw_txstr(pTx, txid);
}


bool btcrpc_getraw_txstr(ucoin_tx_t *pTx, const char *txid)
{
    bool ret;

    ret = getraw_txstr(pTx, txid);

    return ret;
}


bool btcrpc_getxout(bool *pUnspent, uint64_t *pSat, const uint8_t *pTxid, int Txidx)
{
    bool retval;
    char *p_json = NULL;
    char txid[UCOIN_SZ_TXID * 2 + 1];
    *pUnspent = false;

    //TXIDはBE/LE変換
    ucoin_util_bin2str_rev(txid, pTxid, UCOIN_SZ_TXID);

    //まずtxの存在確認を行う
    retval = getraw_txstr(NULL, txid);
    if (!retval) {
        //LOGD("fail: maybe not broadcasted\n");
        goto LABEL_EXIT;
    }

    retval = gettxout_rpc(&p_json, txid, Txidx);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_value;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }
        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF;
        }
        p_value = json_object_get(p_result, M_VALUE);
        if (json_is_real(p_value)) {
            double dval = json_real_value(p_value);
            *pSat = UCOIN_BTC2SATOSHI(dval);
            *pUnspent = true;
        }
LABEL_DECREF:
        json_decref(p_root);
    } else {
        LOGD("fail: gettxout_rpc()\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return retval;
}


bool btcrpc_getnewaddress(char *pAddr)
{
    bool ret = false;
    bool retval;
    char *p_json = NULL;

    retval = getnewaddress_rpc(&p_json);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF;
        }
        if (json_is_string(p_result)) {
            strcpy(pAddr,  (const char *)json_string_value(p_result));
            ret = true;
        }
LABEL_DECREF:
        json_decref(p_root);
    } else {
        LOGD("fail: getnewaddress_rpc()\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


// bool btcrpc_dumpprivkey(char *pWif, const char *pAddr)
// {
//     bool ret = false;
//     bool retval;
//     char *p_json = NULL;

//     retval = dumpprivkey_rpc(&p_json, pAddr);
//     if (retval) {
//         json_t *p_root;
//         json_t *p_result;
//         json_error_t error;

//         p_root = json_loads(p_json, 0, &error);
//         if (!p_root) {
//             LOGD("error: on line %d: %s\n", error.line, error.text);
//             goto LABEL_EXIT;
//         }

//         //これ以降は終了時に json_decref()で参照を減らすこと
//         p_result = json_object_get(p_root, M_RESULT);
//         if (!p_result) {
//             LOGD("error: M_RESULT\n");
//             goto LABEL_DECREF;
//         }
//         if (json_is_string(p_result)) {
//             strcpy(pWif,  (const char *)json_string_value(p_result));
//             ret = true;
//         }
// LABEL_DECREF:
//         json_decref(p_root);
//     } else {
//         LOGD("fail: dumpprivkey_rpc()\n");
//     }

// LABEL_EXIT:
//     APP_FREE(p_json);

//     return ret;
// }


bool btcrpc_estimatefee(uint64_t *pFeeSatoshi, int nBlocks)
{
    bool ret = false;
    bool retval;
    char *p_json = NULL;

    if (nBlocks < 2) {
        LOGD("fail: nBlock < 2\n");
        return false;
    }

    retval = estimatefee_rpc(&p_json, nBlocks);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        json_t *p_feerate;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            LOGD("error: on line %d: %s\n", error.line, error.text);
            goto LABEL_EXIT;
        }

        //これ以降は終了時に json_decref()で参照を減らすこと
        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF;
        }
        p_feerate = json_object_get(p_result, M_FEERATE);
        if (p_feerate && json_is_real(p_feerate)) {
            *pFeeSatoshi = UCOIN_BTC2SATOSHI(json_real_value(p_feerate));
            //-1のときは失敗と見なす
            ret = (*pFeeSatoshi + 1.0) > DBL_EPSILON;
            if (!ret) {
                LOGD("fail: Unable to estimate fee\n");
            }
        } else {
            LOGD("fail: not real value\n");
        }
LABEL_DECREF:
        json_decref(p_root);
    } else {
        LOGD("fail: estimatefee_rpc()\n");
    }

LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


/**************************************************************************
 * private functions
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
        *result->pp_data = (char *)APP_REALLOC(*result->pp_data, result->sz);
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
    LOGD2("\n\n@@@[%lu, %lu=%lu]\n%s@@@\n\n", size, nmemb, size * nmemb, result->p_data + pos);
#endif //M_DBG_SHOWREPLY

    return size * nmemb;
}


/** getrawtransaction(TXID文字列)
 *
 * @retval  true    取得成功
 * @retval  false   取得失敗 or bitcoindエラー
 */
static bool getraw_txstr(ucoin_tx_t *pTx, const char *txid)
{
    bool ret = false;
    bool retval;
    char *p_json;

    retval = getrawtransaction_rpc(&p_json, txid, false);
    if (retval) {
        json_t *p_root;
        json_t *p_result;
        uint8_t *p_hex;
        const char *str_hex;
        uint32_t len;
        json_error_t error;

        p_root = json_loads(p_json, 0, &error);
        if (!p_root) {
            goto LABEL_EXIT;
        }
        //これ以降は終了時に json_decref()で参照を減らすこと

        p_result = json_object_get(p_root, M_RESULT);
        if (!p_result) {
            LOGD("error: M_RESULT\n");
            goto LABEL_DECREF;
        }
        str_hex = (const char *)json_string_value(p_result);
        if (!str_hex) {
            //error_result(p_root);
            goto LABEL_DECREF;
        }
        len = strlen(str_hex);
        if (len & 1) {
            LOGD("error: len\n");
            goto LABEL_DECREF;
        }
        if (pTx) {
            len >>= 1;
            p_hex = (uint8_t *)APP_MALLOC(len);
            misc_str2bin(p_hex, len, str_hex);
            ucoin_tx_read(pTx, p_hex, len);
            APP_FREE(p_hex);
        }
        ret = true;
LABEL_DECREF:
        json_decref(p_root);
    }
LABEL_EXIT:
    APP_FREE(p_json);

    return ret;
}


/** [cURL]getrawtransaction
 *
 */
static bool getrawtransaction_rpc(char **ppJson, const char *pTxid, bool detail)
{
    char *data = (char *)APP_MALLOC(BUFFER_SIZE);
    snprintf(data, BUFFER_SIZE,
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "getrawtransaction") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") ", %s]"
        "}", pTxid, (detail) ? "true" : "false");

    bool ret = rpc_proc(ppJson, data);
    APP_FREE(data);

    return ret;
}


/** [cURL]signrawtransaction
 *
 */
static bool signrawtransaction_rpc(char **ppJson, const char *pTransaction)
{
    char *data = (char *)APP_MALLOC(BUFFER_SIZE);
    snprintf(data, BUFFER_SIZE,
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "signrawtransaction") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") "]"
        "}", pTransaction);

    bool ret = rpc_proc(ppJson, data);
    APP_FREE(data);

    return ret;
}


/** [cURL]sendrawtransaction
 *
 */
static bool sendrawtransaction_rpc(char **ppJson, const char *pTransaction)
{
    char *data = (char *)APP_MALLOC(BUFFER_SIZE);
    snprintf(data, BUFFER_SIZE,
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "sendrawtransaction") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") "]"
        "}", pTransaction);

    bool ret = rpc_proc(ppJson, data);
    APP_FREE(data);

    return ret;
}


static bool gettxout_rpc(char **ppJson, const char *pTxid, int idx)
{
    char data[512];
    snprintf(data, sizeof(data),
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "gettxout") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") ",%d]"
        "}", pTxid, idx);

    bool ret = rpc_proc(ppJson, data);

    return ret;
}


static bool getblock_rpc(char **ppJson, const char *pBlock)
{
    char data[512];
    snprintf(data, sizeof(data),
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "getblock") M_NEXT
            M_QQ("params") ":[" M_QQ("%s") "]"
        "}", pBlock);

    bool ret = rpc_proc(ppJson, data);

    return ret;
}


static bool getblockhash_rpc(char **ppJson, int BHeight)
{
    char data[512];
    snprintf(data, sizeof(data),
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "getblockhash") M_NEXT
            M_QQ("params") ":[ %d ]"
        "}", BHeight);

    bool ret = rpc_proc(ppJson, data);

    return ret;
}


/** [cURL]getblockcount
 *
 */
static bool getblockcount_rpc(char **ppJson)
{
    char data[512];
    snprintf(data, sizeof(data),
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "getblockcount") M_NEXT
            M_QQ("params") ":[]"
        "}");

    bool ret = rpc_proc(ppJson, data);

    return ret;
}


/** [cURL]getnewaddress
 *
 */
static bool getnewaddress_rpc(char **ppJson)
{
    char data[512];
    snprintf(data, sizeof(data),
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "getnewaddress") M_NEXT
            M_QQ("params") ":[]"
        "}");

    bool ret = rpc_proc(ppJson, data);

    return ret;
}


/** [cURL]estimatefee
 *
 */
static bool estimatefee_rpc(char **ppJson, int nBlock)
{
    char data[512];
    snprintf(data, sizeof(data),
        "{"
            ///////////////////////////////////////////
            M_1("jsonrpc", "1.0") M_NEXT
            M_1("id", RPCID) M_NEXT

            ///////////////////////////////////////////
            M_1("method", "estimatesmartfee") M_NEXT
            M_QQ("params") ":[%d]"
        "}", nBlock);

    bool ret = rpc_proc(ppJson, data);

    return ret;
}


/** [cURL]dumpprivkey
 *
 */
// static bool dumpprivkey_rpc(char **ppJson, const char *pAddr)
// {
//     char data[512];
//     snprintf(data, sizeof(data),
//         "{"
//             ///////////////////////////////////////////
//             M_1("jsonrpc", "1.0") M_NEXT
//             M_1("id", RPCID) M_NEXT

//             ///////////////////////////////////////////
//             M_1("method", "dumpprivkey") M_NEXT
//             M_QQ("params") ":[" M_QQ("%s") "]"
//         "}", pAddr);

//     bool ret = rpc_proc(ppJson, data);

//     return ret;
// }


/** JSON-RPC処理
 *
 * @retval  true    成功
 */
static bool rpc_proc(char **ppJson, char *pData)
{
#ifdef M_DBG_SHOWRPC
    LOGD("%s\n", pData);
#endif //M_DBG_SHOWRPC

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
    *ppJson = (char *)APP_MALLOC(result.sz);
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

    return retval == CURLE_OK;
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
	gcc -o tst -I.. -I../include -I../libs/install/include -I../ucoin/include -DNETKIND=1 -DJSONRPC_TEST misc.c btcrpc.c -L../libs/install/lib -lcurl -ljansson -L../ucoin -lucoin -L../ucoin/libs/install/lib -lbase58 -lmbedcrypto -lsodium -llmdb -pthread
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
    ucoin_init(UCOIN_MAINNET, true);
#elif NETKIND==1
    ucoin_init(UCOIN_TESTNET, true);
#endif

    rpc_conf_t rpc_conf;

    strcpy(rpc_conf.rpcuser, "bitcoinuser");
    strcpy(rpc_conf.rpcpasswd, "bitcoinpassword");
    strcpy(rpc_conf.rpcurl, "127.0.0.1");
    btcrpc_init(&rpc_conf);

    bool ret;

//    fprintf(PRINTOUT, "-[getblockcount]-------------------------\n");
//    int blocks = getblockcount();
//    fprintf(PRINTOUT, "blocks = %d\n", blocks);

//    fprintf(PRINTOUT, "-[short_channel_info]-------------------------\n");
//    int bindex;
//    int bheight;
//    ret = btcrpc_get_short_channel_param(&bindex, &bheight, TXID);
//    if (ret) {
//        fprintf(PRINTOUT, "index = %d\n", bindex);
//        fprintf(PRINTOUT, "height = %d\n", bheight);
//    }

//    int conf;
//    fprintf(PRINTOUT, "-conf-------------------------\n");
//    conf = btcrpc_get_confirmation(TXID);
//    fprintf(PRINTOUT, "confirmations = %d\n", conf);

//    fprintf(PRINTOUT, "-getnewaddress-------------------------\n");
//    char addr[UCOIN_SZ_ADDR_MAX];
//    ret = btcrpc_getnewaddress(addr);
//    if (ret) {
//        fprintf(PRINTOUT, "addr=%s\n", addr);
//    }

//    fprintf(PRINTOUT, "-dumpprivkey-------------------------\n");
//    char wif[UCOIN_SZ_WIF_MAX];
//    ret = btcrpc_dumpprivkey(wif, addr);
//    if (ret) {
//        fprintf(PRINTOUT, "wif=%s\n", wif);
//    }

    //fprintf(PRINTOUT, "-gettxout-------------------------\n");
    //bool unspent;
    //uint64_t value;
    //ret = btcrpc_getxout(&unspent, &value, TXID, 1);
    //if (ret && unspent) {
    //    fprintf(PRINTOUT, "value=%" PRIu64 "\n", value);
    //}

//    fprintf(PRINTOUT, "-getrawtx------------------------\n");
//    ucoin_tx_t tx = UCOIN_TX_INIT;
//    ret = btcrpc_getraw_tx(&tx, TXID);
//    if (ret) {
//        ucoin_print_tx(&tx);
//    }
//    ucoin_tx_free(&tx);

//    fprintf(PRINTOUT, "--------------------------\n");
//    uint8_t txid[UCOIN_SZ_TXID];
//    bool ret = btcrpc_sendraw_tx(txid, NULL, TX, sizeof(TX));
//    if (ret) {
//        for (int lp = 0; lp < sizeof(txid); lp++) {
//            fprintf(PRINTOUT, "%02x", txid[lp]);
//        }
//        fprintf(PRINTOUT, "\n");
//    }

    // fprintf(PRINTOUT, "--------------------------\n");
    // {
    //     uint32_t bheight;
    //     uint32_t bindex;
    //     uint32_t vindex;
    //     bool unspent;
    //     uint64_t short_channel_id;

    //     short_channel_id = 0x11a7810000440000ULL;
    //     ln_get_short_channel_id_param(&bheight, &bindex, &vindex, short_channel_id);
    //     unspent = btcrpc_is_short_channel_unspent(bheight, bindex, vindex);
    //     fprintf(PRINTOUT, "%016" PRIx64 " = %d\n", short_channel_id, unspent);

    //     short_channel_id = 0x11a2eb0000210000ULL;
    //     ln_get_short_channel_id_param(&bheight, &bindex, &vindex, short_channel_id);
    //     unspent = btcrpc_is_short_channel_unspent(bheight, bindex, vindex);
    //     fprintf(PRINTOUT, "%016" PRIx64 " = %d\n", short_channel_id, unspent);
    // }

    fprintf(PRINTOUT, "--------------------------\n");
    {
        uint64_t feeperrate;
        bool ret = btcrpc_estimatefee(&feeperrate, 3);
        if (ret) {
            printf("feeperate=%"PRIu64"\n", feeperrate);
        } else {
            printf("feeperate=failure\n");
        }
    }

    fprintf(PRINTOUT, "--------------------------\n");

    btcrpc_term();
    ucoin_term();
}
#endif
