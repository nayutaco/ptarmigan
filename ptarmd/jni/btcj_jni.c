#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include <jni.h>
#include "btcj_jni.h"

#define LOG_TAG     "btcj_jni"
#include "utl_log.h"
#include "utl_time.h"

#include "btc_sw.h"

#include "ptarmd.h"


#define M_CHECKUNSPENT_FAIL             (-1)
#define M_CHECKUNSPENT_UNSPENT          (0)
#define M_CHECKUNSPENT_SPENT            (1)


#define check_exception(env)    { _check_exception(env, __func__, __LINE__); }


enum {
    M_FIELD_PTARMCHAN_HEIGHT,
    M_FIELD_PTARMCHAN_BINDEX,
    M_FIELD_PTARMCHAN_MINEDHASH,
    //
    M_FIELD_PTARMCHAN_MAX,
};


enum {
    M_FIELD_SEARCHOUTPOINT_HEIGHT,
    M_FIELD_SEARCHOUTPOINT_TX,
    //
    M_FIELD_SEARCHOUTPOINT_MAX
};


static JNIEnv *env;
static JavaVM *jvm;

//GlobalRef
static jclass hash_cls;
static jclass arraylist_cls;
static jclass system_cls;
static jobject ptarm_obj;

static jmethodID ptarm_method[METHOD_PTARM_MAX];
static jmethodID arraylist_ctor_method;
static jmethodID arraylist_add_method;
static jmethodID list_get_method;
static jmethodID list_size_method;
static jmethodID system_exit_method;
static jfieldID ptarmcls_field[M_FIELD_PTARMCHAN_MAX];
static jfieldID searchoutpoint_field[M_FIELD_SEARCHOUTPOINT_MAX];

static bool mExceptionHappen;

static jbyteArray buf2jbarray(const btcj_buf_t *buf);
static btcj_buf_t* jbarray2buf(jbyteArray jbarray);
static jobject bufs2list(const btcj_buf_t *bufs);
static btcj_buf_t* list2bufs(jobject list);
static inline void _check_exception(JNIEnv *env, const char *pFuncName, int Line);


const struct {
    const char *name;
    const char *sig;
} kMethod[METHOD_PTARM_MAX] = {
    // METHOD_PTARM_SPV_START,
    { "spv_start", "(Ljava/lang/String;)I" },
    // METHOD_PTARM_SETCREATIONHASH,
    { "setCreationHash", "([B)V" },
    // METHOD_PTARM_GETBLOCKCOUNT,
    { "getBlockCount", "([B)I" },
    // METHOD_PTARM_GETGENESISBLOCKHASH,
    { "getGenesisBlockHash", "()[B" },
    // METHOD_PTARM_GETCONFIRMATION,
    { "getTxConfirmation", "([BI[BJ)I" },
    // METHOD_PTARM_GETSHORTCHANNELPARAM,
    { "getShortChannelParam", "([B)Lco/nayuta/lightning/ShortChannelParam;" },
    // // METHOD_PTARM_GETTXIDFROMSHORTCHANNELID,
    // { "getTxidFromShortChannelId", "(J)[B" },
    // METHOD_PTARM_SEARCHOUTPOINT,
    { "searchOutPoint", "(I[BI)Lco/nayuta/lightning/SearchOutPointResult;" },
    // METHOD_PTARM_SEARCHVOUT,
    { "searchVout", "(ILjava/util/List;)Ljava/util/List;" },
    // METHOD_PTARM_SIGNRAWTX,
    { "signRawTx", "(J[B)[B" },
    // METHOD_PTARM_SENDRAWTX,
    { "sendRawTx", "([B)[B" },
    // METHOD_PTARM_CHECKBROADCAST,
    { "checkBroadcast", "([B[B)Z" },
    // METHOD_PTARM_CHECKUNSPENT,
    { "checkUnspent", "([B[BI)I" },
    // METHOD_PTARM_GETNEWADDRESS,
    { "getNewAddress", "()Ljava/lang/String;" },
    // METHOD_PTARM_ESTIMATEFEE,
    { "estimateFee", "()J" },
    // METHOD_PTARM_SETCHANNEL,
    { "setChannel", "([BJ[BI[B[BI)Z" },
    // METHOD_PTARM_DELCHANNEL,
    { "delChannel", "([B)V" },
    // // METHOD_PTARM_SETCOMMITTXID,
    // { "setCommitTxid", "([BIILorg/bitcoinj/core/Sha256Hash;)V" },
    // METHOD_PTARM_GETBALANCE,
    { "getBalance", "()J" },
    // METHOD_PTARM_EMPTYWALLET,
    { "emptyWallet", "(Ljava/lang/String;)[B" },
    // METHOD_PARAM_EXIT
    { NULL, NULL },
    // METHOD_PTARM_REMOVESUSPENDBLOCK
    { "removeSuspendBlock", "()V" },
};


const struct {
    const char *name;
    const char *sig;
} kField[M_FIELD_PTARMCHAN_MAX] = {
    // M_FIELD_PTARMCHAN_HEIGHT,
    { "height", "I" },
    // M_FIELD_PTARMCHAN_BINDEX,
    { "bIndex", "I" },
    // M_FIELD_PTARMCHAN_MINEDHASH,
    { "minedHash", "[B" },
}, kFieldSearchOutpoint[M_FIELD_SEARCHOUTPOINT_MAX] = {
    // M_FIELD_SEARCHOUTPOINT_HEIGHT,
    { "height", "I" },
    // M_FIELD_SEARCHOUTPOINT_TX,
    { "tx", "[B" },
};


//-----------------------------------------------------------------------------
bool btcj_init(btc_block_chain_t Gen)
{
    mExceptionHappen = false;
    jclass cls;
    char optjar[PATH_MAX];
    snprintf(optjar, sizeof(optjar),
             "-Djava.class.path=%s/jar/bitcoinj-ptarmigan.jar",
             ptarmd_execpath_get());
    LOGD("optjar=%s\n", optjar);

    JavaVMOption opt[9];
    // .classファイルを配置するディレクトリか、.jarファイルのパスを指定する
    opt[0].optionString = optjar;
    // https://stackoverflow.com/questions/14544991/how-to-configure-slf4j-simple
    opt[1].optionString = "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn";
    opt[2].optionString = "-Dorg.slf4j.simpleLogger.log.co.nayuta.lightning=debug";
    opt[3].optionString = "-Dorg.slf4j.simpleLogger.showDateTime=true";
    opt[4].optionString = "-Dorg.slf4j.simpleLogger.dateTimeFormat=yyyy-MM-dd'T'HH:mm:ssZ";
    opt[5].optionString = "-DsimpleLogger.showThreadName=false";
    opt[6].optionString = "-DsimpleLogger.showLogName=false";
    opt[7].optionString = "-Dorg.slf4j.simpleLogger.showShortLogName=true";
    opt[8].optionString = "-Dorg.slf4j.simpleLogger.logFile=System.out";
    //
    JavaVMInitArgs vm_args = {
        .version = JNI_VERSION_1_8,
        .options = opt,
        .nOptions = ARRAY_SIZE(opt)
    };
    // JVM初期化
    LOGD("JNI_CreateJavaVM\n");
    int ret = JNI_CreateJavaVM(&jvm, (void**)&env, (void*)&vm_args);
    if (ret != JNI_OK) {
        // jvm.dllへのパスが通っていない場合など
        LOGD("btcj_init() Error: JNI_CreateJavaVM() = %d\n", ret);
        return false;
    }

    //
    system_cls = (*env)->FindClass(env, "java/lang/System");
    if (system_cls == NULL) {
        LOGE("fail: FindClass()\n");
        return false;
    }
    system_exit_method = (*env)->GetStaticMethodID(env, system_cls, "exit", "(I)V");
    if (system_exit_method == NULL) {
        LOGE("fail: GetMethodID()\n");
        return false;
    }

    LOGD("Class: Ptarmigan\n");

    // クラス検索
    cls = (*env)->FindClass(env, "co/nayuta/lightning/Ptarmigan");
    if (cls == NULL) {
        LOGE("fail: FindClass()\n");
        return false;
    }

    // コンストラクタ呼び出し
    LOGD("call ctor\n");
    jmethodID method = (*env)->GetMethodID(env, cls, "<init>", "()V");
    if ((*env)->ExceptionCheck(env) || (method == NULL)) {
        LOGE("fail: ctor\n");
        return false;
    }
    jobject obj = (*env)->NewObject(env, cls, method);
    if (obj == NULL) {
        LOGE("fail: NewObject\n");
        return false;
    }
    ptarm_obj = (jobject)(*env)->NewGlobalRef(env, obj);
    (*env)->DeleteLocalRef(env, obj);
    //
    LOGD("get methods\n");
    for (size_t lp = 0; lp < ARRAY_SIZE(kMethod); lp++) {
        if (kMethod[lp].name != NULL) {
            ptarm_method[lp] = (*env)->GetMethodID(
                                   env, cls,
                                   kMethod[lp].name,
                                   kMethod[lp].sig);
            if (ptarm_method[lp] == NULL) {
                LOGE("fail: get method id(%s)\n", kMethod[lp].name);
                return false;
            }
        }
    }

    LOGD("Class: ShortChannelParam\n");
    cls = (*env)->FindClass(env, "co/nayuta/lightning/ShortChannelParam");
    if (cls == NULL) {
        LOGE("fail: FindClass()\n");
        return false;
    }
    //field
    //  btcj_get_short_channel_param
    LOGD("get fields\n");
    for (size_t lp = 0; lp < ARRAY_SIZE(kField); lp++) {
        ptarmcls_field[lp] = (*env)->GetFieldID(
                                 env, cls,
                                 kField[lp].name,
                                 kField[lp].sig);
        if (ptarmcls_field[lp] == NULL) {
            LOGE("fail: get field id(%s)\n", kField[lp].name);
            return false;
        }
    }

    LOGD("Class: SearchOutPointResult\n");
    cls = (*env)->FindClass(env, "co/nayuta/lightning/SearchOutPointResult");
    if (cls == NULL) {
        LOGE("fail: FindClass()\n");
        return false;
    }
    LOGD("get fields\n");
    for (size_t lp = 0; lp < ARRAY_SIZE(kFieldSearchOutpoint); lp++) {
        searchoutpoint_field[lp] = (*env)->GetFieldID(
                                       env, cls,
                                       kFieldSearchOutpoint[lp].name,
                                       kFieldSearchOutpoint[lp].sig);
        if (searchoutpoint_field[lp] == NULL) {
            LOGE("fail: get field id(%s)\n", kFieldSearchOutpoint[lp].name);
            return false;
        }
    }

    //ArrayList
    cls = (*env)->FindClass(env, "Ljava/util/ArrayList;");
    if (cls == NULL) {
        LOGE("fail: FindClass()\n");
        return false;
    }
    arraylist_cls = (jclass)(*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    arraylist_ctor_method = (*env)->GetMethodID(env, arraylist_cls, "<init>", "()V");
    if (arraylist_ctor_method == NULL) {
        LOGE("fail: GetMethodID()\n");
        return false;
    }
    arraylist_add_method = (*env)->GetMethodID(env, arraylist_cls, "add", "(Ljava/lang/Object;)Z");
    if (arraylist_add_method == NULL) {
        LOGE("fail: GetMethodID()\n");
        return false;
    }

    //List
    cls = (*env)->FindClass(env, "Ljava/util/List;");
    if (cls == NULL) {
        LOGE("fail: FindClass()\n");
        return false;
    }
    list_get_method = (*env)->GetMethodID(env, cls, "get", "(I)Ljava/lang/Object;");
    if (list_get_method == NULL) {
        LOGE("fail: GetMethodID()\n");
        return false;
    }
    list_size_method = (*env)->GetMethodID(env, cls, "size", "()I");
    if (list_size_method == NULL) {
        LOGE("fail: GetMethodID()\n");
        return false;
    }

    //
    (*env)->DeleteLocalRef(env, cls);

    LOGD("SPV start\n");
    ret = btcj_spv_start(Gen);
    switch (ret) {
    case BTCJ_INI_SPV_START_OK:
        LOGD("OK!\n");
        break;
    case BTCJ_INI_SPV_START_FILE:
        fprintf(stderr, "SPV file already locked.\n");
        fprintf(stderr, "Maybe, another ptarmd is started or file unlock processing.\n");
        fprintf(stderr, "If no other ptarmd, please wait a while and start.\n");
        LOGE("fail: wallet file already locked\n");
        break;
    case BTCJ_INI_SPV_START_BJ:
        fprintf(stderr, "Failed to start SPV.\n");
        fprintf(stderr, "Please wait a while and start.\n");
        LOGE("fail: bitcoinj cannot start\n");
        break;
    case BTCJ_INI_SPV_START_ERR:
    default:
        fprintf(stderr, "Sorry, failed to start SPV.\n");
        LOGE("fail: SPV\n");
        btcj_release();
    }

    LOGD("END: %d\n", ret);
    return (ret == BTCJ_INI_SPV_START_OK);
}
//-----------------------------------------------------------------------------
bool btcj_release(void)
{
    if (env != NULL) {
        (*env)->DeleteGlobalRef(env, ptarm_obj);
        (*env)->DeleteGlobalRef(env, arraylist_cls);
        (*env)->DeleteGlobalRef(env, hash_cls);

        //待ち状態になるためコメントアウト
        // if(jvm != NULL) {
        //     (*jvm)->DestroyJavaVM(jvm);
        //     jvm = NULL;
        // }
        env = NULL;
    }
    //
    return true;
}
//-----------------------------------------------------------------------------
bool btcj_exception_happen(void)
{
    return mExceptionHappen;
}
//-----------------------------------------------------------------------------
int btcj_spv_start(btc_block_chain_t Gen)
{
    LOGD("\n");
    const char *p_chain_name;
    const btc_block_param_t *p_chain = btc_block_get_param_from_chain(Gen);
    if (p_chain != NULL) {
        p_chain_name = btc_block_get_real_chainname(p_chain->chain_name);
    } else {
        LOGE("fail: unknown genesis block hash\n");
        assert(0);
        return false;
    }
    jstring param = (*env)->NewStringUTF(env, p_chain_name);
    jint ret = (*env)->CallIntMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SPV_START], param);
    check_exception(env);
    LOGD("ret=%d\n", ret);
    (*env)->DeleteLocalRef(env, param);
    //
    return ret;
}
//-----------------------------------------------------------------------------
void btcj_setcreationhash(const uint8_t *pHash)
{
    LOGD("\n");
    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pHash, BTC_SZ_HASH256 };
    jbyteArray array = buf2jbarray(&buf);
    (*env)->CallVoidMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SETCREATIONHASH], array);
    check_exception(env);
    //
    (*env)->DeleteLocalRef(env, array);
}
//-----------------------------------------------------------------------------
int32_t btcj_getblockcount(uint8_t *pHash)
{
    jbyteArray array;
    if (pHash != NULL) {
        array = (*env)->NewByteArray(env, BTC_SZ_HASH256);
    } else {
        array = NULL;
    }
    jint ret = (*env)->CallIntMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETBLOCKCOUNT], array);
    check_exception(env);
    if (pHash != NULL) {
        (*env)->GetByteArrayRegion(env, array, 0, BTC_SZ_HASH256, (jbyte *)pHash);
        (*env)->DeleteLocalRef(env, array);
    }
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_getgenesisblockhash(uint8_t *pHash)
{
    jbyteArray hash_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETGENESISBLOCKHASH]);
    check_exception(env);
    btcj_buf_t *bytes = jbarray2buf(hash_obj);
    memcpy(pHash, bytes->buf, bytes->len);
    //
    (*env)->DeleteLocalRef(env, hash_obj);
    UTL_DBG_FREE(bytes->buf);
    //
    return true;
}
//-----------------------------------------------------------------------------
uint32_t btcj_gettxconfirm(const uint8_t *pTxid, int voutIndex, const uint8_t *pVoutWitProg, uint64_t amount)
{
    LOGD("txid=");
    TXIDD(pTxid);

    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pTxid, BTC_SZ_TXID };
    jobject txHash = buf2jbarray(&buf);
    const btcj_buf_t buf_wit = { (CONST_CAST uint8_t *)pVoutWitProg, BTC_SZ_WITPROG_P2WSH };
    jobject witProg = buf2jbarray(&buf_wit);
    jint ret = (*env)->CallIntMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETCONFIRMATION],
                                     txHash, voutIndex, witProg, amount);
    check_exception(env);
    LOGD("ret=%" PRIu32 "\n", ret);
    //
    (*env)->DeleteLocalRef(env, witProg);
    (*env)->DeleteLocalRef(env, txHash);
    //
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_get_short_channel_param(const uint8_t *pPeerId, int32_t *pHeight, int32_t *pbIndex, uint8_t *pMinedHash)
{
    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
    jbyteArray barray = buf2jbarray(&buf);
    jobject param_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETSHORTCHANNELPARAM], barray);
    check_exception(env);
    //
    if (param_obj != NULL) {
        *pHeight = (*env)->GetIntField(env, param_obj, ptarmcls_field[M_FIELD_PTARMCHAN_HEIGHT]);
        *pbIndex = (*env)->GetIntField(env, param_obj, ptarmcls_field[M_FIELD_PTARMCHAN_BINDEX]);
        jbyteArray hash_obj = (*env)->GetObjectField(env, param_obj, ptarmcls_field[M_FIELD_PTARMCHAN_MINEDHASH]);
        if (hash_obj != NULL) {
            btcj_buf_t *bytes = jbarray2buf(hash_obj);
            memcpy(pMinedHash, bytes->buf, bytes->len);
            UTL_DBG_FREE(bytes->buf);
            LOGD("minedHash: ");
            TXIDD(pMinedHash);
        } else {
            LOGE("fail: blockHash field\n");
        }

        if (hash_obj != NULL) {
            (*env)->DeleteLocalRef(env, hash_obj);
        }
        (*env)->DeleteLocalRef(env, param_obj);
    }
    return param_obj != NULL;
}
//-----------------------------------------------------------------------------
// bool btcj_gettxid_from_short_channel(uint64_t ShortChannelId, uint8_t **ppTxid)
// {
//     jbyteArray hash_obj = (*env)->CallObjectMethod(
//                              env, ptarm_obj,
//                              ptarm_method[METHOD_PTARM_GETTXIDFROMSHORTCHANNELID],
//                              ShortChannelId);
//     check_exception(env);
//     if (hash_obj != NULL) {
//         btcj_buf_t *p_hash = jbarray2buf(hash_obj);
//         *ppTxid = p_hash->buf;
//         LOGD("success\n");
//     } else {
//         LOGE("fail: txid\n");
//     }
//     return hash_obj != NULL;
// }
//-----------------------------------------------------------------------------
bool btcj_search_outpoint(btcj_buf_t **ppTx, uint32_t *pMined, uint32_t Blks, const uint8_t *pTxid, uint32_t VIndex)
{
    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pTxid, BTC_SZ_TXID };
    jobject txHash = buf2jbarray(&buf);
    jobject param_obj = (*env)->CallObjectMethod(
                          env, ptarm_obj,
                          ptarm_method[METHOD_PTARM_SEARCHOUTPOINT],
                          Blks, txHash, VIndex);
    check_exception(env);
    //
    bool ret = false;
    if (param_obj != NULL) {
        *pMined = (*env)->GetIntField(
                      env, param_obj,
                      searchoutpoint_field[M_FIELD_SEARCHOUTPOINT_HEIGHT]);
        jbyteArray hash_obj = (*env)->GetObjectField(
                                  env, param_obj,
                                  searchoutpoint_field[M_FIELD_SEARCHOUTPOINT_TX]);
        if (hash_obj != NULL) {
            *ppTx = jbarray2buf(hash_obj);
            ret = true;
            (*env)->DeleteLocalRef(env, hash_obj);
            LOGD("success\n");
        } else {
            LOGE("fail\n");
        }
    } else {
        LOGE("fail\n");
    }
    //
    (*env)->DeleteLocalRef(env, txHash);
    //
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_search_vout(btcj_buf_t **ppTxBuf, uint32_t Blks, const btcj_buf_t *pVout)
{
    LOGD("ppTxBuf=%p, Blks=%d, pVout=%p\n", ppTxBuf, (int)Blks, pVout);

    jobject vout = bufs2list(pVout);
    LOGD(" vout=%p\n", vout);
    jobject list = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SEARCHVOUT], Blks, vout);
    check_exception(env);
    LOGD(" list=%p\n", list);
    if (ppTxBuf != NULL) {
        *ppTxBuf = list2bufs(list);
        LOGD("success\n");
    } else {
        LOGE("fail\n");
    }
    //
    (*env)->DeleteLocalRef(env, vout);
    (*env)->DeleteLocalRef(env, list);
    //
    return true;
}
//-----------------------------------------------------------------------------
bool btcj_signraw_tx(uint64_t Amount, const btcj_buf_t *pScriptPubKey, btcj_buf_t **ppTxData)
{
    LOGD("amount=%" PRIu64 ", scriptPubKey=", Amount);
    DUMPD(pScriptPubKey->buf, pScriptPubKey->len);

    jbyteArray pubKey = buf2jbarray(pScriptPubKey);
    jbyteArray ret = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SIGNRAWTX], (jlong)Amount, pubKey);
    check_exception(env);
    if (ret != NULL) {
        *ppTxData = jbarray2buf(ret);
        LOGD("success\n");
    } else {
        LOGE("fail\n");
    }
    //
    (*env)->DeleteLocalRef(env, pubKey);
    (*env)->DeleteLocalRef(env, ret);
    //
    return ret != NULL;
}
//-----------------------------------------------------------------------------
bool btcj_sendraw_tx(uint8_t *pTxid, int *pCode, const btcj_buf_t *pTxData)
{
    (void)pCode;

    LOGD("rawtx=");
    DUMPD(pTxData->buf, pTxData->len);
    bool ret;
    jbyteArray array = buf2jbarray(pTxData);
    jbyteArray hash_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SENDRAWTX], array);
    check_exception(env);
    if (hash_obj != NULL) {
        btcj_buf_t *hash = jbarray2buf(hash_obj);
        memcpy(pTxid, hash->buf, hash->len);
        UTL_DBG_FREE(hash->buf);
        ret = true;
        LOGD("success\n");
    } else {
        ret = false;
        LOGE("fail\n");
    }
    //
    (*env)->DeleteLocalRef(env, array);
    (*env)->DeleteLocalRef(env, hash_obj);
    //
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_is_tx_broadcasted(const uint8_t *pPeerId, const uint8_t *pTxid)
{
    const btcj_buf_t buf_id = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
    jbyteArray peer_id = buf2jbarray(&buf_id);
    const btcj_buf_t buf_hash = { (CONST_CAST uint8_t *)pTxid, BTC_SZ_TXID };
    jobject txHash = buf2jbarray(&buf_hash);
    jboolean ret = (*env)->CallBooleanMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_CHECKBROADCAST], peer_id, txHash);
    check_exception(env);
    LOGD("result=%d\n", ret);
    //
    (*env)->DeleteLocalRef(env, peer_id);
    (*env)->DeleteLocalRef(env, txHash);
    //
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_check_unspent(const uint8_t *pPeerId, bool *pUnspent, const uint8_t *pTxid, uint32_t VIndex)
{
    jbyteArray peer_id;
    if (pPeerId != NULL) {
        const btcj_buf_t buf = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
        peer_id = buf2jbarray(&buf);
    } else {
        peer_id = NULL;
    }
    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pTxid, BTC_SZ_TXID };
    jobject txHash = buf2jbarray(&buf);
    jint retval = (*env)->CallIntMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_CHECKUNSPENT], peer_id, txHash, VIndex);
    check_exception(env);
    LOGD("result=%d\n", retval);
    //
    bool ret;
    switch (retval) {
    case M_CHECKUNSPENT_UNSPENT:
        ret = true;
        *pUnspent = true;
        break;
    case M_CHECKUNSPENT_SPENT:
        ret = true;
        *pUnspent = false;
        break;
    case M_CHECKUNSPENT_FAIL:
    default:
        ret = false;
        break;
    }
    //
    (*env)->DeleteLocalRef(env, peer_id);
    (*env)->DeleteLocalRef(env, txHash);
    //
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_getnewaddress(char *pAddr)
{
    jstring addr_str = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETNEWADDRESS]);
    check_exception(env);
    if (addr_str != NULL) {
        const char *cs = (*env)->GetStringUTFChars(env, addr_str, JNI_FALSE);
        LOGD("addr=%s\n", cs);
        strcpy(pAddr, cs);
        //
        (*env)->ReleaseStringUTFChars(env, addr_str, cs);
        (*env)->DeleteLocalRef(env, addr_str);
    }
    //
    return addr_str != NULL;
}
//-----------------------------------------------------------------------------
bool btcj_estimatefee(uint64_t *pFeeSatoshi, int Blks)
{
//ToDo: FIX: Dynamic fee
    (void)Blks;
    jlong ret = (*env)->CallLongMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_ESTIMATEFEE]);
    check_exception(env);
    *pFeeSatoshi = ret;
    //
    return true;
}
//-----------------------------------------------------------------------------
bool btcj_set_channel(
    const uint8_t *pPeerId,
    uint64_t ShortChannelId,
    const uint8_t *pFundingTxid,
    int FundingIndex,
    const uint8_t *pScriptPubKey,
    const uint8_t *pMinedHash,
    uint32_t LastConfirm)
{
    btcj_buf_t peer_id = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
    jbyteArray aryPeer = buf2jbarray(&peer_id);
    jlong sci = ShortChannelId;
    jint last_confirm = (jint)LastConfirm;

    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pFundingTxid, BTC_SZ_TXID };
    jobject txHash = buf2jbarray(&buf);

    btcj_buf_t script_pubkey = { (CONST_CAST uint8_t *)pScriptPubKey, BTC_SZ_HASH256 };
    jbyteArray aryScriptPubKey = buf2jbarray(&script_pubkey);

    const btcj_buf_t bufmined = { (CONST_CAST uint8_t *)pMinedHash, BTC_SZ_HASH256 };
    jobject blkhash = buf2jbarray(&bufmined);

    LOGD("sci=%016" PRIx64 "\n", sci);
    jboolean ret = (*env)->CallBooleanMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SETCHANNEL],
                           aryPeer, sci, txHash, FundingIndex, aryScriptPubKey,
                           blkhash, last_confirm);
    LOGD("called: ret=%d\n", ret);
    check_exception(env);
    //
    (*env)->DeleteLocalRef(env, blkhash);
    (*env)->DeleteLocalRef(env, aryScriptPubKey);
    (*env)->DeleteLocalRef(env, txHash);
    (*env)->DeleteLocalRef(env, aryPeer);
    return ret;
}
//-----------------------------------------------------------------------------
void btcj_del_channel(const uint8_t *pPeerId)
{
    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
    jbyteArray barray = buf2jbarray(&buf);
    (*env)->CallVoidMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_DELCHANNEL], barray);
    check_exception(env);
    //
    (*env)->DeleteLocalRef(env, barray);
}
//-----------------------------------------------------------------------------
// void btcj_set_committxid(const uint8_t *peerId, )
// {
// }
//-----------------------------------------------------------------------------
bool btcj_getbalance(uint64_t *pAmount)
{
    jlong ret = (*env)->CallLongMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETBALANCE]);
    check_exception(env);
    *pAmount = ret;
    //
    return true;
}
//-----------------------------------------------------------------------------
bool btcj_emptywallet(const char *pAddr, uint8_t *pTxid)
{
    bool ret;
    jstring addr = (*env)->NewStringUTF(env, pAddr);
    jbyteArray hash_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_EMPTYWALLET], addr);
    check_exception(env);
    if (hash_obj != NULL) {
        btcj_buf_t *hash = jbarray2buf(hash_obj);
        memcpy(pTxid, hash->buf, hash->len);
        UTL_DBG_FREE(hash->buf);
        ret = true;
        (*env)->DeleteLocalRef(env, hash_obj);
    } else {
        ret = false;
    }
    //
    (*env)->DeleteLocalRef(env, addr);
    //
    return ret;
}
//-----------------------------------------------------------------------------
void btcj_exit(void)
{
    (*env)->CallStaticVoidMethod(env, system_cls, system_exit_method, 0);
    check_exception(env);
}
//-----------------------------------------------------------------------------
void btcj_remove_suspend_block(void)
{
    (*env)->CallVoidMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_REMOVESUSPENDBLOCK]);
    check_exception(env);
}
//-----------------------------------------------------------------------------
//-----------------------------------------------------------------------------
static jbyteArray buf2jbarray(const btcj_buf_t *buf)
{
    jbyteArray array = (*env)->NewByteArray(env, buf->len);
    (*env)->SetByteArrayRegion(env, array, 0, buf->len, (const jbyte *)buf->buf);
    return array;
}

static btcj_buf_t* jbarray2buf(jbyteArray jbarray)
{
    jsize size = (*env)->GetArrayLength(env, jbarray);
    btcj_buf_t *buf = UTL_DBG_MALLOC(sizeof(btcj_buf_t));
    buf->len = size;
    buf->buf = UTL_DBG_MALLOC(size);
    (*env)->GetByteArrayRegion(env, jbarray, 0, size, (jbyte *)buf->buf);
    return buf;
}

static jobject bufs2list(const btcj_buf_t *bufs)
{
    jobject list = (*env)->NewObject(env, arraylist_cls, arraylist_ctor_method);
    btcj_buf_t *p = (btcj_buf_t*)bufs->buf;
    int num = bufs->len / sizeof(btcj_buf_t*);
    //
    for (int i = 0; i < num; i++) {
        jbyteArray ba = buf2jbarray((p + i));
        (*env)->CallBooleanMethod(env, list, arraylist_add_method, ba);
        check_exception(env);
        (*env)->DeleteLocalRef(env, ba);
    }
    return list;
}

static btcj_buf_t* list2bufs(jobject list)
{
    jint size = (*env)->CallIntMethod(env, list, list_size_method);
    btcj_buf_t *bufs = UTL_DBG_MALLOC(sizeof(btcj_buf_t));
    bufs->len = sizeof(btcj_buf_t*)*size;
    bufs->buf = UTL_DBG_MALLOC(bufs->len);
    //
    for (int i = 0; i < size; i++) {
        jbyteArray ba = (*env)->CallObjectMethod(env, list, list_get_method, (jint)i);
        check_exception(env);
        ((btcj_buf_t**)bufs->buf)[i] = jbarray2buf(ba);
        (*env)->DeleteLocalRef(env, ba);
    }
    return bufs;
}

static inline void _check_exception(JNIEnv *env, const char *pFuncName, int Line)
{
    if ((*env)->ExceptionCheck(env)) {
        LOGE("fail: exception(%s(): %d)!!\n", pFuncName, Line);
        (*env)->ExceptionClear(env);
        //abort();
        mExceptionHappen = true;
    }
}
