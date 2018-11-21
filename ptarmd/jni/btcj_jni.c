#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include <inttypes.h>
#include <string.h>
#include <libgen.h>
#include <linux/limits.h>
#include "btcj_jni.h"

#include "ptarmd.h"
#include "btc.h"


#define M_CHECKUNSPENT_FAIL             (-1)
#define M_CHECKUNSPENT_UNSPENT          (0)
#define M_CHECKUNSPENT_SPENT            (1)


enum {
    M_FIELD_PTARMCHAN_HEIGHT,
    M_FIELD_PTARMCHAN_BINDEX,
    M_FIELD_PTARMCHAN_MINEDHASH,
    //
    M_FIELD_PTARMCHAN_MAX,
};


static JNIEnv *env;
static JavaVM *jvm;

//GlobalRef
static jclass hash_cls;
static jclass arraylist_cls;
static jobject ptarm_obj;

static jmethodID ptarm_method[METHOD_PTARM_MAX];
//static jmethodID tobech32_method;
static jmethodID sha256_getrevbytes_method;
static jmethodID sha256_wraprev_method;
static jmethodID arraylist_ctor_method;
static jmethodID arraylist_add_method;
static jmethodID list_get_method;
static jmethodID list_size_method;
static jfieldID ptarmcls_field[M_FIELD_PTARMCHAN_MAX];

static uint8_t* hash2bytes(jobject hash_obj);
static jobject bytes2hash(const uint8_t *bytes);
static jbyteArray buf2jbarray(const btcj_buf_t *buf);
static btcj_buf_t* jbarray2buf(jbyteArray jbarray);
static jobject bufs2list(const btcj_buf_t *bufs);
static btcj_buf_t* list2bufs(jobject list);
static bool get_execpath(char *path, size_t dest_len);


const struct {
    const char *name;
    const char *sig;
} kMethod[METHOD_PTARM_MAX] = {
    // METHOD_PTARM_GETBLOCKCOUNT,
    { "getBlockCount", "()I" },
    // METHOD_PTARM_GETGENESISBLOCKHASH,
    { "getGenesisBlockHash", "()Lorg/bitcoinj/core/Sha256Hash;" },
    // METHOD_PTARM_GETCONFIRMATION,
    { "getTxConfirmation", "(Lorg/bitcoinj/core/Sha256Hash;)I" },
    // METHOD_PTARM_GETSHORTCHANNELPARAM,
    { "getShortChannelParam", "([B)Lco/nayuta/lightning/Ptarmigan$ShortChannelParam;" },
    // METHOD_PTARM_GETTXIDFROMSHORTCHANNELID,
    { "getTxidFromShortChannelId", "(J)Lorg/bitcoinj/core/Sha256Hash;" },
    // METHOD_PTARM_SEARCHOUTPOINT,
    { "searchOutPoint", "(ILorg/bitcoinj/core/Sha256Hash;I)[B" },
    // METHOD_PTARM_SEARCHVOUT,
    { "searchVout", "(ILjava/util/List;)Ljava/util/List;" },
    // METHOD_PTARM_SIGNRAWTX,
    { "signRawTx", "(J[B)[B" },
    // METHOD_PTARM_SENDRAWTX,
    { "sendRawTx", "([B)Lorg/bitcoinj/core/Sha256Hash;" },
    // METHOD_PTARM_CHECKBROADCAST,
    { "checkBroadcast", "(Lorg/bitcoinj/core/Sha256Hash;)Z" },
    // METHOD_PTARM_CHECKUNSPENT,
    { "checkUnspent", "([BLorg/bitcoinj/core/Sha256Hash;I)I" },
    // METHOD_PTARM_GETNEWADDRESS,
    { "getNewAddress", "()Ljava/lang/String;" },
    // METHOD_PTARM_ESTIMATEFEE,
    { "estimateFee", "()J" },
    // METHOD_PTARM_SETCHANNEL,
    { "setChannel", "([BJLorg/bitcoinj/core/Sha256Hash;I[BZLorg/bitcoinj/core/Sha256Hash;I)V" },
    // METHOD_PTARM_SETCOMMITTXID,
    { "setCommitTxid", "([BIILorg/bitcoinj/core/Sha256Hash;)V" },
    // METHOD_PTARM_GETBALANCE,
    { "getBalance", "()J" },
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
    { "minedHash", "Lorg/bitcoinj/core/Sha256Hash;" },
};


//-----------------------------------------------------------------------------
bool btcj_init(btc_genesis_t Gen)
{
    jclass cls;
    char exepath[PATH_MAX];
    char optjar[PATH_MAX];
    get_execpath(exepath, sizeof(exepath));
    snprintf(optjar, sizeof(optjar), "-Djava.class.path=%s/jar/bitcoinj-ptarmigan-dev.jar:%s/jar/bcprov-jdk15on-160.jar", exepath, exepath);
    LOGD("optjar=%s\n", optjar);

    JavaVMOption opt[1];
    // .classファイルを配置するディレクトリか、.jarファイルのパスを指定する
    opt[0].optionString = optjar;
    //
    JavaVMInitArgs vm_args = {
        .version = JNI_VERSION_1_8,
        .options = opt,
        .nOptions = 1
    };
    // JVM初期化
    LOGD("JNI_CreateJavaVM\n");
    int ret = JNI_CreateJavaVM(&jvm, (void**)&env, (void*)&vm_args);
    if(ret != JNI_OK) {
        // jvm.dllへのパスが通っていない場合など
        LOGD("btcj_init() Error: JNI_CreateJavaVM() = %d\n", ret);
        return false;
    }

    LOGD("Class: Ptarmigan\n");

    // クラス検索
    cls = (*env)->FindClass(env, "co/nayuta/lightning/Ptarmigan");
    if(cls == NULL) {
        LOGD("fail: FindClass()\n");
        return false;
    }

    // コンストラクタ呼び出し
    LOGD("call ctor\n");
    jmethodID method = (*env)->GetMethodID(env, cls, "<init>", "(Ljava/lang/String;)V");
    if(method == NULL) {
        LOGD("fail: get method id\n");
        return false;
    }
    const char *p_chain;
    switch (Gen) {
    case BTC_GENESIS_BTCMAIN:
        p_chain = "main";
        break;
    case BTC_GENESIS_BTCTEST:
        p_chain = "test";
        break;
    case BTC_GENESIS_BTCREGTEST:
        p_chain = "regtest";
        break;
    default:
        assert(0);
        break;
    }
    jstring param = (*env)->NewStringUTF(env, p_chain);
    jobject obj = (*env)->NewObject(env, cls, method, param);
    if(obj == NULL) {
        return false;
    }
    //
    ptarm_obj = (jobject)(*env)->NewGlobalRef(env, obj);
    (*env)->DeleteLocalRef(env, param);
    (*env)->DeleteLocalRef(env, obj);
    //
    LOGD("get methods\n");
    for(size_t lp = 0; lp < ARRAY_SIZE(kMethod); lp++) {
        ptarm_method[lp] = (*env)->GetMethodID(env, cls, kMethod[lp].name, kMethod[lp].sig);
        if(ptarm_method[lp] == NULL) {
            LOGD("fail: get method id(%s)\n", kMethod[lp].name);
            return false;
        }
    }

    LOGD("Class: Ptarmigan\n");

    cls = (*env)->FindClass(env, "co/nayuta/lightning/Ptarmigan$ShortChannelParam");
    if(cls == NULL) {
        LOGD("fail: FindClass()\n");
        return false;
    }
    //field
    //  btcj_get_short_channel_param
    LOGD("get fields\n");
    for(size_t lp = 0; lp < ARRAY_SIZE(kField); lp++) {
        ptarmcls_field[lp] = (*env)->GetFieldID(env, cls, kField[lp].name, kField[lp].sig);
        if(ptarmcls_field[lp] == NULL) {
            LOGD("fail: get field id(%s)\n", kField[lp].name);
            return false;
        }
    }

    // jclass addr_cls = (*env)->FindClass(env, "org/bitcoinj/core/SegwitAddress");
    // if(addr_cls == NULL) {
    //     LOGD("fail: FindClass()\n");
    //     return false;
    // }
    // tobech32_method = (*env)->GetMethodID(env, addr_cls, "toBech32", "()Ljava/lang/String;");
    // if(tobech32_method == NULL) {
    //     LOGD("fail: GetMethodID()\n");
    //     return false;
    // }

    cls = (*env)->FindClass(env, "org/bitcoinj/core/Sha256Hash");
    if(cls == NULL) {
        LOGD("fail: FindClass()\n");
        return false;
    }
    hash_cls = (jclass)(*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    sha256_getrevbytes_method = (*env)->GetMethodID(env, hash_cls, "getReversedBytes", "()[B");
    if(sha256_getrevbytes_method == NULL) {
        LOGD("fail: GetMethodID()\n");
        return false;
    }
    sha256_wraprev_method = (*env)->GetStaticMethodID(env, hash_cls, "wrapReversed", "([B)Lorg/bitcoinj/core/Sha256Hash;");
    if(sha256_wraprev_method == NULL) {
        LOGD("fail: GetStaticMethodID()\n");
        return false;
    }

    //ArrayList
    cls = (*env)->FindClass(env, "Ljava/util/ArrayList;");
    if(cls == NULL) {
        LOGD("fail: FindClass()\n");
        return false;
    }
    arraylist_cls = (jclass)(*env)->NewGlobalRef(env, cls);
    (*env)->DeleteLocalRef(env, cls);
    arraylist_ctor_method = (*env)->GetMethodID(env, arraylist_cls, "<init>", "()V");
    if(arraylist_ctor_method == NULL) {
        LOGD("fail: GetMethodID()\n");
        return false;
    }
    arraylist_add_method = (*env)->GetMethodID(env, arraylist_cls, "add", "(Ljava/lang/Object;)Z");
    if(arraylist_add_method == NULL) {
        LOGD("fail: GetMethodID()\n");
        return false;
    }

    //List
    cls = (*env)->FindClass(env, "Ljava/util/List;");
    if(cls == NULL) {
        LOGD("fail: FindClass()\n");
        return false;
    }
    list_get_method = (*env)->GetMethodID(env, cls, "get", "(I)Ljava/lang/Object;");
    if(list_get_method == NULL) {
        LOGD("fail: GetMethodID()\n");
        return false;
    }
    list_size_method = (*env)->GetMethodID(env, cls, "size", "()I");
    if(list_size_method == NULL) {
        LOGD("fail: GetMethodID()\n");
        return false;
    }
    (*env)->DeleteLocalRef(env, cls);

    LOGD("END\n");
    return true;
}
//-----------------------------------------------------------------------------
bool btcj_release(void)
{
    (*env)->DeleteGlobalRef(env, ptarm_obj);
    (*env)->DeleteGlobalRef(env, arraylist_cls);
    (*env)->DeleteGlobalRef(env, hash_cls);
    //
    if(jvm != NULL) {
        (*jvm)->DestroyJavaVM(jvm);
    }
    //
    return true;
}
//-----------------------------------------------------------------------------
int32_t btcj_getblockcount(void)
{
    LOGD("\n");
    jint ret = (*env)->CallIntMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETBLOCKCOUNT]);
    LOGD("ret=%d\n", ret);
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_getgenesisblockhash(uint8_t *pHash)
{
    jobject hash_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETGENESISBLOCKHASH]);
    uint8_t *bytes = hash2bytes(hash_obj);
    memcpy(pHash, bytes, BTC_SZ_HASH256);
    //
    (*env)->DeleteLocalRef(env, hash_obj);
    free(bytes);
    //
    return true;
}
//-----------------------------------------------------------------------------
int32_t btcj_get_funding_confirm(const uint8_t *pTxid)
{
    LOGD("txid=");
    TXIDD(pTxid);

    jobject txHash = bytes2hash(pTxid);
    jint ret = (*env)->CallIntMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETCONFIRMATION], txHash);
    LOGD("ret=%d\n", ret);
    //
    (*env)->DeleteLocalRef(env, txHash);
    //
    return (int32_t)ret;
}
//-----------------------------------------------------------------------------
bool btcj_get_short_channel_param(const uint8_t *pPeerId, int32_t *pHeight, int32_t *pbIndex, uint8_t **ppMinedHash)
{
    //jbyteArray barray = bytes2jbarray(pPeerId, BTC_SZ_PUBKEY);
    const btcj_buf_t buf = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
    jbyteArray barray = buf2jbarray(&buf);
    jobject param_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETSHORTCHANNELPARAM], barray);
    //
    if(param_obj != NULL) {
        *pHeight = (*env)->GetIntField(env, param_obj, ptarmcls_field[M_FIELD_PTARMCHAN_HEIGHT]);
        *pbIndex = (*env)->GetIntField(env, param_obj, ptarmcls_field[M_FIELD_PTARMCHAN_BINDEX]);
        jobject hash_obj = (*env)->GetObjectField(env, param_obj, ptarmcls_field[M_FIELD_PTARMCHAN_MINEDHASH]);
        if(hash_obj != NULL) {
            *ppMinedHash = hash2bytes(hash_obj);
        } else {
            LOGD("fail: blockHash field\n");
        }

        (*env)->DeleteLocalRef(env, hash_obj);
        (*env)->DeleteLocalRef(env, param_obj);
    }
    return param_obj != NULL;
}
//-----------------------------------------------------------------------------
bool btcj_gettxid_from_short_channel(uint64_t ShortChannelId, uint8_t **ppTxid)
{
    jobject hash_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETTXIDFROMSHORTCHANNELID], ShortChannelId);
    if(hash_obj != NULL) {
        *ppTxid = hash2bytes(hash_obj);
    } else {
        LOGD("fail: txid\n");
    }
    return hash_obj != NULL;
}
//-----------------------------------------------------------------------------
bool btcj_search_outpoint(btcj_buf_t **ppTx, uint32_t Blks, const uint8_t *pTxid, uint32_t VIndex)
{
    jobject txHash = bytes2hash(pTxid);
    jbyteArray retval = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SEARCHOUTPOINT], Blks, txHash, VIndex);
    //
    bool ret;
    if(retval != NULL) {
        *ppTx = jbarray2buf(retval);
        ret = true;
    } else {
        ret = false;
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
    LOGD(" list=%p\n", list);
    if(ppTxBuf != NULL) {
        *ppTxBuf = list2bufs(list);
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
    //LOGD("amount=%" PRIu64 ", scriptPubKey=", Amount);
    //DUMPD(scriptPubKey->buf, scriptPubKey->len);

    jlong amnt = Amount;
    jbyteArray pubKey = buf2jbarray(pScriptPubKey);
    jbyteArray ret = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SIGNRAWTX], amnt, pubKey);
    if(ret != NULL) {
        *ppTxData = jbarray2buf(ret);
    } else {
        LOGD("fail\n");
    }
    //
    (*env)->DeleteLocalRef(env, pubKey);
    (*env)->DeleteLocalRef(env, ret);
    //
    return ret != NULL;
}
//-----------------------------------------------------------------------------
bool btcj_sendraw_tx(uint8_t **ppTxid, int *pCode, const btcj_buf_t *pTxData)
{
    (void)pCode;
    bool ret;
    jbyteArray array = buf2jbarray(pTxData);
    jobject hash_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SENDRAWTX], array);
    if (hash_obj != NULL) {
        *ppTxid = hash2bytes(hash_obj);
        ret = true;
    } else {
        *ppTxid = NULL;
        ret = false;
    }
    //
    (*env)->DeleteLocalRef(env, array);
    (*env)->DeleteLocalRef(env, hash_obj);
    //
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_is_tx_broadcasted(const uint8_t *pTxid)
{
    jobject txHash = bytes2hash(pTxid);
    jboolean ret = (*env)->CallBooleanMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_CHECKBROADCAST], txHash);
    //
    (*env)->DeleteLocalRef(env, txHash);
    //
    return ret;
}
//-----------------------------------------------------------------------------
bool btcj_check_unspent(const uint8_t *pPeerId, bool *pUnspent, const uint8_t *pTxid, uint32_t VIndex)
{
    jbyteArray peer_id;
    if(pPeerId != NULL) {
        //peer_id = bytes2jbarray(pPeerId, BTC_SZ_PUBKEY);
        const btcj_buf_t buf = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
        peer_id = buf2jbarray(&buf);
    } else {
        peer_id = NULL;
    }
    jobject txHash = bytes2hash(pTxid);
    jint retval = (*env)->CallIntMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_CHECKUNSPENT], peer_id, txHash, VIndex);
    //
    bool ret;
    switch(retval) {
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
#if 0
    jobject addr_obj = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETNEWADDRESS]);
    jstring addr_str = (*env)->CallObjectMethod(env, addr_obj, tobech32_method);
#else
    jstring addr_str = (*env)->CallObjectMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETNEWADDRESS]);
#endif
    if(addr_str != NULL) {
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
#warning FIX: Dynamic fee
    (void)Blks;
    jlong ret = (*env)->CallLongMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_ESTIMATEFEE]);
    *pFeeSatoshi = ret;
    //
    return true;
}
//-----------------------------------------------------------------------------
void btcj_set_channel(
    const uint8_t *pPeerId,
    uint64_t ShortChannelId,
    const uint8_t *pFundingTxid,
    int FundingIndex,
    const uint8_t *pScriptPubKey,
    bool bFundingTxUnspent,
    const uint8_t *pMinedHash, int32_t BlockCnt)
{
    btcj_buf_t peer_id = { (CONST_CAST uint8_t *)pPeerId, BTC_SZ_PUBKEY };
    jbyteArray aryPeer = buf2jbarray(&peer_id);
    jlong sci = ShortChannelId;
    jobject txHash = bytes2hash(pFundingTxid);
    btcj_buf_t script_pubkey = { (CONST_CAST uint8_t *)pScriptPubKey, BTC_SZ_HASH256 };
    jbyteArray aryScriptPubKey = buf2jbarray(&script_pubkey);
    jobject blkhash;
    if(pMinedHash != NULL) {
        blkhash = bytes2hash(pMinedHash);
    } else {
        blkhash = NULL;
    }
    (*env)->CallBooleanMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_SETCHANNEL],
                              aryPeer, sci, txHash, FundingIndex, aryScriptPubKey,
                              bFundingTxUnspent, blkhash, BlockCnt);
    //
    (*env)->DeleteLocalRef(env, blkhash);
    (*env)->DeleteLocalRef(env, aryScriptPubKey);
    (*env)->DeleteLocalRef(env, txHash);
    (*env)->DeleteLocalRef(env, aryPeer);
}
//-----------------------------------------------------------------------------
// void btcj_set_committxid(const uint8_t *peerId, )
// {
// }
//-----------------------------------------------------------------------------
bool btcj_getbalance(uint64_t *pAmount)
{
    jlong ret = (*env)->CallLongMethod(env, ptarm_obj, ptarm_method[METHOD_PTARM_GETBALANCE]);
    *pAmount = ret;
    //
    return true;
}
//-----------------------------------------------------------------------------

/*
public int getBlockCount();
descriptor: ()I

public org.bitcoinj.core.Sha256Hash getGenesisBlockHash();
descriptor: ()Lorg/bitcoinj/core/Sha256Hash;

public int getTxConfirmation(org.bitcoinj.core.Sha256Hash);
descriptor: (Lorg/bitcoinj/core/Sha256Hash;)I

public co.nayuta.lightning.Ptarmigan$ShortChannelParam getShortChannelParam(byte[]);
descriptor: ([B)Lco/nayuta/lightning/Ptarmigan$ShortChannelParam;

public org.bitcoinj.core.Sha256Hash getTxidFromShortChannelId(long);
descriptor: (J)Lorg/bitcoinj/core/Sha256Hash;

public byte[] searchOutPoint(int, byte[], int);
descriptor: (I[BI)[B

public byte[][] searchVout(int, byte[][]);
descriptor: (I[[B)[[B

public byte[] signRawTx(long, byte[]);
descriptor: (J[B)[B

public boolean sendRawTx(byte[]);
descriptor: ([B)Z

public boolean checkBroadcast(org.bitcoinj.core.Sha256Hash);
descriptor: (Lorg/bitcoinj/core/Sha256Hash;)Z

public boolean checkUnspent(org.bitcoinj.core.Sha256Hash);
descriptor: (Lorg/bitcoinj/core/Sha256Hash;)Z

public org.bitcoinj.core.SegwitAddress getNewAddress();
descriptor: ()Lorg/bitcoinj/core/SegwitAddress;

public long estimateFee();
descriptor: ()J
*/

//-----------------------------------------------------------------------------
static uint8_t* hash2bytes(jobject hash_obj)
{
    jbyteArray array = (*env)->CallObjectMethod(env, hash_obj, sha256_getrevbytes_method);
    uint8_t *bytes = malloc(BTC_SZ_HASH256);
    (*env)->GetByteArrayRegion(env, array, 0, BTC_SZ_HASH256, (jbyte *)bytes);
    return bytes;
}

static jobject bytes2hash(const uint8_t *bytes)
{
    const btcj_buf_t buf = { (CONST_CAST uint8_t *)bytes, BTC_SZ_HASH256 };
    jbyteArray array = buf2jbarray(&buf);
    jobject obj = (*env)->CallStaticObjectMethod(env, hash_cls, sha256_wraprev_method, array);
    //
    (*env)->DeleteLocalRef(env, array);
    //
    return obj;
}

static jbyteArray buf2jbarray(const btcj_buf_t *buf)
{
    jbyteArray array = (*env)->NewByteArray(env, buf->len);
    (*env)->SetByteArrayRegion(env, array, 0, buf->len, (const jbyte *)buf->buf);
    return array;
}

static btcj_buf_t* jbarray2buf(jbyteArray jbarray)
{
    jsize size = (*env)->GetArrayLength(env, jbarray);
    btcj_buf_t *buf = malloc(sizeof(btcj_buf_t));
    buf->len = size;
    buf->buf = malloc(size);
    (*env)->GetByteArrayRegion(env, jbarray, 0, size, (jbyte *)buf->buf);
    return buf;
}

static jobject bufs2list(const btcj_buf_t *bufs)
{
    jobject list = (*env)->NewObject(env, arraylist_cls, arraylist_ctor_method);
    btcj_buf_t *p = (btcj_buf_t*)bufs->buf;
    int num = bufs->len / sizeof(btcj_buf_t*);
    //
    for(int i = 0; i < num; i++) {
        jbyteArray ba = buf2jbarray((p + i));
        (*env)->CallBooleanMethod(env, list, arraylist_add_method, ba);
        (*env)->DeleteLocalRef(env, ba);
    }
    return list;
}

static btcj_buf_t* list2bufs(jobject list)
{
    jint size = (*env)->CallIntMethod(env, list, list_size_method);
    btcj_buf_t *bufs = malloc(sizeof(btcj_buf_t));
    bufs->len = sizeof(btcj_buf_t*)*size;
    bufs->buf = malloc(bufs->len);
    //
    for(int i = 0; i < size; i++) {
        jbyteArray ba = (*env)->CallObjectMethod(env, list, list_get_method, (jint)i);
        ((btcj_buf_t**)bufs->buf)[i] = jbarray2buf(ba);
        (*env)->DeleteLocalRef(env, ba);
    }
    return bufs;
}

//https://stackoverflow.com/questions/606041/how-do-i-get-the-path-of-a-process-in-unix-linux
static bool get_execpath(char *path, size_t dest_len)
{
    ssize_t buff_len;
    if((buff_len = readlink("/proc/self/exe", path, dest_len - 1)) != -1) {
        //printf("readlink=%s\n", path);
        path[buff_len] = '\0';
        dirname(path);
    }
    return buff_len != -1;
}
