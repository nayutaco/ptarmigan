#ifndef UTL_LOG_H__
#define UTL_LOG_H__

#include <stdio.h>
#include <stdbool.h>


#ifdef __cplusplus
extern "C" {
#endif


#define UTL_LOG_DIR            "logs"
#define UTL_LOG_NAME           UTL_LOG_DIR "/log"

#define UTL_LOG_MAX            (20)
#define UTL_LOG_SIZE_LIMIT     (1024 * 1024)

#define UTL_LOG_PRI_ERR        (1)
#define UTL_LOG_PRI_INFO       (2)
#define UTL_LOG_PRI_DBG        (3)
#define UTL_LOG_PRI_VERBOSE    (4)
#ifdef DEVELOPER_MODE
#define UTL_LOG_PRI            UTL_LOG_PRI_VERBOSE
#else
#define UTL_LOG_PRI            UTL_LOG_PRI_DBG
#endif


bool utl_log_init(void);
bool utl_log_init_stderr(void);
bool utl_log_init_stdout(void);
void utl_log_term(void);
void utl_log_write(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const char *pFmt, ...);
void utl_log_dump(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len);
void utl_log_dump_rev(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len);


#ifdef PTARM_UTL_LOG_MACRO_DISABLED
#define LOGV(...)       //none
#define DUMPV(...)      //none
#define TXIDV(...)      //none

#define LOGD(...)       //none
#define LOGD2(...)      //none
#define DUMPD(...)      //none
#define TXIDD(...)      //none

#elif defined(ANDROID) //PTARM_UTL_LOG_MACRO_DISABLED
#include <android/log.h>

#define LOGV            ((void)__android_log_print(ANDROID_LOG_VERBOSE, "ptarm::", __VA_ARGS__))
#define DUMPV(dt,ln) {\
    char *p_str = (char *)malloc(ln * 2 + 1);   \
    utl_misc_bin2str(p_str, dt, ln);          \
    __android_log_print(ANDROID_LOG_VERBOSE, "ptarm::", "%s", p_str);  \
    free(p_str); \
}
#define TXIDV(dt) {\
    char *p_str = (char *)malloc(BTC_SZ_TXID * 2 + 1);   \
    utl_misc_bin2str_rev(p_str, dt, BTC_SZ_TXID);      \
    __android_log_print(ANDROID_LOG_VERBOSE, "ptarm::", "%s", p_str);  \
    free(p_str); \
}

#define LOGD(...)       ((void)__android_log_print(ANDROID_LOG_DEBUG, "ptarm::", __VA_ARGS__))
#define LOGD2(...)      ((void)__android_log_print(ANDROID_LOG_DEBUG, "ptarm::", __VA_ARGS__))
#define DUMPD(dt,ln) {\
    char *p_str = (char *)malloc(ln * 2 + 1);   \
    utl_misc_bin2str(p_str, dt, ln);          \
    __android_log_print(ANDROID_LOG_DEBUG, "ptarm::", "%s", p_str);  \
    free(p_str); \
}
#define TXIDD(dt) {\
    char *p_str = (char *)malloc(BTC_SZ_TXID * 2 + 1);   \
    utl_misc_bin2str_rev(p_str, dt, BTC_SZ_TXID);      \
    __android_log_print(ANDROID_LOG_DEBUG, "ptarm::", "%s", p_str);  \
    free(p_str); \
}

#else //PTARM_UTL_LOG_MACRO_DISABLED
#ifndef LOG_TAG
#error "LOG_TAG needs to be defined"
#endif

#define LOGE(...)       utl_log_write(UTL_LOG_PRI_ERR, __FILE__, __LINE__, 1, LOG_TAG, __func__, __VA_ARGS__)
#define DUMPE(dt,ln)    utl_log_dump(UTL_LOG_PRI_ERR, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, ln)
#define TXIDE(dt)       utl_log_dump_rev(UTL_LOG_PRI_ERR, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, BTC_SZ_TXID)

#define LOGI(...)       utl_log_write(UTL_LOG_PRI_INFO, __FILE__, __LINE__, 1, LOG_TAG, __func__, __VA_ARGS__)
#define DUMPI(dt,ln)    utl_log_dump(UTL_LOG_PRI_INFO, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, ln)
#define TXIDI(dt)       utl_log_dump_rev(UTL_LOG_PRI_INFO, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, BTC_SZ_TXID)

#define LOGD(...)       utl_log_write(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 1, LOG_TAG, __func__, __VA_ARGS__)
#define LOGD2(...)      utl_log_write(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 0, LOG_TAG, __func__, __VA_ARGS__)
#define DUMPD(dt,ln)    utl_log_dump(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, ln)
#define TXIDD(dt)       utl_log_dump_rev(UTL_LOG_PRI_DBG, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, BTC_SZ_TXID)

#define LOGV(...)       utl_log_write(UTL_LOG_PRI_VERBOSE, __FILE__, __LINE__, 1, LOG_TAG, __func__, __VA_ARGS__)
#define DUMPV(dt,ln)    utl_log_dump(UTL_LOG_PRI_VERBOSE, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, ln)
#define TXIDV(dt)       utl_log_dump_rev(UTL_LOG_PRI_VERBOSE, __FILE__, __LINE__, 0, LOG_TAG, __func__, dt, BTC_SZ_TXID)

#endif //PTARM_UTL_LOG_MACRO_DISABLED


#ifdef __cplusplus
}
#endif

#endif /* UTL_LOG_H__ */
