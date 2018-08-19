#ifndef UTL_LOG_H__
#define UTL_LOG_H__

#include <stdio.h>


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


#ifdef __cplusplus
}
#endif

#endif /* UTL_LOG_H__ */
