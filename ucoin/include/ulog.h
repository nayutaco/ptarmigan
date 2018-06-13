#ifndef ULOG_H__
#define ULOG_H__

#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


#define ULOG_DIR            "logs"
#define ULOG_NAME           ULOG_DIR "/ulog.log"

#define ULOG_MAX            (20)
#define ULOG_SIZE_LIMIT     (1024 * 1024)

#define ULOG_PRI_ERR        (1)
#define ULOG_PRI_INFO       (2)
#define ULOG_PRI_DBG        (3)
#define ULOG_PRI_VERBOSE    (4)
#define ULOG_PRI            ULOG_PRI_DBG


bool ulog_init(void);
void ulog_term(void);
void ulog_write(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const char *pFmt, ...);
void ulog_dump(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len);
void ulog_dump_rev(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len);


#ifdef __cplusplus
}
#endif

#endif /* ULOG_H__ */
