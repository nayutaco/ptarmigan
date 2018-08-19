#ifndef PLOG_H__
#define PLOG_H__

#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


#define PLOG_DIR            "logs"
#define PLOG_NAME           PLOG_DIR "/plog.log"

#define PLOG_MAX            (20)
#define PLOG_SIZE_LIMIT     (1024 * 1024)

#define PLOG_PRI_ERR        (1)
#define PLOG_PRI_INFO       (2)
#define PLOG_PRI_DBG        (3)
#define PLOG_PRI_VERBOSE    (4)
#ifdef DEVELOPER_MODE
#define PLOG_PRI            PLOG_PRI_VERBOSE
#else
#define PLOG_PRI            PLOG_PRI_DBG
#endif


bool plog_init(void);
bool plog_init_stderr(void);
bool plog_init_stdout(void);
void plog_term(void);
void plog_write(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const char *pFmt, ...);
void plog_dump(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len);
void plog_dump_rev(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len);


#ifdef __cplusplus
}
#endif

#endif /* PLOG_H__ */
