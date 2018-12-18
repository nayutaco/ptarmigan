#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utl_misc.h"
#define LOG_TAG "dummy"
#include "utl_log.h"

#define FNAME_MAX       (50)


static inline int tid(void) {
    return (int)syscall(SYS_gettid);
}


static pthread_mutex_t  mMux;
static FILE             *mFp;

//UTL_LOG_PRI_xxx
//  Error
//  Info
//  Debug
//  Verbose
static const char M_MARK[] = "EIDV";


bool utl_log_init(void)
{
    if (mFp != NULL) {
        return true;
    }

    mkdir(UTL_LOG_DIR, 0755);

    mFp = fopen(UTL_LOG_NAME, "a");
    if (mFp == NULL) {
        return false;
    }

    pthread_mutex_init(&mMux, NULL);

    utl_log_write(UTL_LOG_PRI_INFO, __FILE__, __LINE__, 1, "UTL_LOG", "INIT", "=== UTL_LOG START ===\n");

    return true;
}


bool utl_log_init_stderr(void)
{
    if (mFp != NULL) {
        return true;
    }

    mFp = stderr;

    pthread_mutex_init(&mMux, NULL);

    utl_log_write(UTL_LOG_PRI_INFO, __FILE__, __LINE__, 1, "UTL_LOG", "INIT", "=== UTL_LOG START ===\n");

    return true;
}


bool utl_log_init_stdout(void)
{
    if (mFp != NULL) {
        return true;
    }

    mFp = stdout;

    pthread_mutex_init(&mMux, NULL);

    utl_log_write(UTL_LOG_PRI_INFO, __FILE__, __LINE__, 1, "UTL_LOG", "INIT", "=== UTL_LOG START ===\n");

    return true;
}


void utl_log_term(void)
{
    if (mFp != NULL) {
        fclose(mFp);
        mFp = NULL;
    }
}


void utl_log_write(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const char *pFmt, ...)
{
    if ((mFp == NULL) || (Pri > UTL_LOG_PRI)) {
        return;
    }

    pthread_mutex_lock(&mMux);

    //write log
    va_list ap;
    time_t now = time(NULL);
    char tmstr[UTL_SZ_DTSTR + 1];
    utl_misc_strftime(tmstr, (uint32_t)now);

    va_start(ap, pFmt);
    if (Flag) {
        fprintf(mFp, "%s(%5d)[%c/%s][%s:%d:%s]", tmstr, (int)tid(), M_MARK[Pri - 1], pTag, pFname, Line, pFunc);
    }
    vfprintf(mFp, pFmt, ap);
    va_end(ap);

    fflush(mFp);

    //log rotation
    struct stat buf;
    int retval = stat(UTL_LOG_NAME, &buf);
    if ((retval == 0) && (buf.st_size >= UTL_LOG_SIZE_LIMIT)) {
        fclose(mFp);

        char fname1[FNAME_MAX];
        char fname2[FNAME_MAX];
        sprintf(fname1, "%s.%d", UTL_LOG_NAME, UTL_LOG_MAX - 1);
        remove(fname1);
        for (int lp = UTL_LOG_MAX - 1; lp > 0; lp--) {
            sprintf(fname1, "%s.%d", UTL_LOG_NAME, lp);        //after
            sprintf(fname2, "%s.%d", UTL_LOG_NAME, lp - 1);    //before
            rename(fname2, fname1);
        }
        rename(UTL_LOG_NAME, fname2);

        mFp = fopen(UTL_LOG_NAME, "a");
    }

    pthread_mutex_unlock(&mMux);
}


void utl_log_dump(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len)
{
    char *p_str = (char *)malloc(Len * 2 + 1);
    utl_misc_bin2str(p_str, (const uint8_t *)pData, Len);
    utl_log_write(Pri, pFname, Line, Flag, pTag, pFunc, "%s\n", p_str);
    free(p_str);
}


void utl_log_dump_rev(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len)
{
    char *p_str = (char *)malloc(Len * 2 + 1);
    utl_misc_bin2str_rev(p_str, (const uint8_t *)pData, Len);
    utl_log_write(Pri, pFname, Line, Flag, pTag, pFunc, "%s\n", p_str);
    free(p_str);
}
