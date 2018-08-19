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

#include "misc.h"
#include "plog.h"

#define FNAME_MAX       (50)


static inline int tid(void) {
    return (int)syscall(SYS_gettid);
}


static pthread_mutex_t  mMux;
static FILE             *mFp;


bool plog_init(void)
{
    if (mFp != NULL) {
        return true;
    }

    mkdir(PLOG_DIR, 0755);

    mFp = fopen(PLOG_NAME, "a");
    if (mFp == NULL) {
        return false;
    }

    pthread_mutex_init(&mMux, NULL);

    plog_write(PLOG_PRI_INFO, __FILE__, __LINE__, 1, "PLOG", "INIT", "=== PLOG START ===\n");

    return true;
}


bool plog_init_stderr(void)
{
    if (mFp != NULL) {
        return true;
    }

    mFp = stderr;

    pthread_mutex_init(&mMux, NULL);

    plog_write(PLOG_PRI_INFO, __FILE__, __LINE__, 1, "PLOG", "INIT", "=== PLOG START ===\n");

    return true;
}


bool plog_init_stdout(void)
{
    if (mFp != NULL) {
        return true;
    }

    mFp = stdout;

    pthread_mutex_init(&mMux, NULL);

    plog_write(PLOG_PRI_INFO, __FILE__, __LINE__, 1, "PLOG", "INIT", "=== PLOG START ===\n");

    return true;
}


void plog_term(void)
{
    if (mFp != NULL) {
        fclose(mFp);
        mFp = NULL;
    }
}


void plog_write(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const char *pFmt, ...)
{
    if ((mFp == NULL) || (Pri > PLOG_PRI)) {
        return;
    }

    pthread_mutex_lock(&mMux);

    va_list ap;
    time_t now = time(NULL);
    char tmstr[PTARM_SZ_DTSTR + 1];
    ptarm_util_strftime(tmstr, (uint32_t)now);

    va_start(ap, pFmt);
    if (Flag) {
        fprintf(mFp, "%s(%d)[%s:%d:%s][%s]", tmstr, (int)tid(), pFname, Line, pFunc, pTag);
    }
    vfprintf(mFp, pFmt, ap);
    va_end(ap);

    fflush(mFp);

    struct stat buf;
    int retval = stat(PLOG_NAME, &buf);
    if ((retval == 0) && (buf.st_size >= PLOG_SIZE_LIMIT)) {
        fclose(mFp);

        char fname1[FNAME_MAX];
        char fname2[FNAME_MAX];
        sprintf(fname1, "%s.%d", PLOG_NAME, PLOG_MAX - 1);
        remove(fname1);
        for (int lp = PLOG_MAX - 1; lp > 0; lp--) {
            sprintf(fname1, "%s.%d", PLOG_NAME, lp);        //after
            sprintf(fname2, "%s.%d", PLOG_NAME, lp - 1);    //before
            rename(fname2, fname1);
        }
        rename(PLOG_NAME, fname2);

        mFp = fopen(PLOG_NAME, "a");
    }

    pthread_mutex_unlock(&mMux);
}


void plog_dump(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len)
{
    char *p_str = (char *)malloc(Len * 2 + 1);
    ptarm_util_bin2str(p_str, (const uint8_t *)pData, Len);
    plog_write(Pri, pFname, Line, Flag, pTag, pFunc, "%s\n", p_str);
    free(p_str);
}


void plog_dump_rev(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFunc, const void *pData, size_t Len)
{
    char *p_str = (char *)malloc(Len * 2 + 1);
    ptarm_util_bin2str_rev(p_str, (const uint8_t *)pData, Len);
    plog_write(Pri, pFname, Line, Flag, pTag, pFunc, "%s\n", p_str);
    free(p_str);
}
