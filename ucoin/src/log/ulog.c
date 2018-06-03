#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>

#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ulog.h"

#define FNAME_MAX       (50)


static inline int tid(void) {
    return (int)syscall(SYS_gettid);
}


static pthread_mutex_t  mMux;
static FILE             *mFp;


bool ulog_init(void)
{
    if (mFp != NULL) {
        return true;
    }

    mkdir(ULOG_DIR, 0755);

    mFp = fopen(ULOG_NAME, "a");
    if (mFp == NULL) {
        return false;
    }

    pthread_mutex_init(&mMux, NULL);

    ulog_write(ULOG_PRI_INFO, __FILE__, __LINE__, 1, "ULOG", "=== ULOG START ===\n");

    return true;
}


bool ulog_init_stderr(void)
{
    if (mFp != NULL) {
        return true;
    }

    mFp = stderr;

    pthread_mutex_init(&mMux, NULL);

    ulog_write(ULOG_PRI_INFO, __FILE__, __LINE__, 1, "ULOG", "=== ULOG START ===\n");

    return true;
}


void ulog_term(void)
{
    if (mFp != NULL) {
        fclose(mFp);
        mFp = NULL;
    }
}


void ulog_write(int Pri, const char* pFname, int Line, int Flag, const char *pTag, const char *pFmt, ...)
{
    if ((mFp == NULL) || (Pri > ULOG_PRI)) {
        return;
    }

    pthread_mutex_lock(&mMux);

    va_list ap;
    time_t now = time(NULL);
    char tmstr[50];
    strftime(tmstr, sizeof(tmstr), "%m/%d %H:%M:%S", localtime(&now)); 

    va_start(ap, pFmt);
    if (Flag) {
        fprintf(mFp, "%s(%d)[%s:%d][%s]", tmstr, (int)tid(), pFname, Line, pTag);
    }
    vfprintf(mFp, pFmt, ap);
    va_end(ap);

    fflush(mFp);

    struct stat buf;
    int retval = stat(ULOG_NAME, &buf);
    if ((retval == 0) && (buf.st_size >= ULOG_SIZE_LIMIT)) {
        fclose(mFp);

        char fname1[FNAME_MAX];
        char fname2[FNAME_MAX];
        sprintf(fname1, "%s.%d", ULOG_NAME, ULOG_MAX - 1);
        remove(fname1);
        for (int lp = ULOG_MAX - 1; lp > 0; lp--) {
            sprintf(fname1, "%s.%d", ULOG_NAME, lp);        //after
            sprintf(fname2, "%s.%d", ULOG_NAME, lp - 1);    //before
            rename(fname2, fname1);
        }
        rename(ULOG_NAME, fname2);

        mFp = fopen(ULOG_NAME, "a");
    }

    pthread_mutex_unlock(&mMux);
}
