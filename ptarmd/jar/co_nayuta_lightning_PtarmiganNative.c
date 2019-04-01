#include <stdio.h>
#include <inttypes.h>
#include "co_nayuta_lightning_PtarmiganNative.h"


extern int ptarm_start(const char *pAlias, const char *pIpAddr, uint16_t Port);


/*
 * Class:     co_nayuta_lightning_PtarmiganNative
 * Method:    ptarmStart
 * Signature: (Ljava/lang/String;Ljava/lang/String;I)I
 */
JNIEXPORT jint JNICALL Java_co_nayuta_lightning_PtarmiganNative_ptarmStart
  (JNIEnv *env, jclass clazz, jstring alias, jstring ipAddress, jint port)
{
    (void)clazz;

    const char *p_alias = (*env)->GetStringUTFChars(env, alias, 0);
    const char *p_ipaddr = (*env)->GetStringUTFChars(env, ipAddress, 0);
    return ptarm_start(p_alias, p_ipaddr, (uint16_t)port);
}
