#define LOG_TAG "ex"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "btc.h"
#include "utl_log.h"
#include "mbedtls/sha256.h"


static bool misc_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr)
{
    if (strlen(pStr) != BinLen * 2) {
        fprintf(stderr, "fail: invalid buffer size: %zu != %" PRIu32 " * 2\n", strlen(pStr), BinLen);
        return false;
    }

    bool ret = true;

    char str[3];
    str[2] = '\0';
    uint32_t lp;
    for (lp = 0; lp < BinLen; lp++) {
        str[0] = *(pStr + 2 * lp);
        str[1] = *(pStr + 2 * lp + 1);
        if (!str[0]) {
            //偶数文字で\0ならばOK
            break;
        }
        if (!str[1]) {
            //奇数文字で\0ならばNG
            fprintf(stderr, "fail: odd length\n");
            ret = false;
            break;
        }
        char *endp = NULL;
        uint8_t bin = (uint8_t)strtoul(str, &endp, 16);
        if ((endp != NULL) && (*endp != 0x00)) {
            //変換失敗
            fprintf(stderr, "fail: *endp = %p(%02x)\n", endp, *endp);
            ret = false;
            break;
        }
        pBin[lp] = bin;
    }

    return ret;
}

int main(void)
{
    utl_log_init_stderr();
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, true);

#if 0
    printf("=======================================\n");
    const uint8_t SCRIPT[] = {
        0x76, 0xa9, 0x14, 0xb7, 0x67, 0xec, 0xfc, 0xb1,
        0x90, 0x4f, 0x83, 0x52, 0x04, 0x2c, 0xba, 0xb4,
        0x66, 0x52, 0xb6, 0x72, 0xac, 0x83, 0x8b, 0x87,
        0x63, 0xac, 0x67, 0x21, 0x03, 0x3a, 0x16, 0xd2,
        0x7d, 0xc4, 0x6a, 0x52, 0xe6, 0x12, 0x47, 0xe8,
        0x9a, 0x3e, 0xf0, 0xe5, 0xde, 0xcc, 0xcb, 0x88,
        0xa8, 0x31, 0x0a, 0x81, 0xc2, 0xe5, 0xc2, 0x42,
        0xfb, 0x36, 0x57, 0x9f, 0xb6, 0x7c, 0x82, 0x01,
        0x20, 0x87, 0x64, 0x75, 0x52, 0x7c, 0x21, 0x02,
        0x9e, 0x3b, 0xd7, 0x3e, 0xd3, 0xa3, 0x84, 0x22,
        0x2a, 0x8d, 0x15, 0x3f, 0x9c, 0x01, 0x3b, 0x93,
        0x1f, 0x9a, 0xce, 0x2a, 0xcf, 0xb5, 0x7a, 0x87,
        0x5a, 0xff, 0x2d, 0x74, 0x3d, 0x55, 0x4e, 0x7b,
        0x52, 0xae, 0x67, 0xa9, 0x14, 0x87, 0x02, 0xae,
        0x98, 0xc0, 0x4f, 0x3e, 0xd2, 0x4b, 0xdd, 0x95,
        0xd5, 0xe3, 0x63, 0x2e, 0x16, 0x8c, 0xdd, 0x14,
        0x68, 0x88, 0xac, 0x68, 0x68,
    };
    ptarm_print_script(SCRIPT, sizeof(SCRIPT));
#endif

#if 1
    printf("=======================================\n");
    const char TXSTR[] = "0200000001516aef63107e8d4e909e3cd7a8e5b0bef1bd92a6a2a301ea06837ce26404da2a00000000002350528002882e000000000000220020eb474b65fe06d3c94bbf1cf6752859a6da090408e1af72bde932050a192a1bed90340800000000001600141e7cf6d85b86f2aca987b5519871e5891cd9b1d42a247220";
    size_t len = strlen(TXSTR);
    uint8_t *tx = (uint8_t *)UTL_DBG_MALLOC(len / 2);
    misc_str2bin(tx, len/2, TXSTR);

    const uint8_t byte = 0;
    uint8_t h256[BTC_SZ_HASH256];
    mbedtls_sha256(&byte, 1, h256, 0);
    mbedtls_sha256(h256, sizeof(h256), h256, 0);
    for (int lp = 0; lp < BTC_SZ_HASH256; lp++) {
        printf("%02x", h256[lp]);
    }
    printf("\n");
    btc_print_rawtx(tx, len/2);

    uint32_t vsize = btc_tx_get_vbyte_raw(tx, len/2);
    printf("vsize=%" PRIu32 "\n", vsize);

    UTL_DBG_FREE(tx);
#endif

    printf("=======================================\n");

    btc_term();

    return 0;
}
