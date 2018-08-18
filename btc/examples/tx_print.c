#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "ptarm.h"
#include "mbedtls/sha256.h"

extern bool plog_init_stderr(void);

void ptarm_util_hash160(uint8_t *pHash160, const uint8_t *pData, uint16_t Len);

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
    plog_init_stderr();
    ptarm_init(PTARM_TESTNET, true);

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
    const char TXSTR[] = "02000000000101c5f10f842aa8c57da66f8d7f5a7405feb5aa80505a0b1702ba5052fbd5c9dbed02000000002800000001ace7020000000000160014fb8842d4e461f672c7d2730aef511f0ce026faee03483045022100cc82a015f3414a84eff9f7c7c82e0afcad2ae3adecaa64a9cce8f34248af87a502200c18dbe52cae9055271cba0499605fb2e6befb03e36f983b4c758824045d564601004c6321034328e59c32259384e09a50c7fede31978319baccf6a872203f2095698b035e93670128b2752102f07b2981ef0b6d9d115339a925ac2421fae98847d6315622441d5b109f5ee24a68ac00000000";
    size_t len = strlen(TXSTR);
    uint8_t *tx = (uint8_t *)malloc(len / 2);
    misc_str2bin(tx, len/2, TXSTR);

    const uint8_t byte = 0;
    uint8_t h256[PTARM_SZ_HASH256];
    mbedtls_sha256(&byte, 1, h256, 0);
    mbedtls_sha256(h256, sizeof(h256), h256, 0);
    for (int lp = 0; lp < PTARM_SZ_HASH256; lp++) {
        printf("%02x", h256[lp]);
    }
    printf("\n");
    ptarm_print_rawtx(tx, len/2);

    uint32_t vsize = ptarm_tx_get_vbyte_raw(tx, len/2);
    printf("vsize=%" PRIu32 "\n", vsize);

    free(tx);
#endif

    printf("=======================================\n");

    ptarm_term();

    return 0;
}
