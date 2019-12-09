#define LOG_TAG "ex"
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "btc.h"
#include "btc_crypto.h"
#include "btc_tx.h"
#include "utl_log.h"
#include "utl_dbg.h"
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
#if defined(USE_BITCOIN)
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, true);
#elif defined(USE_ELEMENTS)
    btc_init(BTC_BLOCK_CHAIN_LIQREGTEST, true);
#endif

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
#if defined(USE_BITCOIN)
    //testnet: 364451d26ede19bf9af66766c73dad221410a52bb7ab2601cd26ac91f23a1c9a
    //  weight=669byte
    //  vsize=168byte
    const char TXSTR[] = "020000000001014859f84e131cb30c0258b685867abc9fd813841d4415307a81cdff515f0b16630100000017160014ad3bac99120815f8dfd72f8eb3129a69c97da900feffffff02a4942d040000000017a9140ab15aebc79f1610a181ce0fc165c351dd955e248740420f00000000001976a9143e8720f6486b4e6681e802a955be61b46fbb6e5788ac02473044022012f9ff774b07ddd87a71fc6a85a8dbcab86edd55ac34320f952c06f883c8847d02201953be46b8d89302b0cdfb797e72e9befd6dcb02796569505e75f45a7fd320f6012103e64c663159fe5bbf699a5979bef59fa1fed13303e8c7f6baaeefdaf3e93b551f5da51400";
#elif defined(USE_ELEMENTS)
    //elementsregtest: 5d25915f3ddc914832c1c85e213ee87d7e316d5c69cacc895f644cd257d7568d
    //  weight=1128byte
    //  vsize=282byte
    const char TXSTR[] = "020000000101200414c08a781527c56c8ce492a011d8e13f4d1969191b35e8321e6e9fce7be20000000017160014d187d71e28111ed4da49784fed999578fcd56c49fdffffff0301230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010003baf8270dbf000017a91454dd3bfc29ca216f6144cef1c24d89bf6fb2a6e98701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b2010000000005f569000017a91400c7dd68a8cc06ecd92a838c58f8a9ed2a6669af8701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000160800002e01000000000247304402204cb4b94a4a009f74b676637f7ec385fd2340378da91324e81f9dd363c679dabe02203d78d14089010c5cd1b1dad82ec4b058af0cfeaec928c06a4efd37fb391676dd0121032f7789f47f68b30abea8d1b59b5801d89951482d55f800996ca9bfe6bf74262f00000000000000";
#endif
    size_t len = strlen(TXSTR);
    uint8_t *tx = (uint8_t *)malloc(len / 2);
    misc_str2bin(tx, len/2, TXSTR);

    const uint8_t byte = 0;
    uint8_t h256[BTC_SZ_HASH256];
    mbedtls_sha256(&byte, 1, h256, 0);
    mbedtls_sha256(h256, sizeof(h256), h256, 0);
    for (int lp = 0; lp < BTC_SZ_HASH256; lp++) {
        printf("%02x", h256[lp]);
    }
    printf("\n");
    btc_tx_print_raw(tx, len/2);

    uint32_t vsize = btc_tx_get_vbyte_raw(tx, len/2);
    printf("vsize=%" PRIu32 "\n", vsize);

    free(tx);
#endif

    printf("=======================================\n");

    btc_term();

    return 0;
}
