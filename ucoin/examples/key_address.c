#include <stdio.h>
#include <inttypes.h>
#include "ucoin.h"

extern bool ulog_init_stderr(void);


static void pkh2p2wpkh(void)
{
    const uint8_t SPK[] = {
        0xa9, 0x14, 0x46, 0xdf, 0xf3, 0x3f, 0xe8, 0x28,
        0x86, 0x8a, 0x3b, 0x00, 0xb7, 0xb6, 0x17, 0x82,
        0x96, 0x15, 0xf2, 0x31, 0x54, 0xc1, 0x87,
    };

    char addr[UCOIN_SZ_ADDR_MAX];
    ucoin_buf_t BUF_SPK = { (uint8_t *)SPK, sizeof(SPK) };
    bool ret = ucoin_keys_spk2addr(addr, &BUF_SPK);
    if (ret) {
        printf("addr: %s\n", addr);
    }
}


int main(void)
{
    ulog_init_stderr();

    ucoin_init(UCOIN_TESTNET, false);

    pkh2p2wpkh();

    return 0;
}
