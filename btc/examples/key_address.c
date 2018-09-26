#define LOG_TAG "ex"
#include <stdio.h>
#include <inttypes.h>
#include "utl_log.h"
#include "btc.h"
#include "segwit_addr.h"


static void pkh_to_p2wpkh(void)
{
    const uint8_t SPK[] = {
        0xa9, 0x14, 0x46, 0xdf, 0xf3, 0x3f, 0xe8, 0x28,
        0x86, 0x8a, 0x3b, 0x00, 0xb7, 0xb6, 0x17, 0x82,
        0x96, 0x15, 0xf2, 0x31, 0x54, 0xc1, 0x87,
    };

    char addr[BTC_SZ_ADDR_MAX];
    utl_buf_t BUF_SPK = { (uint8_t *)SPK, sizeof(SPK) };
    bool ret = btc_keys_spk2addr(addr, &BUF_SPK);
    if (ret) {
        printf("addr: %s\n", addr);
    }
}


static void bech32wpkh_to_hash(void)
{
    const char ADDR[] = "tb1qaqsemzwmv9guakgchtv53eze70sz45knv7gpyl";

    int ver;
    uint8_t prog[32];
    size_t prog_len = 32;
    bool ret = segwit_addr_decode(&ver, prog, &prog_len, SEGWIT_ADDR_TESTNET, ADDR);
    if (ret) {
        printf("ver: %02x\n", ver);
        printf("prog[%d]: ", (int)prog_len);
        btc_util_dumpbin(stdout, prog, prog_len, true);
    } else {
        printf("fail: segwit_addr_decode\n");
    }

    char addr[BTC_SZ_ADDR_MAX];
    ret = segwit_addr_encode(addr, SEGWIT_ADDR_TESTNET, ver, prog, prog_len);
    if (ret) {
        printf("addr: %s\n", addr);
    } else {
        printf("fail: segwit_addr_encode\n");
    }
}

int main(void)
{
    utl_log_init_stderr();

    btc_init(BTC_TESTNET, false);

    pkh_to_p2wpkh();
    bech32wpkh_to_hash();

    return 0;
}
