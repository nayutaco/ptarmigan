#define LOG_TAG "ex"
#include <stdio.h>
#include <inttypes.h>
#include "utl_log.h"
#include "btc.h"
#include "btc_tx.h"
#include "btc_keys.h"
#include "btc_sw.h"
#include "segwit_addr.h"

#define DUMP(dt,ln)     utl_log_dump(UTL_LOG_PRI_ERR, __FILE__, __LINE__, 0, "example", __func__, dt, ln)
#define START           printf("\n\n***** %s *****\n", __func__);

static void pkh_to_p2wpkh(void)
{
    START
    const uint8_t SPK[] = {
        0xa9, 0x14, 0x46, 0xdf, 0xf3, 0x3f, 0xe8, 0x28,
        0x86, 0x8a, 0x3b, 0x00, 0xb7, 0xb6, 0x17, 0x82,
        0x96, 0x15, 0xf2, 0x31, 0x54, 0xc1, 0x87,
    };

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    utl_buf_t BUF_SPK = { (uint8_t *)SPK, sizeof(SPK) };
    bool ret = btc_keys_spk2addr(addr, &BUF_SPK);
    if (ret) {
        printf("addr: %s\n", addr);
    }
}


static void bech32wpkh_to_hash(void)
{
    START
    const char ADDR[] = "tb1qaqsemzwmv9guakgchtv53eze70sz45knv7gpyl";

    int ver;
    uint8_t prog[32];
    size_t prog_len = 32;
    bool ret = segwit_addr_decode(&ver, prog, &prog_len, SEGWIT_ADDR_TESTNET, ADDR);
    if (ret) {
        printf("ver: %02x\n", ver);
        printf("prog[%d]: ", (int)prog_len);
        DUMP(prog, prog_len);
    } else {
        printf("fail: segwit_addr_decode\n");
    }

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    ret = segwit_addr_encode(addr, SEGWIT_ADDR_TESTNET, ver, prog, prog_len);
    if (ret) {
        printf("addr: %s\n", addr);
    } else {
        printf("fail: segwit_addr_encode\n");
    }
}

//witnessScript ==> native scriptPubKey
static void witness_to_spk(void)
{
    START
    const uint8_t WITNESS_SCRIPT[] = {
        // 0x51, 0x21, 0x02, 0xa1, 0xec, 0xf6, 0xb4, 0x4b,
        // 0x0b, 0x4b, 0x6c, 0xbd, 0x63, 0x4d, 0x46, 0xd8,
        // 0x23, 0x3f, 0x0c, 0x3f, 0x7f, 0xc8, 0xc2, 0x57,
        // 0x72, 0xbe, 0x47, 0xdd, 0xda, 0xe7, 0xc9, 0x9f,
        // 0xe7, 0xb2, 0xc8, 0x51, 0xae,
        0x51, 0x21, 0x03, 0xcd, 0x2a, 0xec, 0x5b, 0x56,
        0x46, 0x7a, 0x2f, 0x74, 0x79, 0x01, 0x52, 0x18,
        0x64, 0x9b, 0x14, 0x3d, 0xd9, 0x4d, 0xf3, 0x11,
        0xeb, 0x24, 0x15, 0xac, 0x89, 0xd9, 0xe1, 0xb2,
        0x01, 0xef, 0xa7, 0x51, 0xae,
    };
    const utl_buf_t buf = { .buf = (CONST_CAST uint8_t*)WITNESS_SCRIPT, .len = sizeof(WITNESS_SCRIPT) };
    uint8_t wit_prog[BTC_SZ_WITPROG_P2WSH];
    btc_sw_wit2prog_p2wsh(wit_prog, &buf);
    printf("prog: ");
    DUMP(wit_prog, sizeof(wit_prog));
}

int main(void)
{
    utl_log_init_stdout();

    btc_init(BTC_BLOCK_CHAIN_BTCTEST, false);

    pkh_to_p2wpkh();
    bech32wpkh_to_hash();
    witness_to_spk();

    return 0;
}
