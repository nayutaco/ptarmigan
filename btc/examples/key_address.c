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

#if defined(USE_BITCOIN)
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
    bool ret = segwit_addr_decode(&ver, prog, &prog_len, "tb", ADDR);
    if (ret) {
        printf("ver: %02x\n", ver);
        printf("prog[%d]: ", (int)prog_len);
        DUMPD(prog, prog_len);
    } else {
        printf("fail: segwit_addr_decode\n");
    }

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    ret = segwit_addr_encode(addr, "tb", ver, prog, prog_len);
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
#elif defined(USE_ELEMENTS)
static void test_addr_p2pkh(void)
{
    //[P2PKH]
    // $ e1-cli getnewaddress "" legacy
    // CTEpuqxF5toivUfPhbgxn7rUz5bgpzryHFoNwTn3hSpVzMhX5XSuLcgGJ5rMQWq2WucYTwvT7CyrE2Yh
    //
    // $ e1-cli validateaddress CTEpuqxF5toivUfPhbgxn7rUz5bgpzryHFoNwTn3hSpVzMhX5XSuLcgGJ5rMQWq2WucYTwvT7CyrE2Yh
    // {
    // "isvalid": true,
    // "isvalid_parent": false,
    // "address": "CTEpuqxF5toivUfPhbgxn7rUz5bgpzryHFoNwTn3hSpVzMhX5XSuLcgGJ5rMQWq2WucYTwvT7CyrE2Yh",
    // "scriptPubKey": "76a9142e579980831a5532a84afb1711d36062f1485c7188ac",
    // "isscript": false,
    // "iswitness": false,
    // "confidential_key": "02c105973f64fdb72855ded462b2bfd458241875a54ca2b47fabde755a9601f838",
    // "unconfidential": "2ddenQsUruabcPeB2fLNeL3gyswXHFDhBtL"
    // }

    btc_init(BTC_BLOCK_CHAIN_LIQREGTEST, false);

    const uint8_t SPK[] = {
        0x76, 0xa9, 0x14, 0x2e, 0x57, 0x99, 0x80, 0x83,
        0x1a, 0x55, 0x32, 0xa8, 0x4a, 0xfb, 0x17, 0x11,
        0xd3, 0x60, 0x62, 0xf1, 0x48, 0x5c, 0x71, 0x88,
        0xac,
    };
    const char ADDR[] = "2ddenQsUruabcPeB2fLNeL3gyswXHFDhBtL";

    utl_buf_t buf = UTL_BUF_INIT;
    bool ret = btc_keys_addr2spk(&buf, ADDR);
    if (ret) {
        printf("SPK: ");
        DUMPD(buf.buf, buf.len);
        if ((sizeof(SPK) == buf.len) && (memcmp(SPK, buf.buf, sizeof(SPK)) == 0)) {
            printf("OK\n");
        } else {
            printf("fail: scriptPubKey not same\n");
            assert(false);
        }
    } else {
        assert(false);
    }
    utl_buf_free(&buf);

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    const utl_buf_t BUF_SPK = { (CONST_CAST uint8_t *)SPK, sizeof(SPK) };
    ret = btc_keys_spk2addr(addr, &BUF_SPK);
    if (ret) {
        printf("addr: %s\n", addr);
        if (strcmp(addr, ADDR) == 0) {
            printf("OK\n");
        } else {
            printf("fail: Address not same\n");
            assert(false);
        }
    } else {
        assert(false);
    }

    btc_term();
}


static void test_addr_p2sh(void)
{
    //[P2SH]
    // $ e1-cli getnewaddress
    // Azpu6ujNv54tQvmt15JvjgX9iT3wfYew7npTZLYBimbkUVsh39r3ue2NSboeGFVtKe2G9BHLgCGSGfP1
    //
    // $ e1-cli validateaddress Azpu6ujNv54tQvmt15JvjgX9iT3wfYew7npTZLYBimbkUVsh39r3ue2NSboeGFVtKe2G9BHLgCGSGfP1
    // {
    // "isvalid": true,
    // "isvalid_parent": false,
    // "address": "Azpu6ujNv54tQvmt15JvjgX9iT3wfYew7npTZLYBimbkUVsh39r3ue2NSboeGFVtKe2G9BHLgCGSGfP1",
    // "scriptPubKey": "a91415eb80f65014fff067c543d4e1610ccf7712a5a487",
    // "isscript": true,
    // "iswitness": false,
    // "confidential_key": "03762243878fd558befbb066d4f215efdcadab4e9b414eb685350d642235b171c4",
    // "unconfidential": "XDM9AG7JvBvMHhJi79m9F52MaMXPdb5Ro8"
    // }

    btc_init(BTC_BLOCK_CHAIN_LIQREGTEST, false);

    const uint8_t SPK[] = {
        0xa9, 0x14, 0x15, 0xeb, 0x80, 0xf6, 0x50, 0x14,
        0xff, 0xf0, 0x67, 0xc5, 0x43, 0xd4, 0xe1, 0x61,
        0x0c, 0xcf, 0x77, 0x12, 0xa5, 0xa4, 0x87,
    };
    const char ADDR[] = "XDM9AG7JvBvMHhJi79m9F52MaMXPdb5Ro8";

    utl_buf_t buf = UTL_BUF_INIT;
    bool ret = btc_keys_addr2spk(&buf, ADDR);
    if (ret) {
        printf("SPK: ");
        DUMPD(buf.buf, buf.len);
        if ((sizeof(SPK) == buf.len) && (memcmp(SPK, buf.buf, sizeof(SPK)) == 0)) {
            printf("OK\n");
        } else {
            printf("fail: scriptPubKey not same\n");
            assert(false);
        }
    } else {
        assert(false);
    }
    utl_buf_free(&buf);

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    const utl_buf_t BUF_SPK = { (CONST_CAST uint8_t *)SPK, sizeof(SPK) };
    ret = btc_keys_spk2addr(addr, &BUF_SPK);
    if (ret) {
        printf("addr: %s\n", addr);
        if (strcmp(addr, ADDR) == 0) {
            printf("OK\n");
        } else {
            printf("fail: Address not same\n");
            assert(false);
        }
    } else {
        assert(false);
    }

    btc_term();
}


static void test_addr_segwit(void)
{
    //[BECH32]
    // $ e1-cli getnewaddress "" bech32
    // el1qq2akgh05kecfktl64u9w66rgxkh7vxr0k76ejkx9y2j8mjtg29z96kk2qyqlm6c98yzpe95snzra6qeluvg8c8a2keyvvsrnc
    //
    // $ e1-cli validateaddress el1qq2akgh05kecfktl64u9w66rgxkh7vxr0k76ejkx9y2j8mjtg29z96kk2qyqlm6c98yzpe95snzra6qeluvg8c8a2keyvvsrnc
    // {
    // "isvalid": true,
    // "isvalid_parent": false,
    // "address": "el1qq2akgh05kecfktl64u9w66rgxkh7vxr0k76ejkx9y2j8mjtg29z96kk2qyqlm6c98yzpe95snzra6qeluvg8c8a2keyvvsrnc",
    // "scriptPubKey": "00145aca0101fdeb0539041c96909887dd033fe3107c",
    // "isscript": false,
    // "iswitness": true,
    // "witness_version": 0,
    // "witness_program": "5aca0101fdeb0539041c96909887dd033fe3107c",
    // "confidential_key": "02bb645df4b6709b2ffaaf0aed686835afe6186fb7b59958c522a47dc96851445d",
    // "unconfidential": "ert1qtt9qzq0aavznjpquj6gf3p7aqvl7xyruythjue"
    // }

    btc_init(BTC_BLOCK_CHAIN_LIQREGTEST, true);

    const uint8_t SPK[] = {
        0x00, 0x14, 0x5a, 0xca, 0x01, 0x01, 0xfd, 0xeb,
        0x05, 0x39, 0x04, 0x1c, 0x96, 0x90, 0x98, 0x87,
        0xdd, 0x03, 0x3f, 0xe3, 0x10, 0x7c,
    };
    const char ADDR[] = "ert1qtt9qzq0aavznjpquj6gf3p7aqvl7xyruythjue";

    utl_buf_t buf = UTL_BUF_INIT;
    bool ret = btc_keys_addr2spk(&buf, ADDR);
    if (ret) {
        printf("SPK: ");
        DUMPD(buf.buf, buf.len);
        if ((sizeof(SPK) == buf.len) && (memcmp(SPK, buf.buf, sizeof(SPK)) == 0)) {
            printf("OK\n");
        } else {
            printf("fail: scriptPubKey not same\n");
            assert(false);
        }
    } else {
        assert(false);
    }
    utl_buf_free(&buf);

    int ver;
    uint8_t prog[32];
    size_t prog_len = sizeof(prog);
    ret = segwit_addr_decode(&ver, prog, &prog_len, "ert", ADDR);
    if (ret) {
        printf("ver: %02x\n", ver);
        printf("prog[%d]: ", (int)prog_len);
        DUMPD(prog, prog_len);
    } else {
        printf("fail: segwit_addr_decode\n");
        assert(false);
    }

    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    ret = segwit_addr_encode(addr, "ert", ver, prog, prog_len);
    if (ret) {
        printf("addr: %s\n", addr);
        if (strcmp(addr, ADDR) == 0) {
            printf("OK\n");
        } else {
            printf("fail: Address not same\n");
            assert(false);
        }
    } else {
        printf("fail: segwit_addr_encode\n");
        assert(false);
    }

    btc_term();
}

int main(void)
{
    utl_log_init_stdout();

    test_addr_p2pkh();
    test_addr_p2sh();
    test_addr_segwit();

    return 0;
}
#endif
