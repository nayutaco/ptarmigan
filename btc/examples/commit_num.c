#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "mbedtls/sha256.h"
#include "mbedtls/md.h"

#define M_SZ_OBSCURED_COMMIT_NUM   (6)
#define PTARM_SZ_PUBKEY     (33)


static uint64_t ln_commit_tx_calc_obscured_commit_num_mask(const uint8_t *pLocalBasePt, const uint8_t *pRemoteBasePt)
{
    uint64_t obs = 0;
    uint8_t base[32];
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pLocalBasePt, PTARM_SZ_PUBKEY);
    mbedtls_sha256_update(&ctx, pRemoteBasePt, PTARM_SZ_PUBKEY);
    mbedtls_sha256_finish(&ctx, base);
    mbedtls_sha256_free(&ctx);

    for (int lp = 0; lp < M_SZ_OBSCURED_COMMIT_NUM; lp++) {
        obs <<= 8;
        obs |= base[sizeof(base) - M_SZ_OBSCURED_COMMIT_NUM + lp];
    }

    return obs;
}


int main(void)
{
    uint32_t    sequence = 0x80d86e61;
    uint32_t    locktime = 0x20258269;
    const uint8_t OPEN_CH_PAYMENT_BP[] = {
        0x03, 0xe1, 0x90, 0xf6, 0xcc, 0x84, 0x68, 0x08,
        0xd6, 0x19, 0x94, 0x4f, 0xeb, 0xb1, 0xf2, 0x25,
        0xdd, 0x56, 0x9a, 0x50, 0x54, 0x97, 0x01, 0x89,
        0xf7, 0x4a, 0xdf, 0xbb, 0x42, 0x93, 0xa5, 0xce,
        0x2e,
    };
    const uint8_t ACCEPT_CH_PAYMENT_BP[] = {
        0x02, 0x91, 0x34, 0xe9, 0x0c, 0x2a, 0x49, 0x1b,
        0x06, 0x23, 0x88, 0x59, 0x48, 0x51, 0x1b, 0x58,
        0x7b, 0xc0, 0x2c, 0x2c, 0x9d, 0xf6, 0x60, 0xdf,
        0x6a, 0xd6, 0x31, 0x67, 0x88, 0xb6, 0xbd, 0x5e,
        0x3b,
    };

    uint64_t obscured = ln_commit_tx_calc_obscured_commit_num_mask(OPEN_CH_PAYMENT_BP, ACCEPT_CH_PAYMENT_BP);

    //commitment numberの復元
    uint64_t commit_num = ((uint64_t)(sequence & 0xffffff)) << 24;
    commit_num |= (uint64_t)(locktime & 0xffffff);
    commit_num ^= obscured;
    printf("commit_num=%" PRIu64 "\n", commit_num);
}
