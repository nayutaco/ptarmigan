#include <stdio.h>

#include "ucoin.h"


const uint8_t SIG[] = {
    0x30, 0x45, 0x02, 0x21, 0x00, 0x8c, 0x74, 0x92,
    0x3a, 0x8e, 0x9e, 0x98, 0x1f, 0x7e, 0xb8, 0x52,
    0x20, 0x1b, 0x12, 0x35, 0xba, 0xc9, 0xe2, 0xbc,
    0xb1, 0x0a, 0xa6, 0x3b, 0x0b, 0xf2, 0x6e, 0xab,
    0xa5, 0x6a, 0x6b, 0x6d, 0xe3, 0x02, 0x20, 0x03,
    0xc1, 0x41, 0xd0, 0x8f, 0x2c, 0xe0, 0x25, 0x28,
    0x8f, 0xf9, 0x27, 0x49, 0xb5, 0xb3, 0x4e, 0x13,
    0x9c, 0xf2, 0xe7, 0x39, 0x31, 0x30, 0xcf, 0x54,
    0x8b, 0xc3, 0xb6, 0x62, 0xcf, 0x92, 0x29, 0x01,
};

const uint8_t TXHASH[] = {
    0xd9, 0x40, 0xd3, 0x0b, 0xca, 0x1c, 0x9d, 0xe8,
    0xd4, 0x09, 0x9d, 0xe4, 0x1d, 0xb6, 0x7e, 0x46,
    0xfb, 0x23, 0x7f, 0x35, 0xf9, 0x27, 0x3c, 0x96,
    0x05, 0x41, 0x6c, 0x6e, 0xc8, 0x2b, 0x3a, 0xcc,
};

const uint8_t PUB[] = {
    0x03, 0x02, 0xde, 0x08, 0x01, 0xd1, 0x6b, 0x0d,
    0x17, 0x3b, 0x9f, 0xce, 0xd6, 0xec, 0x09, 0x00,
    0xaa, 0xda, 0x2d, 0x7a, 0x44, 0x83, 0x87, 0x1f,
    0x2b, 0x7d, 0xe6, 0x62, 0x90, 0xfb, 0xc8, 0xb0,
    0x7a,
};

int main(void)
{
    ucoin_init(UCOIN_TESTNET, true);

    const ucoin_buf_t sig = { (uint8_t *)SIG, sizeof(SIG) };
    bool ret = ucoin_tx_verify(&sig, TXHASH, PUB);
    printf("ret=%d\n", ret);

    ucoin_term();
    return 0;
}
