#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>

#include "segwit_addr.h"
#include "ucoin.h"

#include "segwit_addr.c"

static int get_hrp_type(const char *hrp) {
    if (strcmp(hrp, "bc") == 0) {
        return SEGWIT_ADDR_MAINNET;
    }
    if (strcmp(hrp, "tb") == 0) {
        return SEGWIT_ADDR_TESTNET;
    }
    if (strcmp(hrp, "BC") == 0) {
        return SEGWIT_ADDR_MAINNET2;
    }
    if (strcmp(hrp, "TB") == 0) {
        return SEGWIT_ADDR_TESTNET2;
    }
    printf("hrp=%s\n", hrp);
    assert(0);
    return -1;
}

#if 1
static const char* valid_checksum[] = {
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
};

static const char* invalid_checksum[] = {
    " 1nwldj5",
    "\x7f""1axkwrx",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
};
#endif

struct valid_address_data {
    const char* address;
    size_t scriptPubKeyLen;
    const uint8_t scriptPubKey[42];
};

struct invalid_address_data {
    const char* hrp;
    int version;
    size_t program_length;
};

static struct valid_address_data valid_address[] = {
    {
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        22, {
            0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        }
    },
    {
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        34, {
            0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
            0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
            0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
            0x62
        }
    },
    {
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
        42, {
            0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
            0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
        }
    },
    {
        "BC1SW50QA3JX3S",
        4, {
           0x60, 0x02, 0x75, 0x1e
        }
    },
    {
        "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        18, {
            0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
            0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
        }
    },
    {
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        34, {
            0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
            0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
            0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
            0x33
        }
    }
};

static const char* invalid_address[] = {
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu",
};

static struct invalid_address_data invalid_address_enc[] = {
    {"BC", 0, 20},
    {"bc", 0, 21},
    {"bc", 17, 32},
    {"bc", 1, 1},
    {"bc", 16, 41},
};

// https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md#examples
struct valid_invoice_data {
    const char* invoice;
    const uint8_t privkey[UCOIN_SZ_PRIVKEY];
    const uint8_t pubkey[UCOIN_SZ_PUBKEY];
    const uint8_t payment_hash[UCOIN_SZ_SHA256];
};
static struct valid_invoice_data ln_valid_invoice[] = {
    {
        "lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
    {
        "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
    {
        "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
    {
        "lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
    {
        "lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
    {
        "lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
    {
        "lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
    {
        "lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q28j0v3rwgy9pvjnd48ee2pl8xrpxysd5g44td63g6xcjcu003j3qe8878hluqlvl3km8rm92f5stamd3jw763n3hck0ct7p8wwj463cql26ava",
        { 0xe1, 0x26, 0xf6, 0x8f, 0x7e, 0xaf, 0xcc, 0x8b, 0x74, 0xf5, 0x4d, 0x26, 0x9f, 0xe2, 0x06, 0xbe, 0x71, 0x50, 0x00, 0xf9, 0x4d, 0xac, 0x06, 0x7d, 0x1c, 0x04, 0xa8, 0xca, 0x3b, 0x2d, 0xb7, 0x34 },
        { 0x03, 0xe7, 0x15, 0x6a, 0xe3, 0x3b, 0x0a, 0x20, 0x8d, 0x07, 0x44, 0x19, 0x91, 0x63, 0x17, 0x7e, 0x90, 0x9e, 0x80, 0x17, 0x6e, 0x55, 0xd9, 0x7a, 0x2f, 0x22, 0x1e, 0xde, 0x0f, 0x93, 0x4d, 0xd9, 0xad },
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x02 },
    },
};

static void segwit_scriptpubkey(uint8_t* scriptpubkey, size_t* scriptpubkeylen, int witver, const uint8_t* witprog, size_t witprog_len) {
    scriptpubkey[0] = witver ? (0x50 + witver) : 0;
    scriptpubkey[1] = witprog_len;
    memcpy(scriptpubkey + 2, witprog, witprog_len);
    *scriptpubkeylen = witprog_len + 2;
}

int my_strncasecmp(const char *s1, const char *s2, size_t n) {
    size_t i = 0;
    while (i < n) {
        char c1 = s1[i];
        char c2 = s2[i];
        if (c1 >= 'A' && c1 <= 'Z') c1 = (c1 - 'A') + 'a';
        if (c2 >= 'A' && c2 <= 'Z') c2 = (c2 - 'A') + 'a';
        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
        if (c1 == 0) return 0;
        ++i;
    }
    return 0;
}

void print_invoice(const ln_invoice_t *p_invoice_data) {
    fprintf(stderr, "-----------------------------------------\n");
    switch (p_invoice_data->hrp_type) {
    case LN_INVOICE_MAINNET:
        fprintf(stderr, "for mainnet\n");
        break;
    case LN_INVOICE_TESTNET:
        fprintf(stderr, "for testnet\n");
        break;
    default:
        fprintf(stderr, "unknown hrp_type\n");
    }
    fprintf(stderr, "amount_msat=%" PRIu64 "\n", p_invoice_data->amount_msat);
    time_t tm = (time_t)p_invoice_data->timestamp;
    fprintf(stderr, "timestamp= %" PRIu64 " : %s", (uint64_t)p_invoice_data->timestamp, ctime(&tm));
    fprintf(stderr, "min_final_cltv_expiry=%d\n", p_invoice_data->min_final_cltv_expiry);
    fprintf(stderr, "pubkey=");
    for (int lp = 0; lp < UCOIN_SZ_PUBKEY; lp++) {
        fprintf(stderr, "%02x", p_invoice_data->pubkey[lp]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "payment_hash=");
    for (int lp = 0; lp < LN_SZ_HASH; lp++) {
        fprintf(stderr, "%02x", p_invoice_data->payment_hash[lp]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "-----------------------------------------\n");
}

int main(void) {
    size_t i;
    int fail = 0;
#if 1
    for (i = 0; i < sizeof(valid_checksum) / sizeof(valid_checksum[0]); ++i) {
        uint8_t data[82];
        char rebuild[92];
        char hrp[84];
        size_t data_len;
        int ok = 1;
        if (!bech32_decode(hrp, data, &data_len, valid_checksum[i], false)) {
            printf("bech32_decode fails: '%s'\n", valid_checksum[i]);
            ok = 0;
        }
        if (ok) {
            if (!bech32_encode(rebuild, hrp, data, data_len, false)) {
                printf("bech32_encode fails: '%s'\n", valid_checksum[i]);
                ok = 0;
            }
        }
        if (ok && my_strncasecmp(rebuild, valid_checksum[i], 92)) {
            printf("bech32_encode produces incorrect result: '%s'\n", valid_checksum[i]);
            ok = 0;
        }
        fail += !ok;
    }
    for (i = 0; i < sizeof(invalid_checksum) / sizeof(invalid_checksum[0]); ++i) {
        uint8_t data[82];
        char hrp[84];
        size_t data_len;
        int ok = 1;
        if (bech32_decode(hrp, data, &data_len, invalid_checksum[i], false)) {
            printf("bech32_decode succeeds on invalid string: '%s'\n", invalid_checksum[i]);
            ok = 0;
        }
        fail += !ok;
    }
#endif
#if 1
    for (i = 0; i < sizeof(valid_address) / sizeof(valid_address[0]); ++i) {
        uint8_t witprog[40];
        size_t witprog_len;
        int witver;
        int hrp_type = SEGWIT_ADDR_MAINNET;
        int ok = 1;
        uint8_t scriptpubkey[42];
        size_t scriptpubkey_len;
        char rebuild[93];
        int ret = segwit_addr_decode(&witver, witprog, &witprog_len, hrp_type, valid_address[i].address);
        if (!ret) {
            hrp_type = SEGWIT_ADDR_TESTNET;
            ret = segwit_addr_decode(&witver, witprog, &witprog_len, hrp_type, valid_address[i].address);
        }
        if (!ret) {
            hrp_type = SEGWIT_ADDR_MAINNET2;
            ret = segwit_addr_decode(&witver, witprog, &witprog_len, hrp_type, valid_address[i].address);
        }
        if (!ret) {
            hrp_type = SEGWIT_ADDR_TESTNET2;
            ret = segwit_addr_decode(&witver, witprog, &witprog_len, hrp_type, valid_address[i].address);
        }
        if (!ret) {
            printf("segwit_addr_decode fails: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        if (ok) segwit_scriptpubkey(scriptpubkey, &scriptpubkey_len, witver, witprog, witprog_len);
        if (ok && (scriptpubkey_len != valid_address[i].scriptPubKeyLen || memcmp(scriptpubkey, valid_address[i].scriptPubKey, scriptpubkey_len))) {
            printf("segwit_addr_decode produces wrong result: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        if (ok && !segwit_addr_encode(rebuild, hrp_type, witver, witprog, witprog_len)) {
            printf("segwit_addr_encode fails: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        if (ok && my_strncasecmp(valid_address[i].address, rebuild, 93)) {
            printf("segwit_addr_encode produces wrong result: '%s'\n", valid_address[i].address);
            ok = 0;
        }
        fail += !ok;
    }
    for (i = 0; i < sizeof(invalid_address) / sizeof(invalid_address[0]); ++i) {
        uint8_t witprog[40];
        size_t witprog_len;
        int witver;
        int ok = 1;
        if (segwit_addr_decode(&witver, witprog, &witprog_len, SEGWIT_ADDR_MAINNET, invalid_address[i])) {
            printf("segwit_addr_decode succeeds on invalid address '%s'\n", invalid_address[i]);
            ok = 0;
        }
        if (segwit_addr_decode(&witver, witprog, &witprog_len, SEGWIT_ADDR_TESTNET, invalid_address[i])) {
            printf("segwit_addr_decode succeeds on invalid address '%s'\n", invalid_address[i]);
            ok = 0;
        }
        fail += !ok;
    }
    for (i = 0; i < sizeof(invalid_address_enc) / sizeof(invalid_address_enc[0]); ++i) {
        char rebuild[93];
        static const uint8_t program[42] = {0};
        if (segwit_addr_encode(rebuild, get_hrp_type(invalid_address_enc[i].hrp), invalid_address_enc[i].version, program, invalid_address_enc[i].program_length)) {
            printf("segwit_addr_encode succeeds on invalid input '%s'\n", rebuild);
            ++fail;
        }
    }
#endif
    ln_node_t node;
    ln_node_set(&node);
    for (i = 0; i < sizeof(ln_valid_invoice) / sizeof(ln_valid_invoice[0]); ++i) {
        printf("\n\n=[%d]=============================\n", (int)i);
        int ok = 1;
        ln_invoice_t invoice_data;
        memcpy(node.keys.priv, ln_valid_invoice[i].privkey, UCOIN_SZ_PRIVKEY);
        memcpy(node.keys.pub, ln_valid_invoice[i].pubkey, UCOIN_SZ_PUBKEY);
        bool ret = ln_invoice_decode(&invoice_data, ln_valid_invoice[i].invoice);
        if (ret && (memcmp(invoice_data.pubkey, ln_valid_invoice[i].pubkey, UCOIN_SZ_PUBKEY) == 0)) {
            print_invoice(&invoice_data);
        } else {
            printf("ln_invoice_decode fails: '%s'\n", ln_valid_invoice[i].invoice);
            ok = 0;
        }
        char *p_invoice = NULL;
        if (ok) {
            ret = ln_invoice_encode(&p_invoice, &invoice_data);
            if (!ret) {
                printf("ln_invoice_encode fails\n");
                ok = 0;
            }
        }
        if (ok) {
            ln_invoice_t invoice_data2;
            ret = ln_invoice_decode(&invoice_data2, p_invoice);
            if (ret) {
                print_invoice(&invoice_data2);
                if (invoice_data.hrp_type != invoice_data2.hrp_type) {
                    printf("false: hrp mismatch\n");
                    ok = 0;
                }
                if (ok && (invoice_data.amount_msat != invoice_data2.amount_msat)) {
                    printf("false: amount_msat mismatch\n");
                    ok = 0;
                }
                //if (ok && (invoice_data.timestamp != invoice_data2.timestamp)) {
                //    printf("false: timestamp mismatch\n");
                //    ok = 0;
                //}
                if (ok && (invoice_data.min_final_cltv_expiry != invoice_data2.min_final_cltv_expiry)) {
                    printf("false: min_final_cltv_expiry mismatch\n");
                    ok = 0;
                }
                if (ok && (memcmp(invoice_data.pubkey, invoice_data2.pubkey, UCOIN_SZ_PUBKEY) != 0)) {
                    printf("false: pubkey mismatch\n");
                    ok = 0;
                }
                if (ok && (memcmp(invoice_data.payment_hash, invoice_data2.payment_hash, LN_SZ_HASH) != 0)) {
                    printf("false: payment_hash mismatch\n");
                    ok = 0;
                }
            } else {
                printf("false: decode2\n");
                ok = 0;
            }
        }
        free(p_invoice);
        fail += !ok;
    }

    printf("%i failures\n", fail);
    return fail != 0;
}
