/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>
#include <assert.h>

#include "mbedtls/sha256.h"

#include "ln_node.h"
#include "segwit_addr.h"

uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
        (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
        (-((b >> 1) & 1) & 0x26508e6dUL) ^
        (-((b >> 2) & 1) & 0x1ea119faUL) ^
        (-((b >> 3) & 1) & 0x3d4233ddUL) ^
        (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const char charset[] = {
    'q', 'p', 'z', 'r', 'y', '9', 'x', '8',
    'g', 'f', '2', 't', 'v', 'd', 'w', '0',
    's', '3', 'j', 'n', '5', '4', 'k', 'h',
    'c', 'e', '6', 'm', 'u', 'a', '7', 'l'
};
static const char *hrp_str[] = {
    "bc", "tb", "BC", "TB", "lnbc", "lntb", "lnbcrt"
};
static const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/** Encode a Bech32 string
 *
 *  Out: output:  Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                will be updated to contain the null-terminated Bech32 string.
 *  In: hrp :     Pointer to the non-null-terminated human readable part(length=2).
 *      data :    Pointer to an array of 5-bit values.
 *      data_len: Length of the data array.
 *  Returns true if successful.
 */
static bool bech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len, bool ln) {
    uint32_t chk = 1;
    size_t i = 0;
    while (hrp[i] != 0) {
        int ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }

        if (ch >= 'A' && ch <= 'Z') return 0;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
        ++i;
    }
    if (!ln && (i + 7 + data_len > 90)) return 0;
    chk = bech32_polymod_step(chk);
    while (*hrp != '\0') {
        chk = bech32_polymod_step(chk) ^ (*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return false;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= 1;
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return true;
}

/** Decode a Bech32 string
 *
 *  Out: hrp:      Pointer to a buffer of size strlen(input) - 6. Will be
 *                 updated to contain the null-terminated human readable part.
 *       data:     Pointer to a buffer of size strlen(input) - 8 that will
 *                 hold the encoded 5-bit data values.
 *       data_len: Pointer to a size_t that will be updated to be the number
 *                 of entries in data.
 *  In: input:     Pointer to a null-terminated Bech32 string.
 *  Returns true if succesful.
 */
static bool bech32_decode(char* hrp, uint8_t *data, size_t *data_len, const char *input, bool ln) {
    uint32_t chk = 1;
    size_t i;
    size_t input_len = strlen(input);
    size_t hrp_len;
    bool have_lower = false, have_upper = false;
    if (ln) {
        if (input_len < (4 + 1 + 7 + 104 + 6)) {
            return false;
        }
    } else {
        if ((input_len < 8) || (90 < input_len)) {
            return false;
        }
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    hrp_len = input_len - (1 + *data_len);
    if (hrp_len < 1 || *data_len < 6) {
        return false;
    }
    *(data_len) -= 6;
    for (i = 0; i < hrp_len; ++i) {
        int ch = input[i];
        if (ch < 33 || ch > 126) {
            return false;
        }
        if (ch >= 'a' && ch <= 'z') {
            have_lower = true;
        } else if (ch >= 'A' && ch <= 'Z') {
            have_upper = true;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
    }
    hrp[i] = 0;
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -1 : charset_rev[(int)input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = true;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = true;
        if (v == -1) {
            return false;
        }
        chk = bech32_polymod_step(chk) ^ v;
        if (i + 6 < input_len) {
            data[i - (1 + hrp_len)] = v;
        }
        ++i;
    }
    if (have_lower && have_upper) {
        return false;
    }
    return chk == 1;
}

//inの先頭からinbitsずつ貯めていき、outbitsを超えるとその分をoutに代入していく
//そのため、
//  inbits:5
//  in [01 0c 12 1f 1c 19 02]
//  outbits:8
//とした場合、out[0x0b 0x25 0xfe 0x64 0x40]が出ていく。
//最後の0x40は最下位bitの0数はinbitsと同じなため、[0x59 0x2f 0xf3 0x22]とはならない。
//その場合は、64bitまでであればconvert_be64()を使用する。
static bool convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, bool pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return false;
    }
    return true;
}

//inbits:5, outbits:8で64bitまで変換可能
static uint64_t convert_be64(const uint8_t *p_data, size_t dlen)
{
    uint64_t ret = 0;
    for (size_t lp = 0; lp < dlen; lp++) {
        ret <<= 5;
        ret |= p_data[lp];
    }
    return ret;
}

//inbits:8, outbits:5で64bitまで変換可能
static int convert64_to8(uint8_t *p_out, uint64_t val)
{
    size_t lp;
    for (lp = 0; lp < sizeof(val); lp++) {
        p_out[lp] = val & 0x1f;
        val >>= 5;
        if (val == 0) {
            break;
        }
    }
    //swap endian
    for (size_t lp2 = 0; lp2 < lp / 2; lp2++) {
        uint8_t tmp = p_out[lp2];
        p_out[lp2] = p_out[lp - lp2];
        p_out[lp - lp2] = tmp;
    }
    return lp + 1;
}

////32進数→10進数変換
//static uint64_t convert_32(const uint8_t *p_data, size_t dlen)
//{
//    uint64_t ret = 0;
//    for (size_t lp = 0; lp < dlen; lp++) {
//        ret *= (uint64_t)32;
//        ret += (uint64_t)p_data[lp];
//    }
//    return ret;
//}

static bool analyze_tag(size_t *p_len, const uint8_t *p_tag, ln_invoice_t *p_invoice_data)
{
    fprintf(stderr, "------------------\n");
    uint8_t tag = *p_tag;
    switch (tag) {
    case 1:
        fprintf(stderr, "[payment_hash]\n");
        break;
    case 13:
        fprintf(stderr, "[purpose of payment(ASCII)]\n");
        break;
    case 19:
        fprintf(stderr, "[pubkey of payee node]\n");
        break;
    case 23:
        fprintf(stderr, "[purpose of payment(SHA256)]\n");
        break;
    case 6:
        fprintf(stderr, "[expiry second]\n");
        break;
    case 24:
        fprintf(stderr, "[min_final_cltv_expiry]\n");
        break;
    case 9:
        fprintf(stderr, "[Fallback on-chain]\n");
        break;
    case 3:
        fprintf(stderr, "[extra routing info]\n");
        break;
    default:
        fprintf(stderr, "unknown tag: %02x\n", *p_tag);
        break;
    }
    fprintf(stderr, "    ");
    int len = p_tag[1] * 0x20 + p_tag[2];
    p_tag += 3;
    uint8_t *p_data = (uint8_t *)malloc((len * 5 + 7) / 8); //確保サイズは切り上げ
    size_t d_len = 0;
    switch (tag) {
    case 6:
        //expiry second
        {
            uint32_t expiry = (uint32_t)convert_be64(p_tag, len);
            fprintf(stderr, "%" PRIu32 " seconds\n", expiry);
        }
        break;
    case 24:
        //min_final_cltv_expiry
        {
            p_invoice_data->min_final_cltv_expiry = convert_be64(p_tag, len);
            fprintf(stderr, "%" PRIu32 " blocks\n", (uint32_t)p_invoice_data->min_final_cltv_expiry);
        }
        break;
    case 3:
        //extra routing info
        if (!convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        if (d_len < 102) return false;

        fprintf(stderr, "\n");
        {
            const uint8_t *p = p_data;

            for (size_t lp2 = 0; lp2 < d_len / 51; lp2++) {
                fprintf(stderr, "-----------\npubkey= ");
                for (size_t lp = 0; lp < 33; lp++) {
                    fprintf(stderr, "%02x", *p++);
                }
                fprintf(stderr, "\n");

                uint64_t short_channel_id = 0;
                for (size_t lp = 0; lp < sizeof(uint64_t); lp++) {
                    short_channel_id <<= 8;
                    short_channel_id |= *p++;
                }
                fprintf(stderr, "short_channel_id= %016" PRIx64 "\n", short_channel_id);

                uint32_t fee_base_msat = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    fee_base_msat <<= 8;
                    fee_base_msat |= *p++;
                }
                fprintf(stderr, "fee_base_msat= %u\n", fee_base_msat);

                uint32_t fee_proportional_millionths = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    fee_proportional_millionths <<= 8;
                    fee_proportional_millionths |= *p++;
                }
                fprintf(stderr, "fee_proportional_millionths= %u\n", fee_proportional_millionths);

                uint16_t cltv_expiry_delta = 0;
                for (size_t lp = 0; lp < sizeof(uint16_t); lp++) {
                    cltv_expiry_delta <<= 8;
                    cltv_expiry_delta |= *p++;
                }
                fprintf(stderr, "cltv_expiry_delta= %d\n", cltv_expiry_delta);
            }
        }
        break;
    default:
        if (!convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        if (tag == 1) {
            memcpy(p_invoice_data->payment_hash, p_data, LN_SZ_HASH);
        }
        if ((tag == 13)) {
            for (size_t lp = 0; lp < d_len; lp++) {
                fprintf(stderr, "%c", p_data[lp]);
            }
        } else {
            for (size_t lp = 0; lp < d_len; lp++) {
                fprintf(stderr, "%02x", p_data[lp]);
            }
        }
    }
    fprintf(stderr, "\n\n");
    free(p_data);

    *p_len = 3 + len;
    return true;
}

bool segwit_addr_encode(char *output, uint8_t hrp_type, int witver, const uint8_t *witprog, size_t witprog_len) {
    uint8_t data[65];
    size_t datalen = 0;
    if (witver > 16) return false;
    if (witver == 0 && witprog_len != 20 && witprog_len != 32) return false;
    if (witprog_len < 2 || witprog_len > 40) return false;
    if ((hrp_type != SEGWIT_ADDR_MAINNET) && (hrp_type != SEGWIT_ADDR_TESTNET)) return false;
    data[0] = witver;
    if (!convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, true)) return false;
    ++datalen;
    return bech32_encode(output, hrp_str[hrp_type], data, datalen, false);
}

bool segwit_addr_decode(int* witver, uint8_t* witdata, size_t* witdata_len, uint8_t hrp_type, const char* addr) {
    uint8_t data[84];
    char hrp_actual[84];
    size_t data_len;
    if ((hrp_type != SEGWIT_ADDR_MAINNET) && (hrp_type != SEGWIT_ADDR_TESTNET)) return false;
    if (!bech32_decode(hrp_actual, data, &data_len, addr, false)) return false;
    if (data_len == 0 || data_len > 65) return false;
    if (strncmp(hrp_str[hrp_type], hrp_actual, 2) != 0) return false;
    if (data[0] > 16) return false;
    *witdata_len = 0;
    if (!convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, false)) return false;
    if (*witdata_len < 2 || *witdata_len > 40) return false;
    if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32) return false;
    *witver = data[0];
    return true;
}


bool ln_invoice_encode(char** pp_invoice, const ln_invoice_t *p_invoice_data) {
    uint8_t data[1024];
    char hrp[128];
    size_t datalen = 0;
    *pp_invoice = NULL;
    if ((p_invoice_data->hrp_type < LN_INVOICE_MAINNET) || (LN_INVOICE_REGTEST < p_invoice_data->hrp_type)) return false;
    strcpy(hrp, hrp_str[p_invoice_data->hrp_type]);
    if (p_invoice_data->amount_msat > 0) {
        //hrpにamount追加
        char unit = '\0';
        uint64_t amount;
        if ((p_invoice_data->amount_msat / (uint64_t)100000000) * (uint64_t)100000000 == p_invoice_data->amount_msat) {
            //mBTC
            unit = 'm';
            amount = p_invoice_data->amount_msat / (uint64_t)100000000;
        } else if ((p_invoice_data->amount_msat / (uint64_t)100000) * (uint64_t)100000 == p_invoice_data->amount_msat) {
            //uBTC
            unit = 'u';
            amount = p_invoice_data->amount_msat / (uint64_t)100000;
        } else if ((p_invoice_data->amount_msat / (uint64_t)100) * (uint64_t)100 == p_invoice_data->amount_msat) {
            //nBTC
            unit = 'n';
            amount = p_invoice_data->amount_msat / (uint64_t)100;
        } else {
            //pBTC
            unit = 'p';
            amount = p_invoice_data->amount_msat * (uint64_t)10;
        }
        char amount_str[20];
        sprintf(amount_str, "%" PRIu64 "%c", amount, unit);
        strcat(hrp, amount_str);
    }

    //timestamp
    time_t now = time(NULL);
    datalen = convert64_to8(data, now);

    //tagged field(payee pubkey)
    data[datalen++] = 0x13; // 33-byte public key of the payee node
    data[datalen++] = 1;  // 264bit --> 53(5bit)
    data[datalen++] = 21;
    if (!convert_bits(data, &datalen, 5, p_invoice_data->pubkey, UCOIN_SZ_PUBKEY, 8, true)) return false;

    //tagged field(payment_hash)
    data[datalen++] = 0x01; // 256-bit SHA256 payment_hash
    data[datalen++] = 1;    // 256bit --> 52(5bit)
    data[datalen++] = 20;
    if (!convert_bits(data, &datalen, 5, p_invoice_data->payment_hash, LN_SZ_HASH, 8, true)) return false;

    //short description
    data[datalen++] = 13; // short description
    data[datalen++] = 0;
    data[datalen++] = 15;
    if (!convert_bits(data, &datalen, 5, (const uint8_t *)"ptarmigan", 9, 8, true)) return false;

    //ここまで、data[0～datalen-1]に1byteずつ5bitデータが入っている
    //署名は、これを詰めて8bitにしてhashを取っている
    uint8_t hashdata[1024];
    size_t hashdatalen = 0;
    strcpy((char *)hashdata, hrp);
    size_t hrp_len = strlen(hrp);
    convert_bits(hashdata + hrp_len, &hashdatalen, 8, data, datalen, 5, true);

    //signature
    uint8_t hash[LN_SZ_HASH];
    mbedtls_sha256(hashdata, hashdatalen + hrp_len, hash, 0);

    uint8_t sign[UCOIN_SZ_SIGN_RS + 1];
    bool ret = ln_node_sign_nodekey(sign, hash);
    if (!ret) return false;

    int recid;
    ret = ucoin_tx_recover_pubkey_id(&recid, p_invoice_data->pubkey, sign, hash);
    if (!ret) return false;
    sign[UCOIN_SZ_SIGN_RS] = (uint8_t)recid;
    if (!convert_bits(data, &datalen, 5, sign, sizeof(sign), 8, true)) return false;

    *pp_invoice = (char *)malloc(2048);
    return bech32_encode(*pp_invoice, hrp, data, datalen, true);
}


bool ln_invoice_decode(ln_invoice_t *p_invoice_data, const char* invoice) {
    bool ret;
    uint8_t data[1024];
    char hrp_actual[86];
    size_t data_len;
    size_t len_hrp;
    if (!bech32_decode(hrp_actual, data, &data_len, invoice, true)) return false;
    if (memcmp(hrp_str[LN_INVOICE_REGTEST], hrp_actual, 6) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_REGTEST;
        len_hrp = 6;
    } else if (memcmp(hrp_str[LN_INVOICE_MAINNET], hrp_actual, 4) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_MAINNET;
        len_hrp = 4;
    } else if (memcmp(hrp_str[LN_INVOICE_TESTNET], hrp_actual, 4) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_TESTNET;
        len_hrp = 4;
    } else {
        return false;
    }
    size_t amt_len = strlen(hrp_actual) - len_hrp;
    if (amt_len > 0) {
        char amount_str[20];

        if ((hrp_actual[len_hrp] < '1') || ('9' < hrp_actual[len_hrp])) return false;
        for (size_t lp = 1; lp < amt_len - 1; lp++) {
            if (!isdigit(hrp_actual[len_hrp + lp])) return false;
        }
        memcpy(amount_str, hrp_actual + len_hrp, amt_len - 1);
        amount_str[amt_len - 1] = '\0';
        char *endptr = NULL;
        uint64_t amount_msat = (uint64_t)strtoull(amount_str, &endptr, 10);
        switch (hrp_actual[len_hrp + amt_len - 1]) {
            case 'm': amount_msat *= (uint64_t)100000000; break;
            case 'u': amount_msat *= (uint64_t)100000; break;
            case 'n': amount_msat *= (uint64_t)100; break;
            case 'p': amount_msat = (uint64_t)(amount_msat * 0.1); break;
            default: return false;
        };
        p_invoice_data->amount_msat = amount_msat;
    } else {
        p_invoice_data->amount_msat = 0;
    }

    /*
     * +-------------------+
     * | "lnbc" or "lntb"  |
     * | (amount)          |
     * +-------------------+
     * | timestamp         |
     * | (tagged fields)   |
     * | signature         |
     * | recovery ID       |
     * | checksum          |
     * +-------------------+
     */
    const uint8_t *p_tag = data + 7;
    const uint8_t *p_sig = data + data_len - 104;

    p_invoice_data->min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;

    //preimage
    uint8_t *pdata = (uint8_t *)malloc(((data_len - 104) * 5 + 7) / 8);
    size_t pdata_len = 0;
    if (!convert_bits(pdata, &pdata_len, 8, data, data_len - 104, 5, true)) return false;
    len_hrp = strlen(hrp_actual);
    size_t total_len = len_hrp + pdata_len;
    uint8_t *preimg = (uint8_t *)malloc(total_len);
    memcpy(preimg, hrp_actual, len_hrp);
    memcpy(preimg + len_hrp, pdata, pdata_len);
    free(pdata);

    //hash
    uint8_t hash[LN_SZ_HASH];
    mbedtls_sha256((uint8_t *)preimg, total_len, hash, 0);
    free(preimg);

    //signature(104 chars)
    uint8_t sig[65];
    size_t sig_len = 0;
    if (!convert_bits(sig, &sig_len, 8, p_sig, 104, 5, false)) return false;
    ret = ucoin_tx_recover_pubkey(p_invoice_data->pubkey, sig[UCOIN_SZ_SIGN_RS], sig, hash);
    if (!ret) {
        return false;
    }

    //timestamp(7 chars)
    time_t tm = (time_t)convert_be64(data, 7);
    p_invoice_data->timestamp = (uint64_t)tm;
    fprintf(stderr, "timestamp= %" PRIu64 " : %s", (uint64_t)tm, ctime(&tm));

    //tagged fields
    ret = true;
    while (p_tag < p_sig) {
        size_t len;
        ret = analyze_tag(&len, p_tag, p_invoice_data);
        if (!ret) {
            break;
        }
        p_tag += len;
    }

    return ret;
}


bool ln_invoice_create(char **ppInvoice, uint8_t Type, const uint8_t *pPayHash, uint64_t Amount)
{
    ln_invoice_t invoice_data;

    invoice_data.hrp_type = Type;
    invoice_data.amount_msat = Amount;
    invoice_data.min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    memcpy(invoice_data.pubkey, ln_node_getid(), UCOIN_SZ_PUBKEY);
    memcpy(invoice_data.payment_hash, pPayHash, LN_SZ_HASH);
    bool ret = ln_invoice_encode(ppInvoice, &invoice_data);
    return ret;
}
