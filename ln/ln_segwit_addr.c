#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <time.h>
#include <assert.h>

#include "mbedtls/sha256.h"

#include "utl_dbg.h"
#include "utl_time.h"

#include "btc_sig.h"
#include "btc_segwit_addr.h"

#include "ln_node.h"
#include "ln_misc.h"
#include "ln_segwit_addr.h"
#include "ln_local.h"

#define M_INVOICE_DESCRIPTION       "ptarmigan"

static const char *ln_hrp_str[] = {
    "bc", "tb", "BC", "TB", "lnbc", "lntb", "lnbcrt"
};

//inの先頭からinbitsずつ貯めていき、outbitsを超えるとその分をoutに代入していく
//そのため、
//  inbits:5
//  in [01 0c 12 1f 1c 19 02]
//  outbits:8
//とした場合、out[0x0b 0x25 0xfe 0x64 0x40]が出ていく。
//最後の0x40は最下位bitの0数はinbitsと同じなため、[0x59 0x2f 0xf3 0x22]とはならない。
//その場合は、64bitまでであればconvert_be64()を使用する。
static bool ln_convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, bool pad) {
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
static uint64_t ln_convert_be64(const uint8_t *p_data, size_t dlen)
{
    uint64_t ret = 0;
    for (size_t lp = 0; lp < dlen; lp++) {
        ret <<= 5;
        ret |= p_data[lp];
    }
    return ret;
}

//inbits:8, outbits:5で64bitまで変換可能
static int ln_convert64_to8(uint8_t *p_out, uint64_t val)
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
    for (size_t lp2 = 0; lp2 < lp; lp2++) {
        if (lp2 > lp - lp2) {
            break;
        }
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

static bool ln_analyze_tag(size_t *p_len, const uint8_t *p_tag, ln_invoice_t **pp_invoice_data)
{
    ln_invoice_t *p_invoice_data = *pp_invoice_data;

    //LOGD("------------------\n");
    uint8_t tag = *p_tag;
    //switch (tag) {
    //case 1:
    //    LOGD("[payment_hash]\n");
    //    break;
    //case 13:
    //    LOGD("[purpose of payment(ASCII)]\n");
    //    break;
    //case 19:
    //    LOGD("[pubkey of payee node]\n");
    //    break;
    //case 23:
    //    LOGD("[purpose of payment(SHA256)]\n");
    //    break;
    //case 6:
    //    LOGD("[expiry second]\n");
    //    break;
    //case 24:
    //    LOGD("[min_final_cltv_expiry]\n");
    //    break;
    //case 9:
    //    LOGD("[Fallback on-chain]\n");
    //    break;
    //case 3:
    //    LOGD("[extra routing info]\n");
    //    break;
    //default:
    //    LOGD("unknown tag: %02x\n", *p_tag);
    //    break;
    //}
    int len = p_tag[1] * 0x20 + p_tag[2];
    p_tag += 3;
    uint8_t *p_data = (uint8_t *)malloc((len * 5 + 7) / 8); //確保サイズは切り上げ
    size_t d_len = 0;
    switch (tag) {
    case 6:
        //expiry second
        {
            p_invoice_data->expiry = (uint32_t)ln_convert_be64(p_tag, len);
            //LOGD("%" PRIu32 " seconds\n", p_invoice_data->expiry);
        }
        break;
    case 24:
        //min_final_cltv_expiry
        {
            p_invoice_data->min_final_cltv_expiry = ln_convert_be64(p_tag, len);
            //LOGD("%" PRIu32 " blocks\n", (uint32_t)p_invoice_data->min_final_cltv_expiry);
        }
        break;
    case 3:
        //extra routing info
        if (!ln_convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        if (d_len < 51) return false;
        d_len /= 51;
        p_invoice_data = (ln_invoice_t *)realloc(p_invoice_data, sizeof(ln_invoice_t) + sizeof(ln_fieldr_t) * d_len);
        p_invoice_data->r_field_num = d_len;

        {
            const uint8_t *p = p_data;

            for (size_t lp2 = 0; lp2 < d_len; lp2++) {
                ln_fieldr_t *p_fieldr = &p_invoice_data->r_field[lp2];

                memcpy(p_fieldr->node_id, p, BTC_SZ_PUBKEY);
                p += BTC_SZ_PUBKEY;

                p_fieldr->short_channel_id = 0;
                for (size_t lp = 0; lp < sizeof(uint64_t); lp++) {
                    p_fieldr->short_channel_id <<= 8;
                    p_fieldr->short_channel_id |= *p++;
                }

                p_fieldr->fee_base_msat = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    p_fieldr->fee_base_msat <<= 8;
                    p_fieldr->fee_base_msat |= *p++;
                }

                p_fieldr->fee_prop_millionths = 0;
                for (size_t lp = 0; lp < sizeof(uint32_t); lp++) {
                    p_fieldr->fee_prop_millionths <<= 8;
                    p_fieldr->fee_prop_millionths |= *p++;
                }

                p_fieldr->cltv_expiry_delta = 0;
                for (size_t lp = 0; lp < sizeof(uint16_t); lp++) {
                    p_fieldr->cltv_expiry_delta <<= 8;
                    p_fieldr->cltv_expiry_delta |= *p++;
                }

                //LOGD("-----------\n");
                //LOGD("pubkey= ");
                //DUMPD(p_fieldr->node_id, BTC_SZ_PUBKEY);
                //LOGD("short_channel_id= %016" PRIx64 "\n", p_fieldr->short_channel_id);
                //LOGD("fee_base_msat= %u\n", p_fieldr->fee_base_msat);
                //LOGD("fee_proportional_millionths= %u\n", p_fieldr->fee_prop_millionths);
                //LOGD("cltv_expiry_delta= %d\n", p_fieldr->cltv_expiry_delta);
            }
            //LOGD("-----------\n");
        }
        break;
    default:
        if (!ln_convert_bits(p_data, &d_len, 8, p_tag, len, 5, true)) return false;
        d_len =  (len * 5) / 8;
        if (tag == 1) {
            memcpy(p_invoice_data->payment_hash, p_data, BTC_SZ_HASH256);
        }
        //if ((tag == 13)) {
        //    char *p_str = (char *)M_ALLOC(d_len + 1);
        //    memcpy(p_str, p_data, d_len);
        //    p_str[d_len - 1] = '\0';
        //    LOGD("%s\n", p_str);
        //    UTL_DBG_FREE(p_str);
        //} else {
        //    DUMPD(p_data, d_len);
        //}
    }
    free(p_data);

    *p_len = 3 + len;
    *pp_invoice_data = p_invoice_data;
    return true;
}

bool ln_invoice_encode(char** pp_invoice, const ln_invoice_t *p_invoice_data) {
    uint8_t data[1024];
    char hrp[128];
    size_t datalen = 0;
    *pp_invoice = NULL;
    if ((p_invoice_data->hrp_type < LN_INVOICE_MAINNET) || (LN_INVOICE_REGTEST < p_invoice_data->hrp_type)) return false;
    strcpy(hrp, ln_hrp_str[p_invoice_data->hrp_type]);
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
    datalen = ln_convert64_to8(data, now);

    //tagged field
    //  1. type (5bits)
    //  2. data_length (10bits, big-endian) [32進数]
    //  3. data (data_length x 5bits)

    //payee pubkey
    data[datalen++] = 19;   // 33-byte public key of the payee node
    data[datalen++] = 1;    // 264bit ÷ 5 ≒ 53
    data[datalen++] = 21;   //      53 --(32進数)--> 32*1 + 21
    if (!ln_convert_bits(data, &datalen, 5, p_invoice_data->pubkey, BTC_SZ_PUBKEY, 8, true)) return false;

    //payment_hash
    data[datalen++] = 1;    // 256-bit SHA256 payment_hash
    data[datalen++] = 1;    // 256bit ÷ 5 ≒ 52
    data[datalen++] = 20;   //      52 --(32進数)--> 32*1 + 20
    if (!ln_convert_bits(data, &datalen, 5, p_invoice_data->payment_hash, BTC_SZ_HASH256, 8, true)) return false;

    //short description
    data[datalen++] = 13;   // short description
    data[datalen++] = 0;    // "ptarmigan": 72bit ÷ 5 ≒ 15
    data[datalen++] = 15;   //      15 --(32進数)--> 32*0 + 15
    if (!ln_convert_bits(data, &datalen, 5, (const uint8_t *)M_INVOICE_DESCRIPTION, 9, 8, true)) return false;

    //expiry
    if (p_invoice_data->expiry != LN_INVOICE_EXPIRY) {
        data[datalen++] = 6;    // expiry
        data[datalen++] = 0;    // 最大32bitなので、ここは0になる
        datalen++;

        int len = ln_convert64_to8(data + datalen, p_invoice_data->expiry);
        data[datalen - 1] = (uint8_t)len;
        datalen += len;
    }

    //min_final_cltv_expiry
    if (p_invoice_data->min_final_cltv_expiry != LN_MIN_FINAL_CLTV_EXPIRY) {
        data[datalen++] = 24;   // min_final_cltv_expiry
        data[datalen++] = 0;    // 最大32bitなので、ここは0になる
        datalen++;

        int len = ln_convert64_to8(data + datalen, p_invoice_data->min_final_cltv_expiry);
        data[datalen - 1] = (uint8_t)len;
        datalen += len;
    }

    //r field
    if (p_invoice_data->r_field_num > 0) {
        // 1項目=408bit
        int bits = 408 * p_invoice_data->r_field_num;
        bits = (bits + 4) / 5;
        int p32 = bits / 32;

        data[datalen++] = 3;    // r field
        data[datalen++] = (uint8_t)p32;
        data[datalen++] = (uint8_t)(bits - p32 * 32);
        uint8_t *rfield = (uint8_t *)UTL_DBG_MALLOC(51 * p_invoice_data->r_field_num);     //408bit * n分
        utl_buf_t buf = { rfield, (uint32_t)(51 * p_invoice_data->r_field_num) };
        utl_push_t push = { 0, &buf };
        for (int lp = 0; lp < p_invoice_data->r_field_num; lp++) {
            const ln_fieldr_t *r = &p_invoice_data->r_field[lp];

            utl_push_data(&push, r->node_id, BTC_SZ_PUBKEY);
            ln_misc_push64be(&push, r->short_channel_id);
            ln_misc_push32be(&push, r->fee_base_msat);
            ln_misc_push32be(&push, r->fee_prop_millionths);
            ln_misc_push16be(&push, r->cltv_expiry_delta);
        }
        bool ret = ln_convert_bits(data, &datalen, 5, rfield, push.pos, 8, true);
        UTL_DBG_FREE(rfield);
        if (!ret) return false;
    }

    //ここまで、data[0～datalen-1]に1byteずつ5bitデータが入っている
    //署名は、これを詰めて8bitにしてhashを取っている
    uint8_t hashdata[1024];
    size_t hashdatalen = 0;
    strcpy((char *)hashdata, hrp);
    size_t hrp_len = strlen(hrp);
    ln_convert_bits(hashdata + hrp_len, &hashdatalen, 8, data, datalen, 5, true);

    //signature
    uint8_t hash[BTC_SZ_HASH256];
    mbedtls_sha256(hashdata, hashdatalen + hrp_len, hash, 0);

    uint8_t sign[BTC_SZ_SIGN_RS + 1];
    bool ret = ln_node_sign_nodekey(sign, hash);
    if (!ret) return false;

    int recid;
    ret = btc_sig_recover_pubkey_id(&recid, p_invoice_data->pubkey, sign, hash);
    if (!ret) return false;
    sign[BTC_SZ_SIGN_RS] = (uint8_t)recid;
    if (!ln_convert_bits(data, &datalen, 5, sign, sizeof(sign), 8, true)) return false;

    *pp_invoice = (char *)malloc(2048);
    return btc_bech32_encode(*pp_invoice, 2048, hrp, data, datalen, true);
}


bool ln_invoice_decode(ln_invoice_t **pp_invoice_data, const char* invoice) {
    bool ret = false;
    uint8_t data[1024];
    char hrp_actual[86];
    size_t data_len;
    size_t len_hrp;
    size_t amt_len;
    const uint8_t *p_tag;
    const uint8_t *p_sig;
    uint8_t *pdata;
    size_t pdata_len = 0;
    size_t total_len;
    uint8_t *preimg;
    uint8_t hash[BTC_SZ_HASH256];
    time_t tm;
    uint8_t sig[65];
    size_t sig_len = 0;
    ln_invoice_t *p_invoice_data = (ln_invoice_t *)malloc(sizeof(ln_invoice_t));

    data_len = sizeof(data);
    if (!btc_bech32_decode(hrp_actual, sizeof(hrp_actual), data, &data_len, invoice, true)) {
        goto LABEL_EXIT;
    }
    if (memcmp(ln_hrp_str[LN_INVOICE_REGTEST], hrp_actual, 6) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_REGTEST;
        len_hrp = 6;
    } else if (memcmp(ln_hrp_str[LN_INVOICE_MAINNET], hrp_actual, 4) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_MAINNET;
        len_hrp = 4;
    } else if (memcmp(ln_hrp_str[LN_INVOICE_TESTNET], hrp_actual, 4) == 0) {
        p_invoice_data->hrp_type = LN_INVOICE_TESTNET;
        len_hrp = 4;
    } else {
        goto LABEL_EXIT;
    }
    amt_len = strlen(hrp_actual) - len_hrp;
    if (amt_len > 0) {
        char amount_str[20];

        if ((hrp_actual[len_hrp] < '1') || ('9' < hrp_actual[len_hrp])) {
            goto LABEL_EXIT;
        }
        for (size_t lp = 1; lp < amt_len - 1; lp++) {
            if (!isdigit(hrp_actual[len_hrp + lp])) {
                goto LABEL_EXIT;
            }
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
            default:
                goto LABEL_EXIT;
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
    p_tag = data + 7;
    p_sig = data + data_len - 104;

    //preimage
    pdata = (uint8_t *)UTL_DBG_MALLOC(((data_len - 104) * 5 + 7) / 8);
    if (!ln_convert_bits(pdata, &pdata_len, 8, data, data_len - 104, 5, true)) {
        UTL_DBG_FREE(pdata);
        goto LABEL_EXIT;
    }
    len_hrp = strlen(hrp_actual);
    total_len = len_hrp + pdata_len;
    preimg = (uint8_t *)UTL_DBG_MALLOC(total_len);
    memcpy(preimg, hrp_actual, len_hrp);
    memcpy(preimg + len_hrp, pdata, pdata_len);
    UTL_DBG_FREE(pdata);

    //hash
    mbedtls_sha256((uint8_t *)preimg, total_len, hash, 0);
    UTL_DBG_FREE(preimg);

    //signature(104 chars)
    if (!ln_convert_bits(sig, &sig_len, 8, p_sig, 104, 5, false)) {
        goto LABEL_EXIT;
    }
    ret = btc_sig_recover_pubkey(p_invoice_data->pubkey, sig[BTC_SZ_SIGN_RS], sig, hash);
    if (!ret) {
        goto LABEL_EXIT;
    }

    //timestamp(7 chars)
    tm = (time_t)ln_convert_be64(data, 7);
    p_invoice_data->timestamp = (uint64_t)tm;
    char time[UTL_SZ_TIME_FMT_STR + 1];
    LOGD("timestamp= %" PRIu64 " : %s\n", (uint64_t)tm, utl_time_fmt(time, tm));

    //tagged fields
    ret = true;
    p_invoice_data->expiry = LN_INVOICE_EXPIRY;
    p_invoice_data->min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    p_invoice_data->r_field_num = 0;
    while (p_tag < p_sig) {
        size_t len;
        ret = ln_analyze_tag(&len, p_tag, &p_invoice_data);
        if (!ret) {
            break;
        }
        p_tag += len;
    }

LABEL_EXIT:
    if (ret) {
        *pp_invoice_data = p_invoice_data;
    } else {
        free(p_invoice_data);
        *pp_invoice_data = NULL;
    }
    return ret;
}


bool ln_invoice_create(char **ppInvoice, uint8_t Type, const uint8_t *pPayHash, uint64_t Amount, uint32_t Expiry,
                        const ln_fieldr_t *pFieldR, uint8_t FieldRNum, uint32_t MinFinalCltvExpiry)
{
    ln_invoice_t *p_invoice_data;

    size_t sz = sizeof(ln_invoice_t);
    if (pFieldR != NULL) {
        sz += sizeof(ln_fieldr_t) * FieldRNum;
    }
    p_invoice_data = (ln_invoice_t *)UTL_DBG_MALLOC(sz);
    p_invoice_data->hrp_type = Type;
    p_invoice_data->amount_msat = Amount;
    p_invoice_data->expiry = Expiry;
    p_invoice_data->min_final_cltv_expiry = MinFinalCltvExpiry;
    memcpy(p_invoice_data->pubkey, ln_node_getid(), BTC_SZ_PUBKEY);
    memcpy(p_invoice_data->payment_hash, pPayHash, BTC_SZ_HASH256);
    p_invoice_data->r_field_num = FieldRNum;
    memcpy(p_invoice_data->r_field, pFieldR, sizeof(ln_fieldr_t) * FieldRNum);

    bool ret = ln_invoice_encode(ppInvoice, p_invoice_data);
    UTL_DBG_FREE(p_invoice_data);

    return ret;
}
