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
#include "utl_mem.h"
#include "utl_int.h"

#include "btc_sig.h"
#include "btc_segwit_addr.h"
#include "btc_buf.h"

#include "ln_node.h"
#include "ln_misc.h"
#include "ln_segwit_addr.h"
#include "ln_local.h"

#define M_INVOICE_DESCRIPTION       "ptarmigan"
#define M_SZ_SIG                    (BTC_SZ_SIGN_RS + 1) //with the recovery id
#define M_SZ_TIMESTAMP_5BIT_BYTE    (7)
#define M_SZ_SIG_5BIT_BYTE          (104)
#define M_5BIT_BYTES_LEN(bits)      (((bits) + 4) / 5)
#define M_SZ_R_FIELD                (51)

#define M_NUMBER_100THOUSAND        100000
#define M_NUMBER_100MILION          100000000
#define M_NUMBER_100BILLION         UINT64_C(100000000000)

#define M_SZ_PREFIX_MAX             (16)

static const char *ln_prefix_str[] = {
    "bc", "tb", "BC", "TB", "lnbc", "lntb", "lnbcrt"
};

//inbits:5, outbits:8, to u64
static uint64_t convert_bits_5to8_value(const uint8_t *p_data, size_t dlen)
{
    assert(dlen <= (64 / 5));

    uint64_t ret = 0;
    for (size_t lp = 0; lp < dlen; lp++) {
        ret <<= 5;
        ret |= p_data[lp];
    }
    return ret;
}

static bool convert_bits_5to8_value_u32(uint32_t *u32, const uint8_t *p_data, size_t dlen)
{
    if (dlen > (32 / 5)) return false;

    *u32 = 0;
    for (size_t lp = 0; lp < dlen; lp++) {
        *u32 <<= 5;
        *u32 |= p_data[lp];
    }
    return true;
}

#if 0
static bool convert_bits_5to8_value_u64(uint64_t *u64, const uint8_t *p_data, size_t dlen)
{
    if (dlen > (64 / 5)) return false;

    *u64 = 0;
    for (size_t lp = 0; lp < dlen; lp++) {
        *u64 <<= 5;
        *u64 |= p_data[lp];
    }
    return true;
}
#endif

static int convert_bits_8to5_value_len(uint64_t val)
{
    assert(val);

    int lp;
    for (lp = 0; lp < 8; lp++) {
        val >>= 5;
        if (!val) break;
    }
    return lp + 1;
}

static int convert_bits_8to5_value(uint8_t *p_out, uint64_t val)
{
    int len = convert_bits_8to5_value_len(val);
    assert(len);
    for (int lp2 = len - 1; lp2 >= 0; lp2--) {
        p_out[lp2] = val & 0x1f;
        val >>= 5;
    }
    return len;
}

static void convert_bits_8to5_value_10bits(uint8_t *p_out_2bytes, uint16_t val)
{
    assert(!(val >> 10));
    p_out_2bytes[0] = (val >> 5) & 0x1f;
    p_out_2bytes[1] = val & 0x1f;
}

#if 0
static void print_type(uint8_t type)
{
    switch (type) {
    case 1:
        LOGD("[payment_hash]\n");
        break;
    case 13:
        LOGD("[purpose of payment(ASCII)]\n");
        break;
    case 19:
        LOGD("[pubkey of payee node]\n");
        break;
    case 23:
        LOGD("[purpose of payment(SHA256)]\n");
        break;
    case 6:
        LOGD("[expiry second]\n");
        break;
    case 24:
        LOGD("[min_final_cltv_expiry]\n");
        break;
    case 9:
        LOGD("[fallback on-chain]\n");
        break;
    case 3:
        LOGD("[extra routing info]\n");
        break;
    default:
        LOGD("unknown type: %02x\n", type);
        break;
    }
}
#endif

static bool analyze_tagged_field(btc_buf_r_t *p_parts, ln_invoice_t **pp_invoice_data)
{
    bool ret = false;
    size_t tmp_len = 0;
    ln_invoice_t *p_invoice_data = *pp_invoice_data;

    uint8_t type;
    uint32_t data_length;
    uint8_t *p_data;

    //LOGD("------------------\n");

    if (btc_buf_r_remains(p_parts) < 3) return false;
    if (!btc_buf_r_read_byte(p_parts, &type)) return false;
    //print_type(type);

    if (!convert_bits_5to8_value_u32(&data_length, btc_buf_r_get_pos(p_parts), 2)) return false;
    if (!btc_buf_r_seek(p_parts, 2)) return false;
    if (btc_buf_r_remains(p_parts) < data_length) return false;

    p_data = (uint8_t *)UTL_DBG_MALLOC(data_length);
    if (!p_data) return false;

    switch (type) {
    //p (1): data_length 52. 256-bit SHA256 payment_hash. Preimage of this provides proof of payment
    case 1:
        if (data_length != 52) break;
        tmp_len = 0;
        if (!btc_convert_bits_5to8(p_data, &tmp_len, btc_buf_r_get_pos(p_parts), data_length, true)) goto LABEL_EXIT;
        memcpy(p_invoice_data->payment_hash, p_data, BTC_SZ_HASH256);
        break;

    //d (13): data_length variable. Short description of purpose of payment (UTF-8)
    //case 13: break; //XXX: check description existence

    //n (19): data_length 53. 33-byte public key of the payee node
    //case 19: break; //XXX: use the public key

    //h (23): data_length 52. 256-bit description of purpose of payment (SHA256)
    //case 23: break;

    //x (6): data_length variable. expiry time in seconds (big-endian)
    case 6:
        if (!convert_bits_5to8_value_u32(&p_invoice_data->expiry, btc_buf_r_get_pos(p_parts), data_length)) goto LABEL_EXIT;
        //LOGD("%" PRIu32 " seconds\n", p_invoice_data->expiry);
        break;

    //c (24): data_length variable. min_final_cltv_expiry to use for the last HTLC in the route
    case 24:
        if (!convert_bits_5to8_value_u32(&p_invoice_data->min_final_cltv_expiry, btc_buf_r_get_pos(p_parts), data_length)) goto LABEL_EXIT;
        //LOGD("%" PRIu32 " blocks\n", (uint32_t)p_invoice_data->min_final_cltv_expiry);
        break;

    //f (9): data_length variable, depending on version
    //case 9: break;

    //r (3): data_length variable. One or more entries containing extra routing information for a private route;
    // there may be more than one r field
    case 3:
        {
            uint32_t n;
            btc_buf_r_t buf_r;

            //XXX: don't support multi r
            if (p_invoice_data->r_field_num) break;

            if (!data_length) goto LABEL_EXIT;
            tmp_len = 0;
            if (!btc_convert_bits_5to8(p_data, &tmp_len, btc_buf_r_get_pos(p_parts), data_length, true)) goto LABEL_EXIT;
            if (tmp_len < M_SZ_R_FIELD) goto LABEL_EXIT;
            n = tmp_len / M_SZ_R_FIELD;
            p_invoice_data = (ln_invoice_t *)UTL_DBG_REALLOC(
                p_invoice_data,
                sizeof(ln_invoice_t) + sizeof(ln_fieldr_t) * n);
            p_invoice_data->r_field_num = n;

            btc_buf_r_init(&buf_r, p_data, tmp_len);

            for (size_t lp = 0; lp < n; lp++) {
                ln_fieldr_t *p_fieldr = &p_invoice_data->r_field[lp];
                if (!btc_buf_r_read(&buf_r, p_fieldr->node_id, BTC_SZ_PUBKEY)) goto LABEL_EXIT;
                if (!btc_buf_r_read_u64be(&buf_r, &p_fieldr->short_channel_id)) goto LABEL_EXIT;
                if (!btc_buf_r_read_u32be(&buf_r, &p_fieldr->fee_base_msat)) goto LABEL_EXIT;
                if (!btc_buf_r_read_u32be(&buf_r, &p_fieldr->fee_prop_millionths)) goto LABEL_EXIT;
                if (!btc_buf_r_read_u16be(&buf_r, &p_fieldr->cltv_expiry_delta)) goto LABEL_EXIT;

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
        ;
    }

    if (!btc_buf_r_seek(p_parts, data_length)) goto LABEL_EXIT;
    *pp_invoice_data = p_invoice_data; //for realloc

    ret = true;

LABEL_EXIT:
    if (p_data) UTL_DBG_FREE(p_data);
    return ret;
}

bool ln_invoice_encode(char** pp_invoice, const ln_invoice_t *p_invoice_data) {
    uint8_t data[1024]; //XXX: malloc
    char hrp[M_SZ_PREFIX_MAX + M_UINT64_MAX_DIGIT + 1]; //prefix | amount | multiplier
    size_t data_len = 0;
    *pp_invoice = NULL;

    if (p_invoice_data->hrp_type != LN_INVOICE_MAINNET &&
        p_invoice_data->hrp_type != LN_INVOICE_TESTNET &&
        p_invoice_data->hrp_type != LN_INVOICE_REGTEST) return false;

    //prefix
    strcpy(hrp, ln_prefix_str[p_invoice_data->hrp_type]);

    //amount
    // 1BTC = 10 ^ 8 Satoshi
    // 1BTC = 10 ^ 11 MilliSatoshi
    if (p_invoice_data->amount_msat) { //XXX: test
        char multiplier = '\0';
        uint64_t amount;
        if (!(p_invoice_data->amount_msat % M_NUMBER_100BILLION)) { //10 ^ 11
            multiplier = '\0';
            amount = p_invoice_data->amount_msat / M_NUMBER_100BILLION;
        } else if (!(p_invoice_data->amount_msat % M_NUMBER_100MILION)) { //10 ^ 8
            //milli 10 ^ -3
            //  10 ^ (11 - 3)
            multiplier = 'm';
            amount = p_invoice_data->amount_msat / M_NUMBER_100MILION;
        } else if (!(p_invoice_data->amount_msat % M_NUMBER_100THOUSAND)) { //10 ^ 5
            //micro 10 ^ -6
            //  10 ^ (11 - 6)
            multiplier = 'u';
            amount = p_invoice_data->amount_msat / M_NUMBER_100THOUSAND;
        } else if (!(p_invoice_data->amount_msat % 100)) { //10 ^ 2
            //nano 10 ^ -9
            //  10 ^ (11 - 9)
            multiplier = 'n';
            amount = p_invoice_data->amount_msat / 100;
        } else { //10 ^ -1
            //pico 10 ^ -12
            //  10 ^ (11 - 12)
            multiplier = 'p';
            amount = p_invoice_data->amount_msat * 10;
        }
        char amount_str[M_UINT64_MAX_DIGIT];
        sprintf(amount_str, "%" PRIu64 "%c", amount, multiplier);
        strcat(hrp, amount_str);
    }

    //timestamp
    data_len = convert_bits_8to5_value(data, utl_time_time());

    //tagged field
    //  1. type (5bits)
    //  2. data_length (10bits, big-endian)
    //  3. data (data_length x 5bits)

    //33-byte public key of the payee node
    data[data_len++] = 19; //type
    convert_bits_8to5_value_10bits(data + data_len, M_5BIT_BYTES_LEN(264));
    data_len += 2;
    if (!btc_convert_bits_8to5(data, &data_len, p_invoice_data->pubkey, BTC_SZ_PUBKEY, true)) return false;

    //256-bit SHA256 payment_hash
    data[data_len++] = 1; //type
    convert_bits_8to5_value_10bits(data + data_len, M_5BIT_BYTES_LEN(256));
    data_len += 2;
    if (!btc_convert_bits_8to5(data, &data_len, p_invoice_data->payment_hash, BTC_SZ_HASH256, true)) return false;

    //short description
    data[data_len++] = 13; //type
    convert_bits_8to5_value_10bits(data + data_len, M_5BIT_BYTES_LEN(strlen(M_INVOICE_DESCRIPTION) * 8));
    data_len += 2;
    if (!btc_convert_bits_8to5(data, &data_len, (const uint8_t *)M_INVOICE_DESCRIPTION, strlen(M_INVOICE_DESCRIPTION), true)) return false;

    //expiry
    if (p_invoice_data->expiry != LN_INVOICE_EXPIRY) {
        data[data_len++] = 6; //type
        int len = convert_bits_8to5_value_len(p_invoice_data->expiry);
        convert_bits_8to5_value_10bits(data + data_len, len);
        data_len += 2;
        convert_bits_8to5_value(data + data_len, p_invoice_data->expiry);
        data_len += len;
    }

    //min_final_cltv_expiry
    if (p_invoice_data->min_final_cltv_expiry != LN_MIN_FINAL_CLTV_EXPIRY) {
        data[data_len++] = 24; //type
        int len = convert_bits_8to5_value_len(p_invoice_data->min_final_cltv_expiry);
        convert_bits_8to5_value_10bits(data + data_len, len);
        data_len += 2;
        convert_bits_8to5_value(data + data_len, p_invoice_data->min_final_cltv_expiry);
        data_len += len;
    }

    //r field
    if (p_invoice_data->r_field_num > 0) {
        int bits = (M_SZ_R_FIELD * 8) * p_invoice_data->r_field_num;
        data[data_len++] = 3; //type
        convert_bits_8to5_value_10bits(data + data_len, M_5BIT_BYTES_LEN(bits));
        data_len += 2;

        btc_buf_w_t buf_w;
        if (!btc_buf_w_init(&buf_w, M_SZ_R_FIELD * p_invoice_data->r_field_num)) return false;
        for (int lp = 0; lp < p_invoice_data->r_field_num; lp++) {
            const ln_fieldr_t *r = &p_invoice_data->r_field[lp];
            if (!btc_buf_w_write_data(&buf_w, r->node_id, BTC_SZ_PUBKEY)) {
                btc_buf_w_free(&buf_w);
                return false;
            }
            if (!btc_buf_w_write_u64be(&buf_w, r->short_channel_id)) {
                btc_buf_w_free(&buf_w);
                return false;
            }
            if (!btc_buf_w_write_u32be(&buf_w, r->fee_base_msat)) {
                btc_buf_w_free(&buf_w);
                return false;
            }
            if (!btc_buf_w_write_u32be(&buf_w, r->fee_prop_millionths)) {
                btc_buf_w_free(&buf_w);
                return false;
            }
            if (!btc_buf_w_write_u16be(&buf_w, r->cltv_expiry_delta)) {
                btc_buf_w_free(&buf_w);
                return false;
            }
        }
        if (!btc_convert_bits_8to5(data, &data_len, btc_buf_w_get_data(&buf_w), btc_buf_w_get_len(&buf_w), true)) {
            btc_buf_w_free(&buf_w);
            return false;
        }
        btc_buf_w_free(&buf_w);
    }

    //hash
    // data: 5bits data -> 8 bits data
    // and hashed
    size_t preimg_len = strlen(hrp);
    uint8_t *p_preimg = (uint8_t *)UTL_DBG_MALLOC(preimg_len + data_len);
    if (!p_preimg) return false;
    strncpy((char *)p_preimg, (const char *)hrp, preimg_len);
    if (!btc_convert_bits_5to8(p_preimg, &preimg_len, data, data_len, true)) {
        UTL_DBG_FREE(p_preimg);
        return false;
    }
    uint8_t hash[BTC_SZ_HASH256];
    btc_md_sha256(hash, p_preimg, preimg_len);
    UTL_DBG_FREE(p_preimg);

    //signature
    uint8_t sign[BTC_SZ_SIGN_RS + 1]; //with recovery id
    if (!ln_node_sign_nodekey(sign, hash)) return false;
    int recid;
    if (!btc_sig_recover_pubkey_id(&recid, p_invoice_data->pubkey, sign, hash)) return false;
    sign[BTC_SZ_SIGN_RS] = (uint8_t)recid;
    if (!btc_convert_bits_8to5(data, &data_len, sign, sizeof(sign), true)) return false;

    size_t invoice_buf_len = strlen(hrp) + data_len + 8;
    *pp_invoice = (char *)UTL_DBG_MALLOC(invoice_buf_len);
    if (!*pp_invoice) return false;
    return btc_bech32_encode(*pp_invoice, invoice_buf_len, hrp, data, data_len, true);
}

static bool read_prefix(uint8_t *type, size_t *len, char *hrp)
{
    const char *s;

    //note: check from the longer one for the longest match
    s  = ln_prefix_str[LN_INVOICE_REGTEST];
    if (!strncasecmp(hrp, s, 6)) {
        *type = LN_INVOICE_REGTEST;
        *len = 6;
        return true;
    }
    s  = ln_prefix_str[LN_INVOICE_MAINNET];
    if (!strncasecmp(hrp, s, 4)) {
        *type = LN_INVOICE_MAINNET;
        *len = 4;
        return true;
    }
    s  = ln_prefix_str[LN_INVOICE_TESTNET];
    if (!strncasecmp(hrp, s, 4)) {
        *type = LN_INVOICE_TESTNET;
        *len = 4;
        return true;
    }
    return false;
}

uint64_t mul_bignums(uint64_t a, uint64_t b) {
    if (a > UINT64_MAX / b) return 0; //check roughly
    return a * b;
}

bool check_amt_len(size_t len) {
    //UINT64_MAX == 18446744073709551615 > 10 ^ 19
    //max. 10 ^ 19 - 1
    if (len > 19) return false; //check roughtly
    return true;
}

static bool read_amount(uint64_t *amount_msat, size_t *len, char *hrp)
{
    size_t amt_len = strlen(hrp);
    *amount_msat = 0;
    *len = amt_len;

    if (!amt_len) return true;

    char multiplier = 0;
    if (!isdigit(hrp[amt_len - 1])) {
        multiplier = hrp[amt_len - 1];
        amt_len -= 1;
        if (!amt_len) return false;
    }

    if (hrp[0] == '0') return false;
    if (!check_amt_len(amt_len)) return false;
    uint64_t btc = 0;
    for (size_t lp = 0; lp < amt_len; lp++) {
        btc *= 10;
        if (!isdigit(hrp[lp])) return false;
        btc += hrp[lp] - '0';
    }

    //1BTC = 10 ^ 8 Satoshi
    //1BTC = 10 ^ 11 MilliSatoshi
    if (multiplier) {
        switch (multiplier) {
        case 'm': //milli 10 ^ -3
        case 'M':
            *amount_msat = mul_bignums(btc, M_NUMBER_100MILION); //10 ^ (11 - 3)
            break;
        case 'u': //micro 10 ^ -6
        case 'U':
            *amount_msat = mul_bignums(btc, M_NUMBER_100THOUSAND); //10 ^ (11 - 6)
            break;
        case 'n': //nano 10 ^ -9
        case 'N':
            *amount_msat = mul_bignums(btc, 100); //10 ^ (11 - 9)
            break;
        case 'p': //pico 10 ^ -12
        case 'P':
            *amount_msat = btc / 10; //10 ^ (11 - 12)
            break;
        default:
            return false;
        };
    } else {
        *amount_msat = mul_bignums(btc, 10 ^ 11);
    }
    if (!*amount_msat) return false;

    return true;
}

bool ln_invoice_decode(ln_invoice_t **pp_invoice_data, const char* invoice) {
    bool ret = false;
    size_t tmp_len;

    char hrp[128];

    uint8_t *p_data = NULL;
    size_t data_len;

    uint8_t *p_preimg = NULL;
    size_t preimg_len;

    const uint8_t *p_tag;
    const uint8_t *p_sig;

    uint8_t hash[BTC_SZ_HASH256];
    uint8_t sig[M_SZ_SIG];
    size_t sig_len = 0;

    time_t tm;

    ln_invoice_t *p_invoice_data = (ln_invoice_t *)UTL_DBG_MALLOC(sizeof(ln_invoice_t));
    if (!p_invoice_data) goto LABEL_EXIT;

    tmp_len = strlen(invoice);

    p_data = (uint8_t *)UTL_DBG_MALLOC(tmp_len);
    if (!p_data) goto LABEL_EXIT;

    p_preimg = (uint8_t *)UTL_DBG_MALLOC(tmp_len);
    if (!p_preimg) goto LABEL_EXIT;

    data_len = tmp_len;
    if (!btc_bech32_decode(hrp, sizeof(hrp), p_data, &data_len, invoice, true)) goto LABEL_EXIT;

    /*
     * +---------------------+
     * | hrp                 |
     * |   prefix            |
     * |   (amount)          |
     * +---------------------+
     * | data                |
     * |   timestamp         |
     * |   (tagged fields)   |
     * |   signature         |
     * |   recovery ID       |
     * |   checksum          |
     * +---------------------+
     */

    //XXX: test
    //prefix
    if (!read_prefix(&p_invoice_data->hrp_type, &tmp_len, hrp)) goto LABEL_EXIT;

    //XXX: test
    //amount
    if (!read_amount(&p_invoice_data->amount_msat, &tmp_len, hrp + tmp_len)) goto LABEL_EXIT;

    if (data_len < M_SZ_TIMESTAMP_5BIT_BYTE + M_SZ_SIG_5BIT_BYTE) goto LABEL_EXIT;
    p_tag = p_data + M_SZ_TIMESTAMP_5BIT_BYTE;
    p_sig = p_data + data_len - M_SZ_SIG_5BIT_BYTE;

    //hash
    preimg_len = strlen(hrp);
    strncpy((char *)p_preimg, (const char *)hrp, preimg_len);
    if (!btc_convert_bits(p_preimg, &preimg_len, 8, p_data, data_len - M_SZ_SIG_5BIT_BYTE, 5, true)) goto LABEL_EXIT;
    btc_md_sha256(hash, p_preimg, preimg_len);

    //signature
    if (!btc_convert_bits(sig, &sig_len, 8, p_sig, M_SZ_SIG_5BIT_BYTE, 5, false)) goto LABEL_EXIT;
    if (!btc_sig_recover_pubkey(p_invoice_data->pubkey, sig[BTC_SZ_SIGN_RS], sig, hash)) goto LABEL_EXIT;

    //timestamp
    tm = (time_t)convert_bits_5to8_value(p_data, M_SZ_TIMESTAMP_5BIT_BYTE);
    p_invoice_data->timestamp = (uint64_t)tm;
    char time[UTL_SZ_TIME_FMT_STR + 1];
    LOGD("timestamp= %" PRIu64 " : %s\n", (uint64_t)tm, utl_time_fmt(time, tm));

    //tagged fields
    memset(p_invoice_data->payment_hash, 0x00, BTC_SZ_HASH256);
    p_invoice_data->expiry = LN_INVOICE_EXPIRY;
    p_invoice_data->min_final_cltv_expiry = LN_MIN_FINAL_CLTV_EXPIRY;
    p_invoice_data->r_field_num = 0;
    {
        btc_buf_r_t buf_r;
        btc_buf_r_init(&buf_r, p_tag, p_sig - p_tag);
        while (btc_buf_r_remains(&buf_r)) {
            if (!analyze_tagged_field(&buf_r, &p_invoice_data)) goto LABEL_EXIT;
        }
    }
    if (utl_mem_is_all_zero(p_invoice_data->payment_hash, BTC_SZ_HASH256)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    if (p_data) UTL_DBG_FREE(p_data);
    if (p_preimg) UTL_DBG_FREE(p_preimg);
    if (ret) {
        *pp_invoice_data = p_invoice_data;
    } else {
        UTL_DBG_FREE(p_invoice_data);
        *pp_invoice_data = NULL;
    }
    return ret;
}


bool ln_invoice_create(char **ppInvoice, uint8_t Type, const uint8_t *pPayHash, uint64_t Amount, uint32_t Expiry,
                        const ln_fieldr_t *pFieldR, uint8_t FieldRNum, uint32_t MinFinalCltvExpiry)
{
    ln_invoice_t *p_invoice_data;

    size_t sz = sizeof(ln_invoice_t);
    if (FieldRNum) {
        if (!pFieldR) return false;
        sz += sizeof(ln_fieldr_t) * FieldRNum;
    }
    p_invoice_data = (ln_invoice_t *)UTL_DBG_MALLOC(sz);
    if (!p_invoice_data) return false;

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
