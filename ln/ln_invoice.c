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
#include "ln_invoice.h"
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

static bool convert_bits_8to5(uint8_t* out, size_t* outlen, const uint8_t* in, size_t inlen, bool pad)
{
    return btc_convert_bits(out, outlen, 5, in, inlen, 8, pad);
}

static bool convert_bits_5to8(uint8_t* out, size_t* outlen, const uint8_t* in, size_t inlen, bool pad)
{
    return btc_convert_bits(out, outlen, 8, in, inlen, 5, pad);
}

static bool write_convert_bits_8to5(btc_buf_w_t *p_buf_w, const uint8_t* in, size_t inlen, bool pad)
{
    size_t len = btc_convert_bits_buf_len(5, inlen, 8);
    if (!btc_buf_w_expand(p_buf_w, len)) return false;
    size_t outlen = 0;
    if (!convert_bits_8to5(btc_buf_w_get_pos(p_buf_w), &outlen, in, inlen, pad)) return false;
    assert(len == outlen);
    if (!btc_buf_w_seek(p_buf_w, len)) return false;
    return true;
}

static bool write_convert_bits_5to8(btc_buf_w_t *p_buf_w, const uint8_t* in, size_t inlen, bool pad)
{
    size_t len = btc_convert_bits_buf_len(8, inlen, 5);
    if (!btc_buf_w_expand(p_buf_w, len)) return false;
    size_t outlen = 0;
    if (!convert_bits_5to8(btc_buf_w_get_pos(p_buf_w), &outlen, in, inlen, pad)) return false;
    assert(len == outlen);
    if (!btc_buf_w_seek(p_buf_w, len)) return false;
    return true;
}

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

static bool write_convert_bits_8to5_value(btc_buf_w_t *p_buf_w, uint64_t val)
{
    int len = convert_bits_8to5_value_len(val);
    if (!btc_buf_w_expand(p_buf_w, len)) return false;
    convert_bits_8to5_value(btc_buf_w_get_pos(p_buf_w), val);
    if (!btc_buf_w_seek(p_buf_w, len)) return false;
    return true;
}

static void convert_bits_8to5_value_10bits(uint8_t *p_out_2bytes, uint16_t val)
{
    assert(!(val >> 10));
    p_out_2bytes[0] = (val >> 5) & 0x1f;
    p_out_2bytes[1] = val & 0x1f;
}

static bool write_convert_bits_8to5_value_10bits(btc_buf_w_t *p_buf_w, uint64_t val)
{
    uint8_t b[2];
    convert_bits_8to5_value_10bits(b, val);
    if (!btc_buf_w_write_data(p_buf_w, b, 2)) return false;
    return true;
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
        if (!convert_bits_5to8(p_data, &tmp_len, btc_buf_r_get_pos(p_parts), data_length, true)) goto LABEL_EXIT;
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
            if (!convert_bits_5to8(p_data, &tmp_len, btc_buf_r_get_pos(p_parts), data_length, true)) goto LABEL_EXIT;
            if (tmp_len < M_SZ_R_FIELD) goto LABEL_EXIT;
            n = tmp_len / M_SZ_R_FIELD;
            p_invoice_data = (ln_invoice_t *)UTL_DBG_REALLOC(
                p_invoice_data,
                sizeof(ln_invoice_t) + sizeof(ln_r_field_t) * n);
            p_invoice_data->r_field_num = n;

            btc_buf_r_init(&buf_r, p_data, tmp_len);

            for (size_t lp = 0; lp < n; lp++) {
                ln_r_field_t *p_fieldr = &p_invoice_data->r_field[lp];
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
    bool ret = false;

    btc_buf_w_t buf_w;
    btc_buf_w_t buf_w_r_field;
    btc_buf_w_t buf_w_preimage;

    *pp_invoice = NULL;

    btc_buf_w_init(&buf_w, 0);
    btc_buf_w_init(&buf_w_r_field, 0);
    btc_buf_w_init(&buf_w_preimage, 0);

    char hrp[M_SZ_PREFIX_MAX + M_UINT64_MAX_DIGIT + 1]; //prefix | amount | multiplier

    if (p_invoice_data->hrp_type != LN_INVOICE_MAINNET &&
        p_invoice_data->hrp_type != LN_INVOICE_TESTNET &&
        p_invoice_data->hrp_type != LN_INVOICE_REGTEST) goto LABEL_EXIT;


    //prefix
    const char *tmp_cstr;
    tmp_cstr = ln_prefix_str[p_invoice_data->hrp_type];
    if (strlen(tmp_cstr) > M_SZ_PREFIX_MAX) goto LABEL_EXIT;
    strcpy(hrp, tmp_cstr);

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
    time_t t;
    t = utl_time_time();
    if (convert_bits_8to5_value_len(t) != 7) goto LABEL_EXIT;
    if (!write_convert_bits_8to5_value(&buf_w, t)) goto LABEL_EXIT;

    //tagged field
    //  1. type (5bits)
    //  2. data_length (10bits, big-endian)
    //  3. data (data_length x 5bits)

    //33-byte public key of the payee node
    if (!btc_buf_w_write_byte(&buf_w, 19)) goto LABEL_EXIT; //type
    if (!write_convert_bits_8to5_value_10bits(&buf_w, M_5BIT_BYTES_LEN(264))) goto LABEL_EXIT;
    if (!write_convert_bits_8to5(&buf_w, p_invoice_data->pubkey, BTC_SZ_PUBKEY, true)) goto LABEL_EXIT;

    //256-bit SHA256 payment_hash
    if (!btc_buf_w_write_byte(&buf_w, 1)) goto LABEL_EXIT; //type
    if (!write_convert_bits_8to5_value_10bits(&buf_w, M_5BIT_BYTES_LEN(256))) goto LABEL_EXIT;
    if (!write_convert_bits_8to5(&buf_w, p_invoice_data->payment_hash, BTC_SZ_HASH256, true)) goto LABEL_EXIT;

    //short description
    if (!btc_buf_w_write_byte(&buf_w, 13)) goto LABEL_EXIT; //type
    if (!write_convert_bits_8to5_value_10bits(&buf_w, M_5BIT_BYTES_LEN(strlen(M_INVOICE_DESCRIPTION) * 8))) goto LABEL_EXIT;
    if (!write_convert_bits_8to5(&buf_w, (const uint8_t *)M_INVOICE_DESCRIPTION, strlen(M_INVOICE_DESCRIPTION), true)) goto LABEL_EXIT;

    //expiry
    if (p_invoice_data->expiry != LN_INVOICE_EXPIRY) {
        if (!btc_buf_w_write_byte(&buf_w, 6)) goto LABEL_EXIT; //type
        int len = convert_bits_8to5_value_len(p_invoice_data->expiry);
        if (!write_convert_bits_8to5_value_10bits(&buf_w, len)) goto LABEL_EXIT;
        if (!write_convert_bits_8to5_value(&buf_w, p_invoice_data->expiry)) goto LABEL_EXIT;
    }

    //min_final_cltv_expiry
    if (p_invoice_data->min_final_cltv_expiry != LN_MIN_FINAL_CLTV_EXPIRY) {
        if (!btc_buf_w_write_byte(&buf_w, 24)) goto LABEL_EXIT; //type
        int len = convert_bits_8to5_value_len(p_invoice_data->min_final_cltv_expiry);
        if (!write_convert_bits_8to5_value_10bits(&buf_w, len)) goto LABEL_EXIT;
        if (!write_convert_bits_8to5_value(&buf_w, p_invoice_data->min_final_cltv_expiry)) goto LABEL_EXIT;
    }

    //r field
    if (p_invoice_data->r_field_num > 0) {
        int bits = (M_SZ_R_FIELD * 8) * p_invoice_data->r_field_num;
        if (!btc_buf_w_write_byte(&buf_w, 3)) goto LABEL_EXIT; //type
        if (!write_convert_bits_8to5_value_10bits(&buf_w, M_5BIT_BYTES_LEN(bits))) goto LABEL_EXIT;

        for (int lp = 0; lp < p_invoice_data->r_field_num; lp++) {
            const ln_r_field_t *r = &p_invoice_data->r_field[lp];
            if (!btc_buf_w_write_data(&buf_w_r_field, r->node_id, BTC_SZ_PUBKEY)) goto LABEL_EXIT;
            if (!btc_buf_w_write_u64be(&buf_w_r_field, r->short_channel_id)) goto LABEL_EXIT;
            if (!btc_buf_w_write_u32be(&buf_w_r_field, r->fee_base_msat)) goto LABEL_EXIT;
            if (!btc_buf_w_write_u32be(&buf_w_r_field, r->fee_prop_millionths)) goto LABEL_EXIT;
            if (!btc_buf_w_write_u16be(&buf_w_r_field, r->cltv_expiry_delta)) goto LABEL_EXIT;
        }
        if (!write_convert_bits_8to5(&buf_w, btc_buf_w_get_data(&buf_w_r_field), btc_buf_w_get_len(&buf_w_r_field), true)) goto LABEL_EXIT;
    }

    //hash
    // data: 5bits data -> 8 bits data
    // and hashed
    if (!btc_buf_w_write_data(&buf_w_preimage, hrp, strlen(hrp))) goto LABEL_EXIT;
    if (!write_convert_bits_5to8(&buf_w_preimage, btc_buf_w_get_data(&buf_w), btc_buf_w_get_len(&buf_w), true)) goto LABEL_EXIT;
    uint8_t hash[BTC_SZ_HASH256];
    btc_md_sha256(hash, btc_buf_w_get_data(&buf_w_preimage), btc_buf_w_get_len(&buf_w_preimage));

    //signature
    uint8_t sign[BTC_SZ_SIGN_RS + 1]; //with recovery id
    if (!ln_node_sign_nodekey(sign, hash)) goto LABEL_EXIT;
    int recid;
    if (!btc_sig_recover_pubkey_id(&recid, p_invoice_data->pubkey, sign, hash)) goto LABEL_EXIT;
    sign[BTC_SZ_SIGN_RS] = (uint8_t)recid;
    if (!write_convert_bits_8to5(&buf_w, sign, sizeof(sign), true)) goto LABEL_EXIT;

    size_t invoice_buf_len;
    invoice_buf_len = btc_bech32_encode_buf_len(hrp, btc_buf_w_get_len(&buf_w));
    *pp_invoice = (char *)UTL_DBG_MALLOC(invoice_buf_len);
    if (!*pp_invoice) goto LABEL_EXIT;
    if (!btc_bech32_encode(*pp_invoice, invoice_buf_len, hrp, btc_buf_w_get_data(&buf_w), btc_buf_w_get_len(&buf_w), true)) goto LABEL_EXIT;

    ret = true;

LABEL_EXIT:
    if (!ret) UTL_DBG_FREE(*pp_invoice);
    btc_buf_w_free(&buf_w);
    btc_buf_w_free(&buf_w_r_field);
    btc_buf_w_free(&buf_w_preimage);
    return ret;
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

    uint8_t *p_preimage = NULL;
    size_t preimage_len;

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

    p_preimage = (uint8_t *)UTL_DBG_MALLOC(tmp_len);
    if (!p_preimage) goto LABEL_EXIT;

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
    preimage_len = strlen(hrp);
    strncpy((char *)p_preimage, (const char *)hrp, preimage_len);
    if (!btc_convert_bits(p_preimage, &preimage_len, 8, p_data, data_len - M_SZ_SIG_5BIT_BYTE, 5, true)) goto LABEL_EXIT;
    btc_md_sha256(hash, p_preimage, preimage_len);

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
    if (p_preimage) UTL_DBG_FREE(p_preimage);
    if (ret) {
        *pp_invoice_data = p_invoice_data;
    } else {
        UTL_DBG_FREE(p_invoice_data);
        *pp_invoice_data = NULL;
    }
    return ret;
}

bool ln_invoice_decode_2(ln_invoice_t **pp_invoice_data, const char* invoice, uint32_t len) {
    char *p_invoice = (char *)UTL_DBG_MALLOC(len + 1);
    if (!p_invoice) return false;

    strncpy(p_invoice, invoice, len + 1);

    bool ret = ln_invoice_decode(pp_invoice_data, p_invoice);

    UTL_DBG_FREE(p_invoice);
    return ret;
}

bool ln_invoice_create(char **ppInvoice, uint8_t Type, const uint8_t *pPaymentHash, uint64_t Amount, uint32_t Expiry,
                        const ln_r_field_t *pRField, uint8_t RFieldNum, uint32_t MinFinalCltvExpiry)
{
    ln_invoice_t *p_invoice_data;

    size_t sz = sizeof(ln_invoice_t);
    if (RFieldNum) {
        if (!pRField) return false;
        sz += sizeof(ln_r_field_t) * RFieldNum;
    }
    p_invoice_data = (ln_invoice_t *)UTL_DBG_MALLOC(sz);
    if (!p_invoice_data) return false;

    p_invoice_data->hrp_type = Type;
    p_invoice_data->amount_msat = Amount;
    p_invoice_data->expiry = Expiry;
    p_invoice_data->min_final_cltv_expiry = MinFinalCltvExpiry;
    memcpy(p_invoice_data->pubkey, ln_node_get_id(), BTC_SZ_PUBKEY);
    memcpy(p_invoice_data->payment_hash, pPaymentHash, BTC_SZ_HASH256);
    p_invoice_data->r_field_num = RFieldNum;
    memcpy(p_invoice_data->r_field, pRField, sizeof(ln_r_field_t) * RFieldNum);

    bool ret = ln_invoice_encode(ppInvoice, p_invoice_data);
    UTL_DBG_FREE(p_invoice_data);

    return ret;
}
