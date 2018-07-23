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

#ifndef _SEGWIT_ADDR_H_
#define _SEGWIT_ADDR_H_ 1

#include <stdint.h>
#include <stdbool.h>
#include "ln.h"

#define SEGWIT_ADDR_MAINNET     ((uint8_t)0)
#define SEGWIT_ADDR_TESTNET     ((uint8_t)1)
#define SEGWIT_ADDR_MAINNET2    ((uint8_t)2)
#define SEGWIT_ADDR_TESTNET2    ((uint8_t)3)
#define LN_INVOICE_MAINNET      ((uint8_t)4)
#define LN_INVOICE_TESTNET      ((uint8_t)5)
#define LN_INVOICE_REGTEST      ((uint8_t)6)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/** Encode a SegWit address
 *
 *  Out: output:   Pointer to a buffer of size 73 + strlen(hrp) that will be
 *                 updated to contain the null-terminated address.
 *  In:  hrp_type: SEGWIT_ADDR_MAINNET or SEGWIT_ADDR_TESTNET
 *       ver:      Version of the witness program (between 0 and 16 inclusive).
 *       prog:     Data bytes for the witness program (between 2 and 40 bytes).
 *       prog_len: Number of data bytes in prog.
 *  Returns true if successful.
 */
bool segwit_addr_encode(
    char *output,
    uint8_t hrp_type,
    int ver,
    const uint8_t *prog,
    size_t prog_len
);

/** Decode a SegWit address
 *
 *  Out: ver:      Pointer to an int that will be updated to contain the witness
 *                 program version (between 0 and 16 inclusive).
 *       prog:     Pointer to a buffer of size 40 that will be updated to
 *                 contain the witness program bytes.
 *       prog_len: Pointer to a size_t that will be updated to contain the length
 *                 of bytes in prog.
 *       hrp_type: SEGWIT_ADDR_MAINNET or SEGWIT_ADDR_TESTNET
 *       addr:     Pointer to the null-terminated address.
 *  Returns true if successful.
 */
bool segwit_addr_decode(
    int* ver,
    uint8_t* prog,
    size_t* prog_len,
    uint8_t hrp_type,
    const char* addr
);


/** @struct ln_fieldr_t;
 *  @brief  r field
 */
typedef struct ln_fieldr_t {
    uint8_t     node_id[PTARM_SZ_PUBKEY];           ///< node_id
    uint64_t    short_channel_id;                   ///< short_channel_id
    uint32_t    fee_base_msat;                      ///< fee_base_msat
    uint32_t    fee_prop_millionths;                ///< fee_proportional_millionths
    uint16_t    cltv_expiry_delta;                  ///< cltv_expiry_delta
} ln_fieldr_t;


/** @struct ln_invoice_t;
 *  @brief  BOLT#11 invoice
 */
typedef struct ln_invoice_t {
    uint8_t     hrp_type;
    uint64_t    amount_msat;
    uint64_t    timestamp;
    uint32_t    expiry;
    uint32_t    min_final_cltv_expiry;
    uint8_t     pubkey[PTARM_SZ_PUBKEY];
    uint8_t     payment_hash[LN_SZ_HASH];
    uint8_t     r_field_num;
    ln_fieldr_t r_field[];
} ln_invoice_t;


/** Encode a BOLT11 invoice
 *
 * @param[out]      pp_invoice
 * @param[in]       p_invoice_data
 * @return  true:success
 * @note
 *      - need `free(pp_invoice)' if don't use it.
 */
bool ln_invoice_encode(char** pp_invoice, const ln_invoice_t *p_invoice_data);

/** Decode a BOLT11 invoice
 *
 * @param[out]      pp_invoice_data
 * @param[in]       invoice
 * @return  true:success
 */
bool ln_invoice_decode(ln_invoice_t **pp_invoice_data, const char* invoice);

/** BOLT11 形式invoice作成
 *
 * @param[out]      ppInvoice
 * @param[in]       Type            LN_INVOICE_xxx
 * @param[in]       pPayHash
 * @param[in]       Amount
 * @param[in]       Expiry          invoice expiry
 * @param[in]       pFieldR
 * @param[in]       FieldRNum       pFieldR数
 * @param[in]       MinFinalCltvExpiry  min_final_cltv_expiry
 * @retval      true        成功
 * @attention
 *      - ppInoviceはmalloc()で確保するため、、使用後にfree()すること
 */
bool ln_invoice_create(char **ppInvoice, uint8_t Type, const uint8_t *pPayHash, uint64_t Amount, uint32_t Expiry,
                        const ln_fieldr_t *pFieldR, uint8_t FieldRNum, uint32_t MinFinalCltvExpiry);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
