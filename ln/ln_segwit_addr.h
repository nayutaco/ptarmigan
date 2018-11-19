#ifndef _LN_SEGWIT_ADDR_H_
#define _LN_SEGWIT_ADDR_H_ 1

#include <stdint.h>
#include <stdbool.h>

#include "ln.h"

#define LN_INVOICE_MAINNET      ((uint8_t)4)
#define LN_INVOICE_TESTNET      ((uint8_t)5)
#define LN_INVOICE_REGTEST      ((uint8_t)6)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/** @struct ln_fieldr_t;
 *  @brief  r field
 */
typedef struct ln_fieldr_t {
    uint8_t     node_id[BTC_SZ_PUBKEY];           ///< node_id
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
    uint8_t     pubkey[BTC_SZ_PUBKEY];
    uint8_t     payment_hash[BTC_SZ_HASH256];
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
