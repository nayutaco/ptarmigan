#ifndef _LN_INVOICE_H_
#define _LN_INVOICE_H_ 1

#include <stdint.h>
#include <stdbool.h>

#include "btc_keys.h"
#include "btc_crypto.h"
#include "btc_segwit_addr.h"

#define LN_INVOICE_DESC_MAX     (32)

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

/** @struct ln_r_field_t;
 *  @brief  r field
 */
typedef struct {
    uint8_t     node_id[BTC_SZ_PUBKEY];           ///< node_id
    uint64_t    short_channel_id;                 ///< short_channel_id
    uint32_t    fee_base_msat;                    ///< fee_base_msat
    uint32_t    fee_prop_millionths;              ///< fee_proportional_millionths
    uint16_t    cltv_expiry_delta;                ///< cltv_expiry_delta
} ln_r_field_t;


/** @enum   ln_invoice_desc_type_t
 *  @brief  description
 */
typedef enum {
    LN_INVOICE_DESC_NONE,
    LN_INVOICE_DESC_TYPE_STRING,
    LN_INVOICE_DESC_TYPE_HASH256,
} ln_invoice_desc_type_t;


typedef struct {
    ln_invoice_desc_type_t  type;
    utl_buf_t               data;
} ln_invoice_desc_t;


/** @struct ln_invoice_t;
 *  @brief  BOLT#11 invoice
 */
typedef struct {
    ln_invoice_hrptype_t hrp_type;
    uint64_t    amount_msat;
    uint64_t    timestamp;
    uint32_t    expiry;
    uint32_t    min_final_cltv_expiry;
    uint8_t     pubkey[BTC_SZ_PUBKEY];
    uint8_t     payment_hash[BTC_SZ_HASH256];
    ln_invoice_desc_t   description;
    uint8_t     r_field_num;
    ln_r_field_t r_field[];
} ln_invoice_t;


/** Encode a BOLT11 invoice
 *
 * @param[out]      pp_invoice
 * @param[in]       p_invoice_data
 * @return  true:success
 * @note
 *      - need `UTL_DBG_FREE(pp_invoice)' if don't use it.
 */
bool ln_invoice_encode(char **pp_invoice, const ln_invoice_t *p_invoice_data);

/** Decode a BOLT11 invoice
 *
 * @param[out]      pp_invoice_data
 * @param[in]       invoice
 * @return  true:success
 */
bool ln_invoice_decode(ln_invoice_t **pp_invoice_data, const char* invoice);

bool ln_invoice_decode_2(ln_invoice_t **pp_invoice_data, const char* invoice, uint32_t len);

void ln_invoice_decode_free(ln_invoice_t *p_invoice_data);


/** BOLT11 形式invoice作成
 *
 * @param[out]      ppInvoice
 * @param[in]       Type            LN_INVOICE_xxx
 * @param[in]       pPaymentHash
 * @param[in]       Amount
 * @param[in]       Expiry          invoice expiry
 * @param[in]       pDesc           description
 * @param[in]       pRField
 * @param[in]       RFieldNum       pRField数
 * @param[in]       MinFinalCltvExpiry  min_final_cltv_expiry
 * @retval      true        成功
 * @attention
 *      - ppInoviceはUTL_DBG_MALLOC()で確保するため、、使用後にUTL_DBG_FREE()すること
 */
bool ln_invoice_create(
            char **ppInvoice,
            ln_invoice_hrptype_t Type,
            const uint8_t *pPaymentHash,
            uint64_t Amount,
            uint32_t Expiry,
            const ln_invoice_desc_t *pDesc,
            const ln_r_field_t *pRField,
            uint8_t RFieldNum,
            uint32_t MinFinalCltvExpiry);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif
