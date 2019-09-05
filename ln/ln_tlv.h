#ifndef LN_TLV_H__
#define LN_TLV_H__

#include <stdint.h>
#include <stdbool.h>

#include "utl_buf.h"


/**************************************************************************
 * macros
 **************************************************************************/


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct ln_tlv_t {
    uint64_t        type;
    utl_buf_t       value;
} ln_tlv_t;


typedef struct ln_tlv_record_t {
    uint16_t        num;
    ln_tlv_t        tlvs[];
} ln_tlv_record_t;


/**************************************************************************
 * prototypes
 **************************************************************************/

bool ln_tlv_read(ln_tlv_record_t **ppTlvRec, const uint8_t *pData, uint32_t Len);
bool ln_tlv_write(utl_buf_t *pBuf, const ln_tlv_record_t *pTlvRec);
void ln_tlv_free(ln_tlv_record_t *pTlvRec);

#endif /* LN_TLV_H__ */
