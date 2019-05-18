#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
#undef LOG_TAG
#include "../../utl/utl_thread.c"
#undef LOG_TAG
#include "../../utl/utl_log.c"
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
#include "../../utl/utl_push.c"
//#include "../../utl/utl_time.c"
#include "../../utl/utl_int.c"
#include "../../utl/utl_str.c"
#undef LOG_TAG
#include "../../btc/btc.c"
#include "../../btc/btc_buf.c"
#include "../../btc/btc_extkey.c"
#include "../../btc/btc_keys.c"
#include "../../btc/btc_sw.c"
#include "../../btc/btc_sig.c"
#include "../../btc/btc_script.c"
#include "../../btc/btc_tx.c"
#include "../../btc/btc_tx_buf.c"
#include "../../btc/btc_crypto.c"
#include "../../btc/segwit_addr.c"
#include "../../btc/btc_segwit_addr.c"
#include "../../btc/btc_test_util.c"

#undef LOG_TAG
#include "ln_derkey.c"
#include "ln_derkey_ex.c"
// #include "ln_msg_anno.c"
// #include "ln_msg_close.c"
// #include "ln_msg_establish.c"
//#include "ln_msg_normalope.c"
// #include "ln_msg_setupctl.c"
#include "ln_anno.c"
#include "ln_node.c"
// #include "ln_onion.c"
// #include "ln_script.c"
#include "ln_noise.c"
#include "ln_signer.c"
// #include "ln_invoice.c"
// #include "ln_print.c"
#include "ln_update_info.c"

#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

FAKE_VOID_FUNC(ln_db_preimage_cur_close, void *, bool);
FAKE_VALUE_FUNC(bool, ln_db_cnlupd_load, utl_buf_t *, uint32_t *, uint64_t, uint8_t, void*);
FAKE_VALUE_FUNC(bool, ln_db_preimage_del, const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_open, void **);
FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_get, void *, bool *, ln_db_preimage_t *);
FAKE_VALUE_FUNC(bool, ln_db_channel_search, ln_db_func_cmp_t, void *);
FAKE_VALUE_FUNC(bool, ln_db_channel_search_readonly, ln_db_func_cmp_t, void *);
FAKE_VALUE_FUNC(bool, ln_db_payment_hash_save, const uint8_t*, const uint8_t*, ln_commit_tx_output_type_t, uint32_t);
FAKE_VALUE_FUNC(bool, ln_db_preimage_search, ln_db_func_preimage_t, void*);
FAKE_VALUE_FUNC(bool, ln_db_cnlupd_need_to_prune, uint64_t , uint32_t );
FAKE_VALUE_FUNC(bool, ln_db_cnlupd_save, const utl_buf_t *, const ln_msg_channel_update_t *, const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_cnlanno_load, utl_buf_t *, uint64_t );

FAKE_VALUE_FUNC(time_t, utl_time_time);
FAKE_VALUE_FUNC(const char *, utl_time_str_time, char *);
FAKE_VALUE_FUNC(const char *, utl_time_fmt, char *, time_t );


//FAKE_VALUE_FUNC(bool, ln_msg_channel_update_write, utl_buf_t *, const ln_msg_channel_update_t *);
FAKE_VALUE_FUNC(bool, ln_msg_channel_update_read, ln_msg_channel_update_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_channel_update_verify, const uint8_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_channel_announcement_read, ln_msg_channel_announcement_t *, const uint8_t *, uint16_t );


////////////////////////////////////////////////////////////////////////

namespace LN_DUMMY {
    const uint8_t CHANNEL_ID[] = {
        0x40, 0xfd, 0xde, 0x21, 0x7b, 0xb2, 0xd6, 0xbc, 0x4c, 0x9e, 0x20, 0xc5, 0xe5, 0x31, 0x93, 0xd0,
        0x71, 0xeb, 0xef, 0x7c, 0x13, 0x81, 0x04, 0x19, 0x82, 0x6a, 0xf8, 0x86, 0x2a, 0xf1, 0x22, 0xad,
    };
}

namespace CHANANNO {
    //regtest
    const uint8_t CHANNEL_ANNO[] = {
        0x01, 0x00,
        //node_signature_1
        0x84, 0xf6, 0xf8, 0x6e, 0xdf, 0x6d, 0xef, 0x37, 0xcb, 0x53, 0x33, 0xc5, 0x0b, 0xb8, 0x07, 0x05,
        0x5b, 0x73, 0xcb, 0x84, 0x80, 0xa8, 0xa3, 0x1f, 0x3e, 0x9b, 0x0a, 0x0e, 0xa6, 0x04, 0xbf, 0xd7,
        0x4f, 0x7a, 0x72, 0xaa, 0x62, 0x97, 0x5d, 0xf0, 0xb6, 0xab, 0xc4, 0x68, 0x40, 0x47, 0xad, 0x2d,
        0x59, 0xe7, 0x5b, 0x51, 0x73, 0x50, 0xb0, 0xdb, 0xd1, 0xb2, 0x91, 0x6d, 0x54, 0x58, 0xaf, 0xdb,
        //node_signature_2
        0x79, 0xba, 0xd6, 0xe3, 0xd6, 0xdf, 0x56, 0x51, 0x1b, 0xfa, 0xed, 0xf9, 0xfd, 0xc5, 0x19, 0x5d,
        0x0e, 0x64, 0x32, 0x1c, 0x2f, 0xa4, 0xcc, 0x7a, 0x61, 0xe7, 0x63, 0xdc, 0x7d, 0x19, 0x12, 0x69,
        0x46, 0xd9, 0xdb, 0xb9, 0x13, 0xdd, 0x16, 0x37, 0x8b, 0xec, 0xc3, 0x75, 0xa1, 0x29, 0x67, 0x71,
        0xc3, 0xb2, 0xdd, 0xec, 0xd8, 0x36, 0x0f, 0x3d, 0x7d, 0x61, 0xca, 0x45, 0x55, 0x0d, 0x84, 0x15,
        //bitcoin_signature_1
        0xd9, 0x84, 0xe6, 0x57, 0xb8, 0xbd, 0xf9, 0x62, 0x5f, 0xbf, 0x9a, 0x77, 0x4f, 0xd6, 0x9c, 0x26,
        0x7e, 0xc2, 0x0f, 0xd9, 0x71, 0x23, 0x72, 0x38, 0xe7, 0x05, 0xbe, 0xe5, 0x78, 0x92, 0x55, 0x98,
        0x10, 0xe9, 0xe0, 0x9d, 0x11, 0xf8, 0xfd, 0x68, 0xd7, 0x75, 0xce, 0x5e, 0x52, 0x7c, 0xb5, 0x67,
        0xaf, 0xa2, 0x62, 0x4e, 0xa3, 0xc7, 0x27, 0xcb, 0x14, 0x31, 0x37, 0x8b, 0x9c, 0xab, 0xbe, 0x66,
        //bitcoin_signature_2
        0x21, 0x8a, 0x4e, 0xa7, 0xd7, 0xa0, 0x83, 0xc9, 0x06, 0x32, 0x7e, 0x89, 0x64, 0x9d, 0xa8, 0x69,
        0x4c, 0xee, 0x7a, 0x45, 0xfd, 0xb5, 0xc7, 0x2a, 0xb7, 0xf9, 0xe4, 0x80, 0xfb, 0xf9, 0xfc, 0xfc,
        0x3c, 0x3f, 0x21, 0x5a, 0x2b, 0xc9, 0x09, 0x32, 0x37, 0x2d, 0x66, 0x19, 0x8a, 0xa3, 0x1f, 0xa7,
        0x92, 0x14, 0x7a, 0xe3, 0x2a, 0x11, 0xff, 0x0d, 0x48, 0x2d, 0xdd, 0x6d, 0xa5, 0xd1, 0x75, 0x6e,
        //len
        0x00, 0x00,
        //chain_hash
        0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
        0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
        //short_channel_id
        0x00, 0x01, 0xb1, 0x00, 0x00, 0x05, 0x00, 0x00,
        //node_id_1
        0x02, 0x44, 0x45, 0x64, 0x34, 0x60, 0x9f, 0x53, 0x68, 0x3c, 0x6d, 0x9c, 0x33, 0x13, 0x29, 0xa6,
        0x3b, 0x0f, 0x24, 0x8b, 0x73, 0xf9, 0x46, 0x8c, 0xf5, 0x49, 0xa5, 0x61, 0x00, 0xdb, 0x07, 0xbf, 0x0e,
        //node_id_2
        0x03, 0xbb, 0x44, 0x01, 0xc2, 0xf2, 0xcd, 0xc5, 0xbf, 0x77, 0x4a, 0x31, 0xef, 0x4a, 0x31, 0x3e,
        0x43, 0xc9, 0x9b, 0x8a, 0x69, 0xa7, 0x7e, 0x08, 0xc8, 0xdf, 0xf4, 0xd7, 0x55, 0x2c, 0xf3, 0xcc, 0x75,
        //bitcoin_key_1
        0x02, 0x14, 0x7b, 0x23, 0xa8, 0xf8, 0x24, 0xe7, 0x16, 0x71, 0x2f, 0xcc, 0xb0, 0x1d, 0x2e, 0x49,
        0x14, 0x6d, 0x53, 0x32, 0x7c, 0xc2, 0xb6, 0xea, 0x93, 0xa6, 0xb4, 0xed, 0x5f, 0x69, 0x80, 0x99, 0xcb,
        //bitcoin_key_2
        0x02, 0x7d, 0xfe, 0x1b, 0xa5, 0x07, 0x34, 0xe8, 0x2e, 0xfa, 0x8c, 0x62, 0x64, 0x11, 0x27, 0xd9,
        0xb2, 0xbb, 0x1d, 0x9b, 0x3a, 0x9c, 0x29, 0xb2, 0x0a, 0xf7, 0xd0, 0x43, 0x93, 0xe2, 0xa2, 0x71, 0x43,
    };


    const uint8_t NODE_SIG1[] = {
        0x84, 0xf6, 0xf8, 0x6e, 0xdf, 0x6d, 0xef, 0x37, 0xcb, 0x53, 0x33, 0xc5, 0x0b, 0xb8, 0x07, 0x05,
        0x5b, 0x73, 0xcb, 0x84, 0x80, 0xa8, 0xa3, 0x1f, 0x3e, 0x9b, 0x0a, 0x0e, 0xa6, 0x04, 0xbf, 0xd7,
        0x4f, 0x7a, 0x72, 0xaa, 0x62, 0x97, 0x5d, 0xf0, 0xb6, 0xab, 0xc4, 0x68, 0x40, 0x47, 0xad, 0x2d,
        0x59, 0xe7, 0x5b, 0x51, 0x73, 0x50, 0xb0, 0xdb, 0xd1, 0xb2, 0x91, 0x6d, 0x54, 0x58, 0xaf, 0xdb,
    };
    const uint8_t NODE_SIG2[] = {
        0x79, 0xba, 0xd6, 0xe3, 0xd6, 0xdf, 0x56, 0x51, 0x1b, 0xfa, 0xed, 0xf9, 0xfd, 0xc5, 0x19, 0x5d,
        0x0e, 0x64, 0x32, 0x1c, 0x2f, 0xa4, 0xcc, 0x7a, 0x61, 0xe7, 0x63, 0xdc, 0x7d, 0x19, 0x12, 0x69,
        0x46, 0xd9, 0xdb, 0xb9, 0x13, 0xdd, 0x16, 0x37, 0x8b, 0xec, 0xc3, 0x75, 0xa1, 0x29, 0x67, 0x71,
        0xc3, 0xb2, 0xdd, 0xec, 0xd8, 0x36, 0x0f, 0x3d, 0x7d, 0x61, 0xca, 0x45, 0x55, 0x0d, 0x84, 0x15,
    };
    const uint8_t BTC_SIG1[] = {
        0xd9, 0x84, 0xe6, 0x57, 0xb8, 0xbd, 0xf9, 0x62, 0x5f, 0xbf, 0x9a, 0x77, 0x4f, 0xd6, 0x9c, 0x26,
        0x7e, 0xc2, 0x0f, 0xd9, 0x71, 0x23, 0x72, 0x38, 0xe7, 0x05, 0xbe, 0xe5, 0x78, 0x92, 0x55, 0x98,
        0x10, 0xe9, 0xe0, 0x9d, 0x11, 0xf8, 0xfd, 0x68, 0xd7, 0x75, 0xce, 0x5e, 0x52, 0x7c, 0xb5, 0x67,
        0xaf, 0xa2, 0x62, 0x4e, 0xa3, 0xc7, 0x27, 0xcb, 0x14, 0x31, 0x37, 0x8b, 0x9c, 0xab, 0xbe, 0x66,
    };
    const uint8_t BTC_SIG2[] = {
        0x21, 0x8a, 0x4e, 0xa7, 0xd7, 0xa0, 0x83, 0xc9, 0x06, 0x32, 0x7e, 0x89, 0x64, 0x9d, 0xa8, 0x69,
        0x4c, 0xee, 0x7a, 0x45, 0xfd, 0xb5, 0xc7, 0x2a, 0xb7, 0xf9, 0xe4, 0x80, 0xfb, 0xf9, 0xfc, 0xfc,
        0x3c, 0x3f, 0x21, 0x5a, 0x2b, 0xc9, 0x09, 0x32, 0x37, 0x2d, 0x66, 0x19, 0x8a, 0xa3, 0x1f, 0xa7,
        0x92, 0x14, 0x7a, 0xe3, 0x2a, 0x11, 0xff, 0x0d, 0x48, 0x2d, 0xdd, 0x6d, 0xa5, 0xd1, 0x75, 0x6e,
    };
    const uint8_t CHAIN_HASH[] = {
        0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
        0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
    };
    const uint64_t SHORT_CHANNEL_ID = 0x0001b10000050000;
    const uint8_t NODEID1[] = {
        0x02, 0x44, 0x45, 0x64, 0x34, 0x60, 0x9f, 0x53, 0x68, 0x3c, 0x6d, 0x9c, 0x33, 0x13, 0x29, 0xa6,
        0x3b, 0x0f, 0x24, 0x8b, 0x73, 0xf9, 0x46, 0x8c, 0xf5, 0x49, 0xa5, 0x61, 0x00, 0xdb, 0x07, 0xbf,
        0x0e,
    };
    const uint8_t NODEID2[] = {
        0x03, 0xbb, 0x44, 0x01, 0xc2, 0xf2, 0xcd, 0xc5, 0xbf, 0x77, 0x4a, 0x31, 0xef, 0x4a, 0x31, 0x3e,
        0x43, 0xc9, 0x9b, 0x8a, 0x69, 0xa7, 0x7e, 0x08, 0xc8, 0xdf, 0xf4, 0xd7, 0x55, 0x2c, 0xf3, 0xcc,
        0x75,
    };
    const uint8_t BTCKEY1[] = {
        0x02, 0x14, 0x7b, 0x23, 0xa8, 0xf8, 0x24, 0xe7, 0x16, 0x71, 0x2f, 0xcc, 0xb0, 0x1d, 0x2e, 0x49,
        0x14, 0x6d, 0x53, 0x32, 0x7c, 0xc2, 0xb6, 0xea, 0x93, 0xa6, 0xb4, 0xed, 0x5f, 0x69, 0x80, 0x99,
        0xcb,
    };
    const uint8_t BTCKEY2[] = {
        0x02, 0x7d, 0xfe, 0x1b, 0xa5, 0x07, 0x34, 0xe8, 0x2e, 0xfa, 0x8c, 0x62, 0x64, 0x11, 0x27, 0xd9,
        0xb2, 0xbb, 0x1d, 0x9b, 0x3a, 0x9c, 0x29, 0xb2, 0x0a, 0xf7, 0xd0, 0x43, 0x93, 0xe2, 0xa2, 0x71,
        0x43,
    };
}

namespace CHANUPD {
    //regtest
    const uint8_t CHANUPD[] = {
        0x01, 0x02,
        
        //signature
        0x0d, 0x25, 0x6b, 0x30, 0xfc, 0x6b, 0x0c, 0xef, 0xff, 0x44, 0x0c, 0xd2, 0xd5, 0x72, 0x4a, 0x1d,
        0x73, 0x22, 0x22, 0xf4, 0x8d, 0x91, 0x5b, 0x39, 0xeb, 0x1b, 0x83, 0x5e, 0x60, 0x38, 0x16, 0x7c,
        0x7b, 0xd7, 0xde, 0xa6, 0xca, 0x7a, 0x50, 0x99, 0x48, 0x3f, 0x7d, 0x89, 0x09, 0x7e, 0xf6, 0xaa,
        0xf7, 0xb1, 0x17, 0x65, 0xea, 0x77, 0x94, 0x72, 0xaa, 0xce, 0x68, 0x0f, 0x85, 0xb5, 0x6a, 0x78,
        //chain_hash
        0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
        0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
        //short_channel_id
        0x00, 0x01, 0xb1, 0x00, 0x00, 0x04, 0x00, 0x00,
        //timestamp
        0x5c, 0x41, 0xa7, 0x78,
        //message_flags
        0x00,
        //channel_flags
        0x01,
        //cltv_expiry_delta
        0x00, 0x24,
        //htlc_minimum_msat
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        //fee_base_msat
        0x00, 0x00, 0x00, 0x0a,
        //fee_proportional_millionths
        0x00, 0x00, 0x00, 0x64,
    };
    const uint64_t SHORT_CHANNEL_ID = 0x0001b10000040000;
    const uint32_t TIMESTAMP = 0x5c41a778;
    const uint8_t MSG_FLAG = 0x00;
    const uint8_t CHAN_FLAG = 0x01;
    const uint16_t CLTV_EXPIRY_DELTA = 0x24;
    const uint64_t HTLC_MINIMUM_MSAT = 0;
    const uint32_t FEE_BASE_MSAT = 0x0a;
    const uint32_t FEE_PROP_MILLIONTHS = 0x64;
}

////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        RESET_FAKE(ln_db_preimage_cur_close)
        RESET_FAKE(ln_db_cnlupd_load)
        RESET_FAKE(ln_db_preimage_del)
        RESET_FAKE(ln_db_preimage_cur_open)
        RESET_FAKE(ln_db_preimage_cur_get)
        RESET_FAKE(ln_db_channel_search)
        RESET_FAKE(ln_db_channel_search_readonly)
        RESET_FAKE(ln_db_payment_hash_save)
        RESET_FAKE(ln_db_preimage_search)
        RESET_FAKE(ln_db_cnlupd_need_to_prune)
        RESET_FAKE(ln_db_cnlupd_save)
        RESET_FAKE(ln_db_cnlanno_load)

        RESET_FAKE(ln_msg_channel_update_read)
        RESET_FAKE(ln_msg_channel_update_verify)
        RESET_FAKE(ln_msg_channel_announcement_read)

        ln_db_cnlupd_need_to_prune_fake.return_val = false;
        ln_db_cnlupd_save_fake.return_val = true;
        ln_db_cnlanno_load_fake.return_val = true;
        ln_msg_channel_update_read_fake.return_val = true;
        ln_msg_channel_update_verify_fake.return_val = true;
        ln_msg_channel_announcement_read_fake.return_val = true;

        utl_dbg_malloc_cnt_reset();
        btc_init(BTC_BLOCK_CHAIN_BTCTEST, true);
    }

    virtual void TearDown() {
        ln_node_term();
        btc_term();
        ASSERT_EQ(0, utl_dbg_malloc_cnt());
    }

public:
    static void DumpBin(const uint8_t *pData, uint16_t Len)
    {
        for (uint16_t lp = 0; lp < Len; lp++) {
            printf("%02x", pData[lp]);
        }
        printf("\n");
    }
    static bool DumpCheck(const void *pData, uint32_t Len, uint8_t Fill)
    {
        bool ret = true;
        const uint8_t *p = (const uint8_t *)pData;
        for (uint32_t lp = 0; lp < Len; lp++) {
            if (p[lp] != Fill) {
                ret = false;
                break;
            }
        }
        return ret;
    }
    static void LnCallbackType(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
        (void)pCommonParam; (void)pTypeSpecificParam;
        const char *p_str;
        switch (Type) {
        case LN_CB_TYPE_NOTIFY_ERROR: p_str = "LN_CB_TYPE_NOTIFY_ERROR"; break;
        case LN_CB_TYPE_NOTIFY_INIT_RECV: p_str = "LN_CB_TYPE_NOTIFY_INIT_RECV"; break;
        case LN_CB_TYPE_NOTIFY_REESTABLISH_RECV: p_str = "LN_CB_TYPE_NOTIFY_REESTABLISH_RECV"; break;
        case LN_CB_TYPE_SIGN_FUNDING_TX: p_str = "LN_CB_TYPE_SIGN_FUNDING_TX"; break;
        case LN_CB_TYPE_WAIT_FUNDING_TX: p_str = "LN_CB_TYPE_WAIT_FUNDING_TX"; break;
        case LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV: p_str = "LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV"; break;
        case LN_CB_TYPE_NOTIFY_ANNODB_UPDATE: p_str = "LN_CB_TYPE_NOTIFY_ANNODB_UPDATE"; break;
        case LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV"; break;
        case LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV"; break;
        case LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE: p_str = "LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE"; break;
        case LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV: p_str = "LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV"; break;
        case LN_CB_TYPE_NOTIFY_SHUTDOWN_RECV: p_str = "LN_CB_TYPE_NOTIFY_SHUTDOWN_RECV"; break;
        case LN_CB_TYPE_UPDATE_CLOSING_FEE: p_str = "LN_CB_TYPE_UPDATE_CLOSING_FEE"; break;
        case LN_CB_TYPE_NOTIFY_CLOSING_END: p_str = "LN_CB_TYPE_NOTIFY_CLOSING_END"; break;
        case LN_CB_TYPE_SEND_MESSAGE: p_str = "LN_CB_TYPE_SEND_MESSAGE"; break;
        case LN_CB_TYPE_GET_LATEST_FEERATE: p_str = "LN_CB_TYPE_GET_LATEST_FEERATE"; break;
        case LN_CB_TYPE_GET_BLOCK_COUNT: p_str = "LN_CB_TYPE_GET_BLOCK_COUNT"; break;
        default:
            p_str = "unknown";
        }
        printf("*** callback: %s(%d)\n", p_str, Type);
    }
    static void LnInit(ln_channel_t *pChannel)
    {
        ln_anno_param_t anno_param;

        memset(pChannel, 0xcc, sizeof(ln_channel_t));
        anno_param.cltv_expiry_delta = 10;
        anno_param.htlc_minimum_msat = 1000;
        anno_param.fee_base_msat = 20;
        anno_param.fee_prop_millionths = 200;

        ln_init(pChannel, &anno_param, NULL, (ln_callback_t)0x123456, NULL);
        pChannel->init_flag = M_INIT_FLAG_SEND | M_INIT_FLAG_RECV | M_INIT_FLAG_REEST_SEND | M_INIT_FLAG_REEST_RECV;
        pChannel->commit_info_local.dust_limit_sat = BTC_DUST_LIMIT;
        pChannel->commit_info_local.htlc_minimum_msat = 0;
        pChannel->commit_info_local.max_accepted_htlcs = 10;
        pChannel->commit_info_local.local_msat = 1000000;
        pChannel->commit_info_local.remote_msat = 1000000;
        pChannel->commit_info_remote.dust_limit_sat = BTC_DUST_LIMIT;
        pChannel->commit_info_remote.htlc_minimum_msat = 0;
        pChannel->commit_info_remote.max_accepted_htlcs = 10;
        pChannel->commit_info_remote.local_msat = 1000000;
        pChannel->commit_info_remote.remote_msat = 1000000;
        btc_tx_init(&pChannel->funding_info.tx_data);
        utl_buf_init(&pChannel->funding_info.wit_script);
        pChannel->p_callback = LnCallbackType;
        memcpy(pChannel->channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
    }
    static void LnInitSend(ln_channel_t *pChannel)
    {
        LnInit(pChannel);
    }
    static void LnInitRecv(ln_channel_t *pChannel)
    {
        LnInit(pChannel);

    }
};

////////////////////////////////////////////////////////////////////////

//OK
TEST_F(ln, recv_updatechannel_ok)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_ANNODB_UPDATE) {
                callback_called++;
            }
        }
        static bool ln_msg_channel_update_read(ln_msg_channel_update_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_chain_hash = ln_genesishash_get();
            pMsg->short_channel_id = CHANUPD::SHORT_CHANNEL_ID;
            pMsg->htlc_minimum_msat = CHANUPD::HTLC_MINIMUM_MSAT;
            pMsg->htlc_maximum_msat = 0;
            pMsg->timestamp = CHANUPD::TIMESTAMP;
            pMsg->fee_base_msat = CHANUPD::FEE_BASE_MSAT;
            pMsg->fee_proportional_millionths = CHANUPD::FEE_PROP_MILLIONTHS;
            pMsg->cltv_expiry_delta = CHANUPD::CLTV_EXPIRY_DELTA;
            pMsg->message_flags = CHANUPD::MSG_FLAG;
            pMsg->channel_flags = CHANUPD::CHAN_FLAG;
            return true;
        }
        static bool ln_db_cnlanno_load(utl_buf_t *pBuf, uint64_t ShortChannelId) {
            utl_buf_alloccopy(pBuf, CHANANNO::CHANNEL_ANNO, sizeof(CHANANNO::CHANNEL_ANNO));
            return true;
        }
        static bool ln_msg_channel_announcement_read(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_node_signature_1 = CHANANNO::NODE_SIG1;
            pMsg->p_node_signature_2 = CHANANNO::NODE_SIG2;
            pMsg->p_bitcoin_signature_1 = CHANANNO::BTC_SIG1;
            pMsg->p_bitcoin_signature_2 = CHANANNO::BTC_SIG2;
            pMsg->short_channel_id = CHANANNO::SHORT_CHANNEL_ID;
            pMsg->p_node_id_1 = CHANANNO::NODEID1;
            pMsg->p_node_id_2 = CHANANNO::NODEID2;
            pMsg->p_bitcoin_key_1 = CHANANNO::BTCKEY1;
            pMsg->p_bitcoin_key_2 = CHANANNO::BTCKEY2;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_channel_update_read_fake.custom_fake = dummy::ln_msg_channel_update_read;
    ln_db_cnlanno_load_fake.custom_fake = dummy::ln_db_cnlanno_load;
    ln_msg_channel_announcement_read_fake.custom_fake = dummy::ln_msg_channel_announcement_read;

    utl_time_time_fake.return_val = CHANUPD::TIMESTAMP;

    bool ret = ln_channel_update_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, ln_db_cnlupd_need_to_prune_fake.call_count);
    //ASSERT_EQ(1, ln_msg_channel_update_verify_fake.call_count); //XXX: dissable to vefiry sigs
    ASSERT_EQ(1, ln_db_cnlupd_save_fake.call_count);
    ASSERT_EQ(1, callback_called);

    ln_term(&channel);
}


TEST_F(ln, recv_updatechannel_timestamp_toofar_in)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_ANNODB_UPDATE) {
                callback_called++;
            }
        }
        static bool ln_msg_channel_update_read(ln_msg_channel_update_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_chain_hash = ln_genesishash_get();
            pMsg->short_channel_id = CHANUPD::SHORT_CHANNEL_ID;
            pMsg->htlc_minimum_msat = CHANUPD::HTLC_MINIMUM_MSAT;
            pMsg->htlc_maximum_msat = 0;
            pMsg->timestamp = CHANUPD::TIMESTAMP + 3600;
            pMsg->fee_base_msat = CHANUPD::FEE_BASE_MSAT;
            pMsg->fee_proportional_millionths = CHANUPD::FEE_PROP_MILLIONTHS;
            pMsg->cltv_expiry_delta = CHANUPD::CLTV_EXPIRY_DELTA;
            pMsg->message_flags = CHANUPD::MSG_FLAG;
            pMsg->channel_flags = CHANUPD::CHAN_FLAG;
            return true;
        }
        static bool ln_db_cnlanno_load(utl_buf_t *pBuf, uint64_t ShortChannelId) {
            utl_buf_alloccopy(pBuf, CHANANNO::CHANNEL_ANNO, sizeof(CHANANNO::CHANNEL_ANNO));
            return true;
        }
        static bool ln_msg_channel_announcement_read(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_node_signature_1 = CHANANNO::NODE_SIG1;
            pMsg->p_node_signature_2 = CHANANNO::NODE_SIG2;
            pMsg->p_bitcoin_signature_1 = CHANANNO::BTC_SIG1;
            pMsg->p_bitcoin_signature_2 = CHANANNO::BTC_SIG2;
            pMsg->short_channel_id = CHANANNO::SHORT_CHANNEL_ID;
            pMsg->p_node_id_1 = CHANANNO::NODEID1;
            pMsg->p_node_id_2 = CHANANNO::NODEID2;
            pMsg->p_bitcoin_key_1 = CHANANNO::BTCKEY1;
            pMsg->p_bitcoin_key_2 = CHANANNO::BTCKEY2;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_channel_update_read_fake.custom_fake = dummy::ln_msg_channel_update_read;
    ln_db_cnlanno_load_fake.custom_fake = dummy::ln_db_cnlanno_load;
    ln_msg_channel_announcement_read_fake.custom_fake = dummy::ln_msg_channel_announcement_read;

    utl_time_time_fake.return_val = CHANUPD::TIMESTAMP;

    bool ret = ln_channel_update_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, ln_db_cnlupd_need_to_prune_fake.call_count);
    //ASSERT_EQ(1, ln_msg_channel_update_verify_fake.call_count); //XXX: disable to verify sigs
    ASSERT_EQ(1, ln_db_cnlupd_save_fake.call_count);
    ASSERT_EQ(1, callback_called);

    ln_term(&channel);
}


TEST_F(ln, recv_updatechannel_timestamp_toofar_out)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_ANNODB_UPDATE) {
                callback_called++;
            }
        }
        static bool ln_msg_channel_update_read(ln_msg_channel_update_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_chain_hash = ln_genesishash_get();
            pMsg->short_channel_id = CHANUPD::SHORT_CHANNEL_ID;
            pMsg->htlc_minimum_msat = CHANUPD::HTLC_MINIMUM_MSAT;
            pMsg->htlc_maximum_msat = 0;
            pMsg->timestamp = CHANUPD::TIMESTAMP + 3600 + 1;    //***
            pMsg->fee_base_msat = CHANUPD::FEE_BASE_MSAT;
            pMsg->fee_proportional_millionths = CHANUPD::FEE_PROP_MILLIONTHS;
            pMsg->cltv_expiry_delta = CHANUPD::CLTV_EXPIRY_DELTA;
            pMsg->message_flags = CHANUPD::MSG_FLAG;
            pMsg->channel_flags = CHANUPD::CHAN_FLAG;
            return true;
        }
        static bool ln_db_cnlanno_load(utl_buf_t *pBuf, uint64_t ShortChannelId) {
            utl_buf_alloccopy(pBuf, CHANANNO::CHANNEL_ANNO, sizeof(CHANANNO::CHANNEL_ANNO));
            return true;
        }
        static bool ln_msg_channel_announcement_read(ln_msg_channel_announcement_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_node_signature_1 = CHANANNO::NODE_SIG1;
            pMsg->p_node_signature_2 = CHANANNO::NODE_SIG2;
            pMsg->p_bitcoin_signature_1 = CHANANNO::BTC_SIG1;
            pMsg->p_bitcoin_signature_2 = CHANANNO::BTC_SIG2;
            pMsg->short_channel_id = CHANANNO::SHORT_CHANNEL_ID;
            pMsg->p_node_id_1 = CHANANNO::NODEID1;
            pMsg->p_node_id_2 = CHANANNO::NODEID2;
            pMsg->p_bitcoin_key_1 = CHANANNO::BTCKEY1;
            pMsg->p_bitcoin_key_2 = CHANANNO::BTCKEY2;
            return true;
        }
    };
    
    channel.p_callback = dummy::callback;
    ln_msg_channel_update_read_fake.custom_fake = dummy::ln_msg_channel_update_read;
    ln_db_cnlanno_load_fake.custom_fake = dummy::ln_db_cnlanno_load;
    ln_msg_channel_announcement_read_fake.custom_fake = dummy::ln_msg_channel_announcement_read;

    utl_time_time_fake.return_val = CHANUPD::TIMESTAMP;

    bool ret = ln_channel_update_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, ln_db_cnlupd_need_to_prune_fake.call_count);
    //ASSERT_EQ(1, ln_msg_channel_update_verify_fake.call_count); //XXX: disable to verify sigs
    ASSERT_EQ(0, ln_db_cnlupd_save_fake.call_count);
    ASSERT_EQ(0, callback_called);

    ln_term(&channel);
}
