#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
#include "../../utl/utl_log.c"
#undef LOG_TAG
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
#include "../../utl/utl_push.c"
#include "../../utl/utl_time.c"
#include "../../utl/utl_int.c"
#include "../../utl/utl_str.c"

#undef LOG_TAG
#include "../../btc/btc.c"
#include "../../btc/btc_buf.c"
// #include "../../btc/btc_extkey.c"
// #include "../../btc/btc_keys.c"
// #include "../../btc/btc_sw.c"
//#include "../../btc/btc_sig.c"
// #include "../../btc/btc_script.c"
// #include "../../btc/btc_tx.c"
// #include "../../btc/btc_tx_buf.c"
#include "../../btc/btc_crypto.c"
// #include "../../btc/segwit_addr.c"
// #include "../../btc/btc_segwit_addr.c"
// #include "../../btc/btc_test_util.c"

#undef LOG_TAG
#include "ln_msg_close.c"
//#include "ln_node.c"
#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

////////////////////////////////////////////////////////////////////////

namespace LN_DUMMY {
    const uint8_t CHANNEL_ID[] = {
        0x40, 0xfd, 0xde, 0x21, 0x7b, 0xb2, 0xd6, 0xbc, 0x4c, 0x9e, 0x20, 0xc5, 0xe5, 0x31, 0x93, 0xd0,
        0x71, 0xeb, 0xef, 0x7c, 0x13, 0x81, 0x04, 0x19, 0x82, 0x6a, 0xf8, 0x86, 0x2a, 0xf1, 0x22, 0xad,
    };
    const uint8_t SCRIPTPUBKEY[] = {
        0x44, 0x5e, 0x17, 0xaf, 0x29, 0x7e, 0xd3, 0x02, 0x98, 0xb9, 0xa0, 0x77, 0x3d, 0x60, 0xec, 0x84,
        0xc5, 0x07, 0xbe, 0x5b, 0xfa, 0xd1, 0xc6, 0xbb, 0xe1, 0xa2, 0x8d, 0xeb, 0x8b, 0xba, 0x10, 0x4f,
        0x20, 0x2a, 0x62, 0x18, 0xb4, 0xbc, 0xcd, 0x5c, 0x52, 0x3c, 0x26, 0x33, 0xa3, 0x83, 0xca, 0xaf,
        0x52, 0x22, 0x4e, 0xf1, 0x7d, 0xee, 
    };
    const uint8_t SIGNATURE[] = {
        0xcd, 0x4a, 0x49, 0x37, 0xab, 0xc6, 0xb7, 0x75, 0x53, 0x21, 0x9c, 0xb0, 0x05, 0xd6, 0xef, 0x77,
        0xb0, 0x78, 0x77, 0xa2, 0xaa, 0x00, 0x23, 0x46, 0x33, 0x98, 0x07, 0x69, 0xea, 0x4c, 0x52, 0x2d,
        0x82, 0xe5, 0x15, 0x92, 0x4a, 0xee, 0xa9, 0x83, 0x86, 0xd9, 0x61, 0x81, 0x34, 0x43, 0x4b, 0x74,
        0x55, 0x5b, 0xbf, 0xba, 0x85, 0x1c, 0x7f, 0x22, 0xac, 0x4d, 0xab, 0x64, 0x79, 0x8f, 0xf3, 0x39,
    };
}


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        utl_dbg_malloc_cnt_reset();
    }

    virtual void TearDown() {
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
};

////////////////////////////////////////////////////////////////////////

TEST_F(ln, shutdown)
{
    ln_msg_shutdown_t msg;
    utl_buf_t buf;

    msg.p_channel_id = LN_DUMMY::CHANNEL_ID;
    msg.len = (uint16_t)sizeof(LN_DUMMY::SCRIPTPUBKEY);
    msg.p_scriptpubkey = LN_DUMMY::SCRIPTPUBKEY;
    bool ret = ln_msg_shutdown_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_shutdown_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(msg.p_channel_id, LN_DUMMY::CHANNEL_ID, sizeof(LN_DUMMY::CHANNEL_ID)));
    ASSERT_EQ(msg.len, sizeof(LN_DUMMY::SCRIPTPUBKEY));
    ASSERT_EQ(0, memcmp(msg.p_scriptpubkey, LN_DUMMY::SCRIPTPUBKEY, sizeof(LN_DUMMY::SCRIPTPUBKEY)));
    utl_buf_free(&buf);
}


TEST_F(ln, closing_signed)
{
    ln_msg_closing_signed_t msg;
    utl_buf_t buf;

    msg.p_channel_id = LN_DUMMY::CHANNEL_ID;
    msg.p_signature = LN_DUMMY::SIGNATURE;
    bool ret = ln_msg_closing_signed_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_closing_signed_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(LN_DUMMY::CHANNEL_ID, msg.p_channel_id, sizeof(LN_DUMMY::CHANNEL_ID)));
    ASSERT_EQ(0, memcmp(LN_DUMMY::SIGNATURE, msg.p_signature, sizeof(LN_DUMMY::SIGNATURE)));
    utl_buf_free(&buf);
}
