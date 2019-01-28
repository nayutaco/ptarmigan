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
#include "ln_msg_anno.c"
#include "ln_misc.c"
//#include "ln_node.c"
#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

////////////////////////////////////////////////////////////////////////

namespace LN_DUMMY {
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
TEST_F(ln, query_short_channel_ids_write_ok)
{
    ln_msg_query_short_channel_ids_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    const uint8_t ENCODED_SHORT_IDS[16] = {
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
    };
    const uint8_t CHAIN_HASH[32] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
    };

    const uint8_t MSG[] = {
        0x01, 0x05,
        //
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
        //
        0x00, 0x10,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
    };

    msg.p_chain_hash = CHAIN_HASH;
    msg.len = 16;
    msg.p_encoded_short_ids = ENCODED_SHORT_IDS;
    bool ret = ln_msg_query_short_channel_ids_write(&buf, &msg);
    ASSERT_TRUE(ret);
    ASSERT_EQ(sizeof(MSG), buf.len);
    ASSERT_EQ(0, memcmp(MSG, buf.buf, sizeof(MSG)));
    utl_buf_free(&buf);
}


TEST_F(ln, query_short_channel_ids_read_ok1)
{
    ln_msg_query_short_channel_ids_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    const uint8_t ENCODED_SHORT_IDS[16] = {
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
    };
    const uint8_t CHAIN_HASH[32] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
    };

    const uint8_t MSG[] = {
        0x01, 0x05,
        //
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
        //
        0x00, 0x10,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
    };

    memset(&msg, 0xcc, sizeof(msg));
    bool ret = ln_msg_query_short_channel_ids_read(&msg, MSG, sizeof(MSG));
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(CHAIN_HASH, msg.p_chain_hash, sizeof(CHAIN_HASH)));
    ASSERT_EQ(MSG + 2, msg.p_chain_hash);
    ASSERT_EQ(MSG + 2 + 32 + 2, msg.p_encoded_short_ids);
    ASSERT_EQ(16, msg.len);
    ASSERT_EQ(0, memcmp(ENCODED_SHORT_IDS, msg.p_encoded_short_ids, sizeof(ENCODED_SHORT_IDS)));
    utl_buf_free(&buf);
}


TEST_F(ln, query_short_channel_ids_read_ok2)
{
    ln_msg_query_short_channel_ids_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    const uint8_t ENCODED_SHORT_IDS[16] = {
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35
    };
    const uint8_t CHAIN_HASH[32] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
    };

    const uint8_t MSG[] = {
        0x01, 0x05,
        //
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
        //
        0x00, 0x10,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
        //dust
        1, 2, 3, 4, 5       //後ろに長くても大丈夫
    };

    memset(&msg, 0xcc, sizeof(msg));
    bool ret = ln_msg_query_short_channel_ids_read(&msg, MSG, sizeof(MSG));
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(CHAIN_HASH, msg.p_chain_hash, sizeof(CHAIN_HASH)));
    ASSERT_EQ(0, memcmp(ENCODED_SHORT_IDS, msg.p_encoded_short_ids, sizeof(ENCODED_SHORT_IDS)));
    utl_buf_free(&buf);
}


TEST_F(ln, query_short_channel_ids_read_len)
{
    ln_msg_query_short_channel_ids_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    const uint8_t MSG[] = {
        0x01, 0x05,
        //
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
        //
        0x00, 0x10,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, //30, 31, 32, 33, 34, 35,   //★短い
    };

    memset(&msg, 0xcc, sizeof(msg));
    bool ret = ln_msg_query_short_channel_ids_read(&msg, MSG, sizeof(MSG));
    ASSERT_FALSE(ret);
    utl_buf_free(&buf);
}


TEST_F(ln, query_short_channel_ids_read_type)
{
    ln_msg_query_short_channel_ids_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    const uint8_t MSG[] = {
        0x01, 0x05 + 1,     //★type違う
        //
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        255, 254, 253, 252, 251, 250, 249, 248, 247, 246, 245, 244, 243, 242, 241, 240,
        //
        0x00, 0x10,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    };

    memset(&msg, 0xcc, sizeof(msg));
    bool ret = ln_msg_query_short_channel_ids_read(&msg, MSG, sizeof(MSG));
    ASSERT_FALSE(ret);
    utl_buf_free(&buf);
}
