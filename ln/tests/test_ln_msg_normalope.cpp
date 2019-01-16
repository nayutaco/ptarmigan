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
#include "ln_msg_normalope.c"
#include "ln_misc.c"
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
    const uint64_t ID = UINT64_C(0x2a9739910d80ed97);
    const uint64_t AMOUNT_MSAT = UINT64_C(0x8386d9618134434b);
    const uint8_t PAYMENT_HASH[] = {
        0x44, 0x5e, 0x17, 0xaf, 0x29, 0x7e, 0xd3, 0x02, 0x98, 0xb9, 0xa0, 0x77, 0x3d, 0x60, 0xec, 0x84,
        0xc5, 0x07, 0xbe, 0x5b, 0xfa, 0xd1, 0xc6, 0xbb, 0xe1, 0xa2, 0x8d, 0xeb, 0x8b, 0xba, 0x10, 0x4f,
    };
    const uint32_t CLTV_EXPIRY = 0xe94ea886;
    uint8_t onion_routing_packet[LN_SZ_ONION_ROUTE];
    const uint8_t PAYMENT_PREIMAGE[] = {
        0x55, 0x5b, 0xbf, 0xba, 0x85, 0x1c, 0x7f, 0x22, 0xac, 0x4d, 0xab, 0x64, 0x79, 0x8f, 0xf3, 0x39,
        0x25, 0xc5, 0x94, 0x3e, 0x04, 0xf6, 0xf2, 0x94, 0xe2, 0x21, 0x9c, 0x70, 0x4c, 0xa0, 0x3b, 0x86,
    };
    uint8_t reason[256];
}


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        utl_dbg_malloc_cnt_reset();
        ASSERT_TRUE(btc_rng_init());
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::onion_routing_packet, sizeof(LN_DUMMY::onion_routing_packet)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::reason, sizeof(LN_DUMMY::reason)));
        btc_rng_free();
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

TEST_F(ln, update_add_htlc)
{
    ln_msg_update_add_htlc_t msg;
    utl_buf_t buf;

    msg.p_channel_id = LN_DUMMY::CHANNEL_ID;
    msg.id = LN_DUMMY::ID;
    msg.amount_msat = LN_DUMMY::AMOUNT_MSAT;
    msg.p_payment_hash = LN_DUMMY::PAYMENT_HASH;
    msg.cltv_expiry = LN_DUMMY::CLTV_EXPIRY;
    msg.p_onion_routing_packet = LN_DUMMY::onion_routing_packet;
    bool ret = ln_msg_update_add_htlc_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_update_add_htlc_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(msg.p_channel_id, LN_DUMMY::CHANNEL_ID, sizeof(LN_DUMMY::CHANNEL_ID)));
    ASSERT_EQ(msg.id, LN_DUMMY::ID);
    ASSERT_EQ(msg.amount_msat, LN_DUMMY::AMOUNT_MSAT);
    ASSERT_EQ(0, memcmp(msg.p_payment_hash, LN_DUMMY::PAYMENT_HASH, sizeof(LN_DUMMY::PAYMENT_HASH)));
    ASSERT_EQ(msg.cltv_expiry, LN_DUMMY::CLTV_EXPIRY);
    ASSERT_EQ(0, memcmp(msg.p_onion_routing_packet, LN_DUMMY::onion_routing_packet, sizeof(LN_DUMMY::onion_routing_packet)));
    utl_buf_free(&buf);
}


TEST_F(ln, update_fulfill_htlc)
{
    ln_msg_update_fulfill_htlc_t msg;
    utl_buf_t buf;

    msg.p_channel_id = LN_DUMMY::CHANNEL_ID;
    msg.id = LN_DUMMY::ID;
    msg.p_payment_preimage = LN_DUMMY::PAYMENT_PREIMAGE;
    bool ret = ln_msg_update_fulfill_htlc_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_update_fulfill_htlc_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(msg.p_channel_id, LN_DUMMY::CHANNEL_ID, sizeof(LN_DUMMY::CHANNEL_ID)));
    ASSERT_EQ(msg.id, LN_DUMMY::ID);
    ASSERT_EQ(0, memcmp(msg.p_payment_preimage, LN_DUMMY::PAYMENT_PREIMAGE, sizeof(LN_DUMMY::PAYMENT_PREIMAGE)));
    utl_buf_free(&buf);
}


TEST_F(ln, update_fail_htlc)
{
    ln_msg_update_fail_htlc_t msg;
    utl_buf_t buf;

    msg.p_channel_id = LN_DUMMY::CHANNEL_ID;
    msg.id = LN_DUMMY::ID;
    msg.len = sizeof(LN_DUMMY::reason);
    msg.p_reason = LN_DUMMY::reason;
    bool ret = ln_msg_update_fail_htlc_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_update_fail_htlc_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(msg.p_channel_id, LN_DUMMY::CHANNEL_ID, sizeof(LN_DUMMY::CHANNEL_ID)));
    ASSERT_EQ(msg.id, LN_DUMMY::ID);
    ASSERT_EQ(msg.len, sizeof(LN_DUMMY::reason));
    ASSERT_EQ(0, memcmp(msg.p_reason, LN_DUMMY::reason, sizeof(LN_DUMMY::reason)));
    utl_buf_free(&buf);
}
