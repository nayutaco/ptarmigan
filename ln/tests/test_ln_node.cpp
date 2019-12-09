#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
// #undef LOG_TAG
// #include "../../utl/utl_thread.c"
#undef LOG_TAG
#include "../../utl/utl_log.c"
#undef LOG_TAG
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
// #include "../../utl/utl_push.c"
#include "../../utl/utl_time.c"
// #include "../../utl/utl_int.c"
#include "../../utl/utl_str.c"
#include "../../utl/utl_addr.c"
#include "../../utl/utl_net.c"
#undef LOG_TAG
#include "../../btc/btc.c"
#include "../../btc/btc_block.c"
#include "../../btc/btc_buf.c"
// #include "../../btc/btc_extkey.c"
#include "../../btc/btc_keys.c"
// #include "../../btc/btc_sw.c"
// #include "../../btc/btc_sig.c"
// #include "../../btc/btc_script.c"
// #include "../../btc/btc_tx.c"
// #include "../../btc/btc_tx_buf.c"
#include "../../btc/btc_crypto.c"
// #include "../../btc/segwit_addr.c"
// #include "../../btc/btc_segwit_addr.c"
// #include "../../btc/btc_test_util.c"

#undef LOG_TAG
#include "ln_node.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
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
};


////////////////////////////////////////////////////////////////////////

TEST_F(ln, ln_node_addr_dec_ok1)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53@1.1.1.1:1";
    const uint8_t CONN_NODE[] = {
        0x03, 0x69, 0x4d, 0x10, 0x90, 0xcb, 0xae, 0xf8, 0x85, 0xbc, 0xdf, 0x56, 0xce, 0x47, 0xe7, 0x8b,
        0x62, 0xe1, 0x30, 0xb9, 0x29, 0x10, 0x7d, 0x32, 0xf5, 0x01, 0xb1, 0x62, 0x8c, 0x4e, 0x01, 0xbd,
        0x53,
    };

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(CONN_NODE, conn.node_id, BTC_SZ_PUBKEY));
    ASSERT_STREQ("1.1.1.1", conn.addr);
    ASSERT_EQ(1, conn.port);
}


TEST_F(ln, ln_node_addr_dec_ok2)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53@223.254.254.254:65535";
    const uint8_t CONN_NODE[] = {
        0x03, 0x69, 0x4d, 0x10, 0x90, 0xcb, 0xae, 0xf8, 0x85, 0xbc, 0xdf, 0x56, 0xce, 0x47, 0xe7, 0x8b,
        0x62, 0xe1, 0x30, 0xb9, 0x29, 0x10, 0x7d, 0x32, 0xf5, 0x01, 0xb1, 0x62, 0x8c, 0x4e, 0x01, 0xbd,
        0x53,
    };

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(CONN_NODE, conn.node_id, BTC_SZ_PUBKEY));
    ASSERT_STREQ("223.254.254.254", conn.addr);
    ASSERT_EQ(65535, conn.port);
}


TEST_F(ln, ln_node_addr_dec_localhost)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53@127.0.0.1:65535";
    const uint8_t CONN_NODE[] = {
        0x03, 0x69, 0x4d, 0x10, 0x90, 0xcb, 0xae, 0xf8, 0x85, 0xbc, 0xdf, 0x56, 0xce, 0x47, 0xe7, 0x8b,
        0x62, 0xe1, 0x30, 0xb9, 0x29, 0x10, 0x7d, 0x32, 0xf5, 0x01, 0xb1, 0x62, 0x8c, 0x4e, 0x01, 0xbd,
        0x53,
    };

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(CONN_NODE, conn.node_id, BTC_SZ_PUBKEY));
    ASSERT_STREQ("127.0.0.1", conn.addr);
    ASSERT_EQ(65535, conn.port);
}


TEST_F(ln, ln_node_addr_dec_ng_key)
{
    // "0369..." --> "0469..."
    const char CONN_STR[] = "04694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53@223.254.254.254:65535";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


TEST_F(ln, ln_node_addr_dec_skip_addr1)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53"
                            "@0.0.0.0:65535";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_TRUE(ret);
}


TEST_F(ln, ln_node_addr_dec_skip_addr2)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53"
                            "@255.255.255.255:65535";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_TRUE(ret);
}


TEST_F(ln, ln_node_addr_dec_ng_no_addr)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53"
                            "@:12345";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


TEST_F(ln, ln_node_addr_dec_ng_addr_len1)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53"
                            "@223.254.254:12345";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


TEST_F(ln, ln_node_addr_dec_ng_addr_len2)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53"
                            "@223.254.254.254.254:12345";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


TEST_F(ln, ln_node_addr_dec_ng_port1)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53"
                            "@223.254.254.254:0";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


TEST_F(ln, ln_node_addr_dec_ng_port2)
{
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd53"
                            "@223.254.254.254:65536";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


TEST_F(ln, ln_node_addr_dec_ng_len1)
{
    //node_id: odd length
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd5"
                            "@223.254.254.254:12345";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


TEST_F(ln, ln_node_addr_dec_ng_len2)
{
    //node_id: 67 length
    const char CONN_STR[] = "03694d1090cbaef885bcdf56ce47e78b62e130b929107d32f501b1628c4e01bd5344"
                            "@223.254.254.254:12345";

    ln_node_conn_t conn;

    memset(&conn, 0, sizeof(conn));
    bool ret = ln_node_addr_dec(&conn, CONN_STR);
    ASSERT_FALSE(ret);
}


////////////////////////////////////////////////////////////////////////
