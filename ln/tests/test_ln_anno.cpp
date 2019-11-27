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
#include "ln_setupctl.h"
#include "ln_anno.c"
#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

FAKE_VALUE_FUNC(bool, ln_msg_query_short_channel_ids_write, utl_buf_t *, const ln_msg_query_short_channel_ids_t *);
FAKE_VALUE_FUNC(bool, ln_msg_reply_short_channel_ids_end_write, utl_buf_t *, const ln_msg_reply_short_channel_ids_end_t *);
FAKE_VALUE_FUNC(bool, ln_msg_query_channel_range_write, utl_buf_t *, const ln_msg_query_channel_range_t *);
FAKE_VALUE_FUNC(bool, ln_msg_reply_channel_range_write, utl_buf_t *, const ln_msg_reply_channel_range_t *);
FAKE_VALUE_FUNC(bool, ln_msg_gossip_timestamp_filter_write, utl_buf_t *, const ln_msg_gossip_timestamp_filter_t *);

FAKE_VALUE_FUNC(bool, ln_msg_query_short_channel_ids_read, ln_msg_query_short_channel_ids_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_reply_short_channel_ids_end_read, ln_msg_reply_short_channel_ids_end_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_query_channel_range_read, ln_msg_query_channel_range_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_reply_channel_range_read, ln_msg_reply_channel_range_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_gossip_timestamp_filter_read, ln_msg_gossip_timestamp_filter_t *, const uint8_t *, uint16_t );

FAKE_VALUE_FUNC(bool, ln_msg_gossip_ids_encode, utl_buf_t *, const uint64_t *, size_t );
FAKE_VALUE_FUNC(bool, ln_msg_gossip_ids_decode, uint64_t **, size_t *, const uint8_t *, size_t );

FAKE_VALUE_FUNC(bool, ln_db_annoinfos_del_node_id, const uint8_t *, const uint64_t *, size_t);
FAKE_VALUE_FUNC(bool, ln_db_anno_transaction)
FAKE_VOID_FUNC(ln_db_anno_commit, bool)
FAKE_VALUE_FUNC(bool, ln_db_anno_cur_open, void **, ln_db_cur_t);
FAKE_VOID_FUNC(ln_db_anno_cur_close, void *);
FAKE_VALUE_FUNC(bool, ln_db_cnlanno_cur_get, void*, uint64_t*, char *, uint32_t *, utl_buf_t *);
FAKE_VALUE_FUNC(bool, ln_db_annoinfos_del_timestamp, const uint8_t *, uint32_t , uint32_t );

////////////////////////////////////////////////////////////////////////

namespace LN_DUMMY {

}


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        utl_log_init_stderr();
        RESET_FAKE(ln_msg_query_short_channel_ids_write)
        RESET_FAKE(ln_msg_reply_short_channel_ids_end_write)
        RESET_FAKE(ln_msg_query_channel_range_write)
        RESET_FAKE(ln_msg_reply_channel_range_write)
        RESET_FAKE(ln_msg_gossip_timestamp_filter_write)
        RESET_FAKE(ln_msg_query_short_channel_ids_read)
        RESET_FAKE(ln_msg_reply_short_channel_ids_end_read)
        RESET_FAKE(ln_msg_query_channel_range_read)
        RESET_FAKE(ln_msg_reply_channel_range_read)
        RESET_FAKE(ln_msg_gossip_timestamp_filter_read)

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



TEST_F(ln, no_gossip_queries)
{
    ln_channel_t channel;
    memset(&channel, 0xcc, sizeof(channel));

    channel.init_flag = 0;

    ln_msg_query_short_channel_ids_t qsci;
    ln_msg_query_channel_range_t qcr;
    memset(&qsci, 0, sizeof(qsci));
    memset(&qcr, 0, sizeof(qcr));

    ASSERT_FALSE(ln_query_short_channel_ids_send(&channel, NULL, 0));
    ASSERT_TRUE(ln_query_short_channel_ids_recv(&channel, NULL, 0));
    ASSERT_FALSE(ln_reply_short_channel_ids_end_send(&channel, &qsci));
    ASSERT_FALSE(ln_reply_short_channel_ids_end_recv(&channel, NULL, 0));
    ASSERT_FALSE(ln_query_channel_range_send(&channel, 0, 0));
    ASSERT_TRUE(ln_query_channel_range_recv(&channel, NULL, 0));
    ASSERT_FALSE(ln_reply_channel_range_send(&channel, &qcr));
    ASSERT_FALSE(ln_reply_channel_range_recv(&channel, NULL, 0));
    ASSERT_FALSE(ln_gossip_timestamp_filter_send(&channel));
    ASSERT_TRUE(ln_gossip_timestamp_filter_recv(&channel, NULL, 0));
}
