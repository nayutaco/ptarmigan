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
//#include "ln_node.c"
#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

////////////////////////////////////////////////////////////////////////

namespace LN_DUMMY {
    uint8_t channel_id[LN_SZ_CHANNEL_ID];
    uint64_t short_channel_id;
    uint8_t node_signature[LN_SZ_SIGNATURE];
    uint8_t bitcoin_signature[LN_SZ_SIGNATURE];
    uint8_t node_signature_1[LN_SZ_SIGNATURE];
    uint8_t node_signature_2[LN_SZ_SIGNATURE];
    uint8_t bitcoin_signature_1[LN_SZ_SIGNATURE];
    uint8_t bitcoin_signature_2[LN_SZ_SIGNATURE];
    uint8_t features[256];
    uint8_t chain_hash[BTC_SZ_HASH256];
    uint8_t node_id_1[BTC_SZ_PUBKEY];
    uint8_t node_id_2[BTC_SZ_PUBKEY];
    uint8_t bitcoin_key_1[BTC_SZ_PUBKEY];
    uint8_t bitcoin_key_2[BTC_SZ_PUBKEY];
    uint8_t signature[LN_SZ_SIGNATURE];
    uint32_t timestamp;
    uint8_t node_id[BTC_SZ_PUBKEY];
    uint8_t rgb_color[LN_SZ_RGB_COLOR];
    uint8_t alias[LN_SZ_ALIAS_STR];
    uint8_t addresses[256];
    uint8_t ipv4_addr[LN_ADDR_DESC_ADDR_LEN_IPV4];
    uint16_t ipv4_port;
    uint8_t ipv6_addr[LN_ADDR_DESC_ADDR_LEN_IPV6];
    uint16_t ipv6_port;
    uint8_t torv2_addr[LN_ADDR_DESC_ADDR_LEN_TORV2];
    uint16_t torv2_port;
    uint8_t torv3_addr[LN_ADDR_DESC_ADDR_LEN_TORV3];
    uint16_t torv3_port;
    uint8_t message_flags;
    uint8_t channel_flags;
    uint16_t cltv_expiry_delta;
    uint64_t htlc_minimum_msat;
    uint32_t fee_base_msat;
    uint32_t fee_proportional_millionths;
    uint64_t htlc_maximum_msat;
    uint8_t encoded_short_ids[128];
    uint8_t complete;
    uint32_t first_blocknum;
    uint32_t number_of_blocks;
    uint32_t first_timestamp;
    uint32_t timestamp_range;
}


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        utl_dbg_malloc_cnt_reset();
        ASSERT_TRUE(btc_rng_init());
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::channel_id, sizeof(LN_DUMMY::channel_id)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::short_channel_id, sizeof(LN_DUMMY::short_channel_id)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::node_signature, sizeof(LN_DUMMY::node_signature)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::bitcoin_signature, sizeof(LN_DUMMY::bitcoin_signature)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::node_signature_1, sizeof(LN_DUMMY::node_signature_1)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::node_signature_2, sizeof(LN_DUMMY::node_signature_2)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::bitcoin_signature_1, sizeof(LN_DUMMY::bitcoin_signature_1)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::bitcoin_signature_2, sizeof(LN_DUMMY::bitcoin_signature_2)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::features, sizeof(LN_DUMMY::features)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::node_id_1, sizeof(LN_DUMMY::node_id_1)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::node_id_2, sizeof(LN_DUMMY::node_id_2)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::bitcoin_key_1, sizeof(LN_DUMMY::bitcoin_key_1)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::bitcoin_key_2, sizeof(LN_DUMMY::bitcoin_key_2)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::signature, sizeof(LN_DUMMY::signature)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::timestamp, sizeof(LN_DUMMY::timestamp)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::node_id, sizeof(LN_DUMMY::node_id)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::rgb_color, sizeof(LN_DUMMY::rgb_color)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::alias, sizeof(LN_DUMMY::alias)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::addresses, sizeof(LN_DUMMY::addresses)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::ipv4_addr, sizeof(LN_DUMMY::ipv4_addr)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::ipv4_port, sizeof(LN_DUMMY::ipv4_port)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::ipv6_addr, sizeof(LN_DUMMY::ipv6_addr)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::ipv6_port, sizeof(LN_DUMMY::ipv6_port)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::torv2_addr, sizeof(LN_DUMMY::torv2_addr)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::torv2_port, sizeof(LN_DUMMY::torv2_port)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::torv3_addr, sizeof(LN_DUMMY::torv3_addr)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::torv3_port, sizeof(LN_DUMMY::torv3_port)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::message_flags, sizeof(LN_DUMMY::message_flags)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::channel_flags, sizeof(LN_DUMMY::channel_flags)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::cltv_expiry_delta, sizeof(LN_DUMMY::cltv_expiry_delta)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::htlc_minimum_msat, sizeof(LN_DUMMY::htlc_minimum_msat)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::fee_base_msat, sizeof(LN_DUMMY::fee_base_msat)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::fee_proportional_millionths, sizeof(LN_DUMMY::fee_proportional_millionths)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::htlc_maximum_msat, sizeof(LN_DUMMY::htlc_maximum_msat)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::encoded_short_ids, sizeof(LN_DUMMY::encoded_short_ids)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::complete, sizeof(LN_DUMMY::complete)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::first_blocknum, sizeof(LN_DUMMY::first_blocknum)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::number_of_blocks, sizeof(LN_DUMMY::number_of_blocks)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::first_timestamp, sizeof(LN_DUMMY::first_timestamp)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::timestamp_range, sizeof(LN_DUMMY::timestamp_range)));
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

TEST_F(ln, announcement_signatures)
{
    ln_msg_announcement_signatures_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_channel_id = LN_DUMMY::channel_id;
    msg.short_channel_id = LN_DUMMY::short_channel_id;
    msg.p_node_signature = LN_DUMMY::node_signature;
    msg.p_bitcoin_signature = LN_DUMMY::bitcoin_signature;
    bool ret = ln_msg_announcement_signatures_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_announcement_signatures_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(msg.p_channel_id, LN_DUMMY::channel_id, sizeof(LN_DUMMY::channel_id)));
    ASSERT_EQ(msg.short_channel_id, LN_DUMMY::short_channel_id);
    ASSERT_EQ(0, memcmp(msg.p_node_signature, LN_DUMMY::node_signature, sizeof(LN_DUMMY::node_signature)));
    ASSERT_EQ(0, memcmp(msg.p_bitcoin_signature, LN_DUMMY::bitcoin_signature, sizeof(LN_DUMMY::bitcoin_signature)));
    utl_buf_free(&buf);
}


TEST_F(ln, channel_announcement)
{
    ln_msg_channel_announcement_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_node_signature_1 = LN_DUMMY::node_signature_1;
    msg.p_node_signature_2 = LN_DUMMY::node_signature_2;
    msg.p_bitcoin_signature_1 = LN_DUMMY::bitcoin_signature_1;
    msg.p_bitcoin_signature_2 = LN_DUMMY::bitcoin_signature_2;
    msg.len = sizeof(LN_DUMMY::features);
    msg.p_features = LN_DUMMY::features;
    msg.p_chain_hash = LN_DUMMY::chain_hash;
    msg.short_channel_id = LN_DUMMY::short_channel_id;
    msg.p_node_id_1 = LN_DUMMY::node_id_1;
    msg.p_node_id_2 = LN_DUMMY::node_id_2;
    msg.p_bitcoin_key_1 = LN_DUMMY::bitcoin_key_1;
    msg.p_bitcoin_key_2 = LN_DUMMY::bitcoin_key_2;
    bool ret = ln_msg_channel_announcement_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_channel_announcement_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(msg.p_node_signature_1, LN_DUMMY::node_signature_1, sizeof(LN_DUMMY::node_signature_1)));
    ASSERT_EQ(0, memcmp(msg.p_node_signature_2, LN_DUMMY::node_signature_2, sizeof(LN_DUMMY::node_signature_2)));
    ASSERT_EQ(0, memcmp(msg.p_bitcoin_signature_1, LN_DUMMY::bitcoin_signature_1, sizeof(LN_DUMMY::bitcoin_signature_1)));
    ASSERT_EQ(0, memcmp(msg.p_bitcoin_signature_2, LN_DUMMY::bitcoin_signature_2, sizeof(LN_DUMMY::bitcoin_signature_2)));
    ASSERT_EQ(msg.len, sizeof(LN_DUMMY::features));
    ASSERT_EQ(0, memcmp(msg.p_features, LN_DUMMY::features, sizeof(LN_DUMMY::features)));
    ASSERT_EQ(0, memcmp(msg.p_chain_hash, LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
    ASSERT_EQ(msg.short_channel_id, LN_DUMMY::short_channel_id);
    ASSERT_EQ(0, memcmp(msg.p_node_id_1, LN_DUMMY::node_id_1, sizeof(LN_DUMMY::node_id_1)));
    ASSERT_EQ(0, memcmp(msg.p_node_id_2, LN_DUMMY::node_id_2, sizeof(LN_DUMMY::node_id_2)));
    ASSERT_EQ(0, memcmp(msg.p_bitcoin_key_1, LN_DUMMY::bitcoin_key_1, sizeof(LN_DUMMY::bitcoin_key_1)));
    ASSERT_EQ(0, memcmp(msg.p_bitcoin_key_2, LN_DUMMY::bitcoin_key_2, sizeof(LN_DUMMY::bitcoin_key_2)));
    utl_buf_free(&buf);
}


TEST_F(ln, node_announcement)
{
    ln_msg_node_announcement_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_signature = LN_DUMMY::signature;
    msg.flen = (uint16_t)sizeof(LN_DUMMY::features);
    msg.p_features = LN_DUMMY::features;
    msg.timestamp = LN_DUMMY::timestamp;
    msg.p_node_id = LN_DUMMY::node_id;
    msg.p_rgb_color = LN_DUMMY::rgb_color;
    msg.p_alias = LN_DUMMY::alias;
    msg.addrlen = (uint16_t)sizeof(LN_DUMMY::addresses);
    msg.p_addresses = LN_DUMMY::addresses;
    bool ret = ln_msg_node_announcement_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_node_announcement_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(msg.p_signature, LN_DUMMY::signature, sizeof(LN_DUMMY::signature)));
    ASSERT_EQ(msg.flen, (uint16_t)sizeof(LN_DUMMY::features));
    ASSERT_EQ(0, memcmp(msg.p_features, LN_DUMMY::features, sizeof(LN_DUMMY::features)));
    ASSERT_EQ(msg.timestamp, LN_DUMMY::timestamp);
    ASSERT_EQ(0, memcmp(msg.p_node_id, LN_DUMMY::node_id, sizeof(LN_DUMMY::node_id)));
    ASSERT_EQ(0, memcmp(msg.p_rgb_color, LN_DUMMY::rgb_color, sizeof(LN_DUMMY::rgb_color)));
    ASSERT_EQ(0, memcmp(msg.p_alias, LN_DUMMY::alias, sizeof(LN_DUMMY::alias)));
    ASSERT_EQ(msg.addrlen, (uint16_t)sizeof(LN_DUMMY::addresses));
    ASSERT_EQ(0, memcmp(msg.p_addresses, LN_DUMMY::addresses, sizeof(LN_DUMMY::addresses)));
    utl_buf_free(&buf);
}


TEST_F(ln, node_announcement_addresses)
{
    ln_msg_node_announcement_addresses_t addrs;
    utl_buf_t buf = UTL_BUF_INIT;

    addrs.num = 0;
    addrs.addresses[addrs.num].type = LN_ADDR_DESC_TYPE_IPV4;
    addrs.addresses[addrs.num].p_addr = LN_DUMMY::ipv4_addr;
    addrs.addresses[addrs.num].port = LN_DUMMY::ipv4_port;
    addrs.num++;
    addrs.addresses[addrs.num].type = LN_ADDR_DESC_TYPE_IPV6;
    addrs.addresses[addrs.num].p_addr = LN_DUMMY::ipv6_addr;
    addrs.addresses[addrs.num].port = LN_DUMMY::ipv6_port;
    addrs.num++;
    addrs.addresses[addrs.num].type = LN_ADDR_DESC_TYPE_TORV2;
    addrs.addresses[addrs.num].p_addr = LN_DUMMY::torv2_addr;
    addrs.addresses[addrs.num].port = LN_DUMMY::torv2_port;
    addrs.num++;
    addrs.addresses[addrs.num].type = LN_ADDR_DESC_TYPE_TORV3;
    addrs.addresses[addrs.num].p_addr = LN_DUMMY::torv3_addr;
    addrs.addresses[addrs.num].port = LN_DUMMY::torv3_port;
    addrs.num++;
    bool ret = ln_msg_node_announcement_addresses_write(&buf, &addrs);
    ASSERT_TRUE(ret);

    memset(&addrs, 0x00, sizeof(addrs)); //clear
    ret = ln_msg_node_announcement_addresses_read(&addrs, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);
    ASSERT_EQ(addrs.num, 4);
    addrs.num = 0;
    ASSERT_EQ(addrs.addresses[addrs.num].type, LN_ADDR_DESC_TYPE_IPV4);
    ASSERT_EQ(0, memcmp(addrs.addresses[addrs.num].p_addr, LN_DUMMY::ipv4_addr, sizeof(LN_DUMMY::ipv4_addr)));
    ASSERT_EQ(addrs.addresses[addrs.num].port, LN_DUMMY::ipv4_port);
    addrs.num++;
    ASSERT_EQ(addrs.addresses[addrs.num].type, LN_ADDR_DESC_TYPE_IPV6);
    ASSERT_EQ(0, memcmp(addrs.addresses[addrs.num].p_addr, LN_DUMMY::ipv6_addr, sizeof(LN_DUMMY::ipv6_addr)));
    ASSERT_EQ(addrs.addresses[addrs.num].port, LN_DUMMY::ipv6_port);
    addrs.num++;
    ASSERT_EQ(addrs.addresses[addrs.num].type, LN_ADDR_DESC_TYPE_TORV2);
    ASSERT_EQ(0, memcmp(addrs.addresses[addrs.num].p_addr, LN_DUMMY::torv2_addr, sizeof(LN_DUMMY::torv2_addr)));
    ASSERT_EQ(addrs.addresses[addrs.num].port, LN_DUMMY::torv2_port);
    addrs.num++;
    ASSERT_EQ(addrs.addresses[addrs.num].type, LN_ADDR_DESC_TYPE_TORV3);
    ASSERT_EQ(0, memcmp(addrs.addresses[addrs.num].p_addr, LN_DUMMY::torv3_addr, sizeof(LN_DUMMY::torv3_addr)));
    ASSERT_EQ(addrs.addresses[addrs.num].port, LN_DUMMY::torv3_port);
    addrs.num++;
    utl_buf_free(&buf);
}


TEST_F(ln, channel_update)
{
    ln_msg_channel_update_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_signature = LN_DUMMY::signature;
    msg.p_chain_hash = LN_DUMMY::chain_hash;
    msg.short_channel_id = LN_DUMMY::short_channel_id;
    msg.timestamp = LN_DUMMY::timestamp;
    msg.message_flags = LN_DUMMY::message_flags | LN_CHANNEL_UPDATE_MSGFLAGS_OPTION_CHANNEL_HTLC_MAX;
    msg.channel_flags = LN_DUMMY::channel_flags;
    msg.cltv_expiry_delta = LN_DUMMY::cltv_expiry_delta;
    msg.htlc_minimum_msat = LN_DUMMY::htlc_minimum_msat;
    msg.fee_base_msat = LN_DUMMY::fee_base_msat;
    msg.fee_proportional_millionths = LN_DUMMY::fee_proportional_millionths;
    msg.htlc_maximum_msat = LN_DUMMY::htlc_maximum_msat;
    bool ret = ln_msg_channel_update_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_channel_update_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);

    ASSERT_EQ(0, memcmp(msg.p_signature, LN_DUMMY::signature, sizeof(LN_DUMMY::signature)));
    ASSERT_EQ(0, memcmp(msg.p_chain_hash, LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
    ASSERT_EQ(msg.short_channel_id, LN_DUMMY::short_channel_id);
    ASSERT_EQ(msg.timestamp, LN_DUMMY::timestamp);
    ASSERT_EQ(msg.message_flags, LN_DUMMY::message_flags | LN_CHANNEL_UPDATE_MSGFLAGS_OPTION_CHANNEL_HTLC_MAX);
    ASSERT_EQ(msg.channel_flags, LN_DUMMY::channel_flags);
    ASSERT_EQ(msg.cltv_expiry_delta, LN_DUMMY::cltv_expiry_delta);
    ASSERT_EQ(msg.htlc_minimum_msat, LN_DUMMY::htlc_minimum_msat);
    ASSERT_EQ(msg.fee_base_msat, LN_DUMMY::fee_base_msat);
    ASSERT_EQ(msg.fee_proportional_millionths, LN_DUMMY::fee_proportional_millionths);
    ASSERT_EQ(msg.htlc_maximum_msat, LN_DUMMY::htlc_maximum_msat);
    utl_buf_free(&buf);
}


TEST_F(ln, query_short_channel_ids)
{
    ln_msg_query_short_channel_ids_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_chain_hash = LN_DUMMY::chain_hash;
    msg.len = (uint16_t)sizeof(LN_DUMMY::encoded_short_ids);
    msg.p_encoded_short_ids = LN_DUMMY::encoded_short_ids;
    bool ret = ln_msg_query_short_channel_ids_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_query_short_channel_ids_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);

    ASSERT_EQ(0, memcmp(msg.p_chain_hash, LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
    ASSERT_EQ(sizeof(LN_DUMMY::encoded_short_ids), msg.len);
    ASSERT_EQ(0, memcmp(msg.p_encoded_short_ids, LN_DUMMY::encoded_short_ids, sizeof(LN_DUMMY::encoded_short_ids)));
    utl_buf_free(&buf);
}


TEST_F(ln, reply_short_channel_ids_end)
{
    ln_msg_reply_short_channel_ids_end_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_chain_hash = LN_DUMMY::chain_hash;
    msg.complete = LN_DUMMY::complete;
    bool ret = ln_msg_reply_short_channel_ids_end_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_reply_short_channel_ids_end_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);

    ASSERT_EQ(0, memcmp(msg.p_chain_hash, LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
    ASSERT_EQ(LN_DUMMY::complete, msg.complete);
    utl_buf_free(&buf);
}


TEST_F(ln, query_channel_range)
{
    ln_msg_query_channel_range_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_chain_hash = LN_DUMMY::chain_hash;
    msg.first_blocknum = LN_DUMMY::first_blocknum;
    msg.number_of_blocks = LN_DUMMY::number_of_blocks;
    bool ret = ln_msg_query_channel_range_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_query_channel_range_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);

    ASSERT_EQ(0, memcmp(msg.p_chain_hash, LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
    ASSERT_EQ(LN_DUMMY::first_blocknum, msg.first_blocknum);
    ASSERT_EQ(LN_DUMMY::number_of_blocks, msg.number_of_blocks);
    utl_buf_free(&buf);
}


TEST_F(ln, reply_channel_range)
{
    ln_msg_reply_channel_range_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_chain_hash = LN_DUMMY::chain_hash;
    msg.first_blocknum = LN_DUMMY::first_blocknum;
    msg.number_of_blocks = LN_DUMMY::number_of_blocks;
    msg.complete = LN_DUMMY::complete;
    msg.len = (uint16_t)sizeof(LN_DUMMY::encoded_short_ids);
    msg.p_encoded_short_ids = LN_DUMMY::encoded_short_ids;
    bool ret = ln_msg_reply_channel_range_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_reply_channel_range_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);

    ASSERT_EQ(0, memcmp(msg.p_chain_hash, LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
    ASSERT_EQ(LN_DUMMY::first_blocknum, msg.first_blocknum);
    ASSERT_EQ(LN_DUMMY::number_of_blocks, msg.number_of_blocks);
    ASSERT_EQ(LN_DUMMY::complete, msg.complete);
    ASSERT_EQ(sizeof(LN_DUMMY::encoded_short_ids), msg.len);
    ASSERT_EQ(0, memcmp(msg.p_encoded_short_ids, LN_DUMMY::encoded_short_ids, sizeof(LN_DUMMY::encoded_short_ids)));
    utl_buf_free(&buf);
}


TEST_F(ln, gossip_timestamp_filter)
{
    ln_msg_gossip_timestamp_filter_t msg;
    utl_buf_t buf = UTL_BUF_INIT;

    msg.p_chain_hash = LN_DUMMY::chain_hash;
    msg.first_timestamp = LN_DUMMY::first_timestamp;
    msg.timestamp_range = LN_DUMMY::timestamp_range;
    bool ret = ln_msg_gossip_timestamp_filter_write(&buf, &msg);
    ASSERT_TRUE(ret);

    memset(&msg, 0x00, sizeof(msg)); //clear
    ret = ln_msg_gossip_timestamp_filter_read(&msg, buf.buf, (uint16_t)buf.len);
    ASSERT_TRUE(ret);

    ASSERT_EQ(0, memcmp(msg.p_chain_hash, LN_DUMMY::chain_hash, sizeof(LN_DUMMY::chain_hash)));
    ASSERT_EQ(LN_DUMMY::first_timestamp, msg.first_timestamp);
    ASSERT_EQ(LN_DUMMY::timestamp_range, msg.timestamp_range);
    utl_buf_free(&buf);
}


TEST_F(ln, gossip_encoded_short_ids_none)
{
    bool ret;

    const uint8_t ENCODED_IDS[] = {
        0x00
    };

    utl_buf_t enc = UTL_BUF_INIT;
    ret = ln_msg_gossip_ids_encode(&enc, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(sizeof(ENCODED_IDS), enc.len);
    ASSERT_EQ(0, memcmp(ENCODED_IDS, enc.buf, sizeof(ENCODED_IDS)));
    utl_buf_free(&enc);

    uint64_t *p_short_ids = NULL;
    size_t num = 0;
    ret = ln_msg_gossip_ids_decode(&p_short_ids, &num, ENCODED_IDS, sizeof(ENCODED_IDS));
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, num);
    UTL_DBG_FREE(p_short_ids);
}


TEST_F(ln, gossip_encoded_short_ids1)
{
    bool ret;

    const uint64_t DECODED_IDS[] = {
        0x123456789abcdef0
    };
    const uint8_t ENCODED_IDS[] = {
        0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
    };

    utl_buf_t enc = UTL_BUF_INIT;
    ret = ln_msg_gossip_ids_encode(&enc, DECODED_IDS, sizeof(DECODED_IDS) / sizeof(uint64_t));
    ASSERT_TRUE(ret);
    ASSERT_EQ(sizeof(ENCODED_IDS), enc.len);
    ASSERT_EQ(0, memcmp(ENCODED_IDS, enc.buf, sizeof(ENCODED_IDS)));
    utl_buf_free(&enc);

    uint64_t *p_short_ids = NULL;
    size_t num = 0;
    ret = ln_msg_gossip_ids_decode(&p_short_ids, &num, ENCODED_IDS, sizeof(ENCODED_IDS));
    ASSERT_TRUE(ret);
    ASSERT_EQ((sizeof(DECODED_IDS) / sizeof(uint64_t)), num);
    ASSERT_EQ(0, memcmp(DECODED_IDS, p_short_ids, sizeof(DECODED_IDS)));
    UTL_DBG_FREE(p_short_ids);
}
