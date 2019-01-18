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

/*    uint64_t id;
    uint64_t amount_msat;
    uint8_t payment_hash[BTC_SZ_HASH256];
    uint32_t cltv_expiry;
    uint8_t onion_routing_packet[LN_SZ_ONION_ROUTE];
    uint8_t payment_preimage[BTC_SZ_PRIVKEY];
    uint8_t reason[256];
    uint8_t sha256_of_onion[BTC_SZ_HASH256];
    uint16_t failure_code;
    uint8_t signature[LN_SZ_SIGNATURE];
    uint8_t htlc_signature[LN_SZ_SIGNATURE * 32];
    uint8_t per_commitment_secret[BTC_SZ_PRIVKEY];
    uint8_t next_per_commitment_point[BTC_SZ_PUBKEY];
    uint32_t feerate_per_kw;*/
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
/*        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::id, sizeof(LN_DUMMY::id)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::amount_msat, sizeof(LN_DUMMY::amount_msat)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::cltv_expiry, sizeof(LN_DUMMY::cltv_expiry)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::payment_hash, sizeof(LN_DUMMY::payment_hash)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::onion_routing_packet, sizeof(LN_DUMMY::onion_routing_packet)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::payment_preimage, sizeof(LN_DUMMY::payment_preimage)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::reason, sizeof(LN_DUMMY::reason)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::sha256_of_onion, sizeof(LN_DUMMY::sha256_of_onion)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::failure_code, sizeof(LN_DUMMY::failure_code)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::signature, sizeof(LN_DUMMY::signature)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::htlc_signature, sizeof(LN_DUMMY::htlc_signature)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::per_commitment_secret, sizeof(LN_DUMMY::per_commitment_secret)));
        ASSERT_TRUE(btc_rng_big_rand(LN_DUMMY::next_per_commitment_point, sizeof(LN_DUMMY::next_per_commitment_point)));
        ASSERT_TRUE(btc_rng_big_rand((uint8_t *)&LN_DUMMY::feerate_per_kw, sizeof(LN_DUMMY::feerate_per_kw)));
*/        btc_rng_free();
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
    utl_buf_t buf;

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
    utl_buf_t buf;

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
