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
#include "../../utl/utl_time.c"
#include "../../utl/utl_int.c"
#include "../../utl/utl_str.c"
#include "../../utl/utl_mem.c"
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
#include "ln_msg_anno.c"
#include "ln_msg_close.c"
//#include "ln_msg_establish.c"
#include "ln_msg_normalope.c"
#include "ln_node.c"
#include "ln_onion.c"
#include "ln_script.c"
#include "ln_noise.c"
#include "ln_signer.c"
#include "ln_invoice.c"
#include "ln_print.c"
#include "ln_update.c"
#include "ln_update_info.c"

#include "ln.c"
#include "ln_setupctl.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

// FAKE_VOID_FUNC(ln_db_preimage_cur_close, void *);
// FAKE_VALUE_FUNC(bool, ln_db_cnlupd_load, utl_buf_t *, uint32_t *, uint64_t, uint8_t);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_del, const uint8_t *);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_open, void **);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_get, void *, bool *, ln_db_preimage_t *, const char**);
// FAKE_VALUE_FUNC(bool, ln_db_channel_search, ln_db_func_cmp_t, void *);
// FAKE_VALUE_FUNC(bool, ln_db_channel_search_readonly, ln_db_func_cmp_t, void *);
// FAKE_VALUE_FUNC(bool, ln_db_payment_hash_save, const uint8_t*, const uint8_t*, ln_commit_tx_output_type_t, uint32_t);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_search, ln_db_func_preimage_t, void*);

// FAKE_VALUE_FUNC(bool, ln_msg_open_channel_write, utl_buf_t *, const ln_open_channel_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_open_channel_read, ln_open_channel_t*, const uint8_t*, uint16_t);
// FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_write, utl_buf_t *, const ln_msg_accept_channel_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_read, ln_msg_accept_channel_t *, const uint8_t *, uint16_t );
// FAKE_VALUE_FUNC(bool, ln_msg_funding_created_write, utl_buf_t *, const ln_funding_writed_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_funding_created_read, ln_msg_funding_created_t *, const uint8_t *, uint16_t );
// FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_write, utl_buf_t *, const ln_msg_funding_signed_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_read, ln_msg_funding_signed_t *, const uint8_t *, uint16_t );

FAKE_VALUE_FUNC(bool, ln_msg_init_write, utl_buf_t *, const ln_msg_init_t *);
FAKE_VALUE_FUNC(bool, ln_msg_init_read, ln_msg_init_t *, const uint8_t *, uint16_t );

FAKE_VALUE_FUNC(bool, ln_db_channel_save, const ln_channel_t *);

FAKE_VALUE_FUNC(bool, ln_msg_error_write, utl_buf_t *, const ln_msg_error_t *);


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        RESET_FAKE(ln_msg_init_write)
        RESET_FAKE(ln_msg_init_read)

        ln_db_channel_save_fake.return_val = true;
        ln_msg_error_write_fake.return_val = true;

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
        case LN_CB_TYPE_STOP_CHANNEL: p_str = "LN_CB_TYPE_STOP_CHANNEL"; break;
        case LN_CB_TYPE_NOTIFY_ERROR: p_str = "LN_CB_TYPE_NOTIFY_ERROR"; break;
        case LN_CB_TYPE_SEND_ERROR: p_str = "LN_CB_TYPE_SEND_ERROR"; break;
        case LN_CB_TYPE_NOTIFY_INIT_RECV: p_str = "LN_CB_TYPE_NOTIFY_INIT_RECV"; break;
        case LN_CB_TYPE_NOTIFY_REESTABLISH_RECV: p_str = "LN_CB_TYPE_NOTIFY_REESTABLISH_RECV"; break;
        case LN_CB_TYPE_SIGN_FUNDING_TX: p_str = "LN_CB_TYPE_SIGN_FUNDING_TX"; break;
        case LN_CB_TYPE_WAIT_FUNDING_TX: p_str = "LN_CB_TYPE_WAIT_FUNDING_TX"; break;
        case LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV: p_str = "LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV"; break;
        case LN_CB_TYPE_NOTIFY_ANNODB_UPDATE: p_str = "LN_CB_TYPE_NOTIFY_ANNODB_UPDATE"; break;
        case LN_CB_TYPE_NOTIFY_ADDFINAL_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_ADDFINAL_HTLC_RECV"; break;
        case LN_CB_TYPE_START_BWD_DEL_HTLC: p_str = "LN_CB_TYPE_START_BWD_DEL_HTLC"; break;
        case LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV"; break;
        case LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE: p_str = "LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE"; break;
        case LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV: p_str = "LN_CB_TYPE_NOTIFY_UPDATE_FEE_RECV"; break;
        case LN_CB_TYPE_NOTIFY_SHUTDOWN_RECV: p_str = "LN_CB_TYPE_NOTIFY_SHUTDOWN_RECV"; break;
        case LN_CB_TYPE_UPDATE_CLOSING_FEE: p_str = "LN_CB_TYPE_UPDATE_CLOSING_FEE"; break;
        case LN_CB_TYPE_NOTIFY_CLOSING_END: p_str = "LN_CB_TYPE_NOTIFY_CLOSING_END"; break;
        case LN_CB_TYPE_SEND_MESSAGE: p_str = "LN_CB_TYPE_SEND_MESSAGE"; break;
        case LN_CB_TYPE_GET_LATEST_FEERATE: p_str = "LN_CB_TYPE_GET_LATEST_FEERATE"; break;
        case LN_CB_TYPE_GET_BLOCK_COUNT: p_str = "LN_CB_TYPE_GET_BLOCK_COUNT"; break;
        case LN_CB_TYPE_NOTIFY_PONG_RECV: p_str = "LN_CB_TYPE_NOTIFY_PONG_RECV"; break;
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
    }
};


////////////////////////////////////////////////////////////////////////

TEST_F(ln, ln_init_send1)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    channel.init_flag = M_INIT_FLAG_SEND;
    bool init_route_sync = false;
    bool have_channel = false;
    ASSERT_FALSE(ln_init_send(&channel, init_route_sync, have_channel));
}

TEST_F(ln, ln_init_send_none_feature)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    class dummy {
    public:
        static bool ln_msg_init_write(utl_buf_t *pBuf, const ln_msg_init_t *pMsg) {
            EXPECT_EQ(0, pMsg->gflen);
            EXPECT_EQ(0, pMsg->lflen);
            return true;
        }
    };
    ln_msg_init_write_fake.custom_fake = dummy::ln_msg_init_write; 

    mInitLocalFeatures = 0;
    bool init_route_sync = false;
    bool have_channel = false;
    ASSERT_TRUE(ln_init_send(&channel, init_route_sync, have_channel));
}

TEST_F(ln, ln_init_send_one_feature)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    class dummy {
    public:
        static bool ln_msg_init_write(utl_buf_t *pBuf, const ln_msg_init_t *pMsg) {
            EXPECT_EQ(0, pMsg->gflen);
            EXPECT_EQ(1, pMsg->lflen);
            EXPECT_EQ(0x55, pMsg->p_localfeatures[0]);
            return true;
        }
    };
    ln_msg_init_write_fake.custom_fake = dummy::ln_msg_init_write; 

    mInitLocalFeatures = 0x55;
    bool init_route_sync = false;
    bool have_channel = false;
    ASSERT_TRUE(ln_init_send(&channel, init_route_sync, have_channel));
}

TEST_F(ln, ln_init_send_two_feature)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    class dummy {
    public:
        static bool ln_msg_init_write(utl_buf_t *pBuf, const ln_msg_init_t *pMsg) {
            EXPECT_EQ(0, pMsg->gflen);
            EXPECT_EQ(2, pMsg->lflen);
            EXPECT_EQ(0xaa, pMsg->p_localfeatures[0]);
            EXPECT_EQ(0x55, pMsg->p_localfeatures[1]);
            return true;
        }
    };
    ln_msg_init_write_fake.custom_fake = dummy::ln_msg_init_write; 

    mInitLocalFeatures = 0xaa55;
    bool init_route_sync = false;
    bool have_channel = false;
    ASSERT_TRUE(ln_init_send(&channel, init_route_sync, have_channel));
}


////////////////////////////////////////////////////////////////////////

TEST_F(ln, ln_init_recv1)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    channel.init_flag = M_INIT_FLAG_RECV;
    ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
}


TEST_F(ln, ln_init_recv_no_feature)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = 0;
            pMsg->p_globalfeatures = NULL;
            pMsg->lflen = 0;
            pMsg->p_localfeatures = NULL;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_TRUE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0, channel.lfeature_remote);
    ASSERT_NE(0, channel.init_flag & M_INIT_FLAG_RECV);
    ASSERT_EQ(0, channel.init_flag & M_INIT_GOSSIP_QUERY);
}


TEST_F(ln, ln_init_recv_even_gfeature)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t GFEATURE[] = { 0x55 };
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = sizeof(GFEATURE);
            pMsg->p_globalfeatures = GFEATURE;
            pMsg->lflen = 0;
            pMsg->p_localfeatures = NULL;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0, channel.lfeature_remote);
    ASSERT_EQ(0, channel.init_flag & M_INIT_FLAG_RECV);
    ASSERT_EQ(0, channel.init_flag & M_INIT_GOSSIP_QUERY);
}


TEST_F(ln, ln_init_recv_odd_gfeature)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t GFEATURE[] = { 0xaa };
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = sizeof(GFEATURE);
            pMsg->p_globalfeatures = GFEATURE;
            pMsg->lflen = 0;
            pMsg->p_localfeatures = NULL;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_TRUE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0, channel.lfeature_remote);
    ASSERT_NE(0, channel.init_flag & M_INIT_FLAG_RECV);
    ASSERT_EQ(0, channel.init_flag & M_INIT_GOSSIP_QUERY);
}


TEST_F(ln, ln_init_recv_greater_gfeature1)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t GFEATURE[] = { 0x40, 0x00 };       //bit 13
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = sizeof(GFEATURE);
            pMsg->p_globalfeatures = GFEATURE;
            pMsg->lflen = 0;
            pMsg->p_localfeatures = NULL;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
}


TEST_F(ln, ln_init_recv_greater_gfeature2)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t GFEATURE[] = { 0x80, 0x00 };       //bit 14
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = sizeof(GFEATURE);
            pMsg->p_globalfeatures = GFEATURE;
            pMsg->lflen = 0;
            pMsg->p_localfeatures = NULL;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
}


TEST_F(ln, ln_init_recv_greater_gfeature3)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    //通常は先頭が0x00ということは無いし、greater than 13なのでエラーにする
    static const uint8_t GFEATURE[] = { 0x00, 0x20, 0x00 };       //3bytes
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = sizeof(GFEATURE);
            pMsg->p_globalfeatures = GFEATURE;
            pMsg->lflen = 0;
            pMsg->p_localfeatures = NULL;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
}


TEST_F(ln, ln_init_recv_even_lfeature1)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t LFEATURE[] = { 0x55 };
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = sizeof(LFEATURE);
            pMsg->p_globalfeatures = LFEATURE;
            pMsg->lflen = 0;
            pMsg->p_localfeatures = NULL;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0, channel.lfeature_remote);
    ASSERT_EQ(0, channel.init_flag & M_INIT_FLAG_RECV);
    ASSERT_EQ(0, channel.init_flag & M_INIT_GOSSIP_QUERY);
}


TEST_F(ln, ln_init_recv_odd_lfeature1)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t LFEATURE[] = { 0xaa };
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = 0;
            pMsg->p_globalfeatures = NULL;
            pMsg->lflen = sizeof(LFEATURE);
            pMsg->p_localfeatures = LFEATURE;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_TRUE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0xaa, channel.lfeature_remote);
    ASSERT_NE(0, channel.init_flag & M_INIT_FLAG_RECV);
    ASSERT_EQ(0, channel.init_flag & M_INIT_GOSSIP_QUERY);
}


TEST_F(ln, ln_init_recv_even_lfeature2)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t LFEATURE[] = { 0x55, 0x55 };
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = 0;
            pMsg->p_globalfeatures = NULL;
            pMsg->lflen = sizeof(LFEATURE);
            pMsg->p_localfeatures = LFEATURE;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0, channel.lfeature_remote);
    ASSERT_EQ(0, channel.init_flag & M_INIT_FLAG_RECV);
    ASSERT_EQ(0, channel.init_flag & M_INIT_GOSSIP_QUERY);
}


TEST_F(ln, ln_init_recv_odd_lfeature2)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t LFEATURE[] = { 0xaa, 0xaa };
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = 0;
            pMsg->p_globalfeatures = NULL;
            pMsg->lflen = sizeof(LFEATURE);
            pMsg->p_localfeatures = LFEATURE;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_TRUE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0xaaaa, channel.lfeature_remote);
    ASSERT_NE(0, channel.init_flag & M_INIT_FLAG_RECV);
    ASSERT_EQ(0, channel.init_flag & M_INIT_GOSSIP_QUERY);
}


TEST_F(ln, ln_init_recv_even_lfeature_req_no)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t LFEATURE[][2] = {
        //{ 0x00, 0x01 },     //option_data_loss_protect
        { 0x00, 0x04 },     //initial_routing_sync(no REQUIRE feature)
        { 0x00, 0x10 },     //option_upfront_shutdown_script
#ifndef USE_GOSSIP_QUERY
        { 0x00, 0x40 },     //gossip_queries
#endif
        { 0x01, 0x00 },     //var_onion_optin
        { 0x04, 0x00 },     //gossip_queries_ex
        { 0x10, 0x00 },     //option_static_remotekey
        { 0x40, 0x00 },     //RFU
    };
    static const uint8_t *pLFeature;
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = 0;
            pMsg->p_globalfeatures = NULL;
            pMsg->lflen = 2;
            pMsg->p_localfeatures = pLFeature;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    for (size_t lp = 0; lp < ARRAY_SIZE(LFEATURE); lp++) {
        pLFeature = LFEATURE[lp];
        channel.init_flag = 0;
        channel.lfeature_remote = 0;
        //printf("[%d]%02x %02x\n", (int)lp, pLFeature[0], pLFeature[1]);
        ASSERT_FALSE(ln_init_recv(&channel, NULL, 0));
        ASSERT_EQ(0, channel.lfeature_remote);
    }
}

TEST_F(ln, ln_init_recv_even_lfeature_req_ok)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t LFEATURE[][2] = {
        { 0x00, 0x01 },     //option_data_loss_protect
        //{ 0x00, 0x04 },     //initial_routing_sync(no REQUIRE feature)
        //{ 0x00, 0x10 },     //option_upfront_shutdown_script
#ifdef USE_GOSSIP_QUERY
        { 0x00, 0x40 },     //gossip_queries
#endif
        //{ 0x01, 0x00 },     //var_onion_optin
        //{ 0x04, 0x00 },     //gossip_queries_ex
        //{ 0x10, 0x00 },     //option_static_remotekey
        //{ 0x40, 0x00 },     //RFU
    };
    static const uint8_t *pLFeature;
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = 0;
            pMsg->p_globalfeatures = NULL;
            pMsg->lflen = 2;
            pMsg->p_localfeatures = pLFeature;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    for (size_t lp = 0; lp < ARRAY_SIZE(LFEATURE); lp++) {
        pLFeature = LFEATURE[lp];
        channel.init_flag = 0;
        channel.lfeature_remote = 0;
        //printf("[%d]%02x %02x\n", (int)lp, pLFeature[0], pLFeature[1]);
        ASSERT_TRUE(ln_init_recv(&channel, NULL, 0));
        ASSERT_EQ(pLFeature[0], channel.lfeature_remote>>8);
        ASSERT_EQ(pLFeature[1], channel.lfeature_remote & 0xff);
    }
}

TEST_F(ln, ln_init_recv_feature_lnd)
{
    ln_channel_t channel;
    LnInit(&channel);
    
    static const uint8_t GFEATURE[] = { 0x22, 0x00 };
    static const uint8_t LFEATURE[] = { 0x22, 0x81 };
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            (void)pData; (void)Len;
            pMsg->gflen = sizeof(GFEATURE);
            pMsg->p_globalfeatures = GFEATURE;
            pMsg->lflen = sizeof(LFEATURE);
            pMsg->p_localfeatures = LFEATURE;
            return true;
        }
    };
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read; 

    ASSERT_TRUE(ln_init_recv(&channel, NULL, 0));
    ASSERT_EQ(0x2281, channel.lfeature_remote);
}
