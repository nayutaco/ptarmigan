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
#undef LOG_TAG
#include "../../btc/btc.c"
#include "../../btc/btc_block.c"
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
// #include "ln_msg_normalope.c"
#include "ln_setupctl.c"
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

FAKE_VALUE_FUNC(bool, ln_msg_init_read, ln_msg_init_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_error_write, utl_buf_t *, const ln_msg_error_t *);
FAKE_VALUE_FUNC(bool, ln_msg_error_read, ln_msg_error_t *, const uint8_t *, uint16_t );


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        RESET_FAKE(ln_msg_init_read)
        RESET_FAKE(ln_msg_error_write)
        RESET_FAKE(ln_msg_error_read)

        ln_msg_init_read_fake.return_val = true;
        ln_msg_error_write_fake.return_val = true;
        ln_msg_error_read_fake.return_val = true;
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
        case LN_CB_TYPE_NOTIFY_ADDFINAL_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_ADDFINAL_HTLC_RECV"; break;
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

TEST_F(ln, init_recv_ok)
{
    ln_channel_t channel;
    LnInit(&channel);

    static bool b_called;
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->gflen = 0;
            pMsg->lflen = 0;
            return true;
        }
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_INIT_RECV) {
                b_called = true;
            }
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read;

    bool ret = ln_init_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0x00, channel.lfeature_remote);
    ASSERT_EQ(M_INIT_FLAG_RECV, channel.init_flag);
    ASSERT_TRUE(b_called);
}


TEST_F(ln, init_recv_fail)
{
    ln_channel_t channel;
    LnInit(&channel);

    static bool b_called;
    class dummy {
    public:
        // static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
        //     return false;
        // }
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_INIT_RECV) {
                b_called = true;
            }
        }
    };
    ln_msg_init_read_fake.return_val = false;
    channel.p_callback = dummy::callback;

    bool ret = ln_init_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);
    ASSERT_FALSE(b_called);
}


TEST_F(ln, init_recv_gf1)
{
    ln_channel_t channel;
    LnInit(&channel);

    static bool b_called;
    static uint8_t gf;
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->gflen = 1;          
            pMsg->p_globalfeatures = &gf;
            pMsg->lflen = 0;
            return true;
        }
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_INIT_RECV) {
                b_called = true;
            }
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read;

    bool ret;
    
    for (int lp = 1; lp <= 0x0f; lp++) {
        channel.init_flag = 0;
        channel.lfeature_remote = 0;
        b_called = false;

        //odd bits(7, 5, 3, 1)
        //          abcd
        //      a0b0c0d0
        gf = (lp & 0x08) << 4 | (lp & 0x04) << 3 | (lp & 0x02) << 2 | (lp & 0x01) << 1;
        ret = ln_init_recv(&channel, NULL, 0);
        ASSERT_TRUE(ret);
        ASSERT_EQ(0x00, channel.lfeature_remote);
        ASSERT_EQ(M_INIT_FLAG_RECV, channel.init_flag);
        ASSERT_TRUE(b_called);
    }
}


TEST_F(ln, init_recv_gf2)
{
    ln_channel_t channel;
    LnInit(&channel);

    static bool b_called;
    static uint8_t gf;
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->gflen = 1;
            pMsg->p_globalfeatures = &gf;
            return true;
        }
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_INIT_RECV) {
                b_called = true;
            }
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read;

    bool ret;
    
    for (int lp = 1; lp <= 0x0f; lp++) {
        channel.init_flag = 0;
        channel.lfeature_remote = 0;
        b_called = false;

        //even bits(6, 4, 2, 0)
        //          abcd
        //      0a0b0c0d
        gf = (lp & 0x08) << 3 | (lp & 0x04) << 2 | (lp & 0x02) << 1 | (lp & 0x01);
        ret = ln_init_recv(&channel, NULL, 0);
        ASSERT_FALSE(ret);
        ASSERT_EQ(0x00, channel.lfeature_remote);
        ASSERT_EQ(0, channel.init_flag);
        ASSERT_FALSE(b_called);
    }
}


TEST_F(ln, init_recv_lf1)
{
    ln_channel_t channel;
    LnInit(&channel);

    static bool b_called;
    static uint8_t lf;
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->gflen = 0;
            pMsg->lflen = 1;
            pMsg->p_localfeatures = &lf;
            return true;
        }
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_INIT_RECV) {
                b_called = true;
            }
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read;

    bool ret;
    
    for (int lp = 1; lp <= 0x0f; lp++) {
        channel.init_flag = 0;
        channel.lfeature_remote = 0;
        b_called = false;

        //odd bits(7, 5, 3, 1)
        //          abcd
        //      a0b0c0d0
        lf = (lp & 0x08) << 4 | (lp & 0x04) << 3 | (lp & 0x02) << 2 | (lp & 0x01) << 1;
        ret = ln_init_recv(&channel, NULL, 0);
        ASSERT_TRUE(ret);
        ASSERT_EQ(lf, channel.lfeature_remote);
        ASSERT_EQ(M_INIT_FLAG_RECV, channel.init_flag);
        ASSERT_TRUE(b_called);
    }
}


TEST_F(ln, init_recv_lf2)
{
    ln_channel_t channel;
    LnInit(&channel);

    static bool b_called;
    static uint8_t lf[sizeof(uint16_t)];
    class dummy {
    public:
        static bool ln_msg_init_read(ln_msg_init_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->gflen = 0;
            pMsg->lflen = sizeof(lf);
            pMsg->p_localfeatures = lf;
            return true;
        }
        static void callback(ln_cb_type_t Type, void *pCommonParam, void *pTypeSpecificParam) {
            (void)pCommonParam; (void)pTypeSpecificParam;
            if (Type == LN_CB_TYPE_NOTIFY_INIT_RECV) {
                b_called = true;
            }
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_init_read_fake.custom_fake = dummy::ln_msg_init_read;

    bool ret;
    
    channel.init_flag = 0;
    channel.lfeature_remote = 0;
    b_called = false;

    lf[0] = 0xaa;
    lf[1] = 0xaa;
    ret = ln_init_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(lf[0], channel.lfeature_remote >> 8);
    ASSERT_EQ(lf[1], channel.lfeature_remote & 0xff);
    ASSERT_EQ(M_INIT_FLAG_RECV, channel.init_flag);
    ASSERT_TRUE(b_called);
}
