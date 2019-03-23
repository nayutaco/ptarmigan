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
#include "ln_msg.c"
// #include "ln_msg_anno.c"
// #include "ln_msg_close.c"
// #include "ln_msg_establish.c"
//#include "ln_msg_normalope.c"
// #include "ln_msg_setupctl.c"
#include "ln_setupctl.c"
#include "ln_node.c"
// #include "ln_onion.c"
// #include "ln_script.c"
#include "ln_noise.c"
#include "ln_signer.c"
// #include "ln_invoice.c"
// #include "ln_print.c"
#include "ln_normalope.c"
#include "ln_funding_info.c"
#include "ln_update.c"
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
FAKE_VALUE_FUNC(bool, ln_db_preimage_set_expiry, void *, uint32_t);

typedef uint8_t (fake_sig_t)[LN_SZ_SIGNATURE];
FAKE_VALUE_FUNC(bool, ln_commit_tx_create_remote, const ln_channel_t *, ln_commit_info_t *, ln_close_force_t *, fake_sig_t **);

FAKE_VALUE_FUNC(bool, ln_msg_update_fee_write, utl_buf_t *, const ln_msg_update_fee_t *);
FAKE_VALUE_FUNC(bool, ln_msg_update_fee_read, ln_msg_update_fee_t *, const uint8_t *, uint16_t );


////////////////////////////////////////////////////////////////////////

namespace LN_DUMMY {
    const uint8_t CHANNEL_ID[] = {
        0x40, 0xfd, 0xde, 0x21, 0x7b, 0xb2, 0xd6, 0xbc, 0x4c, 0x9e, 0x20, 0xc5, 0xe5, 0x31, 0x93, 0xd0,
        0x71, 0xeb, 0xef, 0x7c, 0x13, 0x81, 0x04, 0x19, 0x82, 0x6a, 0xf8, 0x86, 0x2a, 0xf1, 0x22, 0xad,
    };
    const uint8_t CHANNEL_ID_2[] = {
        0xff, /*!!!*/ 0xfd, 0xde, 0x21, 0x7b, 0xb2, 0xd6, 0xbc, 0x4c, 0x9e, 0x20, 0xc5, 0xe5, 0x31, 0x93, 0xd0,
        0x71, 0xeb, 0xef, 0x7c, 0x13, 0x81, 0x04, 0x19, 0x82, 0x6a, 0xf8, 0x86, 0x2a, 0xf1, 0x22, 0xad,
    };
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
        RESET_FAKE(ln_db_preimage_set_expiry)

        RESET_FAKE(ln_commit_tx_create_remote)

        RESET_FAKE(ln_msg_update_fee_write)
        RESET_FAKE(ln_msg_update_fee_read)

        ln_commit_tx_create_remote_fake.return_val = true;
        utl_dbg_malloc_cnt_reset();
        btc_init(BTC_TESTNET, true);
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
    static void LnCallbackType(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
        (void)pChannel; (void)p_param;
        const char *p_str;
        switch (type) {
        case LN_CB_TYPE_NOTIFY_ERROR: p_str = "LN_CB_TYPE_NOTIFY_ERROR"; break;
        case LN_CB_TYPE_NOTIFY_INIT_RECV: p_str = "LN_CB_TYPE_NOTIFY_INIT_RECV"; break;
        case LN_CB_TYPE_NOTIFY_REESTABLISH_RECV: p_str = "LN_CB_TYPE_NOTIFY_REESTABLISH_RECV"; break;
        case LN_CB_TYPE_SIGN_FUNDING_TX: p_str = "LN_CB_TYPE_SIGN_FUNDING_TX"; break;
        case LN_CB_TYPE_WAIT_FUNDING_TX: p_str = "LN_CB_TYPE_WAIT_FUNDING_TX"; break;
        case LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV: p_str = "LN_CB_TYPE_NOTIFY_FUNDING_LOCKED_RECV"; break;
        case LN_CB_TYPE_NOTIFY_ANNODB_UPDATE: p_str = "LN_CB_TYPE_NOTIFY_ANNODB_UPDATE"; break;
        case LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV_PREV: p_str = "LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV_PREV"; break;
        case LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV"; break;
        case LN_CB_TYPE_START_FWD_ADD_HTLC: p_str = "LN_CB_TYPE_START_FWD_ADD_HTLC"; break;
        case LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_FULFILL_HTLC_RECV"; break;
        case LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE: p_str = "LN_CB_TYPE_NOTIFY_REV_AND_ACK_EXCHANGE"; break;
        case LN_CB_TYPE_RETRY_PAYMENT: p_str = "LN_CB_TYPE_RETRY_PAYMENT"; break;
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
        printf("*** callback: %s(%d)\n", p_str, type);
    }
    static void LnInit(ln_channel_t *pChannel)
    {
        ln_anno_param_t anno_param;

        memset(pChannel, 0xcc, sizeof(ln_channel_t));
        anno_param.cltv_expiry_delta = 10;
        anno_param.htlc_minimum_msat = 1000;
        anno_param.fee_base_msat = 20;
        anno_param.fee_prop_millionths = 200;

        ln_init(pChannel, &anno_param, (ln_callback_t)0x123456);
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
    static void LnInitSend(ln_channel_t *pChannel, uint32_t FeeratePerKw)
    {
        LnInit(pChannel);

        uint16_t update_idx;
        ln_update_info_set_fee_pre_send(&pChannel->update_info, &update_idx, FeeratePerKw);
        pChannel->funding_info.role = LN_FUNDING_ROLE_FUNDER;
        ln_msg_update_fee_write_fake.return_val = true;
    }
    static void LnInitRecv(ln_channel_t *pChannel)
    {
        LnInit(pChannel);

        pChannel->funding_info.role = 0;
        ln_msg_update_fee_write_fake.return_val = true;
    }
};

////////////////////////////////////////////////////////////////////////

#if 0
//OK
TEST_F(ln, create_updatefee_ok)
{
    ln_channel_t channel;
    LnInitSend(&channel, 500);

    bool ret = update_fee_send(&channel, 0);
    ASSERT_TRUE(ret);

    ln_term(&channel);
}

//low
TEST_F(ln, create_updatefee_low)
{
    ln_channel_t channel;
    LnInitSend(&channel, LN_FEERATE_PER_KW_MIN);

    bool ret = update_fee_send(&channel, 0);
    ASSERT_TRUE(ret);

    ln_term(&channel);
}

//too low
TEST_F(ln, create_updatefee_toolow)
{
    ln_channel_t channel;
    LnInitSend(&channel, LN_FEERATE_PER_KW_MIN - 1);

    bool ret = update_fee_send(&channel, 0);
    ASSERT_FALSE(ret);

    ln_term(&channel);
}

//create
TEST_F(ln, create_updatefee_create)
{
    ln_channel_t channel;
    LnInitSend(&channel, 1000);

    ln_msg_update_fee_write_fake.return_val = false;

    bool ret = update_fee_send(&channel, 0);
    ASSERT_FALSE(ret);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_ok)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->feerate_per_kw = 500;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, callback_called);
    ASSERT_EQ(500, ln_update_info_get_feerate_per_kw_pre_committed(&channel.update_info, true));

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_decode)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->feerate_per_kw = 500;
            return false;   //★
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);
    ASSERT_EQ(0, callback_called);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_channelid)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID_2;
            pMsg->feerate_per_kw = 500;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_funder)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->feerate_per_kw = 500;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    channel.funding_info.role = LN_FUNDING_ROLE_FUNDER;    //★

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_min)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->feerate_per_kw = 252;     //★
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_low_in)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 5000;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            //now: 5000
            //      low: 5000*0.2 = 1000
            //      hi : 5000*5.0 = 25000
            pMsg->feerate_per_kw = 1000;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_low_out)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 5000;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            //now: 5000
            //      low: 5000*0.2 = 1000
            //      hi : 5000*5.0 = 25000
            pMsg->feerate_per_kw = 1000 - 1;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_hi_in)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 5000;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            //now: 5000
            //      low: 5000*0.2 = 1000
            //      hi : 5000*20.0 = 100000
            pMsg->feerate_per_kw = 100000;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);

    ln_term(&channel);
}


TEST_F(ln, recv_updatefee_hi_out)
{
    ln_channel_t channel;
    LnInitRecv(&channel);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            if (type == LN_CB_TYPE_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 5000;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_msg_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_channel_id = LN_DUMMY::CHANNEL_ID;
            //now: 5000
            //      low: 5000*0.2 = 1000
            //      hi : 5000*20.0 = 100000
            pMsg->feerate_per_kw = 100000 + 1;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = ln_update_fee_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&channel);
}
#endif


TEST_F(ln, update_fee_send)
{
    ln_update_info_t info;
    ln_update_info_init(&info);
    uint16_t update_idx;
    uint32_t feerate_per_kw;
    ln_update_t *p_update;

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(0, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(0, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(0, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(0, feerate_per_kw);

    ASSERT_TRUE(ln_update_info_set_initial_fee_send(&info, 100));

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 200));

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);

    ln_update_info_free(&info);
}


TEST_F(ln, update_fee_recv)
{
    ln_update_info_t info;
    ln_update_info_init(&info);
    uint16_t update_idx;
    uint32_t feerate_per_kw;

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(0, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(0, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(0, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(0, feerate_per_kw);

    ASSERT_TRUE(ln_update_info_set_initial_fee_recv(&info, 100));

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ASSERT_TRUE(ln_update_info_set_fee_recv(&info, &update_idx, 200));

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(200, feerate_per_kw);

    ln_update_info_free(&info);
}


TEST_F(ln, update_fee_send_multi)
{
    ln_update_info_t info;
    ln_update_info_init(&info);
    uint16_t update_idx;
    uint32_t feerate_per_kw;
    ln_update_t *p_update;

    ASSERT_TRUE(ln_update_info_set_initial_fee_send(&info, 100));

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 200));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 500));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 600));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 700));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 800));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_free(&info);
}


TEST_F(ln, update_fee_send_multi_2)
{
    ln_update_info_t info;
    ln_update_info_init(&info);
    uint16_t update_idx;
    uint32_t feerate_per_kw;
    ln_update_t *p_update;

    ASSERT_TRUE(ln_update_info_set_initial_fee_send(&info, 100));

    //1
    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 200));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 500));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 600));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 700));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 800));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    //2
    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 1200));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 1300));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 1400));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 1500));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 1600));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 1700));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 1800));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(1800, feerate_per_kw);

    ln_update_info_free(&info);
}


TEST_F(ln, update_fee_send_multi_3)
{
    ln_update_info_t info;
    ln_update_info_init(&info);
    uint16_t update_idx;
    uint32_t feerate_per_kw;
    ln_update_t *p_update;

    ASSERT_TRUE(ln_update_info_set_initial_fee_send(&info, 100));

    //1
    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 200));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 500));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 600));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 700));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 800));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(100, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    //2 (the same pattern)
    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 200));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 500));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 600));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 700));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 800));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(100, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_RECV);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_SEND);

    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, true);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_pre_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);
    feerate_per_kw = ln_update_info_get_feerate_per_kw_committed(&info, false);
    ASSERT_EQ(800, feerate_per_kw);

    ln_update_info_free(&info);
}


TEST_F(ln, pruning)
{
    ln_update_info_t info;
    ln_update_info_init(&info);
    uint16_t update_idx;
    ln_update_t *p_update;

    ASSERT_TRUE(ln_update_info_set_initial_fee_send(&info, 100));

    //100
    ASSERT_EQ(1, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 100));

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 200));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    //100, 200
    ASSERT_EQ(2, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 200));

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    //100, 200, 300
    ASSERT_EQ(3, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    //100, 300, 400
    //  200 is pruned
    ASSERT_EQ(3, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 500));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    //100, 400, 500
    //  300 is pruned
    ASSERT_EQ(3, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 500));

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    //100, 500, 300
    //  400 is pruned
    ASSERT_EQ(3, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 300));

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_RECV);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_TRUE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));
    p_update = &info.updates[update_idx];
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    //500, 300, 400
    //  100 is pruned
    ASSERT_EQ(3, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_SEND);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_RECV);

    //Explicit pruning
    ln_update_info_prune_fee_updates(&info);

    //500, 400
    //  300 is pruned
    ASSERT_EQ(2, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_CS_RECV);

    ln_update_info_set_state_flag_all(&info, LN_UPDATE_STATE_FLAG_RA_SEND);

    //Explicit pruning
    ln_update_info_prune_fee_updates(&info);

    //400
    //  500 is pruned
    ASSERT_EQ(1, ln_update_info_get_num_fee_updates(&info));

    //fail: same value
    ASSERT_FALSE(ln_update_info_set_fee_pre_send(&info, &update_idx, 400));

    ln_update_info_free(&info);
}


