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
#include "ln_misc.c"
// #include "ln_msg_anno.c"
// #include "ln_msg_close.c"
// #include "ln_msg_establish.c"
//#include "ln_msg_normalope.c"
// #include "ln_msg_setupctl.c"
#include "ln_node.c"
// #include "ln_onion.c"
// #include "ln_script.c"
#include "ln_enc_auth.c"
#include "ln_signer.c"
// #include "ln_segwit_addr.c"
// #include "ln_print.c"

#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

FAKE_VOID_FUNC(ln_db_preimg_cur_close, void *);
FAKE_VALUE_FUNC(bool, ln_db_annocnlupd_load, utl_buf_t *, uint32_t *, uint64_t, uint8_t);
FAKE_VALUE_FUNC(bool, ln_db_preimg_del, const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_preimg_cur_open, void **);
FAKE_VALUE_FUNC(bool, ln_db_preimg_cur_get, void *, bool *, ln_db_preimg_t *);
FAKE_VALUE_FUNC(bool, ln_db_self_search, ln_db_func_cmp_t, void *);
FAKE_VALUE_FUNC(bool, ln_db_self_search_readonly, ln_db_func_cmp_t, void *);
FAKE_VALUE_FUNC(bool, ln_db_phash_save, const uint8_t*, const uint8_t*, ln_htlctype_t, uint32_t);
FAKE_VALUE_FUNC(bool, ln_db_preimg_search, ln_db_func_preimg_t, void*);
FAKE_VALUE_FUNC(bool, ln_db_preimg_set_expiry, void *, uint32_t);

FAKE_VALUE_FUNC(bool, ln_comtx_create_to_remote, const ln_self_t *, ln_commit_data_t *, ln_close_force_t *, uint8_t **, uint64_t);

FAKE_VALUE_FUNC(bool, ln_msg_update_fee_create, utl_buf_t *, const ln_update_fee_t *);
FAKE_VALUE_FUNC(bool, ln_msg_update_fee_read, ln_update_fee_t *, const uint8_t *, uint16_t );


////////////////////////////////////////////////////////////////////////

namespace LN_DUMMY {
    const uint8_t CHANNEL_ID[] = {
        0x40, 0xfd, 0xde, 0x21, 0x7b, 0xb2, 0xd6, 0xbc, 0x4c, 0x9e, 0x20, 0xc5, 0xe5, 0x31, 0x93, 0xd0,
        0x71, 0xeb, 0xef, 0x7c, 0x13, 0x81, 0x04, 0x19, 0x82, 0x6a, 0xf8, 0x86, 0x2a, 0xf1, 0x22, 0xad,
    };
}

////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        RESET_FAKE(ln_db_preimg_cur_close)
        RESET_FAKE(ln_db_annocnlupd_load)
        RESET_FAKE(ln_db_preimg_del)
        RESET_FAKE(ln_db_preimg_cur_open)
        RESET_FAKE(ln_db_preimg_cur_get)
        RESET_FAKE(ln_db_self_search)
        RESET_FAKE(ln_db_self_search_readonly)
        RESET_FAKE(ln_db_phash_save)
        RESET_FAKE(ln_db_preimg_search)
        RESET_FAKE(ln_db_preimg_set_expiry)

        RESET_FAKE(ln_comtx_create_to_remote)

        RESET_FAKE(ln_msg_update_fee_create)
        RESET_FAKE(ln_msg_update_fee_read)

        ln_comtx_create_to_remote_fake.return_val = true;
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
    static void LnCallbackType(ln_self_t *self, ln_cb_t type, void *p_param) {
        (void)self; (void)p_param;
        const char *p_str;
        switch (type) {
        case LN_CB_ERROR: p_str = "LN_CB_ERROR"; break;
        case LN_CB_INIT_RECV: p_str = "LN_CB_INIT_RECV"; break;
        case LN_CB_REESTABLISH_RECV: p_str = "LN_CB_REESTABLISH_RECV"; break;
        case LN_CB_SIGN_FUNDINGTX_REQ: p_str = "LN_CB_SIGN_FUNDINGTX_REQ"; break;
        case LN_CB_FUNDINGTX_WAIT: p_str = "LN_CB_FUNDINGTX_WAIT"; break;
        case LN_CB_FUNDINGLOCKED_RECV: p_str = "LN_CB_FUNDINGLOCKED_RECV"; break;
        case LN_CB_UPDATE_ANNODB: p_str = "LN_CB_UPDATE_ANNODB"; break;
        case LN_CB_ADD_HTLC_RECV_PREV: p_str = "LN_CB_ADD_HTLC_RECV_PREV"; break;
        case LN_CB_ADD_HTLC_RECV: p_str = "LN_CB_ADD_HTLC_RECV"; break;
        case LN_CB_FWD_ADDHTLC_START: p_str = "LN_CB_FWD_ADDHTLC_START"; break;
        case LN_CB_FULFILL_HTLC_RECV: p_str = "LN_CB_FULFILL_HTLC_RECV"; break;
        case LN_CB_FAIL_HTLC_RECV: p_str = "LN_CB_FAIL_HTLC_RECV"; break;
        case LN_CB_REV_AND_ACK_EXCG: p_str = "LN_CB_REV_AND_ACK_EXCG"; break;
        case LN_CB_PAYMENT_RETRY: p_str = "LN_CB_PAYMENT_RETRY"; break;
        case LN_CB_UPDATE_FEE_RECV: p_str = "LN_CB_UPDATE_FEE_RECV"; break;
        case LN_CB_SHUTDOWN_RECV: p_str = "LN_CB_SHUTDOWN_RECV"; break;
        case LN_CB_CLOSED_FEE: p_str = "LN_CB_CLOSED_FEE"; break;
        case LN_CB_CLOSED: p_str = "LN_CB_CLOSED"; break;
        case LN_CB_SEND_REQ: p_str = "LN_CB_SEND_REQ"; break;
        case LN_CB_SEND_QUEUE: p_str = "LN_CB_SEND_QUEUE"; break;
        case LN_CB_GET_LATEST_FEERATE: p_str = "LN_CB_GET_LATEST_FEERATE"; break;
        case LN_CB_GETBLOCKCOUNT: p_str = "LN_CB_GETBLOCKCOUNT"; break;
        default:
            p_str = "unknown";
        }
        printf("*** callback: %s(%d)\n", p_str, type);
    }
    static void LnInit(ln_self_t *self)
    {
        uint8_t seed[LN_SZ_SEED];
        ln_anno_prm_t annoprm;

        memset(self, 0xcc, sizeof(ln_self_t));
        memset(seed, 1, sizeof(seed));
        annoprm.cltv_expiry_delta = 10;
        annoprm.htlc_minimum_msat = 1000;
        annoprm.fee_base_msat = 20;
        annoprm.fee_prop_millionths = 200;

        ln_init(self, seed, &annoprm, (ln_callback_t)0x123456);
        self->init_flag = M_INIT_FLAG_SEND | M_INIT_FLAG_RECV | M_INIT_FLAG_REEST_SEND | M_INIT_FLAG_REEST_RECV;
        self->commit_local.dust_limit_sat = BTC_DUST_LIMIT;
        self->commit_local.htlc_minimum_msat = 0;
        self->commit_local.max_accepted_htlcs = 10;
        self->commit_remote.dust_limit_sat = BTC_DUST_LIMIT;
        self->commit_remote.htlc_minimum_msat = 0;
        self->commit_remote.max_accepted_htlcs = 10;
        self->our_msat = 1000000;
        self->their_msat = 1000000;
        btc_tx_init(&self->tx_funding);
        utl_buf_init(&self->redeem_fund);
        self->p_callback = LnCallbackType;
        memcpy(self->channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
    }
    static void LnInitSend(ln_self_t *self)
    {
        LnInit(self);

        self->fund_flag = LN_FUNDFLAG_FUNDER;
        ln_msg_update_fee_create_fake.return_val = true;
    }
    static void LnInitRecv(ln_self_t *self)
    {
        LnInit(self);

        self->fund_flag = 0;
        ln_msg_update_fee_create_fake.return_val = true;
    }
};

////////////////////////////////////////////////////////////////////////

//OK
TEST_F(ln, create_updatefee_ok)
{
    ln_self_t self;
    LnInitSend(&self);

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_TRUE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}

//not init
TEST_F(ln, create_updatefee_noinit_send)
{
    ln_self_t self;
    LnInitSend(&self);

    self.init_flag = M_INIT_FLAG_SEND | /*M_INIT_FLAG_RECV |*/ M_INIT_FLAG_REEST_SEND | M_INIT_FLAG_REEST_RECV;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_FALSE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}

//not init
TEST_F(ln, create_updatefee_noinit_recv)
{
    ln_self_t self;
    LnInitSend(&self);

    self.init_flag = /*M_INIT_FLAG_SEND |*/ M_INIT_FLAG_RECV | M_INIT_FLAG_REEST_SEND | M_INIT_FLAG_REEST_RECV;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_FALSE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}

//not init
TEST_F(ln, create_updatefee_noinit_reest_recv)
{
    ln_self_t self;
    LnInitSend(&self);

    self.init_flag = M_INIT_FLAG_SEND | M_INIT_FLAG_RECV | M_INIT_FLAG_REEST_SEND /*| M_INIT_FLAG_REEST_RECV*/;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_FALSE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}

//not init
TEST_F(ln, create_updatefee_noinit_reest_send)
{
    ln_self_t self;
    LnInitSend(&self);

    self.init_flag = M_INIT_FLAG_SEND | M_INIT_FLAG_RECV /*| M_INIT_FLAG_REEST_SEND */| M_INIT_FLAG_REEST_RECV;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_FALSE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}

//not init
TEST_F(ln, create_updatefee_noinit_both)
{
    ln_self_t self;
    LnInitSend(&self);

    self.init_flag = 0;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_FALSE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}

//fundee
TEST_F(ln, create_updatefee_fundee)
{
    ln_self_t self;
    LnInitSend(&self);

    self.fund_flag = 0;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_FALSE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}

//create
TEST_F(ln, create_updatefee_create)
{
    ln_self_t self;
    LnInitSend(&self);

    ln_msg_update_fee_create_fake.return_val = false;

    utl_buf_t buf_bolt = UTL_BUF_INIT;
    bool ret = ln_update_fee_create(&self, &buf_bolt, 1000);
    ASSERT_FALSE(ret);

    utl_buf_free(&buf_bolt);
    ln_term(&self);
}


TEST_F(ln, recv_updatefee_ok)
{
    ln_self_t self;
    LnInitRecv(&self);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            memcpy(pMsg->p_channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
            pMsg->feerate_per_kw = 500;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = recv_update_fee(&self, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, callback_called);
    ASSERT_EQ(500, self.feerate_per_kw);

    ln_term(&self);
}


TEST_F(ln, recv_updatefee_decode)
{
    ln_self_t self;
    LnInitRecv(&self);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            memcpy(pMsg->p_channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
            pMsg->feerate_per_kw = 500;
            return false;   //★
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = recv_update_fee(&self, NULL, 0);
    ASSERT_FALSE(ret);
    ASSERT_EQ(0, callback_called);

    ln_term(&self);
}


TEST_F(ln, recv_updatefee_channelid)
{
    ln_self_t self;
    LnInitRecv(&self);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            memcpy(pMsg->p_channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
            pMsg->p_channel_id[0] = 0xff;   //★
            pMsg->feerate_per_kw = 500;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = recv_update_fee(&self, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&self);
}


TEST_F(ln, recv_updatefee_funder)
{
    ln_self_t self;
    LnInitRecv(&self);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            memcpy(pMsg->p_channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
            pMsg->feerate_per_kw = 500;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    self.fund_flag = LN_FUNDFLAG_FUNDER;    //★

    bool ret = recv_update_fee(&self, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&self);
}


TEST_F(ln, recv_updatefee_min)
{
    ln_self_t self;
    LnInitRecv(&self);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            memcpy(pMsg->p_channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
            pMsg->feerate_per_kw = 252;     //★
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = recv_update_fee(&self, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&self);
}


TEST_F(ln, recv_updatefee_low)
{
    ln_self_t self;
    LnInitRecv(&self);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 5000;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            memcpy(pMsg->p_channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
            //now: 5000
            //      low: 5000*0.2 = 1000
            //      hi : 5000*5.0 = 25000
            pMsg->feerate_per_kw = 1000 - 1;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = recv_update_fee(&self, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&self);
}


TEST_F(ln, recv_updatefee_hi)
{
    ln_self_t self;
    LnInitRecv(&self);

    static int callback_called = 0;
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 5000;
                callback_called++;
            }
        }
        static bool ln_msg_update_fee_read(ln_update_fee_t *pMsg, const uint8_t *pData, uint16_t Len) {
            memcpy(pMsg->p_channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
            //now: 5000
            //      low: 5000*0.2 = 1000
            //      hi : 5000*5.0 = 25000
            pMsg->feerate_per_kw = 25000 + 1;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_update_fee_read_fake.custom_fake = dummy::ln_msg_update_fee_read;

    bool ret = recv_update_fee(&self, NULL, 0);
    ASSERT_FALSE(ret);

    ln_term(&self);
}
