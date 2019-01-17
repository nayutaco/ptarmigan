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
#include "ln_msg_anno.c"
#include "ln_msg_close.c"
//#include "ln_msg_establish.c"
#include "ln_msg_normalope.c"
#include "ln_msg_setupctl.c"
#include "ln_node.c"
#include "ln_onion.c"
#include "ln_script.c"
#include "ln_enc_auth.c"
#include "ln_signer.c"
#include "ln_segwit_addr.c"
#include "ln_print.c"

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

FAKE_VALUE_FUNC(bool, ln_msg_open_channel_write, utl_buf_t *, const ln_msg_open_channel_t *);
FAKE_VALUE_FUNC(bool, ln_msg_open_channel_read, ln_msg_open_channel_t*, const uint8_t*, uint16_t);
FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_write, utl_buf_t *, const ln_msg_accept_channel_t *);
FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_read, ln_msg_accept_channel_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_funding_created_write, utl_buf_t *, const ln_msg_funding_created_t *);
FAKE_VALUE_FUNC(bool, ln_msg_funding_created_read, ln_msg_funding_created_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_write, utl_buf_t *, const ln_msg_funding_signed_t *);
FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_read, ln_msg_funding_signed_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_comtx_create_to_remote, const ln_self_t *, ln_commit_data_t *, ln_close_force_t *, uint8_t **, uint64_t);


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
        RESET_FAKE(ln_msg_open_channel_read)
        RESET_FAKE(ln_msg_accept_channel_write)
        RESET_FAKE(ln_msg_accept_channel_read)
        RESET_FAKE(ln_msg_funding_created_write)
        RESET_FAKE(ln_msg_funding_created_read)
        RESET_FAKE(ln_msg_funding_signed_write)
        RESET_FAKE(ln_msg_funding_signed_read)
        RESET_FAKE(ln_comtx_create_to_remote)

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
    }
};


namespace LN_DUMMY {
    const uint8_t PRIV[] = {
        0xcd, 0x77, 0xac, 0xa0, 0x01, 0xfe, 0x88, 0xe8,
        0xf2, 0xdc, 0xdc, 0xc7, 0xfc, 0xd8, 0x6c, 0x34,
        0xd2, 0xaf, 0x54, 0x66, 0x82, 0xcf, 0xed, 0xe6,
        0x5f, 0x9e, 0xd8, 0x48, 0xa8, 0x1d, 0xfa, 0xc6,
    };
    const uint8_t PUB[] = {
        0x03, 0xbe, 0xce, 0xc4, 0x1f, 0x68, 0xd7, 0x7f,
        0xde, 0x9e, 0x97, 0x2c, 0x79, 0xaa, 0x0e, 0x6e,
        0x4e, 0x81, 0x8b, 0xd3, 0x04, 0x62, 0x76, 0x96,
        0x9e, 0x79, 0x37, 0x4e, 0xc0, 0x56, 0x1b, 0xa4,
        0x59,
    };

    const uint8_t PUB1[] = {
        0x03, 0x24, 0x0b, 0xc7, 0x9a, 0x64, 0x79, 0x85,
        0x1a, 0xbe, 0x77, 0x64, 0x65, 0x50, 0x0a, 0x9f,
        0xf2, 0xf8, 0x80, 0x94, 0x0b, 0x22, 0x7b, 0xfc,
        0xbc, 0xb6, 0xd4, 0x79, 0x88, 0x6a, 0x31, 0x8f,
        0xa0,
    };
    const uint8_t PUB2[] = {
        0x03, 0x92, 0x1b, 0x52, 0x4e, 0x16, 0xb8, 0x1c,
        0x81, 0x3b, 0xaf, 0x06, 0x2a, 0x28, 0x44, 0xff,
        0x68, 0x42, 0x07, 0x3c, 0xc0, 0xec, 0x60, 0x92,
        0x31, 0xa0, 0xe3, 0x37, 0x00, 0xdd, 0x24, 0xb5,
        0xf3,
    };
    const uint8_t REDEEM_2OF2[] = {
        0x52, 0x21, 0x03, 0x24, 0x0b, 0xc7, 0x9a, 0x64,
        0x79, 0x85, 0x1a, 0xbe, 0x77, 0x64, 0x65, 0x50,
        0x0a, 0x9f, 0xf2, 0xf8, 0x80, 0x94, 0x0b, 0x22,
        0x7b, 0xfc, 0xbc, 0xb6, 0xd4, 0x79, 0x88, 0x6a,
        0x31, 0x8f, 0xa0, 0x21, 0x03, 0x92, 0x1b, 0x52,
        0x4e, 0x16, 0xb8, 0x1c, 0x81, 0x3b, 0xaf, 0x06,
        0x2a, 0x28, 0x44, 0xff, 0x68, 0x42, 0x07, 0x3c,
        0xc0, 0xec, 0x60, 0x92, 0x31, 0xa0, 0xe3, 0x37,
        0x00, 0xdd, 0x24, 0xb5, 0xf3, 0x52, 0xae,
    };

    const uint8_t CHANNEL_ID[] = {
        0x40, 0xfd, 0xde, 0x21, 0x7b, 0xb2, 0xd6, 0xbc, 0x4c, 0x9e, 0x20, 0xc5, 0xe5, 0x31, 0x93, 0xd0,
        0x71, 0xeb, 0xef, 0x7c, 0x13, 0x81, 0x04, 0x19, 0x82, 0x6a, 0xf8, 0x86, 0x2a, 0xf1, 0x22, 0xad,
    };
    const uint8_t CHANNEL_FLAGS[] = {
        0x00,
    };
}

////////////////////////////////////////////////////////////////////////

//OK
TEST_F(ln, recv_open_channel_ok)
{
    ln_self_t self;
    LnInit(&self);

    static int callback_called = 0;
    static uint8_t pubkey[BTC_SZ_PUBKEY] = {0};
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_open_channel_read(ln_msg_open_channel_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->p_chain_hash = ln_genesishash_get();
            pMsg->funding_satoshis = 100000ULL;
            pMsg->push_msat = 0;
            pMsg->dust_limit_satoshis = 800;
            pMsg->max_htlc_value_in_flight_msat = 1000000ULL;
            pMsg->channel_reserve_satoshis = 10000;
            pMsg->htlc_minimum_msat = 20000;
            pMsg->feerate_per_kw = 700;
            pMsg->to_self_delay = 100;
            pMsg->max_accepted_htlcs = 10;
            pMsg->p_temporary_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->p_funding_pubkey = pubkey;
            pMsg->p_revocation_basepoint = pubkey;
            pMsg->p_payment_basepoint = pubkey;
            pMsg->p_delayed_payment_basepoint = pubkey;
            pMsg->p_htlc_basepoint = pubkey;
            pMsg->p_first_per_commitment_point = pubkey;
            pMsg->p_channel_flags = LN_DUMMY::CHANNEL_FLAGS;
            pMsg->shutdown_len = 0;
            pMsg->p_shutdown_scriptpubkey = NULL;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_open_channel_read_fake.custom_fake = dummy::ln_msg_open_channel_read;

    self.p_establish = (ln_establish_t *)UTL_DBG_CALLOC(1, sizeof(ln_establish_t));
    memcpy(pubkey, LN_DUMMY::PUB, sizeof(pubkey));
    self.p_establish->estprm.dust_limit_sat = 10000;
    self.p_establish->estprm.channel_reserve_sat = 800;

    bool ret = recv_open_channel(&self, NULL, 0);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, callback_called);

    UTL_DBG_FREE(self.p_establish);
    self.p_establish = NULL;
    ln_term(&self);
}


//BOLT02
//  The sender:
//      - MUST set channel_reserve_satoshis greater than or equal to dust_limit_satoshis from the open_channel message.
TEST_F(ln, recv_open_channel_sender1)
{
    ln_self_t self;
    LnInit(&self);

    static int callback_called = 0;
    static uint8_t pubkey[BTC_SZ_PUBKEY];
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_open_channel_read(ln_msg_open_channel_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->funding_satoshis = 100000ULL;
            pMsg->push_msat = 0;
            pMsg->dust_limit_satoshis = 800;     //★
            pMsg->max_htlc_value_in_flight_msat = 1000000ULL;
            pMsg->channel_reserve_satoshis = 10000;
            pMsg->htlc_minimum_msat = 20000;
            pMsg->feerate_per_kw = 700;
            pMsg->to_self_delay = 100;
            pMsg->max_accepted_htlcs = 10;
            pMsg->p_temporary_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->p_funding_pubkey = pubkey;
            pMsg->p_revocation_basepoint = pubkey;
            pMsg->p_payment_basepoint = pubkey;
            pMsg->p_delayed_payment_basepoint = pubkey;
            pMsg->p_htlc_basepoint = pubkey;
            pMsg->p_first_per_commitment_point = pubkey;
            pMsg->p_channel_flags = LN_DUMMY::CHANNEL_FLAGS;
            pMsg->shutdown_len = 0;
            pMsg->p_shutdown_scriptpubkey = NULL;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_open_channel_read_fake.custom_fake = dummy::ln_msg_open_channel_read;

    self.p_establish = (ln_establish_t *)UTL_DBG_CALLOC(1, sizeof(ln_establish_t));
    memcpy(pubkey, LN_DUMMY::PUB, sizeof(pubkey));
    self.p_establish->estprm.dust_limit_sat = 10000;

    //accept_channelで送信するchannel_reserve_satoshis
    self.p_establish->estprm.channel_reserve_sat = 800 - 1;

    bool ret = recv_open_channel(&self, NULL, 0);
    ASSERT_FALSE(ret);

    UTL_DBG_FREE(self.p_establish);
    self.p_establish = NULL;
    ln_term(&self);
}


//BOLT02
//  The sender:
//      - MUST set dust_limit_satoshis less than or equal to channel_reserve_satoshis from the open_channel message.
TEST_F(ln, recv_open_channel_sender2)
{
    ln_self_t self;
    LnInit(&self);

    static int callback_called = 0;
    static uint8_t pubkey[BTC_SZ_PUBKEY];
    class dummy {
    public:
        static void callback(ln_self_t *self, ln_cb_t type, void *p_param) {
            if (type == LN_CB_GET_LATEST_FEERATE) {
                uint32_t *p = (uint32_t *)p_param;
                *p = 500;
                callback_called++;
            }
        }
        static bool ln_msg_open_channel_read(ln_msg_open_channel_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->funding_satoshis = 100000ULL;
            pMsg->push_msat = 0;
            pMsg->dust_limit_satoshis = 800;
            pMsg->max_htlc_value_in_flight_msat = 1000000ULL;
            pMsg->channel_reserve_satoshis = 10000;     //★
            pMsg->htlc_minimum_msat = 20000;
            pMsg->feerate_per_kw = 700;
            pMsg->to_self_delay = 100;
            pMsg->max_accepted_htlcs = 10;
            pMsg->p_temporary_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->p_funding_pubkey = pubkey;
            pMsg->p_revocation_basepoint = pubkey;
            pMsg->p_payment_basepoint = pubkey;
            pMsg->p_delayed_payment_basepoint = pubkey;
            pMsg->p_htlc_basepoint = pubkey;
            pMsg->p_first_per_commitment_point = pubkey;
            pMsg->p_channel_flags = LN_DUMMY::CHANNEL_FLAGS;
            pMsg->shutdown_len = 0;
            pMsg->p_shutdown_scriptpubkey = NULL;
            return true;
        }
    };
    self.p_callback = dummy::callback;
    ln_msg_open_channel_read_fake.custom_fake = dummy::ln_msg_open_channel_read;

    self.p_establish = (ln_establish_t *)UTL_DBG_CALLOC(1, sizeof(ln_establish_t));
    memcpy(pubkey, LN_DUMMY::PUB, sizeof(pubkey));
    self.p_establish->estprm.channel_reserve_sat = 800;

    self.p_establish->estprm.dust_limit_sat = 10000 + 1;

    bool ret = recv_open_channel(&self, NULL, 0);
    ASSERT_FALSE(ret);

    UTL_DBG_FREE(self.p_establish);
    self.p_establish = NULL;
    ln_term(&self);
}
