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
#include "ln_msg_setupctl.c"
#include "ln_setupctl.c"
#include "ln_establish.c"
#include "ln_node.c"
#include "ln_onion.c"
#include "ln_comtx_util.c"
#include "ln_script.c"
#include "ln_noise.c"
#include "ln_signer.c"
#include "ln_invoice.c"
#include "ln_print.c"
#include "ln_funding_info.c"

#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

FAKE_VOID_FUNC(ln_db_preimage_cur_close, void *);
FAKE_VALUE_FUNC(bool, ln_db_annocnlupd_load, utl_buf_t *, uint32_t *, uint64_t, uint8_t, void*);
FAKE_VALUE_FUNC(bool, ln_db_preimage_del, const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_open, void **);
FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_get, void *, bool *, ln_db_preimage_t *);
FAKE_VALUE_FUNC(bool, ln_db_channel_search, ln_db_func_cmp_t, void *);
FAKE_VALUE_FUNC(bool, ln_db_channel_search_readonly, ln_db_func_cmp_t, void *);
FAKE_VALUE_FUNC(bool, ln_db_phash_save, const uint8_t*, const uint8_t*, ln_comtx_output_type_t, uint32_t);
FAKE_VALUE_FUNC(bool, ln_db_preimage_search, ln_db_func_preimage_t, void*);
FAKE_VALUE_FUNC(bool, ln_db_preimage_set_expiry, void *, uint32_t);

FAKE_VALUE_FUNC(bool, ln_msg_open_channel_write, utl_buf_t *, const ln_msg_open_channel_t *);
FAKE_VALUE_FUNC(bool, ln_msg_open_channel_read, ln_msg_open_channel_t*, const uint8_t*, uint16_t);
FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_write, utl_buf_t *, const ln_msg_accept_channel_t *);
FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_read, ln_msg_accept_channel_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_funding_created_write, utl_buf_t *, const ln_msg_funding_created_t *);
FAKE_VALUE_FUNC(bool, ln_msg_funding_created_read, ln_msg_funding_created_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_write, utl_buf_t *, const ln_msg_funding_signed_t *);
FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_read, ln_msg_funding_signed_t *, const uint8_t *, uint16_t );
typedef uint8_t (fake_sig_t)[LN_SZ_SIGNATURE];
FAKE_VALUE_FUNC(bool, ln_comtx_create_remote, const ln_channel_t *, ln_commit_info_t *, ln_close_force_t *, fake_sig_t **);


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        RESET_FAKE(ln_db_preimage_cur_close)
        RESET_FAKE(ln_db_annocnlupd_load)
        RESET_FAKE(ln_db_preimage_del)
        RESET_FAKE(ln_db_preimage_cur_open)
        RESET_FAKE(ln_db_preimage_cur_get)
        RESET_FAKE(ln_db_channel_search)
        RESET_FAKE(ln_db_channel_search_readonly)
        RESET_FAKE(ln_db_phash_save)
        RESET_FAKE(ln_db_preimage_search)
        RESET_FAKE(ln_db_preimage_set_expiry)
        RESET_FAKE(ln_msg_open_channel_read)
        RESET_FAKE(ln_msg_accept_channel_write)
        RESET_FAKE(ln_msg_accept_channel_read)
        RESET_FAKE(ln_msg_funding_created_write)
        RESET_FAKE(ln_msg_funding_created_read)
        RESET_FAKE(ln_msg_funding_signed_write)
        RESET_FAKE(ln_msg_funding_signed_read)
        RESET_FAKE(ln_comtx_create_remote)

        ln_comtx_create_remote_fake.return_val = true;
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
        case LN_CB_TYPE_QUEUE_MESSAGE: p_str = "LN_CB_TYPE_QUEUE_MESSAGE"; break;
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
        pChannel->noise.p_handshake = NULL;
        anno_param.cltv_expiry_delta = 10;
        anno_param.htlc_minimum_msat = 1000;
        anno_param.fee_base_msat = 20;
        anno_param.fee_prop_millionths = 200;
        ln_init(pChannel, &anno_param, (ln_callback_t)0x123456);
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
}

////////////////////////////////////////////////////////////////////////

TEST_F(ln, init)
{
    ln_channel_t channel;
    ln_anno_param_t anno_param;

    memset(&channel, 0xcc, sizeof(channel));
    channel.noise.p_handshake = NULL;
    anno_param.cltv_expiry_delta = 10;
    anno_param.htlc_minimum_msat = 1000;
    anno_param.fee_base_msat = 20;
    anno_param.fee_prop_millionths = 200;
    ln_init(&channel, &anno_param, (ln_callback_t)0x123456);

    ASSERT_EQ(LN_STATUS_NONE, channel.status);
    for (int idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ASSERT_TRUE(utl_mem_is_all_zero(&channel.updates[idx].flags, sizeof(ln_update_flags_t)));
    }
    ASSERT_TRUE(DumpCheck(&channel.noise.send_ctx, sizeof(ln_noise_ctx_t), 0xcc));
    ASSERT_TRUE(DumpCheck(&channel.noise.recv_ctx, sizeof(ln_noise_ctx_t), 0xcc));
    ASSERT_EQ(0xcccccccccccccccc, channel.p_param);
    ASSERT_EQ(0x123456, channel.p_callback);

    ln_term(&channel);
}


//OK
TEST_F(ln, ln_accept_channel_recv_ok)
{
    ln_channel_t channel;
    LnInit(&channel);
    channel.funding_info.role = LN_FUNDING_ROLE_FUNDER;       //funder

    const uint8_t CHANGE_SPK[] = { 0x12, 0x34, 0x56 };

    static uint8_t pubkey[BTC_SZ_PUBKEY];
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            switch (type) {
            case LN_CB_TYPE_SIGN_FUNDING_TX:
                {
                    ln_cb_param_sign_funding_tx_t *p_sig = (ln_cb_param_sign_funding_tx_t *)p_param;
                    p_sig->ret = true;  //署名OK
                }
                break;
            default:
                break;
            }
        }
        static bool ln_msg_accept_channel_read(ln_msg_accept_channel_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->dust_limit_satoshis = 800;
            pMsg->max_htlc_value_in_flight_msat = 1000000ULL;
            pMsg->channel_reserve_satoshis = 10000;
            pMsg->htlc_minimum_msat = 20000;
            pMsg->minimum_depth = 4;
            pMsg->to_self_delay = 100;
            pMsg->max_accepted_htlcs = 10;
            pMsg->p_temporary_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->p_funding_pubkey = pubkey;
            pMsg->p_revocation_basepoint = pubkey;
            pMsg->p_payment_basepoint = pubkey;
            pMsg->p_delayed_payment_basepoint = pubkey;
            pMsg->p_htlc_basepoint = pubkey;
            pMsg->p_first_per_commitment_point = pubkey;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_accept_channel_read_fake.custom_fake = dummy::ln_msg_accept_channel_read;

    memcpy(pubkey, LN_DUMMY::PUB, sizeof(pubkey));
    channel.commit_info_local.dust_limit_sat = 10000;
    channel.commit_info_local.channel_reserve_sat = 800;
    memcpy(channel.channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
    channel.funding_info.funding_satoshis = 100000;

#ifdef USE_BITCOIND
    channel.establish.p_fundin = (ln_fundin_t *)UTL_DBG_CALLOC(1, sizeof(ln_fundin_t));
    ln_fundin_t *p_fundin = channel.establish.p_fundin;
    utl_buf_alloccopy(&p_fundin->change_spk, CHANGE_SPK, sizeof(CHANGE_SPK));
    p_fundin->amount = 500000;
#endif

    memcpy(channel.keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING], LN_DUMMY::PUB1, BTC_SZ_PUBKEY);
    memcpy(channel.keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING], LN_DUMMY::PUB2, BTC_SZ_PUBKEY);

    bool ret = ln_accept_channel_recv(&channel, NULL, 0);
    ASSERT_TRUE(ret);

#ifdef USE_BITCOIND
    utl_buf_free(&p_fundin->change_spk);
    UTL_DBG_FREE(channel.establish.p_fundin);
#endif
    ln_term(&channel);
}


//NG
//BOLT02
//  The receiver:
//    - if channel_reserve_satoshis is less than dust_limit_satoshis within the open_channel message:
//      - MUST reject the channel.
//
// 受信したaccept_channel.channel_reserve_satoshisがopen_channel.dust_limit_satoshisより小さい場合
TEST_F(ln, ln_accept_channel_recv_receiver1)
{
    ln_channel_t channel;
    LnInit(&channel);
    channel.funding_info.role = LN_FUNDING_ROLE_FUNDER;       //funder

    const uint8_t CHANGE_SPK[] = { 0x12, 0x34, 0x56 };

    static uint8_t pubkey[BTC_SZ_PUBKEY];
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            switch (type) {
            case LN_CB_TYPE_SIGN_FUNDING_TX:
                {
                    ln_cb_param_sign_funding_tx_t *p_sig = (ln_cb_param_sign_funding_tx_t *)p_param;
                    p_sig->ret = true;  //署名OK
                }
                break;
            default:
                break;
            }
        }
        static bool ln_msg_accept_channel_read(ln_msg_accept_channel_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->dust_limit_satoshis = 800;
            pMsg->max_htlc_value_in_flight_msat = 1000000ULL;
            pMsg->channel_reserve_satoshis = 10000 - 1;    //★
            pMsg->htlc_minimum_msat = 20000;
            pMsg->minimum_depth = 4;
            pMsg->to_self_delay = 100;
            pMsg->max_accepted_htlcs = 10;
            pMsg->p_temporary_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->p_funding_pubkey = pubkey;
            pMsg->p_revocation_basepoint = pubkey;
            pMsg->p_payment_basepoint = pubkey;
            pMsg->p_delayed_payment_basepoint = pubkey;
            pMsg->p_htlc_basepoint = pubkey;
            pMsg->p_first_per_commitment_point = pubkey;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_accept_channel_read_fake.custom_fake = dummy::ln_msg_accept_channel_read;

    memcpy(pubkey, LN_DUMMY::PUB, sizeof(pubkey));
    channel.commit_info_local.dust_limit_sat = 10000;    //★
    channel.commit_info_local.channel_reserve_sat = 800;
    memcpy(channel.channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
    channel.funding_info.funding_satoshis = 100000;

#ifdef USE_BITCOIND
    channel.establish.p_fundin = (ln_fundin_t *)UTL_DBG_CALLOC(1, sizeof(ln_fundin_t));
    ln_fundin_t *p_fundin = channel.establish.p_fundin;
    utl_buf_alloccopy(&p_fundin->change_spk, CHANGE_SPK, sizeof(CHANGE_SPK));
#endif

    memcpy(channel.keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING], LN_DUMMY::PUB1, BTC_SZ_PUBKEY);
    memcpy(channel.keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING], LN_DUMMY::PUB2, BTC_SZ_PUBKEY);

    bool ret = ln_accept_channel_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);

#ifdef USE_BITCOIND
    utl_buf_free(&p_fundin->change_spk);
    UTL_DBG_FREE(channel.establish.p_fundin);
#endif
    ln_term(&channel);
}


//NG
//BOLT02
//  The receiver:
//    - if channel_reserve_satoshis from the open_channel message is less than dust_limit_satoshis:
//      - MUST reject the channel. Other fields have the same requirements as their counterparts in open_channel.
//
// accept_channelの受信者はopen_channelの送信者である。
// よってここでは、「受信したaccept_channel.dust_limit_satoshisが、送信したopen_channel.channel_reserve_satoshisより小さい場合」である。
TEST_F(ln, ln_accept_channel_recv_receiver2)
{
    ln_channel_t channel;
    LnInit(&channel);
    channel.funding_info.role = LN_FUNDING_ROLE_FUNDER;       //funder

    const uint8_t CHANGE_SPK[] = { 0x12, 0x34, 0x56 };

    static uint8_t pubkey[BTC_SZ_PUBKEY];
    class dummy {
    public:
        static void callback(ln_channel_t *pChannel, ln_cb_type_t type, void *p_param) {
            switch (type) {
            case LN_CB_TYPE_SIGN_FUNDING_TX:
                {
                    ln_cb_param_sign_funding_tx_t *p_sig = (ln_cb_param_sign_funding_tx_t *)p_param;
                    p_sig->ret = true;  //署名OK
                }
                break;
            default:
                break;
            }
        }
        static bool ln_msg_accept_channel_read(ln_msg_accept_channel_t *pMsg, const uint8_t *pData, uint16_t Len) {
            pMsg->dust_limit_satoshis = 800 + 1;    //★
            pMsg->max_htlc_value_in_flight_msat = 1000000ULL;
            pMsg->channel_reserve_satoshis = 10000;
            pMsg->htlc_minimum_msat = 20000;
            pMsg->minimum_depth = 4;
            pMsg->to_self_delay = 100;
            pMsg->max_accepted_htlcs = 10;
            pMsg->p_temporary_channel_id = LN_DUMMY::CHANNEL_ID;
            pMsg->p_funding_pubkey = pubkey;
            pMsg->p_revocation_basepoint = pubkey;
            pMsg->p_payment_basepoint = pubkey;
            pMsg->p_delayed_payment_basepoint = pubkey;
            pMsg->p_htlc_basepoint = pubkey;
            pMsg->p_first_per_commitment_point = pubkey;
            return true;
        }
    };
    channel.p_callback = dummy::callback;
    ln_msg_accept_channel_read_fake.custom_fake = dummy::ln_msg_accept_channel_read;

    memcpy(pubkey, LN_DUMMY::PUB, sizeof(pubkey));
    channel.commit_info_local.dust_limit_sat = 10000;
    channel.commit_info_local.channel_reserve_sat = 800;    //★
    memcpy(channel.channel_id, LN_DUMMY::CHANNEL_ID, LN_SZ_CHANNEL_ID);
    channel.funding_info.funding_satoshis = 100000;

#ifdef USE_BITCOIND
    channel.establish.p_fundin = (ln_fundin_t *)UTL_DBG_CALLOC(1, sizeof(ln_fundin_t));
    ln_fundin_t *p_fundin = channel.establish.p_fundin;
    utl_buf_alloccopy(&p_fundin->change_spk, CHANGE_SPK, sizeof(CHANGE_SPK));
#endif

    memcpy(channel.keys_local.basepoints[LN_BASEPOINT_IDX_FUNDING], LN_DUMMY::PUB1, BTC_SZ_PUBKEY);
    memcpy(channel.keys_remote.basepoints[LN_BASEPOINT_IDX_FUNDING], LN_DUMMY::PUB2, BTC_SZ_PUBKEY);

    bool ret = ln_accept_channel_recv(&channel, NULL, 0);
    ASSERT_FALSE(ret);

#ifdef USE_BITCOIND
    utl_buf_free(&p_fundin->change_spk);
    UTL_DBG_FREE(channel.establish.p_fundin);
#endif
    ln_term(&channel);
}
