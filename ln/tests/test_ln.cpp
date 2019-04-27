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
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

// FAKE_VOID_FUNC(ln_db_preimage_cur_close, void *);
// FAKE_VALUE_FUNC(bool, ln_db_cnlupd_load, utl_buf_t *, uint32_t *, uint64_t, uint8_t);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_del, const uint8_t *);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_open, void **);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_cur_get, void *, bool *, ln_db_preimage_t *);
// FAKE_VALUE_FUNC(bool, ln_db_channel_search, ln_db_func_cmp_t, void *);
// FAKE_VALUE_FUNC(bool, ln_db_channel_search_readonly, ln_db_func_cmp_t, void *);
// FAKE_VALUE_FUNC(bool, ln_db_payment_hash_save, const uint8_t*, const uint8_t*, ln_commit_tx_output_type_t, uint32_t);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_search, ln_db_func_preimage_t, void*);
// FAKE_VALUE_FUNC(bool, ln_db_preimage_set_expiry, void *, uint32_t);

// FAKE_VALUE_FUNC(bool, ln_msg_open_channel_write, utl_buf_t *, const ln_open_channel_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_open_channel_read, ln_open_channel_t*, const uint8_t*, uint16_t);
// FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_write, utl_buf_t *, const ln_msg_accept_channel_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_read, ln_msg_accept_channel_t *, const uint8_t *, uint16_t );
// FAKE_VALUE_FUNC(bool, ln_msg_funding_created_write, utl_buf_t *, const ln_funding_writed_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_funding_created_read, ln_msg_funding_created_t *, const uint8_t *, uint16_t );
// FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_write, utl_buf_t *, const ln_msg_funding_signed_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_read, ln_msg_funding_signed_t *, const uint8_t *, uint16_t );
typedef uint8_t (fake_sig_t)[LN_SZ_SIGNATURE];
FAKE_VALUE_FUNC(bool, ln_commit_tx_create_remote, ln_commit_info_t *, const ln_update_info_t *, const ln_derkey_local_keys_t *, const ln_derkey_remote_keys_t *, fake_sig_t **);
FAKE_VALUE_FUNC(bool, ln_commit_tx_create_remote_close, const ln_commit_info_t *, const ln_update_info_t *, const ln_derkey_local_keys_t *, const ln_derkey_remote_keys_t *, const utl_buf_t *, ln_close_force_t *);


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        // RESET_FAKE(ln_db_preimage_cur_close)
        // RESET_FAKE(ln_db_cnlupd_load)
        // RESET_FAKE(ln_db_preimage_del)
        // RESET_FAKE(ln_db_preimage_cur_open)
        // RESET_FAKE(ln_db_preimage_cur_get)
        // RESET_FAKE(ln_db_channel_search)
        // RESET_FAKE(ln_db_channel_search_readonly)
        // RESET_FAKE(ln_db_payment_hash_save)
        // RESET_FAKE(ln_db_preimage_search)
        // RESET_FAKE(ln_db_preimage_set_expiry)
        // RESET_FAKE(ln_msg_open_channel_read)
        // RESET_FAKE(ln_msg_accept_channel_write)
        // RESET_FAKE(ln_msg_accept_channel_read)
        // RESET_FAKE(ln_msg_funding_created_write)
        // RESET_FAKE(ln_msg_funding_created_read)
        // RESET_FAKE(ln_msg_funding_signed_write)
        // RESET_FAKE(ln_msg_funding_signed_read)
        RESET_FAKE(ln_commit_tx_create_remote)

        ln_commit_tx_create_remote_fake.return_val = true;
        ln_commit_tx_create_remote_close_fake.return_val = true;
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
        case LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV: p_str = "LN_CB_TYPE_NOTIFY_ADD_HTLC_RECV"; break;
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

TEST_F(ln, init)
{
    ln_channel_t channel;
    ln_anno_param_t anno_param;

    memset(&channel, 0xcc, sizeof(channel));
    anno_param.cltv_expiry_delta = 10;
    anno_param.htlc_minimum_msat = 1000;
    anno_param.fee_base_msat = 20;
    anno_param.fee_prop_millionths = 200;
    ln_init(&channel, &anno_param, NULL, (ln_callback_t)0x123456, (void *)0x654321);

    ASSERT_EQ(LN_STATUS_NONE, channel.status);
    for (uint16_t idx = 0; idx < LN_UPDATE_MAX; idx++) {
        ASSERT_TRUE(utl_mem_is_all_zero(
            &channel.update_info.updates[idx].state, sizeof(channel.update_info.updates[idx].state)));
    }
    ASSERT_EQ(0x654321, channel.p_param);
    ASSERT_EQ(0x123456, channel.p_callback);

    ln_term(&channel);
}


////////////////////////////////////////////////////////////////////////

TEST_F(ln, calc_short1)
{
    uint64_t sid = ln_short_channel_id_calc(0x12345678, 0x9abcdef0, 0x6543210f);
    ASSERT_EQ(0x345678bcdef0210f, sid);
}


TEST_F(ln, calc_short2)
{
    uint64_t sid = ln_short_channel_id_calc(1116104, 33, 0);
    ASSERT_EQ(0x1107c80000210000, sid);
}
