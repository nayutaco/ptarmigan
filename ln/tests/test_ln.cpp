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

#include "ln.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数

// FAKE_VOID_FUNC(ln_db_preimg_cur_close, void *);
// FAKE_VALUE_FUNC(bool, ln_db_annocnlupd_load, utl_buf_t *, uint32_t *, uint64_t, uint8_t);
// FAKE_VALUE_FUNC(bool, ln_db_preimg_del, const uint8_t *);
// FAKE_VALUE_FUNC(bool, ln_db_preimg_cur_open, void **);
// FAKE_VALUE_FUNC(bool, ln_db_preimg_cur_get, void *, bool *, ln_db_preimg_t *);
// FAKE_VALUE_FUNC(bool, ln_db_channel_search, ln_db_func_cmp_t, void *);
// FAKE_VALUE_FUNC(bool, ln_db_channel_search_readonly, ln_db_func_cmp_t, void *);
// FAKE_VALUE_FUNC(bool, ln_db_phash_save, const uint8_t*, const uint8_t*, ln_comtx_output_type_t, uint32_t);
// FAKE_VALUE_FUNC(bool, ln_db_preimg_search, ln_db_func_preimg_t, void*);
// FAKE_VALUE_FUNC(bool, ln_db_preimg_set_expiry, void *, uint32_t);

// FAKE_VALUE_FUNC(bool, ln_msg_open_channel_write, utl_buf_t *, const ln_open_channel_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_open_channel_read, ln_open_channel_t*, const uint8_t*, uint16_t);
// FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_write, utl_buf_t *, const ln_msg_accept_channel_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_read, ln_msg_accept_channel_t *, const uint8_t *, uint16_t );
// FAKE_VALUE_FUNC(bool, ln_msg_funding_created_write, utl_buf_t *, const ln_funding_writed_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_funding_created_read, ln_msg_funding_created_t *, const uint8_t *, uint16_t );
// FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_write, utl_buf_t *, const ln_msg_funding_signed_t *);
// FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_read, ln_msg_funding_signed_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_comtx_create_to_remote, const ln_channel_t *, ln_commit_tx_t *, ln_close_force_t *, uint8_t **, uint64_t);


////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        // RESET_FAKE(ln_db_preimg_cur_close)
        // RESET_FAKE(ln_db_annocnlupd_load)
        // RESET_FAKE(ln_db_preimg_del)
        // RESET_FAKE(ln_db_preimg_cur_open)
        // RESET_FAKE(ln_db_preimg_cur_get)
        // RESET_FAKE(ln_db_channel_search)
        // RESET_FAKE(ln_db_channel_search_readonly)
        // RESET_FAKE(ln_db_phash_save)
        // RESET_FAKE(ln_db_preimg_search)
        // RESET_FAKE(ln_db_preimg_set_expiry)
        // RESET_FAKE(ln_msg_open_channel_read)
        // RESET_FAKE(ln_msg_accept_channel_write)
        // RESET_FAKE(ln_msg_accept_channel_read)
        // RESET_FAKE(ln_msg_funding_created_write)
        // RESET_FAKE(ln_msg_funding_created_read)
        // RESET_FAKE(ln_msg_funding_signed_write)
        // RESET_FAKE(ln_msg_funding_signed_read)
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
    static void LnCallbackType(ln_channel_t *pChannel, ln_cb_t type, void *p_param) {
        (void)pChannel; (void)p_param;
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
    static void LnInit(ln_channel_t *pChannel)
    {
        ln_anno_prm_t annoprm;

        memset(pChannel, 0xcc, sizeof(ln_channel_t));
        pChannel->noise.p_handshake = NULL;
        annoprm.cltv_expiry_delta = 10;
        annoprm.htlc_minimum_msat = 1000;
        annoprm.fee_base_msat = 20;
        annoprm.fee_prop_millionths = 200;
        ln_init(pChannel, &annoprm, (ln_callback_t)0x123456);
        pChannel->commit_tx_local.dust_limit_sat = BTC_DUST_LIMIT;
        pChannel->commit_tx_local.htlc_minimum_msat = 0;
        pChannel->commit_tx_local.max_accepted_htlcs = 10;
        pChannel->commit_tx_remote.dust_limit_sat = BTC_DUST_LIMIT;
        pChannel->commit_tx_remote.htlc_minimum_msat = 0;
        pChannel->commit_tx_remote.max_accepted_htlcs = 10;
        pChannel->our_msat = 1000000;
        pChannel->their_msat = 1000000;
        btc_tx_init(&pChannel->tx_funding);
        utl_buf_init(&pChannel->redeem_fund);
        pChannel->p_callback = LnCallbackType;
    }
};


////////////////////////////////////////////////////////////////////////

TEST_F(ln, init)
{
    ln_channel_t channel;
    ln_anno_prm_t annoprm;

    memset(&channel, 0xcc, sizeof(channel));
    channel.noise.p_handshake = NULL;
    annoprm.cltv_expiry_delta = 10;
    annoprm.htlc_minimum_msat = 1000;
    annoprm.fee_base_msat = 20;
    annoprm.fee_prop_millionths = 200;
    ln_init(&channel, &annoprm, (ln_callback_t)0x123456);

    ASSERT_EQ(LN_STATUS_NONE, channel.status);
    for (int idx = 0; idx < LN_HTLC_MAX; idx++) {
        ASSERT_EQ(0, channel.cnl_add_htlc[idx].stat.bits);
    }
    ASSERT_TRUE(DumpCheck(&channel.noise.send_ctx, sizeof(ln_noise_ctx_t), 0xcc));
    ASSERT_TRUE(DumpCheck(&channel.noise.recv_ctx, sizeof(ln_noise_ctx_t), 0xcc));
    ASSERT_EQ(0xcccccccccccccccc, channel.p_param);
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
