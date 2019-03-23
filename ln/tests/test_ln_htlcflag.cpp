#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
// #undef LOG_TAG
// #include "../../utl/utl_thread.c"
#undef LOG_TAG
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

FAKE_VALUE_FUNC(bool, ln_msg_open_channel_write, utl_buf_t *, const ln_msg_open_channel_t *);
FAKE_VALUE_FUNC(bool, ln_msg_open_channel_read, ln_msg_open_channel_t*, const uint8_t*, uint16_t);
FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_write, utl_buf_t *, const ln_msg_accept_channel_t *);
FAKE_VALUE_FUNC(bool, ln_msg_accept_channel_read, ln_msg_accept_channel_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_funding_created_write, utl_buf_t *, const ln_msg_funding_created_t *);
FAKE_VALUE_FUNC(bool, ln_msg_funding_created_read, ln_msg_funding_created_t *, const uint8_t *, uint16_t );
FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_write, utl_buf_t *, const ln_msg_funding_signed_t *);
FAKE_VALUE_FUNC(bool, ln_msg_funding_signed_read, ln_msg_funding_signed_t *, const uint8_t *, uint16_t );
typedef uint8_t (fake_sig_t)[LN_SZ_SIGNATURE];
FAKE_VALUE_FUNC(bool, ln_commit_tx_create_remote, const ln_channel_t *, ln_commit_info_t *, ln_close_force_t *, fake_sig_t **);

////////////////////////////////////////////////////////////////////////

class ln_htlc_flag: public testing::Test {
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
        RESET_FAKE(ln_msg_open_channel_read)
        RESET_FAKE(ln_msg_accept_channel_write)
        RESET_FAKE(ln_msg_accept_channel_read)
        RESET_FAKE(ln_msg_funding_created_write)
        RESET_FAKE(ln_msg_funding_created_read)
        RESET_FAKE(ln_msg_funding_signed_write)
        RESET_FAKE(ln_msg_funding_signed_read)
        RESET_FAKE(ln_commit_tx_create_remote)

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
    static void LnInit(ln_channel_t *pChannel)
    {
        ln_anno_param_t anno_param;

        memset(pChannel, 0xcc, sizeof(ln_channel_t));
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
        pChannel->p_callback = NULL;
    }
};

////////////////////////////////////////////////////////////////////////

TEST_F(ln_htlc_flag, htlc_flag_macro_offer_fulfill)
{
    ln_channel_t channel;
    LnInit(&channel);

    ln_update_t *p_update = &channel.update_info.updates[0];

    //ready update_add_htlc
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;

    ASSERT_TRUE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send update_add_htlc
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv update_fulfill_htlc
    memset(p_update, 0x00, sizeof(ln_update_t));
    p_update->type = LN_UPDATE_TYPE_FULFILL_HTLC;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    ln_term(&channel);
}


TEST_F(ln_htlc_flag, htlc_flag_macro_offer_fail)
{
    ln_channel_t channel;
    LnInit(&channel);

    ln_update_t *p_update = &channel.update_info.updates[0];

    //ready update_add_htlc
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;

    ASSERT_TRUE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send update_add_htlc
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv update_fail_htlc
    memset(p_update, 0x00, sizeof(ln_update_t));
    p_update->type = LN_UPDATE_TYPE_FAIL_HTLC;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    ln_term(&channel);
}


TEST_F(ln_htlc_flag, htlc_flag_macro_recv_fulfill)
{
    ln_channel_t channel;
    LnInit(&channel);

    ln_update_t *p_update = &channel.update_info.updates[0];

    //recv update_add_htlc
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //ready update_fulfill_htlc
    memset(p_update, 0x00, sizeof(ln_update_t));
    p_update->type = LN_UPDATE_TYPE_FULFILL_HTLC;

    ASSERT_TRUE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send update_fulfill_htlc
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    ln_term(&channel);
}


TEST_F(ln_htlc_flag, htlc_flag_macro_recv_fail)
{
    ln_channel_t channel;
    LnInit(&channel);

    ln_update_t *p_update = &channel.update_info.updates[0];

    //recv update_add_htlc
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //ready update_fail_htlc
    memset(p_update, 0x00, sizeof(ln_update_t));
    p_update->type = LN_UPDATE_TYPE_FAIL_HTLC;

    ASSERT_TRUE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send update_fail_htlc
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //send commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //recv revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_TRUE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    //recv commitment_signed
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_FALSE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_TRUE(LN_UPDATE_COMSIGING(p_update));

    //send revoke_and_ack
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_FALSE(LN_UPDATE_WAIT_SEND(p_update));
    ASSERT_FALSE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, true));
    ASSERT_TRUE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, true));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, true));

    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_SEND_ENABLED(p_update, LN_UPDATE_TYPE_ADD_HTLC, false));
    ASSERT_TRUE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_MASK_DEL_HTLC, false));
    ASSERT_FALSE(LN_UPDATE_RECV_ENABLED(p_update, LN_UPDATE_TYPE_FULFILL_HTLC, false));

    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, true));
    ASSERT_FALSE(LN_UPDATE_UNCOMMITTED(p_update, false));
    ASSERT_TRUE(LN_UPDATE_IRREVOCABLY_COMMITTED(p_update));
    ASSERT_FALSE(LN_UPDATE_COMSIGING(p_update));

    ln_term(&channel);
}


TEST_F(ln_htlc_flag, htlc_flag_offer_timeout)
{
    ln_channel_t channel;
    LnInit(&channel);

    ln_update_t *p_update = &channel.update_info.updates[0];
    ln_htlc_t *p_htlc = &channel.update_info.htlcs[0];

    p_update->type_specific_idx = 0;
    p_update->enabled = true;
    p_htlc->cltv_expiry = 100;
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    p_update->state = 0;
    p_update->fin_type = LN_UPDATE_TYPE_NONE;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);
    ln_update_t bak = *p_update;

    ASSERT_TRUE(ln_is_offered_htlc_timeout(&channel, 0, 100)); //just
    ASSERT_TRUE(ln_is_offered_htlc_timeout(&channel, 0, 101)); //pass
    ASSERT_FALSE(ln_is_offered_htlc_timeout(&channel, 0, 99)); //before

    p_update->type = LN_UPDATE_TYPE_NONE;
    ASSERT_FALSE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    ASSERT_TRUE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    p_update->type = LN_UPDATE_TYPE_FULFILL_HTLC;
    ASSERT_FALSE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    *p_update = bak;

    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);
    ASSERT_TRUE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);
    ASSERT_TRUE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV);
    ASSERT_TRUE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);
    ASSERT_FALSE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);
    ASSERT_FALSE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    *p_update = bak;

    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_RECV);
    ASSERT_FALSE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    *p_update = bak;

    p_update->fin_type = LN_UPDATE_TYPE_FULFILL_HTLC;
    ASSERT_TRUE(ln_is_offered_htlc_timeout(&channel, 0, 100));
    *p_update = bak;
}


TEST_F(ln_htlc_flag, htlc_flag_update_add_htlc_resend)
{
    ln_channel_t channel;
    LnInit(&channel);

    ln_update_t *p_update = &channel.update_info.updates[0];

    p_update->enabled = true;
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    p_update->type = LN_UPDATE_TYPE_NONE;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV); //comsiging!
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_TRUE(LN_UPDATE_USED(p_update));
    ASSERT_TRUE(LN_UPDATE_REMOTE_COMSIGING(p_update));
    LN_UPDATE_ENABLE_RESEND_UPDATE(p_update);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ln_term(&channel);
}


TEST_F(ln_htlc_flag, htlc_flag_update_del_htlc_resend)
{
    ln_channel_t channel;
    LnInit(&channel);

    ln_update_t *p_update = &channel.update_info.updates[0];

    p_update->enabled = true;
    p_update->type = LN_UPDATE_TYPE_ADD_HTLC;
    p_update->type = LN_UPDATE_TYPE_FULFILL_HTLC;
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_CS_SEND);
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_RA_RECV); //comsiging!
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_CS_RECV);
    LN_UPDATE_FLAG_UNSET(p_update, LN_UPDATE_STATE_FLAG_RA_SEND);

    ASSERT_TRUE(LN_UPDATE_USED(p_update));
    ASSERT_TRUE(LN_UPDATE_REMOTE_COMSIGING(p_update));
    LN_UPDATE_ENABLE_RESEND_UPDATE(p_update);
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND(p_update));
    LN_UPDATE_FLAG_SET(p_update, LN_UPDATE_STATE_FLAG_UP_SEND);
    ASSERT_TRUE(LN_UPDATE_WAIT_SEND_CS(p_update));

    ln_term(&channel);
}
