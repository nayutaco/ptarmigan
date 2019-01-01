#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#include "../../utl/utl_misc.c"
#undef LOG_TAG
#include "../../utl/utl_log.c"
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
#include "../../utl/utl_push.c"
#include "../../utl/utl_time.c"
#include "../../utl/utl_rng.c"
#include "../../utl/utl_int.c"
#undef LOG_TAG
#include "btc.c"
#include "btc_extkey.c"
#include "btc_keys.c"
#include "btc_sw.c"
#include "btc_sig.c"
#include "btc_script.c"
#include "btc_tx.c"
#include "btc_tx_buf.c"
#include "btc_util.c"
#include "segwit_addr.c"
#include "btc_segwit_addr.c"
}

////////////////////////////////////////////////////////////////////////

class btc: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(btc, first)
{
    //utl_log_init_stderr();
}

TEST_F(btc, btc_setnet_testnet_false)
{
    utl_dbg_malloc_cnt_reset();
    bool ret = btc_init(BTC_TESTNET, false);
    ASSERT_TRUE(ret);
    ASSERT_EQ(2, mPref[BTC_PREF_CHAIN]);
    ASSERT_EQ(0xef, mPref[BTC_PREF_WIF]);
    ASSERT_EQ(0x6f, mPref[BTC_PREF_P2PKH]);
    ASSERT_EQ(0xc4, mPref[BTC_PREF_P2SH]);
    ASSERT_EQ(0x03, mPref[BTC_PREF_ADDRVER]);
    ASSERT_FALSE(mNativeSegwit);
    btc_term();
}

TEST_F(btc, btc_setnet_testnet_true)
{
    utl_dbg_malloc_cnt_reset();
    bool ret = btc_init(BTC_TESTNET, true);
    ASSERT_TRUE(ret);
    ASSERT_EQ(2, mPref[BTC_PREF_CHAIN]);
    ASSERT_EQ(0xef, mPref[BTC_PREF_WIF]);
    ASSERT_EQ(0x6f, mPref[BTC_PREF_P2PKH]);
    ASSERT_EQ(0xc4, mPref[BTC_PREF_P2SH]);
    ASSERT_EQ(0x03, mPref[BTC_PREF_ADDRVER]);
    ASSERT_TRUE(mNativeSegwit);
    btc_term();
}

TEST_F(btc, btc_setnet_mainnet)
{
    utl_dbg_malloc_cnt_reset();
    bool ret = btc_init(BTC_MAINNET, false);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, mPref[BTC_PREF_CHAIN]);
    ASSERT_EQ(0x80, mPref[BTC_PREF_WIF]);
    ASSERT_EQ(0x00, mPref[BTC_PREF_P2PKH]);
    ASSERT_EQ(0x05, mPref[BTC_PREF_P2SH]);
    ASSERT_EQ(0x06, mPref[BTC_PREF_ADDRVER]);
    ASSERT_FALSE(mNativeSegwit);
    btc_term();
}


#include "testinc_hash.cpp"
#include "testinc_keys.cpp"
#include "testinc_keys_native.cpp"
#include "testinc_tx.cpp"
#include "testinc_tx_native.cpp"
#include "testinc_segwit.cpp"
#include "testinc_sw_native.cpp"
#include "testinc_send.cpp"
#include "testinc_extkey.cpp"
#include "testinc_recoverpub.cpp"
#include "testinc_segwit_addr.cpp"
