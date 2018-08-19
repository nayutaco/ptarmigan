#include "gtest/gtest.h"
#include <string.h>
#include "fff.h"
//DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#include "../../utl/utl_misc.c"
#include "../../utl/utl_log.c"
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
#include "../../utl/utl_push.c"
#include "ptarm.c"
#include "ptarm_ekey.c"
#include "ptarm_keys.c"
#include "ptarm_sw.c"
#include "ptarm_tx.c"
#include "ptarm_util.c"
#include "segwit_addr.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
#include "fakeinc.cpp"

////////////////////////////////////////////////////////////////////////

class btc: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(btc, first)
{
    //plog_init_stderr();
}

TEST_F(btc, ptarm_setnet_testnet_false)
{
    utl_dbg_malloc_cnt_reset();
    bool ret = ptarm_init(PTARM_TESTNET, false);
    ASSERT_TRUE(ret);
    ASSERT_EQ(2, mPref[PTARM_PREF]);
    ASSERT_EQ(0xef, mPref[PTARM_PREF_WIF]);
    ASSERT_EQ(0x6f, mPref[PTARM_PREF_P2PKH]);
    ASSERT_EQ(0xc4, mPref[PTARM_PREF_P2SH]);
    ASSERT_EQ(0x03, mPref[PTARM_PREF_ADDRVER]);
    ASSERT_FALSE(mNativeSegwit);
    ptarm_term();
}

TEST_F(btc, ptarm_setnet_testnet_true)
{
    utl_dbg_malloc_cnt_reset();
    bool ret = ptarm_init(PTARM_TESTNET, true);
    ASSERT_TRUE(ret);
    ASSERT_EQ(2, mPref[PTARM_PREF]);
    ASSERT_EQ(0xef, mPref[PTARM_PREF_WIF]);
    ASSERT_EQ(0x6f, mPref[PTARM_PREF_P2PKH]);
    ASSERT_EQ(0xc4, mPref[PTARM_PREF_P2SH]);
    ASSERT_EQ(0x03, mPref[PTARM_PREF_ADDRVER]);
    ASSERT_TRUE(mNativeSegwit);
    ptarm_term();
}

TEST_F(btc, ptarm_setnet_mainnet)
{
    utl_dbg_malloc_cnt_reset();
    bool ret = ptarm_init(PTARM_MAINNET, false);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, mPref[PTARM_PREF]);
    ASSERT_EQ(0x80, mPref[PTARM_PREF_WIF]);
    ASSERT_EQ(0x00, mPref[PTARM_PREF_P2PKH]);
    ASSERT_EQ(0x05, mPref[PTARM_PREF_P2SH]);
    ASSERT_EQ(0x06, mPref[PTARM_PREF_ADDRVER]);
    ASSERT_FALSE(mNativeSegwit);
    ptarm_term();
}


#include "testinc_hash.cpp"
#include "testinc_keys.cpp"
#include "testinc_keys_native.cpp"
#include "testinc_tx.cpp"
#include "testinc_tx_native.cpp"
#include "testinc_segwit.cpp"
#include "testinc_sw_native.cpp"
#include "testinc_send.cpp"
#include "testinc_ekey.cpp"
#include "testinc_recoverpub.cpp"
#include "testinc_bech32.cpp"
