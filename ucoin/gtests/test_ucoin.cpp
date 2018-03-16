#include "gtest/gtest.h"
#include <string.h>
#include "fff.h"
//DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#include "ucoin.c"
#include "ucoin_buf.c"
#include "ucoin_ekey.c"
#include "ucoin_keys.c"
#include "ucoin_push.c"
#include "ucoin_sw.c"
#include "ucoin_tx.c"
#include "ucoin_util.c"
#include "ln.c"
#include "ln_derkey.c"
#include "ln_misc.c"
#include "ln_msg_anno.c"
#include "ln_msg_close.c"
#include "ln_msg_establish.c"
#include "ln_msg_normalope.c"
#include "ln_msg_setupctl.c"
#include "ln_node.c"
#include "ln_onion.c"
#include "ln_script.c"
#include "ln_enc_auth.c"
#include "ln_signer.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
#include "fakeinc.cpp"

////////////////////////////////////////////////////////////////////////

class ucoin: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(ucoin, ucoin_setnet_testnet_false)
{
    bool ret = ucoin_init(UCOIN_TESTNET, false);
    ASSERT_TRUE(ret);
    ASSERT_EQ(2, mPref[UCOIN_PREF]);
    ASSERT_EQ(0xef, mPref[UCOIN_PREF_WIF]);
    ASSERT_EQ(0x6f, mPref[UCOIN_PREF_P2PKH]);
    ASSERT_EQ(0xc4, mPref[UCOIN_PREF_P2SH]);
    ASSERT_EQ(0x03, mPref[UCOIN_PREF_ADDRVER]);
    ASSERT_FALSE(mNativeSegwit);
    ucoin_term();
}

TEST_F(ucoin, ucoin_setnet_testnet_true)
{
    bool ret = ucoin_init(UCOIN_TESTNET, true);
    ASSERT_TRUE(ret);
    ASSERT_EQ(2, mPref[UCOIN_PREF]);
    ASSERT_EQ(0xef, mPref[UCOIN_PREF_WIF]);
    ASSERT_EQ(0x6f, mPref[UCOIN_PREF_P2PKH]);
    ASSERT_EQ(0xc4, mPref[UCOIN_PREF_P2SH]);
    ASSERT_EQ(0x03, mPref[UCOIN_PREF_ADDRVER]);
    ASSERT_TRUE(mNativeSegwit);
    ucoin_term();
}

TEST_F(ucoin, ucoin_setnet_mainnet)
{
    bool ret = ucoin_init(UCOIN_MAINNET, false);
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, mPref[UCOIN_PREF]);
    ASSERT_EQ(0x80, mPref[UCOIN_PREF_WIF]);
    ASSERT_EQ(0x00, mPref[UCOIN_PREF_P2PKH]);
    ASSERT_EQ(0x05, mPref[UCOIN_PREF_P2SH]);
    ASSERT_EQ(0x06, mPref[UCOIN_PREF_ADDRVER]);
    ASSERT_FALSE(mNativeSegwit);
    ucoin_term();
}


#include "testinc_hash.cpp"
#include "testinc_keys.cpp"
#include "testinc_keys_native.cpp"
#include "testinc_buf.cpp"
#include "testinc_tx.cpp"
#include "testinc_tx_native.cpp"
#include "testinc_segwit.cpp"
#include "testinc_sw_native.cpp"
#include "testinc_send.cpp"
#include "testinc_push.cpp"
#include "testinc_ekey.cpp"
#include "testinc_ln.cpp"
#include "testinc_ln_bolt3_b.cpp"
#include "testinc_ln_bolt3_c.cpp"
#include "testinc_ln_bolt3_d.cpp"
#include "testinc_ln_bolt3_e.cpp"
#include "testinc_ln_bolt4.cpp"
#include "testinc_ln_bolt8.cpp"
#include "testinc_ln_misc.cpp"

#include "testinc_recoverpub.cpp"
