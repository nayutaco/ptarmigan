#include "gtest/gtest.h"
#include <string.h>
#include "fff.h"
//DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#include "ptarm.c"
#include "ptarm_buf.c"
#include "ptarm_ekey.c"
#include "ptarm_keys.c"
#include "ptarm_push.c"
#include "ptarm_sw.c"
#include "ptarm_tx.c"
#include "ptarm_util.c"
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
#include "segwit_addr.c"
#include "plog.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
#include "fakeinc.cpp"

////////////////////////////////////////////////////////////////////////

class ptarm: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(ptarm, first)
{
    //plog_init_stderr();
}

TEST_F(ptarm, ptarm_setnet_testnet_false)
{
    ptarm_dbg_malloc_cnt_reset();
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

TEST_F(ptarm, ptarm_setnet_testnet_true)
{
    ptarm_dbg_malloc_cnt_reset();
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

TEST_F(ptarm, ptarm_setnet_mainnet)
{
    ptarm_dbg_malloc_cnt_reset();
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


#include "testinc_ln_bolt4.cpp"
