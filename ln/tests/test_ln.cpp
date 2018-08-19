#include "gtest/gtest.h"
#include <string.h>
#include "fff.h"
//DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#include "../../util/misc.c"
#include "../../util/plog.c"
#include "../../util/ptarm_dbg.c"
#include "../../util/ptarm_buf.c"
#include "../../util/ptarm_push.c"
#include "../../btc/ptarm.c"
#include "../../btc/ptarm_ekey.c"
#include "../../btc/ptarm_keys.c"
#include "../../btc/ptarm_sw.c"
#include "../../btc/ptarm_tx.c"
#include "../../btc/ptarm_util.c"
#include "../../btc/segwit_addr.c"
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
#include "ln_segwit_addr.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
#include "fakeinc.cpp"

////////////////////////////////////////////////////////////////////////

class ln: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(ln, first)
{
    //plog_init_stderr();
}

//TEST_F(ln, init)
//{
//    ptarm_ln_init();
//}
//
//TEST_F(ln, term)
//{
//    ptarm_ln_term();
//}


#include "testinc_ln_bolt3_b.cpp"
#include "testinc_ln_bolt3_c.cpp"
#include "testinc_ln_bolt3_d.cpp"
#include "testinc_ln_bolt3_e.cpp"
#include "testinc_ln_bolt4.cpp"
#include "testinc_ln_bolt8.cpp"
#include "testinc_ln_misc.cpp"
#include "testinc_bech32.cpp"
