#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#undef LOG_TAG
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
#include "../../btc/btc.c"
#include "../../btc/btc_extkey.c"
#include "../../btc/btc_keys.c"
#include "../../btc/btc_sw.c"
#include "../../btc/btc_sig.c"
#include "../../btc/btc_tx.c"
#include "../../btc/btc_util.c"
#include "../../btc/segwit_addr.c"
#include "../../btc/btc_segwit_addr.c"
#undef LOG_TAG
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

class main: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(main, first)
{
    //utl_log_init_stderr();
}

////////////////////////////////////////////////////////////////////////

#include "testinc_ln_bolt3_b.cpp"
#include "testinc_ln_bolt3_c.cpp"
#include "testinc_ln_bolt3_d.cpp"
#include "testinc_ln_bolt3_e.cpp"
#include "testinc_ln_bolt4.cpp"
#include "testinc_ln_bolt8.cpp"
#include "testinc_ln_misc.cpp"
#include "testinc_bech32.cpp"
#include "testinc_ln.cpp"
