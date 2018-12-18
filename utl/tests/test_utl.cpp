#include "gtest/gtest.h"
#include <string.h>
#include "fff.h"
//DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#include "utl_misc.c"
#include "utl_dbg.c"
#include "utl_buf.c"
#include "utl_push.c"
#undef LOG_TAG
#include "utl_log.c"
#include "utl_net.c"
#include "utl_str.c"
#include "utl_opts.c"
#include "utl_jsonrpc.c"
#include "utl_addr.c"
#include "utl_time.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
#include "fakeinc.cpp"

////////////////////////////////////////////////////////////////////////

class utl: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(utl, first)
{
    //utl_log_init_stderr();
}


#include "testinc_addr.cpp"
#include "testinc_buf.cpp"
#include "testinc_jsonrpc.cpp"
#include "testinc_misc.cpp"
#include "testinc_net.cpp"
#include "testinc_opts.cpp"
#include "testinc_push.cpp"
#include "testinc_str.cpp"
#include "testinc_time.cpp"

