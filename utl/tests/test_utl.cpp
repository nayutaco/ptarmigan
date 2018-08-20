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
#include "utl_log.c"
#include "utl_net.c"
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


#include "testinc_buf.cpp"
#include "testinc_push.cpp"
#include "testinc_net.cpp"
