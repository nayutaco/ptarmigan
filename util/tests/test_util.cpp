#include "gtest/gtest.h"
#include <string.h>
#include "fff.h"
//DEFINE_FFF_GLOBALS;


extern "C" {
//評価対象本体
#include "misc.c"
#include "ptarm_dbg.c"
#include "ptarm_buf.c"
#include "ptarm_push.c"
#include "plog.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
#include "fakeinc.cpp"

////////////////////////////////////////////////////////////////////////

class util: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

TEST_F(util, first)
{
    //plog_init_stderr();
}


#include "testinc_buf.cpp"
#include "testinc_push.cpp"
