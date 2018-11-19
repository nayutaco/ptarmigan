#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
#include "../../utl/utl_misc.c"
#undef LOG_TAG
#include "../../utl/utl_log.c"
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
#include "../../utl/utl_push.c"
#include "../../utl/utl_addr.c"
//評価対象本体
#undef LOG_TAG
#include "lnapp.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
//#include "fakeinc.cpp"

////////////////////////////////////////////////////////////////////////

class ptarmd: public testing::Test {
};


////////////////////////////////////////////////////////////////////////

#include "testinc_lnapp.cpp"
