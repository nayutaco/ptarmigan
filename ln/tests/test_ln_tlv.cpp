#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
#include "../../utl/utl_log.c"
#undef LOG_TAG
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
#include "../../utl/utl_push.c"
#include "../../utl/utl_time.c"
#include "../../utl/utl_int.c"
#include "../../utl/utl_str.c"

#undef LOG_TAG
#include "../../btc/btc.c"
#include "../../btc/btc_buf.c"
// #include "../../btc/btc_extkey.c"
// #include "../../btc/btc_keys.c"
// #include "../../btc/btc_sw.c"
//#include "../../btc/btc_sig.c"
// #include "../../btc/btc_script.c"
// #include "../../btc/btc_tx.c"
#include "../../btc/btc_tx_buf.c"
#include "../../btc/btc_crypto.c"
// #include "../../btc/segwit_addr.c"
// #include "../../btc/btc_segwit_addr.c"
// #include "../../btc/btc_test_util.c"

#undef LOG_TAG
#include "ln_tlv.c"
}

////////////////////////////////////////////////////////////////////////
//FAKE関数
////////////////////////////////////////////////////////////////////////

class ln_tlv: public testing::Test {
protected:
    virtual void SetUp() {
        utl_log_init_stderr();
        utl_dbg_malloc_cnt_reset();
    }

    virtual void TearDown() {
        ASSERT_EQ(0, utl_dbg_malloc_cnt());
    }

public:
    static void DumpBin(const uint8_t *pData, uint16_t Len)
    {
        for (uint16_t lp = 0; lp < Len; lp++) {
            printf("%02x", pData[lp]);
        }
        printf("\n");
    }
    static bool DumpCheck(const void *pData, uint32_t Len, uint8_t Fill)
    {
        bool ret = true;
        const uint8_t *p = (const uint8_t *)pData;
        for (uint32_t lp = 0; lp < Len; lp++) {
            if (p[lp] != Fill) {
                ret = false;
                break;
            }
        }
        return ret;
    }
};

////////////////////////////////////////////////////////////////////////

TEST_F(ln_tlv, r_test1)
{
    const uint8_t TEST[] = { 0x01, 0x00 };

    ln_tlv_record_t *p_rec;
    bool ret = ln_tlv_read(&p_rec, TEST, sizeof(TEST));
    ASSERT_TRUE(ret);
    ASSERT_EQ(1, p_rec->num);
    ASSERT_EQ(0x01, p_rec->tlvs[0].type);

    ln_tlv_free(p_rec);
}


TEST_F(ln_tlv, r_test2)
{
    const uint8_t TEST[] = { 0x00, 0x00, 0x01, 0x01, 0xab };

    ln_tlv_record_t *p_rec;
    bool ret = ln_tlv_read(&p_rec, TEST, sizeof(TEST));
    ASSERT_TRUE(ret);
    ASSERT_EQ(2, p_rec->num);

    ln_tlv_free(p_rec);
}
