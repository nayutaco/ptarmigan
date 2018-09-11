////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class str: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
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
};

////////////////////////////////////////////////////////////////////////

TEST_F(str, scan_u32)
{
    uint32_t n;

    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, ""));

    n = 0;
    ASSERT_TRUE(utl_str_scan_u32(&n, "0"));
    ASSERT_EQ(n, 0);
    n = 0;
    ASSERT_TRUE(utl_str_scan_u32(&n, "9"));
    ASSERT_EQ(n, 9);

    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "/"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, ":"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "a"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "f"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "A"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "F"));

    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "00"));

    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "0123456789"));
    n = 0;
    ASSERT_TRUE(utl_str_scan_u32(&n, "1234567890"));
    ASSERT_EQ(n, 1234567890);

    n = 0;
    ASSERT_TRUE(utl_str_scan_u32(&n, "4294967294"));
    ASSERT_EQ(n, 4294967294);
    n = 0;
    ASSERT_TRUE(utl_str_scan_u32(&n, "4294967295")); //max
    ASSERT_EQ(n, 4294967295);
    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "4294967296"));

    n = 0;
    ASSERT_TRUE(utl_str_scan_u32(&n, "1000000000"));
    ASSERT_EQ(n, 1000000000);
    n = 0;
    ASSERT_FALSE(utl_str_scan_u32(&n, "10000000000"));
}

TEST_F(str, str_buf)
{
    utl_str_t x;
    utl_str_init(&x);
    ASSERT_STREQ(utl_str_get(&x), "");
    #define TEST_STR_0 "1234567890-="
    #define TEST_STR_1 "qwertyuiop[]\\"
    #define TEST_STR_2 "asdfghjkl;'"
    #define TEST_STR_3 "zxcvbnm,./"
    ASSERT_TRUE(utl_str_append(&x, TEST_STR_0));
    ASSERT_STREQ(utl_str_get(&x), TEST_STR_0);
    ASSERT_TRUE(utl_str_append(&x, TEST_STR_1));
    ASSERT_STREQ(utl_str_get(&x), TEST_STR_0 TEST_STR_1);
    ASSERT_TRUE(utl_str_append(&x, TEST_STR_2));
    ASSERT_STREQ(utl_str_get(&x), TEST_STR_0 TEST_STR_1 TEST_STR_2);
    ASSERT_TRUE(utl_str_append(&x, TEST_STR_3));
    ASSERT_STREQ(utl_str_get(&x), TEST_STR_0 TEST_STR_1 TEST_STR_2 TEST_STR_3);
    utl_str_free(&x);
}

