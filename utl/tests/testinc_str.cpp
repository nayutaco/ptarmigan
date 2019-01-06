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

TEST_F(str, scan_u16)
{
    uint16_t n;

    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, ""));

    n = 0;
    ASSERT_TRUE(utl_str_scan_u16(&n, "0"));
    ASSERT_EQ(n, 0);
    n = 0;
    ASSERT_TRUE(utl_str_scan_u16(&n, "9"));
    ASSERT_EQ(n, 9);

    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "/"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, ":"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "a"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "f"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "A"));
    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "F"));

    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "00"));

    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "01234"));
    n = 0;
    ASSERT_TRUE(utl_str_scan_u16(&n, "12345"));
    ASSERT_EQ(n, 12345);

    n = 0;
    ASSERT_TRUE(utl_str_scan_u16(&n, "65534"));
    ASSERT_EQ(n, 65534);
    n = 0;
    ASSERT_TRUE(utl_str_scan_u16(&n, "65535")); //max
    ASSERT_EQ(n, 65535);
    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "65536"));

    n = 0;
    ASSERT_TRUE(utl_str_scan_u16(&n, "10000"));
    ASSERT_EQ(n, 10000);
    n = 0;
    ASSERT_FALSE(utl_str_scan_u16(&n, "100000"));
}


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


TEST_F(str, valid)
{
    {
        uint8_t bin[64];
        const char *s = "01";
        uint8_t result[] = {
            0x01,
        };
        uint32_t len = ARRAY_SIZE(result);
        ASSERT_TRUE(utl_str_str2bin(bin, len, s));
        ASSERT_EQ(0, memcmp(bin, result, len));
    }
    {
        uint8_t bin[64];
        const char *s = "0123456789abcdefABCDEF";
        uint8_t result[] = {
            0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd, 0xef,
            0xAB, 0xCD, 0xEF,
        };
        uint32_t len = ARRAY_SIZE(result);
        ASSERT_TRUE(utl_str_str2bin(bin, len, s));
        ASSERT_EQ(0, memcmp(bin, result, len));
    }
}


TEST_F(str, invalid_len)
{
    {
        uint8_t bin[64];
        const char *s = "0123456789abcdefABCDE";
        ASSERT_FALSE(utl_str_str2bin(bin, 10, s));
        ASSERT_FALSE(utl_str_str2bin(bin, 11, s));
    }
    {
        uint8_t bin[64];
        const char *s = "1";
        ASSERT_FALSE(utl_str_str2bin(bin, 0, s));
        ASSERT_FALSE(utl_str_str2bin(bin, 1, s));
    }
}


TEST_F(str, invalid_chars)
{
    {
        uint8_t bin[64];
        const char *s = "g0";
        ASSERT_FALSE(utl_str_str2bin(bin, 1, s));
    }
    {
        uint8_t bin[64];
        const char *s = "0g";
        ASSERT_FALSE(utl_str_str2bin(bin, 1, s));
    }
}
