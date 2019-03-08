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


TEST_F(str, itoa)
{
    char str[128];

    memset(str, 0xff, sizeof(str));
    ASSERT_TRUE(utl_str_itoa(str, 1 + 1, 0));
    ASSERT_EQ(0, strcmp(str, "0"));

    memset(str, 0xff, sizeof(str));
    ASSERT_TRUE(utl_str_itoa(str, M_UINT16_MAX_DIGIT + 1, UINT16_MAX));
    ASSERT_EQ(0, strcmp(str, "65535"));

    memset(str, 0xff, sizeof(str));
    ASSERT_TRUE(utl_str_itoa(str, M_UINT32_MAX_DIGIT + 1, UINT32_MAX));
    ASSERT_EQ(0, strcmp(str, "4294967295"));

    memset(str, 0xff, sizeof(str));
    ASSERT_TRUE(utl_str_itoa(str, M_UINT64_MAX_DIGIT + 1, UINT64_MAX));
    ASSERT_EQ(0, strcmp(str, "18446744073709551615"));
}


TEST_F(str, invalid_itoa)
{
    char str[128];

    memset(str, 0xff, sizeof(str));
    ASSERT_FALSE(utl_str_itoa(str, 1, 0));

    memset(str, 0xff, sizeof(str));
    ASSERT_FALSE(utl_str_itoa(str, M_UINT16_MAX_DIGIT, UINT16_MAX));

    memset(str, 0xff, sizeof(str));
    ASSERT_FALSE(utl_str_itoa(str, M_UINT32_MAX_DIGIT, UINT32_MAX));

    memset(str, 0xff, sizeof(str));
    ASSERT_FALSE(utl_str_itoa(str, M_UINT64_MAX_DIGIT, UINT64_MAX));
}


TEST_F(str, copy_and_fill_zeros)
{
    const char      *src = "abcdefgh";
    const uint8_t   answer[16] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    char            dst[16] = {0};

    memset(dst, 0xcc, sizeof(dst)); //clear
    ASSERT_FALSE(utl_str_copy_and_fill_zeros(dst, src, 7));

    memset(dst, 0xcc, sizeof(dst)); //clear
    ASSERT_TRUE(utl_str_copy_and_fill_zeros(dst, src, 8));
    ASSERT_EQ(0, memcmp(dst, answer, 8));
    ASSERT_EQ(dst[8], (char)0xcc); //check that do not overrun

    memset(dst, 0xcc, sizeof(dst)); //clear
    ASSERT_TRUE(utl_str_copy_and_fill_zeros(dst, src, 9));
    ASSERT_EQ(0, memcmp(dst, answer, 9));
    ASSERT_EQ(dst[9], (char)0xcc); //check that do not overrun
}


TEST_F(str, copy_and_append_zero)
{
    const uint8_t   data[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    char            buf[16] = {0};

    memset(buf, 0xcc, sizeof(buf)); //clear
    ASSERT_FALSE(utl_str_copy_and_append_zero(buf, 7, data, sizeof(data)));

    memset(buf, 0xcc, sizeof(buf)); //clear
    ASSERT_FALSE(utl_str_copy_and_append_zero(buf, 8, data, sizeof(data)));

    memset(buf, 0xcc, sizeof(buf)); //clear
    ASSERT_TRUE(utl_str_copy_and_append_zero(buf, 9, data, sizeof(data)));
    ASSERT_EQ(0, strncmp(buf, (const char *)data, sizeof(data)));
    ASSERT_EQ(buf[8], 0x00); //check zero
    ASSERT_EQ((uint8_t)buf[9], 0xcc); //check that do not overrun

    memset(buf, 0xcc, sizeof(buf)); //clear
    ASSERT_TRUE(utl_str_copy_and_append_zero(buf, 10, data, sizeof(data)));
    ASSERT_EQ(0, strncmp(buf, (const char *)data, sizeof(data)));
    ASSERT_EQ(buf[8], 0x00); //check zero
    ASSERT_EQ((uint8_t)buf[9], 0xcc); //check that do not overrun
}
