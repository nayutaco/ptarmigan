////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class misc: public testing::Test {
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

TEST_F(misc, valid)
{
    {
        uint8_t bin[64];
        const char *s = "01";
        uint8_t result[] = {
            0x01,
        };
        uint32_t len = ARRAY_SIZE(result);
        ASSERT_TRUE(utl_misc_str2bin(bin, len, s));
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
        ASSERT_TRUE(utl_misc_str2bin(bin, len, s));
        ASSERT_EQ(0, memcmp(bin, result, len));
    }
}

TEST_F(misc, invalid_len)
{
    {
        uint8_t bin[64];
        const char *s = "0123456789abcdefABCDE";
        ASSERT_FALSE(utl_misc_str2bin(bin, 10, s));
        ASSERT_FALSE(utl_misc_str2bin(bin, 11, s));
    }
    {
        uint8_t bin[64];
        const char *s = "1";
        ASSERT_FALSE(utl_misc_str2bin(bin, 0, s));
        ASSERT_FALSE(utl_misc_str2bin(bin, 1, s));
    }
}

TEST_F(misc, invalid_chars)
{
    {
        uint8_t bin[64];
        const char *s = "g0";
        ASSERT_FALSE(utl_misc_str2bin(bin, 1, s));
    }
    {
        uint8_t bin[64];
        const char *s = "0g";
        ASSERT_FALSE(utl_misc_str2bin(bin, 1, s));
    }
}
