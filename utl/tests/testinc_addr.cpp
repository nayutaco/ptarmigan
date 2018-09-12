////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class addr: public testing::Test {
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

TEST_F(addr, ipv4_str2bin)
{
    uint8_t b[4];
    int i;

    memset(b, 0x00, 4);
    i = 0;
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "0.0.0.0"));
    ASSERT_EQ(b[i++], 0);
    ASSERT_EQ(b[i++], 0);
    ASSERT_EQ(b[i++], 0);
    ASSERT_EQ(b[i++], 0);

    memset(b, 0x00, 4);
    i = 0;
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "1.2.3.4"));
    ASSERT_EQ(b[i++], 1);
    ASSERT_EQ(b[i++], 2);
    ASSERT_EQ(b[i++], 3);
    ASSERT_EQ(b[i++], 4);

    memset(b, 0x00, 4);
    i = 0;
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "255.255.255.255"));
    ASSERT_EQ(b[i++], 255);
    ASSERT_EQ(b[i++], 255);
    ASSERT_EQ(b[i++], 255);
    ASSERT_EQ(b[i++], 255);

    memset(b, 0x00, 4);
    i = 0;
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "123.45.67.8"));
    ASSERT_EQ(b[i++], 123);
    ASSERT_EQ(b[i++], 45);
    ASSERT_EQ(b[i++], 67);
    ASSERT_EQ(b[i++], 8);

    memset(b, 0x00, 4);
    i = 0;
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "45.67.8.123"));
    ASSERT_EQ(b[i++], 45);
    ASSERT_EQ(b[i++], 67);
    ASSERT_EQ(b[i++], 8);
    ASSERT_EQ(b[i++], 123);

    memset(b, 0x00, 4);
    i = 0;
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "67.8.123.45"));
    ASSERT_EQ(b[i++], 67);
    ASSERT_EQ(b[i++], 8);
    ASSERT_EQ(b[i++], 123);
    ASSERT_EQ(b[i++], 45);

    memset(b, 0x00, 4);
    i = 0;
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "8.123.45.67"));
    ASSERT_EQ(b[i++], 8);
    ASSERT_EQ(b[i++], 123);
    ASSERT_EQ(b[i++], 45);
    ASSERT_EQ(b[i++], 67);
}

TEST_F(addr, ipv4_str2bin_invalid)
{
    uint8_t b[4];

    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "00.0.0.0"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "0.00.0.0"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "0.0.00.0"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "0.0.0.00"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "256.0.0.0"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "0.256.0.0"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "0.0.256.0"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "0.0.0.256"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1."));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1.1"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1.1."));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1.1.1"));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1.1.1."));
    memset(b, 0x00, 4);
    ASSERT_TRUE(utl_addr_ipv4_str2bin(b, "1.1.1.1")); //true
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1.1.1.1."));
    memset(b, 0x00, 4);
    ASSERT_FALSE(utl_addr_ipv4_str2bin(b, "1.1.1.1.1"));
}
