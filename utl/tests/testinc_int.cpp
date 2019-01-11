////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class int_: public testing::Test {
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

TEST_F(int_, pack)
{
    uint8_t data0[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    uint8_t data1[] = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    ASSERT_EQ(utl_int_pack_u16be(data0), 0x0123);
    ASSERT_EQ(utl_int_pack_u16be(data1), 0xfedc);
    ASSERT_EQ(utl_int_pack_u32be(data0), 0x01234567);
    ASSERT_EQ(utl_int_pack_u32be(data1), 0xfedcba98);
    ASSERT_EQ(utl_int_pack_u64be(data0), UINT64_C(0x0123456789abcdef));
    ASSERT_EQ(utl_int_pack_u64be(data1), UINT64_C(0xfedcba9876543210));

    ASSERT_EQ(utl_int_pack_u16le(data0), 0x2301);
    ASSERT_EQ(utl_int_pack_u16le(data1), 0xdcfe);
    ASSERT_EQ(utl_int_pack_u32le(data0), 0x67452301);
    ASSERT_EQ(utl_int_pack_u32le(data1), 0x98badcfe);
    ASSERT_EQ(utl_int_pack_u64le(data0), UINT64_C(0xefcdab8967452301));
    ASSERT_EQ(utl_int_pack_u64le(data1), UINT64_C(0x1032547698badcfe));
}


TEST_F(int_, unpack)
{
    uint8_t data0[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    uint8_t data1[] = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    uint8_t buf[8];

    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u16be(buf, 0x0123);
    ASSERT_EQ(memcmp(buf, data0, 2), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u16be(buf, 0xfedc);
    ASSERT_EQ(memcmp(buf, data1, 2), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u32be(buf, 0x01234567);
    ASSERT_EQ(memcmp(buf, data0, 4), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u32be(buf, 0xfedcba98);
    ASSERT_EQ(memcmp(buf, data1, 4), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u64be(buf, UINT64_C(0x0123456789abcdef));
    ASSERT_EQ(memcmp(buf, data0, 8), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u64be(buf, UINT64_C(0xfedcba9876543210));
    ASSERT_EQ(memcmp(buf, data1, 8), 0);

    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u16le(buf, 0x2301);
    ASSERT_EQ(memcmp(buf, data0, 2), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u16le(buf, 0xdcfe);
    ASSERT_EQ(memcmp(buf, data1, 2), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u32le(buf, 0x67452301);
    ASSERT_EQ(memcmp(buf, data0, 4), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u32le(buf, 0x98badcfe);
    ASSERT_EQ(memcmp(buf, data1, 4), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u64le(buf, UINT64_C(0xefcdab8967452301));
    ASSERT_EQ(memcmp(buf, data0, 8), 0);
    memset(buf, 0x00, sizeof(buf));
    utl_int_unpack_u64le(buf, UINT64_C(0x1032547698badcfe));
    ASSERT_EQ(memcmp(buf, data1, 8), 0);
}


TEST_F(int_, digit)
{
    uint8_t base;

    //base 2
    base = 2;
    ASSERT_EQ(0, utl_int_digit(0, 2));
    ASSERT_EQ(16, utl_int_digit(UINT16_MAX, base));
    ASSERT_EQ(32, utl_int_digit(UINT32_MAX, base));
    ASSERT_EQ(64, utl_int_digit(UINT64_MAX, base));

    //base 10
    base = 10;
    ASSERT_EQ(0, utl_int_digit(0, 10));
    ASSERT_EQ(5, utl_int_digit(UINT16_MAX, base));
    ASSERT_EQ(10, utl_int_digit(UINT32_MAX, base));
    ASSERT_EQ(20, utl_int_digit(UINT64_MAX, base));

    //base 16
    base = 16;
    ASSERT_EQ(0, utl_int_digit(0, base));
    ASSERT_EQ(4, utl_int_digit(UINT16_MAX, base));
    ASSERT_EQ(8, utl_int_digit(UINT32_MAX, base));
    ASSERT_EQ(16, utl_int_digit(UINT64_MAX, base));
}
