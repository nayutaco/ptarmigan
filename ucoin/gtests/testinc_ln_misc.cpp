////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class misc: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
        ucoin_init(UCOIN_TESTNET, false);
    }

    virtual void TearDown() {
        ASSERT_EQ(0, ucoin_dbg_malloc_cnt());
        ucoin_term();
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

TEST_F(misc, push8)
{
    ucoin_buf_t buf;
    ucoin_push_t ps;
    ucoin_push_init(&ps, &buf, 13);

    ln_misc_push8(&ps, 0x34);
    ASSERT_EQ(0x34, buf.buf[0]);
    ASSERT_EQ(1, ps.pos);

    ucoin_buf_free(&buf);
}


TEST_F(misc, push16)
{
    ucoin_buf_t buf;
    ucoin_push_t ps;
    ucoin_push_init(&ps, &buf, 13);

    ln_misc_push16be(&ps, 0x3456);
    ASSERT_EQ(0x34, buf.buf[0]);
    ASSERT_EQ(0x56, buf.buf[1]);
    ASSERT_EQ(2, ps.pos);

    ucoin_buf_free(&buf);
}


TEST_F(misc, push32)
{
    ucoin_buf_t buf;
    ucoin_push_t ps;
    ucoin_push_init(&ps, &buf, 13);

    ln_misc_push32be(&ps, 0x3456789a);
    ASSERT_EQ(0x34, buf.buf[0]);
    ASSERT_EQ(0x56, buf.buf[1]);
    ASSERT_EQ(0x78, buf.buf[2]);
    ASSERT_EQ(0x9a, buf.buf[3]);
    ASSERT_EQ(4, ps.pos);

    ucoin_buf_free(&buf);
}


TEST_F(misc, push64)
{
    ucoin_buf_t buf;
    ucoin_push_t ps;
    ucoin_push_init(&ps, &buf, 13);

    ln_misc_push64be(&ps, 0x3456789abcdef012LL);
    ASSERT_EQ(0x34, buf.buf[0]);
    ASSERT_EQ(0x56, buf.buf[1]);
    ASSERT_EQ(0x78, buf.buf[2]);
    ASSERT_EQ(0x9a, buf.buf[3]);
    ASSERT_EQ(0xbc, buf.buf[4]);
    ASSERT_EQ(0xde, buf.buf[5]);
    ASSERT_EQ(0xf0, buf.buf[6]);
    ASSERT_EQ(0x12, buf.buf[7]);
    ASSERT_EQ(8, ps.pos);

    ucoin_buf_free(&buf);
}




TEST_F(misc, sigtrim1)
{
    //r=20, s=20, total=44 : OK
    const uint8_t SIG1[] = {
        0x30, 0x44,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG1, sizeof(SIG1)));

    uint8_t sig[LN_SZ_SIGNATURE];
    bool ret = ln_misc_sigtrim(sig, SIG1);
    ASSERT_TRUE(ret);

    //復元
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG1, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG1), buf_sig.len);
    ucoin_buf_free(&buf_sig);
}


TEST_F(misc, sigtrim2)
{
    //r=21, s=20, total=44 : NG
    const uint8_t SIG2[] = {
        0x30, 0x44,
        0x02, 0x21, 0xff, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_FALSE(is_valid_signature_encoding(SIG2, sizeof(SIG2)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG2);
    ASSERT_FALSE(ret);
}


TEST_F(misc, sigtrim3)
{
    //r=21, s=20, total=45 : OK
    const uint8_t SIG3[] = {
        0x30, 0x45,
        0x02, 0x21, 0, 0xf1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG3, sizeof(SIG3)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG3);
    ASSERT_TRUE(ret);

    //復元
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG3, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG3), buf_sig.len);
    ucoin_buf_free(&buf_sig);
}


TEST_F(misc, sigtrim4)
{
    //r=20, s=21, total=44 : NG
    const uint8_t SIG4[] = {
        0x30, 0x44,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_FALSE(is_valid_signature_encoding(SIG4, sizeof(SIG4)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG4);
    ASSERT_FALSE(ret);
}


TEST_F(misc, sigtrim5)
{
    //r=20, s=21, total=45 : OK
    const uint8_t SIG5[] = {
        0x30, 0x45,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0, 0xff,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG5, sizeof(SIG5)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG5);
    ASSERT_TRUE(ret);

    //復元
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG5, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG5), buf_sig.len);
    ucoin_buf_free(&buf_sig);
}


TEST_F(misc, sigtrim6)
{
    //r=21, s=21, total=46 : OK
    const uint8_t SIG6[] = {
        0x30, 0x46,
        0x02, 0x21, 0, 0xee,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0, 0xff,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG6, sizeof(SIG6)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG6);
    ASSERT_TRUE(ret);

    //復元
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG6, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG6), buf_sig.len);
    ucoin_buf_free(&buf_sig);
}


TEST_F(misc, sigexp1)
{
    const uint8_t SIG_1[] = {
        1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
    };
    const uint8_t SIG1[] = {
        0x30, 0x44,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG1, sizeof(SIG1)));

    ucoin_buf_t     sig;

    ln_misc_sigexpand(&sig, SIG_1);
    ASSERT_EQ(0, memcmp(SIG1, sig.buf, sizeof(SIG1)));
    ASSERT_EQ(sizeof(SIG1), sig.len);
    ucoin_buf_free(&sig);
}


TEST_F(misc, sigexp2)
{
    const uint8_t SIG_3[] = {
        0x81,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
    };
    const uint8_t SIG3[] = {
        0x30, 0x45,
        0x02, 0x21, 0, 0x81,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG3, sizeof(SIG3)));

    ucoin_buf_t     sig;

    ln_misc_sigexpand(&sig, SIG_3);
    ASSERT_EQ(0, memcmp(SIG3, sig.buf, sizeof(SIG3)));
    ASSERT_EQ(sizeof(SIG3), sig.len);
    ucoin_buf_free(&sig);
}


TEST_F(misc, sigexp3)
{
    const uint8_t SIG_5[] = {
        1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0xc0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
    };
    const uint8_t SIG5[] = {
        0x30, 0x45,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0, 0xc0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG5, sizeof(SIG5)));

    ucoin_buf_t     sig;

    ln_misc_sigexpand(&sig, SIG_5);
    ASSERT_EQ(0, memcmp(SIG5, sig.buf, sizeof(SIG5)));
    ASSERT_EQ(sizeof(SIG5), sig.len);
    ucoin_buf_free(&sig);
}


TEST_F(misc, sigexp4)
{
    const uint8_t SIG_6[] = {
        0x81,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0xc0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
    };
    const uint8_t SIG6[] = {
        0x30, 0x46,
        0x02, 0x21, 0x00, 0x81,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0x00, 0xc0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG6, sizeof(SIG6)));

    ucoin_buf_t     sig;

    ln_misc_sigexpand(&sig, SIG_6);
    ASSERT_EQ(0, memcmp(SIG6, sig.buf, sizeof(SIG6)));
    ASSERT_EQ(sizeof(SIG6), sig.len);
    ucoin_buf_free(&sig);
}


TEST_F(misc, sigtrimexp1)
{
    //r=1, s=1, total=6 : OK
    const uint8_t SIG[] = {
        0x30, 6,
        0x02, 1, 0,
        0x02, 1, 0,
        0x01
    };
    const uint8_t SIGEX[] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG, sizeof(SIG)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SIGEX, sig, LN_SZ_SIGNATURE));

    //復元
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG), buf_sig.len);
    ucoin_buf_free(&buf_sig);
}


TEST_F(misc, sigtrimexp2)
{
    //r=33, s=33, total=6 : OK
    const uint8_t SIG[] = {
        0x30, 4 + 33 + 33,
        0x02, 33, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x02, 33, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x01
    };
    const uint8_t SIGEX[] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG, sizeof(SIG)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SIGEX, sig, LN_SZ_SIGNATURE));

    //復元
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG), buf_sig.len);
    ucoin_buf_free(&buf_sig);
}


TEST_F(misc, sigtrimexp3)
{
    //r=32, s=32, total=6 : OK
    const uint8_t SIG[] = {
        0x30, 4 + 32 + 32,
        0x02, 32, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x02, 32, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x01
    };
    const uint8_t SIGEX[] = {
        0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG, sizeof(SIG)));

    uint8_t sig[LN_SZ_SIGNATURE];

    bool ret = ln_misc_sigtrim(sig, SIG);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SIGEX, sig, LN_SZ_SIGNATURE));

    //復元
    ucoin_buf_t buf_sig = UCOIN_BUF_INIT;
    ln_misc_sigexpand(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG), buf_sig.len);
    ucoin_buf_free(&buf_sig);
}


////////////////////////////////////////////////////////////////////////

TEST_F(misc, calc_short1)
{
    uint64_t sid = ln_misc_calc_short_channel_id(0x12345678, 0x9abcdef0, 0x6543210f);
    ASSERT_EQ(0x345678bcdef0210f, sid);
}


TEST_F(misc, calc_short2)
{
    uint64_t sid = ln_misc_calc_short_channel_id(1116104, 33, 0);
    ASSERT_EQ(0x1107c80000210000, sid);
}
