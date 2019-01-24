////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class sig: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
        utl_dbg_malloc_cnt_reset();
        btc_init(BTC_TESTNET, false);
    }

    virtual void TearDown() {
        ASSERT_EQ(0, utl_dbg_malloc_cnt());
        btc_term();
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





TEST_F(sig, sig_der2rs_1)
{
    //r=20, s=20, total=44 : OK
    const uint8_t SIG1[] = {
        0x30, 0x44,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG1, sizeof(SIG1)));

    uint8_t sig[BTC_SZ_SIGN_RS];
    bool ret = btc_sig_der2rs(sig, SIG1, sizeof(SIG1));
    ASSERT_TRUE(ret);

    //復元
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG1, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG1), buf_sig.len);
    utl_buf_free(&buf_sig);
}


TEST_F(sig, sig_der2rs_2)
{
    //r=21, s=20, total=44 : NG
    const uint8_t SIG2[] = {
        0x30, 0x44,
        0x02, 0x21, 0xff, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_FALSE(is_valid_signature_encoding(SIG2, sizeof(SIG2)));

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG2, sizeof(SIG2));
    ASSERT_FALSE(ret);
}


TEST_F(sig, sig_der2rs_3)
{
    //r=21, s=20, total=45 : OK
    const uint8_t SIG3[] = {
        0x30, 0x45,
        0x02, 0x21, 0, 0xf1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x20, 10,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG3, sizeof(SIG3)));

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG3, sizeof(SIG3));
    ASSERT_TRUE(ret);

    //復元
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG3, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG3), buf_sig.len);
    utl_buf_free(&buf_sig);
}


TEST_F(sig, sig_der2rs_4)
{
    //r=20, s=21, total=44 : NG
    const uint8_t SIG4[] = {
        0x30, 0x44,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_FALSE(is_valid_signature_encoding(SIG4, sizeof(SIG4)));

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG4, sizeof(SIG4));
    ASSERT_FALSE(ret);
}


TEST_F(sig, sig_der2rs_5)
{
    //r=20, s=21, total=45 : OK
    const uint8_t SIG5[] = {
        0x30, 0x45,
        0x02, 0x20, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0, 0xff,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG5, sizeof(SIG5)));

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG5, sizeof(SIG5));
    ASSERT_TRUE(ret);

    //復元
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG5, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG5), buf_sig.len);
    utl_buf_free(&buf_sig);
}


TEST_F(sig, sig_der2rs_6)
{
    //r=21, s=21, total=46 : OK
    const uint8_t SIG6[] = {
        0x30, 0x46,
        0x02, 0x21, 0, 0xee,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,3,4,5,6,7,8,9,0, 1,2,
        0x02, 0x21, 0, 0xff,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,8,7,6,5,4,3,2,1, 0,9,
        0x01
    };
    ASSERT_TRUE(is_valid_signature_encoding(SIG6, sizeof(SIG6)));

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG6, sizeof(SIG6));
    ASSERT_TRUE(ret);

    //復元
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG6, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG6), buf_sig.len);
    utl_buf_free(&buf_sig);
}


TEST_F(sig, sig_rs2der_1)
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

    utl_buf_t     sig = UTL_BUF_INIT;

    btc_sig_rs2der(&sig, SIG_1);
    ASSERT_EQ(0, memcmp(SIG1, sig.buf, sizeof(SIG1)));
    ASSERT_EQ(sizeof(SIG1), sig.len);
    utl_buf_free(&sig);
}


TEST_F(sig, sig_rs2der_2)
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

    utl_buf_t     sig = UTL_BUF_INIT;

    btc_sig_rs2der(&sig, SIG_3);
    ASSERT_EQ(0, memcmp(SIG3, sig.buf, sizeof(SIG3)));
    ASSERT_EQ(sizeof(SIG3), sig.len);
    utl_buf_free(&sig);
}


TEST_F(sig, sig_rs2der_3)
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

    utl_buf_t     sig = UTL_BUF_INIT;

    btc_sig_rs2der(&sig, SIG_5);
    ASSERT_EQ(0, memcmp(SIG5, sig.buf, sizeof(SIG5)));
    ASSERT_EQ(sizeof(SIG5), sig.len);
    utl_buf_free(&sig);
}


TEST_F(sig, sig_rs2der_4)
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

    utl_buf_t     sig = UTL_BUF_INIT;

    btc_sig_rs2der(&sig, SIG_6);
    ASSERT_EQ(0, memcmp(SIG6, sig.buf, sizeof(SIG6)));
    ASSERT_EQ(sizeof(SIG6), sig.len);
    utl_buf_free(&sig);
}


TEST_F(sig, sig_der2rs_exp1)
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

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG, sizeof(SIG));
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SIGEX, sig, BTC_SZ_SIGN_RS));

    //復元
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG), buf_sig.len);
    utl_buf_free(&buf_sig);
}


TEST_F(sig, sig_der2rs_exp2)
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

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG, sizeof(SIG));
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SIGEX, sig, BTC_SZ_SIGN_RS));

    //復元
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG), buf_sig.len);
    utl_buf_free(&buf_sig);
}


TEST_F(sig, sig_der2rs_exp3)
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

    uint8_t sig[BTC_SZ_SIGN_RS];

    bool ret = btc_sig_der2rs(sig, SIG, sizeof(SIG));
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SIGEX, sig, BTC_SZ_SIGN_RS));

    //復元
    utl_buf_t buf_sig = UTL_BUF_INIT;
    btc_sig_rs2der(&buf_sig, sig);
    ASSERT_EQ(0, memcmp(SIG, buf_sig.buf, buf_sig.len));
    ASSERT_EQ(sizeof(SIG), buf_sig.len);
    utl_buf_free(&buf_sig);
}


