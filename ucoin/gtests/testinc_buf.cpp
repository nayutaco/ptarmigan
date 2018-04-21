////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class buf: public testing::Test {
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

TEST_F(buf, init)
{
    ucoin_buf_t buf = UCOIN_BUF_INIT;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    ucoin_buf_init(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);

    ucoin_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloc)
{
    ucoin_buf_t buf;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    ucoin_buf_alloc(&buf, 10);

    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_EQ(10, buf.len);

    ucoin_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloccopy)
{
    ucoin_buf_t buf;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    const uint8_t BUF[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    };

    ucoin_buf_alloccopy(&buf, BUF, sizeof(BUF));

    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_NE(BUF, buf.buf);
    ASSERT_EQ(sizeof(BUF), buf.len);
    ASSERT_EQ(0, memcmp(BUF, buf.buf, sizeof(BUF)));

    ucoin_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}
