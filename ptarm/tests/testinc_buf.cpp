////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class buf: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
        ptarm_dbg_malloc_cnt_reset();
        ptarm_init(PTARM_TESTNET, false);
    }

    virtual void TearDown() {
        ASSERT_EQ(0, ptarm_dbg_malloc_cnt());
        ptarm_term();
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
    ptarm_buf_t buf = PTARM_BUF_INIT;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    ptarm_buf_init(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);

    ptarm_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloc)
{
    ptarm_buf_t buf;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    ptarm_buf_alloc(&buf, 10);

    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_EQ(10, buf.len);

    ptarm_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloccopy)
{
    ptarm_buf_t buf;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    const uint8_t BUF[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    };

    ptarm_buf_alloccopy(&buf, BUF, sizeof(BUF));

    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_NE(BUF, buf.buf);
    ASSERT_EQ(sizeof(BUF), buf.len);
    ASSERT_EQ(0, memcmp(BUF, buf.buf, sizeof(BUF)));

    ptarm_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}
