////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class buf: public testing::Test {
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

TEST_F(buf, init)
{
    utl_buf_t buf = UTL_BUF_INIT;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    utl_buf_init(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);

    utl_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloc)
{
    utl_buf_t buf;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    utl_buf_alloc(&buf, 10);

    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_EQ(10, buf.len);

    utl_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloccopy)
{
    utl_buf_t buf;

    uint8_t a;

    buf.buf = &a;
    buf.len = sizeof(a);

    const uint8_t BUF[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    };

    utl_buf_alloccopy(&buf, BUF, sizeof(BUF));

    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_NE(BUF, buf.buf);
    ASSERT_EQ(sizeof(BUF), buf.len);
    ASSERT_EQ(0, memcmp(BUF, buf.buf, sizeof(BUF)));

    utl_buf_free(&buf);

    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}
