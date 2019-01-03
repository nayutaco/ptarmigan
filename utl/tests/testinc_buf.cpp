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

    static void InitDummy(utl_buf_t *pBuf)
    {
        static uint8_t a = 123;
        pBuf->buf = &a;
        pBuf->len = 12345;
    }
};

////////////////////////////////////////////////////////////////////////

TEST_F(buf, init)
{
    utl_buf_t buf = UTL_BUF_INIT;
    InitDummy(&buf);

    utl_buf_init(&buf);
    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);

    utl_buf_free(&buf);
    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloc)
{
    utl_buf_t buf = UTL_BUF_INIT;
    InitDummy(&buf);

    ASSERT_TRUE(utl_buf_alloc(&buf, 10));
    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_EQ(10, buf.len);

    utl_buf_free(&buf);
    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, realloc)
{
    utl_buf_t buf = UTL_BUF_INIT;
    InitDummy(&buf);

    ASSERT_TRUE(utl_buf_alloc(&buf, 10));
    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_EQ(10, buf.len);

    ASSERT_TRUE(utl_buf_realloc(&buf, 20));
    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_EQ(20, buf.len);

    utl_buf_free(&buf);
    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, alloccopy)
{
    utl_buf_t buf = UTL_BUF_INIT;
    InitDummy(&buf);

    const uint8_t BUF[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    ASSERT_TRUE(utl_buf_alloccopy(&buf, BUF, sizeof(BUF)));
    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_NE(BUF, buf.buf);
    ASSERT_EQ(sizeof(BUF), buf.len);
    ASSERT_EQ(0, memcmp(BUF, buf.buf, sizeof(BUF)));

    utl_buf_free(&buf);
    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}

TEST_F(buf, cmp)
{
    utl_buf_t buf = UTL_BUF_INIT;
    utl_buf_t buf2 = UTL_BUF_INIT;
    utl_buf_t buf3 = UTL_BUF_INIT;
    InitDummy(&buf);
    InitDummy(&buf2);
    InitDummy(&buf3);

    const uint8_t BUF[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    const uint8_t BUF2[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    ASSERT_TRUE(utl_buf_alloccopy(&buf, BUF, sizeof(BUF)));
    ASSERT_TRUE(utl_buf_alloccopy(&buf2, BUF2, sizeof(BUF2)));
    ASSERT_TRUE(utl_buf_alloccopy(&buf3, BUF2, sizeof(BUF2)));

    ASSERT_TRUE(utl_buf_cmp(&buf, &buf));
    ASSERT_FALSE(utl_buf_cmp(&buf, &buf2));
    ASSERT_TRUE(utl_buf_cmp(&buf2, &buf3));

    utl_buf_free(&buf);
    utl_buf_free(&buf2);
    utl_buf_free(&buf3);
}
