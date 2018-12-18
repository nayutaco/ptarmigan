////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class push: public testing::Test {
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

TEST_F(push, init)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_EQ(0, pushbuf.pos);
    ASSERT_TRUE(NULL != buf.buf);
    ASSERT_EQ(5, buf.len);

    utl_buf_free(&buf);
}


TEST_F(push, init_zero)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 0));

    ASSERT_EQ(0, pushbuf.pos);
    ASSERT_TRUE(NULL == buf.buf);
    ASSERT_EQ(0, buf.len);
}


TEST_F(push, data_in1)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(utl_push_data(&pushbuf, DATA, sizeof(DATA)));

    ASSERT_EQ(3, pushbuf.pos);
    ASSERT_EQ(0, memcmp(DATA, buf.buf, sizeof(DATA)));
    ASSERT_EQ(5, buf.len);

    utl_buf_free(&buf);
}


TEST_F(push, data_in2)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    const uint8_t DATA1[] = { 1, 2, 3 };
    ASSERT_TRUE(utl_push_data(&pushbuf, DATA1, sizeof(DATA1)));

    const uint8_t DATA2[] = { 4, 5 };
    ASSERT_TRUE(utl_push_data(&pushbuf, DATA2, sizeof(DATA2)));

    ASSERT_EQ(5, pushbuf.pos);
    const uint8_t DATA[] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(0, memcmp(DATA, buf.buf, sizeof(DATA)));
    ASSERT_EQ(5, buf.len);

    utl_buf_free(&buf);
}


TEST_F(push, data_expand1)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(utl_push_data(&pushbuf, DATA, sizeof(DATA)));

    ASSERT_EQ(6, pushbuf.pos);
    ASSERT_EQ(0, memcmp(DATA, buf.buf, sizeof(DATA)));
    ASSERT_EQ(6, buf.len);

    utl_buf_free(&buf);
}


TEST_F(push, data_expand2)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(utl_push_data(&pushbuf, DATA, sizeof(DATA)));

    ASSERT_EQ(6, pushbuf.pos);
    ASSERT_EQ(0, memcmp(DATA, buf.buf, sizeof(DATA)));
    ASSERT_EQ(6, buf.len);

    const uint8_t DATA2[] = { 7, 8, 9, 10 };
    ASSERT_TRUE(utl_push_data(&pushbuf, DATA2, sizeof(DATA2)));

    ASSERT_EQ(10, pushbuf.pos);
    const uint8_t DATA_ALL[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    ASSERT_EQ(0, memcmp(DATA_ALL, buf.buf, sizeof(DATA_ALL)));
    ASSERT_EQ(10, buf.len);

    utl_buf_free(&buf);
}


TEST_F(push, value0)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_value(&pushbuf, 0));

    ASSERT_EQ(1, pushbuf.pos);
    ASSERT_EQ(0x00, buf.buf[0]);

    utl_buf_free(&buf);
}


TEST_F(push, value01_10)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_value(&pushbuf, 0x01));
    ASSERT_TRUE(utl_push_value(&pushbuf, 0x10));

    ASSERT_EQ(2, pushbuf.pos);
    ASSERT_EQ(0x51, buf.buf[0]);
    ASSERT_EQ(0x60, buf.buf[1]);

    utl_buf_free(&buf);
}


TEST_F(push, value11_7f)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_value(&pushbuf, 0x11));
    ASSERT_TRUE(utl_push_value(&pushbuf, 0x7f));

    ASSERT_EQ(4, pushbuf.pos);
    ASSERT_EQ(0x01, buf.buf[0]);
    ASSERT_EQ(0x11, buf.buf[1]);
    ASSERT_EQ(0x01, buf.buf[2]);
    ASSERT_EQ(0x7f, buf.buf[3]);

    utl_buf_free(&buf);
}


TEST_F(push, value80_7fff)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_value(&pushbuf, 0x80));
    ASSERT_TRUE(utl_push_value(&pushbuf, 0x7fff));

    ASSERT_EQ(6, pushbuf.pos);
    ASSERT_EQ(0x02, buf.buf[0]);
    ASSERT_EQ(0x80, buf.buf[1]);
    ASSERT_EQ(0x00, buf.buf[2]);
    ASSERT_EQ(0x02, buf.buf[3]);
    ASSERT_EQ(0xff, buf.buf[4]);
    ASSERT_EQ(0x7f, buf.buf[5]);

    utl_buf_free(&buf);
}


TEST_F(push, value8000_7fffff)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_value(&pushbuf, 0x8000));
    ASSERT_TRUE(utl_push_value(&pushbuf, 0x7fffff));

    ASSERT_EQ(8, pushbuf.pos);
    ASSERT_EQ(0x03, buf.buf[0]);
    ASSERT_EQ(0x00, buf.buf[1]);
    ASSERT_EQ(0x80, buf.buf[2]);
    ASSERT_EQ(0x00, buf.buf[3]);
    ASSERT_EQ(0x03, buf.buf[4]);
    ASSERT_EQ(0xff, buf.buf[5]);
    ASSERT_EQ(0xff, buf.buf[6]);
    ASSERT_EQ(0x7f, buf.buf[7]);

    utl_buf_free(&buf);
}


TEST_F(push, value800000_7fffffff)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_value(&pushbuf, 0x800000));
    ASSERT_TRUE(utl_push_value(&pushbuf, 0x7fffffff));

    ASSERT_EQ(10, pushbuf.pos);
    ASSERT_EQ(0x04, buf.buf[0]);
    ASSERT_EQ(0x00, buf.buf[1]);
    ASSERT_EQ(0x00, buf.buf[2]);
    ASSERT_EQ(0x80, buf.buf[3]);
    ASSERT_EQ(0x00, buf.buf[4]);
    ASSERT_EQ(0x04, buf.buf[5]);
    ASSERT_EQ(0xff, buf.buf[6]);
    ASSERT_EQ(0xff, buf.buf[7]);
    ASSERT_EQ(0xff, buf.buf[8]);
    ASSERT_EQ(0x7f, buf.buf[9]);

    utl_buf_free(&buf);
}


TEST_F(push, value80000000_7fffffffff)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_value(&pushbuf, 0x80000000));
    ASSERT_TRUE(utl_push_value(&pushbuf, 0x7fffffffff));

    ASSERT_EQ(12, pushbuf.pos);
    ASSERT_EQ(0x05, buf.buf[0]);
    ASSERT_EQ(0x00, buf.buf[1]);
    ASSERT_EQ(0x00, buf.buf[2]);
    ASSERT_EQ(0x00, buf.buf[3]);
    ASSERT_EQ(0x80, buf.buf[4]);
    ASSERT_EQ(0x00, buf.buf[5]);
    ASSERT_EQ(0x05, buf.buf[6]);
    ASSERT_EQ(0xff, buf.buf[7]);
    ASSERT_EQ(0xff, buf.buf[8]);
    ASSERT_EQ(0xff, buf.buf[9]);
    ASSERT_EQ(0xff, buf.buf[10]);
    ASSERT_EQ(0x7f, buf.buf[11]);

    utl_buf_free(&buf);
}

TEST_F(push, invalid_value8000000000)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 16));

    ASSERT_FALSE(utl_push_value(&pushbuf, 0x8000000000));

    utl_buf_free(&buf);
}

TEST_F(push, trim0)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    ASSERT_TRUE(utl_push_trim(&pushbuf));

    ASSERT_EQ(0, pushbuf.pos);
    ASSERT_EQ(0, buf.len);

    utl_buf_free(&buf);
}


TEST_F(push, trim)
{
    utl_push_t pushbuf;
    utl_buf_t buf;

    ASSERT_TRUE(utl_push_init(&pushbuf, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(utl_push_data(&pushbuf, DATA, sizeof(DATA)));

    ASSERT_EQ(3, pushbuf.pos);
    ASSERT_EQ(0, memcmp(DATA, buf.buf, sizeof(DATA)));
    ASSERT_EQ(5, buf.len);

    ASSERT_TRUE(utl_push_trim(&pushbuf));

    ASSERT_EQ(3, pushbuf.pos);
    ASSERT_EQ(0, memcmp(DATA, buf.buf, sizeof(DATA)));
    ASSERT_EQ(3, buf.len);

    utl_buf_free(&buf);
}

