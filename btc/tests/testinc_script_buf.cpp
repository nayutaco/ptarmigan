////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class script_buf: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
        utl_dbg_malloc_cnt_reset();
    }

    virtual void TearDown() {
        ASSERT_EQ(0, utl_dbg_malloc_cnt());
    }

public:
    static const uint8_t* data(size_t &sz) {
        static const uint8_t DATA[] = {
            0xb5, 0xf4, 0xe5, 0x33, 0x8a, 0x2e, 0x8f, 0x69, 0x01, 0xa6, 0x9e, 0x38, 0x1b, 0x36, 0x81, 0x89,
            0xea, 0xe0, 0x20, 0x53, 0xe9, 0x82, 0xb7, 0xcc, 0xb9, 0x70, 0x38, 0x72, 0x48, 0x72, 0x22, 0xc8,
            0xcd, 0x7b, 0xd5, 0x26, 0x56, 0x31, 0xf0, 0xd4, 0x4e, 0x66, 0x2e, 0x73, 0xb1, 0x21, 0x63, 0x17,
            0x3a, 0x2e, 0x9f, 0x5e, 0x17, 0xf0, 0xa2, 0x41, 0xdd, 0x32, 0xa8, 0xd0, 0x35, 0x35, 0xc3, 0x52,
            0x8c, 0x0c, 0x05, 0x75, 0x6d, 0x6f, 0x0f, 0x92, 0xd6, 0xc0, 0x87, 0xdb, 0x7e, 0xa1, 0x5c, 0xd6,
            0x7d, 0xa0, 0xa4, 0x60, 0xfe, 0xb4, 0x1f, 0x73, 0x2c, 0x32, 0x3c, 0x2b, 0xb6, 0x1c, 0x3f, 0x48,
            0xb6, 0x06, 0x3d, 0x66, 0x5e, 0x30, 0x57, 0xb2, 0x2b, 0xb8, 0x4e, 0xe6, 0xd8, 0x0b, 0x7a, 0x0c,
            0xd7, 0x21, 0x5f, 0xcd, 0xf3, 0x6f, 0xba, 0x94, 0x15, 0x7e, 0x28, 0x9f, 0xda, 0x37, 0x65, 0x1a,
            0x38, 0x8d, 0x2d, 0x0f, 0xa6, 0x45, 0xea, 0xa9, 0x1d, 0xee, 0xb4, 0x75, 0x4c, 0x0c, 0x02, 0xb1,
            0x60, 0x47, 0x75, 0xe8, 0x66, 0x36, 0x43, 0x9f, 0x72, 0xc2, 0x9c, 0x92, 0x14, 0x74, 0x2a, 0x9c,
            0xcf, 0x7d, 0x75, 0x00, 0x6d, 0xa4, 0x8e, 0xbf, 0x04, 0x2b, 0xaf, 0x43, 0xd1, 0x48, 0x91, 0xd2,
            0x88, 0xa2, 0xf7, 0x91, 0x8d, 0xe1, 0xe9, 0xb8, 0xaf, 0x1d, 0xb5, 0x6a, 0x8a, 0x21, 0xf3, 0x05,
            0x9c, 0x82, 0x89, 0x5a, 0x0a, 0x36, 0xf3, 0xce, 0xb0, 0xfd, 0x91, 0xa3, 0x97, 0xe4, 0x3c, 0x17,
            0x7d, 0x34, 0x5f, 0x38, 0xec, 0x31, 0x9e, 0x80, 0xcf, 0x01, 0x0a, 0x28, 0x3b, 0x3e, 0x2d, 0x34,
            0xb6, 0x31, 0x2a, 0xd9, 0x30, 0x1a, 0x6c, 0x3a, 0xec, 0x0c, 0xa0, 0x9b, 0x6c, 0x12, 0xf0, 0x40,
            0xaa, 0x29, 0x8a, 0x28, 0xff, 0x48, 0x62, 0x4b, 0x6a, 0x6c, 0xe0, 0x1c, 0xd6, 0xf4, 0xd6, 0x49,
            0x5b, 0x6c, 0x7c, 0x8f, 0x6a, 0x03, 0xb7, 0x7a, 0xe9, 0xd6, 0x48, 0x23, 0xe7, 0x90, 0x83, 0x54,
        };
        sz = sizeof(DATA);
        return DATA;
    }

    static void DumpBin(const uint8_t *pData, uint16_t Len)
    {
        for (uint16_t lp = 0; lp < Len; lp++) {
            printf("%02x", pData[lp]);
        }
        printf("\n");
    }
};

////////////////////////////////////////////////////////////////////////

TEST_F(script_buf, w_init)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_EQ(0, btc_script_buf_w_get_len(&buf_w));
    ASSERT_TRUE(NULL != btc_script_buf_w_get_data(&buf_w));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_init_zero)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 0));

    ASSERT_EQ(0, btc_script_buf_w_get_len(&buf_w));
    ASSERT_TRUE(NULL == btc_script_buf_w_get_data(&buf_w));
    ASSERT_EQ(0, buf_w._buf_len);
}


TEST_F(script_buf, w_data_in1)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_script_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(3, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_script_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_data_in2)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    const uint8_t DATA1[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_script_buf_w_write_data(&buf_w, DATA1, sizeof(DATA1)));

    const uint8_t DATA2[] = { 4, 5 };
    ASSERT_TRUE(btc_script_buf_w_write_data(&buf_w, DATA2, sizeof(DATA2)));

    ASSERT_EQ(5, btc_script_buf_w_get_len(&buf_w));
    const uint8_t DATA[] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(0, memcmp(DATA, btc_script_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_data_expand1)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(btc_script_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(6, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_script_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(1024, buf_w._buf_len); //not buf unit size is 1024

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_data_expand2)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(btc_script_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(6, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_script_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(1024, buf_w._buf_len); //now buf unit size is 1024

    const uint8_t DATA2[] = { 7, 8, 9, 10 };
    ASSERT_TRUE(btc_script_buf_w_write_data(&buf_w, DATA2, sizeof(DATA2)));

    ASSERT_EQ(10, btc_script_buf_w_get_len(&buf_w));
    const uint8_t DATA_ALL[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    ASSERT_EQ(0, memcmp(DATA_ALL, btc_script_buf_w_get_data(&buf_w), sizeof(DATA_ALL)));
    ASSERT_EQ(1024, buf_w._buf_len); //now buf unit size is 1024

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_value0)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0));

    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[0]);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_value01_10)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x01));
    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x10));

    ASSERT_EQ(2, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x51, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x60, btc_script_buf_w_get_data(&buf_w)[1]);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_value11_7f)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x11));
    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x7f));

    ASSERT_EQ(4, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x01, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x11, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x01, btc_script_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x7f, btc_script_buf_w_get_data(&buf_w)[3]);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_value80_7fff)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x80));
    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x7fff));

    ASSERT_EQ(6, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x02, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x80, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x02, btc_script_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0x7f, btc_script_buf_w_get_data(&buf_w)[5]);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_value8000_7fffff)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x8000));
    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x7fffff));

    ASSERT_EQ(8, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x03, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x80, btc_script_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x03, btc_script_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[5]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[6]);
    ASSERT_EQ(0x7f, btc_script_buf_w_get_data(&buf_w)[7]);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_value800000_7fffffff)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x800000));
    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x7fffffff));

    ASSERT_EQ(10, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x04, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x80, btc_script_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0x04, btc_script_buf_w_get_data(&buf_w)[5]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[6]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[7]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[8]);
    ASSERT_EQ(0x7f, btc_script_buf_w_get_data(&buf_w)[9]);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_value80000000_7fffffffff)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x80000000));
    ASSERT_TRUE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x7fffffffff));

    ASSERT_EQ(12, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x05, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x80, btc_script_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[5]);
    ASSERT_EQ(0x05, btc_script_buf_w_get_data(&buf_w)[6]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[7]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[8]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[9]);
    ASSERT_EQ(0xff, btc_script_buf_w_get_data(&buf_w)[10]);
    ASSERT_EQ(0x7f, btc_script_buf_w_get_data(&buf_w)[11]);

    btc_script_buf_w_free(&buf_w);
}

TEST_F(script_buf, w_invalid_value8000000000)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 16));

    ASSERT_FALSE(btc_script_buf_w_write_item_positive_integer(&buf_w, 0x8000000000));

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_truncate)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_script_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(3, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_script_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_script_buf_w_truncate(&buf_w);
    ASSERT_EQ(0, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_wirte_item_op_x)
{ 
    btc_buf_w_t buf_w;
    uint8_t data[256];

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 0));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x00;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_0, *btc_script_buf_w_get_data(&buf_w));
    
    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x01;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x01, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x02;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x02, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x03;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x03, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x04;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x04, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x05;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x05, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x06;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x06, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x07;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x07, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x08;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x08, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x09;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x09, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x0a;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x0a, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x0b;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x0b, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x0c;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x0c, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x0d;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x0d, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x0e;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x0e, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x0f;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x0f, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_truncate(&buf_w);
    data[0] = 0x10;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(1, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_X + 0x10, *btc_script_buf_w_get_data(&buf_w));

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_wirte_item_op_na)
{
    //data len 0x01 - 0x4b 
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 0));

    //(data len == 0x01) and (data[0] > 0x10)
    btc_script_buf_w_truncate(&buf_w);
    uint8_t data = 0x11;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, &data, 1));
    ASSERT_EQ(2, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(1, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x11, btc_script_buf_w_get_data(&buf_w)[1]);

    //data len > 0x01
    size_t sz;
    const uint8_t *p_data = script_buf::data(sz);
    ASSERT_TRUE(sz >= 0x4b);
    for (uint32_t len = 0x02 ; len <= 0x4b; len++) {
        btc_script_buf_w_truncate(&buf_w);
        ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, p_data, len));
        ASSERT_EQ(1 + len, btc_script_buf_w_get_len(&buf_w));
        ASSERT_EQ(len, btc_script_buf_w_get_data(&buf_w)[0]);
        ASSERT_EQ(0, memcmp(p_data, &btc_script_buf_w_get_data(&buf_w)[1], len));
    }

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_wirte_item_pushdata1)
{
    //data len 0x4c - 0xff
    btc_buf_w_t buf_w;
    uint32_t len;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 0));
        
    size_t sz;
    const uint8_t *p_data = script_buf::data(sz);
    ASSERT_TRUE(sz >= 0xff);

    //data len == 0x4c
    btc_script_buf_w_truncate(&buf_w);
    len = 0x4c;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, p_data, len));
    ASSERT_EQ(1 + 1 + len, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_PUSHDATA1, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(len, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0, memcmp(p_data, &btc_script_buf_w_get_data(&buf_w)[2], len));

    //data len == 0xff
    btc_script_buf_w_truncate(&buf_w);
    len = 0xff;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, p_data, len));
    ASSERT_EQ(1 + 1 + len, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_PUSHDATA1, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(len, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0, memcmp(p_data, &btc_script_buf_w_get_data(&buf_w)[2], len));

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_wirte_item_pushdata2)
{
    //data len 0x100 - 0xffff
    btc_buf_w_t buf_w;
    uint32_t len;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 0));
        
    size_t sz;
    const uint8_t *p_data = script_buf::data(sz);
    ASSERT_TRUE(sz >= 0x100);

    //data len == 0x100
    btc_script_buf_w_truncate(&buf_w);
    len = 0x100;
    ASSERT_TRUE(btc_script_buf_w_write_item(&buf_w, p_data, len));
    ASSERT_EQ(1 + 2 + len, btc_script_buf_w_get_len(&buf_w));
    ASSERT_EQ(OP_PUSHDATA2, btc_script_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x01, btc_script_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_script_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0, memcmp(p_data, &btc_script_buf_w_get_data(&buf_w)[3], len));

    btc_script_buf_w_free(&buf_w);
}


TEST_F(script_buf, w_wirte_item_pushdata_invalid)
{
    //data len 0x10000
    btc_buf_w_t buf_w;
    uint32_t len;

    ASSERT_TRUE(btc_script_buf_w_init(&buf_w, 0));
        
    size_t sz;
    const uint8_t *p_data = script_buf::data(sz);

    //data len == 0x10000
    btc_script_buf_w_truncate(&buf_w);
    len = 0x10000;
    ASSERT_FALSE(btc_script_buf_w_write_item(&buf_w, p_data, len));

    btc_script_buf_w_free(&buf_w);
}
