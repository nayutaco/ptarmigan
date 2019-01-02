////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class tx_buf: public testing::Test {
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

TEST_F(tx_buf, init)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    ASSERT_EQ(0, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_TRUE(NULL != btc_tx_buf_w_get_data(&buf_w));
    ASSERT_EQ(5, buf.len);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, init_zero)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 0));

    ASSERT_EQ(0, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_TRUE(NULL == btc_tx_buf_w_get_data(&buf_w));
    ASSERT_EQ(0, buf.len);
}


TEST_F(tx_buf, data_in1)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf.len);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, data_in2)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    const uint8_t DATA1[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA1, sizeof(DATA1)));

    const uint8_t DATA2[] = { 4, 5 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA2, sizeof(DATA2)));

    ASSERT_EQ(5, btc_tx_buf_w_get_len(&buf_w));
    const uint8_t DATA[] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf.len);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, data_expand1)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(6, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(6, buf.len);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, data_expand2)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(6, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(6, buf.len);

    const uint8_t DATA2[] = { 7, 8, 9, 10 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA2, sizeof(DATA2)));

    ASSERT_EQ(10, btc_tx_buf_w_get_len(&buf_w));
    const uint8_t DATA_ALL[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    ASSERT_EQ(0, memcmp(DATA_ALL, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA_ALL)));
    ASSERT_EQ(10, buf.len);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, write_varint_len_uint8) {
    //len < 0xfd
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 0));

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0x00));
    ASSERT_EQ(1, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[0]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0x01));
    ASSERT_EQ(1, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[0]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0xfc));
    ASSERT_EQ(1, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfc, btc_tx_buf_w_get_data(&buf_w)[0]);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, write_varint_len_uint16) {
    //len >= 0xfd
    //len <= UINT16_MAX
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 0));

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0xfd));
    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfd, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0xfd, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[2]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0x0123));
    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfd, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x23, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[2]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, UINT16_MAX));
    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfd, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[2]);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, write_varint_len_uint32) {
    //len > UINT16_MAX
    //len <= UINT32_MAX
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 0));

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0x10000));
    ASSERT_EQ(5, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfe, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[4]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0x01234567));
    ASSERT_EQ(5, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfe, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x67, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x45, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x23, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[4]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, UINT32_MAX));
    ASSERT_EQ(5, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfe, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[4]);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, write_varint_len_uint64) {
    //len > UINT32_MAX
    //len <= UINT64_MAX
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 0));

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0x100000000));
    ASSERT_EQ(9, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[5]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[6]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[7]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[8]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, 0x0123456789abcdef)); //XXX:
    ASSERT_EQ(9, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0xef, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0xcd, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0xab, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x89, btc_tx_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0x67, btc_tx_buf_w_get_data(&buf_w)[5]);
    ASSERT_EQ(0x45, btc_tx_buf_w_get_data(&buf_w)[6]);
    ASSERT_EQ(0x23, btc_tx_buf_w_get_data(&buf_w)[7]);
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[8]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_len(&buf_w, UINT64_MAX));
    ASSERT_EQ(9, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[5]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[6]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[7]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[8]);

    utl_buf_free(&buf);
}


/*bool btc_tx_buf_w_write_varint(btc_buf_w_t *pBufW, uint64_t Size)
{
    uint8_t buf[9];
    uint32_t len;

    if (Size < 0xfd) {
        len = 1;
        buf[0] = (uint8_t)Size;
    } else if (Size <= UINT16_MAX) {
        len = 3;
        buf[0] = 0xfd;
        utl_int_unpack_u16le(buf + 1, (uint16_t)Size);
    } else if (Size <= UINT32_MAX) {
        len = 5;
        buf[0] = 0xfe;
        utl_int_unpack_u32le(buf + 1, (uint32_t)Size);
    } else {
        len = 9;
        buf[0] = 0xff;
        utl_int_unpack_u64le(buf + 1, Size);
    }
    return btc_tx_buf_w_write_data(pBufW, buf, len);
}*/

TEST_F(tx_buf, trim0)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    ASSERT_TRUE(btc_tx_buf_w_trim(&buf_w));

    ASSERT_EQ(0, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, buf.len);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, trim)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf.len);

    ASSERT_TRUE(btc_tx_buf_w_trim(&buf_w));

    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(3, buf.len);

    utl_buf_free(&buf);
}


TEST_F(tx_buf, truncate)
{
    btc_buf_w_t buf_w;
    utl_buf_t buf;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, &buf, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf.len);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_EQ(0, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(5, buf.len);

    utl_buf_free(&buf);
}


