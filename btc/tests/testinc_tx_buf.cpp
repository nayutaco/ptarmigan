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

TEST_F(tx_buf, w_init)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 5));

    ASSERT_EQ(0, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_TRUE(NULL != btc_tx_buf_w_get_data(&buf_w));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_init_zero)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 0));

    ASSERT_EQ(0, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_TRUE(NULL == btc_tx_buf_w_get_data(&buf_w));
    ASSERT_EQ(0, buf_w._buf_len);
}


TEST_F(tx_buf, w_data_in1)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_data_in2)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 5));

    const uint8_t DATA1[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA1, sizeof(DATA1)));

    const uint8_t DATA2[] = { 4, 5 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA2, sizeof(DATA2)));

    ASSERT_EQ(5, btc_tx_buf_w_get_len(&buf_w));
    const uint8_t DATA[] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_data_expand1)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(6, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(1024, buf_w._buf_len); //now buf unit size is 1024

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_data_expand2)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3, 4, 5, 6 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(6, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(1024, buf_w._buf_len); //now buf unit size is 1024

    const uint8_t DATA2[] = { 7, 8, 9, 10 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA2, sizeof(DATA2)));

    ASSERT_EQ(10, btc_tx_buf_w_get_len(&buf_w));
    const uint8_t DATA_ALL[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    ASSERT_EQ(0, memcmp(DATA_ALL, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA_ALL)));
    ASSERT_EQ(1024, buf_w._buf_len); //now buf unit size is 1024

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_write_varint_len_uint8) {
    //len < 0xfd
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 0));

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

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_write_varint_len_uint16) {
    //len >= 0xfd
    //len <= UINT16_MAX
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 0));

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

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_write_varint_len_uint32) {
    //len > UINT16_MAX
    //len <= UINT32_MAX
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 0));

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

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_write_varint_len_uint64) {
    //len > UINT32_MAX
    //len <= UINT64_MAX
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 0));

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

    btc_tx_buf_w_free(&buf_w);
}


TEST_F(tx_buf, w_truncate)
{
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 5));

    const uint8_t DATA[] = { 1, 2, 3 };
    ASSERT_TRUE(btc_tx_buf_w_write_data(&buf_w, DATA, sizeof(DATA)));

    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0, memcmp(DATA, btc_tx_buf_w_get_data(&buf_w), sizeof(DATA)));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_EQ(0, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(5, buf_w._buf_len);

    btc_tx_buf_w_free(&buf_w);
}

//https://github.com/lightningnetwork/lightning-rfc/blob/aa33af0c4d7ae0180c04ef98e61af49c1f876a36/01-messaging.md#bigsize-encoding-tests
TEST_F(tx_buf, w_write_varint_len_bolt1) {
    btc_buf_w_t buf_w;

    ASSERT_TRUE(btc_tx_buf_w_init(&buf_w, 0));

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 0));
    ASSERT_EQ(1, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[0]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 252));
    ASSERT_EQ(1, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfc, btc_tx_buf_w_get_data(&buf_w)[0]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 253));
    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfd, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0xfd, btc_tx_buf_w_get_data(&buf_w)[2]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 65535));
    ASSERT_EQ(3, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfd, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[2]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 65536));
    ASSERT_EQ(5, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfe, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[4]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 4294967295));
    ASSERT_EQ(5, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xfe, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[4]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 4294967296ULL));
    ASSERT_EQ(9, btc_tx_buf_w_get_len(&buf_w));
    ASSERT_EQ(0xff, btc_tx_buf_w_get_data(&buf_w)[0]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[1]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[2]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[3]);
    ASSERT_EQ(0x01, btc_tx_buf_w_get_data(&buf_w)[4]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[5]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[6]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[7]);
    ASSERT_EQ(0x00, btc_tx_buf_w_get_data(&buf_w)[8]);

    btc_tx_buf_w_truncate(&buf_w);
    ASSERT_TRUE(btc_tx_buf_w_write_varint_be_len(&buf_w, 18446744073709551615ULL));
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

    btc_tx_buf_w_free(&buf_w);
}

//https://github.com/lightningnetwork/lightning-rfc/blob/aa33af0c4d7ae0180c04ef98e61af49c1f876a36/01-messaging.md#bigsize-decoding-tests
TEST_F(tx_buf, r_write_varint_len_bolt1_ok) {
    btc_buf_r_t buf_r;
    uint64_t val;

    const uint8_t TEST1[] = { 0x00 };
    const uint64_t TEST1_VAL = 0;
    const uint8_t TEST2[] = { 0xfc };
    const uint64_t TEST2_VAL = 252;
    const uint8_t TEST3[] = { 0xfd, 0x00, 0xfd };
    const uint64_t TEST3_VAL = 253;
    const uint8_t TEST4[] = { 0xfd, 0xff, 0xff };
    const uint64_t TEST4_VAL = 65535;
    const uint8_t TEST5[] = { 0xfe, 0x00, 0x01, 0x00, 0x00 };
    const uint64_t TEST5_VAL = 65536;
    const uint8_t TEST6[] = { 0xfe, 0xff, 0xff, 0xff, 0xff };
    const uint64_t TEST6_VAL = 4294967295;
    const uint8_t TEST7[] = { 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const uint64_t TEST7_VAL = 4294967296;
    const uint8_t TEST8[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const uint64_t TEST8_VAL = 18446744073709551615ULL;

    btc_buf_r_init(&buf_r, TEST1, sizeof(TEST1));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST1_VAL, val);

    btc_buf_r_init(&buf_r, TEST2, sizeof(TEST2));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST2_VAL, val);

    btc_buf_r_init(&buf_r, TEST3, sizeof(TEST3));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST3_VAL, val);

    btc_buf_r_init(&buf_r, TEST4, sizeof(TEST4));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST4_VAL, val);

    btc_buf_r_init(&buf_r, TEST5, sizeof(TEST5));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST5_VAL, val);

    btc_buf_r_init(&buf_r, TEST6, sizeof(TEST6));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST6_VAL, val);

    btc_buf_r_init(&buf_r, TEST7, sizeof(TEST7));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST7_VAL, val);

    btc_buf_r_init(&buf_r, TEST8, sizeof(TEST8));
    ASSERT_TRUE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
    ASSERT_EQ(TEST8_VAL, val);
}

//https://github.com/lightningnetwork/lightning-rfc/blob/aa33af0c4d7ae0180c04ef98e61af49c1f876a36/01-messaging.md#bigsize-decoding-tests
TEST_F(tx_buf, r_write_varint_len_bolt1_ng) {
    btc_buf_r_t buf_r;
    uint64_t val;

    const uint8_t TEST1[] = { 0xfd, 0x00, 0xfc };
    const uint8_t TEST2[] = { 0xfe, 0x00, 0x00, 0xff, 0xff };
    const uint8_t TEST3[] = { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff };
    const uint8_t TEST4[] = { 0xfd, 0x00 };
    const uint8_t TEST5[] = { 0xfe, 0xff, 0xff };
    const uint8_t TEST6[] = { 0xff, 0xff, 0xff, 0xff, 0xff };
    const uint8_t TEST7[] = { 0xfd };
    const uint8_t TEST8[] = { 0xfe };
    const uint8_t TEST9[] = { 0xff };

    btc_buf_r_init(&buf_r, TEST1, sizeof(TEST1));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST2, sizeof(TEST2));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST3, sizeof(TEST3));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST4, sizeof(TEST4));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST5, sizeof(TEST5));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST6, sizeof(TEST6));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST7, sizeof(TEST7));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST8, sizeof(TEST8));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));

    btc_buf_r_init(&buf_r, TEST9, sizeof(TEST9));
    ASSERT_FALSE(btc_tx_buf_r_read_varint_be(&buf_r, &val));
}
