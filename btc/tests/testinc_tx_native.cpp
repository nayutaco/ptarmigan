////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class tx_native: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
        utl_dbg_malloc_cnt_reset();
        ptarm_init(PTARM_TESTNET, true);
    }

    virtual void TearDown() {
        ASSERT_EQ(0, utl_dbg_malloc_cnt());
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

TEST_F(tx_native, add_vout_addr_p2wpkh)
{
    bool ret;
    ptarm_tx_t tx;
    ptarm_tx_init(&tx);

    const char WADDR[] = "tb1q29ccnsx40wsam5lesxfx4w6ttmgz52q8qrpgla";
    const uint8_t SCRIPT_PK[] = {
        0x00, 0x14, 0x51, 0x71, 0x89, 0xc0, 0xd5, 0x7b,
        0xa1, 0xdd, 0xd3, 0xf9, 0x81, 0x92, 0x6a, 0xbb,
        0x4b, 0x5e, 0xd0, 0x2a, 0x28, 0x07,
    };

    ret = ptarm_tx_add_vout_addr(&tx, (uint64_t)0x123456789abcdef0, WADDR);
    ASSERT_TRUE(ret);
    ptarm_vout_t *vout = &tx.vout[0];
    ASSERT_EQ((uint64_t)0x123456789abcdef0, vout->value);
    ASSERT_EQ(sizeof(SCRIPT_PK), vout->script.len);
    ASSERT_EQ(0, memcmp(SCRIPT_PK, vout->script.buf, sizeof(SCRIPT_PK)));

    ptarm_tx_free(&tx);
}

TEST_F(tx_native, add_vout_addr_p2wsh)
{
    bool ret;
    ptarm_tx_t tx;
    ptarm_tx_init(&tx);

    const char WADDR[] = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
    const uint8_t SCRIPT_PK[] = {
        0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5,
        0x16, 0x68, 0x04, 0xbd, 0x19, 0x20, 0x33, 0x56,
        0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d,
        0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90,
        0x32, 0x62,
    };

    ret = ptarm_tx_add_vout_addr(&tx, (uint64_t)0x123456789abcdef0, WADDR);
    ASSERT_TRUE(ret);

    ptarm_vout_t *vout = &tx.vout[0];
    ASSERT_EQ((uint64_t)0x123456789abcdef0, vout->value);
    ASSERT_EQ(0, memcmp(SCRIPT_PK, vout->script.buf, sizeof(SCRIPT_PK)));
    ASSERT_EQ(sizeof(SCRIPT_PK), vout->script.len);

    ptarm_tx_free(&tx);
}


TEST_F(tx_native, addr2spk_p2wpkh)
{
    bool ret;
    utl_buf_t spk;

    const char WADDR[] = "tb1q29ccnsx40wsam5lesxfx4w6ttmgz52q8qrpgla";
    const uint8_t SCRIPT_PK[] = {
        0x00, 0x14, 0x51, 0x71, 0x89, 0xc0, 0xd5, 0x7b,
        0xa1, 0xdd, 0xd3, 0xf9, 0x81, 0x92, 0x6a, 0xbb,
        0x4b, 0x5e, 0xd0, 0x2a, 0x28, 0x07,
    };

    ret = ptarm_keys_addr2spk(&spk, WADDR);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SCRIPT_PK, spk.buf, sizeof(SCRIPT_PK)));
    ASSERT_EQ(sizeof(SCRIPT_PK), spk.len);

    utl_buf_free(&spk);
}


TEST_F(tx_native, addr2spk_p2wsh)
{
    bool ret;
    utl_buf_t spk;

    const char WADDR[] = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
    const uint8_t SCRIPT_PK[] = {
        0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5,
        0x16, 0x68, 0x04, 0xbd, 0x19, 0x20, 0x33, 0x56,
        0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d,
        0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90,
        0x32, 0x62,
    };

    ret = ptarm_keys_addr2spk(&spk, WADDR);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SCRIPT_PK, spk.buf, sizeof(SCRIPT_PK)));
    ASSERT_EQ(sizeof(SCRIPT_PK), spk.len);

    utl_buf_free(&spk);
}
