////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class tx_native: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
        ucoin_init(UCOIN_TESTNET, true);
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
/*
    自分で計算した値を使う
TEST_F(tx_native, testdata)
{
    bool ret;
    const uint8_t PUB[] = {
        0x03, 0xbe, 0xce, 0xc4, 0x1f, 0x68, 0xd7, 0x7f,
        0xde, 0x9e, 0x97, 0x2c, 0x79, 0xaa, 0x0e, 0x6e,
        0x4e, 0x81, 0x8b, 0xd3, 0x04, 0x62, 0x76, 0x96,
        0x9e, 0x79, 0x37, 0x4e, 0xc0, 0x56, 0x1b, 0xa4,
        0x59,
    };
    const uint8_t PKH[] = {
        0xad, 0x3d, 0xc2, 0xf5, 0x22, 0x96, 0xf9, 0x3c,
        0x78, 0x98, 0xeb, 0x63, 0x8b, 0x0d, 0x74, 0xf2,
        0x7d, 0x79, 0xef, 0xc3,
    };
    const char WADDR[] = "QWzDXgBcTiiDaG4LYcjUkj3p9WhVtzt5WhLr";

    uint8_t pkh[UCOIN_SZ_PUBKEYHASH];
    ucoin_util_hash160(pkh, PUB, UCOIN_SZ_PUBKEY);
    printf("pkh= ");
    DumpBin(pkh, sizeof(pkh));
    ASSERT_EQ(0, memcmp(PKH, pkh, sizeof(PKH)));

    char waddr[UCOIN_SZ_WPKHADDR];
    ret = ucoin_keys_pub2p2wpkh(waddr, PUB);
    printf("waddr= %s\n", waddr);
    ASSERT_TRUE(ret);
    ASSERT_STREQ(WADDR, waddr);
}
*/

////////////////////////////////////////////////////////////////////////

TEST_F(tx_native, add_vout_addr)
{
    bool ret;
    ucoin_tx_t tx;
    ucoin_tx_init(&tx);

    const char WADDR[] = "QWzDXgBcTiiDaG4LYcjUkj3p9WhVtzt5WhLr";
    const uint8_t SCRIPT_PK[] = {
        0x00, 0x14,
        0xad, 0x3d, 0xc2, 0xf5, 0x22, 0x96, 0xf9, 0x3c,
        0x78, 0x98, 0xeb, 0x63, 0x8b, 0x0d, 0x74, 0xf2,
        0x7d, 0x79, 0xef, 0xc3,
    };

    ret = ucoin_tx_add_vout_addr(&tx, (uint64_t)0x123456789abcdef0, WADDR);
    ASSERT_TRUE(ret);

    ucoin_vout_t *vout = &tx.vout[0];
    ASSERT_EQ((uint64_t)0x123456789abcdef0, vout->value);
    ASSERT_EQ(0, memcmp(SCRIPT_PK, vout->script.buf, sizeof(SCRIPT_PK)));
    ASSERT_EQ(sizeof(SCRIPT_PK), vout->script.len);

    ucoin_tx_free(&tx);
}


TEST_F(tx_native, addr2spk)
{
    bool ret;
    ucoin_buf_t spk;

    const char WADDR[] = "QWzDXgBcTiiDaG4LYcjUkj3p9WhVtzt5WhLr";
    const uint8_t SCRIPT_PK[] = {
        0x00, 0x14,
        0xad, 0x3d, 0xc2, 0xf5, 0x22, 0x96, 0xf9, 0x3c,
        0x78, 0x98, 0xeb, 0x63, 0x8b, 0x0d, 0x74, 0xf2,
        0x7d, 0x79, 0xef, 0xc3,
    };

    ret = ucoin_keys_addr2spk(&spk, WADDR);
    ASSERT_TRUE(ret);
    ASSERT_EQ(0, memcmp(SCRIPT_PK, spk.buf, sizeof(SCRIPT_PK)));
    ASSERT_EQ(sizeof(SCRIPT_PK), spk.len);

    ucoin_buf_free(&spk);
}
