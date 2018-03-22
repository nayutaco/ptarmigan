////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class keys_native: public testing::Test {
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
