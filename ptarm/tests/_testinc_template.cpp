////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class xxx: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
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

TEST_F(xxx, init)
{
    ASSERT_EQ(0, 0);
    ASSERT_TRUE(NULL != buf.buf);
}
