////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class time: public testing::Test {
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

TEST_F(time, time)
{
    utl_time_time();
}

TEST_F(time, str_time)
{
    char str[UTL_SZ_TIME_FMT_STR + 1] = {0};
    const char *ret = utl_time_str_time(str);
    ASSERT_EQ(str, ret);
}

TEST_F(time, fmt)
{
    char str[UTL_SZ_TIME_FMT_STR + 1] = {0};
    const char *result_str = "2018-12-18T07:42:35Z";
    time_t t = 1545118955;
    const char *ret = utl_time_fmt(str, t);
    ASSERT_EQ(0, strcmp(str, result_str));
    ASSERT_EQ(str, ret);
}
