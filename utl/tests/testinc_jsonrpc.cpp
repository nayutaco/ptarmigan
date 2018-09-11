////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class jsonrpc: public testing::Test {
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

TEST_F(jsonrpc, create_request)
{
    utl_jsonrpc_param_t non_string_params[] = {
        {"method0", 0},
        {"method1", 0},
        {"method1", 1},
        {"method2", 1},
        {"method2", 2},
        {NULL, 0}, //watchdog
    };

    const char *method = "method2";

    const char *paramv[] = {
        "param0", //string
        "param1", //non-string
        "param2", //non-string
        "param3", //string
    };

    utl_str_t body;
    utl_str_init(&body);
    ASSERT_TRUE(utl_jsonrpc_create_request(&body, method, paramv, ARRAY_SIZE(paramv), non_string_params));
    const char *p = utl_str_get(&body);
    ASSERT_NE(p, NULL);
    ASSERT_STREQ(p, ""
        "{"
        "\"method\":\"method2\","
        "\"params\":[\"param0\",param1,param2,\"param3\"]"
        "}"
    );
    utl_str_free(&body);
}
