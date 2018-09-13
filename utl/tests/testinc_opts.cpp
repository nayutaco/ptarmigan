////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class opts: public testing::Test {
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

/*typedef struct {
    const char      *name;          ///< name(required, but set NULL in the watchdog entry)
    const char      *arg;           ///< arg(optional, if set, display name=<arg>)
    const char      *param_default; ///< param_default(optional)
    const char      *help;          ///< help(optional)
    char            *param;         ///< param
    bool            is_set;         ///< is_set
} utl_opt_t;*/

TEST_F(opts, parse0)
{
    // argv[0]: program -- skip
    // argv[1]: -option0
    // argv[2]: -option1

    utl_opt_t opts[] = {
        {"-name0", "arg0", "param_default0", "help0", NULL, false},
        {"-name1", "arg1", "param_default1", "help1", NULL, false},
        {"-name2", "arg2", "param_default2", "help2", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    utl_opts_free(opts);
}

TEST_F(opts, parse1)
{
    // argv[0]: program -- skip
    // argv[1]: command
    // argv[2]: -option0
    // argv[3]: -option1

    utl_opt_t opts[] = {
        {"-name0", "arg0", "param_default0", "help0", NULL, false},
        {"-name1", "arg1", "param_default1", "help1", NULL, false},
        {"-name2", "arg2", "param_default2", "help2", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "command",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    utl_opts_free(opts);
}

TEST_F(opts, parse2)
{
    // argv[0]: program -- skip
    // argv[1]: command
    // argv[2]: -option0
    // argv[3]: -option1
    // argv[4]: command_param0 -- skip
    // argv[5]: command_param1 -- skip

    utl_opt_t opts[] = {
        {"-name0", "arg0", "param_default0", "help0", NULL, false},
        {"-name1", "arg1", "param_default1", "help1", NULL, false},
        {"-name2", "arg2", "param_default2", "help2", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "command",
        "-name0=arg0",
        "-name1=arg1",
        "command_param0",
        "command_param1",
    };

    ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    utl_opts_free(opts);
}

TEST_F(opts, parse_invalid0)
{
    utl_opt_t opts[] = {
        //arg == NULL && param_default == "param_default0" -> invalid
        {"-name0", NULL, "param_default0", "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
}

TEST_F(opts, parse_invalid1)
{
    utl_opt_t opts[] = {
        //is_set == true -> invalid
        {"-name0", "arg0", "param_default0", "help0", NULL, true},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
}

TEST_F(opts, parse_invalid2)
{
    char param0[] = {'p', 'a', 'r', 'a', 'm', '0', '\0'};
    utl_opt_t opts[] = {
        //param == "param0" -> invalid
        {"-name0", "arg0", "param_default0", "help0", param0, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
}

TEST_F(opts, option_with_no_arg)
{
    utl_opt_t opts[] = {
        {"-name0", NULL, NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            //empty
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_FALSE(utl_opts_is_set(opts, "-name0"));
        ASSERT_EQ(utl_opts_get_string(opts, "-name0"), NULL);
        utl_opts_free(opts);
    }
    {
        const char *argv[] = {
            "program",
            "-name0",
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_EQ(utl_opts_get_string(opts, "-name0"), NULL);
        utl_opts_free(opts);
    }
}

TEST_F(opts, option_with_no_arg_invalid)
{
    utl_opt_t opts[] = {
        {"-name0", NULL, NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0=param0", //invalid
        };
        ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    }
    {
        const char *argv[] = {
            "program",
            "-name1", //invalid
        };
        ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    }
}

TEST_F(opts, option_with_arg)
{
    utl_opt_t opts[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            //empty
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_FALSE(utl_opts_is_set(opts, "-name0"));
        ASSERT_EQ(utl_opts_get_string(opts, "-name0"), NULL);
        utl_opts_free(opts);
    }
    {
        const char *argv[] = {
            "program",
            "-name0=param0",
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "param0");
        utl_opts_free(opts);
    }
}

TEST_F(opts, option_with_arg_invalid)
{
    utl_opt_t opts[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0", //invalid
        };
        ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    }
    {
        const char *argv[] = {
            "program",
            "-name1=param1", //invalid
        };
        ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    }
}

TEST_F(opts, option_with_arg_and_param_default) {
    utl_opt_t opts[] = {
        {"-name0", "arg0", "param_default0", "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            //empty
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "param_default0");
        utl_opts_free(opts);
    }
    {
        const char *argv[] = {
            "program",
            "-name0=param0",
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "param0");
        utl_opts_free(opts);
    }
}

TEST_F(opts, option_with_arg_and_param_default_invalid)
{
    utl_opt_t opts[] = {
        {"-name0", "arg0", "param_default0", "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0", //invalid
        };
        ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    }
    {
        const char *argv[] = {
            "program",
            "-name1=param1", //invalid
        };
        ASSERT_FALSE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
    }
}

TEST_F(opts, arg_type)
{
    utl_opt_t opts[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0=1234567890"
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "1234567890");
        uint32_t n;
        ASSERT_TRUE(utl_opts_get_u32(opts, &n, "-name0"));
        ASSERT_EQ(n, 1234567890);
        utl_opts_free(opts);
    }
    {
        const char *argv[] = {
            "program",
            "-name0=12345"
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "12345");
        uint16_t n;
        ASSERT_TRUE(utl_opts_get_u16(opts, &n, "-name0"));
        ASSERT_EQ(n, 12345);
        utl_opts_free(opts);
    }
}

TEST_F(opts, arg_type_u32)
{
    utl_opt_t opts[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0=param0"
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "param0");
        uint32_t n;
        ASSERT_FALSE(utl_opts_get_u32(opts, &n, "-name0"));
        utl_opts_free(opts);
    }
    {
        const char *argv[] = {
            "program",
            "-name0=param0"
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "param0");
        uint16_t n;
        ASSERT_FALSE(utl_opts_get_u16(opts, &n, "-name0"));
        utl_opts_free(opts);
    }
    {
        const char *argv[] = {
            "program",
            "-name0=123456"
        };
        ASSERT_TRUE(utl_opts_parse(opts, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_opts_is_set(opts, "-name0"));
        ASSERT_STREQ(utl_opts_get_string(opts, "-name0"), "123456");
        uint16_t n;
        ASSERT_FALSE(utl_opts_get_u16(opts, &n, "-name0"));
        utl_opts_free(opts);
    }
}

TEST_F(opts, help_messages)
{
    utl_opt_t opts[] = {
        {"-name0", NULL, NULL, "help0", NULL, false},
        {"-name1", "arg1", NULL, "help1", NULL, false},
        {"-name2", "arg2", "param_default2", "help2", NULL, false},
        {"-name3", NULL, NULL, NULL, NULL, false},
        {"-name4", "arg4", NULL, NULL, NULL, false},
        {"-name5", "arg5", "param_default5", NULL, NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    utl_str_t x;
    utl_str_init(&x);
    ASSERT_TRUE(utl_opts_get_help_messages(opts, &x));
    const char *p = utl_str_get(&x);
    ASSERT_NE(p, NULL);
    ASSERT_STREQ(p,
        "  -name0\n"
        "       help0\n"
        "\n"
        "  -name1=<arg1>\n"
        "       help1\n"
        "\n"
        "  -name2=<arg2>\n"
        "       help2 (default: param_default2)\n"
        "\n"
        "  -name3\n"
        "\n"
        "  -name4=<arg4>\n"
        "\n"
        "  -name5=<arg5>\n"
        "       (default: param_default5)\n"
        "\n"
    );
    utl_str_free(&x);
    utl_opts_free(opts);
}
