////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class args: public testing::Test {
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
} utl_arginfo_t;*/

TEST_F(args, parse0)
{
    // argv[0]: program -- skip
    // argv[1]: -option0
    // argv[2]: -option1

    utl_arginfo_t arginfo[] = {
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

    ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    utl_args_free(arginfo);
}

TEST_F(args, parse1)
{
    // argv[0]: program -- skip
    // argv[1]: command
    // argv[2]: -option0
    // argv[3]: -option1

    utl_arginfo_t arginfo[] = {
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

    ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    utl_args_free(arginfo);
}

TEST_F(args, parse2)
{
    // argv[0]: program -- skip
    // argv[1]: command
    // argv[2]: -option0
    // argv[3]: -option1
    // argv[4]: command_param0 -- skip
    // argv[5]: command_param1 -- skip

    utl_arginfo_t arginfo[] = {
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

    ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    utl_args_free(arginfo);
}

TEST_F(args, parse_invalid0)
{
    utl_arginfo_t arginfo[] = {
        //arg == NULL && param_default == "param_default0" -> invalid
        {"-name0", NULL, "param_default0", "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
}

TEST_F(args, parse_invalid1)
{
    utl_arginfo_t arginfo[] = {
        //is_set == true -> invalid
        {"-name0", "arg0", "param_default0", "help0", NULL, true},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
}

TEST_F(args, parse_invalid2)
{
    char param0[] = {'p', 'a', 'r', 'a', 'm', '0', '\0'};
    utl_arginfo_t arginfo[] = {
        //param == "param0" -> invalid
        {"-name0", "arg0", "param_default0", "help0", param0, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };

    const char *argv[] = {
        "program",
        "-name0=arg0",
        "-name1=arg1",
    };

    ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
}

TEST_F(args, option_with_no_arg)
{
    utl_arginfo_t arginfo[] = {
        {"-name0", NULL, NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            //empty
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_FALSE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_EQ(utl_args_get_string(arginfo, "-name0"), NULL);
        utl_args_free(arginfo);
    }
    {
        const char *argv[] = {
            "program",
            "-name0",
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_EQ(utl_args_get_string(arginfo, "-name0"), NULL);
        utl_args_free(arginfo);
    }
}

TEST_F(args, option_with_no_arg_invalid)
{
    utl_arginfo_t arginfo[] = {
        {"-name0", NULL, NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0=param0", //invalid
        };
        ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    }
    {
        const char *argv[] = {
            "program",
            "-name1", //invalid
        };
        ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    }
}

TEST_F(args, option_with_arg)
{
    utl_arginfo_t arginfo[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            //empty
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_FALSE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_EQ(utl_args_get_string(arginfo, "-name0"), NULL);
        utl_args_free(arginfo);
    }
    {
        const char *argv[] = {
            "program",
            "-name0=param0",
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_STREQ(utl_args_get_string(arginfo, "-name0"), "param0");
        utl_args_free(arginfo);
    }
}

TEST_F(args, option_with_arg_invalid)
{
    utl_arginfo_t arginfo[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0", //invalid
        };
        ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    }
    {
        const char *argv[] = {
            "program",
            "-name1=param1", //invalid
        };
        ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    }
}

TEST_F(args, option_with_arg_and_param_default) {
    utl_arginfo_t arginfo[] = {
        {"-name0", "arg0", "param_default0", "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            //empty
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_STREQ(utl_args_get_string(arginfo, "-name0"), "param_default0");
        utl_args_free(arginfo);
    }
    {
        const char *argv[] = {
            "program",
            "-name0=param0",
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_STREQ(utl_args_get_string(arginfo, "-name0"), "param0");
        utl_args_free(arginfo);
    }
}

TEST_F(args, option_with_arg_and_param_default_invalid)
{
    utl_arginfo_t arginfo[] = {
        {"-name0", "arg0", "param_default0", "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0", //invalid
        };
        ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    }
    {
        const char *argv[] = {
            "program",
            "-name1=param1", //invalid
        };
        ASSERT_FALSE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
    }
}

TEST_F(args, arg_type_u32)
{
    utl_arginfo_t arginfo[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0=1234567890"
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_STREQ(utl_args_get_string(arginfo, "-name0"), "1234567890");
        uint32_t n;
        ASSERT_TRUE(utl_args_get_u32(arginfo, &n, "-name0"));
        ASSERT_EQ(n, 1234567890);
        utl_args_free(arginfo);
    }
}

TEST_F(args, arg_type_u32_invalid)
{
    utl_arginfo_t arginfo[] = {
        {"-name0", "arg0", NULL, "help0", NULL, false},
        {NULL, NULL, NULL, NULL, NULL, false}, //watchdog
    };
    {
        const char *argv[] = {
            "program",
            "-name0=param0"
        };
        ASSERT_TRUE(utl_args_parse(arginfo, ARRAY_SIZE(argv), argv));
        ASSERT_TRUE(utl_args_is_set(arginfo, "-name0"));
        ASSERT_STREQ(utl_args_get_string(arginfo, "-name0"), "param0");
        uint32_t n;
        ASSERT_FALSE(utl_args_get_u32(arginfo, &n, "-name0"));
        utl_args_free(arginfo);
    }
}

TEST_F(args, help_messages)
{
    utl_arginfo_t arginfo[] = {
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
    ASSERT_TRUE(utl_args_get_help_messages(arginfo, &x));
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
    utl_args_free(arginfo);
}
