////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class extendedkey: public testing::Test {
protected:
    virtual void SetUp() {
        //RESET_FAKE(external_function)
        utl_log_init_stdout();
        utl_dbg_malloc_cnt_reset();
        btc_init(BTC_BLOCK_CHAIN_BTCMAIN, false);
    }

    virtual void TearDown() {
        ASSERT_EQ(0, utl_dbg_malloc_cnt());
        btc_term();
    }

public:
    static btc_extkey_t extkey;
    static btc_extkey_t extkey_prev;
    static uint8_t priv[BTC_SZ_PRIVKEY];
    static uint8_t pub[BTC_SZ_PUBKEY];
    static uint8_t pub_prev[BTC_SZ_PUBKEY];

public:
    static void DumpBin(const uint8_t *pData, uint16_t Len)
    {
        for (uint16_t lp = 0; lp < Len; lp++) {
            printf("%02x", pData[lp]);
        }
        printf("\n");
    }
};

btc_extkey_t extendedkey::extkey;
btc_extkey_t extendedkey::extkey_prev;
uint8_t extendedkey::priv[BTC_SZ_PRIVKEY];
uint8_t extendedkey::pub[BTC_SZ_PUBKEY];
uint8_t extendedkey::pub_prev[BTC_SZ_PUBKEY];


////////////////////////////////////////////////////////////////////////

TEST_F(extendedkey, chain_m)
{
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
    const uint8_t SEED[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const char XPRIV0[] = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const char XPUB0[] = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    bool b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, 0, 0, NULL, SEED, sizeof(SEED));
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey);
    memcpy(priv, extkey.key, BTC_SZ_PRIVKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPRIV0, xaddr);
    btc_extkey_print(&extkey);

    extkey.type = BTC_EXTKEY_PUB;
    btc_keys_priv2pub(extkey.key, extkey.key);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);
    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0, xaddr);
    btc_extkey_print(&extkey);


    btc_extkey_t extkey2;

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPRIV0);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PRIV, extkey2.type);
    ASSERT_EQ(0, extkey2.depth);
    ASSERT_EQ(0, extkey2.child_number);
    ASSERT_EQ(0, memcmp(priv, extkey2.key, sizeof(priv)));

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPUB0);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PUB, extkey2.type);
    ASSERT_EQ(0, extkey2.depth);
    ASSERT_EQ(0, extkey2.child_number);
    ASSERT_EQ(0, memcmp(pub, extkey2.key, sizeof(pub)));
}

TEST_F(extendedkey, chain_m_0H)
{
    const char XPRIV0H[] = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
    const char XPUB0H[] = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    //pub用
    memcpy(&extkey_prev, &extkey, sizeof(extkey));
    memcpy(pub_prev, pub, sizeof(pub));

    bool b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, 1, BTC_EXTKEY_HARDENED | 0, priv, NULL, 0);
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey);
    memcpy(priv, extkey.key, BTC_SZ_PRIVKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPRIV0H, xaddr);
    btc_extkey_print(&extkey);

    extkey.type = BTC_EXTKEY_PUB;
    btc_keys_priv2pub(extkey.key, extkey.key);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);
    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H, xaddr);
    btc_extkey_print(&extkey);


    btc_extkey_t extkey2;

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPRIV0H);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PRIV, extkey2.type);
    ASSERT_EQ(1, extkey2.depth);
    ASSERT_EQ(0, memcmp(priv, extkey2.key, sizeof(priv)));

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPUB0H);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PUB, extkey2.type);
    ASSERT_EQ(1, extkey2.depth);
    ASSERT_EQ(0, memcmp(pub, extkey2.key, sizeof(pub)));
}


TEST_F(extendedkey, chain_m_0Hpub)
{
    //const char XPUB0H[] = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";

    //hardenedからchild pubkeyはNG
    memcpy(extkey_prev.key, pub_prev, sizeof(pub_prev));
    bool b = btc_extkey_generate(&extkey_prev, BTC_EXTKEY_PUB, 1, BTC_EXTKEY_HARDENED | 0, pub_prev, NULL, 0);
    ASSERT_FALSE(b);
}


TEST_F(extendedkey, chain_m_0H_1)
{
    const char XPRIV0H1[] = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
    const char XPUB0H1[] = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    //pub用
    memcpy(&extkey_prev, &extkey, sizeof(extkey));
    memcpy(pub_prev, pub, sizeof(pub));

    bool b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, 2, 1, priv, NULL, 0);
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey);
    memcpy(priv, extkey.key, BTC_SZ_PRIVKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPRIV0H1, xaddr);
    btc_extkey_print(&extkey);

    extkey.type = BTC_EXTKEY_PUB;
    btc_keys_priv2pub(extkey.key, extkey.key);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);
    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H1, xaddr);
    btc_extkey_print(&extkey);


    btc_extkey_t extkey2;

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPRIV0H1);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PRIV, extkey2.type);
    ASSERT_EQ(2, extkey2.depth);
    ASSERT_EQ(0, memcmp(priv, extkey2.key, sizeof(priv)));

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPUB0H1);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PUB, extkey2.type);
    ASSERT_EQ(2, extkey2.depth);
    ASSERT_EQ(0, memcmp(pub, extkey2.key, sizeof(pub)));
}


TEST_F(extendedkey, chain_m_0H_1pub)
{
    const char XPUB0H1[] = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    bool b = btc_extkey_generate(&extkey_prev, BTC_EXTKEY_PUB, 2, 1, pub_prev, NULL, 0);
    ASSERT_TRUE(b);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey_prev);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H1, xaddr);
}


TEST_F(extendedkey, chain_m_0H_1_2H)
{
    const char XPRIV0H12H[] = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
    const char XPUB0H12H[] = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    //pub用
    memcpy(&extkey_prev, &extkey, sizeof(extkey));
    memcpy(pub_prev, pub, sizeof(pub));

    bool b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, 3, BTC_EXTKEY_HARDENED | 2, priv, NULL, 0);
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey);
    memcpy(priv, extkey.key, BTC_SZ_PRIVKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPRIV0H12H, xaddr);
    btc_extkey_print(&extkey);

    extkey.type = BTC_EXTKEY_PUB;
    btc_keys_priv2pub(extkey.key, extkey.key);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);
    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H12H, xaddr);
    btc_extkey_print(&extkey);


    btc_extkey_t extkey2;

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPRIV0H12H);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PRIV, extkey2.type);
    ASSERT_EQ(3, extkey2.depth);
    ASSERT_EQ(0, memcmp(priv, extkey2.key, sizeof(priv)));

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPUB0H12H);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PUB, extkey2.type);
    ASSERT_EQ(3, extkey2.depth);
    ASSERT_EQ(0, memcmp(pub, extkey2.key, sizeof(pub)));
}


TEST_F(extendedkey, chain_m_0H_1_2Hpub)
{
    //const char XPUB0H12H[] = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";

    memcpy(extkey_prev.key, pub_prev, sizeof(pub_prev));
    bool b = btc_extkey_generate(&extkey_prev, BTC_EXTKEY_PUB, 3, BTC_EXTKEY_HARDENED | 2, pub_prev, NULL, 0);
    ASSERT_FALSE(b);
}


TEST_F(extendedkey, chain_m_0H_1_2H_2)
{
    const char XPRIV0H12H2[] = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
    const char XPUB0H12H2[] = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    //pub用
    memcpy(&extkey_prev, &extkey, sizeof(extkey));
    memcpy(pub_prev, pub, sizeof(pub));

    bool b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, 4, 2, priv, NULL, 0);
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey);
    memcpy(priv, extkey.key, BTC_SZ_PRIVKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPRIV0H12H2, xaddr);
    btc_extkey_print(&extkey);

    extkey.type = BTC_EXTKEY_PUB;
    btc_keys_priv2pub(extkey.key, extkey.key);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);
    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H12H2, xaddr);
    btc_extkey_print(&extkey);


    btc_extkey_t extkey2;

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPRIV0H12H2);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PRIV, extkey2.type);
    ASSERT_EQ(4, extkey2.depth);
    ASSERT_EQ(0, memcmp(priv, extkey2.key, sizeof(priv)));

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPUB0H12H2);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PUB, extkey2.type);
    ASSERT_EQ(4, extkey2.depth);
    ASSERT_EQ(0, memcmp(pub, extkey2.key, sizeof(pub)));
}


TEST_F(extendedkey, chain_m_0H_1_2H_2pub)
{
    const char XPUB0H12H2[] = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    bool b = btc_extkey_generate(&extkey_prev, BTC_EXTKEY_PUB, 4, 2, pub_prev, NULL, 0);
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey_prev);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey_prev);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H12H2, xaddr);
    btc_extkey_print(&extkey_prev);
}


TEST_F(extendedkey, chain_m_0H_1_2H_2_1)
{
    const char XPRIV0H12H21[] = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";
    const char XPUB0H12H21[] = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    //pub用
    memcpy(&extkey_prev, &extkey, sizeof(extkey));
    memcpy(pub_prev, pub, sizeof(pub));

    bool b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, 5, 1000000000, priv, NULL, 0);
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey);
    memcpy(priv, extkey.key, BTC_SZ_PRIVKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPRIV0H12H21, xaddr);
    btc_extkey_print(&extkey);

    extkey.type = BTC_EXTKEY_PUB;
    btc_keys_priv2pub(extkey.key, extkey.key);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);
    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H12H21, xaddr);
    btc_extkey_print(&extkey);


    btc_extkey_t extkey2;

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPRIV0H12H21);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PRIV, extkey2.type);
    ASSERT_EQ(5, extkey2.depth);
    ASSERT_EQ(0, memcmp(priv, extkey2.key, sizeof(priv)));

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPUB0H12H21);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PUB, extkey2.type);
    ASSERT_EQ(5, extkey2.depth);
    ASSERT_EQ(0, memcmp(pub, extkey2.key, sizeof(pub)));
}


TEST_F(extendedkey, chain_m_0H_1_2H_2_1pub)
{
    const char XPUB0H12H21[] = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    bool b = btc_extkey_generate(&extkey_prev, BTC_EXTKEY_PUB, 5, 1000000000, pub_prev, NULL, 0);
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey_prev);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey_prev);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0H12H21, xaddr);
    btc_extkey_print(&extkey_prev);
}


//もう一度masterから初めて、前の値を引きずっていないか確認
TEST_F(extendedkey, chain_m_master2)
{
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
    const uint8_t SEED[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const char XPRIV0[] = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const char XPUB0[] = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

    uint8_t buf_extkey[BTC_SZ_EXTKEY];
    char xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];

    bool b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, 0, 0, NULL, SEED, sizeof(SEED));
    ASSERT_TRUE(b);
    btc_extkey_print(&extkey);
    memcpy(priv, extkey.key, BTC_SZ_PRIVKEY);

    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPRIV0, xaddr);
    btc_extkey_print(&extkey);

    extkey.type = BTC_EXTKEY_PUB;
    btc_keys_priv2pub(extkey.key, extkey.key);
    memcpy(pub, extkey.key, BTC_SZ_PUBKEY);
    b = btc_extkey_create_data(buf_extkey, xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XPUB0, xaddr);
    btc_extkey_print(&extkey);


    btc_extkey_t extkey2;

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPRIV0);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PRIV, extkey2.type);
    ASSERT_EQ(0, extkey2.depth);
    ASSERT_EQ(0, extkey2.child_number);
    ASSERT_EQ(0, memcmp(priv, extkey2.key, sizeof(priv)));

    memset(&extkey2, 0, sizeof(extkey2));
    b = btc_extkey_read_addr(&extkey2, XPUB0);
    ASSERT_TRUE(b);
    ASSERT_EQ(BTC_EXTKEY_PUB, extkey2.type);
    ASSERT_EQ(0, extkey2.depth);
    ASSERT_EQ(0, extkey2.child_number);
    ASSERT_EQ(0, memcmp(pub, extkey2.key, sizeof(pub)));
}


TEST_F(extendedkey, read_addr_fail)
{
    bool b;

    //長い
    const char XPUB0H12H21_LONG[] = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHyaa";

    b = btc_extkey_read_addr(&extkey, XPUB0H12H21_LONG);
    ASSERT_FALSE(b);
}


TEST_F(extendedkey, read_fail_len)
{
    bool b;
    uint8_t buf_extkey[BTC_SZ_EXTKEY];

    b = btc_extkey_create_data(buf_extkey, NULL, &extkey);
    ASSERT_TRUE(b);

    //短い
    b = btc_extkey_read(&extkey, buf_extkey, sizeof(buf_extkey) - 1);
    ASSERT_FALSE(b);
}


TEST_F(extendedkey, read_fail_data)
{
    bool b;
    uint8_t buf_extkey[BTC_SZ_EXTKEY];

    b = btc_extkey_create_data(buf_extkey, NULL, &extkey);
    ASSERT_TRUE(b);

    buf_extkey[3] = ~buf_extkey[3]; //書き換え
    b = btc_extkey_read(&extkey, buf_extkey, sizeof(buf_extkey));
    ASSERT_FALSE(b);
}


TEST_F(extendedkey, read_fail_init)
{
    bool b;
    uint8_t buf_extkey[BTC_SZ_EXTKEY];

    b = btc_extkey_create_data(buf_extkey, NULL, &extkey);
    ASSERT_TRUE(b);

    mInitialized = false;
    b = btc_extkey_read(&extkey, buf_extkey, sizeof(buf_extkey));
    ASSERT_FALSE(b);
}


TEST_F(extendedkey, create_fail)
{
    bool b;
    uint8_t buf_extkey[BTC_SZ_EXTKEY];

    mInitialized = false;
    b = btc_extkey_create_data(buf_extkey, NULL, &extkey);
    ASSERT_FALSE(b);
}


// https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki#test-vectors
TEST_F(extendedkey, bip49)
{
    const char MASTERSEED[] = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd";
    const char XADDR_ACC0[] = "tprv8gRrNu65W2Msef2BdBSUgFdRTGzC8EwVXnV7UGS3faeXtuMVtGfEdidVeGbThs4ELEoayCAzZQ4uUji9DUiAs7erdVskqju7hrBcDvDsdbY";
    const uint8_t ACC0IDX0[] = {
        0xc9, 0xbd, 0xb4, 0x9c, 0xfb, 0xae, 0xdc, 0xa2,
        0x1c, 0x4b, 0x1f, 0x3a, 0x78, 0x03, 0xc3, 0x46,
        0x36, 0xb1, 0xd7, 0xdc, 0x55, 0xa7, 0x17, 0x13,
        0x24, 0x43, 0xfc, 0x3f, 0x4c, 0x58, 0x67, 0xe8,
    };
    const char B58_ACC0IDX0[] = "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2";

    bool b;
    uint8_t extkey_data[BTC_SZ_EXTKEY];
    char extkey_xaddr[BTC_SZ_EXTKEY_ADDR_MAX + 1];
    btc_extkey_t extkey;

    btc_term();
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, false);

    b = btc_extkey_read_addr(&extkey, MASTERSEED);
    ASSERT_TRUE(b);

    b = btc_extkey_bip49_prepare(&extkey, 0, BTC_EXTKEY_BIP_SKIP);
    ASSERT_TRUE(b);
    btc_extkey_create_data(extkey_data, extkey_xaddr, &extkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(XADDR_ACC0, extkey_xaddr);

    b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, extkey.depth + 1, 0, extkey.key, NULL, 0);
    ASSERT_TRUE(b);
    b = btc_extkey_generate(&extkey, BTC_EXTKEY_PRIV, extkey.depth + 1, 0, extkey.key, NULL, 0);
    ASSERT_TRUE(b);
    ASSERT_TRUE(0 == memcmp(ACC0IDX0, extkey.key, BTC_SZ_PRIVKEY));

    //prepareも使っておく
    memset(&extkey, 0, sizeof(extkey));
    btc_extkey_read_addr(&extkey, MASTERSEED);
    b = btc_extkey_bip49_prepare(&extkey, 0, 0);
    ASSERT_TRUE(b);
    btc_extkey_t akey;
    b = btc_extkey_bip_generate(&akey, &extkey, 0);
    ASSERT_TRUE(0 == memcmp(ACC0IDX0, akey.key, BTC_SZ_PRIVKEY));

    uint8_t pubkey[BTC_SZ_PUBKEY];
    btc_keys_priv2pub(pubkey, akey.key);
    char addr[BTC_SZ_ADDR_STR_MAX + 1];
    b = btc_keys_pub2p2wpkh(addr, pubkey);
    ASSERT_TRUE(b);
    ASSERT_STREQ(B58_ACC0IDX0, addr);
}
