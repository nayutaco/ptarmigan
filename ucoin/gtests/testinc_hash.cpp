////////////////////////////////////////////////////////////////////////
//FAKE関数

////////////////////////////////////////////////////////////////////////

class hash: public testing::Test {
    void SetUp() {
        //RESET_FAKE(external_function)
    }

    void TearDown() {
    }
public:
    static const uint8_t* data(size_t &sz) {
        static const uint8_t DATA[] = {
            0x01, 0x00, 0x00, 0x00, 0x01, 0x33, 0x69, 0xbf, 
            0xb4, 0xb5, 0x62, 0xe9, 0x10, 0xb0, 0xee, 0xb9, 
            0x6e, 0x8f, 0x1d, 0x0f, 0xfb, 0x97, 0xec, 0x2d, 
            0xe4, 0x8a, 0x3c, 0x1e, 0x41, 0x51, 0xac, 0xa6, 
            0xda, 0xf0, 0x6c, 0x84, 0x89, 0x00, 0x00, 0x00, 
            0x00, 0x69, 0x52, 0x21, 0x03, 0x24, 0x0b, 0xc7, 
            0x9a, 0x64, 0x79, 0x85, 0x1a, 0xbe, 0x77, 0x64, 
            0x65, 0x50, 0x0a, 0x9f, 0xf2, 0xf8, 0x80, 0x94, 
            0x0b, 0x22, 0x7b, 0xfc, 0xbc, 0xb6, 0xd4, 0x79, 
            0x88, 0x6a, 0x31, 0x8f, 0xa0, 0x21, 0x03, 0x92, 
            0x1b, 0x52, 0x4e, 0x16, 0xb8, 0x1c, 0x81, 0x3b, 
            0xaf, 0x06, 0x2a, 0x28, 0x44, 0xff, 0x68, 0x42, 
            0x07, 0x3c, 0xc0, 0xec, 0x60, 0x92, 0x31, 0xa0, 
            0xe3, 0x37, 0x00, 0xdd, 0x24, 0xb5, 0xf3, 0x21, 
            0x03, 0x29, 0xbd, 0x4a, 0x08, 0x25, 0x0b, 0x6a, 
            0xef, 0x97, 0x58, 0x1b, 0x36, 0x41, 0x2c, 0x9b, 
            0xe2, 0x8c, 0x84, 0xba, 0xb7, 0x7d, 0x7a, 0x51, 
            0x8a, 0x88, 0x00, 0x3a, 0x18, 0x0a, 0xfc, 0xfc, 
            0xdc, 0x53, 0xae, 0xff, 0xff, 0xff, 0xff, 0x01, 
            0x60, 0xae, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x19, 0x76, 0xa9, 0x14, 0xe7, 0xc1, 0x34, 0x5f, 
            0xc8, 0xf8, 0x7c, 0x68, 0x17, 0x0b, 0x3a, 0xa7, 
            0x98, 0xa9, 0x56, 0xc2, 0xfe, 0x6a, 0x9e, 0xff, 
            0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 
            0x00, 0x00, 
        };
        sz = sizeof(DATA);
        return DATA;
    }
};

////////////////////////////////////////////////////////////////////////

TEST_F(hash, hash160_null)
{
    const uint8_t HASH160[] = {
        0xb4, 0x72, 0xa2, 0x66, 0xd0, 0xbd, 0x89, 0xc1, 
        0x37, 0x06, 0xa4, 0x13, 0x2c, 0xcf, 0xb1, 0x6f, 
        0x7c, 0x3b, 0x9f, 0xcb, 
    };
    uint8_t hash[UCOIN_SZ_HASH160];
    ucoin_util_hash160(hash, NULL, 0);
    ASSERT_EQ(0, memcmp(HASH160, hash, sizeof(HASH160)));
}

TEST_F(hash, hash160_data)
{
    const uint8_t HASH160[] = {
        0x62, 0xe9, 0x4f, 0xfc, 0x41, 0xc6, 0x6f, 0x25, 
        0x05, 0x8c, 0xe2, 0x62, 0x1e, 0x26, 0xaf, 0x98, 
        0x20, 0xf0, 0x56, 0x54, 
    };
    uint8_t hash[UCOIN_SZ_HASH160];
    size_t sz;
    const uint8_t *pData = hash::data(sz);
    ucoin_util_hash160(hash, pData, sz);
    ASSERT_EQ(0, memcmp(HASH160, hash, sizeof(HASH160)));
}

TEST_F(hash, hash256_null)
{
    const uint8_t HASH256[] = {
       0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3, 
       0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc, 
       0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4, 
       0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56, 
    };
    uint8_t hash[UCOIN_SZ_HASH256];
    ucoin_util_hash256(hash, NULL, 0);
    ASSERT_EQ(0, memcmp(HASH256, hash, sizeof(HASH256)));
}

TEST_F(hash, hash256_data)
{
    const uint8_t HASH256[] = {
       0xc3, 0x00, 0x8f, 0x64, 0xac, 0x71, 0x05, 0x9c, 
       0xd3, 0x1f, 0xaf, 0x84, 0x9c, 0x02, 0x3c, 0xc5, 
       0xc9, 0xe7, 0x8d, 0x02, 0x88, 0x71, 0xc7, 0x31, 
       0x84, 0x45, 0x0d, 0x0f, 0xd3, 0x3f, 0x63, 0x04, 
    };
    uint8_t hash[UCOIN_SZ_HASH256];
    size_t sz;
    const uint8_t *pData = hash::data(sz);
    ucoin_util_hash256(hash, pData, sz);
    ASSERT_EQ(0, memcmp(HASH256, hash, sizeof(HASH256)));
}
