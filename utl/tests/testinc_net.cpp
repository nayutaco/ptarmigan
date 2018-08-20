////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class net: public testing::Test {
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

TEST_F(net, routable_ipv4_addr)
{
    typedef struct addrinfo {
        uint8_t addr[4];
        bool is_public;
    } addrinfo;

    const addrinfo addrinfos[] = {
        // ref. https://en.wikipedia.org/wiki/IPv4#Special-use_addresses

        // 0.0.0.0-0.255.255.255
        {{0, 0, 0, 0}, false}, // start
        {{0, 0, 0, 1}, false}, // start+1
        {{0, 255, 255, 254}, false}, // end-1
        {{0, 255, 255, 255}, false}, // end
        {{1, 0, 0, 0}, true}, // end+1
        {{1, 0, 0, 1}, true}, // end+2

        // 10.0.0.0-10.255.255.255
        {{9, 255, 255, 254}, true}, // start-2
        {{9, 255, 255, 255}, true}, // start-1
        {{10, 0, 0, 0}, false}, // start
        {{10, 0, 0, 1}, false}, // start+1
        {{10, 255, 255, 254}, false}, // end-1
        {{10, 255, 255, 255}, false}, // end
        {{11, 0, 0, 0}, true}, // end+1
        {{11, 0, 0, 1}, true}, // end+2

        // 100.64.0.0-100.127.255.255
        {{100, 63, 255, 254}, true}, // start-2
        {{100, 63, 255, 255}, true}, // start-1
        {{100, 64, 0, 0}, false}, // start
        {{100, 64, 0, 1}, false}, // start+1
        {{100, 127, 255, 254}, false}, // end-1
        {{100, 127, 255, 255}, false}, // end
        {{100, 128, 0, 0}, true}, // end+1
        {{100, 128, 0, 1}, true}, // end+2

        // 127.0.0.0-127.255.255.255
        {{126, 255, 255, 254}, true}, // start-2
        {{126, 255, 255, 255}, true}, // start-1
        {{127, 0, 0, 0}, false}, // start
        {{127, 0, 0, 1}, false}, // start+1
        {{127, 255, 255, 254}, false}, // end-1
        {{127, 255, 255, 255}, false}, // end
        {{128, 0, 0, 0}, true}, // end+1
        {{128, 0, 0, 1}, true}, // end+2

        // 169.254.0.0-169.254.255.255
        {{169, 253, 255, 254}, true}, // start-2
        {{169, 253, 255, 255}, true}, // start-1
        {{169, 254, 0, 0}, false}, // start
        {{169, 254, 0, 1}, false}, // start+1
        {{169, 254, 255, 254}, false}, // end-1
        {{169, 254, 255, 255}, false}, // end
        {{169, 255, 0, 0}, true}, // end+1
        {{169, 255, 0, 1}, true}, // end+2

        // 172.16.0.0-172.31.255.255
        {{172, 15, 255, 254}, true}, // start-2
        {{172, 15, 255, 255}, true}, // start-1
        {{172, 16, 0, 0}, false}, // start
        {{172, 16, 0, 1}, false}, // start+1
        {{172, 31, 255, 254}, false}, // end-1
        {{172, 31, 255, 255}, false}, // end
        {{172, 32, 0, 0}, true}, // end+1
        {{172, 32, 0, 1}, true}, // end+2

        // 192.0.0.0-192.0.0.255
        {{191, 255, 255, 254}, true}, // start-2
        {{191, 255, 255, 255}, true}, // start-1
        {{192, 0, 0, 0}, false}, // start
        {{192, 0, 0, 1}, false}, // start+1
        {{192, 0, 0, 254}, false}, // end-1
        {{192, 0, 0, 255}, false}, // end
        {{192, 0, 1, 0}, true}, // end+1
        {{192, 0, 1, 1}, true}, // end+2

        // 192.0.2.0-192.0.2.255
        {{192, 0, 1, 254}, true}, // start-2
        {{192, 0, 1, 255}, true}, // start-1
        {{192, 0, 2, 0}, false}, // start
        {{192, 0, 2, 1}, false}, // start+1
        {{192, 0, 2, 254}, false}, // end-1
        {{192, 0, 2, 255}, false}, // end
        {{192, 0, 3, 0}, true}, // end+1
        {{192, 0, 3, 1}, true}, // end+2

        // 192.88.99.0-192.88.99.255
        {{192, 88, 98, 254}, true}, // start-2
        {{192, 88, 98, 255}, true}, // start-1
        {{192, 88, 99, 0}, false}, // start
        {{192, 88, 99, 1}, false}, // start+1
        {{192, 88, 99, 254}, false}, // end-1
        {{192, 88, 99, 255}, false}, // end
        {{192, 88, 100, 0}, true}, // end+1
        {{192, 88, 100, 1}, true}, // end+2

        // 192.168.0.0-192.168.255.255
        {{192, 167, 255, 254}, true}, // start-2
        {{192, 167, 255, 255}, true}, // start-1
        {{192, 168, 0, 0}, false}, // start
        {{192, 168, 0, 1}, false}, // start+1
        {{192, 168, 255, 254}, false}, // end-1
        {{192, 168, 255, 255}, false}, // end
        {{192, 169, 0, 0}, true}, // end+1
        {{192, 169, 0, 1}, true}, // end+2

        // 198.18.0.0-198.19.255.255
        {{198, 17, 255, 254}, true}, // start-2
        {{198, 17, 255, 255}, true}, // start-1
        {{198, 18, 0, 0}, false}, // start
        {{198, 18, 0, 1}, false}, // start+1
        {{198, 19, 255, 254}, false}, // end-1
        {{198, 19, 255, 255}, false}, // end
        {{198, 20, 0, 0}, true}, // end+1
        {{198, 20, 0, 1}, true}, // end+2

        // 198.51.100.0-198.51.100.255
        {{198, 51, 99, 254}, true}, // start-2
        {{198, 51, 99, 255}, true}, // start-1
        {{198, 51, 100, 0}, false}, // start
        {{198, 51, 100, 1}, false}, // start+1
        {{198, 51, 100, 254}, false}, // end-1
        {{198, 51, 100, 255}, false}, // end
        {{198, 51, 101, 0}, true}, // end+1
        {{198, 51, 101, 1}, true}, // end+2

        // 203.0.113.0-203.0.113.255
        {{203, 0, 112, 254}, true}, // start-2
        {{203, 0, 112, 255}, true}, // start-1
        {{203, 0, 113, 0}, false}, // start
        {{203, 0, 113, 1}, false}, // start+1
        {{203, 0, 113, 254}, false}, // end-1
        {{203, 0, 113, 255}, false}, // end
        {{203, 0, 114, 0}, true}, // end+1
        {{203, 0, 114, 1}, true}, // end+2

        // 224.0.0.0-239.255.255.255
        {{223, 255, 255, 254}, true}, // start-2
        {{223, 255, 255, 255}, true}, // start-1
        {{224, 0, 0, 0}, false}, // start
        {{224, 0, 0, 1}, false}, // start+1
        {{239, 255, 255, 254}, false}, // end-1
        {{239, 255, 255, 255}, false}, // end
        //{{240, 0, 0, 0}, true}, // end+1
        //{{240, 0, 0, 1}, true}, // end+2

        // 240.0.0.0-255.255.255.254
        //{{239, 255, 255, 254}, true}, // start-2
        //{{239, 255, 255, 255}, true}, // start-1
        {{240, 0, 0, 0}, false}, // start
        {{240, 0, 0, 1}, false}, // start+1
        {{255, 255, 255, 253}, false}, // end-1
        {{255, 255, 255, 254}, false}, // end

        // 255.255.255.255-255.255.255.255
        {{255, 255, 255, 255}, false},
    };
    for (int i = 0; i < sizeof(addrinfos) / sizeof(addrinfos[0]); i++) {
        printf("\ri=%d", i);
        ASSERT_EQ(utl_net_ipv4_addr_is_routable(addrinfos[i].addr), addrinfos[i].is_public);
    }
    printf("\n");
}
