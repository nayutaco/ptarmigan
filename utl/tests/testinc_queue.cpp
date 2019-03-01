////////////////////////////////////////////////////////////////////////
//FAKE関数

//FAKE_VALUE_FUNC(int, external_function, int);

////////////////////////////////////////////////////////////////////////

class queue: public testing::Test {
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

TEST_F(queue, push_and_pop)
{
    utl_queue_t queue;

    ASSERT_TRUE(utl_queue_create(&queue, sizeof(uint32_t), 5));

    uint32_t item_in = 0xabcd0123;
    uint32_t item_out;
    uint32_t item_expected = item_in;

    ASSERT_FALSE(utl_queue_pop(&queue, &item_in));

    //push x 5
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;

    ASSERT_FALSE(utl_queue_push(&queue, &item_in));

    //pop x 5
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;

    ASSERT_FALSE(utl_queue_pop(&queue, &item_out));

    utl_queue_free(&queue);
}


TEST_F(queue, push_and_pop_and_push_and_pop)
{
    utl_queue_t queue;

    ASSERT_TRUE(utl_queue_create(&queue, sizeof(uint32_t), 5));

    uint32_t item_in = 0xabcd0123;
    uint32_t item_out;
    uint32_t item_expected = item_in;

    ASSERT_FALSE(utl_queue_pop(&queue, &item_in));

    //push x 5
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;

    ASSERT_FALSE(utl_queue_push(&queue, &item_in));

    //pop x 3
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;

    //push x 3
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;
    ASSERT_TRUE(utl_queue_push(&queue, &item_in));
    item_in++;

    ASSERT_FALSE(utl_queue_push(&queue, &item_in));


    //pop x 5
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;
    ASSERT_TRUE(utl_queue_pop(&queue, &item_out));
    ASSERT_EQ(item_out, item_expected);
    item_expected++;

    ASSERT_FALSE(utl_queue_pop(&queue, &item_out));

    utl_queue_free(&queue);
}


