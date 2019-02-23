#include "gtest/gtest.h"
#include <string.h>
#include "tests/fff.h"
DEFINE_FFF_GLOBALS;


extern "C" {
#include "../../utl/utl_thread.c"
#undef LOG_TAG
#include "../../utl/utl_log.c"
#include "../../utl/utl_dbg.c"
#include "../../utl/utl_buf.c"
#include "../../utl/utl_push.c"
#include "../../utl/utl_addr.c"
#include "../../utl/utl_time.c"
#include "../../utl/utl_int.c"
#include "../../utl/utl_mem.c"
#include "../../utl/utl_str.c"
//評価対象本体
#undef LOG_TAG
#include "lnapp.c"
}


////////////////////////////////////////////////////////////////////////
//FAKE関数
// FAKE_VALUE_FUNC(bool, btc_init, btc_chain_t , bool );
// FAKE_VOID_FUNC(btc_term);

FAKE_VOID_FUNC(ln_node_term);
FAKE_VALUE_FUNC(const uint8_t *,ln_remote_node_id, const ln_channel_t *);
FAKE_VALUE_FUNC(uint64_t, ln_short_channel_id, const ln_channel_t *);
FAKE_VALUE_FUNC(const char *, ln_msg_name, uint16_t );
FAKE_VALUE_FUNC(bool, ln_noise_enc, ln_noise_t *, utl_buf_t *, const utl_buf_t *);
FAKE_VALUE_FUNC(bool, ln_getids_cnl_anno, uint64_t *, uint8_t *, uint8_t *, const uint8_t *, uint16_t );
FAKE_VOID_FUNC(ln_short_channel_id_get_param, uint32_t *, uint32_t *, uint32_t *, uint64_t );

FAKE_VALUE_FUNC(bool, ln_db_annoown_check, uint64_t);
FAKE_VALUE_FUNC(bool, ln_db_annocnlupd_is_prune, uint64_t , uint32_t );
FAKE_VALUE_FUNC(bool, ln_db_annocnlinfo_search_nodeid, void *, uint64_t , char , const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_annocnlinfo_add_nodeid, void *, uint64_t , char , bool , const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_annonod_cur_load, void *, utl_buf_t *, uint32_t *, const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_annonodinfo_search_nodeid, void *, const uint8_t *, const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_annonodinfo_add_nodeid, void *, const uint8_t *, bool , const uint8_t *);
FAKE_VALUE_FUNC(bool, ln_db_annocnl_cur_get, void *, uint64_t *, char *, uint32_t *, utl_buf_t *);
FAKE_VALUE_FUNC(bool, ln_db_annocnl_cur_back, void *);
FAKE_VALUE_FUNC(bool, ln_db_annocnl_cur_del, void *);
FAKE_VALUE_FUNC(bool, ln_db_anno_transaction);
FAKE_VOID_FUNC(ln_db_anno_commit, bool);
FAKE_VALUE_FUNC(bool, ln_db_anno_cur_open, void **, ln_db_cur_t );
FAKE_VOID_FUNC(ln_db_anno_cur_close, void *);
FAKE_VALUE_FUNC(bool, ln_db_annocnlall_del, uint64_t );

FAKE_VALUE_FUNC(bool, btcrpc_gettxid_from_short_channel, uint8_t *, int , int );
FAKE_VALUE_FUNC(bool, btcrpc_check_unspent, const uint8_t *, bool *, uint64_t *, const uint8_t *, uint32_t );


////////////////////////////////////////////////////////////////////////
namespace dummy {
    const char *ln_msg_name(uint16_t Type) {
        return "";
    }
    
    bool ln_db_annonod_cur_load(void *pCur, utl_buf_t *pNodeAnno, uint32_t *pTimeStamp, const uint8_t *pNodeId) {
        pNodeAnno->len = sizeof(uint16_t);
        pNodeAnno->buf = (uint8_t *)UTL_DBG_MALLOC(pNodeAnno->len);
        memset(pNodeAnno->buf, 0, pNodeAnno->len);
        return true;
    }

}
////////////////////////////////////////////////////////////////////////

class lnapp: public testing::Test {
protected:
    virtual void SetUp() {
        //utl_log_init_stderr();
        utl_dbg_malloc_cnt_reset();
        
        RESET_FAKE(ln_node_term);
        RESET_FAKE(ln_remote_node_id);
        RESET_FAKE(ln_short_channel_id);
        RESET_FAKE(ln_msg_name);
        RESET_FAKE(ln_noise_enc);
        RESET_FAKE(ln_getids_cnl_anno);
        RESET_FAKE(ln_db_annoown_check);
        RESET_FAKE(ln_db_annocnlupd_is_prune);
        RESET_FAKE(ln_db_annocnlinfo_search_nodeid);
        RESET_FAKE(ln_db_annocnlinfo_add_nodeid);
        RESET_FAKE(ln_db_annonod_cur_load);
        RESET_FAKE(ln_db_annonodinfo_search_nodeid);
        RESET_FAKE(ln_db_annonodinfo_add_nodeid);
        RESET_FAKE(ln_db_annocnl_cur_get);
        RESET_FAKE(ln_db_annocnl_cur_back);
        RESET_FAKE(ln_db_annocnl_cur_del);
        
        ln_msg_name_fake.custom_fake = dummy::ln_msg_name;
        ln_noise_enc_fake.return_val = false;
        ln_db_annonod_cur_load_fake.custom_fake = dummy::ln_db_annonod_cur_load;
    }

    virtual void TearDown() {
        ln_node_term();
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
    static bool DumpCheck(const void *pData, uint32_t Len, uint8_t Fill)
    {
        bool ret = true;
        const uint8_t *p = (const uint8_t *)pData;
        for (uint32_t lp = 0; lp < Len; lp++) {
            if (p[lp] != Fill) {
                ret = false;
                break;
            }
        }
        return ret;
    }
};


////////////////////////////////////////////////////////////////////////

TEST_F(lnapp, prev_check_ok1)
{
    ln_db_annoown_check_fake.return_val = true;
    
    bool ret = anno_prev_check(0, 0);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, prev_check_ok2)
{
    ln_db_annoown_check_fake.return_val = false;
    ln_db_annocnlupd_is_prune_fake.return_val = false;

    bool ret = anno_prev_check(0, 0);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, prev_check_ng)
{
    ln_db_annoown_check_fake.return_val = false;
    ln_db_annocnlupd_is_prune_fake.return_val = true;

    bool ret = anno_prev_check(0, 0);
    ASSERT_FALSE(ret);
}


TEST_F(lnapp, send_cnl_ok1)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));

    ln_db_annocnlinfo_search_nodeid_fake.return_val = true;
    
    bool ret = anno_send_cnl(&conf, 0, 0, NULL, NULL);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, send_cnl_ok2)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };

    ln_db_annocnlinfo_search_nodeid_fake.return_val = false;
    
    bool ret = anno_send_cnl(&conf, 0, 0, NULL, &buf);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, send_node_ok1)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };

    ln_getids_cnl_anno_fake.return_val = true;
    bool seq[] = { true, true };
    ln_db_annonodinfo_search_nodeid_fake.return_val_seq = seq;
    ln_db_annonodinfo_search_nodeid_fake.return_val_seq_len = ARRAY_SIZE(seq);
    
    bool ret = anno_send_node(&conf, 0, 0, &buf);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, send_node_ok2)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };

    ln_getids_cnl_anno_fake.return_val = true;
    bool seq[] = { true, false };
    ln_db_annonodinfo_search_nodeid_fake.return_val_seq = seq;
    ln_db_annonodinfo_search_nodeid_fake.return_val_seq_len = ARRAY_SIZE(seq);
    
    bool ret = anno_send_node(&conf, 0, 0, &buf);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, send_node_ng)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };

    ln_getids_cnl_anno_fake.return_val = false;
    
    bool ret = anno_send_node(&conf, 0, 0, &buf);
    ASSERT_FALSE(ret);
}


TEST_F(lnapp, send_ok1)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };
    
    ln_db_annoown_check_fake.return_val = true;
    struct local {
        static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
            *pShortChannelId = 0;
            *pType = (char)(LN_DB_CNLANNO_UPD0 + ln_db_annocnl_cur_get_fake.call_count - 1);
            pBuf->len = sizeof(uint16_t);
            pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(pBuf->len);
            memset(pBuf->buf, 0, pBuf->len);
            return true;
        }
    };
    ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

    bool ret = anno_send(&conf, 0, &buf, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, send_ok2)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };
    
    ln_db_annoown_check_fake.return_val = true;
    struct local {
        static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
            if (ln_db_annocnl_cur_get_fake.call_count == 1) {
                //skip B
                *pShortChannelId = 0;
                *pType = (char)(LN_DB_CNLANNO_UPD0 + ln_db_annocnl_cur_get_fake.call_count - 1);
                pBuf->len = sizeof(uint16_t);
                pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(pBuf->len);
                memset(pBuf->buf, 0, pBuf->len);
                return true;
            } else {
                return false;
            }
        }
    };
    ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

    bool ret = anno_send(&conf, 0, &buf, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(ret);
}


//最初のln_db_annocnl_cur_get()で失敗した場合は、channel_update無しと同じ
// TEST_F(lnapp, send_ok3)
// {
//     lnapp_conf_t conf;
//     memset(&conf, 0, sizeof(conf));
//     uint16_t msg = 0;
//     utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };
    
//     ln_db_annoown_check_fake.return_val = true;
//     struct local {
//         static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
//             if (ln_db_annocnl_cur_get_fake.call_count == 2) {
//                 //skip B
//                 *pShortChannelId = 0;
//                 *pType = (char)(LN_DB_CNLANNO_UPD0 + ln_db_annocnl_cur_get_fake.call_count - 1);
//                 pBuf->len = sizeof(uint16_t);
//                 pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(pBuf->len);
//                 memset(pBuf->buf, 0, pBuf->len);
//                 return true;
//             } else {
//                 return false;
//             }
//         }
//     };
//     ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

//     bool ret = anno_send(&conf, 0, &buf, NULL, NULL, NULL, NULL);
//     ASSERT_TRUE(ret);
// }


TEST_F(lnapp, send_ng1)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };
    
    ln_db_annoown_check_fake.return_val = true;
    struct local {
        static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
            //no channel_update
            return false;
        }
    };
    ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

    bool ret = anno_send(&conf, 0, &buf, NULL, NULL, NULL, NULL);
    ASSERT_FALSE(ret);
}


TEST_F(lnapp, send_ng2)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };
    
    ln_db_annoown_check_fake.return_val = true;
    struct local {
        static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
            //different short_channel_id
            *pShortChannelId = 1;
            *pType = (char)(LN_DB_CNLANNO_UPD0 + ln_db_annocnl_cur_get_fake.call_count - 1);
            pBuf->len = sizeof(uint16_t);
            pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(pBuf->len);
            memset(pBuf->buf, 0, pBuf->len);
            return true;
        }
    };
    ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

    bool ret = anno_send(&conf, 0, &buf, NULL, NULL, NULL, NULL);
    ASSERT_FALSE(ret);
}


TEST_F(lnapp, send_ng3)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };
    
    ln_db_annoown_check_fake.return_val = true;
    struct local {
        static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
            //not channel_update
            *pShortChannelId = 0;
            *pType = LN_DB_CNLANNO_ANNO;
            pBuf->len = sizeof(uint16_t);
            pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(pBuf->len);
            memset(pBuf->buf, 0, pBuf->len);
            return true;
        }
    };
    ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

    bool ret = anno_send(&conf, 0, &buf, NULL, NULL, NULL, NULL);
    ASSERT_FALSE(ret);
}


TEST_F(lnapp, send_ng4)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    uint16_t msg = 0;
    utl_buf_t buf = { (uint8_t *)&msg, sizeof(msg) };
    
    //fail anno_prev_check()
    ln_db_annoown_check_fake.return_val = false;
    struct local {
        static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
            *pShortChannelId = 0;
            *pType = (char)(LN_DB_CNLANNO_UPD0 + ln_db_annocnl_cur_get_fake.call_count - 1);
            pBuf->len = sizeof(uint16_t);
            pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(pBuf->len);
            memset(pBuf->buf, 0, pBuf->len);
            return true;
        }
    };
    ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

    bool ret = anno_send(&conf, 0, &buf, NULL, NULL, NULL, NULL);
    ASSERT_TRUE(ret);
}


TEST_F(lnapp, proc_ok1)
{
    lnapp_conf_t conf;
    memset(&conf, 0, sizeof(conf));
    conf.loop = true;

    ln_db_anno_transaction_fake.return_val = true;
    ln_db_anno_cur_open_fake.return_val = true;
    ln_db_annocnlall_del_fake.return_val = true;
    btcrpc_gettxid_from_short_channel_fake.return_val = true;
    btcrpc_check_unspent_fake.return_val = true;
    
    ln_db_annoown_check_fake.return_val = true;
    struct local {
        static bool ln_db_annocnl_cur_get(void *pCur, uint64_t *pShortChannelId, char *pType, uint32_t *pTimeStamp, utl_buf_t *pBuf) {
            switch (ln_db_annocnl_cur_get_fake.call_count) {
            case 1:
                //channel_announcement
                *pType = LN_DB_CNLANNO_ANNO;
                break;
            case 2:
                //channel_update dir=0
                *pType = LN_DB_CNLANNO_UPD0;
                break;
            case 3:
                //channel_update dir=1
                *pType = LN_DB_CNLANNO_UPD1;
                break;
            default:
                return false;
            }
            *pShortChannelId = 0;
            pBuf->len = sizeof(uint16_t);
            pBuf->buf = (uint8_t *)UTL_DBG_MALLOC(pBuf->len);
            memset(pBuf->buf, 0, pBuf->len);
            return true;
        }
    };
    ln_db_annocnl_cur_get_fake.custom_fake = local::ln_db_annocnl_cur_get;

    bool ret = anno_proc(&conf);
    ASSERT_TRUE(ret);
}
