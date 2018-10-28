////////////////////////////////////////////////////////////////////////
//FAKE関数

FAKE_VOID_FUNC(btcrpc_term);
FAKE_VOID_FUNC(btcrpc_add_channel, const ln_self_t*, uint64_t, const uint8_t*, uint32_t, bool, const uint8_t*);
FAKE_VOID_FUNC(btcrpc_set_fundingtx, const ln_self_t*, const uint8_t*, uint32_t);
FAKE_VOID_FUNC(btcrpc_set_committxid, const ln_self_t*);
FAKE_VOID_FUNC(ptarmd_stop);
FAKE_VOID_FUNC(ptarmd_preimage_lock);
FAKE_VOID_FUNC(ptarmd_preimage_unlock);
FAKE_VOID_FUNC(ptarmd_nodefail_add, const uint8_t*, const char*, uint16_t, ln_nodedesc_t);
FAKE_VOID_FUNC(monitor_stop);
FAKE_VOID_FUNC(monitor_disable_autoconn, bool);
FAKE_VOID_FUNC(monitor_set_feerate_per_kw, uint32_t);
FAKE_VOID_FUNC(cmd_json_start, uint16_t);
FAKE_VOID_FUNC(cmd_json_stop);
FAKE_VALUE_FUNC(bool, btcrpc_init, const rpc_conf_t*);
FAKE_VALUE_FUNC(int32_t, btcrpc_getblockcount);
FAKE_VALUE_FUNC(bool, btcrpc_getgenesisblock, uint8_t*);
FAKE_VALUE_FUNC(uint32_t, btcrpc_get_funding_confirm, const ln_self_t*);
FAKE_VALUE_FUNC(bool, btcrpc_get_short_channel_param, const ln_self_t*, int*, int*, uint8_t*, const uint8_t*);
FAKE_VALUE_FUNC(bool, btcrpc_gettxid_from_short_channel, uint8_t*, int, int);
FAKE_VALUE_FUNC(bool, btcrpc_search_outpoint, btc_tx_t*, uint32_t, const uint8_t*, uint32_t);
FAKE_VALUE_FUNC(bool, btcrpc_search_vout, utl_buf_t*, uint32_t, const utl_buf_t*);
FAKE_VALUE_FUNC(bool, btcrpc_signraw_tx, btc_tx_t*, const uint8_t*, size_t, uint64_t);
FAKE_VALUE_FUNC(bool, btcrpc_sendraw_tx, uint8_t*, int*, const uint8_t*, uint32_t);
FAKE_VALUE_FUNC(bool, btcrpc_is_tx_broadcasted, const uint8_t*);
FAKE_VALUE_FUNC(bool, btcrpc_check_unspent, bool*, uint64_t*, const uint8_t*, uint32_t);
FAKE_VALUE_FUNC(bool, btcrpc_getnewaddress, char*);
FAKE_VALUE_FUNC(bool, btcrpc_estimatefee, uint64_t*, int);
FAKE_VALUE_FUNC(int, ptarmd_start, uint16_t);
FAKE_VALUE_FUNC(bool, ptarmd_transfer_channel, uint64_t, trans_cmd_t, utl_buf_t*);
FAKE_VALUE_FUNC(lnapp_conf_t*, ptarmd_search_connected_cnl, uint64_t);
FAKE_VALUE_FUNC(bool, ptarmd_nodefail_get, const uint8_t*, const char*, uint16_t, ln_nodedesc_t, bool);
FAKE_VALUE_FUNC(char*, ptarmd_error_str, int);
FAKE_VALUE_FUNC(uint32_t, monitoring_get_latest_feerate_kw);
FAKE_VALUE_FUNC(bool, monitor_close_unilateral_local, ln_self_t*, void*);
FAKE_VALUE_FUNC(int, cmd_json_connect, const uint8_t*, const char*, uint16_t);
FAKE_VALUE_FUNC(int, cmd_json_pay, const char*, uint64_t);
FAKE_VALUE_FUNC(int, cmd_json_pay_retry, const uint8_t*);


////////////////////////////////////////////////////////////////////////

class lnapp: public testing::Test {
protected:
    virtual void SetUp() {
        RESET_FAKE(btcrpc_term);
        RESET_FAKE(btcrpc_add_channel);
        RESET_FAKE(btcrpc_set_fundingtx);
        RESET_FAKE(btcrpc_set_committxid);
        RESET_FAKE(ptarmd_stop);
        RESET_FAKE(ptarmd_preimage_lock);
        RESET_FAKE(ptarmd_preimage_unlock);
        RESET_FAKE(ptarmd_nodefail_add);
        RESET_FAKE(monitor_stop);
        RESET_FAKE(monitor_disable_autoconn);
        RESET_FAKE(monitor_set_feerate_per_kw);
        RESET_FAKE(cmd_json_start);
        RESET_FAKE(cmd_json_stop);
        RESET_FAKE(btcrpc_init);
        RESET_FAKE(btcrpc_getblockcount);
        RESET_FAKE(btcrpc_getgenesisblock);
        RESET_FAKE(btcrpc_get_funding_confirm);
        RESET_FAKE(btcrpc_get_short_channel_param);
        RESET_FAKE(btcrpc_gettxid_from_short_channel);
        RESET_FAKE(btcrpc_search_outpoint);
        RESET_FAKE(btcrpc_search_vout);
        RESET_FAKE(btcrpc_signraw_tx);
        RESET_FAKE(btcrpc_sendraw_tx);
        RESET_FAKE(btcrpc_is_tx_broadcasted);
        RESET_FAKE(btcrpc_check_unspent);
        RESET_FAKE(btcrpc_getnewaddress);
        RESET_FAKE(btcrpc_estimatefee);
        RESET_FAKE(ptarmd_start);
        RESET_FAKE(ptarmd_transfer_channel);
        RESET_FAKE(ptarmd_search_connected_cnl);
        RESET_FAKE(ptarmd_nodefail_get);
        RESET_FAKE(ptarmd_error_str);
        RESET_FAKE(monitoring_get_latest_feerate_kw);
        RESET_FAKE(monitor_close_unilateral_local);
        RESET_FAKE(cmd_json_connect);
        RESET_FAKE(cmd_json_pay);
        RESET_FAKE(cmd_json_pay_retry);
        utl_dbg_malloc_cnt_reset();
        btc_init(BTC_TESTNET, false);
    }

    virtual void TearDown() {
        btc_term();
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

TEST_F(lnapp, init)
{
}
