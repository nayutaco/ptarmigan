////////////////////////////////////////////////////////////////////////
//FAKE関数

FAKE_VOID_FUNC(btcrpc_term);
FAKE_VOID_FUNC(ptarmd_stop);
FAKE_VOID_FUNC(ptarmd_preimage_lock);
FAKE_VOID_FUNC(ptarmd_preimage_unlock);
FAKE_VOID_FUNC(ptarmd_nodefail_add, const uint8_t*, const char*, uint16_t, ln_msg_address_descriptor_type_t);
FAKE_VOID_FUNC(monitor_stop);
FAKE_VOID_FUNC(monitor_disable_autoconn, bool);
FAKE_VOID_FUNC(monitor_set_feerate_per_kw, uint32_t);
FAKE_VOID_FUNC(cmd_json_start, uint16_t);
FAKE_VOID_FUNC(cmd_json_stop);
FAKE_VOID_FUNC(ptarmd_call_script, ptarmd_event_t, const char*);
FAKE_VOID_FUNC_VARARG(ptarmd_eventlog, const uint8_t*, const char*, ...);
FAKE_VALUE_FUNC(bool, btcrpc_init, const rpc_conf_t*);
FAKE_VALUE_FUNC(bool, btcrpc_getblockcount, int32_t*, uint8_t*);
FAKE_VALUE_FUNC(bool, btcrpc_getgenesisblock, uint8_t*);
FAKE_VALUE_FUNC(bool, btcrpc_get_confirmations, uint32_t*, const uint8_t*);
FAKE_VALUE_FUNC(bool, btcrpc_get_short_channel_param, const uint8_t*, int32_t*, int32_t*, uint8_t*, const uint8_t*);
FAKE_VALUE_FUNC(bool, btcrpc_gettxid_from_short_channel, uint8_t*, int, int);
FAKE_VALUE_FUNC(bool, btcrpc_search_outpoint, btc_tx_t*, uint32_t, const uint8_t*, uint32_t);
FAKE_VALUE_FUNC(bool, btcrpc_search_vout, utl_buf_t*, uint32_t, const utl_buf_t*);
FAKE_VALUE_FUNC(bool, btcrpc_sign_fundingtx, btc_tx_t*, const utl_buf_t*, uint64_t);
FAKE_VALUE_FUNC(bool, btcrpc_send_rawtx, uint8_t*, int*, const uint8_t*, uint32_t);
FAKE_VALUE_FUNC(bool, btcrpc_is_tx_broadcasted, const uint8_t*, const uint8_t*);
FAKE_VALUE_FUNC(bool, btcrpc_check_unspent, const uint8_t*, bool*, uint64_t*, const uint8_t*, uint32_t);
FAKE_VALUE_FUNC(bool, btcrpc_getnewaddress, char*);
FAKE_VALUE_FUNC(bool, btcrpc_estimatefee, uint64_t*, int);
FAKE_VALUE_FUNC(int, ptarmd_start, uint16_t, const ln_node_t *, btc_block_chain_t);
// FAKE_VALUE_FUNC(bool, ptarmd_transfer_channel, uint64_t, rcvidle_cmd_t, utl_buf_t*);
FAKE_VALUE_FUNC(lnapp_conf_t*, p2p_search_active_channel, uint64_t);
FAKE_VALUE_FUNC(lnapp_conf_t*, ptarmd_search_transferable_channel, uint64_t);
FAKE_VALUE_FUNC(lnapp_conf_t*, ptarmd_search_connected_node_id, const uint8_t*);
FAKE_VALUE_FUNC(lnapp_conf_t*, ptarmd_search_transferable_node_id, const uint8_t*);
FAKE_VALUE_FUNC(void, lnapp_manager_free_node_ref, lnapp_conf_t*);
FAKE_VALUE_FUNC(bool, ptarmd_nodefail_get, const uint8_t*, const char*, uint16_t, ln_msg_address_descriptor_type_t, bool);
FAKE_VALUE_FUNC(char*, ptarmd_error_str, int);
FAKE_VALUE_FUNC(bool, monitor_btc_getblockcount, int32_t*);
FAKE_VALUE_FUNC(uint32_t, monitor_btc_feerate_per_kw);
FAKE_VALUE_FUNC(bool, monitor_close_unilateral_local, ln_channel_t*, void*);
FAKE_VALUE_FUNC(int, cmd_json_connect, const uint8_t*, const char*, uint16_t);
FAKE_VALUE_FUNC(int, cmd_json_pay, const char*, uint64_t);
FAKE_VALUE_FUNC(int, cmd_json_pay_retry, const uint8_t*);

FAKE_VOID_FUNC(btcrpc_set_channel, const uint8_t *, uint64_t , const uint8_t *, int , const utl_buf_t *, const uint8_t *, uint32_t, const uint8_t*);
FAKE_VOID_FUNC(btcrpc_set_committxid, const ln_channel_t*);


////////////////////////////////////////////////////////////////////////

class lnapp: public testing::Test {
protected:
    virtual void SetUp() {
        RESET_FAKE(btcrpc_term);
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
        RESET_FAKE(btcrpc_get_confirmations);
        RESET_FAKE(btcrpc_get_short_channel_param);
        RESET_FAKE(btcrpc_gettxid_from_short_channel);
        RESET_FAKE(btcrpc_search_outpoint);
        RESET_FAKE(btcrpc_search_vout);
        RESET_FAKE(btcrpc_sign_fundingtx);
        RESET_FAKE(btcrpc_send_rawtx);
        RESET_FAKE(btcrpc_is_tx_broadcasted);
        RESET_FAKE(btcrpc_check_unspent);
        RESET_FAKE(btcrpc_getnewaddress);
        RESET_FAKE(btcrpc_estimatefee);
        RESET_FAKE(ptarmd_start);
        // RESET_FAKE(ptarmd_transfer_channel);
        RESET_FAKE(p2p_search_active_channel);
        RESET_FAKE(ptarmd_nodefail_get);
        RESET_FAKE(ptarmd_error_str);
        RESET_FAKE(monitor_close_unilateral_local);
        RESET_FAKE(cmd_json_connect);
        RESET_FAKE(cmd_json_pay);
        RESET_FAKE(cmd_json_pay_retry);
        RESET_FAKE(btcrpc_set_channel);
        RESET_FAKE(btcrpc_set_committxid);
        utl_dbg_malloc_cnt_reset();
        btc_init(BTC_BLOCK_CHAIN_BTCTEST, false);
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
