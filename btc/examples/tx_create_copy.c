#define LOG_TAG "ex"
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "utl_log.h"
#include "utl_dbg.h"

#include "btc_crypto.h"
#include "btc_tx.h"
#include "btc.h"
#include "btc_sig.h"
#include "btc_script.h"
#include "btc_sw.h"
#include "btc_test_util.h"
#include "utl_push.h"

static bool misc_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr);
static bool misc_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr);



/* P2WPKH(native) --> P2WSH(native)
 *
 * bitcoind v0.18 regtest
 *
 * $ bitcoin-cli getnewaddress "" bech32
 * bcrt1qvaysu6w0punehrn0ds86wpg0s7e0juy055vs89
 * $ bitcoin-cli dumpprivkey bcrt1qvaysu6w0punehrn0ds86wpg0s7e0juy055vs89
 * cNvZBRYn81CRKQmnQ4AtrDTnXKsmXbEb9PEf96vkWTfKR7RsBMzh
 *
 *
 * 送金した(TXID)を PREV_TXID_STR[] に、listunspentしたvoutをPREV_TXINDEXに設定する。
 *
 *
 * $ bitcoin-cli sendtoaddress bcrt1qvaysu6w0punehrn0ds86wpg0s7e0juy055vs89 0.01
 * <TXID>
 * $ (generate)
 * $ bitcoin-cli listunspent | grep -10 <TXID>
  {
    "txid": "ded7fec1fd5ecb6b114609108386053f341493ac2ba91414d4ef8b16ebda1277",
    "vout": 0,
    "address": "bcrt1qvaysu6w0punehrn0ds86wpg0s7e0juy055vs89",
    "label": "",
    "scriptPubKey": "001467490e69cf0f279b8e6f6c0fa7050f87b2f9708f",
    "amount": 0.01000000,
    "confirmations": 1,
    "spendable": true,
    "solvable": true,
    "safe": true
  },
 *
 * HTLCの送金先 A
 * $ bitcoin-cli getnewaddress "" bech32
 * bcrt1q543p9xaxagpywhak9uqdg7jtkx3y7ff0smv09k
 * $ bitcoin-cli dumpprivkey bcrt1q543p9xaxagpywhak9uqdg7jtkx3y7ff0smv09k
 * cTMCooHbRM4epzDjK6y7LfBw4Yy5cocDApRgL4TtmpQFWQ6eXaeD
 *
 * HTLCの送金先 B
 * $ bitcoin-cli getnewaddress "" bech32
 * bcrt1qpyc80vqxaglx7n2ywh8tnqup4nvw9krhhrx6w0
 * $ bitcoin-cli dumpprivkey bcrt1qpyc80vqxaglx7n2ywh8tnqup4nvw9krhhrx6w0
 * cSizcvTyiPRkQsPRnfTHSnqycPehDpo7GJpPX95GvPwPZ74SheNe
 */
int tx_send_to_htlc(void)
{
    btc_init(BTC_BLOCK_CHAIN_BTCREGTEST, true);        //VIN: native

    btc_tx_t tx = BTC_TX_INIT;

    //
    //previous vout
    //      P2WPKH native
    //
    const char PREV_TXID_STR[] = "d2729da5201d4a80729a5f7fb179032945750838c8e9c299b1d66f5843e09c9d";
    const int PREV_TXINDEX = 0;

    const uint64_t PREV_AMOUNT = (uint64_t)1000000;
    const char PREV_WIF[] = "cNvZBRYn81CRKQmnQ4AtrDTnXKsmXbEb9PEf96vkWTfKR7RsBMzh";

    uint8_t PREV_TXID[BTC_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);
    btc_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);


    // A-san
    bool dummy;
    btc_keys_t key_a;
    const char ADDR_A[] = "bcrt1q543p9xaxagpywhak9uqdg7jtkx3y7ff0smv09k";
    assert(btc_keys_wif2keys(&key_a, &dummy, "cTMCooHbRM4epzDjK6y7LfBw4Yy5cocDApRgL4TtmpQFWQ6eXaeD"));
    // B-san
    btc_keys_t key_b;
    const char ADDR_B[] = "bcrt1qpyc80vqxaglx7n2ywh8tnqup4nvw9krhhrx6w0";
    assert(btc_keys_wif2keys(&key_b, &dummy, "cSizcvTyiPRkQsPRnfTHSnqycPehDpo7GJpPX95GvPwPZ74SheNe"));

    // HTLC parameter
    const int local_delay = 5;
    const uint8_t PREIMAGE[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    };
    uint8_t payment_hash[BTC_SZ_HASH256];
    uint8_t hashed_hash[BTC_SZ_HASH160];
    btc_md_sha256(payment_hash, PREIMAGE, sizeof(PREIMAGE));
    btc_md_ripemd160(hashed_hash, payment_hash, sizeof(payment_hash));

    LOGD("preimage= ");
    DUMPD(PREIMAGE, sizeof(PREIMAGE));
    LOGD("payment_hash= ");
    DUMPD(payment_hash, sizeof(payment_hash));
    LOGD("hashed_hash= ");
    DUMPD(hashed_hash, sizeof(hashed_hash));

    // HTLC
    utl_buf_t buf_script = UTL_BUF_INIT;
    utl_push_t push;

    //BOLT3風
    assert(utl_push_init(&push, &buf_script, 77));
    assert(utl_push_data(&push, BTC_OP_IF BTC_OP_HASH160 BTC_OP_SZ20, 3));
    assert(utl_push_data(&push, hashed_hash, BTC_SZ_HASH160));
    assert(utl_push_data(&push, BTC_OP_EQUALVERIFY BTC_OP_SZ_PUBKEY, 2));
    assert(utl_push_data(&push, key_a.pub, BTC_SZ_PUBKEY));
    assert(utl_push_data(&push, BTC_OP_ELSE, 1));
    assert(utl_push_value(&push, local_delay));
    assert(utl_push_data(&push, BTC_OP_CSV BTC_OP_DROP BTC_OP_SZ_PUBKEY, 3));
    assert(utl_push_data(&push, key_b.pub, BTC_SZ_PUBKEY));
    assert(utl_push_data(&push, BTC_OP_ENDIF BTC_OP_CHECKSIG, 2));

    //miniscript: or(and(hash160(H),pk(A)),and(older(5),pk(B)))
    // assert(utl_push_data(&push, BTC_OP_SZ_PUBKEY, 1));
    // assert(utl_push_data(&push, key_a.pub, BTC_SZ_PUBKEY));
    // assert(utl_push_data(&push, BTC_OP_CHECKSIG BTC_OP_NOTIF BTC_OP_SZ_PUBKEY, 3));
    // assert(utl_push_data(&push, key_b.pub, BTC_SZ_PUBKEY));
    // assert(utl_push_data(&push, BTC_OP_CHECKSIGVERIFY, 1));
    // assert(utl_push_value(&push, local_delay));
    // assert(utl_push_data(&push, BTC_OP_CSV BTC_OP_ELSE BTC_OP_SIZE BTC_OP_SZ32 BTC_OP_EQUALVERIFY BTC_OP_HASH160 BTC_OP_SZ20, 7));
    // assert(utl_push_data(&push, hashed_hash, BTC_SZ_HASH160));
    // assert(utl_push_data(&push, BTC_OP_EQUAL BTC_OP_ENDIF, 2));
    // assert(utl_push_trim(&push));



    utl_buf_t buf_scriptpk = UTL_BUF_INIT;
    assert(btc_script_p2wsh_create_scriptpk(&buf_scriptpk, &buf_script));

    const uint64_t FEE = 1000;
    const uint64_t HTLC_AMOUNT = PREV_AMOUNT - FEE;

    btc_tx_add_vout_spk(&tx, HTLC_AMOUNT, &buf_scriptpk);
    //btc_sw_add_vout_p2wsh_wit(&tx, ...);

    btc_keys_t prev_keys;
    bool is_test;
    btc_keys_wif2keys(&prev_keys, &is_test, PREV_WIF);
    assert(btc_test_util_sign_p2wpkh(&tx, 0, PREV_AMOUNT, &prev_keys));

    uint8_t txid_htlc[BTC_SZ_TXID];
    btc_tx_txid(&tx, txid_htlc);

    LOGD("HTLC_TX:\n");
    btc_tx_print(&tx);

    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&tx, &txbuf);
    LOGD("htlc_tx= ");
    DUMPD(txbuf.buf, txbuf.len);
    utl_buf_free(&txbuf);

    btc_tx_free(&tx);

    const uint8_t WIT_TRUE = 0x01;
    const utl_buf_t wit_true = { (CONST_CAST uint8_t *)&WIT_TRUE, 1 };
    const utl_buf_t wit_false = UTL_BUF_INIT;
    uint8_t sighash[BTC_SZ_HASH256];
    utl_buf_t sig = UTL_BUF_INIT;


    //redeem A-san
    btc_tx_t tx_htlc = BTC_TX_INIT;
    btc_tx_add_vout_addr(&tx_htlc, HTLC_AMOUNT - FEE, ADDR_A);
    btc_tx_add_vin(&tx_htlc, txid_htlc, 0);

    assert(btc_sw_sighash_p2wsh_wit(&tx_htlc, sighash, 0, HTLC_AMOUNT, &buf_script));
    assert(btc_sig_sign(&sig, sighash, key_a.priv));

    /*
     * witness:
     *      <A-san signature>
     *      <preimage>
     *      1
     *      <witnessScript>
     */
    const utl_buf_t preimg = { (CONST_CAST uint8_t *)PREIMAGE, sizeof(PREIMAGE) };
    const utl_buf_t *wits_a[] = { &sig, &preimg, &wit_true, &buf_script };
    assert(btc_sw_set_vin_p2wsh(&tx_htlc, 0, (const utl_buf_t **)wits_a, ARRAY_SIZE(wits_a)));
    LOGD("HTLC_REDEEM_TX-A:\n");
    btc_tx_print(&tx_htlc);

    btc_tx_write(&tx_htlc, &txbuf);
    LOGD("htlc_redeem_tx_a= ");
    DUMPD(txbuf.buf, txbuf.len);
    utl_buf_free(&txbuf);
    btc_tx_free(&tx_htlc);

    //redeem B-san
    btc_tx_add_vout_addr(&tx_htlc, HTLC_AMOUNT - FEE, ADDR_B);
    btc_vin_t *vin = btc_tx_add_vin(&tx_htlc, txid_htlc, 0);
    vin->sequence = local_delay;    //OP_CSV
    assert(btc_sw_sighash_p2wsh_wit(&tx_htlc, sighash, 0, HTLC_AMOUNT, &buf_script));
    assert(btc_sig_sign(&sig, sighash, key_b.priv));

    /*
     * witness:
     *      <B-san signature>
     *      0
     *      <witnessScript>
     */
    const utl_buf_t *wits_b[] = { &sig, &wit_false, &buf_script };
    assert(btc_sw_set_vin_p2wsh(&tx_htlc, 0, (const utl_buf_t **)wits_b, ARRAY_SIZE(wits_b)));
    LOGD("HTLC_REDEEM_TX-B:\n");
    btc_tx_print(&tx_htlc);

    btc_tx_write(&tx_htlc, &txbuf);
    LOGD("htlc_redeem_tx_b= ");
    DUMPD(txbuf.buf, txbuf.len);
    utl_buf_free(&txbuf);
    btc_tx_free(&tx_htlc);

    btc_term();
    return 0;
}



int main(void)
{
    utl_log_init_stdout();

    tx_send_to_htlc();

    return 0;
}


static bool misc_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr)
{
    if (strlen(pStr) != BinLen * 2) {
        printf("fail: invalid buffer size: %zu != %" PRIu32 " * 2\n", strlen(pStr), BinLen);
        return false;
    }

    bool ret = true;

    char str[3];
    str[2] = '\0';
    uint32_t lp;
    for (lp = 0; lp < BinLen; lp++) {
        str[0] = *(pStr + 2 * lp);
        str[1] = *(pStr + 2 * lp + 1);
        if (!str[0]) {
            //偶数文字で\0ならばOK
            break;
        }
        if (!str[1]) {
            //奇数文字で\0ならばNG
            printf("fail: odd length\n");
            ret = false;
            break;
        }
        char *endp = NULL;
        uint8_t bin = (uint8_t)strtoul(str, &endp, 16);
        if ((endp != NULL) && (*endp != 0x00)) {
            //変換失敗
            printf("fail: *endp = %p(%02x)\n", endp, *endp);
            ret = false;
            break;
        }
        pBin[lp] = bin;
    }

    return ret;
}


static bool misc_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr)
{
    bool ret = misc_str2bin(pBin, BinLen, pStr);
    if (ret) {
        for (uint32_t lp = 0; lp < BinLen / 2; lp++) {
            uint8_t tmp = pBin[lp];
            pBin[lp] = pBin[BinLen - lp - 1];
            pBin[BinLen - lp - 1] = tmp;
        }
    }

    return ret;
}

