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
#include "btc_script.h"
#include "btc_test_util.h"

static bool misc_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr);
static bool misc_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr);


#if defined(USE_BITCOIN)
/* P2WPKH(nested in BIP16 P2SH) --> P2WPKH(nested in BIP16 P2SH)
 *
 * bitcoind v0.16
 *      $ bitcoin-cli listunspent
 *      {
 *        "txid": "dae822e5209c487cab3977823c4890239bcad1d1ae15973f66dbdff794ccb9e2",
 *        "vout": 1,
 *        "address": "2N1eQ2JFDjHkrHV5A8YyBzNFbNNwjhcTMZE",
 *        "account": "",
 *        "redeemScript": "00141bf9d39538ae6adc7a1683face78c62f0cf2e27c",
 *        "scriptPubKey": "a9145c22f33094e4cb9947329912b97d85af38872c1587",
 *        "amount": 0.00099821,
 *        "confirmations": 25553,
 *        "spendable": true,
 *        "solvable": true,
 *        "safe": true
 *      }
 *
 *      $ bitcoin-cli dumpprivkey 2N1eQ2JFDjHkrHV5A8YyBzNFbNNwjhcTMZE
 *      cUiL3RUGEdVECMEAhXDLxzo9QQTejuvyXx6djgjTPsNCdjFhwiqZ
 *
 *      $ bitcoin-cli getnewaddress
 *      2Mvu4y3iKWyMcWmNoTptMxNka6YcFkC5mNR
 */
int tx_create1(void)
{
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, false);       //VIN: not native

    //
    //previous vout
    //      P2WPKH nested in BIP16 P2SH
    //
    const char PREV_TXID_STR[] = "dae822e5209c487cab3977823c4890239bcad1d1ae15973f66dbdff794ccb9e2";
    const int PREV_TXINDEX = 1;
    const uint64_t PREV_AMOUNT = (uint64_t)99821;
    const uint8_t PREV_VOUT_REDEEM[] = {
        0x00, 0x14, 0x1b, 0xf9, 0xd3, 0x95, 0x38, 0xae,
        0x6a, 0xdc, 0x7a, 0x16, 0x83, 0xfa, 0xce, 0x78,
        0xc6, 0x2f, 0x0c, 0xf2, 0xe2, 0x7c,
    };
    const char PREV_WIF[] = "cUiL3RUGEdVECMEAhXDLxzo9QQTejuvyXx6djgjTPsNCdjFhwiqZ";


    //
    //vout
    //
    const char NEW_VOUT_ADDR[] = "2Mvu4y3iKWyMcWmNoTptMxNka6YcFkC5mNR";
    const uint64_t FEE = 1000;


    uint8_t PREV_TXID[BTC_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


    btc_tx_t tx = BTC_TX_INIT;

    btc_vin_t *vin = btc_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);
    utl_buf_t *pRedeem = btc_tx_add_wit(vin);
    utl_buf_alloccopy(pRedeem, PREV_VOUT_REDEEM, sizeof(PREV_VOUT_REDEEM));

    btc_tx_add_vout_addr(&tx, PREV_AMOUNT - FEE, NEW_VOUT_ADDR);

    btc_keys_t prev_keys;
    bool is_test;
    btc_keys_wif2keys(&prev_keys, &is_test, PREV_WIF);
    bool ret = btc_test_util_sign_p2wpkh(&tx, 0, PREV_AMOUNT, &prev_keys);
    printf("ret=%d\n", ret);

    btc_tx_print(&tx);
    // ======================================
    // txid= 341cc3d10ef50cfe3161c72fa4f150382ff11428642fa87074f18551949c9d6f
    // ======================================
    // version:2
    // txin_cnt=1
    // [vin #0]
    //  txid= dae822e5209c487cab3977823c4890239bcad1d1ae15973f66dbdff794ccb9e2
    //       LE: e2b9cc94f7dfdb663f9715aed1d1ca9b2390483c827739ab7c489c20e522e8da
    //  index= 1
    //  scriptSig[23]= 1600141bf9d39538ae6adc7a1683face78c62f0cf2e27c
    //      16 00141bf9d39538ae6adc7a1683face78c62f0cf2e27c
    //  sequence= 0xffffffff
    //  witness[0][72]= 3045022100f34ea94cc2b4ddd8a898c5ae3c9bf80f83673f24e7c17314b5e9721e7103886002201b2d5d45754fb4796efb33042a829e3f93d581d4b7f3c6ce13d2ec5fb061bae201
    //  witness[1][33]= 03f8dd7803e1247535b8edf1a41b490d37a377be1f6d41c83cc7a8e2330dc34166
    // txout_cnt= 1
    // [vout #0]
    //  value= 98821  : 0582010000000000
    //    0.98821 mBTC, 0.00098821 BTC
    //  scriptPubKey[23]= a9142810a73d941022f4ff6b78878fadf5fb42a888a687
    //      a9 [OP_HASH160]
    //      14 2810a73d941022f4ff6b78878fadf5fb42a888a6
    //      87 [OP_EQUAL]
    // locktime= 0x00000000 : block height
    // ======================================


    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&tx, &txbuf);
    utl_dbg_dump(stdout, txbuf.buf, txbuf.len, true);
    utl_buf_free(&txbuf);

    // $ bitcoin-cli sendrawtransaction 02000000000101e2b9cc94f7dfdb663f9715aed1d1ca9b2390483c827739ab7c489c20e522e8da01000000171600141bf9d39538ae6adc7a1683face78c62f0cf2e27cffffffff01058201000000000017a9142810a73d941022f4ff6b78878fadf5fb42a888a68702483045022100f34ea94cc2b4ddd8a898c5ae3c9bf80f83673f24e7c17314b5e9721e7103886002201b2d5d45754fb4796efb33042a829e3f93d581d4b7f3c6ce13d2ec5fb061bae2012103f8dd7803e1247535b8edf1a41b490d37a377be1f6d41c83cc7a8e2330dc3416600000000
    // 341cc3d10ef50cfe3161c72fa4f150382ff11428642fa87074f18551949c9d6f

    btc_tx_free(&tx);

    btc_term();

    return 0;
}


/* P2WPKH(native) --> P2WPKH(nested in BIP16 P2SH)
 *
 * bitcoind v0.16
 *
 *      $ bitcoin-cli getnewaddress "" bech32
 *      tb1q29ccnsx40wsam5lesxfx4w6ttmgz52q8qrpgla
 *
 *      $ bitcoin-cli sendtoaddress tb1q29ccnsx40wsam5lesxfx4w6ttmgz52q8qrpgla 0.01
 *      9a17cceee2d21db38b6272efdfd13c10b3a60f8eb346a538c5603ffd55628ea7
 *
 *      (wait mining...)
 *
 *      $ bitcoin-cli listunspent
 *      {
 *        "txid": "9a17cceee2d21db38b6272efdfd13c10b3a60f8eb346a538c5603ffd55628ea7",
 *        "vout": 1,
 *        "address": "tb1q29ccnsx40wsam5lesxfx4w6ttmgz52q8qrpgla",
 *        "account": "",
 *        "scriptPubKey": "0014517189c0d57ba1ddd3f981926abb4b5ed02a2807",
 *        "amount": 0.01000000,
 *        "confirmations": 20,
 *        "spendable": true,
 *        "solvable": true,
 *        "safe": true
 *      },
 *
 *      $ bitcoin-cli dumpprivkey tb1q29ccnsx40wsam5lesxfx4w6ttmgz52q8qrpgla
 *      cVPaYCkmnAq7ctxEf3a13qqafK598bxEsGQBAQ2nVJd9X5KhmViL
 *
 *      $ bitcoin-cli getnewaddress
 *      2Mvu4y3iKWyMcWmNoTptMxNka6YcFkC5mNR
 */
int tx_create2(void)
{
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, true);        //VIN: native

    //
    //previous vout
    //      P2WPKH native
    //
    const char PREV_TXID_STR[] = "9a17cceee2d21db38b6272efdfd13c10b3a60f8eb346a538c5603ffd55628ea7";
    const int PREV_TXINDEX = 1;
    const uint64_t PREV_AMOUNT = (uint64_t)1000000;
    const char PREV_WIF[] = "cVPaYCkmnAq7ctxEf3a13qqafK598bxEsGQBAQ2nVJd9X5KhmViL";


    //
    //vout
    //
    const char NEW_VOUT_ADDR[] = "2Mvu4y3iKWyMcWmNoTptMxNka6YcFkC5mNR";
    const uint64_t FEE = 1000;


    uint8_t PREV_TXID[BTC_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


    btc_tx_t tx = BTC_TX_INIT;

    btc_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);

    btc_tx_add_vout_addr(&tx, PREV_AMOUNT - FEE, NEW_VOUT_ADDR);

    btc_keys_t prev_keys;
    bool is_test;
    btc_keys_wif2keys(&prev_keys, &is_test, PREV_WIF);
    bool ret = btc_test_util_sign_p2wpkh(&tx, 0, PREV_AMOUNT, &prev_keys);
    printf("ret=%d\n", ret);

    btc_tx_print(&tx);
    // ======================================
    // txid= cc4c95e4f27788ae40a7a8254657682206518b8585a043f9b42177b37ee866d7
    // ======================================
    //  version:2
    //  txin_cnt=1
    //  [vin #0]
    //   txid= 9a17cceee2d21db38b6272efdfd13c10b3a60f8eb346a538c5603ffd55628ea7
    //        LE: a78e6255fd3f60c538a546b38e0fa6b3103cd1dfef72628bb31dd2e2eecc179a
    //   index= 1
    //   scriptSig[0]=
    //   sequence= 0xffffffff
    //   witness[0][72]= 3045022100a1971b418033d8e198e946f6bbf86c1bd6bff749bbffeeca1dd1168201676bbf022031d20ca73bce80261cac2227c157a5e1ee219db27a77c0e47f3ce2a49316213601
    //   witness[1][33]= 037321e275c52eafcd002e53b741bad8db1cd357e71ad3ef811d879070eddffd31
    //  txout_cnt= 1
    //  [vout #0]
    //   value= 999000  : 583e0f0000000000
    //        9.99000 mBTC, 0.00999000 BTC
    //   scriptPubKey[23]= a9142810a73d941022f4ff6b78878fadf5fb42a888a687
    //       a9 [OP_HASH160]
    //       14 2810a73d941022f4ff6b78878fadf5fb42a888a6
    //       87 [OP_EQUAL]
    //  locktime= 0x00000000 : block height
    // ======================================


    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&tx, &txbuf);
    utl_dbg_dump(stdout, txbuf.buf, txbuf.len, true);
    utl_buf_free(&txbuf);

    // $ bitcoin-cli sendrawtransaction 02000000000101a78e6255fd3f60c538a546b38e0fa6b3103cd1dfef72628bb31dd2e2eecc179a0100000000ffffffff01583e0f000000000017a9142810a73d941022f4ff6b78878fadf5fb42a888a68702483045022100a1971b418033d8e198e946f6bbf86c1bd6bff749bbffeeca1dd1168201676bbf022031d20ca73bce80261cac2227c157a5e1ee219db27a77c0e47f3ce2a4931621360121037321e275c52eafcd002e53b741bad8db1cd357e71ad3ef811d879070eddffd3100000000
    // cc4c95e4f27788ae40a7a8254657682206518b8585a043f9b42177b37ee866d7

    btc_tx_free(&tx);

    btc_term();

    return 0;
}


/* P2WPKH(native) --> P2WPKH(native)
 *
 * bitcoind v0.16
 *
 *      $ bitcoin-cli getnewaddress "" bech32
 *      tb1qapmqrl4l3x60ep294tny43p4f87zdcs5y245f4
 *
 *      $ bitcoin-cli sendtoaddress tb1qapmqrl4l3x60ep294tny43p4f87zdcs5y245f4 0.01
 *      6008de4dd3d00307607aba5a96eb42f09c45990528bc31b3c59253c05a4cce97
 *
 *      (wait mining...)
 *
 *      $ bitcoin-cli listunspent | grep -20 tb1qapmqrl4l3x60ep294tny43p4f87zdcs5y245f4
 *      {
 *        "txid": "6008de4dd3d00307607aba5a96eb42f09c45990528bc31b3c59253c05a4cce97",
 *        "vout": 1,
 *        "address": "tb1qapmqrl4l3x60ep294tny43p4f87zdcs5y245f4",
 *        "account": "",
 *        "scriptPubKey": "0014e87601febf89b4fc8545aae64ac43549fc26e214",
 *        "amount": 0.01000000,
 *        "confirmations": 6,
 *        "spendable": true,
 *        "solvable": true,
 *        "safe": true
 *      },
 *
 *      $ bitcoin-cli dumpprivkey tb1qapmqrl4l3x60ep294tny43p4f87zdcs5y245f4
 *      cQJoSbtqbcPyxS6PRW2LCMbGRBUuxHLMwwWmRYfaXQcL211f32o9
 *
 *      $ bitcoin-cli getnewaddress "" bech32
 *      tb1q7lfnmpcz6r2twcnj9z5a0c8dsvzxfa6fw0clw5
 */
int tx_create3(void)
{
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, true);        //VIN: native

    //
    //previous vout
    //      P2WPKH native
    //
    const char PREV_TXID_STR[] = "178c91f17aab4e9da32ac06ae58e14d11d934998637e642bd2db1df283ae44c5";
    const int PREV_TXINDEX = 0;
    const uint64_t PREV_AMOUNT = (uint64_t)1799667;
    const char PREV_WIF[] = "cTGBVWT6uyU5fJ2gGFM5UF18qVBoWfab3SaoC2zpoXNRMPhoGiqT";


    //
    //vout
    //
    const char NEW_VOUT_ADDR[] = "tb1qvutghc2ukja2yczja3fp5xgx5whc7a6xex07w0";
    const uint64_t FEE = 1000;


    uint8_t PREV_TXID[BTC_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


    btc_tx_t tx = BTC_TX_INIT;

    btc_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);

    btc_tx_add_vout_addr(&tx, PREV_AMOUNT - FEE, NEW_VOUT_ADDR);

    btc_keys_t prev_keys;
    bool is_test;
    btc_keys_wif2keys(&prev_keys, &is_test, PREV_WIF);
    bool ret = btc_test_util_sign_p2wpkh(&tx, 0, PREV_AMOUNT, &prev_keys);
    printf("ret=%d\n", ret);

    btc_tx_print(&tx);
    // ======================================
    // txid= 78bb06807dd07254ad3cdb3c49ec05b726f641a69ee41c581201f6d38912a6fe
    // ======================================
    //  version:2
    //  txin_cnt=1
    //  [vin #0]
    //   txid= 8960b92a4f242cbe2bd5af116e075732c5085e96f212d07f87a123813116f9be
    //        LE: bef916318123a1877fd012f2965e08c53257076e11afd52bbe2c244f2ab96089
    //   index= 1
    //   scriptSig[0]=
    //   sequence= 0xffffffff
    //   witness[0][72]= 3045022100aad64cb35d5d7ddae6ecceaece136a43173e8ef73fa55365f466038be2ebc36b0220548ace73fa23c78e9d35d454b97c83228cbc47a78fd28ddf197e02c75459413801
    //   witness[1][33]= 03158b0e57aafb5e16e6fb5ad375d423376bc45fbe8e4a841d7cdfaf8116d537b0
    //  txout_cnt= 1
    //  [vout #0]
    //   value= 999000  : 583e0f0000000000
    //        9.99000 mBTC, 0.00999000 BTC
    //   scriptPubKey[22]= 0014a782f82af08ce48820cc402f6f7b346aa3daa4e8
    //       00
    //       14 a782f82af08ce48820cc402f6f7b346aa3daa4e8
    //  locktime= 0x00000000 : block height
    // ======================================


    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&tx, &txbuf);
    utl_dbg_dump(stdout, txbuf.buf, txbuf.len, true);
    utl_buf_free(&txbuf);

    // $ bitcoin-cli sendrawtransaction 02000000000101bef916318123a1877fd012f2965e08c53257076e11afd52bbe2c244f2ab960890100000000ffffffff01583e0f0000000000160014a782f82af08ce48820cc402f6f7b346aa3daa4e802483045022100aad64cb35d5d7ddae6ecceaece136a43173e8ef73fa55365f466038be2ebc36b0220548ace73fa23c78e9d35d454b97c83228cbc47a78fd28ddf197e02c754594138012103158b0e57aafb5e16e6fb5ad375d423376bc45fbe8e4a841d7cdfaf8116d537b000000000
    // 78bb06807dd07254ad3cdb3c49ec05b726f641a69ee41c581201f6d38912a6fe

    btc_tx_free(&tx);

    btc_term();

    return 0;
}


/* P2PKH --> P2PKH
 *
 * bitcoind v0.16
 *      $ bitcoin-cli listunspent
 *      {
 *        "txid": "364451d26ede19bf9af66766c73dad221410a52bb7ab2601cd26ac91f23a1c9a",
 *        "vout": 1,
 *        "address": "mmDa4rjGk1YcD5jFN6kNkHADYF6UorPjHK",
 *        "account": "",
 *        "scriptPubKey": "76a9143e8720f6486b4e6681e802a955be61b46fbb6e5788ac",
 *        "amount": 0.01000000,
 *        "confirmations": 2,
 *        "spendable": true,
 *        "solvable": true,
 *        "safe": true
 *      }
 *
 *      $ bitcoin-cli dumpprivkey mmDa4rjGk1YcD5jFN6kNkHADYF6UorPjHK
 *      cRo5gaLGYFcYrdhhj4BQsrhYXVBXNRwCBNvJoPRzdLFxvaLUUUfr
 *
 *      $ bitcoin-cli getnewaddress
 *      mnfEszuxt3SmhwetCTBDNaQpEj5RC6nWb3
 */
int tx_create4(void)
{
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, false);       //VIN: not native

    //
    //previous vout
    //      P2WPKH nested in BIP16 P2SH
    //
    const char PREV_TXID_STR[] = "364451d26ede19bf9af66766c73dad221410a52bb7ab2601cd26ac91f23a1c9a";
    const int PREV_TXINDEX = 1;
    const uint64_t PREV_AMOUNT = (uint64_t)1000000;
    const char PREV_WIF[] = "cRo5gaLGYFcYrdhhj4BQsrhYXVBXNRwCBNvJoPRzdLFxvaLUUUfr";


    //
    //vout
    //
    const char NEW_VOUT_ADDR[] = "mnfEszuxt3SmhwetCTBDNaQpEj5RC6nWb3";
    const uint64_t FEE = 1000;


    uint8_t PREV_TXID[BTC_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


    btc_tx_t tx = BTC_TX_INIT;

    btc_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);
    btc_tx_add_vout_addr(&tx, PREV_AMOUNT - FEE, NEW_VOUT_ADDR);

    btc_keys_t prev_keys;
    bool is_test;
    btc_keys_wif2keys(&prev_keys, &is_test, PREV_WIF);
    bool ret = btc_test_util_sign_p2pkh(&tx, 0, &prev_keys);
    printf("ret=%d\n", ret);

    btc_tx_print(&tx);
    // ======================================
    // txid= b072d8eab1580dae2047c0b92df54c3e5cc33825440e5e4f278e8e62e5575089
    // ======================================
    //  version:2
    //  txin_cnt=1
    //  [vin #0]
    //   txid= 364451d26ede19bf9af66766c73dad221410a52bb7ab2601cd26ac91f23a1c9a
    //        LE: 9a1c3af291ac26cd0126abb72ba5101422ad3dc76667f69abf19de6ed2514436
    //   index= 1
    //   scriptSig[106]= 47304402200ec4abd2df761092961cdfe1fe26200a60e41dadc934b0a212214fc01158dbd302201cc8b0d5c0e31eccf17a248133d97f79b33a66781e251422a8f4ea6983dd4245012102167d244d4230ad06c4b7871d3cb78238b3f5c069c808e7aa4ddbf610bcdfcd33
    //       47 304402200ec4abd2df761092961cdfe1fe26200a60e41dadc934b0a212214fc01158dbd302201cc8b0d5c0e31eccf17a248133d97f79b33a66781e251422a8f4ea6983dd424501
    //       21 02167d244d4230ad06c4b7871d3cb78238b3f5c069c808e7aa4ddbf610bcdfcd33
    //   sequence= 0xffffffff
    //  txout_cnt= 1
    //  [vout #0]
    //   value= 999000  : 583e0f0000000000
    //        9.99000 mBTC, 0.00999000 BTC
    //   scriptPubKey[25]= 76a9144e5a0d8858c484747bccf427c8ab3a017c3c75c788ac
    //       76 [OP_DUP]
    //       a9 [OP_HASH160]
    //       14 4e5a0d8858c484747bccf427c8ab3a017c3c75c7
    //       88 [OP_EQUALVERIFY]
    //       ac [OP_CHECKSIG]
    //     (mnfEszuxt3SmhwetCTBDNaQpEj5RC6nWb3)
    //  locktime= 0x00000000 : block height
    // ======================================


    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&tx, &txbuf);
    utl_dbg_dump(stdout, txbuf.buf, txbuf.len, true);
    utl_buf_free(&txbuf);

    // $ bitcoin-cli sendrawtransaction 02000000019a1c3af291ac26cd0126abb72ba5101422ad3dc76667f69abf19de6ed2514436010000006a47304402200ec4abd2df761092961cdfe1fe26200a60e41dadc934b0a212214fc01158dbd302201cc8b0d5c0e31eccf17a248133d97f79b33a66781e251422a8f4ea6983dd4245012102167d244d4230ad06c4b7871d3cb78238b3f5c069c808e7aa4ddbf610bcdfcd33ffffffff01583e0f00000000001976a9144e5a0d8858c484747bccf427c8ab3a017c3c75c788ac00000000
    // b072d8eab1580dae2047c0b92df54c3e5cc33825440e5e4f278e8e62e5575089

    btc_tx_free(&tx);

    btc_term();

    return 0;
}


/* P2PKH --> P2PKH
 *
 * bitcoind v0.16
 *      $ bitcoin-cli listunspent
 *      {
 *        "txid": "b072d8eab1580dae2047c0b92df54c3e5cc33825440e5e4f278e8e62e5575089",
 *        "vout": 0,
 *        "address": "mnfEszuxt3SmhwetCTBDNaQpEj5RC6nWb3",
 *        "account": "",
 *        "scriptPubKey": "76a9144e5a0d8858c484747bccf427c8ab3a017c3c75c788ac",
 *        "amount": 0.00999000,
 *        "confirmations": 7,
 *        "spendable": true,
 *        "solvable": true,
 *        "safe": true
 *      },
 *
 *      $ bitcoin-cli dumpprivkey mnfEszuxt3SmhwetCTBDNaQpEj5RC6nWb3
 *      cUFWuAMEYjkC4o9K57FMM4hLdgnaQUZmdmANgGxcEKA6b8pn5w2L
 *
 *      $ bitcoin-cli getnewaddress "" bech32
 *      tb1qrywlrzhykppaa77jjzcyvv5vkjr8an8ldq3m5y
 */
int tx_create5(void)
{
    btc_init(BTC_BLOCK_CHAIN_BTCTEST, false);       //VIN: not native

    //
    //previous vout
    //      P2WPKH nested in BIP16 P2SH
    //
    const char PREV_TXID_STR[] = "b072d8eab1580dae2047c0b92df54c3e5cc33825440e5e4f278e8e62e5575089";
    const int PREV_TXINDEX = 0;
    const uint64_t PREV_AMOUNT = (uint64_t)999000;
    const char PREV_WIF[] = "cUFWuAMEYjkC4o9K57FMM4hLdgnaQUZmdmANgGxcEKA6b8pn5w2L";


    //
    //vout
    //
    const char NEW_VOUT_ADDR[] = "tb1qrywlrzhykppaa77jjzcyvv5vkjr8an8ldq3m5y";
    const uint64_t FEE = 1000;


    uint8_t PREV_TXID[BTC_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


    btc_tx_t tx = BTC_TX_INIT;

    btc_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);
    btc_tx_add_vout_addr(&tx, PREV_AMOUNT - FEE, NEW_VOUT_ADDR);

    btc_keys_t prev_keys;
    bool is_test;
    btc_keys_wif2keys(&prev_keys, &is_test, PREV_WIF);
    bool ret = btc_test_util_sign_p2pkh(&tx, 0, &prev_keys);
    printf("ret=%d\n", ret);

    btc_tx_print(&tx);
    // ======================================
    // txid= f2cff303c3f08882604dcfc8bf9a4c5ae26b2a2c23fa10c87db089492a0ba5aa
    // ======================================
    //  version:2
    //  txin_cnt=1
    //  [vin #0]
    //   txid= b072d8eab1580dae2047c0b92df54c3e5cc33825440e5e4f278e8e62e5575089
    //        LE: 895057e5628e8e274f5e0e442538c35c3e4cf52db9c04720ae0d58b1ead872b0
    //   index= 0
    //   scriptSig[106]= 473044022013953d643b12ab2f24ec6b822f7e634dc82c0454a72508ccf47f405c7696692902207dcd6083cf5ec7c8a57bf432056d1a744fc652f814edfeec54869dd241a9a899012102b9caeb43d35763f199b8617c541249392925112a40097a0666cd64d462258bed
    //       47 3044022013953d643b12ab2f24ec6b822f7e634dc82c0454a72508ccf47f405c7696692902207dcd6083cf5ec7c8a57bf432056d1a744fc652f814edfeec54869dd241a9a89901
    //       21 02b9caeb43d35763f199b8617c541249392925112a40097a0666cd64d462258bed
    //   sequence= 0xffffffff
    //  txout_cnt= 1
    //  [vout #0]
    //   value= 998000  : 703a0f0000000000
    //        9.98000 mBTC, 0.00998000 BTC
    //   scriptPubKey[22]= 0014191df18ae4b043defbd290b046328cb4867eccff
    //       00
    //       14 191df18ae4b043defbd290b046328cb4867eccff
    //  locktime= 0x00000000 : block height
    // ======================================


    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&tx, &txbuf);
    utl_dbg_dump(stdout, txbuf.buf, txbuf.len, true);
    utl_buf_free(&txbuf);

    btc_tx_free(&tx);

    btc_term();

    return 0;
}

#elif defined(USE_ELEMENTS)
int tx_create_ele1(void)
{
    btc_init(BTC_BLOCK_CHAIN_LIQREGTEST, false);

    //
    //previous vout
    //      P2WPKH nested in BIP16 P2SH
    //

    // 062c49302d5a56e94e2cd3e7d06d79ec84b34ab8540843f73ce862a558fb661d: vout#1
    // {
    //   "value": 1.99390420,
    //   "asset": "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23",
    //   "commitmentnonce": "",
    //   "commitmentnonce_fully_valid": false,
    //   "n": 1,
    //   "scriptPubKey": {
    //     "asm": "OP_HASH160 d9055d0f9b3fdac0f3d40b23d585d947ce9e855a OP_EQUAL",
    //     "hex": "a914d9055d0f9b3fdac0f3d40b23d585d947ce9e855a87",
    //     "reqSigs": 1,
    //     "type": "scripthash",
    //     "addresses": [
    //       "XX8juSEjnPy8cmzY8HPvqcQG2BZPtnEoPX"
    //     ]
    //   }
    // },

    const char PREV_TXID_STR[] = "062c49302d5a56e94e2cd3e7d06d79ec84b34ab8540843f73ce862a558fb661d";
    const int PREV_TXINDEX = 1;
    const uint64_t PREV_AMOUNT = (uint64_t)199390420;

    // $ e1-cli dumpprivkey XX8juSEjnPy8cmzY8HPvqcQG2BZPtnEoPX
    const char PREV_WIF[] = "cV4h6oZwjnvnkpuDbhrptZsBNykd1ArM3fpPVvJemT1FsW4EofSS";

    btc_tx_t tx = BTC_TX_INIT;
    uint8_t PREV_TXID[BTC_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);
    btc_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);

    //
    //vout#0
    //
    {
        const char VOUT_ADDR[] = "ert1qp62saumthukmzdl5n8zyhclcm2nzw6f39vasypzsfdhw0wxfdgxs4vcw5c";
        const uint64_t AMOUNT = 100000;
        btc_tx_add_vout_addr(&tx, AMOUNT, VOUT_ADDR);
    }

    //
    //vout#1
    //
    {
        const char VOUT_ADDR[] = "XX8juSEjnPy8cmzY8HPvqcQG2BZPtnEoPX";
        const uint64_t AMOUNT = 199290070;
        btc_tx_add_vout_addr(&tx, AMOUNT, VOUT_ADDR);
    }

    //
    //vout#2
    //
    {
        const uint64_t AMOUNT = 350;
        btc_tx_add_vout_fee(&tx, AMOUNT);
    }

    btc_keys_t prev_keys;
    bool is_test;
    btc_keys_wif2keys(&prev_keys, &is_test, PREV_WIF);
    LOGD("privkey= ");
    DUMPD(prev_keys.priv, BTC_SZ_PRIVKEY);
    LOGD("pubkey= ");
    DUMPD(prev_keys.pub, BTC_SZ_PUBKEY);
    utl_buf_t script_code = UTL_BUF_INIT;
    btc_script_p2wpkh_create_scriptcode(&script_code, prev_keys.pub);
    LOGD("scriptCode= ");
    DUMPD(script_code.buf, script_code.len);

    bool ret = btc_test_util_sign_p2wpkh(&tx, 0, PREV_AMOUNT, &prev_keys);
    printf("ret=%d\n", ret);

    btc_tx_print(&tx);

#if 0
    //txid: 88d9554413c9b189061049ca682021e03dcd68d418955a75482df6a3c90edcd8
    //  raw: 0200000001011d66fb58a562e83cf7430854b84ab384ec796dd0e7d32c4ee9565a2d30492c060100000017160014bc4f5624e3a8e8e575560dee505029b69eb5ee5affffffff0301230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b20100000000000186a0002200200e950ef36bbf2db137f499c44be3f8daa62769312b3b0204504b6ee7b8c96a0d01230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000be0ecd60017a914d9055d0f9b3fdac0f3d40b23d585d947ce9e855a8701230f4f5d4b7c6fa845806ee4f67713459e1b69e8e60fcee2e4940c7a0d5de1b201000000000000015e00000000000000000247304402207e5771f6654468e74c429db9b28506015bba0f8147caa0153e76f1e0299b2b02022072480dfd733755a5a49804fde7ae2a301bde4da3a7fcd3af90304cdf9a7af8e1012102a7490c7e5d569aa2c722e7df8e10569ab9e809179e7e39b2ac9ca6b25b5f73e300000000000000
    const uint8_t TX_SIGNED[] = {0x02,0x00,0x00,0x00,0x01,0x01,0x1d,0x66,0xfb,0x58,0xa5,0x62,0xe8,0x3c,0xf7,0x43,0x08,0x54,0xb8,0x4a,0xb3,0x84,0xec,0x79,0x6d,0xd0,0xe7,0xd3,0x2c,0x4e,0xe9,0x56,0x5a,0x2d,0x30,0x49,0x2c,0x06,0x01,0x00,0x00,0x00,0x17,0x16,0x00,0x14,0xbc,0x4f,0x56,0x24,0xe3,0xa8,0xe8,0xe5,0x75,0x56,0x0d,0xee,0x50,0x50,0x29,0xb6,0x9e,0xb5,0xee,0x5a,0xff,0xff,0xff,0xff,0x03,0x01,0x23,0x0f,0x4f,0x5d,0x4b,0x7c,0x6f,0xa8,0x45,0x80,0x6e,0xe4,0xf6,0x77,0x13,0x45,0x9e,0x1b,0x69,0xe8,0xe6,0x0f,0xce,0xe2,0xe4,0x94,0x0c,0x7a,0x0d,0x5d,0xe1,0xb2,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x86,0xa0,0x00,0x22,0x00,0x20,0x0e,0x95,0x0e,0xf3,0x6b,0xbf,0x2d,0xb1,0x37,0xf4,0x99,0xc4,0x4b,0xe3,0xf8,0xda,0xa6,0x27,0x69,0x31,0x2b,0x3b,0x02,0x04,0x50,0x4b,0x6e,0xe7,0xb8,0xc9,0x6a,0x0d,0x01,0x23,0x0f,0x4f,0x5d,0x4b,0x7c,0x6f,0xa8,0x45,0x80,0x6e,0xe4,0xf6,0x77,0x13,0x45,0x9e,0x1b,0x69,0xe8,0xe6,0x0f,0xce,0xe2,0xe4,0x94,0x0c,0x7a,0x0d,0x5d,0xe1,0xb2,0x01,0x00,0x00,0x00,0x00,0x0b,0xe0,0xec,0xd6,0x00,0x17,0xa9,0x14,0xd9,0x05,0x5d,0x0f,0x9b,0x3f,0xda,0xc0,0xf3,0xd4,0x0b,0x23,0xd5,0x85,0xd9,0x47,0xce,0x9e,0x85,0x5a,0x87,0x01,0x23,0x0f,0x4f,0x5d,0x4b,0x7c,0x6f,0xa8,0x45,0x80,0x6e,0xe4,0xf6,0x77,0x13,0x45,0x9e,0x1b,0x69,0xe8,0xe6,0x0f,0xce,0xe2,0xe4,0x94,0x0c,0x7a,0x0d,0x5d,0xe1,0xb2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x5e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x47,0x30,0x44,0x02,0x20,0x7e,0x57,0x71,0xf6,0x65,0x44,0x68,0xe7,0x4c,0x42,0x9d,0xb9,0xb2,0x85,0x06,0x01,0x5b,0xba,0x0f,0x81,0x47,0xca,0xa0,0x15,0x3e,0x76,0xf1,0xe0,0x29,0x9b,0x2b,0x02,0x02,0x20,0x72,0x48,0x0d,0xfd,0x73,0x37,0x55,0xa5,0xa4,0x98,0x04,0xfd,0xe7,0xae,0x2a,0x30,0x1b,0xde,0x4d,0xa3,0xa7,0xfc,0xd3,0xaf,0x90,0x30,0x4c,0xdf,0x9a,0x7a,0xf8,0xe1,0x01,0x21,0x02,0xa7,0x49,0x0c,0x7e,0x5d,0x56,0x9a,0xa2,0xc7,0x22,0xe7,0xdf,0x8e,0x10,0x56,0x9a,0xb9,0xe8,0x09,0x17,0x9e,0x7e,0x39,0xb2,0xac,0x9c,0xa6,0xb2,0x5b,0x5f,0x73,0xe3,0x00,0x00,0x00,0x00,0x00,0x00,0x00,};
    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&tx, &txbuf);
    DUMPD(txbuf.buf, txbuf.len);
    if ((sizeof(TX_SIGNED) == txbuf.len) && (memcmp(TX_SIGNED, txbuf.buf, sizeof(TX_SIGNED)) == 0)) {
        printf("OK\n");
    } else {
        printf("fail: signed tx not same\n");
        assert(false);
    }
    utl_buf_free(&txbuf);
#endif

    btc_tx_free(&tx);

    btc_term();

    return 0;
}
#endif

int main(void)
{
    utl_log_init_stdout();

#if defined(USE_BITCOIN)
    tx_create1();
    tx_create2();
    tx_create3();
    tx_create4();
    tx_create5();
#elif defined(USE_ELEMENTS)
    tx_create_ele1();
#endif

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

