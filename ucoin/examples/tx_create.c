#include <stdio.h>

#include "ucoin.h"

extern bool ulog_init_stderr(void);


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
    ucoin_init(UCOIN_TESTNET, false);       //VIN: not native

    //
    //previous vout
    //      P2WPKH nested in BIP16 P2SH
    //

    //txid:dae822e5209c487cab3977823c4890239bcad1d1ae15973f66dbdff794ccb9e2 : 1
    const uint8_t PREV_TXID[] = {
        0xe2, 0xb9, 0xcc, 0x94, 0xf7, 0xdf, 0xdb, 0x66,
        0x3f, 0x97, 0x15, 0xae, 0xd1, 0xd1, 0xca, 0x9b,
        0x23, 0x90, 0x48, 0x3c, 0x82, 0x77, 0x39, 0xab,
        0x7c, 0x48, 0x9c, 0x20, 0xe5, 0x22, 0xe8, 0xda,
    };
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


    ucoin_tx_t tx = UCOIN_TX_INIT;

    ucoin_vin_t *vin = ucoin_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);
    ucoin_buf_t *pRedeem = ucoin_tx_add_wit(vin);
    ucoin_buf_alloccopy(pRedeem, PREV_VOUT_REDEEM, sizeof(PREV_VOUT_REDEEM));

    ucoin_tx_add_vout_addr(&tx, PREV_AMOUNT - FEE, NEW_VOUT_ADDR);

    ucoin_util_keys_t prev_keys;
    ucoin_chain_t chain;
    ucoin_util_wif2keys(&prev_keys, &chain, PREV_WIF);
    bool ret = ucoin_util_sign_p2wpkh(&tx, 0, PREV_AMOUNT, &prev_keys);
    printf("ret=%d\n", ret);

    ucoin_print_tx(&tx);
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


    ucoin_buf_t txbuf = UCOIN_BUF_INIT;
    ucoin_tx_create(&txbuf, &tx);
    ucoin_util_dumpbin(stdout, txbuf.buf, txbuf.len, true);
    ucoin_buf_free(&txbuf);

    // $ bitcoin-cli sendrawtransaction 02000000000101e2b9cc94f7dfdb663f9715aed1d1ca9b2390483c827739ab7c489c20e522e8da01000000171600141bf9d39538ae6adc7a1683face78c62f0cf2e27cffffffff01058201000000000017a9142810a73d941022f4ff6b78878fadf5fb42a888a68702483045022100f34ea94cc2b4ddd8a898c5ae3c9bf80f83673f24e7c17314b5e9721e7103886002201b2d5d45754fb4796efb33042a829e3f93d581d4b7f3c6ce13d2ec5fb061bae2012103f8dd7803e1247535b8edf1a41b490d37a377be1f6d41c83cc7a8e2330dc3416600000000
    // 341cc3d10ef50cfe3161c72fa4f150382ff11428642fa87074f18551949c9d6f

    ucoin_tx_free(&tx);

    ucoin_term();

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
    ucoin_init(UCOIN_TESTNET, true);        //VIN: native

    //
    //previous vout
    //      P2WPKH native
    //

    //txid:9a17cceee2d21db38b6272efdfd13c10b3a60f8eb346a538c5603ffd55628ea7 : 1
    const uint8_t PREV_TXID[] = {
        0xa7, 0x8e, 0x62, 0x55, 0xfd, 0x3f, 0x60, 0xc5,
        0x38, 0xa5, 0x46, 0xb3, 0x8e, 0x0f, 0xa6, 0xb3,
        0x10, 0x3c, 0xd1, 0xdf, 0xef, 0x72, 0x62, 0x8b,
        0xb3, 0x1d, 0xd2, 0xe2, 0xee, 0xcc, 0x17, 0x9a,
    };
    const int PREV_TXINDEX = 1;
    const uint64_t PREV_AMOUNT = (uint64_t)1000000;
    const char PREV_WIF[] = "cVPaYCkmnAq7ctxEf3a13qqafK598bxEsGQBAQ2nVJd9X5KhmViL";


    //
    //vout
    //
    const char NEW_VOUT_ADDR[] = "2Mvu4y3iKWyMcWmNoTptMxNka6YcFkC5mNR";
    const uint64_t FEE = 1000;


    ucoin_tx_t tx = UCOIN_TX_INIT;

    ucoin_tx_add_vin(&tx, PREV_TXID, PREV_TXINDEX);

    ucoin_tx_add_vout_addr(&tx, PREV_AMOUNT - FEE, NEW_VOUT_ADDR);

    ucoin_util_keys_t prev_keys;
    ucoin_chain_t chain;
    ucoin_util_wif2keys(&prev_keys, &chain, PREV_WIF);
    bool ret = ucoin_util_sign_p2wpkh(&tx, 0, PREV_AMOUNT, &prev_keys);
    printf("ret=%d\n", ret);

    ucoin_print_tx(&tx);
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


    ucoin_buf_t txbuf = UCOIN_BUF_INIT;
    ucoin_tx_create(&txbuf, &tx);
    ucoin_util_dumpbin(stdout, txbuf.buf, txbuf.len, true);
    ucoin_buf_free(&txbuf);

    // $ bitcoin-cli sendrawtransaction 02000000000101a78e6255fd3f60c538a546b38e0fa6b3103cd1dfef72628bb31dd2e2eecc179a0100000000ffffffff01583e0f000000000017a9142810a73d941022f4ff6b78878fadf5fb42a888a68702483045022100a1971b418033d8e198e946f6bbf86c1bd6bff749bbffeeca1dd1168201676bbf022031d20ca73bce80261cac2227c157a5e1ee219db27a77c0e47f3ce2a4931621360121037321e275c52eafcd002e53b741bad8db1cd357e71ad3ef811d879070eddffd3100000000
    // cc4c95e4f27788ae40a7a8254657682206518b8585a043f9b42177b37ee866d7

    ucoin_tx_free(&tx);

    ucoin_term();

    return 0;
}


int main(void)
{
    ulog_init_stderr();

    tx_create1();
    tx_create2();

    return 0;
}
