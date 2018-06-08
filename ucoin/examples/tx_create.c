#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "ucoin.h"

extern bool ulog_init_stderr(void);
static bool misc_str2bin(uint8_t *pBin, uint32_t BinLen, const char *pStr);
static bool misc_str2bin_rev(uint8_t *pBin, uint32_t BinLen, const char *pStr);


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


    uint8_t PREV_TXID[UCOIN_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


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
    ucoin_init(UCOIN_TESTNET, true);        //VIN: native

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


    uint8_t PREV_TXID[UCOIN_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


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
    ucoin_init(UCOIN_TESTNET, true);        //VIN: native

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


    uint8_t PREV_TXID[UCOIN_SZ_TXID];
    misc_str2bin_rev(PREV_TXID, sizeof(PREV_TXID), PREV_TXID_STR);


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


    ucoin_buf_t txbuf = UCOIN_BUF_INIT;
    ucoin_tx_create(&txbuf, &tx);
    ucoin_util_dumpbin(stdout, txbuf.buf, txbuf.len, true);
    ucoin_buf_free(&txbuf);

    // $ bitcoin-cli sendrawtransaction 02000000000101bef916318123a1877fd012f2965e08c53257076e11afd52bbe2c244f2ab960890100000000ffffffff01583e0f0000000000160014a782f82af08ce48820cc402f6f7b346aa3daa4e802483045022100aad64cb35d5d7ddae6ecceaece136a43173e8ef73fa55365f466038be2ebc36b0220548ace73fa23c78e9d35d454b97c83228cbc47a78fd28ddf197e02c754594138012103158b0e57aafb5e16e6fb5ad375d423376bc45fbe8e4a841d7cdfaf8116d537b000000000
    // 78bb06807dd07254ad3cdb3c49ec05b726f641a69ee41c581201f6d38912a6fe

    ucoin_tx_free(&tx);

    ucoin_term();

    return 0;
}


int main(void)
{
    ulog_init_stderr();

    //tx_create1();
    //tx_create2();
    tx_create3();

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

