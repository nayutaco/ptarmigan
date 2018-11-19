#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "btcrpc.h"
#include "ln.h"
#include "ln_db.h"


/********************************************************************
 * prototypes
 ********************************************************************/

typedef struct {
    btc_tx_t        tx;
    uint64_t        amount;
} wallet_t;


/********************************************************************
 * prototypes
 ********************************************************************/

static bool wallet_dbfunc(const ln_db_wallet_t *pWallet, void *p_param);


/********************************************************************
 * public functions
 ********************************************************************/

// ptarmiganから外部walletへ送金
bool wallet_from_ptarm(char **ppRawTx, const char *pAddr, uint32_t FeeratePerKw)
{
    bool ret;
    wallet_t wallet;
    uint8_t txhash[BTC_SZ_HASH256];

    btc_tx_init(&wallet.tx);
    wallet.amount = 0;

    ln_db_wallet_search(wallet_dbfunc, &wallet);
    if (wallet.tx.vin_cnt == 0) {
        LOGD("no input\n");
        ret = false;
        goto LABEL_EXIT;
    }

    ret = btc_tx_add_vout_addr(&wallet.tx, wallet.amount, pAddr); //feeを引く前
    if (!ret) {
        LOGD("fail: btc_tx_add_vout_addr");
        goto LABEL_EXIT;
    }

    //fee計算(wit[0]に仮データを入れているので、vbyteの計算に注意)
    //wit[0]
    //  [32:privkey] + [1:type] + [8:amount]
    {
        utl_buf_t txbuf = UTL_BUF_INIT;
        btc_tx_create(&txbuf, &wallet.tx);
        uint32_t vbyte = btc_tx_get_vbyte_raw(txbuf.buf, txbuf.len);
        vbyte += (72 - (32+1+8)) * wallet.tx.vin_cnt / 4;    //署名サイズを72byteとして計算
                                                        //vbyteはwitness/4だけ増加
        LOGD("vbyte=%d\n", vbyte);
        wallet.tx.vout[0].value -= (uint64_t)vbyte * (uint64_t)FeeratePerKw * 4 / 1000;
        utl_buf_free(&txbuf);
    }

    //署名
    for (uint32_t lp = 0; lp < wallet.tx.vin_cnt; lp++) {
        btc_vin_t *p_vin = &wallet.tx.vin[lp];
        const uint8_t *p = p_vin->witness[0].buf;
        const uint8_t *p_secret = p;
        p += BTC_SZ_PRIVKEY;
        uint8_t type = *p;
        p++;
        uint64_t amount;
        memcpy(&amount, p, sizeof(uint64_t));
        //p += sizeof(uint64_t);

        // LOGD("secret: ");
        // DUMPD(p_secret, BTC_SZ_PRIVKEY);
        // LOGD("type: %02x\n", type);
        // LOGD("amount: %" PRIu64 "\n", amount);

        utl_buf_t sigbuf = UTL_BUF_INIT;
        utl_buf_t script_code = UTL_BUF_INIT;
        switch (type) {
        case LN_DB_WALLET_TYPE_TOREMOTE:
            btc_sw_scriptcode_p2wpkh(&script_code, p_vin->witness[1].buf);
            ret = btc_sw_sighash(txhash, &wallet.tx, lp, amount, &script_code);
            break;
        case LN_DB_WALLET_TYPE_TOLOCAL:
        case LN_DB_WALLET_TYPE_HTLCOUT:
            ret = btc_util_calc_sighash_p2wsh(txhash, &wallet.tx, lp, amount,
                                                &p_vin->witness[p_vin->wit_cnt-1]);
            break;
        default:
            LOGD("fail: invalid type=%d\n", type);
        }
        if (ret) {
            ret = btc_tx_sign(&sigbuf, txhash, p_secret);
        } else {
            LOGD("fail: btc_util_calc_sighash_p2wsh()\n");
        }
        if (ret) {
            //wit[0]: signature
            utl_buf_free(&p_vin->witness[0]);
            utl_buf_alloccopy(&p_vin->witness[0], sigbuf.buf, sigbuf.len);
        } else {
            LOGD("fail: btc_tx_sign()\n");
        }
        utl_buf_free(&sigbuf);
        utl_buf_free(&script_code);
    }

    btc_print_tx(&wallet.tx);
    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_create(&txbuf, &wallet.tx);
    LOGD("raw=");
    DUMPD(txbuf.buf, txbuf.len);
    *ppRawTx = (char *)UTL_DBG_MALLOC(txbuf.len * 2 + 1);
    utl_misc_bin2str(*ppRawTx, txbuf.buf, txbuf.len);
    utl_buf_free(&txbuf);

    btc_tx_free(&wallet.tx);

LABEL_EXIT:
    return ret;
}


// 外部walletからptarmiganへ送金
bool wallet_to_ptarm(void)
{
    return false;
}


/********************************************************************
 * private functions
 ********************************************************************/

static bool wallet_dbfunc(const ln_db_wallet_t *pWallet, void *p_param)
{
    LOGD("txid=");
    TXIDD(pWallet->p_txid);
    LOGD("index=%d\n", pWallet->index);
    // LOGD("amount=%" PRIu64 "\n", pWallet->amount);
    // LOGD("cnt=%d\n", pWallet->wit_cnt);
    // for (uint8_t lp = 0; lp < pWallet->wit_cnt; lp++) {
    //     LOGD("[%d][%d]", lp, pWallet->p_wit[lp].len);
    //     DUMPD(pWallet->p_wit[lp].buf, pWallet->p_wit[lp].len);
    // }

    bool ret;
    wallet_t *p_wlt = (wallet_t *)p_param;

    if (pWallet->wit_cnt == 0) {
        LOGD("no witness\n");
        return false;
    }

    //INPUT確認
    ret = btcrpc_is_tx_broadcasted(pWallet->p_txid);
    if (!ret) {
        LOGD("not broadcasted\n");
        return false;
    }
    bool unspent;
    ret = btcrpc_check_unspent(NULL, &unspent, NULL, pWallet->p_txid, pWallet->index);
    if (ret && !unspent) {
        LOGD("not unspent\n");
        ln_db_wallet_del(pWallet->p_txid, pWallet->index);
        return false;
    }

    if (pWallet->p_wit[0].len != BTC_SZ_PRIVKEY) {
        LOGD("FATAL: maybe BUG\n");
        return false;
    }

    p_wlt->amount += pWallet->amount;
    btc_vin_t *p_vin = btc_tx_add_vin(&p_wlt->tx,
                            pWallet->p_txid, pWallet->index);
    utl_buf_t *p_wit = btc_tx_add_wit(p_vin);

    p_vin->sequence = pWallet->sequence;
    if (p_wlt->tx.locktime < pWallet->locktime) {
        p_wlt->tx.locktime = pWallet->locktime;
    }

    //wit[0]
    //  [32:privkey]
    //     ↓↓↓
    //  [32:privkey] + [1:type] + [8:amount]
    // LOGD("wit[0][%d] ", pWallet->p_wit[0].len);
    // DUMPD(pWallet->p_wit[0].buf, pWallet->p_wit[0].len);
    utl_buf_realloc(p_wit,
            BTC_SZ_PRIVKEY + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t *p = p_wit->buf;
    memcpy(p, pWallet->p_wit[0].buf, pWallet->p_wit[0].len);
    p += BTC_SZ_PRIVKEY;
    *p = pWallet->type;
    p++;
    memcpy(p, &pWallet->amount, sizeof(uint64_t));
    //p += sizeof(uint64_t);
    // LOGD("  --> wit[0][%d] ", p_wit[0].len);
    // DUMPD(p_wit[0].buf, p_wit[0].len);

    //残りwitをコピー
    for (uint8_t lp = 1; lp < pWallet->wit_cnt; lp++) {
        utl_buf_t *p_wit = btc_tx_add_wit(p_vin);
        utl_buf_alloccopy(p_wit, pWallet->p_wit[lp].buf, pWallet->p_wit[lp].len);
        // LOGD("wit[%d][%d] ", lp, p_wit->len);
        // DUMPD(p_wit->buf, p_wit->len);
    }

    return false;       //継続
}

