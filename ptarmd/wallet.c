#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "cJSON.h"

#define LOG_TAG     "wallet"
#include "utl_log.h"

#include "btc_crypto.h"
#include "btc_sig.h"
#include "btc_script.h"
#include "btc_sw.h"

#include "ptarmd.h"
#include "btcrpc.h"


/********************************************************************
 * prototypes
 ********************************************************************/

typedef struct {
    btc_tx_t        tx;
    uint64_t        amount;
    int32_t         block_count;    //mined_height相当
    cJSON           *p_list;        //outpoint
} wallet_t;


/********************************************************************
 * prototypes
 ********************************************************************/

static bool wallet_dbfunc(const ln_db_wallet_t *pWallet, void *p_param);


/********************************************************************
 * public functions
 ********************************************************************/

// ptarmiganから外部walletへ送金
bool wallet_from_ptarm(void *pJson, bool bToSend, const char *pAddr, uint32_t FeeratePerKw)
{
    bool ret;
    wallet_t wallet;
    uint8_t txhash[BTC_SZ_HASH256];
    char str_msg[512] = "";
    uint64_t vout_amount = 0;

    cJSON *p_result = (cJSON *)pJson;

    LOGD("sendto=%s, feerate_per_kw=%" PRIu32 "\n", pAddr, FeeratePerKw);

    ret = btcrpc_getblockcount(&wallet.block_count, NULL);
    if (!ret) {
        LOGE("fail\n");
        return false;
    }

    btc_tx_init(&wallet.tx);
    wallet.amount = 0;
    if (p_result != NULL) {
        wallet.p_list = cJSON_CreateArray();
    } else {
        wallet.p_list = NULL;
    }

    ln_db_wallet_search(wallet_dbfunc, &wallet);
    if (wallet.tx.vin_cnt == 0) {
        ret = true;
        strcpy(str_msg, "no input");
        LOGE("%s\n", str_msg);
        goto LABEL_EXIT;
    }

    ret = btc_tx_add_vout_addr(&wallet.tx, wallet.amount, pAddr); //feeを引く前
    if (!ret) {
        strcpy(str_msg, "btc_tx_add_vout_addr");
        LOGE("%s\n", str_msg);
        goto LABEL_EXIT;
    }

    //fee計算(wit[0]に仮データを入れているので、vbyteの計算に注意)
    //wit[0]
    //  [32:privkey] + [1:type] + [8:amount]
    uint64_t fee = 0;
    {
        const int SZ_SIGN = 72;             //署名サイズを72byteと仮定
        utl_buf_t txbuf = UTL_BUF_INIT;
        btc_tx_write(&wallet.tx, &txbuf);   //wallet.tx.vin[]には仮データが入っている(32+1+8)
        uint32_t weight = btc_tx_get_weight_raw(txbuf.buf, txbuf.len);
        weight += ((SZ_SIGN - (32+1+8)) * wallet.tx.vin_cnt);   //weightではwitnessを1回だけ加算
        LOGD("weight=%d\n", weight);
        fee = ((uint64_t)weight * (uint64_t)FeeratePerKw + 999) / 1000;
        LOGD("fee=%" PRIu64 "\n", fee);
        if (fee + BTC_DUST_LIMIT > wallet.tx.vout[0].value) {
            snprintf(str_msg, sizeof(str_msg),
                "fail: amount(%" PRIu64 ") is too low to send(fee=%" PRIu64 ", dust=%" PRIu64 ")",
                    wallet.tx.vout[0].value, fee, BTC_DUST_LIMIT);
            LOGE("%s\n", str_msg);
            ret = true;
            goto LABEL_EXIT;
        }

        utl_buf_free(&txbuf);
    }
    wallet.tx.vout[0].value -= fee;
    vout_amount = wallet.tx.vout[0].value;

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

        //LOGD("[%d]secret: ", lp);
        //DUMPD(p_secret, BTC_SZ_PRIVKEY);
        LOGD("[%d]\n", lp);
        LOGD("   type: %02x\n", type);
        LOGD("   amount: %" PRIu64 "\n", amount);

        utl_buf_t sigbuf = UTL_BUF_INIT;
        utl_buf_t script_code = UTL_BUF_INIT;
        switch (type) {
        case LN_DB_WALLET_TYPE_TO_REMOTE:
            btc_script_p2wpkh_create_scriptcode(&script_code, p_vin->witness[1].buf);
            ret = btc_sw_sighash(&wallet.tx, txhash, lp, amount, &script_code);
            break;
        case LN_DB_WALLET_TYPE_TO_LOCAL:
        case LN_DB_WALLET_TYPE_HTLC_OUTPUT:
            ret = btc_sw_sighash_p2wsh_wit(&wallet.tx, txhash, lp, amount,
                                                &p_vin->witness[p_vin->wit_item_cnt-1]);
            break;
        default:
            LOGE("fail: invalid type=%d\n", type);
        }
        if (ret) {
            ret = btc_sig_sign(&sigbuf, txhash, p_secret);
        } else {
            LOGE("fail: btc_sw_sighash_p2wsh_wit()\n");
        }
        if (ret) {
            //wit[0]: signature
            utl_buf_free(&p_vin->witness[0]);
            utl_buf_alloccopy(&p_vin->witness[0], sigbuf.buf, sigbuf.len);
        } else {
            LOGE("fail: btc_sig_sign()\n");
        }
        utl_buf_free(&sigbuf);
        utl_buf_free(&script_code);
    }

    btc_tx_print(&wallet.tx);
    utl_buf_t txbuf = UTL_BUF_INIT;
    btc_tx_write(&wallet.tx, &txbuf);
    LOGD("raw=");
    DUMPD(txbuf.buf, txbuf.len);

    if (bToSend) {
        //broadcast
        uint8_t txid[BTC_SZ_TXID];
        ret = btcrpc_send_rawtx(txid, NULL, txbuf.buf, txbuf.len);
        if (ret) {
            //remove from DB
            LOGD("$$$ broadcast\n");
            for (uint32_t lp = 0; lp < wallet.tx.vin_cnt; lp++) {
                ln_db_wallet_del(wallet.tx.vin[lp].txid, wallet.tx.vin[lp].index);
            }

            char str_txid[BTC_SZ_TXID * 2 + 1];
            utl_str_bin2str_rev(str_txid, txid, BTC_SZ_TXID);
            snprintf(str_msg, sizeof(str_msg), "pay to '%s', txid=%s", pAddr, str_txid);
        } else {
            LOGE("fail: broadcast\n");
        }
    } else {
        snprintf(str_msg, sizeof(str_msg),
            "Can pay to wallet(fee=%" PRIu64 ")",
                fee);
    }
    utl_buf_free(&txbuf);

    btc_tx_free(&wallet.tx);

LABEL_EXIT:
    if (p_result != NULL) {
        cJSON *p_message = cJSON_CreateObject();
        cJSON_AddStringToObject(p_message, "message", str_msg);
        cJSON_AddNumber64ToObject(p_message, "amount", vout_amount);
        cJSON_AddItemToObject(p_result, "wallet", p_message);
        cJSON_AddItemToObject(p_result, "list", wallet.p_list);
    }
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
    wallet_t *p_wlt = (wallet_t *)p_param;

    LOGD("txid=");
    TXIDD(pWallet->p_txid);
    LOGD("index=%d\n", pWallet->index);
    LOGD("amount=%" PRIu64 "\n", pWallet->amount);
    LOGD("cnt=%d\n", pWallet->wit_item_cnt);
    for (uint8_t lp = 0; lp < pWallet->wit_item_cnt; lp++) {
        LOGD("[%d][%d]", lp, pWallet->p_wit_items[lp].len);
        DUMPD(pWallet->p_wit_items[lp].buf, pWallet->p_wit_items[lp].len);
    }
    LOGD("sequence=%d\n", pWallet->sequence);
    LOGD("locktime=%d\n", p_wlt->tx.locktime);
    LOGD("mined_height=%d\n", pWallet->mined_height);

    if (pWallet->wit_item_cnt == 0) {
        LOGE("no witness\n");
        return false;
    }

#if defined(USE_BITCOIND)
    bool unspent;
    bool ret = btcrpc_check_unspent(NULL, &unspent, NULL, pWallet->p_txid, pWallet->index);
    if (!ret || !unspent) {
        LOGE("fail btcrpc_check_unspent() or already spent\n");
        //remain DB if you cannot get.
        //ln_db_wallet_del(pWallet->p_txid, pWallet->index);
        return false;
    }
#elif defined(USE_BITCOINJ)
    bool ret;
#endif

    if (pWallet->p_wit_items[0].len != BTC_SZ_PRIVKEY) {
        LOGE("FATAL: maybe BUG\n");
        return false;
    }

    ret = true;
    char str_msg[512];
    if ( (pWallet->sequence != BTC_TX_SEQUENCE) ||
         ((p_wlt->tx.locktime != 0) && (p_wlt->tx.locktime < BTC_TX_LOCKTIME_LIMIT)) ) {
        uint32_t confm;
#if defined(USE_BITCOIND)
        ret = btcrpc_get_confirmations(&confm, pWallet->p_txid);
#elif defined(USE_BITCOINJ)
        confm = p_wlt->block_count - pWallet->mined_height + 1;
        LOGD("confirm=%d\n", (int)confm);
#endif
        if (ret) {
            if (pWallet->sequence != BTC_TX_SEQUENCE) {
                if (confm < pWallet->sequence) {
                    snprintf(str_msg, sizeof(str_msg),
                        "less confirmation(current=%" PRIu32 ", need=%" PRIu32 ")",
                            confm, pWallet->sequence);
                    LOGD("%s\n", str_msg);
                    ret = false;
                }
            } else {
                if (confm < p_wlt->tx.locktime) {
                    snprintf(str_msg, sizeof(str_msg),
                        "less confirmation(current=%" PRIu32 ", need=%" PRIu32 ")",
                            confm, p_wlt->tx.locktime);
                    LOGD("%s\n", str_msg);
                    ret = false;
                }
            }
        } else {
            strcpy(str_msg, "fail get confirmation");
            LOGD("%s\n", str_msg);
        }
    }

    if (!ret) {
        goto LABEL_EXIT;
    }
    strcpy(str_msg, "payable");

    p_wlt->amount += pWallet->amount;
    btc_vin_t *p_vin = btc_tx_add_vin(&p_wlt->tx,
                            pWallet->p_txid, pWallet->index);
    utl_buf_t *p_wit_items = btc_tx_add_wit(p_vin);

    p_vin->sequence = pWallet->sequence;
    if (p_wlt->tx.locktime < pWallet->locktime) {
        p_wlt->tx.locktime = pWallet->locktime;
    }

    //wit[0]
    //  [32:privkey]
    //     ↓↓↓
    //  [32:privkey] + [1:type] + [8:amount]
    LOGD("wit[0][%d] ", pWallet->p_wit_items[0].len);
    DUMPD(pWallet->p_wit_items[0].buf, pWallet->p_wit_items[0].len);
    utl_buf_realloc(p_wit_items,
            BTC_SZ_PRIVKEY + sizeof(uint8_t) + sizeof(uint64_t));
    uint8_t *p = p_wit_items->buf;
    memcpy(p, pWallet->p_wit_items[0].buf, pWallet->p_wit_items[0].len);
    p += BTC_SZ_PRIVKEY;
    *p = pWallet->type;
    p++;
    memcpy(p, &pWallet->amount, sizeof(uint64_t));
    //p += sizeof(uint64_t);

    LOGD("  --> wit[0][%d] ", p_wit_items[0].len);
    DUMPD(p_wit_items[0].buf, p_wit_items[0].len);

    //残りwitをコピー
    for (uint8_t lp = 1; lp < pWallet->wit_item_cnt; lp++) {
        utl_buf_t *p_wit_items = btc_tx_add_wit(p_vin);
        utl_buf_alloccopy(p_wit_items, pWallet->p_wit_items[lp].buf, pWallet->p_wit_items[lp].len);
        LOGD("wit[%d][%d] ", lp, p_wit_items->len);
        DUMPD(p_wit_items->buf, p_wit_items->len);
    }

LABEL_EXIT:
    if (p_wlt->p_list != NULL) {
        cJSON *p_json = cJSON_CreateObject();
        const char *p_type_str;
        switch (pWallet->type) {
        case LN_DB_WALLET_TYPE_TO_LOCAL:
            p_type_str = "to_local output";
            break;
        case LN_DB_WALLET_TYPE_TO_REMOTE:
            p_type_str = "to_remote output";
            break;
        case LN_DB_WALLET_TYPE_HTLC_OUTPUT:
            p_type_str = "HTLC_tx output";
            break;
        default:
            p_type_str = "unknown";
        }
        cJSON_AddStringToObject(p_json, "type", p_type_str);

        char outpoint[BTC_SZ_TXID * 2 + 1 + 10];
        utl_str_bin2str_rev(outpoint, pWallet->p_txid, BTC_SZ_TXID);
        char idx[5];
        (void)utl_str_itoa(idx, sizeof(idx), pWallet->index);
        strncat(outpoint, ":", sizeof(outpoint) - 1);
        strncat(outpoint, idx, sizeof(outpoint));
        outpoint[sizeof(outpoint) - 1] = '\0';
        cJSON_AddStringToObject(p_json, "outpoint", outpoint);
        cJSON_AddNumber64ToObject(p_json, "amount", pWallet->amount);
        cJSON_AddStringToObject(p_json, "state", str_msg);

        cJSON_AddItemToArray(p_wlt->p_list, p_json);

    }
    return false;       //継続
}
