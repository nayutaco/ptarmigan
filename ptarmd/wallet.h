#ifndef WALLET_H__
#define WALLET_H__

/** DBで保持しているclosingのvoutをwalletに戻す
 *      [bitcoind]sendrawtransaction用の文字列
 *      [SPV]展開後のTXID文字列
 * 
 * @param[out]      ppResult        結果文字列
 * @param[out]      pAmount         pAddrへ送金するamount[satoshis]
 * @param[in]       bToSend         true:送金を行う / false:amountだけ求める
 * @param[in]       pAddr           送金先アドレス
 * @param[in]       FeeratePerKw    feerate_per_kw
 */
bool wallet_from_ptarm(char **ppResult, uint64_t *pAmount, bool bToSend, const char *pAddr, uint32_t FeeratePerKw);


bool wallet_to_ptarm(void);

#endif /* WALLET_H__ */
