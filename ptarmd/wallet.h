#ifndef WALLET_H__
#define WALLET_H__

/** DBで保持しているclosingのvoutをwalletに戻す
 *      [bitcoind]sendrawtransaction用の文字列
 *      [SPV]展開後のTXID文字列
 * 
 * @param[out]      ppResult        結果文字列
 * @param[in]       pAddr           送金先アドレス
 * @param[in]       FeeratePerKb    feerate per 1000byte
 */
bool wallet_from_ptarm(char **ppResult, const char *pAddr, uint32_t FeeratePerKb);


bool wallet_to_ptarm(void);

#endif /* WALLET_H__ */
