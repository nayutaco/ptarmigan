#ifndef WALLET_H__
#define WALLET_H__

/** DBで保持しているclosingのvoutをwalletに戻す
 *      [bitcoind]sendrawtransaction用の文字列
 *      [SPV]展開後のTXID文字列
 */
bool wallet_from_ptarm(char **ppResult, const char *pAddr, uint32_t FeeratePerKw);
bool wallet_to_ptarm(void);

#endif /* WALLET_H__ */
