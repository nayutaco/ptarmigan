#ifndef WALLET_H__
#define WALLET_H__

bool wallet_from_ptarm(char **ppRawTx, const char *pAddr, uint32_t FeeratePerKw);
bool wallet_to_ptarm(void);

#endif /* WALLET_H__ */
