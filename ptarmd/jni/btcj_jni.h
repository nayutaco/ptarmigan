#ifndef BTCJ_JNI_H__
#define BTCJ_JNI_H__

#include <inttypes.h>
#include <stdbool.h>

#include "btc.h"


typedef struct {
    uint8_t		*buf;
    uint32_t	len;
} btcj_buf_t;

//共通
//  btcrpc_bitcoinj.c : kJniFuncs[]
//  btcj_jni.c        : kMethod[]
typedef enum {
    METHOD_PTARM_SETCREATIONHASH,
    METHOD_PTARM_GETBLOCKCOUNT,
    METHOD_PTARM_GETGENESISBLOCKHASH,
    METHOD_PTARM_GETCONFIRMATION,
    METHOD_PTARM_GETSHORTCHANNELPARAM,
    METHOD_PTARM_GETTXIDFROMSHORTCHANNELID,
    METHOD_PTARM_SEARCHOUTPOINT,
    METHOD_PTARM_SEARCHVOUT,
    METHOD_PTARM_SIGNRAWTX,
    METHOD_PTARM_SENDRAWTX,
    METHOD_PTARM_CHECKBROADCAST,
    METHOD_PTARM_CHECKUNSPENT,
    METHOD_PTARM_GETNEWADDRESS,
    METHOD_PTARM_ESTIMATEFEE,
    METHOD_PTARM_SETCHANNEL,
    METHOD_PTARM_DELCHANNEL,
    METHOD_PTARM_SETCOMMITTXID,
    METHOD_PTARM_GETBALANCE,
    METHOD_PTARM_EMPTYWALLET,
    //
    METHOD_PTARM_MAX
} btcj_method_t;


bool btcj_init(btc_block_chain_t Gen);
bool btcj_release(void);
void btcj_setcreationhash(const uint8_t *pHash);
int32_t btcj_getblockcount(uint8_t *pHash);
bool btcj_getgenesisblockhash(uint8_t *pHash);


/** get confirmation
 * 
 *  @param[in]      pTxid
 *  @retval     >0  confirmation count
 *  @retval     <=0 fail
 */
uint32_t btcj_gettxconfirm(const uint8_t *pTxid);


bool btcj_get_short_channel_param(const uint8_t *pPeerId, int32_t *pHeight, int32_t *pbIndex, uint8_t *pMinedHash);
bool btcj_gettxid_from_short_channel(uint64_t ShortChannelId, uint8_t **ppTxid);
bool btcj_search_outpoint(btcj_buf_t **ppTx, uint32_t Blks, const uint8_t *pTxid, uint32_t VIndex);
bool btcj_search_vout(btcj_buf_t **ppTxBuf, uint32_t blks, const btcj_buf_t *pVout);
bool btcj_signraw_tx(uint64_t Amount, const btcj_buf_t *pScriptPubKey, btcj_buf_t **ppTxData);
bool btcj_sendraw_tx(uint8_t *pTxid, int *pCode, const btcj_buf_t *pTxData);
bool btcj_is_tx_broadcasted(const uint8_t *pTxid);
bool btcj_check_unspent(const uint8_t *pPeerId, bool *pUnspent, const uint8_t *pTxid, uint32_t VIndex);
bool btcj_getnewaddress(char *pAddr);
bool btcj_estimatefee(uint64_t *pFeeSatoshi, int Blks);
void btcj_set_channel(
    const uint8_t *pPeerId,
    uint64_t ShortChannelId,
    const uint8_t *pFundingTxid,
    int FundingIndex,
    const uint8_t *pScriptPubKey,
    const uint8_t *pMinedHash,
    uint32_t LastConfirm);
void btcj_del_channel(const uint8_t *pPeerId);
// void btcj_set_committxid(const uint8_t *peerId, )
bool btcj_getbalance(uint64_t *pAmount);
bool btcj_emptywallet(const char *pAddr, uint8_t *pTxid);

#endif
