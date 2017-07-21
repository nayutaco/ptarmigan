#ifndef LNAPP_H__
#define LNAPP_H__

#include <pthread.h>

#include "ucoind.h"
#include "conf.h"


/********************************************************************
 * typedefs
 ********************************************************************/

typedef struct {
    //p2p_svr/cli用
    volatile int    sock;
    pthread_t       th;

    //制御内容通知
    bool            initiator;                  ///< true:init送信する
    uint8_t         node_id[UCOIN_SZ_PUBKEY];   //接続先(initiator==true時)
    my_daemoncmd_t  cmd;
    funding_conf_t  *p_funding;

    //lnappワーク
    void            *p_work;
} lnapp_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

void lnapp_init(const node_conf_t *pNodeConf);
void lnapp_start(lnapp_conf_t *pAppConf);
void lnapp_stop(lnapp_conf_t *pAppConf);
bool lnapp_have_channel(const uint8_t *pNodeId);
void lnapp_add_preimage(lnapp_conf_t *pAppConf, char *pResMsg);
void lnapp_show_payment_hash(lnapp_conf_t *pAppConf);
bool lnapp_payment(lnapp_conf_t *pAppConf, const payment_conf_t *pPay);
bool lnapp_payment_forward(lnapp_conf_t *pAppConf, const ln_cb_add_htlc_recv_t *pAdd, uint64_t prev_short_channel_id);
bool lnapp_fulfill_backward(lnapp_conf_t *pAppConf, const ln_cb_fulfill_htlc_recv_t *pFulFill);
bool lnapp_close_channel(lnapp_conf_t *pAppConf);
bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id);
void lnapp_show_self(const lnapp_conf_t *pAppConf, char *pResMsg);
bool lnapp_is_looping(const lnapp_conf_t *pAppConf);

#endif /* LNAPP_H__ */
