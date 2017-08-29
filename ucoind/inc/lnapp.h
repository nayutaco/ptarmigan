#ifndef LNAPP_H__
#define LNAPP_H__

#include <pthread.h>

#include "ucoind.h"
#include "conf.h"


/**************************************************************************
 * macros
 **************************************************************************/

#define APP_PREIMAGE_NUM        (10)        ///< 保持できるpreimage数

#define APP_FWD_PROC_MAX        (5)         ///< 他スレッドからの処理要求キュー数
                                            ///< TODO: オーバーフローチェックはしていない


/********************************************************************
 * typedefs
 ********************************************************************/

/** @struct preimage_t
 *  @brief  preimage情報
 */
typedef struct {
    bool            use;                            ///< true:使用中
    uint64_t        amount;                         ///< invoiceで要求した額[msat]
    uint8_t         preimage[LN_SZ_PREIMAGE];       ///< preimage
} preimage_t;


/** @enum   recv_proc_t
 *  @brief  処理要求
 */
typedef enum {
    //外部用
    FWD_PROC_NONE,                  ///< 要求無し

    FWD_PROC_ADD,                   ///< update_add_htlc転送
    FWD_PROC_FULFILL,               ///< update_fulfill_htlc転送

    //内部用
    INNER_SEND_ANNO_SIGNS,          ///< announcement_signatures送信要求
    INNER_SEND_ANNOUNCEMENT,        ///< announcement送信要求
} recv_proc_t;


/** @struct lnapp_conf_t
 *  @brief  アプリ側のチャネル管理情報
 */
typedef struct {
    //p2p_svr/cli用
    volatile int    sock;
    pthread_t       th;

    //制御内容通知
    bool            initiator;                  ///< true:init送信する
    uint8_t         node_id[UCOIN_SZ_PUBKEY];   ///< 接続先(initiator==true時)
    my_daemoncmd_t  cmd;                        ///< ucoincliからの処理要求
    funding_conf_t  *p_funding;                 ///< ucoincliで #DCMD_CREATE 時のパラメータ

    //lnappワーク
    volatile bool   loop;                   ///< true:channel動作中
    ln_self_t       *p_self;                ///< channelのコンテキスト
    ln_establish_t  *p_establish;           ///< Establish用のワーク領域

    uint32_t        last_cnl_anno_sent;     ///< 最後に送信したchannel_announcementのEPOCH TIME
    uint32_t        last_node_anno_sent;    ///< 最後に送信したnode_announcementのEPOCH TIME
    uint8_t         ping_counter;           ///< 無送受信時にping送信するカウンタ(カウントアップ)
    bool            first;                  ///< false:node_announcement受信済み
    bool            shutdown_sent;          ///< true:shutdownを最初に送信した側
    bool            funding_waiting;        ///< true:funding_txの安定待ち
    int32_t         funding_confirm;        ///< funding_txのconfirmation数
    uint32_t        funding_min_depth;

    preimage_t      preimage[APP_PREIMAGE_NUM]; ///< preimage

    pthread_cond_t  cond;           ///< muxの待ち合わせ
    pthread_mutex_t mux;            ///< 処理待ち合わせ用のmutex
    pthread_mutex_t mux_proc;       ///< 処理中のmutex
    pthread_mutex_t mux_send;       ///< socket送信中のmutex

    //他スレッドからの転送処理要求
    uint8_t         fwd_proc_rpnt;  ///< fwd_procの読込み位置
    uint8_t         fwd_proc_wpnt;  ///< fwd_procの書込み位置
    struct {
        recv_proc_t cmd;            ///< 要求
        uint16_t    len;            ///< p_data長
        void        *p_data;        ///< mallocで確保
    } fwd_proc[APP_FWD_PROC_MAX];
} lnapp_conf_t;


/********************************************************************
 * prototypes
 ********************************************************************/

void lnapp_init(ln_node_t *pNode);
void lnapp_start(lnapp_conf_t *pAppConf);
void lnapp_stop(lnapp_conf_t *pAppConf);
void lnapp_add_preimage(lnapp_conf_t *pAppConf, uint64_t Amount, char *pResMsg);
void lnapp_show_payment_hash(lnapp_conf_t *pAppConf);
bool lnapp_payment(lnapp_conf_t *pAppConf, const payment_conf_t *pPay);
bool lnapp_payment_forward(lnapp_conf_t *pAppConf, const ln_cb_add_htlc_recv_t *pAdd, uint64_t prev_short_channel_id);
bool lnapp_fulfill_backward(lnapp_conf_t *pAppConf, const ln_cb_fulfill_htlc_recv_t *pFulFill);
bool lnapp_close_channel(lnapp_conf_t *pAppConf);
bool lnapp_match_short_channel_id(const lnapp_conf_t *pAppConf, uint64_t short_channel_id);
void lnapp_show_self(const lnapp_conf_t *pAppConf, char *pResMsg);
bool lnapp_is_looping(const lnapp_conf_t *pAppConf);

#endif /* LNAPP_H__ */
