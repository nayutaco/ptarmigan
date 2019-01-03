/*
 *  Copyright (C) 2017, Nayuta, Inc. All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
/** @file   monitoring.c
 *  @brief  channel monitor
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#define LOG_TAG     "monitoring"
#include "utl_log.h"

#include "ptarmd.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "btcrpc.h"
#include "cmd_json.h"
#include "monitoring.h"


/**************************************************************************
 * macro
 **************************************************************************/

#define M_WAIT_MON_SEC                  (30)        ///< 監視周期[sec]


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    uint32_t    feerate_per_kw;         ///< feerate_per_kw
    int32_t     height;                 ///< current block height
    uint32_t    confm;                  ///< funding_tx confirmation
} monparam_t;


/**************************************************************************
 * private variables
 **************************************************************************/

static volatile bool        mMonitoring;                ///< true:監視thread継続
static bool                 mDisableAutoConn;           ///< true:channelのある他nodeへの自動接続停止
static uint32_t             mFeeratePerKw;              ///< 0:estimate fee / !0:use this value


/********************************************************************
 * prototypes
 ********************************************************************/

static bool monfunc(ln_self_t *self, void *p_db_param, void *p_param);

static bool funding_unspent(ln_self_t *self, monparam_t *p_prm, void *p_db_param);
static bool funding_spent(ln_self_t *self, monparam_t *p_prm, void *p_db_param);
static bool channel_reconnect(ln_self_t *self);
static bool channel_reconnect_ipv4(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port);

static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);
static bool close_unilateral_local_received(bool spent);

static bool close_unilateral_remote(ln_self_t *self, void *pDbParam);
static void close_unilateral_remote_offered(ln_self_t *self, bool *pDel, ln_close_force_t *pCloseDat, int lp, void *pDbParam);
static void close_unilateral_local_sendreq(bool *pDel, const btc_tx_t *pTx, const btc_tx_t *pHtlcTx, int Num);

static bool close_revoked_first(ln_self_t *self, btc_tx_t *pTx, uint32_t confm, void *pDbParam);
static bool close_revoked_after(ln_self_t *self, uint32_t confm, void *pDbParam);
static bool close_revoked_tolocal(const ln_self_t *self, const btc_tx_t *pTx, int VIndex);
static bool close_revoked_toremote(const ln_self_t *self, const btc_tx_t *pTx, int VIndex);
static bool close_revoked_htlc(const ln_self_t *self, const btc_tx_t *pTx, int VIndex, int WitIndex);

static void set_wallet_data(ln_db_wallet_t *pWlt, const btc_tx_t *pTx);


/**************************************************************************
 * public functions
 **************************************************************************/

void *monitor_thread_start(void *pArg)
{
    (void)pArg;

    LOGD("[THREAD]monitor initialize\n");

    mMonitoring = true;

    while (mMonitoring) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < M_WAIT_MON_SEC; lp++) {
            sleep(1);
            if (!mMonitoring) {
                break;
            }
        }

        monparam_t param;
        if (mFeeratePerKw == 0) {
            param.feerate_per_kw = monitoring_get_latest_feerate_kw();
        } else {
            param.feerate_per_kw = mFeeratePerKw;
        }
        bool ret = btcrpc_getblockcount(&param.height);
        if (ret) {
            ln_db_self_search(monfunc, &param);
        }
    }
    LOGD("[exit]monitor thread\n");

    return NULL;
}


void monitor_stop(void)
{
    mMonitoring = false;
}


void monitor_disable_autoconn(bool bDisable)
{
    mDisableAutoConn = bDisable;
}


uint32_t monitoring_get_latest_feerate_kw(void)
{
    //estimate fee
    uint32_t feerate_kw;
    uint64_t feerate_kb = 0;
    bool ret = btcrpc_estimatefee(&feerate_kb, LN_BLK_FEEESTIMATE);
    if (ret) {
        feerate_kw = ln_feerate_per_kw_calc(feerate_kb);
    } else {
        LOGD("fail: estimatefee\n");
        feerate_kw = LN_FEERATE_PER_KW;
    }
    LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_kw);
    if (feerate_kw < LN_FEERATE_PER_KW_MIN) {
        // estimatesmartfeeは1000satoshisが下限のようだが、c-lightningは1000/4=250ではなく253を下限としている。
        // 毎回変更が手間になるため、値を合わせる。
        //      https://github.com/ElementsProject/lightning/issues/1443
        //      https://github.com/ElementsProject/lightning/issues/1391
        //LOGD("FIX: calc feerate_per_kw(%" PRIu32 ") < MIN\n", feerate_kw);
        feerate_kw = LN_FEERATE_PER_KW_MIN;
    }

    return feerate_kw;
}


void monitor_set_feerate_per_kw(uint32_t FeeratePerKw)
{
    LOGD("feerate_per_kw: %" PRIu32 " --> %" PRIu32 "\n", mFeeratePerKw, FeeratePerKw);
    mFeeratePerKw = FeeratePerKw;
}


/* unilateral closeを自分が行っていた場合の処理(localのcommit_txを展開)
 *
 *  to_local output
 *      to_self_delay後に使用可能
 *  to_remote output
 *      相手のみ使用可能
 *  Offered HTLC outputs
 *      cltv_expiry後にHTLC timeout_txを展開可能
 *  Received HTLC outputs
 *      preimage入手後にHTLC success_txを展開可能
 */
bool monitor_close_unilateral_local(ln_self_t *self, void *pDbParam)
{
    LOGD("closed: unilateral close[local]\n");

    ln_close_force_t close_dat;
    bool ret = ln_close_create_unilateral_tx(self, &close_dat);
    if (!ret) {
        LOGD("fail\n");
        return false;
    }

    bool del = true;
    for (int lp = 0; lp < close_dat.num; lp++) {
        const btc_tx_t *p_tx = &close_dat.p_tx[lp];

        switch (lp) {
        case LN_CLOSE_IDX_COMMIT:
            //LOGD("$$$ commit_tx\n");
            //for (int lp2 = 0; lp2 < p_tx->vout_cnt; lp2++) {
            //    LOGD("vout[%d]=%x\n", lp2, p_tx->vout[lp2].opt);
            //}
            break;
        case LN_CLOSE_IDX_TOLOCAL:
            if (p_tx->vin_cnt > 0) {
                LOGD("$$$ to_local tx ==> DB\n");

                ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TOLOCAL);
                set_wallet_data(&wlt, p_tx);
                ln_db_wallet_add(&wlt);
            }
            continue;
        case LN_CLOSE_IDX_TOREMOTE:
            //LOGD("$$$ to_remote tx\n");
            continue;
        default:
            LOGD("$$$ HTLC[%d]\n", lp - LN_CLOSE_IDX_HTLC);
            break;
        }

        if (p_tx->vin_cnt <= 0) {
            LOGD("skip tx[%d]\n", lp);
            del = false;
            continue;
        }

        //自分のtxを展開済みかチェック
        uint8_t txid[BTC_SZ_TXID];
        btc_tx_txid(p_tx, txid);
        LOGD("txid[%d]= ", lp);
        TXIDD(txid);
        bool broad = btcrpc_is_tx_broadcasted(txid);
        if (broad) {
            LOGD("already broadcasted[%d] --> OK\n", lp);
            continue;
        }

        //各close_dat.p_tx[]のINPUT展開済みチェック
        bool unspent;
        bool ret = btcrpc_check_unspent(
                            ln_their_node_id(self),
                            &unspent, NULL,
                            p_tx->vin[0].txid, p_tx->vin[0].index);
        if (!ret) {
            LOGD("fail: check unspent\n");
            del = false;
            continue;
        }

        LOGD("  INPUT txid: ");
        TXIDD(p_tx->vin[0].txid);
        LOGD("       index: %d\n", p_tx->vin[0].index);
        LOGD("         --> unspent[%d]=%d\n", lp, unspent);

        //ln_script_htlctx_create()後だから、OFFERED/RECEIVEDがわかる
        bool send_req = false;
        switch (p_tx->vout[0].opt) {
        case LN_HTLCTYPE_OFFERED:
            send_req = close_unilateral_local_offered(self, &del, !unspent, &close_dat, lp, pDbParam);
            break;
        case LN_HTLCTYPE_RECEIVED:
            send_req = close_unilateral_local_received(!unspent);
            break;
        default:
            LOGD("opt=%x\n", p_tx->vout[0].opt);
            send_req = true;
            break;
        }
        if (!unspent) {
            //INPUTがspentになってwalletに残っていたら削除する
            ln_db_wallet_del(p_tx->vin[0].txid, p_tx->vin[0].index);
        }

        if (send_req) {
            LOGD("sendreq[%d]: ", lp);
            const btc_tx_t *p_htlctx = (const btc_tx_t *)close_dat.tx_buf.buf;
            int num = close_dat.tx_buf.len / sizeof(btc_tx_t);
            close_unilateral_local_sendreq(&del, p_tx, p_htlctx, num);
        }
    }

    ln_close_free_forcetx(&close_dat);

    LOGD("del=%d\n", del);

    return del;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** 監視処理(#ln_db_self_search()のコールバック)
 *
 * @param[in,out]   self        チャネル情報
 * @param[in,out]   p_db_param  DB情報
 * @param[in,out]   p_param     パラメータ(未使用)
 */
static bool monfunc(ln_self_t *self, void *p_db_param, void *p_param)
{
    monparam_t *p_prm = (monparam_t *)p_param;

    p_prm->confm = 0;
    (void)btcrpc_get_confirm(&p_prm->confm, ln_funding_txid(self));
    bool ret;
    bool del = false;
    bool unspent;
    if (ln_status_is_closing(self)) {
        ret = true;
        unspent = false;
    } else {
        ret = btcrpc_check_unspent(ln_their_node_id(self), &unspent, NULL, ln_funding_txid(self), ln_funding_txindex(self));
    }
    if (ret && !unspent) {
        //funding_tx SPENT
        del = funding_spent(self, p_prm, p_db_param);
    } else {
        //funding_tx UNSPENT
        del = funding_unspent(self, p_prm, p_db_param);
    }
    if (del) {
        LOGD("delete from DB\n");
        ln_db_annoown_del(ln_short_channel_id(self));
        ret = ln_db_self_del_prm(self, p_db_param);
        if (ret) {
            ptarmd_eventlog(ln_channel_id(self), "close: finish");
        } else {
            LOGD("fail: del channel: ");
            DUMPD(ln_channel_id(self), LN_SZ_CHANNEL_ID);
        }
#ifndef USE_SPV
#else
        btcrpc_del_channel(ln_their_node_id(self));
#endif
    }

    return false;
}


static bool funding_unspent(ln_self_t *self, monparam_t *p_prm, void *p_db_param)
{
    bool del = false;

    lnapp_conf_t *p_app_conf = ptarmd_search_connected_cnl(ln_short_channel_id(self));
    if ( (p_app_conf == NULL) && LN_DBG_NODE_AUTO_CONNECT() &&
            !mDisableAutoConn && !ln_status_is_closing(self) ) {
        //socket未接続であれば、再接続を試行
        del = channel_reconnect(self);
    } else if (p_app_conf != NULL) {
        //socket接続済みであれば、feerate_per_kwチェック
        //  当面、feerate_per_kwを手動で変更した場合のみとする
        if ((mFeeratePerKw != 0) && (ln_feerate_per_kw(self) != p_prm->feerate_per_kw)) {
            LOGD("differenct feerate_per_kw: %" PRIu32 " : %" PRIu32 "\n", ln_feerate_per_kw(self), p_prm->feerate_per_kw);
            pthread_mutex_lock(&p_app_conf->mux_self);
            lnapp_send_updatefee(p_app_conf, p_prm->feerate_per_kw);
            pthread_mutex_unlock(&p_app_conf->mux_self);
        }
    } else {
        //LOGD("No Auto connect mode\n");
    }

    //Offered HTLCのtimeoutチェック
    for (int lp = 0; lp < LN_HTLC_MAX; lp++) {
        if (ln_is_offered_htlc_timeout(self, lp, p_prm->height)) {
            LOGD("detect: offered HTLC timeout[%d] --> close 0x%016" PRIx64 "\n", lp, ln_short_channel_id(self));
            bool ret = monitor_close_unilateral_local(self, p_db_param);
            if (!ret) {
                LOGD("fail: unilateral close\n");
            }
            break;
        }
    }

#ifndef USE_SPV
#else
    if (p_prm->confm > ln_last_conf_get(self)) {
        ln_last_conf_set(self, p_prm->confm);
        ln_db_self_save_lastconf(self, p_db_param);

        btcrpc_set_channel(ln_their_node_id(self),
                ln_short_channel_id(self),
                ln_funding_txid(self),
                ln_funding_txindex(self),
                ln_funding_redeem(self),
                ln_funding_blockhash(self),
                ln_last_conf_get(self));
    }
#endif

    return del;
}


/**
 *
 * @param[in,out]   self        チャネル情報
 * @param[in]       confm       confirmation数
 * @param[in,out]   p_db_param  DB情報
 * @retval      true    selfをDB削除可能
 */
static bool funding_spent(ln_self_t *self, monparam_t *p_prm, void *p_db_param)
{
    bool del = false;
    bool ret;
    char txid_str[BTC_SZ_TXID * 2 + 1];

    btc_tx_t close_tx = BTC_TX_INIT;
    ln_status_t stat = ln_status_get(self);
    utl_misc_bin2str_rev(txid_str, ln_funding_txid(self), BTC_SZ_TXID);

    LOGD("$$$ close: %s (confirm=%" PRIu32 ", status=%s)\n", txid_str, p_prm->confm, ln_status_string(self));
    if (stat <= LN_STATUS_CLOSE_SPENT) {
        //update status
        ret = btcrpc_search_outpoint(&close_tx, p_prm->confm, ln_funding_txid(self), ln_funding_txindex(self));
        if (ret || (stat == LN_STATUS_NORMAL)) {
            //funding_txをoutpointに持つtxがblockに入った or statusがNormal Operationのまま
            ln_close_change_stat(self, &close_tx, p_db_param);
            stat = ln_status_get(self);
            const char *p_str = ln_status_string(self);
            ptarmd_eventlog(ln_channel_id(self), "close: %s(%s)", p_str, txid_str);
        }
    }

    ln_db_revtx_load(self, p_db_param);
    const utl_buf_t *p_vout = ln_revoked_vout(self);
    if (p_vout == NULL) {
        switch (stat) {
        case LN_STATUS_CLOSE_MUTUAL:
            LOGD("closed: mutual close\n");
            del = true;
            break;
        case LN_STATUS_CLOSE_UNI_LOCAL:
            //最新のlocal commit_tx --> unilateral close(local)
            del = monitor_close_unilateral_local(self, p_db_param);
            break;
        case LN_STATUS_CLOSE_UNI_REMOTE:
            //最新のremote commit_tx --> unilateral close(remote)
            del = close_unilateral_remote(self, p_db_param);
            break;
        case LN_STATUS_CLOSE_REVOKED:
            //相手にrevoked transaction closeされた
            LOGD("closed: revoked transaction close\n");
            ret = ln_close_remoterevoked(self, &close_tx, p_db_param);
            if (ret) {
                if (ln_revoked_cnt(self) > 0) {
                    //revoked transactionのvoutに未解決あり
                    //  2回目以降はclose_revoked_after()が呼び出される
                    del = close_revoked_first(self, &close_tx, p_prm->confm, p_db_param);
                } else {
                    LOGD("all revoked transaction vout is already solved.\n");
                    del = true;
                }
            } else {
                LOGD("fail: ln_close_remoterevoked\n");
            }
            break;
        default:
            break;
        }
    } else {
        // revoked transaction close
        del = close_revoked_after(self, p_prm->confm, p_db_param);
    }
    btc_tx_free(&close_tx);

    return del;
}


static bool channel_reconnect(ln_self_t *self)
{
    const uint8_t *p_node_id = ln_their_node_id(self);
    struct {
        char ipaddr[SZ_IPV4_LEN + 1];
        uint16_t port;
    } conn_addr[3];

    for (size_t lp = 0; lp < ARRAY_SIZE(conn_addr); lp++) {
        conn_addr[lp].port = 0;
    }

    //conn_addr[0]
    //clientとして接続したときの接続先情報があれば、そこに接続する
    peer_conn_t last_peer_conn;
    if (p2p_cli_load_peer_conn(&last_peer_conn, p_node_id)) {
        strcpy(conn_addr[0].ipaddr, last_peer_conn.ipaddr);
        conn_addr[0].port = last_peer_conn.port;
        LOGD("conn_addr[0]: %s:%d\n", conn_addr[0].ipaddr, conn_addr[0].port);
    }

    //conn_addr[1]
    //self->last_connected_addrがあれば、それを使う
    switch (ln_last_connected_addr(self)->type) {
    case LN_NODEDESC_IPV4:
        sprintf(conn_addr[1].ipaddr, "%d.%d.%d.%d",
            ln_last_connected_addr(self)->addrinfo.ipv4.addr[0],
            ln_last_connected_addr(self)->addrinfo.ipv4.addr[1],
            ln_last_connected_addr(self)->addrinfo.ipv4.addr[2],
            ln_last_connected_addr(self)->addrinfo.ipv4.addr[3]);
        conn_addr[1].port = ln_last_connected_addr(self)->port;
        LOGD("conn_addr[1]: %s:%d\n", conn_addr[1].ipaddr, conn_addr[1].port);
        break;
    default:
        //LOGD("addrtype: %d\n", anno.addr.type);
        break;
    }

    //conn_addr[2]
    //node_announcementで通知されたアドレスに接続する
    ln_node_announce_t anno;
    bool ret = ln_node_search_nodeanno(&anno, p_node_id);
    if (ret) {
        switch (anno.addr.type) {
        case LN_NODEDESC_IPV4:
            sprintf(conn_addr[2].ipaddr, "%d.%d.%d.%d",
                anno.addr.addrinfo.ipv4.addr[0],
                anno.addr.addrinfo.ipv4.addr[1],
                anno.addr.addrinfo.ipv4.addr[2],
                anno.addr.addrinfo.ipv4.addr[3]);
            conn_addr[2].port = anno.addr.port;
            LOGD("conn_addr[2]: %s:%d\n", conn_addr[2].ipaddr, conn_addr[2].port);
            break;
        default:
            //LOGD("addrtype: %d\n", anno.addr.type);
            break;
        }
    }

    for (size_t lp = 0; lp < ARRAY_SIZE(conn_addr); lp++) {
        if (conn_addr[lp].port != 0) {
            ret = channel_reconnect_ipv4(p_node_id, conn_addr[lp].ipaddr, conn_addr[lp].port);
            if (ret) {
                break;
            }
            if (conn_addr[lp].port != LN_PORT_DEFAULT) {
                //だめだったらLNのdefault portで試す
                ret = channel_reconnect_ipv4(p_node_id, conn_addr[lp].ipaddr, LN_PORT_DEFAULT);
                if (ret) {
                    break;
                }
            }
        }
    }

    return false;
}


static bool channel_reconnect_ipv4(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port)
{
    int retval = -1;
    bool ret = ptarmd_nodefail_get(
                    pNodeId, pIpAddr, LN_PORT_DEFAULT,
                    LN_NODEDESC_IPV4, false);
    if (!ret) {
        //ノード接続失敗リストに載っていない場合は、自分に対して「接続要求」のJSON-RPCを送信する
        LOGD("try connect: %s:%d\n", pIpAddr, Port);
        retval = cmd_json_connect(pNodeId, pIpAddr, Port);
        LOGD("retval=%d\n", retval);
    }

    return retval == 0;
}


// Unilateral Close(自分がcommit_tx展開): Offered HTLC output
static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    bool send_req = false;

    LOGD("offered HTLC output\n");
    if (spent) {
        const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
        if (p_htlc->prev_short_channel_id == UINT64_MAX) {
            LOGD("origin node\n");
        } else if (p_htlc->prev_short_channel_id != 0) {
            //転送元がある場合、preimageを抽出する
            LOGD("hop node\n");
            LOGD("  prev_short_channel_id=%016" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);

            uint32_t confm;
            bool b_get = btcrpc_get_confirm(&confm, ln_funding_txid(self));
            if (b_get) {
                btc_tx_t tx = BTC_TX_INIT;
                uint8_t txid[BTC_SZ_TXID];
                btc_tx_txid(&pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT], txid);
                bool ret = btcrpc_search_outpoint(&tx, confm, txid, pCloseDat->p_htlc_idx[lp]);
                if (ret) {
                    //preimageを登録(自分が持っているのと同じ状態にする)
                    const utl_buf_t *p_buf = ln_preimage_remote(&tx);
                    if (p_buf != NULL) {
                        LOGD("backwind preimage: ");
                        DUMPD(p_buf->buf, p_buf->len);

                        ln_db_preimg_t preimg;
                        memcpy(preimg.preimage, p_buf->buf, LN_SZ_PREIMAGE);
                        preimg.amount_msat = 0;
                        preimg.expiry = UINT32_MAX;
                        ln_db_preimg_save(&preimg, pDbParam);
                    } else {
                        assert(0);
                    }
                } else {
                    LOGD("not found txid: ");
                    TXIDD(txid);
                    LOGD("index=%d\n", pCloseDat->p_htlc_idx[lp]);
                    *pDel = false;
                }
                btc_tx_free(&tx);
            } else {
                LOGD("fail: get confirmation\n");
            }
        }
    } else {
        //タイムアウト用Txを展開
        //  commit_txが展開されてcltv_expiryブロック経過するまではBIP68エラーになる
        send_req = true;
    }

    return send_req;
}


// Unilateral Close(自分がcommit_tx展開): Received HTLC output
//      true: tx展開する
static bool close_unilateral_local_received(bool spent)
{
    bool send_req;

    LOGD("received HTLC output\n");
    if (!spent) {
        //展開(preimageがなければsendrawtransactionに失敗する)
        send_req = true;
    } else {
        //展開済みならOK
        LOGD("-->OK(broadcasted)\n");
        send_req = false;
    }

    return send_req;
}


/** unilateral closeを相手が行っていた場合の処理(remoteがcommit_txを展開)
 *
 *  to_local output
 *      相手のみ使用可能
 *  to_remote output
 *      commit_txが展開された時点で、即座に使用可能
 *  Offered HTLC outputs
 *      preimage入手後、即座に使用可能
 *  Received HTLC outputs
 *      cltv_expiry後、即座に使用可能
 */
static bool close_unilateral_remote(ln_self_t *self, void *pDbParam)
{
    bool del = true;
    ln_close_force_t close_dat;

    LOGD("closed: unilateral close[remote]\n");

    bool ret = ln_close_create_tx(self, &close_dat);
    if (ret) {
        for (int lp = 0; lp < close_dat.num; lp++) {
            const btc_tx_t *p_tx = &close_dat.p_tx[lp];
            if (lp == LN_CLOSE_IDX_COMMIT) {
                //LOGD("$$$ commit_tx\n");
            } else if (lp == LN_CLOSE_IDX_TOLOCAL) {
                //LOGD("$$$ to_local tx\n");
            } else if (lp == LN_CLOSE_IDX_TOREMOTE) {
                if (p_tx->vin_cnt > 0) {
                    LOGD("$$$ to_remote tx ==> DB\n");

                    uint8_t pub[BTC_SZ_PUBKEY];
                    btc_keys_priv2pub(pub, p_tx->vin[0].witness[0].buf);

                    ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TOREMOTE);
                    set_wallet_data(&wlt, p_tx);
                    utl_buf_t witbuf[2] = {
                        { p_tx->vin[0].witness[0].buf, BTC_SZ_PRIVKEY },
                        { pub, sizeof(pub) }
                    };
                    wlt.wit_item_cnt = 2;
                    wlt.p_wit = witbuf;
                    (void)ln_db_wallet_add(&wlt);
                }
            } else {
                LOGD("$$$ HTLC[%d]\n", lp - LN_CLOSE_IDX_HTLC);

                if ((p_tx->vin_cnt == 0) && (p_tx->vout_cnt == 0)) {
                    LOGD("  no resolved tx\n");
                    del = false;
                } else if (p_tx->vin[0].wit_item_cnt > 0) {
                    //INPUT spent check
                    bool unspent;
                    bool ret = btcrpc_check_unspent(ln_their_node_id(self), &unspent, NULL,
                                    p_tx->vin[0].txid, p_tx->vin[0].index);
                    if (ret && !unspent) {
                        LOGD("already spent\n");
                        ln_db_wallet_del(p_tx->vin[0].txid, p_tx->vin[0].index);
                        continue;
                    }

                    //これをINPUTとするwalletの有無
                    bool saved = ln_db_wallet_load(NULL, p_tx->vin[0].txid, p_tx->vin[0].index);
                    if (!saved) {
                        //まだ保存していないので、保存する
                        int32_t blkcnt;
                        ret = btcrpc_getblockcount(&blkcnt);
                        LOGD("blkcnt=%" PRIu32 "\n", blkcnt);
                        if ((p_tx->locktime == 0) || (ret && (blkcnt > 0) && (p_tx->locktime <= (uint32_t)blkcnt))) {
                            if (p_tx->vin_cnt > 0) {
                                LOGD("$$$ remote HTLC[%d] ==> DB(%" PRId32 ")\n", lp, blkcnt);

                                ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_HTLCOUT);
                                set_wallet_data(&wlt, p_tx);
                                wlt.amount = close_dat.p_tx[LN_CLOSE_IDX_COMMIT].vout[wlt.index].value;     //HTLC_txはfeeが引かれているためoriginalの値を使う
                                ln_db_wallet_add(&wlt);
                            }
                        } else {
                            del = false;
                        }
                    }
                } else {
                    if ((p_tx->vout_cnt > 0) && (p_tx->vout[0].opt == LN_HTLCTYPE_OFFERED)) {
                        //preimageを取得できていない
                        LOGD("  not have preimage\n");
                        close_unilateral_remote_offered(self, &del, &close_dat, lp, pDbParam);
                    } else {
                        LOGD("\n");
                    }
                }
            }
        }

        ln_close_free_forcetx(&close_dat);
    } else {
        del = false;
    }

    LOGD("del=%d\n", del);

    return del;
}


// Unilateral Close(相手がcommit_tx展開): Offered HTLC output
//  相手からofferされているから、preimageがあれば取り戻す
static void close_unilateral_remote_offered(ln_self_t *self, bool *pDel, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    LOGD("offered HTLC output\n");

    const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
    if (p_htlc->prev_short_channel_id != 0) {
        LOGD("origin/hop node\n");

        bool unspent;
        bool ret = btcrpc_check_unspent(ln_their_node_id(self), &unspent, NULL,
                        pCloseDat->p_tx[lp].vin[0].txid, pCloseDat->p_tx[lp].vin[0].index);
        if (ret && !unspent) {
            LOGD("already spent\n");
            ln_db_wallet_del(pCloseDat->p_tx[lp].vin[0].txid, pCloseDat->p_tx[lp].vin[0].index);
            return;
        }

        //転送元がある場合、preimageを抽出する
        LOGD("  prev_short_channel_id=%016" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);
        uint32_t confm;
        bool b_get = btcrpc_get_confirm(&confm, ln_funding_txid(self));
        if (b_get) {
            btc_tx_t tx = BTC_TX_INIT;
            uint8_t txid[BTC_SZ_TXID];
            btc_tx_txid(&pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT], txid);
            bool ret = btcrpc_search_outpoint(&tx, confm, txid, pCloseDat->p_htlc_idx[lp]);
            if (ret) {
                //preimageを登録(自分が持っているのと同じ状態にする)
                const utl_buf_t *p_buf = ln_preimage_remote(&tx);
                if (p_buf != NULL) {
                    LOGD("backwind preimage: ");
                    DUMPD(p_buf->buf, p_buf->len);

                    ln_db_preimg_t preimg;
                    memcpy(preimg.preimage, p_buf->buf, LN_SZ_PREIMAGE);
                    preimg.amount_msat = 0;
                    preimg.expiry = UINT32_MAX;
                    ln_db_preimg_save(&preimg, pDbParam);
                } else {
                    assert(0);
                }
            } else {
                LOGD("not found txid: ");
                TXIDD(txid);
                LOGD("index=%d\n", pCloseDat->p_htlc_idx[lp]);
                *pDel = false;
            }
            btc_tx_free(&tx);
        } else {
            LOGD("fail: get confirmation\n");
        }
    }
}


static void close_unilateral_local_sendreq(bool *pDel, const btc_tx_t *pTx, const btc_tx_t *pHtlcTx, int Num)
{
    utl_buf_t buf;
    uint8_t txid[BTC_SZ_TXID];

    btc_tx_write(pTx, &buf);
    bool ret = btcrpc_send_rawtx(txid, NULL, buf.buf, buf.len);
    utl_buf_free(&buf);
    if (ret) {
        LOGD("$$$ broadcast\n");

        if ( (pTx->vout[0].opt == LN_HTLCTYPE_OFFERED) ||
             (pTx->vout[0].opt == LN_HTLCTYPE_RECEIVED) ) {
            for (int lp = 0; lp < Num; lp++) {
                if (pHtlcTx[lp].vin_cnt > 0) {
                    LOGD("$$$ to_local tx[%d] ==> DB\n", lp);

                    ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_HTLCOUT);
                    set_wallet_data(&wlt, &pHtlcTx[lp]);
                    ln_db_wallet_add(&wlt);
                }
            }
        }
    } else {
        *pDel = false;
        LOGE("fail: broadcast\n");
    }
}


/** revoked transactionから即座に取り戻す
 *
 * @param[in,out]   self
 * @param[in]       pTx         revoked transaction
 * @param[in]       confm       confirmation
 * @param[in]       pDbParam    DB parameter
 */
static bool close_revoked_first(ln_self_t *self, btc_tx_t *pTx, uint32_t confm, void *pDbParam)
{
    bool del = false;
    bool save = true;
    bool ret;

    ptarmd_eventlog(ln_channel_id(self), "close: ugly way");

    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        const utl_buf_t *p_vout = ln_revoked_vout(self);

        LOGD("vout[%u]=", lp);
        DUMPD(pTx->vout[lp].script.buf, pTx->vout[lp].script.len);
        if (utl_buf_cmp(&pTx->vout[lp].script, &p_vout[LN_RCLOSE_IDX_TOLOCAL])) {
            LOGD("[%u]to_local !\n", lp);

            ret = close_revoked_tolocal(self, pTx, lp);
            if (ret) {
                del = ln_revoked_cnt_dec(self);
                ln_set_revoked_confm(self, confm);
            } else {
                save = false;
            }
        } else if (utl_buf_cmp(&pTx->vout[lp].script, &p_vout[LN_RCLOSE_IDX_TOREMOTE])) {
            LOGD("[%u]to_remote !\n", lp);
            ret = close_revoked_toremote(self, pTx, lp);
            if (ret) {
                save = true;
            }
        } else {
            for (int lp2 = LN_RCLOSE_IDX_HTLC; lp2 < ln_revoked_num(self); lp2++) {
                // LOGD("p_vout[%u][%d]=", lp, lp2);
                // DUMPD(p_vout[lp2].buf, p_vout[lp2].len);
                if (utl_buf_cmp(&pTx->vout[lp].script, &p_vout[lp2])) {
                    LOGD("[%u]HTLC vout[%d] !\n", lp, lp2);

                    ret = close_revoked_htlc(self, pTx, lp, lp2);
                    if (ret) {
                        del = ln_revoked_cnt_dec(self);
                        ln_set_revoked_confm(self, confm);
                    }
                } else {
                    LOGD(" --> not match\n");
                }
            }
        }
    }
    if (save) {
        ln_db_revtx_save(self, true, pDbParam);
    }

    return del;
}


/** HTLC Timeout/Success Tx後から取り戻す
 *
 * @param[in,out]   self
 * @param[in]       confm       confirmation
 * @param[in]       pDbParam    DB parameter
 */
static bool close_revoked_after(ln_self_t *self, uint32_t confm, void *pDbParam)
{
    bool del = false;

    if (confm != ln_revoked_confm(self)) {
        //HTLC Timeout/Success Txのvoutと一致するトランザクションを検索
        utl_buf_t txbuf;
        const utl_buf_t *p_vout = ln_revoked_vout(self);
        bool ret = btcrpc_search_vout(&txbuf, confm - ln_revoked_confm(self), &p_vout[0]);
        if (ret) {
            bool sendret = true;
            int num = txbuf.len / sizeof(btc_tx_t);
            LOGD("find! %d\n", num);
            btc_tx_t *pTx = (btc_tx_t *)txbuf.buf;
            for (int lp = 0; lp < num; lp++) {
                LOGD("-------- %d ----------\n", lp);
                btc_tx_print(&pTx[lp]);

                ret = close_revoked_tolocal(self, &pTx[lp], 0);
                btc_tx_free(&pTx[lp]);
                if (ret) {
                    del = ln_revoked_cnt_dec(self);
                    LOGD("del=%d, revoked_cnt=%d\n", del, ln_revoked_cnt(self));
                } else {
                    sendret = false;
                    break;
                }
            }
            utl_buf_free(&txbuf);

            if (sendret) {
                ln_set_revoked_confm(self, confm);
                ln_db_revtx_save(self, false, pDbParam);
                LOGD("del=%d, revoked_cnt=%d\n", del, ln_revoked_cnt(self));
            } else {
                //送信エラーがあった場合には、次回やり直す
                LOGD("sendtx error\n");
            }
        } else {
            ln_set_revoked_confm(self, confm);
            ln_db_revtx_save(self, false, pDbParam);
            LOGD("no target txid: %u, revoked_cnt=%d\n", confm, ln_revoked_cnt(self));
        }
    } else {
        LOGD("same block: %u, revoked_cnt=%d\n", confm, ln_revoked_cnt(self));
    }

    return del;
}


//revoked to_local output/HTLC Timeout/Success Txを取り戻す
static bool close_revoked_tolocal(const ln_self_t *self, const btc_tx_t *pTx, int VIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    const utl_buf_t *p_wit = ln_revoked_wit(self);

    bool ret = ln_wallet_create_tolocal(self, &tx,
                pTx->vout[VIndex].value,
                ln_commit_local(self)->to_self_delay,
                &p_wit[0], txid, VIndex, true);
    if (ret) {
        if (tx.vin_cnt > 0) {
            LOGD("$$$ to_local tx ==> DB\n");

            ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TOLOCAL);
            set_wallet_data(&wlt, &tx);
            wlt.sequence = ln_commit_local(self)->to_self_delay;
            ln_db_wallet_add(&wlt);
        }

        btc_tx_free(&tx);
    }

    return ret;
}


//revoked to_remote outputを取り戻す
//  to_remoteはP2WPKHで支払い済みだが、bitcoindがremotekeyを知らないため、転送する
static bool close_revoked_toremote(const ln_self_t *self, const btc_tx_t *pTx, int VIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    bool ret = ln_wallet_create_toremote(
                    self, &tx, pTx->vout[VIndex].value,
                    txid, VIndex);
    if (ret) {
        if (tx.vin_cnt > 0) {
            LOGD("$$$ to_remote tx ==> DB\n");

            ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TOREMOTE);
            set_wallet_data(&wlt, &tx);
            uint8_t pub[BTC_SZ_PUBKEY];
            btc_keys_priv2pub(pub, tx.vin[0].witness[0].buf);
            wlt.wit_item_cnt = 2;
            utl_buf_t witbuf[2] = {
                { tx.vin[0].witness[0].buf, BTC_SZ_PRIVKEY },
                { pub, sizeof(pub) }
            };
            wlt.p_wit = witbuf;
            (void)ln_db_wallet_add(&wlt);
        }

        btc_tx_free(&tx);
    }

    return ret;
}


//Offered/Recieved HTLCを取り戻す
static bool close_revoked_htlc(const ln_self_t *self, const btc_tx_t *pTx, int VIndex, int WitIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    ln_revokedhtlc_create_spenttx(self, &tx, pTx->vout[VIndex].value, WitIndex, txid, VIndex);
    btc_tx_print(&tx);
    utl_buf_t buf;
    btc_tx_write(&tx, &buf);
    btc_tx_free(&tx);
    bool ret = btcrpc_send_rawtx(txid, NULL, buf.buf, buf.len);
    if (ret) {
        LOGD("$$$ broadcast\n");
    } else {
        LOGE("fail: broadcast\n");
    }
    utl_buf_free(&buf);

    return ret;
}


static void set_wallet_data(ln_db_wallet_t *pWlt, const btc_tx_t *pTx)
{
    pWlt->p_txid = pTx->vin[0].txid;
    pWlt->index = pTx->vin[0].index;
    pWlt->amount = pTx->vout[0].value;
    pWlt->sequence = pTx->vin[0].sequence;
    pWlt->locktime = pTx->locktime;
    pWlt->wit_item_cnt = pTx->vin[0].wit_item_cnt;
    pWlt->p_wit = pTx->vin[0].witness;
}
