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

#include "ln_msg_anno.h"
#include "ln_wallet.h"

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

#define M_WAIT_START_SEC                (5)         ///< monitoring start[sec]
#ifdef DEVELOPER_MODE
//Workaround for `lightning-integration`'s timeout (outside BOLT specifications)
#define M_WAIT_MON_SEC                  (20)        ///< monitoring cyclic[sec] for developer mode
#else
#define M_WAIT_MON_SEC                  (30)        ///< monitoring cyclic[sec]
#endif

/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    //global
    uint32_t    feerate_per_kw;         ///< feerate_per_kw
    int32_t     height;                 ///< current block height

    //work: each channel
    uint32_t    confm;                  ///< funding_tx confirmation
} monparam_t;


/** @struct     monchanlist_t
 *  @brief      monitoring channel list
 */
typedef struct monchanlist_t {
    LIST_ENTRY(monchanlist_t) list;

    uint8_t     channel_id[LN_SZ_CHANNEL_ID];   // monitoring channel_id
    uint32_t    last_check_confm;               // last confirmation btcrpc_search_outpoint()
} monchanlist_t;
LIST_HEAD(monchanlisthead_t, monchanlist_t);


/**************************************************************************
 * private variables
 **************************************************************************/

static volatile bool        mMonitoring;                ///< true:監視thread継続
static bool                 mDisableAutoConn;           ///< true:channelのある他nodeへの自動接続停止
static uint32_t             mFeeratePerKw;              ///< 0:estimate fee / !0:use this value
static monparam_t           mMonParam;
static struct monchanlisthead_t mMonChanListHead;


/********************************************************************
 * prototypes
 ********************************************************************/

static void connect_nodelist(void);
static bool monfunc(ln_channel_t *pChannel, void *p_db_param, void *pParam);

static bool funding_unspent(ln_channel_t *pChannel, monparam_t *p_param, void *p_db_param);
static bool funding_spent(ln_channel_t *pChannel, monparam_t *p_param, void *p_db_param);
static bool channel_reconnect(ln_channel_t *pChannel);
static bool node_connect_ipv4(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port);

static bool close_unilateral_local_offered(ln_channel_t *pChannel, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);
static bool close_unilateral_local_received(bool spent);

static bool close_unilateral_remote(ln_channel_t *pChannel, void *pDbParam);
static void close_unilateral_remote_offered(ln_channel_t *pChannel, bool *pDel, ln_close_force_t *pCloseDat, int lp, void *pDbParam);
static bool close_unilateral_local_sendreq(bool *pDel, const btc_tx_t *pTx, const btc_tx_t *pHtlcTx, int Num);

static bool close_revoked_first(ln_channel_t *pChannel, btc_tx_t *pTx, uint32_t confm, void *pDbParam);
static bool close_revoked_after(ln_channel_t *pChannel, uint32_t confm, void *pDbParam);
static bool close_revoked_to_local(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex);
static bool close_revoked_to_remote(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex);
static bool close_revoked_htlc(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex, int WitIndex);

static void set_wallet_data(ln_db_wallet_t *pWlt, const btc_tx_t *pTx);

static uint32_t get_latest_feerate_kw(void);
static bool update_btc_values(void);

static bool monchanlist_search(monchanlist_t **ppList, const uint8_t *pChannelId, bool bRemove);
static void monchanlist_add(monchanlist_t *pList);


/**************************************************************************
 * public functions
 **************************************************************************/

void *monitor_thread_start(void *pArg)
{
    (void)pArg;

    LOGD("[THREAD]monitor initialize\n");

    mMonitoring = true;
    update_btc_values();

    //wait for accept user command before reconnect
    for (int lp = 0; lp < M_WAIT_START_SEC; lp++) {
        sleep(1);
        if (!mMonitoring) {
            break;
        }
    }

    connect_nodelist();

    while (mMonitoring) {
        LOGD("$$$----begin\n");
        bool ret = update_btc_values();
        if (ret) {
            ln_db_channel_search(monfunc, &mMonParam);
        }
        LOGD("$$$----end\n");

        for (int lp = 0; lp < M_WAIT_MON_SEC; lp++) {
            sleep(1);
            if (!mMonitoring) {
                LOGD("stop monitoring\n");
                break;
            }
        }
    }
    LOGD("[exit]monitor thread\n");
    ptarmd_stop();

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


void monitor_set_feerate_per_kw(uint32_t FeeratePerKw)
{
    LOGD("feerate_per_kw: %" PRIu32 " --> %" PRIu32 "\n", mFeeratePerKw, FeeratePerKw);
    mFeeratePerKw = FeeratePerKw;
}


bool monitor_btc_getblockcount(int32_t *pBlockCount)
{
    if (mMonParam.height > 0) {
        *pBlockCount = mMonParam.height;
        return true;
    }
    return false;
}


uint32_t monitor_btc_feerate_per_kw(void)
{
    return mMonParam.feerate_per_kw;
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
bool monitor_close_unilateral_local(ln_channel_t *pChannel, void *pDbParam)
{
    LOGD("closed: unilateral close[local]\n");

    ln_close_force_t close_dat;
    bool ret = ln_close_create_unilateral_tx(pChannel, &close_dat);
    if (!ret) {
        LOGE("fail\n");
        return false;
    }

    bool del = true;
    for (int lp = 0; lp < close_dat.num; lp++) {
        const btc_tx_t *p_tx = &close_dat.p_tx[lp];

        switch (lp) {
        case LN_CLOSE_IDX_COMMIT:
            LOGD("$$$ commit_tx\n");
            //for (int lp2 = 0; lp2 < p_tx->vout_cnt; lp2++) {
            //    LOGD("vout[%d]=%x\n", lp2, p_tx->vout[lp2].opt);
            //}
            break;
        case LN_CLOSE_IDX_TO_LOCAL:
            if (p_tx->vin_cnt > 0) {
                LOGD("$$$ to_local tx ==> DB\n");

                ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TO_LOCAL);
                set_wallet_data(&wlt, p_tx);
                ln_db_wallet_add(&wlt);
            }
            continue;
        case LN_CLOSE_IDX_TO_REMOTE:
            LOGD("$$$ to_remote tx\n");
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

        //check own tx is broadcasted
        uint8_t txid[BTC_SZ_TXID];
        btc_tx_txid(p_tx, txid);
        LOGD("txid[%d]= ", lp);
        TXIDD(txid);
        bool broad = btcrpc_is_tx_broadcasted(txid);
        if (broad) {
            LOGD("already broadcasted[%d] --> OK\n", lp);
            continue;
        }

        //check each close_dat.p_tx[] INPUT is broadcasted
        bool unspent;
        bool ret = btcrpc_check_unspent(
                            ln_remote_node_id(pChannel),
                            &unspent, NULL,
                            p_tx->vin[0].txid, p_tx->vin[0].index);
        if (!ret) {
            LOGE("fail: check unspent\n");
            del = false;
            continue;
        }

        LOGD("  INPUT txid: ");
        TXIDD(p_tx->vin[0].txid);
        LOGD("       index: %d\n", p_tx->vin[0].index);
        LOGD("         --> unspent[%d]=%d\n", lp, unspent);

        //ln_htlc_tx_create()後だから、OFFERED/RECEIVEDがわかる
        bool send_req = false;
        switch (p_tx->vout[0].opt) {
        case LN_COMMIT_TX_OUTPUT_TYPE_OFFERED:
            send_req = close_unilateral_local_offered(pChannel, &del, !unspent, &close_dat, lp, pDbParam);
            break;
        case LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED:
            send_req = close_unilateral_local_received(!unspent);
            break;
        default:
            LOGD("opt=%x\n", p_tx->vout[0].opt);
            send_req = true;
            break;
        }
        if (!unspent) {
            //delete from wallet DB if INPUT is SPENT
            ln_db_wallet_del(p_tx->vin[0].txid, p_tx->vin[0].index);
        }

        if (send_req) {
            LOGD("sendreq[%d]: ", lp);
            const btc_tx_t *p_htlc_tx = (const btc_tx_t *)close_dat.tx_buf.buf;
            int num = close_dat.tx_buf.len / sizeof(btc_tx_t);
            bool ret = close_unilateral_local_sendreq(&del, p_tx, p_htlc_tx, num);
            if (ret && (lp == LN_CLOSE_IDX_COMMIT)) {
                ln_close_change_stat(pChannel, NULL, pDbParam);
            }
        }
    }

    ln_close_free_forcetx(&close_dat);

    LOGD("del=%d\n", del);

    return del;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** node connection with connlist.conf
 *
 *  connecting nodes at startup according to node list.
 */
static void connect_nodelist(void)
{
    connect_conf_t *p_conf = (connect_conf_t *)UTL_DBG_MALLOC(sizeof(connect_conf_t));
    conf_connect_init(p_conf);
    bool bconf = conf_connect_load(FNAME_CONF_CONNLIST, p_conf);
    if (!bconf) {
        LOGD("not connect list\n");
        return;
    }
    for (int lp = 0; lp < PTARMD_CONNLIST_MAX; lp++) {
        if (p_conf->conn_str[lp][0] != '\0') {
            ln_node_conn_t node_conn;
            bool ret = ln_node_addr_dec(&node_conn, p_conf->conn_str[lp]);
            if (ret) {
                char node_id_str[BTC_SZ_PUBKEY * 2 + 1];
                utl_str_bin2str(node_id_str, node_conn.node_id, BTC_SZ_PUBKEY);
                node_connect_ipv4(node_conn.node_id, node_conn.addr, node_conn.port);
            } else {
                LOGE("fail: %s\n", p_conf->conn_str[lp]);
            }
        }
    }
    UTL_DBG_FREE(p_conf);
}


/** 監視処理(#ln_db_channel_search()のコールバック)
 *
 * @param[in,out]   pChannel    チャネル情報
 * @param[in,out]   p_db_param  DB情報
 * @param[in,out]   p_param     パラメータ(未使用)
 * @return  false(always)
 */
static bool monfunc(ln_channel_t *pChannel, void *p_db_param, void *pParam)
{
    monparam_t *p_param = (monparam_t *)pParam;

    p_param->confm = 0;
    (void)btcrpc_get_confirm(&p_param->confm, ln_funding_info_txid(&pChannel->funding_info));
    bool ret;
    bool del = false;
    bool unspent;
    if (ln_status_is_closing(pChannel)) {
        ret = true;
        unspent = false;
    } else {
        ret = btcrpc_check_unspent(ln_remote_node_id(pChannel), &unspent, NULL, ln_funding_info_txid(&pChannel->funding_info), ln_funding_info_txindex(&pChannel->funding_info));
    }
    if (ret && !unspent) {
        //funding_tx SPENT
        del = funding_spent(pChannel, p_param, p_db_param);
    } else {
        //funding_tx UNSPENT
        del = funding_unspent(pChannel, p_param, p_db_param);
    }
    if (del) {
        LOGD("delete from DB\n");
        ln_db_annoown_del(ln_short_channel_id(pChannel));
        ret = ln_db_channel_del_param(pChannel, p_db_param);
        if (ret) {
            ptarmd_eventlog(ln_channel_id(pChannel), "close: finish");
        } else {
            LOGE("fail: del channel: ");
            DUMPD(ln_channel_id(pChannel), LN_SZ_CHANNEL_ID);
        }
        btcrpc_del_channel(ln_remote_node_id(pChannel));
    }

    return false;
}


static bool funding_unspent(ln_channel_t *pChannel, monparam_t *p_param, void *p_db_param)
{
    bool del = false;

    lnapp_conf_t *p_app_conf = ptarmd_search_connected_cnl(ln_short_channel_id(pChannel));
    if ( (p_app_conf == NULL) && LN_DBG_NODE_AUTO_CONNECT() &&
            !mDisableAutoConn && !ln_status_is_closing(pChannel) ) {
        //socket未接続であれば、再接続を試行
        del = channel_reconnect(pChannel);
    } else if (p_app_conf != NULL) {
        //socket接続済みであれば、feerate_per_kwチェック
        //  当面、feerate_per_kwを手動で変更した場合のみとする
        if ((ln_status_get(pChannel) == LN_STATUS_NORMAL) && (mFeeratePerKw != 0)) {
            lnapp_set_feerate(p_app_conf, p_param->feerate_per_kw);
        }
    } else {
        //LOGD("No Auto connect mode\n");
    }

    //Offered HTLCのtimeoutチェック
    for (int lp = 0; lp < LN_UPDATE_MAX; lp++) {
        if (ln_is_offered_htlc_timeout(pChannel, lp, p_param->height)) {
            LOGD("detect: offered HTLC timeout[%d] --> close 0x%016" PRIx64 "\n", lp, ln_short_channel_id(pChannel));
            bool ret = monitor_close_unilateral_local(pChannel, p_db_param);
            if (!ret) {
                LOGE("fail: unilateral close\n");
            }
            break;
        }
    }

    if (p_param->confm > ln_funding_last_confirm_get(pChannel)) {
        ln_funding_last_confirm_set(pChannel, p_param->confm);
        ln_db_channel_save_last_confirm(pChannel, p_db_param);

        btcrpc_set_channel(ln_remote_node_id(pChannel),
                ln_short_channel_id(pChannel),
                ln_funding_info_txid(&pChannel->funding_info),
                ln_funding_info_txindex(&pChannel->funding_info),
                ln_funding_info_wit_script(&pChannel->funding_info),
                ln_funding_blockhash(pChannel),
                ln_funding_last_confirm_get(pChannel));
    }

    return del;
}


/**
 *
 * @param[in,out]   pChannel    チャネル情報
 * @param[in]       confm       confirmation数
 * @param[in,out]   p_db_param  DB情報
 * @retval      true    pChannelをDB削除可能
 */
static bool funding_spent(ln_channel_t *pChannel, monparam_t *p_param, void *p_db_param)
{
    bool del = false;
    bool ret;
    char txid_str[BTC_SZ_TXID * 2 + 1];

    btc_tx_t close_tx = BTC_TX_INIT;
    ln_status_t stat = ln_status_get(pChannel);
    utl_str_bin2str_rev(txid_str, ln_funding_info_txid(&pChannel->funding_info), BTC_SZ_TXID);

    LOGD("$$$ close: %s (confirm=%" PRIu32 ", status=%s)\n", txid_str, p_param->confm, ln_status_string(pChannel));
    if (stat <= LN_STATUS_CLOSE_WAIT) {
        //update status
        monchanlist_t *p_list = NULL;
        ret = monchanlist_search(&p_list, ln_channel_id(pChannel), false);
        if (!ret) {
            p_list = (monchanlist_t *)UTL_DBG_MALLOC(sizeof(monchanlist_t));
            memcpy(p_list->channel_id, ln_channel_id(pChannel), LN_SZ_CHANNEL_ID);
            p_list->last_check_confm = 0;
            monchanlist_add(p_list);
        }
        btc_tx_t *p_tx = NULL;
        ret = btcrpc_search_outpoint(
            &close_tx, p_param->confm - p_list->last_check_confm, ln_funding_info_txid(&pChannel->funding_info), ln_funding_info_txindex(&pChannel->funding_info));
        if (ret) {
            p_tx = &close_tx;
        }
        p_list->last_check_confm = p_param->confm;
        if (ret || (stat == LN_STATUS_NORMAL)) {
            //funding_txをoutpointに持つtxがblockに入った or statusがNormal Operationのまま
            ln_close_change_stat(pChannel, p_tx, p_db_param);
            stat = ln_status_get(pChannel);
            const char *p_str = ln_status_string(pChannel);
            ptarmd_eventlog(ln_channel_id(pChannel), "close: %s(%s)", p_str, txid_str);
        }
    }

    ln_db_revtx_load(pChannel, p_db_param);
    const utl_buf_t *p_vout = ln_revoked_vout(pChannel);
    if (p_vout == NULL) {
        switch (stat) {
        case LN_STATUS_CLOSE_MUTUAL:
            LOGD("closed: mutual close\n");
            del = true;
            break;
        case LN_STATUS_CLOSE_UNI_LOCAL:
            //最新のlocal commit_tx --> unilateral close(local)
            del = monitor_close_unilateral_local(pChannel, p_db_param);
            break;
        case LN_STATUS_CLOSE_UNI_REMOTE:
            //最新のremote commit_tx --> unilateral close(remote)
            del = close_unilateral_remote(pChannel, p_db_param);
            break;
        case LN_STATUS_CLOSE_REVOKED:
            //相手にrevoked transaction closeされた
            LOGD("closed: revoked transaction close\n");
            ret = ln_close_remote_revoked(pChannel, &close_tx, p_db_param);
            if (ret) {
                if (ln_revoked_cnt(pChannel) > 0) {
                    //revoked transactionのvoutに未解決あり
                    //  2回目以降はclose_revoked_after()が呼び出される
                    del = close_revoked_first(pChannel, &close_tx, p_param->confm, p_db_param);
                } else {
                    LOGD("all revoked transaction vout is already solved.\n");
                    del = true;
                }
            } else {
                LOGE("fail: ln_close_remote_revoked\n");
            }
            break;
        default:
            break;
        }
    } else {
        // revoked transaction close
        del = close_revoked_after(pChannel, p_param->confm, p_db_param);
    }
    btc_tx_free(&close_tx);

    if (del) {
        (void)monchanlist_search(NULL, ln_channel_id(pChannel), true);
    }

    return del;
}


static bool channel_reconnect(ln_channel_t *pChannel)
{
    const uint8_t *p_node_id = ln_remote_node_id(pChannel);
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
    //pChannel->last_connected_addrがあれば、それを使う
    switch (ln_last_connected_addr(pChannel)->type) {
    case LN_ADDR_DESC_TYPE_IPV4:
        sprintf(conn_addr[1].ipaddr, "%d.%d.%d.%d",
            ln_last_connected_addr(pChannel)->addr[0],
            ln_last_connected_addr(pChannel)->addr[1],
            ln_last_connected_addr(pChannel)->addr[2],
            ln_last_connected_addr(pChannel)->addr[3]);
        conn_addr[1].port = ln_last_connected_addr(pChannel)->port;
        LOGD("conn_addr[1]: %s:%d\n", conn_addr[1].ipaddr, conn_addr[1].port);
        break;
    default:
        //LOGD("addrtype: %d\n", anno.addr.type);
        break;
    }

    //conn_addr[2]
    //node_announcementで通知されたアドレスに接続する
    ln_msg_node_announcement_t anno;
    ln_msg_node_announcement_addresses_t addrs;
    utl_buf_t anno_buf = UTL_BUF_INIT;
    if (ln_node_search_nodeanno(&anno, &anno_buf, p_node_id) &&
        ln_msg_node_announcement_addresses_read(&addrs, anno.p_addresses, anno.addrlen) &&
        addrs.num) {
        ln_msg_node_announcement_address_descriptor_t *addr_desc = &addrs.addresses[0];
        switch (addr_desc->type) {
        case LN_ADDR_DESC_TYPE_IPV4:
            sprintf(conn_addr[2].ipaddr, "%d.%d.%d.%d",
                addr_desc->p_addr[0],
                addr_desc->p_addr[1],
                addr_desc->p_addr[2],
                addr_desc->p_addr[3]);
            conn_addr[2].port = addr_desc->port;
            LOGD("conn_addr[2]: %s:%d\n", conn_addr[2].ipaddr, conn_addr[2].port);
            break;
        default:
            //LOGD("addrtype: %d\n", anno.addr.type);
            break;
        }
    }
    utl_buf_free(&anno_buf);

    for (size_t lp = 0; lp < ARRAY_SIZE(conn_addr); lp++) {
        if (!conn_addr[lp].port) continue;
        if (node_connect_ipv4(p_node_id, conn_addr[lp].ipaddr, conn_addr[lp].port)) {
            //success
            break;
        }
        //if not default port, try default port
        if (conn_addr[lp].port == LN_PORT_DEFAULT) continue;
        if (node_connect_ipv4(p_node_id, conn_addr[lp].ipaddr, LN_PORT_DEFAULT)) {
            //success
            break;
        }
    }

    return false;
}


static bool node_connect_ipv4(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port)
{
    int retval = -1;
    bool ret = ptarmd_nodefail_get(
                    pNodeId, pIpAddr, LN_PORT_DEFAULT,
                    LN_ADDR_DESC_TYPE_IPV4, false);
    if (!ret) {
        //ノード接続失敗リストに載っていない場合は、自分に対して「接続要求」のJSON-RPCを送信する
        retval = cmd_json_connect(pNodeId, pIpAddr, Port);
        LOGD("retval=%d\n", retval);
    }

    return retval == 0;
}


// Unilateral Close(自分がcommit_tx展開): Offered HTLC output
//Unilateral Close Handling: Local Commitment Transaction
//  HTLC Output Handling: Local Commitment, Local Offers
static bool close_unilateral_local_offered(ln_channel_t *pChannel, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    LOGD("offered HTLC output\n");
    if (!spent) {
        //タイムアウト用Txを展開
        //  commit_txが展開されてcltv_expiryブロック経過するまではBIP68エラーになる
        return true; //return send request
    }
    uint16_t update_idx;
    if (!ln_update_info_get_update(
        &pChannel->update_info, &update_idx, LN_UPDATE_TYPE_ADD_HTLC, pCloseDat->p_htlc_idxs[lp])) return false;
    const ln_update_t *p_update = &pChannel->update_info.updates[update_idx];
    if (!p_update) return false;
    const ln_htlc_t *p_htlc = ln_htlc(pChannel, pCloseDat->p_htlc_idxs[lp]);
    if (!p_htlc) return false;

    //extract the preimage for backwinding
    LOGD("hop node\n");
    LOGD("  neighbor_short_channel_id=%016" PRIx64 "(vout=%d)\n",
        p_htlc->neighbor_short_channel_id, pCloseDat->p_tx[lp].vin[0].index);

    uint32_t confirm;
    if (!btcrpc_get_confirm(&confirm, ln_funding_info_txid(&pChannel->funding_info))) {
        LOGE("fail: get confirmation\n");
        return false;
    }
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(&pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT], txid);
    if (!btcrpc_search_outpoint(&tx, confirm, txid, pCloseDat->p_tx[lp].vin[0].index)) {
        LOGD("not found txid: ");
        TXIDD(txid);
        LOGD("index=%d\n", lp);
        *pDel = false;
        btc_tx_free(&tx);
        return false;
    }
    const utl_buf_t *p_buf = ln_preimage_remote(&tx);
    if (!p_buf) {
        btc_tx_free(&tx);
        return false;
    }
    LOGD("backwind preimage: ");
    DUMPD(p_buf->buf, p_buf->len);

    //register preimage
    //  (自分が持っているのと同じ状態にする)
    ln_db_preimage_t preimage;
    memcpy(preimage.preimage, p_buf->buf, LN_SZ_PREIMAGE);
    preimage.amount_msat = 0;
    preimage.expiry = UINT32_MAX;
    ln_db_preimage_save(&preimage, pDbParam);
    btc_tx_free(&tx);
    return false; //not return send request
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
static bool close_unilateral_remote(ln_channel_t *pChannel, void *pDbParam)
{
    bool del = true;
    ln_close_force_t close_dat;

    LOGD("closed: unilateral close[remote]\n");

    bool ret = ln_close_create_tx(pChannel, &close_dat);
    if (ret) {
        for (int lp = 0; lp < close_dat.num; lp++) {
            const btc_tx_t *p_tx = &close_dat.p_tx[lp];
            if (lp == LN_CLOSE_IDX_COMMIT) {
                //LOGD("$$$ commit_tx\n");
            } else if (lp == LN_CLOSE_IDX_TO_LOCAL) {
                //LOGD("$$$ to_local tx\n");
            } else if (lp == LN_CLOSE_IDX_TO_REMOTE) {
                if (p_tx->vin_cnt > 0) {
                    LOGD("$$$ to_remote tx ==> DB\n");

                    uint8_t pub[BTC_SZ_PUBKEY];
                    btc_keys_priv2pub(pub, p_tx->vin[0].witness[0].buf);

                    ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TO_REMOTE);
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
                    bool ret = btcrpc_check_unspent(ln_remote_node_id(pChannel), &unspent, NULL,
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
                    if ((p_tx->vout_cnt > 0) && (p_tx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED)) {
                        //preimageを取得できていない
                        LOGD("  not have preimage\n");
                        close_unilateral_remote_offered(pChannel, &del, &close_dat, lp, pDbParam);
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
//Unilateral Close Handling: Remote Commitment Transaction
//  HTLC Output Handling: Remote Commitment, Remote Offers
static void close_unilateral_remote_offered(ln_channel_t *pChannel, bool *pDel, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    //XXX:
    //Probably this function will be for `Received` HTLC output not `Offered`...

    LOGD("offered HTLC output\n");

    //XXX: We should return a return value

    const ln_htlc_t *p_htlc = ln_htlc(pChannel, pCloseDat->p_htlc_idxs[lp]);
    if (!p_htlc) return;

    bool unspent;
    if (btcrpc_check_unspent(
        ln_remote_node_id(pChannel), &unspent, NULL, pCloseDat->p_tx[lp].vin[0].txid,
        pCloseDat->p_tx[lp].vin[0].index)) {
        if (!unspent) {
            LOGD("already spent\n");
            ln_db_wallet_del(pCloseDat->p_tx[lp].vin[0].txid, pCloseDat->p_tx[lp].vin[0].index);
            return;
        }
    }

    LOGD("  neighbor_short_channel_id=%016" PRIx64 "(vout=%d)\n",
        p_htlc->neighbor_short_channel_id, pCloseDat->p_tx[lp].vin[0].index);
    uint32_t confirm;
    if (!btcrpc_get_confirm(&confirm, ln_funding_info_txid(&pChannel->funding_info))) {
        LOGE("fail: get confirmation\n");
        return;
    }

    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(&pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT], txid);
    if (!btcrpc_search_outpoint(&tx, confirm, txid, pCloseDat->p_tx[lp].vin[0].index)) {
        LOGD("not found txid: ");
        TXIDD(txid);
        LOGD("index=%d\n", pCloseDat->p_htlc_idxs[lp]);
        *pDel = false;
        btc_tx_free(&tx);
        return;
    }
    //preimageを登録(自分が持っているのと同じ状態にする)
    const utl_buf_t *p_buf = ln_preimage_remote(&tx);
    if (!p_buf) {
        btc_tx_free(&tx);
        return;
    }
    LOGD("backwind preimage: ");
    DUMPD(p_buf->buf, p_buf->len);

    ln_db_preimage_t preimage;
    memcpy(preimage.preimage, p_buf->buf, LN_SZ_PREIMAGE);
    preimage.amount_msat = 0;
    preimage.expiry = UINT32_MAX;
    ln_db_preimage_save(&preimage, pDbParam);
    btc_tx_free(&tx);
}


static bool close_unilateral_local_sendreq(bool *pDel, const btc_tx_t *pTx, const btc_tx_t *pHtlcTx, int Num)
{
    utl_buf_t buf = UTL_BUF_INIT;
    uint8_t txid[BTC_SZ_TXID];

    btc_tx_write(pTx, &buf);
    bool ret = btcrpc_send_rawtx(txid, NULL, buf.buf, buf.len);
    utl_buf_free(&buf);
    if (ret) {
        LOGD("$$$ broadcast\n");

        if ( (pTx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) ||
             (pTx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED) ) {
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

    return ret;
}


/** revoked transactionから即座に取り戻す
 *
 * @param[in,out]   pChannel
 * @param[in]       pTx         revoked transaction
 * @param[in]       confm       confirmation
 * @param[in]       pDbParam    DB parameter
 */
static bool close_revoked_first(ln_channel_t *pChannel, btc_tx_t *pTx, uint32_t confm, void *pDbParam)
{
    bool del = false;
    bool save = true;
    bool ret;

    ptarmd_eventlog(ln_channel_id(pChannel), "close: ugly way");

    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        const utl_buf_t *p_vout = ln_revoked_vout(pChannel);

        LOGD("vout[%u]=", lp);
        DUMPD(pTx->vout[lp].script.buf, pTx->vout[lp].script.len);
        if (utl_buf_equal(&pTx->vout[lp].script, &p_vout[LN_RCLOSE_IDX_TO_LOCAL])) {
            LOGD("[%u]to_local !\n", lp);

            ret = close_revoked_to_local(pChannel, pTx, lp);
            if (ret) {
                del = ln_revoked_cnt_dec(pChannel);
                ln_set_revoked_confm(pChannel, confm);
            } else {
                save = false;
            }
        } else if (utl_buf_equal(&pTx->vout[lp].script, &p_vout[LN_RCLOSE_IDX_TO_REMOTE])) {
            LOGD("[%u]to_remote !\n", lp);
            ret = close_revoked_to_remote(pChannel, pTx, lp);
            if (ret) {
                save = true;
            }
        } else {
            for (int lp2 = LN_RCLOSE_IDX_HTLC; lp2 < ln_revoked_num(pChannel); lp2++) {
                // LOGD("p_vout[%u][%d]=", lp, lp2);
                // DUMPD(p_vout[lp2].buf, p_vout[lp2].len);
                if (utl_buf_equal(&pTx->vout[lp].script, &p_vout[lp2])) {
                    LOGD("[%u]HTLC vout[%d] !\n", lp, lp2);

                    ret = close_revoked_htlc(pChannel, pTx, lp, lp2);
                    if (ret) {
                        del = ln_revoked_cnt_dec(pChannel);
                        ln_set_revoked_confm(pChannel, confm);
                    }
                } else {
                    LOGD(" --> not match\n");
                }
            }
        }
    }
    if (save) {
        ln_db_revtx_save(pChannel, true, pDbParam);
    }

    return del;
}


/** HTLC Timeout/Success Tx後から取り戻す
 *
 * @param[in,out]   pChannel
 * @param[in]       confm       confirmation
 * @param[in]       pDbParam    DB parameter
 */
static bool close_revoked_after(ln_channel_t *pChannel, uint32_t confm, void *pDbParam)
{
    bool del = false;

    if (confm != ln_revoked_confm(pChannel)) {
        //HTLC Timeout/Success Txのvoutと一致するトランザクションを検索
        utl_buf_t txbuf = UTL_BUF_INIT;
        const utl_buf_t *p_vout = ln_revoked_vout(pChannel);
        bool ret = btcrpc_search_vout(&txbuf, confm - ln_revoked_confm(pChannel), &p_vout[0]);
        if (ret) {
            bool sendret = true;
            int num = txbuf.len / sizeof(btc_tx_t);
            LOGD("find! %d\n", num);
            btc_tx_t *pTx = (btc_tx_t *)txbuf.buf;
            for (int lp = 0; lp < num; lp++) {
                LOGD("-------- %d ----------\n", lp);
                btc_tx_print(&pTx[lp]);

                ret = close_revoked_to_local(pChannel, &pTx[lp], 0);
                btc_tx_free(&pTx[lp]);
                if (ret) {
                    del = ln_revoked_cnt_dec(pChannel);
                    LOGD("del=%d, revoked_cnt=%d\n", del, ln_revoked_cnt(pChannel));
                } else {
                    sendret = false;
                    break;
                }
            }
            utl_buf_free(&txbuf);

            if (sendret) {
                ln_set_revoked_confm(pChannel, confm);
                ln_db_revtx_save(pChannel, false, pDbParam);
                LOGD("del=%d, revoked_cnt=%d\n", del, ln_revoked_cnt(pChannel));
            } else {
                //送信エラーがあった場合には、次回やり直す
                LOGD("sendtx error\n");
            }
        } else {
            ln_set_revoked_confm(pChannel, confm);
            ln_db_revtx_save(pChannel, false, pDbParam);
            LOGD("no target txid: %u, revoked_cnt=%d\n", confm, ln_revoked_cnt(pChannel));
        }
    } else {
        LOGD("same block: %u, revoked_cnt=%d\n", confm, ln_revoked_cnt(pChannel));
    }

    return del;
}


//revoked to_local output/HTLC Timeout/Success Txを取り戻す
static bool close_revoked_to_local(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    const utl_buf_t *p_wit = ln_revoked_wit(pChannel);

    bool ret = ln_wallet_create_to_local(pChannel, &tx,
                pTx->vout[VIndex].value,
                ln_commit_info_remote(pChannel)->to_self_delay,
                &p_wit[0], txid, VIndex, true);
    if (ret) {
        if (tx.vin_cnt > 0) {
            LOGD("$$$ to_local tx ==> DB\n");

            ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TO_LOCAL);
            set_wallet_data(&wlt, &tx);
            wlt.sequence = ln_commit_info_remote(pChannel)->to_self_delay;
            ln_db_wallet_add(&wlt);
        }

        btc_tx_free(&tx);
    }

    return ret;
}


//revoked to_remote outputを取り戻す
//  to_remoteはP2WPKHで支払い済みだが、bitcoindがremotekeyを知らないため、転送する
static bool close_revoked_to_remote(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    bool ret = ln_wallet_create_to_remote(
                    pChannel, &tx, pTx->vout[VIndex].value,
                    txid, VIndex);
    if (ret) {
        if (tx.vin_cnt > 0) {
            LOGD("$$$ to_remote tx ==> DB\n");

            ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TO_REMOTE);
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
static bool close_revoked_htlc(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex, int WitIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    ln_revokedhtlc_create_spenttx(pChannel, &tx, pTx->vout[VIndex].value, WitIndex, txid, VIndex);
    btc_tx_print(&tx);
    utl_buf_t buf = UTL_BUF_INIT;
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


/** 最新のfeerate_per_kw取得
 *
 * @return      bitcoind estimatesmartfeeから算出したfeerate_per_kw(取得失敗=0)
 * @note
 *      - #LN_FEERATE_PER_KW_MIN未満になる場合、#LN_FEERATE_PER_KW_MINを返す
 */
static uint32_t get_latest_feerate_kw(void)
{
    //estimate fee
    uint32_t feerate_kw;
    uint64_t feerate_kb = 0;
    bool ret = btcrpc_estimatefee(&feerate_kb, LN_BLK_FEEESTIMATE);
    if (ret) {
        feerate_kw = ln_feerate_per_kw_calc(feerate_kb);
        if (feerate_kw < LN_FEERATE_PER_KW_MIN) {
            // estimatesmartfeeは1000satoshisが下限のようだが、c-lightningは1000/4=250ではなく253を下限としている。
            //      https://github.com/ElementsProject/lightning/issues/1443
            //      https://github.com/ElementsProject/lightning/issues/1391
            //LOGD("FIX: calc feerate_per_kw(%" PRIu32 ") < MIN\n", feerate_kw);
            feerate_kw = LN_FEERATE_PER_KW_MIN;
        }
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_kw);
    } else if (btc_block_get_chain(ln_genesishash_get()) == BTC_BLOCK_CHAIN_BTCREGTEST) {
        LOGD("regtest\n");
        feerate_kw = LN_FEERATE_PER_KW;
    } else {
        LOGE("fail: estimatefee\n");
        feerate_kw = 0;
    }

    return feerate_kw;
}


static bool update_btc_values(void)
{
#ifdef USE_BITCOINJ
    int32_t height;
    bool ret = btcrpc_getblockcount(&height);
    if (ret && (height != mMonParam.height)) {
        mMonParam.height = height;

        //update feerate if blockcount changed
        if (mFeeratePerKw == 0) {
            mMonParam.feerate_per_kw = get_latest_feerate_kw();
        } else {
            mMonParam.feerate_per_kw = mFeeratePerKw;
        }
        if (mMonParam.feerate_per_kw < LN_FEERATE_PER_KW_MIN) {
            mMonParam.feerate_per_kw = 0;
        }
    }
#else
    //update feerate if blockcount changed
    if (mFeeratePerKw == 0) {
        mMonParam.feerate_per_kw = get_latest_feerate_kw();
    } else {
        mMonParam.feerate_per_kw = mFeeratePerKw;
    }
    if (mMonParam.feerate_per_kw < LN_FEERATE_PER_KW_MIN) {
        mMonParam.feerate_per_kw = 0;
    }
    bool ret = btcrpc_getblockcount(&mMonParam.height);
#endif
    return ret;
}


static bool monchanlist_search(monchanlist_t **ppList, const uint8_t *pChannelId, bool bRemove)
{
    bool detect = false;
    monchanlist_t *p = LIST_FIRST(&mMonChanListHead);
    while (p != NULL) {
        if (memcmp(p->channel_id, pChannelId, LN_SZ_CHANNEL_ID) == 0) {
            if (!bRemove) {
                *ppList = p;
            } else {
                LOGD("remove from list\n");
                LIST_REMOVE(p, list);
                UTL_DBG_FREE(p);
            }
            detect = true;
            break;
        }
        p = LIST_NEXT(p, list);
    }

    return detect;
}


static void monchanlist_add(monchanlist_t *pList)
{
    LIST_INSERT_HEAD(&mMonChanListHead, pList, list);
}
