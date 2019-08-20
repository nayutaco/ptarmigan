/*
 *  Copyright (C) 2017 Ptarmigan Project
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
#include "ln_normalope.h"

#include "ptarmd.h"
#include "p2p.h"
#include "lnapp.h"
#include "lnapp_manager.h"
#include "btcrpc.h"
#include "cmd_json.h"
#include "monitoring.h"
#include "wallet.h"


/**************************************************************************
 * macro
 **************************************************************************/

#define M_WAIT_START_SEC                    (5)         ///< monitoring start[sec]
#ifdef DEVELOPER_MODE
//Workaround for `lightning-integration`'s timeout (outside BOLT specifications)
#define M_WAIT_MON_SEC                      (20)        ///< monitoring cyclic[sec] for developer mode
#else
#define M_WAIT_MON_SEC                      (30)        ///< monitoring cyclic[sec]
#endif
#define M_WAIT_MON_PRUNE_NODE_SEC           (5)         ///< monitoring cyclic[sec] (prune node)
#define M_WAIT_MON_PROC_INACTIVE_NODE_SEC   (1)         ///< monitoring cyclic[sec] (proc inactive node)

//offset for btcrpc_search_outpoint(), btcrpc_search_vout()
#define M_SEARCH_OUTPOINT(conf)         ((conf) + 3)

#define M_SZ_SCRIPT_PARAM       (512)


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

static volatile bool        mActive = true;             ///< true:監視thread継続
static bool                 mDisableAutoConn;           ///< true:channelのある他nodeへの自動接続停止
static uint32_t             mFeeratePerKw;              ///< 0:estimate fee / !0:use this value
static monparam_t           mMonParam;
static struct monchanlisthead_t mMonChanListHead;


/********************************************************************
 * prototypes
 ********************************************************************/

static void connect_nodelist(void);
static void proc_inactive_channel(lnapp_conf_t *pConf, void *pParam);
static bool monfunc(lnapp_conf_t *pConf, void *pDbParam, void *pParam);
static void monfunc_2(lnapp_conf_t *pConf, void *pParam);

static bool funding_unspent(lnapp_conf_t *pConf, monparam_t *pParam, void *pDbParam);
static bool funding_spent(lnapp_conf_t *pConf, monparam_t *pParam, void *pDbParam);
static bool channel_reconnect(lnapp_conf_t *pConf);
static bool node_connect_ipv4(const uint8_t *pNodeId, const char *pIpAddr, uint16_t Port);

static bool close_unilateral_local(ln_channel_t *pChannel, void *pDbParam, uint32_t MinedHeight);
static void close_unilateral_local_offered(ln_channel_t *pChannel, bool *pDel, ln_close_force_t *pCloseDat, int lp);
static bool close_unilateral_local_htlc_sendreq(const btc_tx_t *pTx, const btc_tx_t *pHtlcTx, int Num);

static bool close_unilateral_remote(ln_channel_t *pChannel, uint32_t MinedHeight);
static void close_unilateral_remote_received(ln_channel_t *pChannel, bool *pDel, ln_close_force_t *pCloseDat, int lp);

static bool update_fail_htlc_forward(ln_channel_t *pChannel, ln_close_force_t *pCloseDat, int lp);

static bool close_revoked_first(ln_channel_t *pChannel, btc_tx_t *pTx, uint32_t confm, void *pDbParam, uint32_t MinedHeight);
static bool close_revoked_after(ln_channel_t *pChannel, uint32_t confm, void *pDbParam, uint32_t MinedHeight);
static bool close_revoked_to_local(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex, uint32_t MinedHeight);
static bool close_revoked_to_remote(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex, uint32_t MinedHeight);
static bool close_revoked_htlc(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex, int WitIndex);

static void set_wallet_data(ln_db_wallet_t *pWlt, const btc_tx_t *pTx);

static uint32_t get_latest_feerate_kw(void);
static bool update_btc_values(void);

static bool monchanlist_search(monchanlist_t **ppList, const uint8_t *pChannelId, bool bRemove);
static void monchanlist_add(monchanlist_t *pList);


/**************************************************************************
 * public functions
 **************************************************************************/

void *monitor_start(void *pArg)
{
    (void)pArg;

    LOGD("[THREAD]monitor initialize\n");

    update_btc_values();

    //wait for accept user command before reconnect
    for (int lp = 0; lp < M_WAIT_START_SEC; lp++) {
        sleep(1);
        if (!mActive) {
            break;
        }
    }

    connect_nodelist();

    for (uint32_t lp = 0; mActive; lp++) {
        if (!(lp % M_WAIT_MON_SEC)) {
            LOGD("$$$----begin\n");
            if (update_btc_values()) {
                lnapp_manager_each_node(monfunc_2, &mMonParam);
            }
            LOGD("$$$----end\n");
        }
        if (!(lp % M_WAIT_MON_PRUNE_NODE_SEC)) {
            lnapp_manager_prune_node();
        }
        if (!(lp % M_WAIT_MON_PROC_INACTIVE_NODE_SEC)) {
            lnapp_manager_each_node(proc_inactive_channel, NULL);
        }
        mActive = !btcrpc_exception_happen();
        sleep(1);
    }
    LOGD("[exit]monitor thread\n");
    ptarmd_stop();

    return NULL;
}


void monitor_stop(void)
{
    LOGD("stop\n");
    mActive = false;
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


/* broadcast commit_tx
 */
bool monitor_close_unilateral_local(ln_channel_t *pChannel)
{
    LOGD("close: unilateral close[local]\n");

    bool ret;
    ln_close_force_t close_dat;
    ret = ln_close_create_unilateral_tx(pChannel, &close_dat);
    if (!ret) {
        LOGE("fail\n");
        return false;
    }

    utl_buf_t buf = UTL_BUF_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_write(&close_dat.p_tx[LN_CLOSE_IDX_COMMIT], &buf);
    ret = btcrpc_send_rawtx(txid, NULL, buf.buf, buf.len);
    utl_buf_free(&buf);
    if (ret) {
        LOGD("$$$ broadcast\n");
    } else {
        LOGE("fail: broadcast\n");
    }
    ln_close_free_forcetx(&close_dat);
    return ret;
}


static bool update_fail_htlc_forward(ln_channel_t *pChannel, ln_close_force_t *pCloseDat, int lp)
{
    uint16_t update_idx;
    if (!ln_update_info_get_update(
        &pChannel->update_info, &update_idx, LN_UPDATE_TYPE_ADD_HTLC, pCloseDat->p_htlc_idxs[lp])) return false;
    const ln_update_t *p_update = &pChannel->update_info.updates[update_idx];
    if (!p_update) return false;
    const ln_htlc_t *p_htlc = ln_htlc(pChannel, pCloseDat->p_htlc_idxs[lp]);
    if (!p_htlc) return false;

    utl_buf_t   reason = UTL_BUF_INIT;
    utl_push_t  push_reason;
    utl_push_init(&push_reason, &reason, 0);
    utl_push_u16be(&push_reason, LNONION_PERM_CHAN_FAIL);

    if (!ln_update_fail_htlc_forward(
        p_htlc->neighbor_short_channel_id, p_htlc->neighbor_id, reason.buf, reason.len)) {
        LOGE("fail: ???\n");
        utl_buf_free(&reason);
        return false;
    }
    utl_buf_free(&reason);
    return true;
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
        LOGD("no connect list\n");
        UTL_DBG_FREE(p_conf);
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


static void proc_inactive_channel(lnapp_conf_t *pConf, void *pParam)
{
    (void)pParam;

    pthread_mutex_lock(&pConf->mux_conf);
    if (!pConf->active) {
        ln_idle_proc_inactive(&pConf->channel);
    }
    pthread_mutex_unlock(&pConf->mux_conf);
}


/** 監視処理(#ln_db_channel_search()のコールバック)
 *
 * @param[in,out]   pConf       conf
 * @param[in,out]   p_db_param  DB情報
 * @param[in,out]   p_param     パラメータ(未使用)
 * @return  false(always)
 */
static bool monfunc(lnapp_conf_t *pConf, void *pDbParam, void *pParam)
{
    monparam_t      *p_param = (monparam_t *)pParam;
    ln_channel_t    *p_channel = &pConf->channel;

    p_param->confm = 0;
    bool b_get = btcrpc_get_confirmations_funding_tx(
        &p_param->confm, &p_channel->funding_info);
    if (b_get) {
        if (p_param->confm > pConf->funding_confirm) {
            pConf->funding_confirm = p_param->confm;

            LOGD2("***********************************\n");
            LOGD2("* CONFIRMATION: %d\n", pConf->funding_confirm);
            LOGD2("*    funding_txid: ");
            TXIDD(ln_funding_info_txid(&pConf->channel.funding_info));
            LOGD2("***********************************\n");
        }
    }

    bool del = false;

    bool unspent = true;
    if (ln_status_is_closing(p_channel)) {
        unspent = false;
    } else {
        if (!btcrpc_check_unspent(
            ln_remote_node_id(p_channel), &unspent, NULL,
            ln_funding_info_txid(&p_channel->funding_info),
            ln_funding_info_txindex(&p_channel->funding_info))) {
            unspent = true;
        }
    }

    if (unspent) {
        del = funding_unspent(pConf, p_param, pDbParam);
    } else {
        del = funding_spent(pConf, p_param, pDbParam);
    }

    if (del) {
        bool ret;
        ln_status_set(p_channel, LN_STATUS_CLOSED); //XXX:

        LOGD("delete from DB\n");
        char str_ci[LN_SZ_CHANNEL_ID_STR * 2 + 1];
        utl_str_bin2str(str_ci, ln_channel_id(p_channel), LN_SZ_CHANNEL_ID);
        ln_db_forward_add_htlc_drop(ln_short_channel_id(p_channel));
        ln_db_forward_del_htlc_drop(ln_short_channel_id(p_channel));
        ln_db_channel_owned_del(ln_short_channel_id(p_channel));
        if (pDbParam) {
            ret = ln_db_channel_del_param(p_channel, pDbParam);
        } else {
            ret = ln_db_channel_del(p_channel->channel_id);
        }
        if (ret) {
            ptarmd_eventlog(ln_channel_id(p_channel), "close: finish");
            ptarmd_eventlog(NULL, "channel DB closed: %s", str_ci);
        } else {
            LOGE("fail: del channel: ");
            DUMPD(ln_channel_id(p_channel), LN_SZ_CHANNEL_ID);
        }
        btcrpc_del_channel(ln_remote_node_id(p_channel));

        // method: dbclosed
        // $1: short_channel_id
        // $2: node_id
        // $3: channel_id
        char param[M_SZ_SCRIPT_PARAM];
        char str_sci[LN_SZ_SHORT_CHANNEL_ID_STR + 1];
        ln_short_channel_id_string(str_sci, ln_short_channel_id(p_channel));
        char str_nodeid[BTC_SZ_PUBKEY * 2 + 1];
        utl_str_bin2str(str_nodeid, ln_node_get_id(), BTC_SZ_PUBKEY);
        snprintf(param, sizeof(param), "%s %s "
                    "%s",
                    str_sci, str_nodeid,
                    str_ci);
        ptarmd_call_script(PTARMD_EVT_DBCLOSED, param);
    }

    return false; //always
}


static void monfunc_2(lnapp_conf_t *pConf, void *pParam)
{
    pthread_mutex_lock(&pConf->mux_conf);
    /*ignore*/monfunc(pConf, NULL, pParam);
    pthread_mutex_unlock(&pConf->mux_conf);
}


static bool funding_unspent(lnapp_conf_t *pConf, monparam_t *pParam, void *pDbParam)
{
    bool del = false;
    ln_channel_t *p_channel = &pConf->channel;

    if (pConf->active) {
        //socket接続済みであれば、feerate_per_kwチェック
        if (ln_status_get(p_channel) == LN_STATUS_NORMAL_OPE) {
            lnapp_set_feerate(pConf, pParam->feerate_per_kw);
        }
    } else if (LN_DBG_NODE_AUTO_CONNECT() &&
        !mDisableAutoConn && !ln_status_is_closing(p_channel) ) {
        //socket未接続であれば、再接続を試行
        del = channel_reconnect(pConf);
    } else {
        //LOGD("No Auto connect mode\n");
    }

    //Offered HTLCのtimeoutチェック
    for (int lp = 0; lp < LN_UPDATE_MAX; lp++) {
        if (ln_is_offered_htlc_timeout(p_channel, lp, pParam->height)) {
            LOGD("detect: offered HTLC timeout[%d] --> close 0x%016" PRIx64 "\n", lp, ln_short_channel_id(p_channel));
            bool ret = monitor_close_unilateral_local(p_channel);
            if (!ret) {
                LOGE("fail: unilateral close\n");
            }
            break;
        }
    }

    uint32_t last_conf = ln_funding_last_confirm_get(p_channel);
    if (pParam->confm > last_conf) {
        // confirmation update
        ln_funding_last_confirm_set(p_channel, pParam->confm);
        ln_db_channel_save_last_confirm(p_channel, pDbParam);

        if (last_conf == 0) {
            // first confirmation update
            int32_t bheight = 0;
            int32_t bindex = 0;
            uint8_t mined_hash[BTC_SZ_HASH256];
            bool ret = btcrpc_get_short_channel_param(
                ln_remote_node_id(p_channel),
                &bheight, &bindex, mined_hash,
                ln_funding_info_txid(&p_channel->funding_info));
            if (ret) {
                LOGD("bindex=%d, bheight=%d\n", bindex, bheight);
                ln_short_channel_id_set_param(p_channel, bheight, bindex);

                //mined block hash
                ln_funding_blockhash_set(p_channel, mined_hash);

                btcrpc_set_channel(
                    ln_remote_node_id(p_channel),
                    ln_short_channel_id(p_channel),
                    ln_funding_info_txid(&p_channel->funding_info),
                    ln_funding_info_txindex(&p_channel->funding_info),
                    ln_funding_info_wit_script(&p_channel->funding_info),
                    ln_funding_blockhash(p_channel),
                    pParam->confm);
            }
        }
    }

    return del;
}


/**
 *
 * @param[in,out]   pConf       conf
 * @param[in]       pParam      param
 * @param[in,out]   pDbParam    DB情報
 * @retval      true    pChannelをDB削除可能
 */
static bool funding_spent(lnapp_conf_t *pConf, monparam_t *pParam, void *pDbParam)
{
    bool del = false;
    bool ret;
    char txid_str[BTC_SZ_TXID * 2 + 1];
    ln_channel_t *p_channel = &pConf->channel;
#if defined(USE_BITCOIND)
    uint32_t mined_height = UINT32_MAX; //0の場合はwallet DBに保存しないため
#elif defined(USE_BITCOINJ)
    uint32_t mined_height = 0;
#endif

    btc_tx_t close_tx = BTC_TX_INIT;
    ln_status_t stat = ln_status_get(p_channel);
    utl_str_bin2str_rev(txid_str, ln_funding_info_txid(&p_channel->funding_info), BTC_SZ_TXID);

    LOGD("$$$ close: %s (confirm=%" PRIu32 ", status=%s)\n", txid_str, pParam->confm, ln_status_string(p_channel));
    if (stat <= LN_STATUS_CLOSE_WAIT) {
        //update status
        monchanlist_t *p_list = NULL;
        ret = monchanlist_search(&p_list, ln_channel_id(p_channel), false);
        if (!ret) {
            p_list = (monchanlist_t *)UTL_DBG_MALLOC(sizeof(monchanlist_t));
            memcpy(p_list->channel_id, ln_channel_id(p_channel), LN_SZ_CHANNEL_ID);
            p_list->last_check_confm = ln_funding_last_confirm_get(&pConf->channel);
            monchanlist_add(p_list);
        }
        btc_tx_t *p_tx = NULL;
        ret = btcrpc_search_outpoint(
            &close_tx, &mined_height,
            M_SEARCH_OUTPOINT(pParam->confm - p_list->last_check_confm),
            ln_funding_info_txid(&p_channel->funding_info),
            ln_funding_info_txindex(&p_channel->funding_info));
        if (ret) {
            p_tx = &close_tx;
        }
        p_list->last_check_confm = pParam->confm;
        if (ret || (stat == LN_STATUS_NORMAL_OPE)) {
            //funding_txをoutpointに持つtxがblockに入った or statusがNormal Operationのまま
            ln_close_change_stat(p_channel, p_tx, pDbParam);
            stat = ln_status_get(p_channel);
            const char *p_str = ln_status_string(p_channel);
            ptarmd_eventlog(ln_channel_id(p_channel), "close: %s(%s)", p_str, txid_str);
        }
    }

    if (pDbParam) {
        ln_db_revoked_tx_load(p_channel, pDbParam);
    }
    const utl_buf_t *p_vout = ln_revoked_vout(p_channel);
    if (p_vout == NULL) {
        switch (stat) {
        case LN_STATUS_CLOSE_MUTUAL:
            LOGD("closed: mutual close\n");
            del = true;
            break;
        case LN_STATUS_CLOSE_UNI_LOCAL:
            del = close_unilateral_local(p_channel, pDbParam, mined_height);
            break;
        case LN_STATUS_CLOSE_UNI_REMOTE_LAST:
            del = close_unilateral_remote(p_channel, mined_height);
            break;
        case LN_STATUS_CLOSE_UNI_REMOTE_SECOND_LAST:
            del = close_unilateral_remote(p_channel, mined_height);
            break;
        case LN_STATUS_CLOSE_REVOKED:
            LOGD("closed: revoked transaction close\n");
            ret = ln_close_remote_revoked(p_channel, &close_tx, pDbParam);
            if (ret) {
                if (ln_revoked_cnt(p_channel) > 0) {
                    //revoked transactionのvoutに未解決あり
                    //  2回目以降はclose_revoked_after()が呼び出される
                    del = close_revoked_first(p_channel, &close_tx, pParam->confm, pDbParam, mined_height);
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
        del = close_revoked_after(p_channel, pParam->confm, pDbParam, mined_height);
    }
    btc_tx_free(&close_tx);

    if (del) {
        (void)monchanlist_search(NULL, ln_channel_id(p_channel), true);
    }

    return del;
}


static bool channel_reconnect(lnapp_conf_t *pConf)
{
    ln_channel_t *p_channel = &pConf->channel;
    const uint8_t *p_node_id = ln_remote_node_id(p_channel);
    struct {
        char ipaddr[SZ_IPV4_LEN + 1];
        uint16_t port;
    } conn_addr[3];

    for (size_t lp = 0; lp < ARRAY_SIZE(conn_addr); lp++) {
        conn_addr[lp].port = 0;
    }


    //conn_addr[1]
    //p_channel->last_connected_addrがあれば、それを使う
    switch (ln_last_connected_addr(p_channel)->type) {
    case LN_ADDR_DESC_TYPE_IPV4:
        sprintf(conn_addr[1].ipaddr, "%d.%d.%d.%d",
            ln_last_connected_addr(p_channel)->addr[0],
            ln_last_connected_addr(p_channel)->addr[1],
            ln_last_connected_addr(p_channel)->addr[2],
            ln_last_connected_addr(p_channel)->addr[3]);
        conn_addr[1].port = ln_last_connected_addr(p_channel)->port;
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

    //this mutex was locked in `monfunc_2`
    //  we need to send json-rpc to reconnect
    //  and unlock the mutex before that
    pthread_mutex_unlock(&pConf->mux_conf); //unlock

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

    pthread_mutex_lock(&pConf->mux_conf); //lock

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


/* unilateral closeにおけるbitcoindとbitcoinjの実装差異について
 *
 *  bitcoindの場合、どのtransactionに対してもTXIDからconfirmationを取得できる。
 *  ptarmcli paytowalletでvinとして使用可能かどうかのチェックは容易である。
 *  また、TXIDが展開済みかどうかもmempoolの段階でチェックするため、btcrpc_is_tx_broadcasted()で
 *  事前にチェックできてしまう。
 *
 *  bitcoinjの場合、今のところminingされた情報しか取得できていない。
 *  また、展開済みかどうかも同じ要領で確認しているため、bitcoindよりも１テンポ遅れる。
 *  そしてもう1つ、bitcoinjではconfirmationが簡単には取得できない。
 *  そのため、miningされたblockcountを保持して、現在のheightからの差分でconfirmationを計算している。
 *
 * こうした理由から、set_wallet_data()の前後でbitcoind/bitcoinjによる違いが生じている。
 * wallet.cにも類似した実装がある。
 */

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
static bool close_unilateral_local(ln_channel_t *pChannel, void *pDbParam, uint32_t MinedHeight)
{
    (void)pDbParam;

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

        bool not_proc = true;
        if (lp == LN_CLOSE_IDX_COMMIT) {
            LOGD("$$$ commit_tx\n");
        } else if (lp == LN_CLOSE_IDX_TO_LOCAL) {
            if (p_tx->vin_cnt <= 0) {
                LOGD("skip to_local: tx[%d]\n", lp);
            }
            if (MinedHeight > 0) {
                LOGD("$$$ to_local tx ==> DB\n");
                ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TO_LOCAL);
                set_wallet_data(&wlt, p_tx);
                wlt.mined_height = MinedHeight;
                (void)ln_db_wallet_save(&wlt);
            } else {
                LOGD("MinedHeight==0\n");
            }
        } else if (lp == LN_CLOSE_IDX_TO_REMOTE) {
            LOGD("$$$ to_remote tx\n");
        } else {
            if (p_tx->vin_cnt <= 0) {
                LOGD("skip HTLC: tx[%d]\n", lp);
            } else {
                LOGD("$$$ HTLC[%d]\n", lp - LN_CLOSE_IDX_HTLC);
                not_proc = false;
            }
        }
        if (not_proc) {
            continue;
        }

        //check own tx is broadcasted
        uint8_t txid[BTC_SZ_TXID];
        btc_tx_txid(p_tx, txid);
        LOGD("txid[%d]= ", lp);
        TXIDD(txid);
        if (btcrpc_is_tx_broadcasted(ln_remote_node_id(pChannel), txid)) {
            LOGD("already broadcasted[%d] --> OK\n", lp);

#ifdef USE_BITCOINJ
            int32_t blkcnt = 0;
            uint32_t confm = 0;

            ret = monitor_btc_getblockcount(&blkcnt);
            if (ret) {
                ret = btcrpc_get_confirmations(&confm, txid);
            }
            if (ret && (confm > 0)) {
                //HTLC_txのconfirmationが確認できた場合に成功とする
                LOGD("already broadcasted: confm=%d\n", (int)confm);
                const btc_tx_t *p_htlc_tx = (const btc_tx_t *)close_dat.tx_buf.buf;
                int num = close_dat.tx_buf.len / sizeof(btc_tx_t);
                //展開したtxのvoutは、それぞれwallet DBに保存する
                for (int lp = 0; lp < num; lp++) {
                    if (p_htlc_tx[lp].vin_cnt > 0) {
                        LOGD("$$$ spending tx[%d] ==> DB\n", lp);
                        ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_HTLC_OUTPUT);
                        set_wallet_data(&wlt, &p_htlc_tx[lp]);
                        wlt.mined_height = blkcnt - confm + 1;
                        (void)ln_db_wallet_save(&wlt);
                    }
                }
                LOGD("OK\n");
            } else {
                ret = false;
            }
            if (!ret) {
                del = false;
            }
#endif

            continue;
        }

        //check each close_dat.p_tx[] INPUT is broadcasted
        //  ret:
        //    true: input tx is broadcasted
        //    false: not
        //  unspent:
        //    true: input is unspent
        //    false: spent
        bool unspent;
        if (!btcrpc_check_unspent(
                ln_remote_node_id(pChannel), &unspent, NULL,
                p_tx->vin[0].txid, p_tx->vin[0].index)) {
            LOGD("fail: check unspent\n");
            del = false;
            continue;
        }

        LOGD("  INPUT txid: ");
        TXIDD(p_tx->vin[0].txid);
        LOGD("    index: %d\n", p_tx->vin[0].index);
        LOGD("      --> unspent[%d]=%d\n", lp, unspent);

        bool send_req = false;
        if (p_tx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) {
            LOGD("offered HTLC output\n");
            if (unspent) {
                send_req = true;
            } else {
                LOGD("\n");
                //extract preimage
                close_unilateral_local_offered(pChannel, &del, &close_dat, lp);
                //delete from wallet DB if INPUT is SPENT ???
                ln_db_wallet_del(p_tx->vin[0].txid, p_tx->vin[0].index);
            }
        } else if (p_tx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED) {
            LOGD("received HTLC output\n");
            if (unspent) {
                if (p_tx->vin[0].wit_item_cnt) { //have preimage
                    send_req = true;
                } else {
                    LOGD("\n");
                    del = false;
                    continue;
                }
            } else {
                LOGD("\n");
                //delete from wallet DB if INPUT is SPENT ???
                ln_db_wallet_del(p_tx->vin[0].txid, p_tx->vin[0].index);
            }
        } else {
            LOGE("fail: ???\n");
        }

        if (send_req) {
            LOGD("sendreq HTLC[%d]\n", lp - LN_CLOSE_IDX_HTLC);
            const btc_tx_t *p_htlc_tx = (const btc_tx_t *)close_dat.tx_buf.buf;
            int num = close_dat.tx_buf.len / sizeof(btc_tx_t);
            if (close_unilateral_local_htlc_sendreq(p_tx, p_htlc_tx, num)) {
                if (p_tx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) {
                    LOGD("offered\n");
                    if (!update_fail_htlc_forward(pChannel, &close_dat, lp)) {
                        LOGE("fail: ???\n");
                    }
                }
            } else {
                LOGD("\n");
                del = false;
            }
        }
    }

    ln_close_free_forcetx(&close_dat);

    LOGD("del=%d\n", del);

    return del;
}


//Unilateral Close Handling: Local Commitment Transaction
//  HTLC Output Handling: Local Commitment, Local Offers
static void close_unilateral_local_offered(ln_channel_t *pChannel, bool *pDel, ln_close_force_t *pCloseDat, int lp)
{
    const ln_htlc_t *p_htlc = ln_htlc(pChannel, pCloseDat->p_htlc_idxs[lp]);
    if (!p_htlc) return;

    LOGD("  neighbor_short_channel_id=%016" PRIx64 "(vout=%d)\n",
        p_htlc->neighbor_short_channel_id, pCloseDat->p_tx[lp].vin[0].index);

    uint32_t confirm;
    if (!btcrpc_get_confirmations(&confirm, ln_funding_info_txid(&pChannel->funding_info))) {
        LOGE("fail: get confirmation\n");
        return;
    }

    btc_tx_t tx = BTC_TX_INIT;
    uint32_t mined_height = 0;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(&pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT], txid);
    if (!btcrpc_search_outpoint(
            &tx, &mined_height,
            M_SEARCH_OUTPOINT(confirm),
            txid, pCloseDat->p_tx[lp].vin[0].index)) {
        LOGD("not found txid: ");
        TXIDD(txid);
        LOGD("index=%d\n", lp);
        *pDel = false;
        btc_tx_free(&tx);
        return;
    }

    const utl_buf_t *p_buf = ln_preimage_remote(&tx);
    if (!p_buf) {
        LOGE("fail: get preimage\n");
        btc_tx_free(&tx);
        return;
    }

    //LOGD("backwind preimage: ");
    //DUMPD(p_buf->buf, p_buf->len);
    LOGD("backwind preimage\n");
    if (!ln_update_fulfill_htlc_forward(
        p_htlc->neighbor_short_channel_id, p_htlc->neighbor_id, p_buf->buf)) {
        LOGE("fail: ???\n");
        btc_tx_free(&tx);
        return;
    }

    btc_tx_free(&tx);
    return;
}


/** [unilateral close]broadcast and save wallet DB
 *      commit_txとto_localはここを通らない。
 *          commit_tx: unilateral close要求でbroadcast、wallet DBに保存するものはない。
 *          to_local : commit_txがminingされたらwallet DBに保存している。
 *      対象はoffered/received HTLC outputである。
 */
static bool close_unilateral_local_htlc_sendreq(const btc_tx_t *pTx, const btc_tx_t *pHtlcTx, int Num)
{
    bool ret;
    utl_buf_t buf = UTL_BUF_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_write(pTx, &buf);

#ifdef USE_BITCOINJ
    //bitcoinjでは、miningされるまで送信したかどうかの確証が得られないため、何度もこのルートを通る。
    int32_t blkcnt = 0;
    uint32_t confm = 0;

    btc_tx_txid(pTx, txid);
    ret = monitor_btc_getblockcount(&blkcnt);
    if (ret) {
        ret = btcrpc_get_confirmations(&confm, txid);
    }
    if (ret && (confm > 0)) {
        //HTLC_txのconfirmationが確認できた場合に成功とする
        LOGD("already broadcasted: confm=%d\n", (int)confm);
        //展開したtxのvoutは、それぞれwallet DBに保存する
        for (int lp = 0; lp < Num; lp++) {
            if (pHtlcTx[lp].vin_cnt > 0) {
                LOGD("$$$ spending tx[%d] ==> DB\n", lp);
                ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_HTLC_OUTPUT);
                set_wallet_data(&wlt, &pHtlcTx[lp]);
                wlt.mined_height = blkcnt - confm + 1;
                (void)ln_db_wallet_save(&wlt);
            }
        }
        LOGD("OK\n");
        return true;
    }
#endif

    ret = btcrpc_send_rawtx(txid, NULL, buf.buf, buf.len);
    utl_buf_free(&buf);
    if (ret) {
        LOGD("$$$ broadcast\n");
    } else {
        LOGE("fail: broadcast\n");
    }

#if defined(USE_BITCOIND)
    if (ret) {
        for (int lp = 0; lp < Num; lp++) {
            if (pHtlcTx[lp].vin_cnt > 0) {
                LOGD("$$$ spending tx[%d] ==> DB\n", lp);
                ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_HTLC_OUTPUT);
                set_wallet_data(&wlt, &pHtlcTx[lp]);
                wlt.mined_height = 0;
                (void)ln_db_wallet_save(&wlt);
            }
        }
    }

    return ret;
#elif defined(USE_BITCOINJ)
    return false;
#endif
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
 *
 * @param[in]       pChannel
 * @param[in]       MinedHeight     commit_txがminingされたblockcount
 */
static bool close_unilateral_remote(ln_channel_t *pChannel, uint32_t MinedHeight)
{
    ln_close_force_t close_dat;

    LOGD("closed: unilateral close[remote]\n");

    if (!ln_close_create_tx(pChannel, &close_dat)) {
        LOGE("fail: ???\n");
        return false;
    }

    bool del = true;
    for (int lp = 0; lp < close_dat.num; lp++) {
        const btc_tx_t *p_tx = &close_dat.p_tx[lp];

        if (lp == LN_CLOSE_IDX_COMMIT) {
            //LOGD("$$$ commit_tx\n");
            continue;
        } else if (lp == LN_CLOSE_IDX_TO_LOCAL) {
            //LOGD("$$$ to_local tx\n");
            continue;
        } else if (lp == LN_CLOSE_IDX_TO_REMOTE) {
            if (p_tx->vin_cnt <= 0) {
                LOGE("fail: skip tx[%d]\n", lp);
                continue;
            }
            LOGD("$$$ to_remote tx ==> DB\n");
            uint8_t pub[BTC_SZ_PUBKEY];
            btc_keys_priv2pub(pub, p_tx->vin[0].witness[0].buf);

            if (MinedHeight > 0) {
                ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TO_REMOTE);
                set_wallet_data(&wlt, p_tx);
                utl_buf_t wit_items[2] = {
                    { p_tx->vin[0].witness[0].buf, BTC_SZ_PRIVKEY },
                    { pub, sizeof(pub) }
                };
                wlt.wit_item_cnt = ARRAY_SIZE(wit_items);
                wlt.p_wit_items = wit_items;
                wlt.mined_height = MinedHeight;
                (void)ln_db_wallet_save(&wlt);
            } else {
                LOGD("MinedHeight==0\n");
            }
            continue;
        } else {
            if (p_tx->vin_cnt <= 0) {
                LOGE("fail: skip tx[%d]\n", lp);
                continue;
            }
            LOGD("$$$ HTLC[%d]\n", lp - LN_CLOSE_IDX_HTLC);
        }

        //check own tx is broadcasted
        uint8_t txid[BTC_SZ_TXID];
        btc_tx_txid(p_tx, txid);
        LOGD("txid[%d]= ", lp);
        TXIDD(txid);
        if (btcrpc_is_tx_broadcasted(ln_remote_node_id(pChannel), txid)) {
            LOGD("already broadcasted[%d] --> OK\n", lp);
            continue;
        }

        //check each close_dat.p_tx[] INPUT is broadcasted
        //  ret:
        //    true: input tx is broadcasted
        //    false: not
        //  unspent:
        //    true: input is unspent
        //    false: spent
        bool unspent;
        if (!btcrpc_check_unspent(
            ln_remote_node_id(pChannel), &unspent, NULL,
            p_tx->vin[0].txid, p_tx->vin[0].index)) {
            LOGE("fail: check unspent\n");
            del = false;
            continue;
        }

        LOGD("  INPUT txid: ");
        TXIDD(p_tx->vin[0].txid);
        LOGD("    index: %d\n", p_tx->vin[0].index);
        LOGD("      --> unspent[%d]=%d\n", lp, unspent);

        if (p_tx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_OFFERED) {
            LOGD("offered HTLC output\n");
            if (unspent) {
                if (p_tx->vin[0].wit_item_cnt) { //have preimage
                    //broadcast
                    utl_buf_t buf = UTL_BUF_INIT;
                    if (!btc_tx_write(p_tx, &buf)) {
                        LOGE("fail: ???\n");
                        utl_buf_free(&buf);
                        continue;
                    }
                    if (btcrpc_send_rawtx(txid, NULL, buf.buf, buf.len)) {
                        LOGD("$$$ broadcast\n");
                    } else {
                        LOGE("fail: broadcast\n");
                        del = false;
                    }
                    utl_buf_free(&buf);
                } else {
                    LOGD("\n");
                    del = false;
                }
            }
        } else if (p_tx->vout[0].opt == LN_COMMIT_TX_OUTPUT_TYPE_RECEIVED) {
            LOGD("received HTLC output\n");
            if (unspent) {
                //broadcast
                utl_buf_t buf = UTL_BUF_INIT;
                if (!btc_tx_write(p_tx, &buf)) {
                    LOGE("fail: ???\n");
                    utl_buf_free(&buf);
                    continue;
                }
                if (btcrpc_send_rawtx(txid, NULL, buf.buf, buf.len)) {
                    LOGD("$$$ broadcast\n");
                    //remote preimage was blocked! (to be timeout)
                    if (!update_fail_htlc_forward(pChannel, &close_dat, lp)) {
                        LOGE("fail: ???\n");
                    }
                } else {
                    LOGE("fail: broadcast\n");
                    del = false;
                }
                utl_buf_free(&buf);
            } else {
                LOGD("\n");
                //extract preimage
                close_unilateral_remote_received(pChannel, &del, &close_dat, lp);
            }
        } else {
            LOGE("fail: ???\n");
        }
    }

    ln_close_free_forcetx(&close_dat);
    LOGD("del=%d\n", del);
    return del;
}


//Unilateral Close Handling: Remote Commitment Transaction
//  HTLC Output Handling: Remote Commitment, Remote Offers
static void close_unilateral_remote_received(ln_channel_t *pChannel, bool *pDel, ln_close_force_t *pCloseDat, int lp)
{
    const ln_htlc_t *p_htlc = ln_htlc(pChannel, pCloseDat->p_htlc_idxs[lp]);
    if (!p_htlc) return;

    LOGD("  neighbor_short_channel_id=%016" PRIx64 "(vout=%d)\n",
        p_htlc->neighbor_short_channel_id, pCloseDat->p_tx[lp].vin[0].index);

    uint32_t confirm;
    if (!btcrpc_get_confirmations(&confirm, ln_funding_info_txid(&pChannel->funding_info))) {
        LOGE("fail: get confirmation\n");
        return;
    }

    btc_tx_t tx = BTC_TX_INIT;
    uint32_t mined_height = 0;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(&pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT], txid);
    if (!btcrpc_search_outpoint(
            &tx, &mined_height,
            M_SEARCH_OUTPOINT(confirm),
            txid, pCloseDat->p_tx[lp].vin[0].index)) {
        LOGD("not found txid: ");
        TXIDD(txid);
        LOGD("index=%d\n", pCloseDat->p_htlc_idxs[lp]);
        *pDel = false;
        btc_tx_free(&tx);
        return;
    }

    const utl_buf_t *p_buf = ln_preimage_remote(&tx);
    if (!p_buf) {
        LOGE("fail: get preimage\n");
        btc_tx_free(&tx);
        return;
    }
    //LOGD("backwind preimage: ");
    //DUMPD(p_buf->buf, p_buf->len);
    LOGD("backwind preimage\n");

    if (!ln_update_fulfill_htlc_forward(
        p_htlc->neighbor_short_channel_id, p_htlc->neighbor_id, p_buf->buf)) {
        LOGE("fail: ???\n");
        btc_tx_free(&tx);
        return;
    }

    btc_tx_free(&tx);
}


/** revoked transactionから即座に取り戻す
 *
 * @param[in,out]   pChannel
 * @param[in]       pTx         revoked transaction
 * @param[in]       confm       confirmation
 * @param[in]       pDbParam    DB parameter
 */
static bool close_revoked_first(ln_channel_t *pChannel, btc_tx_t *pTx, uint32_t confm, void *pDbParam, uint32_t MinedHeight)
{
    bool del = false;
    bool save = true;
    bool revoked = false;
    bool ret;

    ptarmd_eventlog(ln_channel_id(pChannel), "close: ugly way");

    for (uint32_t lp = 0; lp < pTx->vout_cnt; lp++) {
        const utl_buf_t *p_vout = ln_revoked_vout(pChannel);

        LOGD("vout[%u]=", lp);
        DUMPD(pTx->vout[lp].script.buf, pTx->vout[lp].script.len);
        if (utl_buf_equal(&pTx->vout[lp].script, &p_vout[LN_RCLOSE_IDX_TO_LOCAL])) {
            LOGD("[%u]to_local !\n", lp);

            ret = close_revoked_to_local(pChannel, pTx, lp, MinedHeight);
            if (ret) {
                del = ln_revoked_cnt_dec(pChannel);
                ln_set_revoked_confm(pChannel, confm);
                revoked = true;
            } else {
                save = false;
            }
        } else if (utl_buf_equal(&pTx->vout[lp].script, &p_vout[LN_RCLOSE_IDX_TO_REMOTE])) {
            LOGD("[%u]to_remote !\n", lp);
            ret = close_revoked_to_remote(pChannel, pTx, lp, MinedHeight);
            if (ret) {
                save = true;
                revoked = true;
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
        ln_db_revoked_tx_save(pChannel, true, pDbParam);
    }
    if (revoked) {
        //pay to wallet
        uint32_t feerate_per_kw = monitor_btc_feerate_per_kw();
        char addr[BTC_SZ_ADDR_STR_MAX + 1];
        ret = btc_keys_spk2addr(addr, &pChannel->shutdown_scriptpk_local);
        if (ret) {
            ret = wallet_from_ptarm(NULL, true, addr, feerate_per_kw);
        }
        if (ret) {
            LOGD("broadcast\n");
        } else {
            LOGE("fail\n");
        }
    }

    return del;
}


/** HTLC Timeout/Success Tx後から取り戻す
 *
 * @param[in,out]   pChannel
 * @param[in]       confm       confirmation
 * @param[in]       pDbParam    DB parameter
 */
static bool close_revoked_after(ln_channel_t *pChannel, uint32_t confm, void *pDbParam, uint32_t MinedHeight)
{
    bool del = false;

    if (confm != ln_revoked_confm(pChannel)) {
        //HTLC Timeout/Success Txのvoutと一致するトランザクションを検索
        utl_buf_t txbuf = UTL_BUF_INIT;
        const utl_buf_t *p_vout = ln_revoked_vout(pChannel);
        bool ret = btcrpc_search_vout(&txbuf, M_SEARCH_OUTPOINT(confm - ln_revoked_confm(pChannel)), &p_vout[0]);
        if (ret) {
            bool sendret = true;
            int num = txbuf.len / sizeof(btc_tx_t);
            LOGD("find! %d\n", num);
            btc_tx_t *pTx = (btc_tx_t *)txbuf.buf;
            for (int lp = 0; lp < num; lp++) {
                LOGD("-------- %d ----------\n", lp);
                btc_tx_print(&pTx[lp]);

                ret = close_revoked_to_local(pChannel, &pTx[lp], 0, MinedHeight);
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
                ln_db_revoked_tx_save(pChannel, false, pDbParam);
                LOGD("del=%d, revoked_cnt=%d\n", del, ln_revoked_cnt(pChannel));
            } else {
                //送信エラーがあった場合には、次回やり直す
                LOGD("sendtx error\n");
            }
        } else {
            ln_set_revoked_confm(pChannel, confm);
            ln_db_revoked_tx_save(pChannel, false, pDbParam);
            LOGD("no target txid: %u, revoked_cnt=%d\n", confm, ln_revoked_cnt(pChannel));
        }
    } else {
        LOGD("same block: %u, revoked_cnt=%d\n", confm, ln_revoked_cnt(pChannel));
    }

    return del;
}


//revoked to_local output/HTLC Timeout/Success Txを取り戻す
static bool close_revoked_to_local(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex, uint32_t MinedHeight)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    const utl_buf_t *p_wit_items = ln_revoked_wit(pChannel);

    bool ret = ln_wallet_create_to_local_2(pChannel, &tx,
                pTx->vout[VIndex].value,
                ln_commit_info_remote(pChannel)->to_self_delay,
                &p_wit_items[0], txid, VIndex, true);
    if (ret) {
        if (tx.vin_cnt > 0) {
            LOGD("$$$ to_local tx ==> DB\n");
            ln_db_wallet_t wlt = LN_DB_WALLET_INIT(LN_DB_WALLET_TYPE_TO_LOCAL);
            set_wallet_data(&wlt, &tx);
            wlt.sequence = BTC_TX_SEQUENCE;
            wlt.mined_height = MinedHeight;
            (void)ln_db_wallet_save(&wlt);
        }

        btc_tx_free(&tx);
    }

    return ret;
}


//revoked to_remote outputを取り戻す
//  to_remoteはP2WPKHで支払い済みだが、bitcoindがremotekeyを知らないため、転送する
static bool close_revoked_to_remote(const ln_channel_t *pChannel, const btc_tx_t *pTx, int VIndex, uint32_t MinedHeight)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(pTx, txid);

    bool ret = ln_wallet_create_to_remote_2(
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
            wlt.p_wit_items = witbuf;
            wlt.mined_height = MinedHeight;     //revoked transaction closeは即座に使用できる
            (void)ln_db_wallet_save(&wlt);
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
    pWlt->p_wit_items = pTx->vin[0].witness;
}


/** 最新のfeerate_per_kw取得
 *
 * @return      bitcoind estimatesmartfeeから算出したfeerate_per_kw(取得失敗=0)
 */
static uint32_t get_latest_feerate_kw(void)
{
    //estimate fee
    uint32_t feerate_kw;
    uint64_t feerate_kb = 0;
    bool ret = btcrpc_estimatefee(&feerate_kb, LN_BLK_FEEESTIMATE);
    if (ret) {
        feerate_kw = ln_feerate_per_kw_calc(feerate_kb);
        LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_kw);
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
    bool ret = btcrpc_getblockcount(&height, NULL);
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
        mMonParam.feerate_per_kw = LN_FEERATE_PER_KW_MIN;
    }
    bool ret = btcrpc_getblockcount(&mMonParam.height, NULL);
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
