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

#define PTARM_DEBUG_MEM
#include "ptarmd.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "lnapp.h"
#include "btcrpc.h"
#include "cmd_json.h"
#include "utl_misc.h"
#include "ln_db.h"

#include "monitoring.h"


/**************************************************************************
 * macro
 **************************************************************************/

#define M_WAIT_MON_SEC                  (30)        ///< 監視周期[sec]


/**************************************************************************
 * typedefs
 **************************************************************************/

typedef struct {
    uint32_t feerate_per_kw;
    int32_t height;
} monparam_t;


/**************************************************************************
 * private variables
 **************************************************************************/

static volatile bool        mMonitoring;                ///< true:監視thread継続
static bool                 mDisableAutoConn;           ///< true:channelのある他nodeへの自動接続停止
static uint32_t             mFeeratePerKw;              ///< 0:bitcoind estimatesmartfee使用 / 非0:強制feerate_per_kw


/********************************************************************
 * prototypes
 ********************************************************************/

static bool monfunc(ln_self_t *self, void *p_db_param, void *p_param);

static bool funding_spent(ln_self_t *self, uint32_t confm, void *p_db_param);
static bool channel_reconnect(ln_self_t *self, uint32_t confm, void *p_db_param);

static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);
static bool close_unilateral_local_received(bool spent);

static bool close_unilateral_remote(ln_self_t *self, void *pDbParam);
static bool close_unilateral_remote_offered(bool spent);
static bool close_unilateral_remote_received(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);

static bool close_revoked_first(ln_self_t *self, btc_tx_t *pTx, uint32_t confm, void *pDbParam);
static bool close_revoked_after(ln_self_t *self, uint32_t confm, void *pDbParam);
static bool close_revoked_tolocal(const ln_self_t *self, const btc_tx_t *pTx, int VIndex);
static bool close_revoked_toremote(const ln_self_t *self, const btc_tx_t *pTx, int VIndex);
static bool close_revoked_htlc(const ln_self_t *self, const btc_tx_t *pTx, int VIndex, int WitIndex);


/**************************************************************************
 * public functions
 **************************************************************************/

void *monitor_thread_start(void *pArg)
{
    (void)pArg;

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
        param.height = btcrpc_getblockcount();
        ln_db_self_search(monfunc, &param);
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
    uint64_t feerate_kb;
    bool ret = btcrpc_estimatefee(&feerate_kb, LN_BLK_FEEESTIMATE);
    if (ret) {
        feerate_kw = ln_calc_feerate_per_kw(feerate_kb);
    } else {
        LOGD("fail: estimatefee\n");
        feerate_kw = LN_FEERATE_PER_KW;
    }
    //LOGD("feerate_per_kw=%" PRIu32 "\n", feerate_kw);
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
 */
bool monitor_close_unilateral_local(ln_self_t *self, void *pDbParam)
{
    bool del;
    bool ret;
    ln_close_force_t close_dat;

    LOGD("unilateral close[local]\n");

    ret = ln_create_close_unilateral_tx(self, &close_dat);
    if (ret) {
        del = true;
        uint8_t txid[BTC_SZ_TXID];
        for (int lp = 0; lp < close_dat.num; lp++) {
            if (lp == LN_CLOSE_IDX_COMMIT) {
                LOGD("$$$ commit_tx\n");
                //for (int lp2 = 0; lp2 < close_dat.p_tx[lp].vout_cnt; lp2++) {
                //    LOGD("vout[%d]=%x\n", lp2, close_dat.p_tx[lp].vout[lp2].opt);
                //}
            } else if (lp == LN_CLOSE_IDX_TOLOCAL) {
                LOGD("$$$ to_local tx\n");
            } else if (lp == LN_CLOSE_IDX_TOREMOTE) {
                LOGD("$$$ to_remote tx\n");
            } else {
                LOGD("$$$ HTLC[%d]\n", lp - LN_CLOSE_IDX_HTLC);
            }
            if (close_dat.p_tx[lp].vin_cnt > 0) {
                //自分のtxを展開済みかチェック
                btc_tx_txid(txid, &close_dat.p_tx[lp]);
                LOGD("txid[%d]= ", lp);
                TXIDD(txid);
                bool broad = btcrpc_is_tx_broadcasted(self, txid);
                if (broad) {
                    LOGD("already broadcasted[%d]\n", lp);
                    LOGD("-->OK\n");
                    continue;
                }

                bool send_req = false;

                //展開済みチェック
                bool unspent;
                bool ret = btcrpc_check_unspent(&unspent, NULL, close_dat.p_tx[lp].vin[0].txid, close_dat.p_tx[lp].vin[0].index);
                if (!ret) {
                    goto LABEL_EXIT;
                }
                LOGD("vin unspent[%d]=%d\n", lp, unspent);

                //ln_create_htlc_tx()後だから、OFFERED/RECEIVEDがわかる
                switch (close_dat.p_tx[lp].vout[0].opt) {
                case LN_HTLCTYPE_OFFERED:
                    send_req = close_unilateral_local_offered(self, &del, !unspent, &close_dat, lp, pDbParam);
                    break;
                case LN_HTLCTYPE_RECEIVED:
                    send_req = close_unilateral_local_received(!unspent);
                    break;
                default:
                    LOGD("opt=%x\n", close_dat.p_tx[lp].vout[0].opt);
                    send_req = true;
                    break;
                }

                if (send_req) {
                    utl_buf_t buf;
                    btc_tx_create(&buf, &close_dat.p_tx[lp]);
                    int code = 0;
                    ret = btcrpc_sendraw_tx(txid, &code, buf.buf, buf.len);
                    LOGD("code=%d\n", code);
                    utl_buf_free(&buf);
                    if (ret) {
                        LOGD("broadcast now tx[%d]: ", lp);
                        TXIDD(txid);
                        LOGD("-->OK\n");
                    } else {
                        del = false;
                        LOGD("fail[%d]: sendrawtransaction\n", lp);
                    }
                }
            } else {
                LOGD("skip tx[%d]\n", lp);
            }
        }

        //自分が展開した場合には、HTLC Timeout/Success Txからの出力も行う
        btc_tx_t *p_tx = (btc_tx_t *)close_dat.tx_buf.buf;
        int num = close_dat.tx_buf.len / sizeof(btc_tx_t);
        for (int lp = 0; lp < num; lp++) {
            utl_buf_t buf;
            btc_tx_create(&buf, &p_tx[lp]);
            int code = 0;
            ret = btcrpc_sendraw_tx(txid, &code, buf.buf, buf.len);
            LOGD("code=%d\n", code);
            utl_buf_free(&buf);
            if (ret) {
                LOGD("broadcast now tx[%d]: ", lp);
                TXIDD(txid);
                LOGD("-->OK\n");
            } else if ((code == BTCRPC_ERR_MISSING_INPUT) || (code == BTCRPC_ERR_ALREADY_BLOCK)) {
                LOGD("through[%d]: already spent vin\n", lp);
            } else {
                del = false;
                LOGD("fail[%d]: sendrawtransaction\n", lp);
            }
        }

LABEL_EXIT:
        ln_free_close_force_tx(&close_dat);
    } else {
        del = false;
    }

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

    uint32_t confm = btcrpc_get_funding_confirm(self);
    if (confm > 0) {
        bool del = false;
        bool unspent;
        bool ret = btcrpc_check_unspent(&unspent, NULL, ln_funding_txid(self), ln_funding_txindex(self));
        if (ret && !unspent) {
            //funding_tx使用済み
            del = funding_spent(self, confm, p_db_param);
        } else {
            //funding_tx未使用
            lnapp_conf_t *p_app_conf = ptarmd_search_connected_cnl(ln_short_channel_id(self));
            if ((p_app_conf == NULL) && LN_DBG_NODE_AUTO_CONNECT() && !mDisableAutoConn) {
                //socket未接続であれば、再接続を試行
                del = channel_reconnect(self, confm, p_db_param);
            } else if (p_app_conf != NULL) {
                //socket接続済みであれば、feerate_per_kwチェック
                //  当面、feerate_per_kwを手動で変更した場合のみとする
                if ((mFeeratePerKw != 0) && (ln_feerate_per_kw(self) != p_prm->feerate_per_kw)) {
                    LOGD("differenct feerate_per_kw: %" PRIu32 " : %" PRIu32 "\n", ln_feerate_per_kw(self), p_prm->feerate_per_kw);
                    lnapp_send_updatefee(p_app_conf, p_prm->feerate_per_kw);
                }
            } else {
                //LOGD("No Auto connect mode\n");
            }
        }
        if (del) {
            LOGD("delete from DB\n");
            ret = ln_db_self_del_prm(self, p_db_param);
            if (ret) {
                lnapp_save_event(ln_channel_id(self), "close: finish");
            } else {
                LOGD("fail: del channel: ");
                DUMPD(ln_channel_id(self), LN_SZ_CHANNEL_ID);
            }
        }
    }

    return false;
}


/**
 *
 * @param[in,out]   self        チャネル情報
 * @param[in]       confm       confirmation数
 * @param[in,out]   p_db_param  DB情報
 * @retval      true    selfをDB削除可能
 */
static bool funding_spent(ln_self_t *self, uint32_t confm, void *p_db_param)
{
    bool del = false;
    bool ret;

    LOGD("close: confirm=%" PRIu32 "\n", confm);

    btc_tx_t close_tx = BTC_TX_INIT;
    ln_closetype_t type = ln_close_type(self);
    if (type == LN_CLOSETYPE_NONE) {
        //初めてclosing処理を行う(まだln_goto_closing()を呼び出していない)
        char txid_str[BTC_SZ_TXID * 2 + 1];
        utl_misc_bin2str_rev(txid_str, ln_funding_txid(self), BTC_SZ_TXID);
        lnapp_save_event(ln_channel_id(self), "close: funding_tx spent(%s)", txid_str);

        //funding_txをINPUTにもつtx
        ret = btcrpc_search_outpoint(&close_tx, confm, ln_funding_txid(self), ln_funding_txindex(self));
        if (ret) {
            LOGD("find!\n");

            ln_goto_closing(self, &close_tx, p_db_param);
            type = ln_close_type(self);
        } else {
            LOGD("fail: not found\n");
        }
    }

    ln_db_revtx_load(self, p_db_param);
    const utl_buf_t *p_vout = ln_revoked_vout(self);
    if (p_vout == NULL) {
        switch (type) {
        case LN_CLOSETYPE_MUTUAL:
            del = true;
            break;
        case LN_CLOSETYPE_UNI_LOCAL:
            //最新のlocal commit_tx --> unilateral close(local)
            del = monitor_close_unilateral_local(self, p_db_param);
            break;
        case LN_CLOSETYPE_UNI_REMOTE:
            //最新のremote commit_tx --> unilateral close(remote)
            del = close_unilateral_remote(self, p_db_param);
            break;
        case LN_CLOSETYPE_REVOKED:
            //相手にrevoked transaction closeされた
            LOGD("closed: ugly way\n");
            ret = ln_close_ugly(self, &close_tx, p_db_param);
            if (ret) {
                if (ln_revoked_cnt(self) > 0) {
                    //revoked transactionのvoutに未解決あり
                    //  2回目以降はclose_revoked_after()が呼び出される
                    del = close_revoked_first(self, &close_tx, confm, p_db_param);
                } else {
                    LOGD("all revoked transaction vout is already solved.\n");
                    del = true;
                }
            } else {
                LOGD("fail: ln_close_ugly\n");
            }
            break;
        case LN_CLOSETYPE_NONE:
        default:
            break;
        }
    } else {
        // revoked transaction close
        del = close_revoked_after(self, confm, p_db_param);
    }
    btc_tx_free(&close_tx);

    return del;
}


static bool channel_reconnect(ln_self_t *self, uint32_t confm, void *p_db_param)
{
    (void)confm; (void)p_db_param;

    // LOGD("opening: funding_tx[conf=%u, idx=%d]: ", confm, ln_funding_txindex(self));
    // TXIDD(ln_funding_txid(self));

    const uint8_t *p_node_id = ln_their_node_id(self);

    //clientとして接続したときの接続先情報があれば、そこに接続する
    peer_conn_t last_peer_conn;
    if (p2p_cli_load_peer_conn(&last_peer_conn, p_node_id)) {
        bool ret = ptarmd_nodefail_get(last_peer_conn.node_id, last_peer_conn.ipaddr, last_peer_conn.port, LN_NODEDESC_IPV4, false);
        if (!ret) {
            utl_misc_msleep(10 + rand() % 2000);
            int retval = cmd_json_connect(last_peer_conn.node_id, last_peer_conn.ipaddr, last_peer_conn.port);
            LOGD("retval=%d\n", retval);
            if (retval == 0) {
                return false;
            }
        }
    }

    //node_announcementで通知されたアドレスに接続する
    ln_node_announce_t anno;
    bool ret = ln_node_search_nodeanno(&anno, p_node_id);
    if (ret) {
        switch (anno.addr.type) {
        case LN_NODEDESC_IPV4:
            {
                char ipaddr[SZ_IPV4_LEN + 1];
                sprintf(ipaddr, "%d.%d.%d.%d",
                            anno.addr.addrinfo.ipv4.addr[0], anno.addr.addrinfo.ipv4.addr[1],
                            anno.addr.addrinfo.ipv4.addr[2], anno.addr.addrinfo.ipv4.addr[3]);

                ret = ptarmd_nodefail_get(p_node_id, ipaddr, anno.addr.port, LN_NODEDESC_IPV4, false);
                if (!ret) {
                    //ノード接続失敗リストに載っていない場合は、自分に対して「接続要求」のJSON-RPCを送信する
                    utl_misc_msleep(10 + rand() % 2000);    //双方が同時に接続しに行かないように時差を付ける(効果があるかは不明)
                    int retval = cmd_json_connect(p_node_id, ipaddr, anno.addr.port);
                    LOGD("retval=%d\n", retval);
                }
            }
            break;
        default:
            //LOGD("addrtype: %d\n", anno.addr.type);
            break;
        }
    } else {
        //LOGD("  not found: node_announcement: ");
        //DUMPD(p_node_id, BTC_SZ_PUBKEY);
    }

    return false;
}


// Unilateral Close(自分がcommit_tx展開): Offered HTLC output
static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    bool send_req = false;

    LOGD("offered HTLC output\n");
    if (spent) {
        const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
        if (p_htlc->prev_short_channel_id != 0) {
            //転送元がある場合、preimageを抽出する
            LOGD("prev_short_channel_id=%016" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);

            uint32_t confm = btcrpc_get_funding_confirm(self);
            if (confm > 0) {
                btc_tx_t tx = BTC_TX_INIT;
                uint8_t txid[BTC_SZ_TXID];
                btc_tx_txid(txid, &pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT]);
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
        //  おそらく"Missing inputs"になる→意味あるのか？
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
        LOGD("-->OK\n");
        send_req = false;
    }

    return send_req;
}


/** unilateral closeを相手が行っていた場合の処理(remoteのcommit_txを展開)
 *
 */
static bool close_unilateral_remote(ln_self_t *self, void *pDbParam)
{
    bool del = true;
    ln_close_force_t close_dat;

    LOGD("unilateral close[remote]\n");

    bool ret = ln_create_closed_tx(self, &close_dat);
    if (ret) {
        uint8_t txid[BTC_SZ_TXID];
        for (int lp = 0; lp < close_dat.num; lp++) {
            if (lp == LN_CLOSE_IDX_COMMIT) {
                LOGD("$$$ commit_tx\n");
                continue;
            } else if (lp == LN_CLOSE_IDX_TOLOCAL) {
                LOGD("$$$ to_local tx\n");
                continue;
            } else if (lp == LN_CLOSE_IDX_TOREMOTE) {
                LOGD("$$$ to_remote tx\n");
            } else {
                LOGD("$$$ HTLC[%d]\n", lp - LN_CLOSE_IDX_HTLC);
            }
            if (close_dat.p_tx[lp].vin_cnt > 0) {
                //自分のtxを展開済みかチェック
                btc_tx_txid(txid, &close_dat.p_tx[lp]);
                LOGD("txid[%d]= ", lp);
                TXIDD(txid);
                bool broad = btcrpc_is_tx_broadcasted(self, txid);
                if (broad) {
                    LOGD("already broadcasted[%d]\n", lp);
                    LOGD("-->OK\n");
                    continue;
                }

                bool send_req = false;

                //展開済みチェック
                bool unspent;
                bool ret = btcrpc_check_unspent(&unspent, NULL, close_dat.p_tx[lp].vin[0].txid, close_dat.p_tx[lp].vin[0].index);
                if (lp == LN_CLOSE_IDX_TOREMOTE) {
                    //to_remoteは自分へのP2WPKH(remotekey)をbitcoind walletに送金する
                    send_req = ret && unspent;
                    if (!ret) {
                        //del
                        //  send_req == true: 送信結果次第
                        //  ret == false: まだDB削除しない
                        del = false;
                    }
                    LOGD("to_remote sendto local wallet: %d\n", send_req);
                    //btc_print_tx(&close_dat.p_tx[lp]);
                } else  if (!ret) {
                    del = false;
                    goto LABEL_EXIT;
                }
                //LOGD("vin unspent[%d]=%d\n", lp, unspent);

                //ln_create_htlc_tx()後だから、OFFERED/RECEIVEDがわかる
                switch (close_dat.p_tx[lp].vout[0].opt) {
                case LN_HTLCTYPE_OFFERED:
                    send_req = close_unilateral_remote_offered(!unspent);
                    break;
                case LN_HTLCTYPE_RECEIVED:
                    send_req = close_unilateral_remote_received(self, &del, !unspent, &close_dat, lp, pDbParam);
                    break;
                default:
                    LOGD("opt=%x\n", close_dat.p_tx[lp].vout[0].opt);
                    break;
                }

                if (send_req) {
                    utl_buf_t buf;
                    btc_tx_create(&buf, &close_dat.p_tx[lp]);
                    ret = btcrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
                    utl_buf_free(&buf);
                    if (ret) {
                        LOGD("broadcast now tx[%d]: ", lp);
                        TXIDD(txid);
                        LOGD("-->OK\n");
                    } else {
                        del = false;
                        LOGD("fail[%d]: sendrawtransaction\n", lp);
                    }
                }
            } else if (lp == LN_CLOSE_IDX_TOREMOTE) {
                LOGD("skip: no to_remote payment\n");
            } else {
                LOGD("skip tx[%d]\n", lp);
                del = false;
            }
        }

LABEL_EXIT:
        ln_free_close_force_tx(&close_dat);
    } else {
        del = false;
    }

    LOGD("del=%d\n", del);

    return del;
}


// Unilateral Close(相手がcommit_tx展開): Offered HTLC output
static bool close_unilateral_remote_offered(bool spent)
{
    bool send_req;

    LOGD("offered HTLC output\n");
    if (spent) {
        //展開済みならOK
        LOGD("-->OK\n");
        send_req = false;
    } else {
        //展開(preimageがなければsendrawtransactionに失敗する)
        send_req = true;
    }

    return send_req;
}


// Unilateral Close(相手がcommit_tx展開): Received HTLC output
static bool close_unilateral_remote_received(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    bool send_req = false;

    LOGD("received HTLC output\n");
    if (spent) {
        const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
        if (p_htlc->prev_short_channel_id != 0) {
            //転送元がある場合、preimageを抽出する
            LOGD("prev_short_channel_id=%016" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);

            uint32_t confm = btcrpc_get_funding_confirm(self);
            if (confm > 0) {
                btc_tx_t tx = BTC_TX_INIT;
                uint8_t txid[BTC_SZ_TXID];
                btc_tx_txid(txid, &pCloseDat->p_tx[LN_CLOSE_IDX_COMMIT]);
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
        //  おそらく"Missing inputs"になる→意味あるのか？
    }

    return send_req;
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

    lnapp_save_event(ln_channel_id(self), "close: ugly way");

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
                btc_print_tx(&pTx[lp]);

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
    btc_tx_txid(txid, pTx);

    const utl_buf_t *p_wit = ln_revoked_wit(self);

    bool ret = ln_create_tolocal_spent(self, &tx, pTx->vout[VIndex].value,
                ln_commit_local(self)->to_self_delay,
                &p_wit[0], txid, VIndex, true);
    if (ret) {
        btc_print_tx(&tx);
        utl_buf_t buf;
        btc_tx_create(&buf, &tx);
        btc_tx_free(&tx);
        ret = btcrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
        if (ret) {
            LOGD("broadcast now: ");
            TXIDD(txid);
        }
        utl_buf_free(&buf);
    }

    return ret;
}


//revoked to_remote outputを取り戻す
//  to_remoteはP2WPKHで支払い済みだが、bitcoindがremotekeyを知らないため、転送する
static bool close_revoked_toremote(const ln_self_t *self, const btc_tx_t *pTx, int VIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(txid, pTx);

    bool ret = ln_create_toremote_spent(self, &tx, pTx->vout[VIndex].value, txid, VIndex);
    if (ret) {
        btc_print_tx(&tx);
        utl_buf_t buf;
        btc_tx_create(&buf, &tx);
        btc_tx_free(&tx);
        ret = btcrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
        if (ret) {
            LOGD("broadcast now: ");
            TXIDD(txid);
        }
        utl_buf_free(&buf);
    }

    return ret;
}


//Offered/Recieved HTLCを取り戻す
static bool close_revoked_htlc(const ln_self_t *self, const btc_tx_t *pTx, int VIndex, int WitIndex)
{
    btc_tx_t tx = BTC_TX_INIT;
    uint8_t txid[BTC_SZ_TXID];
    btc_tx_txid(txid, pTx);

    ln_create_revokedhtlc_spent(self, &tx, pTx->vout[VIndex].value, WitIndex, txid, VIndex);
    btc_print_tx(&tx);
    utl_buf_t buf;
    btc_tx_create(&buf, &tx);
    btc_tx_free(&tx);
    bool ret = btcrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
    if (ret) {
        LOGD("broadcast now: ");
        TXIDD(txid);
    }
    utl_buf_free(&buf);

    return ret;
}
