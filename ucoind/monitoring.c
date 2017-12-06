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
 *  @brief  channel close monitor
 */
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include "ucoind.h"
#include "p2p_svr.h"
#include "p2p_cli.h"
#include "jsonrpc.h"
#include "misc.h"
#include "ln_db.h"

#include "monitoring.h"


/**************************************************************************
 * macro
 **************************************************************************/

#define M_WAIT_MON_SEC                  (30)        ///< 監視周期[sec]


/**************************************************************************
 * private variables
 **************************************************************************/

static volatile bool        mMonitoring;


/********************************************************************
 * prototypes
 ********************************************************************/

static bool monfunc(ln_self_t *self, void *p_db_param, void *p_param);

static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);
static bool close_unilateral_local_received(bool spent);

static bool close_unilateral_remote(ln_self_t *self, void *pDbParam);
static bool close_unilateral_remote_offered(bool spent);
static bool close_unilateral_remote_received(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam);

static bool close_others(ln_self_t *self, uint32_t confm, void *pDbParam);
static bool close_revoked_after(ln_self_t *self, uint32_t confm, void *pDbParam);
static bool close_revoked_vout(const ln_self_t *self, const ucoin_tx_t *pTx, int VIndex);

static bool search_spent_tx(ucoin_tx_t *pTx, uint32_t confm, const uint8_t *pTxid, int Index);
static bool search_vout(ucoin_buf_t *pTxBuf, uint32_t confm, const ucoin_buf_t *pVout);


/**************************************************************************
 * public functions
 **************************************************************************/

void *monitor_thread_start(void *pArg)
{
    (void)pArg;

    mMonitoring = true;
    ln_db_search_channel(monfunc, NULL);

    while (mMonitoring) {
        //ループ解除まで時間が長くなるので、短くチェックする
        for (int lp = 0; lp < M_WAIT_MON_SEC; lp++) {
            sleep(1);
            if (!mMonitoring) {
                break;
            }
        }

        ln_db_search_channel(monfunc, NULL);
    }
    DBG_PRINTF("stop\n");

    return NULL;
}


void monitor_stop(void)
{
    mMonitoring = false;
}


/* unilateral closeを自分が行っていた場合の処理(localのcommit_txを展開)
 *
 */
bool monitor_close_unilateral_local(ln_self_t *self, void *pDbParam)
{
    bool del;
    bool ret;

    ln_close_force_t close_dat;
    ret = ln_create_close_force_tx(self, &close_dat);
    if (ret) {
        del = true;
        uint8_t txid[UCOIN_SZ_TXID];
        for (int lp = 0; lp < close_dat.num; lp++) {
            if (lp == 0) {
                DBG_PRINTF2("\n$$$ commit_tx\n");
                //for (int lp2 = 0; lp2 < close_dat.p_tx[lp].vout_cnt; lp2++) {
                //    DBG_PRINTF("vout[%d]=%x\n", lp2, close_dat.p_tx[lp].vout[lp2].opt);
                //}
            } else if (lp == 1) {
                DBG_PRINTF2("\n$$$ to_local tx\n");
            } else {
                DBG_PRINTF2("\n$$$ HTLC[%d]\n", lp - 2);
            }
            if (close_dat.p_tx[lp].vin_cnt > 0) {
                //自分のtxを展開済みかチェック
                ucoin_tx_txid(txid, &close_dat.p_tx[lp]);
                DBG_PRINTF("txid[%d]= ", lp);
                DUMPTXID(txid);
                bool broad = jsonrpc_getraw_tx(NULL, txid);
                if (broad) {
                    DBG_PRINTF("already broadcasted[%d]\n", lp);
                    DBG_PRINTF("-->OK\n");
                    continue;
                }

                bool send_req = false;

                //展開済みチェック
                uint64_t sat;
                bool spent = !jsonrpc_getxout(&sat, close_dat.p_tx[lp].vin[0].txid, close_dat.p_tx[lp].vin[0].index);
                DBG_PRINTF("vin spent[%d]=%d\n", lp, spent);

                //ln_create_htlc_tx()後だから、OFFERED/RECEIVEDがわかる
                switch (close_dat.p_tx[lp].vout[0].opt) {
                case LN_HTLCTYPE_OFFERED:
                    send_req = close_unilateral_local_offered(self, &del, spent, &close_dat, lp, pDbParam);
                    break;
                case LN_HTLCTYPE_RECEIVED:
                    send_req = close_unilateral_local_received(spent);
                    break;
                default:
                    DBG_PRINTF("opt=%x\n", close_dat.p_tx[lp].vout[0].opt);
                    send_req = true;
                    break;
                }

                if (send_req) {
                    ucoin_buf_t buf;
                    ucoin_tx_create(&buf, &close_dat.p_tx[lp]);
                    int code = 0;
                    ret = jsonrpc_sendraw_tx(txid, &code, buf.buf, buf.len);
                    DBG_PRINTF("code=%d\n", code);
                    ucoin_buf_free(&buf);
                    if (ret) {
                        DBG_PRINTF("broadcast txid[%d]\n", lp);
                        DBG_PRINTF("-->OK\n");
                    } else {
                        del = false;
                        DBG_PRINTF("fail[%d]: sendrawtransaction\n", lp);
                    }
                }
            } else {
                DBG_PRINTF("skip tx[%d]\n", lp);
                del = false;
            }
        }

        //自分が展開した場合には、HTLC Timeout/Success Txからの出力も行う
        ucoin_tx_t *p_tx = (ucoin_tx_t *)close_dat.tx_buf.buf;
        int num = close_dat.tx_buf.len / sizeof(ucoin_tx_t);
        for (int lp = 0; lp < num; lp++) {
            ucoin_buf_t buf;
            ucoin_tx_create(&buf, &p_tx[lp]);
            int code = 0;
            ret = jsonrpc_sendraw_tx(txid, &code, buf.buf, buf.len);
            DBG_PRINTF("code=%d\n", code);
            ucoin_buf_free(&buf);
            if (ret) {
                DBG_PRINTF("broadcast after tx[%d]\n", lp);
                DBG_PRINTF("-->OK\n");
            } else if ((code == JSONRPC_ERR_MISSING_INPUT) || (code == JSONRPC_ERR_ALREADY_BLOCK)) {
                DBG_PRINTF("through[%d]: already spent vin\n", lp);
            } else {
                del = false;
                DBG_PRINTF("fail[%d]: sendrawtransaction\n", lp);
            }
        }

        ln_free_close_force_tx(&close_dat);
    } else {
        del = false;
    }

    DBG_PRINTF("del=%d\n", del);

    return del;
}


/********************************************************************
 * private functions
 ********************************************************************/

/** 監視処理
 *
 */
static bool monfunc(ln_self_t *self, void *p_db_param, void *p_param)
{
    (void)p_param;

    uint32_t confm = jsonrpc_get_confirmation(ln_funding_txid(self));
    if (confm > 0) {
        DBG_PRINTF("funding_txid[conf=%u, idx=%d]: ", confm, ln_funding_txindex(self));
        DUMPTXID(ln_funding_txid(self));

        bool del = false;
        uint64_t sat;
        bool ret = jsonrpc_getxout(&sat, ln_funding_txid(self), ln_funding_txindex(self));
        if (!ret) {
            //funding_tx使用済み

            ln_db_load_revoked(self, p_db_param);
            if (self->revoked_vout.len == 0) {
                //展開されているのが最新のcommit_txか
                ucoin_tx_t tx_commit;
                ucoin_tx_init(&tx_commit);
                if (jsonrpc_getraw_tx(&tx_commit, ln_commit_local(self)->txid)) {
                    //最新のlocal commit_tx --> unilateral close(local)
                    del = monitor_close_unilateral_local(self, p_db_param);
                } else if (jsonrpc_getraw_tx(&tx_commit, ln_commit_remote(self)->txid)) {
                    //最新のremote commit_tx --> unilateral close(remote)
                    del = close_unilateral_remote(self, p_db_param);
                } else {
                    //最新ではないcommit_tx --> mutual close or revoked transaction close
                    del = close_others(self, confm, p_db_param);
                }
                ucoin_tx_free(&tx_commit);
            } else {
                // revoked transaction close
                del = close_revoked_after(self, confm, p_db_param);
            }
        }
        if (del) {
            DBG_PRINTF("delete from DB\n");
            ret = ln_db_del_channel(self, p_db_param);
            assert(ret);
        }
    }

    return false;
}


// Unilateral Close(自分がcommit_tx展開): Offered HTLC output
static bool close_unilateral_local_offered(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    bool send_req = false;

    DBG_PRINTF("offered HTLC output\n");
    if (spent) {
        const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
        if (p_htlc->prev_short_channel_id != 0) {
            //転送元がある場合、preimageを抽出する
            DBG_PRINTF("prev_short_channel_id=%" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);
            ucoin_tx_t tx;
            ucoin_tx_init(&tx);
            uint32_t confm = jsonrpc_get_confirmation(ln_funding_txid(self));
            uint8_t txid[UCOIN_SZ_TXID];
            ucoin_tx_txid(txid, &pCloseDat->p_tx[0]);
            bool ret = search_spent_tx(&tx, confm, txid, pCloseDat->p_htlc_idx[lp]);
            if (ret) {
                //preimageを登録(自分が持っているのと同じ状態にする)
                const ucoin_buf_t *p_buf = ln_preimage_remote(&tx);
                if (p_buf != NULL) {
                    DBG_PRINTF("backward preimage: ");
                    DUMPBIN(p_buf->buf, p_buf->len);
                    ln_db_save_preimage(p_buf->buf, 0, pDbParam);
                } else {
                    assert(0);
                }
            } else {
                DBG_PRINTF("not found txid: ");
                DUMPTXID(txid);
                DBG_PRINTF("index=%d\n", pCloseDat->p_htlc_idx[lp]);
                *pDel = false;
            }
            ucoin_tx_free(&tx);
        }
    } else {
        //タイムアウト用Txを展開(non-BIP68-finalの可能性あり)
        send_req = true;
    }

    return send_req;
}


// Unilateral Close(自分がcommit_tx展開): Received HTLC output
static bool close_unilateral_local_received(bool spent)
{
    bool send_req;

    DBG_PRINTF("received HTLC output\n");
    if (!spent) {
        //展開(preimageがなければsendrawtransactionに失敗する)
        send_req = true;
    } else {
        //展開済みならOK
        DBG_PRINTF("-->OK\n");
    }

    return send_req;
}


/** unilateral closeを相手が行っていた場合の処理(remoteのcommit_txを展開)
 *
 */
static bool close_unilateral_remote(ln_self_t *self, void *pDbParam)
{
    bool del = true;

    if (ln_htlc_num(self) == 0) {
        DBG_PRINTF("no HTLCS\n");
    } else {
        ln_close_force_t close_dat;
        bool ret = ln_create_closed_tx(self, &close_dat);
        if (ret) {
            del = true;
            uint8_t txid[UCOIN_SZ_TXID];
            for (int lp = 0; lp < close_dat.num; lp++) {
                if (lp == 0) {
                    DBG_PRINTF2("\n$$$ commit_tx\n");
                    continue;
                } else if (lp == 1) {
                    DBG_PRINTF2("\n$$$ to_local tx\n");
                    continue;
                } else {
                    DBG_PRINTF2("\n$$$ HTLC[%d]\n", lp - 2);
                }
                if (close_dat.p_tx[lp].vin_cnt > 0) {
                    //自分のtxを展開済みかチェック
                    ucoin_tx_txid(txid, &close_dat.p_tx[lp]);
                    DBG_PRINTF("txid[%d]= ", lp);
                    DUMPTXID(txid);
                    bool broad = jsonrpc_getraw_tx(NULL, txid);
                    if (broad) {
                        DBG_PRINTF("already broadcasted[%d]\n", lp);
                        DBG_PRINTF("-->OK\n");
                        continue;
                    }

                    bool send_req = false;

                    //展開済みチェック
                    uint64_t sat;
                    bool spent = !jsonrpc_getxout(&sat, close_dat.p_tx[lp].vin[0].txid, close_dat.p_tx[lp].vin[0].index);
                    DBG_PRINTF("vin spent[%d]=%d\n", lp, spent);

                    //ln_create_htlc_tx()後だから、OFFERED/RECEIVEDがわかる
                    switch (close_dat.p_tx[lp].vout[0].opt) {
                    case LN_HTLCTYPE_OFFERED:
                        send_req = close_unilateral_remote_offered(spent);
                        break;
                    case LN_HTLCTYPE_RECEIVED:
                        send_req = close_unilateral_remote_received(self, &del, spent, &close_dat, lp, pDbParam);
                        break;
                    default:
                        DBG_PRINTF("opt=%x\n", close_dat.p_tx[lp].vout[0].opt);
                        break;
                    }

                    if (send_req) {
                        ucoin_buf_t buf;
                        ucoin_tx_create(&buf, &close_dat.p_tx[lp]);
                        ret = jsonrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
                        ucoin_buf_free(&buf);
                        if (ret) {
                            DBG_PRINTF("broadcast txid[%d]: ", lp);
                            DUMPTXID(txid);
                            DBG_PRINTF("-->OK\n");
                        } else {
                            del = false;
                            DBG_PRINTF("fail[%d]: sendrawtransaction\n", lp);
                        }
                    }
                } else {
                    DBG_PRINTF("skip tx[%d]\n", lp);
                    del = false;
                }
            }
            ln_free_close_force_tx(&close_dat);
        } else {
            del = false;
        }
    }

    DBG_PRINTF("del=%d\n", del);

    return del;
}


// Unilateral Close(相手がcommit_tx展開): Offered HTLC output
static bool close_unilateral_remote_offered(bool spent)
{
    bool send_req;

    DBG_PRINTF("offered HTLC output\n");
    if (!spent) {
        //展開(preimageがなければsendrawtransactionに失敗する)
        send_req = true;
    } else {
        //展開済みならOK
        DBG_PRINTF("-->OK\n");
        send_req = false;
    }

    return send_req;
}


// Unilateral Close(相手がcommit_tx展開): Received HTLC output
static bool close_unilateral_remote_received(ln_self_t *self, bool *pDel, bool spent, ln_close_force_t *pCloseDat, int lp, void *pDbParam)
{
    bool send_req = false;

    DBG_PRINTF("received HTLC output\n");
    if (spent) {
        const ln_update_add_htlc_t *p_htlc = ln_update_add_htlc(self, pCloseDat->p_htlc_idx[lp]);
        if (p_htlc->prev_short_channel_id != 0) {
            //転送元がある場合、preimageを抽出する
            DBG_PRINTF("prev_short_channel_id=%" PRIx64 "(vout=%d)\n", p_htlc->prev_short_channel_id, pCloseDat->p_htlc_idx[lp]);
            ucoin_tx_t tx;
            ucoin_tx_init(&tx);
            uint32_t confm = jsonrpc_get_confirmation(ln_funding_txid(self));
            uint8_t txid[UCOIN_SZ_TXID];
            ucoin_tx_txid(txid, &pCloseDat->p_tx[0]);
            bool ret = search_spent_tx(&tx, confm, txid, pCloseDat->p_htlc_idx[lp]);
            if (ret) {
                //preimageを登録(自分が持っているのと同じ状態にする)
                const ucoin_buf_t *p_buf = ln_preimage_remote(&tx);
                if (p_buf != NULL) {
                    DBG_PRINTF("backward preimage: ");
                    DUMPBIN(p_buf->buf, p_buf->len);
                    ln_db_save_preimage(p_buf->buf, 0, pDbParam);
                } else {
                    assert(0);
                }
            } else {
                DBG_PRINTF("not found txid: ");
                DUMPTXID(txid);
                DBG_PRINTF("index=%d\n", pCloseDat->p_htlc_idx[lp]);
                *pDel = false;
            }
        }
    } else {
        //タイムアウト用Txを展開(non-BIP68-finalの可能性あり)
        send_req = true;
    }

    return send_req;
}


// Mutual Close or Revoked Transaction Close
static bool close_others(ln_self_t *self, uint32_t confm, void *pDbParam)
{
    (void)pDbParam;
    bool del = false;

    ucoin_tx_t tx;
    ucoin_tx_init(&tx);
    bool ret = search_spent_tx(&tx, confm, ln_funding_txid(self), ln_funding_txindex(self));
    if (ret) {
        DBG_PRINTF("find!\n");
        ucoin_print_tx(&tx);
        ucoin_buf_t *p_buf_pk = &tx.vout[0].script;
        if ( (tx.vout_cnt <= 2) &&
             (ucoin_buf_cmp(p_buf_pk, &self->shutdown_scriptpk_local) ||
              ucoin_buf_cmp(p_buf_pk, &self->shutdown_scriptpk_remote)) ) {
            //voutのどちらかがshutdown時のscriptPubkeyと一致すればclosing_txと見なす
            DBG_PRINTF("This is closing_tx\n");
            del = true;
        } else {
            //revoked transaction close
            SYSLOG_WARN("closed: ugly way\n");
            ln_close_ugly(self, &tx);

            //即座に取り戻せるもの
            bool save = true;
            for (int lp = 0; lp < tx.vout_cnt; lp++) {
                if (ucoin_buf_cmp(&tx.vout[lp].script, &self->revoked_vout)) {
                    DBG_PRINTF("[%d]to_local !\n", lp);

                    ret = close_revoked_vout(self, &tx, lp);
                    if (ret) {
                        del = ln_revoked_cnt_dec(self);
                        ln_set_revoked_confm(self, confm);
                    } else {
                        save = false;
                    }
                    break;
                }
            }
            if (save) {
                ln_db_save_revoked(self, true, pDbParam);
            }
        }
    }
    ucoin_tx_free(&tx);

    return del;
}


// HTLC Timeout/Success Tx後から取り戻す
static bool close_revoked_after(ln_self_t *self, uint32_t confm, void *pDbParam)
{
    bool del = false;

    if (confm != ln_revoked_confm(self)) {
        //HTLC Timeout/Success Txのvoutと一致するトランザクションを検索
        ucoin_buf_t txbuf;
        bool ret = search_vout(&txbuf, confm - ln_revoked_confm(self), ln_revoked_vout(self));
        if (ret) {
            bool sendret = true;
            int num = txbuf.len / sizeof(ucoin_tx_t);
            DBG_PRINTF("find! %d\n", num);
            ucoin_tx_t *pTx = (ucoin_tx_t *)txbuf.buf;
            for (int lp = 0; lp < num; lp++) {
                DBG_PRINTF2("-------- %d ----------\n", lp);
                ucoin_print_tx(&pTx[lp]);

                ret = close_revoked_vout(self, &pTx[lp], 0);
                ucoin_tx_free(&pTx[lp]);
                if (ret) {
                    del = ln_revoked_cnt_dec(self);
                    DBG_PRINTF("del=%d, revoked_cnt=%d\n", del, self->revoked_cnt);
                } else {
                    sendret = false;
                    break;
                }
            }
            ucoin_buf_free(&txbuf);

            if (sendret) {
                ln_set_revoked_confm(self, confm);
                ln_db_save_revoked(self, false, pDbParam);
                DBG_PRINTF("del=%d, revoked_cnt=%d\n", del, self->revoked_cnt);
            } else {
                //送信エラーがあった場合には、次回やり直す
                DBG_PRINTF("sendtx error\n");
            }
        } else {
            ln_set_revoked_confm(self, confm);
            ln_db_save_revoked(self, false, pDbParam);
            DBG_PRINTF("no target txid: %d, revoked_cnt=%d\n", confm, self->revoked_cnt);
        }
    } else {
        DBG_PRINTF("same block: %d, revoked_cnt=%d\n", confm, self->revoked_cnt);
    }

    return del;
}


//revoked HTLC Timeout/Success Txの送金先になって取り戻す
static bool close_revoked_vout(const ln_self_t *self, const ucoin_tx_t *pTx, int VIndex)
{
    uint8_t txid[UCOIN_SZ_TXID];
    ucoin_tx_txid(txid, pTx);

    ucoin_tx_t tx;
    ucoin_tx_init(&tx);
    ln_create_tolocal_spent(self, &tx, pTx->vout[VIndex].value,
                self->commit_local.to_self_delay,
                ln_revoked_wit(self), txid, VIndex, true);
    ucoin_print_tx(&tx);
    ucoin_buf_t buf;
    ucoin_tx_create(&buf, &tx);
    ucoin_tx_free(&tx);
    bool ret = jsonrpc_sendraw_tx(txid, NULL, buf.buf, buf.len);
    ucoin_buf_free(&buf);

    return ret;
}


//該当するoutpointをvinに持つトランザクションを検索
static bool search_spent_tx(ucoin_tx_t *pTx, uint32_t confm, const uint8_t *pTxid, int Index)
{
    bool ret = false;
    int height = jsonrpc_getblockcount();

    //現在からconfmの間に使用したtransactionがある
    if (height > 0) {
        for (uint32_t lp = 0; lp < confm; lp++) {
            ret = jsonrpc_search_txid_block(pTx, height - lp, pTxid, Index);
            if (ret) {
                break;
            }
        }
    }

    return ret;
}


//該当するscriptPubKeyを vout[0]に持つトランザクション検索
static bool search_vout(ucoin_buf_t *pTxBuf, uint32_t confm, const ucoin_buf_t *pVout)
{
    bool ret = false;
    int height = jsonrpc_getblockcount();

    //現在からconfmの間に使用したtransactionがある
    if (height > 0) {
        for (uint32_t lp = 0; lp < confm; lp++) {
            ret = jsonrpc_search_vout_block(pTxBuf, height - lp, pVout);
            if (ret) {
                DBG_PRINTF("buf.len=%d\n", pTxBuf->len);
                break;
            }
        }
    }

    return ret;
}
