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
#define LOG_TAG     "lnapp_manager"
#include "utl_log.h"

#include "ln_db.h"

#include "lnapp.h"
#include "lnapp_manager.h"


/********************************************************************
 * static variables
 ********************************************************************/

static lnapp_conf_t     mAppConf[MAX_CHANNELS + 1];
    //the additional one is for handling origin/final node itself.
    //  treat as a dummy channel as node_id=0 and short_channel_id=0.
pthread_mutex_t         mMuxAppconf = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
const uint8_t           mNodeIdOrigin[BTC_SZ_PUBKEY] = {0};


/********************************************************************
 * prototypes
 ********************************************************************/

static bool load_channel(ln_channel_t *pChannel, void *pDbParam, void *pParam);


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_manager_init(void)
{
    memset(&mAppConf, 0x00, sizeof(mAppConf));
    int idx = 0;
    ln_db_channel_search_cont(load_channel, &idx); //XXX: error check
}


void lnapp_manager_term(void)
{
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (!mAppConf[lp].enabled) continue;
        lnapp_stop(&mAppConf[lp]);
        lnapp_conf_term(&mAppConf[lp]);
    }
}


void lnapp_manager_start_origin_node(void *(*pThreadChannelStart)(void *pArg))
{
    LOGD("\n");
    lnapp_conf_t *p_conf = lnapp_manager_get_new_node(mNodeIdOrigin, pThreadChannelStart);
    assert(p_conf);
    lnapp_start(p_conf);
    LOGD("\n");
}


lnapp_conf_t *lnapp_manager_get_node(const uint8_t *pNodeId)
{
    pthread_mutex_lock(&mMuxAppconf);
    lnapp_conf_t *p_conf = NULL;
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (!mAppConf[lp].enabled) continue;
        if (memcmp(mAppConf[lp].node_id, pNodeId, BTC_SZ_PUBKEY)) continue;
        p_conf = &mAppConf[lp];
        p_conf->ref_counter++;
        LOGD("ref_counter++: [%p] %u -> %u\n", p_conf, p_conf->ref_counter - 1, p_conf->ref_counter);
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);
    return p_conf;
}


void lnapp_manager_each_node(void (*pCallback)(lnapp_conf_t *pConf, void *pParam), void *pParam)
{
    pthread_mutex_lock(&mMuxAppconf);
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        lnapp_conf_t *p_conf = &mAppConf[lp];
        if (!memcmp(p_conf->node_id, mNodeIdOrigin, BTC_SZ_PUBKEY)) continue; //skip origin node
        if (!p_conf->enabled) continue;
        p_conf->ref_counter++;
        LOGD("ref_counter++: [%p] %u -> %u\n", p_conf, p_conf->ref_counter - 1, p_conf->ref_counter);
        pthread_mutex_unlock(&mMuxAppconf);
        pCallback(p_conf, pParam);
        pthread_mutex_lock(&mMuxAppconf);
        p_conf->ref_counter--;
        LOGD("ref_counter--: [%p] %u -> %u\n", p_conf, p_conf->ref_counter + 1, p_conf->ref_counter);
    }
    pthread_mutex_unlock(&mMuxAppconf);
}


lnapp_conf_t *lnapp_manager_get_new_node(
    const uint8_t *pNodeId, void *(*pThreadChannelStart)(void *pArg))
{
    pthread_mutex_lock(&mMuxAppconf);
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (!mAppConf[lp].enabled) continue;
        if (memcmp(mAppConf[lp].node_id, pNodeId, BTC_SZ_PUBKEY)) continue;
        LOGE("fail: always exists\n");
        pthread_mutex_unlock(&mMuxAppconf);
        return NULL;
    }
    lnapp_conf_t *p_conf = NULL;
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (mAppConf[lp].enabled) continue;
        p_conf = &mAppConf[lp];
        lnapp_conf_init(p_conf, pNodeId, pThreadChannelStart);
        p_conf->ref_counter++;
        LOGD("ref_counter++: [%p] %u -> %u\n", p_conf, p_conf->ref_counter - 1, p_conf->ref_counter);
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);
    return p_conf;
}


void lnapp_manager_free_node_ref(lnapp_conf_t *pConf)
{
    if (!pConf) return;
    pthread_mutex_lock(&mMuxAppconf);
    assert(pConf->ref_counter);
    pConf->ref_counter--;
    LOGD("ref_counter--: [%p] %u -> %u\n", pConf, pConf->ref_counter + 1, pConf->ref_counter);
    pthread_mutex_unlock(&mMuxAppconf);
}


void lnapp_manager_term_node(const uint8_t *pNodeId)
{
    lnapp_conf_t *p_conf = lnapp_manager_get_node(pNodeId);
    if (!p_conf) return;
    lnapp_manager_free_node_ref(p_conf);
    lnapp_manager_free_node_ref(p_conf);
}


void lnapp_manager_prune_node()
{
    pthread_mutex_lock(&mMuxAppconf);
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (!memcmp(mAppConf[lp].node_id, mNodeIdOrigin, BTC_SZ_PUBKEY)) continue; //skip origin node
        if (!mAppConf[lp].enabled) continue;
        if (mAppConf[lp].ref_counter) continue;
        //no lock required
        if (ln_status_get(&mAppConf[lp].channel) >= LN_STATUS_ESTABLISH &&
            ln_status_get(&mAppConf[lp].channel) != LN_STATUS_CLOSED) continue;
        LOGD("prune node: ");
        DUMPD(mAppConf[lp].node_id, BTC_SZ_PUBKEY);
        lnapp_stop(&mAppConf[lp]);
        lnapp_conf_term(&mAppConf[lp]);
    }
    pthread_mutex_unlock(&mMuxAppconf);
}


/********************************************************************
 * private functions
 ********************************************************************/

static bool load_channel(ln_channel_t *pChannel, void *pDbParam, void *pParam)
{
    (void)pDbParam;

    int *p_idx = (int *)pParam;

    if (*p_idx >= MAX_CHANNELS) {
        assert(0);
        return false;
    }

    ln_channel_t *p_channel = &mAppConf[*p_idx].channel;
    lnapp_conf_init(&mAppConf[*p_idx], pChannel->peer_node_id, lnapp_thread_channel_start);
    ln_db_copy_channel(p_channel, pChannel);
    if (p_channel->short_channel_id) {
        ln_db_cnlanno_load(&p_channel->cnl_anno, p_channel->short_channel_id);
    }
    ln_print_keys(p_channel);
    (*p_idx)++;
    return true;
}

