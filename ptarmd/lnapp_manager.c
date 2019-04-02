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


/********************************************************************
 * static variables
 ********************************************************************/

static lnapp_conf_t     mAppConf[MAX_CHANNELS];
pthread_mutex_t         mMuxAppconf = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


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


lnapp_conf_t *lnapp_manager_get_node(const uint8_t *pNodeId)
{
    pthread_mutex_lock(&mMuxAppconf);
    lnapp_conf_t *p_conf = NULL;
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (!mAppConf[lp].enabled) continue;
        if (memcmp(mAppConf[lp].node_id, pNodeId, BTC_SZ_PUBKEY)) continue;
        p_conf = &mAppConf[lp];
        p_conf->ref_counter++;
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);
    return p_conf;
}


void lnapp_manager_each_node(void (*pCallback)(lnapp_conf_t *pConf, void *pParam), void *pParam)
{
    pthread_mutex_lock(&mMuxAppconf);
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (!mAppConf[lp].enabled) continue;
        mAppConf[lp].ref_counter++;
        pthread_mutex_unlock(&mMuxAppconf);
        pCallback(&mAppConf[lp], pParam);
        pthread_mutex_lock(&mMuxAppconf);
        mAppConf[lp].ref_counter--;
    }
    pthread_mutex_unlock(&mMuxAppconf);
}


lnapp_conf_t *lnapp_manager_get_new_node(const uint8_t *pNodeId)
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
        lnapp_conf_init(p_conf, pNodeId);
        p_conf->ref_counter++;
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);
    return p_conf;
}


void lnapp_manager_free_node_ref(lnapp_conf_t *pConf)
{
    pthread_mutex_lock(&mMuxAppconf);
    assert(pConf->ref_counter);
    pConf->ref_counter--;
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
    lnapp_conf_init(&mAppConf[*p_idx], pChannel->peer_node_id);
    ln_db_copy_channel(p_channel, pChannel);
    if (p_channel->short_channel_id) {
        ln_db_cnlanno_load(&p_channel->cnl_anno, p_channel->short_channel_id);
    }
    ln_print_keys(p_channel);
    (*p_idx)++;
    return true;
}

