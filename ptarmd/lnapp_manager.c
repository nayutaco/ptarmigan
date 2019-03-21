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

#include "lnapp.h"


/********************************************************************
 * static variables
 ********************************************************************/

static lnapp_conf_t     mAppConf[MAX_CHANNELS];
pthread_mutex_t         mMuxAppconf = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;


/********************************************************************
 * public functions
 ********************************************************************/

void lnapp_manager_init(void)
{
    memset(&mAppConf, 0x00, sizeof(mAppConf));
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        //lnapp_init(&mAppConf[lp]);
    }
}


void lnapp_manager_term(void)
{
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (mAppConf[lp].state == LNAPP_STATE_NONE) continue;
        //lnapp_term(&mAppConf[lp]);
    }
}


lnapp_conf_t *lnapp_manager_get_node(const uint8_t *pNodeId, lnapp_state_t State)
{
    pthread_mutex_lock(&mMuxAppconf);
    lnapp_conf_t *p_conf = NULL;
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (memcmp(pNodeId, mAppConf[lp].node_id, BTC_SZ_PUBKEY)) continue;
        if (mAppConf[lp].state & State) continue;
        p_conf = &mAppConf[lp];
        p_conf->ref_counter++;
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);

    return p_conf;
}


lnapp_conf_t *lnapp_manager_get_new_node(const uint8_t *pNodeId)
{
    pthread_mutex_lock(&mMuxAppconf);
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (memcmp(pNodeId, mAppConf[lp].node_id, BTC_SZ_PUBKEY)) continue;
        LOGE("fail: always exists\n");
        pthread_mutex_unlock(&mMuxAppconf);
        return NULL;
    }
    lnapp_conf_t *p_conf = NULL;
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        if (mAppConf[lp].state != LNAPP_STATE_NONE) continue;
        p_conf = &mAppConf[lp];
        p_conf->state = LNAPP_STATE_INIT;
        memcpy(p_conf->node_id, pNodeId, BTC_SZ_PUBKEY);
        p_conf->ref_counter++;
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);

    return p_conf;
}


void lnapp_manager_decrement_ref(lnapp_conf_t **ppConf)
{
    if (!*ppConf) return;
    pthread_mutex_lock(&mMuxAppconf);
    assert((*ppConf)->ref_counter);
    (*ppConf)->ref_counter--;
    pthread_mutex_unlock(&mMuxAppconf);
    *ppConf = NULL;
}


void lnapp_manager_term_node(const uint8_t *pNodeId)
{
    pthread_mutex_lock(&mMuxAppconf);
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        lnapp_conf_t *p_conf = &mAppConf[lp];
        if (memcmp(pNodeId, p_conf->node_id, BTC_SZ_PUBKEY)) continue;
        if (p_conf->state != LNAPP_STATE_INIT) break;
        if (mAppConf[lp].ref_counter) break;
        //lnapp_term(&mAppConf[lp]);
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);
}


void lnapp_manager_set_node_state(const uint8_t *pNodeId, lnapp_state_t State)
{
    pthread_mutex_lock(&mMuxAppconf);
    for (int lp = 0; lp < (int)ARRAY_SIZE(mAppConf); lp++) {
        lnapp_conf_t *p_conf = &mAppConf[lp];
        if (memcmp(pNodeId, p_conf->node_id, BTC_SZ_PUBKEY)) continue;
        p_conf->state = State;
        break;
    }
    pthread_mutex_unlock(&mMuxAppconf);
}
