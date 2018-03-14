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
/** @file   ln_signer.c
 *  @brief  [LN]秘密鍵管理
 *  @author ueno@nayuta.co
 */
#include "ln_signer.h"


/**************************************************************************
 * public functions
 **************************************************************************/

void ln_signer_init(ln_self_t *self, const uint8_t *pSeed)
{
    self->storage_index = LN_SECINDEX_INIT;
    if (pSeed) {
        memcpy(self->storage_seed, pSeed, LN_SZ_SEED);
        ln_derkey_storage_init(&self->peer_storage);
    }
}


void ln_signer_term(ln_self_t *self)
{
    memset(self->storage_seed, 0, UCOIN_SZ_PRIVKEY);
}


void ln_signer_keys_update(ln_self_t *self, uint64_t Index)
{
    ln_derkey_create_secret(self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].priv, self->storage_seed, Index);
    ucoin_keys_priv2pub(self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].pub, self->funding_local.keys[MSG_FUNDIDX_PER_COMMIT].priv);
}
