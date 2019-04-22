#ifndef LN_VERSION_H__
#define LN_VERSION_H__

/** @def    LN_DB_VERSION
 *  @brief  database version
 */
#define LN_DB_VERSION    ((int32_t)(-68))
/*
    -1 : first
    -2 : ln_update_add_htlc_t変更
    -3 : ln_funding_remote_data_t変更
    -4 : ln_funding_local_data_t, ln_funding_remote_data_t変更
    -5 : backup_self_tにln_node_info_t追加
    -6 : self.min_depth追加
    -7 : ln_commit_tx_tにtxid追加
    -8 : ln_commit_tx_tにhtlc_num追加
    -9 : self.shutdown_scriptpk_localを対象に追加
    -10: htlckey対応
    -11: self.shutdown_scriptpk_remoteを対象に追加, LOCALKEY削除, funding_local/remote整理
    -12: revoked transaction用データ追加
    -13: self.anno_flag追加
    -14: announcementの送信管理追加
    -15: node.conf情報をversionに追加
    -16: selfはmpDbEnv、それ以外はmpDbNodeEnvにする
    -17: selfの構造体を個別に保存する
         selfのsecret情報をself.priv_dataに集約
    -18: node_announcement除外用DB追加(annoinfo_chan)
    -18: [SPVのみ]funding_txのblock hash追加
    -19: revocation_number追加
    -20: current_commit_num追加、scriptpubkeys削除
    -21: fix: alias length
    -22: onion route
    -23: announcement dbを分離
    -24: self.cnl_add_htlc[].flag変更
    -25: self.close_type追加
    -26: DB_COPYにhtlc_num, htld_id_num追加
    -27: self.close_type変更
    -28: self.htlc_num削除
    -29: self.statusとself.close_typeのマージ
    -30: bitcoindとSPVを同じにする
    -31: include peer_storage_index in ln_derkey_storage_t
    -32: exchange the values of commit_tx_local.to_self_delay and commit_tx_remote.to_self_delay
    -33: change the format of pub/priv keys
    -34: change the size of ln_derkey_local_privkeys_t::per_commitment_secret
         BTC_SZ_PUBKEY -> BTC_SZ_PRIVKEY
    -35: change the order of internal members in ln_derkey_local_privkeys_t
    -36: change self->peer_storage -> self->privkeys_remote
    -37: funding_local -> pubkeys_local, funding_remote -> pubkeys_remote
    -38: rename db name, dbparam_self -> dbptarm_chnl
         rename self -> channel
    -39: DBCHANNEL_SECRET:
             ln_channel_t::privkeys_local ->
                 ln_channel_t::keys_local.ln_derkey_local_keys_t::secrets
                 ln_channel_t::keys_local.ln_derkey_local_keys_t::storage_seed
                 ln_channel_t::keys_local.ln_derkey_local_keys_t::next_storage_index
         DBCHANNEL_VALUES:
             ln_channel_t::privkeys_remote
             ln_channel_t::pubkeys_remote ->
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::basepoints
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::next_storage_index
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::storage
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::per_commitment_point
                 ln_channel_t::keys_remote.ln_derkey_remote_keys_t::prev_per_commitment_point
             ln_channel_t::pubkeys_local -> removed
         and the local public keys and the script pubkeys are restored after loading
    -40: save only txid and txindex in ln_funding_tx_t
    -41: add `funding_tx_t::funding_satoshis`
         rm `ln_channel_t::funding_sat`
    -42: rename `our_msat` -> `local_msat` and `their_msat` -> `remote_msat`
    -43: rename `ln_update_add_htlc_t::stat` -> `ln_update_add_htlc_t::flags`
    -44: rm `ln_channel_t::local_msat`
         rm `ln_channel_t::remote_msat`
         add `ln_commit_tx_t::local_msat`
         add `ln_commit_tx_t::remote_msat`
    -45: rename `htlc_id_num` -> `num_htlc_ids`
         rename `htlc_output_num` -> `num_htlc_outputs`
    -46: separate `ln_update_add_htlc_t` into `ln_update_t` and `ln_htlc_t`
         rename `num_htlc_ids` -> `next_htlc_id`
    -47: the size of `ln_update_t` gets smaller
         rm `ln_update_t::prev_short_channel_id`
         rm `ln_update_t::prev_idx`
         rm `ln_update_t::next_short_channel_id`
         rm `ln_update_t::next_idx`
         add `ln_update_t::neighbor_short_channel_id`
         add `ln_update_t::neighbor_idx`
    -48: fix ln_update_t::enabled
    -49: update `ln_update_t` and `ln_htlc_t`
    -50: rename `ln_funding_tx_t` -> `ln_funding_info_t`
         rename `ln_commit_t` -> `ln_commit_info_t`
    -51: `ln_channel_t::updates` -> `ln_channel_t::update_info.updates`
         `ln_channel_t::htlcs` -> `ln_channel_t::update_info.htlcs`
         `ln_channel_t::next_htlc_id` -> `ln_channel_t::update_info.next_htlc_id`
    -52: rm `ln_channel_t::feerate_per_kw`
         add `ln_commit_info_t::feerate_per_kw`
    -53: add `ln_update_info_t::fee_updates`
    -54: update `ln_update_info_t::updates`
    -55: update `ln_update_info_t::fee_updates`
    -56: add `ln_update_info_t::next_fee_update_id`
         add `ln_fee_update_t::id`
         rename `ln_update_t::htlc_idx` -> `ln_update_t::type_specific_idx`
    -57: channel_announcement/channel_update key: little endian -> big endian(for auto sort)
    -58: update the size of `ln_update_info_t::updates` and `ln_update_info_t::fee_updates`
         rm `ln_commit_info_t::feerate_per_kw`
    -59: updated a lot!
         change db paths and db names and so on
    -60: increase the num of htlcs (6 -> 12)
    -61: rm `ln_htlc_t::neighbor_idx`
         add `ln_htlc_t::neighbor_id`
         add closed channel environment and move backup db to the environment
    -62: add `ln_htlc_t::forward_msg`
    -63: add `payment` env
    -64: rm `ln_update_t::fin_type`
    -65: add `ln_channel_t::update_info::feerate_per_kw_irrevocably_committed`
    -66: update `ln_channel_t::shutdown_flag`
    -67: update `ln_channel_t::status`
    -68: add `ln_channel_t::prev_remote_commit_txid`
 */

#endif /* LN_VERSION_H__ */
