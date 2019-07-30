#!/bin/bash -ue

LOG_FILES=$@

grep -n -e "\/E" -e "fail\:" -e "fail$" $LOG_FILES | \
    grep -v \
        -e "not real value" \
        -e "channel_id is 0" \
        -e "recv_peer]fail: timeout(" \
        -e "already connected" \
        -e "cmd_json_connect]fail: connect test" \
        -e "Connection reset by peer" \
        -e "confirm=fail" \
        -e "btcrpc_get_confirmations_funding_tx]fail: invalid txid" \
        -e "handshake" || :
