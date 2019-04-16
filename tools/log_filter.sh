#!/bin/bash -ue

LOG_FILE=$1

grep -n -e "\/E" -e "fail\:" $LOG_FILE | \
    grep -v \
        -e "not real value" \
        -e "channel_id is 0" \
        -e "recv_peer]fail: timeout(" \
        -e "already connected" \
        -e "cmd_json_connect]fail: connect test" \
        -e "Connection reset by peer" \
        -e "handshake" || :
