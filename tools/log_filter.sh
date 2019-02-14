#!/bin/bash -ue

SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=$(cd $(dirname $0); pwd)
PRJ_HOME=$SCRIPT_DIR/../

(
cd $PRJ_HOME
grep -n -e "\/E" -e "fail\:"  tests/4nodes_test/node_*/logs/log | \
    grep -v \
        -e "not real value" \
        -e "channel_id is 0" \
        -e "recv_peer]fail: timeout(" \
        -e "already connected"
cd -
)
