#!/bin/bash
set -eu
#   method: error
#   $1: short_channel_id
#   $2: node_id
#   $3: err_str
#   $4: direction
#   $5: peer_id
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{
    "method":"error",
    "date":"$DATE",
    "short_channel_id":"$1",
    "node_id":"$2",
    "err_str":"$3",
    "direction":"$4",
    "peer_id":"$5"
}
EOS
