#!/bin/bash
set -eu
#   method: started
#   $1: short_channel_id
#   $2: node_id
#   $3: local_msat
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{
    "method":"started",
    "date":"$DATE",
    "short_channel_id":"$1",
    "node_id":"$2",
    "local_msat":$3
}
EOS
