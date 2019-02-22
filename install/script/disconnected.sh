#!/bin/bash
set -eu
#   method: disconnected
#   $1: short_channel_id
#   $2: node_id
#   $3: peer_id
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{ "method":"disconnected", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "peer_id":"$3" }
EOS
