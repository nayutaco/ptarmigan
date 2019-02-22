#!/bin/bash
set -eu
#   method: connected
#   $1: short_channel_id
#   $2: node_id
#   $3: peer_id
#   $4: received localfeatures
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{ "method":"connected", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "peer_id":"$3", "localfeatures":$4 }
EOS
