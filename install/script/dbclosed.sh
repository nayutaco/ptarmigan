#!/bin/bash
set -eu
#   method: dbclosed
#   $1: short_channel_id
#   $2: node_id
#   $3: channel_id
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{ "method":"dbclosed", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "channel_id":"$3" }
EOS
