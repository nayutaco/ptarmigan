#!/bin/bash
set -eu
#   method: error
#   $1: short_channel_id
#   $2: node_id
#   $3: err_str
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{ "method":"error", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "err_str":"$3" }
EOS
