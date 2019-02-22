#!/bin/bash
set -eu
#   method: started
#   $1: short_channel_id
#   $2: node_id
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{ "method":"started", "short_channel_id":"$1", "node_id":"$2" }
EOS
