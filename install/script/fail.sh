#!/bin/bash
set -eu
#   method: fail
#   $1: short_channel_id
#   $2: node_id
#   $3: info
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{
    "method":"fail",
    "date":"$DATE",
    "short_channel_id":"$1",
    "node_id":"$2",
    "info":"$3"
}
EOS
