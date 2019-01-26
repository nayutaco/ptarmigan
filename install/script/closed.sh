#!/bin/sh
set -eu
#   method: closed
#   $1: short_channel_id
#   $2: node_id
#   $3: closing_txid
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq
{ "method":"closed", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "closing_txid":"$3" }
EOS
