#!/bin/bash
set -eu
#   method: established
#   $1: short_channel_id
#   $2: node_id
#   $3: local_msat
#   $4: funding_txid
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{
    "method":"established",
    "date":"$DATE",
    "short_channel_id":"$1",
    "node_id":"$2",
    "local_msat":$3,
    "funding_txid":"$4"
}
EOS
