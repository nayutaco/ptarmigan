#!/bin/bash
set -eu
#   method: fulfill
#   $1: short_channel_id
#   $2: node_id
#   $3: payment_hash
#   $4: payment_preimage
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{ "method":"fulfill", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "payment_hash":"$3", "payment_preimage":"$4" }
EOS
