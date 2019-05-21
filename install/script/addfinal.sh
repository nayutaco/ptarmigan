#!/bin/bash
set -eu

#   method: addfinal
#   $1: short_channel_id
#   $2: node_id
#   $3: payment_hash
#   $4: amount_msat
#   $5: local_msat
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{ "method":"addfinal", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "payment_hash":"$3", "amount_msat":$4, "local_msat":$5 }
EOS
