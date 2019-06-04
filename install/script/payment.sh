#!/bin/bash
set -eu
#   method: payment
#   $1: short_channel_id
#   $2: node_id
#   $3: amt_to_forward
#   $4: outgoing_cltv_value
#   $5: payment_id
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq -e '.'
{
    "method":"payment",
    "date":"$DATE",
    "short_channel_id":"$1",
    "node_id":"$2",
    "amt_to_forward":$3,
    "outgoing_cltv_value":$4,
    "payment_id":$5
}
EOS
