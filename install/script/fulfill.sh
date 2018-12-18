#!/bin/sh
#   method: fulfill
#   $1: short_channel_id
#   $2: node_id
#   $3: payment_hash
#   $4: payment_preimage
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"fulfill\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"debug\": \"payment_hash=$3, payment_preimage=$4\" } | jq -c .
