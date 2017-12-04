#!/bin/sh
#	method: fulfill
#	$1: short_channel_id
#	$2: payment_preimage
#	$3: payment_hash
#	$4: node_id
DATE=`date +"%c %N"`
echo { \"method\": \"fulfill\", \"short_channel_id\": \"$1\", \"payment_preimage\": \"$2\", \"payment_hash\": \"$3\", \"node_id\": \"$4\", \"date\": \"$DATE\" } | jq .
