#!/bin/sh
#	method: fulfill
#	$1: short_channel_id
#	$2: payment_preimage
#	$3: payment_hash
echo $(date +%c) $(date +%N)
echo { \"method\": \"fulfill\", \"short_channel_id\": $1, \"payment_preimage\": \"$2\", \"payment_hash\": \"$3\" } | jq .
