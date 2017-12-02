#!/bin/sh
#	method: payment
#	$1: short_channel_id
#	$2: amt_to_forward
#	$3: outgoing_cltv_value
#	$4: payment_hash
echo $(date +%c) $(date +%N)
echo { \"method\": \"payment\", \"short_channel_id\": \"$1\", \"amt_to_forward\": $2, \"outgoing_cltv_value\": $3, \"payment_hash\": \"$4\" } | jq .
