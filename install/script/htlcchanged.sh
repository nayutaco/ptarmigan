#!/bin/sh
#	method: htlc_changed
#	$1: short_channel_id
#	$2: our_msat
#	$3: htlc_num
#	$4: node_id
DATE=`date +"%c %N"`
echo { \"method\": \"htlc_changed\", \"short_channel_id\": \"$1\", \"our_msat\": $2, \"htlc_num\": $3, \"node_id\": \"$4\", \"date\": \"$DATE\" } | jq .
