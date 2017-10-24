#!/bin/sh
#	method: htlc_changed
#	$1: short_channel_id
#	$2: our_msat
#	$3: htlc_num
echo $(date +%c) $(date +%N)
echo { \"method\": \"htlc_changed\", \"short_channel_id\": $1, \"our_msat\": $2, \"htlc_num\": $3 } | jq .
