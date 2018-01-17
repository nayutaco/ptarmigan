#!/bin/sh
#	method: htlc_changed
#	$1: short_channel_id
#	$2: node_id
#	$3: our_msat
#	$4: htlc_num
DATE=`date +"%c %N"`
echo { \"method\": \"htlc_changed\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"our_msat\": $3, \"debug\": \"htlc_num=$4\" } | jq .
