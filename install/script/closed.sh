#!/bin/sh
#	method: closed
#	$1: short_channel_id
#	$2: closing_txid
echo $(date +%c) $(date +%N)
echo { \"method\": \"closed\", \"short_channel_id\": $1, \"closing_txid\": \"$2\" } | jq .
