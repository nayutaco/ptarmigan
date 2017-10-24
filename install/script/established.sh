#!/bin/sh
#	method: established
#	$1: short_channel_id
#	$2: our_msat
#	$3: funding_txid
echo $(date +%c) $(date +%N)
echo { \"method\": \"established\", \"short_channel_id\": $1, \"our_msat\": $2, \"funding_txid\": \"$3\" } | jq .
