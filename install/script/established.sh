#!/bin/sh
#	method: established
#	$1: short_channel_id
#	$2: our_msat
#	$3: funding_txid
#	$4: node_id
echo $(date +%c) $(date +%N)
echo { \"method\": \"established\", \"short_channel_id\": \"$1\", \"our_msat\": $2, \"funding_txid\": \"$3\", \"node_id\": \"$4\" } | jq .
