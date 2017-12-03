#!/bin/sh
#	method: fail
#	$1: short_channel_id
#	$2: node_id
echo $(date +%c) $(date +%N)
echo { \"method\": \"fail\", \"short_channel_id\": $1, \"node_id\": \"$2\" } | jq .
