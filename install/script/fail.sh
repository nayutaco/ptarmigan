#!/bin/sh
#	method: fail
#	$1: short_channel_id
echo $(date +%c) $(date +%N)
echo { \"method\": \"fail\", \"short_channel_id\": $1 } | jq .
