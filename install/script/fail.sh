#!/bin/sh
#	method: fail
#	$1: short_channel_id
#	$2: node_id
DATE=`date +"%c %N"`
echo { \"method\": \"debug\", \"kind\": \"fail\", \"short_channel_id\": $1, \"node_id\": \"$2\", \"date\": \"$DATE\" } | jq .
