#!/bin/sh
#	method: closed
#	$1: short_channel_id
#	$2: closing_txid
#	$3: node_id
DATE=`date +"%c %N"`
echo { \"method\": \"closed\", \"short_channel_id\": \"$1\", \"closing_txid\": \"$2\", \"node_id\": \"$3\", \"date\": \"$DATE\" } | jq .
