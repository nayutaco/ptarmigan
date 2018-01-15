#!/bin/sh
#	method: closed
#	$1: short_channel_id
#	$2: node_id
#	$3: closing_txid
DATE=`date +"%c %N"`
echo { \"method\": \"closed\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"debug\": \"closing_txid=$3\" } | jq .
