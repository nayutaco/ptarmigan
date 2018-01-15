#!/bin/sh
#	method: connected
#	$1: short_channel_id
#	$2: node_id
#   $3: peer_id
#   $4: JSON-RPC port
DATE=`date +"%c %N"`
echo { \"method\": \"connected\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"debug\": \"peer_id=$3\" } | jq .
