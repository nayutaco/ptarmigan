#!/bin/sh
#   method: closed
#   $1: short_channel_id
#   $2: node_id
#   $3: closing_txid
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"closed\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"debug\": \"closing_txid=$3\" } | jq -c .
