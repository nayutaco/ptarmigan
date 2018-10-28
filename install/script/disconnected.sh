#!/bin/bash
#   method: disconnected
#   $1: short_channel_id
#   $2: node_id
#   $3: peer_id
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"disconnected\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"debug\": \"peer_id=$3\" } | jq -c .

