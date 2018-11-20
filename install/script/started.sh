#!/bin/sh
#   method: started
#   $1: 0
#   $2: node_id
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"started\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\" } | jq -c .
