#!/bin/bash
#   method: error
#   $1: short_channel_id
#   $2: node_id
#   $3: err_str
DATE=`date +"%c %N"`
echo { \"method\": \"connected\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"err_str\": \"$3\" } | jq .

echo $err_str >> err_$1.log
