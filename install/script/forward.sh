#!/bin/sh
#   method: forward
#   $1: short_channel_id
#   $2: node_id
#   $3: amt_to_forward
#   $4: outgoing_cltv_value
#   $5: payment_hash
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"forward\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"amt_to_forward\": $3, \"debug\": \"outgoing_cltv_value=$4, payment_hash=$5\" } | jq -c . > j.json

if [ -f script/PTARMTEST.txt ]; then
    PTARMTEST=`cat script/PTARMTEST.txt`
fi
if [ -n "$PTARMTEST" ]; then
    cat j.json | curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d @- http://${PTARMTEST}/reports/
fi
rm -f j.json
