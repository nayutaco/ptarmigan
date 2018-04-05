#!/bin/sh
#   method: fulfill
#   $1: short_channel_id
#   $2: node_id
#   $3: payment_hash
#   $4: payment_preimage
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"fulfill\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"debug\": \"payment_hash=$3, payment_preimage=$4\" } | jq -c . > j.json

export PTARMTEST=`cat script/PTARMTEST.txt`
if [ -n "$PTARMTEST" ]; then
    cat j.json | curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d @- http://${PTARMTEST}/reports/
fi
rm j.json
