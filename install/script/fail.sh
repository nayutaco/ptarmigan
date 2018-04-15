#!/bin/sh
#   method: fail
#   $1: short_channel_id
#   $2: node_id
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"fail\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\" } | jq -c . > j.json

if [ -f script/PTARMTEST.txt ]; then
    PTARMTEST=`cat script/PTARMTEST.txt`
fi
if [ -n "$PTARMTEST" ]; then
    cat j.json | curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d @- http://${PTARMTEST}/reports/
fi
rm j.json
