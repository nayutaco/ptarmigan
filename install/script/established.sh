#!/bin/sh
#   method: established
#   $1: short_channel_id
#   $2: node_id
#   $3: our_msat
#   $4: funding_txid
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"established\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"our_msat\": $3, \"debug\": \"funding_txid=$4\" } | jq -c . > j.json

export PTARMTEST=`cat script/PTARMTEST.txt`
if [ -n "$PTARMTEST" ]; then
    cat j.json | curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d @- http://${PTARMTEST}/reports/
fi
rm j.json

## our_msat
#echo $3 > our_msat_$1.txt
