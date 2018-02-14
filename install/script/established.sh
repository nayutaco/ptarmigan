#!/bin/sh
#   method: established
#   $1: short_channel_id
#   $2: node_id
#   $3: our_msat
#   $4: funding_txid
DATE=`date +"%c %N"`
echo { \"method\": \"established\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"our_msat\": $3, \"debug\": \"funding_txid=$4\" } | jq .

# our_msat
echo $3 > our_msat_$1.txt
