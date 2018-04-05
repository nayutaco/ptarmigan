#!/bin/bash
#   method: htlc_changed
#   $1: short_channel_id
#   $2: node_id
#   $3: our_msat
#   $4: htlc_num
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"htlc_changed\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"our_msat\": $3, \"debug\": \"htlc_num=$4\" } | jq -c . > j.json

if [ -f script/PTARMTEST.txt ]; then
    PTARMTEST=`cat script/PTARMTEST.txt`
fi
if [ -n "$PTARMTEST" ]; then
    cat j.json | curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d @- http://${PTARMTEST}/reports/
fi
rm j.json

## changes in amount
#if [ -f our_msat_$1.txt ]; then
#    OUR_MSAT=`cat our_msat_$1.txt`
#    pay=$(($3-$OUR_MSAT))
#    if [ $pay -gt 0 ]; then
#        echo GET: $pay msat!
#        #./script/something_get.sh $pay
#    fi
#    if [ $pay -lt 0 ]; then
#        echo PAY: $((0-$pay)) msat!
#        #./script/something_pay.sh $pay
#    fi
#    echo $3 > our_msat_$1.txt
#fi
