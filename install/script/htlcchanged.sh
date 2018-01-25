#!/bin/bash
#   method: htlc_changed
#   $1: short_channel_id
#   $2: node_id
#   $3: our_msat
#   $4: htlc_num
DATE=`date +"%c %N"`
echo { \"method\": \"htlc_changed\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"our_msat\": $3, \"debug\": \"htlc_num=$4\" } | jq .

# changes in amount
if [ -f our_msat.txt ]; then
    OUR_MSAT=`cat our_msat.txt`
    pay=$(($3-$OUR_MSAT))
    if [ $pay -gt 0 ]; then
        echo GET: $pay msat!
        #./script/something_get.sh $pay
    fi
    if [ $pay -lt 0 ]; then
        echo PAY: $((0-$pay)) msat!
        #./script/something_pay.sh $pay
    fi
    echo $3 > our_msat.txt
fi
