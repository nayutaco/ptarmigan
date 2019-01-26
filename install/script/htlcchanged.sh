#!/bin/bash
set -eu
#   method: htlc_changed
#   $1: short_channel_id
#   $2: node_id
#   $3: our_msat
DATE=`date -u +"%Y-%m-%dT%H:%M:%S.%N"`
cat << EOS | jq
{ "method":"htlc_changed", "short_channel_id":"$1", "node_id":"$2", "date":"$DATE", "our_msat":$3 }
EOS

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
