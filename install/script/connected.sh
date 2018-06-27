#!/bin/bash
#   method: connected
#   $1: short_channel_id
#   $2: node_id
#   $3: peer_id
DATE=`date +"%Y-%m-%dT%H:%M:%S.%N"`
echo { \"method\": \"connected\", \"short_channel_id\": \"$1\", \"node_id\": \"$2\", \"date\": \"$DATE\", \"debug\": \"peer_id=$3\" } | jq -c .

##自動fundingしたいnode_idを列挙
#peer_array=("")

## funding_txに送金する元になる額(BTC). feeを考慮して少し多めにしておく.
## bitcoindから直接native-segwitアドレスに送金できないので、addwitnessaddressでP2SH-segwitアドレスを作って送金している。
#FUND_BTC=0.01

## FUND_BTCのうち、funding_txに送金する額(satoshi)
#FUND_SAT=600000

#if [ ! -e ./dbucoin ]; then
#    echo no DB directory
#    exit 1
#fi
#i=0
#fund_node=""
#for elm in ${peer_array[@]}; do
#    if [ $elm = $3 ]; then
#        res=`../showdb -s | grep "peer_node_id" | grep -c $elm`
#        if [ $res -eq 0 ]; then
#            echo funding $elm
#            CONF=~/.bitcoin/bitcoin.conf
#            DATADIR=~/.bitcoin
#            ADDR=`bitcoin-cli -conf=$CONF -datadir=$DATADIR getnewaddress`
#            SEG=`bitcoin-cli -conf=$CONF -datadir=$DATADIR addwitnessaddress $ADDR`
#            TXID=`bitcoin-cli -conf=$CONF -datadir=$DATADIR sendtoaddress $SEG $FUND_BTC`
#            CNT=`bitcoin-cli -conf=$CONF -datadir=$DATADIR gettxout $TXID 0 | grep $SEG | wc -c`
#            if [ $CNT -gt 0 ]; then
#                TXINDEX=0
#            else
#                TXINDEX=1
#            fi
#            echo "{\"method\":\"fund\",\"params\":[\"$elm\",\"0.0.0.0\",0,\"$TXID\",$TXINDEX,\"$ADDR\",$FUND_SAT,0]}" | nc localhost $4
#        fi
#        break;
#    fi
#    let i++
#done
#echo connect.sh DONE
