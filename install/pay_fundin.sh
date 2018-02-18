#!/bin/sh
set -eu

FUNDIN_BTC=`echo "scale=10; $1/100000000" | bc`
FUNDIN_BTC=`printf "%.8f" $FUNDIN_BTC`
FUND_SAT=$2
PUSH_SAT=$3

CONF=~/.bitcoin/bitcoin.conf
DATADIR=~/.bitcoin

ADDR=`bitcoin-cli -conf=$CONF -datadir=$DATADIR getnewaddress`
SEG=`bitcoin-cli -conf=$CONF -datadir=$DATADIR addwitnessaddress $ADDR`
TXID=`bitcoin-cli -conf=$CONF -datadir=$DATADIR sendtoaddress $SEG $FUNDIN_BTC`
echo txid=$TXID
CNT=`bitcoin-cli -conf=$CONF -datadir=$DATADIR gettxout $TXID 0 | grep $SEG | wc -c`
if [ $CNT -gt 0 ]; then
	echo txindex=0
else
	echo txindex=1
fi
echo signaddr=$ADDR
echo funding_sat=$FUND_SAT
echo push_sat=$PUSH_SAT
