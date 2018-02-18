#!/bin/sh
FUNDIN_BTC=0.1
FUND_SAT=600000
PUSH_SAT=300000

CONF=`pwd`/regtest.conf
DATADIR=`pwd`/regtest
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
