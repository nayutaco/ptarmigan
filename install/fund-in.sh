#!/bin/sh
set -eu

CONF=~/.bitcoin/bitcoin.conf
DATADIR=~/.bitcoin

ADDR=`bitcoin-cli -conf=$CONF -datadir=$DATADIR getnewaddress`
SEG=`bitcoin-cli -conf=$CONF -datadir=$DATADIR addwitnessaddress $ADDR`
TXID=`bitcoin-cli -conf=$CONF -datadir=$DATADIR sendtoaddress $SEG $1`
echo txid=$TXID
CNT=`bitcoin-cli -conf=$CONF -datadir=$DATADIR gettxout $TXID 0 | grep $SEG | wc -c`
if [ $CNT -gt 0 ]; then
	echo txindex=0
else
	echo txindex=1
fi
echo signaddr=$ADDR
cat $2
