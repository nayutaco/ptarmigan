#!/bin/sh
set -eu

ADDR=`bitcoin-cli getnewaddress`
SEG=`bitcoin-cli addwitnessaddress $ADDR`
TXID=`bitcoin-cli sendtoaddress $SEG $1`
echo txid=$TXID
CNT=`bitcoin-cli gettxout $TXID 0 | grep $SEG | wc -c`
if [ $CNT -gt 0 ]; then
	echo txindex=0
else
	echo txindex=1
fi
echo signaddr=$ADDR
cat $2
