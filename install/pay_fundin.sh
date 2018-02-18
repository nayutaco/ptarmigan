#!/bin/sh
set -eu

if [ $# -ne 3 ]; then
	echo "create fund-in information file."
	echo "  - create P2WPKH address"
	echo "  - pay from bitcoind to the address"
	echo
	echo "  usage:"
	echo "    pay_fundin.sh <pay to P2WPKH(satoshi)> <pay to our channel(satoshi)> <pay to their channel(satoshi)>"
	return 1
fi

FUNDIN_CONF=fund_`date +%Y%m%d%H%M%S`.conf
FUNDIN_BTC=`echo "scale=10; $1/100000000" | bc`
FUNDIN_BTC=`printf "%.8f" $FUNDIN_BTC`
FUND_SAT=$2
PUSH_SAT=$3

CONF=~/.bitcoin/bitcoin.conf
DATADIR=~/.bitcoin

ADDR=`bitcoin-cli -conf=$CONF -datadir=$DATADIR getnewaddress`
SEG=`bitcoin-cli -conf=$CONF -datadir=$DATADIR addwitnessaddress $ADDR`
TXID=`bitcoin-cli -conf=$CONF -datadir=$DATADIR sendtoaddress $SEG $FUNDIN_BTC`
echo txid=$TXID > $FUNDIN_CONF
CNT=`bitcoin-cli -conf=$CONF -datadir=$DATADIR gettxout $TXID 0 | grep $SEG | wc -c`
if [ $CNT -gt 0 ]; then
	echo txindex=0 >> $FUNDIN_CONF
else
	echo txindex=1 >> $FUNDIN_CONF
fi
echo signaddr=$ADDR >> $FUNDIN_CONF
echo funding_sat=$FUND_SAT >> $FUNDIN_CONF
echo push_sat=$PUSH_SAT >> $FUNDIN_CONF
