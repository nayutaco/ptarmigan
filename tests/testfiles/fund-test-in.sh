#!/bin/sh
FUNDIN_BTC=0.1
FUND_SAT=600000
PUSH_MSAT=300000000
CONFFILE=`pwd`/regtest.conf
DATADIR=`pwd`

cli() {
	bitcoin-cli -conf=$CONFFILE -datadir=$DATADIR $@
}

ADDR=`cli getnewaddress`
TXID=`cli sendtoaddress $ADDR $FUNDIN_BTC`
echo txid=$TXID
CNT=`cli gettxout $TXID 0 | grep $ADDR | wc -c`
if [ $CNT -gt 0 ]; then
	echo txindex=0
else
	echo txindex=1
fi
echo funding_sat=$FUND_SAT
echo push_msat=$PUSH_MSAT
